//! Managed entries (SPEC-engine.md, Managed entries; #747): a module owns the
//! members of the arrays of a JSON fragment inside a project-owned JSON file
//! (`.claude/settings.json`: deny rules, hook entries) and nothing else in it.
//! The plan appends a missing entry after the project's members, leaves a
//! present one alone and refuses a member that carries the same name with other
//! content; a retirement and `remove` take the recorded entries out again. The
//! file is written only when an entry is added or removed, so a file whose
//! entries already match is never rewritten. A string leaf of the fragment is
//! an owned member of the object that holds it, named by its key (#751:
//! `opencode.json`'s `permission.read` and `permission.edit` patterns).
use crate::{Result, refuse};
use serde_json::{Map, Value};
use std::collections::BTreeSet;

/// One array of a fragment: where it sits and the entries owned there.
struct Owned {
    tokens: Vec<String>,
    members: Vec<Value>,
}

/// One object member of a fragment: the object's pointer, the key and its
/// string value (#751).
#[derive(PartialEq)]
struct Key {
    tokens: Vec<String>,
    key: String,
    value: Value,
}

/// What a fragment owns: array members and object members.
#[derive(Default)]
struct Parts {
    arrays: Vec<Owned>,
    keys: Vec<Key>,
}

/// Parses a module's fragment: a JSON object whose arrays, at any depth, hold
/// the owned entries. Anything else refuses naming the module and the pointer.
pub fn fragment(module: &str, path: &str, text: &str) -> Result<Value> {
    match serde_json::from_str::<Value>(text) {
        Ok(value @ Value::Object(_)) => {
            owned(module, path, &value)?;
            Ok(value)
        }
        _ => refuse(format!(
            "Module {module}: managed entries must be a JSON object: {path}"
        )),
    }
}

/// The arrays and string leaves of a checked fragment, in key order.
fn owned(module: &str, path: &str, fragment: &Value) -> Result<Parts> {
    fn walk(
        module: &str,
        path: &str,
        value: &Value,
        tokens: &mut Vec<String>,
        out: &mut Parts,
    ) -> Result<()> {
        match value {
            Value::Object(map) => {
                for (key, child) in map {
                    if child.is_string() {
                        out.keys.push(Key {
                            tokens: tokens.clone(),
                            key: key.clone(),
                            value: child.clone(),
                        });
                        continue;
                    }
                    tokens.push(key.clone());
                    walk(module, path, child, tokens, out)?;
                    tokens.pop();
                }
                Ok(())
            }
            Value::Array(members) => {
                out.arrays.push(Owned {
                    tokens: tokens.clone(),
                    members: members.clone(),
                });
                Ok(())
            }
            _ => refuse(format!(
                "Module {module}: managed entries must be arrays: {path} at {}",
                pointer(tokens)
            )),
        }
    }
    let mut out = Parts::default();
    walk(module, path, fragment, &mut Vec::new(), &mut out)?;
    Ok(out)
}

/// The object at `tokens`, created with its parents when absent; a present
/// value of another type refuses naming the pointer.
fn object_or_create<'a>(
    path: &str,
    document: &'a mut Value,
    tokens: &[String],
) -> Result<&'a mut Map<String, Value>> {
    let mut current = document;
    for token in tokens {
        current = match current {
            Value::Object(map) => map
                .entry(token.clone())
                .or_insert_with(|| Value::Object(Map::new())),
            _ => break,
        };
    }
    match current {
        Value::Object(map) => Ok(map),
        _ => refuse(format!(
            "Managed entries destination has no object at {}: {path}",
            pointer(tokens)
        )),
    }
}

/// Takes object members out: equal → removed, other value → `refusal` with the
/// member's pointer and key, absent → forgotten. Returns whether it changed.
fn take_keys(
    document: &mut Value,
    keys: &[&Key],
    refusal: impl Fn(&str, &str) -> String,
) -> Result<bool> {
    let mut changed = false;
    for Key { tokens, key, value } in keys {
        let Some(map) = object_mut(document, tokens) else {
            continue;
        };
        match map.get(key) {
            Some(present) if present == value => {
                map.remove(key);
                changed = true;
                prune(document, tokens);
            }
            Some(_) => {
                let mut at = tokens.clone();
                at.push(key.clone());
                return refuse(refusal(&pointer(&at), key));
            }
            None => {}
        }
    }
    Ok(changed)
}

/// An RFC 6901 pointer for a message.
fn pointer(tokens: &[String]) -> String {
    tokens
        .iter()
        .map(|t| format!("/{}", t.replace('~', "~0").replace('/', "~1")))
        .collect()
}

/// The project file as a JSON object; absent counts as `{}`.
fn document(path: &str, current: Option<&str>) -> Result<Value> {
    match current.map(serde_json::from_str::<Value>) {
        None => Ok(Value::Object(Map::new())),
        Some(Ok(value @ Value::Object(_))) => Ok(value),
        Some(_) => refuse(format!(
            "Managed entries destination is not a JSON object: {path}"
        )),
    }
}

fn text(document: &Value) -> Result<String> {
    Ok(serde_json::to_string_pretty(document)? + "\n")
}

/// The names of an entry: a string names itself; an object is named by its
/// `command` values at any depth. An object without one has no name, so an
/// edit of it reads as a deletion.
fn names(entry: &Value) -> BTreeSet<String> {
    fn collect(value: &Value, out: &mut BTreeSet<String>) {
        match value {
            Value::Object(map) => {
                for (key, child) in map {
                    match child {
                        Value::String(command) if key == "command" => {
                            out.insert(command.clone());
                        }
                        _ => collect(child, out),
                    }
                }
            }
            Value::Array(items) => items.iter().for_each(|item| collect(item, out)),
            _ => {}
        }
    }
    let mut out = BTreeSet::new();
    match entry {
        Value::String(text) => {
            out.insert(text.clone());
        }
        other => collect(other, &mut out),
    }
    out
}

/// Whether `present` is `owned` edited in place: not equal, but sharing a name.
fn same_name(present: &Value, owned: &Value) -> bool {
    let theirs = names(present);
    present != owned && !theirs.is_empty() && !theirs.is_disjoint(&names(owned))
}

fn name_of(entry: &Value) -> String {
    let names = names(entry);
    if names.is_empty() {
        entry.to_string()
    } else {
        names.into_iter().collect::<Vec<_>>().join(", ")
    }
}

/// The object at `tokens`, objects only; `None` when absent or not an object.
fn object_mut<'a>(
    document: &'a mut Value,
    tokens: &[String],
) -> Option<&'a mut Map<String, Value>> {
    let mut current = document;
    for token in tokens {
        current = match current {
            Value::Object(map) => map.get_mut(token)?,
            _ => return None,
        };
    }
    current.as_object_mut()
}

/// The array at `tokens`, created with its parent objects when absent; a
/// present value of another type refuses naming the pointer.
fn array_mut<'a>(
    path: &str,
    document: &'a mut Value,
    tokens: &[String],
) -> Result<&'a mut Vec<Value>> {
    let mut current = document;
    for (i, token) in tokens.iter().enumerate() {
        let last = i + 1 == tokens.len();
        current = match current {
            Value::Object(map) => map.entry(token.clone()).or_insert_with(|| {
                if last {
                    Value::Array(Vec::new())
                } else {
                    Value::Object(Map::new())
                }
            }),
            _ => break,
        };
    }
    match current {
        Value::Array(items) => Ok(items),
        _ => refuse(format!(
            "Managed entries destination has no array at {}: {path}",
            pointer(tokens)
        )),
    }
}

/// Removes the key at `tokens` when it is an empty array or object, then each
/// emptied ancestor, never the root.
fn prune(document: &mut Value, tokens: &[String]) {
    for depth in (1..=tokens.len()).rev() {
        let Some(parent) = object_mut(document, &tokens[..depth - 1]) else {
            return;
        };
        let key = &tokens[depth - 1];
        let empty = match parent.get(key) {
            Some(Value::Array(items)) => items.is_empty(),
            Some(Value::Object(map)) => map.is_empty(),
            _ => false,
        };
        if !empty {
            return;
        }
        parent.remove(key);
    }
}

/// Takes `members` out of the array at `tokens`: a member present exactly is
/// removed, one present under its name refuses with `refusal`, an absent one is
/// forgotten. Returns whether the document changed.
fn take(
    document: &mut Value,
    tokens: &[String],
    members: &[&Value],
    refusal: impl Fn(&str) -> String,
) -> Result<bool> {
    let Some((last, parents)) = tokens.split_last() else {
        return Ok(false);
    };
    let Some(Value::Array(array)) = object_mut(document, parents).and_then(|map| map.get_mut(last))
    else {
        return Ok(false);
    };
    let mut changed = false;
    for member in members {
        if let Some(i) = array.iter().position(|present| present == *member) {
            array.remove(i);
            changed = true;
        } else if let Some(found) = array.iter().find(|present| same_name(present, member)) {
            return refuse(refusal(&name_of(found)));
        }
    }
    if changed {
        prune(document, tokens);
    }
    Ok(changed)
}

/// What the plan writes at `path` for `fragment`, after taking out the entries
/// of `prior` (the lock's) it no longer renders: `None` when every entry is
/// already in place.
pub fn reconcile(
    module: &str,
    path: &str,
    current: Option<&str>,
    fragment: &Value,
    prior: Option<&Value>,
) -> Result<Option<String>> {
    let mut document = document(path, current)?;
    let now = owned(module, path, fragment)?;
    let mut changed = false;
    if let Some(prior) = prior {
        let old_parts = owned(module, path, prior)?;
        let retired: Vec<&Key> = old_parts
            .keys
            .iter()
            .filter(|k| !now.keys.contains(k))
            .collect();
        changed |= take_keys(&mut document, &retired, |at, key| {
            format!("Locally changed retired managed entry: {path} at {at} ({key})")
        })?;
        for old in old_parts.arrays {
            let kept = now
                .arrays
                .iter()
                .find(|o| o.tokens == old.tokens)
                .map_or(&[][..], |o| o.members.as_slice());
            let retired: Vec<&Value> = old.members.iter().filter(|m| !kept.contains(m)).collect();
            changed |= take(&mut document, &old.tokens, &retired, |name| {
                format!(
                    "Locally changed retired managed entry: {path} at {} ({name})",
                    pointer(&old.tokens)
                )
            })?;
        }
    }
    for Key { tokens, key, value } in &now.keys {
        let map = object_or_create(path, &mut document, tokens)?;
        match map.get(key) {
            Some(present) if present == value => {}
            Some(_) => {
                let mut at = tokens.clone();
                at.push(key.clone());
                return refuse(format!(
                    "Locally changed managed entry: {path} at {} ({key})",
                    pointer(&at)
                ));
            }
            None => {
                map.insert(key.clone(), value.clone());
                changed = true;
            }
        }
    }
    for Owned { tokens, members } in &now.arrays {
        let array = array_mut(path, &mut document, tokens)?;
        for member in members {
            if array.contains(member) {
                continue;
            }
            if let Some(found) = array.iter().find(|present| same_name(present, member)) {
                return refuse(format!(
                    "Locally changed managed entry: {path} at {} ({})",
                    pointer(tokens),
                    name_of(found)
                ));
            }
            array.push(member.clone());
            changed = true;
        }
    }
    if changed {
        Ok(Some(text(&document)?))
    } else {
        Ok(None)
    }
}

/// Takes the recorded `entries` out of `path` when the module retires it or is
/// removed: `Ok(None)` when there is nothing to write (no file, or nothing of
/// the module's in it), `Some(None)` when `{}` is all that remains (the file is
/// deleted), `Some(Some(text))` otherwise. `refusal` takes the pointer and the
/// name of an entry edited in place.
pub fn retire(
    module: &str,
    path: &str,
    current: Option<&str>,
    entries: &Value,
    refusal: impl Fn(&str, &str) -> String,
) -> Result<Option<Option<String>>> {
    let Some(current) = current else {
        return Ok(None);
    };
    let mut document = document(path, Some(current))?;
    let mut changed = false;
    let parts = owned(module, path, entries)?;
    let keys: Vec<&Key> = parts.keys.iter().collect();
    changed |= take_keys(&mut document, &keys, &refusal)?;
    for old in parts.arrays {
        let members: Vec<&Value> = old.members.iter().collect();
        changed |= take(&mut document, &old.tokens, &members, |name| {
            refusal(&pointer(&old.tokens), name)
        })?;
    }
    if !changed {
        return Ok(None);
    }
    if document.as_object().is_some_and(Map::is_empty) {
        return Ok(Some(None));
    }
    Ok(Some(Some(text(&document)?)))
}

/// Whether every entry of `entries` is present exactly in `current`: what
/// `doctor` checks instead of a digest for this class.
pub fn in_place(current: Option<&str>, entries: &Value) -> bool {
    let Ok(mut document) = document("", current) else {
        return false;
    };
    let Ok(owned) = owned("", "", entries) else {
        return false;
    };
    let keys_in_place = owned.keys.iter().all(|Key { tokens, key, value }| {
        object_mut(&mut document, tokens).and_then(|map| map.get(key)) == Some(value)
    });
    keys_in_place
        && owned.arrays.iter().all(|Owned { tokens, members }| {
            let Some((last, parents)) = tokens.split_last() else {
                return members.is_empty();
            };
            match object_mut(&mut document, parents).and_then(|map| map.get(last)) {
                Some(Value::Array(array)) => members.iter().all(|m| array.contains(m)),
                _ => members.is_empty(),
            }
        })
}
