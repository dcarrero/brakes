//! Read-only check of alerts-as-code: Prometheus `groups[].rules[]` files only.
//! A small block-YAML subset reader keeps the installer free of a YAML dependency.
use crate::{Result, destination, directory};
use serde_json::{Map, Value};
use std::{fs, path::Path};

type Lines = Vec<(usize, String)>;

fn strip_comment(line: &str) -> &str {
    let mut quote = None;
    let mut prev = ' ';
    for (i, c) in line.char_indices() {
        match (quote, c) {
            (None, '"' | '\'') => quote = Some(c),
            (Some(q), c) if c == q => quote = None,
            (None, '#') if prev.is_whitespace() => return &line[..i],
            _ => {}
        }
        prev = c;
    }
    line
}

fn lines(text: &str) -> Option<Lines> {
    let mut out = Lines::new();
    for raw in text.lines() {
        let raw = strip_comment(raw).trim_end();
        if raw.trim().is_empty() || raw.trim() == "---" {
            continue;
        }
        if raw.contains('\t') && raw.trim_start_matches(' ').starts_with('\t') {
            return None;
        }
        let text = raw.trim_start_matches(' ');
        out.push((raw.len() - text.len(), text.to_owned()));
    }
    Some(out)
}

fn unquote(s: &str) -> String {
    let s = s.trim();
    for q in ['"', '\''] {
        if let Some(inner) = s.strip_prefix(q).and_then(|r| r.strip_suffix(q)) {
            return inner.to_owned();
        }
    }
    s.to_owned()
}

/// Splits `key: rest` at the first colon followed by a space or the end of the line.
fn entry(text: &str) -> Option<(String, &str)> {
    if text.starts_with('"') || text.starts_with('\'') {
        let end = text[1..].find(&text[..1])? + 2;
        let rest = text[end..].strip_prefix(':')?;
        return Some((unquote(&text[..end]), rest.trim()));
    }
    let at = text
        .match_indices(':')
        .map(|(i, _)| i)
        .find(|&i| text[i + 1..].is_empty() || text[i + 1..].starts_with(' '))?;
    Some((text[..at].trim().to_owned(), text[at + 1..].trim()))
}

fn block(ls: &mut Lines, at: &mut usize, indent: usize) -> Option<Value> {
    let is_seq = |t: &str| t == "-" || t.starts_with("- ");
    if is_seq(&ls[*at].1) {
        let mut items = Vec::new();
        while *at < ls.len() && ls[*at].0 == indent && is_seq(&ls[*at].1) {
            let rest = ls[*at].1[1..].trim_start().to_owned();
            let offset = ls[*at].1.len() - rest.len();
            if rest.is_empty() {
                *at += 1;
                items.push(match ls.get(*at) {
                    Some((i, _)) if *i > indent => block(ls, at, *i)?,
                    _ => Value::Null,
                });
            } else if entry(&rest).is_some() || is_seq(&rest) {
                ls[*at] = (indent + offset, rest);
                items.push(block(ls, at, indent + offset)?);
            } else {
                *at += 1;
                items.push(Value::String(unquote(&rest)));
            }
        }
        return Some(Value::Array(items));
    }
    let mut map = Map::new();
    while *at < ls.len() && ls[*at].0 == indent && !is_seq(&ls[*at].1) {
        let text = ls[*at].1.clone();
        let (key, rest) = entry(&text)?;
        *at += 1;
        let value = if rest.is_empty() {
            match ls.get(*at) {
                Some((i, t)) if *i > indent || (*i == indent && is_seq(t)) => {
                    let i = *i;
                    block(ls, at, i)?
                }
                _ => Value::Null,
            }
        } else {
            let mut text = rest.to_owned();
            let folded = rest.starts_with(['|', '>']);
            while *at < ls.len() && ls[*at].0 > indent {
                if !folded {
                    text = format!("{text} {}", ls[*at].1);
                }
                *at += 1;
            }
            Value::String(if folded {
                String::new()
            } else {
                unquote(&text)
            })
        };
        map.insert(key, value);
    }
    Some(Value::Object(map))
}

pub fn parse(text: &str) -> Option<Value> {
    let mut ls = lines(text)?;
    if ls.is_empty() {
        return None;
    }
    let mut at = 0;
    let indent = ls[0].0;
    let value = block(&mut ls, &mut at, indent)?;
    (at == ls.len()).then_some(value)
}

fn filled(value: &Value) -> Option<&str> {
    value.as_str().map(str::trim).filter(|s| !s.is_empty())
}

fn check_file(root: &Path, runbooks: Option<&str>, name: &str, text: &str, out: &mut Vec<String>) {
    let unrecognised =
        format!("Unrecognised alert file (expected Prometheus groups/rules): {name}");
    let Some(groups) = parse(text).and_then(|v| v.get("groups").cloned()) else {
        return out.push(unrecognised);
    };
    let Some(groups) = groups.as_array() else {
        return out.push(unrecognised);
    };
    let mut found = Vec::new();
    for group in groups {
        match group.get("rules").and_then(Value::as_array) {
            Some(rules) if group.is_object() => found.extend(rules),
            _ => return out.push(unrecognised),
        }
    }
    for rule in found {
        let Some(rule) = rule.as_object() else {
            return out.push(unrecognised);
        };
        let Some(alert) = rule.get("alert").and_then(filled) else {
            if rule.contains_key("record") {
                continue;
            }
            return out.push(unrecognised);
        };
        for (map, key) in [("labels", "owner"), ("labels", "severity")] {
            if rule
                .get(map)
                .and_then(|m| m.get(key))
                .and_then(filled)
                .is_none()
            {
                out.push(format!("Alert {alert} in {name} missing {map}.{key}"));
            }
        }
        match rule
            .get("annotations")
            .and_then(|m| m.get("runbook_url"))
            .and_then(filled)
        {
            None => out.push(format!(
                "Alert {alert} in {name} missing annotations.runbook_url"
            )),
            Some(url) if url.contains("://") => {}
            Some(url) => {
                let path = url.split('#').next().unwrap_or(url);
                let exists = [
                    Some(path.to_owned()),
                    runbooks.map(|d| format!("{d}/{path}")),
                ]
                .into_iter()
                .flatten()
                .any(|p| destination(root, &p).is_ok_and(|p| p.is_file()));
                if !exists {
                    out.push(format!("Alert {alert} in {name} runbook not found: {url}"));
                }
            }
        }
    }
}

pub fn check(root: &Path, alerts: &str, runbooks: Option<&str>) -> Result<Vec<String>> {
    let mut out = Vec::new();
    if let Some(dir) = runbooks.filter(|d| !directory(root, d).is_ok_and(|p| p.is_dir())) {
        out.push(format!("Runbooks directory missing: {dir}"));
    }
    let dir = directory(root, alerts)?;
    let Ok(entries) = fs::read_dir(&dir) else {
        out.push(format!("Alerts directory missing: {alerts}"));
        return Ok(out);
    };
    let mut files: Vec<_> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.is_file() && matches!(p.extension().and_then(|e| e.to_str()), Some("yml" | "yaml"))
        })
        .collect();
    files.sort();
    for path in files {
        let name = format!(
            "{alerts}/{}",
            path.file_name().expect("file").to_string_lossy()
        );
        match fs::read_to_string(&path) {
            Ok(text) => check_file(root, runbooks, &name, &text, &mut out),
            Err(_) => out.push(format!("Unrecognised alert file (unreadable): {name}")),
        }
    }
    Ok(out)
}
