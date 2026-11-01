//! The contracts `qa-contracts` judges (`SPEC-qa.md`, Contracts (slice 2);
//! T17, #1016): the `openapi`, `asyncapi` and `contract_ruleset` answers,
//! derived from the repository's files when unanswered, and their refusals.
//! The engine's answer schema has no null value, so `none` stands for "no
//! contract"; a contract path always ends in `.yaml`, `.yml` or `.json`.
//! Since #1182 a target lists several contracts (comma-separated), may declare
//! each live contract's frozen published copy (`contract_published`) and may
//! name the declared command that already checks compatibility
//! (`contract_compat_by`).
use crate::{Result, refuse};
use serde_json::Value;
use std::{fs, path::Path};

/// The answer meaning "no contract" (or no ruleset).
pub const NONE: &str = "none";
/// How many directory levels below the root the derivation looks.
const DEPTH: usize = 4;
/// Directories the derivation never enters, besides `qa_dir`.
const SKIPPED: [&str; 6] = [".git", "node_modules", "vendor", "target", "dist", "build"];
const EXTENSIONS: [&str; 3] = [".yaml", ".yml", ".json"];
/// The Spectral rulesets `contract_ruleset` is derived from, at the root.
pub const RULESETS: [&str; 3] = [".spectral.yaml", ".spectral.yml", ".spectral.json"];

/// What a file's first top-level key says it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    OpenApi,
    AsyncApi,
    Swagger,
}

/// The `contract_compat_by` answer meaning "`qa-contracts` compares".
pub const COMPAT_BY_QA: &str = "qa";

/// The resolved contract answers: empty lists are "no contract".
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Contracts {
    /// The live OpenAPI contracts, in answer order.
    pub openapi: Vec<String>,
    /// The live AsyncAPI contracts, in answer order.
    pub asyncapi: Vec<String>,
    /// `Some` only with an OpenAPI contract.
    pub ruleset: Option<String>,
    /// `(live, published)`: the live contract is compared with its frozen
    /// published copy instead of the base branch's file (#1182).
    pub published: Vec<(String, String)>,
    /// The declared command that checks compatibility instead of
    /// `qa-contracts` (#1182); `None` is `qa`.
    pub compat_by: Option<String>,
}

impl Contracts {
    pub fn any(&self) -> bool {
        !self.openapi.is_empty() || !self.asyncapi.is_empty()
    }

    /// The live contracts, OpenAPI first.
    pub fn live(&self) -> impl Iterator<Item = &String> {
        self.openapi.iter().chain(&self.asyncapi)
    }

    /// The declared published copies.
    pub fn published_copies(&self) -> impl Iterator<Item = &String> {
        self.published.iter().map(|(_, p)| p)
    }

    /// Every file of the project these answers name: contracts, published
    /// copies and the ruleset.
    pub fn files(&self) -> impl Iterator<Item = &String> {
        self.live()
            .chain(self.published_copies())
            .chain(self.ruleset.iter())
    }
}

/// The contract answers of the target at `path` (`.` for the root, else an
/// app's directory) of the repository at `repo`: `answer` reads the raw answer
/// of a field, `prefix` is the key's (`apps.<id>.` for an app), `skip` the
/// directories under `path` the walk never enters (`qa_dir`, and at the root
/// every listed app). Paths are relative to `path`; derived notes are pushed
/// on `notes`.
pub fn load(
    repo: &Path,
    path: &str,
    prefix: &str,
    skip: &[String],
    answer: impl Fn(&str) -> Option<String>,
    notes: &mut Vec<String>,
) -> Result<Contracts> {
    let root = &if path == "." {
        repo.to_path_buf()
    } else {
        repo.join(path)
    };
    let key = |field: &str| format!("{prefix}{field}");
    let pairs = published_pairs(
        root,
        &key("contract_published"),
        answer("contract_published"),
    )?;
    // A declared published copy is a baseline, never a contract to derive.
    let found: Vec<(String, Kind)> = documents(root, skip)
        .into_iter()
        .filter(|(p, _)| !pairs.iter().any(|(_, published, _)| published == p))
        .collect();
    let openapi = resolve(
        root,
        &key("openapi"),
        Kind::OpenApi,
        answer("openapi"),
        &found,
        notes,
    )?;
    let asyncapi = resolve(
        root,
        &key("asyncapi"),
        Kind::AsyncApi,
        answer("asyncapi"),
        &found,
        notes,
    )?;
    for (found_path, kind) in &found {
        if *kind == Kind::Swagger && answer("openapi").is_none() {
            let shown = match path {
                "." => found_path.clone(),
                dir => format!("{dir}/{found_path}"),
            };
            notes.push(format!(
                "{shown} is Swagger 2.0; oasdiff compares OpenAPI 3 only"
            ));
        }
    }
    let mut published = Vec::new();
    for (live, copy, text) in pairs {
        let id = key("contract_published");
        let kind = if openapi.contains(&live) {
            Kind::OpenApi
        } else if asyncapi.contains(&live) {
            Kind::AsyncApi
        } else {
            return refuse(format!(
                "qa: {id} {text} names {live}, which openapi and asyncapi do not list"
            ));
        };
        if openapi.contains(&copy) || asyncapi.contains(&copy) {
            return refuse(format!(
                "qa: {id} {text} names {copy} as a live contract too"
            ));
        }
        if first_key(&root.join(&copy)) != Some(kind) {
            let name = match kind {
                Kind::OpenApi => "an OpenAPI",
                _ => "an AsyncAPI",
            };
            return refuse(format!(
                "qa: {id} {text} names {copy}, which is not {name} document"
            ));
        }
        published.push((live, copy));
    }
    let ruleset = match (openapi.is_empty(), answer("contract_ruleset")) {
        (true, _) => None,
        (false, Some(text)) if text == NONE => None,
        (false, Some(text)) => Some(file(root, &key("contract_ruleset"), &text)?),
        (false, None) => {
            let present: Vec<&str> = RULESETS
                .into_iter()
                .filter(|r| root.join(r).is_file())
                .collect();
            match present.as_slice() {
                [one] => {
                    notes.push(format!(
                        "{} {one} (derived: the only Spectral ruleset at the root)",
                        key("contract_ruleset")
                    ));
                    Some((*one).to_owned())
                }
                _ => None,
            }
        }
    };
    let compat_by = answer("contract_compat_by").filter(|by| by != COMPAT_BY_QA);
    Ok(Contracts {
        openapi,
        asyncapi,
        ruleset,
        published,
        compat_by,
    })
}

/// The `contract_published` answer as `(live, published, pair as written)`,
/// each path a contract-like file of the repository; `none` or unanswered is
/// no pair.
fn published_pairs(
    root: &Path,
    id: &str,
    answered: Option<String>,
) -> Result<Vec<(String, String, String)>> {
    let Some(text) = answered.filter(|t| t != NONE) else {
        return Ok(Vec::new());
    };
    let mut pairs = Vec::new();
    for pair in text.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let Some((live, copy)) = pair
            .split_once('=')
            .filter(|(l, c)| !l.trim().is_empty() && !c.trim().is_empty())
        else {
            return refuse(format!("qa: {id} {pair} is not live=published"));
        };
        let live = live
            .trim()
            .strip_prefix("./")
            .unwrap_or(live.trim())
            .to_owned();
        let copy = copy.trim();
        let Ok(copy) = file(root, id, copy) else {
            return refuse(format!(
                "qa: {id} {pair} names {copy}, which is not a contract file in the repository"
            ));
        };
        pairs.push((live, copy, pair.to_owned()));
    }
    Ok(pairs)
}

/// Whether `required` runs the command `name` that `contract_compat_by`
/// declares as the compatibility check of `contracts` (paths relative to the
/// target at `base`): the target's `profile` (read from `profile_file`)
/// declares it, and ci-baseline's answers `ci` generate the workflow, answer
/// `commands` with it and never skip `checks` for a pull request that changes
/// only a contract. `Err` carries the reason.
pub fn compat_command_runs(
    name: &str,
    base: &str,
    contracts: &Contracts,
    ci: &crate::engine::answers::Answers,
    profile: &Value,
    profile_file: &str,
) -> std::result::Result<(), String> {
    if !profile["commands"][name].is_string() {
        return Err(format!("{profile_file} does not declare commands.{name}"));
    }
    if ci.get("workflow").and_then(Value::as_str) == Some("existing") {
        return Err("ci-baseline's workflow is existing".to_owned());
    }
    let answered = ci
        .get("commands")
        .and_then(Value::as_array)
        .is_some_and(|c| c.iter().any(|v| v.as_str() == Some(name)));
    if !answered {
        return Err(format!("ci-baseline does not answer commands with {name}"));
    }
    if ci.get("tiers").and_then(Value::as_bool) != Some(false) {
        let inert: Vec<String> = match ci.get("inert_paths").and_then(Value::as_array) {
            Some(items) => items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect(),
            None => crate::modules::ci_baseline::scope::DEFAULT_INERT_PATHS
                .iter()
                .map(|p| (*p).to_owned())
                .collect(),
        };
        for contract in contracts.live() {
            let path = super::seeds::join(base, contract);
            if inert.iter().any(|p| super::audit::case_match(p, &path)) {
                return Err(format!(
                    "{path} is an inert path of ci-baseline, so a pull request changing only it skips checks"
                ));
            }
        }
    }
    Ok(())
}

/// One contract answer: the answered paths (comma-separated) checked, `none`,
/// or the one document of `kind` the walk found.
fn resolve(
    root: &Path,
    id: &str,
    kind: Kind,
    answered: Option<String>,
    found: &[(String, Kind)],
    notes: &mut Vec<String>,
) -> Result<Vec<String>> {
    if let Some(text) = answered {
        if text == NONE {
            return Ok(Vec::new());
        }
        let mut paths: Vec<String> = Vec::new();
        for item in text.split(',').map(str::trim).filter(|i| !i.is_empty()) {
            let path = file(root, id, item)?;
            if kind == Kind::OpenApi && first_key(&root.join(&path)) == Some(Kind::Swagger) {
                return refuse(format!(
                    "qa: {id} {path} is Swagger 2.0; convert it to OpenAPI 3 or leave {id} unset"
                ));
            }
            if paths.contains(&path) {
                return refuse(format!("qa: {id} lists {path} twice"));
            }
            paths.push(path);
        }
        return Ok(paths);
    }
    let matches: Vec<&str> = found
        .iter()
        .filter(|(_, k)| *k == kind)
        .map(|(p, _)| p.as_str())
        .collect();
    let name = match kind {
        Kind::OpenApi => "OpenAPI",
        _ => "AsyncAPI",
    };
    match matches.as_slice() {
        [] => Ok(Vec::new()),
        [one] => {
            notes.push(format!("{id} {one} (derived: the only {name} document)"));
            Ok(vec![(*one).to_owned()])
        }
        many => {
            notes.push(format!(
                "{id}: several documents ({}); answer {id} with the live contracts, separated by commas",
                many.join(", ")
            ));
            Ok(Vec::new())
        }
    }
}

/// `text` as a repository path of an existing contract-like file, or the refusal.
fn file(root: &Path, id: &str, text: &str) -> Result<String> {
    let path = text.strip_prefix("./").unwrap_or(text);
    let inside = !path.is_empty()
        && !path.starts_with('/')
        && path.split('/').all(|s| !matches!(s, "" | "." | ".."));
    let extension = EXTENSIONS.iter().any(|e| path.ends_with(e));
    if !inside || !extension || !root.join(path).is_file() {
        return refuse(format!(
            "qa: {id} {text} is not a contract file in the repository"
        ));
    }
    Ok(path.to_owned())
}

/// Every contract-like file within [`DEPTH`] levels, with what it is, in path order.
pub fn documents(root: &Path, skip: &[String]) -> Vec<(String, Kind)> {
    fn walk(root: &Path, dir: &str, depth: usize, skip: &[String], out: &mut Vec<(String, Kind)>) {
        let full = if dir.is_empty() {
            root.to_path_buf()
        } else {
            root.join(dir)
        };
        let Ok(entries) = fs::read_dir(full) else {
            return;
        };
        let mut entries: Vec<_> = entries.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let path = if dir.is_empty() {
                name.clone()
            } else {
                format!("{dir}/{name}")
            };
            if kind.is_file() && EXTENSIONS.iter().any(|e| name.ends_with(e)) {
                if let Some(found) = first_key(&entry.path()) {
                    out.push((path, found));
                }
            } else if kind.is_dir()
                && depth > 0
                && !SKIPPED.contains(&name.as_str())
                && !skip.contains(&path)
            {
                walk(root, &path, depth - 1, skip, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, "", DEPTH, skip, &mut out);
    out
}

/// What the first top-level key of the file at `path` says, if anything: YAML
/// line-wise (comments, blank lines and `---` skipped), JSON its first key.
pub fn first_key(path: &Path) -> Option<Kind> {
    let text = fs::read_to_string(path).ok()?;
    let (key, value) = if path.extension().is_some_and(|e| e == "json") {
        json_first(&text)?
    } else {
        let line = text.lines().find(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with('#') && t != "---"
        })?;
        if line.starts_with([' ', '\t']) {
            return None;
        }
        let (key, value) = line.split_once(':')?;
        (
            key.trim().trim_matches(['"', '\'']).to_owned(),
            value.trim().trim_matches(['"', '\'']).to_owned(),
        )
    };
    match key.as_str() {
        "openapi" if value.starts_with("3.") => Some(Kind::OpenApi),
        "asyncapi" if value.starts_with("2.") || value.starts_with("3.") => Some(Kind::AsyncApi),
        "swagger" if value.starts_with("2.") => Some(Kind::Swagger),
        _ => None,
    }
}

/// The first key of a JSON object and its value as text, read up to that key.
fn json_first(text: &str) -> Option<(String, String)> {
    let rest = text.trim_start().strip_prefix('{')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let (key, rest) = rest.split_once('"')?;
    let rest = rest.trim_start().strip_prefix(':')?.trim_start();
    let value = match rest.strip_prefix('"') {
        Some(quoted) => quoted.split_once('"')?.0.to_owned(),
        None => rest.split([',', '}', '\n']).next()?.trim().to_owned(),
    };
    Some((key.to_owned(), value))
}
