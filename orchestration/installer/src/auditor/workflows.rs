//! The YAML walker over GitHub Actions workflows (decision 2026-10-28, point 12:
//! `yaml-rust2`, the crate's only YAML reader besides `alerts.rs`'s line scan).
//! It keeps the keys the static rules read (`name`, `on`, `permissions`, and per job
//! `name`, `uses`, `runs-on`, `timeout-minutes`, `permissions`, `if`, `needs`,
//! `continue-on-error`, `concurrency`, `cache-mode`, `steps[].id`, `steps[].uses`, `steps[].with`,
//! `steps[].env` and `steps[].run`; the workflow's `concurrency`, `cache-mode` and each
//! event's `types`) as plain strings, so `ci-baseline`, `security` and the
//! auditor share one reading. Anything it cannot read is an `Err` with the reason, never a panic.
use super::{Files, WORKFLOWS};
use std::collections::{BTreeMap, BTreeSet};
use yaml_rust2::{Yaml, YamlLoader};

/// `permissions:` as written: a scalar such as `read-all`, or scope → access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Permissions {
    Scalar(String),
    Scopes(BTreeMap<String, String>),
}

/// One step: its `uses:` (trailing comment dropped by YAML), `with:` inputs,
/// `env:` values and `run:` script.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Step {
    /// `id:`, which `steps.<id>.outputs` names.
    pub id: Option<String>,
    pub uses: Option<String>,
    pub with: BTreeMap<String, String>,
    pub env: BTreeMap<String, String>,
    pub run: Option<String>,
    /// `working-directory:` as written, the directory `run:` paths are relative to.
    pub working_directory: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Job {
    pub id: String,
    pub name: Option<String>,
    /// A reusable workflow call (`jobs.<id>.uses`).
    pub uses: Option<String>,
    /// Labels, or the expression as written when `runs-on` is one.
    pub runs_on: Vec<String>,
    pub timeout_minutes: Option<String>,
    pub permissions: Option<Permissions>,
    /// `if:` as written.
    pub condition: Option<String>,
    pub needs: Vec<String>,
    /// True unless absent or literally `false`.
    pub continue_on_error: bool,
    /// `environment:` as a name, or the `name` of its mapping form.
    pub environment: Option<String>,
    /// `concurrency:` as its group, written as a scalar or as `group:`.
    pub concurrency: Option<String>,
    /// `cache-mode:` as written (`read`, `write`, `write-only`, `none`).
    pub cache_mode: Option<String>,
    pub steps: Vec<Step>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Workflow {
    /// `name:`, which GitHub reports as the name of the workflow's runs.
    pub name: Option<String>,
    /// The events of `on:`, in order.
    pub triggers: Vec<String>,
    /// `on.<event>.types`, for the events that list them.
    pub trigger_types: BTreeMap<String, Vec<String>>,
    pub permissions: Option<Permissions>,
    /// The workflow's `concurrency:` group.
    pub concurrency: Option<String>,
    /// The workflow's `cache-mode:`, which every job without its own inherits.
    pub cache_mode: Option<String>,
    /// In file order.
    pub jobs: Vec<Job>,
}

impl Workflow {
    pub fn job(&self, id: &str) -> Option<&Job> {
        self.jobs.iter().find(|j| j.id == id)
    }
    /// Every `uses:` of a job or step not pinned by a 40-hex SHA; local
    /// actions (`./`) and `docker://` images are not actions to pin.
    pub fn unpinned_uses(&self) -> Vec<&str> {
        self.jobs
            .iter()
            .flat_map(|j| {
                j.uses
                    .iter()
                    .chain(j.steps.iter().filter_map(|s| s.uses.as_ref()))
            })
            .map(String::as_str)
            .filter(|u| !u.starts_with("./") && !u.starts_with("docker://") && !pinned(u))
            .collect()
    }
}

pub fn pinned(uses: &str) -> bool {
    uses.rsplit_once('@')
        .is_some_and(|(_, sha)| sha.len() == 40 && sha.chars().all(|c| c.is_ascii_hexdigit()))
}

/// The largest workflow file read, as the contents API caps it (SPEC-auditor.md,
/// "Fleet"): 256 KiB, a margin over the largest workflow the installer renders
/// (`security`'s `full.yml`, 81 KiB), and a hard cap, so a hostile file is a
/// refusal (`unverified`), never an exhausted memory (SPEC-security.md Open
/// question 16, coordinator, 2026-10-29).
pub const MAX_BYTES: usize = 256 * 1024;

/// Every `.yml`/`.yaml` file under [`WORKFLOWS`] with its parse, in path
/// order; an unreadable listing is one entry for the directory itself.
pub fn read_all(files: &dyn Files) -> Parsed {
    let paths = match files.list(WORKFLOWS) {
        Ok(paths) => paths,
        Err(e) => return vec![(WORKFLOWS.to_owned(), Err(e.to_string()))],
    };
    paths
        .into_iter()
        .filter(|p| p.ends_with(".yml") || p.ends_with(".yaml"))
        .filter_map(|path| {
            let parsed = match files.read(&path) {
                Ok(Some(text)) => parse(&text),
                Ok(None) => return None,
                Err(e) => Err(e.to_string()),
            };
            Some((path, parsed))
        })
        .collect()
}

/// Parses one workflow file.
pub fn parse(text: &str) -> Result<Workflow, String> {
    if text.len() > MAX_BYTES {
        return Err(format!(
            "{} bytes, over the {MAX_BYTES}-byte cap of the workflow reader",
            text.len()
        ));
    }
    let root = document(text)?;
    let root = mapping(&root, "the workflow")?;
    let triggers = match get(root, "on") {
        None => Vec::new(),
        Some(Yaml::Hash(events)) => events.keys().filter_map(scalar).collect(),
        Some(other) => strings(other),
    };
    let trigger_types = match get(root, "on") {
        Some(Yaml::Hash(events)) => events
            .iter()
            .filter_map(|(event, body)| match body {
                Yaml::Hash(body) => Some((scalar(event)?, strings(get(body, "types")?))),
                _ => None,
            })
            .collect(),
        _ => BTreeMap::new(),
    };
    let jobs = match get(root, "jobs") {
        None => Vec::new(),
        Some(jobs) => mapping(jobs, "jobs")?
            .iter()
            .map(|(id, body)| job(id, body))
            .collect::<Result<_, _>>()?,
    };
    Ok(Workflow {
        name: get(root, "name").and_then(scalar),
        triggers,
        trigger_types,
        permissions: get(root, "permissions").map(permissions),
        concurrency: get(root, "concurrency").and_then(concurrency),
        cache_mode: get(root, "cache-mode").and_then(scalar),
        jobs,
    })
}

/// The `package-ecosystem` of every entry of `updates:` in a Dependabot file.
pub fn dependabot_ecosystems(text: &str) -> Result<Vec<String>, String> {
    let root = document(text)?;
    let root = mapping(&root, "the Dependabot configuration")?;
    let Some(updates) = get(root, "updates") else {
        return Ok(Vec::new());
    };
    let Yaml::Array(updates) = updates else {
        return Err("updates is not a list".to_owned());
    };
    Ok(updates
        .iter()
        .filter_map(|u| match u {
            Yaml::Hash(h) => get(h, "package-ecosystem").and_then(scalar),
            _ => None,
        })
        .collect())
}

fn document(text: &str) -> Result<Yaml, String> {
    let mut docs = YamlLoader::load_from_str(text).map_err(|e| e.to_string())?;
    match docs.len() {
        0 => Err("empty document".to_owned()),
        1 => Ok(docs.remove(0)),
        n => Err(format!("{n} documents in one file")),
    }
}

fn mapping<'a>(value: &'a Yaml, what: &str) -> Result<&'a yaml_rust2::yaml::Hash, String> {
    match value {
        Yaml::Hash(h) => Ok(h),
        _ => Err(format!("{what} is not a mapping")),
    }
}

fn get<'a>(map: &'a yaml_rust2::yaml::Hash, key: &str) -> Option<&'a Yaml> {
    map.get(&Yaml::String(key.to_owned()))
}

/// A scalar as text; `None` for collections, null and aliases.
fn scalar(value: &Yaml) -> Option<String> {
    match value {
        Yaml::String(s) | Yaml::Real(s) => Some(s.clone()),
        Yaml::Integer(i) => Some(i.to_string()),
        Yaml::Boolean(b) => Some(b.to_string()),
        _ => None,
    }
}

/// A scalar as a one-item list, or the scalars of a list.
fn strings(value: &Yaml) -> Vec<String> {
    match value {
        Yaml::Array(items) => items.iter().filter_map(scalar).collect(),
        other => scalar(other).into_iter().collect(),
    }
}

fn permissions(value: &Yaml) -> Permissions {
    match value {
        Yaml::Hash(scopes) => Permissions::Scopes(
            scopes
                .iter()
                .filter_map(|(k, v)| Some((scalar(k)?, scalar(v).unwrap_or_default())))
                .collect(),
        ),
        other => Permissions::Scalar(scalar(other).unwrap_or_default()),
    }
}

fn job(id: &Yaml, body: &Yaml) -> Result<Job, String> {
    let id = scalar(id).ok_or("a job id is not a scalar")?;
    let map = mapping(body, &format!("job {id}"))?;
    let text = |key: &str| get(map, key).and_then(scalar);
    let runs_on = match get(map, "runs-on") {
        // `runs-on: {group, labels}`: the labels are what is matched.
        Some(Yaml::Hash(h)) => get(h, "labels").map(strings).unwrap_or_default(),
        Some(other) => strings(other),
        None => Vec::new(),
    };
    let steps = match get(map, "steps") {
        Some(Yaml::Array(steps)) => steps.iter().map(step).collect(),
        _ => Vec::new(),
    };
    Ok(Job {
        name: text("name"),
        uses: text("uses"),
        runs_on,
        timeout_minutes: text("timeout-minutes"),
        permissions: get(map, "permissions").map(permissions),
        condition: text("if"),
        needs: get(map, "needs").map(strings).unwrap_or_default(),
        continue_on_error: get(map, "continue-on-error")
            .is_some_and(|v| scalar(v).as_deref() != Some("false")),
        environment: match get(map, "environment") {
            Some(Yaml::Hash(h)) => get(h, "name").and_then(scalar),
            Some(other) => scalar(other),
            None => None,
        },
        concurrency: get(map, "concurrency").and_then(concurrency),
        cache_mode: text("cache-mode"),
        steps,
        id,
    })
}

/// `concurrency:` as its group: the scalar form, or `group:` of the mapping form.
fn concurrency(value: &Yaml) -> Option<String> {
    match value {
        Yaml::Hash(h) => get(h, "group").and_then(scalar),
        other => scalar(other),
    }
}

fn step(value: &Yaml) -> Step {
    let Yaml::Hash(map) = value else {
        return Step::default();
    };
    let pairs = |key: &str| match get(map, key) {
        Some(Yaml::Hash(entries)) => entries
            .iter()
            .filter_map(|(k, v)| Some((scalar(k)?, scalar(v)?)))
            .collect(),
        _ => BTreeMap::new(),
    };
    Step {
        id: get(map, "id").and_then(scalar),
        uses: get(map, "uses").and_then(scalar),
        with: pairs("with"),
        env: pairs("env"),
        run: get(map, "run").and_then(scalar),
        working_directory: get(map, "working-directory").and_then(scalar),
    }
}

// --- the doctor channel of the static rules -----------------------------------
//
// Shared by `ci_baseline::audit` and `security::audit` (SPEC-ci-baseline.md and
// SPEC-security.md, "How `doctor` reports the static rules"): a failed rule is
// `WARNING: <rule>: <text>`, an unreadable file `WARNING: <rule>: unverified:
// <file>: <reason>`, a passed rule nothing.

pub fn warn(rule: &str, text: impl std::fmt::Display) -> String {
    format!("WARNING: {rule}: {text}")
}

pub fn unverified(rule: &str, path: &str, reason: &str) -> String {
    warn(rule, format!("unverified: {path}: {}", reason.trim()))
}

/// Every workflow file with its parse, or the reason it could not be read.
pub type Parsed = Vec<(String, Result<Workflow, String>)>;

/// A rule one workflow satisfies for the repository: failed only when no file
/// satisfies it and every file was read; unverified per unread file otherwise.
pub fn repository_rule(
    rule: &str,
    text: &str,
    read: &Parsed,
    satisfies: impl Fn(&Workflow) -> bool,
    out: &mut Vec<String>,
) {
    if read.iter().any(|(_, wf)| wf.as_ref().is_ok_and(&satisfies)) {
        return;
    }
    let broken: Vec<String> = read
        .iter()
        .filter_map(|(path, wf)| wf.as_ref().err().map(|e| unverified(rule, path, e)))
        .collect();
    if broken.is_empty() {
        out.push(warn(rule, text));
    } else {
        out.extend(broken);
    }
}

/// A rule every workflow must satisfy: its finding texts, in file order,
/// without repeats; an unread file is unverified.
pub fn file_rule(
    rule: &str,
    read: &Parsed,
    check: impl Fn(&str, &Workflow) -> Vec<String>,
    out: &mut Vec<String>,
) {
    for (path, wf) in read {
        match wf {
            Ok(wf) => {
                let mut seen = BTreeSet::new();
                out.extend(
                    check(path, wf)
                        .into_iter()
                        .filter(|t| seen.insert(t.clone()))
                        .map(|t| warn(rule, t)),
                );
            }
            Err(e) => out.push(unverified(rule, path, e)),
        }
    }
}
