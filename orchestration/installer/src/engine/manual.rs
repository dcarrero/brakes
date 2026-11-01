//! Manual steps (SPEC-engine.md): work a module cannot do for the owner, declared
//! with a read-only probe that tells `doctor` whether it was done. Probes read files
//! inside the repository root; a `remote` probe names an entry of host-adapter's
//! registry (`host::probes`, #683), checked at load and answered by the runner
//! `doctor --remote` passes, `unavailable` otherwise. No probe runs a command, and
//! none but a remote one under `doctor --remote` touches the network.
use crate::{Result, refuse};
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

/// Who performs the step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Owner {
    /// The repository owner, by hand or with the instructions given.
    Owner,
    /// The platform (CI, host) once the owner enabled it.
    Platform,
    /// The project, in a file it owns that the installer may not write
    /// (`.claude/settings.json`, #442).
    Project,
}

impl std::fmt::Display for Owner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Owner::Owner => "owner",
            Owner::Platform => "platform",
            Owner::Project => "project",
        })
    }
}

/// How `doctor` finds out whether a step was done.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Probe {
    /// A file exists at the repository-relative path.
    FileExists { path: String },
    /// The RFC 6901 pointer resolves inside the JSON file and its value equals `equals`.
    JsonPointer {
        path: String,
        pointer: String,
        equals: Value,
    },
    /// The pointer resolves to an array holding every member of `contains_all`;
    /// other members do not matter (a union, not an equality).
    JsonPointerContainsAll {
        path: String,
        pointer: String,
        contains_all: Vec<Value>,
    },
    /// Some string at or beneath the pointer `under` contains `contains`.
    JsonPointerContains {
        path: String,
        under: String,
        contains: String,
    },
    /// A probe of host-adapter's registry; `unavailable` without `doctor --remote`.
    Remote {
        id: String,
        args: BTreeMap<String, Value>,
    },
}

/// A step the owner or the platform performs; the engine never does it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManualStep {
    pub id: String,
    pub title: String,
    pub owner: Owner,
    /// What to run or do; shown to the owner, never executed.
    pub instructions: String,
    pub probe: Probe,
    /// The id of a step of the same module that must be `verified` before this one
    /// can be done; until then this step is `blocked`.
    pub after: Option<String>,
}

/// What a probe answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeResult {
    /// The probe answered no; the text says what it looked for.
    Pending(String),
    /// The probe answered yes, with its evidence.
    Verified(String),
    /// The probe could not answer because something is wrong, with the error.
    Failed(String),
    /// The probe has no runner in this invocation, with the reason.
    Unavailable(String),
    /// The host says the step does not exist for this repository, with its
    /// answer; only a `remote` probe returns it (#846).
    NotApplicable(String),
}

/// A step's state as `doctor` reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum StepState {
    Pending,
    Verified,
    Failed,
    Unavailable,
    /// The step named in `after` is not verified; the probe did not run.
    Blocked,
    /// The step does not exist for this repository; never changes readiness (#846).
    #[serde(rename = "not-applicable")]
    NotApplicable,
}

impl std::fmt::Display for StepState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            StepState::Pending => "pending",
            StepState::Verified => "verified",
            StepState::Failed => "failed",
            StepState::Unavailable => "unavailable",
            StepState::Blocked => "blocked",
            StepState::NotApplicable => "not-applicable",
        })
    }
}

/// One evaluated step: what `plan` and `doctor` print and `--json` emits.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StepReport {
    pub id: String,
    pub module: String,
    pub title: String,
    pub owner: Owner,
    pub state: StepState,
    /// What the probe observed, for every state but `failed`.
    pub evidence: Option<String>,
    /// Why the probe could not answer, for `failed` only.
    pub error: Option<String>,
}

impl StepReport {
    /// What the probe observed or why it failed: the text of a doctor line.
    pub fn detail(&self) -> &str {
        self.evidence
            .as_deref()
            .or(self.error.as_deref())
            .unwrap_or("")
    }
    /// The plan line: `STEP [state:module] id — title`.
    pub fn plan_line(&self) -> String {
        format!(
            "STEP [{}:{}] {} — {}",
            self.state, self.module, self.id, self.title
        )
    }
    /// The doctor line: `STEP [state:module] id — evidence` (or the error).
    pub fn doctor_line(&self) -> String {
        format!(
            "STEP [{}:{}] {} — {}",
            self.state,
            self.module,
            self.id,
            self.detail()
        )
    }
}

/// Runs `remote` probes: `host::probes::HostRunner` under `doctor --remote`.
pub trait RemoteRunner {
    fn run(&self, id: &str, args: &BTreeMap<String, Value>) -> ProbeResult;
}

/// The runner of an invocation without `--remote`: every remote probe is unavailable.
pub struct NoRunner;
impl RemoteRunner for NoRunner {
    fn run(&self, id: &str, _args: &BTreeMap<String, Value>) -> ProbeResult {
        ProbeResult::Unavailable(format!(
            "remote probe `{id}` runs only with doctor --remote"
        ))
    }
}

/// Validates the steps one module declared: unique ids, probe paths inside the
/// repository, well-formed pointers, remote probes the host-adapter registry can
/// run with their arguments, and `after` naming a step of the same module
/// without cycles. Refuses at load so a module cannot ship a step `doctor` cannot run.
pub fn check(module: &str, steps: &[ManualStep]) -> Result<()> {
    let mut ids = BTreeSet::new();
    for step in steps {
        if !ids.insert(step.id.as_str()) {
            return refuse(format!(
                "Module {module}: step `{}` is declared twice",
                step.id
            ));
        }
        match &step.probe {
            Probe::FileExists { path } => check_path(module, &step.id, path)?,
            Probe::JsonPointer { path, pointer, .. }
            | Probe::JsonPointerContainsAll { path, pointer, .. }
            | Probe::JsonPointerContains {
                path,
                under: pointer,
                ..
            } => {
                check_path(module, &step.id, path)?;
                if pointer_tokens(pointer).is_none() {
                    return refuse(format!(
                        "Module {module}: step `{}` has an invalid JSON pointer: {pointer}",
                        step.id
                    ));
                }
            }
            Probe::Remote { id, args } => {
                if let Err(reason) = crate::host::probes::check(id, args) {
                    return refuse(format!("Module {module}: step `{}`: {reason}", step.id));
                }
            }
        }
    }
    for step in steps {
        let Some(after) = &step.after else {
            continue;
        };
        if !ids.contains(after.as_str()) {
            return refuse(format!(
                "Module {module}: step `{}` waits for unknown step `{after}`",
                step.id
            ));
        }
        let mut seen = BTreeSet::from([step.id.as_str()]);
        let mut next = after.as_str();
        while seen.insert(next) {
            match steps
                .iter()
                .find(|s| s.id == next)
                .and_then(|s| s.after.as_deref())
            {
                Some(further) => next = further,
                None => break,
            }
        }
        if next == step.id {
            return refuse(format!(
                "Module {module}: step `{}` waits for itself through `after`",
                step.id
            ));
        }
    }
    Ok(())
}

fn check_path(module: &str, step: &str, path: &str) -> Result<()> {
    let relative = Path::new(path);
    if relative.is_absolute() || relative.components().any(|c| c == Component::ParentDir) {
        return refuse(format!(
            "Module {module}: step `{step}` probes a path outside the repository: {path}"
        ));
    }
    Ok(())
}

/// The reference tokens of an RFC 6901 pointer, unescaped; `None` when malformed.
fn pointer_tokens(pointer: &str) -> Option<Vec<String>> {
    if pointer.is_empty() {
        return Some(Vec::new());
    }
    let rest = pointer.strip_prefix('/')?;
    rest.split('/')
        .map(|token| {
            let mut out = String::with_capacity(token.len());
            let mut chars = token.chars();
            while let Some(c) = chars.next() {
                if c != '~' {
                    out.push(c);
                    continue;
                }
                match chars.next() {
                    Some('0') => out.push('~'),
                    Some('1') => out.push('/'),
                    _ => return None,
                }
            }
            Some(out)
        })
        .collect()
}

/// Resolves a checked pointer; `None` when a token does not exist.
fn resolve<'a>(document: &'a Value, tokens: &[String]) -> Option<&'a Value> {
    tokens
        .iter()
        .try_fold(document, |current, token| match current {
            Value::Object(map) => map.get(token),
            Value::Array(items) => {
                let index: usize = if token == "0" {
                    0
                } else if token.starts_with('0') || token.is_empty() {
                    return None;
                } else {
                    token.parse().ok()?
                };
                items.get(index)
            }
            _ => None,
        })
}

/// Runs one probe against the repository. Reads only; errors become `Failed`.
pub fn run(root: &Path, probe: &Probe, runner: &dyn RemoteRunner) -> ProbeResult {
    match probe {
        Probe::FileExists { path } => match crate::destination(root, path) {
            Err(error) => ProbeResult::Failed(error.to_string()),
            Ok(location) if location.is_file() => ProbeResult::Verified(format!("{path} exists")),
            Ok(_) => ProbeResult::Pending(format!("{path} is absent")),
        },
        Probe::JsonPointer {
            path,
            pointer,
            equals,
        } => at_pointer(root, path, pointer, |found| {
            if found == equals {
                ProbeResult::Verified(format!("{path}: {pointer} is {found}"))
            } else {
                ProbeResult::Pending(format!("{path}: {pointer} is {found}, expected {equals}"))
            }
        }),
        Probe::JsonPointerContainsAll {
            path,
            pointer,
            contains_all,
        } => at_pointer(root, path, pointer, |found| {
            let Some(items) = found.as_array() else {
                return ProbeResult::Pending(format!(
                    "{path}: {pointer} is {found}, expected an array"
                ));
            };
            let list = |values: Vec<&Value>| {
                values
                    .iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let missing: Vec<&Value> = contains_all
                .iter()
                .filter(|member| !items.contains(member))
                .collect();
            if missing.is_empty() {
                let all = list(contains_all.iter().collect());
                ProbeResult::Verified(format!("{path}: {pointer} contains {all}"))
            } else {
                ProbeResult::Pending(format!("{path}: {pointer} lacks {}", list(missing)))
            }
        }),
        Probe::JsonPointerContains {
            path,
            under,
            contains,
        } => at_pointer(root, path, under, |found| {
            if names(found, contains) {
                ProbeResult::Verified(format!("{path}: {under} names {contains}"))
            } else {
                ProbeResult::Pending(format!("{path}: {under} does not name {contains}"))
            }
        }),
        Probe::Remote { id, args } => runner.run(id, args),
    }
}

/// Reads the JSON file at `path` and hands `judge` the value at the checked
/// `pointer`; an absent file or pointer is pending, an unreadable one failed.
fn at_pointer(
    root: &Path,
    path: &str,
    pointer: &str,
    judge: impl FnOnce(&Value) -> ProbeResult,
) -> ProbeResult {
    let text = match crate::read(root, path) {
        Err(error) => return ProbeResult::Failed(error.to_string()),
        Ok(None) => return ProbeResult::Pending(format!("{path} is absent")),
        Ok(Some(text)) => text,
    };
    let document: Value = match serde_json::from_str(&text) {
        Ok(document) => document,
        Err(error) => return ProbeResult::Failed(format!("{path}: {error}")),
    };
    let tokens = pointer_tokens(pointer).unwrap_or_default();
    match resolve(&document, &tokens) {
        None => ProbeResult::Pending(format!("{path}: {pointer} is absent")),
        Some(found) => judge(found),
    }
}

/// Whether some string at or beneath `value` contains `text`.
fn names(value: &Value, text: &str) -> bool {
    match value {
        Value::String(s) => s.contains(text),
        Value::Array(items) => items.iter().any(|item| names(item, text)),
        Value::Object(map) => map.values().any(|item| names(item, text)),
        _ => false,
    }
}

/// Evaluates the checked steps of one module in declaration order, honouring
/// `after`: a step whose predecessor is not verified is `blocked` and its probe
/// does not run. The result is sorted by step id.
pub fn evaluate(
    root: &Path,
    module: &str,
    steps: &[ManualStep],
    runner: &dyn RemoteRunner,
) -> Vec<StepReport> {
    let mut states: BTreeMap<&str, (StepState, Option<String>, Option<String>)> = BTreeMap::new();
    for step in steps {
        settle(root, steps, step, runner, &mut states);
    }
    let mut reports = steps
        .iter()
        .map(|step| {
            let (state, evidence, error) = states.remove(step.id.as_str()).unwrap_or((
                StepState::Failed,
                None,
                Some("not evaluated".to_owned()),
            ));
            StepReport {
                id: step.id.clone(),
                module: module.to_owned(),
                title: step.title.clone(),
                owner: step.owner,
                state,
                evidence,
                error,
            }
        })
        .collect::<Vec<_>>();
    reports.sort_by(|a, b| a.id.cmp(&b.id));
    reports
}

fn settle<'a>(
    root: &Path,
    steps: &'a [ManualStep],
    step: &'a ManualStep,
    runner: &dyn RemoteRunner,
    states: &mut BTreeMap<&'a str, (StepState, Option<String>, Option<String>)>,
) -> StepState {
    if let Some((state, _, _)) = states.get(step.id.as_str()) {
        return *state;
    }
    if let Some(before) = step
        .after
        .as_deref()
        .and_then(|after| steps.iter().find(|s| s.id == after))
    {
        let state = settle(root, steps, before, runner, states);
        if state != StepState::Verified {
            states.insert(
                &step.id,
                (
                    StepState::Blocked,
                    Some(format!("waits for step `{}` ({state})", before.id)),
                    None,
                ),
            );
            return StepState::Blocked;
        }
    }
    let settled = match run(root, &step.probe, runner) {
        ProbeResult::Pending(text) => (StepState::Pending, Some(text), None),
        ProbeResult::Verified(text) => (StepState::Verified, Some(text), None),
        ProbeResult::Failed(text) => (StepState::Failed, None, Some(text)),
        ProbeResult::Unavailable(text) => (StepState::Unavailable, Some(text), None),
        ProbeResult::NotApplicable(text) => (StepState::NotApplicable, Some(text), None),
    };
    let state = settled.0;
    states.insert(&step.id, settled);
    state
}
