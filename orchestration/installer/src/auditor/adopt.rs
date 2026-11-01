//! `adopt <repo> [--apply]` (SPEC-auditor.md, "adopt — contract"; #738): the
//! plan that would bring a repository the installer never touched under the
//! modules its audit names. The plan is the engine's own `install --module …`
//! plan, re-labelled with additive verbs only:
//!
//! - `ADD [managed-block:setup-core] <path>`: the block appended to an existing
//!   entrypoint, its content untouched;
//! - `SEED <path> [<class>:<module>]`: a file that does not exist;
//! - `STEP [<state>:<module>] …`: a manual step with its probe;
//! - `PROPOSE <path>: <what exists> → <what the module would render>`: every
//!   collision, printed and in `--json`, never written.
//!
//! The modules are those the remediation of a required rule names (`FAIL`, or
//! the gap of `NEXT`), with what they require; one whose plan the engine
//! refuses becomes a proposal and stays out. Nothing is written in this slice:
//! `--apply` is refused, after the write scope for a repository outside it.
use super::{
    Today, audit_checkout, checkout_identity, offline_host,
    rules::{Remediation, Status},
};
use crate::{
    LOCK, Result, Source, diagnose_at,
    engine::{Ownership, Planned, StepState},
    host::CallBudget,
    modules, personal_scope, plan_install, read, read_scope, refuse,
};
use serde_json::{Value, json};
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    process::ExitCode,
};

pub const USAGE: &str = "Usage: brakes adopt <project> [--apply] [--json]";
/// The refusal of `--apply` until the apply path lands.
pub const APPLY_LATER: &str = "adopt --apply lands in a later slice";

/// One line of an adoption plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    Add {
        path: String,
        module: String,
    },
    Seed {
        path: String,
        tag: Option<String>,
    },
    Step(String),
    Propose {
        path: String,
        exists: String,
        would: String,
    },
}
impl std::fmt::Display for Line {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Line::Add { path, module } => write!(f, "ADD [managed-block:{module}] {path}"),
            Line::Seed { path, tag: None } => write!(f, "SEED {path}"),
            Line::Seed {
                path,
                tag: Some(tag),
            } => write!(f, "SEED {path} [{tag}]"),
            Line::Step(line) => f.write_str(line),
            Line::Propose {
                path,
                exists,
                would,
            } => write!(f, "PROPOSE {path}: {exists} → {would}"),
        }
    }
}

/// The adoption plan of one repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adoption {
    pub repo: String,
    /// The modules planned, in registry order.
    pub modules: Vec<String>,
    /// Modules a remediation names that this build does not compile.
    pub waiting: Vec<String>,
    pub lines: Vec<Line>,
}
impl Adoption {
    /// True when the plan adds or seeds something.
    pub fn changes(&self) -> bool {
        self.lines
            .iter()
            .any(|l| matches!(l, Line::Add { .. } | Line::Seed { .. }))
    }
    /// The closing line, after the plan lines.
    pub fn closing(&self) -> String {
        if self.changes() {
            format!("Plan only; no writes. {APPLY_LATER}.")
        } else {
            "No changes.".to_owned()
        }
    }
    pub fn json(&self) -> Value {
        let verb = |l: &Line| match l {
            Line::Add { .. } => "ADD",
            Line::Seed { .. } => "SEED",
            Line::Step(_) => "STEP",
            Line::Propose { .. } => "PROPOSE",
        };
        let proposals: Vec<Value> = self
            .lines
            .iter()
            .filter_map(|l| match l {
                Line::Propose {
                    path,
                    exists,
                    would,
                } => Some(json!({"path": path, "exists": exists, "would": would})),
                _ => None,
            })
            .collect();
        json!({
            "schema": 1,
            "repo": self.repo,
            "modules": self.modules,
            "waiting": self.waiting,
            "lines": self.lines.iter().map(|l| json!({"verb": verb(l), "line": l.to_string()})).collect::<Vec<_>>(),
            "proposals": proposals,
            "changes": self.changes(),
            "apply": APPLY_LATER,
        })
    }
}

/// The compiled modules the required rules' remediations name, with what they
/// require, in registry order; and the named ids no compiled module answers to.
fn named_modules(audit: &super::Audit) -> (Vec<&'static str>, Vec<String>) {
    let gap = audit.next.as_ref().map_or(&[][..], |n| n.gap.as_slice());
    let mut named: Vec<&str> = audit
        .rules
        .iter()
        .filter(|e| e.required && (e.outcome.status == Status::Failed || gap.contains(&e.rule.id)))
        .flat_map(|e| e.remediations())
        .filter_map(|r| match r {
            Remediation::Module { id } => Some(id),
            _ => None,
        })
        .collect();
    named.sort_unstable();
    named.dedup();
    let waiting = named
        .iter()
        .filter(|id| modules::find(id).is_none())
        .map(|id| (*id).to_owned())
        .collect();
    let compiled = named
        .into_iter()
        .filter(|id| modules::find(id).is_some())
        .collect();
    (compiled, waiting)
}

/// `id` and every module it requires, transitively.
fn with_requirements(id: &'static str, out: &mut Vec<&'static str>) {
    if out.contains(&id) {
        return;
    }
    out.push(id);
    if let Some(module) = modules::find(id) {
        for required in module.requires() {
            with_requirements(required, out);
        }
    }
}

/// The path a module refusal names, when it names one the repository has.
fn refused_path(root: &Path, error: &str) -> Option<String> {
    let path = error
        .strip_prefix("Unowned managed destination: ")
        .map(str::to_owned)
        .or_else(|| {
            let (_, rest) = error.split_once(": ")?;
            Some(rest.split_once(' ')?.0.to_owned())
        })?;
    root.join(&path).is_file().then_some(path)
}

/// The adoption plan of the checkout at `root` at `now`: the offline audit names
/// the modules, the engine plans them (`install --module …`), and the plan is
/// re-labelled. Nothing is written.
pub fn plan(root: &Path, now: chrono::NaiveDate) -> Result<Adoption> {
    let diagnosis = diagnose_at(root, now)?;
    let today = Today {
        findings: &diagnosis.findings,
        steps: &diagnosis.steps,
        remote: false,
    };
    let identity = checkout_identity(root);
    let budget = CallBudget::new(super::CALL_BUDGET);
    let audited = audit_checkout(
        root,
        &offline_host(),
        &budget,
        &identity,
        now,
        false,
        &today,
    )?;
    let (named, waiting) = named_modules(&audited.audit);
    let source = Source::embedded();
    let mut accepted: Vec<&'static str> = Vec::new();
    let mut proposals = Vec::new();
    let mut planned = plan_install(root, &source, &[], None)?;
    // Registry order; a module whose plan the engine refuses stays out.
    for module in modules::all() {
        let id = module.id();
        if !named.contains(&id) || accepted.contains(&id) {
            continue;
        }
        let mut tried = accepted.clone();
        with_requirements(id, &mut tried);
        match plan_install(root, &source, &tried, None) {
            Ok(plan) => {
                planned = plan;
                accepted = tried;
            }
            Err(error) => {
                let error = error.to_string();
                proposals.push(match refused_path(root, &error) {
                    Some(path) => Line::Propose {
                        path,
                        exists: "existing file".to_owned(),
                        would: format!("module {id} not planned: {error}"),
                    },
                    None => Line::Propose {
                        path: format!("module {id}"),
                        exists: "not planned".to_owned(),
                        would: error,
                    },
                });
            }
        }
    }
    let mut lines = relabel(root, &planned)?;
    lines.extend(proposals);
    // Manual steps close the plan, as in `install`.
    lines.sort_by_key(|l| matches!(l, Line::Step(_)));
    let modules: Vec<String> = modules::all()
        .iter()
        .map(|m| m.id())
        .filter(|id| *id == crate::engine::lock::SETUP_CORE || accepted.contains(id))
        .map(str::to_owned)
        .collect();
    Ok(Adoption {
        repo: identity.to_string(),
        modules,
        waiting,
        lines,
    })
}

/// The engine's plan as adopt verbs: a new file is `SEED`, a block appended to
/// an existing entrypoint of `setup-core` is `ADD`, anything else that would
/// change an existing file, and every skipped seed whose file differs from what
/// the module renders, is `PROPOSE`. The lock is written with the plan, never
/// listed; manual steps already verified or not applicable are left out.
pub fn relabel(root: &Path, planned: &Planned) -> Result<Vec<Line>> {
    let mut lines = Vec::new();
    let lines_of = |text: &str| match text.lines().count() {
        1 => "1 line".to_owned(),
        n => format!("{n} lines"),
    };
    for (path, content) in &planned.changes {
        if path == LOCK {
            continue;
        }
        let tag = planned
            .tags
            .get(path)
            .map(|(class, module)| (*class, module.as_str()))
            .or_else(|| {
                planned
                    .answers
                    .get(path)
                    .map(|m| (Ownership::Seed, m.as_str()))
            });
        let current = read(root, path)?;
        lines.push(match (current, content, tag) {
            (None, Some(_), tag) => Line::Seed {
                path: path.clone(),
                tag: tag.map(|(class, module)| format!("{class}:{module}")),
            },
            (Some(_), Some(_), Some((Ownership::ManagedBlock, module)))
                if module == crate::engine::lock::SETUP_CORE =>
            {
                Line::Add {
                    path: path.clone(),
                    module: module.to_owned(),
                }
            }
            (Some(current), Some(after), tag) => Line::Propose {
                path: path.clone(),
                exists: format!("existing file ({})", lines_of(&current)),
                would: match tag {
                    Some((Ownership::ManagedBlock, module)) => {
                        format!("managed block of {module} appended")
                    }
                    Some((class, module)) => format!("{class} of {module} ({})", lines_of(after)),
                    None => format!("rendered file ({})", lines_of(after)),
                },
            },
            (current, None, _) => Line::Propose {
                path: path.clone(),
                exists: if current.is_some() {
                    "existing file".to_owned()
                } else {
                    "absent".to_owned()
                },
                would: "deleted by the module; adopt never deletes".to_owned(),
            },
        });
    }
    for (path, seed) in &planned.skipped_seeds {
        let current = read(root, path)?.unwrap_or_default();
        if &current == seed {
            continue;
        }
        let module = planned.tags.get(path).map_or("", |(_, m)| m.as_str());
        lines.push(Line::Propose {
            path: path.clone(),
            exists: format!("existing file ({})", lines_of(&current)),
            would: format!("seed of {module} ({}), not written", lines_of(seed)),
        });
    }
    lines.extend(
        planned
            .steps
            .iter()
            .filter(|s| !matches!(s.state, StepState::Verified | StepState::NotApplicable))
            .map(|s| Line::Step(s.plan_line())),
    );
    Ok(lines)
}

/// `adopt <project> [--apply] [--json]`: exit 0 with the plan, 2 when refused.
pub fn cli(args: &[OsString]) -> ExitCode {
    match command(args, crate::today()) {
        Ok(out) => {
            print!("{out}");
            ExitCode::from(0)
        }
        Err(error) => {
            eprintln!("REFUSED: {error}");
            ExitCode::from(2)
        }
    }
}

/// The output of `adopt` with `args` (after the subcommand) at `now`.
pub fn command(args: &[OsString], now: chrono::NaiveDate) -> Result<String> {
    let mut project = None;
    let mut apply = false;
    let mut json = false;
    for arg in args {
        match arg.to_str() {
            Some("--apply") => apply = true,
            Some("--json") => json = true,
            Some(s) if s.starts_with('-') => return refuse(USAGE),
            _ if project.is_none() => project = Some(PathBuf::from(arg)),
            _ => return refuse(USAGE),
        }
    }
    let project = project.ok_or(USAGE)?;
    if apply {
        // Outside the write scope the refusal is today's; inside it, the slice's.
        personal_scope(&project, false)?;
        return refuse(APPLY_LATER);
    }
    let root = read_scope(&project)?;
    let adoption = plan(&root, now)?;
    if json {
        return Ok(serde_json::to_string_pretty(&adoption.json())? + "\n");
    }
    let mut out = String::new();
    for line in &adoption.lines {
        out.push_str(&format!("{line}\n"));
    }
    out.push_str(&adoption.closing());
    out.push('\n');
    Ok(out)
}
