//! `apply <repo>` without `--remote` (decision 2026-10-28, #848 point 2; #901,
//! slice 1 of #900; SPEC-engine.md, Remote items and `apply`): the read-only
//! diff of the `remote` items the lock records for the installed modules. Each
//! item `github:<id>` is judged by the step of the same id of its module,
//! evaluated with `reader` (host-adapter's probes in the CLI), so `after` gives
//! `blocked` exactly as `doctor` does. A pending item is named `create`,
//! `update` or `remove` from the desired state its module declares (#902).
//! Nothing is written; the write path is #903.
use crate::{
    LOCK, Result, Source, engine,
    host::{
        Host, WriteToken,
        desired::{self, Change, Desired, RemoteWrite, change},
        probes::HostRunner,
        types::WriteReport,
    },
    known_path, modules, profile_for, read, refuse,
};
use std::collections::BTreeMap;
use std::path::Path;

/// The reads of `apply`: the probes of the steps, and the classification of a
/// pending item from its desired state (`host::desired::change`).
pub trait RemoteReader: engine::RemoteRunner {
    /// The verb of a pending item, or the host's message when the read failed.
    fn change(&self, desired: &Desired) -> std::result::Result<Change, String>;
}

/// The writes of `apply --remote`: one `Host` write per desired state.
pub trait RemoteWriter {
    /// What the host did, or its message when the write failed.
    fn write(&self, write: &RemoteWrite) -> std::result::Result<WriteReport, String>;
}

/// Writes through `host` with the token `authorize::write` minted, so no
/// write reaches a repository the gate refused.
pub struct HostWriter<'a> {
    host: &'a dyn Host,
    token: WriteToken,
}

impl<'a> HostWriter<'a> {
    pub fn new(host: &'a dyn Host, token: WriteToken) -> Self {
        Self { host, token }
    }
}

impl RemoteWriter for HostWriter<'_> {
    fn write(&self, write: &RemoteWrite) -> std::result::Result<WriteReport, String> {
        desired::write(self.host, &self.token, write).map_err(|e| crate::remote::plain(&e.message))
    }
}

impl RemoteReader for HostRunner<'_> {
    fn change(&self, desired: &Desired) -> std::result::Result<Change, String> {
        change(self.host(), self.repo(), desired).map_err(|e| crate::remote::plain(&e.message))
    }
}

/// What `apply --remote` would do with an item, from its step's state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoteVerb {
    /// The probe answered no and the item does not exist: it will be created.
    Create,
    /// The probe answered no and the item exists: it will be updated.
    Update,
    /// The probe answered no and the item goes: it will be removed.
    Remove,
    /// The probe verified it: nothing to write.
    Unchanged,
    /// Its `after` step is not verified: not written in this run.
    Blocked,
    /// The feature or the runner is unavailable: never attempted.
    Unavailable,
    /// The host says the item does not exist for this repository: nothing to write (#846).
    NotApplicable,
    /// The read failed.
    Failed,
}

impl std::fmt::Display for RemoteVerb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            RemoteVerb::Create => "create",
            RemoteVerb::Update => "update",
            RemoteVerb::Remove => "remove",
            RemoteVerb::Unchanged => "unchanged",
            RemoteVerb::Blocked => "blocked",
            RemoteVerb::Unavailable => "unavailable",
            RemoteVerb::NotApplicable => "not-applicable",
            RemoteVerb::Failed => "failed",
        })
    }
}

/// One line of the diff.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteLine {
    /// The lock path, `github:<id>`.
    pub item: String,
    pub module: String,
    pub verb: RemoteVerb,
    /// The probe's evidence or error.
    pub detail: String,
}

impl RemoteLine {
    /// `REMOTE github:<id> [<module>] <verb> — <detail>`.
    pub fn line(&self) -> String {
        format!(
            "REMOTE {} [{}] {} — {}",
            self.item, self.module, self.verb, self.detail
        )
    }
}

/// The closing line of the diff.
pub fn closing(diff: &[RemoteLine]) -> &'static str {
    if diff.iter().any(|l| writes_something(l.verb)) {
        "Remote plan only; no writes."
    } else {
        "No remote changes."
    }
}

/// The diff of every remote item the installed lock records under one of
/// `registry`'s modules, in module and id order.
pub fn remote_plan(
    root: &Path,
    source: &Source,
    registry: &[&dyn engine::Module],
    reader: &dyn RemoteReader,
) -> Result<Vec<RemoteLine>> {
    Ok(diff(root, source, registry, reader)?.0)
}

/// What `apply <repo> --remote` printed and whether every written item verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Applied {
    /// The `REMOTE`, then `WRITE`, then `VERIFY` lines.
    pub lines: Vec<String>,
    pub closing: String,
    /// False when an attempted item did not verify (exit code 1).
    pub verified: bool,
}

/// `apply <repo> --remote` (#903; SPEC-engine.md): the diff, then exactly the
/// items it names `create`, `update` or `remove`, written through `writer` in
/// the modules' declaration order, then the probes once more. A failed write
/// does not stop the others; nothing is retried. After each round of writes the
/// steps are evaluated again, and an item the diff listed `blocked` whose step
/// is now pending is written in the next round of the same run (#1148).
pub fn apply_remote(
    root: &Path,
    source: &Source,
    registry: &[&dyn engine::Module],
    reader: &dyn RemoteReader,
    writer: &dyn RemoteWriter,
) -> Result<Applied> {
    let (diff, writes, installed) = diff(root, source, registry, reader)?;
    let mut lines: Vec<String> = diff.iter().map(RemoteLine::line).collect();
    let line_of = |module: &String, write: &RemoteWrite| {
        let item = format!("github:{}", write.id);
        diff.iter().find(|l| &l.module == module && l.item == item)
    };
    let mut round: Vec<(&String, &RemoteWrite, RemoteVerb)> = writes
        .iter()
        .filter_map(|(module, write)| {
            let line = line_of(module, write)?;
            writes_something(line.verb).then_some((module, write, line.verb))
        })
        .collect();
    if round.is_empty() {
        return Ok(Applied {
            lines,
            closing: "No remote changes.".to_owned(),
            verified: true,
        });
    }
    let mut blocked: Vec<(&String, &RemoteWrite)> = writes
        .iter()
        .filter(|(module, write)| {
            line_of(module, write).is_some_and(|l| l.verb == RemoteVerb::Blocked)
        })
        .map(|(module, write)| (module, write))
        .collect();
    let mut attempted: Vec<(&String, &RemoteWrite)> = Vec::new();
    let steps = loop {
        for (module, write, verb) in &round {
            lines.push(match writer.write(write) {
                Ok(report) => format!(
                    "WRITE github:{} [{module}] {verb} — {}",
                    write.id,
                    summary(&report)
                ),
                Err(message) => format!("WRITE github:{} [{module}] failed — {message}", write.id),
            });
            attempted.push((module, write));
        }
        let steps = engine::steps(
            root,
            source,
            &installed.profile,
            &installed.active,
            &installed.lock,
            reader,
        )?;
        let step_of = |module: &String, id: &str| {
            steps
                .iter()
                .find(|s| &s.module == module && s.id == id)
                .cloned()
        };
        // The blocked items whose `after` step verified in this run, classified
        // like the diff's pending ones; the rest wait for a later round or run.
        let (now_pending, still): (Vec<_>, Vec<_>) = blocked.into_iter().partition(|(m, w)| {
            step_of(m, &w.id).is_some_and(|s| s.state == engine::StepState::Pending)
        });
        blocked = still;
        round = Vec::new();
        for (module, write) in now_pending {
            let detail =
                step_of(module, &write.id).map_or_else(String::new, |s| s.detail().to_owned());
            let item = format!("github:{}", write.id);
            match reader.change(&write.desired) {
                Ok(change) => {
                    let verb = pending(change);
                    lines.push(format!("REMOTE {item} [{module}] {verb} — {detail}"));
                    round.push((module, write, verb));
                }
                Err(message) => lines.push(format!(
                    "REMOTE {item} [{module}] {} — {message}",
                    RemoteVerb::Failed
                )),
            }
        }
        if round.is_empty() {
            break steps;
        }
    };
    let mut unverified = 0;
    for (module, write) in &attempted {
        let step = steps
            .iter()
            .find(|s| &&s.module == module && s.id == write.id);
        let (state, detail) =
            step.map_or((engine::StepState::Failed, ""), |s| (s.state, s.detail()));
        if state != engine::StepState::Verified {
            unverified += 1;
        }
        lines.push(format!(
            "VERIFY github:{} [{module}] {state} — {detail}",
            write.id
        ));
    }
    Ok(Applied {
        lines,
        closing: if unverified == 0 {
            "Remote writes applied; every written item verified.".to_owned()
        } else {
            format!(
                "Remote writes applied; {unverified} of {} items not verified.",
                attempted.len()
            )
        },
        verified: unverified == 0,
    })
}

/// The modules the lock records, with the lock and the project profile.
struct Installed<'a> {
    lock: engine::Lock,
    profile: crate::profile::Profile,
    active: Vec<&'a dyn engine::Module>,
}

type Diff<'a> = (Vec<RemoteLine>, Vec<(String, RemoteWrite)>, Installed<'a>);

/// The diff, the declared desired states in declaration order, and what was loaded.
fn diff<'a>(
    root: &Path,
    source: &Source,
    registry: &[&'a dyn engine::Module],
    reader: &dyn RemoteReader,
) -> Result<Diff<'a>> {
    let Some(raw) = read(root, LOCK)? else {
        return refuse(format!("Setup lock missing: {LOCK}; run install first"));
    };
    let lock = engine::Lock::parse(&raw, modules::core_version(), &known_path)?;
    let active: Vec<&dyn engine::Module> = registry
        .iter()
        .copied()
        .filter(|m| lock.modules.contains_key(m.id()))
        .collect();
    let profile = profile_for(root)?;
    let items: Vec<(&String, &engine::lock::FileEntry, &str)> = lock
        .files
        .iter()
        .filter(|(_, entry)| entry.class == engine::Ownership::Remote)
        .filter_map(|(path, entry)| Some((path, entry, path.strip_prefix("github:")?)))
        .collect();
    let writes = engine::remote_writes(root, source, &profile, &active, &lock)?;
    let desired = desired_states(&items, &writes)?;
    let steps = engine::steps(root, source, &profile, &active, &lock, reader)?;
    let mut diff: Vec<RemoteLine> = items
        .iter()
        .map(|(path, entry, id)| {
            let step = steps
                .iter()
                .find(|s| s.module == entry.module && s.id == *id);
            let (verb, detail) = match step {
                None => (
                    RemoteVerb::Failed,
                    format!("module {} declares no probe for {path}", entry.module),
                ),
                Some(step) if step.state == engine::StepState::Pending => {
                    match reader.change(&desired[&(entry.module.as_str(), *id)]) {
                        Ok(change) => (pending(change), step.detail().to_owned()),
                        Err(message) => (RemoteVerb::Failed, message),
                    }
                }
                Some(step) => (verb(step.state), step.detail().to_owned()),
            };
            RemoteLine {
                item: (*path).clone(),
                module: entry.module.clone(),
                verb,
                detail,
            }
        })
        .collect();
    diff.sort_by(|a, b| (&a.module, &a.item).cmp(&(&b.module, &b.item)));
    Ok((
        diff,
        writes,
        Installed {
            lock,
            profile,
            active,
        },
    ))
}

/// Whether `apply --remote` writes an item with this verb.
fn writes_something(verb: RemoteVerb) -> bool {
    matches!(
        verb,
        RemoteVerb::Create | RemoteVerb::Update | RemoteVerb::Remove
    )
}

/// The non-empty parts of a write report, `created: …; updated: …; …`.
fn summary(report: &WriteReport) -> String {
    let mut parts: Vec<String> = [
        ("created", &report.created),
        ("updated", &report.updated),
        ("unchanged", &report.unchanged),
        ("removed", &report.removed),
    ]
    .iter()
    .filter(|(_, items)| !items.is_empty())
    .map(|(what, items)| format!("{what}: {}", items.join(", ")))
    .collect();
    parts.extend(
        report
            .skipped
            .iter()
            .map(|(item, why)| format!("skipped: {item} ({why})")),
    );
    if parts.is_empty() {
        "nothing to report".to_owned()
    } else {
        parts.join("; ")
    }
}

/// The desired state of each item by module and id: exactly one per item,
/// refused otherwise; states for items the lock does not record are ignored.
fn desired_states<'a>(
    items: &[(&String, &'a engine::lock::FileEntry, &'a str)],
    writes: &[(String, RemoteWrite)],
) -> Result<BTreeMap<(&'a str, &'a str), Desired>> {
    let mut found = BTreeMap::new();
    for (path, entry, id) in items {
        let mut declared = writes
            .iter()
            .filter(|(module, write)| *module == entry.module && write.id == *id);
        let Some((_, write)) = declared.next() else {
            return refuse(format!(
                "Module {}: remote item {path} declares no desired state",
                entry.module
            ));
        };
        if declared.next().is_some() {
            return refuse(format!(
                "Module {}: remote item {path} declares two desired states",
                entry.module
            ));
        }
        found.insert((entry.module.as_str(), *id), write.desired.clone());
    }
    Ok(found)
}

fn pending(change: Change) -> RemoteVerb {
    match change {
        Change::Create => RemoteVerb::Create,
        Change::Update => RemoteVerb::Update,
        Change::Remove => RemoteVerb::Remove,
    }
}

/// The verb of a step that is not pending; a pending one is classified from
/// its desired state by the caller, so it never reaches this arm unclassified.
fn verb(state: engine::StepState) -> RemoteVerb {
    match state {
        engine::StepState::Pending => RemoteVerb::Failed,
        engine::StepState::Verified => RemoteVerb::Unchanged,
        engine::StepState::Blocked => RemoteVerb::Blocked,
        engine::StepState::Unavailable => RemoteVerb::Unavailable,
        engine::StepState::Failed => RemoteVerb::Failed,
        engine::StepState::NotApplicable => RemoteVerb::NotApplicable,
    }
}
