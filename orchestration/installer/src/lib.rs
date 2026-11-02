//! Conservative installer: target commands are data and are never executed.
pub mod alerts;
pub mod apply_remote;
pub mod auditor;
pub mod ci_init;
pub mod config;
pub mod engine;
pub mod guard;
pub mod host;
/// Former names this build still recognises, so repositories installed under them are
/// migrated in place (#1067). The owner's build carries them (`legacy.rs`, never exported);
/// the product has no former name.
#[cfg(not(feature = "setup-core"))]
pub mod legacy {
    pub const BLOCK_MARKERS: &[(&str, &str)] = &[];
    pub const RULESET_NAMES: &[(&str, &str)] = &[];
    pub const BINARIES: &[&str] = &[];
}
pub mod mcp;
pub mod modules;
pub mod profile;
pub mod questions;
pub mod remote;
pub mod scope;

#[cfg(feature = "setup-core")]
use conventions::DECISIONS_INDEX;
pub use profile::{default_profile, profile_for};
pub use scope::{destination, directory, personal_scope, read_scope};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::Path};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
pub const BEGIN: &str = "<!-- brakes:begin -->";
pub const END: &str = "<!-- brakes:end -->";
pub const PROFILE: &str = ".agent-setup/project.json";
pub const LOCK: &str = ".agent-setup/lock.json";

pub fn refuse<T>(message: impl Into<String>) -> Result<T> {
    Err(std::io::Error::other(message.into()).into())
}
pub fn digest(text: &str) -> String {
    format!("{:x}", Sha256::digest(text.as_bytes()))
}
pub fn read(root: &Path, name: &str) -> Result<Option<String>> {
    let path = destination(root, name)?;
    match fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// `setup-core`'s guides and templates (feature `setup-core`, SPEC-product-boundary.md).
#[cfg(feature = "setup-core")]
macro_rules! guides {
    ($($name:literal),* $(,)?) => {
        pub const DOCUMENTS: &[(&str, &str)] = &[$(($name, include_str!(concat!("../../../templates/", $name)))),*];
    };
}
#[cfg(feature = "setup-core")]
guides!(
    "principles.md",
    "task.md",
    "index.md",
    "architecture.md",
    "decisions.md",
    "testing.md",
    "code-style.md",
    "domain.md",
    "delivery.md",
    "operations.md",
    "observability.md",
    "security.md",
    "project-context-template.md",
    "adr-template.md",
    "review-template.md",
    "patterns.md",
    "contracts.md",
    "containers.md",
    "ci.md",
    "cd.md",
    "e2e.md",
    "contract-template.md",
    "delivery-profile-template.md",
    "incidents.md",
    "runbook-template.md",
    "postmortem-template.md",
    "workflow.md",
);

/// The hook files the source carries for `merge-guard` (#696).
pub use modules::merge_guard::HOOKS;

pub struct Source {
    pub documents: BTreeMap<String, String>,
    pub version: String,
    pub revision: Option<String>,
    pub dirty: bool,
}
/// `setup-core`'s decisions index, which no other module renders.
fn is_decisions_index(name: &str) -> bool {
    #[cfg(feature = "setup-core")]
    return name == DECISIONS_INDEX;
    #[cfg(not(feature = "setup-core"))]
    return {
        let _ = name;
        false
    };
}

/// Template text that names a document only `setup-core` installs is wrapped in
/// `[[setup-core:` … `]]`. The text is kept, without the marker, when the build
/// has `setup-core`, and dropped without it, so the product never names a guide it
/// does not install (#1247). An unclosed marker is a refusal.
pub fn setup_core_text(template: &str) -> Result<String> {
    const OPEN: &str = "[[setup-core:";
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find(OPEN) {
        out.push_str(&rest[..start]);
        let inner = &rest[start + OPEN.len()..];
        let Some(end) = inner.find("]]") else {
            return refuse("Template: unclosed [[setup-core: marker");
        };
        if cfg!(feature = "setup-core") {
            out.push_str(&inner[..end]);
        }
        rest = &inner[end + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

/// The guides `setup-core` installs, by file name; none without the feature.
fn guide_documents() -> &'static [(&'static str, &'static str)] {
    #[cfg(feature = "setup-core")]
    return DOCUMENTS;
    #[cfg(not(feature = "setup-core"))]
    return &[];
}

impl Source {
    pub fn embedded() -> Self {
        Self {
            documents: guide_documents()
                .iter()
                .map(|(n, s)| (format!("docs/agent-setup/{n}"), (*s).to_owned()))
                .chain(
                    HOOKS
                        .iter()
                        .map(|(n, s)| ((*n).to_owned(), (*s).to_owned())),
                )
                .collect(),
            version: include_str!("../../../VERSION").trim().to_owned(),
            revision: match env!("BRAKES_COMMIT") {
                "" => None,
                s => Some(s.to_owned()),
            },
            dirty: env!("BRAKES_DIRTY") != "false",
        }
    }
    pub fn checkout(root: &Path) -> Result<Self> {
        let documents = guide_documents()
            .iter()
            .map(|(n, _)| {
                Ok((
                    format!("docs/agent-setup/{n}"),
                    fs::read_to_string(root.join("templates").join(n))?,
                ))
            })
            .chain(
                HOOKS
                    .iter()
                    .map(|(n, _)| Ok(((*n).to_owned(), fs::read_to_string(root.join(n))?))),
            )
            .collect::<Result<_>>()?;
        let revision = scope::git(root, &["rev-parse", "HEAD"]).ok();
        let dirty = scope::git(root, &["status", "--porcelain"]).map_or(true, |s| !s.is_empty());
        Ok(Self {
            documents,
            version: fs::read_to_string(root.join("VERSION"))?.trim().to_owned(),
            revision,
            dirty,
        })
    }
}

/// The managed block of `text`, between [`BEGIN`] and [`END`] or a former pair of
/// markers ([`legacy::BLOCK_MARKERS`]), which the next install rewrites with the
/// current ones; one block at most, whichever markers it carries.
pub fn block_content(text: &str) -> Result<Option<&str>> {
    let mut found = None;
    for (begin, end) in std::iter::once((BEGIN, END)).chain(legacy::BLOCK_MARKERS.iter().copied()) {
        let starts = text.matches(begin).count();
        let ends = text.matches(end).count();
        if starts == 0 && ends == 0 {
            continue;
        }
        if starts != 1 || ends != 1 || found.is_some() {
            return refuse("Duplicate or incomplete managed block");
        }
        let start = text.find(begin).expect("begin marker");
        let stop = text.find(end).expect("end marker") + end.len();
        if stop <= start {
            return refuse("Invalid managed block order");
        }
        found = Some(&text[start..stop]);
    }
    Ok(found)
}

/// `text` with its managed block's two marker lines removed and everything else kept,
/// for a block whose module is released (#48); `None` when `text` holds no block.
/// A marker that shares its line with other text, a duplicate or an incomplete block
/// refuses: releasing never guesses which text is the project's.
pub fn unmark_block(text: &str) -> Result<Option<String>> {
    let Some(block) = block_content(text)? else {
        return Ok(None);
    };
    let pair = std::iter::once((BEGIN, END))
        .chain(legacy::BLOCK_MARKERS.iter().copied())
        .find(|(begin, end)| block.starts_with(begin) && block.ends_with(end));
    let Some((begin, end)) = pair else {
        return refuse("Duplicate or incomplete managed block");
    };
    let start = text.find(block).expect("the block is in the text");
    let stop = start + block.len();
    let own_line = (start == 0 || text[..start].ends_with('\n'))
        && block[begin.len()..].starts_with('\n')
        && block[..block.len() - end.len()].ends_with('\n')
        && (stop == text.len() || text[stop..].starts_with('\n'));
    if !own_line {
        return refuse("A managed block marker shares its line with other text");
    }
    let inner = &block[begin.len() + 1..block.len() - end.len()];
    let after = text[stop..].strip_prefix('\n').unwrap_or("");
    Ok(Some(format!("{}{inner}{after}", &text[..start])))
}

/// True when the dotted version `a` is newer than `b`, comparing numeric parts;
/// a part that is not a number compares as 0.
pub fn version_newer(a: &str, b: &str) -> bool {
    let parts = |v: &str| -> Vec<u64> {
        v.trim_start_matches('v')
            .split('.')
            .map(|p| p.parse().unwrap_or(0))
            .collect()
    };
    let (mut a, mut b) = (parts(a), parts(b));
    let len = a.len().max(b.len());
    a.resize(len, 0);
    b.resize(len, 0);
    a > b
}

/// The current ruleset name a former one was renamed to (#1067).
pub fn renamed_ruleset(name: &str) -> Option<&'static str> {
    legacy::RULESET_NAMES
        .iter()
        .find(|(former, _)| *former == name)
        .map(|(_, current)| *current)
}

/// Guides this setup installed before and has since withdrawn (decision 2026-10-27,
/// "Planning follows Agent Skills as published"). An unchanged copy is deleted on
/// install; a locally edited one is refused, like any other managed content.
#[cfg(feature = "setup-core")]
pub const RETIRED: &[&str] = &[
    "docs/agent-setup/change-template.md",
    "docs/agent-setup/plan-template.md",
    "docs/agent-setup/prd-template.md",
];

#[cfg(feature = "setup-core")]
fn expected_paths() -> Vec<String> {
    ["AGENTS.md", "CLAUDE.md", DECISIONS_INDEX]
        .into_iter()
        .map(str::to_owned)
        .chain(
            DOCUMENTS
                .iter()
                .map(|(n, _)| format!("docs/agent-setup/{n}")),
        )
        .collect()
}
/// Destination -> new content, or `None` to delete a retired managed file.
pub type Plan = BTreeMap<String, Option<String>>;
pub fn plan(root: &Path, source: &Source) -> Result<Plan> {
    Ok(plan_detailed(root, source)?.changes)
}
/// The plan with, per rendered path, its ownership class and module.
pub fn plan_detailed(root: &Path, source: &Source) -> Result<engine::Planned> {
    plan_install(root, source, &[], None)
}
/// The plan of `install [--module <id>]... [--profile <P>]`: `setup-core`, every
/// module the installed lock records and the `requested` ids are reconciled; an
/// unknown id is refused by name before anything is read (SPEC-engine.md,
/// Commands). `tier` installs the requested modules for that maturity profile,
/// recorded with their answers (`engine::install`).
pub fn plan_install(
    root: &Path,
    source: &Source,
    requested: &[&str],
    tier: Option<&str>,
) -> Result<engine::Planned> {
    let profile = profile_for(root)?;
    engine::install(
        root,
        source,
        &profile,
        &modules::all(),
        &known_path,
        requested,
        tier,
        &BTreeMap::new(),
    )
}
/// `install` with `--preset` and `--answers` (SPEC-questions.md, Commands): each
/// installed module with a section is configured first, then installed; the
/// provenance lines and preset notes are printed, never written.
pub fn install(
    root: &Path,
    source: &Source,
    requested: &[&str],
    tier: Option<&str>,
    inputs: &questions::Inputs,
) -> Result<questions::Installed> {
    let profile = profile_for(root)?;
    questions::install(
        root,
        source,
        &profile,
        &modules::all(),
        &known_path,
        requested,
        tier,
        inputs,
    )
}
/// The `configure` subcommand: the answers files and `--set` pairs in `inputs`
/// resolved by the questions driver and recorded through the engine; the plan
/// includes the answers file and nothing is written (SPEC-questions.md).
pub fn configure(
    root: &Path,
    source: &Source,
    module_id: &str,
    inputs: &questions::Inputs,
) -> Result<questions::Configured> {
    let profile = profile_for(root)?;
    questions::configure(
        root,
        source,
        &profile,
        &modules::all(),
        &known_path,
        module_id,
        inputs,
    )
}
/// The TUI over `input` and `output` for `module_id`: the patch `configure`
/// takes as `Inputs::interactive`; nothing is written (SPEC-questions.md).
pub fn interview(
    root: &Path,
    source: &Source,
    module_id: &str,
    inputs: &questions::Inputs,
    input: &mut impl std::io::BufRead,
    output: &mut impl std::io::Write,
) -> Result<engine::Answers> {
    questions::interview(
        root,
        source,
        &modules::all(),
        module_id,
        inputs,
        input,
        output,
    )
}
/// The plan that uninstalls `module_id`: unchanged managed content deleted, edited
/// content refused, seeds kept and reported, its lock entries and answers file
/// dropped; nothing is written (SPEC-engine.md, `remove`).
pub fn remove(root: &Path, module_id: &str) -> Result<engine::Planned> {
    engine::remove(root, &modules::all(), &known_path, module_id)
}
/// The plan as the CLI prints it, one line per change: verb, path and, when the
/// engine knows it, class and module; then the SKIP/KEEP notes, the manual steps
/// and the module notes. `apply_changes` picks `WRITE`/`DELETE` over `PLAN`.
/// `configure`, `install` and `remove` print these; `mcp`'s `plan` returns them.
pub fn plan_lines(planned: &engine::Planned, apply_changes: bool) -> Vec<String> {
    // What a module this build does not ship leaves behind comes first (#48).
    let mut lines = planned.released.clone();
    for (name, content) in &planned.changes {
        let verb = match (apply_changes, content.is_some()) {
            (true, true) => "WRITE",
            (true, false) => "DELETE",
            (false, true) => "PLAN",
            (false, false) => "PLAN DELETE",
        };
        lines.push(if let Some((class, module)) = planned.tags.get(name) {
            format!("{verb} {name} [{class}:{module}]")
        } else if let Some(module) = planned.answers.get(name) {
            format!("{verb} {name} [answers:{module}]")
        } else {
            format!("{verb} {name}")
        });
    }
    // SKIP (a seed that already exists) and KEEP (a retired seed, never-touch or
    // remote entry) report paths the engine leaves alone; nothing is written for them.
    let prefix = if apply_changes { "" } else { "PLAN " };
    for (name, note) in &planned.notes {
        lines.push(match planned.tags.get(name) {
            Some((class, module)) => format!("{prefix}{note} {name} [{class}:{module}]"),
            None => format!("{prefix}{note} {name}"),
        });
    }
    // Manual steps are informative in both modes: nothing is written for them.
    lines.extend(planned.steps.iter().map(engine::StepReport::plan_line));
    // Module notes close the plan; like steps, they change nothing.
    lines.extend(planned.plan_notes.iter().map(ToString::to_string));
    lines
}
/// A path today's content may have recorded in a schema-1 lock: `setup-core`'s,
/// a retired guide or the hook `merge-guard` took over.
fn known_path(path: &str) -> bool {
    #[cfg(feature = "setup-core")]
    if expected_paths().iter().any(|p| p == path) || RETIRED.contains(&path) {
        return true;
    }
    HOOKS.iter().any(|(n, _)| *n == path)
}

pub fn apply(root: &Path, changes: &Plan) -> Result<()> {
    // Validate every destination before the first write, and write the lock last.
    for name in changes.keys() {
        destination(root, name)?;
    }
    for (name, content) in changes
        .iter()
        .filter(|(n, _)| n.as_str() != LOCK)
        .chain(changes.iter().filter(|(n, _)| n.as_str() == LOCK))
    {
        let path = destination(root, name)?;
        match content {
            Some(content) => {
                fs::create_dir_all(path.parent().expect("destination parent"))?;
                fs::write(path, content)?;
            }
            None => match fs::remove_file(path) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
                _ => {}
            },
        }
    }
    Ok(())
}

/// Reads `Last verified: YYYY-MM-DD` from the header block (first lines) of a guide.
pub fn last_verified(text: &str) -> Option<chrono::NaiveDate> {
    text.lines().take(10).find_map(|line| {
        let date = line.trim().strip_prefix("Last verified:")?.trim();
        chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d").ok()
    })
}

pub fn today() -> chrono::NaiveDate {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    chrono::DateTime::from_timestamp(secs as i64, 0)
        .expect("current time")
        .date_naive()
}

/// What `doctor` found: the findings (today's lines, without their prefix), the
/// manual steps of the installed modules evaluated, and the installed module versions.
#[derive(Debug)]
pub struct Diagnosis {
    pub findings: Vec<String>,
    pub steps: Vec<engine::StepReport>,
    /// `(id, version)` of every module the lock records, sorted by id.
    pub modules: Vec<(String, String)>,
    /// The declared exclusions of the rules that judge files a walk finds, as
    /// printed (`EXCLUDED [<rule>] <path> — …`): information, never a finding (#1171).
    pub excluded: Vec<String>,
}

impl Diagnosis {
    /// The findings as `doctor` prints them: `WARNING: ` ones as they are, the
    /// rest behind `NOT READY: `.
    pub fn printed_findings(&self) -> Vec<String> {
        self.findings
            .iter()
            .map(|finding| {
                if finding.starts_with("WARNING: ") {
                    finding.clone()
                } else {
                    format!("NOT READY: {finding}")
                }
            })
            .collect()
    }
    /// Readiness is about managed content and the profile: warnings and manual
    /// steps never fail it.
    pub fn ready(&self) -> bool {
        self.findings.iter().all(|f| f.starts_with("WARNING: "))
    }
}

/// The `doctor --json` document, schema 1: `findings` are the lines as printed
/// (so a remote diagnosis adds its own), `steps` and `modules` as diagnosed.
pub fn doctor_json(
    ready: bool,
    findings: &[String],
    steps: &[engine::StepReport],
    modules: &[(String, String)],
) -> Result<String> {
    doctor_audit_json(ready, findings, steps, modules, None)
}

/// [`doctor_json`] with the audit's schema-1 additions
/// ([`auditor::report::Audited::json`]) after today's keys.
pub fn doctor_audit_json(
    ready: bool,
    findings: &[String],
    steps: &[engine::StepReport],
    modules: &[(String, String)],
    audit: Option<&serde_json::Map<String, serde_json::Value>>,
) -> Result<String> {
    #[derive(serde::Serialize)]
    struct ModuleVersion<'a> {
        id: &'a str,
        version: &'a str,
    }
    #[derive(serde::Serialize)]
    struct Document<'a> {
        schema: u64,
        ready: bool,
        findings: &'a [String],
        steps: &'a [engine::StepReport],
        modules: Vec<ModuleVersion<'a>>,
        #[serde(flatten)]
        audit: Option<&'a serde_json::Map<String, serde_json::Value>>,
    }
    let document = Document {
        schema: 1,
        ready,
        findings,
        steps,
        modules: modules
            .iter()
            .map(|(id, version)| ModuleVersion { id, version })
            .collect(),
        audit,
    };
    Ok(serde_json::to_string_pretty(&document)? + "\n")
}

pub fn doctor(root: &Path) -> Result<Vec<String>> {
    doctor_at(root, today())
}

pub fn doctor_at(root: &Path, today: chrono::NaiveDate) -> Result<Vec<String>> {
    Ok(diagnose_at(root, today)?.findings)
}

/// The diagnosis of the compiled-in modules without a host adapter.
pub fn diagnose(root: &Path) -> Result<Diagnosis> {
    diagnose_at(root, today())
}

pub fn diagnose_at(root: &Path, today: chrono::NaiveDate) -> Result<Diagnosis> {
    diagnose_with(
        root,
        today,
        &Source::embedded(),
        &modules::all(),
        &engine::NoRunner,
    )
}

/// `doctor` over `modules`: findings as today, plus the manual steps of those the
/// lock records as installed, evaluated with `runner` answering remote probes.
pub fn diagnose_with(
    root: &Path,
    today: chrono::NaiveDate,
    source: &Source,
    modules: &[&dyn engine::Module],
    runner: &dyn engine::RemoteRunner,
) -> Result<Diagnosis> {
    let profile = profile_for(root)?;
    let mut issues = Vec::new();
    let mut steps = Vec::new();
    let mut installed = Vec::new();
    if profile.raw.is_none() {
        issues.push("Setup not installed: project profile missing".to_owned());
    }
    if profile.value["purpose"]
        .as_str()
        .unwrap_or("")
        .trim()
        .is_empty()
    {
        issues.push("Project purpose missing".to_owned());
    }
    if profile.value["commands"]["verify"].is_null() {
        issues.push("Verification command missing".to_owned());
    }
    #[cfg(feature = "setup-core")]
    let conventions = conventions::parse(&profile.value["conventions"]);
    #[cfg(feature = "setup-core")]
    {
        for c in &conventions {
            if read(root, &c.path)?.is_none() {
                issues.push(format!("Convention reference missing: {}", c.path));
            }
        }
        issues.extend(conventions::findings(root, &conventions)?);
    }
    if profile.value.get("planning").is_some() {
        // The workflow guide is setup-core's: named only when this build installs it (#1247).
        let guide = if cfg!(feature = "setup-core") {
            " (docs/agent-setup/workflow.md)"
        } else {
            ""
        };
        issues.push(format!(
            "Obsolete profile field: planning; the workflow is a project convention{guide}, remove the field"
        ));
    }
    let observability = &profile.value["observability"];
    if let Some(alerts) = observability["alerts_dir"].as_str() {
        issues.extend(alerts::check(
            root,
            alerts,
            observability["runbooks_dir"].as_str(),
        )?);
    }
    match read(root, LOCK)? {
        None => issues.push("Setup lock missing".to_owned()),
        Some(raw) => {
            let lock = engine::Lock::parse(&raw, modules::core_version(), &known_path)?;
            let files: BTreeMap<String, Option<String>> = lock
                .files
                .iter()
                .map(|(k, v)| (k.clone(), v.digest.clone()))
                .collect();
            #[cfg(feature = "setup-core")]
            let mut expected = expected_paths();
            #[cfg(not(feature = "setup-core"))]
            let mut expected: Vec<String> = Vec::new();
            // The hook is expected where merge-guard is installed (#696).
            if lock.modules.contains_key(modules::merge_guard::MERGE_GUARD) {
                expected.extend(HOOKS.iter().map(|(n, _)| (*n).to_owned()));
            }
            #[cfg(feature = "setup-core")]
            {
                let has_index =
                    conventions.iter().any(|c| c.object) || files.contains_key(DECISIONS_INDEX);
                // The index is derived from project decisions; staleness must not reject a decision-only PR.
                if has_index {
                    let index = read(root, DECISIONS_INDEX)?;
                    let expected_index = conventions::decisions_index(root, &conventions)?;
                    if index.as_deref() != Some(&expected_index)
                        || files.get(DECISIONS_INDEX).and_then(|d| d.as_deref())
                            != Some(&digest(&expected_index))
                    {
                        issues.push(format!("WARNING: Decisions index stale: {DECISIONS_INDEX}; regenerate with the setup installer"));
                    }
                }
                expected.retain(|name| name != DECISIONS_INDEX);
            }
            expected.sort();
            for name in expected.iter().filter(|n| !files.contains_key(*n)) {
                issues.push(format!(
                    "Engineering guide not installed; update setup: {name}"
                ));
            }
            #[cfg(feature = "setup-core")]
            for name in RETIRED.iter().filter(|n| files.contains_key(**n)) {
                issues.push(format!(
                    "Retired guide still installed; update setup: {name}"
                ));
            }
            if lock.source_dirty {
                issues.push("Installed source was uncommitted; not a release baseline".to_owned());
            }
            for (name, expected) in &files {
                if is_decisions_index(name) || expected.is_none() {
                    continue;
                }
                let value = read(root, name)?;
                // Managed entries (#747) are checked one by one, not by the file's digest.
                if let Some(entries) = lock.files[name].entries.as_ref() {
                    if !engine::entries::in_place(value.as_deref(), entries) {
                        issues.push(format!(
                            "Managed entries drift: {name} (module {})",
                            lock.files[name].module
                        ));
                    }
                    continue;
                }
                // The lock's class decides, as in the engine (#1106): a managed
                // block's digest is the block's, whatever the file is called.
                let installed = if lock.files[name].class == engine::Ownership::ManagedBlock {
                    block_content(value.as_deref().unwrap_or(""))?
                } else {
                    value.as_deref()
                };
                if installed.is_none_or(|s| expected.as_deref() != Some(&digest(s))) {
                    issues.push(format!(
                        "Managed content drift: {name} (module {})",
                        lock.files[name].module
                    ));
                }
            }
            let bound = profile::guide_verification_days(&profile.value) as i64;
            // Managed guides only: a seed is the project's file, and its module's
            // own rule judges its date (`agents.technical-debt`, #1172).
            for name in files.keys().filter(|n| {
                n.starts_with("docs/agent-setup/")
                    && !is_decisions_index(n)
                    && lock.files[*n].class != engine::Ownership::Seed
            }) {
                let Some(text) = read(root, name)? else {
                    continue;
                };
                let label = name.trim_start_matches("docs/agent-setup/");
                match last_verified(&text) {
                    None => issues.push(format!("Guide verification date missing: {label}")),
                    Some(date) => {
                        let age = (today - date).num_days();
                        if age > bound {
                            issues.push(format!("Guide not verified for {age} days: {label}"));
                        }
                    }
                }
            }
            #[cfg(feature = "setup-core")]
            for (name, expected) in modules::setup_core::managed_blocks(&profile) {
                if block_content(read(root, &name)?.as_deref().unwrap_or(""))? != Some(&expected) {
                    issues.push(format!(
                        "Entrypoint does not reflect project profile: {name}"
                    ));
                }
            }
            let active: Vec<&dyn engine::Module> = modules
                .iter()
                .copied()
                .filter(|m| lock.modules.contains_key(m.id()))
                .collect();
            steps = engine::steps(root, source, &profile, &active, &lock, runner)?;
            if lock
                .modules
                .contains_key(modules::agent_guardrails::AGENT_GUARDRAILS)
            {
                issues.extend(modules::agent_guardrails::doctor::findings(
                    root, &profile, today,
                )?);
            }
            installed = lock
                .modules
                .iter()
                .map(|(id, entry)| (id.clone(), entry.version.clone()))
                .collect();
        }
    }
    for name in ["AGENTS.md", "CLAUDE.md"] {
        let value = read(root, name)?.unwrap_or_default();
        if value.lines().any(|line| {
            let text = line
                .trim()
                .strip_prefix('-')
                .or_else(|| line.trim().strip_prefix('*'))
                .unwrap_or(line.trim())
                .trim();
            ["TODO", "TBD", "ninguna declarada", "Levantar:"].contains(&text)
        }) {
            issues.push(format!(
                "Existing placeholder guidance needs review: {name}"
            ));
        }
    }
    // The card mirrors the profile's criticality: a warning in every checkout (#1236).
    issues.extend(modules::repo_baseline::card_criticality_finding(
        root,
        &profile.value,
    )?);
    issues.extend(guard::doctor::registration(root)?);
    issues.extend(modules::stack_packs::detect::unconfigured(root)?);
    // The static stack.* rules and the pin-table age: warnings, never readiness (#763).
    issues.extend(modules::stack_packs::audit::diagnose(root, today)?);
    // The static ci.* rules: warnings over every workflow, never readiness (#777).
    issues.extend(modules::ci_baseline::audit::diagnose(root, &profile.value));
    // The static security.* rules: warnings over workflows and exception files (#793).
    issues.extend(modules::security::audit::diagnose(root, today));
    // The static agents.* content rules: warnings in every checkout (#746).
    issues.extend(modules::agent_guardrails::audit::diagnose(root));
    // The static Bronze qa.* rules: warnings in every checkout (#1008).
    issues.extend(modules::qa::audit::diagnose(root));
    let mut excluded = profile::exclusion_lines(&profile.value);
    excluded.extend(modules::security::audit::excluded(root));
    excluded.extend(modules::qa::audit::excluded(root));
    Ok(Diagnosis {
        findings: issues,
        steps,
        modules: installed,
        excluded,
    })
}
