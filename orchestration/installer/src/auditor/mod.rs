//! The auditor (SPEC-auditor.md): evaluates every rule of [`rules::REGISTRY`]
//! against one repository, decides which are required for its dimensions and
//! computes the level reached, the next-level gap and the exit code. Evaluation
//! is a pure function of the host's responses, the files and `now`; nothing
//! here writes, and absence of evidence is `Unavailable`, never a pass.
pub mod adopt;
pub mod cached;
pub mod catalogue;
pub mod ci_audit;
pub mod counters;
pub mod fleet;
pub mod measures;
pub mod report;
pub mod rules;
pub mod workflows;

use crate::{
    Result,
    host::{
        Availability, CallBudget, Host, HostError, HostErrorKind, HostKind, RepoId, github::GitHub,
    },
    refuse, remote, scope,
};
use rules::{
    Cadence, Condition, Criticality, Level, Milestone, Outcome, Plan, Profile, REGISTRY, Rule,
    Services, Status,
};
use serde_json::Value;
use std::{fs, io::ErrorKind, path::Path};

/// Everything a rule may read: the host, the files, the repository, the
/// clock and the profile. The same rules serve a checkout and `--fleet`.
pub struct Cx<'a> {
    pub host: &'a dyn Host,
    pub files: &'a dyn Files,
    pub repo: &'a RepoId,
    pub default_branch: &'a str,
    pub now: chrono::NaiveDate,
    pub budget: &'a CallBudget,
    /// The profile a rule whose criterion differs by profile judges against
    /// (`posture.production-environment-guarded`, #889). [`evaluate`] sets it
    /// from the measured [`Dimensions`]; measures, which derive it, never read it.
    pub profile: Profile,
    /// Today's `doctor` over the checkout, which the baseline block re-labels
    /// (#730); `None` under `--fleet`, which has no checkout, and the rules
    /// that re-label it are then `NotRequired` (#734).
    pub today: Option<&'a Today<'a>>,
}

/// What today's `doctor` found over a checkout: the findings as
/// [`crate::Diagnosis`] holds them (`WARNING: ` kept, `NOT READY: ` not added),
/// those of `remote::inspect_report` appended when `remote`, and the manual
/// steps of the installed modules as the engine's probes answered them.
#[derive(Debug, Clone, Copy)]
pub struct Today<'a> {
    pub findings: &'a [String],
    pub steps: &'a [crate::engine::StepReport],
    /// `doctor --remote` ran: the remote findings are among `findings`.
    pub remote: bool,
}

/// The repository files rules may read, bounded by [`FILE_ALLOWLIST`] and the
/// workflow directory: the local checkout here, the contents API in `--fleet`.
pub trait Files {
    /// The text of an allowlisted file, `None` when it does not exist.
    fn read(&self, path: &str) -> Result<Option<String>>;
    /// The files directly under `dir`, one of [`WORKFLOWS`] and
    /// [`ISSUE_TEMPLATES`], as sorted repository paths.
    fn list(&self, dir: &str) -> Result<Vec<String>>;
    /// Whether each read is a host call: true for the contents API of
    /// `--fleet`, so the fleet allowances apply (SPEC-auditor.md, #935).
    fn costs_calls(&self) -> bool {
        false
    }
}

/// The files rules may read (SPEC-auditor.md, "Fleet"), plus the service card
/// path the ruleset policy seeds (decision "Full-lifecycle installer", point 7);
/// Markdown documents are admitted by extension (see [`allowed`]).
pub const FILE_ALLOWLIST: &[&str] = &[
    ".agent-setup/project.json",
    ".agent-setup/lock.json",
    ".agent-setup/security-exceptions.json",
    // The remote `ci.*` rules read ci-baseline's `aggregate_check` and
    // `minutes_budget` (SPEC-ci-baseline.md, slice 2; #783).
    ".agent-setup/modules/ci-baseline.json",
    ".agent-setup/service.yaml",
    "AGENTS.md",
    "CODEOWNERS",
    ".github/CODEOWNERS",
    "docs/CODEOWNERS",
    "service.yaml",
    "catalog-info.yaml",
    ".github/dependabot.yml",
    ".github/dependabot.yaml",
    "renovate.json",
    "Dockerfile",
];
/// The directory of workflows: rules may list it and read its direct files.
pub const WORKFLOWS: &str = ".github/workflows";
/// The directory of issue templates: rules may list it, never read it.
pub const ISSUE_TEMPLATES: &str = ".github/ISSUE_TEMPLATE";
/// The directories [`Files::list`] admits.
const LISTABLE: [&str; 2] = [WORKFLOWS, ISSUE_TEMPLATES];

/// An allowlisted file, a direct file of [`WORKFLOWS`], or a Markdown document
/// (pull request templates, the decision files `project.json` conventions
/// declare); never a path that climbs out of the checkout.
fn allowed(path: &str) -> bool {
    FILE_ALLOWLIST.contains(&path)
        || path
            .strip_prefix(WORKFLOWS)
            .and_then(|rest| rest.strip_prefix('/'))
            .is_some_and(|name| !name.is_empty() && !name.contains('/') && name != "..")
        || (path.ends_with(".md")
            && !path.starts_with('/')
            && path
                .split('/')
                .all(|part| !part.is_empty() && part != ".." && part != "."))
}

/// [`Files`] over a local checkout, through the crate's path guard.
pub struct LocalFiles<'a> {
    root: &'a Path,
}
impl<'a> LocalFiles<'a> {
    pub fn new(root: &'a Path) -> Self {
        Self { root }
    }
}
impl Files for LocalFiles<'_> {
    fn read(&self, path: &str) -> Result<Option<String>> {
        if !allowed(path) {
            return refuse(format!(
                "Auditor file read refused: {path} is outside the auditor's path allowlist"
            ));
        }
        crate::read(self.root, path)
    }
    fn list(&self, dir: &str) -> Result<Vec<String>> {
        if !LISTABLE.contains(&dir) {
            return refuse(format!(
                "Auditor listing refused: {dir} is not one of {}",
                LISTABLE.join(", ")
            ));
        }
        let entries = match fs::read_dir(scope::directory(self.root, dir)?) {
            Ok(entries) => entries,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut paths = Vec::new();
        for entry in entries {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                paths.push(format!("{dir}/{}", entry.file_name().to_string_lossy()));
            }
        }
        paths.sort();
        Ok(paths)
    }
}

/// The measured dimensions a rule's `required` is decided from; `None` is a
/// measure without evidence, which satisfies no condition. An undeclared
/// criticality is audited as `internal`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dimensions {
    pub profile: Profile,
    pub cadence: Option<Cadence>,
    pub services: Option<Services>,
    pub criticality: Option<Criticality>,
}
impl Dimensions {
    fn holds(&self, condition: &Condition) -> bool {
        match *condition {
            Condition::CadenceAtLeast(tier) => self.cadence.is_some_and(|c| c >= tier),
            Condition::ServicesAtLeast(tier) => self.services.is_some_and(|s| s >= tier),
            Condition::CriticalityAtLeast(tier) => {
                self.criticality.unwrap_or(Criticality::Internal) >= tier
            }
            Condition::PlatformLadderL4 => false,
        }
    }
    /// A rule is required when the profile is listed or any condition holds.
    pub fn requires(&self, rule: &Rule) -> bool {
        rule.required.profiles.contains(&self.profile)
            || rule.required.when.iter().any(|c| self.holds(c))
    }
}

/// One rule as evaluated for one repository; reported whether required or not.
#[derive(Debug, Clone)]
pub struct Evaluated {
    pub rule: &'static Rule,
    pub required: bool,
    pub outcome: Outcome,
}
impl PartialEq for Evaluated {
    fn eq(&self, other: &Self) -> bool {
        self.rule.id == other.rule.id
            && self.required == other.required
            && self.outcome == other.outcome
    }
}
impl Evaluated {
    /// What fixes the rule: the outcome's own remediations when it names them,
    /// else the rule's (#1254).
    pub fn remediations(&self) -> Vec<rules::Remediation> {
        if self.outcome.remediations.is_empty() {
            vec![self.rule.remediation]
        } else {
            self.outcome.remediations.clone()
        }
    }
    fn blocks(&self, level: Level, status: Status) -> bool {
        self.blocks_any(status) && self.rule.level == level
    }
    /// Required, at any level, and in `status`.
    fn blocks_any(&self, status: Status) -> bool {
        self.required && self.outcome.status == status
    }
}

/// The first level not reached and the required rules that block it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NextLevel {
    pub level: Level,
    pub gap: Vec<&'static str>,
}

/// The audit of one repository.
#[derive(Debug, Clone, PartialEq)]
pub struct Audit {
    /// Every rule, in registry order.
    pub rules: Vec<Evaluated>,
    /// The highest level whose required rules, and those of every level below,
    /// all passed; `None` below Basic.
    pub reached: Option<Level>,
    /// The first level not reached, when only `Unavailable` evidence blocks it.
    pub unverified_from: Option<Level>,
    /// `None` once Gold is reached.
    pub next: Option<NextLevel>,
    /// The failing rules an active `accepted-risk` entry covers (#1217): shown
    /// as `ACCEPTED`, never counted as passed, so `reached` and `next` ignore them.
    pub accepted_risks: Vec<AcceptedRisk>,
    /// What the accepted-risk entries got wrong: a target naming no rule.
    pub risk_findings: Vec<String>,
}

/// An owner-accepted risk on one failing rule: the inventory entry's fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedRisk {
    pub rule: &'static str,
    pub id: String,
    pub reason: String,
    pub issue: String,
    pub owner: String,
    pub expires: String,
}

/// The accepted risks of `rules` and the findings about the entries: an
/// active `accepted-risk` entry of the inventory covers each failing rule its
/// `target` names (decision 2026-10-31, #1217). An expired or invalid entry
/// accepts nothing (its own rules report it); an unreadable inventory, none.
fn accepted_risks(cx: &Cx<'_>, rules: &[Evaluated]) -> (Vec<AcceptedRisk>, Vec<String>) {
    use crate::modules::security::exceptions::{
        DEFAULT_BYPASS_MAX_DAYS, INVENTORY, Inventory, Kind, State, state,
    };
    let Some(inventory) = cx
        .files
        .read(INVENTORY)
        .ok()
        .flatten()
        .and_then(|text| Inventory::parse(&text))
    else {
        return (Vec::new(), Vec::new());
    };
    let (mut accepted, mut findings) = (Vec::new(), Vec::new());
    for entry in inventory
        .exceptions
        .iter()
        .filter(|e| e.kind.as_deref() == Some(Kind::AcceptedRisk.as_str()))
    {
        let targets = entry.target.as_deref().unwrap_or_default();
        for target in targets.split(',').map(str::trim).filter(|t| !t.is_empty()) {
            let Some(evaluated) = rules.iter().find(|e| e.rule.id == target) else {
                findings.push(format!(
                    "accepted risk {} names unknown rule {target}",
                    entry.label()
                ));
                continue;
            };
            let active = state(entry, cx.now, DEFAULT_BYPASS_MAX_DAYS).state == State::Active;
            let failing = evaluated.outcome.status == Status::Failed;
            if active && failing && !accepted.iter().any(|a: &AcceptedRisk| a.rule == target) {
                let field = |f: &Option<String>| f.clone().unwrap_or_default();
                accepted.push(AcceptedRisk {
                    rule: evaluated.rule.id,
                    id: entry.label(),
                    reason: field(&entry.reason),
                    issue: field(&entry.issue),
                    owner: field(&entry.owner),
                    expires: field(&entry.expires),
                });
            }
        }
    }
    (accepted, findings)
}
impl Audit {
    /// The CI contract of SPEC-auditor.md: 1 when today's `doctor` is not ready,
    /// 0 when `required` is reached, 3 when a required rule at or below it
    /// failed, 4 when only `Unavailable` evidence keeps it out of reach. Code 2
    /// (refused) never comes from an audit.
    pub fn exit_code(&self, ready: bool, required: Level) -> i32 {
        if !ready {
            1
        } else if self.reached >= Some(required) {
            0
        } else if self
            .rules
            .iter()
            .any(|e| e.required && e.rule.level <= required && e.outcome.status == Status::Failed)
        {
            3
        } else {
            4
        }
    }
}

/// Audits the repository of `cx` against the whole registry.
pub fn audit(cx: &Cx<'_>, dims: &Dimensions) -> Audit {
    evaluate(cx, dims, REGISTRY)
}

/// Evaluates `rules` (the registry, or a test's own) and computes the level.
/// A rule waiting for a module is `Unavailable` without being evaluated. The
/// evaluation owns a [`cached::Cached`] read cache, so each read is made once.
pub fn evaluate(cx: &Cx<'_>, dims: &Dimensions, rules: &'static [Rule]) -> Audit {
    let cached = cached::Cached::new(cx.host);
    evaluate_reading(
        &Cx {
            host: &cached,
            ..*cx
        },
        dims,
        rules,
        0,
    )
}

/// [`evaluate`], then the counters over the same read cache, as a remote
/// audit reads them: their allowance is held back while the rules read.
pub fn evaluate_counted(
    cx: &Cx<'_>,
    dims: &Dimensions,
    rules: &'static [Rule],
) -> (Audit, counters::Counters) {
    let cached = cached::Cached::new(cx.host);
    let cx = Cx {
        host: &cached,
        ..*cx
    };
    let audit = evaluate_reading(&cx, dims, rules, counters::ALLOWANCE);
    (audit, counters::count(&cx, true))
}

/// [`evaluate`] over `cx.host` as it is: the caller owns the read cache.
/// `after` calls stay held back once the last rule starts, for what reads
/// after the rules (the counters).
fn evaluate_reading(cx: &Cx<'_>, dims: &Dimensions, rules: &'static [Rule], after: u32) -> Audit {
    let cx = &Cx {
        profile: dims.profile,
        ..*cx
    };
    // Before each rule, the allowances of the rules after it are held back,
    // when they fit what remains (SPEC-auditor.md, "Block allowances").
    let allowance = allowances(cx.files);
    let mut later: u32 = rules.iter().map(|r| allowance(r.id)).sum::<u32>() + after;
    let holds = later <= cx.budget.limit().saturating_sub(cx.budget.used());
    let mut rules: Vec<Evaluated> = rules
        .iter()
        .map(|rule| {
            later -= allowance(rule.id);
            cx.budget.hold(if holds { later } else { 0 });
            Evaluated {
                rule,
                required: dims.requires(rule),
                outcome: match rule.feasible_by {
                    Milestone::WaitsFor(module) => {
                        Outcome::unavailable(format!("waits for module {module}"))
                    }
                    Milestone::Nov7 => (rule.evaluate)(cx),
                },
            }
        })
        .collect();
    // Every manual step of an installed module is a rule, judged from the
    // engine's probe result, never probed again (SPEC-auditor.md, point 7).
    let steps = cx.today.map_or(&[][..], |today| today.steps);
    rules.extend(steps.iter().map(|step| {
        let rule = catalogue::baseline::step_rule(step);
        Evaluated {
            rule,
            required: dims.requires(rule),
            outcome: catalogue::baseline::step_outcome(step),
        }
    }));
    let failed = |level| rules.iter().any(|e| e.blocks(level, Status::Failed));
    let unavailable = |level| rules.iter().any(|e| e.blocks(level, Status::Unavailable));
    let first_blocked = Level::ALL
        .into_iter()
        .find(|&level| failed(level) || unavailable(level));
    let reached = match first_blocked {
        None => Some(Level::Gold),
        Some(blocked) => Level::ALL.into_iter().take_while(|&l| l < blocked).last(),
    };
    let next = first_blocked.map(|level| {
        let mut gap: Vec<&'static str> = rules
            .iter()
            .filter(|e| e.blocks(level, Status::Failed) || e.blocks(level, Status::Unavailable))
            .map(|e| e.rule.id)
            .collect();
        gap.sort_unstable();
        NextLevel { level, gap }
    });
    let (accepted_risks, risk_findings) = accepted_risks(cx, &rules);
    Audit {
        unverified_from: first_blocked.filter(|&level| !failed(level)),
        reached,
        next,
        rules,
        accepted_risks,
        risk_findings,
    }
}

/// The first step of a plan-dependent rule: the feature probe decides, never
/// the plan name. `None` when the feature is available and the rule may go on;
/// otherwise the `Unavailable` outcome to report.
pub fn plan_gate(plan: Plan, feature: &Availability) -> Option<Outcome> {
    match feature {
        Availability::Available => None,
        Availability::Unavailable { .. } => Some(Outcome::requires_plan(plan)),
        Availability::Unknown { reason } => Some(Outcome::unavailable(reason.clone())),
    }
}

/// Host calls one repository's audit may spend (SPEC-auditor.md, "Fleet").
pub const CALL_BUDGET: u32 = 60;

/// Host calls one repository of `--fleet` may spend: [`CALL_BUDGET`] plus what
/// a checkout reads for free and the fleet reads through the contents API
/// (SPEC-auditor.md, "Fleet call budget", #1318).
pub const FLEET_CALL_BUDGET: u32 = 100;

/// The transport of an audit without `--remote`: every read answers that it is
/// unavailable, so host-backed rules and measures report it and none passes.
pub struct Offline;
impl remote::Api for Offline {
    fn get(&self, path: &str) -> Result<Value> {
        Err(HostError::new(
            HostErrorKind::Unsupported,
            format!("{path} is unavailable without --remote"),
        )
        .into())
    }
}

/// The `GitHub` host over [`Offline`]. Its own budget never binds: offline
/// reads are not calls, so the audit reports its budget untouched.
pub fn offline_host() -> GitHub<'static> {
    GitHub::new(&Offline, CallBudget::new(u32::MAX))
}

/// The identity a checkout is audited and reported under: its GitHub origin,
/// or `local/<directory>` when it has none (no host read can use it).
pub fn checkout_identity(root: &Path) -> RepoId {
    remote::repository(root)
        .ok()
        .and_then(|identity| RepoId::parse(&identity).ok())
        .unwrap_or_else(|| RepoId {
            host: HostKind::GitHub,
            owner: "local".to_owned(),
            project: None,
            name: root.file_name().map_or_else(
                || "repository".to_owned(),
                |n| n.to_string_lossy().into_owned(),
            ),
        })
}

/// [`Files`] over the contents API of the host at one reference, for
/// `--fleet`, which has no checkout (SPEC-auditor.md, "Fleet"): the same
/// allowlist as [`LocalFiles`], one call per file or listing, each at most
/// 256 KiB. Build it over the audit's [`cached::Cached`] host, so a file the
/// rules read twice costs one call.
pub struct ContentsFiles<'a> {
    host: &'a dyn Host,
    repo: &'a RepoId,
    reference: &'a str,
}
impl<'a> ContentsFiles<'a> {
    pub fn new(host: &'a dyn Host, repo: &'a RepoId, reference: &'a str) -> Self {
        Self {
            host,
            repo,
            reference,
        }
    }
}
impl Files for ContentsFiles<'_> {
    fn read(&self, path: &str) -> Result<Option<String>> {
        if !allowed(path) {
            return refuse(format!(
                "Auditor file read refused: {path} is outside the auditor's path allowlist"
            ));
        }
        Ok(self
            .host
            .file_contents(self.repo, path, self.reference)?
            .map(|file| file.text))
    }
    fn list(&self, dir: &str) -> Result<Vec<String>> {
        if !LISTABLE.contains(&dir) {
            return refuse(format!(
                "Auditor listing refused: {dir} is not one of {}",
                LISTABLE.join(", ")
            ));
        }
        let entries = self
            .host
            .list_directory(self.repo, dir, self.reference)?
            .unwrap_or_default();
        let mut paths: Vec<String> = entries
            .into_iter()
            .filter(|e| e.kind == crate::host::types::EntryKind::File)
            .map(|e| format!("{dir}/{}", e.name))
            .collect();
        paths.sort();
        Ok(paths)
    }
    fn costs_calls(&self) -> bool {
        true
    }
}

/// The allowance of a rule when its files are read through `files`: under
/// `--fleet` the file reads too (SPEC-auditor.md, "Fleet file reads").
fn allowances(files: &dyn Files) -> fn(&str) -> u32 {
    if files.costs_calls() {
        rules::fleet_allowance
    } else {
        rules::allowance
    }
}

/// The counters' allowance over a checkout; none under `--fleet`, whose file
/// allowances leave the measures 13 calls, so the counters read what the
/// rules leave there (SPEC-auditor.md, "Counters").
fn counters_allowance(files: &dyn Files) -> u32 {
    if files.costs_calls() {
        0
    } else {
        counters::ALLOWANCE
    }
}

/// Holds back every rule's allowance and the counters' while the measures
/// read, when they fit what remains of `budget` (SPEC-auditor.md, "Block
/// allowances" and "Counters").
fn hold_allowances(budget: &CallBudget, files: &dyn Files) {
    let allowance = allowances(files);
    let allowances: u32 =
        REGISTRY.iter().map(|r| allowance(r.id)).sum::<u32>() + counters_allowance(files);
    if allowances <= budget.limit().saturating_sub(budget.used()) {
        budget.hold(allowances);
    }
}

/// Audits the checkout at `root` as `repo` at `now`: measures (host reads only
/// when `remote`), every rule of the registry and `today`'s manual steps, and
/// the budget `host` spent.
/// The default branch is the host's when it can be read, `main` otherwise.
pub fn audit_checkout(
    root: &Path,
    host: &dyn Host,
    budget: &CallBudget,
    repo: &RepoId,
    now: chrono::NaiveDate,
    remote: bool,
    today: &Today<'_>,
) -> Result<report::Audited> {
    let files = LocalFiles::new(root);
    // One read cache for the whole audit: measures and rules share it.
    let cached = cached::Cached::new(host);
    let host: &dyn Host = &cached;
    hold_allowances(budget, &files);
    let default_branch = remote
        .then(|| host.repository(repo).ok())
        .flatten()
        .map_or_else(|| "main".to_owned(), |r| r.default_branch);
    audit_reading(
        &Cx {
            host,
            files: &files,
            repo,
            default_branch: &default_branch,
            now,
            budget,
            profile: Profile::P1,
            today: Some(today),
        },
        remote,
    )
}

/// Audits one repository of `--fleet` through the host only: the files come
/// from the contents API at `default_branch`, there is no diagnosis of today's
/// `doctor`, and the audit owns its read cache, dropped when it ends.
pub fn audit_remote(
    host: &dyn Host,
    budget: &CallBudget,
    repo: &RepoId,
    default_branch: &str,
    now: chrono::NaiveDate,
) -> Result<report::Audited> {
    let cached = cached::Cached::new(host);
    let files = ContentsFiles::new(&cached, repo, default_branch);
    hold_allowances(budget, &files);
    audit_reading(
        &Cx {
            host: &cached,
            files: &files,
            repo,
            default_branch,
            now,
            budget,
            profile: Profile::P1,
            today: None,
        },
        true,
    )
}

/// The measures, every rule and the counters over `cx`, whose host is the
/// audit's cache: the counters read last, from the listings already cached.
fn audit_reading(cx: &Cx<'_>, remote: bool) -> Result<report::Audited> {
    let budget = cx.budget;
    let measured = measures::measure(cx, remote)?;
    let audit = evaluate_reading(
        cx,
        &measured.dimensions,
        REGISTRY,
        counters_allowance(cx.files),
    );
    let counters = counters::count(cx, remote);
    Ok(report::Audited {
        repo: cx.repo.to_string(),
        now: cx.now,
        measured,
        audit,
        counters,
        budget: report::Budget {
            api_calls: budget.used(),
            limit: budget.limit(),
            exhausted: budget.used() >= budget.limit() || budget.refused(),
        },
    })
}
