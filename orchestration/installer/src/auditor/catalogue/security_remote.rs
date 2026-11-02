//! The remote `security.*` rules (SPEC-security.md slice 5, "Auditor rules
//! this module enables"; T13, #801): read through the host adapter, at the
//! levels of "Auditor standard v1, amended" (#873, rows added by #801).
//!
//! - `security.secret-scanning` (Bronze): secret scanning and push protection
//!   enabled, or, on a repository that is not public, the plan recorded as the
//!   risk `secret-scanning-unavailable-on-plan`: Secret Protection is never
//!   assumed (decision 2026-10-28, point 11) and `security-gate` is the gate.
//! - `security.private-vulnerability-reporting` (Bronze): enabled on a public
//!   repository; `not-required` elsewhere (#846).
//! - `security.secrets-full-history` and `security.bypass-unregistered`
//!   (Bronze) keep their static half, judged from today's `doctor` as every
//!   module rule, and add their remote half: the history claim of the latest
//!   default-branch run's secrets job log when the job is not the managed
//!   shape, and the ids of `vars.SECURITY_BYPASS` against the inventory.
//! - `security.scanner-stale` (Gold): every scanner a workflow pins by
//!   checksum or digest is at most 90 days behind its upstream's latest release.
//! - `security.attestation-verified`, `security.sbom-scanned` (Gold): wait for
//!   `delivery`, which attests and generates the SBOM.
use super::{
    baseline::{Origin, relabelled},
    posture::unread,
    waiting,
};
use crate::{
    auditor::{
        Cx, Files, WORKFLOWS,
        catalogue::ci_health::RECENT_RUNS,
        rules::{
            Block, Level, Milestone, Outcome, Probe, Profile, Remediation, Required, Rule, Status,
        },
        workflows,
    },
    host::{
        HostErrorKind, RepoId, Visibility,
        types::{RunFilter, SecurityToggle},
    },
    modules::security::{
        audit::secrets_job,
        exceptions::{BYPASS_VARIABLE, INVENTORY, Inventory},
        pins::{PINS, UPSTREAMS},
    },
};
use chrono::NaiveDate;
use serde_json::Value;
use std::collections::BTreeMap;

const ALL: Required = Required {
    profiles: &[Profile::P1, Profile::P2, Profile::P3],
    when: &[],
};
const SECURITY: &str = "security";
const DELIVERY: &str = "delivery";

/// The risk recorded where the plan lacks secret scanning.
pub const SECRET_SCANNING_RISK: &str = "secret-scanning-unavailable-on-plan";
/// How far behind its upstream a pin may fall.
pub const STALE_DAYS: i64 = 90;
/// The newest default-branch pushes searched for the secrets job.
pub const HISTORY_RUNS: usize = 3;

pub const SECURITY_SECRET_SCANNING: Rule = Rule {
    id: "security.secret-scanning",
    title: "Secret scanning with push protection",
    block: Block::Security,
    checks: "Secret scanning and push protection are enabled, or the repository is not public and the plan is recorded as the risk `secret-scanning-unavailable-on-plan`.",
    how: Probe::Remote { id: "repository" },
    level: Level::Bronze,
    required: ALL,
    remediation: Remediation::Module { id: SECURITY },
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: secret_scanning,
};

pub const SECURITY_PRIVATE_VULNERABILITY_REPORTING: Rule = Rule {
    id: "security.private-vulnerability-reporting",
    title: "Private vulnerability reporting",
    block: Block::Security,
    checks: "Private vulnerability reporting is enabled on a public repository; not required on a private one.",
    how: Probe::Remote {
        id: "private-vulnerability-reporting",
    },
    level: Level::Bronze,
    required: ALL,
    remediation: Remediation::Module { id: SECURITY },
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: private_vulnerability_reporting,
};

pub const SECURITY_SECRETS_FULL_HISTORY: Rule = Rule {
    id: "security.secrets-full-history",
    title: "Secrets scan covers full history",
    block: Block::Security,
    checks: "The secrets job has the managed shape that scans every push to the default branch and the full history against a reviewed baseline, or its latest default-branch run's log claims `history: full` or `history: pushed <range>`.",
    how: Probe::LocalFile { path: WORKFLOWS },
    level: Level::Bronze,
    required: ALL,
    remediation: Remediation::Module { id: SECURITY },
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: secrets_full_history,
};

pub const SECURITY_BYPASS_UNREGISTERED: Rule = Rule {
    id: "security.bypass-unregistered",
    title: "Bypasses registered",
    block: Block::Security,
    checks: "Every bypass of a scanning gate, `vars.SECURITY_BYPASS` ids included, has a matching entry in the inventory.",
    how: Probe::LocalFile { path: INVENTORY },
    level: Level::Bronze,
    required: ALL,
    remediation: Remediation::Module { id: SECURITY },
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: bypass_unregistered,
};

pub const SECURITY_SCANNER_STALE: Rule = Rule {
    id: "security.scanner-stale",
    title: "Scanner pins current",
    block: Block::Security,
    checks: "Every scanner a workflow pins by checksum or digest is at most 90 days behind its upstream's latest release.",
    how: Probe::Remote { id: "releases" },
    level: Level::Gold,
    required: ALL,
    remediation: Remediation::Module { id: SECURITY },
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: scanner_stale,
};

const fn waits(
    id: &'static str,
    title: &'static str,
    checks: &'static str,
    step: &'static str,
) -> Rule {
    Rule {
        id,
        title,
        block: Block::Security,
        checks,
        how: Probe::ManualStep {
            module: DELIVERY,
            step,
        },
        level: Level::Gold,
        required: ALL,
        remediation: Remediation::Module { id: DELIVERY },
        plan: None,
        feasible_by: Milestone::WaitsFor(DELIVERY),
        evaluate: waiting,
    }
}

pub const SECURITY_ATTESTATION_VERIFIED: Rule = waits(
    "security.attestation-verified",
    "Production image attested",
    "`gh attestation verify` succeeds for the digest of the latest production deployment.",
    "attestations",
);

pub const SECURITY_SBOM_SCANNED: Rule = waits(
    "security.sbom-scanned",
    "Attested SBOM scanned",
    "The release workflow scans the attested SBOM (`trivy sbom` or `osv-scanner scan --sbom`).",
    "sbom",
);

// --- secret scanning and private vulnerability reporting ---------------------------

pub(super) fn visibility_name(visibility: Visibility) -> &'static str {
    match visibility {
        Visibility::Public => "public",
        Visibility::Private => "private",
        Visibility::Internal => "internal",
    }
}

fn secret_scanning(cx: &Cx<'_>) -> Outcome {
    let settings = match cx.host.repository(cx.repo) {
        Ok(settings) => settings,
        Err(e) => return unread(&e),
    };
    let status = |s: &Option<String>| s.clone().unwrap_or_else(|| "not reported".to_owned());
    let evidence = format!(
        "secret scanning {}, push protection {}",
        status(&settings.secret_scanning),
        status(&settings.secret_scanning_push_protection)
    );
    let enabled = |s: &Option<String>| s.as_deref() == Some("enabled");
    if enabled(&settings.secret_scanning) && enabled(&settings.secret_scanning_push_protection) {
        return Outcome::passed([evidence]);
    }
    if settings.visibility != Visibility::Public {
        return Outcome::passed([
            evidence,
            format!(
                "risk {SECRET_SCANNING_RISK}: a {} repository needs Secret Protection (Team or Enterprise), which the installer never assumes; security-gate is the gate",
                visibility_name(settings.visibility)
            ),
        ]);
    }
    Outcome::failed([
        "Secret scanning available on this plan and not enabled".to_owned(),
        evidence,
    ])
}

fn private_vulnerability_reporting(cx: &Cx<'_>) -> Outcome {
    let settings = match cx.host.repository(cx.repo) {
        Ok(settings) => settings,
        Err(e) => return unread(&e),
    };
    if settings.visibility != Visibility::Public {
        return Outcome::not_required(format!(
            "a {} repository: private vulnerability reporting is required on public repositories only",
            visibility_name(settings.visibility)
        ));
    }
    match cx
        .host
        .security_toggle(cx.repo, SecurityToggle::PrivateVulnerabilityReporting)
    {
        Ok(true) => Outcome::passed(["private vulnerability reporting enabled"]),
        Ok(false) => {
            Outcome::failed(["Private vulnerability reporting off on a public repository"])
        }
        Err(e) if e.kind == HostErrorKind::NotFound => Outcome::not_required(e.message),
        Err(e) => unread(&e),
    }
}

// --- the remote halves ----------------------------------------------------------------

/// `outcome` with one more evidence line, or its reason extended.
fn noted(mut outcome: Outcome, note: impl Into<String>) -> Outcome {
    let note = note.into();
    match outcome.status {
        Status::Passed | Status::Failed => outcome.evidence.push(note),
        Status::Unavailable | Status::NotRequired => {
            outcome.reason = Some(match outcome.reason.take() {
                Some(reason) => format!("{reason}; {note}"),
                None => note,
            })
        }
    }
    outcome
}

/// The names the jobs API reports for the secrets jobs of every readable
/// workflow: the job's `name`, or its id when it has none.
fn secrets_job_names(files: &dyn Files) -> Vec<String> {
    let mut names: Vec<String> = workflows::read_all(files)
        .into_iter()
        .filter_map(|(_, parsed)| parsed.ok())
        .flat_map(|wf| wf.jobs)
        .filter(secrets_job)
        .map(|job| job.name.clone().unwrap_or(job.id))
        .collect();
    names.sort();
    names.dedup();
    names
}

/// What one log line claims: `Some(true)` for `history: full` or a push's own
/// range (`history: pushed <before>..<after>`, #1253), `Some(false)` for a
/// pull request range, `None` for anything else. The timestamp GitHub prefixes
/// is dropped, so the script echoed in the log (`echo "history: full"`) never counts.
fn history_claim(line: &str) -> Option<(bool, &str)> {
    let line = line.trim_start_matches('\u{feff}').trim_end();
    let text = match line.split_once(' ') {
        Some((stamp, rest))
            if stamp.len() >= 20 && stamp.ends_with('Z') && stamp.as_bytes()[4] == b'-' =>
        {
            rest
        }
        _ => line,
    };
    let claim = text.strip_prefix("history: ")?;
    let is_range = |r: &str| r.contains("..") && !r.contains(char::is_whitespace);
    if claim == "full" || claim.strip_prefix("pushed ").is_some_and(is_range) {
        Some((true, claim))
    } else if is_range(claim) {
        Some((false, claim))
    } else {
        None
    }
}

/// Static half from today's `doctor`; when it is `unavailable` because the
/// secrets job is not the managed shape, the log of the newest default-branch
/// push run that has the job decides.
fn secrets_full_history(cx: &Cx<'_>) -> Outcome {
    let id = SECURITY_SECRETS_FULL_HISTORY.id;
    let outcome = relabelled(cx, id, Origin::Checkout);
    if outcome.status != Status::Unavailable {
        return outcome;
    }
    let names = secrets_job_names(cx.files);
    if names.is_empty() {
        return outcome;
    }
    let filter = RunFilter {
        branch: Some(cx.default_branch.to_owned()),
        event: Some("push".to_owned()),
        status: Some("completed".to_owned()),
        limit: Some(RECENT_RUNS),
        ..RunFilter::default()
    };
    let runs = match cx.host.workflow_runs(cx.repo, &filter) {
        Ok(runs) => runs,
        Err(e) => {
            return noted(
                outcome,
                format!(
                    "remote half not read: {}",
                    unread(&e).reason.unwrap_or_default()
                ),
            );
        }
    };
    for run in runs.iter().take(HISTORY_RUNS) {
        let jobs = match cx.host.jobs(cx.repo, run.id) {
            Ok(jobs) => jobs,
            Err(e) => {
                return noted(
                    outcome,
                    format!(
                        "remote half not read: {}",
                        unread(&e).reason.unwrap_or_default()
                    ),
                );
            }
        };
        let Some(job) = jobs.iter().find(|j| names.contains(&j.name)) else {
            continue;
        };
        let log = match cx.host.job_log(cx.repo, job.id) {
            Ok(log) => log,
            Err(e) => {
                return noted(
                    outcome,
                    format!(
                        "remote half not read: {}",
                        unread(&e).reason.unwrap_or_default()
                    ),
                );
            }
        };
        let at = format!("job {} of run {}", job.name, run.id);
        return match log.lines().find_map(history_claim) {
            Some((true, claim)) => Outcome::passed([format!("{at} claims history: {claim}")]),
            Some((false, _)) => Outcome::failed([
                "Secrets scan covers pull-request diffs only".to_owned(),
                format!("{at} claims a commit range on a push to the default branch"),
            ]),
            None => noted(outcome, format!("the log of {at} carries no history claim")),
        };
    }
    noted(
        outcome,
        format!(
            "no secrets job ({}) in the latest {} default-branch push runs",
            names.join(", "),
            runs.len().min(HISTORY_RUNS)
        ),
    )
}

/// Static half from today's `doctor`, then the ids `vars.SECURITY_BYPASS`
/// names: each must have an entry in the inventory (its kind and expiry are
/// `security-gate`'s and `bypass-expired`'s).
fn bypass_unregistered(cx: &Cx<'_>) -> Outcome {
    let outcome = relabelled(cx, SECURITY_BYPASS_UNREGISTERED.id, Origin::Checkout);
    if !matches!(outcome.status, Status::Passed | Status::Failed) {
        return outcome;
    }
    let raw = match cx.host.repo_variable(cx.repo, BYPASS_VARIABLE) {
        Ok(Some(raw)) => raw,
        Ok(None) => return noted(outcome, format!("{BYPASS_VARIABLE} is unset")),
        Err(e) => {
            return noted(
                outcome,
                format!(
                    "remote half not read: {}",
                    unread(&e).reason.unwrap_or_default()
                ),
            );
        }
    };
    let ids: Option<Vec<String>> = if raw.trim().is_empty() {
        Some(Vec::new())
    } else {
        serde_json::from_str::<Value>(&raw).ok().and_then(|v| {
            v.as_array()?
                .iter()
                .map(|id| id.as_str().filter(|s| !s.is_empty()).map(str::to_owned))
                .collect()
        })
    };
    let Some(ids) = ids else {
        let finding = format!("{BYPASS_VARIABLE} is not a JSON array of exception ids");
        return failed_with(outcome, vec![finding]);
    };
    let inventory = cx
        .files
        .read(INVENTORY)
        .ok()
        .flatten()
        .and_then(|text| Inventory::parse(&text));
    let registered = |id: &str| {
        inventory
            .as_ref()
            .is_some_and(|inv| inv.exceptions.iter().any(|e| e.id.as_deref() == Some(id)))
    };
    let findings: Vec<String> = ids
        .iter()
        .filter(|id| !registered(id))
        .map(|id| format!("Bypass {id} is not registered in security-exceptions.json"))
        .collect();
    if findings.is_empty() {
        noted(
            outcome,
            format!("{BYPASS_VARIABLE} names {} registered id(s)", ids.len()),
        )
    } else {
        failed_with(outcome, findings)
    }
}

/// A failure carrying the static findings, if any, then `findings`.
fn failed_with(outcome: Outcome, findings: Vec<String>) -> Outcome {
    let mut evidence = if outcome.status == Status::Failed {
        outcome.evidence
    } else {
        Vec::new()
    };
    evidence.extend(findings);
    Outcome::failed(evidence)
}

// --- scanner-stale ------------------------------------------------------------------

/// The scanners the workflows pin: `TOOL_NAME`/`TOOL_VERSION` of the checksum
/// install fragment, and the Semgrep image tag of `SEMGREP_IMAGE`; only tools
/// with a known upstream. Sorted by tool.
pub fn pinned_scanners(files: &dyn Files) -> BTreeMap<&'static str, String> {
    let known = |name: &str| {
        UPSTREAMS
            .iter()
            .find(|(tool, _)| *tool == name)
            .map(|(t, _)| *t)
    };
    let mut out = BTreeMap::new();
    for (_, parsed) in workflows::read_all(files) {
        let Ok(wf) = parsed else { continue };
        for step in wf.jobs.iter().flat_map(|j| &j.steps) {
            if let (Some(name), Some(version)) =
                (step.env.get("TOOL_NAME"), step.env.get("TOOL_VERSION"))
                && let Some(tool) = known(name)
            {
                out.insert(tool, version.trim_start_matches('v').to_owned());
            }
            if let Some(image) = step.env.get("SEMGREP_IMAGE")
                && let Some(rest) = image.split("semgrep/semgrep:").nth(1)
                && let Some(tool) = known("semgrep")
            {
                let version = rest.split('@').next().unwrap_or("");
                if !version.is_empty() {
                    out.insert(tool, version.trim_start_matches('v').to_owned());
                }
            }
        }
    }
    out
}

fn date(text: &str) -> Option<NaiveDate> {
    NaiveDate::parse_from_str(text.get(..10)?, "%Y-%m-%d").ok()
}

fn scanner_stale(cx: &Cx<'_>) -> Outcome {
    let pinned = pinned_scanners(cx.files);
    if pinned.is_empty() {
        return Outcome::not_required("no workflow pins a scanner by checksum or digest");
    }
    let mut evidence = Vec::new();
    let mut findings = Vec::new();
    for (tool, version) in &pinned {
        let upstream = UPSTREAMS
            .iter()
            .find(|(t, _)| t == tool)
            .map(|(_, repo)| *repo)
            .expect("pinned_scanners keeps known tools");
        let Ok(repo) = RepoId::parse(upstream) else {
            return Outcome::unavailable(format!("{upstream} is not a repository"));
        };
        let latest = match cx.host.latest_release(&repo) {
            Ok(release) => release,
            Err(e) => return unread(&e),
        };
        let latest_version = latest.tag_name.trim_start_matches('v');
        if latest_version == version {
            evidence.push(format!(
                "{tool} {version} is the latest release of {upstream}"
            ));
            continue;
        }
        let local = PINS
            .iter()
            .find(|p| p.name == *tool && p.version == version)
            .and_then(|p| date(p.released));
        let pinned_date = match local {
            Some(d) => d,
            None => match cx.host.release_by_tag(&repo, &format!("v{version}")) {
                Ok(release) => match date(&release.published_at) {
                    Some(d) => d,
                    None => {
                        return Outcome::unavailable(format!(
                            "{tool} {version}: no publication date"
                        ));
                    }
                },
                Err(e) => return unread(&e),
            },
        };
        let Some(latest_date) = date(&latest.published_at) else {
            return Outcome::unavailable(format!(
                "{upstream}: the latest release has no publication date"
            ));
        };
        let days = (latest_date - pinned_date).num_days();
        if days > STALE_DAYS {
            findings.push(format!(
                "{tool} pin {version} is {days} days behind {latest_version}"
            ));
        } else {
            evidence.push(format!(
                "{tool} pin {version} is {days} days behind {latest_version}"
            ));
        }
    }
    if findings.is_empty() {
        Outcome::passed(evidence)
    } else {
        Outcome::failed(findings)
    }
}
