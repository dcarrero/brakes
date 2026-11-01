//! The `doctor` lines of agent-guardrails (SPEC-agent-guardrails.md, Doctor and
//! auditor rules; #744). The installer registers the hook and the deny rules in
//! `.claude/settings.json` as managed entries (#748); the probes here read that
//! file so `doctor` warns, as the rules' findings, when a hand-edit dropped them.
//! Nothing here runs `verify`: the baked command is read from the hook's text and
//! compared with `project.json`.
use super::{
    AGENT_GUARDRAILS, SETTINGS_PATH as SETTINGS, STOP_VERIFY_PATH, TECHNICAL_DEBT,
    TECHNICAL_DEBT_PATH,
    audit::{
        CROSS_REVIEW, HELDOUT_DENIED, PROTECTED_PATHS, TECHNICAL_DEBT as TECHNICAL_DEBT_RULE,
        UNATTENDED_GATED, heldout_enabled,
    },
    heldout_deny, review, unattended,
};
use crate::Result;
use crate::auditor::workflows::{self, warn};
use crate::engine::{
    answers,
    manual::{self, NoRunner, Probe, ProbeResult},
};
use crate::modules::ci_baseline;
use crate::profile::Profile;
use chrono::NaiveDate;
use serde_json::json;
use std::path::Path;

/// The deny rules whose presence stands for the fragment being registered: the
/// rules anchored at the filesystem root (#1309, #1314), so an install that still
/// holds the `./`-anchored ones is reported.
const REQUIRED_DENY: [&str; 3] = [
    "Read(//**/.env)",
    "Read(//**/secrets/**)",
    "Edit(//**/.agent-setup/lock.json)",
];
/// The deny rule `agents.protected-paths` adds in P2 and P3 (owner, 2026-10-28, point 10),
/// anchored at the filesystem root since #1314.
const WORKFLOWS_DENY: &str = "Edit(//**/.github/workflows/**)";
/// A dated "None yet" older than this is a Silver finding of `agents.technical-debt`.
const NONE_YET_DAYS: i64 = 90;
/// The heredoc delimiter of `templates/agent-guardrails/stop_verify.sh` that
/// encloses the baked `verify`.
const VERIFY_DELIMITER: &str = "AGENTIC_SETUP_VERIFY";

pub const STOP_UNREGISTERED: &str = "WARNING: Stop verify hook is not registered in .claude/settings.json (hooks.Stop, stop_verify.sh)";
pub const DENY_UNREGISTERED: &str = "WARNING: Deny rules for secrets are not registered in .claude/settings.json (permissions.deny)";

/// The secrets and the lock: what `agents.deny-secrets` reads.
fn deny_probe() -> Probe {
    denies(REQUIRED_DENY.iter().map(|rule| json!(rule)).collect())
}

fn denies(contains_all: Vec<serde_json::Value>) -> Probe {
    Probe::JsonPointerContainsAll {
        path: SETTINGS.to_owned(),
        pointer: "/permissions/deny".to_owned(),
        contains_all,
    }
}

fn stop_probe() -> Probe {
    Probe::JsonPointerContains {
        path: SETTINGS.to_owned(),
        under: "/hooks/Stop".to_owned(),
        contains: "stop_verify.sh".to_owned(),
    }
}

/// The `doctor` findings of an installed agent-guardrails: one `WARNING` per
/// registration missing from `.claude/settings.json` (`agents.deny-secrets`,
/// `agents.stop-verify`), a `NOT READY` finding (unprefixed, as `Diagnosis`
/// expects) when the hook's baked command is not the `verify` that `project.json`
/// declares, then `agents.protected-paths` and `agents.technical-debt` (#746).
pub fn findings(root: &Path, profile: &Profile, today: NaiveDate) -> Result<Vec<String>> {
    let registered = |probe: &Probe| {
        matches!(
            manual::run(root, probe, &NoRunner),
            ProbeResult::Verified(_)
        )
    };
    let mut findings = Vec::new();
    let hook = crate::read(root, STOP_VERIFY_PATH)?;
    if hook.is_some() && !registered(&stop_probe()) {
        findings.push(STOP_UNREGISTERED.to_owned());
    }
    if !registered(&deny_probe()) {
        findings.push(DENY_UNREGISTERED.to_owned());
    }
    let declared = profile.value["commands"]["verify"].as_str().unwrap_or("");
    if let Some(baked) = hook.as_deref().and_then(baked_verify)
        && baked != declared
    {
        findings.push(format!(
            "Stop verify hook {STOP_VERIFY_PATH} runs `{baked}` but project.json declares `{declared}`; re-run install"
        ));
    }
    let recorded = answers::recorded(root, AGENT_GUARDRAILS)?;
    let tier = recorded
        .as_ref()
        .map(|file| file.tier().to_owned())
        .unwrap_or_else(|| answers::DEFAULT_TIER.to_owned());
    if tier != "P1" && !registered(&denies(vec![json!(WORKFLOWS_DENY)])) {
        findings.push(warn(
            PROTECTED_PATHS,
            format!("{SETTINGS} permissions.deny lacks {WORKFLOWS_DENY} (profile {tier})"),
        ));
    }
    // A placeholder names no path: the entry protects nothing (#1229).
    let protected = recorded
        .as_ref()
        .and_then(|file| file.answers.get("protected_paths")?.as_array().cloned())
        .unwrap_or_default();
    for path in protected
        .iter()
        .filter_map(serde_json::Value::as_str)
        .filter(|p| ci_baseline::scope::unresolved_placeholder(p))
    {
        findings.push(warn(
            PROTECTED_PATHS,
            format!(
                "protected_paths entry {path} carries an unresolved placeholder; re-run install"
            ),
        ));
    }
    if heldout_enabled(&crate::auditor::LocalFiles::new(root)) {
        let [edit, read] = heldout_deny(&recorded_heldout_dir(root)?);
        for (rule, can) in [(edit, "edit"), (read, "read and search")] {
            if !registered(&denies(vec![json!(rule)])) {
                findings.push(warn(
                    HELDOUT_DENIED,
                    format!(
                        "{SETTINGS} permissions.deny lacks {rule}; agents can {can} the held-out tests (re-run install)"
                    ),
                ));
            }
        }
    }
    findings.extend(technical_debt(
        crate::read(root, TECHNICAL_DEBT_PATH)?.as_deref(),
        today,
        crate::profile::guide_verification_days(&profile.value) as i64,
    ));
    let answered = recorded
        .as_ref()
        .is_none_or(|file| review::reviewer(&file.answers).is_some());
    findings.extend(cross_review(root, answered));
    let unattended = recorded
        .as_ref()
        .is_some_and(|file| unattended::enabled(&file.answers));
    if unattended && crate::read(root, unattended::WORKFLOW_PATH)?.is_none() {
        findings.push(warn(
            UNATTENDED_GATED,
            format!(
                "unattended is true but {} is missing; re-run install",
                unattended::WORKFLOW_PATH
            ),
        ));
    }
    Ok(findings)
}

/// ci-baseline's recorded `heldout_dir`, normalised as it renders it; its default
/// when unanswered or refused (ci-baseline refuses that answer at plan time).
fn recorded_heldout_dir(root: &Path) -> Result<String> {
    let answer = answers::recorded(root, ci_baseline::CI_BASELINE)?
        .and_then(|file| file.answers.get("heldout_dir")?.as_str().map(str::to_owned));
    Ok(answer
        .and_then(|dir| ci_baseline::model::heldout_dir(&dir).ok())
        .unwrap_or_else(|| ci_baseline::DEFAULT_HELDOUT_DIR.to_owned()))
}

/// `agents.cross-review` (#940, #969): a reviewer is answered and the aggregate of
/// a workflow (`required`, or `agentic-required` under `workflow: existing`) needs
/// both the `cross-review-model` and the `cross-review` job. The remote half (its
/// last pull-request run concluded) waits for the auditor's run reader.
fn cross_review(root: &Path, answered: bool) -> Option<String> {
    if !answered {
        return Some(warn(
            CROSS_REVIEW,
            "review_family is none; no other model family reviews pull requests (configure --set review_family=codex, claude or deepseek)",
        ));
    }
    // Both jobs must be in an aggregate's `needs` ("CI hardening for agent
    // workflows"); the finding names the first one missing.
    let workflows: Vec<_> = workflows::read_all(&crate::auditor::LocalFiles::new(root))
        .into_iter()
        .filter_map(|(_, parsed)| parsed.ok())
        .collect();
    let needed = |id: &str| {
        workflows.iter().any(|wf| {
            ["required", "agentic-required"].iter().any(|aggregate| {
                wf.job(aggregate)
                    .is_some_and(|job| job.needs.iter().any(|n| n == id))
            })
        })
    };
    [review::CROSS_REVIEW_MODEL, review::CROSS_REVIEW]
        .into_iter()
        .find(|id| !needed(id))
        .map(|id| {
            warn(
                CROSS_REVIEW,
                format!(
                    "no required or agentic-required job in {} needs {id}; re-run install",
                    crate::auditor::WORKFLOWS
                ),
            )
        })
}

/// `agents.technical-debt`: the file exists and carries a `Last verified` date
/// no older than `bound` days (Bronze; the seed is the project's, so its date is
/// this rule's and never setup-core's `guides-verified`, #1172); it differs from
/// the seed and no dated "None yet" is older than 90 days (Silver).
fn technical_debt(text: Option<&str>, today: NaiveDate, bound: i64) -> Vec<String> {
    let Some(text) = text else {
        return vec![warn(
            TECHNICAL_DEBT_RULE,
            format!("{TECHNICAL_DEBT_PATH} is missing; re-run install to seed it"),
        )];
    };
    let mut out = Vec::new();
    match crate::last_verified(text) {
        None => out.push(warn(
            TECHNICAL_DEBT_RULE,
            format!(
                "{TECHNICAL_DEBT_PATH} has no Last verified date; re-read it and add Last verified: YYYY-MM-DD"
            ),
        )),
        Some(date) if (today - date).num_days() > bound => out.push(warn(
            TECHNICAL_DEBT_RULE,
            format!(
                "{TECHNICAL_DEBT_PATH} not verified for {} days; re-read it and bump Last verified",
                (today - date).num_days()
            ),
        )),
        Some(_) => {}
    }
    if text == TECHNICAL_DEBT {
        out.push(warn(
            TECHNICAL_DEBT_RULE,
            format!(
                "Silver: {TECHNICAL_DEBT_PATH} still equals the seed; record the patterns not to copy"
            ),
        ));
        return out;
    }
    let oldest = text
        .match_indices("None yet (")
        .filter_map(|(at, marker)| text.get(at + marker.len()..at + marker.len() + 10))
        .filter_map(|date| NaiveDate::parse_from_str(date, "%Y-%m-%d").ok())
        .min();
    if let Some(oldest) = oldest
        && (today - oldest).num_days() > NONE_YET_DAYS
    {
        out.push(warn(
            TECHNICAL_DEBT_RULE,
            format!(
                "Silver: {TECHNICAL_DEBT_PATH} says \"None yet\" since {oldest}, more than {NONE_YET_DAYS} days ago; review it"
            ),
        ));
    }
    out
}

/// The command baked into a rendered hook: the lines of its quoted heredoc.
/// `None` when the delimiters are gone (an edited hook is managed-content drift).
fn baked_verify(hook: &str) -> Option<String> {
    let opening = format!("<<'{VERIFY_DELIMITER}'");
    let mut lines = hook.lines().skip_while(|line| !line.ends_with(&opening));
    lines.next()?;
    let mut body = Vec::new();
    for line in lines {
        if line == VERIFY_DELIMITER {
            return Some(body.join("\n"));
        }
        body.push(line);
    }
    None
}
