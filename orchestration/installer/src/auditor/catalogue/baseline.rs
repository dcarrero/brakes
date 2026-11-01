//! Baseline rules: what a stranger needs to tell what the repository is, read
//! from local files; every finding today's `doctor` and `remote::inspect_report`
//! produce, re-labelled through [`FINDINGS`] and never re-implemented; and every
//! manual step of an installed module, judged from the engine's probe (#730).
use crate::{
    LOCK, PROFILE,
    auditor::{
        Cx, WORKFLOWS,
        rules::{
            Block, Criticality, Level, Milestone, Outcome, Probe, Profile, REGISTRY, Remediation,
            Required, Rule, Status,
        },
    },
    engine::{StepReport, StepState},
};
use serde_json::{Map, Value};
use std::{
    collections::BTreeMap,
    sync::{Mutex, PoisonError},
};

const ALL: Required = Required {
    profiles: &[Profile::P1, Profile::P2, Profile::P3],
    when: &[],
};

pub const PURPOSE_DECLARED: Rule = Rule {
    id: "baseline.purpose-declared",
    title: "Purpose declared",
    block: Block::Baseline,
    checks: "`.agent-setup/project.json` declares a non-empty `purpose`.",
    how: Probe::LocalFile { path: PROFILE },
    level: Level::Basic,
    required: ALL,
    remediation: Remediation::Manual {
        step: "declare-purpose",
        instructions: "Write one sentence in `purpose` of .agent-setup/project.json.",
    },
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: purpose_declared,
};

pub const VERIFY_DECLARED: Rule = Rule {
    id: "baseline.verify-declared",
    title: "Verify command declared",
    block: Block::Baseline,
    checks: "`.agent-setup/project.json` declares `commands.verify`.",
    how: Probe::LocalFile { path: PROFILE },
    level: Level::Basic,
    required: ALL,
    remediation: Remediation::Manual {
        step: "declare-verify",
        instructions: "Declare the project's own command in `commands.verify` of .agent-setup/project.json.",
    },
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: verify_declared,
};

pub const CRITICALITY_DECLARED: Rule = Rule {
    id: "baseline.criticality-declared",
    title: "Criticality declared",
    block: Block::Baseline,
    checks: "`.agent-setup/project.json` declares `criticality` as internal, customers or personal-data-or-payments.",
    how: Probe::LocalFile { path: PROFILE },
    level: Level::Basic,
    required: ALL,
    remediation: Remediation::Manual {
        step: "declare-criticality",
        instructions: "Set `criticality` in .agent-setup/project.json to internal, customers or personal-data-or-payments.",
    },
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: criticality_declared,
};

#[cfg(feature = "setup-core")]
pub const SETUP_INSTALLED: Rule = Rule {
    id: "baseline.setup-installed",
    title: "Setup installed",
    block: Block::Baseline,
    checks: "`.agent-setup/lock.json` records the installed setup; without it the rule is not required.",
    how: Probe::Lock,
    level: Level::Basic,
    required: ALL,
    remediation: Remediation::Module { id: "setup-core" },
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: setup_installed,
};

/// The profile as a JSON object, or the failed outcome that says why not.
fn profile(cx: &Cx<'_>) -> Result<Map<String, Value>, Outcome> {
    json_object(cx, PROFILE)?.ok_or_else(|| Outcome::failed([format!("{PROFILE} missing")]))
}

fn json_object(cx: &Cx<'_>, path: &str) -> Result<Option<Map<String, Value>>, Outcome> {
    let text = match cx.files.read(path) {
        Ok(Some(text)) => text,
        Ok(None) => return Ok(None),
        Err(e) => return Err(Outcome::unavailable(format!("{path} unreadable: {e}"))),
    };
    match serde_json::from_str(&text) {
        Ok(Value::Object(map)) => Ok(Some(map)),
        _ => Err(Outcome::failed([format!("{path} is not a JSON object")])),
    }
}

fn purpose_declared(cx: &Cx<'_>) -> Outcome {
    let profile = match profile(cx) {
        Ok(p) => p,
        Err(outcome) => return outcome,
    };
    match profile
        .get("purpose")
        .and_then(Value::as_str)
        .map(str::trim)
    {
        Some(purpose) if !purpose.is_empty() => Outcome::passed([format!("purpose: {purpose}")]),
        _ => Outcome::failed([format!("purpose is empty in {PROFILE}")]),
    }
}

fn verify_declared(cx: &Cx<'_>) -> Outcome {
    let profile = match profile(cx) {
        Ok(p) => p,
        Err(outcome) => return outcome,
    };
    let verify = profile
        .get("commands")
        .and_then(|c| c.get("verify"))
        .and_then(Value::as_str)
        .map(str::trim);
    match verify {
        Some(command) if !command.is_empty() => {
            Outcome::passed([format!("commands.verify: {command}")])
        }
        _ => Outcome::failed([format!("commands.verify is not declared in {PROFILE}")]),
    }
}

fn criticality_declared(cx: &Cx<'_>) -> Outcome {
    let profile = match profile(cx) {
        Ok(p) => p,
        Err(outcome) => return outcome,
    };
    match profile.get("criticality") {
        None | Some(Value::Null) => Outcome::failed([format!(
            "criticality undeclared in {PROFILE} (audited as internal)"
        )]),
        Some(Value::String(name)) if Criticality::parse(name).is_some() => {
            Outcome::passed([format!("criticality: {name}")])
        }
        Some(other) => {
            let shown = other
                .as_str()
                .map_or_else(|| other.to_string(), str::to_owned);
            Outcome::failed([format!(
                "criticality {shown} is not one of {}",
                Criticality::NAMES.join(", ")
            )])
        }
    }
}

#[cfg(feature = "setup-core")]
fn setup_installed(cx: &Cx<'_>) -> Outcome {
    match json_object(cx, LOCK) {
        Ok(Some(_)) => Outcome::passed([format!("{LOCK} present")]),
        Ok(None) => Outcome::not_required("setup not installed"),
        Err(outcome) => outcome,
    }
}

// --- today's doctor findings (#730) ---------------------------------------------------

/// Which rule a finding is: a rule of the registry, or the module rule id the
/// finding itself carries (`WARNING: ci.<id>: …`, likewise `security.`, `stack.`,
/// `agents.` and `qa.`), a rule of its module's block since #873 (`catalogue::modules`)
/// unless the allocation leaves it a warning with no level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relabel {
    Rule(&'static str),
    Own,
}

/// Every finding of today's `doctor` and `remote::inspect_report`, as a pattern
/// (`*` matches any text, newlines included) and the rule it is. The first
/// matching row wins; `tests/auditor_rules.rs` fails on a finding no row
/// matches. Levels follow decision "Auditor standard v1", point 1: a `NOT
/// READY` finding is Basic, a `WARNING` Bronze, unless the allocation table
/// names its rule (`operations.runbook-per-alert` is today's `alerts.rs`; the
/// agent-guardrails registrations are `agents.*` and pinned actions
/// `posture.actions-pinned`, #873).
pub static FINDINGS: &[(&str, Relabel)] = &[
    // The profile and the lock, which the first local rules already judge.
    (
        "Setup not installed: project profile missing",
        Relabel::Rule("baseline.purpose-declared"),
    ),
    (
        "Project purpose missing",
        Relabel::Rule("baseline.purpose-declared"),
    ),
    (
        "Verification command missing",
        Relabel::Rule("baseline.verify-declared"),
    ),
    #[cfg(feature = "setup-core")]
    (
        "Setup lock missing",
        Relabel::Rule("baseline.setup-installed"),
    ),
    // The conventions and the profile's fields.
    #[cfg(feature = "setup-core")]
    (
        "Convention reference missing: *",
        Relabel::Rule(CONVENTIONS_RESOLVED.id),
    ),
    #[cfg(feature = "setup-core")]
    (
        "Convention without a decision: *",
        Relabel::Rule(CONVENTIONS_RESOLVED.id),
    ),
    #[cfg(feature = "setup-core")]
    (
        "Convention decision does not resolve: *",
        Relabel::Rule(CONVENTIONS_RESOLVED.id),
    ),
    #[cfg(feature = "setup-core")]
    (
        "Convention points at a * decision: *",
        Relabel::Rule(CONVENTIONS_RESOLVED.id),
    ),
    (
        "Obsolete profile field: *",
        Relabel::Rule(PROFILE_CURRENT.id),
    ),
    // Alerts as code (`alerts.rs`).
    (
        "Unrecognised alert file *",
        Relabel::Rule("operations.runbook-per-alert"),
    ),
    (
        "Alert * in * missing *",
        Relabel::Rule("operations.runbook-per-alert"),
    ),
    (
        "Alert * in * runbook not found: *",
        Relabel::Rule("operations.runbook-per-alert"),
    ),
    (
        "Runbooks directory missing: *",
        Relabel::Rule("operations.runbook-per-alert"),
    ),
    // The installed setup, checked against the lock.
    #[cfg(feature = "setup-core")]
    (
        "WARNING: Decisions index stale: *",
        Relabel::Rule(DECISIONS_INDEX_CURRENT.id),
    ),
    #[cfg(feature = "setup-core")]
    (
        "Engineering guide not installed; update setup: *",
        Relabel::Rule(GUIDES_INSTALLED.id),
    ),
    #[cfg(feature = "setup-core")]
    (
        "Retired guide still installed; update setup: *",
        Relabel::Rule(GUIDES_INSTALLED.id),
    ),
    (
        "Installed source was uncommitted; not a release baseline",
        Relabel::Rule(RELEASE_BASELINE.id),
    ),
    (
        "Managed content drift: *",
        Relabel::Rule(MANAGED_CONTENT_INTACT.id),
    ),
    (
        "Managed entries drift: *",
        Relabel::Rule(MANAGED_CONTENT_INTACT.id),
    ),
    #[cfg(feature = "setup-core")]
    (
        "Guide verification date missing: *",
        Relabel::Rule(GUIDES_VERIFIED.id),
    ),
    #[cfg(feature = "setup-core")]
    (
        "Guide not verified for * days: *",
        Relabel::Rule(GUIDES_VERIFIED.id),
    ),
    #[cfg(feature = "setup-core")]
    (
        "Entrypoint does not reflect project profile: *",
        Relabel::Rule(ENTRYPOINTS_CURRENT.id),
    ),
    // agent-guardrails' registrations and baked command (#873, point 3).
    (
        "WARNING: Stop verify hook is not registered in *",
        Relabel::Rule("agents.stop-verify"),
    ),
    (
        "WARNING: Deny rules for secrets are not registered in *",
        Relabel::Rule("agents.deny-secrets"),
    ),
    (
        "Stop verify hook * runs `*` but project.json declares `*`; re-run install",
        Relabel::Rule("agents.stop-verify"),
    ),
    // The checkout, managed or not.
    #[cfg(feature = "setup-core")]
    (
        "Existing placeholder guidance needs review: *",
        Relabel::Rule(PLACEHOLDERS_REVIEWED.id),
    ),
    (
        "WARNING: Merge guard hook is not registered in *",
        Relabel::Rule(MERGE_GUARD_REGISTERED.id),
    ),
    // ci-baseline's pinned-actions check, under the one id kept (#873, point 3).
    (
        "WARNING: posture.actions-pinned: *",
        Relabel::Rule("posture.actions-pinned"),
    ),
    // The static rules modules declare, each a rule of its own id (#873).
    ("WARNING: ci.*", Relabel::Own),
    ("WARNING: security.*", Relabel::Own),
    ("WARNING: stack.*", Relabel::Own),
    ("WARNING: agents.*", Relabel::Own),
    ("WARNING: qa.*", Relabel::Own),
    // `remote::inspect_report`: whether it could read the repository at all.
    (
        "Remote diagnosis refuses repositories outside *",
        Relabel::Rule(REMOTE_READABLE.id),
    ),
    (
        "Remote diagnosis needs an unambiguous GitHub origin repository.",
        Relabel::Rule(REMOTE_READABLE.id),
    ),
    (
        "The repository default branch could not be read*",
        Relabel::Rule(REMOTE_READABLE.id),
    ),
    // Its protection facts against the declared required checks.
    (
        "Default branch is not protected.",
        Relabel::Rule(BRANCH_PROTECTION_MATCHES.id),
    ),
    (
        "The default branch *",
        Relabel::Rule(BRANCH_PROTECTION_MATCHES.id),
    ),
    (
        "The project has no valid declared required CI checks.",
        Relabel::Rule(BRANCH_PROTECTION_MATCHES.id),
    ),
    // Its sample of the latest CI cycles against the declared CI policy.
    (
        "The project has no declared CI policy *",
        Relabel::Rule(CI_POLICY_MET.id),
    ),
    ("The CI *", Relabel::Rule(CI_POLICY_MET.id)),
    ("The declared CI tiers *", Relabel::Rule(CI_POLICY_MET.id)),
    (
        "Recent CI runs could not be read*",
        Relabel::Rule(CI_POLICY_MET.id),
    ),
    ("No recent * CI cycle *", Relabel::Rule(CI_POLICY_MET.id)),
    ("The latest *", Relabel::Rule(CI_POLICY_MET.id)),
    (
        "A workflow in the latest *",
        Relabel::Rule(CI_POLICY_MET.id),
    ),
    ("Jobs in the latest *", Relabel::Rule(CI_POLICY_MET.id)),
    ("The Scope job claims *", Relabel::Rule(CI_POLICY_MET.id)),
    ("A shard ran *", Relabel::Rule(CI_POLICY_MET.id)),
    (
        "The shard * in the latest *",
        Relabel::Rule(CI_POLICY_MET.id),
    ),
    ("Lint *", Relabel::Rule(CI_POLICY_MET.id)),
];

/// The rule id `finding` is, by the first row of [`FINDINGS`] that matches it;
/// `None` for a finding no row knows (a gap the completeness test catches).
pub fn relabel(finding: &str) -> Option<String> {
    let (_, relabel) = FINDINGS
        .iter()
        .find(|(pattern, _)| matches(pattern, finding))?;
    match relabel {
        Relabel::Rule(id) => Some((*id).to_owned()),
        Relabel::Own => {
            let rest = finding.strip_prefix(WARNING)?;
            rest.split_once(':').map(|(id, _)| id.to_owned())
        }
    }
}

const WARNING: &str = "WARNING: ";

/// Whether `text` matches `pattern`, whose `*` stands for any text.
fn matches(pattern: &str, text: &str) -> bool {
    let mut parts = pattern.split('*');
    let first = parts.next().unwrap_or_default();
    let Some(mut rest) = text.strip_prefix(first) else {
        return false;
    };
    let mut parts: Vec<&str> = parts.collect();
    let Some(last) = parts.pop() else {
        return rest.is_empty();
    };
    for part in parts {
        match rest.find(part) {
            Some(at) => rest = &rest[at + part.len()..],
            None => return false,
        }
    }
    rest.ends_with(last)
}

/// Where a re-labelled finding comes from, which decides when its rule can say
/// nothing: a managed rule needs the lock, a remote one `doctor --remote`, a
/// module rule the checkout `doctor` evaluates it in (#873).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Any checkout, managed or not.
    Checkout,
    /// Only a checkout the setup is installed in: `not-required` without a lock.
    Managed,
    /// `remote::inspect_report`, under `doctor --remote`.
    Remote,
    /// A checkout with a workflow file: `not-required` without one.
    Workflows,
    /// A checkout whose lock records the module: `not-required` otherwise.
    Installed(&'static str),
}

/// Why `origin` says nothing about this checkout, as the outcome to report.
fn outside(cx: &Cx<'_>, origin: Origin) -> Option<Outcome> {
    match origin {
        Origin::Checkout | Origin::Remote => None,
        Origin::Managed => match cx.files.read(LOCK) {
            Ok(Some(_)) => None,
            Ok(None) => Some(Outcome::not_required("setup not installed")),
            Err(e) => Some(Outcome::unavailable(format!("{LOCK} unreadable: {e}"))),
        },
        Origin::Workflows => match cx.files.list(WORKFLOWS) {
            Ok(paths)
                if paths
                    .iter()
                    .any(|p| p.ends_with(".yml") || p.ends_with(".yaml")) =>
            {
                None
            }
            Ok(_) => Some(Outcome::not_required(format!(
                "no workflow under {WORKFLOWS}"
            ))),
            Err(e) => Some(Outcome::unavailable(format!("{WORKFLOWS} unreadable: {e}"))),
        },
        Origin::Installed(module) => match json_object(cx, LOCK) {
            Ok(Some(lock)) if lock.get("modules").and_then(|m| m.get(module)).is_some() => None,
            Ok(_) => Some(Outcome::not_required(format!("{module} not installed"))),
            Err(outcome) => Some(outcome),
        },
    }
}

/// The reason a plan-refusal finding of `remote::inspect_report` gives,
/// `requires plan …` (#1164); `None` for any other finding.
fn plan_refusal(finding: &str) -> Option<&str> {
    finding
        .strip_prefix(crate::remote::PLAN_REFUSED_SUBJECT)
        .filter(|reason| reason.starts_with("requires plan "))
}

/// Why the rules that re-label today's `doctor` are not required under `--fleet`.
pub const NO_CHECKOUT: &str = "no checkout under --fleet";

/// The outcome of the rule `id` from today's findings: failed with every
/// finding [`relabel`] gives it (without `WARNING: ` and the id it carries),
/// passed when there is none. A module rule's finding that is only
/// `unverified: …` leaves it unavailable, and one naming a level above the
/// rule's (`Silver: …`) never fails it.
pub fn relabelled(cx: &Cx<'_>, id: &str, origin: Origin) -> Outcome {
    // A module rule under `--fleet` reads nothing: its module's check reads a
    // checkout, which `--fleet` does not have (#873).
    if cx.today.is_none() && matches!(origin, Origin::Workflows | Origin::Installed(_)) {
        return Outcome::not_required(NO_CHECKOUT);
    }
    if let Some(outcome) = outside(cx, origin) {
        return outcome;
    }
    // Only `--fleet` audits without a checkout: there is nothing to re-label,
    // so the rule is not required there (SPEC-auditor.md, "Baseline block", #734).
    let Some(today) = cx.today else {
        return Outcome::not_required(NO_CHECKOUT);
    };
    if origin == Origin::Remote {
        if !today.remote {
            return Outcome::unavailable("remote findings run only with doctor --remote");
        }
        if id != REMOTE_READABLE.id
            && let Some(unread) = today
                .findings
                .iter()
                .find(|f| relabel(f).as_deref() == Some(REMOTE_READABLE.id))
        {
            return Outcome::unavailable(format!("remote diagnosis did not run: {unread}"));
        }
    }
    let own = format!("{id}: ");
    let found: Vec<&str> = today
        .findings
        .iter()
        .filter(|f| relabel(f).as_deref() == Some(id))
        .map(|f| f.strip_prefix(WARNING).unwrap_or(f))
        .map(|f| f.strip_prefix(own.as_str()).unwrap_or(f))
        // A multi-line finding (`stack.unconfigured`'s proposal block) is
        // evidence by its first line; `doctor` printed it whole above.
        .map(|f| f.lines().next().unwrap_or(f))
        .collect();
    let level = REGISTRY
        .iter()
        .find(|r| r.id == id)
        .map_or(Level::Basic, |r| r.level);
    let above = |f: &&str| {
        f.split_once(": ")
            .and_then(|(name, _)| Level::parse(name))
            .is_some_and(|named| named > level)
    };
    let (above, found): (Vec<&str>, Vec<&str>) = found.into_iter().partition(above);
    if found.is_empty() && above.is_empty() {
        Outcome::passed(["today's doctor reports none"])
    } else if found.is_empty() {
        Outcome::passed(
            std::iter::once("today's doctor reports none at this level".to_owned())
                .chain(above.iter().map(|f| format!("above it: {f}"))),
        )
    } else if found.iter().all(|f| f.starts_with("unverified: ")) {
        Outcome::unavailable(found.join("; "))
    } else if let Some(reasons) = found
        .iter()
        .map(|f| plan_refusal(f))
        .collect::<Option<Vec<&str>>>()
    {
        // The plan refuses protection (#1164): what the rule needs is a plan,
        // never a module, so it is `requires plan …`, never failed.
        Outcome::unavailable(reasons.join("; "))
    } else {
        Outcome::failed(found)
    }
}

#[cfg(feature = "setup-core")]
const SETUP_CORE: Remediation = Remediation::Module { id: "setup-core" };

/// `baseline.managed-content-intact`'s remediation: re-running setup-core's
/// install with the feature, else restoring the file, since no module named
/// `setup-core` exists in that build.
#[cfg(feature = "setup-core")]
const MANAGED_REMEDIATION: Remediation = SETUP_CORE;
#[cfg(not(feature = "setup-core"))]
const MANAGED_REMEDIATION: Remediation = RESTORE_MANAGED;
/// The fix for a drifted file whose module this build does not compile (#1254).
const RESTORE_MANAGED: Remediation = Remediation::Manual {
    step: "restore-managed-content",
    instructions: "Undo the hand edit of each managed file doctor names, or re-run install; change a managed file through its module's answers.",
};

/// `baseline.release-baseline`'s remediation: setup-core's reinstall with the
/// feature; without it, re-running install from a committed source (#1260).
#[cfg(feature = "setup-core")]
const RELEASE_REMEDIATION: Remediation = SETUP_CORE;
#[cfg(not(feature = "setup-core"))]
const RELEASE_REMEDIATION: Remediation = Remediation::Manual {
    step: "reinstall-from-committed-source",
    instructions: "Re-run install with a binary built from a committed source (a tagged release or a clean checkout), not from a checkout with local changes.",
};

#[allow(clippy::too_many_arguments)]
const fn finding_rule(
    id: &'static str,
    title: &'static str,
    checks: &'static str,
    how: Probe,
    level: Level,
    remediation: Remediation,
    evaluate: fn(&Cx<'_>) -> Outcome,
) -> Rule {
    Rule {
        id,
        title,
        block: Block::Baseline,
        checks,
        how,
        level,
        required: ALL,
        remediation,
        plan: None,
        feasible_by: Milestone::Nov7,
        evaluate,
    }
}

#[cfg(feature = "setup-core")]
pub const CONVENTIONS_RESOLVED: Rule = finding_rule(
    "baseline.conventions-resolved",
    "Conventions resolve",
    "Every `conventions` entry of `.agent-setup/project.json` names an existing file and a decision that resolves and is open.",
    Probe::LocalFile { path: PROFILE },
    Level::Basic,
    Remediation::Manual {
        step: "resolve-conventions",
        instructions: "Point each convention doctor names at an existing file and an accepted decision.",
    },
    |cx| relabelled(cx, CONVENTIONS_RESOLVED.id, Origin::Checkout),
);

pub const PROFILE_CURRENT: Rule = finding_rule(
    "baseline.profile-current",
    "Profile without obsolete fields",
    "`.agent-setup/project.json` carries no field the installer retired.",
    Probe::LocalFile { path: PROFILE },
    Level::Basic,
    Remediation::Manual {
        step: "remove-obsolete-fields",
        instructions: "Remove the obsolete fields doctor names from .agent-setup/project.json.",
    },
    |cx| relabelled(cx, PROFILE_CURRENT.id, Origin::Checkout),
);

#[cfg(feature = "setup-core")]
pub const PLACEHOLDERS_REVIEWED: Rule = finding_rule(
    "baseline.placeholder-guidance-reviewed",
    "No placeholder guidance",
    "`AGENTS.md` and `CLAUDE.md` carry no placeholder line (TODO, TBD).",
    Probe::LocalFile { path: "AGENTS.md" },
    Level::Basic,
    Remediation::Manual {
        step: "review-placeholders",
        instructions: "Replace the placeholder lines of AGENTS.md and CLAUDE.md with real guidance.",
    },
    |cx| relabelled(cx, PLACEHOLDERS_REVIEWED.id, Origin::Checkout),
);

pub const MERGE_GUARD_REGISTERED: Rule = finding_rule(
    "baseline.merge-guard-registered",
    "Merge guard hook registered",
    "A merge guard hook in the checkout is registered in `.claude/settings.json`.",
    Probe::LocalFile {
        path: ".claude/settings.json",
    },
    Level::Bronze,
    Remediation::Module { id: "merge-guard" },
    |cx| relabelled(cx, MERGE_GUARD_REGISTERED.id, Origin::Checkout),
);

#[cfg(feature = "setup-core")]
pub const GUIDES_INSTALLED: Rule = finding_rule(
    "baseline.guides-installed",
    "Guides installed",
    "The lock records every current engineering guide and no retired one; without a lock it is not required.",
    Probe::Lock,
    Level::Basic,
    SETUP_CORE,
    |cx| relabelled(cx, GUIDES_INSTALLED.id, Origin::Managed),
);

pub const RELEASE_BASELINE: Rule = finding_rule(
    "baseline.release-baseline",
    "Installed from a committed source",
    "The lock records a setup installed from a committed source; without a lock it is not required.",
    Probe::Lock,
    Level::Basic,
    RELEASE_REMEDIATION,
    |cx| relabelled(cx, RELEASE_BASELINE.id, Origin::Managed),
);

/// Every module's managed files and blocks, with or without `setup-core`
/// (SPEC-product-boundary.md, Decided (coordinator) 9): a hand edit of a
/// managed file is what a brake catches, whichever module owns it.
pub const MANAGED_CONTENT_INTACT: Rule = finding_rule(
    "baseline.managed-content-intact",
    "Managed content intact",
    "Every managed file and block matches the digest the lock records; without a lock it is not required.",
    Probe::Lock,
    Level::Basic,
    MANAGED_REMEDIATION,
    managed_content_intact,
);

/// The findings name the module the lock records for each file (`… (module
/// <id>)`, #1254); that module is the remediation, in finding order, unless
/// this build does not compile it, where the file is restored by hand.
fn managed_content_intact(cx: &Cx<'_>) -> Outcome {
    let mut outcome = relabelled(cx, MANAGED_CONTENT_INTACT.id, Origin::Managed);
    if outcome.status != Status::Failed {
        return outcome;
    }
    let mut remediations = Vec::new();
    for finding in &outcome.evidence {
        let named = finding
            .strip_suffix(')')
            .and_then(|f| f.rsplit_once(" (module "))
            .map(|(_, id)| id);
        let remediation = match named.and_then(crate::modules::find) {
            Some(module) => Remediation::Module { id: module.id() },
            None => RESTORE_MANAGED,
        };
        if !remediations.contains(&remediation) {
            remediations.push(remediation);
        }
    }
    outcome.remediations = remediations;
    outcome
}

#[cfg(feature = "setup-core")]
pub const GUIDES_VERIFIED: Rule = finding_rule(
    "baseline.guides-verified",
    "Guides verified recently",
    "Every installed guide carries a `Last verified` date within the profile's bound; without a lock it is not required.",
    Probe::Lock,
    Level::Basic,
    SETUP_CORE,
    |cx| relabelled(cx, GUIDES_VERIFIED.id, Origin::Managed),
);

#[cfg(feature = "setup-core")]
pub const ENTRYPOINTS_CURRENT: Rule = finding_rule(
    "baseline.entrypoints-current",
    "Entrypoints reflect the profile",
    "The managed blocks of the entrypoints match `.agent-setup/project.json`; without a lock it is not required.",
    Probe::Lock,
    Level::Basic,
    SETUP_CORE,
    |cx| relabelled(cx, ENTRYPOINTS_CURRENT.id, Origin::Managed),
);

#[cfg(feature = "setup-core")]
pub const DECISIONS_INDEX_CURRENT: Rule = finding_rule(
    "baseline.decisions-index-current",
    "Decisions index current",
    "The generated decisions index matches the project's decisions; without a lock it is not required.",
    Probe::Lock,
    Level::Bronze,
    SETUP_CORE,
    |cx| relabelled(cx, DECISIONS_INDEX_CURRENT.id, Origin::Managed),
);

pub const REMOTE_READABLE: Rule = finding_rule(
    "baseline.remote-readable",
    "Remote diagnosis readable",
    "`doctor --remote` reads the origin repository and its default branch.",
    Probe::Remote {
        id: "inspect-report",
    },
    Level::Basic,
    Remediation::Manual {
        step: "remote-access",
        instructions: "Run doctor --remote in a checkout whose origin is one GitHub repository the token reads.",
    },
    |cx| relabelled(cx, REMOTE_READABLE.id, Origin::Remote),
);

pub const BRANCH_PROTECTION_MATCHES: Rule = finding_rule(
    "baseline.branch-protection-matches",
    "Protection matches the declared checks",
    "The default branch is protected, requires every declared CI check (with ci-baseline, the rendered ruleset's or the aggregate, by classic protection or an active ruleset), forbids force-push and deletion and, under classic protection, covers administrators.",
    Probe::Remote {
        id: "inspect-report",
    },
    Level::Basic,
    Remediation::Module {
        id: "repo-baseline",
    },
    |cx| relabelled(cx, BRANCH_PROTECTION_MATCHES.id, Origin::Remote),
);

pub const CI_POLICY_MET: Rule = finding_rule(
    "baseline.ci-policy-met",
    "Latest CI cycles meet the declared policy",
    "The declared CI policy is valid and the latest CI cycles succeeded within its budget, shards and tiers; with ci-baseline, shards and budget only when declared and its own tiers.",
    Probe::Remote {
        id: "inspect-report",
    },
    Level::Basic,
    Remediation::Module { id: "ci-baseline" },
    |cx| relabelled(cx, CI_POLICY_MET.id, Origin::Remote),
);

// --- manual steps of installed modules (#730) ----------------------------------------

/// Each compiled module's level (decision "Auditor standard v1, amended",
/// point 6, #873): the lowest level of the rules the module serves. Its manual
/// steps take it but never below Bronze ([`step_level`]).
pub const MODULE_LEVELS: &[(&str, Level)] = &[
    #[cfg(feature = "setup-core")]
    ("setup-core", Level::Basic),
    ("repo-baseline", Level::Basic),
    ("merge-guard", Level::Bronze),
    ("stack-packs", Level::Basic),
    ("ci-baseline", Level::Basic),
    ("security", Level::Basic),
    ("agent-guardrails", Level::Basic),
    ("qa", Level::Silver),
];

/// The level of `module`'s manual steps: `max(Bronze, its module's level)`,
/// Bronze for a module no decision names yet. A pending step is owner work,
/// often remote, and Basic is about the checkout, so a step never blocks
/// Basic nor changes readiness.
pub fn step_level(module: &str) -> Level {
    MODULE_LEVELS
        .iter()
        .find(|(id, _)| *id == module)
        .map_or(Level::Bronze, |(_, level)| (*level).max(Level::Bronze))
}

/// The rule of one manual step: `baseline.<module>.<step>`, at its module's
/// [`step_level`] (never below Bronze) in every profile. Rules are `'static` data; a step is known only once the
/// engine declares it, so each distinct step's rule is built once per process
/// and kept (a handful per installed module).
pub fn step_rule(step: &StepReport) -> &'static Rule {
    type Key = (String, String, String);
    static RULES: Mutex<BTreeMap<Key, &'static Rule>> = Mutex::new(BTreeMap::new());
    let key = (step.module.clone(), step.id.clone(), step.title.clone());
    let mut rules = RULES.lock().unwrap_or_else(PoisonError::into_inner);
    rules.entry(key).or_insert_with(|| {
        let keep = |text: String| -> &'static str { Box::leak(text.into_boxed_str()) };
        let module = keep(step.module.clone());
        let id = keep(step.id.clone());
        let title = keep(step.title.clone());
        Box::leak(Box::new(Rule {
            id: keep(format!("baseline.{module}.{id}")),
            title,
            block: Block::Baseline,
            checks: keep(format!(
                "The probe of manual step `{id}` of module {module} answers verified."
            )),
            how: Probe::ManualStep { module, step: id },
            level: step_level(module),
            required: ALL,
            remediation: Remediation::Manual {
                step: id,
                instructions: title,
            },
            plan: None,
            feasible_by: Milestone::Nov7,
            evaluate: step_unevaluated,
        }))
    })
}

/// A step rule's outcome comes from the engine's probe ([`step_outcome`]);
/// `evaluate` never probes again and answers that.
fn step_unevaluated(_: &Cx<'_>) -> Outcome {
    Outcome::unavailable("a manual step is judged from the engine's probe result")
}

/// What the engine's probe answered, as a rule outcome with its evidence:
/// verified passes, pending fails, a probe that could not answer (failed,
/// unavailable, or blocked behind another step) is unavailable, and a step
/// the host says does not exist here is not required.
pub fn step_outcome(step: &StepReport) -> Outcome {
    let detail = step.detail();
    match step.state {
        StepState::Verified => Outcome::passed([detail]),
        StepState::Pending => Outcome::failed([detail]),
        StepState::Failed | StepState::Unavailable | StepState::Blocked => {
            Outcome::unavailable(detail)
        }
        StepState::NotApplicable => Outcome::not_required(detail),
    }
}
