//! Posture rules (SPEC-auditor.md, "Posture reads and the budget", #721): how
//! the default branch is guarded, who may bypass it, organisation 2FA, open
//! alerts, secrets beside `production`, stale branches and pinned actions. Host
//! reads go through the adapter only, never `features`; a plan refusal is read
//! from the error of the read itself.
use crate::{
    auditor::{
        Cx, WORKFLOWS,
        catalogue::security_remote::visibility_name,
        rules::{
            Block, Cadence, Condition, Level, Milestone, Outcome, Plan, Probe, Profile,
            Remediation, Required, Rule,
        },
        workflows,
    },
    host::{
        HostError, HostErrorKind, OwnerKind, SecretScope, Visibility,
        github::names_plan,
        types::{BranchProtection, DeploymentBranchPolicy, Environment, Ruleset},
    },
    modules::security::exceptions::{INVENTORY, Inventory, Kind},
};
use chrono::{Days, NaiveDate};
use std::collections::BTreeMap;

const ALL: Required = Required {
    profiles: &[Profile::P1, Profile::P2, Profile::P3],
    when: &[],
};
/// Formal approvals: with one human another approval adds nothing.
const TEAMS: Required = Required {
    profiles: &[Profile::P2, Profile::P3],
    when: &[],
};
/// Cadence rules, whatever the profile.
const CADENCE_MID: Required = Required {
    profiles: &[],
    when: &[Condition::CadenceAtLeast(Cadence::Mid)],
};
/// The environment `production-environment-guarded` and
/// `no-repo-secrets-with-production` read.
pub const PRODUCTION: &str = "production";
/// The single aggregate status check (decision "Full-lifecycle installer", point 4).
pub const AGGREGATE_CHECK: &str = "required";
/// Critical Dependabot alerts may stay open this many days.
pub const CRITICAL_ALERT_DAYS: u64 = 7;
/// A branch whose last commit is older than this many days is stale.
pub const STALE_DAYS: u64 = 90;
/// More stale branches than this fails.
pub const MAX_STALE: usize = 10;
/// Commit dates `stale-branches` may read: the 11 a failure needs plus room
/// to settle a pass, within the 60-call budget of a repository.
pub const STALE_DATE_CAP: usize = 15;
/// The bypass actor that classic protection without `enforce_admins` grants.
pub const CLASSIC_ADMINS: &str = "classic-protection:admins";

const RULESET_REMEDIATION: Remediation = Remediation::Module {
    id: "repo-baseline",
};

pub const DEFAULT_BRANCH_PROTECTED: Rule = Rule {
    id: "posture.default-branch-protected",
    title: "Default branch protected",
    block: Block::Posture,
    checks: "Classic protection or an active ruleset blocks force-push and deletion on the default branch.",
    how: Probe::Remote {
        id: "branch-protection+rulesets",
    },
    level: Level::Basic,
    required: ALL,
    remediation: RULESET_REMEDIATION,
    plan: Some(Plan::Team),
    feasible_by: Milestone::Nov7,
    evaluate: default_branch_protected,
};

pub const NO_OPEN_SECRET_SCANNING_ALERTS: Rule = Rule {
    id: "posture.no-open-secret-scanning-alerts",
    title: "No open secret-scanning alerts",
    block: Block::Posture,
    checks: "The repository has no open secret-scanning alert.",
    how: Probe::Remote {
        id: "secret-scanning-alerts",
    },
    level: Level::Basic,
    required: ALL,
    remediation: Remediation::Manual {
        step: "resolve-secret-scanning-alerts",
        instructions: "Revoke and rotate each exposed secret, then close its alert under Security > Secret scanning.",
    },
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: no_open_secret_scanning_alerts,
};

pub const REQUIRED_CHECK_ENFORCED: Rule = Rule {
    id: "posture.required-check-enforced",
    title: "Aggregate check required",
    block: Block::Posture,
    checks: "Classic protection or an active ruleset requires the aggregate check `required` on the default branch.",
    how: Probe::Remote {
        id: "branch-protection+rulesets",
    },
    level: Level::Bronze,
    required: ALL,
    remediation: RULESET_REMEDIATION,
    plan: Some(Plan::Team),
    feasible_by: Milestone::Nov7,
    evaluate: required_check_enforced,
};

pub const NO_UNLISTED_BYPASS_ACTORS: Rule = Rule {
    id: "posture.no-unlisted-bypass-actors",
    title: "No unlisted bypass actors",
    block: Block::Posture,
    checks: "Every bypass actor of the default branch is a `ruleset-bypass-actor` entry of `.agent-setup/security-exceptions.json`.",
    how: Probe::Remote {
        id: "branch-protection+rulesets",
    },
    level: Level::Bronze,
    required: ALL,
    remediation: Remediation::Manual {
        step: "register-bypass-actors",
        instructions: "Remove the bypass actor from the ruleset, or add a ruleset-bypass-actor entry with an issue and an expiry to .agent-setup/security-exceptions.json.",
    },
    plan: Some(Plan::Team),
    feasible_by: Milestone::Nov7,
    evaluate: no_unlisted_bypass_actors,
};

pub const HUMAN_APPROVAL_REQUIRED: Rule = Rule {
    id: "posture.human-approval-required",
    title: "Approving review required",
    block: Block::Posture,
    checks: "Classic protection or an active ruleset requires at least one approving review before merging to the default branch.",
    how: Probe::Remote {
        id: "branch-protection+rulesets",
    },
    level: Level::Bronze,
    required: TEAMS,
    remediation: RULESET_REMEDIATION,
    plan: Some(Plan::Team),
    feasible_by: Milestone::Nov7,
    evaluate: human_approval_required,
};

pub const CODEOWNERS_REVIEW: Rule = Rule {
    id: "posture.codeowners-review",
    title: "Code owner review required",
    block: Block::Posture,
    checks: "Classic protection or an active ruleset requires a code owner's review before merging to the default branch.",
    how: Probe::Remote {
        id: "branch-protection+rulesets",
    },
    level: Level::Bronze,
    required: TEAMS,
    remediation: RULESET_REMEDIATION,
    plan: Some(Plan::Team),
    feasible_by: Milestone::Nov7,
    evaluate: codeowners_review,
};

pub const SERIALISED_MERGES: Rule = Rule {
    id: "posture.serialised-merges",
    title: "Merges serialised",
    block: Block::Posture,
    checks: "An active ruleset requires a merge queue, or classic protection or a ruleset requires branches up to date with the default branch before merging.",
    how: Probe::Remote {
        id: "branch-protection+rulesets",
    },
    level: Level::Bronze,
    required: CADENCE_MID,
    remediation: RULESET_REMEDIATION,
    plan: Some(Plan::Team),
    feasible_by: Milestone::Nov7,
    evaluate: serialised_merges,
};

pub const ACTIONS_PINNED: Rule = Rule {
    id: "posture.actions-pinned",
    title: "Actions pinned by SHA",
    block: Block::Posture,
    checks: "Every `uses:` of every workflow names a 40-hex commit SHA.",
    how: Probe::LocalFile { path: WORKFLOWS },
    level: Level::Bronze,
    required: ALL,
    remediation: Remediation::Manual {
        step: "pin-actions",
        instructions: "Replace each tag or branch after @ with the full commit SHA it points to, keeping the tag as a comment.",
    },
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: actions_pinned,
};

pub const NO_STALE_CRITICAL_ALERTS: Rule = Rule {
    id: "posture.no-stale-critical-alerts",
    title: "No stale critical alerts",
    block: Block::Posture,
    checks: "No critical Dependabot alert has been open more than 7 days.",
    how: Probe::Remote {
        id: "dependabot-alerts",
    },
    level: Level::Bronze,
    required: ALL,
    remediation: Remediation::Manual {
        step: "fix-critical-alerts",
        instructions: "Upgrade or replace the vulnerable dependency, or dismiss the alert with a reason, within 7 days.",
    },
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: no_stale_critical_alerts,
};

pub const NO_REPO_SECRETS_WITH_PRODUCTION: Rule = Rule {
    id: "posture.no-repo-secrets-with-production",
    title: "No repository secrets beside production",
    block: Block::Posture,
    checks: "When a `production` environment exists, no secret is set at repository level.",
    how: Probe::Remote {
        id: "environments+secret-names",
    },
    level: Level::Bronze,
    required: ALL,
    remediation: Remediation::Manual {
        step: "move-secrets-to-environments",
        instructions: "Move each repository-level secret into the environment that uses it, then delete it at repository level.",
    },
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: no_repo_secrets_with_production,
};

pub const PRODUCTION_ENVIRONMENT_GUARDED: Rule = Rule {
    id: "posture.production-environment-guarded",
    title: "Production environment guarded",
    block: Block::Posture,
    checks: "The `production` environment restricts deployments to chosen branches at P1, and requires reviewers or a wait timer at P2 and P3; a repository that is not public has those only on Enterprise Cloud, so without them the branch restriction decides there.",
    how: Probe::Remote { id: "environments" },
    level: Level::Silver,
    required: ALL,
    remediation: Remediation::Manual {
        step: "guard-production-environment",
        instructions: "Under Settings > Environments > production, limit deployment branches to protected or selected branches (P1), and add required reviewers or a wait timer (P2, P3; on a repository that is not public, Enterprise Cloud only).",
    },
    // Deployment branches need Team on a private repository, reviewers and
    // wait timers Enterprise Cloud; the rule records the higher (#1321).
    plan: Some(Plan::EnterpriseCloud),
    feasible_by: Milestone::Nov7,
    evaluate: production_environment_guarded,
};

pub const STALE_BRANCHES: Rule = Rule {
    id: "posture.stale-branches",
    title: "Few stale branches",
    block: Block::Posture,
    checks: "At most 10 branches besides the default one have a last commit older than 90 days.",
    how: Probe::Remote {
        id: "branch-heads+commit-dates",
    },
    level: Level::Bronze,
    required: ALL,
    remediation: Remediation::Manual {
        step: "delete-stale-branches",
        instructions: "Delete merged or abandoned branches older than 90 days, and enable automatic deletion of head branches.",
    },
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: stale_branches,
};

pub const ORG_2FA_REQUIRED: Rule = Rule {
    id: "posture.org-2fa-required",
    title: "Organisation requires 2FA",
    block: Block::Posture,
    checks: "The owning organization requires two-factor authentication of its members.",
    how: Probe::Remote { id: "org-settings" },
    level: Level::Gold,
    required: ALL,
    remediation: Remediation::Manual {
        step: "require-2fa",
        instructions: "Enable Require two-factor authentication under the organization's Authentication security settings.",
    },
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: org_2fa_required,
};

pub const REPO_ADMINS_ARE_OWNERS: Rule = Rule {
    id: "posture.repo-admins-are-owners",
    title: "Repository admins are owners",
    block: Block::Posture,
    checks: "Every collaborator with admin on the repository is the user that owns it or an owner of its organization (decision 2026-10-31, #1218).",
    how: Probe::Remote {
        id: "collaborators+org-owners",
    },
    level: Level::Silver,
    required: TEAMS,
    remediation: Remediation::Manual {
        step: "lower-repository-admins",
        instructions: "Lower each named collaborator to maintain or write under Settings > Collaborators and teams, or record an accepted-risk entry for posture.repo-admins-are-owners with an issue and an expiry in .agent-setup/security-exceptions.json.",
    },
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: repo_admins_are_owners,
};

// --- shared readings --------------------------------------------------------------

/// The `Unavailable` outcome of a read that failed: its own sentence, or
/// `budget exhausted: …` when the call budget stopped it.
pub(crate) fn unread(e: &HostError) -> Outcome {
    if matches!(e.kind, HostErrorKind::RateLimited { .. }) && e.message.starts_with("call budget") {
        Outcome::unavailable(format!("budget exhausted: {e}"))
    } else {
        Outcome::unavailable(e.message.clone())
    }
}

/// Whether `outcome` is a read the call budget refused: a sample cut there is
/// judged on what it read once it reached its minimum (SPEC-auditor.md,
/// "Block allowances", #920).
pub(crate) fn budget_stopped(outcome: &Outcome) -> bool {
    outcome
        .reason
        .as_deref()
        .is_some_and(|r| r.starts_with("budget exhausted"))
}

/// A `403` whose message names an upgrade or a plan.
fn plan_refused(e: &HostError) -> bool {
    e.kind == HostErrorKind::Forbidden && names_plan(&e.message)
}

/// What guards the default branch: classic protection and the rulesets.
/// Shared with ci-baseline's `ci.required-is-aggregate` (#783), which reads
/// the same two sources from the audit's cache.
pub(crate) struct Guard {
    pub(crate) branch: String,
    protection: Result<Option<BranchProtection>, HostError>,
    rulesets: Result<Vec<Ruleset>, HostError>,
}
impl Guard {
    pub(crate) fn read(cx: &Cx<'_>) -> Self {
        Self {
            branch: cx.default_branch.to_owned(),
            protection: cx.host.branch_protection(cx.repo, cx.default_branch),
            rulesets: cx.host.rulesets(cx.repo),
        }
    }
    pub(crate) fn protection(&self) -> Option<&BranchProtection> {
        self.protection.as_ref().ok().and_then(Option::as_ref)
    }
    /// The first source that failed for a reason other than the plan: a
    /// verdict over the other source alone would say nothing.
    pub(crate) fn unreadable(&self) -> Option<&HostError> {
        [self.protection.as_ref().err(), self.rulesets.as_ref().err()]
            .into_iter()
            .flatten()
            .find(|e| !plan_refused(e))
    }
    /// Active branch rulesets whose conditions include the default branch.
    pub(crate) fn active(&self) -> Vec<&Ruleset> {
        let reference = format!("refs/heads/{}", self.branch);
        let names = |patterns: &[String]| {
            patterns.iter().any(|p| {
                p == "~ALL" || p == "~DEFAULT_BRANCH" || p == &reference || glob(p, &reference)
            })
        };
        self.rulesets
            .as_ref()
            .map(|all| {
                all.iter()
                    .filter(|r| r.target == "branch" && r.enforcement == "active")
                    .filter(|r| names(&r.include) && !names(&r.exclude))
                    .collect()
            })
            .unwrap_or_default()
    }
    /// The outcome when the answering sources did not prove the rule: the
    /// first unreadable source that could have; `requires plan Team` when
    /// every source was refused by plan; otherwise `failed` with `evidence`
    /// and the plan refusals.
    pub(crate) fn settle(&self, mut evidence: Vec<String>) -> Outcome {
        if let Some(e) = self.unreadable() {
            return unread(e);
        }
        let errors: Vec<&HostError> =
            [self.protection.as_ref().err(), self.rulesets.as_ref().err()]
                .into_iter()
                .flatten()
                .collect();
        if errors.len() == 2 {
            return Outcome::requires_plan(Plan::Team);
        }
        let refusals = errors.iter().map(|e| e.message.clone());
        evidence.splice(0..0, refusals);
        Outcome::failed(evidence)
    }
}

/// The rule's outcome over both sources: `classic` answers the passing
/// evidence or why classic protection does not prove the rule, `ruleset` the
/// passing evidence of an active ruleset that proves it; `none` is the failing
/// evidence when no ruleset does. A source that proves the rule passes it even
/// when the other is unreadable.
fn proved_by(
    guard: &Guard,
    classic: impl Fn(&BranchProtection) -> Result<String, String>,
    ruleset: impl Fn(&Ruleset) -> Option<String>,
    none: String,
) -> Outcome {
    let mut evidence = Vec::new();
    match guard.protection() {
        Some(p) => match classic(p) {
            Ok(proof) => return Outcome::passed([proof]),
            Err(why) => evidence.push(why),
        },
        None if guard.protection.is_ok() => {
            evidence.push(format!("{} has no classic protection", guard.branch));
        }
        None => {}
    }
    if guard.rulesets.is_ok() {
        if let Some(proof) = guard.active().into_iter().find_map(ruleset) {
            return Outcome::passed([proof]);
        }
        evidence.push(none);
    }
    guard.settle(evidence)
}

/// The parameter `key` of a ruleset's rule `kind`.
fn parameter<'a>(r: &'a Ruleset, kind: &str, key: &str) -> &'a serde_json::Value {
    r.rule_parameters
        .get(kind)
        .map_or(&serde_json::Value::Null, |p| &p[key])
}

/// `fnmatch`-style `*` over a ruleset ref pattern.
fn glob(pattern: &str, text: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == text,
        Some((head, tail)) => {
            text.starts_with(head)
                && (0..=text.len() - head.len()).any(|i| glob(tail, &text[head.len() + i..]))
        }
    }
}

fn label(r: &Ruleset) -> String {
    match r.id {
        Some(id) => format!("{} ({id})", r.name),
        None => r.name.clone(),
    }
}

/// The date part of an ISO-8601 time.
fn date(time: &str) -> Option<NaiveDate> {
    NaiveDate::parse_from_str(time.get(..10)?, "%Y-%m-%d").ok()
}

// --- rules ------------------------------------------------------------------------

fn default_branch_protected(cx: &Cx<'_>) -> Outcome {
    let guard = Guard::read(cx);
    let branch = &guard.branch;
    let mut evidence = Vec::new();
    match guard.protection() {
        Some(p) if p.allow_force_pushes == Some(false) && p.allow_deletions == Some(false) => {
            return Outcome::passed([format!(
                "classic protection of {branch} blocks force-push and deletion"
            )]);
        }
        Some(p) => {
            if p.allow_force_pushes != Some(false) {
                evidence.push(format!(
                    "classic protection of {branch} does not block force-push"
                ));
            }
            if p.allow_deletions != Some(false) {
                evidence.push(format!(
                    "classic protection of {branch} does not block deletion"
                ));
            }
        }
        None if guard.protection.is_ok() => {
            evidence.push(format!("{branch} has no classic protection"));
        }
        None => {}
    }
    if guard.rulesets.is_ok() {
        let active = guard.active();
        let mut proved = Vec::new();
        for (kind, what) in [("non_fast_forward", "force-push"), ("deletion", "deletion")] {
            match active.iter().find(|r| r.rules.iter().any(|k| k == kind)) {
                Some(r) => proved.push(format!(
                    "{what} blocked on {branch} by ruleset {}",
                    label(r)
                )),
                None => evidence.push(format!("no active ruleset blocks {what} on {branch}")),
            }
        }
        if proved.len() == 2 {
            return Outcome::passed(proved);
        }
    }
    guard.settle(evidence)
}

fn required_check_enforced(cx: &Cx<'_>) -> Outcome {
    let guard = Guard::read(cx);
    let branch = &guard.branch;
    let mut checks = Vec::new();
    if let Some(p) = guard.protection() {
        if p.required_status_checks
            .iter()
            .any(|c| c == AGGREGATE_CHECK)
        {
            return Outcome::passed([format!(
                "classic protection of {branch} requires check {AGGREGATE_CHECK}"
            )]);
        }
        checks.extend(p.required_status_checks.iter().cloned());
    }
    // A ruleset with bypass actors does not prove the check: a bypass never
    // skips the checks (decision 2026-10-31, #1218), so they live in a ruleset
    // nobody bypasses.
    let mut bypassed = Vec::new();
    for r in guard.active() {
        if r.required_status_checks
            .iter()
            .any(|c| c == AGGREGATE_CHECK)
        {
            if r.bypass_actors.is_empty() {
                return Outcome::passed([format!(
                    "ruleset {} requires check {AGGREGATE_CHECK} on {branch}",
                    label(r)
                )]);
            }
            bypassed.push(format!(
                "ruleset {} requires check {AGGREGATE_CHECK} on {branch}, but {} can bypass it; a bypass never skips the checks: move it to a ruleset of its own",
                label(r),
                r.bypass_actors.join(", ")
            ));
        }
        checks.extend(r.required_status_checks.iter().cloned());
    }
    if !bypassed.is_empty() {
        return guard.settle(bypassed);
    }
    checks.sort();
    checks.dedup();
    let evidence = if checks.is_empty() {
        format!("{branch} requires no status check")
    } else {
        format!(
            "{branch} requires checks {}; the aggregate check {AGGREGATE_CHECK} is not among them",
            checks.join(", ")
        )
    };
    guard.settle(vec![evidence])
}

fn no_unlisted_bypass_actors(cx: &Cx<'_>) -> Outcome {
    let guard = Guard::read(cx);
    let branch = &guard.branch;
    let mut actors: Vec<(String, String)> = Vec::new();
    if guard
        .protection()
        .is_some_and(|p| p.enforce_admins == Some(false))
    {
        actors.push((CLASSIC_ADMINS.to_owned(), "classic protection".to_owned()));
    }
    for r in guard.active() {
        for actor in &r.bypass_actors {
            actors.push((actor.clone(), format!("ruleset {}", label(r))));
        }
    }
    let listed: Vec<String> = if actors.is_empty() {
        Vec::new()
    } else {
        match cx.files.read(INVENTORY) {
            Ok(None) => Vec::new(),
            Ok(Some(text)) => match Inventory::parse(&text) {
                Some(inventory) => inventory
                    .exceptions
                    .into_iter()
                    .filter(|e| e.kind.as_deref() == Some(Kind::RulesetBypassActor.as_str()))
                    .filter_map(|e| e.target)
                    .collect(),
                None => {
                    return Outcome::unavailable(format!(
                        "{INVENTORY} does not parse, so bypass actors cannot be matched"
                    ));
                }
            },
            Err(e) => return Outcome::unavailable(format!("{INVENTORY} unreadable: {e}")),
        }
    };
    // Listed by the full `type:id:mode` or by its `type:id` prefix.
    let is_listed = |actor: &str| {
        listed.iter().any(|t| {
            t == actor
                || actor
                    .rsplit_once(':')
                    .is_some_and(|(prefix, _)| t == prefix)
        })
    };
    let (ok, unlisted): (Vec<_>, Vec<_>) = actors.iter().partition(|(a, _)| is_listed(a));
    if !unlisted.is_empty() {
        return Outcome::failed(unlisted.iter().map(|(actor, source)| {
            format!("bypass actor {actor} of {source} is not listed in {INVENTORY}")
        }));
    }
    let proved = guard.protection.is_ok() || guard.rulesets.is_ok();
    let errors = [
        guard.protection.as_ref().err(),
        guard.rulesets.as_ref().err(),
    ];
    if let Some(e) = errors.into_iter().flatten().find(|e| !plan_refused(e)) {
        return unread(e);
    }
    if !proved {
        return Outcome::requires_plan(Plan::Team);
    }
    if ok.is_empty() {
        return Outcome::passed([format!("no bypass actor on {branch}")]);
    }
    Outcome::passed(
        ok.iter().map(|(actor, source)| {
            format!("bypass actor {actor} of {source} listed in {INVENTORY}")
        }),
    )
}

fn human_approval_required(cx: &Cx<'_>) -> Outcome {
    let guard = Guard::read(cx);
    let branch = &guard.branch;
    let reviews = |n: u32| match n {
        1 => "1 approving review".to_owned(),
        n => format!("{n} approving reviews"),
    };
    proved_by(
        &guard,
        |p| match p.required_approving_review_count.unwrap_or(0) {
            0 => Err(format!(
                "classic protection of {branch} requires no approving review"
            )),
            n => Ok(format!(
                "classic protection of {branch} requires {}",
                reviews(n)
            )),
        },
        |r| {
            r.required_approving_review_count
                .filter(|n| *n > 0)
                .map(|n| {
                    let proof = format!("ruleset {} requires {} on {branch}", label(r), reviews(n));
                    // A bypass is shown, never hidden behind the pass (#1218).
                    if r.bypass_actors.is_empty() {
                        proof
                    } else {
                        format!("{proof}; bypassed by {}", r.bypass_actors.join(", "))
                    }
                })
        },
        format!("no active ruleset requires an approving review on {branch}"),
    )
}

/// A repository admin can edit or disable the ruleset in the UI; the
/// capability is reported, not only its effects (#1218).
fn repo_admins_are_owners(cx: &Cx<'_>) -> Outcome {
    let repo = cx.repo;
    let collaborators = match cx.host.collaborators(repo) {
        Ok(c) => c,
        Err(e) => return unread(&e),
    };
    let mut admins: Vec<&str> = collaborators
        .iter()
        .filter(|c| c.permission == "admin")
        .map(|c| c.login.as_str())
        .collect();
    admins.sort_unstable();
    if admins.is_empty() {
        return Outcome::passed([format!("no collaborator has admin on {repo}")]);
    }
    let owner = match cx.host.owner(&cx.repo.owner) {
        Ok(owner) => owner,
        Err(e) => return unread(&e),
    };
    let name = &owner.name;
    let (owners, is, is_not) = match owner.kind {
        OwnerKind::User => (
            vec![name.clone()],
            "is the user that owns it".to_owned(),
            "is not the user that owns it".to_owned(),
        ),
        OwnerKind::Organization => match cx.host.org_owners(name) {
            Ok(owners) => (
                owners,
                format!("is an owner of organization {name}"),
                format!("is not an owner of organization {name}"),
            ),
            Err(e) => return unread(&e),
        },
        OwnerKind::Unknown => {
            return Outcome::unavailable(format!("{name} is neither a user nor an organization"));
        }
    };
    let owned = |login: &str| owners.iter().any(|o| o.eq_ignore_ascii_case(login));
    let (ok, outsiders): (Vec<&str>, Vec<&str>) = admins.into_iter().partition(|a| owned(a));
    if !outsiders.is_empty() {
        return Outcome::failed(
            outsiders
                .iter()
                .map(|login| format!("{login} has admin on {repo} and {is_not}")),
        );
    }
    Outcome::passed(
        ok.iter()
            .map(|login| format!("{login} has admin on {repo} and {is}")),
    )
}

fn codeowners_review(cx: &Cx<'_>) -> Outcome {
    let guard = Guard::read(cx);
    let branch = &guard.branch;
    proved_by(
        &guard,
        |p| {
            if p.require_code_owner_reviews == Some(true) {
                Ok(format!(
                    "classic protection of {branch} requires code owner review"
                ))
            } else {
                Err(format!(
                    "classic protection of {branch} does not require code owner review"
                ))
            }
        },
        |r| {
            (parameter(r, "pull_request", "require_code_owner_review") == true).then(|| {
                format!(
                    "ruleset {} requires code owner review on {branch}",
                    label(r)
                )
            })
        },
        format!("no active ruleset requires code owner review on {branch}"),
    )
}

/// A merge queue, or branches up to date before merging (GitHub's strict
/// required status checks), lets one change at a time land on the tested tip.
fn serialised_merges(cx: &Cx<'_>) -> Outcome {
    let guard = Guard::read(cx);
    let branch = &guard.branch;
    proved_by(
        &guard,
        |p| match (p.strict, p.required_status_checks.is_empty()) {
            (Some(true), false) => Ok(format!(
                "classic protection of {branch} requires branches up to date before merging"
            )),
            (Some(true), true) => Err(format!(
                "classic protection of {branch} requires branches up to date but no status check"
            )),
            _ => Err(format!(
                "classic protection of {branch} does not require branches up to date before merging"
            )),
        },
        |r| {
            if r.rules.iter().any(|k| k == "merge_queue") {
                Some(format!(
                    "ruleset {} requires a merge queue on {branch}",
                    label(r)
                ))
            } else if parameter(
                r,
                "required_status_checks",
                "strict_required_status_checks_policy",
            ) == true
                && !r.required_status_checks.is_empty()
            {
                Some(format!(
                    "ruleset {} requires branches up to date before merging on {branch}",
                    label(r)
                ))
            } else {
                None
            }
        },
        format!("no active ruleset requires a merge queue or up-to-date branches on {branch}"),
    )
}

/// Whether `env` restricts which branches deploy: `Ok` with the passing
/// evidence, `Err` with the failing one.
fn branch_policy(env: &Environment) -> Result<String, String> {
    match &env.deployment_branch_policy {
        DeploymentBranchPolicy::Unrestricted => Err(format!(
            "{PRODUCTION} has no deployment branch policy: any branch may deploy"
        )),
        DeploymentBranchPolicy::ProtectedBranches => {
            Ok(format!("{PRODUCTION} deploys only from protected branches"))
        }
        DeploymentBranchPolicy::Custom { patterns } => {
            match patterns.iter().find(|p| *p == "*" || *p == "**") {
                Some(p) => Err(format!(
                    "{PRODUCTION}'s deployment branch pattern {p} admits any branch"
                )),
                None if patterns.is_empty() => {
                    Ok(format!("{PRODUCTION} allows no branch to deploy"))
                }
                None => Ok(format!(
                    "{PRODUCTION} deploys only from {}",
                    patterns.join(", ")
                )),
            }
        }
    }
}

/// P1 (decision "Auditor standard v1"): a deployment branch policy that does
/// not admit every branch; P2 and P3: required reviewers or a wait timer. On a
/// repository that is not public, GitHub offers reviewers and wait timers only
/// on Enterprise Cloud ("Deployments and environments": on Free, Pro and Team
/// they "are only available for public repositories"), so there the P1 guard
/// decides and the missing reviewers are `not-required` for the plan (#1321).
fn production_environment_guarded(cx: &Cx<'_>) -> Outcome {
    let environments = match cx.host.environments(cx.repo) {
        Err(e) if plan_refused(&e) => return Outcome::requires_plan(Plan::Team),
        Err(e) => return unread(&e),
        Ok(environments) => environments,
    };
    let Some(env) = environments.iter().find(|e| e.name == PRODUCTION) else {
        return Outcome::not_required("no production environment");
    };
    if cx.profile == Profile::P1 {
        return match branch_policy(env) {
            Ok(evidence) => Outcome::passed([evidence]),
            Err(evidence) => Outcome::failed([evidence]),
        };
    }
    let mut evidence = Vec::new();
    if !env.reviewers.is_empty() {
        evidence.push(format!(
            "{PRODUCTION} requires review by {}",
            env.reviewers.join(", ")
        ));
    }
    if let Some(n) = env.wait_timer_minutes.filter(|n| *n > 0) {
        let plural = if n == 1 { "" } else { "s" };
        evidence.push(format!(
            "{PRODUCTION} waits {n} minute{plural} before deploying"
        ));
    }
    if !evidence.is_empty() {
        return Outcome::passed(evidence);
    }
    let visibility = match cx.host.repository(cx.repo) {
        Ok(settings) => settings.visibility,
        Err(e) => return unread(&e),
    };
    if visibility == Visibility::Public {
        return Outcome::failed([format!(
            "{PRODUCTION} has neither required reviewers nor a wait timer"
        )]);
    }
    match branch_policy(env) {
        Ok(guard) => Outcome::not_required(format!(
            "requires plan {}: required reviewers and wait timers are only available for public repositories on Free, Pro and Team, and this repository is {}; {guard}",
            Plan::EnterpriseCloud,
            visibility_name(visibility)
        )),
        Err(open) => Outcome::failed([
            open,
            format!(
                "{PRODUCTION} has neither required reviewers nor a wait timer, which a {} repository has only on {}",
                visibility_name(visibility),
                Plan::EnterpriseCloud
            ),
        ]),
    }
}

fn org_2fa_required(cx: &Cx<'_>) -> Outcome {
    let owner = match cx.host.owner(&cx.repo.owner) {
        Ok(owner) => owner,
        Err(e) => return unread(&e),
    };
    let name = &owner.name;
    match owner.kind {
        OwnerKind::User => {
            return Outcome::unavailable(format!(
                "{name} is a user account; the two-factor requirement is an organization setting"
            ));
        }
        OwnerKind::Unknown => {
            return Outcome::unavailable(format!("{name} is neither a user nor an organization"));
        }
        OwnerKind::Organization => {}
    }
    match cx.host.org_settings(name) {
        Err(e) => unread(&e),
        Ok(settings) => match settings.two_factor_requirement_enabled {
            Some(true) => Outcome::passed([format!(
                "organization {name} requires two-factor authentication"
            )]),
            Some(false) => Outcome::failed([format!(
                "organization {name} does not require two-factor authentication"
            )]),
            None => Outcome::unavailable(format!(
                "the two-factor requirement of organization {name} is not visible to this token (it needs an organization owner)"
            )),
        },
    }
}

fn no_stale_critical_alerts(cx: &Cx<'_>) -> Outcome {
    let alerts = match cx.host.dependabot_alerts(cx.repo) {
        Ok(alerts) => alerts,
        Err(e) => return unread(&e),
    };
    if alerts.is_empty() {
        return Outcome::passed(["no open Dependabot alerts"]);
    }
    let mut stale = Vec::new();
    for a in alerts.iter().filter(|a| a.severity == "critical") {
        let Some(created) = date(&a.created_at) else {
            return Outcome::unavailable(format!(
                "Dependabot alert #{} has an unreadable created_at: {}",
                a.number, a.created_at
            ));
        };
        let days = (cx.now - created).num_days();
        if days > CRITICAL_ALERT_DAYS as i64 {
            let package = a
                .package
                .as_ref()
                .map(|p| format!(" ({p})"))
                .unwrap_or_default();
            stale.push(format!(
                "critical Dependabot alert #{}{package} open since {created}, {days} days",
                a.number
            ));
        }
    }
    if !stale.is_empty() {
        return Outcome::failed(stale);
    }
    let mut counts: BTreeMap<usize, (&str, usize)> = BTreeMap::new();
    for a in &alerts {
        let rank = ["critical", "high", "medium", "low"]
            .iter()
            .position(|s| *s == a.severity)
            .unwrap_or(4);
        counts.entry(rank).or_insert((a.severity.as_str(), 0)).1 += 1;
    }
    let counts: Vec<String> = counts
        .values()
        .map(|(severity, n)| format!("{severity} {n}"))
        .collect();
    Outcome::passed([format!(
        "{} open Dependabot alerts ({}); none critical older than {CRITICAL_ALERT_DAYS} days",
        alerts.len(),
        counts.join(", ")
    )])
}

fn no_open_secret_scanning_alerts(cx: &Cx<'_>) -> Outcome {
    match cx.host.secret_scanning_alerts(cx.repo) {
        Err(e) => unread(&e),
        Ok(alerts) if alerts.is_empty() => Outcome::passed(["no open secret-scanning alerts"]),
        Ok(alerts) => Outcome::failed(alerts.iter().map(|a| {
            let kind = a
                .secret_type_display_name
                .as_ref()
                .unwrap_or(&a.secret_type);
            let since = a.created_at.get(..10).unwrap_or(&a.created_at);
            format!(
                "open secret-scanning alert #{}: {kind} since {since}",
                a.number
            )
        })),
    }
}

fn no_repo_secrets_with_production(cx: &Cx<'_>) -> Outcome {
    match cx.host.environments(cx.repo) {
        Err(e) => return unread(&e),
        Ok(environments) if !environments.iter().any(|e| e.name == PRODUCTION) => {
            return Outcome::not_required("no production environment");
        }
        Ok(_) => {}
    }
    match cx.host.secret_names(cx.repo, &SecretScope::Repository) {
        Err(e) => unread(&e),
        Ok(secrets) if secrets.is_empty() => {
            Outcome::passed(["production environment exists; no repository-level secrets"])
        }
        Ok(secrets) => {
            let mut names: Vec<&str> = secrets.iter().map(|s| s.name.as_str()).collect();
            names.sort_unstable();
            Outcome::failed([format!(
                "repository-level secrets with a production environment: {}",
                names.join(", ")
            )])
        }
    }
}

/// Dates branches one at a time within [`STALE_DATE_CAP`], stopping as soon
/// as the verdict is decided (SPEC-auditor.md, "Posture reads and the budget").
fn stale_branches(cx: &Cx<'_>) -> Outcome {
    let mut heads = match cx.host.branch_heads(cx.repo) {
        Ok(heads) => heads,
        Err(e) => return unread(&e),
    };
    heads.retain(|b| b.name != cx.default_branch);
    heads.sort_by(|a, b| a.name.cmp(&b.name));
    let main = cx.default_branch;
    let n = heads.len();
    if n <= MAX_STALE {
        return Outcome::passed([format!(
            "{n} branches besides {main}: at most {MAX_STALE} can be older than {STALE_DAYS} days"
        )]);
    }
    let cutoff = cx.now - Days::new(STALE_DAYS);
    let mut stale = Vec::new();
    let mut dated = 0;
    let mut undated = n;
    let mut stopped = None;
    let mut read = 0;
    for branch in heads.iter().take(STALE_DATE_CAP) {
        let when = match cx.host.commit_date(cx.repo, &branch.sha) {
            Ok(when) => when,
            Err(e) => match unread(&e) {
                outcome if budget_stopped(&outcome) => {
                    stopped = outcome.reason;
                    break;
                }
                outcome => return outcome,
            },
        };
        read += 1;
        undated -= 1;
        match when.as_deref().and_then(date) {
            Some(day) => {
                dated += 1;
                if day < cutoff {
                    stale.push(branch.name.as_str());
                }
            }
            // A missing date counts as not dated: it may still be stale.
            None => undated += 1,
        }
        if stale.len() > MAX_STALE {
            return Outcome::failed([format!(
                "{} of {n} branches besides {main} older than {STALE_DAYS} days (before {cutoff}): {}",
                stale.len(),
                stale.join(", ")
            )]);
        }
        if stale.len() + undated <= MAX_STALE {
            return Outcome::passed([format!(
                "{n} branches besides {main}: {dated} dated, {} older than {STALE_DAYS} days (before {cutoff}), {undated} not dated: at most {} can be stale",
                stale.len(),
                stale.len() + undated
            )]);
        }
    }
    match stopped {
        Some(reason) => Outcome::unavailable(format!(
            "dated {read} of {n} branches besides {main} before the call budget stopped the date reads ({reason}): {} older than {STALE_DAYS} days, undecided",
            stale.len()
        )),
        None => Outcome::unavailable(format!(
            "dated {} of {n} branches besides {main} within the cap of {STALE_DATE_CAP} date reads: {} older than {STALE_DAYS} days, undecided",
            n.min(STALE_DATE_CAP),
            stale.len()
        )),
    }
}

fn actions_pinned(cx: &Cx<'_>) -> Outcome {
    let read = workflows::read_all(cx.files);
    if read.is_empty() {
        return Outcome::not_required(format!("no workflow under {WORKFLOWS}"));
    }
    let mut unpinned = Vec::new();
    let mut unreadable = None;
    for (path, parsed) in &read {
        match parsed {
            Ok(wf) => {
                let mut uses = wf.unpinned_uses();
                uses.sort_unstable();
                unpinned.extend(
                    uses.iter()
                        .map(|u| format!("Unpinned action {u} in {path}")),
                );
            }
            Err(reason) => {
                unreadable.get_or_insert_with(|| format!("{path}: {}", reason.trim()));
            }
        }
    }
    if !unpinned.is_empty() {
        return Outcome::failed(unpinned);
    }
    if let Some(reason) = unreadable {
        return Outcome::unavailable(reason);
    }
    let n = read.len();
    let plural = if n == 1 { "" } else { "s" };
    Outcome::passed([format!(
        "every uses: of {n} workflow{plural} is pinned by SHA"
    )])
}
