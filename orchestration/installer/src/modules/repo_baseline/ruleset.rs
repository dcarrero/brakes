//! The default-branch ruleset as a value (SPEC-repo-baseline.md, Data model:
//! Ruleset). Pure over the maturity profile, the module's answers and the
//! project profile: same inputs, same value. Never templated as text.
//!
//! Policy fixed by the owner (decision 2026-10-28, point 7): P1 `checks-only`
//! with no bypass actors, administrators included; P2 and P3 `one-approval`
//! with no bypass actors; agent identities are never bypass actors. The
//! repository-admin bypass exists as the P1 answer `checks-only-owner-bypass`,
//! which the auditor records as a standing exception. Amended 2026-10-31
//! (#1218): any profile may declare bypass actors in `bypass_actors`, within
//! `host::types::bypass_actor_refusal`'s policy, never implicitly.
use crate::{
    Result,
    host::types::{bypass_actor_json, bypass_actor_refusal},
    modules::ci_baseline::CONTRIBUTED_AGGREGATE_CHECK,
    profile, refuse,
};
use serde_json::{Value, json};

/// The ruleset's name on GitHub; the `ruleset-present` probe looks it up by name.
pub const RULESET_NAME: &str = "brakes: default branch baseline";
/// The review ruleset's name, rendered only with a declared bypass (#1218).
pub const REVIEW_RULESET_NAME: &str = "brakes: default branch review";
/// The single aggregate status check every repository requires (decision
/// 2026-10-28, point 4); `ci-baseline` names its `always()` job after it.
pub const REQUIRED_CHECK: &str = "required";
/// GitHub Actions' App id: a status from another app cannot satisfy the rule.
pub const GITHUB_ACTIONS_APP_ID: u64 = 15368;
/// The `RepositoryRole` id of a repository administrator.
pub const REPOSITORY_ADMIN_ROLE_ID: u64 = 5;

/// The maturity profile the module reads, never computes: P1 until the auditor
/// derives it (SPEC-repo-baseline.md, assumption 2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Tier {
    #[default]
    P1,
    P2,
    P3,
}

impl Tier {
    pub fn parse(text: &str) -> Option<Tier> {
        match text {
            "P1" => Some(Tier::P1),
            "P2" => Some(Tier::P2),
            "P3" => Some(Tier::P3),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::P1 => "P1",
            Tier::P2 => "P2",
            Tier::P3 => "P3",
        }
    }
}

/// The `approvals` answer, as the question of SPEC-repo-baseline.md enumerates it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Approvals {
    /// 0 approvals, no bypass actor ("Never merge on red", administrators included).
    ChecksOnly,
    /// 0 approvals, the repository admin bypasses; P1-only, an auditor exception.
    ChecksOnlyOwnerBypass,
    /// 1 approval of the last push, stale approvals dismissed, no bypass.
    OneApproval,
    /// Like `OneApproval` with a review App's check in place of the human; not yet.
    ReviewApp,
}

impl Approvals {
    pub const ALL: &'static [Approvals] = &[
        Approvals::ChecksOnly,
        Approvals::ChecksOnlyOwnerBypass,
        Approvals::OneApproval,
        Approvals::ReviewApp,
    ];
    pub fn parse(text: &str) -> Option<Approvals> {
        Self::ALL.iter().copied().find(|a| a.as_str() == text)
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Approvals::ChecksOnly => "checks-only",
            Approvals::ChecksOnlyOwnerBypass => "checks-only-owner-bypass",
            Approvals::OneApproval => "one-approval",
            Approvals::ReviewApp => "review-app",
        }
    }
}

/// The answers the ruleset reads, typed from the engine's answers by
/// `Choices::from_answers`; `defaults(tier)` are the questions' per-profile defaults.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answers {
    pub approvals: Approvals,
    /// `require_code_owner_review` under `one-approval`; P1 defaults to `false`
    /// because, with agents pushing under the owner's token, CODEOWNERS only asks
    /// the owner to review the owner's PRs.
    pub codeowners: bool,
    /// Declared bypass actors, `actor_type:actor_id:bypass_mode`, rendered after
    /// the one `checks-only-owner-bypass` adds; empty by default (#1218).
    pub bypass_actors: Vec<String>,
}

impl Answers {
    /// The spec's per-profile defaults for `approvals` and `codeowners`.
    pub fn defaults(tier: Tier) -> Answers {
        match tier {
            Tier::P1 => Answers {
                approvals: Approvals::ChecksOnly,
                codeowners: false,
                bypass_actors: Vec::new(),
            },
            Tier::P2 | Tier::P3 => Answers {
                approvals: Approvals::OneApproval,
                codeowners: true,
                bypass_actors: Vec::new(),
            },
        }
    }
}

/// What `ruleset` produces: the value the module serialises to
/// `.github/rulesets/main.json`, and the findings `doctor` reports about it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ruleset {
    /// `.github/rulesets/main.json`: with a declared bypass, every rule but
    /// the review, and no bypass actor, so a bypass never skips the checks.
    pub value: Value,
    /// `.github/rulesets/main-review.json`: the review rule alone with the
    /// declared bypass actors; `None` when none is declared (#1218).
    pub review: Option<Value>,
    pub findings: Vec<String>,
}

/// The checks the ruleset requires unless the project declares others.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Standard {
    /// `required`, or ci-baseline's required checks when it is active (#1159).
    pub checks: Vec<String>,
    /// True when ci-baseline's `github:switch-required-check` leaves `checks`
    /// the only required ones on the host, so a declared `ci.required_checks`
    /// is replaced rather than rendered (#1299).
    pub replaces_declared: bool,
}

/// The contexts the ruleset requires: the project's declared `ci.required_checks`
/// verbatim when it lists any and the standard does not replace them, else the
/// standard's checks. Declared checks are followed by `agentic-required` when
/// the standard holds it and they do not: ci-baseline's
/// `github:add-agentic-required-check` adds it to the live ruleset, so the
/// rendered one lists it too and `ruleset-main` can verify (#1297).
pub fn required_checks(project: &profile::Profile, standard: &Standard) -> Vec<String> {
    let mut declared: Vec<String> = profile::strings(&project.value["ci"]["required_checks"])
        .into_iter()
        .map(str::to_owned)
        .collect();
    if declared.is_empty() || standard.replaces_declared {
        return standard.checks.clone();
    }
    let added = CONTRIBUTED_AGGREGATE_CHECK.to_owned();
    if standard.checks.contains(&added) && !declared.contains(&added) {
        declared.push(added);
    }
    declared
}

/// The standard when ci-baseline is not active: the cross-module `required`.
pub fn default_checks() -> Standard {
    Standard {
        checks: vec![REQUIRED_CHECK.to_owned()],
        replaces_declared: false,
    }
}

/// Pure: same profile, answers, project and standard, same ruleset. The
/// `standard` contexts (`required`, or ci-baseline's required checks) unless the
/// project declares others; then they render verbatim and the finding says so,
/// so no repository loses a check it has today.
pub fn ruleset(
    tier: Tier,
    answers: &Answers,
    project: &profile::Profile,
    standard: &Standard,
) -> Result<Ruleset> {
    match answers.approvals {
        Approvals::ChecksOnlyOwnerBypass if tier != Tier::P1 => {
            return refuse(
                "Module repo-baseline: approvals `checks-only-owner-bypass` is P1-only; use `checks-only` or `one-approval`",
            );
        }
        Approvals::ReviewApp => {
            return refuse(
                "Module repo-baseline: review-app needs the agent App (org-level slice)",
            );
        }
        Approvals::ChecksOnlyOwnerBypass if !answers.bypass_actors.is_empty() => {
            return refuse(
                "Module repo-baseline: approvals `checks-only-owner-bypass` bypasses the required checks too, so it cannot be combined with bypass_actors; use `checks-only` or `one-approval`",
            );
        }
        _ => {}
    }
    let actors = bypass_actors(answers)?;
    let checks = required_checks(project, standard);
    let findings = if checks == standard.checks {
        Vec::new()
    } else {
        vec![format!(
            "Required checks: {} context{}, the standard is one aggregate check",
            checks.len(),
            if checks.len() == 1 { "" } else { "s" }
        )]
    };
    let ruleset = |name: &str, actors: Vec<Value>, rules: Vec<Value>| {
        json!({
            "name": name,
            "target": "branch",
            "enforcement": "active",
            "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
            "bypass_actors": actors,
            "rules": rules,
        })
    };
    let rules = rules(answers, &checks);
    if answers.bypass_actors.is_empty() {
        return Ok(Ruleset {
            value: ruleset(RULESET_NAME, actors, rules),
            review: None,
            findings,
        });
    }
    // A declared bypass applies to the review alone (decision 2026-10-31,
    // #1218): the checks stay in a ruleset nobody bypasses.
    let (review, checked): (Vec<Value>, Vec<Value>) =
        rules.into_iter().partition(|r| r["type"] == "pull_request");
    Ok(Ruleset {
        value: ruleset(RULESET_NAME, Vec::new(), checked),
        review: Some(ruleset(REVIEW_RULESET_NAME, actors, review)),
        findings,
    })
}

/// The owner bypass of `checks-only-owner-bypass`, then each declared actor
/// verbatim; an actor outside the policy, or one repeated, refuses.
fn bypass_actors(answers: &Answers) -> Result<Vec<Value>> {
    let mut actors: Vec<String> = Vec::new();
    if answers.approvals == Approvals::ChecksOnlyOwnerBypass {
        actors.push(format!("RepositoryRole:{REPOSITORY_ADMIN_ROLE_ID}:always"));
    }
    for actor in &answers.bypass_actors {
        if let Err(why) = bypass_actor_refusal(actor) {
            return refuse(format!(
                "Module repo-baseline: bypass actor `{actor}` refused: {why}"
            ));
        }
        if actors.contains(actor) {
            return refuse(format!(
                "Module repo-baseline: bypass actor `{actor}` is declared twice"
            ));
        }
        actors.push(actor.clone());
    }
    Ok(actors
        .iter()
        .map(|actor| bypass_actor_json(actor))
        .collect())
}

fn rules(answers: &Answers, checks: &[String]) -> Vec<Value> {
    let one_approval = answers.approvals == Approvals::OneApproval;
    let contexts: Vec<Value> = checks
        .iter()
        .map(|context| json!({ "context": context, "integration_id": GITHUB_ACTIONS_APP_ID }))
        .collect();
    vec![
        json!({ "type": "deletion" }),
        json!({ "type": "non_fast_forward" }),
        json!({ "type": "required_linear_history" }),
        json!({ "type": "pull_request", "parameters": {
            "required_approving_review_count": if one_approval { 1 } else { 0 },
            "dismiss_stale_reviews_on_push": true,
            "require_code_owner_review": one_approval && answers.codeowners,
            "require_last_push_approval": one_approval,
            "required_review_thread_resolution": true,
            "allowed_merge_methods": ["squash"],
        } }),
        json!({ "type": "required_status_checks", "parameters": {
            "strict_required_status_checks_policy": true,
            "do_not_enforce_on_create": false,
            "required_status_checks": contexts,
        } }),
    ]
}
