//! The auditor's standard as data (SPEC-auditor.md, "Data model"): rules with a
//! level, the profiles and conditions that make them required, and how each is
//! remediated. The allocation is the accepted decision "Auditor standard v1"
//! (docs/decisions.md, #706); `tests/auditor_level.rs` asserts every entry of
//! [`REGISTRY`] against it.
use super::{
    Cx,
    catalogue::{
        baseline, ci_health, dora, governance, modules, operations, posture, qa, security_remote,
    },
};
use std::fmt;

/// A group of rules; its [`Block::id`] is the prefix of every rule id in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Block {
    Baseline,
    Posture,
    CiHealth,
    Dora,
    Operations,
    Governance,
    Ci,
    Security,
    Stack,
    Agents,
    Qa,
}
impl Block {
    pub fn id(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::Posture => "posture",
            Self::CiHealth => "ci-health",
            Self::Dora => "dora",
            Self::Operations => "operations",
            Self::Governance => "governance",
            Self::Ci => "ci",
            Self::Security => "security",
            Self::Stack => "stack",
            Self::Agents => "agents",
            Self::Qa => "qa",
        }
    }
}

/// Cumulative levels: reaching one needs every required rule of it and below.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Basic,
    Bronze,
    Silver,
    Gold,
}
impl Level {
    pub const ALL: [Level; 4] = [Level::Basic, Level::Bronze, Level::Silver, Level::Gold];
    /// The level named as printed (`Basic`, `Bronze`, `Silver`, `Gold`).
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|l| l.to_string() == name)
    }
    /// The next level up, capped at Gold.
    pub fn raised(self) -> Self {
        match self {
            Self::Basic => Self::Bronze,
            Self::Bronze => Self::Silver,
            Self::Silver | Self::Gold => Self::Gold,
        }
    }
}
impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// P1 one person with agents, P2 small team, P3 several teams.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Profile {
    P1,
    P2,
    P3,
}

/// Merge cadence tier: < 10, 10–40, > 40 merged PRs per week.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Cadence {
    Low,
    Mid,
    High,
}

/// Deployable services tier: 1, 2–5, > 5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Services {
    Single,
    Few,
    Many,
}

/// Declared criticality, ordered by what it demands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Criticality {
    Internal,
    Customers,
    PersonalDataOrPayments,
}
impl Criticality {
    /// The values `project.json#criticality` accepts, in order.
    pub const NAMES: [&'static str; 3] = ["internal", "customers", "personal-data-or-payments"];
    pub fn name(self) -> &'static str {
        match self {
            Self::Internal => Self::NAMES[0],
            Self::Customers => Self::NAMES[1],
            Self::PersonalDataOrPayments => Self::NAMES[2],
        }
    }
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "internal" => Some(Self::Internal),
            "customers" => Some(Self::Customers),
            "personal-data-or-payments" => Some(Self::PersonalDataOrPayments),
            _ => None,
        }
    }
}

/// A dimension that makes a rule required whatever the profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Condition {
    CadenceAtLeast(Cadence),
    ServicesAtLeast(Services),
    CriticalityAtLeast(Criticality),
    /// The platform ladder is at L4 (Kubernetes). No measure states the rung
    /// until the `k8s` module lands, so it holds nowhere yet.
    PlatformLadderL4,
}

/// Required when the profile is listed **or** any condition holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Required {
    pub profiles: &'static [Profile],
    pub when: &'static [Condition],
}

/// Where a rule's evidence comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe {
    /// A file of the bounded allowlist, read through [`super::Files`].
    LocalFile { path: &'static str },
    /// The installer's lock.
    Lock,
    /// A host read.
    Remote { id: &'static str },
    /// A manual step an installed module declares, with its probe.
    ManualStep {
        module: &'static str,
        step: &'static str,
    },
}

/// What fixes a failed rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Remediation {
    Module {
        id: &'static str,
    },
    Command {
        text: &'static str,
    },
    Manual {
        step: &'static str,
        instructions: &'static str,
    },
}

/// The GitHub plan a rule needs; a lacking plan is `Unavailable`, never `Failed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Plan {
    Free,
    Team,
    EnterpriseCloud,
}
impl fmt::Display for Plan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Free => "Free",
            Self::Team => "Team",
            Self::EnterpriseCloud => "Enterprise Cloud",
        })
    }
}

/// When a rule can produce evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Milestone {
    Nov7,
    /// Always `unavailable: waits for module <id>` until that module lands.
    WaitsFor(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Passed,
    Failed,
    Unavailable,
    NotRequired,
}

/// What evaluating one rule found: evidence for passed and failed, a reason for
/// unavailable and not-required.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub status: Status,
    pub evidence: Vec<String>,
    pub reason: Option<String>,
    /// What fixes this outcome when its findings name it, in place of the
    /// rule's own remediation (`baseline.managed-content-intact` names the
    /// module the lock records for each file, #1254); empty means the rule's.
    pub remediations: Vec<Remediation>,
}
impl Outcome {
    pub fn passed<S: Into<String>>(evidence: impl IntoIterator<Item = S>) -> Self {
        Self::with(Status::Passed, evidence)
    }
    pub fn failed<S: Into<String>>(evidence: impl IntoIterator<Item = S>) -> Self {
        Self::with(Status::Failed, evidence)
    }
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self::because(Status::Unavailable, reason)
    }
    pub fn not_required(reason: impl Into<String>) -> Self {
        Self::because(Status::NotRequired, reason)
    }
    /// The repository's plan lacks the feature: `requires plan <plan>`.
    pub fn requires_plan(plan: Plan) -> Self {
        Self::unavailable(format!("requires plan {plan}"))
    }
    fn with<S: Into<String>>(status: Status, evidence: impl IntoIterator<Item = S>) -> Self {
        Self {
            status,
            evidence: evidence.into_iter().map(Into::into).collect(),
            reason: None,
            remediations: Vec::new(),
        }
    }
    fn because(status: Status, reason: impl Into<String>) -> Self {
        Self {
            status,
            evidence: Vec::new(),
            reason: Some(reason.into()),
            remediations: Vec::new(),
        }
    }
}

/// One entry of the standard. `evaluate` is a pure function of the context: it
/// never panics, and a missing or unreadable input is `Unavailable` with why.
#[derive(Debug, Clone, Copy)]
pub struct Rule {
    /// `<block>.<kebab>`, stable once shipped.
    pub id: &'static str,
    pub title: &'static str,
    pub block: Block,
    /// One sentence: what is true when it passes.
    pub checks: &'static str,
    pub how: Probe,
    pub level: Level,
    pub required: Required,
    pub remediation: Remediation,
    pub plan: Option<Plan>,
    pub feasible_by: Milestone,
    pub evaluate: fn(&Cx<'_>) -> Outcome,
}

/// Every rule the auditor knows, in report order. Each block adds its rules here;
/// the manual steps of installed modules follow them as rules of their own
/// (`baseline::step_rule`).
pub static REGISTRY: &[Rule] = &[
    baseline::PURPOSE_DECLARED,
    baseline::VERIFY_DECLARED,
    baseline::CRITICALITY_DECLARED,
    #[cfg(feature = "setup-core")]
    baseline::SETUP_INSTALLED,
    #[cfg(feature = "setup-core")]
    baseline::CONVENTIONS_RESOLVED,
    baseline::PROFILE_CURRENT,
    #[cfg(feature = "setup-core")]
    baseline::PLACEHOLDERS_REVIEWED,
    baseline::MERGE_GUARD_REGISTERED,
    #[cfg(feature = "setup-core")]
    baseline::GUIDES_INSTALLED,
    baseline::RELEASE_BASELINE,
    baseline::MANAGED_CONTENT_INTACT,
    #[cfg(feature = "setup-core")]
    baseline::GUIDES_VERIFIED,
    #[cfg(feature = "setup-core")]
    baseline::ENTRYPOINTS_CURRENT,
    #[cfg(feature = "setup-core")]
    baseline::DECISIONS_INDEX_CURRENT,
    baseline::REMOTE_READABLE,
    baseline::BRANCH_PROTECTION_MATCHES,
    baseline::CI_POLICY_MET,
    posture::DEFAULT_BRANCH_PROTECTED,
    posture::NO_OPEN_SECRET_SCANNING_ALERTS,
    posture::REQUIRED_CHECK_ENFORCED,
    posture::NO_UNLISTED_BYPASS_ACTORS,
    posture::HUMAN_APPROVAL_REQUIRED,
    posture::CODEOWNERS_REVIEW,
    posture::SERIALISED_MERGES,
    posture::ACTIONS_PINNED,
    posture::NO_STALE_CRITICAL_ALERTS,
    posture::NO_REPO_SECRETS_WITH_PRODUCTION,
    posture::PRODUCTION_ENVIRONMENT_GUARDED,
    posture::STALE_BRANCHES,
    posture::ORG_2FA_REQUIRED,
    posture::REPO_ADMINS_ARE_OWNERS,
    ci_health::WORKFLOW_EXISTS,
    ci_health::RERUN_RATE,
    ci_health::CANCELLATION_RATE,
    ci_health::MINUTES_BUDGET,
    dora::DEPLOYMENTS_API_IN_USE,
    dora::TIME_TO_RESTORE,
    dora::DEPLOYMENT_FREQUENCY,
    dora::LEAD_TIME,
    dora::CHANGE_FAILURE_RATE,
    operations::POST_DEPLOY_SMOKE,
    operations::ROLLBACK_EVIDENCE,
    operations::UPTIME_FOOTPRINT,
    operations::INCIDENTS_BOUNDED,
    operations::RUNBOOK_PER_ALERT,
    operations::SLO_BURN_RATE_VALIDATED,
    operations::BACKUP_AGE_WITHIN_RPO,
    operations::RESTORE_DRILL_FRESH,
    governance::DEPENDENCY_UPDATES_WITH_COOLDOWN,
    governance::SERVICE_CARD_OWNER,
    governance::CODEOWNERS_PRESENT,
    governance::PR_TEMPLATE_AND_ISSUE_FORMS,
    governance::NO_EXPIRED_BYPASS,
    governance::POSTMORTEM_ACTIONS_CLOSED,
    governance::ADR_STATE_KNOWN,
    governance::NO_EXPIRED_FLAGS,
    governance::COST_TAGS,
    governance::NO_PERSISTENT_OVERSIZING,
    // The module rules the owner allocated (#873); `posture.actions-pinned`
    // stands for `ci.actions-pinned`.
    modules::CI_COMMAND_MISSING,
    modules::CI_AGGREGATE_PRESENT,
    modules::CI_JOB_TIMEOUTS,
    modules::CI_PERMISSIONS_LEAST,
    modules::CI_WORKFLOW_LINT,
    modules::CI_NO_SELF_HOSTED_LABEL,
    modules::CI_HOSTED_MACOS,
    modules::CI_DEPENDABOT_ACTIONS,
    modules::CI_HELDOUT_PRESENT,
    modules::CI_PROTECTED_PATHS_GATE,
    modules::CI_HELDOUT_PROPERTIES,
    modules::CI_PROJECT_CI_STALE,
    modules::CI_REQUIRED_IS_AGGREGATE,
    modules::CI_MAIN_RED,
    modules::CI_MINUTES_MONTH,
    modules::SECURITY_SECRETS_GATE,
    modules::SECURITY_SECRETS_FULL_HISTORY,
    modules::SECURITY_DEPS_GATE,
    modules::SECURITY_SCANNER_UNPINNED,
    modules::SECURITY_TRIVY_COMPROMISED_VERSION,
    modules::SECURITY_BYPASS_INVENTORY_VALID,
    modules::SECURITY_BYPASS_UNREGISTERED,
    modules::SECURITY_BYPASS_EXPIRED,
    security_remote::SECURITY_SECRET_SCANNING,
    security_remote::SECURITY_PRIVATE_VULNERABILITY_REPORTING,
    security_remote::SECURITY_SCANNER_STALE,
    security_remote::SECURITY_ATTESTATION_VERIFIED,
    security_remote::SECURITY_SBOM_SCANNED,
    modules::SECURITY_BINARY_ARTIFACTS,
    modules::SECURITY_SAST_GATE,
    modules::SECURITY_CONTAINER_GATE,
    modules::SECURITY_PII_DECLARED,
    modules::SECURITY_COVERAGE_RATCHET,
    modules::SECURITY_MUTATION_GATE,
    modules::SECURITY_DIFF_COVERAGE,
    modules::STACK_UNCONFIGURED,
    modules::STACK_LOCKFILE_PRESENT,
    modules::STACK_LOCKFILE_NOT_ENFORCED,
    modules::STACK_TOOLCHAIN_PINNED,
    modules::STACK_IMAGE_BY_DIGEST,
    modules::STACK_IMAGE_NONROOT,
    modules::STACK_IMAGE_ARBITRARY_UID,
    modules::AGENTS_DENY_SECRETS,
    modules::AGENTS_STOP_VERIFY,
    modules::AGENTS_PROTECTED_PATHS,
    modules::AGENTS_MCP_ALLOWLIST,
    modules::AGENTS_TECHNICAL_DEBT,
    modules::AGENTS_READABLE_SECRETS,
    modules::AGENTS_CROSS_REVIEW,
    modules::AGENTS_UNATTENDED_GATED,
    modules::AGENTS_HELDOUT_DENIED,
    modules::AGENTS_WORKFLOW_CAPS,
    modules::AGENTS_IDENTITY,
    modules::AGENTS_WORKFLOW_INJECTION,
    // qa (SPEC-qa.md; T10 #1008): the nine ids at the spec's levels, reported
    // after agents; the Silver ones and `qa.main-green` are evaluated by T11
    // (#1009) and T19 (#1019) and say so until then (#873 point 5).
    qa::API_SMOKE_PRESENT,
    qa::WEB_SMOKE_PRESENT,
    qa::SCREENSHOT_BASELINE_PRESENT,
    qa::SNAPSHOTS_PROTECTED,
    qa::HURL_NO_LITERAL_HOST,
    qa::TOOLS_PINNED,
    qa::NO_SNAPSHOT_UPDATE_IN_CI,
    qa::REPORT_ARTIFACT,
    qa::MAIN_GREEN,
    qa::CONTRACT_LINT,
    qa::CONTRACT_COMPATIBLE,
];

/// The calls each rule is guaranteed (SPEC-auditor.md, "Block allowances",
/// #920): what it needs to settle with its samples at their minimum, recorded
/// against the recorded fixtures with the reads shared through the audit's
/// cache. While a rule reads, the allowances of the rules after it are held
/// back. A rule not listed has none: it reads no host, or only from the cache.
/// Per block: posture 12, ci-health 7, DORA 7, governance 1, ci 7; 34 of 60.
/// The static module rules (#873) read no host and have none; ci-baseline's
/// remote rules (#783) read the host: `ci.workflow-lint` the jobs of one run,
/// `ci.minutes-month` its listing and the jobs of `MONTH_MIN_RUNS` runs, the
/// other two only what posture and ci-health already cached. The remote
/// `security.*` rules (#801) have none: last in report order, they read from
/// what the blocks before them left, so they never take from those blocks; a
/// remote half the budget refuses keeps its static half.
pub static ALLOWANCES: &[(&str, u32)] = &[
    ("posture.default-branch-protected", 2),
    ("posture.no-open-secret-scanning-alerts", 1),
    ("posture.no-stale-critical-alerts", 1),
    ("posture.no-repo-secrets-with-production", 3),
    ("posture.stale-branches", 1),
    ("posture.org-2fa-required", 2),
    ("posture.repo-admins-are-owners", 2),
    ("ci-health.workflow-exists", 1),
    ("ci-health.rerun-rate", 1),
    ("ci-health.minutes-budget", ci_health::CYCLE_MIN_RUNS as u32),
    ("dora.deployments-api-in-use", 1),
    ("dora.time-to-restore", 1),
    ("dora.deployment-frequency", dora::FREQUENCY_MIN as u32),
    ("dora.lead-time", 1),
    ("governance.postmortem-actions-closed", 1),
    ("ci.workflow-lint", 1),
    (
        "ci.minutes-month",
        1 + crate::modules::ci_baseline::audit::MONTH_MIN_RUNS as u32,
    ),
];

/// The allowance of the rule `id`, 0 when it has none.
pub fn allowance(id: &str) -> u32 {
    calls_of(ALLOWANCES, id)
}

/// The files each governance rule reads through the contents API under
/// `--fleet`, where a file costs a call (SPEC-auditor.md, "Fleet file reads",
/// #935): every path it reads when none exists, the worst case. The module
/// blocks (#873) read nothing the measures have not cached. Governance 16
/// under `--fleet`; baseline 1, the lock (#1318), which the measures do not
/// read: held for the first baseline rule, it passes on to the first that
/// reads the lock whichever features are built. 50 of the fleet's 100.
pub static FLEET_FILE_READS: &[(&str, u32)] = &[
    ("baseline.purpose-declared", 1),
    ("governance.dependency-updates-with-cooldown", 3),
    ("governance.service-card-owner", 3),
    ("governance.codeowners-present", 3),
    ("governance.pr-template-and-issue-forms", 4),
    ("governance.no-expired-bypass", 1),
    ("governance.adr-state-known", 1),
];

/// The allowance of the rule `id` under `--fleet`: its [`allowance`] plus the
/// files it reads through the contents API.
pub fn fleet_allowance(id: &str) -> u32 {
    allowance(id) + calls_of(FLEET_FILE_READS, id)
}

fn calls_of(table: &[(&str, u32)], id: &str) -> u32 {
    table
        .iter()
        .find(|(rule, _)| *rule == id)
        .map_or(0, |(_, calls)| *calls)
}
