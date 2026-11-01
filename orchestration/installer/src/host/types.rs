//! Identities, errors, availability and the read models of the host contract.
//! Plain serde structs: no type here can hold a secret value, and `None` always
//! means "the token could not see the field", never `false`.
use super::azure_devops::AzureDevOps;
use crate::{Result, refuse, scope};
use serde::{Deserialize, Serialize};
use std::{cell::Cell, collections::BTreeMap, fmt};

/// The code hosts the contract knows; only GitHub has an implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum HostKind {
    #[serde(rename = "github")]
    GitHub,
    #[serde(rename = "azure-devops")]
    AzureDevOps,
}
impl fmt::Display for HostKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::GitHub => "github",
            Self::AzureDevOps => "azure-devops",
        })
    }
}

/// What the host says an owner is; `Unknown` until `Host::owner` asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OwnerKind {
    User,
    Organization,
    Unknown,
}

/// A user or organization on a host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerId {
    pub host: HostKind,
    pub name: String,
    pub kind: OwnerKind,
}
impl fmt::Display for OwnerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)
    }
}

/// A repository on a host: `owner/name` on GitHub, `org/project/name` on Azure
/// DevOps. Lowercased, `.git` stripped, the character set `remote::inspect_report`
/// enforces. Build one with `parse` or `from_remote`; a hand-built value still
/// goes through the gates of `host::authorize`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RepoId {
    pub host: HostKind,
    pub owner: String,
    pub project: Option<String>,
    pub name: String,
}
impl RepoId {
    /// `owner/name` of a GitHub repository, any owner; an identity naming a word of
    /// the configured denylist is refused here, before any gate or transport.
    pub fn parse(identity: &str) -> Result<Self> {
        crate::config::refuse_denied_repository(identity)?;
        let parts: Vec<&str> = identity.split('/').collect();
        let [owner, name] = parts.as_slice() else {
            return refuse(format!("Repository identity is not owner/name: {identity}"));
        };
        let name = name.strip_suffix(".git").unwrap_or(name);
        if !segment_ok(owner) || !segment_ok(name) {
            return refuse(format!("Repository identity is not owner/name: {identity}"));
        }
        Ok(Self {
            host: HostKind::GitHub,
            owner: owner.to_lowercase(),
            project: None,
            name: name.to_lowercase(),
        })
    }
    /// The repository a Git remote URL names, dispatched on the hostname: an
    /// Azure DevOps remote parses with `azure_devops::AzureDevOps::parse_remote`,
    /// any other with the URL, host and protocol rules of
    /// `scope::remote_identity` and without its allowlist.
    pub fn from_remote(remote: &str) -> Result<Self> {
        crate::config::refuse_denied_repository(remote)?;
        if AzureDevOps::is_remote(remote) {
            return AzureDevOps::parse_remote(remote);
        }
        Self::parse(&scope::github_path(remote)?)
    }
    /// The identity the allowlist and the refusals name: `owner/name` or
    /// `owner/project/name`.
    pub fn identity(&self) -> String {
        match &self.project {
            Some(project) => format!("{}/{}/{}", self.owner, project, self.name),
            None => format!("{}/{}", self.owner, self.name),
        }
    }
    /// Whether any part of the identity names a word of the configured denylist
    /// (case-insensitive); a configuration that cannot load denies everything.
    pub fn is_denied(&self) -> bool {
        crate::config::denied_word(&self.identity()).map_or(true, |w| w.is_some())
    }
}
impl fmt::Display for RepoId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.identity())
    }
}
pub(crate) fn segment_ok(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}

/// Why a host operation did not answer; the HTTP mapping lives in the GitHub
/// implementation, every other kind is produced by the adapter itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostErrorKind {
    Unsupported,
    Unauthenticated,
    Forbidden,
    NotFound,
    RateLimited { reset_epoch: Option<i64> },
    Truncated,
    Shape,
    Transport,
    WriteRefused,
}

/// One sentence that names the repository, organization or operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostError {
    pub kind: HostErrorKind,
    pub message: String,
}
impl HostError {
    pub fn new(kind: HostErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
    /// The fixed sentence of an operation a host does not implement.
    pub fn unsupported(operation: &str, repo: &RepoId) -> Self {
        Self::new(
            HostErrorKind::Unsupported,
            format!("{operation} is not supported on {repo} by this host adapter"),
        )
    }
}
impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for HostError {}

/// What a probe said about a plan-dependent feature; never decided by a plan name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    Available,
    Unavailable { reason: String },
    Unknown { reason: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Visibility {
    Public,
    Private,
    Internal,
}

/// Probed availability per repository (SPEC-host-adapter.md, "Features").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Features {
    pub visibility: Visibility,
    /// The owner's plan name when readable; a hint for the report, never a verdict.
    pub plan_hint: Option<String>,
    pub rulesets: Availability,
    pub environments: Availability,
    pub branch_protection: Availability,
    pub required_reviewers: Availability,
    pub dependabot_alerts: Availability,
    pub secret_scanning: Availability,
    pub workflow_lockfile: Availability,
    pub merge_queue: Availability,
}

impl std::fmt::Display for Availability {
    /// `available`, `unavailable (status: message)` or `unknown (reason)`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Available => f.write_str("available"),
            Self::Unavailable { reason } => write!(f, "unavailable ({reason})"),
            Self::Unknown { reason } => write!(f, "unknown ({reason})"),
        }
    }
}
impl Features {
    /// The text form of `host features`: visibility, the plan hint, then one
    /// line per feature in field order.
    pub fn lines(&self) -> Vec<String> {
        let visibility = match self.visibility {
            Visibility::Public => "public",
            Visibility::Private => "private",
            Visibility::Internal => "internal",
        };
        let hint = match &self.plan_hint {
            Some(plan) => format!("{plan} (never decides)"),
            None => "none".to_owned(),
        };
        let mut lines = vec![
            format!("visibility: {visibility}"),
            format!("plan_hint: {hint}"),
        ];
        for (name, availability) in [
            ("rulesets", &self.rulesets),
            ("environments", &self.environments),
            ("branch_protection", &self.branch_protection),
            ("required_reviewers", &self.required_reviewers),
            ("dependabot_alerts", &self.dependabot_alerts),
            ("secret_scanning", &self.secret_scanning),
            ("workflow_lockfile", &self.workflow_lockfile),
            ("merge_queue", &self.merge_queue),
        ] {
            lines.push(format!("{name}: {availability}"));
        }
        lines
    }
}

/// Where a secret name was listed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretScope {
    Repository,
    Environment(String),
    Organization,
    /// The repository's Dependabot secrets, the only ones a Dependabot-triggered
    /// run can read (#940).
    Dependabot,
}

/// A secret's name, scope and last update. There is no field for a value and
/// no type in this crate that could hold one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretName {
    pub name: String,
    pub scope: SecretScope,
    pub updated_at: Option<String>,
}

/// A read that may have stopped early: what was read, why it stopped, and the
/// identities it could not read. Never a silent partial result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Partial<T> {
    pub items: Vec<T>,
    pub stopped: Option<HostError>,
    pub unread: Vec<String>,
}
impl<T> Partial<T> {
    pub fn complete(items: Vec<T>) -> Self {
        Self {
            items,
            stopped: None,
            unread: Vec::new(),
        }
    }
    pub fn is_complete(&self) -> bool {
        self.stopped.is_none() && self.unread.is_empty()
    }
}

/// How many host calls one invocation may spend; exhaustion stops, never waits.
/// A caller may hold back part of it for later work ([`CallBudget::hold`]).
#[derive(Debug)]
pub struct CallBudget {
    limit: u32,
    used: Cell<u32>,
    held: Cell<u32>,
    refused: Cell<bool>,
}
impl CallBudget {
    pub const DEFAULT_LIMIT: u32 = 2_000;
    pub fn new(limit: u32) -> Self {
        Self {
            limit,
            used: Cell::new(0),
            held: Cell::new(0),
            refused: Cell::new(false),
        }
    }
    pub fn limit(&self) -> u32 {
        self.limit
    }
    pub fn used(&self) -> u32 {
        self.used.get()
    }
    /// Holds back `calls` of the limit from now on, replacing what was held:
    /// a call is refused once it would eat into them. `hold(0)` releases.
    pub fn hold(&self, calls: u32) {
        self.held.set(calls);
    }
    /// Whether a call was refused, the held-back calls included.
    pub fn refused(&self) -> bool {
        self.refused.get()
    }
    /// Counts one call, or refuses it as `RateLimited` without a reset time.
    pub fn spend(&self) -> std::result::Result<(), HostError> {
        let held = self.held.get();
        if self.used.get().saturating_add(held) >= self.limit {
            self.refused.set(true);
            let mut message = format!("call budget of {} exhausted", self.limit);
            if held > 0 {
                message.push_str(&format!(", {held} held back"));
            }
            return Err(HostError::new(
                HostErrorKind::RateLimited { reset_epoch: None },
                message,
            ));
        }
        self.used.set(self.used.get() + 1);
        Ok(())
    }
}
impl Default for CallBudget {
    fn default() -> Self {
        Self::new(Self::DEFAULT_LIMIT)
    }
}

// --- read models -----------------------------------------------------------------

/// `GET repos/{r}`: the settings the auditor and `apply --remote` compare.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepositorySettings {
    pub id: String,
    pub default_branch: String,
    pub visibility: Visibility,
    pub archived: bool,
    pub fork: bool,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub pushed_at: Option<String>,
    #[serde(default)]
    pub allow_squash_merge: Option<bool>,
    #[serde(default)]
    pub allow_merge_commit: Option<bool>,
    #[serde(default)]
    pub allow_rebase_merge: Option<bool>,
    #[serde(default)]
    pub delete_branch_on_merge: Option<bool>,
    #[serde(default)]
    pub allow_auto_merge: Option<bool>,
    #[serde(default)]
    pub has_wiki: Option<bool>,
    #[serde(default)]
    pub has_projects: Option<bool>,
    #[serde(default)]
    pub web_commit_signoff_required: Option<bool>,
    #[serde(default)]
    pub secret_scanning: Option<String>,
    #[serde(default)]
    pub secret_scanning_push_protection: Option<String>,
    /// Read by the `repo-settings` probe (#683).
    #[serde(default)]
    pub allow_update_branch: Option<bool>,
}

/// `GET repos/{r}/code-scanning/default-setup` (T10, #798): answered 200 with a
/// `state` (`configured` or `not-configured`) where Code Security is available,
/// 403 with the plan message elsewhere.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeScanningSetup {
    pub state: String,
}

/// A release of a repository: `GET repos/{r}/releases/latest` or
/// `releases/tags/{tag}` (#801, `security.scanner-stale`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Release {
    pub tag_name: String,
    pub published_at: String,
}

/// A repository security setting GitHub exposes as its own endpoint, read by
/// [`crate::host::Host::security_toggle`] (#683).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityToggle {
    /// `repos/{r}/vulnerability-alerts`: 204 enabled, 404 disabled.
    VulnerabilityAlerts,
    /// `repos/{r}/automated-security-fixes`: `enabled`, or 404 disabled.
    AutomatedSecurityFixes,
    /// `repos/{r}/private-vulnerability-reporting`: `enabled`; 404 stays
    /// `NotFound` (GitHub answers it for private repositories).
    PrivateVulnerabilityReporting,
}

impl SecurityToggle {
    /// The endpoint under `repos/{r}/`.
    pub fn endpoint(self) -> &'static str {
        match self {
            SecurityToggle::VulnerabilityAlerts => "vulnerability-alerts",
            SecurityToggle::AutomatedSecurityFixes => "automated-security-fixes",
            SecurityToggle::PrivateVulnerabilityReporting => "private-vulnerability-reporting",
        }
    }
    /// What the setting is called in messages.
    pub fn title(self) -> &'static str {
        match self {
            SecurityToggle::VulnerabilityAlerts => "Dependabot alerts",
            SecurityToggle::AutomatedSecurityFixes => "Dependabot security updates",
            SecurityToggle::PrivateVulnerabilityReporting => "private vulnerability reporting",
        }
    }
}

/// The settings `set_repository_settings` may write; nothing else. The
/// boolean keys and the two secret-scanning statuses (`enabled` or
/// `disabled`) go in one `PATCH repos/{r}`; `vulnerability_alerts`,
/// `automated_security_fixes` and `private_vulnerability_reporting` are `PUT`
/// to their own endpoints and may only be `true` (disabling needs `DELETE`,
/// which is ask-first). An unknown key is refused when the patch is read,
/// naming the key (#876).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositorySettingsPatch {
    #[serde(default)]
    pub allow_squash_merge: Option<bool>,
    #[serde(default)]
    pub allow_merge_commit: Option<bool>,
    #[serde(default)]
    pub allow_rebase_merge: Option<bool>,
    #[serde(default)]
    pub delete_branch_on_merge: Option<bool>,
    #[serde(default)]
    pub allow_auto_merge: Option<bool>,
    #[serde(default)]
    pub has_wiki: Option<bool>,
    #[serde(default)]
    pub has_projects: Option<bool>,
    #[serde(default)]
    pub web_commit_signoff_required: Option<bool>,
    #[serde(default)]
    pub secret_scanning: Option<String>,
    #[serde(default)]
    pub secret_scanning_push_protection: Option<String>,
    #[serde(default)]
    pub allow_update_branch: Option<bool>,
    /// `PUT repos/{r}/vulnerability-alerts` (Dependabot alerts).
    #[serde(default)]
    pub vulnerability_alerts: Option<bool>,
    /// `PUT repos/{r}/automated-security-fixes` (Dependabot security updates).
    #[serde(default)]
    pub automated_security_fixes: Option<bool>,
    /// `PUT repos/{r}/private-vulnerability-reporting` (#854).
    #[serde(default)]
    pub private_vulnerability_reporting: Option<bool>,
}

/// A repository or organization ruleset, as read or as written by name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ruleset {
    #[serde(default)]
    pub id: Option<u64>,
    pub name: String,
    pub target: String,
    pub enforcement: String,
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub rules: Vec<String>,
    #[serde(default)]
    pub required_status_checks: Vec<String>,
    #[serde(default)]
    pub required_approving_review_count: Option<u32>,
    #[serde(default)]
    pub bypass_actors: Vec<String>,
    /// Each rule's `parameters` object by rule type, as GitHub returns it or a
    /// committed ruleset file declares it; `put_ruleset` sends it verbatim (#878).
    #[serde(default)]
    pub rule_parameters: BTreeMap<String, serde_json::Value>,
}

/// The ruleset bypass policy (decision 2026-10-31, #1218, amending 2026-10-28
/// point 7) over one actor in the adapter's `actor_type:actor_id:bypass_mode`
/// form: `Err` with why it is refused. `repo-baseline` refuses a declared actor
/// with it and `put_ruleset` refuses to send one; neither adds an actor.
pub fn bypass_actor_refusal(actor: &str) -> std::result::Result<(), String> {
    let mut parts = actor.split(':');
    let (Some(kind), Some(id), Some(mode), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(BYPASS_SHAPE.to_owned());
    };
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_digit()) {
        return Err(BYPASS_SHAPE.to_owned());
    }
    if !BYPASS_ACTOR_TYPES.contains(&kind) {
        return Err(format!(
            "type {kind} is not allowed; bypass actors are OrganizationAdmin, RepositoryRole or Team, never an agent identity or App"
        ));
    }
    if !BYPASS_MODES.contains(&mode) {
        return Err(format!(
            "mode {mode} is not allowed; use pull_request or always"
        ));
    }
    if kind == ORGANIZATION_ADMIN && id != "1" {
        return Err("OrganizationAdmin is written with the id 1, which GitHub ignores".to_owned());
    }
    Ok(())
}

/// One actor of the adapter's form as GitHub's `bypass_actors` item; the
/// actor passed `bypass_actor_refusal`, so its id is numeric.
pub fn bypass_actor_json(actor: &str) -> serde_json::Value {
    let mut parts = actor.splitn(3, ':');
    let (kind, id, mode) = (parts.next(), parts.next(), parts.next());
    serde_json::json!({
        "actor_id": id.and_then(|id| id.parse::<u64>().ok()),
        "actor_type": kind,
        "bypass_mode": mode,
    })
}

const BYPASS_SHAPE: &str = "not actor_type:actor_id:bypass_mode with a numeric actor_id";
/// The actor types a ruleset may bypass with: never `Integration` (any App,
/// agent identities included), `DeployKey` or `User`.
pub const BYPASS_ACTOR_TYPES: [&str; 3] = [ORGANIZATION_ADMIN, "RepositoryRole", "Team"];
/// `pull_request` keeps direct pushes impossible; `always` is admitted with the
/// inventory entry's reason; `exempt` leaves no bypass audit entry.
pub const BYPASS_MODES: [&str; 2] = ["pull_request", "always"];
/// GitHub ignores `actor_id` for this type; `1` is its canonical id.
pub const ORGANIZATION_ADMIN: &str = "OrganizationAdmin";

/// The full classic protection `put_branch_protection` writes to one branch
/// (#879). Required checks need `enforce_admins` ("Never merge on red");
/// `required_approving_review_count: None` means no review requirement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BranchProtectionSpec {
    #[serde(default)]
    pub required_status_checks: Vec<String>,
    #[serde(default)]
    pub strict: bool,
    pub enforce_admins: bool,
    #[serde(default)]
    pub required_approving_review_count: Option<u32>,
    #[serde(default)]
    pub required_linear_history: bool,
    #[serde(default)]
    pub allow_force_pushes: bool,
    #[serde(default)]
    pub allow_deletions: bool,
}

/// Classic branch protection as read; written from a [`BranchProtectionSpec`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BranchProtection {
    pub branch: String,
    #[serde(default)]
    pub required_status_checks: Vec<String>,
    #[serde(default)]
    pub strict: Option<bool>,
    #[serde(default)]
    pub enforce_admins: Option<bool>,
    #[serde(default)]
    pub required_approving_review_count: Option<u32>,
    /// `required_pull_request_reviews.require_code_owner_reviews` (#889).
    #[serde(default)]
    pub require_code_owner_reviews: Option<bool>,
    #[serde(default)]
    pub required_linear_history: Option<bool>,
    #[serde(default)]
    pub allow_force_pushes: Option<bool>,
    #[serde(default)]
    pub allow_deletions: Option<bool>,
}

/// How an environment restricts deployments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentBranchPolicy {
    Unrestricted,
    ProtectedBranches,
    Custom { patterns: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Environment {
    #[serde(default)]
    pub id: Option<u64>,
    pub name: String,
    pub deployment_branch_policy: DeploymentBranchPolicy,
    #[serde(default)]
    pub reviewers: Vec<String>,
    #[serde(default)]
    pub wait_timer_minutes: Option<u32>,
}

/// What `put_environment` sends (`PUT repos/{r}/environments/{name}`); never secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentSpec {
    pub name: String,
    pub deployment_branch_policy: DeploymentBranchPolicy,
    #[serde(default)]
    pub reviewers: Vec<String>,
    #[serde(default)]
    pub wait_timer_minutes: Option<u32>,
}

/// Which workflow runs to read; every field narrows.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunFilter {
    #[serde(default)]
    pub branch: Option<String>,
    #[serde(default)]
    pub event: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub created_since: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowRun {
    pub id: u64,
    pub name: String,
    pub head_sha: String,
    pub head_branch: String,
    pub event: String,
    pub status: String,
    #[serde(default)]
    pub conclusion: Option<String>,
    #[serde(default)]
    pub run_attempt: Option<u32>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
    /// When the latest attempt started (#983); `None` when GitHub did not say.
    #[serde(default)]
    pub run_started_at: Option<String>,
    #[serde(default)]
    pub pull_requests: Vec<u64>,
}

/// `GET actions/runs/{id}/timing`: the wall-clock duration of one run, the
/// figure CI minutes are summed from (billable minutes are not read).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunTiming {
    pub run_id: u64,
    pub run_duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Job {
    pub id: u64,
    pub name: String,
    pub status: String,
    #[serde(default)]
    pub conclusion: Option<String>,
    #[serde(default)]
    pub started_at: Option<String>,
    #[serde(default)]
    pub completed_at: Option<String>,
    #[serde(default)]
    pub labels: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckRun {
    pub id: u64,
    pub name: String,
    pub status: String,
    #[serde(default)]
    pub conclusion: Option<String>,
    #[serde(default)]
    pub app: Option<String>,
    #[serde(default)]
    pub completed_at: Option<String>,
}

/// Login and permission only; no emails, no names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Collaborator {
    pub login: String,
    pub permission: String,
    #[serde(default)]
    pub kind: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deployment {
    pub id: u64,
    pub environment: String,
    pub sha: String,
    #[serde(default)]
    pub reference: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    /// Not in GitHub's deployment list: `Host::deployments` leaves it `None`;
    /// the final state is the first of `Host::deployment_statuses`.
    #[serde(default)]
    pub state: Option<String>,
}

/// One status of a deployment (`queued`, `in_progress`, `success`, `failure`,
/// `error`, `inactive`, …); GitHub lists them newest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentStatus {
    pub id: u64,
    pub state: String,
    #[serde(default)]
    pub environment: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueFilter {
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub since: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueMeta {
    pub number: u64,
    pub title: String,
    pub state: String,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub author: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub closed_at: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    /// The Markdown body, where issue forms put their fields.
    #[serde(default)]
    pub body: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PullFilter {
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub base: Option<String>,
    #[serde(default)]
    pub since: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PullMeta {
    pub number: u64,
    pub title: String,
    pub state: String,
    pub head_sha: String,
    pub base: String,
    #[serde(default)]
    pub author: Option<String>,
    #[serde(default)]
    pub draft: Option<bool>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub merged_at: Option<String>,
    #[serde(default)]
    pub closed_at: Option<String>,
    #[serde(default)]
    pub merge_commit_sha: Option<String>,
}

/// One entry of `GET repos/{r}/pulls/{n}/files` (#983): the path, GitHub's
/// `status` (`added`, `modified`, `removed`, `renamed`, …) and, for a rename,
/// the path it had before.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PullFile {
    pub filename: String,
    pub status: String,
    #[serde(default)]
    pub previous_filename: Option<String>,
}

/// One row of `list_repositories`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoSummary {
    pub id: RepoId,
    pub visibility: Visibility,
    pub default_branch: String,
    pub archived: bool,
    pub fork: bool,
    #[serde(default)]
    pub pushed_at: Option<String>,
    #[serde(default)]
    pub language: Option<String>,
}

/// `GET orgs/{o}`: `None` means the token could not see the field, never `false`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgSettings {
    #[serde(default)]
    pub two_factor_requirement_enabled: Option<bool>,
    #[serde(default)]
    pub default_repository_permission: Option<String>,
    #[serde(default)]
    pub members_can_create_public_repositories: Option<bool>,
    #[serde(default)]
    pub plan_hint: Option<String>,
    #[serde(default)]
    pub web_commit_signoff_required: Option<bool>,
}

/// A label to ensure: created when absent, updated when colour or description differ.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Label {
    pub name: String,
    pub color: String,
    #[serde(default)]
    pub description: Option<String>,
}

/// An issue to create; the body is the caller's, the adapter never adds to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewIssue {
    pub title: String,
    pub body: String,
    #[serde(default)]
    pub labels: Vec<String>,
}

/// What a write did, per item, so a second run can report `unchanged`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteReport {
    pub created: Vec<String>,
    pub updated: Vec<String>,
    pub unchanged: Vec<String>,
    /// Item → the single-line reason it was not written.
    pub skipped: BTreeMap<String, String>,
    /// Items the write removed (classic protection retired, #879).
    #[serde(default)]
    pub removed: Vec<String>,
}

// --- security, branch and contents reads (#679) ------------------------------------

/// One open Dependabot alert: what the auditor ranks by severity and age.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependabotAlert {
    pub number: u64,
    /// `low`, `medium`, `high` or `critical`.
    pub severity: String,
    #[serde(default)]
    pub package: Option<String>,
    #[serde(default)]
    pub ecosystem: Option<String>,
    #[serde(default)]
    pub manifest_path: Option<String>,
    pub created_at: String,
}

/// One open secret-scanning alert: the kind of secret, never the secret. There
/// is no field that could hold the literal value GitHub calls `secret`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretScanningAlert {
    pub number: u64,
    pub secret_type: String,
    #[serde(default)]
    pub secret_type_display_name: Option<String>,
    #[serde(default)]
    pub validity: Option<String>,
    #[serde(default)]
    pub push_protection_bypassed: Option<bool>,
    pub created_at: String,
}

/// A branch and the date of its last commit (`committer.date`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Branch {
    pub name: String,
    pub sha: String,
    #[serde(default)]
    pub protected: Option<bool>,
    #[serde(default)]
    pub committed_at: Option<String>,
}

/// A text file of at most 64 KiB, decoded from GitHub's base64.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileContents {
    pub path: String,
    pub sha: String,
    pub size: u64,
    pub text: String,
}

/// What a directory entry is, in GitHub's `type` words.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    File,
    Dir,
    Symlink,
    Submodule,
}

/// One directory entry: name, type and sha only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirEntry {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: EntryKind,
    pub sha: String,
}
