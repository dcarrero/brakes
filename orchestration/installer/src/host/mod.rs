//! The host adapter (SPEC-host-adapter.md): one place that talks to a code host,
//! so rules, probes and the auditor never know how GitHub is read or written.
//! This module holds the contract, the identities, the errors and the two gates;
//! [`github::GitHub`] implements it over `remote::Api`;
//! [`azure_devops::AzureDevOps`] is the documented example of a second host:
//! it parses its identities and answers `Unsupported` from every operation.
pub mod authorize;
pub mod azure_devops;
pub mod cli;
pub mod desired;
pub mod github;
pub mod probes;
pub mod types;

pub use authorize::WriteToken;
pub use types::{
    Availability, CallBudget, Features, HostError, HostErrorKind, HostKind, OwnerId, OwnerKind,
    Partial, RepoId, SecretName, SecretScope, Visibility,
};
use types::{
    BranchProtection, BranchProtectionSpec, CheckRun, Collaborator, Deployment, DeploymentStatus,
    Environment, EnvironmentSpec, IssueFilter, IssueMeta, Job, Label, NewIssue, OrgSettings,
    PullFile, PullFilter, PullMeta, RepoSummary, RepositorySettings, RepositorySettingsPatch,
    Ruleset, RunFilter, RunTiming, WorkflowRun, WriteReport,
};
// Security, branch and contents reads (#679)
use types::{
    Branch, CodeScanningSetup, DependabotAlert, DirEntry, FileContents, Release,
    SecretScanningAlert, SecurityToggle,
};

/// What the engine, the auditor and merge-guard know about a code host.
///
/// Reads work on any repository the token can read, except denylisted identities
/// (`authorize::read`). Writes need a [`WriteToken`], minted only by
/// [`authorize::write`] for repositories in the configured write allowlist when the caller
/// passed the explicit write flag; no method accepts more than one repository,
/// none returns or sends a secret value, none merges, re-runs or cancels anything.
/// Every error is a [`HostError`] whose message is one sentence naming the
/// repository, organization or operation. An implementation that does not
/// support an operation answers [`HostErrorKind::Unsupported`]. A method added
/// here is also delegated by the auditor's read cache, `auditor::cached::Cached`.
pub trait Host {
    /// Which host this is.
    fn kind(&self) -> HostKind;

    // Repository reads
    /// `GET repos/{r}`.
    fn repository(&self, repo: &RepoId) -> Result<RepositorySettings, HostError>;
    /// Availability of plan-dependent features, probed per endpoint.
    fn features(&self, repo: &RepoId) -> Result<Features, HostError>;
    /// Classic protection of `branch`; `None` when the branch is not protected.
    fn branch_protection(
        &self,
        repo: &RepoId,
        branch: &str,
    ) -> Result<Option<BranchProtection>, HostError>;
    /// Repository rulesets.
    fn rulesets(&self, repo: &RepoId) -> Result<Vec<Ruleset>, HostError>;
    /// Deployment environments with their branch policy.
    fn environments(&self, repo: &RepoId) -> Result<Vec<Environment>, HostError>;
    /// Whether the workflow token may create (and approve) pull requests:
    /// `can_approve_pull_request_reviews` of `GET repos/{r}/actions/permissions/workflow`
    /// (#946). Default `Unsupported`, as for every additive method.
    fn actions_pull_requests_allowed(&self, repo: &RepoId) -> Result<bool, HostError> {
        Err(HostError::unsupported(
            "actions_pull_requests_allowed",
            repo,
        ))
    }
    /// Which repositories may call the workflows of a private `repo`:
    /// `access_level` of `GET repos/{r}/actions/permissions/access` (`none`,
    /// `user`, `organization`, `enterprise`; #785). Default `Unsupported`.
    fn actions_access(&self, repo: &RepoId) -> Result<String, HostError> {
        Err(HostError::unsupported("actions_access", repo))
    }
    /// Secret names in `scope`: names and update times only, never values.
    fn secret_names(
        &self,
        repo: &RepoId,
        scope: &SecretScope,
    ) -> Result<Vec<SecretName>, HostError>;
    /// Workflow runs matching `filter`, newest first.
    fn workflow_runs(
        &self,
        repo: &RepoId,
        filter: &RunFilter,
    ) -> Result<Vec<WorkflowRun>, HostError>;
    /// Wall-clock duration of one run. Added to the spec's trait by #678; the
    /// default answers `Unsupported` so existing implementations keep compiling.
    fn run_timing(&self, repo: &RepoId, _run_id: u64) -> Result<RunTiming, HostError> {
        Err(HostError::unsupported("run_timing", repo))
    }
    /// Jobs of one run.
    fn jobs(&self, repo: &RepoId, run_id: u64) -> Result<Vec<Job>, HostError>;
    /// Check runs of one commit.
    fn check_runs(&self, repo: &RepoId, sha: &str) -> Result<Vec<CheckRun>, HostError>;
    /// Collaborators: login and permission, no emails.
    fn collaborators(&self, repo: &RepoId) -> Result<Vec<Collaborator>, HostError>;
    /// Deployments, optionally of one environment.
    fn deployments(
        &self,
        repo: &RepoId,
        environment: Option<&str>,
    ) -> Result<Vec<Deployment>, HostError>;
    /// Statuses of one deployment, newest first: the first is the final state.
    /// Added to the spec's trait by #678 (default `Unsupported`).
    fn deployment_statuses(
        &self,
        repo: &RepoId,
        _deployment_id: u64,
    ) -> Result<Vec<DeploymentStatus>, HostError> {
        Err(HostError::unsupported("deployment_statuses", repo))
    }
    /// The newest 100 deployments of `environment`, one call: GitHub lists
    /// them newest first, so a full page never reads the next. Added by #726
    /// so the DORA rules fit their budget (SPEC-auditor.md, "DORA reads").
    fn latest_deployments(
        &self,
        repo: &RepoId,
        _environment: &str,
    ) -> Result<Vec<Deployment>, HostError> {
        Err(HostError::unsupported("latest_deployments", repo))
    }
    /// Issues matching `filter`; pull requests are left out.
    fn issues(&self, repo: &RepoId, filter: &IssueFilter) -> Result<Vec<IssueMeta>, HostError>;
    /// Pull requests matching `filter`.
    fn pulls(&self, repo: &RepoId, filter: &PullFilter) -> Result<Vec<PullMeta>, HostError>;
    /// Pull requests that contain commit `sha` (`merged_at` gives lead time).
    /// Added to the spec's trait by #678 (default `Unsupported`).
    fn pulls_for_commit(&self, repo: &RepoId, _sha: &str) -> Result<Vec<PullMeta>, HostError> {
        Err(HostError::unsupported("pulls_for_commit", repo))
    }
    /// The files pull request `number` changed: one page of 100, `Truncated`
    /// beyond. Added by #983 for the auditor's `post_merge_corrections`
    /// counter (default `Unsupported`).
    fn pull_files(&self, repo: &RepoId, _number: u64) -> Result<Vec<PullFile>, HostError> {
        Err(HostError::unsupported("pull_files", repo))
    }
    /// The blob sha of `path` at `reference`, or `None` when absent.
    fn file_exists(
        &self,
        repo: &RepoId,
        path: &str,
        reference: &str,
    ) -> Result<Option<String>, HostError>;

    // Security, branch and contents reads (#679). Added to the spec's trait by
    // #679; each default answers `Unsupported` so existing implementations keep
    // compiling.
    /// Open Dependabot alerts with severity and creation time.
    fn dependabot_alerts(&self, repo: &RepoId) -> Result<Vec<DependabotAlert>, HostError> {
        Err(HostError::unsupported("dependabot_alerts", repo))
    }
    /// Open secret-scanning alerts: the kind of secret, never the secret.
    fn secret_scanning_alerts(&self, repo: &RepoId) -> Result<Vec<SecretScanningAlert>, HostError> {
        Err(HostError::unsupported("secret_scanning_alerts", repo))
    }
    /// Up to 100 branches with their last-commit dates; `Truncated` beyond.
    fn branches(&self, repo: &RepoId) -> Result<Vec<Branch>, HostError> {
        Err(HostError::unsupported("branches", repo))
    }
    /// Up to 100 branches without their dates (`committed_at` is `None`), at
    /// most two calls; `Truncated` beyond. Added by #721 so a rule can date
    /// branches within its own budget (SPEC-auditor.md, "Posture reads").
    fn branch_heads(&self, repo: &RepoId) -> Result<Vec<Branch>, HostError> {
        Err(HostError::unsupported("branch_heads", repo))
    }
    /// The committer date of commit `sha`, one call; `None` when absent. Added by #721.
    fn commit_date(&self, repo: &RepoId, _sha: &str) -> Result<Option<String>, HostError> {
        Err(HostError::unsupported("commit_date", repo))
    }
    /// The text of `path` at `reference`, at most 64 KiB (`Truncated` beyond);
    /// `None` when absent or a directory.
    fn file_contents(
        &self,
        repo: &RepoId,
        _path: &str,
        _reference: &str,
    ) -> Result<Option<FileContents>, HostError> {
        Err(HostError::unsupported("file_contents", repo))
    }
    /// Name, type and sha of each entry of directory `path` (`""` is the
    /// root) at `reference`; `None` when absent.
    fn list_directory(
        &self,
        repo: &RepoId,
        _path: &str,
        _reference: &str,
    ) -> Result<Option<Vec<DirEntry>>, HostError> {
        Err(HostError::unsupported("list_directory", repo))
    }

    // Reads the probe registry adds (#683); each default answers `Unsupported`.
    /// Every label: name, color and description.
    fn labels(&self, repo: &RepoId) -> Result<Vec<Label>, HostError> {
        Err(HostError::unsupported("labels", repo))
    }
    /// The shas of the newest `limit` commits of `branch` (one page).
    fn recent_commits(
        &self,
        repo: &RepoId,
        _branch: &str,
        _limit: u32,
    ) -> Result<Vec<String>, HostError> {
        Err(HostError::unsupported("recent_commits", repo))
    }
    /// Whether a security setting with its own endpoint is enabled.
    fn security_toggle(&self, repo: &RepoId, _toggle: SecurityToggle) -> Result<bool, HostError> {
        Err(HostError::unsupported("security_toggle", repo))
    }
    /// `GET repos/{r}/code-scanning/default-setup` (#798): any state where
    /// Code Security is available; the plan refusal otherwise.
    fn code_scanning_default_setup(&self, repo: &RepoId) -> Result<CodeScanningSetup, HostError> {
        Err(HostError::unsupported("code_scanning_default_setup", repo))
    }
    /// `GET repos/{r}/actions/variables/{name}`: its value, `None` when unset (#801).
    fn repo_variable(&self, repo: &RepoId, _name: &str) -> Result<Option<String>, HostError> {
        Err(HostError::unsupported("repo_variable", repo))
    }
    /// `GET repos/{r}/releases/latest` of any repository, a scanner's upstream (#801).
    fn latest_release(&self, repo: &RepoId) -> Result<Release, HostError> {
        Err(HostError::unsupported("latest_release", repo))
    }
    /// `GET repos/{r}/releases/tags/{tag}` (#801).
    fn release_by_tag(&self, repo: &RepoId, _tag: &str) -> Result<Release, HostError> {
        Err(HostError::unsupported("release_by_tag", repo))
    }
    /// `GET repos/{r}/actions/jobs/{id}/logs`: the job's log as text (#801).
    fn job_log(&self, repo: &RepoId, _job_id: u64) -> Result<String, HostError> {
        Err(HostError::unsupported("job_log", repo))
    }

    // Organization reads
    /// Whether `name` is a user or an organization.
    fn owner(&self, name: &str) -> Result<OwnerId, HostError>;
    /// Every repository of `owner` the token can see; partial when the rate
    /// limit or the call budget stopped the listing.
    fn list_repositories(&self, owner: &OwnerId) -> Result<Partial<RepoSummary>, HostError>;
    /// Organization rulesets.
    fn org_rulesets(&self, org: &str) -> Result<Vec<Ruleset>, HostError>;
    /// Organization settings the token can read; `None` fields were not visible.
    fn org_settings(&self, org: &str) -> Result<OrgSettings, HostError>;
    /// The logins of the organization's owners (`GET orgs/{org}/members?role=admin`),
    /// read by `posture.repo-admins-are-owners` (#1218). Default `Unsupported`,
    /// as for every additive method.
    fn org_owners(&self, org: &str) -> Result<Vec<String>, HostError> {
        Err(HostError::new(
            HostErrorKind::Unsupported,
            format!("org_owners of {org} is not supported by this host"),
        ))
    }

    // Writes: one repository per call, never secrets, never merges, never protection bypass
    /// Create or update `labels`; a second run reports them `unchanged`.
    fn ensure_labels(&self, token: &WriteToken, labels: &[Label])
    -> Result<WriteReport, HostError>;
    /// Open one issue.
    fn create_issue(&self, token: &WriteToken, issue: &NewIssue) -> Result<IssueMeta, HostError>;
    /// Comment on issue or pull request `number`; returns the comment id.
    fn comment(&self, token: &WriteToken, number: u64, body: &str) -> Result<u64, HostError>;
    /// `PATCH repos/{r}` with the allowed keys only.
    fn set_repository_settings(
        &self,
        token: &WriteToken,
        settings: &RepositorySettingsPatch,
    ) -> Result<WriteReport, HostError>;
    /// Create or update a ruleset by name.
    fn put_ruleset(&self, token: &WriteToken, ruleset: &Ruleset) -> Result<WriteReport, HostError>;
    /// Create or update an environment and its deployment branch policy.
    fn put_environment(
        &self,
        token: &WriteToken,
        environment: &EnvironmentSpec,
    ) -> Result<WriteReport, HostError>;
    /// Write the classic protection of `branch` (#879); default `Unsupported`.
    fn put_branch_protection(
        &self,
        token: &WriteToken,
        _branch: &str,
        _protection: &BranchProtectionSpec,
    ) -> Result<WriteReport, HostError> {
        Err(HostError::unsupported(
            "put_branch_protection",
            token.repo(),
        ))
    }
    /// Remove the classic protection of `branch` once a ruleset requires its
    /// checks (#879), or requires `superseded_by`, the aggregate check that
    /// supersedes them (#1149); default `Unsupported`.
    fn retire_branch_protection(
        &self,
        token: &WriteToken,
        _branch: &str,
        _superseded_by: Option<&str>,
    ) -> Result<WriteReport, HostError> {
        Err(HostError::unsupported(
            "retire_branch_protection",
            token.repo(),
        ))
    }
}
