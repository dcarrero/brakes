//! The Azure DevOps interface (decision 2026-10-28, "Host adapter", point 5):
//! the documented example of a second host. It parses the two Azure DevOps
//! identity forms into a [`RepoId`] with a project and answers
//! [`HostErrorKind::Unsupported`] with the one sentence [`UNSUPPORTED`] from
//! every operation. No REST call, no `az` CLI, no credentials: filling it is a
//! module of its own, written only if a host the owner works on uses it.
//!
//! ```
//! use brakes::host::{Host, HostErrorKind, RepoId, azure_devops::{AzureDevOps, UNSUPPORTED}};
//! let repo = RepoId::from_remote("https://dev.azure.com/exampleorg/platform/_git/service").unwrap();
//! assert_eq!(repo.identity(), "exampleorg/platform/service");
//! let error = AzureDevOps.repository(&repo).unwrap_err();
//! assert_eq!((error.kind, error.message.as_str()), (HostErrorKind::Unsupported, UNSUPPORTED));
//! ```
use super::types::{
    Branch, BranchProtection, BranchProtectionSpec, CheckRun, CodeScanningSetup, Collaborator,
    DependabotAlert, Deployment, DeploymentStatus, DirEntry, Environment, EnvironmentSpec,
    FileContents, IssueFilter, IssueMeta, Job, Label, NewIssue, OrgSettings, PullFile, PullFilter,
    PullMeta, Release, RepoSummary, RepositorySettings, RepositorySettingsPatch, Ruleset,
    RunFilter, RunTiming, SecretScanningAlert, SecurityToggle, WorkflowRun, WriteReport,
    segment_ok,
};
use super::{
    Features, Host, HostError, HostErrorKind, HostKind, OwnerId, Partial, RepoId, SecretName,
    SecretScope, WriteToken,
};
use crate::{Result, refuse};

/// The one message every operation of the stub answers.
pub const UNSUPPORTED: &str = "Azure DevOps host adapter is an interface without an implementation; GitHub is the supported host (issue #648)";

const SSH_PREFIX: &str = "git@ssh.dev.azure.com:v3/";
const HTTPS_HOST: &str = "dev.azure.com";

type R<T> = std::result::Result<T, HostError>;

fn unsupported<T>() -> R<T> {
    Err(HostError::new(HostErrorKind::Unsupported, UNSUPPORTED))
}

/// Azure DevOps: identities only; every [`Host`] operation is `Unsupported`.
#[derive(Debug, Clone, Copy, Default)]
pub struct AzureDevOps;

impl AzureDevOps {
    /// Whether `remote` names an Azure DevOps host, so `RepoId::from_remote`
    /// parses it here instead of as a GitHub remote.
    pub fn is_remote(remote: &str) -> bool {
        remote.starts_with("git@ssh.dev.azure.com:")
            || url::Url::parse(remote)
                .is_ok_and(|url| matches!(url.host_str(), Some(HTTPS_HOST | "ssh.dev.azure.com")))
    }

    /// `https://dev.azure.com/{org}/{project}/_git/{repo}` or
    /// `git@ssh.dev.azure.com:v3/{org}/{project}/{repo}`, lowercased with
    /// `.git` stripped; anything else is refused naming both forms.
    pub fn parse_remote(remote: &str) -> Result<RepoId> {
        crate::config::refuse_denied_repository(remote)?;
        let segments = if let Some(path) = remote.strip_prefix(SSH_PREFIX) {
            path.split('/').map(str::to_owned).collect::<Vec<_>>()
        } else {
            let https = url::Url::parse(remote)
                .ok()
                .filter(|url| url.scheme() == "https" && url.host_str() == Some(HTTPS_HOST));
            let Some(url) = https else {
                return refuse(form_error(remote));
            };
            // `_git` sits between project and repository in the HTTPS form only.
            let mut path: Vec<String> = url
                .path()
                .trim_matches('/')
                .split('/')
                .map(str::to_owned)
                .collect();
            if path.len() != 4 || path[2] != "_git" {
                return refuse(form_error(remote));
            }
            path.remove(2);
            path
        };
        let [org, project, name] = segments.as_slice() else {
            return refuse(form_error(remote));
        };
        let name = name.strip_suffix(".git").unwrap_or(name);
        if ![org, project, name].iter().all(|s| segment_ok(s)) {
            return refuse(form_error(remote));
        }
        Ok(RepoId {
            host: HostKind::AzureDevOps,
            owner: org.to_lowercase(),
            project: Some(project.to_lowercase()),
            name: name.to_lowercase(),
        })
    }
}

impl Host for AzureDevOps {
    fn kind(&self) -> HostKind {
        HostKind::AzureDevOps
    }
    fn repository(&self, _repo: &RepoId) -> R<RepositorySettings> {
        unsupported()
    }
    fn features(&self, _repo: &RepoId) -> R<Features> {
        unsupported()
    }
    fn branch_protection(&self, _repo: &RepoId, _branch: &str) -> R<Option<BranchProtection>> {
        unsupported()
    }
    fn rulesets(&self, _repo: &RepoId) -> R<Vec<Ruleset>> {
        unsupported()
    }
    fn environments(&self, _repo: &RepoId) -> R<Vec<Environment>> {
        unsupported()
    }
    fn actions_pull_requests_allowed(&self, _repo: &RepoId) -> R<bool> {
        unsupported()
    }
    fn actions_access(&self, _repo: &RepoId) -> R<String> {
        unsupported()
    }
    fn secret_names(&self, _repo: &RepoId, _scope: &SecretScope) -> R<Vec<SecretName>> {
        unsupported()
    }
    fn workflow_runs(&self, _repo: &RepoId, _filter: &RunFilter) -> R<Vec<WorkflowRun>> {
        unsupported()
    }
    fn run_timing(&self, _repo: &RepoId, _run_id: u64) -> R<RunTiming> {
        unsupported()
    }
    fn jobs(&self, _repo: &RepoId, _run_id: u64) -> R<Vec<Job>> {
        unsupported()
    }
    fn check_runs(&self, _repo: &RepoId, _sha: &str) -> R<Vec<CheckRun>> {
        unsupported()
    }
    fn collaborators(&self, _repo: &RepoId) -> R<Vec<Collaborator>> {
        unsupported()
    }
    fn deployments(&self, _repo: &RepoId, _environment: Option<&str>) -> R<Vec<Deployment>> {
        unsupported()
    }
    fn deployment_statuses(&self, _repo: &RepoId, _deployment_id: u64) -> R<Vec<DeploymentStatus>> {
        unsupported()
    }
    fn latest_deployments(&self, _repo: &RepoId, _environment: &str) -> R<Vec<Deployment>> {
        unsupported()
    }
    fn issues(&self, _repo: &RepoId, _filter: &IssueFilter) -> R<Vec<IssueMeta>> {
        unsupported()
    }
    fn pulls(&self, _repo: &RepoId, _filter: &PullFilter) -> R<Vec<PullMeta>> {
        unsupported()
    }
    fn pulls_for_commit(&self, _repo: &RepoId, _sha: &str) -> R<Vec<PullMeta>> {
        unsupported()
    }
    fn pull_files(&self, _repo: &RepoId, _number: u64) -> R<Vec<PullFile>> {
        unsupported()
    }
    fn file_exists(&self, _repo: &RepoId, _path: &str, _reference: &str) -> R<Option<String>> {
        unsupported()
    }
    fn dependabot_alerts(&self, _repo: &RepoId) -> R<Vec<DependabotAlert>> {
        unsupported()
    }
    fn secret_scanning_alerts(&self, _repo: &RepoId) -> R<Vec<SecretScanningAlert>> {
        unsupported()
    }
    fn branches(&self, _repo: &RepoId) -> R<Vec<Branch>> {
        unsupported()
    }
    fn branch_heads(&self, _repo: &RepoId) -> R<Vec<Branch>> {
        unsupported()
    }
    fn commit_date(&self, _repo: &RepoId, _sha: &str) -> R<Option<String>> {
        unsupported()
    }
    fn file_contents(
        &self,
        _repo: &RepoId,
        _path: &str,
        _reference: &str,
    ) -> R<Option<FileContents>> {
        unsupported()
    }
    fn list_directory(
        &self,
        _repo: &RepoId,
        _path: &str,
        _reference: &str,
    ) -> R<Option<Vec<DirEntry>>> {
        unsupported()
    }
    fn labels(&self, _repo: &RepoId) -> R<Vec<Label>> {
        unsupported()
    }
    fn recent_commits(&self, _repo: &RepoId, _branch: &str, _limit: u32) -> R<Vec<String>> {
        unsupported()
    }
    fn security_toggle(&self, _repo: &RepoId, _toggle: SecurityToggle) -> R<bool> {
        unsupported()
    }
    fn code_scanning_default_setup(&self, _repo: &RepoId) -> R<CodeScanningSetup> {
        unsupported()
    }
    fn repo_variable(&self, _repo: &RepoId, _name: &str) -> R<Option<String>> {
        unsupported()
    }
    fn latest_release(&self, _repo: &RepoId) -> R<Release> {
        unsupported()
    }
    fn release_by_tag(&self, _repo: &RepoId, _tag: &str) -> R<Release> {
        unsupported()
    }
    fn job_log(&self, _repo: &RepoId, _job_id: u64) -> R<String> {
        unsupported()
    }
    fn owner(&self, _name: &str) -> R<OwnerId> {
        unsupported()
    }
    fn list_repositories(&self, _owner: &OwnerId) -> R<Partial<RepoSummary>> {
        unsupported()
    }
    fn org_rulesets(&self, _org: &str) -> R<Vec<Ruleset>> {
        unsupported()
    }
    fn org_settings(&self, _org: &str) -> R<OrgSettings> {
        unsupported()
    }
    fn org_owners(&self, _org: &str) -> R<Vec<String>> {
        unsupported()
    }
    fn ensure_labels(&self, _token: &WriteToken, _labels: &[Label]) -> R<WriteReport> {
        unsupported()
    }
    fn create_issue(&self, _token: &WriteToken, _issue: &NewIssue) -> R<IssueMeta> {
        unsupported()
    }
    fn comment(&self, _token: &WriteToken, _number: u64, _body: &str) -> R<u64> {
        unsupported()
    }
    fn set_repository_settings(
        &self,
        _token: &WriteToken,
        _settings: &RepositorySettingsPatch,
    ) -> R<WriteReport> {
        unsupported()
    }
    fn put_ruleset(&self, _token: &WriteToken, _ruleset: &Ruleset) -> R<WriteReport> {
        unsupported()
    }
    fn put_environment(
        &self,
        _token: &WriteToken,
        _environment: &EnvironmentSpec,
    ) -> R<WriteReport> {
        unsupported()
    }
    fn put_branch_protection(
        &self,
        _token: &WriteToken,
        _branch: &str,
        _protection: &BranchProtectionSpec,
    ) -> R<WriteReport> {
        unsupported()
    }
    fn retire_branch_protection(
        &self,
        _token: &WriteToken,
        _branch: &str,
        _superseded_by: Option<&str>,
    ) -> R<WriteReport> {
        unsupported()
    }
}

fn form_error(remote: &str) -> String {
    format!(
        "Azure DevOps remote is neither https://dev.azure.com/{{org}}/{{project}}/_git/{{repo}} nor git@ssh.dev.azure.com:v3/{{org}}/{{project}}/{{repo}}: {remote}"
    )
}
