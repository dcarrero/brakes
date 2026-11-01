//! The read cache of one audit (SPEC-auditor.md, "One read per endpoint per
//! audit", #917): a [`Host`] in front of the audit's host that answers a read
//! it has already made from memory, so the rules that share a source (classic
//! protection, the rulesets, the environments, the latest runs) spend one call
//! between them and the call budget counts real calls only. The audit owns it
//! and drops it when it ends; it is not part of the host adapter's contract.
use crate::host::{
    Features, Host, HostError, HostErrorKind, HostKind, OwnerId, Partial, RepoId, SecretScope,
    WriteToken,
    types::{
        Branch, BranchProtection, BranchProtectionSpec, CheckRun, CodeScanningSetup, Collaborator,
        DependabotAlert, Deployment, DeploymentStatus, DirEntry, Environment, EnvironmentSpec,
        FileContents, IssueFilter, IssueMeta, Job, Label, NewIssue, OrgSettings, PullFile,
        PullFilter, PullMeta, Release, RepoSummary, RepositorySettings, RepositorySettingsPatch,
        Ruleset, RunFilter, RunTiming, SecretName, SecretScanningAlert, SecurityToggle,
        WorkflowRun, WriteReport,
    },
};
use std::{any::Any, cell::RefCell, collections::HashMap};

type R<T> = Result<T, HostError>;

/// Memoises every read of `host` by method and arguments; writes pass through
/// and forget what was read, since they may change it. Every method of
/// [`Host`] is delegated explicitly: a method left to its default would answer
/// `Unsupported` through the cache, so `tests/auditor_cached.rs` fails until a
/// method added to the trait is delegated here too (#920).
pub struct Cached<'a> {
    host: &'a dyn Host,
    reads: RefCell<HashMap<String, Box<dyn Any>>>,
}

impl<'a> Cached<'a> {
    pub fn new(host: &'a dyn Host) -> Self {
        Self {
            host,
            reads: RefCell::default(),
        }
    }

    /// The answer read before under `key`, or `read`'s, kept unless it is an
    /// error that may clear within the audit.
    fn read<T: Clone + 'static>(&self, key: String, read: impl FnOnce() -> R<T>) -> R<T> {
        if let Some(hit) = self
            .reads
            .borrow()
            .get(&key)
            .and_then(|hit| hit.downcast_ref::<R<T>>())
        {
            return hit.clone();
        }
        let answer = read();
        if lasts(&answer) {
            self.reads
                .borrow_mut()
                .insert(key, Box::new(answer.clone()));
        }
        answer
    }

    fn wrote<T>(&self, answer: R<T>) -> R<T> {
        self.reads.borrow_mut().clear();
        answer
    }
}

/// An answer, or an error that is a property of the repository. A rate limit,
/// the call budget exhausted and a transport failure may clear: read again.
fn lasts<T>(answer: &R<T>) -> bool {
    !matches!(
        answer,
        Err(HostError {
            kind: HostErrorKind::RateLimited { .. } | HostErrorKind::Transport,
            ..
        })
    )
}

impl Host for Cached<'_> {
    fn kind(&self) -> HostKind {
        self.host.kind()
    }
    fn repository(&self, repo: &RepoId) -> R<RepositorySettings> {
        self.read(format!("repository {repo}"), || self.host.repository(repo))
    }
    fn features(&self, repo: &RepoId) -> R<Features> {
        self.read(format!("features {repo}"), || self.host.features(repo))
    }
    fn branch_protection(&self, repo: &RepoId, branch: &str) -> R<Option<BranchProtection>> {
        self.read(format!("branch_protection {repo} {branch:?}"), || {
            self.host.branch_protection(repo, branch)
        })
    }
    fn rulesets(&self, repo: &RepoId) -> R<Vec<Ruleset>> {
        self.read(format!("rulesets {repo}"), || self.host.rulesets(repo))
    }
    fn environments(&self, repo: &RepoId) -> R<Vec<Environment>> {
        self.read(format!("environments {repo}"), || {
            self.host.environments(repo)
        })
    }
    fn actions_pull_requests_allowed(&self, repo: &RepoId) -> R<bool> {
        self.read(format!("actions_pull_requests_allowed {repo}"), || {
            self.host.actions_pull_requests_allowed(repo)
        })
    }
    fn actions_access(&self, repo: &RepoId) -> R<String> {
        self.read(format!("actions_access {repo}"), || {
            self.host.actions_access(repo)
        })
    }
    fn secret_names(&self, repo: &RepoId, scope: &SecretScope) -> R<Vec<SecretName>> {
        self.read(format!("secret_names {repo} {scope:?}"), || {
            self.host.secret_names(repo, scope)
        })
    }
    fn workflow_runs(&self, repo: &RepoId, filter: &RunFilter) -> R<Vec<WorkflowRun>> {
        self.read(format!("workflow_runs {repo} {filter:?}"), || {
            self.host.workflow_runs(repo, filter)
        })
    }
    fn run_timing(&self, repo: &RepoId, run_id: u64) -> R<RunTiming> {
        self.read(format!("run_timing {repo} {run_id}"), || {
            self.host.run_timing(repo, run_id)
        })
    }
    fn jobs(&self, repo: &RepoId, run_id: u64) -> R<Vec<Job>> {
        self.read(format!("jobs {repo} {run_id}"), || {
            self.host.jobs(repo, run_id)
        })
    }
    fn check_runs(&self, repo: &RepoId, sha: &str) -> R<Vec<CheckRun>> {
        self.read(format!("check_runs {repo} {sha:?}"), || {
            self.host.check_runs(repo, sha)
        })
    }
    fn collaborators(&self, repo: &RepoId) -> R<Vec<Collaborator>> {
        self.read(format!("collaborators {repo}"), || {
            self.host.collaborators(repo)
        })
    }
    fn deployments(&self, repo: &RepoId, environment: Option<&str>) -> R<Vec<Deployment>> {
        self.read(format!("deployments {repo} {environment:?}"), || {
            self.host.deployments(repo, environment)
        })
    }
    fn deployment_statuses(&self, repo: &RepoId, deployment_id: u64) -> R<Vec<DeploymentStatus>> {
        self.read(
            format!("deployment_statuses {repo} {deployment_id}"),
            || self.host.deployment_statuses(repo, deployment_id),
        )
    }
    fn latest_deployments(&self, repo: &RepoId, environment: &str) -> R<Vec<Deployment>> {
        self.read(format!("latest_deployments {repo} {environment:?}"), || {
            self.host.latest_deployments(repo, environment)
        })
    }
    fn issues(&self, repo: &RepoId, filter: &IssueFilter) -> R<Vec<IssueMeta>> {
        self.read(format!("issues {repo} {filter:?}"), || {
            self.host.issues(repo, filter)
        })
    }
    fn pulls(&self, repo: &RepoId, filter: &PullFilter) -> R<Vec<PullMeta>> {
        self.read(format!("pulls {repo} {filter:?}"), || {
            self.host.pulls(repo, filter)
        })
    }
    fn pulls_for_commit(&self, repo: &RepoId, sha: &str) -> R<Vec<PullMeta>> {
        self.read(format!("pulls_for_commit {repo} {sha:?}"), || {
            self.host.pulls_for_commit(repo, sha)
        })
    }
    fn pull_files(&self, repo: &RepoId, number: u64) -> R<Vec<PullFile>> {
        self.read(format!("pull_files {repo} {number}"), || {
            self.host.pull_files(repo, number)
        })
    }
    fn file_exists(&self, repo: &RepoId, path: &str, reference: &str) -> R<Option<String>> {
        self.read(format!("file_exists {repo} {path:?} {reference:?}"), || {
            self.host.file_exists(repo, path, reference)
        })
    }
    fn dependabot_alerts(&self, repo: &RepoId) -> R<Vec<DependabotAlert>> {
        self.read(format!("dependabot_alerts {repo}"), || {
            self.host.dependabot_alerts(repo)
        })
    }
    fn secret_scanning_alerts(&self, repo: &RepoId) -> R<Vec<SecretScanningAlert>> {
        self.read(format!("secret_scanning_alerts {repo}"), || {
            self.host.secret_scanning_alerts(repo)
        })
    }
    fn branches(&self, repo: &RepoId) -> R<Vec<Branch>> {
        self.read(format!("branches {repo}"), || self.host.branches(repo))
    }
    fn branch_heads(&self, repo: &RepoId) -> R<Vec<Branch>> {
        self.read(format!("branch_heads {repo}"), || {
            self.host.branch_heads(repo)
        })
    }
    fn commit_date(&self, repo: &RepoId, sha: &str) -> R<Option<String>> {
        self.read(format!("commit_date {repo} {sha:?}"), || {
            self.host.commit_date(repo, sha)
        })
    }
    fn file_contents(&self, repo: &RepoId, path: &str, reference: &str) -> R<Option<FileContents>> {
        self.read(
            format!("file_contents {repo} {path:?} {reference:?}"),
            || self.host.file_contents(repo, path, reference),
        )
    }
    fn list_directory(
        &self,
        repo: &RepoId,
        path: &str,
        reference: &str,
    ) -> R<Option<Vec<DirEntry>>> {
        self.read(
            format!("list_directory {repo} {path:?} {reference:?}"),
            || self.host.list_directory(repo, path, reference),
        )
    }
    fn labels(&self, repo: &RepoId) -> R<Vec<Label>> {
        self.read(format!("labels {repo}"), || self.host.labels(repo))
    }
    fn recent_commits(&self, repo: &RepoId, branch: &str, limit: u32) -> R<Vec<String>> {
        self.read(format!("recent_commits {repo} {branch:?} {limit}"), || {
            self.host.recent_commits(repo, branch, limit)
        })
    }
    fn security_toggle(&self, repo: &RepoId, toggle: SecurityToggle) -> R<bool> {
        self.read(format!("security_toggle {repo} {toggle:?}"), || {
            self.host.security_toggle(repo, toggle)
        })
    }
    fn code_scanning_default_setup(&self, repo: &RepoId) -> R<CodeScanningSetup> {
        self.read(format!("code_scanning_default_setup {repo}"), || {
            self.host.code_scanning_default_setup(repo)
        })
    }
    fn repo_variable(&self, repo: &RepoId, name: &str) -> R<Option<String>> {
        self.read(format!("repo_variable {repo} {name:?}"), || {
            self.host.repo_variable(repo, name)
        })
    }
    fn latest_release(&self, repo: &RepoId) -> R<Release> {
        self.read(format!("latest_release {repo}"), || {
            self.host.latest_release(repo)
        })
    }
    fn release_by_tag(&self, repo: &RepoId, tag: &str) -> R<Release> {
        self.read(format!("release_by_tag {repo} {tag:?}"), || {
            self.host.release_by_tag(repo, tag)
        })
    }
    fn job_log(&self, repo: &RepoId, job_id: u64) -> R<String> {
        self.read(format!("job_log {repo} {job_id}"), || {
            self.host.job_log(repo, job_id)
        })
    }
    fn owner(&self, name: &str) -> R<OwnerId> {
        self.read(format!("owner {name:?}"), || self.host.owner(name))
    }
    fn list_repositories(&self, owner: &OwnerId) -> R<Partial<RepoSummary>> {
        self.read(format!("list_repositories {owner:?}"), || {
            self.host.list_repositories(owner)
        })
    }
    fn org_rulesets(&self, org: &str) -> R<Vec<Ruleset>> {
        self.read(format!("org_rulesets {org:?}"), || {
            self.host.org_rulesets(org)
        })
    }
    fn org_settings(&self, org: &str) -> R<OrgSettings> {
        self.read(format!("org_settings {org:?}"), || {
            self.host.org_settings(org)
        })
    }
    fn org_owners(&self, org: &str) -> R<Vec<String>> {
        self.read(format!("org_owners {org:?}"), || self.host.org_owners(org))
    }

    fn ensure_labels(&self, token: &WriteToken, labels: &[Label]) -> R<WriteReport> {
        self.wrote(self.host.ensure_labels(token, labels))
    }
    fn create_issue(&self, token: &WriteToken, issue: &NewIssue) -> R<IssueMeta> {
        self.wrote(self.host.create_issue(token, issue))
    }
    fn comment(&self, token: &WriteToken, number: u64, body: &str) -> R<u64> {
        self.wrote(self.host.comment(token, number, body))
    }
    fn set_repository_settings(
        &self,
        token: &WriteToken,
        settings: &RepositorySettingsPatch,
    ) -> R<WriteReport> {
        self.wrote(self.host.set_repository_settings(token, settings))
    }
    fn put_ruleset(&self, token: &WriteToken, ruleset: &Ruleset) -> R<WriteReport> {
        self.wrote(self.host.put_ruleset(token, ruleset))
    }
    fn put_environment(&self, token: &WriteToken, environment: &EnvironmentSpec) -> R<WriteReport> {
        self.wrote(self.host.put_environment(token, environment))
    }
    fn put_branch_protection(
        &self,
        token: &WriteToken,
        branch: &str,
        protection: &BranchProtectionSpec,
    ) -> R<WriteReport> {
        self.wrote(self.host.put_branch_protection(token, branch, protection))
    }
    fn retire_branch_protection(
        &self,
        token: &WriteToken,
        branch: &str,
        superseded_by: Option<&str>,
    ) -> R<WriteReport> {
        self.wrote(
            self.host
                .retire_branch_protection(token, branch, superseded_by),
        )
    }
}
