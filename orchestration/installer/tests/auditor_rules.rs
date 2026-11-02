//! Every catalogue rule in its four states (SPEC-auditor.md, "Testing
//! Strategy"): passed, failed, unavailable (403, 404, malformed body, budget
//! exhausted) and not-required, with the evidence asserted. One section per
//! block. The host is a fake that spends a real `CallBudget`; no `gh` runs.
use brakes::{
    auditor::{
        Audit, CALL_BUDGET, Cx, Dimensions, FLEET_CALL_BUDGET, LocalFiles, audit,
        cached::Cached,
        catalogue::{ci_health, dora, governance, operations, posture},
        counters::{self, Counter, Counters},
        evaluate, evaluate_counted, measures,
        rules::{
            ALLOWANCES, Block, Cadence, Condition, FLEET_FILE_READS, Level, Milestone, Outcome,
            Profile, REGISTRY, Remediation, Rule, Status, allowance, fleet_allowance,
        },
        workflows,
    },
    host::{
        CallBudget, Features, Host, HostError, HostErrorKind, HostKind, OwnerId, OwnerKind,
        Partial, RepoId, SecretName, SecretScope,
        types::{
            Branch, BranchProtection, Collaborator, DependabotAlert, Deployment,
            DeploymentBranchPolicy, DeploymentStatus, Environment, IssueFilter, IssueMeta, Job,
            OrgSettings, PullFile, PullMeta, Ruleset, RunFilter, RunTiming, SecretScanningAlert,
            WorkflowRun,
        },
    },
};
use chrono::NaiveDate;
use std::{cell::RefCell, collections::BTreeMap, fs};

// --- the fake host ------------------------------------------------------------------

type R<T> = Result<T, HostError>;

/// Answers the posture reads with what each test sets, spending one call of
/// its budget per read; every other read is `Unsupported`.
struct FakeHost {
    budget: CallBudget,
    protection: R<Option<BranchProtection>>,
    rulesets: R<Vec<Ruleset>>,
    environments: R<Vec<Environment>>,
    repo_secrets: R<Vec<SecretName>>,
    dependabot: R<Vec<DependabotAlert>>,
    secret_scanning: R<Vec<SecretScanningAlert>>,
    heads: R<Vec<Branch>>,
    /// sha → committer date
    dates: BTreeMap<String, String>,
    owner: R<OwnerId>,
    org: R<OrgSettings>,
    /// Workflow runs, newest first; `workflow_runs` applies the filter.
    runs: R<Vec<WorkflowRun>>,
    /// run id → its jobs (none when absent)
    jobs: BTreeMap<u64, Vec<Job>>,
    /// run id → `run_duration_ms`
    timing: BTreeMap<u64, u64>,
    /// The newest production deployments, newest first.
    deployments: R<Vec<Deployment>>,
    /// deployment id → its statuses, newest first (none when absent)
    statuses: BTreeMap<u64, Vec<DeploymentStatus>>,
    /// sha → the pull requests containing it (none when absent)
    commit_pulls: BTreeMap<String, Vec<PullMeta>>,
    /// The closed issues labelled `incident`.
    incidents: R<Vec<IssueMeta>>,
    /// The pull request listing the cadence measure and the counters share.
    pulls: R<Vec<PullMeta>>,
    /// pull request number → its files (none when absent)
    files: BTreeMap<u64, R<Vec<PullFile>>>,
    collaborators: R<Vec<Collaborator>>,
    org_owners: R<Vec<String>>,
    /// `GET repos/{r}`: the visibility `production-environment-guarded` reads.
    repository: R<brakes::host::types::RepositorySettings>,
    /// The operations read, in order.
    calls: RefCell<Vec<&'static str>>,
}
fn unsupported(operation: &str) -> HostError {
    HostError::new(
        HostErrorKind::Unsupported,
        format!("{operation} is not supported by this fake"),
    )
}
impl Default for FakeHost {
    fn default() -> Self {
        Self {
            budget: CallBudget::new(60),
            protection: Err(unsupported("branch_protection")),
            rulesets: Err(unsupported("rulesets")),
            environments: Err(unsupported("environments")),
            repo_secrets: Err(unsupported("secret_names")),
            dependabot: Err(unsupported("dependabot_alerts")),
            secret_scanning: Err(unsupported("secret_scanning_alerts")),
            heads: Err(unsupported("branch_heads")),
            dates: BTreeMap::new(),
            owner: Err(unsupported("owner")),
            org: Err(unsupported("org_settings")),
            runs: Err(unsupported("workflow_runs")),
            jobs: BTreeMap::new(),
            timing: BTreeMap::new(),
            deployments: Err(unsupported("latest_deployments")),
            statuses: BTreeMap::new(),
            commit_pulls: BTreeMap::new(),
            incidents: Err(unsupported("issues")),
            pulls: Err(unsupported("pulls")),
            files: BTreeMap::new(),
            collaborators: Err(unsupported("collaborators")),
            org_owners: Err(unsupported("org_owners")),
            repository: Err(unsupported("repository")),
            calls: RefCell::default(),
        }
    }
}
impl FakeHost {
    /// Every posture read answers `error`.
    fn failing(error: &HostError) -> Self {
        Self {
            budget: CallBudget::new(60),
            protection: Err(error.clone()),
            rulesets: Err(error.clone()),
            environments: Err(error.clone()),
            repo_secrets: Err(error.clone()),
            dependabot: Err(error.clone()),
            secret_scanning: Err(error.clone()),
            heads: Err(error.clone()),
            dates: BTreeMap::new(),
            owner: Err(error.clone()),
            org: Err(error.clone()),
            runs: Err(error.clone()),
            jobs: BTreeMap::new(),
            timing: BTreeMap::new(),
            deployments: Err(error.clone()),
            statuses: BTreeMap::new(),
            commit_pulls: BTreeMap::new(),
            incidents: Err(error.clone()),
            pulls: Err(error.clone()),
            files: BTreeMap::new(),
            collaborators: Err(error.clone()),
            org_owners: Err(error.clone()),
            repository: Err(error.clone()),
            calls: RefCell::default(),
        }
    }
    fn read<T: Clone>(&self, operation: &'static str, answer: &R<T>) -> R<T> {
        self.calls.borrow_mut().push(operation);
        self.budget.spend()?;
        answer.clone()
    }
    fn count(&self, operation: &str) -> usize {
        self.calls
            .borrow()
            .iter()
            .filter(|c| **c == operation)
            .count()
    }
}
impl Host for FakeHost {
    fn kind(&self) -> HostKind {
        HostKind::GitHub
    }
    fn repository(&self, _: &RepoId) -> R<brakes::host::types::RepositorySettings> {
        self.read("repository", &self.repository)
    }
    fn features(&self, _: &RepoId) -> R<Features> {
        panic!("posture rules never probe features (eight calls)")
    }
    fn branch_protection(&self, _: &RepoId, branch: &str) -> R<Option<BranchProtection>> {
        assert_eq!(branch, "main", "the default branch is read");
        self.read("branch_protection", &self.protection)
    }
    fn rulesets(&self, _: &RepoId) -> R<Vec<Ruleset>> {
        self.read("rulesets", &self.rulesets)
    }
    fn environments(&self, _: &RepoId) -> R<Vec<Environment>> {
        self.read("environments", &self.environments)
    }
    fn secret_names(&self, _: &RepoId, scope: &SecretScope) -> R<Vec<SecretName>> {
        assert_eq!(scope, &SecretScope::Repository);
        self.read("secret_names", &self.repo_secrets)
    }
    fn workflow_runs(&self, _: &RepoId, filter: &RunFilter) -> R<Vec<WorkflowRun>> {
        let runs = self.read("workflow_runs", &self.runs)?;
        Ok(runs
            .into_iter()
            .filter(|r| filter.branch.as_ref().is_none_or(|b| *b == r.head_branch))
            .filter(|r| filter.event.as_ref().is_none_or(|e| *e == r.event))
            .filter(|r| filter.status.as_ref().is_none_or(|s| *s == r.status))
            // `created=>=<date>`: ISO timestamps compare as text.
            .filter(|r| {
                filter.created_since.as_ref().is_none_or(|since| {
                    r.created_at
                        .as_deref()
                        .is_some_and(|created| created >= since.as_str())
                })
            })
            .take(filter.limit.map_or(usize::MAX, |n| n as usize))
            .collect())
    }
    fn run_timing(&self, repo: &RepoId, run_id: u64) -> R<RunTiming> {
        let answer = self
            .timing
            .get(&run_id)
            .map(|&run_duration_ms| RunTiming {
                run_id,
                run_duration_ms,
            })
            .ok_or_else(|| HostError::unsupported("run_timing", repo));
        self.read("run_timing", &answer)
    }
    fn jobs(&self, _: &RepoId, run_id: u64) -> R<Vec<Job>> {
        self.read(
            "jobs",
            &Ok(self.jobs.get(&run_id).cloned().unwrap_or_default()),
        )
    }
    fn check_runs(&self, _: &RepoId, _: &str) -> R<Vec<brakes::host::types::CheckRun>> {
        Err(unsupported("check_runs"))
    }
    fn collaborators(&self, _: &RepoId) -> R<Vec<Collaborator>> {
        self.read("collaborators", &self.collaborators)
    }
    fn deployments(&self, _: &RepoId, _: Option<&str>) -> R<Vec<Deployment>> {
        panic!("DORA reads latest_deployments, never every page")
    }
    fn latest_deployments(&self, _: &RepoId, environment: &str) -> R<Vec<Deployment>> {
        assert_eq!(environment, "production");
        self.read("latest_deployments", &self.deployments)
    }
    fn deployment_statuses(&self, _: &RepoId, id: u64) -> R<Vec<DeploymentStatus>> {
        self.read(
            "deployment_statuses",
            &Ok(self.statuses.get(&id).cloned().unwrap_or_default()),
        )
    }
    fn pulls_for_commit(&self, _: &RepoId, sha: &str) -> R<Vec<PullMeta>> {
        self.read(
            "pulls_for_commit",
            &Ok(self.commit_pulls.get(sha).cloned().unwrap_or_default()),
        )
    }
    fn issues(&self, _: &RepoId, filter: &IssueFilter) -> R<Vec<IssueMeta>> {
        // The post-mortem actions (#728) have their own tests over `Replay`.
        if filter.labels == ["type:post-mortem-action"] {
            return Err(unsupported("post-mortem actions"));
        }
        assert_eq!(filter.labels, ["incident"]);
        assert_eq!(filter.state.as_deref(), Some("closed"));
        self.read("issues", &self.incidents)
    }
    fn pulls(
        &self,
        _: &RepoId,
        filter: &brakes::host::types::PullFilter,
    ) -> R<Vec<brakes::host::types::PullMeta>> {
        assert_eq!(
            filter,
            &measures::pulls_filter(now()),
            "the cadence listing"
        );
        self.read("pulls", &self.pulls)
    }
    fn pull_files(&self, _: &RepoId, number: u64) -> R<Vec<PullFile>> {
        let answer = self.files.get(&number).cloned().unwrap_or(Ok(Vec::new()));
        self.read("pull_files", &answer)
    }
    fn file_exists(&self, _: &RepoId, _: &str, _: &str) -> R<Option<String>> {
        Err(unsupported("file_exists"))
    }
    fn dependabot_alerts(&self, _: &RepoId) -> R<Vec<DependabotAlert>> {
        self.read("dependabot_alerts", &self.dependabot)
    }
    fn secret_scanning_alerts(&self, _: &RepoId) -> R<Vec<SecretScanningAlert>> {
        self.read("secret_scanning_alerts", &self.secret_scanning)
    }
    fn branches(&self, _: &RepoId) -> R<Vec<Branch>> {
        panic!("stale-branches never reads every date at once (up to 102 calls)")
    }
    fn branch_heads(&self, _: &RepoId) -> R<Vec<Branch>> {
        self.read("branch_heads", &self.heads)
    }
    fn commit_date(&self, _: &RepoId, sha: &str) -> R<Option<String>> {
        self.read("commit_date", &Ok(self.dates.get(sha).cloned()))
    }
    fn owner(&self, name: &str) -> R<OwnerId> {
        assert_eq!(name, "acme");
        self.read("owner", &self.owner)
    }
    fn list_repositories(&self, _: &OwnerId) -> R<Partial<brakes::host::types::RepoSummary>> {
        Err(unsupported("list_repositories"))
    }
    fn org_rulesets(&self, _: &str) -> R<Vec<Ruleset>> {
        Err(unsupported("org_rulesets"))
    }
    fn org_settings(&self, org: &str) -> R<OrgSettings> {
        assert_eq!(org, "acme");
        self.read("org_settings", &self.org)
    }
    fn org_owners(&self, org: &str) -> R<Vec<String>> {
        assert_eq!(org, "acme");
        self.read("org_owners", &self.org_owners)
    }
    fn ensure_labels(
        &self,
        _: &brakes::host::WriteToken,
        _: &[brakes::host::types::Label],
    ) -> R<brakes::host::types::WriteReport> {
        panic!("the auditor never writes")
    }
    fn create_issue(
        &self,
        _: &brakes::host::WriteToken,
        _: &brakes::host::types::NewIssue,
    ) -> R<brakes::host::types::IssueMeta> {
        panic!("the auditor never writes")
    }
    fn comment(&self, _: &brakes::host::WriteToken, _: u64, _: &str) -> R<u64> {
        panic!("the auditor never writes")
    }
    fn set_repository_settings(
        &self,
        _: &brakes::host::WriteToken,
        _: &brakes::host::types::RepositorySettingsPatch,
    ) -> R<brakes::host::types::WriteReport> {
        panic!("the auditor never writes")
    }
    fn put_ruleset(
        &self,
        _: &brakes::host::WriteToken,
        _: &Ruleset,
    ) -> R<brakes::host::types::WriteReport> {
        panic!("the auditor never writes")
    }
    fn put_environment(
        &self,
        _: &brakes::host::WriteToken,
        _: &brakes::host::types::EnvironmentSpec,
    ) -> R<brakes::host::types::WriteReport> {
        panic!("the auditor never writes")
    }
}

// --- helpers --------------------------------------------------------------------------

fn now() -> NaiveDate {
    NaiveDate::from_ymd_opt(2026, 10, 28).unwrap()
}
fn dims(profile: Profile) -> Dimensions {
    Dimensions {
        profile,
        cadence: None,
        services: None,
        criticality: None,
    }
}

/// Audits a checkout holding `files` (repository path → text) as `acme/shop`.
fn run_with(host: &FakeHost, files: &[(&str, &str)]) -> Audit {
    run_as(host, files, Profile::P1)
}
/// [`run_with`] for a repository measured at `profile`.
fn run_as(host: &FakeHost, files: &[(&str, &str)], profile: Profile) -> Audit {
    let dir = tempfile::tempdir().unwrap();
    for (path, text) in files {
        let path = dir.path().join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
    let local = LocalFiles::new(dir.path());
    let repo = RepoId::parse("acme/shop").unwrap();
    let cx = Cx {
        host,
        files: &local,
        repo: &repo,
        default_branch: "main",
        now: now(),
        budget: &host.budget,
        // As `audit_checkout` does before measuring: `evaluate` sets the
        // measured profile, so the P2 and P3 cases below also prove that.
        profile: Profile::P1,
        today: None,
    };
    audit(&cx, &dims(profile))
}
fn run(host: &FakeHost) -> Audit {
    run_with(host, &[])
}
fn outcome(audit: &Audit, id: &str) -> Outcome {
    audit
        .rules
        .iter()
        .find(|e| e.rule.id == id)
        .unwrap_or_else(|| panic!("{id} not in the registry"))
        .outcome
        .clone()
}
#[track_caller]
fn passed(o: &Outcome, evidence: &[&str]) {
    assert_eq!(o.status, Status::Passed, "{o:?}");
    assert_eq!(o.evidence, evidence);
}
#[track_caller]
fn failed(o: &Outcome, evidence: &[&str]) {
    assert_eq!(o.status, Status::Failed, "{o:?}");
    assert_eq!(o.evidence, evidence);
}
#[track_caller]
fn unavailable(o: &Outcome, reason: &str) {
    assert_eq!(o.status, Status::Unavailable, "{o:?}");
    assert_eq!(o.reason.as_deref(), Some(reason));
}

fn ruleset(id: u64, rules: &[&str]) -> Ruleset {
    Ruleset {
        id: Some(id),
        name: "main".to_owned(),
        target: "branch".to_owned(),
        enforcement: "active".to_owned(),
        include: vec!["~DEFAULT_BRANCH".to_owned()],
        exclude: Vec::new(),
        rules: rules.iter().map(|r| (*r).to_owned()).collect(),
        required_status_checks: Vec::new(),
        required_approving_review_count: None,
        bypass_actors: Vec::new(),
        rule_parameters: Default::default(),
    }
}
fn protection(force: Option<bool>, deletions: Option<bool>) -> BranchProtection {
    BranchProtection {
        branch: "main".to_owned(),
        required_status_checks: Vec::new(),
        strict: None,
        enforce_admins: Some(true),
        required_approving_review_count: None,
        require_code_owner_reviews: None,
        required_linear_history: None,
        allow_force_pushes: force,
        allow_deletions: deletions,
    }
}

const PLAN_403: &str = "Reading rulesets of acme/shop is forbidden (403: Upgrade to GitHub Pro or make this repository public to enable this feature.)";
const PROTECTION_PLAN_403: &str = "Reading protection of branch main in acme/shop is forbidden (403: Upgrade to GitHub Pro or make this repository public to enable this feature.)";
fn plan_refused(message: &str) -> HostError {
    HostError::new(HostErrorKind::Forbidden, message)
}

const POSTURE: &[&str] = &[
    "posture.default-branch-protected",
    "posture.no-open-secret-scanning-alerts",
    "posture.required-check-enforced",
    "posture.no-unlisted-bypass-actors",
    "posture.actions-pinned",
    "posture.no-stale-critical-alerts",
    "posture.no-repo-secrets-with-production",
    "posture.stale-branches",
    "posture.org-2fa-required",
    "posture.repo-admins-are-owners",
    "posture.human-approval-required",
    "posture.codeowners-review",
    "posture.serialised-merges",
    "posture.production-environment-guarded",
];

// --- posture: every rule unavailable on 403, 404, a malformed body, the budget --------

#[test]
fn every_remote_posture_rule_reports_the_reads_own_sentence_when_it_fails() {
    for error in [
        HostError::new(
            HostErrorKind::Forbidden,
            "Reading acme/shop is forbidden (403: Resource not accessible by integration)",
        ),
        HostError::new(
            HostErrorKind::NotFound,
            "acme/shop was not found (404: Not Found)",
        ),
        HostError::new(
            HostErrorKind::Shape,
            "acme/shop has an unexpected shape: the response is not a list",
        ),
    ] {
        let audit = run(&FakeHost::failing(&error));
        for id in POSTURE.iter().filter(|id| **id != "posture.actions-pinned") {
            unavailable(&outcome(&audit, id), &error.message);
        }
    }
}

/// #917: an error that is a property of the repository is read once per audit
/// and every rule reports it; one that may clear is read again by each rule.
#[test]
fn a_lasting_error_is_read_once_and_a_passing_one_again() {
    let lasting = HostError::new(
        HostErrorKind::Forbidden,
        "Reading acme/shop is forbidden (403: Resource not accessible by integration)",
    );
    let host = FakeHost::failing(&lasting);
    let audit = run(&host);
    unavailable(
        &outcome(&audit, "posture.serialised-merges"),
        &lasting.message,
    );
    assert_eq!(host.count("branch_protection"), 1, "{:?}", host.calls);
    assert_eq!(host.count("rulesets"), 1, "{:?}", host.calls);
    for passing in [
        HostError::new(
            HostErrorKind::Transport,
            "gh api failed for acme/shop: connection reset",
        ),
        HostError::new(
            HostErrorKind::RateLimited {
                reset_epoch: Some(1),
            },
            "the rate limit of acme/shop is exhausted",
        ),
    ] {
        let host = FakeHost::failing(&passing);
        let audit = run(&host);
        unavailable(
            &outcome(&audit, "posture.serialised-merges"),
            &passing.message,
        );
        // Seven ruleset and protection rules (six of posture and
        // ci.required-is-aggregate), each reading both sources again.
        assert_eq!(host.count("branch_protection"), 7, "{:?}", host.calls);
    }
}

#[test]
fn every_remote_posture_rule_is_unavailable_once_the_budget_is_exhausted() {
    let host = FakeHost {
        budget: CallBudget::new(0),
        protection: Ok(None),
        rulesets: Ok(Vec::new()),
        environments: Ok(Vec::new()),
        repo_secrets: Ok(Vec::new()),
        dependabot: Ok(Vec::new()),
        secret_scanning: Ok(Vec::new()),
        heads: Ok(Vec::new()),
        owner: Ok(OwnerId {
            host: HostKind::GitHub,
            name: "acme".to_owned(),
            kind: OwnerKind::Organization,
        }),
        org: Ok(OrgSettings::default()),
        ..FakeHost::default()
    };
    let audit = run(&host);
    for id in POSTURE.iter().filter(|id| **id != "posture.actions-pinned") {
        unavailable(
            &outcome(&audit, id),
            "budget exhausted: call budget of 0 exhausted",
        );
    }
}

#[test]
fn posture_rules_are_required_in_every_profile_or_as_allocated() {
    // "Not required" by profile: the allocation makes the first nine and
    // production-environment-guarded required in every profile, so no profile
    // leaves one out; the natural not-required outcomes are tested with their rule.
    let rule = |id: &str| REGISTRY.iter().find(|r| r.id == id).expect(id);
    let by_dimension = [
        "posture.human-approval-required",
        "posture.codeowners-review",
        "posture.repo-admins-are-owners",
        "posture.serialised-merges",
    ];
    for profile in [Profile::P1, Profile::P2, Profile::P3] {
        for id in POSTURE.iter().filter(|id| !by_dimension.contains(id)) {
            assert!(dims(profile).requires(rule(id)), "{id} in {profile:?}");
        }
    }
    // Formal approvals only with more than one human (P2, P3); serialised
    // merges by cadence, whatever the profile.
    for id in &by_dimension[..3] {
        assert!(!dims(Profile::P1).requires(rule(id)), "{id} in P1");
        assert!(dims(Profile::P2).requires(rule(id)), "{id} in P2");
        assert!(dims(Profile::P3).requires(rule(id)), "{id} in P3");
    }
    let serialised = rule("posture.serialised-merges");
    for (cadence, required) in [
        (None, false),
        (Some(Cadence::Low), false),
        (Some(Cadence::Mid), true),
        (Some(Cadence::High), true),
    ] {
        for profile in [Profile::P1, Profile::P3] {
            let d = Dimensions {
                cadence,
                ..dims(profile)
            };
            assert_eq!(d.requires(serialised), required, "{cadence:?} {profile:?}");
        }
    }
}

// --- posture.default-branch-protected -------------------------------------------------

#[test]
fn classic_protection_without_force_push_and_deletion_protects_the_default_branch() {
    let host = FakeHost {
        protection: Ok(Some(protection(Some(false), Some(false)))),
        rulesets: Ok(Vec::new()),
        ..FakeHost::default()
    };
    passed(
        &outcome(&run(&host), "posture.default-branch-protected"),
        &["classic protection of main blocks force-push and deletion"],
    );
}

#[test]
fn rulesets_protect_the_default_branch_even_when_protection_is_unreadable() {
    let host = FakeHost {
        protection: Err(plan_refused(PROTECTION_PLAN_403)),
        rulesets: Ok(vec![
            ruleset(42, &["non_fast_forward"]),
            ruleset(43, &["deletion", "pull_request"]),
        ]),
        ..FakeHost::default()
    };
    passed(
        &outcome(&run(&host), "posture.default-branch-protected"),
        &[
            "force-push blocked on main by ruleset main (42)",
            "deletion blocked on main by ruleset main (43)",
        ],
    );
}

#[test]
fn an_unprotected_default_branch_fails_naming_each_source() {
    let mut disabled = ruleset(44, &["non_fast_forward", "deletion"]);
    disabled.enforcement = "disabled".to_owned();
    let mut other = ruleset(45, &["non_fast_forward", "deletion"]);
    other.include = vec!["refs/heads/release/*".to_owned()];
    let host = FakeHost {
        protection: Ok(Some(protection(Some(true), None))),
        rulesets: Ok(vec![ruleset(42, &["deletion"]), disabled, other]),
        ..FakeHost::default()
    };
    failed(
        &outcome(&run(&host), "posture.default-branch-protected"),
        &[
            "classic protection of main does not block force-push",
            "classic protection of main does not block deletion",
            "no active ruleset blocks force-push on main",
        ],
    );
}

#[test]
fn no_protection_and_no_ruleset_fails() {
    let host = FakeHost {
        protection: Ok(None),
        rulesets: Ok(Vec::new()),
        ..FakeHost::default()
    };
    failed(
        &outcome(&run(&host), "posture.default-branch-protected"),
        &[
            "main has no classic protection",
            "no active ruleset blocks force-push on main",
            "no active ruleset blocks deletion on main",
        ],
    );
}

#[test]
fn a_ruleset_less_private_free_repository_requires_plan_team_not_a_failure() {
    let host = FakeHost {
        protection: Err(plan_refused(PROTECTION_PLAN_403)),
        rulesets: Err(plan_refused(PLAN_403)),
        ..FakeHost::default()
    };
    let audit = run(&host);
    for id in [
        "posture.default-branch-protected",
        "posture.required-check-enforced",
        "posture.no-unlisted-bypass-actors",
    ] {
        unavailable(&outcome(&audit, id), "requires plan Team");
    }
}

#[test]
fn a_plan_refused_source_next_to_an_answering_one_still_fails() {
    let host = FakeHost {
        protection: Err(plan_refused(PROTECTION_PLAN_403)),
        rulesets: Ok(Vec::new()),
        ..FakeHost::default()
    };
    failed(
        &outcome(&run(&host), "posture.default-branch-protected"),
        &[
            PROTECTION_PLAN_403,
            "no active ruleset blocks force-push on main",
            "no active ruleset blocks deletion on main",
        ],
    );
}

#[test]
fn an_unreadable_source_that_could_protect_leaves_the_rule_unavailable() {
    let error = HostError::new(
        HostErrorKind::Forbidden,
        "Reading rulesets of acme/shop is forbidden (403: Resource not accessible by integration)",
    );
    let host = FakeHost {
        protection: Ok(None),
        rulesets: Err(error.clone()),
        ..FakeHost::default()
    };
    unavailable(
        &outcome(&run(&host), "posture.default-branch-protected"),
        &error.message,
    );
}

// --- posture.required-check-enforced --------------------------------------------------

#[test]
fn the_aggregate_check_required_by_a_ruleset_passes() {
    let mut rs = ruleset(42, &["required_status_checks"]);
    rs.required_status_checks = vec!["required".to_owned()];
    let host = FakeHost {
        protection: Ok(None),
        rulesets: Ok(vec![rs]),
        ..FakeHost::default()
    };
    passed(
        &outcome(&run(&host), "posture.required-check-enforced"),
        &["ruleset main (42) requires check required on main"],
    );
}

#[test]
fn the_aggregate_check_required_by_classic_protection_passes() {
    let mut p = protection(Some(false), Some(false));
    p.required_status_checks = vec!["lint".to_owned(), "required".to_owned()];
    let host = FakeHost {
        protection: Ok(Some(p)),
        rulesets: Ok(Vec::new()),
        ..FakeHost::default()
    };
    passed(
        &outcome(&run(&host), "posture.required-check-enforced"),
        &["classic protection of main requires check required"],
    );
}

#[test]
fn other_required_checks_fail_naming_them() {
    let mut p = protection(Some(false), Some(false));
    p.required_status_checks = vec!["all-checks-passed".to_owned()];
    let mut rs = ruleset(42, &["required_status_checks"]);
    rs.required_status_checks = vec!["verify".to_owned(), "lint".to_owned()];
    let host = FakeHost {
        protection: Ok(Some(p)),
        rulesets: Ok(vec![rs]),
        ..FakeHost::default()
    };
    failed(
        &outcome(&run(&host), "posture.required-check-enforced"),
        &[
            "main requires checks all-checks-passed, lint, verify; the aggregate check required is not among them",
        ],
    );
    let host = FakeHost {
        protection: Ok(None),
        rulesets: Ok(Vec::new()),
        ..FakeHost::default()
    };
    failed(
        &outcome(&run(&host), "posture.required-check-enforced"),
        &["main requires no status check"],
    );
}

// --- posture.no-unlisted-bypass-actors ------------------------------------------------

const INVENTORY: &str = ".agent-setup/security-exceptions.json";

fn bypassed(actors: &[&str]) -> Ruleset {
    let mut rs = ruleset(42, &["deletion"]);
    rs.bypass_actors = actors.iter().map(|a| (*a).to_owned()).collect();
    rs
}

#[test]
fn no_bypass_actor_passes() {
    let host = FakeHost {
        protection: Ok(Some(protection(Some(false), Some(false)))),
        rulesets: Ok(vec![ruleset(42, &["deletion"])]),
        ..FakeHost::default()
    };
    passed(
        &outcome(&run(&host), "posture.no-unlisted-bypass-actors"),
        &["no bypass actor on main"],
    );
}

#[test]
fn bypass_actors_listed_in_the_inventory_pass_by_full_name_or_type_and_id() {
    let host = FakeHost {
        protection: Ok(None),
        rulesets: Ok(vec![bypassed(&[
            "RepositoryRole:5:always",
            "Integration:99:pull_request",
        ])]),
        ..FakeHost::default()
    };
    let inventory = r#"{"schema": 1, "exceptions": [
        {"id": "owner", "kind": "ruleset-bypass-actor", "target": "RepositoryRole:5"},
        {"id": "app", "kind": "ruleset-bypass-actor", "target": "Integration:99:pull_request", "expires": "2020-01-01"}
    ]}"#;
    passed(
        &outcome(
            &run_with(&host, &[(INVENTORY, inventory)]),
            "posture.no-unlisted-bypass-actors",
        ),
        &[
            "bypass actor RepositoryRole:5:always of ruleset main (42) listed in .agent-setup/security-exceptions.json",
            "bypass actor Integration:99:pull_request of ruleset main (42) listed in .agent-setup/security-exceptions.json",
        ],
    );
}

#[test]
fn unlisted_bypass_actors_and_admins_outside_classic_protection_fail() {
    let mut p = protection(Some(false), Some(false));
    p.enforce_admins = Some(false);
    let host = FakeHost {
        protection: Ok(Some(p)),
        rulesets: Ok(vec![bypassed(&["Team:7:always"])]),
        ..FakeHost::default()
    };
    let inventory = r#"{"schema": 1, "exceptions": [
        {"id": "job", "kind": "job-bypass", "target": "Team:7"}
    ]}"#;
    failed(
        &outcome(
            &run_with(&host, &[(INVENTORY, inventory)]),
            "posture.no-unlisted-bypass-actors",
        ),
        &[
            "bypass actor classic-protection:admins of classic protection is not listed in .agent-setup/security-exceptions.json",
            "bypass actor Team:7:always of ruleset main (42) is not listed in .agent-setup/security-exceptions.json",
        ],
    );
}

#[test]
fn a_malformed_inventory_leaves_bypass_actors_unverified() {
    let host = FakeHost {
        protection: Ok(None),
        rulesets: Ok(vec![bypassed(&["Team:7:always"])]),
        ..FakeHost::default()
    };
    unavailable(
        &outcome(
            &run_with(&host, &[(INVENTORY, "{not json")]),
            "posture.no-unlisted-bypass-actors",
        ),
        ".agent-setup/security-exceptions.json does not parse, so bypass actors cannot be matched",
    );
}

// --- posture.human-approval-required ------------------------------------------------

fn reviewed(count: u32) -> BranchProtection {
    BranchProtection {
        required_approving_review_count: Some(count),
        ..protection(Some(false), Some(false))
    }
}
fn pull_request_ruleset(parameters: serde_json::Value) -> Ruleset {
    let mut r = ruleset(7, &["pull_request"]);
    r.required_approving_review_count = parameters["required_approving_review_count"]
        .as_u64()
        .map(|n| n as u32);
    r.rule_parameters
        .insert("pull_request".to_owned(), parameters);
    r
}

#[test]
fn an_approving_review_required_by_classic_protection_passes() {
    let host = FakeHost {
        protection: Ok(Some(reviewed(1))),
        rulesets: Ok(Vec::new()),
        ..FakeHost::default()
    };
    passed(
        &outcome(&run(&host), "posture.human-approval-required"),
        &["classic protection of main requires 1 approving review"],
    );
}

#[test]
fn approving_reviews_required_by_a_ruleset_pass_even_when_protection_is_unreadable() {
    let host = FakeHost {
        protection: Err(HostError::new(HostErrorKind::Forbidden, "no admin")),
        rulesets: Ok(vec![pull_request_ruleset(
            serde_json::json!({"required_approving_review_count": 2}),
        )]),
        ..FakeHost::default()
    };
    passed(
        &outcome(&run(&host), "posture.human-approval-required"),
        &["ruleset main (7) requires 2 approving reviews on main"],
    );
}

#[test]
fn zero_approving_reviews_fail_naming_each_source() {
    let host = FakeHost {
        protection: Ok(Some(reviewed(0))),
        rulesets: Ok(vec![pull_request_ruleset(
            serde_json::json!({"required_approving_review_count": 0}),
        )]),
        ..FakeHost::default()
    };
    failed(
        &outcome(&run(&host), "posture.human-approval-required"),
        &[
            "classic protection of main requires no approving review",
            "no active ruleset requires an approving review on main",
        ],
    );
}

#[test]
fn approval_rules_refused_by_plan_on_both_sources_require_plan_team() {
    let host = FakeHost {
        protection: Err(plan_refused(PROTECTION_PLAN_403)),
        rulesets: Err(plan_refused(PLAN_403)),
        ..FakeHost::default()
    };
    let audit = run_as(&host, &[], Profile::P2);
    for id in [
        "posture.human-approval-required",
        "posture.codeowners-review",
        "posture.serialised-merges",
    ] {
        unavailable(&outcome(&audit, id), "requires plan Team");
    }
}

#[test]
fn approval_with_an_org_admin_pull_request_bypass_passes_and_names_the_bypass() {
    let mut rs = pull_request_ruleset(serde_json::json!({"required_approving_review_count": 1}));
    rs.bypass_actors = vec!["OrganizationAdmin:1:pull_request".to_owned()];
    let host = FakeHost {
        protection: Ok(None),
        rulesets: Ok(vec![rs]),
        ..FakeHost::default()
    };
    passed(
        &outcome(&run(&host), "posture.human-approval-required"),
        &[
            "ruleset main (7) requires 1 approving review on main; bypassed by OrganizationAdmin:1:pull_request",
        ],
    );
}

// --- split rulesets: checks without bypass, review with it (#1218) ------------------

/// What repo-baseline renders when a bypass is declared: ruleset 41 requires
/// the checks with no bypass actor, ruleset 42 the approval with the bypass.
fn split_rulesets() -> Vec<Ruleset> {
    let mut checks = ruleset(
        41,
        &["deletion", "non_fast_forward", "required_status_checks"],
    );
    checks.name = "baseline".to_owned();
    checks.required_status_checks = vec!["required".to_owned()];
    let mut review =
        pull_request_ruleset(serde_json::json!({"required_approving_review_count": 1}));
    review.id = Some(42);
    review.name = "review".to_owned();
    review.bypass_actors = vec!["OrganizationAdmin:1:pull_request".to_owned()];
    vec![review, checks]
}

#[test]
fn split_rulesets_prove_the_check_unbypassed_and_the_approval_with_its_bypass_named() {
    let host = FakeHost {
        protection: Ok(None),
        rulesets: Ok(split_rulesets()),
        ..FakeHost::default()
    };
    let inventory = r#"{"schema": 1, "exceptions": [
        {"id": "owners", "kind": "ruleset-bypass-actor", "target": "OrganizationAdmin:1"}
    ]}"#;
    let audit = run_with(&host, &[(INVENTORY, inventory)]);
    passed(
        &outcome(&audit, "posture.required-check-enforced"),
        &["ruleset baseline (41) requires check required on main"],
    );
    passed(
        &outcome(&audit, "posture.human-approval-required"),
        &[
            "ruleset review (42) requires 1 approving review on main; bypassed by OrganizationAdmin:1:pull_request",
        ],
    );
    passed(
        &outcome(&audit, "posture.no-unlisted-bypass-actors"),
        &[
            "bypass actor OrganizationAdmin:1:pull_request of ruleset review (42) listed in .agent-setup/security-exceptions.json",
        ],
    );
}

#[test]
fn a_required_check_only_a_bypassed_ruleset_requires_fails_naming_the_bypass() {
    let mut rs = ruleset(42, &["required_status_checks", "pull_request"]);
    rs.required_status_checks = vec!["required".to_owned()];
    rs.bypass_actors = vec!["OrganizationAdmin:1:pull_request".to_owned()];
    let host = FakeHost {
        protection: Ok(None),
        rulesets: Ok(vec![rs]),
        ..FakeHost::default()
    };
    failed(
        &outcome(&run(&host), "posture.required-check-enforced"),
        &[
            "ruleset main (42) requires check required on main, but OrganizationAdmin:1:pull_request can bypass it; a bypass never skips the checks: move it to a ruleset of its own",
        ],
    );
}

// --- posture.repo-admins-are-owners (#1218) --------------------------------------------

fn collaborator(login: &str, permission: &str) -> Collaborator {
    Collaborator {
        login: login.to_owned(),
        permission: permission.to_owned(),
        kind: Some("User".to_owned()),
    }
}

#[test]
fn repository_admins_who_are_organization_owners_pass() {
    let host = FakeHost {
        owner: org_owner(OwnerKind::Organization),
        org_owners: Ok(vec!["alice".to_owned(), "bob".to_owned()]),
        collaborators: Ok(vec![
            collaborator("alice", "admin"),
            collaborator("bob", "admin"),
            collaborator("carol", "write"),
        ]),
        ..FakeHost::default()
    };
    passed(
        &outcome(&run(&host), "posture.repo-admins-are-owners"),
        &[
            "alice has admin on acme/shop and is an owner of organization acme",
            "bob has admin on acme/shop and is an owner of organization acme",
        ],
    );
}

#[test]
fn a_repository_admin_who_is_not_an_owner_fails_naming_them() {
    let host = FakeHost {
        owner: org_owner(OwnerKind::Organization),
        org_owners: Ok(vec!["alice".to_owned()]),
        collaborators: Ok(vec![
            collaborator("alice", "admin"),
            collaborator("rafa", "admin"),
            collaborator("carol", "maintain"),
        ]),
        ..FakeHost::default()
    };
    failed(
        &outcome(&run(&host), "posture.repo-admins-are-owners"),
        &["rafa has admin on acme/shop and is not an owner of organization acme"],
    );
}

#[test]
fn on_a_personal_repository_only_the_owning_user_may_be_admin() {
    let host = FakeHost {
        owner: org_owner(OwnerKind::User),
        collaborators: Ok(vec![collaborator("acme", "admin")]),
        ..FakeHost::default()
    };
    passed(
        &outcome(&run(&host), "posture.repo-admins-are-owners"),
        &["acme has admin on acme/shop and is the user that owns it"],
    );
    assert_eq!(
        host.count("org_owners"),
        0,
        "a user has no organization owners"
    );
    let host = FakeHost {
        owner: org_owner(OwnerKind::User),
        collaborators: Ok(vec![
            collaborator("acme", "admin"),
            collaborator("guest", "admin"),
        ]),
        ..FakeHost::default()
    };
    failed(
        &outcome(&run(&host), "posture.repo-admins-are-owners"),
        &["guest has admin on acme/shop and is not the user that owns it"],
    );
}

#[test]
fn no_repository_admin_passes_and_unreadable_owners_are_unavailable() {
    let host = FakeHost {
        owner: org_owner(OwnerKind::Organization),
        org_owners: Ok(Vec::new()),
        collaborators: Ok(vec![collaborator("carol", "write")]),
        ..FakeHost::default()
    };
    passed(
        &outcome(&run(&host), "posture.repo-admins-are-owners"),
        &["no collaborator has admin on acme/shop"],
    );
    let host = FakeHost {
        owner: org_owner(OwnerKind::Organization),
        org_owners: Err(HostError::new(
            HostErrorKind::Forbidden,
            "Reading owners of organization acme is forbidden (403: Must have admin rights)",
        )),
        collaborators: Ok(vec![collaborator("rafa", "admin")]),
        ..FakeHost::default()
    };
    unavailable(
        &outcome(&run(&host), "posture.repo-admins-are-owners"),
        "Reading owners of organization acme is forbidden (403: Must have admin rights)",
    );
}

#[test]
fn repo_admins_are_owners_is_a_silver_rule_of_teams() {
    let rule = REGISTRY
        .iter()
        .find(|r| r.id == "posture.repo-admins-are-owners")
        .unwrap();
    assert_eq!(rule.level, Level::Silver);
    assert!(!dims(Profile::P1).requires(rule));
    assert!(dims(Profile::P2).requires(rule));
    assert!(dims(Profile::P3).requires(rule));
    assert_eq!(allowance(rule.id), 2);
}

// --- posture.codeowners-review --------------------------------------------------------

#[test]
fn code_owner_review_required_by_classic_protection_passes() {
    let host = FakeHost {
        protection: Ok(Some(BranchProtection {
            require_code_owner_reviews: Some(true),
            ..reviewed(1)
        })),
        rulesets: Ok(Vec::new()),
        ..FakeHost::default()
    };
    passed(
        &outcome(&run(&host), "posture.codeowners-review"),
        &["classic protection of main requires code owner review"],
    );
}

#[test]
fn code_owner_review_required_by_a_ruleset_passes() {
    let host = FakeHost {
        protection: Ok(None),
        rulesets: Ok(vec![pull_request_ruleset(serde_json::json!({
            "required_approving_review_count": 1,
            "require_code_owner_review": true
        }))]),
        ..FakeHost::default()
    };
    passed(
        &outcome(&run(&host), "posture.codeowners-review"),
        &["ruleset main (7) requires code owner review on main"],
    );
}

#[test]
fn without_code_owner_review_the_rule_fails_naming_each_source() {
    let host = FakeHost {
        protection: Ok(Some(BranchProtection {
            require_code_owner_reviews: Some(false),
            ..reviewed(1)
        })),
        rulesets: Ok(vec![pull_request_ruleset(serde_json::json!({
            "required_approving_review_count": 1,
            "require_code_owner_review": false
        }))]),
        ..FakeHost::default()
    };
    failed(
        &outcome(&run(&host), "posture.codeowners-review"),
        &[
            "classic protection of main does not require code owner review",
            "no active ruleset requires code owner review on main",
        ],
    );
}

// --- posture.serialised-merges --------------------------------------------------------

#[test]
fn a_merge_queue_serialises_merges() {
    let host = FakeHost {
        protection: Ok(None),
        rulesets: Ok(vec![ruleset(3, &["merge_queue"])]),
        ..FakeHost::default()
    };
    passed(
        &outcome(&run(&host), "posture.serialised-merges"),
        &["ruleset main (3) requires a merge queue on main"],
    );
}

#[test]
fn up_to_date_branches_required_by_classic_protection_serialise_merges() {
    let host = FakeHost {
        protection: Ok(Some(BranchProtection {
            strict: Some(true),
            required_status_checks: vec!["required".to_owned()],
            ..protection(Some(false), Some(false))
        })),
        rulesets: Ok(Vec::new()),
        ..FakeHost::default()
    };
    passed(
        &outcome(&run(&host), "posture.serialised-merges"),
        &["classic protection of main requires branches up to date before merging"],
    );
}

#[test]
fn up_to_date_branches_required_by_a_ruleset_serialise_merges() {
    let mut strict = ruleset(4, &["required_status_checks"]);
    strict.required_status_checks = vec!["required".to_owned()];
    strict.rule_parameters.insert(
        "required_status_checks".to_owned(),
        serde_json::json!({
            "strict_required_status_checks_policy": true,
            "required_status_checks": [{"context": "required"}]
        }),
    );
    let host = FakeHost {
        protection: Ok(None),
        rulesets: Ok(vec![strict]),
        ..FakeHost::default()
    };
    passed(
        &outcome(&run(&host), "posture.serialised-merges"),
        &["ruleset main (4) requires branches up to date before merging on main"],
    );
}

#[test]
fn a_strict_policy_without_required_checks_does_not_serialise_merges() {
    let mut strict = ruleset(4, &["required_status_checks"]);
    strict.rule_parameters.insert(
        "required_status_checks".to_owned(),
        serde_json::json!({"strict_required_status_checks_policy": true, "required_status_checks": []}),
    );
    let host = FakeHost {
        protection: Ok(Some(BranchProtection {
            strict: Some(true),
            ..protection(Some(false), Some(false))
        })),
        rulesets: Ok(vec![strict]),
        ..FakeHost::default()
    };
    failed(
        &outcome(&run(&host), "posture.serialised-merges"),
        &[
            "classic protection of main requires branches up to date but no status check",
            "no active ruleset requires a merge queue or up-to-date branches on main",
        ],
    );
}

// --- posture.production-environment-guarded -------------------------------------------

fn production(policy: DeploymentBranchPolicy) -> Environment {
    Environment {
        deployment_branch_policy: policy,
        ..environment("production")
    }
}
/// `GET repos/{r}` answering `visibility`.
fn settings(visibility: &str) -> R<brakes::host::types::RepositorySettings> {
    Ok(serde_json::from_value(serde_json::json!({
        "id": "R_1", "default_branch": "main", "visibility": visibility,
        "archived": false, "fork": false,
    }))
    .unwrap())
}
fn guarded(env: Environment, profile: Profile) -> Outcome {
    guarded_in(env, profile, "public")
}
fn guarded_in(env: Environment, profile: Profile, visibility: &str) -> Outcome {
    let host = FakeHost {
        environments: Ok(vec![environment("staging"), env]),
        repository: settings(visibility),
        ..FakeHost::default()
    };
    outcome(
        &run_as(&host, &[], profile),
        "posture.production-environment-guarded",
    )
}

#[test]
fn without_a_production_environment_guarding_is_not_required() {
    let host = FakeHost {
        environments: Ok(vec![environment("staging")]),
        ..FakeHost::default()
    };
    let o = outcome(&run(&host), "posture.production-environment-guarded");
    assert_eq!(o.status, Status::NotRequired);
    assert_eq!(o.reason.as_deref(), Some("no production environment"));
}

#[test]
fn at_p1_a_deployment_branch_policy_guards_production() {
    passed(
        &guarded(
            production(DeploymentBranchPolicy::ProtectedBranches),
            Profile::P1,
        ),
        &["production deploys only from protected branches"],
    );
    passed(
        &guarded(
            production(DeploymentBranchPolicy::Custom {
                patterns: vec!["main".to_owned(), "tag:v*".to_owned()],
            }),
            Profile::P1,
        ),
        &["production deploys only from main, tag:v*"],
    );
}

#[test]
fn at_p1_production_open_to_every_branch_fails() {
    failed(
        &guarded(
            production(DeploymentBranchPolicy::Unrestricted),
            Profile::P1,
        ),
        &["production has no deployment branch policy: any branch may deploy"],
    );
    failed(
        &guarded(
            production(DeploymentBranchPolicy::Custom {
                patterns: vec!["main".to_owned(), "*".to_owned()],
            }),
            Profile::P1,
        ),
        &["production's deployment branch pattern * admits any branch"],
    );
}

#[test]
fn at_p2_and_p3_reviewers_or_a_wait_timer_guard_production() {
    let reviewers = Environment {
        reviewers: vec!["octo".to_owned(), "ops".to_owned()],
        ..production(DeploymentBranchPolicy::Unrestricted)
    };
    passed(
        &guarded(reviewers, Profile::P2),
        &["production requires review by octo, ops"],
    );
    let timer = Environment {
        wait_timer_minutes: Some(15),
        ..production(DeploymentBranchPolicy::Unrestricted)
    };
    passed(
        &guarded(timer, Profile::P3),
        &["production waits 15 minutes before deploying"],
    );
}

#[test]
fn at_p2_a_branch_policy_alone_does_not_guard_production() {
    let zero_timer = Environment {
        wait_timer_minutes: Some(0),
        ..production(DeploymentBranchPolicy::ProtectedBranches)
    };
    failed(
        &guarded(zero_timer, Profile::P2),
        &["production has neither required reviewers nor a wait timer"],
    );
}

/// GitHub, "Deployments and environments": on Free, Pro and Team, required
/// reviewers and wait timers are only available for public repositories, and
/// deployment branches are available for private ones on Pro and Team (#1321).
#[test]
fn at_p2_a_private_repository_without_reviewers_is_not_required_for_the_plan() {
    for (visibility, profile) in [("private", Profile::P2), ("internal", Profile::P3)] {
        let o = guarded_in(
            production(DeploymentBranchPolicy::Custom {
                patterns: vec!["main".to_owned()],
            }),
            profile,
            visibility,
        );
        assert_eq!(o.status, Status::NotRequired, "{o:?}");
        assert_eq!(
            o.reason.as_deref(),
            Some(format!(
                "requires plan Enterprise Cloud: required reviewers and wait timers are only available for public repositories on Free, Pro and Team, and this repository is {visibility}; production deploys only from main"
            ))
            .as_deref()
        );
    }
}

#[test]
fn the_catalogue_says_reviewers_on_a_private_repository_need_enterprise_cloud() {
    let rule = posture::PRODUCTION_ENVIRONMENT_GUARDED;
    assert_eq!(
        rule.plan,
        Some(brakes::auditor::rules::Plan::EnterpriseCloud)
    );
    assert!(rule.checks.contains("Enterprise Cloud"), "{}", rule.checks);
}

#[test]
fn at_p2_a_private_repository_open_to_every_branch_still_fails() {
    failed(
        &guarded_in(
            production(DeploymentBranchPolicy::Unrestricted),
            Profile::P2,
            "private",
        ),
        &[
            "production has no deployment branch policy: any branch may deploy",
            "production has neither required reviewers nor a wait timer, which a private repository has only on Enterprise Cloud",
        ],
    );
}

#[test]
fn at_p2_a_private_repository_with_reviewers_passes_without_reading_visibility() {
    let reviewers = Environment {
        reviewers: vec!["octo".to_owned()],
        ..production(DeploymentBranchPolicy::Unrestricted)
    };
    let host = FakeHost {
        environments: Ok(vec![reviewers]),
        ..FakeHost::default()
    };
    let audit = run_as(&host, &[], Profile::P2);
    passed(
        &outcome(&audit, "posture.production-environment-guarded"),
        &["production requires review by octo"],
    );
}

#[test]
fn at_p2_an_unreadable_visibility_is_unavailable() {
    let host = FakeHost {
        environments: Ok(vec![production(DeploymentBranchPolicy::ProtectedBranches)]),
        repository: Err(HostError::new(HostErrorKind::NotFound, "repository gone")),
        ..FakeHost::default()
    };
    unavailable(
        &outcome(
            &run_as(&host, &[], Profile::P2),
            "posture.production-environment-guarded",
        ),
        "repository gone",
    );
}

// --- posture.org-2fa-required ---------------------------------------------------------

fn org_owner(kind: OwnerKind) -> R<OwnerId> {
    Ok(OwnerId {
        host: HostKind::GitHub,
        name: "acme".to_owned(),
        kind,
    })
}

#[test]
fn an_organization_requiring_2fa_passes_and_one_without_fails() {
    for (enabled, status) in [(true, Status::Passed), (false, Status::Failed)] {
        let host = FakeHost {
            owner: org_owner(OwnerKind::Organization),
            org: Ok(OrgSettings {
                two_factor_requirement_enabled: Some(enabled),
                ..OrgSettings::default()
            }),
            ..FakeHost::default()
        };
        let o = outcome(&run(&host), "posture.org-2fa-required");
        assert_eq!(o.status, status);
        let expected = if enabled {
            "organization acme requires two-factor authentication"
        } else {
            "organization acme does not require two-factor authentication"
        };
        assert_eq!(o.evidence, [expected]);
    }
}

#[test]
fn a_user_account_reports_2fa_unavailable() {
    let host = FakeHost {
        owner: org_owner(OwnerKind::User),
        ..FakeHost::default()
    };
    unavailable(
        &outcome(&run(&host), "posture.org-2fa-required"),
        "acme is a user account; the two-factor requirement is an organization setting",
    );
}

#[test]
fn a_hidden_2fa_setting_is_unavailable() {
    let host = FakeHost {
        owner: org_owner(OwnerKind::Organization),
        org: Ok(OrgSettings::default()),
        ..FakeHost::default()
    };
    unavailable(
        &outcome(&run(&host), "posture.org-2fa-required"),
        "the two-factor requirement of organization acme is not visible to this token (it needs an organization owner)",
    );
}

// --- posture.no-stale-critical-alerts -------------------------------------------------

fn alert(number: u64, severity: &str, created: &str) -> DependabotAlert {
    DependabotAlert {
        number,
        severity: severity.to_owned(),
        package: Some("lodash".to_owned()),
        ecosystem: Some("npm".to_owned()),
        manifest_path: Some("package-lock.json".to_owned()),
        created_at: created.to_owned(),
    }
}

#[test]
fn critical_alerts_seven_days_old_or_younger_pass_with_counts() {
    let host = FakeHost {
        dependabot: Ok(vec![
            alert(1, "critical", "2026-10-21T10:00:00Z"),
            alert(2, "high", "2025-01-01T00:00:00Z"),
            alert(3, "low", "2026-10-01T00:00:00Z"),
        ]),
        ..FakeHost::default()
    };
    passed(
        &outcome(&run(&host), "posture.no-stale-critical-alerts"),
        &["3 open Dependabot alerts (critical 1, high 1, low 1); none critical older than 7 days"],
    );
    let host = FakeHost {
        dependabot: Ok(Vec::new()),
        ..FakeHost::default()
    };
    passed(
        &outcome(&run(&host), "posture.no-stale-critical-alerts"),
        &["no open Dependabot alerts"],
    );
}

#[test]
fn a_critical_alert_older_than_seven_days_fails() {
    let host = FakeHost {
        dependabot: Ok(vec![
            alert(12, "critical", "2026-10-20T23:59:59Z"),
            alert(13, "critical", "2026-10-25T00:00:00Z"),
        ]),
        ..FakeHost::default()
    };
    failed(
        &outcome(&run(&host), "posture.no-stale-critical-alerts"),
        &["critical Dependabot alert #12 (lodash) open since 2026-10-20, 8 days"],
    );
}

#[test]
fn an_alert_with_an_unreadable_date_is_unavailable() {
    let host = FakeHost {
        dependabot: Ok(vec![alert(12, "critical", "yesterday")]),
        ..FakeHost::default()
    };
    unavailable(
        &outcome(&run(&host), "posture.no-stale-critical-alerts"),
        "Dependabot alert #12 has an unreadable created_at: yesterday",
    );
}

// --- posture.no-open-secret-scanning-alerts -------------------------------------------

#[test]
fn no_open_secret_scanning_alert_passes_and_one_fails_naming_the_kind() {
    let host = FakeHost {
        secret_scanning: Ok(Vec::new()),
        ..FakeHost::default()
    };
    passed(
        &outcome(&run(&host), "posture.no-open-secret-scanning-alerts"),
        &["no open secret-scanning alerts"],
    );
    let host = FakeHost {
        secret_scanning: Ok(vec![SecretScanningAlert {
            number: 3,
            secret_type: "github_personal_access_token".to_owned(),
            secret_type_display_name: Some("GitHub Personal Access Token".to_owned()),
            validity: None,
            push_protection_bypassed: None,
            created_at: "2026-10-20T08:00:00Z".to_owned(),
        }]),
        ..FakeHost::default()
    };
    failed(
        &outcome(&run(&host), "posture.no-open-secret-scanning-alerts"),
        &["open secret-scanning alert #3: GitHub Personal Access Token since 2026-10-20"],
    );
}

// --- posture.no-repo-secrets-with-production ------------------------------------------

fn environment(name: &str) -> Environment {
    Environment {
        id: None,
        name: name.to_owned(),
        deployment_branch_policy: DeploymentBranchPolicy::ProtectedBranches,
        reviewers: Vec::new(),
        wait_timer_minutes: None,
    }
}
fn secret(name: &str) -> SecretName {
    SecretName {
        name: name.to_owned(),
        scope: SecretScope::Repository,
        updated_at: None,
    }
}

#[test]
fn without_a_production_environment_repository_secrets_are_not_required_absent() {
    let host = FakeHost {
        environments: Ok(vec![environment("staging")]),
        ..FakeHost::default()
    };
    let audit = run(&host);
    let o = outcome(&audit, "posture.no-repo-secrets-with-production");
    assert_eq!(o.status, Status::NotRequired);
    assert_eq!(o.reason.as_deref(), Some("no production environment"));
    assert_eq!(
        host.count("secret_names"),
        0,
        "secrets are not read without production"
    );
}

#[test]
fn production_with_repository_secrets_fails_and_without_passes() {
    let host = FakeHost {
        environments: Ok(vec![environment("production")]),
        repo_secrets: Ok(vec![secret("DEPLOY_KEY"), secret("API_TOKEN")]),
        ..FakeHost::default()
    };
    failed(
        &outcome(&run(&host), "posture.no-repo-secrets-with-production"),
        &["repository-level secrets with a production environment: API_TOKEN, DEPLOY_KEY"],
    );
    let host = FakeHost {
        environments: Ok(vec![environment("production")]),
        repo_secrets: Ok(Vec::new()),
        ..FakeHost::default()
    };
    passed(
        &outcome(&run(&host), "posture.no-repo-secrets-with-production"),
        &["production environment exists; no repository-level secrets"],
    );
}

// --- posture.stale-branches -----------------------------------------------------------

fn heads(n: usize) -> Vec<Branch> {
    let mut branches: Vec<Branch> = (0..n)
        .map(|i| Branch {
            name: format!("b{i:02}"),
            sha: format!("{i:040x}"),
            protected: Some(false),
            committed_at: None,
        })
        .collect();
    branches.push(Branch {
        name: "main".to_owned(),
        sha: "f".repeat(40),
        protected: Some(true),
        committed_at: None,
    });
    branches
}
/// Dates for branch `i`: stale ones in 2026-01, recent ones in 2026-10.
fn dates(stale: impl Fn(usize) -> bool, n: usize) -> BTreeMap<String, String> {
    (0..n)
        .map(|i| {
            let date = if stale(i) {
                "2026-01-15T00:00:00Z"
            } else {
                "2026-10-20T00:00:00Z"
            };
            (format!("{i:040x}"), date.to_owned())
        })
        .collect()
}

#[test]
fn ten_branches_besides_the_default_pass_without_dating_any() {
    let host = FakeHost {
        heads: Ok(heads(10)),
        ..FakeHost::default()
    };
    passed(
        &outcome(&run(&host), "posture.stale-branches"),
        &["10 branches besides main: at most 10 can be older than 90 days"],
    );
    assert_eq!(host.count("commit_date"), 0, "no date read");
}

#[test]
fn eleven_stale_branches_fail_as_soon_as_found() {
    let host = FakeHost {
        heads: Ok(heads(40)),
        dates: dates(|_| true, 40),
        ..FakeHost::default()
    };
    failed(
        &outcome(&run(&host), "posture.stale-branches"),
        &[
            "11 of 40 branches besides main older than 90 days (before 2026-07-30): b00, b01, b02, b03, b04, b05, b06, b07, b08, b09, b10",
        ],
    );
    assert_eq!(host.count("commit_date"), 11);
}

#[test]
fn undecided_at_the_cap_of_fifteen_date_reads_is_unavailable() {
    let host = FakeHost {
        heads: Ok(heads(40)),
        dates: dates(|i| i % 2 == 0, 40),
        ..FakeHost::default()
    };
    unavailable(
        &outcome(&run(&host), "posture.stale-branches"),
        "dated 15 of 40 branches besides main within the cap of 15 date reads: 8 older than 90 days, undecided",
    );
    assert_eq!(host.count("commit_date"), 15);
}

#[test]
fn recent_branches_pass_once_the_rest_cannot_exceed_ten() {
    let host = FakeHost {
        heads: Ok(heads(15)),
        dates: dates(|i| i >= 5, 15),
        ..FakeHost::default()
    };
    passed(
        &outcome(&run(&host), "posture.stale-branches"),
        &[
            "15 branches besides main: 5 dated, 0 older than 90 days (before 2026-07-30), 10 not dated: at most 10 can be stale",
        ],
    );
    assert_eq!(
        host.count("commit_date"),
        5,
        "stops after five recent dates"
    );
}

#[test]
fn a_branch_without_a_date_counts_as_not_dated() {
    let mut known = dates(|_| false, 12);
    known.remove(&format!("{:040x}", 0));
    let host = FakeHost {
        heads: Ok(heads(12)),
        dates: known,
        ..FakeHost::default()
    };
    passed(
        &outcome(&run(&host), "posture.stale-branches"),
        &[
            "12 branches besides main: 2 dated, 0 older than 90 days (before 2026-07-30), 10 not dated: at most 10 can be stale",
        ],
    );
}

#[test]
fn dates_cut_by_the_allowances_held_back_leave_it_undecided_naming_the_reads() {
    let host = FakeHost {
        heads: Ok(heads(40)),
        dates: dates(|i| i % 2 == 0, 40),
        ..FakeHost::default()
    };
    // 26 calls spent before the audit (the most the measures may spend while
    // the 34 allowances fit): the 26 held back for the rules after
    // stale-branches (#920; 7 of them for ci-baseline's remote rules, #783;
    // 2 for posture.repo-admins-are-owners, #1218) leave it fewer date reads
    // than its cap of 15.
    for _ in 0..26 {
        host.budget.spend().unwrap();
    }
    let audit = run(&host);
    let dated = host.count("commit_date") - 1;
    unavailable(
        &outcome(&audit, "posture.stale-branches"),
        &format!(
            "dated {dated} of 40 branches besides main before the call budget stopped the date reads (budget exhausted: call budget of 60 exhausted, 26 held back): {} older than 90 days, undecided",
            dated.div_ceil(2)
        ),
    );
    assert!(dated < 15, "{dated} dates read");
    let org = outcome(&audit, "posture.org-2fa-required");
    assert!(
        !org.reason
            .unwrap_or_default()
            .starts_with("budget exhausted"),
        "org-2fa-required keeps its allowance"
    );
}

#[test]
fn more_than_100_branches_is_unavailable() {
    let error = HostError::new(
        HostErrorKind::Truncated,
        "branches of acme/shop has more than 100 items, the cap of this read",
    );
    let host = FakeHost {
        heads: Err(error.clone()),
        ..FakeHost::default()
    };
    unavailable(
        &outcome(&run(&host), "posture.stale-branches"),
        &error.message,
    );
}

// --- posture.actions-pinned and the workflow walker ----------------------------------

const PINNED: &str = "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n      - uses: ./local\n      - uses: docker://alpine:3\n";
const UNPINNED: &str = "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n  call:\n    uses: acme/flows/.github/workflows/x.yml@main\n";

#[test]
fn pinned_workflows_pass() {
    passed(
        &outcome(
            &run_with(
                &FakeHost::default(),
                &[(".github/workflows/ci.yml", PINNED)],
            ),
            "posture.actions-pinned",
        ),
        &["every uses: of 1 workflow is pinned by SHA"],
    );
}

#[test]
fn unpinned_uses_fail_naming_action_and_file() {
    failed(
        &outcome(
            &run_with(
                &FakeHost::default(),
                &[
                    (".github/workflows/a.yml", PINNED),
                    (".github/workflows/b.yaml", UNPINNED),
                ],
            ),
            "posture.actions-pinned",
        ),
        &[
            "Unpinned action acme/flows/.github/workflows/x.yml@main in .github/workflows/b.yaml",
            "Unpinned action actions/checkout@v4 in .github/workflows/b.yaml",
        ],
    );
}

#[test]
fn no_workflow_makes_pinning_not_required() {
    let o = outcome(&run(&FakeHost::default()), "posture.actions-pinned");
    assert_eq!(o.status, Status::NotRequired);
    assert_eq!(
        o.reason.as_deref(),
        Some("no workflow under .github/workflows")
    );
}

#[test]
fn invalid_yaml_is_unavailable_naming_the_file_never_a_panic() {
    let o = outcome(
        &run_with(
            &FakeHost::default(),
            &[(".github/workflows/bad.yml", "jobs: [unclosed\n  - {")],
        ),
        "posture.actions-pinned",
    );
    assert_eq!(o.status, Status::Unavailable);
    assert!(
        o.reason
            .as_deref()
            .unwrap()
            .starts_with(".github/workflows/bad.yml: "),
        "{o:?}"
    );
}

#[test]
fn an_unpinned_file_fails_even_next_to_an_unreadable_one() {
    let o = outcome(
        &run_with(
            &FakeHost::default(),
            &[
                (".github/workflows/bad.yml", "jobs: [unclosed\n  - {"),
                (".github/workflows/b.yml", UNPINNED),
            ],
        ),
        "posture.actions-pinned",
    );
    assert_eq!(o.status, Status::Failed);
}

#[test]
fn the_walker_refuses_a_file_over_256_kib() {
    // SPEC-security.md Open question 16 (coordinator, 2026-10-29): the cap
    // stays a refusal, raised from 64 KiB over the largest golden rendered.
    assert_eq!(workflows::MAX_BYTES, 256 * 1024);
    let big = format!("on: push\n#{}\n", "x".repeat(256 * 1024));
    assert_eq!(
        workflows::parse(&big).unwrap_err(),
        format!(
            "{} bytes, over the 262144-byte cap of the workflow reader",
            big.len()
        )
    );
    let o = outcome(
        &run_with(&FakeHost::default(), &[(".github/workflows/big.yml", &big)]),
        "posture.actions-pinned",
    );
    unavailable(
        &o,
        &format!(
            ".github/workflows/big.yml: {} bytes, over the 262144-byte cap of the workflow reader",
            big.len()
        ),
    );
}

#[test]
fn the_walker_reads_each_jobs_environment() {
    let wf = workflows::parse(
        "on: push\njobs:\n  deploy:\n    environment: production\n    runs-on: x\n  named:\n    environment:\n      name: staging\n      url: https://x\n  none:\n    runs-on: x\n",
    )
    .unwrap();
    let envs: Vec<Option<&str>> = wf.jobs.iter().map(|j| j.environment.as_deref()).collect();
    assert_eq!(envs, [Some("production"), Some("staging"), None]);
}

// --- posture on recorded GitHub answers: example-app and a repository without CI ---------

/// Serves the GETs recorded under `tests/fixtures/auditor/posture/` (read-only
/// `gh api`, commit and owner bodies reduced to the fields read); any other
/// path is an error naming it.
struct Replay {
    replies: serde_json::Map<String, serde_json::Value>,
    /// Every GET served, in order, so a test can count the reads of each path.
    gets: RefCell<Vec<String>>,
}
impl brakes::remote::Api for Replay {
    fn get(&self, path: &str) -> brakes::Result<serde_json::Value> {
        self.gets.borrow_mut().push(path.to_owned());
        let reply = self
            .replies
            .get(path)
            .ok_or_else(|| format!("unrecorded GET {path}"))?;
        match reply["status"].as_u64() {
            Some(200) => Ok(reply["body"].clone()),
            status => Err(brakes::remote::HttpError {
                status: status.and_then(|s| u16::try_from(s).ok()).unwrap_or(500),
                message: reply["message"].as_str().unwrap_or_default().to_owned(),
            }
            .into()),
        }
    }
}

/// The posture block alone, so a recorded posture fixture answers every read.
static POSTURE_RULES: &[Rule] = &[
    posture::DEFAULT_BRANCH_PROTECTED,
    posture::NO_OPEN_SECRET_SCANNING_ALERTS,
    posture::REQUIRED_CHECK_ENFORCED,
    posture::NO_UNLISTED_BYPASS_ACTORS,
    posture::ACTIONS_PINNED,
    posture::NO_STALE_CRITICAL_ALERTS,
    posture::NO_REPO_SECRETS_WITH_PRODUCTION,
    posture::STALE_BRANCHES,
    posture::ORG_2FA_REQUIRED,
    posture::HUMAN_APPROVAL_REQUIRED,
    posture::CODEOWNERS_REVIEW,
    posture::SERIALISED_MERGES,
    posture::PRODUCTION_ENVIRONMENT_GUARDED,
];

/// Audits `rules` against the replies recorded in `tests/fixtures/auditor/
/// <fixture>.json`, over a checkout holding `files` (repository path → text).
fn recorded(fixture: &str, files: &[(&str, &str)], rules: &'static [Rule]) -> (Audit, u32) {
    recorded_together(&[fixture], &[], files, rules, 0)
}

/// [`recorded`] over the replies of several fixtures of one repository (the
/// first names it), plus `extra` replies, after `spent` calls of the budget.
fn recorded_together(
    fixtures: &[&str],
    extra: &[(&str, serde_json::Value)],
    files: &[(&str, &str)],
    rules: &'static [Rule],
    spent: u32,
) -> (Audit, u32) {
    let (audit, _, calls) = recorded_reading(fixtures, extra, files, rules, spent, false);
    (audit, calls)
}

/// [`recorded_together`], then the counters as a remote audit reads them
/// (`evaluate_counted`): their allowance held back while the rules read.
fn recorded_counted(
    fixtures: &[&str],
    extra: &[(&str, serde_json::Value)],
    files: &[(&str, &str)],
    rules: &'static [Rule],
    spent: u32,
) -> (Audit, Counters, u32) {
    let (audit, counters, calls) = recorded_reading(fixtures, extra, files, rules, spent, true);
    (audit, counters.unwrap(), calls)
}

fn recorded_reading(
    fixtures: &[&str],
    extra: &[(&str, serde_json::Value)],
    files: &[(&str, &str)],
    rules: &'static [Rule],
    spent: u32,
    counted: bool,
) -> (Audit, Option<Counters>, u32) {
    let read = |fixture: &str| -> serde_json::Value {
        let path = format!(
            "{}/tests/fixtures/auditor/{fixture}.json",
            env!("CARGO_MANIFEST_DIR")
        );
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap()
    };
    let fixture = read(fixtures[0]);
    let mut replies = serde_json::Map::new();
    for other in fixtures {
        replies.extend(read(other)["replies"].as_object().unwrap().clone());
    }
    for (path, reply) in extra {
        replies.insert((*path).to_owned(), reply.clone());
    }
    let replay = Replay {
        replies,
        gets: RefCell::default(),
    };
    let host = brakes::host::github::GitHub::new(&replay, CallBudget::new(60));
    let repo = RepoId::parse(fixture["repo"].as_str().unwrap()).unwrap();
    // A counted audit's measures have read the pull request listing the
    // counters share: it is among the calls spent, answered from a cache.
    let measured = Cached::new(&host);
    if counted {
        measured
            .pulls(&repo, &measures::pulls_filter(now()))
            .unwrap();
    }
    while host.budget().used() < spent {
        host.budget().spend().unwrap();
    }
    let dir = tempfile::tempdir().unwrap();
    for (file, text) in files {
        let file = dir.path().join(file);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, text).unwrap();
    }
    let local = LocalFiles::new(dir.path());
    let cx = Cx {
        host: if counted { &measured } else { &host },
        files: &local,
        repo: &repo,
        default_branch: fixture["default_branch"].as_str().unwrap(),
        now: now(),
        budget: host.budget(),
        profile: Profile::P1,
        today: None,
    };
    if counted {
        let (audit, counters) = evaluate_counted(&cx, &dims(Profile::P1), rules);
        return (audit, Some(counters), host.budget().used());
    }
    let audit = evaluate(&cx, &dims(Profile::P1), rules);
    (audit, None, host.budget().used())
}

#[test]
fn example_app_recorded_posture() {
    let example_app_ci = fs::read_to_string(format!(
        "{}/tests/fixtures/ci-baseline/monorepo-ci.yml",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let (audit, calls) = recorded(
        "posture/example-app",
        &[(".github/workflows/ci.yml", &example_app_ci)],
        POSTURE_RULES,
    );
    passed(
        &outcome(&audit, "posture.default-branch-protected"),
        &["classic protection of main blocks force-push and deletion"],
    );
    failed(
        &outcome(&audit, "posture.required-check-enforced"),
        &["main requires checks all-checks-passed; the aggregate check required is not among them"],
    );
    passed(
        &outcome(&audit, "posture.no-unlisted-bypass-actors"),
        &["no bypass actor on main"],
    );
    unavailable(
        &outcome(&audit, "posture.no-open-secret-scanning-alerts"),
        "open secret-scanning alerts of example-org/example-app was not found (404: Secret scanning is disabled on this repository.)",
    );
    unavailable(
        &outcome(&audit, "posture.no-stale-critical-alerts"),
        "Reading open Dependabot alerts of example-org/example-app is forbidden (403: Dependabot alerts are disabled for this repository.)",
    );
    let secrets = outcome(&audit, "posture.no-repo-secrets-with-production");
    assert_eq!(secrets.status, Status::Failed);
    assert!(
        secrets.evidence[0].starts_with(
            "repository-level secrets with a production environment: ANTHROPIC_API_KEY, "
        ),
        "{secrets:?}"
    );
    passed(
        &outcome(&audit, "posture.stale-branches"),
        &["4 branches besides main: at most 10 can be older than 90 days"],
    );
    failed(
        &outcome(&audit, "posture.org-2fa-required"),
        &["organization example-org does not require two-factor authentication"],
    );
    assert_eq!(
        outcome(&audit, "posture.actions-pinned").status,
        Status::Failed
    );
    // #889: classic protection with zero reviews and no code owner review,
    // strict required checks, production limited to main.
    failed(
        &outcome(&audit, "posture.human-approval-required"),
        &[
            "classic protection of main requires no approving review",
            "no active ruleset requires an approving review on main",
        ],
    );
    failed(
        &outcome(&audit, "posture.codeowners-review"),
        &[
            "classic protection of main does not require code owner review",
            "no active ruleset requires code owner review on main",
        ],
    );
    passed(
        &outcome(&audit, "posture.serialised-merges"),
        &["classic protection of main requires branches up to date before merging"],
    );
    passed(
        &outcome(&audit, "posture.production-environment-guarded"),
        &["production deploys only from main"],
    );
    // 22 calls before #917, which reads protection, rulesets and environments
    // once for every rule that needs them.
    assert_eq!(calls, 10, "posture spent {calls} calls");
}

#[test]
fn a_repository_without_ci_recorded_posture() {
    let (audit, _) = recorded("posture/no-ci", &[], POSTURE_RULES);
    failed(
        &outcome(&audit, "posture.default-branch-protected"),
        &[
            "main has no classic protection",
            "no active ruleset blocks force-push on main",
            "no active ruleset blocks deletion on main",
        ],
    );
    failed(
        &outcome(&audit, "posture.required-check-enforced"),
        &["main requires no status check"],
    );
    passed(
        &outcome(&audit, "posture.no-open-secret-scanning-alerts"),
        &["no open secret-scanning alerts"],
    );
    let o = outcome(&audit, "posture.no-repo-secrets-with-production");
    assert_eq!(o.status, Status::NotRequired);
    unavailable(
        &outcome(&audit, "posture.org-2fa-required"),
        "example-owner is a user account; the two-factor requirement is an organization setting",
    );
    let o = outcome(&audit, "posture.actions-pinned");
    assert_eq!(o.status, Status::NotRequired);
    assert_eq!(
        o.reason.as_deref(),
        Some("no workflow under .github/workflows")
    );
    failed(
        &outcome(&audit, "posture.human-approval-required"),
        &[
            "main has no classic protection",
            "no active ruleset requires an approving review on main",
        ],
    );
    failed(
        &outcome(&audit, "posture.serialised-merges"),
        &[
            "main has no classic protection",
            "no active ruleset requires a merge queue or up-to-date branches on main",
        ],
    );
    let o = outcome(&audit, "posture.production-environment-guarded");
    assert_eq!(o.status, Status::NotRequired);
    assert_eq!(o.reason.as_deref(), Some("no production environment"));
}

#[test]
fn a_branch_exactly_90_days_old_is_not_stale() {
    let at_cutoff = (0..11)
        .map(|i| (format!("{i:040x}"), "2026-07-30T12:00:00Z".to_owned()))
        .collect();
    let host = FakeHost {
        heads: Ok(heads(11)),
        dates: at_cutoff,
        ..FakeHost::default()
    };
    passed(
        &outcome(&run(&host), "posture.stale-branches"),
        &[
            "11 branches besides main: 1 dated, 0 older than 90 days (before 2026-07-30), 10 not dated: at most 10 can be stale",
        ],
    );
}

// --- ci-health ------------------------------------------------------------------------

/// The ci-health block alone, in registry order.
static CI_HEALTH: &[Rule] = &[
    ci_health::WORKFLOW_EXISTS,
    ci_health::RERUN_RATE,
    ci_health::CANCELLATION_RATE,
    ci_health::MINUTES_BUDGET,
];

const CI_YML: &str = "name: CI\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo test\n  required:\n    needs: test\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n";
const DEPLOY_YML: &str = "name: Deploy\non: push\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo deploy\n";
const PROJECT_BUDGET_15: &str =
    r#"{"ci": {"required_checks": ["required"], "cycle_budget_minutes": 15}}"#;

/// A run of `workflow` created at 10:00 on `day` (October 2026).
fn wrun(
    id: u64,
    workflow: &str,
    branch: &str,
    conclusion: Option<&str>,
    attempt: u32,
) -> WorkflowRun {
    WorkflowRun {
        id,
        name: workflow.to_owned(),
        head_sha: format!("{id:040x}"),
        head_branch: branch.to_owned(),
        event: "push".to_owned(),
        status: if conclusion.is_some() {
            "completed"
        } else {
            "in_progress"
        }
        .to_owned(),
        conclusion: conclusion.map(str::to_owned),
        run_attempt: Some(attempt),
        created_at: Some("2026-10-27T10:00:00Z".to_owned()),
        updated_at: None,
        run_started_at: None,
        pull_requests: Vec::new(),
    }
}
/// A job that completed `minutes` after its run was created.
fn job_done(name: &str, minutes: u32) -> Job {
    Job {
        id: 1,
        name: name.to_owned(),
        status: "completed".to_owned(),
        conclusion: Some("success".to_owned()),
        started_at: Some("2026-10-27T10:00:30Z".to_owned()),
        completed_at: Some(format!(
            "2026-10-27T{:02}:{:02}:00Z",
            10 + minutes / 60,
            minutes % 60
        )),
        labels: Vec::new(),
    }
}
/// `n` runs on `branch`, `rerun` of them re-run and `cancelled` cancelled.
fn runs(n: u64, rerun: u64, cancelled: u64) -> Vec<WorkflowRun> {
    (0..n)
        .map(|i| {
            let conclusion = if i < cancelled {
                "cancelled"
            } else {
                "success"
            };
            wrun(
                1000 + i,
                "CI",
                "feature",
                Some(conclusion),
                if i < rerun { 2 } else { 1 },
            )
        })
        .collect()
}
fn ci_audit(host: &FakeHost, files: &[(&str, &str)]) -> Audit {
    ci_audit_as(host, files, dims(Profile::P1))
}
fn ci_audit_as(host: &FakeHost, files: &[(&str, &str)], dims: Dimensions) -> Audit {
    let dir = tempfile::tempdir().unwrap();
    for (path, text) in files {
        let path = dir.path().join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
    let local = LocalFiles::new(dir.path());
    let repo = RepoId::parse("acme/shop").unwrap();
    let cx = Cx {
        host,
        files: &local,
        repo: &repo,
        default_branch: "main",
        now: now(),
        budget: &host.budget,
        profile: Profile::P1,
        today: None,
    };
    evaluate(&cx, &dims, CI_HEALTH)
}
#[track_caller]
fn not_required(o: &Outcome, reason: &str) {
    assert_eq!(o.status, Status::NotRequired, "{o:?}");
    assert_eq!(o.reason.as_deref(), Some(reason));
}

#[test]
fn the_ci_health_rules_are_registered_in_order() {
    let ids: Vec<&str> = REGISTRY
        .iter()
        .filter(|r| r.id.starts_with("ci-health."))
        .map(|r| r.id)
        .collect();
    let expected: Vec<&str> = CI_HEALTH.iter().map(|r| r.id).collect();
    assert_eq!(ids, expected);
}

// ci-health.workflow-exists

#[test]
fn no_workflow_fails_the_basic_rule_with_the_ci_baseline_module() {
    let host = FakeHost::default();
    let audit = ci_audit(&host, &[]);
    failed(
        &outcome(&audit, "ci-health.workflow-exists"),
        &["no workflow under .github/workflows"],
    );
    assert_eq!(
        ci_health::WORKFLOW_EXISTS.remediation,
        Remediation::Module { id: "ci-baseline" }
    );
    // Without a workflow the Basic rule reads nothing; the other three share
    // one listing of the latest runs (#917).
    assert_eq!(host.count("workflow_runs"), 1, "{:?}", host.calls);
}

#[test]
fn the_latest_conclusive_default_branch_run_decides_the_basic_rule() {
    let green = FakeHost {
        runs: Ok(vec![
            wrun(9, "CI", "main", None, 1),
            wrun(8, "CI", "feature", Some("failure"), 1),
            wrun(7, "CI", "main", Some("cancelled"), 1),
            wrun(6, "CI", "main", Some("success"), 1),
            wrun(5, "CI", "main", Some("failure"), 1),
        ]),
        ..FakeHost::default()
    };
    passed(
        &outcome(
            &ci_audit(&green, &[(".github/workflows/ci.yml", CI_YML)]),
            "ci-health.workflow-exists",
        ),
        &["1 workflow; the latest conclusive push run on main, run 6 of CI, succeeded"],
    );
    let red = FakeHost {
        runs: Ok(vec![wrun(6, "Deploy", "main", Some("failure"), 1)]),
        ..FakeHost::default()
    };
    failed(
        &outcome(
            &ci_audit(
                &red,
                &[
                    (".github/workflows/ci.yml", CI_YML),
                    (".github/workflows/deploy.yml", DEPLOY_YML),
                ],
            ),
            "ci-health.workflow-exists",
        ),
        &[
            "2 workflows; the latest conclusive push run on main, run 6 of Deploy, concluded failure",
        ],
    );
}

#[test]
fn a_workflow_without_a_conclusive_default_branch_run_is_unavailable() {
    let host = FakeHost {
        runs: Ok(vec![wrun(7, "CI", "main", Some("cancelled"), 1)]),
        ..FakeHost::default()
    };
    unavailable(
        &outcome(
            &ci_audit(&host, &[(".github/workflows/ci.yml", CI_YML)]),
            "ci-health.workflow-exists",
        ),
        "no completed push run on main among the latest 20 that was neither cancelled nor skipped",
    );
}

// ci-health.rerun-rate and ci-health.cancellation-rate

#[test]
fn twelve_re_runs_in_a_hundred_fail_and_ten_pass() {
    let host = FakeHost {
        runs: Ok(runs(100, 12, 0)),
        ..FakeHost::default()
    };
    failed(
        &outcome(&ci_audit(&host, &[]), "ci-health.rerun-rate"),
        &["12 of 100 CI runs re-run (12.0 %) > 10 %"],
    );
    let host = FakeHost {
        runs: Ok(runs(100, 10, 0)),
        ..FakeHost::default()
    };
    passed(
        &outcome(&ci_audit(&host, &[]), "ci-health.rerun-rate"),
        &["10 of 100 CI runs re-run (10.0 %) ≤ 10 %"],
    );
}

#[test]
fn cancellations_count_over_completed_runs_only() {
    let mut listed = runs(100, 0, 21);
    listed.push(wrun(5, "CI", "feature", None, 1));
    let host = FakeHost {
        runs: Ok(listed),
        ..FakeHost::default()
    };
    failed(
        &outcome(&ci_audit(&host, &[]), "ci-health.cancellation-rate"),
        &["21 of 100 completed CI runs cancelled (21.0 %) > 20 %"],
    );
    let host = FakeHost {
        runs: Ok(runs(80, 0, 16)),
        ..FakeHost::default()
    };
    passed(
        &outcome(&ci_audit(&host, &[]), "ci-health.cancellation-rate"),
        &["16 of 80 completed CI runs cancelled (20.0 %) ≤ 20 %"],
    );
}

#[test]
fn scheduled_and_chained_runs_do_not_count_in_the_rates() {
    let mut listed = runs(10, 2, 1);
    for i in 0..40 {
        let mut uptime = wrun(i, "uptime", "main", Some("cancelled"), 2);
        uptime.event = if i % 2 == 0 {
            "schedule"
        } else {
            "workflow_run"
        }
        .to_owned();
        listed.push(uptime);
    }
    let host = FakeHost {
        runs: Ok(listed),
        ..FakeHost::default()
    };
    let audit = ci_audit(&host, &[]);
    failed(
        &outcome(&audit, "ci-health.rerun-rate"),
        &["2 of 10 CI runs re-run (20.0 %) > 10 %"],
    );
    passed(
        &outcome(&audit, "ci-health.cancellation-rate"),
        &["1 of 10 completed CI runs cancelled (10.0 %) ≤ 20 %"],
    );
}

#[test]
fn rates_without_runs_are_not_required() {
    let host = FakeHost {
        runs: Ok(vec![wrun(5, "CI", "feature", None, 1)]),
        ..FakeHost::default()
    };
    let audit = ci_audit(&host, &[]);
    let empty = FakeHost {
        runs: Ok(Vec::new()),
        ..FakeHost::default()
    };
    not_required(
        &outcome(&ci_audit(&empty, &[]), "ci-health.rerun-rate"),
        "no CI run among the latest 100 workflow runs",
    );
    not_required(
        &outcome(&audit, "ci-health.cancellation-rate"),
        "no completed CI run among the latest 100 workflow runs",
    );
}

// ci-health.minutes-budget

/// Three first-attempt `CI` runs on main whose `required` job completed 10,
/// 12 and 20 minutes after the run was created, plus runs the median skips.
fn budget_host() -> FakeHost {
    let mut listed = vec![
        wrun(30, "CI", "main", Some("success"), 1),
        wrun(29, "CI", "main", Some("failure"), 2),
        wrun(28, "Deploy", "main", Some("success"), 1),
        wrun(27, "CI", "main", Some("success"), 1),
        wrun(26, "CI", "main", Some("cancelled"), 1),
        wrun(25, "CI", "main", Some("success"), 1),
    ];
    listed.push(wrun(24, "CI", "feature", Some("success"), 1));
    FakeHost {
        runs: Ok(listed),
        jobs: BTreeMap::from([
            (30, vec![job_done("test", 9), job_done("required", 10)]),
            (27, vec![job_done("required", 12)]),
            (25, vec![job_done("required", 20)]),
        ]),
        ..FakeHost::default()
    }
}

#[test]
fn a_median_cycle_within_the_budget_passes_with_the_minutes_sample() {
    let mut queued = wrun(31, "CI", "feature", None, 1);
    queued.status = "queued".to_owned();
    let mut listed = vec![queued];
    listed.extend(budget_host().runs.unwrap());
    // Only completed runs count toward the sample: the queued one does not.
    let host = FakeHost {
        runs: Ok(listed),
        ..budget_host()
    };
    passed(
        &outcome(
            &ci_audit(
                &host,
                &[
                    (".github/workflows/ci.yml", CI_YML),
                    (".agent-setup/project.json", PROJECT_BUDGET_15),
                ],
            ),
            "ci-health.minutes-budget",
        ),
        &[
            "median 12.0 min from run creation to job required over 3 first-attempt push runs of CI on main ≤ the cycle budget of 15 min",
            "CI minutes this month (a sample, not billing): 0.0 min, the wall-clock of 0 of 7 completed runs created this month among the latest 100 listed, from run start to last update",
        ],
    );
    assert_eq!(host.count("jobs"), 3, "{:?}", host.calls);
}

/// The minutes sample is read from the listing the rates already hold: each
/// completed run of the month from its start to its last update, no call per
/// run (#1318: the `timing` of the same runs `ci.minutes-month` reads the jobs
/// of cost up to 10 calls a repository).
#[test]
fn the_minutes_sample_reads_the_listing_and_spends_no_call_per_run() {
    let timed = |id, start: Option<&str>, end: Option<&str>| {
        let mut run = wrun(id, "CI", "main", Some("success"), 1);
        run.run_started_at = start.map(str::to_owned);
        run.updated_at = end.map(str::to_owned);
        run
    };
    let mut queued = wrun(31, "CI", "feature", None, 1);
    queued.status = "queued".to_owned();
    let mut september = timed(
        20,
        Some("2026-09-30T10:00:00Z"),
        Some("2026-09-30T11:00:00Z"),
    );
    september.created_at = Some("2026-09-30T10:00:00Z".to_owned());
    let host = FakeHost {
        runs: Ok(vec![
            queued,
            timed(
                30,
                Some("2026-10-27T10:00:00Z"),
                Some("2026-10-27T10:10:00Z"),
            ),
            // No start: from its creation, 2026-10-27T10:00:00Z.
            timed(29, None, Some("2026-10-27T10:03:00Z")),
            // No end, or an end before the start: listed, not timed.
            timed(28, Some("2026-10-27T10:00:00Z"), None),
            timed(
                27,
                Some("2026-10-27T10:05:00Z"),
                Some("2026-10-27T10:00:00Z"),
            ),
            september,
        ]),
        ..FakeHost::default()
    };
    let o = outcome(
        &ci_audit(&host, &[(".github/workflows/ci.yml", CI_YML)]),
        "ci-health.minutes-budget",
    );
    assert_eq!(
        o.evidence[2],
        "CI minutes this month (a sample, not billing): 13.0 min, the wall-clock of 2 of 4 completed runs created this month among the latest 100 listed, from run start to last update"
    );
    assert_eq!(host.count("run_timing"), 0, "{:?}", host.calls);
}

#[test]
fn a_median_cycle_over_the_budget_fails() {
    let project = r#"{"ci": {"required_checks": ["required"], "cycle_budget_minutes": 11.5}}"#;
    failed(
        &outcome(
            &ci_audit(
                &budget_host(),
                &[
                    (".github/workflows/ci.yml", CI_YML),
                    (".agent-setup/project.json", project),
                ],
            ),
            "ci-health.minutes-budget",
        ),
        &[
            "median 12.0 min from run creation to job required over 3 first-attempt push runs of CI on main > the cycle budget of 11.5 min",
            "CI minutes this month (a sample, not billing): 0.0 min, the wall-clock of 0 of 7 completed runs created this month among the latest 100 listed, from run start to last update",
        ],
    );
}

#[test]
fn an_undeclared_budget_fails_naming_each_missing_field() {
    let host = budget_host();
    let o = outcome(
        &ci_audit(&host, &[(".github/workflows/ci.yml", CI_YML)]),
        "ci-health.minutes-budget",
    );
    assert_eq!(o.status, Status::Failed, "{o:?}");
    assert_eq!(
        o.evidence[..2],
        [
            "ci.required_checks undeclared in .agent-setup/project.json",
            "ci.cycle_budget_minutes undeclared in .agent-setup/project.json",
        ]
    );
    assert!(o.evidence[2].starts_with("CI minutes this month"), "{o:?}");
    assert_eq!(host.count("jobs"), 0, "{:?}", host.calls);
}

#[test]
fn a_required_check_no_workflow_declares_is_unavailable() {
    let project =
        r#"{"ci": {"required_checks": ["all-checks-passed"], "cycle_budget_minutes": 15}}"#;
    unavailable(
        &outcome(
            &ci_audit(
                &budget_host(),
                &[
                    (".github/workflows/ci.yml", CI_YML),
                    (".agent-setup/project.json", project),
                ],
            ),
            "ci-health.minutes-budget",
        ),
        "no workflow under .github/workflows declares a job named all-checks-passed",
    );
}

#[test]
fn a_budget_without_any_measured_cycle_is_unavailable() {
    let host = FakeHost {
        runs: Ok(vec![wrun(30, "CI", "main", Some("success"), 1)]),
        ..FakeHost::default()
    };
    unavailable(
        &outcome(
            &ci_audit(
                &host,
                &[
                    (".github/workflows/ci.yml", CI_YML),
                    (".agent-setup/project.json", PROJECT_BUDGET_15),
                ],
            ),
            "ci-health.minutes-budget",
        ),
        "none of the latest 100 completed push runs on main is a first-attempt run of CI whose job required completed",
    );
}

#[test]
fn the_median_reads_at_most_twenty_runs() {
    let listed: Vec<WorkflowRun> = (0..30)
        .map(|i| wrun(100 - i, "CI", "main", Some("success"), 1))
        .collect();
    let jobs = listed
        .iter()
        .map(|r| (r.id, vec![job_done("required", 5)]))
        .collect();
    let host = FakeHost {
        runs: Ok(listed),
        jobs,
        ..FakeHost::default()
    };
    let o = outcome(
        &ci_audit(
            &host,
            &[
                (".github/workflows/ci.yml", CI_YML),
                (".agent-setup/project.json", PROJECT_BUDGET_15),
            ],
        ),
        "ci-health.minutes-budget",
    );
    assert_eq!(
        o.evidence[0],
        "median 5.0 min from run creation to job required over 20 first-attempt push runs of CI on main ≤ the cycle budget of 15 min"
    );
    assert_eq!(host.count("jobs"), 20);
    assert_eq!(host.count("run_timing"), 0, "the sample reads the listing");
}

// ci-health: every remote rule unavailable on a failed read and on the budget

#[test]
fn every_remote_ci_health_rule_reports_the_reads_own_sentence_when_it_fails() {
    let error = HostError::new(
        HostErrorKind::Forbidden,
        "Reading workflow runs of acme/shop is forbidden (403: Resource not accessible by integration)",
    );
    let audit = ci_audit(
        &FakeHost::failing(&error),
        &[
            (".github/workflows/ci.yml", CI_YML),
            (".agent-setup/project.json", PROJECT_BUDGET_15),
        ],
    );
    for rule in CI_HEALTH {
        unavailable(&outcome(&audit, rule.id), &error.message);
    }
}

#[test]
fn budget_exhaustion_mid_block_marks_the_remaining_rules_unavailable() {
    let host = FakeHost {
        budget: CallBudget::new(1),
        ..budget_host()
    };
    let audit = ci_audit(
        &host,
        &[
            (".github/workflows/ci.yml", CI_YML),
            (".agent-setup/project.json", PROJECT_BUDGET_15),
        ],
    );
    passed(
        &outcome(&audit, "ci-health.workflow-exists"),
        &["1 workflow; the latest conclusive push run on main, run 30 of CI, succeeded"],
    );
    for id in [
        "ci-health.rerun-rate",
        "ci-health.cancellation-rate",
        "ci-health.minutes-budget",
    ] {
        unavailable(
            &outcome(&audit, id),
            "budget exhausted: call budget of 1 exhausted",
        );
    }
}

#[test]
fn the_budget_stopping_the_median_leaves_it_unavailable() {
    // 1 push listing (exists, and the median from the cache, #917) + 1 listing
    // (both rates) + 1 job read.
    let host = FakeHost {
        budget: CallBudget::new(3),
        ..budget_host()
    };
    let audit = ci_audit(
        &host,
        &[
            (".github/workflows/ci.yml", CI_YML),
            (".agent-setup/project.json", PROJECT_BUDGET_15),
        ],
    );
    unavailable(
        &outcome(&audit, "ci-health.minutes-budget"),
        "budget exhausted: call budget of 3 exhausted",
    );
}

// The cadence condition: required at P1 when the agents merge enough.

#[test]
fn a_p1_repository_with_cadence_mid_has_the_ci_budget_rule_required() {
    let host = budget_host();
    let files = [
        (".github/workflows/ci.yml", CI_YML),
        (".agent-setup/project.json", PROJECT_BUDGET_15),
    ];
    let required = |cadence| {
        let audit = ci_audit_as(
            &host,
            &files,
            Dimensions {
                cadence: Some(cadence),
                ..dims(Profile::P1)
            },
        );
        audit
            .rules
            .iter()
            .map(|e| (e.rule.id, e.required, e.outcome.status))
            .collect::<Vec<_>>()
    };
    for (id, req, status) in required(Cadence::Mid) {
        assert!(req, "{id} required at P1 with cadence mid");
        assert_ne!(status, Status::NotRequired, "{id}");
    }
    let low = required(Cadence::Low);
    for (id, req, status) in &low {
        let expected = !matches!(*id, "ci-health.minutes-budget" | "ci-health.rerun-rate");
        assert_eq!(*req, expected, "{id} at P1 with cadence low");
        assert_ne!(
            *status,
            Status::NotRequired,
            "{id} is still evaluated and reported"
        );
    }
    // Every profile requires the two unconditioned rules.
    for profile in [Profile::P1, Profile::P2, Profile::P3] {
        for rule in [ci_health::WORKFLOW_EXISTS, ci_health::CANCELLATION_RATE] {
            assert!(dims(profile).requires(&rule), "{} in {profile:?}", rule.id);
        }
    }
}

// ci-health on recorded GitHub answers: example-app and a repository without CI

/// example-app with its aggregate check and a budget declared for the test
/// (its `project.json` declares neither yet).
const EXAMPLE_APP_PROJECT: &str =
    r#"{"ci": {"required_checks": ["all-checks-passed"], "cycle_budget_minutes": 20}}"#;

#[test]
fn example_app_recorded_ci_health() {
    let example_app_ci = fs::read_to_string(format!(
        "{}/tests/fixtures/ci-baseline/monorepo-ci.yml",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let (audit, calls) = recorded(
        "ci-health/example-app",
        &[
            (".github/workflows/ci.yml", &example_app_ci),
            (".agent-setup/project.json", EXAMPLE_APP_PROJECT),
        ],
        CI_HEALTH,
    );
    passed(
        &outcome(&audit, "ci-health.workflow-exists"),
        &["1 workflow; the latest conclusive push run on main, run 40862628372 of CI, succeeded"],
    );
    passed(
        &outcome(&audit, "ci-health.rerun-rate"),
        &["0 of 20 CI runs re-run (0.0 %) ≤ 10 %"],
    );
    passed(
        &outcome(&audit, "ci-health.cancellation-rate"),
        &["1 of 20 completed CI runs cancelled (5.0 %) ≤ 20 %"],
    );
    passed(
        &outcome(&audit, "ci-health.minutes-budget"),
        &[
            "median 5.2 min from run creation to job all-checks-passed over 20 first-attempt push runs of CI on main ≤ the cycle budget of 20 min",
            "CI minutes this month (a sample, not billing): 120.5 min, the wall-clock of 100 of 100 completed runs created this month among the latest 100 listed, from run start to last update",
        ],
    );
    // 1 push listing (workflow-exists, then the median), 1 listing of the
    // latest runs (both rates, then the minutes sample), 20 jobs: 35 before
    // #917 read each listing once per rule, 32 before the minutes sample read
    // the listing instead of 10 timings (#1318).
    assert_eq!(calls, 22);
}

#[test]
fn a_repository_without_ci_recorded_ci_health() {
    let (audit, calls) = recorded("ci-health/no-ci", &[], CI_HEALTH);
    failed(
        &outcome(&audit, "ci-health.workflow-exists"),
        &["no workflow under .github/workflows"],
    );
    not_required(
        &outcome(&audit, "ci-health.rerun-rate"),
        "no CI run among the latest 100 workflow runs",
    );
    not_required(
        &outcome(&audit, "ci-health.cancellation-rate"),
        "no completed CI run among the latest 100 workflow runs",
    );
    failed(
        &outcome(&audit, "ci-health.minutes-budget"),
        &[
            "ci.required_checks undeclared in .agent-setup/project.json",
            "ci.cycle_budget_minutes undeclared in .agent-setup/project.json",
            "CI minutes this month (a sample, not billing): no completed run this month among the latest 100",
        ],
    );
    // One listing of the latest runs, shared by the rates and the sample (#917).
    assert_eq!(calls, 1);
}

/// Posture, ci-health and DORA together, as one audit of example-app reads them.
static EXAMPLE_APP_REMOTE_BLOCKS: &[Rule] = &[
    posture::DEFAULT_BRANCH_PROTECTED,
    posture::NO_OPEN_SECRET_SCANNING_ALERTS,
    posture::REQUIRED_CHECK_ENFORCED,
    posture::NO_UNLISTED_BYPASS_ACTORS,
    posture::ACTIONS_PINNED,
    posture::NO_STALE_CRITICAL_ALERTS,
    posture::NO_REPO_SECRETS_WITH_PRODUCTION,
    posture::STALE_BRANCHES,
    posture::ORG_2FA_REQUIRED,
    posture::HUMAN_APPROVAL_REQUIRED,
    posture::CODEOWNERS_REVIEW,
    posture::SERIALISED_MERGES,
    posture::PRODUCTION_ENVIRONMENT_GUARDED,
    ci_health::WORKFLOW_EXISTS,
    ci_health::RERUN_RATE,
    ci_health::CANCELLATION_RATE,
    ci_health::MINUTES_BUDGET,
    dora::DEPLOYMENTS_API_IN_USE,
    dora::TIME_TO_RESTORE,
    dora::DEPLOYMENT_FREQUENCY,
    dora::LEAD_TIME,
    dora::CHANGE_FAILURE_RATE,
];

/// #917: one audit reads each endpoint once. The posture, ci-health and DORA
/// recordings of example-app (disjoint paths) answer one audit of the three blocks;
/// every GET is served once and the budget counts exactly the GETs served.
#[test]
fn one_audit_of_example_app_reads_each_endpoint_once() {
    let fixture = |name: &str| -> serde_json::Value {
        let path = format!(
            "{}/tests/fixtures/auditor/{name}.json",
            env!("CARGO_MANIFEST_DIR")
        );
        serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
    };
    let mut replies = fixture("posture/example-app")["replies"]
        .as_object()
        .unwrap()
        .clone();
    for block in ["ci-health/example-app", "dora/example-app"] {
        let more = fixture(block)["replies"].as_object().unwrap().clone();
        assert!(
            more.keys().all(|path| !replies.contains_key(path)),
            "{block}"
        );
        replies.extend(more);
    }
    let replay = Replay {
        replies,
        gets: RefCell::default(),
    };
    let host = brakes::host::github::GitHub::new(&replay, CallBudget::new(60));
    let repo = RepoId::parse("example-org/example-app").unwrap();
    let example_app_ci = fs::read_to_string(format!(
        "{}/tests/fixtures/ci-baseline/monorepo-ci.yml",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    for (file, text) in [
        (".github/workflows/ci.yml", example_app_ci.as_str()),
        (".agent-setup/project.json", EXAMPLE_APP_PROJECT),
    ] {
        let file = dir.path().join(file);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, text).unwrap();
    }
    let local = LocalFiles::new(dir.path());
    let cx = Cx {
        host: &host,
        files: &local,
        repo: &repo,
        default_branch: "main",
        now: now(),
        budget: host.budget(),
        profile: Profile::P1,
        today: None,
    };
    let audit = evaluate(&cx, &dims(Profile::P1), EXAMPLE_APP_REMOTE_BLOCKS);
    let mut served: BTreeMap<String, usize> = BTreeMap::new();
    for path in replay.gets.borrow().iter() {
        *served.entry(path.clone()).or_default() += 1;
    }
    let repeated: Vec<_> = served.iter().filter(|(_, n)| **n > 1).collect();
    assert!(repeated.is_empty(), "read more than once: {repeated:?}");
    assert_eq!(host.budget().used() as usize, replay.gets.borrow().len());
    // 10 for posture, 22 for ci-health and 13 for DORA; 22 + 35 + 23 = 80
    // before #917, 55 before the minutes sample read the listing (#1318).
    // The measures and the repository read come on top.
    assert_eq!(host.budget().used(), 45);
    // The outcomes are those of each block audited alone.
    passed(
        &outcome(&audit, "posture.serialised-merges"),
        &["classic protection of main requires branches up to date before merging"],
    );
    passed(
        &outcome(&audit, "ci-health.cancellation-rate"),
        &["1 of 20 completed CI runs cancelled (5.0 %) ≤ 20 %"],
    );
    passed(
        &outcome(&audit, "dora.change-failure-rate"),
        &[
            "1 of the newest 8 of 10 production deployments in the 28 days to 2026-10-28 failed or rolled back (12.5 %) ≤ 15 %",
            "failed: 7381596985 failure",
        ],
    );
}

// --- dora: deployments, statuses, pull requests of a commit and incident issues -------

static DORA: &[Rule] = &[
    dora::DEPLOYMENTS_API_IN_USE,
    dora::TIME_TO_RESTORE,
    dora::DEPLOYMENT_FREQUENCY,
    dora::LEAD_TIME,
    dora::CHANGE_FAILURE_RATE,
];

/// The DORA block alone over an empty checkout, so the calls are its own.
fn dora_audit(host: &FakeHost) -> Audit {
    dora_rules(host, DORA)
}
/// One DORA rule alone.
fn evaluate_one(host: &FakeHost, rule: Rule) -> Audit {
    dora_rules(host, Box::leak(Box::new([rule])))
}
fn dora_rules(host: &FakeHost, rules: &'static [Rule]) -> Audit {
    let dir = tempfile::tempdir().unwrap();
    let local = LocalFiles::new(dir.path());
    let repo = RepoId::parse("acme/shop").unwrap();
    let cx = Cx {
        host,
        files: &local,
        repo: &repo,
        default_branch: "main",
        now: now(),
        budget: &host.budget,
        profile: Profile::P1,
        today: None,
    };
    evaluate(&cx, &dims(Profile::P1), rules)
}

fn deploy(id: u64, sha: &str, created: &str) -> Deployment {
    Deployment {
        id,
        environment: "production".to_owned(),
        sha: sha.to_owned(),
        reference: Some("main".to_owned()),
        created_at: Some(created.to_owned()),
        state: None,
    }
}
/// The final status of deployment `id`, set at `at`.
fn finished(id: u64, state: &str, at: &str) -> (u64, Vec<DeploymentStatus>) {
    let status = |n: u64, state: &str| DeploymentStatus {
        id: id * 10 + n,
        state: state.to_owned(),
        environment: Some("production".to_owned()),
        created_at: Some(at.to_owned()),
    };
    (id, vec![status(2, state), status(1, "in_progress")])
}
fn merged(number: u64, at: &str) -> PullMeta {
    PullMeta {
        number,
        title: format!("change {number}"),
        state: "closed".to_owned(),
        head_sha: format!("{number:040x}"),
        base: "main".to_owned(),
        author: None,
        draft: Some(false),
        created_at: None,
        merged_at: Some(at.to_owned()),
        closed_at: Some(at.to_owned()),
        merge_commit_sha: None,
    }
}
fn incident(number: u64, opened: &str, closed: &str) -> IssueMeta {
    IssueMeta {
        number,
        title: format!("incident {number}"),
        state: "closed".to_owned(),
        labels: vec!["incident".to_owned()],
        author: None,
        created_at: Some(opened.to_owned()),
        updated_at: Some(closed.to_owned()),
        closed_at: Some(closed.to_owned()),
        url: None,
        body: None,
    }
}
/// `n` deployments a day apart from 2026-10-28 back, each of its own sha, all
/// succeeded an hour after creation.
fn daily(n: u64) -> FakeHost {
    let deployments: Vec<Deployment> = (0..n)
        .map(|i| {
            deploy(
                100 + i,
                &format!("sha{i}"),
                &format!("2026-10-{:02}T10:00:00Z", 28 - i),
            )
        })
        .collect();
    let statuses = (0..n)
        .map(|i| {
            finished(
                100 + i,
                "success",
                &format!("2026-10-{:02}T11:00:00Z", 28 - i),
            )
        })
        .collect();
    FakeHost {
        deployments: Ok(deployments),
        statuses,
        incidents: Ok(Vec::new()),
        ..FakeHost::default()
    }
}

#[test]
fn without_deployments_the_api_rule_fails_and_the_other_three_are_unavailable() {
    let host = FakeHost {
        deployments: Ok(Vec::new()),
        incidents: Ok(Vec::new()),
        ..FakeHost::default()
    };
    let audit = dora_audit(&host);
    failed(
        &outcome(&audit, "dora.deployments-api-in-use"),
        &["no production deployment recorded through the Deployments API"],
    );
    assert_eq!(
        dora::DEPLOYMENTS_API_IN_USE.remediation,
        Remediation::Module { id: "delivery" }
    );
    for id in [
        "dora.deployment-frequency",
        "dora.lead-time",
        "dora.change-failure-rate",
    ] {
        unavailable(&outcome(&audit, id), "no deployments recorded");
    }
    not_required(
        &outcome(&audit, "dora.time-to-restore"),
        "no issue labelled incident closed in the 28 days to 2026-10-28",
    );
    assert_eq!(host.count("deployment_statuses"), 0);
}

#[test]
fn every_dora_rule_reports_the_reads_own_sentence_when_it_fails() {
    for error in [
        HostError::new(
            HostErrorKind::Forbidden,
            "Reading acme/shop is forbidden (403: Resource not accessible by integration)",
        ),
        HostError::new(
            HostErrorKind::NotFound,
            "acme/shop was not found (404: Not Found)",
        ),
        HostError::new(
            HostErrorKind::Shape,
            "acme/shop has an unexpected shape: the response is not a list",
        ),
    ] {
        let audit = dora_audit(&FakeHost::failing(&error));
        for rule in DORA {
            unavailable(&outcome(&audit, rule.id), &error.message);
        }
    }
}

#[test]
fn every_dora_rule_is_unavailable_once_the_budget_is_exhausted() {
    let host = FakeHost {
        budget: CallBudget::new(0),
        ..daily(10)
    };
    let audit = dora_audit(&host);
    for rule in DORA {
        unavailable(
            &outcome(&audit, rule.id),
            "budget exhausted: call budget of 0 exhausted",
        );
    }
}

#[test]
fn a_deployment_with_an_unreadable_date_is_unavailable() {
    let host = FakeHost {
        deployments: Ok(vec![Deployment {
            created_at: None,
            ..deploy(7, "abc", "")
        }]),
        ..FakeHost::default()
    };
    let audit = dora_audit(&host);
    unavailable(
        &outcome(&audit, "dora.deployment-frequency"),
        "deployment 7 has no readable created_at",
    );
}

#[test]
fn dora_rules_are_required_in_every_profile() {
    for profile in [Profile::P1, Profile::P2, Profile::P3] {
        for rule in DORA {
            assert!(dims(profile).requires(rule), "{} in {profile:?}", rule.id);
            assert!(REGISTRY.iter().any(|r| r.id == rule.id), "{}", rule.id);
        }
    }
}

#[test]
fn the_dora_block_spends_at_most_13_calls() {
    // Ten deployments, every one a failure: no rule stops early.
    let mut host = daily(10);
    for i in 0..10 {
        let (id, statuses) = finished(100 + i, "failure", "2026-10-20T00:00:00Z");
        host.statuses.insert(id, statuses);
    }
    host.deployments = Ok((0..10)
        .map(|i| deploy(100 + i, &format!("sha{i}"), "2026-10-27T10:00:00Z"))
        .collect());
    dora_audit(&host);
    // The listing and the incidents once, then the statuses of the newest 8
    // once between the three rules that read them (#917; 23 before).
    assert_eq!(host.budget.used(), 1 + 1 + 8);
    // The worst case: frequency decided at the eighth status, three merged leads.
    let mut host = daily(10);
    for i in [3, 4, 5, 6] {
        let (id, statuses) = finished(100 + i, "failure", "2026-10-20T00:00:00Z");
        host.statuses.insert(id, statuses);
    }
    for i in 0..3 {
        host.commit_pulls
            .insert(format!("sha{i}"), vec![merged(i, "2026-10-01T00:00:00Z")]);
    }
    dora_audit(&host);
    // The listing, the incidents, 8 statuses and 3 commits' pulls, each once
    // per audit (#917; 1 + 1 + (1 + 8) + (1 + 3 + 3) + (1 + 8) = 27 before).
    assert_eq!(host.budget.used(), 1 + 1 + 8 + 3);
}

// dora.deployments-api-in-use

#[test]
fn recorded_production_deployments_put_the_api_in_use() {
    let audit = dora_audit(&daily(2));
    passed(
        &outcome(&audit, "dora.deployments-api-in-use"),
        &["production deployments recorded; the newest, 100, created 2026-10-28T10:00:00Z"],
    );
}

// dora.deployment-frequency

#[test]
fn four_successful_deployments_pass_after_four_status_reads() {
    let host = daily(10);
    let audit = evaluate_one(&host, dora::DEPLOYMENT_FREQUENCY);
    passed(
        &outcome(&audit, "dora.deployment-frequency"),
        &[
            "at least 4 of 10 production deployments in the 28 days to 2026-10-28 succeeded: 4 of the newest 4 (needs 4 successful, 1 per week)",
        ],
    );
    assert_eq!(host.count("deployment_statuses"), 4);
}

/// Four successful deployments, the oldest `oldest` days before 2026-10-28.
fn four_with_oldest(oldest: &str) -> FakeHost {
    let mut host = daily(3);
    let mut deployments = host.deployments.clone().unwrap();
    deployments.push(deploy(200, "old", oldest));
    host.deployments = Ok(deployments);
    let (id, statuses) = finished(200, "success", oldest);
    host.statuses.insert(id, statuses);
    host
}

#[test]
fn a_deployment_exactly_28_days_old_is_in_the_window_and_29_out() {
    // --now is 2026-10-28: 28 days before is 2026-09-30.
    let host = four_with_oldest("2026-09-30T00:00:00Z");
    let audit = evaluate_one(&host, dora::DEPLOYMENT_FREQUENCY);
    assert_eq!(
        outcome(&audit, "dora.deployment-frequency").status,
        Status::Passed
    );

    let host = four_with_oldest("2026-09-29T23:59:59Z");
    let audit = evaluate_one(&host, dora::DEPLOYMENT_FREQUENCY);
    failed(
        &outcome(&audit, "dora.deployment-frequency"),
        &[
            "at most 3 of 3 production deployments in the 28 days to 2026-10-28 succeeded, 0 final statuses read (needs 4 successful, 1 per week)",
        ],
    );
    assert_eq!(host.count("deployment_statuses"), 0, "decided by the count");
}

#[test]
fn a_deployment_after_now_is_outside_the_window() {
    let mut host = daily(3);
    let mut deployments = host.deployments.clone().unwrap();
    deployments.insert(0, deploy(300, "future", "2026-10-29T00:00:00Z"));
    host.deployments = Ok(deployments);
    let audit = evaluate_one(&host, dora::DEPLOYMENT_FREQUENCY);
    assert_eq!(
        outcome(&audit, "dora.deployment-frequency").status,
        Status::Failed
    );
}

#[test]
fn no_deployment_in_the_window_fails() {
    let host = FakeHost {
        deployments: Ok(vec![deploy(1, "a", "2026-08-01T00:00:00Z")]),
        incidents: Ok(Vec::new()),
        ..FakeHost::default()
    };
    let audit = dora_audit(&host);
    failed(
        &outcome(&audit, "dora.deployment-frequency"),
        &["0 production deployments in the 28 days to 2026-10-28 (needs 4 successful, 1 per week)"],
    );
    unavailable(
        &outcome(&audit, "dora.lead-time"),
        "no production deployment in the 28 days to 2026-10-28",
    );
    unavailable(
        &outcome(&audit, "dora.change-failure-rate"),
        "no production deployment in the 28 days to 2026-10-28",
    );
    passed(
        &outcome(&audit, "dora.deployments-api-in-use"),
        &["production deployments recorded; the newest, 1, created 2026-08-01T00:00:00Z"],
    );
}

#[test]
fn failures_decide_a_failed_frequency_before_reading_every_status() {
    let mut host = daily(5);
    for i in [0, 1] {
        let (id, statuses) = finished(100 + i, "error", "2026-10-28T11:00:00Z");
        host.statuses.insert(id, statuses);
    }
    let audit = evaluate_one(&host, dora::DEPLOYMENT_FREQUENCY);
    failed(
        &outcome(&audit, "dora.deployment-frequency"),
        &[
            "at most 3 of 5 production deployments in the 28 days to 2026-10-28 succeeded, 2 final statuses read (needs 4 successful, 1 per week)",
        ],
    );
    assert_eq!(host.count("deployment_statuses"), 2);
}

#[test]
fn undecided_at_the_status_cap_is_unavailable() {
    // 12 deployments, the newest five failed: 3 successes at the cap of 8
    // reads, with 4 deployments left unread that could still make 4.
    let mut host = daily(12);
    for i in [0, 1, 2, 3, 4] {
        let (id, statuses) = finished(100 + i, "failure", "2026-10-28T11:00:00Z");
        host.statuses.insert(id, statuses);
    }
    let audit = evaluate_one(&host, dora::DEPLOYMENT_FREQUENCY);
    unavailable(
        &outcome(&audit, "dora.deployment-frequency"),
        "3 of the newest 8 of 12 production deployments in the 28 days to 2026-10-28 succeeded, undecided at the cap of 8 status reads (needs 4 successful, 1 per week)",
    );
    assert_eq!(host.count("deployment_statuses"), 8);
}

// dora.lead-time

/// `daily(n)` with the pull request of each listed sha merged `hours` before
/// its deployment succeeded (11:00 on its day).
fn with_leads(n: u64, hours: &[(u64, &str)]) -> FakeHost {
    let mut host = daily(n);
    for (i, merged_at) in hours {
        host.commit_pulls
            .insert(format!("sha{i}"), vec![merged(*i, merged_at)]);
    }
    host
}

#[test]
fn lead_time_is_the_median_over_an_odd_count() {
    let host = with_leads(
        5,
        &[
            (0, "2026-10-28T10:00:00Z"), // 1 h
            (1, "2026-10-27T05:00:00Z"), // 6 h
            (2, "2026-10-20T11:00:00Z"), // 6 days
            (3, "2026-10-01T00:00:00Z"), // outside the sample of 3
        ],
    );
    let audit = evaluate_one(&host, dora::LEAD_TIME);
    passed(
        &outcome(&audit, "dora.lead-time"),
        &[
            "median 6.0 h from merge to successful deployment over 3 of the newest 3 of 5 production deployments in the 28 days to 2026-10-28 (a sample) ≤ 7 days",
        ],
    );
    assert_eq!(host.count("pulls_for_commit"), 3);
}

#[test]
fn lead_time_is_the_mean_of_the_two_middle_values_over_an_even_count() {
    // The newest deployment failed: no pull request is read for it.
    let mut host = with_leads(
        3,
        &[(1, "2026-10-27T09:00:00Z"), (2, "2026-10-26T05:00:00Z")], // 2 h, 6 h
    );
    let (id, statuses) = finished(100, "failure", "2026-10-28T11:00:00Z");
    host.statuses.insert(id, statuses);
    let audit = evaluate_one(&host, dora::LEAD_TIME);
    passed(
        &outcome(&audit, "dora.lead-time"),
        &[
            "median 4.0 h from merge to successful deployment over 2 of the newest 3 of 3 production deployments in the 28 days to 2026-10-28 (a sample) ≤ 7 days",
        ],
    );
    assert_eq!(host.count("pulls_for_commit"), 2);
}

#[test]
fn lead_time_runs_from_the_earliest_merge_of_a_pull_request_containing_the_sha() {
    let mut host = daily(1);
    host.commit_pulls.insert(
        "sha0".to_owned(),
        vec![
            merged(1, "2026-10-28T10:00:00Z"),
            merged(2, "2026-10-28T09:00:00Z"),
        ],
    );
    let audit = evaluate_one(&host, dora::LEAD_TIME);
    passed(
        &outcome(&audit, "dora.lead-time"),
        &[
            "median 2.0 h from merge to successful deployment over 1 of the newest 1 of 1 production deployments in the 28 days to 2026-10-28 (a sample) ≤ 7 days",
        ],
    );
}

#[test]
fn a_median_lead_time_over_seven_days_fails() {
    let host = with_leads(1, &[(0, "2026-10-20T10:00:00Z")]); // 8 days 1 h
    let audit = evaluate_one(&host, dora::LEAD_TIME);
    failed(
        &outcome(&audit, "dora.lead-time"),
        &[
            "median 193.0 h from merge to successful deployment over 1 of the newest 1 of 1 production deployments in the 28 days to 2026-10-28 (a sample) > 7 days",
        ],
    );
}

#[test]
fn deployments_without_a_merged_pull_request_leave_lead_time_unavailable() {
    let host = daily(2);
    let audit = evaluate_one(&host, dora::LEAD_TIME);
    unavailable(
        &outcome(&audit, "dora.lead-time"),
        "none of the newest 2 of 2 production deployments in the 28 days to 2026-10-28 succeeded with a merged pull request containing its sha",
    );
}

// dora.change-failure-rate

#[test]
fn a_rollback_by_a_repeated_sha_within_24_hours_counts_as_a_failure() {
    // Newest first: 102 redeploys sha "a" that 100 deployed 20 h earlier.
    let mut host = daily(0);
    host.deployments = Ok(vec![
        deploy(102, "a", "2026-10-28T06:00:00Z"),
        deploy(101, "b", "2026-10-27T12:00:00Z"),
        deploy(100, "a", "2026-10-27T10:00:00Z"),
    ]);
    for id in [100, 101, 102] {
        let (id, statuses) = finished(id, "success", "2026-10-28T00:00:00Z");
        host.statuses.insert(id, statuses);
    }
    let audit = evaluate_one(&host, dora::CHANGE_FAILURE_RATE);
    failed(
        &outcome(&audit, "dora.change-failure-rate"),
        &[
            "1 of the newest 3 of 3 production deployments in the 28 days to 2026-10-28 failed or rolled back (33.3 %) > 15 %",
            "failed: 102 rollback to 100",
        ],
    );
}

#[test]
fn a_repeated_sha_more_than_24_hours_later_or_after_a_failure_is_not_a_rollback() {
    let mut host = daily(0);
    host.deployments = Ok(vec![
        deploy(104, "c", "2026-10-28T10:00:00Z"),
        deploy(103, "c", "2026-10-28T09:00:00Z"),
        deploy(102, "a", "2026-10-27T10:00:01Z"),
        deploy(101, "b", "2026-10-26T12:00:00Z"),
        deploy(100, "a", "2026-10-26T10:00:00Z"),
        deploy(99, "d", "2026-10-25T10:00:00Z"),
        deploy(98, "e", "2026-10-24T10:00:00Z"),
    ]);
    for id in [98, 99, 100, 101, 102, 104] {
        let (id, statuses) = finished(id, "success", "2026-10-28T00:00:00Z");
        host.statuses.insert(id, statuses);
    }
    let (id, statuses) = finished(103, "error", "2026-10-28T09:30:00Z");
    host.statuses.insert(id, statuses);
    let audit = evaluate_one(&host, dora::CHANGE_FAILURE_RATE);
    passed(
        &outcome(&audit, "dora.change-failure-rate"),
        &[
            "1 of the newest 7 of 7 production deployments in the 28 days to 2026-10-28 failed or rolled back (14.3 %) ≤ 15 %",
            "failed: 103 error",
        ],
    );
}

#[test]
fn failed_and_errored_deployments_count_over_the_sample_of_eight() {
    let mut host = daily(10);
    for (i, state) in [(1, "failure"), (5, "error"), (9, "failure")] {
        let (id, statuses) = finished(100 + i, state, "2026-10-28T11:00:00Z");
        host.statuses.insert(id, statuses);
    }
    let audit = evaluate_one(&host, dora::CHANGE_FAILURE_RATE);
    failed(
        &outcome(&audit, "dora.change-failure-rate"),
        &[
            "2 of the newest 8 of 10 production deployments in the 28 days to 2026-10-28 failed or rolled back (25.0 %) > 15 %",
            "failed: 101 failure, 105 error",
        ],
    );
    assert_eq!(host.count("deployment_statuses"), 8);
}

#[test]
fn no_failed_deployment_passes() {
    let audit = evaluate_one(&daily(4), dora::CHANGE_FAILURE_RATE);
    passed(
        &outcome(&audit, "dora.change-failure-rate"),
        &[
            "0 of the newest 4 of 4 production deployments in the 28 days to 2026-10-28 failed or rolled back (0.0 %) ≤ 15 %",
        ],
    );
}

// dora.time-to-restore

fn restoring(incidents: Vec<IssueMeta>) -> Outcome {
    let host = FakeHost {
        incidents: Ok(incidents),
        ..FakeHost::default()
    };
    outcome(
        &evaluate_one(&host, dora::TIME_TO_RESTORE),
        "dora.time-to-restore",
    )
}

#[test]
fn time_to_restore_is_the_median_over_an_odd_count() {
    passed(
        &restoring(vec![
            incident(1, "2026-10-20T00:00:00Z", "2026-10-20T02:00:00Z"), // 2 h
            incident(2, "2026-10-21T00:00:00Z", "2026-10-21T05:00:00Z"), // 5 h
            incident(3, "2026-10-22T00:00:00Z", "2026-10-24T00:00:00Z"), // 48 h
            incident(4, "2026-09-01T00:00:00Z", "2026-09-29T00:00:00Z"), // closed outside
        ]),
        &[
            "median 5.0 h from opening to closing over 3 issues labelled incident closed in the 28 days to 2026-10-28 ≤ 24 h",
        ],
    );
}

#[test]
fn time_to_restore_over_an_even_count_over_24_hours_fails() {
    failed(
        &restoring(vec![
            incident(1, "2026-10-20T00:00:00Z", "2026-10-21T00:00:00Z"), // 24 h
            incident(2, "2026-10-21T00:00:00Z", "2026-10-23T00:00:00Z"), // 48 h
        ]),
        &[
            "median 36.0 h from opening to closing over 2 issues labelled incident closed in the 28 days to 2026-10-28 > 24 h",
        ],
    );
}

#[test]
fn no_incident_closed_in_the_window_is_not_required() {
    not_required(
        &restoring(Vec::new()),
        "no issue labelled incident closed in the 28 days to 2026-10-28",
    );
}

#[test]
fn an_incident_with_an_unreadable_date_is_unavailable() {
    let mut open = incident(9, "2026-10-20T00:00:00Z", "");
    open.closed_at = None;
    unavailable(
        &restoring(vec![open]),
        "issue #9 labelled incident has no readable created_at or closed_at",
    );
}

// dora on recorded GitHub answers: example-app and a repository without deployments

#[test]
fn example_app_recorded_dora() {
    let (audit, calls) = recorded("dora/example-app", &[], DORA);
    passed(
        &outcome(&audit, "dora.deployments-api-in-use"),
        &["production deployments recorded; the newest, 7397645433, created 2026-10-28T21:21:25Z"],
    );
    not_required(
        &outcome(&audit, "dora.time-to-restore"),
        "no issue labelled incident closed in the 28 days to 2026-10-28",
    );
    passed(
        &outcome(&audit, "dora.deployment-frequency"),
        &[
            "at least 4 of 10 production deployments in the 28 days to 2026-10-28 succeeded: 4 of the newest 4 (needs 4 successful, 1 per week)",
        ],
    );
    passed(
        &outcome(&audit, "dora.lead-time"),
        &[
            "median 0.2 h from merge to successful deployment over 3 of the newest 3 of 10 production deployments in the 28 days to 2026-10-28 (a sample) ≤ 7 days",
        ],
    );
    // 7381629510 redeployed the sha of the failed 7381596985: a retry, not a rollback.
    passed(
        &outcome(&audit, "dora.change-failure-rate"),
        &[
            "1 of the newest 8 of 10 production deployments in the 28 days to 2026-10-28 failed or rolled back (12.5 %) ≤ 15 %",
            "failed: 7381596985 failure",
        ],
    );
    // The listing, the incidents, the statuses of the newest 8 and the pulls of
    // 3 commits, each once (#917; 1 + 1 + (1 + 4) + (1 + 3 + 3) + (1 + 8) = 23 before).
    assert_eq!(calls, 13);
}

#[test]
fn a_repository_without_deployments_recorded_dora() {
    let (audit, calls) = recorded("dora/no-deployments", &[], DORA);
    failed(
        &outcome(&audit, "dora.deployments-api-in-use"),
        &["no production deployment recorded through the Deployments API"],
    );
    for id in [
        "dora.deployment-frequency",
        "dora.lead-time",
        "dora.change-failure-rate",
    ] {
        unavailable(&outcome(&audit, id), "no deployments recorded");
    }
    not_required(
        &outcome(&audit, "dora.time-to-restore"),
        "no issue labelled incident closed in the 28 days to 2026-10-28",
    );
    // The listing and the incidents, once each (#917; 5 before).
    assert_eq!(calls, 2);
}

// --- operations and the governance rules that wait for a module (#728) ---------------

/// Every rule whose convention another module defines, and that module.
const WAITING: &[(&str, &str)] = &[
    ("operations.post-deploy-smoke", "delivery"),
    ("operations.rollback-evidence", "delivery"),
    ("operations.uptime-footprint", "observability"),
    ("operations.incidents-bounded", "incidents"),
    ("operations.runbook-per-alert", "incidents"),
    ("operations.slo-burn-rate-validated", "incidents"),
    ("operations.backup-age-within-rpo", "continuity"),
    ("operations.restore-drill-fresh", "continuity"),
    ("governance.no-expired-flags", "flags"),
    ("governance.cost-tags", "iac"),
    ("governance.no-persistent-oversizing", "k8s"),
    ("security.attestation-verified", "delivery"),
    ("security.sbom-scanned", "delivery"),
];

fn waiting_rules() -> Vec<&'static Rule> {
    REGISTRY
        .iter()
        .filter(|r| matches!(r.feasible_by, Milestone::WaitsFor(_)))
        .collect()
}

#[test]
fn the_waiting_rules_are_the_operations_block_three_governance_and_two_security_rules() {
    let mut ids: Vec<&str> = waiting_rules().iter().map(|r| r.id).collect();
    ids.sort_unstable();
    let mut expected: Vec<&str> = WAITING.iter().map(|(id, _)| *id).collect();
    expected.sort_unstable();
    assert_eq!(ids, expected);
    for rule in REGISTRY.iter().filter(|r| r.block == Block::Operations) {
        assert!(
            matches!(rule.feasible_by, Milestone::WaitsFor(_)),
            "{} evaluates before its module lands",
            rule.id
        );
    }
}

#[test]
fn every_waiting_rule_is_unavailable_naming_its_module_and_never_failed() {
    // Every read fails and every file is present: nothing a waiting rule could
    // read changes its outcome.
    let audit = run_with(
        &FakeHost::failing(&unsupported("any read")),
        &[(".github/CODEOWNERS", "* @acme\n")],
    );
    for (id, module) in WAITING {
        let rule = REGISTRY.iter().find(|r| r.id == *id).unwrap();
        assert_eq!(rule.feasible_by, Milestone::WaitsFor(module), "{id}");
        assert_eq!(rule.remediation, Remediation::Module { id: module }, "{id}");
        let o = outcome(&audit, id);
        unavailable(&o, &format!("waits for module {module}"));
        assert!(o.evidence.is_empty(), "{id}");
    }
}

#[test]
fn a_level_blocked_only_by_waiting_rules_is_unverified_never_failed() {
    static OPERATIONS: &[Rule] = &[
        operations::POST_DEPLOY_SMOKE,
        operations::ROLLBACK_EVIDENCE,
        operations::UPTIME_FOOTPRINT,
        operations::INCIDENTS_BOUNDED,
        operations::RUNBOOK_PER_ALERT,
        operations::SLO_BURN_RATE_VALIDATED,
        operations::BACKUP_AGE_WITHIN_RPO,
        operations::RESTORE_DRILL_FRESH,
    ];
    let host = FakeHost::default();
    let dir = tempfile::tempdir().unwrap();
    let local = LocalFiles::new(dir.path());
    let repo = RepoId::parse("acme/shop").unwrap();
    let cx = Cx {
        host: &host,
        files: &local,
        repo: &repo,
        default_branch: "main",
        now: now(),
        budget: &host.budget,
        profile: Profile::P1,
        today: None,
    };
    let audit = evaluate(&cx, &dims(Profile::P1), OPERATIONS);
    assert_eq!(audit.reached, Some(Level::Bronze));
    assert_eq!(audit.unverified_from, Some(Level::Silver));
    assert_eq!(audit.exit_code(true, Level::Gold), 4);
    // Called directly, outside `evaluate`, a waiting rule still never fails.
    for rule in OPERATIONS {
        assert_eq!(
            (rule.evaluate)(&cx).status,
            Status::Unavailable,
            "{}",
            rule.id
        );
    }
    assert_eq!(host.calls.borrow().len(), 0, "a waiting rule reads nothing");
}

#[test]
fn oversizing_is_required_only_on_platform_ladder_l4_which_nothing_measures_yet() {
    let rule = REGISTRY
        .iter()
        .find(|r| r.id == "governance.no-persistent-oversizing")
        .unwrap();
    assert_eq!(rule.required.profiles, &[] as &[Profile]);
    assert_eq!(rule.required.when, &[Condition::PlatformLadderL4]);
    for profile in [Profile::P1, Profile::P2, Profile::P3] {
        assert!(!dims(profile).requires(rule), "{profile:?}");
    }
}

// --- governance: rules over local files (#728) ----------------------------------------

/// Audits `rules` over a checkout holding `files` (path → text; a path ending
/// in `/` is created as a directory, so reading it fails) at `profile`.
fn gov_as(files: &[(&str, &str)], profile: Profile, rules: &'static [Rule]) -> Audit {
    let host = FakeHost::default();
    let dir = tempfile::tempdir().unwrap();
    for (path, text) in files {
        let full = dir.path().join(path);
        if path.ends_with('/') {
            fs::create_dir_all(&full).unwrap();
        } else {
            fs::create_dir_all(full.parent().unwrap()).unwrap();
            fs::write(full, text).unwrap();
        }
    }
    let local = LocalFiles::new(dir.path());
    let repo = RepoId::parse("acme/shop").unwrap();
    let cx = Cx {
        host: &host,
        files: &local,
        repo: &repo,
        default_branch: "main",
        now: now(),
        budget: &host.budget,
        profile,
        today: None,
    };
    let audit = evaluate(&cx, &dims(profile), rules);
    assert_eq!(
        host.calls.borrow().len(),
        0,
        "local-file rules spend no call"
    );
    audit
}
fn gov(files: &[(&str, &str)], rules: &'static [Rule]) -> Audit {
    gov_as(files, Profile::P1, rules)
}
fn evaluated<'a>(audit: &'a Audit, id: &str) -> &'a brakes::auditor::Evaluated {
    audit.rules.iter().find(|e| e.rule.id == id).unwrap()
}

static COOLDOWN: &[Rule] = &[governance::DEPENDENCY_UPDATES_WITH_COOLDOWN];
const COOLDOWN_ID: &str = "governance.dependency-updates-with-cooldown";
const DEPENDABOT_OK: &str = "version: 2\nupdates:\n  - package-ecosystem: cargo\n    directory: /\n    schedule:\n      interval: weekly\n    cooldown:\n      default-days: 7\n  - package-ecosystem: github-actions\n    directory: /\n    schedule:\n      interval: weekly\n    cooldown:\n      default-days: 7\n";

#[test]
fn dependabot_with_a_cooldown_on_every_entry_passes() {
    let audit = gov(&[(".github/dependabot.yml", DEPENDABOT_OK)], COOLDOWN);
    passed(
        &outcome(&audit, COOLDOWN_ID),
        &[".github/dependabot.yml: cooldown on every update (cargo /, github-actions /)"],
    );
}

#[test]
fn renovate_with_a_minimum_release_age_passes() {
    let audit = gov(
        &[(
            "renovate.json",
            r#"{"extends": ["config:recommended"], "minimumReleaseAge": "7 days"}"#,
        )],
        COOLDOWN,
    );
    passed(
        &outcome(&audit, COOLDOWN_ID),
        &["renovate.json: minimumReleaseAge 7 days"],
    );
}

#[test]
fn a_dependabot_entry_without_cooldown_fails_naming_it() {
    let text = "version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /web\n    schedule:\n      interval: daily\n  - package-ecosystem: cargo\n    directory: /\n    cooldown:\n      default-days: 0\n";
    let audit = gov(&[(".github/dependabot.yml", text)], COOLDOWN);
    let e = evaluated(&audit, COOLDOWN_ID);
    failed(
        &e.outcome,
        &[
            ".github/dependabot.yml: update npm /web has no cooldown",
            ".github/dependabot.yml: update cargo / has no cooldown",
        ],
    );
    assert_eq!(
        e.rule.remediation,
        Remediation::Module {
            id: "repo-baseline"
        }
    );
}

#[test]
fn no_dependency_update_tool_fails_and_renovate_without_age_fails() {
    failed(
        &outcome(&gov(&[], COOLDOWN), COOLDOWN_ID),
        &["neither .github/dependabot.yml nor renovate.json configures dependency updates"],
    );
    failed(
        &outcome(&gov(&[("renovate.json", "{}")], COOLDOWN), COOLDOWN_ID),
        &["renovate.json declares no minimumReleaseAge"],
    );
    failed(
        &outcome(
            &gov(&[(".github/dependabot.yml", "updates: [")], COOLDOWN),
            COOLDOWN_ID,
        ),
        &[".github/dependabot.yml is not valid YAML"],
    );
}

#[test]
fn either_tool_with_a_cooldown_passes_next_to_one_without() {
    let audit = gov(
        &[
            (".github/dependabot.yml", "version: 2\nupdates: []\n"),
            ("renovate.json", r#"{"minimumReleaseAge": "3 days"}"#),
        ],
        COOLDOWN,
    );
    passed(
        &outcome(&audit, COOLDOWN_ID),
        &["renovate.json: minimumReleaseAge 3 days"],
    );
}

#[test]
fn an_unreadable_dependabot_file_is_unavailable() {
    let o = outcome(
        &gov(&[(".github/dependabot.yml/", "")], COOLDOWN),
        COOLDOWN_ID,
    );
    assert_eq!(o.status, Status::Unavailable, "{o:?}");
    assert!(
        o.reason
            .as_deref()
            .unwrap()
            .starts_with(".github/dependabot.yml unreadable: "),
        "{o:?}"
    );
}

static SERVICE_CARD: &[Rule] = &[governance::SERVICE_CARD_OWNER];
const CARD_ID: &str = "governance.service-card-owner";

#[test]
fn the_seeded_service_card_with_an_owner_passes() {
    let audit = gov(
        &[(
            ".agent-setup/service.yaml",
            "name: acme/shop\nowner: acme-team   # GitHub login or team\ntier: 3\n",
        )],
        SERVICE_CARD,
    );
    passed(
        &outcome(&audit, CARD_ID),
        &["owner acme-team in .agent-setup/service.yaml"],
    );
}

#[test]
fn a_backstage_catalog_info_owner_passes() {
    let text = "apiVersion: backstage.io/v1alpha1\nkind: Component\nmetadata:\n  name: shop\nspec:\n  owner: group:payments\n";
    passed(
        &outcome(&gov(&[("catalog-info.yaml", text)], SERVICE_CARD), CARD_ID),
        &["owner group:payments in catalog-info.yaml"],
    );
}

#[test]
fn a_card_without_owner_or_with_unknown_fails_and_none_fails() {
    let audit = gov(
        &[
            (
                ".agent-setup/service.yaml",
                "name: acme/shop\nowner: unknown\n",
            ),
            ("service.yaml", "name: shop\nowner: \"  \"\n"),
        ],
        SERVICE_CARD,
    );
    let e = evaluated(&audit, CARD_ID);
    failed(
        &e.outcome,
        &[
            ".agent-setup/service.yaml: owner is unknown",
            "service.yaml: owner is empty",
        ],
    );
    assert_eq!(
        e.rule.remediation,
        Remediation::Module {
            id: "repo-baseline"
        }
    );
    failed(
        &outcome(&gov(&[], SERVICE_CARD), CARD_ID),
        &["no service card: .agent-setup/service.yaml, service.yaml or catalog-info.yaml"],
    );
}

#[test]
fn an_unreadable_service_card_is_unavailable() {
    let o = outcome(&gov(&[("service.yaml/", "")], SERVICE_CARD), CARD_ID);
    assert_eq!(o.status, Status::Unavailable, "{o:?}");
    assert!(
        o.reason
            .as_deref()
            .unwrap()
            .starts_with("service.yaml unreadable: ")
    );
}

static CODEOWNERS: &[Rule] = &[governance::CODEOWNERS_PRESENT];
const CODEOWNERS_ID: &str = "governance.codeowners-present";

#[test]
fn codeowners_is_required_at_p2_and_p3_never_at_p1() {
    let rule = &governance::CODEOWNERS_PRESENT;
    assert!(!dims(Profile::P1).requires(rule));
    assert!(dims(Profile::P2).requires(rule));
    assert!(dims(Profile::P3).requires(rule));
    // Evaluated and reported at P1 too, so the owner sees what P2 would ask.
    let p1 = gov_as(&[], Profile::P1, CODEOWNERS);
    assert!(!evaluated(&p1, CODEOWNERS_ID).required);
    assert_eq!(
        p1.reached,
        Some(Level::Gold),
        "a rule not required blocks nothing"
    );
    let p2 = gov_as(&[], Profile::P2, CODEOWNERS);
    assert!(evaluated(&p2, CODEOWNERS_ID).required);
    assert_eq!(p2.reached, Some(Level::Basic));
}

#[test]
fn codeowners_in_the_first_location_github_reads_passes_counting_rules() {
    let audit = gov(
        &[
            (
                ".github/CODEOWNERS",
                "# owners\n\n* @acme/devs\n/docs/ @acme/writers\n",
            ),
            ("CODEOWNERS", "* @someone-else\n"),
        ],
        CODEOWNERS,
    );
    passed(
        &outcome(&audit, CODEOWNERS_ID),
        &[".github/CODEOWNERS: 2 ownership rules"],
    );
    passed(
        &outcome(
            &gov(&[("docs/CODEOWNERS", "* @acme\n")], CODEOWNERS),
            CODEOWNERS_ID,
        ),
        &["docs/CODEOWNERS: 1 ownership rule"],
    );
}

#[test]
fn missing_or_empty_codeowners_fails_and_unreadable_is_unavailable() {
    failed(
        &outcome(&gov(&[], CODEOWNERS), CODEOWNERS_ID),
        &["no CODEOWNERS in .github/, the root or docs/"],
    );
    failed(
        &outcome(
            &gov(&[("CODEOWNERS", "# nobody yet\n")], CODEOWNERS),
            CODEOWNERS_ID,
        ),
        &["CODEOWNERS has no ownership rule"],
    );
    let o = outcome(
        &gov(&[(".github/CODEOWNERS/", "")], CODEOWNERS),
        CODEOWNERS_ID,
    );
    assert_eq!(o.status, Status::Unavailable, "{o:?}");
}

static TEMPLATES: &[Rule] = &[governance::PR_TEMPLATE_AND_ISSUE_FORMS];
const TEMPLATES_ID: &str = "governance.pr-template-and-issue-forms";
const FORM: &str = "name: Task\ndescription: x\nbody:\n  - type: textarea\n    id: goal\n    attributes:\n      label: Goal\n";

#[test]
fn a_pr_template_and_issue_forms_pass() {
    let audit = gov(
        &[
            (".github/pull_request_template.md", "Summary (one line):\n"),
            (".github/ISSUE_TEMPLATE/task.yml", FORM),
            (".github/ISSUE_TEMPLATE/incident.yaml", FORM),
            (
                ".github/ISSUE_TEMPLATE/config.yml",
                "blank_issues_enabled: false\n",
            ),
        ],
        TEMPLATES,
    );
    passed(
        &outcome(&audit, TEMPLATES_ID),
        &[
            "pull request template .github/pull_request_template.md",
            "issue forms: .github/ISSUE_TEMPLATE/incident.yaml, .github/ISSUE_TEMPLATE/task.yml",
        ],
    );
}

#[test]
fn markdown_issue_templates_are_not_forms_and_a_missing_pr_template_fails() {
    let audit = gov(
        &[
            ("docs/pull_request_template.md", "x\n"),
            (".github/ISSUE_TEMPLATE/bug.md", "---\nname: Bug\n---\n"),
            (
                ".github/ISSUE_TEMPLATE/config.yml",
                "blank_issues_enabled: false\n",
            ),
        ],
        TEMPLATES,
    );
    let e = evaluated(&audit, TEMPLATES_ID);
    failed(
        &e.outcome,
        &["no issue form (.yml) under .github/ISSUE_TEMPLATE"],
    );
    assert_eq!(
        e.rule.remediation,
        Remediation::Module {
            id: "repo-baseline"
        }
    );
    failed(
        &outcome(&gov(&[], TEMPLATES), TEMPLATES_ID),
        &[
            "no pull request template in .github/, the root or docs/",
            "no issue form (.yml) under .github/ISSUE_TEMPLATE",
        ],
    );
}

#[test]
fn an_unreadable_pr_template_is_unavailable() {
    let o = outcome(
        &gov(&[(".github/pull_request_template.md/", "")], TEMPLATES),
        TEMPLATES_ID,
    );
    assert_eq!(o.status, Status::Unavailable, "{o:?}");
}

// --- governance.no-expired-bypass ------------------------------------------------------

static BYPASS: &[Rule] = &[governance::NO_EXPIRED_BYPASS];
const BYPASS_ID: &str = "governance.no-expired-bypass";

fn inventory(entries: &[(&str, Option<&str>)]) -> String {
    let exceptions: Vec<serde_json::Value> = entries
        .iter()
        .map(|(id, expires)| {
            serde_json::json!({
                "id": id, "kind": "ruleset-bypass-actor", "target": "RepositoryRole:admin",
                "reason": "x", "issue": "#1", "owner": "acme", "created": "2026-10-01",
                "expires": expires,
            })
        })
        .collect();
    serde_json::json!({"schema": 1, "exceptions": exceptions}).to_string()
}

#[test]
fn bypasses_active_through_today_pass() {
    let text = inventory(&[
        ("owner-bypass", Some("2027-02-01")),
        ("hotfix", Some("2026-10-28")),
    ]);
    let audit = gov(&[(INVENTORY, &text)], BYPASS);
    passed(
        &outcome(&audit, BYPASS_ID),
        &[
            "exception owner-bypass active until 2027-02-01",
            "exception hotfix active until 2026-10-28",
        ],
    );
}

#[test]
fn an_expired_or_undated_bypass_fails_at_silver() {
    let text = inventory(&[
        ("old", Some("2026-10-27")),
        ("undated", None),
        ("typo", Some("2026-13-01")),
        ("fine", Some("2027-01-01")),
    ]);
    let audit = gov(&[(INVENTORY, &text)], BYPASS);
    let e = evaluated(&audit, BYPASS_ID);
    failed(
        &e.outcome,
        &[
            "exception old expired on 2026-10-27",
            "exception undated has no expires",
            "exception typo has an invalid expires date 2026-13-01",
        ],
    );
    assert_eq!(e.rule.level, Level::Silver);
    assert!(matches!(
        e.rule.remediation,
        Remediation::Manual {
            step: "renew-or-remove-bypass",
            ..
        }
    ));
    assert_eq!(audit.reached, Some(Level::Bronze));
}

#[test]
fn no_inventory_is_not_required_and_a_broken_one_fails_or_is_unavailable() {
    not_required(
        &outcome(&gov(&[], BYPASS), BYPASS_ID),
        "no bypass registered: .agent-setup/security-exceptions.json absent",
    );
    failed(
        &outcome(&gov(&[(INVENTORY, "[]")], BYPASS), BYPASS_ID),
        &[".agent-setup/security-exceptions.json does not parse as the bypass inventory"],
    );
    let o = outcome(
        &gov(&[(".agent-setup/security-exceptions.json/", "")], BYPASS),
        BYPASS_ID,
    );
    assert_eq!(o.status, Status::Unavailable, "{o:?}");
}

// --- governance.adr-state-known ---------------------------------------------------------

static ADR: &[Rule] = &[governance::ADR_STATE_KNOWN];
const ADR_ID: &str = "governance.adr-state-known";
const ADR_PROFILE: &str = r#"{"conventions": [
    {"path": "docs/design.md", "adr": "docs/decisions.md#one--accepted-2026-10-10"},
    {"path": "docs/api.md", "adr": "docs/decisions.md#two"},
    "docs/sources.md"
]}"#;

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "lists setup-core or its guides; product-boundary T7a"
)]
#[test]
fn decision_headings_with_a_known_state_pass() {
    let decisions = "# Decisions\n\nIntro.\n\n## One — accepted, 2026-10-10\n\n### Context\n\n## Two — Superseded by One, 2026-10-11\n\n## Three — proposed\n\n## Four — rejected, 2026-10-12\n\n## Five — deprecated, 2026-10-13\n";
    let audit = gov(
        &[
            (".agent-setup/project.json", ADR_PROFILE),
            ("docs/decisions.md", decisions),
        ],
        ADR,
    );
    passed(
        &outcome(&audit, ADR_ID),
        &["docs/decisions.md: 5 decision headings, each with a known state"],
    );
}

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "lists setup-core or its guides; product-boundary T7a"
)]
#[test]
fn a_heading_without_a_state_or_with_an_unknown_one_fails() {
    let decisions =
        "# Decisions\n\n## One — accepted, 2026-10-10\n\n## Two — owner, 2026-10-28\n\n## Notes\n";
    let audit = gov(
        &[
            (".agent-setup/project.json", ADR_PROFILE),
            ("docs/decisions.md", decisions),
        ],
        ADR,
    );
    let e = evaluated(&audit, ADR_ID);
    failed(
        &e.outcome,
        &[
            "docs/decisions.md: \"Two\" has the unknown state \"owner, 2026-10-28\"",
            "docs/decisions.md: \"Notes\" has no state",
        ],
    );
    assert_eq!(e.rule.level, Level::Gold);
}

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "lists setup-core or its guides; product-boundary T7a"
)]
#[test]
fn more_than_ten_unknown_headings_are_summarised() {
    let decisions: String = (1..=12).map(|i| format!("## D{i}\n\n")).collect();
    let audit = gov(
        &[
            (".agent-setup/project.json", ADR_PROFILE),
            ("docs/decisions.md", &decisions),
        ],
        ADR,
    );
    let o = outcome(&audit, ADR_ID);
    assert_eq!(o.status, Status::Failed);
    assert_eq!(o.evidence.len(), 11, "{o:?}");
    assert_eq!(
        o.evidence[10],
        "and 2 more decision headings without a known state"
    );
}

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "lists setup-core or its guides; product-boundary T7a"
)]
#[test]
fn without_a_declared_decision_file_adr_state_is_not_required() {
    not_required(
        &outcome(
            &gov(
                &[(
                    ".agent-setup/project.json",
                    r#"{"conventions": ["docs/a.md"]}"#,
                )],
                ADR,
            ),
            ADR_ID,
        ),
        "no decision file declared in .agent-setup/project.json conventions",
    );
    not_required(
        &outcome(&gov(&[], ADR), ADR_ID),
        "no decision file declared in .agent-setup/project.json conventions",
    );
}

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "lists setup-core or its guides; product-boundary T7a"
)]
#[test]
fn a_declared_decision_file_missing_fails_and_unreadable_is_unavailable() {
    failed(
        &outcome(
            &gov(&[(".agent-setup/project.json", ADR_PROFILE)], ADR),
            ADR_ID,
        ),
        &["docs/decisions.md, declared in .agent-setup/project.json conventions, does not exist"],
    );
    let o = outcome(
        &gov(
            &[
                (".agent-setup/project.json", ADR_PROFILE),
                ("docs/decisions.md/", ""),
            ],
            ADR,
        ),
        ADR_ID,
    );
    assert_eq!(o.status, Status::Unavailable, "{o:?}");
}

// --- governance.postmortem-actions-closed -------------------------------------------------

static POSTMORTEM: &[Rule] = &[governance::POSTMORTEM_ACTIONS_CLOSED];
const POSTMORTEM_ID: &str = "governance.postmortem-actions-closed";
const ACTIONS_PATH: &str =
    "repos/acme/shop/issues?state=open&labels=type%3Apost-mortem-action&per_page=100&page=1";

/// Audits the post-mortem rule over GitHub answering `reply` (a recorded
/// shape: `{"status": 200, "body": [...]}`) at `ACTIONS_PATH`.
fn postmortem(reply: serde_json::Value, budget: u32) -> (Audit, u32) {
    let mut replies = serde_json::Map::new();
    replies.insert(ACTIONS_PATH.to_owned(), reply);
    let replay = Replay {
        replies,
        gets: RefCell::default(),
    };
    let host = brakes::host::github::GitHub::new(&replay, CallBudget::new(budget));
    let repo = RepoId::parse("acme/shop").unwrap();
    let dir = tempfile::tempdir().unwrap();
    let local = LocalFiles::new(dir.path());
    let cx = Cx {
        host: &host,
        files: &local,
        repo: &repo,
        default_branch: "main",
        now: now(),
        budget: host.budget(),
        profile: Profile::P1,
        today: None,
    };
    let audit = evaluate(&cx, &dims(Profile::P1), POSTMORTEM);
    (audit, host.budget().used())
}
fn action(number: u64, body: Option<&str>) -> serde_json::Value {
    serde_json::json!({
        "number": number, "title": format!("Action {number}"), "state": "open",
        "labels": [{"name": "type:post-mortem-action"}], "body": body,
    })
}

#[test]
fn open_actions_not_yet_due_pass_in_one_call() {
    let (audit, calls) = postmortem(
        serde_json::json!({"status": 200, "body": [
            action(12, Some("### Post-mortem\n\nhttps://x\n\n### Due date\n\n2026-10-28\n\n### Converted into\n\nalert")),
            action(13, Some("Follow-up.\n\ndue: 2026-11-30\n")),
        ]}),
        60,
    );
    passed(
        &outcome(&audit, POSTMORTEM_ID),
        &["2 open post-mortem actions, none past its due date"],
    );
    assert_eq!(calls, 1);
}

#[test]
fn an_action_past_its_due_date_or_without_one_fails() {
    let (audit, _) = postmortem(
        serde_json::json!({"status": 200, "body": [
            action(12, Some("### Due date\n\n2026-10-27\n")),
            action(14, Some("### Due date\n\n_No response_\n")),
            action(15, None),
            action(16, Some("### Due date\n\n2026-12-01\n")),
        ]}),
        60,
    );
    let e = evaluated(&audit, POSTMORTEM_ID);
    failed(
        &e.outcome,
        &[
            "#12 \"Action 12\" was due on 2026-10-27",
            "#14 \"Action 14\" has no due date",
            "#15 \"Action 15\" has no due date",
        ],
    );
    assert_eq!(e.rule.level, Level::Gold);
}

#[test]
fn unreadable_actions_and_an_exhausted_budget_are_unavailable() {
    let (audit, _) = postmortem(
        serde_json::json!({"status": 403, "message": "Resource not accessible by integration"}),
        60,
    );
    let o = outcome(&audit, POSTMORTEM_ID);
    assert_eq!(o.status, Status::Unavailable, "{o:?}");
    assert!(
        o.reason.as_deref().unwrap().contains("issues of acme/shop"),
        "{o:?}"
    );
    let (audit, calls) = postmortem(serde_json::json!({"status": 200, "body": []}), 0);
    let o = outcome(&audit, POSTMORTEM_ID);
    assert_eq!(o.status, Status::Unavailable, "{o:?}");
    assert!(
        o.reason
            .as_deref()
            .unwrap()
            .starts_with("budget exhausted: "),
        "{o:?}"
    );
    assert_eq!(calls, 0);
}

#[test]
fn a_hundred_open_actions_none_overdue_is_unavailable() {
    let body: Vec<serde_json::Value> = (1..=100)
        .map(|n| action(n, Some("### Due date\n\n2027-01-01\n")))
        .collect();
    let (audit, _) = postmortem(serde_json::json!({"status": 200, "body": body}), 60);
    unavailable(
        &outcome(&audit, POSTMORTEM_ID),
        "100 open post-mortem actions or more; the first 100 are not past their due date",
    );
}

#[test]
fn example_app_recorded_postmortem_actions() {
    let (audit, calls) = recorded("governance/example-app", &[], POSTMORTEM);
    passed(
        &outcome(&audit, POSTMORTEM_ID),
        &["no open type:post-mortem-action issue"],
    );
    assert_eq!(calls, 1);
}

#[test]
fn formal_approval_and_ownership_are_never_required_at_p1_and_always_at_p2() {
    for id in [
        "posture.human-approval-required",
        "posture.codeowners-review",
        "governance.codeowners-present",
    ] {
        let rule = REGISTRY
            .iter()
            .find(|r| r.id == id)
            .unwrap_or_else(|| panic!("{id} not in the registry"));
        assert!(!dims(Profile::P1).requires(rule), "{id} at P1");
        assert!(dims(Profile::P2).requires(rule), "{id} at P2");
    }
}

// --- block allowances (#920) --------------------------------------------------------

#[test]
fn the_allowances_name_registry_rules_and_sum_per_block_as_specified() {
    for (id, _) in ALLOWANCES {
        assert!(
            REGISTRY.iter().any(|r| r.id == *id),
            "{id} not in the registry"
        );
    }
    let block = |b: Block| -> u32 {
        REGISTRY
            .iter()
            .filter(|r| r.block == b)
            .map(|r| allowance(r.id))
            .sum()
    };
    // SPEC-auditor.md, "Block allowances", in report order.
    assert_eq!(
        [
            Block::Baseline,
            Block::Posture,
            Block::CiHealth,
            Block::Dora,
            Block::Operations,
            Block::Governance,
            Block::Ci,
            Block::Security,
            Block::Stack,
            Block::Agents,
            Block::Qa,
        ]
        .map(block),
        [0, 12, 7, 7, 0, 1, 7, 0, 0, 0, 0]
    );
    let total: u32 = REGISTRY.iter().map(|r| allowance(r.id)).sum();
    assert!(total <= CALL_BUDGET, "{total} > {CALL_BUDGET}");
}

/// SPEC-auditor.md, "Fleet file reads" (#935): under `--fleet` governance
/// adds the files its rules read through the contents API, and baseline the
/// lock (#1318: the measures read only the profile, so seven baseline rules
/// found the lock unreadable on the live fleet run); the sum stays within the fleet
/// budget.
#[test]
fn the_fleet_allowances_add_the_governance_file_reads_and_the_lock() {
    for (id, _) in FLEET_FILE_READS {
        let rule = REGISTRY.iter().find(|r| r.id == *id);
        assert!(
            rule.is_some_and(|r| r.block == Block::Governance || r.block == Block::Baseline),
            "{id} is not a governance or baseline rule of the registry"
        );
    }
    // The lock's call sits on the first baseline rule, so it passes on to the
    // first that reads the lock whichever features are built.
    assert_eq!(REGISTRY[0].id, "baseline.purpose-declared");
    assert_eq!(fleet_allowance("baseline.purpose-declared"), 1);
    let block = |b: Block| -> u32 {
        REGISTRY
            .iter()
            .filter(|r| r.block == b)
            .map(|r| fleet_allowance(r.id))
            .sum()
    };
    assert_eq!(
        [
            Block::Baseline,
            Block::Posture,
            Block::CiHealth,
            Block::Dora,
            Block::Operations,
            Block::Governance,
            Block::Ci,
            Block::Security,
            Block::Stack,
            Block::Agents,
            Block::Qa,
        ]
        .map(block),
        // ci keeps its 7 (#783): minutes-month reads under --fleet too, and
        // workflow-lint's call is held though its static half is not-required.
        [1, 12, 7, 7, 0, 16, 7, 0, 0, 0, 0]
    );
    let total: u32 = REGISTRY.iter().map(|r| fleet_allowance(r.id)).sum();
    assert_eq!(total, 50);
    // The measures read first from what the allowances leave: 7 to 24 calls on
    // the repositories of the live fleet run (#1318: the profile, the collaborators, a
    // page per 100 pull requests closed in 56 days, the workflows one by one,
    // the Dockerfile, the environments), more than the 9 that 60 leaves.
    const MEASURES_RECORDED: u32 = 24;
    assert!(total + MEASURES_RECORDED > CALL_BUDGET);
    assert!(total + MEASURES_RECORDED <= FLEET_CALL_BUDGET);
}

#[test]
fn a_held_back_call_is_refused_naming_what_is_held() {
    let budget = CallBudget::new(3);
    budget.hold(2);
    budget.spend().unwrap();
    let refused = budget.spend().unwrap_err();
    assert_eq!(refused.message, "call budget of 3 exhausted, 2 held back");
    assert!(matches!(refused.kind, HostErrorKind::RateLimited { .. }));
    assert!(budget.refused());
    assert_eq!(budget.used(), 1);
    budget.hold(0);
    budget.spend().unwrap();
    assert_eq!(budget.used(), 2);
}

/// The worst case: the whole registry over the example-app fixtures after 28
/// calls already spent (what the measures may spend while the 38 calls of the
/// allowances, the counters' 6 included (#983), stay held back). Without allowances ci-health would spend 32 of
/// the 32 left and DORA, governance and ci would report `budget exhausted`;
/// with them every block reports a verdict, ci-health, DORA and ci over
/// smaller samples.
/// The remote `security.*` rules (#801) have no allowance by design: last in
/// report order, they read only what is left, and say so rather than take
/// from the blocks before them.
#[test]
fn every_block_reports_a_verdict_within_60_calls_in_the_worst_case() {
    let example_app_ci = fs::read_to_string(format!(
        "{}/tests/fixtures/ci-baseline/monorepo-ci.yml",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    // Not recorded for example-org/example-app: no open post-mortem action, as the
    // governance fixture records, so governance has its one read answered.
    let actions = (
        "repos/example-org/example-app/issues?state=open&labels=type%3Apost-mortem-action&per_page=100&page=1",
        serde_json::json!({"status": 200, "body": []}),
    );
    // Not recorded either: the 30-day listing ci.minutes-month reads (#783),
    // the recorded push listing re-keyed, every run of it inside the window.
    let fixture: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(format!(
            "{}/tests/fixtures/auditor/ci-health/example-app.json",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
    .unwrap();
    let month = (
        "repos/example-org/example-app/actions/runs?status=completed&created=%3E%3D2026-09-28&per_page=100&page=1",
        fixture["replies"]["repos/example-org/example-app/actions/runs?branch=main&event=push&status=completed&per_page=100&page=1"].clone(),
    );
    let recorded_answers = r#"{"module": "ci-baseline", "version": "1.0.0", "answers": {"workflow": "existing", "aggregate_check": "all-checks-passed"}}"#;
    // Not recorded either: the collaborators (the measures read them first in
    // a real audit, so the rule reads them from the cache there) and the
    // organization's owners `posture.repo-admins-are-owners` reads (#1218).
    let collaborators = (
        "repos/example-org/example-app/collaborators?per_page=100&page=1",
        serde_json::json!({"status": 200, "body": [
            {"login": "owner-one", "type": "User", "role_name": "admin"}
        ]}),
    );
    let owners = (
        "orgs/example-org/members?role=admin&per_page=100&page=1",
        serde_json::json!({"status": 200, "body": [{"login": "owner-one"}]}),
    );
    // The counters' pull listing and files from their own recording, listed
    // before ci-health so its runs listing stays the one recorded there.
    let (audit, counters, calls) = recorded_counted(
        &[
            "posture/example-app",
            "counters/example-app",
            "ci-health/example-app",
            "dora/example-app",
        ],
        &[actions, month, collaborators, owners],
        &[
            (".github/workflows/ci.yml", &example_app_ci),
            (".agent-setup/project.json", EXAMPLE_APP_PROJECT),
            (".agent-setup/modules/ci-baseline.json", recorded_answers),
        ],
        REGISTRY,
        20,
    );
    // The counters read last, with their 6 and what the rules left: the one
    // call the rules left before #801 now goes to the security block's
    // repository read (a rule, read before the counters), so three judged pull
    // requests, `CORRECTIONS_MIN`, settle the corrections over their own 6
    // calls; the runs recorded on 2026-10-28 name no merged pull request of
    // the newer listing.
    assert_eq!(calls, 60);
    let corrections = &counters.post_merge_corrections;
    assert_eq!(corrections.value, Some(100.0));
    assert_eq!(
        corrections.evidence[0],
        "judged 3 of 190 merged 2026-08-31..2026-09-28; files read for 5 of 310 followers"
    );
    assert_eq!(
        counters.cost_per_change.reason.as_deref(),
        Some(
            "measured 0 of 338 merged 2026-09-30..2026-10-28: none has a pull_request run among the latest 100 workflow runs"
        )
    );
    // The remote reads of the security block (#801), which hold no allowance.
    const LEFTOVER_READERS: [&str; 3] = [
        "security.secret-scanning",
        "security.private-vulnerability-reporting",
        "security.scanner-stale",
    ];
    for e in &audit.rules {
        let reason = e.outcome.reason.as_deref().unwrap_or_default();
        if LEFTOVER_READERS.contains(&e.rule.id) {
            continue;
        }
        assert!(
            !reason.starts_with("budget exhausted"),
            "{}: {reason}",
            e.rule.id
        );
    }
    // The one call left reads the repository, recorded on example-app without its
    // `id`: both rules that need it say so, from one read; nothing pins a scanner.
    assert_eq!(calls, 60);
    for id in &LEFTOVER_READERS[..2] {
        unavailable(
            &outcome(&audit, id),
            "repository example-org/example-app has an unexpected shape: missing number field id",
        );
    }
    not_required(
        &outcome(&audit, "security.scanner-stale"),
        "no workflow pins a scanner by checksum or digest",
    );
    for id in [
        "posture.default-branch-protected",
        "posture.org-2fa-required",
        "ci-health.workflow-exists",
        "ci-health.rerun-rate",
        "dora.deployments-api-in-use",
        "dora.deployment-frequency",
        "governance.postmortem-actions-closed",
    ] {
        assert_ne!(outcome(&audit, id).status, Status::Unavailable, "{id}");
    }
    passed(
        &outcome(&audit, "ci-health.minutes-budget"),
        &[
            "median 5.2 min from run creation to job all-checks-passed over 5 first-attempt push runs of CI on main (a sample: the call budget stopped it at 5 of 20 runs) ≤ the cycle budget of 20 min",
            "CI minutes this month (a sample, not billing): 120.5 min, the wall-clock of 100 of 100 completed runs created this month among the latest 100 listed, from run start to last update",
        ],
    );
    passed(
        &outcome(&audit, "dora.lead-time"),
        &[
            "median 0.2 h from merge to successful deployment over 1 of the newest 3 of 10 production deployments in the 28 days to 2026-10-28 (a sample: the call budget stopped it at 1 of 3 deployments) ≤ 7 days",
        ],
    );
    passed(
        &outcome(&audit, "dora.change-failure-rate"),
        &[
            "0 of the newest 4 of 10 production deployments in the 28 days to 2026-10-28 failed or rolled back (0.0 %) ≤ 15 % (a sample: the call budget stopped it at 4 of 8)",
        ],
    );
    // ci-baseline's remote rules (#783): the two cached ones answer from
    // posture's and ci-health's reads; the minutes read their whole sample
    // from what the earlier blocks left.
    passed(
        &outcome(&audit, "ci.required-is-aggregate"),
        &["main requires only all-checks-passed"],
    );
    passed(
        &outcome(&audit, "ci.main-red"),
        &["the latest conclusive push run of CI on main, run 40862628372, succeeded"],
    );
    passed(
        &outcome(&audit, "ci.minutes-month"),
        &[
            "Billed about 100 minutes in 30 days; budget 2000",
            "the jobs of 10 of 100 completed runs since 2026-09-28, each rounded up to the minute, extrapolated to the 100 listed; earlier runs of the window are not counted",
        ],
    );
}

// --- counters (#983): post_merge_corrections and cost_per_change -------------------

/// A pull request into main by `author`, merged at `merged_at`.
fn merged_by(number: u64, merged_at: &str, author: &str) -> PullMeta {
    PullMeta {
        number,
        title: format!("pull request {number}"),
        state: "closed".to_owned(),
        head_sha: format!("{number:040x}"),
        base: "main".to_owned(),
        author: Some(author.to_owned()),
        draft: Some(false),
        created_at: None,
        merged_at: Some(merged_at.to_owned()),
        closed_at: Some(merged_at.to_owned()),
        merge_commit_sha: None,
    }
}
fn merged_pr(number: u64, merged_at: &str) -> PullMeta {
    merged_by(number, merged_at, "example-owner")
}
fn touched(names: &[&str]) -> R<Vec<PullFile>> {
    Ok(names
        .iter()
        .map(|name| PullFile {
            filename: (*name).to_owned(),
            status: "modified".to_owned(),
            previous_filename: None,
        })
        .collect())
}
/// The counters of `host` over an empty checkout, as `--remote` reads them.
fn counted(host: &FakeHost, remote: bool) -> Counters {
    let dir = tempfile::tempdir().unwrap();
    let local = LocalFiles::new(dir.path());
    let repo = RepoId::parse("acme/shop").unwrap();
    let cx = Cx {
        host,
        files: &local,
        repo: &repo,
        default_branch: "main",
        now: now(),
        budget: &host.budget,
        profile: Profile::P1,
        today: None,
    };
    counters::count(&cx, remote)
}
/// Six pages of closed pull requests since 2026-09-01 and the latest runs.
const EXAMPLE_APP_LISTING_CALLS: u32 = 7;
const EXAMPLE_APP_COST: &str = "measured 8 of 346 merged 2026-10-01..2026-10-29; runs 8, attempts 0; median 5.1 min, p90 6.2 min";
const CEILING: &str = "a ceiling, not a level: a later pull request touching the same file is a correction or a planned second slice; read the trend";
const NOT_READ: &str = "wall-clock of the pull_request runs among the latest 100 (a floor of runner minutes when jobs run in parallel); not read: billable minutes (actions/runs/{id}/timing is closing down), the model's spend, human time, runs older than the latest 100";

/// Three judged pull requests and a bot's: a follower inside 30 days corrects
/// #10, one outside the window of #11 is not a follower, a bot's change is not
/// a correction, and #23 touching the name #12 renamed away corrects it.
fn corrections_host() -> FakeHost {
    FakeHost {
        pulls: Ok(vec![
            merged_pr(23, "2026-10-03T10:00:00Z"),
            merged_by(22, "2026-10-02T10:00:00Z", "renovate[bot]"),
            merged_pr(21, "2026-10-25T10:00:00Z"),
            merged_pr(20, "2026-10-01T10:00:00Z"),
            merged_by(13, "2026-09-23T10:00:00Z", "dependabot[bot]"),
            merged_pr(12, "2026-09-22T10:00:00Z"),
            merged_pr(11, "2026-09-21T10:00:00Z"),
            merged_pr(10, "2026-09-20T10:00:00Z"),
        ]),
        files: BTreeMap::from([
            (10, touched(&["src/a.rs"])),
            (11, touched(&["src/b.rs"])),
            (
                12,
                Ok(vec![PullFile {
                    filename: "docs/new.md".to_owned(),
                    status: "renamed".to_owned(),
                    previous_filename: Some("docs/old.md".to_owned()),
                }]),
            ),
            (13, touched(&["Cargo.lock"])),
            (20, touched(&["src/a.rs"])),
            (21, touched(&["src/b.rs"])),
            (22, touched(&["src/b.rs"])),
            (23, touched(&["docs/old.md"])),
        ]),
        ..FakeHost::default()
    }
}

#[test]
fn post_merge_corrections_counts_followers_within_30_days_on_both_names_of_a_rename() {
    let host = corrections_host();
    let counters = counted(&host, true);
    assert_eq!(
        counters.post_merge_corrections,
        Counter {
            value: Some(66.7),
            unit: "percent",
            evidence: vec![
                "judged 3 of 3 merged 2026-08-31..2026-09-28; files read for 4 of 4 followers"
                    .to_owned(),
                "corrected: #10 by #20 (src/a.rs), #12 by #23 (docs/old.md)".to_owned(),
                CEILING.to_owned(),
            ],
            reason: None,
        }
    );
    // The listing, the three judged and the two followers that are not judged:
    // neither bot nor #21, outside every window, is read.
    assert_eq!(host.count("pulls"), 1);
    assert_eq!(host.count("pull_files"), 5);
}

#[test]
fn post_merge_corrections_leaves_a_truncated_file_list_unjudged() {
    let mut host = corrections_host();
    host.files.insert(
        10,
        Err(HostError::new(
            HostErrorKind::Truncated,
            "files of pull request #10 in acme/shop has 100 or more files, the cap of this read",
        )),
    );
    let corrections = counted(&host, true).post_merge_corrections;
    assert_eq!(corrections.value, None);
    assert_eq!(
        corrections.reason.as_deref(),
        Some(
            "fewer than 3 judged: judged 2 of 3 merged 2026-08-31..2026-09-28; files read for 3 of 3 followers; unjudged: #10 (100 or more files)"
        )
    );
}

/// Four judged: the budget stops the follower reads once three are decided
/// (above `CORRECTIONS_MIN`, a value) or before any is (below, unavailable).
/// `limit` counts the pull request listing and the file reads; one more call
/// goes to the runs listing `cost_per_change` reads first, uncached here.
fn four_judged(limit: u32) -> FakeHost {
    FakeHost {
        budget: CallBudget::new(limit + 1),
        pulls: Ok(vec![
            merged_pr(22, "2026-10-03T10:00:00Z"),
            merged_pr(21, "2026-10-02T10:00:00Z"),
            merged_pr(20, "2026-10-01T10:00:00Z"),
            merged_pr(13, "2026-09-23T10:00:00Z"),
            merged_pr(12, "2026-09-22T10:00:00Z"),
            merged_pr(11, "2026-09-21T10:00:00Z"),
            merged_pr(10, "2026-09-20T10:00:00Z"),
        ]),
        files: BTreeMap::from([
            (10, touched(&["src/a.rs"])),
            (11, touched(&["src/b.rs"])),
            (12, touched(&["src/c.rs"])),
            (13, touched(&["src/d.rs"])),
            (20, touched(&["src/a.rs", "src/b.rs", "src/c.rs"])),
            (21, touched(&["src/e.rs"])),
            (22, touched(&["src/f.rs"])),
        ]),
        ..FakeHost::default()
    }
}

#[test]
fn post_merge_corrections_settles_when_the_budget_stops_it_above_the_minimum() {
    let host = four_judged(7);
    let corrections = counted(&host, true).post_merge_corrections;
    assert_eq!(corrections.value, Some(100.0));
    assert_eq!(
        corrections.evidence[..3],
        [
            "judged 3 of 4 merged 2026-08-31..2026-09-28; files read for 5 of 6 followers",
            "corrected: #10 by #20 (src/a.rs), #11 by #20 (src/b.rs), #12 by #20 (src/c.rs)",
            "the call budget stopped the file reads: call budget of 8 exhausted",
        ]
    );
}

#[test]
fn post_merge_corrections_is_budget_exhausted_below_the_minimum() {
    let host = four_judged(3);
    let corrections = counted(&host, true).post_merge_corrections;
    assert_eq!(corrections.value, None);
    assert_eq!(
        corrections.reason.as_deref(),
        Some(
            "budget exhausted: judged 0 of 4 merged 2026-08-31..2026-09-28; files read for 1 of 4 followers (call budget of 4 exhausted)"
        )
    );
}

#[test]
fn counters_are_unavailable_when_pull_files_is_unsupported_and_without_remote() {
    let mut host = corrections_host();
    host.files.insert(10, Err(unsupported("pull_files")));
    let corrections = counted(&host, true).post_merge_corrections;
    assert_eq!(corrections.value, None);
    assert_eq!(
        corrections.reason.as_deref(),
        Some("pull_files is not supported by this fake")
    );

    let host = corrections_host();
    let offline = counted(&host, false);
    for counter in [&offline.post_merge_corrections, &offline.cost_per_change] {
        assert_eq!(counter.value, None);
        assert_eq!(counter.reason.as_deref(), Some("not read without --remote"));
    }
    assert!(host.calls.borrow().is_empty());
}

/// A pull_request run of `pulls` created at `created` and updated at `updated`.
fn pr_run(
    id: u64,
    pulls: &[u64],
    attempt: u32,
    started: Option<&str>,
    created: &str,
    updated: &str,
) -> WorkflowRun {
    WorkflowRun {
        event: "pull_request".to_owned(),
        status: "completed".to_owned(),
        conclusion: Some("success".to_owned()),
        run_attempt: Some(attempt),
        created_at: Some(created.to_owned()),
        updated_at: Some(updated.to_owned()),
        run_started_at: started.map(str::to_owned),
        pull_requests: pulls.to_vec(),
        ..wrun(id, "CI", "feature", Some("success"), attempt)
    }
}

#[test]
fn cost_per_change_is_the_median_wall_clock_of_each_merged_pull_requests_runs() {
    let host = FakeHost {
        pulls: Ok(vec![
            merged_pr(32, "2026-10-12T10:00:00Z"),
            merged_pr(31, "2026-10-11T10:00:00Z"),
            merged_pr(30, "2026-10-10T10:00:00Z"),
            merged_pr(9, "2026-09-29T10:00:00Z"),
        ]),
        runs: Ok(vec![
            // A re-run: its second attempt is part of the cost.
            pr_run(
                1,
                &[30],
                2,
                Some("2026-10-10T08:02:00Z"),
                "2026-10-10T08:00:00Z",
                "2026-10-10T08:12:00Z",
            ),
            pr_run(
                2,
                &[30],
                1,
                Some("2026-10-10T09:00:00Z"),
                "2026-10-10T09:00:00Z",
                "2026-10-10T09:05:00Z",
            ),
            // No run_started_at: from created_at. GitHub empties
            // `pull_requests` once the branch is gone: the head sha names it.
            WorkflowRun {
                head_sha: format!("{:040x}", 31),
                ..pr_run(
                    3,
                    &[],
                    1,
                    None,
                    "2026-10-11T09:00:00Z",
                    "2026-10-11T09:20:00Z",
                )
            },
            // A push run of the same pull request is not its pull_request cost.
            WorkflowRun {
                pull_requests: vec![30],
                updated_at: Some("2026-10-10T12:00:00Z".to_owned()),
                ..wrun(4, "CI", "main", Some("success"), 1)
            },
            // #9 merged before the 28 days.
            pr_run(
                5,
                &[9],
                1,
                None,
                "2026-09-29T09:00:00Z",
                "2026-09-29T09:30:00Z",
            ),
        ]),
        ..FakeHost::default()
    };
    let cost = counted(&host, true).cost_per_change;
    assert_eq!(
        cost,
        Counter {
            value: Some(17.5),
            unit: "minutes",
            evidence: vec![
                "measured 2 of 3 merged 2026-09-30..2026-10-28; runs 3, attempts 1; median 17.5 min, p90 20.0 min"
                    .to_owned(),
                NOT_READ.to_owned(),
            ],
            reason: None,
        }
    );
    // Both from the listings the cadence measure and rerun-rate read.
    assert_eq!(host.count("workflow_runs"), 1);
}

#[test]
fn cost_per_change_without_a_run_of_any_merged_pull_request_is_unavailable() {
    let host = FakeHost {
        pulls: Ok(vec![merged_pr(30, "2026-10-10T10:00:00Z")]),
        runs: Ok(vec![]),
        ..FakeHost::default()
    };
    let cost = counted(&host, true).cost_per_change;
    assert_eq!(cost.value, None);
    assert_eq!(
        cost.reason.as_deref(),
        Some(
            "measured 0 of 1 merged 2026-09-30..2026-10-28: none has a pull_request run among the latest 100 workflow runs"
        )
    );
}

/// The counters over the GETs recorded from example-app on 2026-10-29 (read-only
/// `gh api`; titles replaced, bodies reduced to the fields read), after
/// `spent` calls of 60. Each listing costs its calls here: no rule cached it.
fn example_app_counters(spent: u32) -> (Counters, u32) {
    let path = format!(
        "{}/tests/fixtures/auditor/counters/example-app.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let fixture: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    let replay = Replay {
        replies: fixture["replies"].as_object().unwrap().clone(),
        gets: RefCell::default(),
    };
    let host = brakes::host::github::GitHub::new(&replay, CallBudget::new(60));
    for _ in 0..spent {
        host.budget().spend().unwrap();
    }
    let dir = tempfile::tempdir().unwrap();
    let local = LocalFiles::new(dir.path());
    let repo = RepoId::parse("example-org/example-app").unwrap();
    let cx = Cx {
        host: &host,
        files: &local,
        repo: &repo,
        default_branch: "main",
        now: NaiveDate::from_ymd_opt(2026, 10, 29).unwrap(),
        budget: host.budget(),
        profile: Profile::P1,
        today: None,
    };
    let counters = counters::count(&cx, true);
    (counters, host.budget().used())
}

/// The full budget: every judged pull request of the sample is read and the
/// followers until the budget stops them; the shared state and plan files
/// (`.agent/STATE.md`, execution specs) make the ceiling 100 %.
#[test]
fn example_app_recorded_counters() {
    let (counters, calls) = example_app_counters(0);
    assert_eq!(calls, 60);
    assert_eq!(
        counters.post_merge_corrections,
        Counter {
            value: Some(100.0),
            unit: "percent",
            evidence: vec![
                "judged 8 of 187 merged 2026-09-01..2026-09-29; files read for 51 of 314 followers; unjudged: #1056 (100 or more files)".to_owned(),
                "corrected: #1053 by #1126 (part-004.md), #1055 by #1058 (part-000/part-000.md), #1057 by #1078 (part-006/part-000.md), #1058 by #1059 (part-006/part-006/part-004/part-014.md), #1059 by #1063 (part-006/part-006/part-004/part-014.md), #1063 by #1080 (part-006/part-006/part-004/part-014.md), #1065 by #1067 (part-006/part-006/part-004/part-008.md), #1066 by #1067 (part-006/part-006/part-004/part-006.md)".to_owned(),
                "the call budget stopped the file reads: call budget of 60 exhausted".to_owned(),
                CEILING.to_owned(),
            ],
            reason: None,
        }
    );
    assert_eq!(counters.cost_per_change.value, Some(5.1));
    assert_eq!(
        counters.cost_per_change.evidence,
        [EXAMPLE_APP_COST, NOT_READ]
    );
}

/// What the allowance alone buys once the two listings are read: six judged
/// pull requests, three of them decided by followers among the six.
#[test]
fn example_app_recorded_counters_within_the_allowance() {
    let (counters, calls) =
        example_app_counters(60 - EXAMPLE_APP_LISTING_CALLS - counters::ALLOWANCE);
    assert_eq!(calls, 60);
    let corrections = &counters.post_merge_corrections;
    assert_eq!(corrections.value, Some(100.0));
    assert_eq!(
        corrections.evidence[..3],
        [
            "judged 3 of 187 merged 2026-09-01..2026-09-29; files read for 5 of 310 followers",
            "corrected: #1059 by #1063 (part-006/part-006/part-004/part-014.md), #1065 by #1067 (part-006/part-006/part-004/part-008.md), #1066 by #1067 (part-006/part-006/part-004/part-006.md)",
            "the call budget stopped the file reads: call budget of 60 exhausted",
        ]
    );
    assert_eq!(counters.cost_per_change.evidence[0], EXAMPLE_APP_COST);
}

#[test]
/// A checkout holds the counters' 6 beside the rules' 34; `--fleet` holds
/// none for them, so the sum stays 50 there (49 and the lock, #1318).
fn counters_allowance_brings_the_checkout_sum_to_40_and_leaves_the_fleet_at_50() {
    let rules: u32 = ALLOWANCES.iter().map(|(_, calls)| calls).sum();
    assert_eq!(rules + counters::ALLOWANCE, 40);
    let fleet: u32 = REGISTRY.iter().map(|r| fleet_allowance(r.id)).sum();
    assert_eq!(fleet, 50);
    assert!(rules + counters::ALLOWANCE <= CALL_BUDGET);
}

// --- baseline: today's doctor findings re-labelled (#730) -----------------------------

mod baseline_findings {
    use super::{FakeHost, dims, now};
    use brakes::{
        LOCK, PROFILE, Result,
        auditor::{
            Audit, Cx, LocalFiles, Today,
            catalogue::baseline::{self, FINDINGS, Relabel},
            evaluate,
            rules::{
                Block, Level, Milestone, Outcome, Probe, Profile, REGISTRY, Required, Rule, Status,
            },
        },
        doctor_at,
        host::RepoId,
        remote::{Api, HttpError, inspect_report},
    };
    use serde_json::{Value, json};
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs,
        path::Path,
        process::Command,
    };

    fn git_init(root: &Path) {
        assert!(
            Command::new("git")
                .args(["init", "-q"])
                .arg(root)
                .status()
                .unwrap()
                .success()
        );
    }
    fn cli(root: &Path, args: &[&str]) {
        let out = Command::new(env!("CARGO_BIN_EXE_brakes"))
            .args(args)
            .arg(root)
            .output()
            .unwrap();
        assert!(out.status.success(), "{args:?}: {out:?}");
    }
    fn read_json(root: &Path, path: &str) -> Value {
        serde_json::from_str(&fs::read_to_string(root.join(path)).unwrap()).unwrap()
    }
    fn write(root: &Path, path: &str, text: &str) {
        let full = root.join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, text).unwrap();
    }
    fn write_json(root: &Path, path: &str, value: &Value) {
        write(root, path, &serde_json::to_string_pretty(value).unwrap());
    }
    fn installed() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        git_init(dir.path());
        cli(dir.path(), &["install", "--new-personal", "--apply"]);
        dir
    }

    /// The findings of `doctor_at` over fixtures that reach each family of
    /// local finding: an empty checkout, an installed one broken in every way
    /// the lock, the profile, conventions, alerts and entrypoints can be, and
    /// one with agent-guardrails, ci-baseline and stack-packs installed.
    fn local_findings() -> Vec<String> {
        let mut found = Vec::new();
        let empty = tempfile::tempdir().unwrap();
        git_init(empty.path());
        found.extend(doctor_at(empty.path(), now()).unwrap());

        let broken = installed();
        let root = broken.path();
        write(
            root,
            "docs/decisions.md",
            "# Decisions\n\n## Choice — accepted, 2026-10-22\n",
        );
        let mut profile = read_json(root, PROFILE);
        profile["conventions"] = json!([
            {"path": "docs/decisions.md", "adr": "docs/decisions.md#choice--accepted-2026-10-22"}
        ]);
        write_json(root, PROFILE, &profile);
        cli(root, &["install", "--apply"]);
        write(
            root,
            "docs/decisions.md",
            "# Decisions\n\n## Choice — accepted, 2026-10-22\n\n## Another — accepted, 2026-10-23\n",
        );
        write(root, "docs/conv.md", "# Convention\n");
        let mut profile = read_json(root, PROFILE);
        profile["purpose"] = json!("Changed after install");
        profile["planning"] = json!("tasks/plan.md");
        profile["conventions"] = json!([
            {"path": "docs/decisions.md", "adr": "docs/decisions.md#choice--accepted-2026-10-22"},
            "docs/missing.md",
            {"path": "docs/conv.md"},
            {"path": "docs/conv.md", "adr": "docs/decisions.md#nope"}
        ]);
        profile["observability"] = json!({"alerts_dir": "alerts", "runbooks_dir": "runbooks"});
        write_json(root, PROFILE, &profile);
        write(root, "alerts/bad.yml", "not prometheus\n");
        write(
            root,
            "alerts/rules.yml",
            "groups:\n  - name: g\n    rules:\n      - alert: Down\n        expr: up == 0\n        annotations:\n          runbook_url: runbooks/down.md\n",
        );
        let mut claude = fs::read_to_string(root.join("CLAUDE.md")).unwrap_or_default();
        claude.push_str("\n- TODO\n");
        write(root, "CLAUDE.md", &claude);
        let mut lock = read_json(root, LOCK);
        lock["source_dirty"] = json!(true);
        let guides: Vec<String> = lock["files"]
            .as_object()
            .unwrap()
            .keys()
            .filter(|k| k.starts_with("docs/agent-setup/") && k.ends_with(".md"))
            .cloned()
            .collect();
        lock["files"].as_object_mut().unwrap().remove(&guides[0]);
        write_json(root, LOCK, &lock);
        write(root, &guides[1], "# Edited by hand\n");
        found.extend(doctor_at(root, now()).unwrap());
        let later = now() + chrono::Days::new(400);
        found.extend(doctor_at(root, later).unwrap());

        let guarded = installed();
        let root = guarded.path();
        let mut profile = read_json(root, PROFILE);
        profile["commands"]["verify"] = json!("cargo test --locked");
        profile["commands"]["test"] = json!("cargo test --locked");
        write_json(root, PROFILE, &profile);
        write(root, "Cargo.toml", "");
        write(root, "Cargo.lock", "");
        write_json(
            root,
            ".agent-setup/modules/stack-packs.json",
            &json!({"module": "stack-packs", "version": "1.0.0",
                "answers": {"apps.root.path": ".", "apps.root.stack": "rust"}}),
        );
        let mut args = vec!["install"];
        for id in [
            "repo-baseline",
            "stack-packs",
            "ci-baseline",
            "agent-guardrails",
        ] {
            args.extend(["--module", id]);
        }
        args.push("--apply");
        cli(root, &args);
        let mut profile = read_json(root, PROFILE);
        profile["commands"]["verify"] = json!("cargo test");
        write_json(root, PROFILE, &profile);
        // The registered deny rules deleted by hand (#748): agents.deny-secrets
        // and the engine's managed-entries drift.
        let mut settings = read_json(root, ".claude/settings.json");
        settings.as_object_mut().unwrap().remove("permissions");
        write_json(root, ".claude/settings.json", &settings);
        write(
            root,
            ".github/workflows/extra.yml",
            "on: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n",
        );
        found.extend(doctor_at(root, now()).unwrap());
        found
    }

    /// Serves `responses` by path; anything else is a 404, as GitHub answers it.
    struct Fake(BTreeMap<String, Value>);
    impl Api for Fake {
        fn get(&self, path: &str) -> Result<Value> {
            match self.0.get(path) {
                Some(value) if value["status"].is_string() => Err(HttpError {
                    status: value["status"].as_str().unwrap().parse().unwrap(),
                    message: value["message"].as_str().unwrap_or("").to_owned(),
                }
                .into()),
                Some(value) => Ok(value.clone()),
                None => Err(HttpError {
                    status: 404,
                    message: format!("Not Found: {path}"),
                }
                .into()),
            }
        }
    }

    const REPO: &str = "example-owner/example";
    const BASE: &str = "repos/example-owner/example";

    fn ci() -> Value {
        json!({"required_checks": ["verify"],
            "shards": {"count": 2, "command": "cargo nextest run --partition count:<i>/2"},
            "tiers": {"pull_request": {"inert_paths": ["docs/"], "full_paths": ["src/"]}, "main": {"paths": ["**"]}},
            "cycle_budget_minutes": 1})
    }
    fn run(id: u64, event: &str, status: &str, conclusion: Value) -> Value {
        json!({"id": id, "head_sha": format!("head-{id}"),
            "head_branch": if event == "push" {"trunk"} else {"feature"},
            "event": event, "status": status, "conclusion": conclusion,
            "pull_requests": [{"number": 8}], "created_at": "2026-10-22T10:00:00Z"})
    }

    /// The findings of `inspect_report` over fake hosts reaching each family:
    /// out of scope, unreadable, unprotected without a CI policy, protection
    /// unreadable with an empty policy, drifted protection with failing,
    /// incomplete, slow and unsharded cycles.
    fn remote_findings() -> Vec<String> {
        let repo = || (BASE.to_owned(), json!({"default_branch": "trunk"}));
        let protection = format!("{BASE}/branches/trunk/protection");
        let runs = format!("{BASE}/actions/runs?per_page=100");
        // (repository, the host's responses by path, the declared `ci`)
        type Scenario<'a> = (&'a str, Vec<(String, Value)>, Value);
        let scenarios: Vec<Scenario> = vec![
            ("acme/shop", vec![], ci()),
            (REPO, vec![], ci()),
            (
                REPO,
                vec![
                    repo(),
                    (
                        protection.clone(),
                        json!({"status": "404", "message": "Branch not protected"}),
                    ),
                ],
                Value::Null,
            ),
            (
                REPO,
                vec![
                    repo(),
                    (
                        protection.clone(),
                        json!({"status": "403", "message": "Forbidden"}),
                    ),
                ],
                json!({}),
            ),
            (
                REPO,
                vec![
                    repo(),
                    (
                        protection.clone(),
                        json!({"status": "403", "message": "Upgrade to GitHub Pro or make this repository public to enable this feature."}),
                    ),
                ],
                ci(),
            ),
            (
                REPO,
                vec![
                    repo(),
                    (
                        protection.clone(),
                        json!({"enforce_admins": {"enabled": false},
                        "allow_force_pushes": {"enabled": true}, "allow_deletions": {"enabled": true}}),
                    ),
                    (
                        runs.clone(),
                        json!({"workflow_runs": [
                            run(3, "pull_request", "in_progress", Value::Null),
                            run(2, "pull_request", "completed", json!("success")),
                            run(1, "push", "completed", json!("failure")),
                        ]}),
                    ),
                    (
                        format!("{BASE}/actions/runs/1/jobs?per_page=100&page=1"),
                        json!({"total_count": 1, "jobs": [
                        {"name": "Rust shard 1/3 (linux)", "conclusion": "skipped",
                         "started_at": "2026-10-22T10:00:01Z", "completed_at": "2026-10-22T10:09:00Z", "steps": []}]}),
                    ),
                    (
                        format!("{BASE}/pulls/8"),
                        json!({"head": {"sha": "other"}, "base": {"sha": "base"}}),
                    ),
                ],
                ci(),
            ),
            (
                REPO,
                vec![repo(), (runs, json!({"workflow_runs": []}))],
                ci(),
            ),
        ];
        scenarios
            .into_iter()
            .flat_map(|(repository, responses, ci)| {
                inspect_report(&Fake(responses.into_iter().collect()), repository, &ci).findings
            })
            .collect()
    }

    #[cfg_attr(
        not(feature = "setup-core"),
        ignore = "lists setup-core or its guides; product-boundary T7a"
    )]
    #[test]
    fn every_finding_doctor_and_inspect_report_reach_from_fixtures_has_a_rule_id() {
        let local = local_findings();
        let remote = remote_findings();
        let unmapped: Vec<&String> = local
            .iter()
            .chain(&remote)
            .filter(|f| baseline::relabel(f).is_none())
            .collect();
        assert!(
            unmapped.is_empty(),
            "findings without a rule id: {unmapped:#?}"
        );
        // The fixtures keep reaching every family the table names, so a
        // finding string that changes cannot slip past this test.
        let reached: BTreeSet<String> = local
            .iter()
            .chain(&remote)
            .filter_map(|f| baseline::relabel(f))
            .collect();
        let named: BTreeSet<&str> = FINDINGS
            .iter()
            .filter_map(|(_, r)| match r {
                Relabel::Rule(id) => Some(*id),
                Relabel::Own => None,
            })
            .collect();
        let missed: Vec<&&str> = named.iter().filter(|id| !reached.contains(**id)).collect();
        assert!(
            missed.is_empty(),
            "no fixture reaches {missed:?}; reached {reached:#?}"
        );
        // The module rules keep their own ids, registry rules since #873.
        for prefix in ["ci.", "security.", "stack.", "agents."] {
            assert!(
                reached.iter().any(|id| id.starts_with(prefix)),
                "no {prefix}* warning reached: {reached:#?}"
            );
        }
    }

    #[test]
    fn module_warnings_keep_their_own_rule_id_which_is_a_registry_rule_since_873() {
        let registered = |id: &str| REGISTRY.iter().any(|r| r.id == id);
        for (finding, id) in [
            (
                "WARNING: ci.job-timeouts: Job x has no timeout-minutes",
                "ci.job-timeouts",
            ),
            (
                "WARNING: stack.unconfigured: a stack is detected\n- rust at .",
                "stack.unconfigured",
            ),
            (
                "WARNING: security.deps-gate: No lockfile vulnerability scan in CI",
                "security.deps-gate",
            ),
            (
                "WARNING: agents.readable-secrets: secrets/x.key is tracked",
                "agents.readable-secrets",
            ),
            // One id for pinned actions: ci-baseline's line carries the posture id.
            (
                "WARNING: posture.actions-pinned: Unpinned action a@v1 in x.yml",
                "posture.actions-pinned",
            ),
            // The registrations agent-guardrails reports are its own rules.
            (
                brakes::modules::agent_guardrails::doctor::DENY_UNREGISTERED,
                "agents.deny-secrets",
            ),
            (
                brakes::modules::agent_guardrails::doctor::STOP_UNREGISTERED,
                "agents.stop-verify",
            ),
            (
                "Stop verify hook h runs `a` but project.json declares `b`; re-run install",
                "agents.stop-verify",
            ),
        ] {
            assert_eq!(baseline::relabel(finding).as_deref(), Some(id), "{finding}");
            assert!(registered(id), "{id}");
        }
        // Warning only (#873, point 4): its own id, and no registry rule.
        let stale = "WARNING: stack.pin-table-stale: the pin table was verified 200 days ago";
        assert_eq!(
            baseline::relabel(stale).as_deref(),
            Some("stack.pin-table-stale")
        );
        assert!(!registered("stack.pin-table-stale"));
        assert!(!registered("stack.no-healthcheck"));
        assert_eq!(baseline::relabel("Something nobody prints"), None);
        // A pattern is anchored at both ends.
        assert_eq!(baseline::relabel("Setup lock missing, twice"), None);
        assert_eq!(
            baseline::relabel("Stop verify hook h runs `a` but project.json declares `b`; ignore"),
            None
        );
    }

    #[test]
    fn every_rule_the_table_names_is_in_the_registry_at_basic_or_bronze_unless_allocated() {
        for (pattern, relabel) in FINDINGS {
            let Relabel::Rule(id) = relabel else { continue };
            let rule = REGISTRY
                .iter()
                .find(|r| r.id == *id)
                .unwrap_or_else(|| panic!("{pattern}: {id} is not in the registry"));
            // Decision "Auditor standard v1", point 1: by origin, unless the
            // allocation table names the rule (alerts are runbook-per-alert;
            // since #873 the module rules of their own blocks).
            let allocated = rule.block != Block::Baseline;
            assert!(
                allocated || (rule.block == Block::Baseline && rule.level <= Level::Bronze),
                "{id}"
            );
            // The first local rules judge the profile and lock themselves (#709).
            let first_slice = [
                "baseline.purpose-declared",
                "baseline.verify-declared",
                "baseline.setup-installed",
            ];
            if rule.block == Block::Baseline && !first_slice.contains(id) {
                let warning = pattern.starts_with("WARNING: ");
                assert_eq!(rule.level == Level::Bronze, warning, "{pattern} → {id}");
            }
        }
    }

    // --- re-labelled outcomes ------------------------------------------------------

    fn checkout(lock: bool) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let mut profile = brakes::default_profile();
        profile["purpose"] = json!("Sell bread");
        profile["commands"]["verify"] = json!("cargo test");
        profile["criticality"] = json!("internal");
        write_json(dir.path(), PROFILE, &profile);
        if lock {
            write(dir.path(), LOCK, r#"{"schema": 2}"#);
        }
        dir
    }

    fn audit_with(root: &Path, today: Option<&Today<'_>>, rules: &'static [Rule]) -> Audit {
        let host = FakeHost::default();
        let files = LocalFiles::new(root);
        let repo = RepoId::parse("acme/shop").unwrap();
        let cx = Cx {
            host: &host,
            files: &files,
            repo: &repo,
            default_branch: "main",
            now: now(),
            budget: &host.budget,
            profile: Profile::P1,
            today,
        };
        evaluate(&cx, &dims(Profile::P1), rules)
    }
    fn outcome_of(audit: &Audit, id: &str) -> Outcome {
        audit
            .rules
            .iter()
            .find(|e| e.rule.id == id)
            .unwrap()
            .outcome
            .clone()
    }

    static RELABELLED: &[Rule] = &[
        #[cfg(feature = "setup-core")]
        baseline::GUIDES_INSTALLED,
        #[cfg(feature = "setup-core")]
        baseline::DECISIONS_INDEX_CURRENT,
        #[cfg(feature = "setup-core")]
        baseline::PLACEHOLDERS_REVIEWED,
        baseline::REMOTE_READABLE,
        baseline::BRANCH_PROTECTION_MATCHES,
        baseline::CI_POLICY_MET,
    ];

    /// #1164: the finding `inspect_report` raises when the plan refuses protection.
    const PLAN_REFUSED: &str = "The default branch protection requires plan Team: the plan refuses branch protection and rulesets on this private repository (HTTP 403: Upgrade to GitHub Pro or make this repository public to enable this feature.), so there is no server-side merge barrier and the session hook is the only barrier.";

    #[test]
    fn a_plan_refused_protection_is_unavailable_requiring_the_plan_never_failed() {
        let dir = checkout(true);
        let findings = [PLAN_REFUSED.to_owned()];
        let today = Today {
            findings: &findings,
            steps: &[],
            remote: true,
        };
        let audit = audit_with(dir.path(), Some(&today), RELABELLED);
        let protection = outcome_of(&audit, "baseline.branch-protection-matches");
        assert_eq!(protection.status, Status::Unavailable);
        assert_eq!(
            protection.reason.as_deref(),
            Some(
                "requires plan Team: the plan refuses branch protection and rulesets on this private repository (HTTP 403: Upgrade to GitHub Pro or make this repository public to enable this feature.), so there is no server-side merge barrier and the session hook is the only barrier."
            )
        );
        for id in ["baseline.remote-readable", "baseline.ci-policy-met"] {
            assert_eq!(outcome_of(&audit, id).status, Status::Passed, "{id}");
        }
    }

    #[test]
    fn a_real_protection_finding_beside_the_plan_refusal_still_fails_the_rule() {
        let dir = checkout(true);
        let missing = "The project has no valid declared required CI checks.";
        let findings = [missing.to_owned(), PLAN_REFUSED.to_owned()];
        let today = Today {
            findings: &findings,
            steps: &[],
            remote: true,
        };
        let audit = audit_with(dir.path(), Some(&today), RELABELLED);
        let protection = outcome_of(&audit, "baseline.branch-protection-matches");
        assert_eq!(protection.status, Status::Failed);
        assert_eq!(protection.evidence, vec![missing, PLAN_REFUSED]);
    }

    #[cfg_attr(
        not(feature = "setup-core"),
        ignore = "asserts setup-core's own content or id; product-boundary T7b"
    )]
    #[test]
    fn a_finding_fails_its_rule_with_the_finding_as_evidence_and_the_others_pass() {
        let dir = checkout(true);
        let findings = [
            "Engineering guide not installed; update setup: docs/agent-setup/ci.md".to_owned(),
            "WARNING: Decisions index stale: docs/agent-setup/decisions-index.md; regenerate with the setup installer".to_owned(),
            "Default branch is not protected.".to_owned(),
        ];
        let today = Today {
            findings: &findings,
            steps: &[],
            remote: true,
        };
        let audit = audit_with(dir.path(), Some(&today), RELABELLED);
        let guides = outcome_of(&audit, "baseline.guides-installed");
        assert_eq!(guides.status, Status::Failed);
        assert_eq!(guides.evidence, vec![findings[0].as_str()]);
        let index = outcome_of(&audit, "baseline.decisions-index-current");
        assert_eq!(index.status, Status::Failed);
        assert_eq!(
            index.evidence,
            vec![
                "Decisions index stale: docs/agent-setup/decisions-index.md; regenerate with the setup installer"
            ]
        );
        let protection = outcome_of(&audit, "baseline.branch-protection-matches");
        assert_eq!(protection.status, Status::Failed);
        assert_eq!(
            protection.evidence,
            vec!["Default branch is not protected."]
        );
        for id in [
            "baseline.placeholder-guidance-reviewed",
            "baseline.remote-readable",
            "baseline.ci-policy-met",
        ] {
            let o = outcome_of(&audit, id);
            assert_eq!(o.status, Status::Passed, "{id}");
            assert_eq!(o.evidence, vec!["today's doctor reports none"], "{id}");
        }
    }

    #[cfg_attr(
        not(feature = "setup-core"),
        ignore = "asserts setup-core's own content or id; product-boundary T7b"
    )]
    #[test]
    fn without_a_lock_the_guide_rules_are_not_required_and_without_a_checkout_too() {
        let dir = checkout(false);
        let findings = ["Setup lock missing".to_owned()];
        let today = Today {
            findings: &findings,
            steps: &[],
            remote: false,
        };
        let audit = audit_with(dir.path(), Some(&today), RELABELLED);
        for id in [
            "baseline.guides-installed",
            "baseline.decisions-index-current",
        ] {
            let o = outcome_of(&audit, id);
            assert_eq!(o.status, Status::NotRequired, "{id}");
            assert_eq!(o.reason.as_deref(), Some("setup not installed"), "{id}");
        }
        assert_eq!(
            outcome_of(&audit, "baseline.placeholder-guidance-reviewed").status,
            Status::Passed
        );
        for id in [
            "baseline.remote-readable",
            "baseline.branch-protection-matches",
            "baseline.ci-policy-met",
        ] {
            let o = outcome_of(&audit, id);
            assert_eq!(o.status, Status::Unavailable, "{id}");
            assert_eq!(
                o.reason.as_deref(),
                Some("remote findings run only with doctor --remote"),
                "{id}"
            );
        }
        // No checkout under `--fleet` (#734): nothing to re-label, so not required.
        let audit = audit_with(dir.path(), None, RELABELLED);
        for id in [
            "baseline.placeholder-guidance-reviewed",
            "baseline.remote-readable",
            "baseline.ci-policy-met",
        ] {
            let o = outcome_of(&audit, id);
            assert_eq!(o.status, Status::NotRequired, "{id}");
            assert_eq!(
                o.reason.as_deref(),
                Some("no checkout under --fleet"),
                "{id}"
            );
        }
    }

    #[test]
    fn an_unreadable_remote_makes_the_other_remote_rules_unavailable_never_passed() {
        let dir = checkout(true);
        let unread = "The repository default branch could not be read, so remote protection and CI are unverified.";
        let findings = [unread.to_owned()];
        let today = Today {
            findings: &findings,
            steps: &[],
            remote: true,
        };
        let audit = audit_with(dir.path(), Some(&today), RELABELLED);
        let readable = outcome_of(&audit, "baseline.remote-readable");
        assert_eq!(readable.status, Status::Failed);
        assert_eq!(readable.evidence, vec![unread]);
        for id in [
            "baseline.branch-protection-matches",
            "baseline.ci-policy-met",
        ] {
            let o = outcome_of(&audit, id);
            assert_eq!(o.status, Status::Unavailable, "{id}");
            assert_eq!(
                o.reason,
                Some(format!("remote diagnosis did not run: {unread}")),
                "{id}"
            );
        }
    }

    // --- a repository without a lock reaches Bronze on its own merits ----------------

    fn silver_fails(_: &Cx<'_>) -> Outcome {
        Outcome::failed(["a Silver rule, so the level stops at Bronze"])
    }
    static UNMANAGED: &[Rule] = &[
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
        Rule {
            id: "governance.next-level",
            title: "A Silver rule",
            block: Block::Governance,
            checks: "Fails.",
            how: Probe::Remote { id: "test" },
            level: Level::Silver,
            required: Required {
                profiles: &[Profile::P1, Profile::P2, Profile::P3],
                when: &[],
            },
            remediation: brakes::auditor::rules::Remediation::Module { id: "delivery" },
            plan: None,
            feasible_by: Milestone::Nov7,
            evaluate: silver_fails,
        },
    ];

    #[cfg_attr(
        not(feature = "setup-core"),
        ignore = "asserts setup-core's own content or id; product-boundary T7b"
    )]
    #[test]
    fn a_repository_without_a_lock_reaches_bronze_with_no_guide_rule_required() {
        let dir = checkout(false);
        git_init(dir.path());
        let findings = doctor_at(dir.path(), now()).unwrap();
        assert!(
            findings.contains(&"Setup lock missing".to_owned()),
            "{findings:?}"
        );
        // A clean `doctor --remote`: what this test owns is the local findings.
        let today = Today {
            findings: &findings,
            steps: &[],
            remote: true,
        };
        let audit = audit_with(dir.path(), Some(&today), UNMANAGED);
        assert_eq!(audit.reached, Some(Level::Bronze), "{:#?}", audit.rules);
        assert_eq!(
            audit.next.as_ref().unwrap().gap,
            vec!["governance.next-level"]
        );
        for id in [
            "baseline.setup-installed",
            "baseline.guides-installed",
            "baseline.release-baseline",
            "baseline.managed-content-intact",
            "baseline.guides-verified",
            "baseline.entrypoints-current",
            "baseline.decisions-index-current",
        ] {
            assert_eq!(outcome_of(&audit, id).status, Status::NotRequired, "{id}");
        }
    }
}

// --- module rules allocated by the owner (#873) -------------------------------------

mod module_rules {
    use super::{FakeHost, dims, now};
    use brakes::{
        LOCK, PROFILE,
        auditor::{
            Audit, Cx, LocalFiles, Today,
            catalogue::modules,
            evaluate,
            rules::{Outcome, Profile, Rule, Status},
        },
        host::RepoId,
    };
    use serde_json::json;
    use std::{fs, path::Path};

    fn write(root: &Path, path: &str, text: &str) {
        let full = root.join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, text).unwrap();
    }
    /// A checkout with a profile, a lock recording `installed` and, when
    /// `workflow`, one workflow file.
    fn checkout(installed: &[&str], workflow: bool) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let mut profile = brakes::default_profile();
        profile["purpose"] = json!("Sell bread");
        write(dir.path(), PROFILE, &profile.to_string());
        let modules: serde_json::Map<String, serde_json::Value> = installed
            .iter()
            .map(|m| ((*m).to_owned(), json!({"version": "1.0.0"})))
            .collect();
        write(
            dir.path(),
            LOCK,
            &json!({"schema": 2, "modules": modules}).to_string(),
        );
        if workflow {
            write(
                dir.path(),
                ".github/workflows/ci.yml",
                "on: push\njobs: {}\n",
            );
        }
        dir
    }
    fn audit_with(root: &Path, findings: &[String], rules: &'static [Rule]) -> Audit {
        let host = FakeHost::default();
        let files = LocalFiles::new(root);
        let repo = RepoId::parse("acme/shop").unwrap();
        let today = Today {
            findings,
            steps: &[],
            remote: false,
        };
        let cx = Cx {
            host: &host,
            files: &files,
            repo: &repo,
            default_branch: "main",
            now: now(),
            budget: &host.budget,
            profile: Profile::P1,
            today: Some(&today),
        };
        evaluate(&cx, &dims(Profile::P1), rules)
    }
    fn outcome_of(audit: &Audit, id: &str) -> Outcome {
        audit
            .rules
            .iter()
            .find(|e| e.rule.id == id)
            .unwrap()
            .outcome
            .clone()
    }

    static RULES: &[Rule] = &[
        modules::CI_COMMAND_MISSING,
        modules::CI_JOB_TIMEOUTS,
        modules::CI_WORKFLOW_LINT,
        modules::SECURITY_DEPS_GATE,
        modules::SECURITY_SECRETS_GATE,
        modules::STACK_UNCONFIGURED,
        modules::STACK_LOCKFILE_PRESENT,
        modules::AGENTS_MCP_ALLOWLIST,
        modules::AGENTS_DENY_SECRETS,
    ];

    /// `ci.heldout-properties` (#980) in its four states, today's findings
    /// computed by ci-baseline's own `doctor` check over the checkout.
    #[test]
    fn heldout_properties_is_judged_in_its_four_states() {
        static PROPERTIES: &[Rule] = &[modules::CI_HELDOUT_PROPERTIES];
        let goldens =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../templates/ci-baseline/goldens");
        let golden = |name: &str| fs::read_to_string(goldens.join(name)).unwrap();
        let generated = golden("heldout-properties-rust.yml");
        let no_seed = generated.replace(
            "          HELDOUT_SEED: \"${{ steps.seed.outputs.seed }}\"\n",
            "",
        );
        assert_ne!(no_seed, generated);
        let plain = golden("heldout.yml");
        let broken = "on: [push\n".to_owned();
        let on = json!({"heldout": true, "heldout_properties": true});
        for (state, workflow, answered) in [
            (Status::NotRequired, &plain, false),
            (Status::Passed, &generated, false),
            (Status::Failed, &no_seed, false),
            (Status::Failed, &plain, true),
            (Status::Unavailable, &broken, true),
        ] {
            let dir = checkout(&["ci-baseline"], false);
            write(dir.path(), ".github/workflows/ci.yml", workflow);
            let answers: Option<brakes::engine::answers::Answers> =
                answered.then(|| serde_json::from_value(on.clone()).unwrap());
            let findings = brakes::modules::ci_baseline::audit::findings(
                dir.path(),
                &json!({}),
                answers.as_ref(),
            );
            let audit = audit_with(dir.path(), &findings, PROPERTIES);
            let outcome = outcome_of(&audit, "ci.heldout-properties");
            assert_eq!(outcome.status, state, "{outcome:?}\n{findings:#?}");
        }
    }

    #[test]
    fn a_module_finding_fails_its_rule_with_its_text_and_the_others_pass() {
        let dir = checkout(&["ci-baseline", "stack-packs", "agent-guardrails"], true);
        let findings = [
            "WARNING: ci.job-timeouts: Job build has no timeout-minutes".to_owned(),
            "WARNING: security.deps-gate: No lockfile vulnerability scan in CI".to_owned(),
            brakes::modules::agent_guardrails::doctor::DENY_UNREGISTERED.to_owned(),
            "WARNING: stack.unconfigured: a stack is detected that no stack-packs answers record\n- rust at .".to_owned(),
        ];
        let audit = audit_with(dir.path(), &findings, RULES);
        // A multi-line finding is evidence by its first line: an `AUDIT` line
        // stays one line, and `doctor` printed the whole block above it.
        let stack = outcome_of(&audit, "stack.unconfigured");
        assert_eq!(stack.status, Status::Failed);
        assert_eq!(
            stack.evidence,
            vec!["a stack is detected that no stack-packs answers record"]
        );
        let timeouts = outcome_of(&audit, "ci.job-timeouts");
        assert_eq!(timeouts.status, Status::Failed);
        assert_eq!(timeouts.evidence, vec!["Job build has no timeout-minutes"]);
        let deps = outcome_of(&audit, "security.deps-gate");
        assert_eq!(deps.status, Status::Failed);
        assert_eq!(deps.evidence, vec!["No lockfile vulnerability scan in CI"]);
        let deny = outcome_of(&audit, "agents.deny-secrets");
        assert_eq!(deny.status, Status::Failed);
        assert_eq!(
            deny.evidence,
            vec![
                "Deny rules for secrets are not registered in .claude/settings.json (permissions.deny)"
            ]
        );
        for id in [
            "ci.command-missing",
            "ci.workflow-lint",
            "security.secrets-gate",
            "stack.lockfile-present",
            "agents.mcp-allowlist",
        ] {
            let o = outcome_of(&audit, id);
            assert_eq!(o.status, Status::Passed, "{id}");
            assert_eq!(o.evidence, vec!["today's doctor reports none"], "{id}");
        }
    }

    #[test]
    fn a_rule_with_only_unverified_findings_is_unavailable_and_with_a_real_one_failed() {
        let dir = checkout(&[], true);
        let unread =
            "WARNING: ci.job-timeouts: unverified: .github/workflows/a.yml: bad indentation";
        let findings = [unread.to_owned()];
        let audit = audit_with(dir.path(), &findings, RULES);
        let o = outcome_of(&audit, "ci.job-timeouts");
        assert_eq!(o.status, Status::Unavailable);
        assert_eq!(
            o.reason.as_deref(),
            Some("unverified: .github/workflows/a.yml: bad indentation")
        );
        let findings = [
            unread.to_owned(),
            "WARNING: ci.job-timeouts: Job b has no timeout-minutes".to_owned(),
        ];
        let audit = audit_with(dir.path(), &findings, RULES);
        let o = outcome_of(&audit, "ci.job-timeouts");
        assert_eq!(o.status, Status::Failed);
        assert_eq!(
            o.evidence,
            vec![
                "unverified: .github/workflows/a.yml: bad indentation",
                "Job b has no timeout-minutes"
            ]
        );
    }

    #[test]
    fn a_finding_naming_a_higher_level_never_fails_the_lower_rule() {
        let dir = checkout(&["agent-guardrails"], false);
        let silver = "Silver: .agent-setup/mcp-allowlist.json server `db` is read-write; purpose: none written";
        let findings = [format!("WARNING: agents.mcp-allowlist: {silver}")];
        let audit = audit_with(dir.path(), &findings, RULES);
        let o = outcome_of(&audit, "agents.mcp-allowlist");
        assert_eq!(o.status, Status::Passed);
        assert_eq!(
            o.evidence,
            vec![
                "today's doctor reports none at this level".to_owned(),
                format!("above it: {silver}")
            ]
        );
    }

    #[test]
    fn rules_doctor_does_not_evaluate_in_a_checkout_are_not_required_there() {
        let dir = checkout(&[], false);
        let audit = audit_with(dir.path(), &[], RULES);
        let reason = |id: &str| {
            let o = outcome_of(&audit, id);
            assert_eq!(o.status, Status::NotRequired, "{id}");
            o.reason.unwrap()
        };
        assert_eq!(
            reason("ci.job-timeouts"),
            "no workflow under .github/workflows"
        );
        assert_eq!(
            reason("ci.workflow-lint"),
            "no workflow under .github/workflows"
        );
        assert_eq!(reason("ci.command-missing"), "ci-baseline not installed");
        assert_eq!(
            reason("stack.lockfile-present"),
            "stack-packs not installed"
        );
        assert_eq!(
            reason("agents.deny-secrets"),
            "agent-guardrails not installed"
        );
        // Evaluated in every checkout, managed or not.
        for id in [
            "security.secrets-gate",
            "security.deps-gate",
            "stack.unconfigured",
            "agents.mcp-allowlist",
        ] {
            assert_eq!(outcome_of(&audit, id).status, Status::Passed, "{id}");
        }
        // Under `--fleet` there is no checkout and no diagnosis: every module
        // rule is not required, before it reads the lock or the workflows.
        let host = FakeHost::default();
        let files = LocalFiles::new(dir.path());
        let repo = RepoId::parse("acme/shop").unwrap();
        let cx = Cx {
            host: &host,
            files: &files,
            repo: &repo,
            default_branch: "main",
            now: now(),
            budget: &host.budget,
            profile: Profile::P1,
            today: None,
        };
        let fleet = evaluate(&cx, &dims(Profile::P1), RULES);
        for e in &fleet.rules {
            assert_eq!(e.outcome.status, Status::NotRequired, "{}", e.rule.id);
            assert_eq!(
                e.outcome.reason.as_deref(),
                Some(brakes::auditor::catalogue::baseline::NO_CHECKOUT),
                "{}",
                e.rule.id
            );
        }
        // Without a lock at all, the installed-only rules are not required either.
        fs::remove_file(dir.path().join(LOCK)).unwrap();
        let audit = audit_with(dir.path(), &[], RULES);
        assert_eq!(
            outcome_of(&audit, "ci.command-missing").status,
            Status::NotRequired
        );
    }
}

// --- ci: the remote rules through the host adapter (SPEC-ci-baseline.md, slice 2; #783)

mod ci_remote {
    use super::{
        FakeHost, PLAN_403, dims, failed, job_done, not_required, now, outcome, passed,
        plan_refused, protection, recorded_together, ruleset, unavailable, wrun,
    };
    use brakes::{
        auditor::{
            Audit, Cx, LocalFiles, Today,
            catalogue::modules,
            evaluate,
            rules::{Level, Probe, Profile, REGISTRY, Rule, Status, allowance},
        },
        host::{
            HostError, HostErrorKind, RepoId,
            types::{Job, WorkflowRun},
        },
    };
    use std::{collections::BTreeMap, fs};

    const ANSWERS: &str = ".agent-setup/modules/ci-baseline.json";
    const CI_YML: &str = ".github/workflows/ci.yml";

    static REQUIRED_IS_AGGREGATE: &[Rule] = &[modules::CI_REQUIRED_IS_AGGREGATE];
    static MAIN_RED: &[Rule] = &[modules::CI_MAIN_RED];
    static MINUTES_MONTH: &[Rule] = &[modules::CI_MINUTES_MONTH];
    static WORKFLOW_LINT: &[Rule] = &[modules::CI_WORKFLOW_LINT];

    /// A recorded ci-baseline answers file with `answers` (a JSON object).
    fn answers(answers: &str) -> String {
        format!(r#"{{"module": "ci-baseline", "version": "1.0.0", "answers": {answers}}}"#)
    }
    fn golden(name: &str) -> String {
        fs::read_to_string(format!(
            "{}/../../templates/ci-baseline/goldens/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }
    fn example_app_ci() -> String {
        fs::read_to_string(format!(
            "{}/tests/fixtures/ci-baseline/monorepo-ci.yml",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }
    const EXISTING_EXAMPLE_APP: &str =
        r#"{"workflow": "existing", "aggregate_check": "all-checks-passed"}"#;

    /// Audits `rules` over `host` and a checkout of `files`, under `today`.
    fn audited(
        host: &FakeHost,
        files: &[(&str, &str)],
        today: Option<&Today<'_>>,
        rules: &'static [Rule],
    ) -> Audit {
        let dir = tempfile::tempdir().unwrap();
        for (path, text) in files {
            let path = dir.path().join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        }
        let local = LocalFiles::new(dir.path());
        let repo = RepoId::parse("acme/shop").unwrap();
        let cx = Cx {
            host,
            files: &local,
            repo: &repo,
            default_branch: "main",
            now: now(),
            budget: &host.budget,
            profile: Profile::P1,
            today,
        };
        evaluate(&cx, &dims(Profile::P1), rules)
    }
    const REMOTE: Today<'static> = Today {
        findings: &[],
        steps: &[],
        remote: true,
    };
    const OFFLINE: Today<'static> = Today {
        findings: &[],
        steps: &[],
        remote: false,
    };

    fn requiring(checks: &[&str]) -> FakeHost {
        let mut classic = protection(Some(false), Some(false));
        classic.required_status_checks = checks.iter().map(|c| (*c).to_owned()).collect();
        FakeHost {
            protection: Ok(Some(classic)),
            rulesets: Ok(Vec::new()),
            ..FakeHost::default()
        }
    }

    #[test]
    fn the_remote_ci_rules_are_registered_last_in_the_block_at_their_levels() {
        let ids: Vec<&str> = REGISTRY
            .iter()
            .filter(|r| r.id.starts_with("ci."))
            .map(|r| r.id)
            .collect();
        assert_eq!(
            &ids[ids.len() - 4..],
            [
                "ci.project-ci-stale",
                "ci.required-is-aggregate",
                "ci.main-red",
                "ci.minutes-month",
            ]
        );
        for (rule, level, probe) in [
            (
                &modules::CI_REQUIRED_IS_AGGREGATE,
                Level::Silver,
                "branch-protection+rulesets",
            ),
            (&modules::CI_MAIN_RED, Level::Silver, "workflow-runs"),
            (
                &modules::CI_MINUTES_MONTH,
                Level::Gold,
                "workflow-runs+jobs",
            ),
        ] {
            assert_eq!(rule.level, level, "{}", rule.id);
            assert_eq!(rule.how, Probe::Remote { id: probe }, "{}", rule.id);
            assert_eq!(
                rule.required.profiles,
                [Profile::P1, Profile::P2, Profile::P3],
                "{}",
                rule.id
            );
        }
        // The remote half reads the host under `doctor --remote` (#783).
        assert_eq!(
            modules::CI_WORKFLOW_LINT.how,
            Probe::Remote {
                id: "workflows+workflow-runs+jobs"
            }
        );
        // The allowances: the listing and the jobs of five runs for the
        // minutes, the jobs of one run for the lint; the rest from the cache.
        assert_eq!(allowance("ci.required-is-aggregate"), 0);
        assert_eq!(allowance("ci.main-red"), 0);
        assert_eq!(allowance("ci.minutes-month"), 6);
        assert_eq!(allowance("ci.workflow-lint"), 1);
    }

    // ci.required-is-aggregate

    #[test]
    fn required_is_aggregate_passes_when_the_default_branch_requires_only_required() {
        let host = requiring(&["required"]);
        let audit = audited(&host, &[], None, REQUIRED_IS_AGGREGATE);
        passed(
            &outcome(&audit, "ci.required-is-aggregate"),
            &["main requires only required"],
        );
    }

    #[test]
    fn required_is_aggregate_compares_with_the_recorded_aggregate_check_under_workflow_existing() {
        let host = requiring(&["all-checks-passed"]);
        let files = [(ANSWERS, answers(EXISTING_EXAMPLE_APP))];
        let files: Vec<(&str, &str)> = files.iter().map(|(p, t)| (*p, t.as_str())).collect();
        let audit = audited(&host, &files, None, REQUIRED_IS_AGGREGATE);
        passed(
            &outcome(&audit, "ci.required-is-aggregate"),
            &["main requires only all-checks-passed"],
        );
    }

    /// #1159: with contributed jobs (the lock records ci-baseline's
    /// `github:add-agentic-required-check`) the default branch also requires
    /// `agentic-required`, and the rule expects both.
    #[test]
    fn required_is_aggregate_expects_agentic_required_when_the_lock_records_its_item() {
        let lock = r#"{"files": {"github:add-agentic-required-check": {"module": "ci-baseline", "class": "remote"}}}"#;
        let files = [
            (ANSWERS, answers(EXISTING_EXAMPLE_APP)),
            (".agent-setup/lock.json", lock.to_owned()),
        ];
        let files: Vec<(&str, &str)> = files.iter().map(|(p, t)| (*p, t.as_str())).collect();
        let host = requiring(&["all-checks-passed", "agentic-required"]);
        let audit = audited(&host, &files, None, REQUIRED_IS_AGGREGATE);
        passed(
            &outcome(&audit, "ci.required-is-aggregate"),
            &["main requires only agentic-required, all-checks-passed"],
        );
        let host = requiring(&["all-checks-passed"]);
        let audit = audited(&host, &files, None, REQUIRED_IS_AGGREGATE);
        failed(
            &outcome(&audit, "ci.required-is-aggregate"),
            &[
                "Required checks are all-checks-passed; expected only agentic-required, all-checks-passed",
            ],
        );
    }

    /// #32: under `workflow: generate`, once the lock records ci-baseline's
    /// `github:switch-required-check`, the default branch requires what the
    /// switch leaves: a declared `ci.required_checks` that names `required`
    /// verbatim, else `required` alone.
    #[test]
    fn required_is_aggregate_expects_the_checks_the_switch_leaves() {
        let lock = r#"{"files": {"github:switch-required-check": {"module": "ci-baseline", "class": "remote"}}}"#;
        let profile = r#"{"ci": {"required_checks": ["required", "neutrality"]}}"#;
        let files = [
            (".agent-setup/lock.json", lock),
            (".agent-setup/project.json", profile),
        ];
        let host = requiring(&["required", "neutrality"]);
        let audit = audited(&host, &files, None, REQUIRED_IS_AGGREGATE);
        passed(
            &outcome(&audit, "ci.required-is-aggregate"),
            &["main requires only neutrality, required"],
        );
        // A declared list without `required` is superseded by `required`.
        let profile = r#"{"ci": {"required_checks": ["build", "neutrality"]}}"#;
        let files = [
            (".agent-setup/lock.json", lock),
            (".agent-setup/project.json", profile),
        ];
        let host = requiring(&["build", "neutrality"]);
        let audit = audited(&host, &files, None, REQUIRED_IS_AGGREGATE);
        failed(
            &outcome(&audit, "ci.required-is-aggregate"),
            &["Required checks are build, neutrality; expected only required"],
        );
    }

    #[test]
    fn required_is_aggregate_fails_naming_the_checks_required_from_rulesets_and_protection() {
        let mut ruleset = ruleset(7, &["required_status_checks"]);
        ruleset.required_status_checks = vec!["Rust (linux)".to_owned(), "promote".to_owned()];
        let mut classic = protection(Some(false), Some(false));
        classic.required_status_checks = vec!["promote".to_owned(), "Rust (macos)".to_owned()];
        let host = FakeHost {
            protection: Ok(Some(classic)),
            rulesets: Ok(vec![ruleset]),
            ..FakeHost::default()
        };
        let audit = audited(&host, &[], None, REQUIRED_IS_AGGREGATE);
        failed(
            &outcome(&audit, "ci.required-is-aggregate"),
            &["Required checks are Rust (linux), Rust (macos), promote; expected only required"],
        );
    }

    #[test]
    fn required_is_aggregate_fails_when_nothing_is_required() {
        let host = FakeHost {
            protection: Ok(None),
            rulesets: Ok(Vec::new()),
            ..FakeHost::default()
        };
        let audit = audited(&host, &[], None, REQUIRED_IS_AGGREGATE);
        failed(
            &outcome(&audit, "ci.required-is-aggregate"),
            &["Required checks are none; expected only required"],
        );
    }

    #[test]
    fn required_is_aggregate_is_unavailable_when_a_source_cannot_be_read() {
        // A transport failure on either source says nothing about the other.
        let lost = HostError::new(
            HostErrorKind::Transport,
            "Reading rulesets of acme/shop failed: connection reset",
        );
        let host = FakeHost {
            protection: Ok(Some(protection(Some(false), Some(false)))),
            rulesets: Err(lost.clone()),
            ..FakeHost::default()
        };
        let audit = audited(&host, &[], None, REQUIRED_IS_AGGREGATE);
        unavailable(&outcome(&audit, "ci.required-is-aggregate"), &lost.message);
        // Both sources refused by the plan: the feature needs a plan, as posture says.
        let host = FakeHost::failing(&plan_refused(PLAN_403));
        let audit = audited(&host, &[], None, REQUIRED_IS_AGGREGATE);
        unavailable(
            &outcome(&audit, "ci.required-is-aggregate"),
            "requires plan Team",
        );
    }

    #[test]
    fn required_is_aggregate_is_unavailable_when_the_answers_file_does_not_parse() {
        let host = requiring(&["required"]);
        let audit = audited(&host, &[(ANSWERS, "{")], None, REQUIRED_IS_AGGREGATE);
        unavailable(
            &outcome(&audit, "ci.required-is-aggregate"),
            ".agent-setup/modules/ci-baseline.json does not parse",
        );
    }

    #[test]
    fn example_app_recorded_required_is_aggregate() {
        // example-app requires its own aggregate; the default expects `required`.
        let (audit, _) =
            recorded_together(&["posture/example-app"], &[], &[], REQUIRED_IS_AGGREGATE, 0);
        failed(
            &outcome(&audit, "ci.required-is-aggregate"),
            &["Required checks are all-checks-passed; expected only required"],
        );
        // Recorded as `workflow: existing` with its aggregate, it passes.
        let recorded_answers = answers(EXISTING_EXAMPLE_APP);
        let (audit, calls) = recorded_together(
            &["posture/example-app"],
            &[],
            &[(ANSWERS, &recorded_answers)],
            REQUIRED_IS_AGGREGATE,
            0,
        );
        passed(
            &outcome(&audit, "ci.required-is-aggregate"),
            &["main requires only all-checks-passed"],
        );
        // The rulesets and the classic protection: what posture reads too.
        assert_eq!(calls, 2);
    }

    // ci.main-red

    fn main_runs(conclusions: &[&str]) -> FakeHost {
        FakeHost {
            runs: Ok(conclusions
                .iter()
                .enumerate()
                .map(|(i, c)| wrun(100 + i as u64, "CI", "main", Some(c), 1))
                .collect()),
            ..FakeHost::default()
        }
    }

    #[test]
    fn main_red_passes_when_the_latest_conclusive_run_of_the_aggregates_workflow_succeeded() {
        let host = main_runs(&["cancelled", "success", "failure"]);
        let ci = example_app_ci();
        let recorded = answers(EXISTING_EXAMPLE_APP);
        let audit = audited(
            &host,
            &[(CI_YML, &ci), (ANSWERS, &recorded)],
            None,
            MAIN_RED,
        );
        passed(
            &outcome(&audit, "ci.main-red"),
            &["the latest conclusive push run of CI on main, run 101, succeeded"],
        );
    }

    #[test]
    fn main_red_fails_naming_the_run_and_its_conclusion() {
        let host = main_runs(&["failure", "success"]);
        let ci = example_app_ci();
        let recorded = answers(EXISTING_EXAMPLE_APP);
        let audit = audited(
            &host,
            &[(CI_YML, &ci), (ANSWERS, &recorded)],
            None,
            MAIN_RED,
        );
        failed(
            &outcome(&audit, "ci.main-red"),
            &["Latest main cycle is red: run 100 of CI on main concluded failure"],
        );
    }

    #[test]
    fn main_red_judges_only_the_workflows_that_declare_the_aggregate() {
        let host = FakeHost {
            runs: Ok(vec![
                wrun(100, "Uptime", "main", Some("failure"), 1),
                wrun(101, "CI", "main", Some("success"), 1),
            ]),
            ..FakeHost::default()
        };
        let ci = example_app_ci();
        let recorded = answers(EXISTING_EXAMPLE_APP);
        let audit = audited(
            &host,
            &[(CI_YML, &ci), (ANSWERS, &recorded)],
            None,
            MAIN_RED,
        );
        passed(
            &outcome(&audit, "ci.main-red"),
            &["the latest conclusive push run of CI on main, run 101, succeeded"],
        );
    }

    #[test]
    fn main_red_is_unavailable_without_a_run_a_workflow_or_the_host() {
        let ci = example_app_ci();
        let recorded = answers(EXISTING_EXAMPLE_APP);
        let host = main_runs(&["cancelled"]);
        let audit = audited(
            &host,
            &[(CI_YML, &ci), (ANSWERS, &recorded)],
            None,
            MAIN_RED,
        );
        unavailable(
            &outcome(&audit, "ci.main-red"),
            "no completed push run of CI on main among the latest 100 that was neither cancelled nor skipped",
        );
        // Without the answers the aggregate is `required`, which example-app's workflow lacks.
        let audit = audited(&host, &[(CI_YML, &ci)], None, MAIN_RED);
        unavailable(
            &outcome(&audit, "ci.main-red"),
            "no workflow under .github/workflows declares a job named required",
        );
        let host = FakeHost::failing(&plan_refused(PLAN_403));
        let audit = audited(
            &host,
            &[(CI_YML, &ci), (ANSWERS, &recorded)],
            None,
            MAIN_RED,
        );
        unavailable(&outcome(&audit, "ci.main-red"), PLAN_403);
    }

    #[test]
    fn example_app_recorded_main_red() {
        let ci = example_app_ci();
        let recorded = answers(EXISTING_EXAMPLE_APP);
        let (audit, calls) = recorded_together(
            &["ci-health/example-app"],
            &[],
            &[(CI_YML, &ci), (ANSWERS, &recorded)],
            MAIN_RED,
            0,
        );
        passed(
            &outcome(&audit, "ci.main-red"),
            &["the latest conclusive push run of CI on main, run 40862628372, succeeded"],
        );
        // The listing ci-health.workflow-exists reads: one call, shared.
        assert_eq!(calls, 1);
    }

    // ci.minutes-month

    /// A job that ran `seconds` seconds.
    fn job_ran(name: &str, seconds: u32) -> Job {
        Job {
            started_at: Some("2026-10-27T10:00:00Z".to_owned()),
            completed_at: Some(format!(
                "2026-10-27T10:{:02}:{:02}Z",
                seconds / 60,
                seconds % 60
            )),
            ..job_done(name, 0)
        }
    }
    fn run_on(id: u64, created: &str) -> WorkflowRun {
        WorkflowRun {
            created_at: Some(created.to_owned()),
            ..wrun(id, "CI", "main", Some("success"), 1)
        }
    }

    #[test]
    fn minutes_month_sums_each_job_rounded_up_to_the_minute_over_the_last_30_days() {
        let host = FakeHost {
            runs: Ok(vec![
                run_on(1, "2026-10-27T10:00:00Z"),
                run_on(2, "2026-09-28T00:00:00Z"),
                // Older than 30 days: outside the window.
                run_on(3, "2026-09-27T23:59:59Z"),
            ]),
            jobs: BTreeMap::from([
                (
                    1,
                    vec![
                        job_ran("checks", 30),
                        job_ran("required", 130),
                        Job {
                            conclusion: Some("skipped".to_owned()),
                            ..job_ran("macos", 0)
                        },
                    ],
                ),
                (2, vec![job_ran("checks", 59)]),
                (3, vec![job_ran("checks", 3600)]),
            ]),
            ..FakeHost::default()
        };
        let audit = audited(&host, &[], None, MINUTES_MONTH);
        passed(
            &outcome(&audit, "ci.minutes-month"),
            &[
                "Billed about 5 minutes in 30 days; budget 2000",
                "the jobs of 2 of 2 completed runs since 2026-09-28, each rounded up to the minute",
            ],
        );
        assert_eq!(host.count("workflow_runs"), 1);
        assert_eq!(host.count("jobs"), 2);
    }

    #[test]
    fn minutes_month_fails_over_the_recorded_budget() {
        let host = FakeHost {
            runs: Ok(vec![run_on(1, "2026-10-27T10:00:00Z")]),
            jobs: BTreeMap::from([(1, vec![job_ran("checks", 240)])]),
            ..FakeHost::default()
        };
        let recorded = answers(r#"{"minutes_budget": 3}"#);
        let audit = audited(&host, &[(ANSWERS, &recorded)], None, MINUTES_MONTH);
        failed(
            &outcome(&audit, "ci.minutes-month"),
            &[
                "Billed about 4 minutes in 30 days; budget 3",
                "the jobs of 1 of 1 completed runs since 2026-09-28, each rounded up to the minute",
            ],
        );
    }

    #[test]
    fn minutes_month_extrapolates_from_the_sample_it_reads() {
        let runs: Vec<WorkflowRun> = (1..=12)
            .map(|i| run_on(i, "2026-10-20T10:00:00Z"))
            .collect();
        let jobs = (1..=12)
            .map(|i| (i, vec![job_ran("checks", 120)]))
            .collect();
        let host = FakeHost {
            runs: Ok(runs),
            jobs,
            ..FakeHost::default()
        };
        let audit = audited(&host, &[], None, MINUTES_MONTH);
        passed(
            &outcome(&audit, "ci.minutes-month"),
            &[
                "Billed about 24 minutes in 30 days; budget 2000",
                "the jobs of 10 of 12 completed runs since 2026-09-28, each rounded up to the minute, extrapolated to the 12",
            ],
        );
        assert_eq!(host.count("jobs"), 10);
    }

    #[test]
    fn minutes_month_cut_by_the_budget_is_judged_on_five_runs_or_more_and_unavailable_below() {
        let runs: Vec<WorkflowRun> = (1..=12)
            .map(|i| run_on(i, "2026-10-20T10:00:00Z"))
            .collect();
        let jobs: BTreeMap<u64, Vec<Job>> = (1..=12)
            .map(|i| (i, vec![job_ran("checks", 120)]))
            .collect();
        let host = FakeHost {
            runs: Ok(runs.clone()),
            jobs: jobs.clone(),
            ..FakeHost::default()
        };
        // The listing and five jobs fit; the sixth read is refused.
        for _ in 0..54 {
            host.budget.spend().unwrap();
        }
        let audit = audited(&host, &[], None, MINUTES_MONTH);
        passed(
            &outcome(&audit, "ci.minutes-month"),
            &[
                "Billed about 24 minutes in 30 days; budget 2000",
                "the jobs of 5 of 12 completed runs since 2026-09-28, each rounded up to the minute, extrapolated to the 12 (the call budget stopped it at 5 of 10 runs)",
            ],
        );
        let host = FakeHost {
            runs: Ok(runs),
            jobs,
            ..FakeHost::default()
        };
        for _ in 0..56 {
            host.budget.spend().unwrap();
        }
        let audit = audited(&host, &[], None, MINUTES_MONTH);
        unavailable(
            &outcome(&audit, "ci.minutes-month"),
            "budget exhausted: call budget of 60 exhausted",
        );
    }

    #[test]
    fn minutes_month_without_a_run_in_the_window_bills_nothing() {
        let host = FakeHost {
            runs: Ok(Vec::new()),
            ..FakeHost::default()
        };
        let audit = audited(&host, &[], None, MINUTES_MONTH);
        passed(
            &outcome(&audit, "ci.minutes-month"),
            &[
                "Billed about 0 minutes in 30 days; budget 2000",
                "no completed run since 2026-09-28",
            ],
        );
    }

    #[test]
    fn minutes_month_is_unavailable_when_the_runs_cannot_be_listed() {
        let host = FakeHost::failing(&plan_refused(PLAN_403));
        let audit = audited(&host, &[], None, MINUTES_MONTH);
        unavailable(&outcome(&audit, "ci.minutes-month"), PLAN_403);
    }

    #[test]
    fn example_app_recorded_minutes_month() {
        // The 30-day listing is the recorded push listing re-keyed: every one
        // of its 100 completed runs was created inside the window.
        let fixture: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(format!(
                "{}/tests/fixtures/auditor/ci-health/example-app.json",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap(),
        )
        .unwrap();
        let listing = fixture["replies"]
            ["repos/example-org/example-app/actions/runs?branch=main&event=push&status=completed&per_page=100&page=1"]
            .clone();
        let month = "repos/example-org/example-app/actions/runs?status=completed&created=%3E%3D2026-09-28&per_page=100&page=1";
        let (audit, calls) = recorded_together(
            &["ci-health/example-app"],
            &[(month, listing)],
            &[],
            MINUTES_MONTH,
            0,
        );
        // Computed apart from the rule: the recorded jobs of the first 10 runs
        // bill one minute each, extrapolated to the 100 listed.
        passed(
            &outcome(&audit, "ci.minutes-month"),
            &[
                "Billed about 100 minutes in 30 days; budget 2000",
                "the jobs of 10 of 100 completed runs since 2026-09-28, each rounded up to the minute, extrapolated to the 100 listed; earlier runs of the window are not counted",
            ],
        );
        assert_eq!(calls, 11);
    }

    // ci.workflow-lint: the remote half (SPEC-ci-baseline.md, "Workflow lint red on main")

    fn lint_host(conclusion: Option<&str>) -> FakeHost {
        let jobs = match conclusion {
            Some(c) => vec![Job {
                conclusion: Some(c.to_owned()),
                ..job_done("workflow-lint", 1)
            }],
            None => vec![job_done("checks", 1)],
        };
        FakeHost {
            runs: Ok(vec![wrun(7, "CI", "main", Some("success"), 1)]),
            jobs: BTreeMap::from([(7, jobs)]),
            ..FakeHost::default()
        }
    }

    #[test]
    fn workflow_lint_passes_under_remote_when_the_jobs_last_push_run_succeeded() {
        let host = lint_host(Some("success"));
        let single = golden("single.yml");
        let audit = audited(&host, &[(CI_YML, &single)], Some(&REMOTE), WORKFLOW_LINT);
        passed(
            &outcome(&audit, "ci.workflow-lint"),
            &["workflow-lint succeeded in run 7 of CI on main"],
        );
        assert_eq!(host.count("jobs"), 1);
    }

    #[test]
    fn workflow_lint_fails_under_remote_when_the_job_is_red_on_main() {
        let host = lint_host(Some("failure"));
        let single = golden("single.yml");
        let audit = audited(&host, &[(CI_YML, &single)], Some(&REMOTE), WORKFLOW_LINT);
        failed(
            &outcome(&audit, "ci.workflow-lint"),
            &["Workflow lint red on main: job workflow-lint of run 7 of CI concluded failure"],
        );
    }

    #[test]
    fn workflow_lint_is_unavailable_under_remote_without_a_run_or_the_job_in_it() {
        let single = golden("single.yml");
        let host = lint_host(None);
        let audit = audited(&host, &[(CI_YML, &single)], Some(&REMOTE), WORKFLOW_LINT);
        unavailable(
            &outcome(&audit, "ci.workflow-lint"),
            "run 7 of CI on main has no job workflow-lint",
        );
        let host = FakeHost {
            runs: Ok(Vec::new()),
            ..FakeHost::default()
        };
        let audit = audited(&host, &[(CI_YML, &single)], Some(&REMOTE), WORKFLOW_LINT);
        unavailable(
            &outcome(&audit, "ci.workflow-lint"),
            "no completed push run of CI on main among the latest 100 that was neither cancelled nor skipped",
        );
        let host = FakeHost::failing(&plan_refused(PLAN_403));
        let audit = audited(&host, &[(CI_YML, &single)], Some(&REMOTE), WORKFLOW_LINT);
        unavailable(&outcome(&audit, "ci.workflow-lint"), PLAN_403);
    }

    #[test]
    fn workflow_lint_keeps_the_static_verdict_offline_and_a_static_finding_reads_nothing() {
        let single = golden("single.yml");
        let host = lint_host(Some("failure"));
        let audit = audited(&host, &[(CI_YML, &single)], Some(&OFFLINE), WORKFLOW_LINT);
        passed(
            &outcome(&audit, "ci.workflow-lint"),
            &["today's doctor reports none"],
        );
        assert_eq!(host.count("workflow_runs"), 0);
        let findings = ["WARNING: ci.workflow-lint: Workflow lint absent".to_owned()];
        let today = Today {
            findings: &findings,
            steps: &[],
            remote: true,
        };
        let host = lint_host(Some("success"));
        let audit = audited(&host, &[(CI_YML, &single)], Some(&today), WORKFLOW_LINT);
        failed(
            &outcome(&audit, "ci.workflow-lint"),
            &["Workflow lint absent"],
        );
        assert_eq!(host.count("workflow_runs"), 0);
        // Under --fleet there is no checkout to judge the static half in.
        let audit = audited(&host, &[(CI_YML, &single)], None, WORKFLOW_LINT);
        not_required(
            &outcome(&audit, "ci.workflow-lint"),
            "no checkout under --fleet",
        );
    }

    #[test]
    fn the_rules_read_nothing_before_a_remote_audit_through_the_offline_host() {
        let host = brakes::auditor::offline_host();
        let dir = tempfile::tempdir().unwrap();
        for (path, text) in [
            (CI_YML, example_app_ci()),
            (ANSWERS, answers(EXISTING_EXAMPLE_APP)),
        ] {
            let path = dir.path().join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        }
        let local = LocalFiles::new(dir.path());
        let repo = RepoId::parse("acme/shop").unwrap();
        let cx = Cx {
            host: &host,
            files: &local,
            repo: &repo,
            default_branch: "main",
            now: now(),
            budget: host.budget(),
            profile: Profile::P1,
            today: Some(&OFFLINE),
        };
        let rules: &'static [Rule] = &[
            modules::CI_REQUIRED_IS_AGGREGATE,
            modules::CI_MAIN_RED,
            modules::CI_MINUTES_MONTH,
        ];
        let audit = evaluate(&cx, &dims(Profile::P1), rules);
        for rule in rules {
            let o = outcome(&audit, rule.id);
            assert_eq!(o.status, Status::Unavailable, "{}: {o:?}", rule.id);
            assert!(
                o.reason
                    .as_deref()
                    .unwrap_or_default()
                    .contains("without --remote"),
                "{}: {o:?}",
                rule.id
            );
        }
    }
}

// --- qa.main-green (SPEC-qa.md, Auditor rules; T19 #1018) ----------------------------
// Replays the synthetic `example-org/example-api` recording: its default-branch push
// runs and the jobs of two `CI` runs, where the QA job is `e2e` (`npx playwright test`)
// in `fixtures/qa/example-api-ci.yml`. The red and the never-ran cases change one reply.

mod qa_main_green {
    use super::{Replay, dims, failed, not_required, now, outcome, passed, unavailable};
    use brakes::{
        auditor::{
            Audit, Cx, LocalFiles, Today,
            catalogue::qa,
            evaluate,
            rules::{Profile, Rule},
        },
        host::{CallBudget, RepoId, github::GitHub},
    };
    use serde_json::{Value, json};
    use std::{cell::RefCell, fs};

    static MAIN_GREEN: &[Rule] = &[qa::MAIN_GREEN];
    const CI_YML: &str = ".github/workflows/ci.yml";
    const REPO: &str = "example-org/example-api";
    const LISTING: &str = "repos/example-org/example-api/actions/runs?branch=main&event=push&status=completed&per_page=100&page=1";
    const GREEN_RUN: u64 = 40970587970;
    const SKIPPED_RUN: u64 = 40768459286;
    const REMOTE: Today<'static> = Today {
        findings: &[],
        steps: &[],
        remote: true,
    };
    const OFFLINE: Today<'static> = Today {
        findings: &[],
        steps: &[],
        remote: false,
    };

    fn recording() -> Value {
        let path = format!(
            "{}/tests/fixtures/auditor/qa/example-api.json",
            env!("CARGO_MANIFEST_DIR")
        );
        serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
    }
    fn example_api_ci() -> String {
        fs::read_to_string(format!(
            "{}/tests/fixtures/qa/example-api-ci.yml",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }
    fn jobs_key(run: u64) -> String {
        format!("repos/{REPO}/actions/runs/{run}/jobs?per_page=100&page=1")
    }

    /// Audits `qa.main-green` under `today` over the recorded replies, changed by
    /// `edit`, and a checkout of `files`.
    fn audited(
        today: Option<&Today<'_>>,
        files: &[(&str, &str)],
        edit: impl FnOnce(&mut serde_json::Map<String, Value>),
    ) -> Audit {
        let mut replies = recording()["replies"].as_object().unwrap().clone();
        edit(&mut replies);
        let replay = Replay {
            replies,
            gets: RefCell::default(),
        };
        let host = GitHub::new(&replay, CallBudget::new(60));
        let repo = RepoId::parse(REPO).unwrap();
        let dir = tempfile::tempdir().unwrap();
        for (file, text) in files {
            let file = dir.path().join(file);
            fs::create_dir_all(file.parent().unwrap()).unwrap();
            fs::write(file, text).unwrap();
        }
        let local = LocalFiles::new(dir.path());
        let cx = Cx {
            host: &host,
            files: &local,
            repo: &repo,
            default_branch: "main",
            now: now(),
            budget: host.budget(),
            profile: Profile::P1,
            today,
        };
        evaluate(&cx, &dims(Profile::P1), MAIN_GREEN)
    }

    /// The recorded listing with only the `CI` runs `ids`, in that order.
    fn only_runs(replies: &mut serde_json::Map<String, Value>, ids: &[u64]) {
        let all = replies[LISTING]["body"]["workflow_runs"]
            .as_array()
            .unwrap()
            .clone();
        let runs: Vec<Value> = ids
            .iter()
            .map(|id| all.iter().find(|r| r["id"] == json!(id)).unwrap().clone())
            .collect();
        replies[LISTING]["body"]["workflow_runs"] = json!(runs);
        replies[LISTING]["body"]["total_count"] = json!(runs.len());
    }

    fn e2e_concluded(replies: &mut serde_json::Map<String, Value>, run: u64, conclusion: &str) {
        let jobs = replies.get_mut(&jobs_key(run)).unwrap()["body"]["jobs"]
            .as_array_mut()
            .unwrap();
        let job = jobs.iter_mut().find(|j| j["name"] == "e2e").unwrap();
        job["conclusion"] = json!(conclusion);
    }

    #[test]
    fn green_when_the_qa_job_succeeded_in_the_latest_main_run() {
        let ci = example_api_ci();
        let audit = audited(Some(&REMOTE), &[(CI_YML, &ci)], |_| {});
        passed(
            &outcome(&audit, "qa.main-green"),
            &[&format!(
                "QA job e2e succeeded in run {GREEN_RUN} of CI on main"
            )],
        );
    }

    #[test]
    fn red_names_the_job_the_run_and_its_conclusion() {
        let ci = example_api_ci();
        let audit = audited(Some(&REMOTE), &[(CI_YML, &ci)], |r| {
            e2e_concluded(r, GREEN_RUN, "failure")
        });
        failed(
            &outcome(&audit, "qa.main-green"),
            &[&format!(
                "QA job e2e red on main: run {GREEN_RUN} of CI concluded failure"
            )],
        );
    }

    #[test]
    fn any_red_matrix_instance_makes_the_qa_job_red() {
        // `e2e` as a matrix: the recorded instance succeeded, a second one failed.
        let ci = example_api_ci();
        let audit = audited(Some(&REMOTE), &[(CI_YML, &ci)], |r| {
            let jobs = r.get_mut(&jobs_key(GREEN_RUN)).unwrap()["body"]["jobs"]
                .as_array_mut()
                .unwrap();
            let e2e = jobs.iter().position(|j| j["name"] == "e2e").unwrap();
            let mut chromium = jobs[e2e].clone();
            chromium["name"] = json!("e2e (chromium)");
            let mut webkit = jobs[e2e].clone();
            webkit["name"] = json!("e2e (webkit)");
            webkit["conclusion"] = json!("failure");
            jobs.splice(e2e..=e2e, [chromium, webkit]);
        });
        failed(
            &outcome(&audit, "qa.main-green"),
            &[&format!(
                "QA job e2e red on main: run {GREEN_RUN} of CI concluded failure"
            )],
        );
    }

    #[test]
    fn a_run_that_skipped_the_qa_job_is_not_its_latest_run() {
        // The recorded run where `e2e` was skipped (a path filter) comes first.
        let ci = example_api_ci();
        let audit = audited(Some(&REMOTE), &[(CI_YML, &ci)], |r| {
            only_runs(r, &[SKIPPED_RUN, GREEN_RUN])
        });
        passed(
            &outcome(&audit, "qa.main-green"),
            &[&format!(
                "QA job e2e succeeded in run {GREEN_RUN} of CI on main"
            )],
        );
    }

    #[test]
    fn no_run_yet_is_unavailable() {
        let ci = example_api_ci();
        let audit = audited(Some(&REMOTE), &[(CI_YML, &ci)], |r| only_runs(r, &[]));
        unavailable(
            &outcome(&audit, "qa.main-green"),
            "QA job e2e has not run on main: no completed push run of CI among the latest 100",
        );
        let audit = audited(Some(&REMOTE), &[(CI_YML, &ci)], |r| {
            only_runs(r, &[SKIPPED_RUN])
        });
        unavailable(
            &outcome(&audit, "qa.main-green"),
            "QA job e2e has not run on main: skipped or cancelled in the latest 1 conclusive push runs of CI",
        );
    }

    #[test]
    fn unreadable_jobs_are_unavailable_with_the_host_s_reason() {
        let ci = example_api_ci();
        let audit = audited(Some(&REMOTE), &[(CI_YML, &ci)], |r| {
            r.insert(
                jobs_key(GREEN_RUN),
                json!({"status": 502, "message": "Bad gateway"}),
            );
        });
        let o = outcome(&audit, "qa.main-green");
        assert_eq!(
            o.status,
            brakes::auditor::rules::Status::Unavailable,
            "{o:?}"
        );
        assert!(
            o.reason.as_deref().unwrap_or("").contains("jobs of run"),
            "{o:?}"
        );
    }

    #[test]
    fn not_required_without_a_qa_job_unavailable_offline_and_not_required_under_fleet() {
        let plain = "name: CI\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: cargo test\n";
        let audit = audited(Some(&REMOTE), &[(CI_YML, plain)], |_| {});
        not_required(
            &outcome(&audit, "qa.main-green"),
            "no QA job (hurl --test or playwright test) in .github/workflows",
        );
        let ci = example_api_ci();
        let audit = audited(Some(&OFFLINE), &[(CI_YML, &ci)], |_| {});
        unavailable(
            &outcome(&audit, "qa.main-green"),
            "remote findings run only with doctor --remote",
        );
        let audit = audited(None, &[(CI_YML, &ci)], |_| {});
        not_required(
            &outcome(&audit, "qa.main-green"),
            "no checkout under --fleet",
        );
    }
}
