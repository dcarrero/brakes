//! The auditor's core (SPEC-auditor.md, #709): the level algorithm, the exit
//! codes, the first local Basic rules and the registry invariant against the
//! allocation recorded in docs/decisions.md ("Auditor standard v1", #706).
//! Pure evaluation: the host is a fake that answers `Unsupported`, no `gh` runs.
mod support;
use brakes::{
    auditor::{
        Audit, Cx, Dimensions, Files, LocalFiles, Today, audit,
        catalogue::baseline,
        evaluate, plan_gate,
        rules::{
            Block, Cadence, Condition, Criticality, Level, Milestone, Outcome, Plan, Probe,
            Profile, REGISTRY, Remediation, Required, Rule, Status,
        },
    },
    host::{
        Availability, CallBudget, Features, Host, HostError, HostKind, OwnerId, Partial, RepoId,
        SecretName, SecretScope, Visibility, types,
    },
};
use chrono::NaiveDate;
use std::{collections::BTreeSet, fs, path::Path};

// --- fakes ----------------------------------------------------------------------

/// A host that answers `Unsupported` everywhere except `features`, which says
/// what the test needs about plan-dependent features.
struct FakeHost {
    rulesets: Availability,
}
impl FakeHost {
    fn none() -> Self {
        Self {
            rulesets: Availability::Available,
        }
    }
}
impl Host for FakeHost {
    fn kind(&self) -> HostKind {
        HostKind::GitHub
    }
    fn repository(&self, repo: &RepoId) -> Result<types::RepositorySettings, HostError> {
        Err(HostError::unsupported("repository", repo))
    }
    fn features(&self, _repo: &RepoId) -> Result<Features, HostError> {
        Ok(Features {
            visibility: Visibility::Private,
            plan_hint: None,
            rulesets: self.rulesets.clone(),
            environments: Availability::Available,
            branch_protection: Availability::Available,
            required_reviewers: Availability::Available,
            dependabot_alerts: Availability::Available,
            secret_scanning: Availability::Available,
            workflow_lockfile: Availability::Available,
            merge_queue: Availability::Available,
        })
    }
    fn branch_protection(
        &self,
        repo: &RepoId,
        _branch: &str,
    ) -> Result<Option<types::BranchProtection>, HostError> {
        Err(HostError::unsupported("branch_protection", repo))
    }
    fn rulesets(&self, repo: &RepoId) -> Result<Vec<types::Ruleset>, HostError> {
        Err(HostError::unsupported("rulesets", repo))
    }
    fn environments(&self, repo: &RepoId) -> Result<Vec<types::Environment>, HostError> {
        Err(HostError::unsupported("environments", repo))
    }
    fn secret_names(
        &self,
        repo: &RepoId,
        _scope: &SecretScope,
    ) -> Result<Vec<SecretName>, HostError> {
        Err(HostError::unsupported("secret_names", repo))
    }
    fn workflow_runs(
        &self,
        repo: &RepoId,
        _filter: &types::RunFilter,
    ) -> Result<Vec<types::WorkflowRun>, HostError> {
        Err(HostError::unsupported("workflow_runs", repo))
    }
    fn jobs(&self, repo: &RepoId, _run_id: u64) -> Result<Vec<types::Job>, HostError> {
        Err(HostError::unsupported("jobs", repo))
    }
    fn check_runs(&self, repo: &RepoId, _sha: &str) -> Result<Vec<types::CheckRun>, HostError> {
        Err(HostError::unsupported("check_runs", repo))
    }
    fn collaborators(&self, repo: &RepoId) -> Result<Vec<types::Collaborator>, HostError> {
        Err(HostError::unsupported("collaborators", repo))
    }
    fn deployments(
        &self,
        repo: &RepoId,
        _environment: Option<&str>,
    ) -> Result<Vec<types::Deployment>, HostError> {
        Err(HostError::unsupported("deployments", repo))
    }
    fn issues(
        &self,
        repo: &RepoId,
        _filter: &types::IssueFilter,
    ) -> Result<Vec<types::IssueMeta>, HostError> {
        Err(HostError::unsupported("issues", repo))
    }
    fn pulls(
        &self,
        repo: &RepoId,
        _filter: &types::PullFilter,
    ) -> Result<Vec<types::PullMeta>, HostError> {
        Err(HostError::unsupported("pulls", repo))
    }
    fn file_exists(
        &self,
        repo: &RepoId,
        _path: &str,
        _reference: &str,
    ) -> Result<Option<String>, HostError> {
        Err(HostError::unsupported("file_exists", repo))
    }
    fn owner(&self, name: &str) -> Result<OwnerId, HostError> {
        Err(HostError::new(
            brakes::host::HostErrorKind::Unsupported,
            format!("owner {name} is not supported by this fake"),
        ))
    }
    fn list_repositories(&self, owner: &OwnerId) -> Result<Partial<types::RepoSummary>, HostError> {
        Err(HostError::new(
            brakes::host::HostErrorKind::Unsupported,
            format!("listing {owner} is not supported by this fake"),
        ))
    }
    fn org_rulesets(&self, org: &str) -> Result<Vec<types::Ruleset>, HostError> {
        Err(HostError::new(
            brakes::host::HostErrorKind::Unsupported,
            format!("rulesets of {org} are not supported by this fake"),
        ))
    }
    fn org_settings(&self, org: &str) -> Result<types::OrgSettings, HostError> {
        Err(HostError::new(
            brakes::host::HostErrorKind::Unsupported,
            format!("settings of {org} are not supported by this fake"),
        ))
    }
    fn ensure_labels(
        &self,
        token: &brakes::host::WriteToken,
        _labels: &[types::Label],
    ) -> Result<types::WriteReport, HostError> {
        panic!(
            "the auditor never writes: ensure_labels on {}",
            token.repo()
        )
    }
    fn create_issue(
        &self,
        token: &brakes::host::WriteToken,
        _issue: &types::NewIssue,
    ) -> Result<types::IssueMeta, HostError> {
        panic!("the auditor never writes: create_issue on {}", token.repo())
    }
    fn comment(
        &self,
        token: &brakes::host::WriteToken,
        _number: u64,
        _body: &str,
    ) -> Result<u64, HostError> {
        panic!("the auditor never writes: comment on {}", token.repo())
    }
    fn set_repository_settings(
        &self,
        token: &brakes::host::WriteToken,
        _settings: &types::RepositorySettingsPatch,
    ) -> Result<types::WriteReport, HostError> {
        panic!("the auditor never writes: settings on {}", token.repo())
    }
    fn put_ruleset(
        &self,
        token: &brakes::host::WriteToken,
        _ruleset: &types::Ruleset,
    ) -> Result<types::WriteReport, HostError> {
        panic!("the auditor never writes: ruleset on {}", token.repo())
    }
    fn put_environment(
        &self,
        token: &brakes::host::WriteToken,
        _environment: &types::EnvironmentSpec,
    ) -> Result<types::WriteReport, HostError> {
        panic!("the auditor never writes: environment on {}", token.repo())
    }
}

fn repo() -> RepoId {
    RepoId::parse("example-owner/example").unwrap()
}
fn now() -> NaiveDate {
    NaiveDate::from_ymd_opt(2026, 10, 28).unwrap()
}
fn p1() -> Dimensions {
    Dimensions {
        profile: Profile::P1,
        cadence: None,
        services: None,
        criticality: None,
        humans: None,
    }
}

/// Runs `rules` over an empty checkout with a fake host.
fn run(rules: &'static [Rule], dims: &Dimensions, host: &FakeHost) -> Audit {
    let dir = tempfile::tempdir().unwrap();
    let files = LocalFiles::new(dir.path());
    let repo = repo();
    let budget = CallBudget::new(60);
    let cx = Cx {
        host,
        files: &files,
        repo: &repo,
        default_branch: "main",
        now: now(),
        budget: &budget,
        profile: Profile::P1,
        today: None,
    };
    evaluate(&cx, dims, rules)
}

fn status_of(audit: &Audit, id: &str) -> Status {
    audit
        .rules
        .iter()
        .find(|e| e.rule.id == id)
        .unwrap_or_else(|| panic!("{id} not evaluated"))
        .outcome
        .status
}

// --- test rules -------------------------------------------------------------------

fn pass(_: &Cx<'_>) -> Outcome {
    Outcome::passed(["checked"])
}
fn fail(_: &Cx<'_>) -> Outcome {
    Outcome::failed(["missing"])
}
fn unavailable(_: &Cx<'_>) -> Outcome {
    Outcome::unavailable("token cannot read it (HTTP 403)")
}
fn rulesets_gated(cx: &Cx<'_>) -> Outcome {
    match cx.host.features(cx.repo) {
        Ok(features) => plan_gate(Plan::Team, &features.rulesets)
            .unwrap_or_else(|| Outcome::failed(["no ruleset targets main"])),
        Err(e) => Outcome::unavailable(e.message),
    }
}

const ALL: &[Profile] = &[Profile::P1, Profile::P2, Profile::P3];

const fn rule(
    id: &'static str,
    level: Level,
    required: Required,
    evaluate: fn(&Cx<'_>) -> Outcome,
) -> Rule {
    Rule {
        id,
        title: "test rule",
        block: Block::Posture,
        checks: "A test condition holds.",
        how: Probe::Remote { id: "test" },
        level,
        required,
        remediation: Remediation::Command {
            text: "fix it by hand",
        },
        plan: None,
        feasible_by: Milestone::Nov7,
        evaluate,
    }
}
const fn everyone() -> Required {
    Required {
        profiles: ALL,
        when: &[],
    }
}

/// Every Basic, Bronze and Silver rule passes except one Bronze failure.
static SILVER_WITH_BRONZE_FAILURE: &[Rule] = &[
    rule("posture.basic-a", Level::Basic, everyone(), pass),
    rule("posture.bronze-a", Level::Bronze, everyone(), fail),
    rule("posture.bronze-b", Level::Bronze, everyone(), pass),
    rule("posture.silver-a", Level::Silver, everyone(), pass),
];

static BRONZE_UNAVAILABLE: &[Rule] = &[
    rule("posture.basic-a", Level::Basic, everyone(), pass),
    rule("posture.bronze-a", Level::Bronze, everyone(), unavailable),
    rule("posture.silver-a", Level::Silver, everyone(), pass),
];

static PLAN_GATED: &[Rule] = &[
    rule("posture.basic-a", Level::Basic, everyone(), pass),
    Rule {
        plan: Some(Plan::Team),
        ..rule(
            "posture.bronze-gated",
            Level::Bronze,
            everyone(),
            rulesets_gated,
        )
    },
];

static NOT_REQUIRED_FAILURE: &[Rule] = &[
    rule("posture.basic-a", Level::Basic, everyone(), pass),
    rule(
        "posture.human-approval",
        Level::Bronze,
        Required {
            profiles: &[Profile::P2, Profile::P3],
            when: &[],
        },
        fail,
    ),
];

static CADENCE_RULE: &[Rule] = &[rule(
    "ci-health.minutes",
    Level::Bronze,
    Required {
        profiles: &[],
        when: &[Condition::CadenceAtLeast(Cadence::Mid)],
    },
    fail,
)];

static CRITICALITY_RULE: &[Rule] = &[rule(
    "posture.pii",
    Level::Silver,
    Required {
        profiles: &[],
        when: &[Condition::CriticalityAtLeast(Criticality::Customers)],
    },
    pass,
)];

static WAITING: &[Rule] = &[
    rule("posture.basic-a", Level::Basic, everyone(), pass),
    Rule {
        feasible_by: Milestone::WaitsFor("observability"),
        ..rule("operations.uptime", Level::Silver, everyone(), pass)
    },
];

static BASIC_FAILURE: &[Rule] = &[
    rule("posture.basic-a", Level::Basic, everyone(), fail),
    rule("posture.bronze-a", Level::Bronze, everyone(), pass),
];

static ALL_PASS: &[Rule] = &[
    rule("posture.basic-a", Level::Basic, everyone(), pass),
    rule("posture.bronze-a", Level::Bronze, everyone(), pass),
    rule("posture.silver-a", Level::Silver, everyone(), pass),
    rule("posture.gold-a", Level::Gold, everyone(), pass),
];

// --- level algorithm --------------------------------------------------------------

#[test]
fn a_silver_repository_with_one_bronze_failure_reaches_basic() {
    let audit = run(SILVER_WITH_BRONZE_FAILURE, &p1(), &FakeHost::none());
    assert_eq!(audit.reached, Some(Level::Basic));
    assert_eq!(audit.unverified_from, None);
    let next = audit.next.as_ref().expect("a next level");
    assert_eq!(next.level, Level::Bronze);
    assert_eq!(next.gap, vec!["posture.bronze-a"]);
}

#[test]
fn one_unavailable_at_bronze_is_unverified_from_bronze_and_exits_4() {
    let audit = run(BRONZE_UNAVAILABLE, &p1(), &FakeHost::none());
    assert_eq!(audit.reached, Some(Level::Basic));
    assert_eq!(audit.unverified_from, Some(Level::Bronze));
    assert_eq!(audit.exit_code(true, Level::Bronze), 4);
    assert_eq!(audit.next.as_ref().unwrap().gap, vec!["posture.bronze-a"]);
}

#[test]
fn a_rule_whose_plan_the_repository_lacks_is_unavailable_never_failed() {
    let host = FakeHost {
        rulesets: Availability::Unavailable {
            reason: "HTTP 403: Upgrade to GitHub Pro or make this repository public".to_owned(),
        },
    };
    let audit = run(PLAN_GATED, &p1(), &host);
    let gated = audit
        .rules
        .iter()
        .find(|e| e.rule.id == "posture.bronze-gated")
        .unwrap();
    assert_eq!(gated.outcome.status, Status::Unavailable);
    assert_eq!(gated.outcome.reason.as_deref(), Some("requires plan Team"));
    assert_eq!(audit.unverified_from, Some(Level::Bronze));
    assert_eq!(audit.exit_code(true, Level::Bronze), 4);
}

#[test]
fn a_plan_gated_rule_with_the_feature_available_is_evaluated() {
    let audit = run(PLAN_GATED, &p1(), &FakeHost::none());
    assert_eq!(status_of(&audit, "posture.bronze-gated"), Status::Failed);
}

#[test]
fn an_unknown_feature_is_unavailable_with_the_probe_reason() {
    let gate = plan_gate(
        Plan::Team,
        &Availability::Unknown {
            reason: "rulesets endpoint timed out".to_owned(),
        },
    )
    .expect("unknown is not available");
    assert_eq!(gate.status, Status::Unavailable);
    assert_eq!(gate.reason.as_deref(), Some("rulesets endpoint timed out"));
    assert!(plan_gate(Plan::Team, &Availability::Available).is_none());
}

#[test]
fn not_required_rules_are_evaluated_and_reported_without_blocking() {
    let audit = run(NOT_REQUIRED_FAILURE, &p1(), &FakeHost::none());
    let approval = audit
        .rules
        .iter()
        .find(|e| e.rule.id == "posture.human-approval")
        .expect("reported");
    assert!(!approval.required);
    assert_eq!(approval.outcome.status, Status::Failed);
    assert_eq!(approval.outcome.evidence, vec!["missing"]);
    assert_eq!(audit.reached, Some(Level::Gold));
    assert_eq!(audit.next, None);
    assert_eq!(audit.exit_code(true, Level::Bronze), 0);
}

#[test]
fn the_same_rule_is_required_and_blocks_at_p2() {
    let p2 = Dimensions {
        profile: Profile::P2,
        ..p1()
    };
    let audit = run(NOT_REQUIRED_FAILURE, &p2, &FakeHost::none());
    assert!(audit.rules[1].required);
    assert_eq!(audit.reached, Some(Level::Basic));
    assert_eq!(audit.exit_code(true, Level::Silver), 3);
}

#[test]
fn a_required_failure_exits_3_when_otherwise_ready() {
    let audit = run(SILVER_WITH_BRONZE_FAILURE, &p1(), &FakeHost::none());
    assert_eq!(audit.exit_code(true, Level::Bronze), 3);
}

#[test]
fn not_ready_exits_1_whatever_the_level() {
    let failing = run(SILVER_WITH_BRONZE_FAILURE, &p1(), &FakeHost::none());
    assert_eq!(failing.exit_code(false, Level::Bronze), 1);
    let passing = run(ALL_PASS, &p1(), &FakeHost::none());
    assert_eq!(passing.exit_code(false, Level::Bronze), 1);
}

#[test]
fn a_reached_required_level_exits_0_even_with_failures_above_it() {
    let audit = run(SILVER_WITH_BRONZE_FAILURE, &p1(), &FakeHost::none());
    assert_eq!(audit.exit_code(true, Level::Basic), 0);
}

#[test]
fn a_failure_above_the_required_level_does_not_turn_unavailable_into_3() {
    // Bronze unverified, Silver would fail: required Bronze is unverified, exit 4.
    static RULES: &[Rule] = &[
        rule("posture.basic-a", Level::Basic, everyone(), pass),
        rule("posture.bronze-a", Level::Bronze, everyone(), unavailable),
        rule("posture.silver-a", Level::Silver, everyone(), fail),
    ];
    let audit = run(RULES, &p1(), &FakeHost::none());
    assert_eq!(audit.exit_code(true, Level::Bronze), 4);
    assert_eq!(audit.exit_code(true, Level::Silver), 3);
}

#[test]
fn a_basic_failure_reaches_no_level() {
    let audit = run(BASIC_FAILURE, &p1(), &FakeHost::none());
    assert_eq!(audit.reached, None);
    assert_eq!(audit.unverified_from, None);
    let next = audit.next.as_ref().unwrap();
    assert_eq!(next.level, Level::Basic);
    assert_eq!(next.gap, vec!["posture.basic-a"]);
    assert_eq!(audit.exit_code(true, Level::Bronze), 3);
}

#[test]
fn every_level_passed_reaches_gold_with_no_next_level() {
    let audit = run(ALL_PASS, &p1(), &FakeHost::none());
    assert_eq!(audit.reached, Some(Level::Gold));
    assert_eq!(audit.next, None);
    assert_eq!(audit.exit_code(true, Level::Gold), 0);
}

#[test]
fn a_cadence_condition_requires_a_rule_regardless_of_profile() {
    let low = Dimensions {
        cadence: Some(Cadence::Low),
        ..p1()
    };
    assert!(!run(CADENCE_RULE, &low, &FakeHost::none()).rules[0].required);
    let unknown = p1();
    assert!(!run(CADENCE_RULE, &unknown, &FakeHost::none()).rules[0].required);
    for cadence in [Cadence::Mid, Cadence::High] {
        let dims = Dimensions {
            cadence: Some(cadence),
            ..p1()
        };
        assert!(run(CADENCE_RULE, &dims, &FakeHost::none()).rules[0].required);
    }
}

#[test]
fn an_undeclared_criticality_is_audited_as_internal() {
    assert!(!run(CRITICALITY_RULE, &p1(), &FakeHost::none()).rules[0].required);
    let pdp = Dimensions {
        criticality: Some(Criticality::PersonalDataOrPayments),
        ..p1()
    };
    assert!(run(CRITICALITY_RULE, &pdp, &FakeHost::none()).rules[0].required);
}

#[test]
fn a_rule_waiting_for_a_module_is_unavailable_without_evaluation() {
    let audit = run(WAITING, &p1(), &FakeHost::none());
    let waiting = &audit.rules[1];
    assert_eq!(waiting.outcome.status, Status::Unavailable);
    assert_eq!(
        waiting.outcome.reason.as_deref(),
        Some("waits for module observability")
    );
    assert_eq!(audit.reached, Some(Level::Bronze));
    assert_eq!(audit.unverified_from, Some(Level::Silver));
}

#[test]
fn outcomes_keep_registry_order_and_runs_are_identical() {
    let first = run(SILVER_WITH_BRONZE_FAILURE, &p1(), &FakeHost::none());
    let second = run(SILVER_WITH_BRONZE_FAILURE, &p1(), &FakeHost::none());
    let ids: Vec<&str> = first.rules.iter().map(|e| e.rule.id).collect();
    assert_eq!(
        ids,
        vec![
            "posture.basic-a",
            "posture.bronze-a",
            "posture.bronze-b",
            "posture.silver-a"
        ]
    );
    assert_eq!(first, second);
}

// --- Files ------------------------------------------------------------------------

#[test]
fn local_files_read_only_the_allowlist() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join(".agent-setup")).unwrap();
    fs::write(dir.path().join(".agent-setup/project.json"), "{}").unwrap();
    fs::write(dir.path().join("secret.txt"), "x").unwrap();
    let files = LocalFiles::new(dir.path());
    assert_eq!(
        files.read(".agent-setup/project.json").unwrap().as_deref(),
        Some("{}")
    );
    assert_eq!(files.read("AGENTS.md").unwrap(), None);
    // Markdown documents (pull request templates, decision files) by extension.
    assert_eq!(files.read("docs/decisions.md").unwrap(), None);
    for climbing in ["../outside.md", "docs/../../outside.md", "/etc/x.md"] {
        assert!(files.read(climbing).is_err(), "{climbing}");
    }
    let refused = files.read("secret.txt").expect_err("outside the allowlist");
    assert_eq!(
        refused.to_string(),
        "Auditor file read refused: secret.txt is outside the auditor's path allowlist"
    );
}

#[test]
fn local_files_list_workflows_sorted_and_read_them() {
    let dir = tempfile::tempdir().unwrap();
    let workflows = dir.path().join(".github/workflows");
    fs::create_dir_all(&workflows).unwrap();
    fs::write(workflows.join("verify.yml"), "on: push").unwrap();
    fs::write(workflows.join("deploy.yaml"), "on: push").unwrap();
    fs::create_dir_all(workflows.join("nested")).unwrap();
    let files = LocalFiles::new(dir.path());
    assert_eq!(
        files.list(".github/workflows").unwrap(),
        vec![
            ".github/workflows/deploy.yaml",
            ".github/workflows/verify.yml"
        ]
    );
    assert_eq!(
        files
            .read(".github/workflows/verify.yml")
            .unwrap()
            .as_deref(),
        Some("on: push")
    );
    assert!(files.read(".github/workflows/../../etc").is_err());
    assert_eq!(
        files.list(".agent-setup").unwrap_err().to_string(),
        "Auditor listing refused: .agent-setup is not one of .github/workflows, .github/ISSUE_TEMPLATE"
    );
}

#[test]
fn local_files_list_nothing_without_workflows() {
    let dir = tempfile::tempdir().unwrap();
    assert!(
        LocalFiles::new(dir.path())
            .list(".github/workflows")
            .unwrap()
            .is_empty()
    );
}

// --- first local Basic rules ------------------------------------------------------

fn checkout(project: Option<&str>, lock: Option<&str>) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join(".agent-setup")).unwrap();
    if let Some(text) = project {
        fs::write(dir.path().join(".agent-setup/project.json"), text).unwrap();
    }
    if let Some(text) = lock {
        fs::write(dir.path().join(".agent-setup/lock.json"), text).unwrap();
    }
    dir
}

fn audit_checkout(root: &Path) -> Audit {
    let files = LocalFiles::new(root);
    let host = FakeHost::none();
    let repo = repo();
    let budget = CallBudget::new(60);
    let cx = Cx {
        host: &host,
        files: &files,
        repo: &repo,
        default_branch: "main",
        now: now(),
        budget: &budget,
        profile: Profile::P1,
        // A `doctor --remote` that found nothing: what these tests own is the
        // local rules (#730 re-labels today's findings).
        today: Some(&Today {
            findings: &[],
            steps: &[],
            remote: true,
        }),
    };
    audit(&cx, &p1())
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

/// Remote rules are unavailable through the fake host, so the level is not
/// Gold; what these tests own is that no baseline rule is in the gap.
fn assert_no_baseline_rule_blocks(audit: &Audit) {
    let gap = audit
        .next
        .as_ref()
        .map(|n| n.gap.clone())
        .unwrap_or_default();
    assert!(!gap.iter().any(|id| id.starts_with("baseline.")), "{gap:?}");
}

const DECLARED: &str = r#"{"purpose": "Sell bread", "commands": {"verify": "cargo test"}, "criticality": "customers"}"#;

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "asserts setup-core's own content or id; product-boundary T7b"
)]
#[test]
fn a_declared_installed_repository_passes_every_baseline_rule() {
    let dir = checkout(Some(DECLARED), Some(r#"{"schema": 2}"#));
    let audit = audit_checkout(dir.path());
    let purpose = outcome(&audit, "baseline.purpose-declared");
    assert_eq!(purpose.status, Status::Passed);
    assert_eq!(purpose.evidence, vec!["purpose: Sell bread"]);
    let verify = outcome(&audit, "baseline.verify-declared");
    assert_eq!(verify.status, Status::Passed);
    assert_eq!(verify.evidence, vec!["commands.verify: cargo test"]);
    let criticality = outcome(&audit, "baseline.criticality-declared");
    assert_eq!(criticality.status, Status::Passed);
    assert_eq!(criticality.evidence, vec!["criticality: customers"]);
    let setup = outcome(&audit, "baseline.setup-installed");
    assert_eq!(setup.status, Status::Passed);
    assert_eq!(setup.evidence, vec![".agent-setup/lock.json present"]);
    assert_no_baseline_rule_blocks(&audit);
}

#[test]
fn an_empty_profile_fails_purpose_verify_and_criticality() {
    let dir = checkout(
        Some(r#"{"purpose": "  ", "commands": {"verify": null}}"#),
        None,
    );
    let audit = audit_checkout(dir.path());
    let purpose = outcome(&audit, "baseline.purpose-declared");
    assert_eq!(purpose.status, Status::Failed);
    assert_eq!(
        purpose.evidence,
        vec!["purpose is empty in .agent-setup/project.json"]
    );
    let verify = outcome(&audit, "baseline.verify-declared");
    assert_eq!(verify.status, Status::Failed);
    assert_eq!(
        verify.evidence,
        vec!["commands.verify is not declared in .agent-setup/project.json"]
    );
    let criticality = outcome(&audit, "baseline.criticality-declared");
    assert_eq!(criticality.status, Status::Failed);
    assert_eq!(
        criticality.evidence,
        vec!["criticality undeclared in .agent-setup/project.json (audited as internal)"]
    );
    assert_eq!(audit.reached, None);
    assert_eq!(audit.exit_code(true, Level::Bronze), 3);
}

#[test]
fn an_unknown_criticality_names_the_allowed_values() {
    let dir = checkout(Some(r#"{"criticality": "banking"}"#), None);
    let criticality = outcome(&audit_checkout(dir.path()), "baseline.criticality-declared");
    assert_eq!(criticality.status, Status::Failed);
    assert_eq!(
        criticality.evidence,
        vec!["criticality banking is not one of internal, customers, personal-data-or-payments"]
    );
}

#[test]
fn a_missing_profile_fails_the_profile_rules() {
    let dir = checkout(None, None);
    let audit = audit_checkout(dir.path());
    for id in [
        "baseline.purpose-declared",
        "baseline.verify-declared",
        "baseline.criticality-declared",
    ] {
        let o = outcome(&audit, id);
        assert_eq!(o.status, Status::Failed, "{id}");
        assert_eq!(
            o.evidence,
            vec![".agent-setup/project.json missing"],
            "{id}"
        );
    }
}

#[test]
fn a_malformed_profile_fails_naming_the_file() {
    let dir = checkout(Some("{not json"), None);
    let o = outcome(&audit_checkout(dir.path()), "baseline.purpose-declared");
    assert_eq!(o.status, Status::Failed);
    assert_eq!(
        o.evidence,
        vec![".agent-setup/project.json is not a JSON object"]
    );
}

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "asserts setup-core's own content or id; product-boundary T7b"
)]
#[test]
fn without_a_lock_setup_installed_is_not_required_and_does_not_block() {
    let dir = checkout(Some(DECLARED), None);
    let audit = audit_checkout(dir.path());
    let setup = outcome(&audit, "baseline.setup-installed");
    assert_eq!(setup.status, Status::NotRequired);
    assert_eq!(setup.reason.as_deref(), Some("setup not installed"));
    assert_no_baseline_rule_blocks(&audit);
}

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "asserts setup-core's own content or id; product-boundary T7b"
)]
#[test]
fn a_malformed_lock_fails_setup_installed() {
    let dir = checkout(Some(DECLARED), Some("[]"));
    let setup = outcome(&audit_checkout(dir.path()), "baseline.setup-installed");
    assert_eq!(setup.status, Status::Failed);
    assert_eq!(
        setup.evidence,
        vec![".agent-setup/lock.json is not a JSON object"]
    );
}

// --- registry invariant -----------------------------------------------------------

/// "Auditor standard v1", point 1 (docs/decisions.md, #706): every rule id, its
/// block, level and the profiles or condition that make it required. A rule that
/// ships must match its row; moving a rule is a new decision, then this table.
const ALLOCATION: &[(&str, Level, &str)] = &[
    ("baseline.purpose-declared", Level::Basic, "all"),
    ("baseline.verify-declared", Level::Basic, "all"),
    ("baseline.criticality-declared", Level::Basic, "all"),
    ("baseline.setup-installed", Level::Basic, "all"),
    ("posture.default-branch-protected", Level::Basic, "all"),
    (
        "posture.no-open-secret-scanning-alerts",
        Level::Basic,
        "all",
    ),
    ("ci-health.workflow-exists", Level::Basic, "all"),
    ("posture.required-check-enforced", Level::Bronze, "all"),
    ("posture.no-unlisted-bypass-actors", Level::Bronze, "all"),
    ("posture.human-approval-required", Level::Bronze, "P2, P3"),
    ("posture.codeowners-review", Level::Bronze, "P2, P3"),
    ("posture.serialised-merges", Level::Bronze, "cadence >= mid"),
    ("posture.actions-pinned", Level::Bronze, "all"),
    ("posture.no-stale-critical-alerts", Level::Bronze, "all"),
    (
        "posture.no-repo-secrets-with-production",
        Level::Bronze,
        "all",
    ),
    ("posture.stale-branches", Level::Bronze, "all"),
    ("ci-health.minutes-budget", Level::Bronze, "cadence >= mid"),
    (
        "governance.dependency-updates-with-cooldown",
        Level::Bronze,
        "all",
    ),
    ("governance.service-card-owner", Level::Bronze, "all"),
    ("governance.codeowners-present", Level::Bronze, "P2, P3"),
    (
        "governance.pr-template-and-issue-forms",
        Level::Bronze,
        "all",
    ),
    ("dora.deployments-api-in-use", Level::Silver, "all"),
    ("dora.deployment-frequency", Level::Silver, "all"),
    ("dora.lead-time", Level::Silver, "all"),
    ("dora.change-failure-rate", Level::Silver, "all"),
    (
        "posture.production-environment-guarded",
        Level::Silver,
        "all",
    ),
    ("ci-health.rerun-rate", Level::Silver, "cadence >= mid"),
    ("ci-health.cancellation-rate", Level::Silver, "all"),
    ("operations.post-deploy-smoke", Level::Silver, "all"),
    ("operations.rollback-evidence", Level::Silver, "all"),
    ("operations.uptime-footprint", Level::Silver, "all"),
    ("operations.incidents-bounded", Level::Silver, "all"),
    ("operations.runbook-per-alert", Level::Silver, "all"),
    ("governance.no-expired-bypass", Level::Silver, "all"),
    ("dora.time-to-restore", Level::Gold, "all"),
    ("operations.slo-burn-rate-validated", Level::Gold, "all"),
    ("operations.backup-age-within-rpo", Level::Gold, "all"),
    ("operations.restore-drill-fresh", Level::Gold, "all"),
    ("governance.postmortem-actions-closed", Level::Gold, "all"),
    ("governance.no-expired-flags", Level::Gold, "all"),
    ("governance.adr-state-known", Level::Gold, "all"),
    ("governance.cost-tags", Level::Gold, "all"),
    (
        "governance.no-persistent-oversizing",
        Level::Gold,
        "platform ladder L4",
    ),
    ("posture.org-2fa-required", Level::Gold, "all"),
    // Decided 2026-10-31 (#1218): the capability a non-owner admin holds.
    ("posture.repo-admins-are-owners", Level::Silver, "P2, P3"),
    // Amended 2026-10-29 (#873): the static module rules.
    ("ci.command-missing", Level::Basic, "all"),
    ("ci.aggregate-present", Level::Basic, "all"),
    ("ci.job-timeouts", Level::Basic, "all"),
    ("ci.permissions-least", Level::Bronze, "all"),
    ("ci.workflow-lint", Level::Bronze, "all"),
    ("ci.no-self-hosted-label", Level::Bronze, "all"),
    ("ci.hosted-macos", Level::Bronze, "all"),
    ("ci.dependabot-actions", Level::Bronze, "all"),
    ("ci.heldout-present", Level::Silver, "all"),
    ("ci.protected-paths-gate", Level::Silver, "all"),
    ("ci.heldout-properties", Level::Silver, "all"),
    ("ci.project-ci-stale", Level::Bronze, "all"),
    // Added with their slice (#783): the remote rules of ci-baseline.
    ("ci.required-is-aggregate", Level::Silver, "all"),
    ("ci.main-red", Level::Silver, "all"),
    ("ci.minutes-month", Level::Gold, "all"),
    ("security.secrets-gate", Level::Basic, "all"),
    ("security.secrets-full-history", Level::Bronze, "all"),
    ("security.deps-gate", Level::Bronze, "all"),
    ("security.scanner-unpinned", Level::Bronze, "all"),
    ("security.trivy-compromised-version", Level::Bronze, "all"),
    ("security.bypass-inventory-valid", Level::Bronze, "all"),
    ("security.bypass-unregistered", Level::Bronze, "all"),
    ("security.bypass-expired", Level::Silver, "all"),
    ("security.secret-scanning", Level::Bronze, "all"),
    (
        "security.private-vulnerability-reporting",
        Level::Bronze,
        "all",
    ),
    ("security.scanner-stale", Level::Gold, "all"),
    ("security.attestation-verified", Level::Gold, "all"),
    ("security.sbom-scanned", Level::Gold, "all"),
    ("security.binary-artifacts", Level::Bronze, "all"),
    (
        "security.sast-gate",
        Level::Silver,
        "criticality >= Customers",
    ),
    ("security.container-gate", Level::Silver, "all"),
    (
        "security.pii-declared",
        Level::Silver,
        "criticality >= PersonalDataOrPayments",
    ),
    // #799: Gold, opt-in, as decision #873 point 5 names it, entering with its slice.
    ("security.coverage-ratchet", Level::Gold, "all"),
    // #979: the level the spec proposes, opt-in through `mutation_diff`.
    ("security.mutation-gate", Level::Gold, "all"),
    // #978: the level the spec proposes (Silver, static), entering with its slice.
    ("security.diff-coverage", Level::Silver, "all"),
    ("stack.unconfigured", Level::Basic, "all"),
    ("stack.lockfile-present", Level::Basic, "all"),
    ("stack.lockfile-not-enforced", Level::Basic, "all"),
    ("stack.toolchain-pinned", Level::Silver, "all"),
    ("stack.image-by-digest", Level::Silver, "all"),
    ("stack.image-nonroot", Level::Silver, "all"),
    ("stack.image-arbitrary-uid", Level::Gold, "P3"),
    ("agents.deny-secrets", Level::Basic, "all"),
    ("agents.readable-secrets", Level::Basic, "all"),
    ("agents.stop-verify", Level::Bronze, "all"),
    ("agents.mcp-allowlist", Level::Bronze, "all"),
    ("agents.technical-debt", Level::Bronze, "all"),
    ("agents.protected-paths", Level::Bronze, "P2, P3"),
    // #940: the level SPEC-agent-guardrails.md proposes, adopted by #873's rule
    // ("adopt the level each module spec proposes"), entering with its slice (point 5).
    ("agents.cross-review", Level::Silver, "all"),
    // #946: the level the spec proposes, adopted by #873's rule, entering with its slice.
    ("agents.unattended-gated", Level::Silver, "all"),
    // #945: the level the spec proposes, adopted by #873's rule, entering with its slice.
    ("agents.heldout-denied", Level::Silver, "all"),
    ("agents.workflow-caps", Level::Silver, "all"),
    ("agents.identity", Level::Silver, "P2, P3"),
    // #972: Bronze, static ("CI hardening for agent workflows", point 6).
    ("agents.workflow-injection", Level::Bronze, "all"),
    // qa (#1008): the levels SPEC-qa.md proposes, adopted by #873's rule; the
    // Silver ones and the remote `qa.main-green` enter with the first slice (point 5).
    ("qa.api-smoke-present", Level::Silver, "all"),
    ("qa.web-smoke-present", Level::Silver, "all"),
    ("qa.screenshot-baseline-present", Level::Silver, "all"),
    ("qa.snapshots-protected", Level::Silver, "all"),
    ("qa.hurl-no-literal-host", Level::Bronze, "all"),
    ("qa.tools-pinned", Level::Bronze, "all"),
    ("qa.no-snapshot-update-in-ci", Level::Bronze, "all"),
    ("qa.report-artifact", Level::Bronze, "all"),
    ("qa.main-green", Level::Silver, "all"),
    // #1016: the contract rules, Silver as #1015 sets.
    ("qa.contract-lint", Level::Silver, "all"),
    ("qa.contract-compatible", Level::Silver, "all"),
];

/// The rules the amendment leaves as `doctor` warnings with no level, and the
/// ids it retires for the one it keeps (#873, points 3 and 4).
const WARNING_ONLY: &[&str] = &["stack.no-healthcheck", "stack.pin-table-stale"];
const RETIRED: &[&str] = &[
    "ci.actions-pinned",
    "baseline.agent-hooks-registered",
    "baseline.stop-hook-current",
];

/// Point 6 of the amendment: each compiled module's level; its manual steps
/// take it but never below Bronze, in every profile.
const MODULE_LEVELS: &[(&str, Level)] = &[
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

/// The registry's `required` in the words of the decision's last column.
fn required_for(required: &Required) -> String {
    let profiles: Vec<String> = required.profiles.iter().map(|p| format!("{p:?}")).collect();
    let when: Vec<String> = required
        .when
        .iter()
        .map(|c| match c {
            Condition::CadenceAtLeast(t) => {
                format!("cadence >= {}", format!("{t:?}").to_lowercase())
            }
            Condition::ServicesAtLeast(t) => {
                format!("services >= {}", format!("{t:?}").to_lowercase())
            }
            Condition::CriticalityAtLeast(t) => format!("criticality >= {t:?}"),
            Condition::PlatformLadderL4 => "platform ladder L4".to_owned(),
        })
        .collect();
    match (profiles.len(), when.is_empty()) {
        (3, true) => "all".to_owned(),
        (_, true) => profiles.join(", "),
        (0, false) => when.join(", "),
        _ => format!("{}; {}", profiles.join(", "), when.join(", ")),
    }
}

fn kebab(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('-')
        && !s.ends_with('-')
        && !s.contains("--")
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

#[test]
fn the_allocation_table_has_unique_well_formed_ids() {
    let mut seen = BTreeSet::new();
    for (id, _, _) in ALLOCATION {
        assert!(seen.insert(*id), "duplicate row {id}");
        let (block, name) = id.split_once('.').expect(id);
        assert!(kebab(block) && kebab(name), "{id}");
    }
}

#[test]
fn every_registry_rule_is_complete_unique_and_allocated_as_decided() {
    assert!(!REGISTRY.is_empty());
    let mut ids = BTreeSet::new();
    for rule in REGISTRY {
        assert!(ids.insert(rule.id), "duplicate rule id {}", rule.id);
        let (block, name) = rule
            .id
            .split_once('.')
            .unwrap_or_else(|| panic!("{} is not <block>.<kebab>", rule.id));
        assert_eq!(
            block,
            rule.block.id(),
            "{} is not in block {}",
            rule.id,
            block
        );
        assert!(kebab(name), "{} is not <block>.<kebab>", rule.id);
        assert!(!rule.title.trim().is_empty(), "{} has no title", rule.id);
        assert!(!rule.checks.trim().is_empty(), "{} has no checks", rule.id);
        assert!(probe_complete(&rule.how), "{} has an empty probe", rule.id);
        assert!(
            remediation_complete(&rule.remediation),
            "{} has an empty remediation",
            rule.id
        );
        if let Milestone::WaitsFor(module) = rule.feasible_by {
            assert!(!module.is_empty(), "{} waits for nothing", rule.id);
        }
        assert!(
            !rule.required.profiles.is_empty() || !rule.required.when.is_empty(),
            "{} is required nowhere",
            rule.id
        );
        match ALLOCATION.iter().find(|(id, _, _)| *id == rule.id) {
            Some((_, level, required)) => {
                assert_eq!(
                    rule.level, *level,
                    "{} level differs from the decision",
                    rule.id
                );
                assert_eq!(
                    required_for(&rule.required),
                    *required,
                    "{} required-for differs from the decision",
                    rule.id
                );
            }
            // Decision point 1: baseline findings not named keep their level by
            // origin (NOT READY is Basic, WARNING Bronze); their ids are T9's.
            None => assert!(
                rule.block == Block::Baseline && rule.level <= Level::Bronze,
                "{} is not in the recorded allocation",
                rule.id
            ),
        }
    }
}

fn probe_complete(probe: &Probe) -> bool {
    match probe {
        Probe::LocalFile { path } => !path.is_empty(),
        Probe::Lock => true,
        Probe::Remote { id } => !id.is_empty(),
        Probe::ManualStep { module, step } => !module.is_empty() && !step.is_empty(),
    }
}

fn remediation_complete(remediation: &Remediation) -> bool {
    match remediation {
        Remediation::Module { id } => !id.is_empty(),
        Remediation::Command { text } => !text.trim().is_empty(),
        Remediation::Manual { step, instructions } => {
            !step.is_empty() && !instructions.trim().is_empty()
        }
    }
}

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "asserts setup-core's own content or id; product-boundary T7b"
)]
#[test]
fn every_allocated_row_is_in_the_registry_and_no_warning_only_or_retired_id_is() {
    let ids: BTreeSet<&str> = REGISTRY.iter().map(|r| r.id).collect();
    for (id, _, _) in ALLOCATION {
        assert!(
            ids.contains(id),
            "{id} is allocated and missing from REGISTRY"
        );
    }
    for id in WARNING_ONLY.iter().chain(RETIRED) {
        assert!(!ids.contains(id), "{id} must not be a registry rule");
        assert!(!ALLOCATION.iter().any(|(a, _, _)| a == id), "{id}");
    }
}

#[test]
fn each_compiled_module_has_the_decided_level_for_its_manual_steps() {
    let compiled: BTreeSet<&str> = brakes::modules::all().iter().map(|m| m.id()).collect();
    let decided: BTreeSet<&str> = MODULE_LEVELS.iter().map(|(m, _)| *m).collect();
    assert_eq!(
        compiled, decided,
        "a compiled module without a decided level"
    );
    for (module, level) in MODULE_LEVELS {
        assert_eq!(
            baseline::step_level(module),
            (*level).max(Level::Bronze),
            "{module}: max(Bronze, its level)"
        );
    }
    // A module no decision names keeps Bronze by origin.
    assert_eq!(baseline::step_level("not-a-module"), Level::Bronze);
}

#[test]
fn a_pending_manual_step_of_a_basic_module_never_blocks_basic() {
    use brakes::engine::{StepReport, StepState, manual::Owner};
    let pending = [StepReport {
        id: "ruleset-main".to_owned(),
        module: "repo-baseline".to_owned(),
        title: "Apply the default branch ruleset".to_owned(),
        owner: Owner::Platform,
        state: StepState::Pending,
        evidence: Some("no ruleset requires required on main".to_owned()),
        error: None,
    }];
    let dir = tempfile::tempdir().unwrap();
    let files = LocalFiles::new(dir.path());
    let host = FakeHost::none();
    let repo = repo();
    let budget = CallBudget::new(60);
    let cx = Cx {
        host: &host,
        files: &files,
        repo: &repo,
        default_branch: "main",
        now: now(),
        budget: &budget,
        profile: Profile::P1,
        today: Some(&Today {
            findings: &[],
            steps: &pending,
            remote: true,
        }),
    };
    let audit = evaluate(&cx, &p1(), &[]);
    let step = &audit.rules[0];
    assert_eq!(step.rule.id, "baseline.repo-baseline.ruleset-main");
    assert_eq!(step.outcome.status, Status::Failed);
    assert_eq!(step.rule.level, Level::Bronze);
    assert_eq!(audit.reached, Some(Level::Basic), "{:#?}", audit.rules);
    assert_eq!(
        audit.next.unwrap().gap,
        vec!["baseline.repo-baseline.ruleset-main"]
    );
}

#[test]
fn the_agents_registry_rules_match_the_data_agent_guardrails_exports() {
    use brakes::modules::agent_guardrails::audit::RULES;
    for data in RULES {
        let rule = REGISTRY
            .iter()
            .find(|r| r.id == data.id)
            .unwrap_or_else(|| panic!("{} missing from REGISTRY", data.id));
        assert_eq!(rule.level, data.level, "{}", data.id);
        assert_eq!(rule.required.profiles, data.profiles, "{}", data.id);
        assert!(rule.required.when.is_empty(), "{}", data.id);
    }
}

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "asserts setup-core's own content or id; product-boundary T7b"
)]
#[test]
fn the_first_slice_ships_the_four_local_basic_rules() {
    let ids: Vec<&str> = REGISTRY.iter().map(|r| r.id).collect();
    for id in [
        "baseline.purpose-declared",
        "baseline.verify-declared",
        "baseline.criticality-declared",
        "baseline.setup-installed",
    ] {
        assert!(ids.contains(&id), "{id} missing from REGISTRY");
    }
}

#[test]
fn block_ids_are_the_kebab_names_of_the_json() {
    let blocks = [
        (Block::Baseline, "baseline"),
        (Block::Posture, "posture"),
        (Block::CiHealth, "ci-health"),
        (Block::Dora, "dora"),
        (Block::Operations, "operations"),
        (Block::Governance, "governance"),
        (Block::Ci, "ci"),
        (Block::Security, "security"),
        (Block::Stack, "stack"),
        (Block::Agents, "agents"),
    ];
    for (block, id) in blocks {
        assert_eq!(block.id(), id);
    }
    assert_eq!(Level::Gold.to_string(), "Gold");
    assert_eq!(Plan::EnterpriseCloud.to_string(), "Enterprise Cloud");
}
