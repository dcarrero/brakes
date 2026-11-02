//! The auditor's measures and profile (SPEC-auditor.md "Profiles and measures",
//! #712): the four measures at their tier boundaries, with evidence; the
//! required level per profile and criticality; `audit.accepted_level`; the run
//! without `--remote`; and the `project.json` fields at profile load. The host
//! is a fake fed in memory, no `gh` runs.
use brakes::{
    auditor::{
        Audit, Cx, Dimensions, LocalFiles, evaluate,
        measures::{Measured, cadence_tier, humans_tier, measure, required_level, services_tier},
        rules::{
            Block, Cadence, Criticality, Level, Milestone, Outcome, Probe, Profile, Remediation,
            Required, Rule, Services,
        },
    },
    host::{
        CallBudget, Features, Host, HostError, HostErrorKind, HostKind, OwnerId, Partial, RepoId,
        SecretName, SecretScope, WriteToken,
        types::{self, Collaborator, DeploymentBranchPolicy, Environment, PullMeta},
    },
    profile::{default_profile, profile_for},
};
use chrono::NaiveDate;
use serde_json::Value;
use std::{fs, path::Path};

// --- fake host ------------------------------------------------------------------

/// Answers `collaborators`, `pulls` and `environments` from memory; every other
/// read is `Unsupported` and every write panics.
#[derive(Default)]
struct FakeHost {
    collaborators: Vec<Collaborator>,
    pulls: Vec<PullMeta>,
    environments: Vec<&'static str>,
    forbidden: bool,
}
impl FakeHost {
    fn forbidden(&self, what: &str, repo: &RepoId) -> Result<(), HostError> {
        if self.forbidden {
            Err(HostError::new(
                HostErrorKind::Forbidden,
                format!("{what} of {repo}: token cannot read it (HTTP 403)"),
            ))
        } else {
            Ok(())
        }
    }
}
fn unsupported<T>(what: &str) -> Result<T, HostError> {
    Err(HostError::new(
        HostErrorKind::Unsupported,
        format!("{what} is not supported by this fake"),
    ))
}
impl Host for FakeHost {
    fn kind(&self) -> HostKind {
        HostKind::GitHub
    }
    fn repository(&self, _: &RepoId) -> Result<types::RepositorySettings, HostError> {
        unsupported("repository")
    }
    fn features(&self, _: &RepoId) -> Result<Features, HostError> {
        unsupported("features")
    }
    fn branch_protection(
        &self,
        _: &RepoId,
        _: &str,
    ) -> Result<Option<types::BranchProtection>, HostError> {
        unsupported("branch_protection")
    }
    fn rulesets(&self, _: &RepoId) -> Result<Vec<types::Ruleset>, HostError> {
        unsupported("rulesets")
    }
    fn environments(&self, repo: &RepoId) -> Result<Vec<Environment>, HostError> {
        self.forbidden("environments", repo)?;
        Ok(self
            .environments
            .iter()
            .map(|name| Environment {
                id: None,
                name: (*name).to_owned(),
                deployment_branch_policy: DeploymentBranchPolicy::Unrestricted,
                reviewers: Vec::new(),
                wait_timer_minutes: None,
            })
            .collect())
    }
    fn secret_names(&self, _: &RepoId, _: &SecretScope) -> Result<Vec<SecretName>, HostError> {
        unsupported("secret_names")
    }
    fn workflow_runs(
        &self,
        _: &RepoId,
        _: &types::RunFilter,
    ) -> Result<Vec<types::WorkflowRun>, HostError> {
        unsupported("workflow_runs")
    }
    fn jobs(&self, _: &RepoId, _: u64) -> Result<Vec<types::Job>, HostError> {
        unsupported("jobs")
    }
    fn check_runs(&self, _: &RepoId, _: &str) -> Result<Vec<types::CheckRun>, HostError> {
        unsupported("check_runs")
    }
    fn collaborators(&self, repo: &RepoId) -> Result<Vec<Collaborator>, HostError> {
        self.forbidden("collaborators", repo)?;
        Ok(self.collaborators.clone())
    }
    fn deployments(
        &self,
        _: &RepoId,
        _: Option<&str>,
    ) -> Result<Vec<types::Deployment>, HostError> {
        unsupported("deployments")
    }
    fn issues(
        &self,
        _: &RepoId,
        _: &types::IssueFilter,
    ) -> Result<Vec<types::IssueMeta>, HostError> {
        unsupported("issues")
    }
    fn pulls(&self, repo: &RepoId, filter: &types::PullFilter) -> Result<Vec<PullMeta>, HostError> {
        self.forbidden("pulls", repo)?;
        assert_eq!(filter.state.as_deref(), Some("closed"));
        Ok(self.pulls.clone())
    }
    fn file_exists(&self, _: &RepoId, _: &str, _: &str) -> Result<Option<String>, HostError> {
        unsupported("file_exists")
    }
    fn owner(&self, _: &str) -> Result<OwnerId, HostError> {
        unsupported("owner")
    }
    fn list_repositories(&self, _: &OwnerId) -> Result<Partial<types::RepoSummary>, HostError> {
        unsupported("list_repositories")
    }
    fn org_rulesets(&self, _: &str) -> Result<Vec<types::Ruleset>, HostError> {
        unsupported("org_rulesets")
    }
    fn org_settings(&self, _: &str) -> Result<types::OrgSettings, HostError> {
        unsupported("org_settings")
    }
    fn ensure_labels(
        &self,
        _: &WriteToken,
        _: &[types::Label],
    ) -> Result<types::WriteReport, HostError> {
        panic!("the auditor never writes")
    }
    fn create_issue(
        &self,
        _: &WriteToken,
        _: &types::NewIssue,
    ) -> Result<types::IssueMeta, HostError> {
        panic!("the auditor never writes")
    }
    fn comment(&self, _: &WriteToken, _: u64, _: &str) -> Result<u64, HostError> {
        panic!("the auditor never writes")
    }
    fn set_repository_settings(
        &self,
        _: &WriteToken,
        _: &types::RepositorySettingsPatch,
    ) -> Result<types::WriteReport, HostError> {
        panic!("the auditor never writes")
    }
    fn put_ruleset(
        &self,
        _: &WriteToken,
        _: &types::Ruleset,
    ) -> Result<types::WriteReport, HostError> {
        panic!("the auditor never writes")
    }
    fn put_environment(
        &self,
        _: &WriteToken,
        _: &types::EnvironmentSpec,
    ) -> Result<types::WriteReport, HostError> {
        panic!("the auditor never writes")
    }
}

// --- helpers --------------------------------------------------------------------

fn now() -> NaiveDate {
    NaiveDate::from_ymd_opt(2026, 10, 28).unwrap()
}

fn user(login: &str, permission: &str) -> Collaborator {
    Collaborator {
        login: login.to_owned(),
        permission: permission.to_owned(),
        kind: Some("User".to_owned()),
    }
}

/// `n` human writers after the owner, who is admin.
fn humans(n: usize) -> Vec<Collaborator> {
    let mut all = vec![user("example-owner", "admin")];
    all.extend((1..n).map(|i| user(&format!("dev{i}"), "write")));
    all
}

fn merged(number: u64, merged_at: Option<&str>) -> PullMeta {
    PullMeta {
        number,
        title: format!("change {number}"),
        state: "closed".to_owned(),
        head_sha: format!("{number:040x}"),
        base: "main".to_owned(),
        author: None,
        draft: Some(false),
        created_at: None,
        merged_at: merged_at.map(str::to_owned),
        closed_at: merged_at.map(str::to_owned),
        merge_commit_sha: None,
    }
}

/// A checkout holding only `.agent-setup/project.json` with `profile`.
fn checkout(profile: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join(".agent-setup")).unwrap();
    fs::write(dir.path().join(".agent-setup/project.json"), profile).unwrap();
    dir
}

const MINIMAL: &str = r#"{"purpose": "x", "commands": {"verify": "true"}}"#;

fn measure_at(root: &Path, host: &FakeHost, remote: bool) -> Measured {
    let files = LocalFiles::new(root);
    let repo = RepoId::parse("example-owner/example").unwrap();
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
    measure(&cx, remote).unwrap()
}

fn measured(profile: &str, host: &FakeHost) -> Measured {
    let dir = checkout(profile);
    measure_at(dir.path(), host, true)
}

fn fixture() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/auditor/services")
}

// --- humans with merge rights --------------------------------------------------

#[test]
fn humans_tiers_at_the_boundaries() {
    assert_eq!(humans_tier(1), Profile::P1);
    assert_eq!(humans_tier(2), Profile::P2);
    assert_eq!(humans_tier(5), Profile::P2);
    assert_eq!(humans_tier(6), Profile::P3);
}

#[test]
fn one_two_and_six_humans_derive_p1_p2_p3_and_their_required_level() {
    for (n, profile, required) in [
        (1, Profile::P1, Level::Bronze),
        (2, Profile::P2, Level::Silver),
        (6, Profile::P3, Level::Gold),
    ] {
        let host = FakeHost {
            collaborators: humans(n),
            ..Default::default()
        };
        let m = measured(MINIMAL, &host);
        assert_eq!(m.profile, profile, "{n} humans");
        assert_eq!(m.dimensions.profile, profile);
        assert_eq!(m.required, required, "{n} humans");
        assert_eq!(m.measures.humans.value, Value::from(n));
        assert!(!m.unverified);
    }
}

#[test]
fn a_declared_agent_account_apps_and_readers_do_not_count_as_humans() {
    let host = FakeHost {
        collaborators: vec![
            user("example-owner", "admin"),
            user("aps-codex", "write"),
            user("reader", "read"),
            user("triager", "triage"),
            Collaborator {
                login: "renovate[bot]".to_owned(),
                permission: "write".to_owned(),
                kind: Some("Bot".to_owned()),
            },
        ],
        ..Default::default()
    };
    let m = measured(
        r#"{"purpose": "x", "commands": {}, "audit": {"agent_accounts": ["aps-codex"]}}"#,
        &host,
    );
    assert_eq!(m.profile, Profile::P1);
    assert_eq!(m.measures.humans.value, Value::from(1));
    assert_eq!(m.measures.humans.tier, "P1");
    assert_eq!(
        m.measures.humans.evidence,
        [
            "collaborators: example-owner (admin)",
            "excluded agent account: aps-codex",
            "excluded non-user account: renovate[bot] (Bot)",
        ]
    );
}

#[test]
fn an_undeclared_agent_account_counts_as_a_human() {
    let host = FakeHost {
        collaborators: vec![user("example-owner", "admin"), user("aps-codex", "write")],
        ..Default::default()
    };
    let m = measured(MINIMAL, &host);
    assert_eq!(m.profile, Profile::P2);
    assert_eq!(
        m.measures.humans.evidence,
        ["collaborators: aps-codex (write), example-owner (admin)"]
    );
}

// --- merge cadence ---------------------------------------------------------------

#[test]
fn cadence_tiers_at_the_boundaries() {
    assert_eq!(cadence_tier(9.9), Cadence::Low);
    assert_eq!(cadence_tier(10.0), Cadence::Mid);
    assert_eq!(cadence_tier(40.0), Cadence::Mid);
    assert_eq!(cadence_tier(40.1), Cadence::High);
}

#[test]
fn cadence_counts_prs_merged_in_the_28_day_window_divided_by_four() {
    let mut pulls: Vec<PullMeta> = (1..=40)
        .map(|n| merged(n, Some("2026-10-20T09:00:00Z")))
        .collect();
    pulls.push(merged(41, Some("2026-09-29T23:59:59Z"))); // before the window
    pulls.push(merged(42, None)); // closed without merge
    pulls.push(merged(43, Some("2026-09-30T00:00:00Z"))); // first instant inside
    let host = FakeHost {
        collaborators: humans(1),
        pulls,
        ..Default::default()
    };
    let m = measured(MINIMAL, &host);
    assert_eq!(m.measures.cadence.value, Value::from(10.25));
    assert_eq!(m.measures.cadence.tier, "mid");
    assert_eq!(
        m.measures.cadence.evidence,
        ["41 merged PRs 2026-09-30..2026-10-28"]
    );
    assert_eq!(m.dimensions.cadence, Some(Cadence::Mid));
}

#[test]
fn cadence_at_forty_per_week_is_mid_and_above_is_high() {
    for (count, tier, dim) in [
        (39, "low", Cadence::Low),
        (160, "mid", Cadence::Mid),
        (161, "high", Cadence::High),
    ] {
        let host = FakeHost {
            collaborators: humans(1),
            pulls: (1..=count)
                .map(|n| merged(n, Some("2026-10-27T10:00:00Z")))
                .collect(),
            ..Default::default()
        };
        let m = measured(MINIMAL, &host);
        assert_eq!(m.measures.cadence.tier, tier, "{count} PRs");
        assert_eq!(m.dimensions.cadence, Some(dim));
    }
}

// --- deployable services ---------------------------------------------------------

#[test]
fn services_tiers_at_the_boundaries() {
    assert_eq!(services_tier(1), Services::Single);
    assert_eq!(services_tier(2), Services::Few);
    assert_eq!(services_tier(5), Services::Few);
    assert_eq!(services_tier(6), Services::Many);
}

#[test]
fn one_two_and_six_declared_environments_give_single_few_many() {
    for (environments, tier, dim) in [
        (vec!["production"], "single", Services::Single),
        (vec!["production", "staging"], "few", Services::Few),
        (vec!["a", "b", "c", "d", "e", "f"], "many", Services::Many),
    ] {
        let host = FakeHost {
            collaborators: humans(1),
            environments: environments.clone(),
            ..Default::default()
        };
        let m = measured(MINIMAL, &host);
        assert_eq!(m.measures.services.value, Value::from(environments.len()));
        assert_eq!(m.measures.services.tier, tier);
        assert_eq!(m.dimensions.services, Some(dim));
    }
}

#[test]
fn services_is_the_max_of_deploy_workflows_dockerfiles_and_environments() {
    let host = FakeHost {
        collaborators: humans(1),
        environments: vec!["production"],
        ..Default::default()
    };
    let m = measure_at(&fixture(), &host, true);
    assert_eq!(m.measures.services.value, Value::from(2));
    assert_eq!(m.measures.services.tier, "few");
    assert_eq!(
        m.measures.services.evidence,
        [
            "workflows with environment: .github/workflows/deploy.yml, .github/workflows/preview.yaml",
            "Dockerfile",
            "environments: production",
        ]
    );
}

// --- criticality and the required level ------------------------------------------

#[test]
fn required_level_for_every_profile_and_criticality() {
    use Criticality::*;
    use Level::*;
    use Profile::*;
    let table = [
        (P1, None, Bronze),
        (P1, Some(Internal), Bronze),
        (P1, Some(Customers), Silver),
        (P1, Some(PersonalDataOrPayments), Silver),
        (P2, None, Silver),
        (P2, Some(Internal), Silver),
        (P2, Some(Customers), Silver),
        (P2, Some(PersonalDataOrPayments), Gold),
        (P3, None, Gold),
        (P3, Some(Internal), Gold),
        (P3, Some(Customers), Gold),
        (P3, Some(PersonalDataOrPayments), Gold),
    ];
    for (profile, criticality, level) in table {
        assert_eq!(
            required_level(profile, criticality),
            level,
            "{profile:?} {criticality:?}"
        );
    }
}

#[test]
fn each_declared_criticality_and_undeclared_is_measured_with_evidence() {
    for (declared, value, tier, dim, required) in [
        (None, "undeclared", "internal", None, Level::Bronze),
        (
            Some("internal"),
            "internal",
            "internal",
            Some(Criticality::Internal),
            Level::Bronze,
        ),
        (
            Some("customers"),
            "customers",
            "customers",
            Some(Criticality::Customers),
            Level::Silver,
        ),
        (
            Some("personal-data-or-payments"),
            "personal-data-or-payments",
            "personal-data-or-payments",
            Some(Criticality::PersonalDataOrPayments),
            Level::Silver,
        ),
    ] {
        let profile = match declared {
            Some(name) => {
                format!(r#"{{"purpose": "x", "commands": {{}}, "criticality": "{name}"}}"#)
            }
            None => MINIMAL.to_owned(),
        };
        let host = FakeHost {
            collaborators: humans(1),
            ..Default::default()
        };
        let m = measured(&profile, &host);
        assert_eq!(m.measures.criticality.value, Value::from(value));
        assert_eq!(m.measures.criticality.tier, tier);
        assert_eq!(m.dimensions.criticality, dim);
        assert_eq!(m.required, required, "{value}");
        let evidence = if declared.is_some() {
            "project.json#criticality".to_owned()
        } else {
            "project.json#criticality undeclared (audited as internal)".to_owned()
        };
        assert_eq!(m.measures.criticality.evidence, [evidence]);
    }
}

// --- JSON shape and the run without --remote -------------------------------------

#[test]
fn every_measure_carries_value_tier_and_evidence_strings() {
    let host = FakeHost {
        collaborators: humans(1),
        environments: vec!["production"],
        ..Default::default()
    };
    let json = measure_at(&fixture(), &host, true).to_json();
    assert_eq!(json["id"], "P1");
    assert_eq!(json["unverified"], false);
    let measures = json["measures"].as_object().unwrap();
    let names: Vec<&str> = measures.keys().map(String::as_str).collect();
    assert_eq!(
        names,
        [
            "criticality",
            "deployable_services",
            "humans_with_merge",
            "merge_cadence_per_week",
        ]
    );
    for (name, measure) in measures {
        assert!(!measure["value"].is_null(), "{name} value");
        assert!(measure["tier"].is_string(), "{name} tier");
        let evidence = measure["evidence"].as_array().unwrap();
        assert!(!evidence.is_empty(), "{name} evidence");
        assert!(evidence.iter().all(Value::is_string), "{name} evidence");
    }
    assert_eq!(measures["criticality"]["value"], "customers");
}

#[test]
fn without_remote_host_measures_are_unavailable_and_the_profile_is_unverified_p1() {
    let host = FakeHost {
        collaborators: humans(6),
        ..Default::default()
    };
    let m = measure_at(&fixture(), &host, false);
    assert_eq!(m.profile, Profile::P1);
    assert!(m.unverified);
    assert_eq!(m.dimensions.cadence, None);
    assert_eq!(m.dimensions.services, None);
    assert_eq!(m.dimensions.criticality, Some(Criticality::Customers));
    assert_eq!(
        m.required,
        Level::Silver,
        "the required level is still stated"
    );
    for measure in [
        &m.measures.humans,
        &m.measures.cadence,
        &m.measures.services,
    ] {
        assert_eq!(measure.value, Value::Null);
        assert_eq!(measure.tier, "unavailable");
        assert_eq!(measure.evidence, ["unavailable without --remote"]);
    }
    let json = m.to_json();
    assert_eq!(json["unverified"], true);
    assert_eq!(json["id"], "P1");
}

#[test]
fn a_host_refusal_makes_the_measure_unavailable_with_the_reason() {
    let host = FakeHost {
        collaborators: humans(6),
        forbidden: true,
        ..Default::default()
    };
    let m = measured(MINIMAL, &host);
    assert_eq!(m.profile, Profile::P1);
    assert!(m.unverified);
    assert_eq!(m.measures.humans.tier, "unavailable");
    assert_eq!(
        m.measures.humans.evidence,
        ["collaborators of example-owner/example: token cannot read it (HTTP 403)"]
    );
}

// --- audit.accepted_level --------------------------------------------------------

fn fail(_: &Cx<'_>) -> Outcome {
    Outcome::failed(["missing"])
}
const ALL: &[Profile] = &[Profile::P1, Profile::P2, Profile::P3];
static BRONZE_FAILS: &[Rule] = &[Rule {
    id: "posture.fixture-bronze",
    title: "Fixture",
    block: Block::Posture,
    checks: "A Bronze rule that fails.",
    how: Probe::Remote { id: "fixture" },
    level: Level::Bronze,
    required: Required {
        profiles: ALL,
        when: &[],
    },
    remediation: Remediation::Command { text: "true" },
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: fail,
}];

fn audited(profile: &str) -> (Measured, Audit) {
    let dir = checkout(profile);
    let host = FakeHost {
        collaborators: humans(1),
        ..Default::default()
    };
    let m = measure_at(dir.path(), &host, true);
    let files = LocalFiles::new(dir.path());
    let repo = RepoId::parse("example-owner/example").unwrap();
    let budget = CallBudget::new(60);
    let cx = Cx {
        host: &host,
        files: &files,
        repo: &repo,
        default_branch: "main",
        now: now(),
        budget: &budget,
        profile: Profile::P1,
        today: None,
    };
    let audit = evaluate(&cx, &m.dimensions, BRONZE_FAILS);
    (m, audit)
}

#[test]
fn without_acceptance_a_missing_required_level_exits_3() {
    let (m, audit) = audited(MINIMAL);
    assert_eq!(m.required, Level::Bronze);
    assert_eq!(audit.reached, Some(Level::Basic));
    assert_eq!(m.exit_code(&audit, true), 3);
    assert!(m.findings.is_empty());
}

#[test]
fn an_unexpired_acceptance_exits_0_and_keeps_required_level_and_gap() {
    let (m, audit) = audited(
        r#"{"purpose": "x", "commands": {},
            "audit": {"accepted_level": {"level": "Basic", "expires": "2026-10-28"}}}"#,
    );
    assert_eq!(m.exit_code(&audit, true), 0);
    assert_eq!(m.exit_code(&audit, false), 1, "NOT READY is never lowered");
    assert_eq!(m.required, Level::Bronze);
    let next = audit.next.as_ref().unwrap();
    assert_eq!(next.level, Level::Bronze);
    assert_eq!(next.gap, ["posture.fixture-bronze"]);
    assert!(m.findings.is_empty());
}

#[test]
fn an_expired_acceptance_is_a_finding_and_does_not_lower_the_exit_code() {
    let (m, audit) = audited(
        r#"{"purpose": "x", "commands": {},
            "audit": {"accepted_level": {"level": "Basic", "expires": "2026-10-27"}}}"#,
    );
    assert_eq!(m.exit_code(&audit, true), 3);
    assert_eq!(m.findings, ["audit.accepted_level expired on 2026-10-27"]);
}

#[test]
fn any_unexpired_acceptance_lowers_the_level_gap_to_0_whatever_its_level() {
    let (m, audit) = audited(
        r#"{"purpose": "x", "commands": {},
            "audit": {"accepted_level": {"level": "Bronze", "expires": "2026-12-31"}}}"#,
    );
    assert_eq!(audit.reached, Some(Level::Basic));
    assert_eq!(m.exit_code(&audit, true), 0);
    assert_eq!(m.exit_code(&audit, false), 1, "NOT READY is never lowered");
    assert_eq!(m.required, Level::Bronze);
    assert_eq!(audit.next.as_ref().unwrap().gap, ["posture.fixture-bronze"]);
}

// --- project.json fields at profile load -----------------------------------------

/// The default profile with `extra`'s top-level fields set over it.
fn full(extra: &str) -> String {
    let mut profile = default_profile();
    let extra: Value = serde_json::from_str(extra).unwrap();
    for (key, value) in extra.as_object().unwrap() {
        profile[key] = value.clone();
    }
    profile.to_string()
}

fn load_error(profile: &str) -> String {
    let dir = checkout(&full(profile));
    match profile_for(dir.path()) {
        Ok(_) => panic!("profile accepted: {profile}"),
        Err(e) => e.to_string(),
    }
}

#[test]
fn profile_load_accepts_the_audit_fields() {
    let dir = checkout(&full(
        r#"{"criticality": "personal-data-or-payments",
            "audit": {"agent_accounts": ["aps-codex", "aps-claude"],
                      "accepted_level": {"level": "Silver", "expires": "2027-01-31"}}}"#,
    ));
    profile_for(dir.path()).unwrap();
    profile_for(checkout(&full(r#"{"criticality": null}"#)).path()).unwrap();
}

#[test]
fn profile_load_refuses_an_unknown_criticality_naming_the_allowed_values() {
    let message = load_error(r#"{"criticality": "high"}"#);
    assert!(
        message.contains("internal, customers, personal-data-or-payments"),
        "{message}"
    );
    assert!(message.contains("high"), "{message}");
}

#[test]
fn profile_load_refuses_malformed_audit_fields() {
    for (profile, expected) in [
        (r#""audit": []"#, "audit block must be an object"),
        (
            r#""audit": {"agent_accounts": "aps-codex"}"#,
            "audit.agent_accounts must be a list of logins",
        ),
        (
            r#""audit": {"agent_accounts": [""]}"#,
            "audit.agent_accounts must be a list of logins",
        ),
        (
            r#""audit": {"accepted_level": {"level": "Platinum", "expires": "2027-01-01"}}"#,
            "Basic, Bronze, Silver, Gold",
        ),
        (
            r#""audit": {"accepted_level": {"level": "Silver"}}"#,
            "audit.accepted_level.expires must be a YYYY-MM-DD date",
        ),
        (
            r#""audit": {"accepted_level": {"level": "Silver", "expires": "31/01/2027"}}"#,
            "audit.accepted_level.expires must be a YYYY-MM-DD date",
        ),
    ] {
        let message = load_error(&format!("{{{profile}}}"));
        assert!(message.contains(expected), "{profile}: {message}");
    }
}

#[test]
fn measures_refuse_an_unknown_criticality_too() {
    let dir = checkout(r#"{"purpose": "x", "commands": {}, "criticality": "high"}"#);
    let host = FakeHost::default();
    let files = LocalFiles::new(dir.path());
    let repo = RepoId::parse("example-owner/example").unwrap();
    let budget = CallBudget::new(60);
    let cx = Cx {
        host: &host,
        files: &files,
        repo: &repo,
        default_branch: "main",
        now: now(),
        budget: &budget,
        profile: Profile::P1,
        today: None,
    };
    let message = measure(&cx, true).err().unwrap().to_string();
    assert!(
        message.contains("internal, customers, personal-data-or-payments"),
        "{message}"
    );
}

#[test]
fn dimensions_are_what_the_audit_consumes() {
    let host = FakeHost {
        collaborators: humans(2),
        ..Default::default()
    };
    let m = measured(MINIMAL, &host);
    assert_eq!(
        m.dimensions,
        Dimensions {
            profile: Profile::P2,
            cadence: Some(Cadence::Low),
            services: Some(Services::Single),
            criticality: None,
            humans: Some(2),
        }
    );
}
