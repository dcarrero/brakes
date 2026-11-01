//! The host contract with zero GitHub calls: identities, the read gate, the write
//! gate and the only constructor of `WriteToken` (SPEC-host-adapter.md, #675).
use brakes::{
    config::Config,
    host::{
        Availability, CallBudget, Features, Host, HostError, HostErrorKind, HostKind, OwnerId,
        OwnerKind, Partial, RepoId, SecretName, SecretScope, Visibility, authorize,
        authorize::WriteToken, types,
    },
    scope::{remote_identity, write_allowed},
};
use serde_json::{Value, json};

mod configured;
use configured::{capitalised, denied};

fn repo(identity: &str) -> RepoId {
    RepoId::parse(identity).expect(identity)
}
fn message(result: Result<impl std::fmt::Debug, Box<dyn std::error::Error>>) -> String {
    result.expect_err("expected a refusal").to_string()
}

// --- write gate ---------------------------------------------------------------

#[test]
fn write_without_the_flag_refuses_before_looking_at_the_allowlist() {
    let text = message(authorize::write(&repo("example-owner/x"), false));
    assert_eq!(
        text,
        "Remote write to example-owner/x needs the explicit --remote flag of apply"
    );
}

#[test]
fn write_outside_the_allowlist_names_the_decision_file() {
    let text = message(authorize::write(&repo("other-org/repo"), true));
    assert_eq!(
        text,
        "Remote write refused: other-org/repo is not in the authorized write allowlist; a new organization needs an owner decision in docs/decisions.md"
    );
}

#[test]
fn every_allowlisted_repository_mints_a_token_for_itself() {
    let allowlist = configured::config().write_allowlist;
    assert!(!allowlist.is_empty());
    for entry in allowlist {
        let identity = entry.replace("/*", "/x");
        let token: WriteToken = authorize::write(&repo(&identity), true).expect(&identity);
        assert_eq!(token.repo(), &repo(&identity));
        assert_eq!(token.repo().to_string(), identity);
    }
}

#[test]
fn the_token_is_minted_from_the_normalised_identity() {
    let token = authorize::write(&repo("Example-Owner/Example.git"), true).unwrap();
    assert_eq!(token.repo().to_string(), "example-owner/example");
    let cloned = token.clone();
    assert!(format!("{cloned:?}").contains("example-owner/example"));
}

#[test]
fn a_denylisted_identity_built_by_hand_is_refused_for_write_even_with_the_flag() {
    let word = denied();
    let hand_made = RepoId {
        host: HostKind::GitHub,
        owner: "example-owner".to_owned(),
        project: None,
        name: format!("{word}-notes"),
    };
    let text = message(authorize::write(&hand_made, true));
    assert!(text.contains(&capitalised(&word)), "{text}");
    assert!(!text.contains("allowlist"), "{text}");
}

#[test]
fn an_azure_devops_identity_is_never_writable_today() {
    let azure = RepoId {
        host: HostKind::AzureDevOps,
        owner: "example-owner".to_owned(),
        project: Some("project".to_owned()),
        name: "repo".to_owned(),
    };
    assert_eq!(azure.to_string(), "example-owner/project/repo");
    let text = message(authorize::write(&azure, true));
    assert!(text.starts_with("Remote write refused: example-owner/project/repo"));
}

// --- read gate ----------------------------------------------------------------

#[test]
fn reads_proceed_anywhere_except_denylisted_identities() {
    let word = denied();
    let word_cap = capitalised(&word);
    let word_upper = word.to_uppercase();
    authorize::read(&repo("some-other-org/repo")).unwrap();
    authorize::read(&repo("example-owner/x")).unwrap();
    authorize::read_owner("outside-org").unwrap();
    for identity in [
        format!("{word}/x"),
        format!("{word_cap}-Tech/app"),
        format!("someone/{word}app"),
    ] {
        let text = message(RepoId::parse(&identity));
        assert_eq!(
            text,
            format!("{word_cap} repository refused, regardless of remote owner"),
            "{identity}"
        );
    }
    let hand_made = RepoId {
        host: HostKind::GitHub,
        owner: word_upper.clone(),
        project: None,
        name: "x".to_owned(),
    };
    assert_eq!(
        message(authorize::read(&hand_made)),
        format!(
            "Remote read refused: {word_upper}/x is a {word_cap} identity and the installer never reads one (decision 2026-10-28)"
        )
    );
    assert_eq!(
        message(authorize::read_owner(&word_cap)),
        format!(
            "Remote read refused: {word_cap} is a {word_cap} identity and the installer never reads one (decision 2026-10-28)"
        )
    );
    assert!(
        message(RepoId::from_remote(&format!("git@github.com:{word}/x.git"))).contains(&word_cap)
    );
}

// --- identities ---------------------------------------------------------------

#[test]
fn parse_normalises_like_remote_identity() {
    let id = repo("Example-Owner/Example-Project.git");
    assert_eq!(id.host, HostKind::GitHub);
    assert_eq!(id.owner, "example-owner");
    assert_eq!(id.name, "example-project");
    assert_eq!(id.project, None);
    assert_eq!(id.identity(), "example-owner/example-project");
    assert_eq!(id.to_string(), id.identity());
    assert_eq!(repo("a_b.c-d/e.f_g-h").identity(), "a_b.c-d/e.f_g-h");
}

#[test]
fn parse_refuses_what_inspect_report_refuses() {
    for bad in [
        "", "x", "a/b/c", "a//b", "/a/b", "a/b/", "a/b c", "a/b?x", "a/../b", "a/b%2Fc", "á/b",
    ] {
        let text = message(RepoId::parse(bad));
        assert_eq!(
            text,
            format!("Repository identity is not owner/name: {bad}")
        );
    }
}

#[test]
fn from_remote_accepts_every_form_remote_identity_accepts() {
    for url in [
        "git@github.com:example-owner/example.git",
        "https://github.com/example-owner/example",
        "https://github.com/Example-Owner/Example.git",
        "ssh://git@github.com/example-org/example-app.git",
        "https://github.com/example-org/other-app/",
    ] {
        let id = RepoId::from_remote(url).expect(url);
        assert_eq!(id.identity(), remote_identity(url).unwrap(), "{url}");
        assert_eq!(id.host, HostKind::GitHub);
    }
}

#[test]
fn from_remote_reads_organizations_remote_identity_refuses() {
    let id = RepoId::from_remote("https://github.com/outside-org/Shop.git").unwrap();
    assert_eq!(id.identity(), "outside-org/shop");
    assert_eq!(
        message(remote_identity("https://github.com/outside-org/Shop.git")),
        "Non-personal remote owner refused: outside-org"
    );
    authorize::read(&id).unwrap();
    assert!(message(authorize::write(&id, true)).contains("docs/decisions.md"));
}

#[test]
fn from_remote_keeps_the_transport_rules_of_remote_identity() {
    assert_eq!(
        message(RepoId::from_remote("https://gitlab.com/a/b")),
        "Remote is not an allowed personal GitHub repository"
    );
    assert_eq!(
        message(RepoId::from_remote("ftp://github.com/a/b")),
        "Remote protocol is not supported"
    );
    assert_eq!(
        message(RepoId::from_remote("https://github.com/a/b/c")),
        "Remote is not an allowed personal GitHub repository"
    );
    assert_eq!(
        message(RepoId::from_remote("git@github.com:a")),
        "Remote is not an allowed personal GitHub repository"
    );
}

#[test]
fn owner_ids_carry_host_name_and_kind() {
    let owner = OwnerId {
        host: HostKind::GitHub,
        name: "outside-org".to_owned(),
        kind: OwnerKind::Organization,
    };
    assert_eq!(owner.to_string(), "outside-org");
    assert_eq!(
        serde_json::to_value(&owner).unwrap(),
        json!({"host": "github", "name": "outside-org", "kind": "organization"})
    );
    assert_eq!(HostKind::AzureDevOps.to_string(), "azure-devops");
}

#[test]
fn write_allowed_matches_the_owner_wildcard_and_exact_repositories_only() {
    for yes in [
        "example-owner/anything",
        "Example-Owner/Anything",
        "example-org/example-app",
        "EXAMPLE-ORG/EXAMPLE-APP",
    ] {
        assert!(write_allowed(yes), "{yes}");
    }
    let denied_owner = format!("{}/example-owner", denied());
    for no in [
        "other-org/repo",
        "example-owner",
        "example-owner/",
        "example-owner/a/b",
        denied_owner.as_str(),
        "",
    ] {
        assert!(!write_allowed(no), "{no}");
    }
    // Exact entries match their repository only, never a sibling.
    let exact = Config::for_test(
        "example-owner",
        &["example-owner/*", "example-team/app"],
        &[],
    );
    for yes in ["example-team/app", "EXAMPLE-TEAM/APP"] {
        assert!(exact.write_allowed(yes), "{yes}");
    }
    for no in ["example-team/other", "example-team/app-2"] {
        assert!(!exact.write_allowed(no), "{no}");
    }
}

#[test]
fn remote_identity_behaviour_is_unchanged_by_the_extraction() {
    assert_eq!(
        remote_identity("git@github.com:Example-Owner/Example.git").unwrap(),
        "example-owner/example"
    );
    assert_eq!(
        remote_identity("https://github.com/example-org/example-app").unwrap(),
        "example-org/example-app"
    );
    assert_eq!(
        message(remote_identity("https://github.com/Outside-Org/other")),
        "Non-personal remote owner refused: Outside-Org"
    );
    let word = denied();
    assert_eq!(
        message(remote_identity(&format!(
            "https://github.com/example-owner/{word}-x"
        ))),
        format!(
            "{} repository refused, regardless of remote owner",
            capitalised(&word)
        )
    );
}

// --- errors, availability, budget, models ---------------------------------------

#[test]
fn host_errors_display_their_sentence_and_keep_their_kind() {
    let error = HostError::new(
        HostErrorKind::RateLimited {
            reset_epoch: Some(1_700_000_000),
        },
        "GitHub rate limit reached while reading outside-org",
    );
    assert_eq!(
        error.to_string(),
        "GitHub rate limit reached while reading outside-org"
    );
    assert!(matches!(
        error.kind,
        HostErrorKind::RateLimited {
            reset_epoch: Some(1_700_000_000)
        }
    ));
    let boxed: Box<dyn std::error::Error> = error.into();
    assert!(boxed.downcast_ref::<HostError>().is_some());
    let unsupported = HostError::unsupported("put_ruleset", &repo("a/b"));
    assert_eq!(unsupported.kind, HostErrorKind::Unsupported);
    assert_eq!(
        unsupported.to_string(),
        "put_ruleset is not supported on a/b by this host adapter"
    );
    assert_eq!(
        serde_json::to_value(&unsupported).unwrap(),
        json!({"kind": "unsupported", "message": "put_ruleset is not supported on a/b by this host adapter"})
    );
}

#[test]
fn call_budget_counts_calls_and_exhausts_as_rate_limited_without_a_reset() {
    let budget = CallBudget::new(2);
    assert_eq!(budget.limit(), 2);
    budget.spend().unwrap();
    budget.spend().unwrap();
    assert_eq!(budget.used(), 2);
    let error = budget.spend().unwrap_err();
    assert_eq!(error.kind, HostErrorKind::RateLimited { reset_epoch: None });
    assert_eq!(error.to_string(), "call budget of 2 exhausted");
    assert_eq!(CallBudget::default().limit(), 2_000);
}

#[test]
fn availability_and_partial_serialise_plainly() {
    let availability = vec![
        Availability::Available,
        Availability::Unavailable {
            reason: "403: Upgrade to GitHub Pro".to_owned(),
        },
        Availability::Unknown {
            reason: "needs org owner".to_owned(),
        },
    ];
    let value = serde_json::to_value(&availability).unwrap();
    assert_eq!(
        value,
        json!([
            "available",
            {"unavailable": {"reason": "403: Upgrade to GitHub Pro"}},
            {"unknown": {"reason": "needs org owner"}}
        ])
    );
    let back: Vec<Availability> = serde_json::from_value(value).unwrap();
    assert_eq!(back, availability);

    let partial = Partial {
        items: vec!["a".to_owned()],
        stopped: Some(HostError::new(
            HostErrorKind::Truncated,
            "listing capped at 100 pages",
        )),
        unread: vec!["outside-org/b".to_owned()],
    };
    let value = serde_json::to_value(&partial).unwrap();
    assert_eq!(value["items"], json!(["a"]));
    assert_eq!(value["stopped"]["kind"], json!("truncated"));
    assert_eq!(value["unread"], json!(["outside-org/b"]));
    let complete: Partial<String> = Partial::complete(vec!["x".to_owned()]);
    assert!(complete.is_complete());
    assert!(!partial.is_complete());
}

#[test]
fn secret_names_carry_name_scope_and_updated_at_only() {
    let secret = SecretName {
        name: "DEPLOY_KEY".to_owned(),
        scope: SecretScope::Environment("production".to_owned()),
        updated_at: Some("2026-10-28T00:00:00Z".to_owned()),
    };
    let value = serde_json::to_value(&secret).unwrap();
    let keys: Vec<&str> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, ["name", "scope", "updated_at"]);
    assert_eq!(value["scope"], json!({"environment": "production"}));
    assert_eq!(
        serde_json::to_value(SecretScope::Repository).unwrap(),
        json!("repository")
    );
}

#[test]
fn features_fields_are_the_spec_table_and_the_plan_hint_is_a_string() {
    let features = Features {
        visibility: Visibility::Private,
        plan_hint: Some("free".to_owned()),
        rulesets: Availability::Available,
        environments: Availability::Unknown {
            reason: "not probed".to_owned(),
        },
        branch_protection: Availability::Available,
        required_reviewers: Availability::Unknown {
            reason: "not probed".to_owned(),
        },
        dependabot_alerts: Availability::Available,
        secret_scanning: Availability::Available,
        workflow_lockfile: Availability::Available,
        merge_queue: Availability::Unknown {
            reason: "not probed".to_owned(),
        },
    };
    let value = serde_json::to_value(&features).unwrap();
    let keys: Vec<&str> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        [
            "branch_protection",
            "dependabot_alerts",
            "environments",
            "merge_queue",
            "plan_hint",
            "required_reviewers",
            "rulesets",
            "secret_scanning",
            "visibility",
            "workflow_lockfile",
        ]
    );
    assert_eq!(value["visibility"], json!("private"));
}

#[test]
fn read_models_round_trip_through_json_with_absent_fields_as_none() {
    let settings: types::RepositorySettings = serde_json::from_value(json!({
        "id": "example-owner/example",
        "default_branch": "main",
        "visibility": "public",
        "archived": false,
        "fork": false,
    }))
    .unwrap();
    assert_eq!(settings.default_branch, "main");
    assert_eq!(settings.allow_squash_merge, None);
    assert_eq!(settings.pushed_at, None);
    let org: types::OrgSettings = serde_json::from_value(json!({})).unwrap();
    assert_eq!(org.two_factor_requirement_enabled, None);
    let back: Value = serde_json::to_value(&org).unwrap();
    assert_eq!(back["plan_hint"], Value::Null);
}

// --- the contract is implementable and object-safe with zero transport ------------

/// A host that answers `Unsupported` everywhere: the shape the Azure DevOps
/// interface (#685) and the auditor's fakes take.
struct Nothing;
impl Host for Nothing {
    fn kind(&self) -> HostKind {
        HostKind::AzureDevOps
    }
    fn repository(&self, repo: &RepoId) -> Result<types::RepositorySettings, HostError> {
        Err(HostError::unsupported("repository", repo))
    }
    fn features(&self, repo: &RepoId) -> Result<Features, HostError> {
        Err(HostError::unsupported("features", repo))
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
            HostErrorKind::Unsupported,
            format!("owner is not supported for {name}"),
        ))
    }
    fn list_repositories(&self, owner: &OwnerId) -> Result<Partial<types::RepoSummary>, HostError> {
        Err(HostError::new(
            HostErrorKind::Unsupported,
            format!("list_repositories is not supported for {owner}"),
        ))
    }
    fn org_rulesets(&self, org: &str) -> Result<Vec<types::Ruleset>, HostError> {
        Err(HostError::new(
            HostErrorKind::Unsupported,
            format!("org_rulesets is not supported for {org}"),
        ))
    }
    fn org_settings(&self, org: &str) -> Result<types::OrgSettings, HostError> {
        Err(HostError::new(
            HostErrorKind::Unsupported,
            format!("org_settings is not supported for {org}"),
        ))
    }
    fn ensure_labels(
        &self,
        token: &WriteToken,
        _labels: &[types::Label],
    ) -> Result<types::WriteReport, HostError> {
        Err(HostError::unsupported("ensure_labels", token.repo()))
    }
    fn create_issue(
        &self,
        token: &WriteToken,
        _issue: &types::NewIssue,
    ) -> Result<types::IssueMeta, HostError> {
        Err(HostError::unsupported("create_issue", token.repo()))
    }
    fn comment(&self, token: &WriteToken, _number: u64, _body: &str) -> Result<u64, HostError> {
        Err(HostError::unsupported("comment", token.repo()))
    }
    fn set_repository_settings(
        &self,
        token: &WriteToken,
        _settings: &types::RepositorySettingsPatch,
    ) -> Result<types::WriteReport, HostError> {
        Err(HostError::unsupported(
            "set_repository_settings",
            token.repo(),
        ))
    }
    fn put_ruleset(
        &self,
        token: &WriteToken,
        _ruleset: &types::Ruleset,
    ) -> Result<types::WriteReport, HostError> {
        Err(HostError::unsupported("put_ruleset", token.repo()))
    }
    fn put_environment(
        &self,
        token: &WriteToken,
        _environment: &types::EnvironmentSpec,
    ) -> Result<types::WriteReport, HostError> {
        Err(HostError::unsupported("put_environment", token.repo()))
    }
}

#[test]
fn the_contract_is_object_safe_and_writes_need_a_minted_token() {
    let host: &dyn Host = &Nothing;
    assert_eq!(host.kind(), HostKind::AzureDevOps);
    let error = host.rulesets(&repo("some-other-org/repo")).unwrap_err();
    assert_eq!(error.kind, HostErrorKind::Unsupported);
    let token = authorize::write(&repo("example-owner/x"), true).unwrap();
    let error = host.comment(&token, 1, "hello").unwrap_err();
    assert_eq!(
        error.to_string(),
        "comment is not supported on example-owner/x by this host adapter"
    );
}

/// `Nothing` leaves out the #679 reads: their trait defaults answer
/// `Unsupported`, so implementations written before them keep compiling.
#[test]
fn the_security_branch_and_contents_reads_default_to_unsupported() {
    let host: &dyn Host = &Nothing;
    let r = repo("some-other-org/repo");
    let errors = [
        host.dependabot_alerts(&r).map(|_| ()).unwrap_err(),
        host.secret_scanning_alerts(&r).map(|_| ()).unwrap_err(),
        host.branches(&r).map(|_| ()).unwrap_err(),
        host.file_contents(&r, "a", "main").map(|_| ()).unwrap_err(),
        host.list_directory(&r, "", "main").map(|_| ()).unwrap_err(),
    ];
    let names = [
        "dependabot_alerts",
        "secret_scanning_alerts",
        "branches",
        "file_contents",
        "list_directory",
    ];
    for (error, name) in errors.iter().zip(names) {
        assert_eq!(error.kind, HostErrorKind::Unsupported);
        assert_eq!(
            error.message,
            format!("{name} is not supported on some-other-org/repo by this host adapter")
        );
    }
}
