//! The Azure DevOps interface (#685): its two identity forms parse into a
//! `RepoId` with a project, `RepoId::from_remote` dispatches on the hostname,
//! and every `Host` operation answers `Unsupported` with one fixed message.
//! No network, no credentials: the stub has nothing to call.
use brakes::host::{
    Host, HostErrorKind, HostKind, OwnerId, OwnerKind, RepoId, SecretScope, authorize,
    azure_devops::{AzureDevOps, UNSUPPORTED},
    types::{
        BranchProtectionSpec, DeploymentBranchPolicy, EnvironmentSpec, IssueFilter, Label,
        NewIssue, PullFilter, RepositorySettingsPatch, Ruleset, RunFilter, SecurityToggle,
    },
};
use std::collections::BTreeMap;

mod configured;
use configured::{capitalised, denied};

fn azure(owner: &str, project: &str, name: &str) -> RepoId {
    RepoId {
        host: HostKind::AzureDevOps,
        owner: owner.into(),
        project: Some(project.into()),
        name: name.into(),
    }
}
fn refusal(remote: &str) -> String {
    RepoId::from_remote(remote).expect_err(remote).to_string()
}

// --- identities ---------------------------------------------------------------

#[test]
fn the_https_form_parses_into_org_project_and_repo() {
    let repo =
        RepoId::from_remote("https://dev.azure.com/ExampleOrg/Platform/_git/Service.git").unwrap();
    assert_eq!(repo, azure("exampleorg", "platform", "service"));
    assert_eq!(repo.identity(), "exampleorg/platform/service");
}

#[test]
fn the_https_form_with_a_user_before_the_host_parses() {
    let repo =
        RepoId::from_remote("https://exampleorg@dev.azure.com/exampleorg/platform/_git/service")
            .unwrap();
    assert_eq!(repo, azure("exampleorg", "platform", "service"));
}

#[test]
fn the_ssh_form_parses_into_org_project_and_repo() {
    let repo = RepoId::from_remote("git@ssh.dev.azure.com:v3/exampleorg/platform/service").unwrap();
    assert_eq!(repo, azure("exampleorg", "platform", "service"));
}

#[test]
fn the_parser_is_reachable_without_from_remote() {
    let repo = AzureDevOps::parse_remote("git@ssh.dev.azure.com:v3/a/b/c").unwrap();
    assert_eq!(repo, azure("a", "b", "c"));
}

#[test]
fn a_github_url_is_not_mistaken_for_azure() {
    for remote in [
        "https://github.com/example-owner/example.git",
        "git@github.com:example-owner/example.git",
    ] {
        let repo = RepoId::from_remote(remote).unwrap();
        assert_eq!(repo.host, HostKind::GitHub, "{remote}");
        assert_eq!(repo.project, None, "{remote}");
        assert_eq!(repo.identity(), "example-owner/example");
    }
}

#[test]
fn a_github_path_that_looks_like_azure_stays_github() {
    let text = refusal("https://github.com/exampleorg/platform/_git/service");
    assert_eq!(text, "Remote is not an allowed personal GitHub repository");
}

#[test]
fn a_malformed_azure_url_is_refused_naming_the_form() {
    for remote in [
        "https://dev.azure.com/exampleorg/platform/service",
        "https://dev.azure.com/exampleorg/platform/_wiki/service",
        "https://dev.azure.com/exampleorg/_git/service",
        "https://dev.azure.com/exampleorg/platform/_git/service/extra",
        "https://dev.azure.com/exampleorg/platform/_git/",
        "http://dev.azure.com/exampleorg/platform/_git/service",
        "git@ssh.dev.azure.com:v3/exampleorg/service",
        "git@ssh.dev.azure.com:exampleorg/platform/service",
        "git@ssh.dev.azure.com:v3/exampleorg/plat form/service",
        "https://dev.azure.com/exampleorg/../_git/service",
    ] {
        assert_eq!(
            refusal(remote),
            format!(
                "Azure DevOps remote is neither https://dev.azure.com/{{org}}/{{project}}/_git/{{repo}} nor git@ssh.dev.azure.com:v3/{{org}}/{{project}}/{{repo}}: {remote}"
            ),
        );
    }
}

#[test]
fn a_denylisted_azure_identity_is_refused_before_parsing() {
    let word = capitalised(&denied());
    let text = refusal(&format!(
        "https://dev.azure.com/{word}/platform/_git/service"
    ));
    assert_eq!(
        text,
        format!("{word} repository refused, regardless of remote owner")
    );
}

#[test]
fn an_unknown_host_is_still_refused_as_not_github() {
    let text = refusal("https://example.com/exampleorg/service.git");
    assert_eq!(text, "Remote is not an allowed personal GitHub repository");
}

// --- every operation ----------------------------------------------------------

#[test]
fn the_stub_names_its_host() {
    assert_eq!(AzureDevOps.kind(), HostKind::AzureDevOps);
}

#[test]
fn every_host_operation_answers_unsupported_with_the_one_message() {
    let host = AzureDevOps;
    let repo = azure("exampleorg", "platform", "service");
    // No write gate admits an Azure identity today; the stub refuses whatever
    // token reaches it, so one minted for an allowlisted repository serves.
    let token = authorize::write(&RepoId::parse("example-owner/example").unwrap(), true).unwrap();
    let owner = OwnerId {
        host: HostKind::AzureDevOps,
        name: "exampleorg".into(),
        kind: OwnerKind::Organization,
    };
    let ruleset = Ruleset {
        id: None,
        name: "main".into(),
        target: "branch".into(),
        enforcement: "active".into(),
        include: vec![],
        exclude: vec![],
        rules: vec![],
        required_status_checks: vec![],
        required_approving_review_count: None,
        bypass_actors: vec![],
        rule_parameters: BTreeMap::new(),
    };
    let environment = EnvironmentSpec {
        name: "production".into(),
        deployment_branch_policy: DeploymentBranchPolicy::ProtectedBranches,
        reviewers: vec![],
        wait_timer_minutes: None,
    };
    let protection = BranchProtectionSpec {
        required_status_checks: vec![],
        strict: false,
        enforce_admins: true,
        required_approving_review_count: None,
        required_linear_history: false,
        allow_force_pushes: false,
        allow_deletions: false,
    };
    let label = Label {
        name: "status:in-review".into(),
        color: "ffffff".into(),
        description: None,
    };
    let issue = NewIssue {
        title: "t".into(),
        body: "b".into(),
        labels: vec![],
    };

    let answers: Vec<(&str, Option<brakes::host::HostError>)> = vec![
        ("repository", host.repository(&repo).err()),
        ("features", host.features(&repo).err()),
        (
            "branch_protection",
            host.branch_protection(&repo, "main").err(),
        ),
        ("rulesets", host.rulesets(&repo).err()),
        ("environments", host.environments(&repo).err()),
        (
            "secret_names",
            host.secret_names(&repo, &SecretScope::Repository).err(),
        ),
        (
            "workflow_runs",
            host.workflow_runs(&repo, &RunFilter::default()).err(),
        ),
        ("run_timing", host.run_timing(&repo, 1).err()),
        ("jobs", host.jobs(&repo, 1).err()),
        ("check_runs", host.check_runs(&repo, "abc").err()),
        ("collaborators", host.collaborators(&repo).err()),
        ("deployments", host.deployments(&repo, None).err()),
        (
            "deployment_statuses",
            host.deployment_statuses(&repo, 1).err(),
        ),
        (
            "latest_deployments",
            host.latest_deployments(&repo, "production").err(),
        ),
        ("issues", host.issues(&repo, &IssueFilter::default()).err()),
        ("pulls", host.pulls(&repo, &PullFilter::default()).err()),
        (
            "pulls_for_commit",
            host.pulls_for_commit(&repo, "abc").err(),
        ),
        (
            "file_exists",
            host.file_exists(&repo, "README.md", "main").err(),
        ),
        ("dependabot_alerts", host.dependabot_alerts(&repo).err()),
        (
            "secret_scanning_alerts",
            host.secret_scanning_alerts(&repo).err(),
        ),
        ("branches", host.branches(&repo).err()),
        ("branch_heads", host.branch_heads(&repo).err()),
        ("commit_date", host.commit_date(&repo, "abc").err()),
        (
            "file_contents",
            host.file_contents(&repo, "README.md", "main").err(),
        ),
        (
            "list_directory",
            host.list_directory(&repo, "", "main").err(),
        ),
        ("labels", host.labels(&repo).err()),
        (
            "recent_commits",
            host.recent_commits(&repo, "main", 10).err(),
        ),
        (
            "security_toggle",
            host.security_toggle(&repo, SecurityToggle::VulnerabilityAlerts)
                .err(),
        ),
        ("owner", host.owner("exampleorg").err()),
        ("list_repositories", host.list_repositories(&owner).err()),
        ("org_rulesets", host.org_rulesets("exampleorg").err()),
        ("org_settings", host.org_settings("exampleorg").err()),
        ("ensure_labels", host.ensure_labels(&token, &[label]).err()),
        ("create_issue", host.create_issue(&token, &issue).err()),
        ("comment", host.comment(&token, 1, "body").err()),
        (
            "set_repository_settings",
            host.set_repository_settings(&token, &RepositorySettingsPatch::default())
                .err(),
        ),
        ("put_ruleset", host.put_ruleset(&token, &ruleset).err()),
        (
            "put_environment",
            host.put_environment(&token, &environment).err(),
        ),
        (
            "put_branch_protection",
            host.put_branch_protection(&token, "main", &protection)
                .err(),
        ),
        (
            "retire_branch_protection",
            host.retire_branch_protection(&token, "main", None).err(),
        ),
    ];
    // Every method of the trait but `kind`; `auditor_cached.rs` checks that
    // the stub implements each one itself rather than through a default.
    assert_eq!(answers.len(), 40);
    for (operation, error) in answers {
        let error = error.unwrap_or_else(|| panic!("{operation} answered Ok"));
        assert_eq!(error.kind, HostErrorKind::Unsupported, "{operation}");
        assert_eq!(error.message, UNSUPPORTED, "{operation}");
    }
    assert_eq!(
        UNSUPPORTED,
        "Azure DevOps host adapter is an interface without an implementation; GitHub is the supported host (issue #648)"
    );
}
