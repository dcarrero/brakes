//! The writes of the GitHub host adapter (#684): labels, issues and comments over
//! a recording fake transport. Every test asserts the exact method, path and body
//! the adapter sent; no test spawns `gh` for a write.
use brakes::{
    Result,
    host::{
        CallBudget, Host, HostErrorKind, RepoId, authorize,
        github::GitHub,
        types::{
            BranchProtectionSpec, DeploymentBranchPolicy, EnvironmentSpec, Label, NewIssue,
            RepositorySettingsPatch, Ruleset, WriteReport,
        },
    },
    remote::{Api, HttpError, refuse_secret_body},
};
use serde_json::{Value, json};
use std::{cell::RefCell, collections::BTreeMap};

const BASE: &str = "repos/example-owner/example";

/// Serves GETs and writes by `"METHOD path"`, recording every call with its body.
#[derive(Default)]
struct Fake {
    replies: BTreeMap<String, std::result::Result<Value, (u16, String)>>,
    calls: RefCell<Vec<(String, String, Option<Value>)>>,
}
impl Fake {
    fn reply(mut self, method: &str, path: &str, value: Value) -> Self {
        self.replies.insert(format!("{method} {path}"), Ok(value));
        self
    }
    fn fail(self, method: &str, path: &str, status: u16) -> Self {
        self.fail_with(method, path, status, "Validation Failed")
    }
    fn fail_with(mut self, method: &str, path: &str, status: u16, message: &str) -> Self {
        self.replies.insert(
            format!("{method} {path}"),
            Err((status, message.to_owned())),
        );
        self
    }
    fn answer(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value> {
        self.calls
            .borrow_mut()
            .push((method.to_owned(), path.to_owned(), body.cloned()));
        match self.replies.get(&format!("{method} {path}")) {
            Some(Ok(value)) => Ok(value.clone()),
            Some(Err((status, message))) => Err(HttpError {
                status: *status,
                message: message.clone(),
            }
            .into()),
            None => Err(format!("unexpected {method} {path}").into()),
        }
    }
    /// The non-GET calls, in order.
    fn writes(&self) -> Vec<(String, String, Option<Value>)> {
        self.calls
            .borrow()
            .iter()
            .filter(|(method, _, _)| method != "GET")
            .cloned()
            .collect()
    }
}
impl Api for Fake {
    fn get(&self, path: &str) -> Result<Value> {
        self.answer("GET", path, None)
    }
    fn send(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value> {
        self.answer(method, path, body)
    }
}

fn token() -> authorize::WriteToken {
    authorize::write(&RepoId::parse("example-owner/example").unwrap(), true).unwrap()
}
fn host(fake: &Fake) -> GitHub<'_> {
    GitHub::new(fake, CallBudget::new(100))
}
fn labels_page() -> String {
    format!("{BASE}/labels?per_page=100&page=1")
}
fn label(name: &str, color: &str, description: Option<&str>) -> Label {
    Label {
        name: name.to_owned(),
        color: color.to_owned(),
        description: description.map(str::to_owned),
    }
}

// --- labels ------------------------------------------------------------------------------

#[test]
fn ensure_labels_creates_updates_and_leaves_matching_labels_alone() {
    let fake = Fake::default()
        .reply(
            "GET",
            &labels_page(),
            json!([
                {"name": "bug", "color": "D73A4A", "description": "Something is broken"},
                {"name": "Status:Ready", "color": "0e8a16", "description": "old"},
            ]),
        )
        .reply("POST", &format!("{BASE}/labels"), json!({"id": 1}))
        .reply(
            "PATCH",
            &format!("{BASE}/labels/Status%3AReady"),
            json!({"id": 2}),
        );
    let report = host(&fake)
        .ensure_labels(
            &token(),
            &[
                label("bug", "#d73a4a", Some("Something is broken")),
                label("status:ready", "0E8A16", Some("Ready to start")),
                label("fleet-audit", "5319e7", None),
            ],
        )
        .unwrap();
    assert_eq!(
        report,
        WriteReport {
            created: vec!["fleet-audit".into()],
            updated: vec!["status:ready".into()],
            unchanged: vec!["bug".into()],
            skipped: BTreeMap::new(),
            removed: vec![],
        }
    );
    assert_eq!(
        fake.writes(),
        [
            (
                "PATCH".into(),
                format!("{BASE}/labels/Status%3AReady"),
                Some(json!({"color": "0e8a16", "description": "Ready to start"}))
            ),
            (
                "POST".into(),
                format!("{BASE}/labels"),
                Some(json!({"name": "fleet-audit", "color": "5319e7"}))
            ),
        ]
    );
}

#[test]
fn ensure_labels_second_run_reports_unchanged_and_sends_nothing() {
    let fake = Fake::default().reply(
        "GET",
        &labels_page(),
        json!([
            {"name": "fleet-audit", "color": "5319e7", "description": "Fleet report"},
            {"name": "triage", "color": "fbca04", "description": "Kept as it is"},
        ]),
    );
    let report = host(&fake)
        .ensure_labels(
            &token(),
            &[
                label("fleet-audit", "5319E7", Some("Fleet report")),
                label("triage", "#FBCA04", None),
            ],
        )
        .unwrap();
    assert_eq!(report.unchanged, ["fleet-audit", "triage"]);
    assert!(report.created.is_empty() && report.updated.is_empty());
    assert!(fake.writes().is_empty());
}

#[test]
fn ensure_labels_reports_a_failed_write_naming_the_label_and_repository() {
    let fake = Fake::default()
        .reply("GET", &labels_page(), json!([]))
        .fail("POST", &format!("{BASE}/labels"), 422);
    let error = host(&fake)
        .ensure_labels(&token(), &[label("bad", "zz", None)])
        .unwrap_err();
    assert_eq!(error.kind, HostErrorKind::Transport);
    assert_eq!(
        error.message,
        "creating label bad in example-owner/example failed (422: Validation Failed)"
    );
}

// --- issues and comments -----------------------------------------------------------------

#[test]
fn create_issue_posts_title_body_and_labels_and_returns_its_meta() {
    let fake = Fake::default().reply(
        "POST",
        &format!("{BASE}/issues"),
        json!({"number": 42, "title": "Fleet audit", "state": "open",
            "labels": [{"name": "fleet-audit"}],
            "html_url": "https://github.com/example-owner/example/issues/42"}),
    );
    let issue = host(&fake)
        .create_issue(
            &token(),
            &NewIssue {
                title: "Fleet audit".into(),
                body: "Report".into(),
                labels: vec!["fleet-audit".into()],
            },
        )
        .unwrap();
    assert_eq!(issue.number, 42);
    assert_eq!(
        issue.url.as_deref(),
        Some("https://github.com/example-owner/example/issues/42")
    );
    assert_eq!(
        fake.writes(),
        [(
            "POST".into(),
            format!("{BASE}/issues"),
            Some(json!({"title": "Fleet audit", "body": "Report", "labels": ["fleet-audit"]}))
        )]
    );
}

#[test]
fn comment_posts_the_body_and_returns_the_comment_id() {
    let fake = Fake::default().reply(
        "POST",
        &format!("{BASE}/issues/7/comments"),
        json!({"id": 991, "body": "Done"}),
    );
    assert_eq!(host(&fake).comment(&token(), 7, "Done").unwrap(), 991);
    assert_eq!(
        fake.writes(),
        [(
            "POST".into(),
            format!("{BASE}/issues/7/comments"),
            Some(json!({"body": "Done"}))
        )]
    );
}

#[test]
fn comment_on_a_missing_issue_is_not_found() {
    let fake = Fake::default().fail("POST", &format!("{BASE}/issues/9/comments"), 404);
    let error = host(&fake).comment(&token(), 9, "x").unwrap_err();
    assert_eq!(error.kind, HostErrorKind::NotFound);
    assert_eq!(
        error.message,
        "commenting on #9 in example-owner/example failed (404: Validation Failed)"
    );
}

// --- repository settings (#876) -----------------------------------------------------------

fn repository_page(extra: Value) -> Value {
    let mut v = json!({
        "id": 7, "default_branch": "main", "visibility": "private", "private": true,
        "archived": false, "fork": false,
        "allow_squash_merge": true, "allow_merge_commit": true, "allow_rebase_merge": false,
        "delete_branch_on_merge": false, "allow_auto_merge": false, "allow_update_branch": false,
        "has_wiki": true, "has_projects": true, "web_commit_signoff_required": false,
        "security_and_analysis": {
            "secret_scanning": {"status": "enabled"},
            "secret_scanning_push_protection": {"status": "disabled"},
        },
    });
    for (key, value) in extra.as_object().unwrap() {
        v[key] = value.clone();
    }
    v
}

#[test]
fn set_repository_settings_patches_only_the_differing_keys() {
    let fake = Fake::default()
        .reply("GET", BASE, repository_page(json!({})))
        .reply("PATCH", BASE, json!({"id": 7}));
    let patch = RepositorySettingsPatch {
        allow_squash_merge: Some(true),
        allow_merge_commit: Some(false),
        allow_update_branch: Some(true),
        has_wiki: Some(true),
        secret_scanning: Some("enabled".into()),
        secret_scanning_push_protection: Some("enabled".into()),
        ..Default::default()
    };
    let report = host(&fake)
        .set_repository_settings(&token(), &patch)
        .unwrap();
    assert_eq!(
        fake.writes(),
        vec![(
            "PATCH".to_owned(),
            BASE.to_owned(),
            Some(json!({
                "allow_merge_commit": false,
                "allow_update_branch": true,
                "security_and_analysis": {
                    "secret_scanning_push_protection": {"status": "enabled"},
                },
            })),
        )]
    );
    assert_eq!(
        report,
        WriteReport {
            created: vec![],
            updated: vec![
                "allow_merge_commit".into(),
                "allow_update_branch".into(),
                "secret_scanning_push_protection".into(),
            ],
            unchanged: vec![
                "allow_squash_merge".into(),
                "has_wiki".into(),
                "secret_scanning".into(),
            ],
            skipped: BTreeMap::new(),
            removed: vec![],
        }
    );
}

#[test]
fn set_repository_settings_already_matching_reports_unchanged_and_sends_nothing() {
    let fake = Fake::default()
        .reply("GET", BASE, repository_page(json!({})))
        .reply("GET", &format!("{BASE}/vulnerability-alerts"), Value::Null)
        .reply(
            "GET",
            &format!("{BASE}/automated-security-fixes"),
            json!({"enabled": true, "paused": false}),
        );
    let patch = RepositorySettingsPatch {
        delete_branch_on_merge: Some(false),
        web_commit_signoff_required: Some(false),
        secret_scanning: Some("enabled".into()),
        vulnerability_alerts: Some(true),
        automated_security_fixes: Some(true),
        ..Default::default()
    };
    let report = host(&fake)
        .set_repository_settings(&token(), &patch)
        .unwrap();
    assert!(fake.writes().is_empty(), "{:?}", fake.writes());
    assert!(report.updated.is_empty());
    assert_eq!(
        report.unchanged,
        [
            "delete_branch_on_merge",
            "web_commit_signoff_required",
            "secret_scanning",
            "vulnerability_alerts",
            "automated_security_fixes",
        ]
    );
}

#[test]
fn set_repository_settings_enables_dependabot_alerts_before_security_fixes() {
    let fake = Fake::default()
        .fail("GET", &format!("{BASE}/vulnerability-alerts"), 404)
        .fail("GET", &format!("{BASE}/automated-security-fixes"), 404)
        .reply("PUT", &format!("{BASE}/vulnerability-alerts"), Value::Null)
        .reply(
            "PUT",
            &format!("{BASE}/automated-security-fixes"),
            Value::Null,
        );
    let patch = RepositorySettingsPatch {
        vulnerability_alerts: Some(true),
        automated_security_fixes: Some(true),
        ..Default::default()
    };
    let report = host(&fake)
        .set_repository_settings(&token(), &patch)
        .unwrap();
    assert_eq!(
        fake.writes(),
        vec![
            (
                "PUT".to_owned(),
                format!("{BASE}/vulnerability-alerts"),
                None
            ),
            (
                "PUT".to_owned(),
                format!("{BASE}/automated-security-fixes"),
                None
            ),
        ]
    );
    assert_eq!(
        report.updated,
        ["vulnerability_alerts", "automated_security_fixes"]
    );
    assert!(
        fake.calls.borrow().iter().all(|(_, path, _)| path != BASE),
        "no PATCH key declared, so repos/{{r}} is not read"
    );
}

/// #854: private vulnerability reporting is `PUT` only after a read shows it
/// off, and an enabled one costs no write.
#[test]
fn set_repository_settings_enables_private_vulnerability_reporting_when_off() {
    let patch = RepositorySettingsPatch {
        private_vulnerability_reporting: Some(true),
        ..Default::default()
    };
    let path = format!("{BASE}/private-vulnerability-reporting");
    let off = Fake::default()
        .reply("GET", &path, json!({"enabled": false}))
        .reply("PUT", &path, Value::Null);
    let report = host(&off)
        .set_repository_settings(&token(), &patch)
        .unwrap();
    assert_eq!(off.writes(), vec![("PUT".to_owned(), path.clone(), None)]);
    assert_eq!(report.updated, ["private_vulnerability_reporting"]);
    let on = Fake::default().reply("GET", &path, json!({"enabled": true}));
    let report = host(&on).set_repository_settings(&token(), &patch).unwrap();
    assert!(on.writes().is_empty(), "{:?}", on.writes());
    assert_eq!(report.unchanged, ["private_vulnerability_reporting"]);
}

/// A 404 (private repository) is the read's error, never a reason to send.
#[test]
fn private_vulnerability_reporting_not_found_sends_nothing() {
    let patch = RepositorySettingsPatch {
        private_vulnerability_reporting: Some(true),
        ..Default::default()
    };
    let fake = Fake::default().fail_with(
        "GET",
        &format!("{BASE}/private-vulnerability-reporting"),
        404,
        "Not Found",
    );
    let error = host(&fake)
        .set_repository_settings(&token(), &patch)
        .unwrap_err();
    assert_eq!(error.kind, HostErrorKind::NotFound);
    assert!(fake.writes().is_empty(), "{:?}", fake.writes());
}

#[test]
fn a_settings_key_outside_the_allowed_list_is_refused_naming_it() {
    let error = serde_json::from_value::<RepositorySettingsPatch>(json!({"has_issues": false}))
        .unwrap_err();
    assert!(
        error.to_string().contains("unknown field `has_issues`"),
        "{error}"
    );
    let error = serde_json::from_value::<RepositorySettingsPatch>(
        json!({"security_and_analysis": {"advanced_security": {"status": "enabled"}}}),
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("unknown field `security_and_analysis`"),
        "{error}"
    );
}

#[test]
fn an_invalid_settings_value_is_refused_before_any_call() {
    for (patch, key) in [
        (
            RepositorySettingsPatch {
                secret_scanning: Some("on".into()),
                ..Default::default()
            },
            "secret_scanning",
        ),
        (
            RepositorySettingsPatch {
                vulnerability_alerts: Some(false),
                ..Default::default()
            },
            "vulnerability_alerts",
        ),
        (
            RepositorySettingsPatch {
                automated_security_fixes: Some(false),
                ..Default::default()
            },
            "automated_security_fixes",
        ),
        (
            RepositorySettingsPatch {
                private_vulnerability_reporting: Some(false),
                ..Default::default()
            },
            "private_vulnerability_reporting",
        ),
    ] {
        let fake = Fake::default();
        let error = host(&fake)
            .set_repository_settings(&token(), &patch)
            .unwrap_err();
        assert_eq!(error.kind, HostErrorKind::WriteRefused, "{key}");
        assert!(error.message.contains(key), "{}", error.message);
        assert!(fake.calls.borrow().is_empty(), "{key}");
    }
}

#[test]
fn a_settings_key_github_does_not_show_is_written() {
    let mut page = repository_page(json!({}));
    page.as_object_mut().unwrap().remove("allow_update_branch");
    let fake = Fake::default()
        .reply("GET", BASE, page)
        .reply("PATCH", BASE, json!({"id": 7}));
    let patch = RepositorySettingsPatch {
        allow_update_branch: Some(false),
        ..Default::default()
    };
    let report = host(&fake)
        .set_repository_settings(&token(), &patch)
        .unwrap();
    assert_eq!(report.updated, ["allow_update_branch"]);
    assert_eq!(
        fake.writes()[0].2,
        Some(json!({"allow_update_branch": false}))
    );
}

#[test]
fn a_failed_settings_write_names_the_repository() {
    let fake = Fake::default()
        .reply("GET", BASE, repository_page(json!({})))
        .fail("PATCH", BASE, 422);
    let patch = RepositorySettingsPatch {
        has_projects: Some(false),
        ..Default::default()
    };
    let error = host(&fake)
        .set_repository_settings(&token(), &patch)
        .unwrap_err();
    assert_eq!(error.kind, HostErrorKind::Transport);
    assert_eq!(
        error.message,
        "updating the settings of example-owner/example failed (422: Validation Failed)"
    );
}

// --- environments (#877) ------------------------------------------------------------------

fn environments_page() -> String {
    format!("{BASE}/environments?per_page=100&page=1")
}
fn policies_page(environment: &str) -> String {
    format!("{BASE}/environments/{environment}/deployment-branch-policies?per_page=100&page=1")
}
fn environment(name: &str, policy: DeploymentBranchPolicy) -> EnvironmentSpec {
    EnvironmentSpec {
        name: name.to_owned(),
        deployment_branch_policy: policy,
        reviewers: vec![],
        wait_timer_minutes: None,
    }
}
fn custom(patterns: &[&str]) -> DeploymentBranchPolicy {
    DeploymentBranchPolicy::Custom {
        patterns: patterns.iter().map(|p| (*p).to_owned()).collect(),
    }
}
/// The `features` reads with environments answering `environments`; the
/// other probes answer 404 or a plan refusal, so no verdict needs them.
fn with_features(fake: Fake, environments: Value) -> Fake {
    fake.reply(
        "GET",
        BASE,
        json!({"id": 7, "default_branch": "main", "visibility": "private", "private": true,
               "archived": false, "fork": false}),
    )
    .fail("GET", &format!("{BASE}/rulesets"), 403)
    .reply("GET", &format!("{BASE}/environments"), environments)
    .fail("GET", &format!("{BASE}/branches/main/protection"), 404)
    .fail("GET", &format!("{BASE}/vulnerability-alerts"), 404)
    .fail(
        "GET",
        &format!("{BASE}/contents/.github/workflows/actions.lock?ref=main"),
        404,
    )
}

#[test]
fn put_environment_creates_a_missing_environment_with_its_custom_branch_policies() {
    let fake = Fake::default()
        .reply(
            "GET",
            &environments_page(),
            json!({"total_count": 0, "environments": []}),
        )
        .reply(
            "PUT",
            &format!("{BASE}/environments/production"),
            json!({"id": 1}),
        )
        .reply(
            "POST",
            &format!("{BASE}/environments/production/deployment-branch-policies"),
            json!({"id": 2}),
        );
    let mut spec = environment("production", custom(&["main", "tag:v*"]));
    spec.wait_timer_minutes = Some(5);
    let report = host(&fake).put_environment(&token(), &spec).unwrap();
    let policies = format!("{BASE}/environments/production/deployment-branch-policies");
    assert_eq!(
        fake.writes(),
        vec![
            (
                "PUT".to_owned(),
                format!("{BASE}/environments/production"),
                Some(json!({
                    "wait_timer": 5,
                    "deployment_branch_policy": {
                        "protected_branches": false,
                        "custom_branch_policies": true,
                    },
                })),
            ),
            (
                "POST".to_owned(),
                policies.clone(),
                Some(json!({"name": "main", "type": "branch"})),
            ),
            (
                "POST".to_owned(),
                policies,
                Some(json!({"name": "v*", "type": "tag"})),
            ),
        ]
    );
    assert_eq!(report.created, ["production"]);
    assert!(report.updated.is_empty() && report.unchanged.is_empty());
}

#[test]
fn put_environment_already_matching_reports_unchanged_and_sends_nothing() {
    let fake = Fake::default()
        .reply(
            "GET",
            &environments_page(),
            json!({"total_count": 2, "environments": [
                {"id": 1, "name": "Production",
                 "deployment_branch_policy": {"protected_branches": false, "custom_branch_policies": true},
                 "protection_rules": [{"type": "wait_timer", "wait_timer": 5}]},
                {"id": 2, "name": "staging", "deployment_branch_policy": null},
            ]}),
        )
        .reply(
            "GET",
            &policies_page("Production"),
            json!({"total_count": 1, "branch_policies": [{"name": "main", "type": "branch"}]}),
        );
    let mut spec = environment("production", custom(&["main"]));
    spec.wait_timer_minutes = Some(5);
    let github = host(&fake);
    let report = github.put_environment(&token(), &spec).unwrap();
    assert_eq!(report.unchanged, ["production"]);
    let report = github
        .put_environment(
            &token(),
            &environment("staging", DeploymentBranchPolicy::Unrestricted),
        )
        .unwrap();
    assert_eq!(report.unchanged, ["staging"]);
    assert!(fake.writes().is_empty(), "{:?}", fake.writes());
}

#[test]
fn put_environment_updates_a_differing_policy_with_one_put() {
    let fake = Fake::default()
        .reply(
            "GET",
            &environments_page(),
            json!({"total_count": 1, "environments": [
                {"id": 1, "name": "production", "deployment_branch_policy": null,
                 "protection_rules": [{"type": "wait_timer", "wait_timer": 30}]},
            ]}),
        )
        .reply(
            "PUT",
            &format!("{BASE}/environments/production"),
            json!({"id": 1}),
        );
    let report = host(&fake)
        .put_environment(
            &token(),
            &environment("production", DeploymentBranchPolicy::ProtectedBranches),
        )
        .unwrap();
    assert_eq!(
        fake.writes(),
        vec![(
            "PUT".to_owned(),
            format!("{BASE}/environments/production"),
            Some(json!({"deployment_branch_policy": {
                "protected_branches": true,
                "custom_branch_policies": false,
            }})),
        )],
        "an undeclared wait timer is kept, not sent"
    );
    assert_eq!(report.updated, ["production"]);
}

#[test]
fn put_environment_sends_null_for_an_unrestricted_policy() {
    let fake = Fake::default()
        .reply(
            "GET",
            &environments_page(),
            json!({"total_count": 1, "environments": [
                {"id": 1, "name": "preview",
                 "deployment_branch_policy": {"protected_branches": true, "custom_branch_policies": false}},
            ]}),
        )
        .reply("PUT", &format!("{BASE}/environments/preview"), json!({"id": 1}));
    host(&fake)
        .put_environment(
            &token(),
            &environment("preview", DeploymentBranchPolicy::Unrestricted),
        )
        .unwrap();
    assert_eq!(
        fake.writes()[0].2,
        Some(json!({"deployment_branch_policy": null}))
    );
}

#[test]
fn put_environment_posts_only_missing_patterns_and_reports_undeclared_ones() {
    let fake = Fake::default()
        .reply(
            "GET",
            &environments_page(),
            json!({"total_count": 1, "environments": [
                {"id": 1, "name": "production",
                 "deployment_branch_policy": {"protected_branches": false, "custom_branch_policies": true}},
            ]}),
        )
        .reply(
            "GET",
            &policies_page("production"),
            json!({"total_count": 2, "branch_policies": [
                {"name": "main", "type": "branch"},
                {"name": "release/*", "type": "branch"},
            ]}),
        )
        .reply(
            "POST",
            &format!("{BASE}/environments/production/deployment-branch-policies"),
            json!({"id": 3}),
        );
    let report = host(&fake)
        .put_environment(
            &token(),
            &environment("production", custom(&["main", "hotfix/*"])),
        )
        .unwrap();
    assert_eq!(
        fake.writes(),
        vec![(
            "POST".to_owned(),
            format!("{BASE}/environments/production/deployment-branch-policies"),
            Some(json!({"name": "hotfix/*", "type": "branch"})),
        )]
    );
    assert_eq!(report.updated, ["production"]);
    assert_eq!(
        report.skipped,
        BTreeMap::from([(
            "production branch policy release/*".to_owned(),
            "the environment has it but it is not declared; removing it needs DELETE, which the host adapter does not send".to_owned(),
        )])
    );
}

#[test]
fn put_environment_with_reviewers_is_skipped_when_required_reviewers_is_unavailable() {
    let fake = with_features(Fake::default(), json!({})).fail_with(
        "GET",
        &format!("{BASE}/environments"),
        403,
        "Upgrade to GitHub Pro or make this repository public to enable this feature.",
    );
    let mut spec = environment("production", DeploymentBranchPolicy::ProtectedBranches);
    spec.reviewers = vec!["example-owner".into()];
    let report = host(&fake).put_environment(&token(), &spec).unwrap();
    assert!(fake.writes().is_empty(), "{:?}", fake.writes());
    assert!(report.created.is_empty() && report.updated.is_empty());
    assert_eq!(
        report.skipped,
        BTreeMap::from([(
            "production".to_owned(),
            "required reviewers are unavailable (403: Upgrade to GitHub Pro or make this repository public to enable this feature.), so the environment was not written".to_owned(),
        )])
    );
}

#[test]
fn put_environment_with_reviewers_is_attempted_when_required_reviewers_is_unknown() {
    let fake = with_features(
        Fake::default(),
        json!({"total_count": 0, "environments": []}),
    )
    .reply(
        "GET",
        &environments_page(),
        json!({"total_count": 0, "environments": []}),
    )
    .reply(
        "GET",
        "users/example-owner",
        json!({"login": "example-owner", "id": 42}),
    )
    .fail("PUT", &format!("{BASE}/environments/production"), 422);
    let mut spec = environment("production", DeploymentBranchPolicy::ProtectedBranches);
    spec.reviewers = vec!["example-owner".into()];
    let error = host(&fake).put_environment(&token(), &spec).unwrap_err();
    assert_eq!(
        fake.writes(),
        vec![(
            "PUT".to_owned(),
            format!("{BASE}/environments/production"),
            Some(json!({
                "reviewers": [{"type": "User", "id": 42}],
                "deployment_branch_policy": {
                    "protected_branches": true,
                    "custom_branch_policies": false,
                },
            })),
        )]
    );
    assert_eq!(error.kind, HostErrorKind::Transport);
    assert_eq!(
        error.message,
        "writing environment production in example-owner/example failed (422: Validation Failed)"
    );
}

#[test]
fn put_environment_sends_reviewers_by_id_when_required_reviewers_is_available() {
    let fake = with_features(
        Fake::default(),
        json!({"total_count": 1, "environments": [{"name": "staging",
            "protection_rules": [{"type": "required_reviewers",
                "reviewers": [{"type": "User", "reviewer": {"login": "someone"}}]}]}]}),
    )
    .reply(
        "GET",
        &environments_page(),
        json!({"total_count": 0, "environments": []}),
    )
    .reply(
        "GET",
        "users/example-owner",
        json!({"login": "example-owner", "id": 42}),
    )
    .reply(
        "PUT",
        &format!("{BASE}/environments/production"),
        json!({"id": 1}),
    );
    let mut spec = environment("production", DeploymentBranchPolicy::ProtectedBranches);
    spec.reviewers = vec!["example-owner".into()];
    let report = host(&fake).put_environment(&token(), &spec).unwrap();
    assert_eq!(
        fake.writes(),
        vec![(
            "PUT".to_owned(),
            format!("{BASE}/environments/production"),
            Some(json!({
                "reviewers": [{"type": "User", "id": 42}],
                "deployment_branch_policy": {
                    "protected_branches": true,
                    "custom_branch_policies": false,
                },
            })),
        )]
    );
    assert_eq!(report.created, ["production"]);
}

#[test]
fn put_environment_refuses_a_team_reviewer_and_an_empty_name_before_any_call() {
    let mut team = environment("production", DeploymentBranchPolicy::ProtectedBranches);
    team.reviewers = vec!["some-org/admins".into()];
    let unnamed = environment(" ", DeploymentBranchPolicy::ProtectedBranches);
    for (spec, needle) in [(team, "some-org/admins"), (unnamed, "name")] {
        let fake = Fake::default();
        let error = host(&fake).put_environment(&token(), &spec).unwrap_err();
        assert_eq!(error.kind, HostErrorKind::WriteRefused);
        assert!(error.message.contains(needle), "{}", error.message);
        assert!(fake.calls.borrow().is_empty());
    }
}

// --- rulesets (#878) ------------------------------------------------------------------------

const RULESET: &str = "brakes: default branch baseline";

fn rulesets_page() -> String {
    format!("{BASE}/rulesets?per_page=100&page=1")
}
fn pull_request_parameters(dismiss_stale: bool) -> Value {
    json!({
        "required_approving_review_count": 0,
        "dismiss_stale_reviews_on_push": dismiss_stale,
        "require_code_owner_review": false,
        "require_last_push_approval": false,
        "required_review_thread_resolution": true,
        "allowed_merge_methods": ["squash"],
    })
}
fn checks_parameters() -> Value {
    json!({
        "strict_required_status_checks_policy": false,
        "required_status_checks": [{"context": "required", "integration_id": 15368}],
    })
}
/// The ruleset `repo-baseline` renders for P1 `checks-only`, as a `Ruleset`.
fn declared_ruleset() -> Ruleset {
    Ruleset {
        id: None,
        name: RULESET.to_owned(),
        target: "branch".to_owned(),
        enforcement: "active".to_owned(),
        include: vec!["~DEFAULT_BRANCH".to_owned()],
        exclude: vec![],
        rules: ["deletion", "pull_request", "required_status_checks"]
            .map(str::to_owned)
            .to_vec(),
        required_status_checks: vec!["required".to_owned()],
        required_approving_review_count: Some(0),
        bypass_actors: vec![],
        rule_parameters: BTreeMap::from([
            ("pull_request".to_owned(), pull_request_parameters(true)),
            ("required_status_checks".to_owned(), checks_parameters()),
        ]),
    }
}
/// The body `put_ruleset` sends for `declared_ruleset()`.
fn ruleset_body(bypass_actors: Value) -> Value {
    json!({
        "name": RULESET,
        "target": "branch",
        "enforcement": "active",
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
        "bypass_actors": bypass_actors,
        "rules": [
            {"type": "deletion"},
            {"type": "pull_request", "parameters": pull_request_parameters(true)},
            {"type": "required_status_checks", "parameters": checks_parameters()},
        ],
    })
}
/// GitHub's detail of ruleset 42, with the fields and parameter keys GitHub adds.
fn remote_ruleset(dismiss_stale: bool) -> Value {
    let mut checks = checks_parameters();
    checks["do_not_enforce_on_create"] = json!(false);
    json!({
        "id": 42, "name": RULESET, "target": "branch", "enforcement": "active",
        "source_type": "Repository", "source": "example-owner/example",
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
        "bypass_actors": [],
        "rules": [
            {"type": "required_status_checks", "parameters": checks},
            {"type": "deletion"},
            {"type": "pull_request", "parameters": pull_request_parameters(dismiss_stale)},
        ],
    })
}

#[test]
fn put_ruleset_creates_a_missing_ruleset_with_the_exact_body() {
    let fake = Fake::default()
        .reply("GET", &rulesets_page(), json!([]))
        .reply("POST", &format!("{BASE}/rulesets"), json!({"id": 42}));
    let report = host(&fake)
        .put_ruleset(&token(), &declared_ruleset())
        .unwrap();
    assert_eq!(
        fake.writes(),
        vec![(
            "POST".to_owned(),
            format!("{BASE}/rulesets"),
            Some(ruleset_body(json!([]))),
        )],
        "no bypass actor is added by the adapter"
    );
    assert_eq!(report.created, [RULESET]);
}

#[test]
fn put_ruleset_already_matching_reports_unchanged_and_sends_nothing() {
    let fake = Fake::default()
        .reply(
            "GET",
            &rulesets_page(),
            json!([{"id": 7, "name": "other"}, {"id": 42, "name": RULESET}]),
        )
        .reply(
            "GET",
            &format!("{BASE}/rulesets/7"),
            json!({
            "id": 7, "name": "other", "target": "tag", "enforcement": "active", "rules": []}),
        )
        .reply("GET", &format!("{BASE}/rulesets/42"), remote_ruleset(true));
    let report = host(&fake)
        .put_ruleset(&token(), &declared_ruleset())
        .unwrap();
    assert!(fake.writes().is_empty(), "{:?}", fake.writes());
    assert_eq!(report.unchanged, [RULESET]);
}

#[test]
fn put_ruleset_updates_a_differing_ruleset_by_id() {
    let fake = Fake::default()
        .reply(
            "GET",
            &rulesets_page(),
            json!([{"id": 42, "name": RULESET}]),
        )
        .reply("GET", &format!("{BASE}/rulesets/42"), remote_ruleset(false))
        .reply("PUT", &format!("{BASE}/rulesets/42"), json!({"id": 42}));
    let report = host(&fake)
        .put_ruleset(&token(), &declared_ruleset())
        .unwrap();
    assert_eq!(
        fake.writes(),
        vec![(
            "PUT".to_owned(),
            format!("{BASE}/rulesets/42"),
            Some(ruleset_body(json!([]))),
        )]
    );
    assert_eq!(report.updated, [RULESET]);
}

/// The owner's build renames a ruleset written under the tool's former name in
/// place, by its id, even when nothing else differs: never a second ruleset (#1067).
#[cfg(feature = "setup-core")]
#[test]
fn put_ruleset_renames_a_ruleset_found_by_its_former_name() {
    const FORMER: &str = "agentic-setup: default branch baseline";
    let mut remote = remote_ruleset(true);
    remote["name"] = json!(FORMER);
    let fake = Fake::default()
        .reply("GET", &rulesets_page(), json!([{"id": 42, "name": FORMER}]))
        .reply("GET", &format!("{BASE}/rulesets/42"), remote)
        .reply("PUT", &format!("{BASE}/rulesets/42"), json!({"id": 42}));
    let report = host(&fake)
        .put_ruleset(&token(), &declared_ruleset())
        .unwrap();
    assert_eq!(
        fake.writes(),
        vec![(
            "PUT".to_owned(),
            format!("{BASE}/rulesets/42"),
            Some(ruleset_body(json!([]))),
        )]
    );
    assert_eq!(report.updated, [RULESET]);
}

#[test]
fn put_ruleset_is_skipped_when_the_plan_refuses_rulesets() {
    let fake = Fake::default().fail_with(
        "GET",
        &rulesets_page(),
        403,
        "Upgrade to GitHub Pro or make this repository public to enable this feature.",
    );
    let report = host(&fake)
        .put_ruleset(&token(), &declared_ruleset())
        .unwrap();
    assert!(fake.writes().is_empty(), "{:?}", fake.writes());
    assert!(report.created.is_empty() && report.updated.is_empty());
    assert_eq!(
        report.skipped,
        BTreeMap::from([(
            RULESET.to_owned(),
            "rulesets are unavailable (403: Upgrade to GitHub Pro or make this repository public to enable this feature.), so the ruleset was not written".to_owned(),
        )])
    );
}

#[test]
fn put_ruleset_sends_the_repository_admin_bypass_only_as_declared() {
    let fake = Fake::default()
        .reply("GET", &rulesets_page(), json!([]))
        .reply("POST", &format!("{BASE}/rulesets"), json!({"id": 42}));
    let mut ruleset = declared_ruleset();
    ruleset.bypass_actors = vec!["RepositoryRole:5:always".to_owned()];
    host(&fake).put_ruleset(&token(), &ruleset).unwrap();
    assert_eq!(
        fake.writes()[0].2,
        Some(ruleset_body(json!([
            {"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"},
        ])))
    );
}

#[test]
fn put_ruleset_refuses_a_bypass_actor_outside_the_policy_before_any_call() {
    for (actor, why) in [
        (
            "Integration:15368:always",
            "type Integration is not allowed; bypass actors are OrganizationAdmin, RepositoryRole or Team, never an agent identity or App",
        ),
        (
            "User:1:pull_request",
            "type User is not allowed; bypass actors are OrganizationAdmin, RepositoryRole or Team, never an agent identity or App",
        ),
        (
            "DeployKey::always",
            "not actor_type:actor_id:bypass_mode with a numeric actor_id",
        ),
        (
            "Team:7:exempt",
            "mode exempt is not allowed; use pull_request or always",
        ),
        (
            "OrganizationAdmin:3:pull_request",
            "OrganizationAdmin is written with the id 1, which GitHub ignores",
        ),
    ] {
        let mut ruleset = declared_ruleset();
        ruleset.bypass_actors = vec![actor.to_owned()];
        let fake = Fake::default();
        let error = host(&fake).put_ruleset(&token(), &ruleset).unwrap_err();
        assert_eq!(error.kind, HostErrorKind::WriteRefused, "{actor}");
        assert_eq!(
            error.message,
            format!(
                "Remote write refused: ruleset \"{RULESET}\" of example-owner/example declares bypass actor {actor}: {why}"
            )
        );
        assert!(fake.calls.borrow().is_empty(), "{actor}");
    }
}

#[test]
fn put_ruleset_writes_exactly_the_declared_bypass_actors() {
    let fake = Fake::default()
        .reply("GET", &rulesets_page(), json!([]))
        .reply("POST", &format!("{BASE}/rulesets"), json!({"id": 42}));
    let mut ruleset = declared_ruleset();
    ruleset.bypass_actors = vec![
        "OrganizationAdmin:1:pull_request".to_owned(),
        "Team:7:always".to_owned(),
        "RepositoryRole:4:pull_request".to_owned(),
    ];
    host(&fake).put_ruleset(&token(), &ruleset).unwrap();
    assert_eq!(
        fake.writes()[0].2,
        Some(ruleset_body(json!([
            {"actor_id": 1, "actor_type": "OrganizationAdmin", "bypass_mode": "pull_request"},
            {"actor_id": 7, "actor_type": "Team", "bypass_mode": "always"},
            {"actor_id": 4, "actor_type": "RepositoryRole", "bypass_mode": "pull_request"},
        ])))
    );
}

#[test]
fn put_ruleset_matches_a_live_org_admin_bypass_whatever_id_github_returns() {
    for live_id in [json!(1), json!(null), json!(0)] {
        let mut remote = remote_ruleset(true);
        remote["bypass_actors"] = json!([
            {"actor_id": live_id, "actor_type": "OrganizationAdmin", "bypass_mode": "pull_request"}
        ]);
        let fake = Fake::default()
            .reply(
                "GET",
                &rulesets_page(),
                json!([{"id": 42, "name": RULESET}]),
            )
            .reply("GET", &format!("{BASE}/rulesets/42"), remote);
        let mut ruleset = declared_ruleset();
        ruleset.bypass_actors = vec!["OrganizationAdmin:1:pull_request".to_owned()];
        let report = host(&fake).put_ruleset(&token(), &ruleset).unwrap();
        assert!(fake.writes().is_empty(), "{live_id}: {:?}", fake.writes());
        assert_eq!(report.unchanged, [RULESET], "{live_id}");
    }
}

#[test]
fn put_ruleset_refuses_missing_or_stray_rule_parameters_before_any_call() {
    let mut missing = declared_ruleset();
    missing.rule_parameters.remove("pull_request");
    let mut stray = declared_ruleset();
    stray
        .rule_parameters
        .insert("merge_queue".to_owned(), json!({}));
    let mut unnamed = declared_ruleset();
    unnamed.name = String::new();
    for (ruleset, needle) in [
        (missing, "pull_request"),
        (stray, "merge_queue"),
        (unnamed, "name"),
    ] {
        let fake = Fake::default();
        let error = host(&fake).put_ruleset(&token(), &ruleset).unwrap_err();
        assert_eq!(error.kind, HostErrorKind::WriteRefused, "{needle}");
        assert!(error.message.contains(needle), "{}", error.message);
        assert!(fake.calls.borrow().is_empty(), "{needle}");
    }
}

// --- classic branch protection (#879) -------------------------------------------------------

fn protection_path(branch: &str) -> String {
    format!("{BASE}/branches/{branch}/protection")
}
/// Checks-only protection with administrators included, as "Never merge on red" asks.
fn protection_spec() -> BranchProtectionSpec {
    BranchProtectionSpec {
        required_status_checks: vec!["required".to_owned()],
        strict: true,
        enforce_admins: true,
        required_approving_review_count: None,
        required_linear_history: true,
        allow_force_pushes: false,
        allow_deletions: false,
    }
}
fn protection_body(enforce_admins: bool) -> Value {
    json!({
        "required_status_checks": {"strict": true, "contexts": ["required"]},
        "enforce_admins": enforce_admins,
        "required_pull_request_reviews": null,
        "restrictions": null,
        "required_linear_history": true,
        "allow_force_pushes": false,
        "allow_deletions": false,
    })
}
/// GitHub's answer for `protection_spec()`, with `enforce_admins` as given.
fn remote_protection(enforce_admins: bool) -> Value {
    json!({
        "url": "https://api.github.com/repos/example-owner/example/branches/main/protection",
        "required_status_checks": {"strict": true, "contexts": ["required"],
            "checks": [{"context": "required", "app_id": null}]},
        "enforce_admins": {"enabled": enforce_admins},
        "required_linear_history": {"enabled": true},
        "allow_force_pushes": {"enabled": false},
        "allow_deletions": {"enabled": false},
    })
}

#[test]
fn put_branch_protection_creates_it_on_an_unprotected_branch_with_the_full_body() {
    let path = protection_path("release%2F1.x");
    let fake = Fake::default()
        .fail_with("GET", &path, 404, "Branch not protected")
        .reply("PUT", &path, json!({}));
    let report = host(&fake)
        .put_branch_protection(&token(), "release/1.x", &protection_spec())
        .unwrap();
    assert_eq!(
        fake.writes(),
        vec![("PUT".to_owned(), path, Some(protection_body(true)))]
    );
    assert_eq!(report.created, ["release/1.x"]);
}

#[test]
fn put_branch_protection_already_matching_reports_unchanged_and_sends_nothing() {
    let fake = Fake::default().reply("GET", &protection_path("main"), remote_protection(true));
    let report = host(&fake)
        .put_branch_protection(&token(), "main", &protection_spec())
        .unwrap();
    assert!(fake.writes().is_empty(), "{:?}", fake.writes());
    assert_eq!(report.unchanged, ["main"]);
}

#[test]
fn put_branch_protection_updates_differing_protection() {
    let fake = Fake::default()
        .reply("GET", &protection_path("main"), remote_protection(false))
        .reply("PUT", &protection_path("main"), json!({}));
    let report = host(&fake)
        .put_branch_protection(&token(), "main", &protection_spec())
        .unwrap();
    assert_eq!(
        fake.writes(),
        vec![(
            "PUT".to_owned(),
            protection_path("main"),
            Some(protection_body(true))
        )]
    );
    assert_eq!(report.updated, ["main"]);
}

#[test]
fn put_branch_protection_is_skipped_when_the_plan_refuses_it() {
    let fake = Fake::default().fail_with(
        "GET",
        &protection_path("main"),
        403,
        "Upgrade to GitHub Pro or make this repository public to enable this feature.",
    );
    let report = host(&fake)
        .put_branch_protection(&token(), "main", &protection_spec())
        .unwrap();
    assert!(fake.writes().is_empty(), "{:?}", fake.writes());
    assert_eq!(
        report.skipped,
        BTreeMap::from([(
            "main".to_owned(),
            "branch protection is unavailable (403: Upgrade to GitHub Pro or make this repository public to enable this feature.), so it was not written".to_owned(),
        )])
    );
}

#[test]
fn put_branch_protection_refuses_required_checks_without_admins_and_an_empty_branch() {
    let mut admins_off = protection_spec();
    admins_off.enforce_admins = false;
    for (branch, spec, needle) in [
        ("main", admins_off, "enforce_admins"),
        ("", protection_spec(), "empty branch"),
    ] {
        let fake = Fake::default();
        let error = host(&fake)
            .put_branch_protection(&token(), branch, &spec)
            .unwrap_err();
        assert_eq!(error.kind, HostErrorKind::WriteRefused, "{needle}");
        assert!(error.message.contains(needle), "{}", error.message);
        assert!(fake.calls.borrow().is_empty(), "{needle}");
    }
}

#[test]
fn retire_branch_protection_on_an_unprotected_branch_sends_nothing() {
    let fake =
        Fake::default().fail_with("GET", &protection_path("main"), 404, "Branch not protected");
    let report = host(&fake)
        .retire_branch_protection(&token(), "main", None)
        .unwrap();
    assert!(fake.writes().is_empty(), "{:?}", fake.writes());
    assert_eq!(report.unchanged, ["main"]);
}

#[test]
fn retire_branch_protection_deletes_it_once_a_ruleset_requires_its_checks() {
    let fake = Fake::default()
        .reply("GET", &protection_path("main"), remote_protection(true))
        .reply(
            "GET",
            &rulesets_page(),
            json!([{"id": 42, "name": RULESET}]),
        )
        .reply("GET", &format!("{BASE}/rulesets/42"), remote_ruleset(true))
        .reply("GET", BASE, repository_page(json!({})))
        .reply("DELETE", &protection_path("main"), Value::Null);
    let report = host(&fake)
        .retire_branch_protection(&token(), "main", None)
        .unwrap();
    assert_eq!(
        fake.writes(),
        vec![("DELETE".to_owned(), protection_path("main"), None)]
    );
    assert_eq!(report.removed, ["main"]);
}

#[test]
fn retire_branch_protection_is_refused_while_no_ruleset_requires_its_checks() {
    let mut ruleset = remote_ruleset(true);
    ruleset["rules"] = json!([{"type": "deletion"}]);
    let fake = Fake::default()
        .reply("GET", &protection_path("main"), remote_protection(true))
        .reply(
            "GET",
            &rulesets_page(),
            json!([{"id": 42, "name": RULESET}]),
        )
        .reply("GET", &format!("{BASE}/rulesets/42"), ruleset)
        .reply("GET", BASE, repository_page(json!({})));
    let error = host(&fake)
        .retire_branch_protection(&token(), "main", None)
        .unwrap_err();
    assert!(fake.writes().is_empty(), "{:?}", fake.writes());
    assert_eq!(error.kind, HostErrorKind::WriteRefused);
    assert_eq!(
        error.message,
        "Remote write refused: classic protection of branch main in example-owner/example is not retired, because no active ruleset that applies to main requires required"
    );
}

// --- surface -----------------------------------------------------------------------------

/// Runs every implemented write once and returns what the fake saw.
fn whole_write_suite() -> Fake {
    let fake = Fake::default()
        .reply(
            "GET",
            &labels_page(),
            json!([{"name": "old", "color": "000000"}]),
        )
        .reply("POST", &format!("{BASE}/labels"), json!({"id": 1}))
        .reply("PATCH", &format!("{BASE}/labels/old"), json!({"id": 2}))
        .reply(
            "POST",
            &format!("{BASE}/issues"),
            json!({"number": 1, "title": "t", "state": "open"}),
        )
        .reply(
            "POST",
            &format!("{BASE}/issues/1/comments"),
            json!({"id": 3}),
        )
        .reply("GET", BASE, repository_page(json!({})))
        .reply("PATCH", BASE, json!({"id": 7}))
        .fail("GET", &format!("{BASE}/vulnerability-alerts"), 404)
        .reply("PUT", &format!("{BASE}/vulnerability-alerts"), Value::Null)
        .reply(
            "GET",
            &environments_page(),
            json!({"total_count": 0, "environments": []}),
        )
        .reply(
            "PUT",
            &format!("{BASE}/environments/production"),
            json!({"id": 1}),
        )
        .reply(
            "POST",
            &format!("{BASE}/environments/production/deployment-branch-policies"),
            json!({"id": 2}),
        )
        .reply("GET", &rulesets_page(), json!([{"id": 42}]))
        .reply("POST", &format!("{BASE}/rulesets"), json!({"id": 43}))
        .fail_with("GET", &protection_path("main"), 404, "Branch not protected")
        .reply("PUT", &protection_path("main"), json!({}))
        .reply("GET", &protection_path("legacy"), remote_protection(true))
        .reply(
            "GET",
            &format!("{BASE}/rulesets/42"),
            json!({"id": 42, "name": "all", "target": "branch", "enforcement": "active",
                   "conditions": {"ref_name": {"include": ["~ALL"], "exclude": []}},
                   "rules": [{"type": "required_status_checks", "parameters":
                       {"required_status_checks": [{"context": "required"}]}}]}),
        )
        .reply("DELETE", &protection_path("legacy"), Value::Null);
    let github = host(&fake);
    let token = token();
    github
        .ensure_labels(
            &token,
            &[label("old", "ffffff", None), label("new", "111111", None)],
        )
        .unwrap();
    github
        .create_issue(
            &token,
            &NewIssue {
                title: "t".into(),
                body: "b".into(),
                labels: vec![],
            },
        )
        .unwrap();
    github.comment(&token, 1, "c").unwrap();
    github
        .set_repository_settings(
            &token,
            &RepositorySettingsPatch {
                has_wiki: Some(false),
                vulnerability_alerts: Some(true),
                ..Default::default()
            },
        )
        .unwrap();
    github
        .put_environment(&token, &environment("production", custom(&["main"])))
        .unwrap();
    github.put_ruleset(&token, &declared_ruleset()).unwrap();
    github
        .put_branch_protection(&token, "main", &protection_spec())
        .unwrap();
    github
        .retire_branch_protection(&token, "legacy", None)
        .unwrap();
    fake
}

#[test]
fn no_write_reaches_a_forbidden_path_or_another_repository() {
    let fake = whole_write_suite();
    let writes = fake.writes();
    assert_eq!(writes.len(), 11, "every write of the suite was sent");
    for (method, path, body) in &writes {
        assert!(
            ["POST", "PATCH", "PUT"].contains(&method.as_str())
                || (method == "DELETE" && path.ends_with("/protection")),
            "{method} {path}"
        );
        assert!(
            path == BASE || path.starts_with(&format!("{BASE}/")),
            "{method} {path}"
        );
        let segments: Vec<&str> = path.split(['/', '?']).collect();
        for forbidden in ["secrets", "merge", "merges", "rerun", "collaborators"] {
            assert!(!segments.contains(&forbidden), "{method} {path}");
        }
        assert!(!path.starts_with("orgs/"), "{method} {path}");
        match body {
            Some(body) => assert!(refuse_secret_body(body).is_ok(), "{method} {path}"),
            None => assert!(
                ["PUT", "DELETE"].contains(&method.as_str()),
                "only a toggle PUT or the protection DELETE has no body: {path}"
            ),
        }
    }
}

#[test]
fn a_body_with_a_secret_value_key_is_refused_at_any_depth() {
    let error = refuse_secret_body(&json!({"a": [{"b": {"Encrypted_Value": "x"}}]})).unwrap_err();
    assert_eq!(
        error.to_string(),
        "Remote write refused: the request body carries a secret value field (encrypted_value), which the installer never sends"
    );
    assert!(refuse_secret_body(&json!({"name": "encrypted_value", "secrets": []})).is_ok());
}

#[test]
fn writes_spend_the_call_budget() {
    let fake = Fake::default().reply(
        "POST",
        &format!("{BASE}/issues/1/comments"),
        json!({"id": 3}),
    );
    let github = GitHub::new(&fake, CallBudget::new(0));
    let error = github.comment(&token(), 1, "c").unwrap_err();
    assert_eq!(error.kind, HostErrorKind::RateLimited { reset_epoch: None });
    assert!(fake.writes().is_empty());
}
