//! The GitHub implementation of `Host` over a recording fake transport (#676):
//! endpoints and queries, pagination, the HTTP mapping, the call budget, the
//! rate-limit floor and the sanitised fixtures under `tests/fixtures/github/`.
use brakes::{
    Result,
    host::{
        CallBudget, Host, HostError, HostErrorKind, HostKind, RepoId, SecretScope, Visibility,
        github::{FILE_CAP, GitHub, PAGE_CAP},
        types::{
            Branch, DependabotAlert, DeploymentBranchPolicy, DeploymentStatus, DirEntry, EntryKind,
            FileContents, IssueFilter, Label, PullFile, PullFilter, Release, RunFilter, RunTiming,
            SecretScanningAlert, SecurityToggle,
        },
    },
    remote::{Api, HttpError, RateLimit},
};
use serde_json::{Value, json};

mod configured;
use configured::{capitalised, denied};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    path::{Path, PathBuf},
};

const BASE: &str = "repos/example-owner/example";

enum Reply {
    Json(Value),
    Http(u16, &'static str),
    Unparsable,
}

/// Serves canned replies by path, records every GET, and reports the rate
/// limit the test sets, as `gh` would after its last response.
#[derive(Default)]
struct Fake {
    replies: BTreeMap<String, Reply>,
    calls: RefCell<Vec<String>>,
    rate: Cell<Option<RateLimit>>,
    /// The headers the next response carries, recorded as `gh` does after reading it.
    rate_after_call: Cell<Option<RateLimit>>,
}
impl Fake {
    fn with(mut self, path: impl Into<String>, reply: Reply) -> Self {
        self.replies.insert(path.into(), reply);
        self
    }
    fn json(self, path: impl Into<String>, value: Value) -> Self {
        self.with(path, Reply::Json(value))
    }
    fn calls(&self) -> Vec<String> {
        self.calls.borrow().clone()
    }
}
impl Api for Fake {
    fn get(&self, path: &str) -> Result<Value> {
        self.calls.borrow_mut().push(path.to_owned());
        if let Some(rate) = self.rate_after_call.get() {
            self.rate.set(Some(rate));
        }
        match self.replies.get(path) {
            Some(Reply::Json(value)) => Ok(value.clone()),
            Some(Reply::Http(status, message)) => Err(HttpError {
                status: *status,
                message: (*message).to_owned(),
            }
            .into()),
            Some(Reply::Unparsable) => Err(serde_json::from_str::<Value>("{\"id\":")
                .unwrap_err()
                .into()),
            None => Err(format!("unexpected GET {path}").into()),
        }
    }
    fn rate_limit(&self) -> Option<RateLimit> {
        self.rate.get()
    }
}

/// A fake that implements only `get`, as `tests/remote.rs` does.
struct GetOnly;
impl Api for GetOnly {
    fn get(&self, path: &str) -> Result<Value> {
        Err(format!("unexpected GET {path}").into())
    }
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/github")
}
fn fixture(name: &str) -> Value {
    let path = fixtures().join(name);
    serde_json::from_str(&std::fs::read_to_string(&path).expect(name)).expect(name)
}
fn repo() -> RepoId {
    RepoId::parse("example-owner/example").unwrap()
}
fn host(fake: &Fake) -> GitHub<'_> {
    GitHub::new(fake, CallBudget::default())
}
fn err<T: std::fmt::Debug>(result: std::result::Result<T, HostError>) -> HostError {
    result.expect_err("expected a host error")
}

// --- security reads (#801) ------------------------------------------------------------

#[test]
fn a_repository_variable_is_its_value_and_absent_on_404() {
    let fake = Fake::default()
        .json(
            format!("{BASE}/actions/variables/SECURITY_BYPASS"),
            json!({"name": "SECURITY_BYPASS", "value": "[\"osv-outage\"]"}),
        )
        .with(
            format!("{BASE}/actions/variables/OTHER"),
            Reply::Http(404, "Not Found"),
        );
    let host = host(&fake);
    assert_eq!(
        host.repo_variable(&repo(), "SECURITY_BYPASS").unwrap(),
        Some("[\"osv-outage\"]".to_owned())
    );
    assert_eq!(host.repo_variable(&repo(), "OTHER").unwrap(), None);
    let error = err(host.repo_variable(&repo(), "bad name"));
    assert_eq!(error.kind, HostErrorKind::Shape);
}

#[test]
fn releases_read_the_tag_and_the_publication_date() {
    let fake = Fake::default()
        .json(
            "repos/aquasecurity/trivy/releases/latest",
            json!({"tag_name": "v0.76.1", "published_at": "2026-10-21T11:18:34Z", "assets": []}),
        )
        .json(
            "repos/aquasecurity/trivy/releases/tags/v0.70.0",
            json!({"tag_name": "v0.70.0", "published_at": "2026-05-02T09:00:00Z"}),
        )
        .json(
            "repos/rhysd/actionlint/releases/latest",
            json!({"name": "x"}),
        );
    let host = host(&fake);
    let trivy = RepoId::parse("aquasecurity/trivy").unwrap();
    assert_eq!(
        host.latest_release(&trivy).unwrap(),
        Release {
            tag_name: "v0.76.1".to_owned(),
            published_at: "2026-10-21T11:18:34Z".to_owned()
        }
    );
    assert_eq!(
        host.release_by_tag(&trivy, "v0.70.0").unwrap().published_at,
        "2026-05-02T09:00:00Z"
    );
    let error = err(host.latest_release(&RepoId::parse("rhysd/actionlint").unwrap()));
    assert_eq!(error.kind, HostErrorKind::Shape);
}

#[test]
fn a_job_log_is_the_text_the_transport_reads() {
    let fake = Fake::default()
        .json(
            format!("{BASE}/actions/jobs/7/logs"),
            Value::String("history: full\n".to_owned()),
        )
        .json(format!("{BASE}/actions/jobs/8/logs"), json!({"x": 1}));
    let host = host(&fake);
    assert_eq!(host.job_log(&repo(), 7).unwrap(), "history: full\n");
    assert_eq!(err(host.job_log(&repo(), 8)).kind, HostErrorKind::Shape);
}

// --- transport compatibility -------------------------------------------------------

#[test]
fn a_get_only_transport_refuses_send_naming_the_method() {
    let error = GetOnly
        .send(
            "POST",
            "repos/example-owner/example/issues",
            Some(&json!({})),
        )
        .unwrap_err();
    let error = error.downcast_ref::<HostError>().expect("a HostError");
    assert_eq!(error.kind, HostErrorKind::Unsupported);
    assert_eq!(
        error.message,
        "POST repos/example-owner/example/issues is not supported by this read-only transport"
    );
    assert_eq!(GetOnly.rate_limit(), None);
}

// --- reads against the sanitised fixtures ------------------------------------------

#[test]
fn repository_reads_the_repository_endpoint_into_settings() {
    let fake = Fake::default().json(BASE, fixture("repository.json"));
    let settings = host(&fake).repository(&repo()).unwrap();
    assert_eq!(fake.calls(), [BASE]);
    assert_eq!(settings.id, "1412945614");
    assert_eq!(settings.default_branch, "main");
    assert_eq!(settings.visibility, Visibility::Private);
    assert!(!settings.archived && !settings.fork);
    assert_eq!(settings.delete_branch_on_merge, Some(true));
    assert_eq!(settings.allow_auto_merge, Some(false));
    assert_eq!(
        settings.secret_scanning, None,
        "null security_and_analysis is not visible"
    );
}

#[test]
fn repository_reads_secret_scanning_status_and_keeps_unseen_settings_none() {
    let fake = Fake::default().json(
        BASE,
        json!({"id": 1, "default_branch": "trunk", "visibility": "public", "archived": true, "fork": true,
            "security_and_analysis": {"secret_scanning": {"status": "enabled"},
                "secret_scanning_push_protection": {"status": "disabled"}}}),
    );
    let settings = host(&fake).repository(&repo()).unwrap();
    assert_eq!(settings.visibility, Visibility::Public);
    assert!(settings.archived && settings.fork);
    assert_eq!(settings.secret_scanning.as_deref(), Some("enabled"));
    assert_eq!(
        settings.secret_scanning_push_protection.as_deref(),
        Some("disabled")
    );
    assert_eq!(settings.allow_squash_merge, None);
}

#[test]
fn branch_protection_reads_contexts_and_flags() {
    let path = format!("{BASE}/branches/main/protection");
    let fake = Fake::default().json(&path, fixture("branch_protection.json"));
    let protection = host(&fake)
        .branch_protection(&repo(), "main")
        .unwrap()
        .unwrap();
    assert_eq!(fake.calls(), [path]);
    assert_eq!(protection.branch, "main");
    assert_eq!(
        protection.required_status_checks,
        [
            "Rust (linux)",
            "Rust (macos)",
            "build",
            "promote",
            "test / verify"
        ]
    );
    assert_eq!(protection.strict, Some(false));
    assert_eq!(protection.enforce_admins, Some(true));
    assert_eq!(protection.allow_force_pushes, Some(false));
    assert_eq!(protection.allow_deletions, Some(false));
    assert_eq!(protection.required_approving_review_count, None);
    assert_eq!(protection.require_code_owner_reviews, None);
}

#[test]
fn branch_protection_reads_the_review_requirements() {
    let path = format!("{BASE}/branches/main/protection");
    let fake = Fake::default().json(
        &path,
        json!({"required_pull_request_reviews": {
            "dismiss_stale_reviews": false,
            "require_code_owner_reviews": true,
            "required_approving_review_count": 2
        }}),
    );
    let protection = host(&fake)
        .branch_protection(&repo(), "main")
        .unwrap()
        .unwrap();
    assert_eq!(protection.required_approving_review_count, Some(2));
    assert_eq!(protection.require_code_owner_reviews, Some(true));
}

#[test]
fn branch_protection_is_none_when_github_says_not_protected_and_encodes_the_branch() {
    let path = format!("{BASE}/branches/release%2F1.0/protection");
    let fake = Fake::default().with(&path, Reply::Http(404, "Branch not protected"));
    assert_eq!(
        host(&fake)
            .branch_protection(&repo(), "release/1.0")
            .unwrap(),
        None
    );
    assert_eq!(fake.calls(), [path]);

    let fake = Fake::default().with(
        format!("{BASE}/branches/gone/protection"),
        Reply::Http(404, "Branch not found"),
    );
    assert_eq!(
        err(host(&fake).branch_protection(&repo(), "gone")).kind,
        HostErrorKind::NotFound
    );
}

#[test]
fn rulesets_read_the_list_then_each_ruleset() {
    let fake = Fake::default()
        .json(
            format!("{BASE}/rulesets?per_page=100&page=1"),
            fixture("rulesets.json"),
        )
        .json(format!("{BASE}/rulesets/42"), fixture("ruleset_42.json"));
    let rulesets = host(&fake).rulesets(&repo()).unwrap();
    assert_eq!(
        fake.calls(),
        [
            format!("{BASE}/rulesets?per_page=100&page=1"),
            format!("{BASE}/rulesets/42")
        ]
    );
    let main = &rulesets[0];
    assert_eq!(main.id, Some(42));
    assert_eq!(
        (
            main.name.as_str(),
            main.target.as_str(),
            main.enforcement.as_str()
        ),
        ("main", "branch", "active")
    );
    assert_eq!(main.include, ["~DEFAULT_BRANCH"]);
    assert!(main.exclude.is_empty());
    assert_eq!(
        main.rules,
        [
            "deletion",
            "non_fast_forward",
            "pull_request",
            "required_status_checks"
        ]
    );
    assert_eq!(main.required_status_checks, ["verify", "lint"]);
    assert_eq!(main.required_approving_review_count, Some(0));
    assert_eq!(main.bypass_actors, ["RepositoryRole:5:pull_request"]);
}

#[test]
fn environments_read_custom_branch_policies_by_name() {
    let fake = Fake::default()
        .json(
            format!("{BASE}/environments?per_page=100&page=1"),
            fixture("environments.json"),
        )
        .json(
            format!(
                "{BASE}/environments/production/deployment-branch-policies?per_page=100&page=1"
            ),
            fixture("deployment_branch_policies.json"),
        );
    let environments = host(&fake).environments(&repo()).unwrap();
    assert_eq!(fake.calls().len(), 2);
    assert_eq!(environments[0].name, "production");
    assert_eq!(environments[0].id, Some(25468712708));
    assert_eq!(
        environments[0].deployment_branch_policy,
        DeploymentBranchPolicy::Custom {
            patterns: vec!["main".to_owned()]
        }
    );
    assert!(environments[0].reviewers.is_empty());
}

#[test]
fn environments_map_unrestricted_protected_reviewers_wait_timer_and_tag_patterns() {
    let fake = Fake::default()
        .json(
            format!("{BASE}/environments?per_page=100&page=1"),
            json!({"total_count": 3, "environments": [
                {"name": "preview", "deployment_branch_policy": null},
                {"name": "staging", "deployment_branch_policy": {"protected_branches": true, "custom_branch_policies": false},
                 "protection_rules": [{"type": "wait_timer", "wait_timer": 5},
                    {"type": "required_reviewers", "reviewers": [{"type": "User", "reviewer": {"login": "example-owner"}},
                        {"type": "Team", "reviewer": {"slug": "maintainers"}}]}]},
                {"name": "release env", "deployment_branch_policy": {"protected_branches": false, "custom_branch_policies": true}}]}),
        )
        .json(
            format!("{BASE}/environments/release%20env/deployment-branch-policies?per_page=100&page=1"),
            json!({"total_count": 2, "branch_policies": [{"name": "main", "type": "branch"}, {"name": "v*", "type": "tag"}]}),
        );
    let environments = host(&fake).environments(&repo()).unwrap();
    assert_eq!(
        environments[0].deployment_branch_policy,
        DeploymentBranchPolicy::Unrestricted
    );
    assert_eq!(
        environments[1].deployment_branch_policy,
        DeploymentBranchPolicy::ProtectedBranches
    );
    assert_eq!(environments[1].reviewers, ["example-owner", "maintainers"]);
    assert_eq!(environments[1].wait_timer_minutes, Some(5));
    assert_eq!(
        environments[2].deployment_branch_policy,
        DeploymentBranchPolicy::Custom {
            patterns: vec!["main".to_owned(), "tag:v*".to_owned()]
        }
    );
}

#[test]
fn secret_names_read_each_scope_endpoint_and_keep_name_and_update_time_only() {
    for (scope, path) in [
        (
            SecretScope::Repository,
            format!("{BASE}/actions/secrets?per_page=100&page=1"),
        ),
        (
            SecretScope::Environment("production".to_owned()),
            format!("{BASE}/environments/production/secrets?per_page=100&page=1"),
        ),
        (
            SecretScope::Organization,
            format!("{BASE}/actions/organization-secrets?per_page=100&page=1"),
        ),
    ] {
        let fake = Fake::default().json(&path, fixture("secrets.json"));
        let names = host(&fake).secret_names(&repo(), &scope).unwrap();
        assert_eq!(fake.calls(), [path]);
        assert_eq!(
            names.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(),
            ["DEPLOY_HOOK_URL", "RELEASE_API_KEY"]
        );
        assert_eq!(names[0].scope, scope);
        assert_eq!(names[0].updated_at.as_deref(), Some("2026-10-27T14:11:51Z"));
        let printed = serde_json::to_string(&names).unwrap();
        assert!(!printed.contains("created_at"), "{printed}");
    }
}

#[test]
fn collaborators_carry_login_permission_and_type_only() {
    let fake = Fake::default().json(
        format!("{BASE}/collaborators?per_page=100&page=1"),
        fixture("collaborators.json"),
    );
    let people = host(&fake).collaborators(&repo()).unwrap();
    assert_eq!(people.len(), 1);
    assert_eq!(people[0].login, "example-owner");
    assert_eq!(people[0].permission, "admin");
    assert_eq!(people[0].kind.as_deref(), Some("User"));
}

#[test]
fn collaborators_without_role_name_take_the_strongest_permission_flag() {
    let fake = Fake::default().json(
        format!("{BASE}/collaborators?per_page=100&page=1"),
        json!([{"login": "a", "permissions": {"admin": false, "maintain": false, "push": true, "triage": true, "pull": true}},
               {"login": "b", "permissions": {"pull": true}}]),
    );
    let people = host(&fake).collaborators(&repo()).unwrap();
    assert_eq!(people[0].permission, "write");
    assert_eq!(people[1].permission, "read");
}

#[test]
fn pulls_send_the_filter_as_the_documented_query() {
    let path =
        format!("{BASE}/pulls?state=all&base=main&sort=updated&direction=desc&per_page=100&page=1");
    let fake = Fake::default().json(&path, fixture("pulls.json"));
    let filter = PullFilter {
        state: Some("all".to_owned()),
        base: Some("main".to_owned()),
        ..Default::default()
    };
    let pulls = host(&fake).pulls(&repo(), &filter).unwrap();
    assert_eq!(fake.calls(), [path]);
    assert_eq!(pulls.len(), 3);
    assert_eq!(pulls[0].number, 822);
    assert_eq!(pulls[0].state, "closed");
    assert_eq!(pulls[0].base, "main");
    assert_eq!(
        pulls[0].head_sha,
        "c9dac70654a690c1021a7a8ea82bf66d190ff450"
    );
    assert_eq!(pulls[0].author.as_deref(), Some("example-owner"));
    assert_eq!(pulls[0].draft, Some(false));
    assert_eq!(pulls[0].merged_at.as_deref(), Some("2026-10-28T16:29:09Z"));
    assert_eq!(
        pulls[0].merge_commit_sha.as_deref(),
        Some("817af378ed772c64c5e2d2526dbc234c423d02c9")
    );
}

/// `pull_files` (#983): one page of 100, name, status and the previous name
/// of a rename; recorded from agentic-project-setup#43, reduced to those fields.
#[test]
fn pull_files_read_one_page_with_the_previous_name_of_a_rename() {
    let path = format!("{BASE}/pulls/43/files?per_page=100&page=1");
    let fake = Fake::default().json(&path, fixture("pull_files.json"));
    let files = host(&fake).pull_files(&repo(), 43).unwrap();
    assert_eq!(fake.calls(), [path]);
    assert_eq!(files.len(), 8);
    assert_eq!(
        files[0],
        PullFile {
            filename: "docs/orchestration-technical-contract.md".to_owned(),
            status: "modified".to_owned(),
            previous_filename: None,
        }
    );
    let renamed = files.iter().find(|f| f.status == "renamed").unwrap();
    assert_eq!(renamed.filename, "orchestration/src/runner.rs");
    assert_eq!(
        renamed.previous_filename.as_deref(),
        Some("orchestration/src/codex_runner.rs")
    );
}

#[test]
fn pull_files_of_100_or_more_are_truncated_without_a_second_page() {
    let path = format!("{BASE}/pulls/7/files?per_page=100&page=1");
    let page: Value = (0..100)
        .map(|i| json!({"filename": format!("src/{i}.rs"), "status": "modified"}))
        .collect();
    let fake = Fake::default().json(&path, page);
    let error = err(host(&fake).pull_files(&repo(), 7));
    assert_eq!(error.kind, HostErrorKind::Truncated);
    assert_eq!(
        error.message,
        "files of pull request #7 in example-owner/example has 100 or more files, the cap of this read"
    );
    assert_eq!(fake.calls(), [path]);
}

#[test]
fn pulls_stop_at_the_limit_and_at_since_without_reading_more_pages() {
    let page = |n: u64| -> Value {
        (0..100)
            .map(|i| {
                let number = n * 1000 + i;
                json!({"number": number, "title": "t", "state": "open", "head": {"sha": "s"}, "base": {"ref": "main"},
                    "updated_at": format!("2026-10-{:02}T00:00:00Z", 28 - n)})
            })
            .collect()
    };
    let path = |n: u64| format!("{BASE}/pulls?sort=updated&direction=desc&per_page=100&page={n}");
    let fake = Fake::default()
        .json(path(1), page(1))
        .json(path(2), page(2))
        .json(path(3), page(3));
    let limited = host(&fake)
        .pulls(
            &repo(),
            &PullFilter {
                limit: Some(150),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(limited.len(), 150);
    assert_eq!(fake.calls(), [path(1), path(2)]);

    let fake = Fake::default()
        .json(path(1), page(1))
        .json(path(2), page(2))
        .json(path(3), page(3));
    let recent = host(&fake)
        .pulls(
            &repo(),
            &PullFilter {
                since: Some("2026-10-27T00:00:00Z".to_owned()),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(
        recent.len(),
        100,
        "page 1 is 27 October; page 2 is 26 October"
    );
    assert_eq!(fake.calls(), [path(1), path(2)]);
}

#[test]
fn file_exists_returns_the_blob_sha_none_on_404_and_none_for_a_directory() {
    let path = format!("{BASE}/contents/.github/workflows/actions.lock?ref=main");
    let fake = Fake::default().json(&path, fixture("contents_file.json"));
    assert_eq!(
        host(&fake)
            .file_exists(&repo(), ".github/workflows/actions.lock", "main")
            .unwrap()
            .as_deref(),
        Some("10f9957fa46c85c9fd5023b4209743c6ed5fd36a")
    );
    assert_eq!(fake.calls(), [path]);

    let fake = Fake::default().with(
        format!("{BASE}/contents/missing?ref=main"),
        Reply::Http(404, "Not Found"),
    );
    assert_eq!(
        host(&fake).file_exists(&repo(), "missing", "main").unwrap(),
        None
    );

    let fake = Fake::default().json(format!("{BASE}/contents/docs?ref=feature%2Fx"), json!([]));
    assert_eq!(
        host(&fake)
            .file_exists(&repo(), "docs", "feature/x")
            .unwrap(),
        None
    );
}

#[test]
fn file_exists_refuses_a_path_that_could_leave_contents_before_any_call() {
    for path in ["../../issues", "/README.md", "docs//x", "docs/./x", ""] {
        let fake = Fake::default();
        let error = err(host(&fake).file_exists(&repo(), path, "main"));
        assert_eq!(error.kind, HostErrorKind::Shape, "{path}");
        assert!(
            error.message.contains("is not a plain repository path"),
            "{}",
            error.message
        );
        assert!(fake.calls().is_empty(), "{path}");
    }
    let fake = Fake::default().json(
        format!("{BASE}/contents/a%20b/c%3Fd?ref=main"),
        json!({"sha": "1"}),
    );
    assert!(
        host(&fake)
            .file_exists(&repo(), "a b/c?d", "main")
            .unwrap()
            .is_some()
    );
}

// --- pagination ----------------------------------------------------------------------

/// Three pages (100, 100, 5) and a cap of `PAGE_CAP` full pages for every list read.
/// A list read: its name, its path without the page query, one item, and the
/// wrapper that turns a page of items into GitHub's response.
type ListRead = (
    &'static str,
    String,
    fn(u64) -> Value,
    fn(Vec<Value>) -> Value,
);

fn list_reads() -> Vec<ListRead> {
    let reads: Vec<ListRead> = vec![
        (
            "collaborators",
            format!("{BASE}/collaborators"),
            |i| json!({"login": format!("u{i}"), "role_name": "read"}),
            Value::Array,
        ),
        (
            "environments",
            format!("{BASE}/environments"),
            |i| json!({"name": format!("e{i}"), "deployment_branch_policy": null}),
            |items| json!({"total_count": 0, "environments": items}),
        ),
        (
            "secret_names",
            format!("{BASE}/actions/secrets"),
            |i| json!({"name": format!("S{i}")}),
            |items| json!({"total_count": 0, "secrets": items}),
        ),
        (
            "pulls",
            format!("{BASE}/pulls?sort=updated&direction=desc"),
            |i| json!({"number": i, "title": "t", "state": "open", "head": {"sha": "s"}, "base": {"ref": "main"}}),
            Value::Array,
        ),
        (
            "secret_scanning_alerts",
            format!("{BASE}/secret-scanning/alerts?state=open&hide_secret=true"),
            |i| json!({"number": i, "secret_type": "t", "created_at": "2026-10-20T10:15:00Z"}),
            Value::Array,
        ),
        (
            "rulesets",
            format!("{BASE}/rulesets"),
            |i| json!({"id": i}),
            Value::Array,
        ),
    ];
    reads.into_iter().chain(ci_list_reads()).collect()
}
fn read_list(host: &GitHub<'_>, read: &str) -> std::result::Result<usize, HostError> {
    let repo = repo();
    Ok(match read {
        "collaborators" => host.collaborators(&repo)?.len(),
        "environments" => host.environments(&repo)?.len(),
        "secret_names" => host.secret_names(&repo, &SecretScope::Repository)?.len(),
        "pulls" => host.pulls(&repo, &PullFilter::default())?.len(),
        "rulesets" => host.rulesets(&repo)?.len(),
        "secret_scanning_alerts" => host.secret_scanning_alerts(&repo)?.len(),
        other => return ci_read_list(host, other),
    })
}
fn page_path(base: &str, n: u32) -> String {
    let separator = if base.contains('?') { '&' } else { '?' };
    format!("{base}{separator}per_page=100&page={n}")
}
fn with_ruleset_details(mut fake: Fake, read: &str, count: u64) -> Fake {
    if read == "rulesets" {
        for i in 0..count {
            fake = fake.json(
                format!("{BASE}/rulesets/{i}"),
                json!({"id": i, "name": "r", "target": "branch", "enforcement": "active"}),
            );
        }
    }
    fake
}

#[test]
fn every_list_read_pages_across_three_pages_and_stops_under_100() {
    for (read, base, item, wrap) in list_reads() {
        let mut fake = Fake::default();
        let mut next = 0;
        for (n, size) in [(1, 100), (2, 100), (3, 5)] {
            fake = fake.json(
                page_path(&base, n),
                wrap((next..next + size).map(item).collect()),
            );
            next += size;
        }
        let fake = with_ruleset_details(fake, read, next);
        assert_eq!(read_list(&host(&fake), read).unwrap(), 205, "{read}");
        let pages: Vec<_> = fake
            .calls()
            .into_iter()
            .filter(|c| c.contains("per_page="))
            .collect();
        assert_eq!(
            pages,
            (1..=3).map(|n| page_path(&base, n)).collect::<Vec<_>>(),
            "{read}"
        );
    }
}

#[test]
fn every_list_read_reports_truncated_at_the_page_cap() {
    for (read, base, item, wrap) in list_reads() {
        let mut fake = Fake::default();
        for n in 1..=PAGE_CAP {
            fake = fake.json(page_path(&base, n), wrap((0..100).map(item).collect()));
        }
        let error = err(read_list(&host(&fake), read));
        assert_eq!(error.kind, HostErrorKind::Truncated, "{read}");
        assert!(
            error.message.contains("more than 3000 items"),
            "{}",
            error.message
        );
        assert_eq!(
            fake.calls().len(),
            PAGE_CAP as usize,
            "{read}: no page beyond the cap"
        );
    }
}

// --- HTTP mapping ------------------------------------------------------------------------

fn failing(reply: Reply, rate: Option<RateLimit>) -> HostError {
    let fake = Fake::default().with(BASE, reply);
    fake.rate_after_call.set(rate);
    err(host(&fake).repository(&repo()))
}

#[test]
fn http_401_is_unauthenticated() {
    let error = failing(Reply::Http(401, "Bad credentials"), None);
    assert_eq!(error.kind, HostErrorKind::Unauthenticated);
    assert_eq!(
        error.message,
        "GitHub CLI is not authenticated, so repository example-owner/example could not be read (401: Bad credentials)"
    );
}

#[test]
fn http_403_with_no_remaining_calls_and_429_are_rate_limited_with_the_reset() {
    let exhausted = Some(RateLimit {
        remaining: 0,
        reset_epoch: Some(1793215725),
    });
    let error = failing(Reply::Http(403, "API rate limit exceeded"), exhausted);
    assert_eq!(
        error.kind,
        HostErrorKind::RateLimited {
            reset_epoch: Some(1793215725)
        }
    );
    assert_eq!(
        error.message,
        "GitHub rate limit reached while reading repository example-owner/example (403: API rate limit exceeded)"
    );
    let error = failing(Reply::Http(429, "Too Many Requests"), None);
    assert_eq!(error.kind, HostErrorKind::RateLimited { reset_epoch: None });
}

#[test]
fn other_http_403_is_forbidden_and_keeps_githubs_message() {
    let upgrade = fixture("forbidden_upgrade.json");
    let message: &'static str = upgrade["message"].as_str().unwrap().to_owned().leak();
    let error = failing(
        Reply::Http(403, message),
        Some(RateLimit {
            remaining: 4000,
            reset_epoch: None,
        }),
    );
    assert_eq!(error.kind, HostErrorKind::Forbidden);
    assert_eq!(
        error.message,
        "Reading repository example-owner/example is forbidden (403: Upgrade to GitHub Pro or make this repository public to enable this feature.)"
    );
}

#[test]
fn http_404_is_not_found() {
    let error = failing(Reply::Http(404, "Not Found"), None);
    assert_eq!(error.kind, HostErrorKind::NotFound);
    assert_eq!(
        error.message,
        "repository example-owner/example was not found (404: Not Found)"
    );
}

#[test]
fn an_unparsable_body_and_a_wrong_shape_are_shape() {
    let error = failing(Reply::Unparsable, None);
    assert_eq!(error.kind, HostErrorKind::Shape);
    assert!(
        error
            .message
            .starts_with("repository example-owner/example has an unexpected shape: "),
        "{}",
        error.message
    );

    let error = failing(
        Reply::Json(json!({"id": 1, "default_branch": "main"})),
        None,
    );
    assert_eq!(error.kind, HostErrorKind::Shape);
    assert_eq!(
        error.message,
        "repository example-owner/example has an unexpected shape: missing or unknown visibility"
    );
    let fake = Fake::default().json(
        format!("{BASE}/collaborators?per_page=100&page=1"),
        json!({"message": "x"}),
    );
    assert_eq!(
        err(host(&fake).collaborators(&repo())).kind,
        HostErrorKind::Shape
    );
}

#[test]
fn a_transport_failure_and_other_statuses_are_transport() {
    // An unknown path is the fake's stand-in for gh missing, a timeout or a body over 4 MiB.
    let fake = Fake::default();
    let error = err(host(&fake).repository(&repo()));
    assert_eq!(error.kind, HostErrorKind::Transport);
    assert_eq!(
        error.message,
        "repository example-owner/example could not be read: unexpected GET repos/example-owner/example"
    );
    assert_eq!(
        failing(Reply::Http(502, "Bad Gateway"), None).kind,
        HostErrorKind::Transport
    );
}

#[test]
fn githubs_message_is_kept_on_one_line() {
    let error = failing(Reply::Http(403, "first line\nsecond\tline"), None);
    assert!(
        error.message.ends_with("(403: first line second line)"),
        "{}",
        error.message
    );
}

// --- call budget and rate-limit floor ------------------------------------------------------

#[test]
fn the_call_budget_stops_reads_with_a_rate_limited_error_without_reset() {
    let fake = Fake::default().json(BASE, fixture("repository.json"));
    let host = GitHub::new(&fake, CallBudget::new(2));
    host.repository(&repo()).unwrap();
    host.repository(&repo()).unwrap();
    let error = err(host.repository(&repo()));
    assert_eq!(error.kind, HostErrorKind::RateLimited { reset_epoch: None });
    assert_eq!(error.message, "call budget of 2 exhausted");
    assert_eq!(
        fake.calls().len(),
        2,
        "the third call never reached the transport"
    );
    assert_eq!(host.budget().used(), 2);
}

#[test]
fn the_budget_default_is_2000_and_pages_count_against_it() {
    let fake = Fake::default();
    assert_eq!(
        GitHub::new(&fake, CallBudget::default()).budget().limit(),
        2_000
    );
    let full: Value = (0..100)
        .map(|i| json!({"login": format!("u{i}"), "role_name": "read"}))
        .collect();
    let fake = Fake::default()
        .json(
            format!("{BASE}/collaborators?per_page=100&page=1"),
            full.clone(),
        )
        .json(format!("{BASE}/collaborators?per_page=100&page=2"), full);
    let error = err(GitHub::new(&fake, CallBudget::new(1)).collaborators(&repo()));
    assert_eq!(error.message, "call budget of 1 exhausted");
    assert_eq!(fake.calls().len(), 1);
}

#[test]
fn the_adapter_stops_under_50_remaining_calls_before_calling() {
    let fake = Fake::default().json(BASE, fixture("repository.json"));
    fake.rate.set(Some(RateLimit {
        remaining: 49,
        reset_epoch: Some(1793215725),
    }));
    let error = err(host(&fake).repository(&repo()));
    assert_eq!(
        error.kind,
        HostErrorKind::RateLimited {
            reset_epoch: Some(1793215725)
        }
    );
    assert_eq!(
        error.message,
        "GitHub rate limit is down to 49 calls, under the floor of 50, so repository example-owner/example was not read"
    );
    assert!(fake.calls().is_empty());

    fake.rate.set(Some(RateLimit {
        remaining: 50,
        reset_epoch: None,
    }));
    host(&fake).repository(&repo()).unwrap();
    assert_eq!(fake.calls().len(), 1);
}

// --- gates and unsupported operations ---------------------------------------------------

#[test]
fn a_hand_built_denylisted_identity_is_refused_with_no_call() {
    let fake = Fake::default();
    let word = denied();
    let repo = RepoId {
        host: HostKind::GitHub,
        owner: word.clone(),
        name: "x".to_owned(),
        project: None,
    };
    let error = err(host(&fake).repository(&repo));
    assert_eq!(error.kind, HostErrorKind::Forbidden);
    assert!(
        error.message.starts_with(&format!(
            "Remote read refused: {word}/x is a {} identity",
            capitalised(&word)
        )),
        "{}",
        error.message
    );
    assert!(fake.calls().is_empty());
}

#[test]
fn a_non_github_repository_is_unsupported_with_no_call() {
    let fake = Fake::default();
    let repo = RepoId {
        host: HostKind::AzureDevOps,
        owner: "org".to_owned(),
        project: Some("project".to_owned()),
        name: "repo".to_owned(),
    };
    let error = err(host(&fake).collaborators(&repo));
    assert_eq!(error.kind, HostErrorKind::Unsupported);
    assert_eq!(
        error.message,
        "org/project/repo is not a GitHub repository, so the GitHub host adapter cannot read it"
    );
    assert!(fake.calls().is_empty());
}

/// The fleet reads (`owner`, `list_repositories`, `org_rulesets`,
/// `org_settings`) left the `Unsupported` stubs in #681; `tests/host_fleet.rs` covers them.
#[test]
fn the_adapter_is_the_github_host() {
    let fake = Fake::default();
    assert_eq!(host(&fake).kind(), HostKind::GitHub);
    assert!(fake.calls().is_empty());
}

// --- security, branch and contents reads (#679) ------------------------------------------

const DEPENDABOT: &str = "repos/example-owner/example/dependabot/alerts?state=open&per_page=100";
const SECRET_SCANNING: &str = "repos/example-owner/example/secret-scanning/alerts?state=open&hide_secret=true&per_page=100&page=1";

#[test]
fn dependabot_alerts_read_one_page_of_open_alerts_with_severity_package_and_age() {
    let fake = Fake::default().json(DEPENDABOT, fixture("dependabot_alerts.json"));
    let alerts = host(&fake).dependabot_alerts(&repo()).unwrap();
    assert_eq!(fake.calls(), [DEPENDABOT]);
    assert_eq!(
        alerts,
        [
            DependabotAlert {
                number: 7,
                severity: "critical".to_owned(),
                package: Some("example-crate".to_owned()),
                ecosystem: Some("cargo".to_owned()),
                manifest_path: Some("orchestration/Cargo.lock".to_owned()),
                created_at: "2026-10-12T08:00:00Z".to_owned(),
            },
            DependabotAlert {
                number: 5,
                severity: "low".to_owned(),
                package: Some("example-package".to_owned()),
                ecosystem: Some("pip".to_owned()),
                manifest_path: Some("requirements.txt".to_owned()),
                created_at: "2026-09-30T17:45:00Z".to_owned(),
            },
        ]
    );
}

#[test]
fn dependabot_alerts_without_a_severity_are_shape_and_a_full_page_is_truncated() {
    let fake = Fake::default().json(
        DEPENDABOT,
        json!([{"number": 1, "created_at": "2026-10-01T00:00:00Z"}]),
    );
    let error = err(host(&fake).dependabot_alerts(&repo()));
    assert_eq!(error.kind, HostErrorKind::Shape);
    assert_eq!(
        error.message,
        "open Dependabot alerts of example-owner/example has an unexpected shape: missing severity"
    );

    let full: Value = (0..100)
        .map(|i| json!({"number": i, "security_advisory": {"severity": "low"}, "created_at": "2026-10-01T00:00:00Z"}))
        .collect();
    let fake = Fake::default().json(DEPENDABOT, full);
    let error = err(host(&fake).dependabot_alerts(&repo()));
    assert_eq!(error.kind, HostErrorKind::Truncated);
    assert_eq!(
        error.message,
        "open Dependabot alerts of example-owner/example has 100 or more items, the cap of this read"
    );
    assert_eq!(fake.calls(), [DEPENDABOT], "no guessed second page");
}

#[test]
fn alert_endpoints_map_403_to_forbidden_with_githubs_message() {
    for (name, path) in [
        ("dependabot_disabled.json", DEPENDABOT),
        ("dependabot_archived.json", DEPENDABOT),
    ] {
        let message: &'static str = fixture(name)["message"].as_str().unwrap().to_owned().leak();
        let fake = Fake::default().with(path, Reply::Http(403, message));
        let error = err(host(&fake).dependabot_alerts(&repo()));
        assert_eq!(error.kind, HostErrorKind::Forbidden, "{name}");
        assert_eq!(
            error.message,
            format!(
                "Reading open Dependabot alerts of example-owner/example is forbidden (403: {message})"
            )
        );
    }
    let fake = Fake::default().with(
        SECRET_SCANNING,
        Reply::Http(403, "Resource not accessible by integration"),
    );
    let error = err(host(&fake).secret_scanning_alerts(&repo()));
    assert_eq!(error.kind, HostErrorKind::Forbidden);
    assert_eq!(
        error.message,
        "Reading open secret-scanning alerts of example-owner/example is forbidden (403: Resource not accessible by integration)"
    );

    let disabled: &'static str = fixture("secret_scanning_disabled.json")["message"]
        .as_str()
        .unwrap()
        .to_owned()
        .leak();
    let fake = Fake::default().with(SECRET_SCANNING, Reply::Http(404, disabled));
    let error = err(host(&fake).secret_scanning_alerts(&repo()));
    assert_eq!(error.kind, HostErrorKind::NotFound);
    assert_eq!(
        error.message,
        "open secret-scanning alerts of example-owner/example was not found (404: Secret scanning is disabled on this repository.)"
    );
}

#[test]
fn secret_scanning_alerts_ask_github_to_hide_the_secret_and_carry_its_kind_only() {
    let fake = Fake::default().json(SECRET_SCANNING, fixture("secret_scanning_alerts.json"));
    let alerts = host(&fake).secret_scanning_alerts(&repo()).unwrap();
    assert_eq!(fake.calls(), [SECRET_SCANNING]);
    assert_eq!(
        alerts,
        [SecretScanningAlert {
            number: 3,
            secret_type: "example_service_api_credential".to_owned(),
            secret_type_display_name: Some("Example Service API credential".to_owned()),
            validity: Some("unknown".to_owned()),
            push_protection_bypassed: Some(false),
            created_at: "2026-10-20T10:15:00Z".to_owned(),
        }]
    );
}

#[test]
fn a_secret_github_sends_anyway_never_reaches_the_alert() {
    let fake = Fake::default().json(
        SECRET_SCANNING,
        json!([{"number": 1, "secret_type": "t", "created_at": "2026-10-20T10:15:00Z",
            "secret": "PLANTED-LITERAL", "secret_type_display_name": "T"}]),
    );
    let alerts = host(&fake).secret_scanning_alerts(&repo()).unwrap();
    let json = serde_json::to_string(&alerts).unwrap();
    assert!(!json.contains("PLANTED-LITERAL"), "{json}");
    assert!(!format!("{alerts:?}").contains("PLANTED-LITERAL"));
    let keys: Vec<String> = serde_json::to_value(&alerts[0])
        .unwrap()
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    assert!(!keys.iter().any(|k| k == "secret"), "{keys:?}");
}

#[test]
fn branches_read_one_page_then_each_last_commit_date() {
    let page = format!("{BASE}/branches?per_page=100&page=1");
    let first = format!("{BASE}/git/commits/5537864a0912be43f4a9327619f6b79f9f5f2cec");
    let main = format!("{BASE}/git/commits/36675625c6052bc5c3286dcbc5d0a0d44b2ecfa1");
    let fake = Fake::default()
        .json(&page, fixture("branches.json"))
        .json(&first, fixture("git_commit.json"))
        .json(
            &main,
            json!({"sha": "36675625c6052bc5c3286dcbc5d0a0d44b2ecfa1", "committer": {"date": "2026-10-28T19:02:11Z"}}),
        );
    let branches = host(&fake).branches(&repo()).unwrap();
    assert_eq!(fake.calls(), [page, first, main], "no page 2 under 100");
    assert_eq!(
        branches,
        [
            Branch {
                name: "a2-autonomy-policy-check".to_owned(),
                sha: "5537864a0912be43f4a9327619f6b79f9f5f2cec".to_owned(),
                protected: Some(false),
                committed_at: Some("2026-10-15T20:09:34Z".to_owned()),
            },
            Branch {
                name: "main".to_owned(),
                sha: "36675625c6052bc5c3286dcbc5d0a0d44b2ecfa1".to_owned(),
                protected: Some(true),
                committed_at: Some("2026-10-28T19:02:11Z".to_owned()),
            },
        ]
    );
}

#[test]
fn branches_beyond_100_are_truncated_before_any_commit_read_and_exactly_100_are_not() {
    let branch = |i: u64| json!({"name": format!("b{i}"), "commit": {"sha": format!("{i:040x}")}, "protected": false});
    let page = |n| format!("{BASE}/branches?per_page=100&page={n}");
    let full: Value = (0..100).map(branch).collect();

    let fake = Fake::default()
        .json(page(1), full.clone())
        .json(page(2), json!([branch(100)]));
    let error = err(host(&fake).branches(&repo()));
    assert_eq!(error.kind, HostErrorKind::Truncated);
    assert_eq!(
        error.message,
        "branches of example-owner/example has more than 100 items, the cap of this read"
    );
    assert_eq!(fake.calls(), [page(1), page(2)]);

    let mut fake = Fake::default().json(page(1), full).json(page(2), json!([]));
    for i in 0..100u64 {
        fake = fake.json(
            format!("{BASE}/git/commits/{i:040x}"),
            json!({"committer": {"date": "2026-10-01T00:00:00Z"}}),
        );
    }
    assert_eq!(host(&fake).branches(&repo()).unwrap().len(), 100);
    assert_eq!(fake.calls().len(), 102);
}

#[test]
fn branch_heads_read_names_without_dates_in_one_call() {
    let page = format!("{BASE}/branches?per_page=100&page=1");
    let fake = Fake::default().json(&page, fixture("branches.json"));
    let heads = host(&fake).branch_heads(&repo()).unwrap();
    assert_eq!(fake.calls(), [page], "no commit read, no page 2 under 100");
    assert_eq!(
        heads
            .iter()
            .map(|b| (b.name.as_str(), b.committed_at.as_deref()))
            .collect::<Vec<_>>(),
        [("a2-autonomy-policy-check", None), ("main", None)]
    );
    assert_eq!(heads[1].protected, Some(true));
}

#[test]
fn branch_heads_beyond_100_are_truncated() {
    let branch = |i: u64| json!({"name": format!("b{i}"), "commit": {"sha": format!("{i:040x}")}});
    let page = |n| format!("{BASE}/branches?per_page=100&page={n}");
    let full: Value = (0..100).map(branch).collect();
    let fake = Fake::default()
        .json(page(1), full)
        .json(page(2), json!([branch(100)]));
    let error = err(host(&fake).branch_heads(&repo()));
    assert_eq!(error.kind, HostErrorKind::Truncated);
    assert_eq!(fake.calls(), [page(1), page(2)]);
}

#[test]
fn commit_date_reads_one_commit() {
    let sha = "5537864a0912be43f4a9327619f6b79f9f5f2cec";
    let path = format!("{BASE}/git/commits/{sha}");
    let fake = Fake::default().json(&path, fixture("git_commit.json"));
    assert_eq!(
        host(&fake).commit_date(&repo(), sha).unwrap().as_deref(),
        Some("2026-10-15T20:09:34Z")
    );
    assert_eq!(fake.calls(), [path]);
}

#[test]
fn file_contents_decode_base64_text() {
    let path = format!("{BASE}/contents/VERSION?ref=main");
    let fake = Fake::default().json(&path, fixture("contents_text_file.json"));
    let file = host(&fake)
        .file_contents(&repo(), "VERSION", "main")
        .unwrap()
        .unwrap();
    assert_eq!(fake.calls(), [path]);
    assert_eq!(
        file,
        FileContents {
            path: "VERSION".to_owned(),
            sha: "1d0ba9ea182b0f7354f3daf12120744ec5e0c2f8".to_owned(),
            size: 6,
            text: "0.4.0\n".to_owned(),
        }
    );

    // GitHub wraps base64 every 60 characters; padding of one and two bytes.
    let fake = Fake::default().json(
        format!("{BASE}/contents/a/b.txt?ref=release%2F1"),
        json!({"type": "file", "path": "a/b.txt", "sha": "s", "size": 5, "encoding": "base64",
            "content": "aGVs\nbG8=\n"}),
    );
    let file = host(&fake)
        .file_contents(&repo(), "a/b.txt", "release/1")
        .unwrap()
        .unwrap();
    assert_eq!(file.text, "hello");
}

#[test]
fn file_contents_over_256_kib_are_truncated_before_decoding() {
    // The cap the workflow reader shares (SPEC-security.md Open question 16).
    assert_eq!(FILE_CAP, 256 * 1024);
    // The recorded 108769-byte decisions file is under the cap now.
    let path = format!("{BASE}/contents/docs/decisions.md?ref=main");
    let fake = Fake::default().json(&path, fixture("contents_large_file.json"));
    assert!(
        host(&fake)
            .file_contents(&repo(), "docs/decisions.md", "main")
            .is_ok()
    );

    let at_cap = json!({"type": "file", "path": "x", "sha": "s", "size": 262144, "encoding": "base64",
        "content": "QUFB\n".repeat(262144 / 3) + "QQ=="});
    let fake = Fake::default().json(format!("{BASE}/contents/x?ref=main"), at_cap);
    let file = host(&fake)
        .file_contents(&repo(), "x", "main")
        .unwrap()
        .unwrap();
    assert_eq!(file.text.len(), 262144);

    let big = json!({"type": "file", "path": "x", "sha": "s", "size": 300000, "encoding": "base64", "content": ""});
    let fake = Fake::default().json(format!("{BASE}/contents/x?ref=main"), big);
    assert_eq!(
        err(host(&fake).file_contents(&repo(), "x", "main")).message,
        "file x at main in example-owner/example is 300000 bytes, over the 262144-byte cap of this read"
    );

    let over = json!({"type": "file", "path": "x", "sha": "s", "size": 262145, "encoding": "base64", "content": ""});
    let fake = Fake::default().json(format!("{BASE}/contents/x?ref=main"), over);
    assert_eq!(
        err(host(&fake).file_contents(&repo(), "x", "main")).kind,
        HostErrorKind::Truncated
    );

    // A `size` that understates the content is caught after decoding.
    let lying = json!({"type": "file", "path": "x", "sha": "s", "size": 3, "encoding": "base64",
        "content": "QUFB".repeat(262144 / 3 + 1)});
    let fake = Fake::default().json(format!("{BASE}/contents/x?ref=main"), lying);
    assert_eq!(
        err(host(&fake).file_contents(&repo(), "x", "main")).message,
        "file x at main in example-owner/example is 262146 bytes, over the 262144-byte cap of this read"
    );
}

#[test]
fn file_contents_are_none_on_404_or_a_directory_and_shape_on_bad_content() {
    let path = format!("{BASE}/contents/missing?ref=main");
    let fake = Fake::default().with(&path, Reply::Http(404, "Not Found"));
    assert_eq!(
        host(&fake)
            .file_contents(&repo(), "missing", "main")
            .unwrap(),
        None
    );
    let path = format!("{BASE}/contents/.github/workflows?ref=main");
    let fake = Fake::default().json(&path, fixture("contents_directory.json"));
    assert_eq!(
        host(&fake)
            .file_contents(&repo(), ".github/workflows", "main")
            .unwrap(),
        None
    );

    let file = |content: &str, encoding: &str| json!({"type": "file", "path": "f", "sha": "s", "size": 3, "encoding": encoding, "content": content});
    for (body, detail) in [
        (file("!!!!", "base64"), "the content is not base64"),
        (file("QQ=A", "base64"), "the content is not base64"),
        (file("QQ==QUFB", "base64"), "the content is not base64"),
        (file("QUF", "base64"), "the content is not base64"),
        (file("//79", "base64"), "the content is not UTF-8 text"),
        (file("", "none"), "unsupported encoding none"),
        (
            json!({"type": "symlink", "path": "f", "sha": "s", "size": 3, "target": "VERSION"}),
            "the path is not a regular file",
        ),
    ] {
        let fake = Fake::default().json(format!("{BASE}/contents/f?ref=main"), body);
        let error = err(host(&fake).file_contents(&repo(), "f", "main"));
        assert_eq!(error.kind, HostErrorKind::Shape);
        assert_eq!(
            error.message,
            format!("file f at main in example-owner/example has an unexpected shape: {detail}")
        );
    }
}

#[test]
fn contents_reads_refuse_a_path_that_could_leave_contents_before_any_call() {
    let fake = Fake::default();
    for path in ["../secrets", "a//b", "./x"] {
        assert_eq!(
            err(host(&fake).file_contents(&repo(), path, "main")).kind,
            HostErrorKind::Shape
        );
        assert_eq!(
            err(host(&fake).list_directory(&repo(), path, "main")).kind,
            HostErrorKind::Shape
        );
    }
    assert!(fake.calls().is_empty());
}

#[test]
fn list_directory_keeps_name_type_and_sha_only() {
    let path = format!("{BASE}/contents/.github/workflows?ref=main");
    let fake = Fake::default().json(&path, fixture("contents_directory.json"));
    let entries = host(&fake)
        .list_directory(&repo(), ".github/workflows", "main")
        .unwrap()
        .unwrap();
    assert_eq!(fake.calls(), [path]);
    assert_eq!(entries.len(), 5);
    assert_eq!(
        entries[0],
        DirEntry {
            name: "checks.yml".to_owned(),
            kind: EntryKind::File,
            sha: "9ca9423f9faac105664b14c810bf1138b62f1307".to_owned(),
        }
    );
    assert_eq!(
        serde_json::to_value(&entries[0]).unwrap(),
        json!({"name": "checks.yml", "type": "file", "sha": "9ca9423f9faac105664b14c810bf1138b62f1307"})
    );
}

#[test]
fn list_directory_reads_the_root_maps_every_kind_and_is_none_on_404() {
    let root = format!("{BASE}/contents?ref=main");
    let fake = Fake::default().json(
        &root,
        json!([
            {"name": "docs", "type": "dir", "sha": "d"},
            {"name": "link", "type": "symlink", "sha": "l"},
            {"name": "vendor", "type": "submodule", "sha": "m"},
        ]),
    );
    let kinds: Vec<EntryKind> = host(&fake)
        .list_directory(&repo(), "", "main")
        .unwrap()
        .unwrap()
        .into_iter()
        .map(|e| e.kind)
        .collect();
    assert_eq!(
        kinds,
        [EntryKind::Dir, EntryKind::Symlink, EntryKind::Submodule]
    );
    assert_eq!(fake.calls(), [root]);

    let path = format!("{BASE}/contents/gone?ref=main");
    let fake = Fake::default().with(&path, Reply::Http(404, "Not Found"));
    assert_eq!(
        host(&fake).list_directory(&repo(), "gone", "main").unwrap(),
        None
    );
}

#[test]
fn list_directory_of_a_file_or_an_unknown_kind_is_shape() {
    let path = format!("{BASE}/contents/VERSION?ref=main");
    let fake = Fake::default().json(&path, fixture("contents_text_file.json"));
    let error = err(host(&fake).list_directory(&repo(), "VERSION", "main"));
    assert_eq!(error.kind, HostErrorKind::Shape);
    assert_eq!(
        error.message,
        "directory VERSION at main in example-owner/example has an unexpected shape: the path is not a directory"
    );
    let path = format!("{BASE}/contents/d?ref=main");
    let fake = Fake::default().json(&path, json!([{"name": "x", "type": "socket", "sha": "s"}]));
    assert_eq!(
        err(host(&fake).list_directory(&repo(), "d", "main")).message,
        "directory d at main in example-owner/example has an unexpected shape: unknown entry type socket"
    );
}

// --- fixtures ----------------------------------------------------------------------------

fn forbidden_keys(value: &Value, path: &str, found: &mut Vec<String>) {
    const FORBIDDEN: [&str; 5] = [
        "token",
        "secret_value",
        "encrypted_value",
        "password",
        "private_key",
    ];
    // Exact keys: `secret` is the literal value of a secret-scanning alert (#679);
    // `secrets` and `secret_scanning` are names and statuses, not values.
    const FORBIDDEN_EXACT: [&str; 1] = ["secret"];
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let lower = key.to_lowercase();
                if FORBIDDEN.iter().any(|f| lower.contains(f))
                    || FORBIDDEN_EXACT.contains(&lower.as_str())
                {
                    found.push(format!("{path}.{key}"));
                }
                forbidden_keys(child, &format!("{path}.{key}"), found);
            }
        }
        Value::Array(items) => {
            for (i, child) in items.iter().enumerate() {
                forbidden_keys(child, &format!("{path}[{i}]"), found);
            }
        }
        _ => {}
    }
}

#[test]
fn no_fixture_carries_a_secret_shaped_key() {
    let mut found = Vec::new();
    let mut files = 0;
    for entry in std::fs::read_dir(fixtures()).unwrap() {
        let path = entry.unwrap().path();
        let text = std::fs::read_to_string(&path).unwrap();
        let value: Value =
            serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        forbidden_keys(
            &value,
            &path.file_name().unwrap().to_string_lossy(),
            &mut found,
        );
        files += 1;
    }
    assert!(files >= 20, "the fixtures directory was read");
    assert!(
        found.is_empty(),
        "secret-shaped keys in fixtures: {found:?}"
    );

    let mut planted = Vec::new();
    forbidden_keys(
        &json!({"a": [{"Access_Token": "x"}], "encrypted_value": "y",
            "alerts": [{"Secret": "z", "secret_type": "t", "secrets": [], "secret_scanning": {}}]}),
        "planted",
        &mut planted,
    );
    assert_eq!(
        planted,
        [
            "planted.a[0].Access_Token",
            "planted.alerts[0].Secret",
            "planted.encrypted_value"
        ]
    );
}

// --- CI and delivery reads (#678) --------------------------------------------------------
// Fixtures shaped like the answers of read-only `gh api` GETs, sanitised
// to the fields the adapter reads.

fn ci_list_reads() -> Vec<ListRead> {
    vec![
        (
            "workflow_runs",
            format!("{BASE}/actions/runs"),
            |i| json!({"id": i, "name": "CI", "head_sha": "s", "head_branch": "main", "event": "push", "status": "completed"}),
            |items| json!({"total_count": 0, "workflow_runs": items}),
        ),
        (
            "jobs",
            format!("{BASE}/actions/runs/7/jobs"),
            |i| json!({"id": i, "name": "verify", "status": "completed"}),
            |items| json!({"total_count": 0, "jobs": items}),
        ),
        (
            "check_runs",
            format!("{BASE}/commits/abc/check-runs"),
            |i| json!({"id": i, "name": "verify", "status": "completed"}),
            |items| json!({"total_count": 0, "check_runs": items}),
        ),
        (
            "deployments",
            format!("{BASE}/deployments"),
            |i| json!({"id": i, "sha": "s", "environment": "production"}),
            Value::Array,
        ),
        (
            "deployment_statuses",
            format!("{BASE}/deployments/9/statuses"),
            |i| json!({"id": i, "state": "success"}),
            Value::Array,
        ),
        (
            "pulls_for_commit",
            format!("{BASE}/commits/abc/pulls"),
            |i| json!({"number": i, "title": "t", "state": "closed", "head": {"sha": "s"}, "base": {"ref": "main"}}),
            Value::Array,
        ),
        (
            "issues",
            format!("{BASE}/issues"),
            |i| json!({"number": i, "title": "t", "state": "open"}),
            Value::Array,
        ),
    ]
}
fn ci_read_list(host: &GitHub<'_>, read: &str) -> std::result::Result<usize, HostError> {
    let repo = repo();
    Ok(match read {
        "workflow_runs" => host.workflow_runs(&repo, &RunFilter::default())?.len(),
        "jobs" => host.jobs(&repo, 7)?.len(),
        "check_runs" => host.check_runs(&repo, "abc")?.len(),
        "deployments" => host.deployments(&repo, None)?.len(),
        "deployment_statuses" => host.deployment_statuses(&repo, 9)?.len(),
        "pulls_for_commit" => host.pulls_for_commit(&repo, "abc")?.len(),
        "issues" => host.issues(&repo, &IssueFilter::default())?.len(),
        other => panic!("{other}"),
    })
}

#[test]
fn workflow_runs_send_the_filter_and_carry_attempt_and_pull_requests() {
    let path = format!(
        "{BASE}/actions/runs?branch=main&event=push&status=completed&created=%3E%3D2026-10-01&per_page=100&page=1"
    );
    let fake = Fake::default().json(&path, fixture("workflow_runs.json"));
    let filter = RunFilter {
        branch: Some("main".to_owned()),
        event: Some("push".to_owned()),
        status: Some("completed".to_owned()),
        created_since: Some("2026-10-01".to_owned()),
        limit: None,
    };
    let runs = host(&fake).workflow_runs(&repo(), &filter).unwrap();
    assert_eq!(fake.calls(), [path]);
    assert_eq!(runs.len(), 3);
    assert_eq!(runs[0].id, 40764044137);
    assert_eq!(runs[0].status, "in_progress");
    assert_eq!(runs[0].conclusion, None);
    assert_eq!(runs[0].pull_requests, [1592]);
    assert_eq!(runs[1].head_branch, "main");
    assert_eq!(runs[1].event, "push");
    assert_eq!(runs[1].conclusion.as_deref(), Some("success"));
    assert_eq!(runs[1].run_attempt, Some(1));
    assert_eq!(runs[1].created_at.as_deref(), Some("2026-10-28T20:14:17Z"));
    assert_eq!(runs[2].run_attempt, Some(2), "a re-run is visible");
}

#[test]
fn workflow_runs_stop_at_the_limit_without_reading_more_pages() {
    let full: Value = (0..100)
        .map(|i| json!({"id": i, "name": "CI", "head_sha": "s", "head_branch": "main", "event": "push", "status": "completed"}))
        .collect();
    let path = format!("{BASE}/actions/runs?branch=main&per_page=100&page=1");
    let fake = Fake::default().json(&path, json!({"workflow_runs": full}));
    let filter = RunFilter {
        branch: Some("main".to_owned()),
        limit: Some(20),
        ..RunFilter::default()
    };
    let runs = host(&fake).workflow_runs(&repo(), &filter).unwrap();
    assert_eq!(runs.len(), 20);
    assert_eq!(fake.calls(), [path], "no second page");
}

#[test]
fn run_timing_reads_run_duration_ms() {
    let path = format!("{BASE}/actions/runs/40761452906/timing");
    let fake = Fake::default().json(&path, fixture("run_timing.json"));
    let timing = host(&fake).run_timing(&repo(), 40761452906).unwrap();
    assert_eq!(fake.calls(), [path]);
    assert_eq!(
        timing,
        RunTiming {
            run_id: 40761452906,
            run_duration_ms: 731000
        }
    );
}

#[test]
fn jobs_read_the_run_jobs_with_times_and_labels() {
    let path = format!("{BASE}/actions/runs/40761452906/jobs?per_page=100&page=1");
    let fake = Fake::default().json(&path, fixture("jobs.json"));
    let jobs = host(&fake).jobs(&repo(), 40761452906).unwrap();
    assert_eq!(fake.calls(), [path]);
    assert_eq!(jobs.len(), 3);
    assert_eq!(jobs[0].id, 123074173632);
    assert_eq!(jobs[0].name, "scripts-test");
    assert_eq!(jobs[0].conclusion.as_deref(), Some("success"));
    assert_eq!(jobs[0].started_at.as_deref(), Some("2026-10-28T20:14:35Z"));
    assert_eq!(
        jobs[0].completed_at.as_deref(),
        Some("2026-10-28T20:15:15Z")
    );
    assert_eq!(jobs[0].labels, ["example-runner-2"]);
}

#[test]
fn check_runs_read_the_commit_checks_with_the_app_slug() {
    let sha = "6141bf5d00dc182822b69611ed4e29bf608fd9fd";
    let path = format!("{BASE}/commits/{sha}/check-runs?per_page=100&page=1");
    let fake = Fake::default().json(&path, fixture("check_runs.json"));
    let checks = host(&fake).check_runs(&repo(), sha).unwrap();
    assert_eq!(fake.calls(), [path]);
    assert_eq!(checks.len(), 3);
    assert_eq!(checks[0].name, "backup");
    assert_eq!(checks[0].conclusion.as_deref(), Some("skipped"));
    assert_eq!(checks[2].name, "web");
    assert_eq!(checks[2].app.as_deref(), Some("github-actions"));
    assert_eq!(
        checks[2].completed_at.as_deref(),
        Some("2026-10-28T20:31:18Z")
    );
}

#[test]
fn deployments_filter_by_environment_and_carry_the_sha() {
    let path = format!("{BASE}/deployments?environment=production&per_page=100&page=1");
    let fake = Fake::default().json(&path, fixture("deployments.json"));
    let deployments = host(&fake)
        .deployments(&repo(), Some("production"))
        .unwrap();
    assert_eq!(fake.calls(), [path]);
    assert_eq!(deployments.len(), 3);
    assert_eq!(deployments[0].id, 7396475064);
    assert_eq!(deployments[0].environment, "production");
    assert_eq!(
        deployments[0].sha,
        "6141bf5d00dc182822b69611ed4e29bf608fd9fd"
    );
    assert_eq!(deployments[0].reference.as_deref(), Some("main"));
    assert_eq!(
        deployments[0].created_at.as_deref(),
        Some("2026-10-28T20:25:31Z")
    );
    assert_eq!(
        deployments[0].state, None,
        "the state is read per deployment"
    );

    let fake = Fake::default().json(
        format!("{BASE}/deployments?environment=pre%20prod&per_page=100&page=1"),
        json!([]),
    );
    assert!(
        host(&fake)
            .deployments(&repo(), Some("pre prod"))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn deployment_statuses_come_newest_first_so_the_first_is_the_final_status() {
    let path = format!("{BASE}/deployments/7396475064/statuses?per_page=100&page=1");
    let fake = Fake::default().json(&path, fixture("deployment_statuses.json"));
    let statuses = host(&fake)
        .deployment_statuses(&repo(), 7396475064)
        .unwrap();
    assert_eq!(fake.calls(), [path]);
    assert_eq!(statuses.len(), 5);
    assert_eq!(
        statuses[0],
        DeploymentStatus {
            id: 20854318427,
            state: "success".to_owned(),
            environment: Some("production".to_owned()),
            created_at: Some("2026-10-28T20:26:28Z".to_owned()),
        }
    );
    assert_eq!(statuses[4].state, "waiting");
}

#[test]
fn pulls_for_commit_carry_merged_at() {
    let sha = "6141bf5d00dc182822b69611ed4e29bf608fd9fd";
    let path = format!("{BASE}/commits/{sha}/pulls?per_page=100&page=1");
    let fake = Fake::default().json(&path, fixture("commit_pulls.json"));
    let pulls = host(&fake).pulls_for_commit(&repo(), sha).unwrap();
    assert_eq!(fake.calls(), [path]);
    assert_eq!(pulls.len(), 1);
    assert_eq!(pulls[0].number, 1583);
    assert_eq!(pulls[0].base, "main");
    assert_eq!(pulls[0].merged_at.as_deref(), Some("2026-10-28T20:14:14Z"));
    assert_eq!(pulls[0].merge_commit_sha.as_deref(), Some(sha));
}

#[test]
fn issues_send_the_filter_and_leave_pull_requests_out() {
    let path = format!(
        "{BASE}/issues?state=closed&labels=ops%3Aalert,incident&since=2026-10-01T00%3A00%3A00Z&per_page=100&page=1"
    );
    let fake = Fake::default().json(&path, fixture("issues.json"));
    let filter = IssueFilter {
        state: Some("closed".to_owned()),
        labels: vec!["ops:alert".to_owned(), "incident".to_owned()],
        since: Some("2026-10-01T00:00:00Z".to_owned()),
        limit: None,
    };
    let issues = host(&fake).issues(&repo(), &filter).unwrap();
    assert_eq!(fake.calls(), [path]);
    assert_eq!(issues.len(), 1, "the pull request item is not an issue");
    let issue = &issues[0];
    assert_eq!(issue.number, 1544);
    assert_eq!(issue.state, "closed");
    assert_eq!(issue.labels, ["ops:alert"]);
    assert_eq!(issue.author.as_deref(), Some("github-actions[bot]"));
    assert_eq!(issue.created_at.as_deref(), Some("2026-10-27T14:19:48Z"));
    assert_eq!(issue.closed_at.as_deref(), Some("2026-10-27T14:33:07Z"));
    assert_eq!(
        issue.url.as_deref(),
        Some("https://github.com/example-org/example-app/issues/1544")
    );
}

#[test]
fn issues_carry_the_body_issue_forms_write() {
    let path = format!("{BASE}/issues?state=open&per_page=100&page=1");
    let body = "### Due date\n\n2026-11-01";
    let fake = Fake::default().json(
        &path,
        json!([
            {"number": 7, "title": "a", "state": "open", "body": body},
            {"number": 8, "title": "b", "state": "open", "body": null}
        ]),
    );
    let filter = IssueFilter {
        state: Some("open".to_owned()),
        ..IssueFilter::default()
    };
    let issues = host(&fake).issues(&repo(), &filter).unwrap();
    assert_eq!(issues[0].body.as_deref(), Some(body));
    assert_eq!(issues[1].body, None);
}

#[test]
fn issues_stop_at_the_limit_counting_issues_only() {
    let page: Value = (0..100)
        .map(|i| {
            if i % 2 == 0 {
                json!({"number": i, "title": "t", "state": "open", "pull_request": {}})
            } else {
                json!({"number": i, "title": "t", "state": "open"})
            }
        })
        .collect();
    let fake = Fake::default()
        .json(format!("{BASE}/issues?per_page=100&page=1"), page.clone())
        .json(format!("{BASE}/issues?per_page=100&page=2"), page);
    let filter = IssueFilter {
        limit: Some(60),
        ..IssueFilter::default()
    };
    let issues = host(&fake).issues(&repo(), &filter).unwrap();
    assert_eq!(issues.len(), 60);
    assert!(issues.iter().all(|i| i.number % 2 == 1));
    assert_eq!(fake.calls().len(), 2, "50 issues on page 1 were not enough");
}

/// The path GitHub answers, the reply, the read, and the exact error message.
type ShapeCase = (String, Value, fn(&GitHub<'_>) -> HostError, &'static str);

#[test]
fn a_missing_field_in_a_ci_read_is_shape_naming_the_field() {
    let cases: Vec<ShapeCase> = vec![
        (
            format!("{BASE}/actions/runs/1/timing"),
            json!({"billable": {}}),
            |h| err(h.run_timing(&repo(), 1)),
            "timing of run 1 in example-owner/example has an unexpected shape: missing number field run_duration_ms",
        ),
        (
            format!("{BASE}/actions/runs?per_page=100&page=1"),
            json!({"workflow_runs": [{"id": 1, "name": "CI", "head_branch": "main", "event": "push", "status": "completed"}]}),
            |h| err(h.workflow_runs(&repo(), &RunFilter::default())),
            "workflow runs of example-owner/example has an unexpected shape: missing text field head_sha",
        ),
        (
            format!("{BASE}/deployments?per_page=100&page=1"),
            json!([{"id": 1, "environment": "production"}]),
            |h| err(h.deployments(&repo(), None)),
            "deployments of example-owner/example has an unexpected shape: missing text field sha",
        ),
        (
            format!("{BASE}/deployments/1/statuses?per_page=100&page=1"),
            json!([{"id": 1}]),
            |h| err(h.deployment_statuses(&repo(), 1)),
            "statuses of deployment 1 in example-owner/example has an unexpected shape: missing text field state",
        ),
        (
            format!("{BASE}/actions/runs/1/jobs?per_page=100&page=1"),
            json!({"jobs": [{"id": 1, "status": "completed"}]}),
            |h| err(h.jobs(&repo(), 1)),
            "jobs of run 1 in example-owner/example has an unexpected shape: missing text field name",
        ),
        (
            format!("{BASE}/commits/abc/check-runs?per_page=100&page=1"),
            json!({"check_runs": [{"name": "verify", "status": "completed"}]}),
            |h| err(h.check_runs(&repo(), "abc")),
            "check runs of commit abc in example-owner/example has an unexpected shape: missing number field id",
        ),
        (
            format!("{BASE}/commits/abc/pulls?per_page=100&page=1"),
            json!([{"number": 1, "title": "t", "state": "closed", "base": {"ref": "main"}}]),
            |h| err(h.pulls_for_commit(&repo(), "abc")),
            "pull requests of commit abc in example-owner/example has an unexpected shape: missing text field sha",
        ),
        (
            format!("{BASE}/issues?per_page=100&page=1"),
            json!([{"number": 1, "state": "open"}]),
            |h| err(h.issues(&repo(), &IssueFilter::default())),
            "issues of example-owner/example has an unexpected shape: missing text field title",
        ),
    ];
    for (path, reply, read, message) in cases {
        let fake = Fake::default().json(path, reply);
        let error = read(&host(&fake));
        assert_eq!(error.kind, HostErrorKind::Shape, "{message}");
        assert_eq!(error.message, message);
    }
}

#[test]
fn ci_reads_map_http_errors_as_every_other_read() {
    let fake = Fake::default()
        .with(
            format!("{BASE}/actions/runs/5/timing"),
            Reply::Http(404, "Not Found"),
        )
        .with(
            format!("{BASE}/deployments?environment=production&per_page=100&page=1"),
            Reply::Http(401, "Bad credentials"),
        )
        .with(
            format!("{BASE}/issues?per_page=100&page=1"),
            Reply::Http(403, "Resource not accessible by integration"),
        );
    let error = err(host(&fake).run_timing(&repo(), 5));
    assert_eq!(error.kind, HostErrorKind::NotFound);
    assert_eq!(
        error.message,
        "timing of run 5 in example-owner/example was not found (404: Not Found)"
    );
    let error = err(host(&fake).deployments(&repo(), Some("production")));
    assert_eq!(error.kind, HostErrorKind::Unauthenticated);
    assert_eq!(
        error.message,
        "GitHub CLI is not authenticated, so production deployments of example-owner/example could not be read (401: Bad credentials)"
    );
    let error = err(host(&fake).issues(&repo(), &IssueFilter::default()));
    assert_eq!(error.kind, HostErrorKind::Forbidden);
}

#[test]
fn ci_reads_encode_the_sha_and_pass_the_read_gate_before_any_call() {
    let fake = Fake::default().json(
        format!("{BASE}/commits/a%2F..%2Fb/check-runs?per_page=100&page=1"),
        json!({"check_runs": []}),
    );
    assert!(
        host(&fake)
            .check_runs(&repo(), "a/../b")
            .unwrap()
            .is_empty()
    );

    let denylisted = RepoId {
        host: HostKind::GitHub,
        owner: denied(),
        name: "x".to_owned(),
        project: None,
    };
    let fake = Fake::default();
    let host = host(&fake);
    assert_eq!(
        err(host.workflow_runs(&denylisted, &RunFilter::default())).kind,
        HostErrorKind::Forbidden
    );
    assert_eq!(
        err(host.run_timing(&denylisted, 1)).kind,
        HostErrorKind::Forbidden
    );
    assert_eq!(
        err(host.deployment_statuses(&denylisted, 1)).kind,
        HostErrorKind::Forbidden
    );
    assert_eq!(
        err(host.pulls_for_commit(&denylisted, "abc")).kind,
        HostErrorKind::Forbidden
    );
    assert!(fake.calls().is_empty());
}

// ---- reads the probe registry adds (#683) -------------------------------------------

#[test]
fn repository_reads_allow_update_branch() {
    let fake = Fake::default().json(
        BASE,
        json!({"id": 1, "default_branch": "main", "visibility": "private", "archived": false,
            "fork": false, "allow_update_branch": true}),
    );
    let settings = host(&fake).repository(&repo()).unwrap();
    assert_eq!(settings.allow_update_branch, Some(true));
}

#[test]
fn labels_page_the_label_list_and_keep_name_color_and_description() {
    let fake = Fake::default().json(
        format!("{BASE}/labels?per_page=100&page=1"),
        json!([{"id": 1, "name": "bug", "color": "d73a4a", "description": "Broken"},
               {"id": 2, "name": "status:ready", "color": "0e8a16", "description": null}]),
    );
    let labels = host(&fake).labels(&repo()).unwrap();
    assert_eq!(
        labels,
        [
            Label {
                name: "bug".to_owned(),
                color: "d73a4a".to_owned(),
                description: Some("Broken".to_owned())
            },
            Label {
                name: "status:ready".to_owned(),
                color: "0e8a16".to_owned(),
                description: None
            },
        ]
    );
}

#[test]
fn recent_commits_read_one_page_of_the_branch_history() {
    let fake = Fake::default().json(
        format!("{BASE}/commits?sha=release%2F1&per_page=10"),
        json!([{"sha": "aaa"}, {"sha": "bbb"}]),
    );
    let commits = host(&fake)
        .recent_commits(&repo(), "release/1", 10)
        .unwrap();
    assert_eq!(commits, ["aaa", "bbb"]);
}

#[test]
fn security_toggles_read_enabled_and_take_404_as_disabled_where_github_documents_it() {
    let fake = Fake::default()
        .json(format!("{BASE}/vulnerability-alerts"), Value::Null)
        .json(
            format!("{BASE}/automated-security-fixes"),
            json!({"enabled": false, "paused": false}),
        )
        .json(
            format!("{BASE}/private-vulnerability-reporting"),
            json!({"enabled": true}),
        );
    let host = GitHub::new(&fake, CallBudget::default());
    assert!(
        host.security_toggle(&repo(), SecurityToggle::VulnerabilityAlerts)
            .unwrap()
    );
    assert!(
        !host
            .security_toggle(&repo(), SecurityToggle::AutomatedSecurityFixes)
            .unwrap()
    );
    assert!(
        host.security_toggle(&repo(), SecurityToggle::PrivateVulnerabilityReporting)
            .unwrap()
    );

    let fake = Fake::default()
        .with(
            format!("{BASE}/vulnerability-alerts"),
            Reply::Http(404, "Not Found"),
        )
        .with(
            format!("{BASE}/automated-security-fixes"),
            Reply::Http(404, "Not Found"),
        )
        .with(
            format!("{BASE}/private-vulnerability-reporting"),
            Reply::Http(404, "Not Found"),
        );
    let host = GitHub::new(&fake, CallBudget::default());
    assert!(
        !host
            .security_toggle(&repo(), SecurityToggle::VulnerabilityAlerts)
            .unwrap()
    );
    assert!(
        !host
            .security_toggle(&repo(), SecurityToggle::AutomatedSecurityFixes)
            .unwrap()
    );
    let error = err(host.security_toggle(&repo(), SecurityToggle::PrivateVulnerabilityReporting));
    assert_eq!(error.kind, HostErrorKind::NotFound);
    assert_eq!(
        error.message,
        "private vulnerability reporting of example-owner/example was not found (404: Not Found)"
    );
}

#[test]
fn latest_deployments_read_the_newest_hundred_in_one_call() {
    let deployment = |i: u64| {
        json!({"id": i, "environment": "production", "sha": format!("{i:040x}"),
               "ref": "main", "created_at": "2026-10-28T20:25:31Z"})
    };
    let path = format!("{BASE}/deployments?environment=production&per_page=100&page=1");
    let full: Value = (0..100).map(deployment).collect();
    let fake = Fake::default().json(&path, full);
    let deployments = host(&fake)
        .latest_deployments(&repo(), "production")
        .unwrap();
    assert_eq!(fake.calls(), [path], "a full page never reads page 2");
    assert_eq!(deployments.len(), 100);
    assert_eq!(deployments[0].id, 0);
}
