//! Fleet reads of the GitHub host adapter (#681): `owner`, `list_repositories`
//! (user vs organization, pagination, page cap, rate limit and call budget
//! mid-list), `org_rulesets` and `org_settings`, over a recording fake
//! transport and the sanitised fixtures under `tests/fixtures/github/`.
use brakes::{
    Result,
    host::{
        CallBudget, Host, HostError, HostErrorKind, HostKind, OwnerId, OwnerKind, Partial, RepoId,
        Visibility,
        github::GitHub,
        types::{OrgSettings, RepoSummary},
    },
    remote::{Api, HttpError, RateLimit},
};
use serde_json::{Value, json};

mod configured;
use configured::{capitalised, denied};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    path::Path,
};

enum Reply {
    Json(Value),
    Http(u16, &'static str),
}

#[derive(Default)]
struct Fake {
    replies: BTreeMap<String, Reply>,
    calls: RefCell<Vec<String>>,
    rate: Cell<Option<RateLimit>>,
    /// The rate limit seen after this many calls (a limit that runs out mid-list).
    rate_after: Option<(usize, RateLimit)>,
}
impl Fake {
    fn json(mut self, path: impl Into<String>, value: Value) -> Self {
        self.replies.insert(path.into(), Reply::Json(value));
        self
    }
    fn fixture(self, path: impl Into<String>, name: &str) -> Self {
        self.json(path, fixture(name))
    }
    fn http(mut self, path: impl Into<String>, status: u16, message: &'static str) -> Self {
        self.replies
            .insert(path.into(), Reply::Http(status, message));
        self
    }
    fn calls(&self) -> Vec<String> {
        self.calls.borrow().clone()
    }
}
impl Api for Fake {
    fn get(&self, path: &str) -> Result<Value> {
        self.calls.borrow_mut().push(path.to_owned());
        if let Some((after, limit)) = self.rate_after
            && self.calls.borrow().len() >= after
        {
            self.rate.set(Some(limit));
        }
        match self.replies.get(path) {
            Some(Reply::Json(value)) => Ok(value.clone()),
            Some(Reply::Http(status, message)) => Err(HttpError {
                status: *status,
                message: (*message).to_owned(),
            }
            .into()),
            None => Err(format!("unexpected GET {path}").into()),
        }
    }
    fn rate_limit(&self) -> Option<RateLimit> {
        self.rate.get()
    }
}

fn fixture(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/github")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(&path).expect(name)).expect(name)
}
fn host(fake: &Fake) -> GitHub<'_> {
    GitHub::new(fake, CallBudget::default())
}
fn owner(name: &str, kind: OwnerKind) -> OwnerId {
    OwnerId {
        host: HostKind::GitHub,
        name: name.to_owned(),
        kind,
    }
}
fn err<T: std::fmt::Debug>(result: std::result::Result<T, HostError>) -> HostError {
    result.expect_err("expected a host error")
}

const ORG_REPOS: &str = "orgs/example-org/repos?type=all&per_page=100";

/// `count` repositories of `example-org`, numbered from `first`, in reverse
/// order so the test sees the adapter sort them.
fn org_page(first: usize, count: usize) -> Value {
    Value::Array(
        (first..first + count)
            .rev()
            .map(|i| {
                json!({"full_name": format!("example-org/repo-{i:05}"), "visibility": "private",
                    "default_branch": "main", "archived": false, "fork": false,
                    "pushed_at": null, "language": null})
            })
            .collect(),
    )
}

// --- owner ---------------------------------------------------------------------------------

#[test]
fn owner_reads_users_and_tells_a_user_from_an_organization() {
    let fake = Fake::default()
        .fixture("users/example-owner", "users_example_owner.json")
        .fixture("users/Example-Org", "users_example_org.json");
    let github = host(&fake);
    assert_eq!(
        github.owner("example-owner").unwrap(),
        owner("example-owner", OwnerKind::User)
    );
    assert_eq!(
        github.owner("Example-Org").unwrap(),
        owner("example-org", OwnerKind::Organization)
    );
    assert_eq!(fake.calls(), ["users/example-owner", "users/Example-Org"]);
}

#[test]
fn owner_of_another_type_is_unknown_and_a_missing_owner_is_not_found() {
    let fake = Fake::default()
        .json(
            "users/some-bot",
            json!({"login": "some-bot", "type": "Bot"}),
        )
        .http("users/nobody", 404, "Not Found");
    let github = host(&fake);
    assert_eq!(github.owner("some-bot").unwrap().kind, OwnerKind::Unknown);
    let error = err(github.owner("nobody"));
    assert_eq!(error.kind, HostErrorKind::NotFound);
    assert_eq!(error.message, "owner nobody was not found (404: Not Found)");
}

#[test]
fn denylisted_owners_are_refused_before_any_call() {
    let fake = Fake::default();
    let github = host(&fake);
    let word = denied();
    let word_cap = capitalised(&word);
    for error in [
        err(github.owner(&format!("{word_cap}-Tech"))),
        err(github.list_repositories(&owner(&word, OwnerKind::Organization))),
        err(github.org_rulesets(&word)),
        err(github.org_settings(&format!("{word}-tech"))),
    ] {
        assert_eq!(error.kind, HostErrorKind::Forbidden, "{error:?}");
        assert!(error.message.contains(&word_cap), "{error:?}");
    }
    assert!(fake.calls().is_empty());
}

// --- list_repositories: endpoint choice ------------------------------------------------------

#[test]
fn the_owners_own_listing_reads_user_repos_so_private_repositories_are_included() {
    let fake = Fake::default()
        .fixture("user", "user_owner_counts.json")
        .fixture(
            "user/repos?affiliation=owner&per_page=100&page=1",
            "user_repos.json",
        );
    let listing = host(&fake)
        .list_repositories(&owner("example-owner", OwnerKind::User))
        .unwrap();
    assert!(listing.is_complete());
    assert_eq!(
        fake.calls(),
        ["user", "user/repos?affiliation=owner&per_page=100&page=1"]
    );
    let names: Vec<String> = listing.items.iter().map(|r| r.id.to_string()).collect();
    assert_eq!(
        names,
        [
            "example-owner/archived-notes",
            "example-owner/example",
            "example-owner/forked-tool"
        ],
        "sorted by full name"
    );
    assert_eq!(
        listing.items[0],
        RepoSummary {
            id: RepoId::parse("example-owner/archived-notes").unwrap(),
            visibility: Visibility::Public,
            default_branch: "master".to_owned(),
            archived: true,
            fork: false,
            pushed_at: Some("2024-01-02T03:04:05Z".to_owned()),
            language: None,
        }
    );
    assert_eq!(listing.items[1].visibility, Visibility::Private);
    assert_eq!(listing.items[1].language.as_deref(), Some("Rust"));
    assert!(listing.items[2].fork);
    assert_eq!(listing.items[2].pushed_at, None);
}

#[test]
fn another_users_listing_reads_users_repos_with_type_owner() {
    let fake = Fake::default()
        .fixture("user", "user_owner_counts.json")
        .json(
            "users/someone",
            json!({"login": "someone", "type": "User", "public_repos": 1}),
        )
        .json(
            "users/someone/repos?type=owner&per_page=100&page=1",
            json!([{"full_name": "someone/tool", "visibility": "public", "default_branch": "main",
                "archived": false, "fork": false, "pushed_at": null, "language": null}]),
        );
    let listing = host(&fake)
        .list_repositories(&owner("someone", OwnerKind::User))
        .unwrap();
    assert!(listing.is_complete());
    assert_eq!(listing.items.len(), 1);
    assert_eq!(
        fake.calls(),
        [
            "user",
            "users/someone",
            "users/someone/repos?type=owner&per_page=100&page=1"
        ]
    );
}

#[test]
fn an_organization_listing_reads_orgs_repos_with_type_all_across_pages() {
    let fake = Fake::default()
        .fixture("orgs/example-org", "org.json")
        .json(format!("{ORG_REPOS}&page=1"), org_page(1, 100))
        .json(format!("{ORG_REPOS}&page=2"), org_page(101, 50));
    let listing = host(&fake)
        .list_repositories(&owner("example-org", OwnerKind::Organization))
        .unwrap();
    assert!(listing.is_complete());
    assert_eq!(listing.items.len(), 150);
    assert_eq!(listing.items[0].id.to_string(), "example-org/repo-00001");
    assert_eq!(listing.items[149].id.to_string(), "example-org/repo-00150");
    assert_eq!(
        fake.calls(),
        [
            "orgs/example-org".to_owned(),
            format!("{ORG_REPOS}&page=1"),
            format!("{ORG_REPOS}&page=2")
        ]
    );
}

#[test]
fn an_unknown_owner_kind_is_resolved_first() {
    let fake = Fake::default()
        .fixture("users/example-org", "users_example_org.json")
        .fixture("orgs/example-org", "org.json")
        .json(format!("{ORG_REPOS}&page=1"), org_page(1, 3));
    let listing = host(&fake)
        .list_repositories(&owner("example-org", OwnerKind::Unknown))
        .unwrap();
    assert_eq!(listing.items.len(), 3);
    assert_eq!(fake.calls()[0], "users/example-org");
}

#[test]
fn a_denylisted_identity_in_a_listing_is_left_out_and_reported_unread() {
    let word = denied();
    let fake = Fake::default()
        .fixture("user", "user_owner_counts.json")
        .json(
            "user/repos?affiliation=owner&per_page=100&page=1",
            json!([
                {"full_name": "example-owner/example", "visibility": "private", "default_branch": "main",
                 "archived": false, "fork": false, "pushed_at": null, "language": null},
                {"full_name": format!("example-owner/notes-{word}"), "visibility": "private", "default_branch": "main",
                 "archived": false, "fork": false, "pushed_at": null, "language": null}
            ]),
        );
    let listing = host(&fake)
        .list_repositories(&owner("example-owner", OwnerKind::User))
        .unwrap();
    assert_eq!(listing.items.len(), 1);
    assert_eq!(listing.stopped, None);
    assert_eq!(
        listing.unread,
        [format!(
            "1 repositories not read: {} identities are refused by the read gate",
            capitalised(&word)
        )]
    );
}

// --- list_repositories: partial and capped ---------------------------------------------------

#[test]
fn a_rate_limit_on_page_two_returns_what_was_read_and_counts_the_rest() {
    let fake = Fake::default()
        .fixture("orgs/example-org", "org.json")
        .json(format!("{ORG_REPOS}&page=1"), org_page(1, 100))
        .http(format!("{ORG_REPOS}&page=2"), 429, "slow down");
    let listing = host(&fake)
        .list_repositories(&owner("example-org", OwnerKind::Organization))
        .unwrap();
    assert_eq!(listing.items.len(), 100);
    let stopped = listing.stopped.clone().unwrap();
    assert_eq!(
        stopped.kind,
        HostErrorKind::RateLimited { reset_epoch: None }
    );
    assert_eq!(
        stopped.message,
        "GitHub rate limit reached while reading repositories of example-org (429: slow down)"
    );
    assert_eq!(
        listing.unread,
        ["50 repositories not read: example-org from page 2 on"]
    );
    assert!(!listing.is_complete());
}

#[test]
fn the_rate_limit_floor_mid_list_stops_without_calling_page_two() {
    let fake = Fake {
        rate_after: Some((
            2,
            RateLimit {
                remaining: 10,
                reset_epoch: Some(1_800_000_000),
            },
        )),
        ..Fake::default()
    }
    .fixture("orgs/example-org", "org.json")
    .json(format!("{ORG_REPOS}&page=1"), org_page(1, 100));
    let listing = host(&fake)
        .list_repositories(&owner("example-org", OwnerKind::Organization))
        .unwrap();
    assert_eq!(listing.items.len(), 100);
    assert_eq!(
        listing.stopped.unwrap().kind,
        HostErrorKind::RateLimited {
            reset_epoch: Some(1_800_000_000)
        }
    );
    assert_eq!(fake.calls().len(), 2, "page 2 was never requested");
    assert_eq!(
        listing.unread,
        ["50 repositories not read: example-org from page 2 on"]
    );
}

#[test]
fn call_budget_exhaustion_mid_list_is_partial_too() {
    let fake = Fake::default()
        .fixture("orgs/example-org", "org.json")
        .json(format!("{ORG_REPOS}&page=1"), org_page(1, 100));
    let github = GitHub::new(&fake, CallBudget::new(2));
    let listing = github
        .list_repositories(&owner("example-org", OwnerKind::Organization))
        .unwrap();
    assert_eq!(listing.items.len(), 100);
    let stopped = listing.stopped.unwrap();
    assert_eq!(
        stopped.kind,
        HostErrorKind::RateLimited { reset_epoch: None }
    );
    assert_eq!(stopped.message, "call budget of 2 exhausted");
    assert_eq!(
        listing.unread,
        ["50 repositories not read: example-org from page 2 on"]
    );
}

#[test]
fn an_unknown_count_says_so_instead_of_guessing() {
    let fake = Fake::default()
        .fixture("orgs/example-org", "org_outsider.json")
        .json(format!("{ORG_REPOS}&page=1"), org_page(1, 100))
        .http(format!("{ORG_REPOS}&page=2"), 429, "slow down");
    let listing = host(&fake)
        .list_repositories(&owner("example-org", OwnerKind::Organization))
        .unwrap();
    assert_eq!(
        listing.unread,
        ["repositories of example-org from page 2 on not read (count unknown)"]
    );
}

#[test]
fn a_rate_limit_before_any_page_is_an_error_and_other_errors_are_not_partial() {
    let fake = Fake::default().http("orgs/example-org", 429, "slow down");
    let error = err(host(&fake).list_repositories(&owner("example-org", OwnerKind::Organization)));
    assert!(matches!(error.kind, HostErrorKind::RateLimited { .. }));

    let fake = Fake::default()
        .fixture("orgs/example-org", "org.json")
        .json(format!("{ORG_REPOS}&page=1"), org_page(1, 100))
        .http(format!("{ORG_REPOS}&page=2"), 502, "Bad Gateway");
    let error = err(host(&fake).list_repositories(&owner("example-org", OwnerKind::Organization)));
    assert_eq!(error.kind, HostErrorKind::Transport);
}

#[test]
fn one_hundred_full_pages_are_truncated() {
    let mut fake = Fake::default().fixture("orgs/example-org", "org.json");
    for page in 1..=100 {
        fake = fake.json(
            format!("{ORG_REPOS}&page={page}"),
            org_page((page - 1) * 100 + 1, 100),
        );
    }
    let error = err(host(&fake).list_repositories(&owner("example-org", OwnerKind::Organization)));
    assert_eq!(error.kind, HostErrorKind::Truncated);
    assert_eq!(
        error.message,
        "repositories of example-org has more than 10000 items, the page cap of this read"
    );
    assert_eq!(fake.calls().len(), 101);
}

#[test]
fn a_repository_without_visibility_is_a_shape_error() {
    let fake = Fake::default().fixture("orgs/example-org", "org.json").json(
        format!("{ORG_REPOS}&page=1"),
        json!([{"full_name": "example-org/x", "default_branch": "main", "archived": false, "fork": false}]),
    );
    let error = err(host(&fake).list_repositories(&owner("example-org", OwnerKind::Organization)));
    assert_eq!(error.kind, HostErrorKind::Shape);
}

#[test]
fn a_complete_partial_is_the_listing() {
    let partial: Partial<RepoSummary> = Partial::complete(Vec::new());
    assert!(partial.is_complete());
}

// --- org_rulesets and org_settings ------------------------------------------------------------

#[test]
fn org_rulesets_read_the_list_then_each_detail() {
    let fake = Fake::default()
        .fixture(
            "orgs/example-org/rulesets?per_page=100&page=1",
            "org_rulesets.json",
        )
        .fixture("orgs/example-org/rulesets/7", "org_ruleset_7.json");
    let rulesets = host(&fake).org_rulesets("example-org").unwrap();
    assert_eq!(rulesets.len(), 1);
    assert_eq!(rulesets[0].name, "default-branch");
    assert_eq!(rulesets[0].include, ["~DEFAULT_BRANCH"]);
    assert_eq!(rulesets[0].required_approving_review_count, Some(1));
}

#[test]
fn org_rulesets_forbidden_names_the_plan_or_admin_need() {
    let fake = Fake::default().http(
        "orgs/example-org/rulesets?per_page=100&page=1",
        403,
        "Upgrade to GitHub Team to enable this feature.",
    );
    let error = err(host(&fake).org_rulesets("example-org"));
    assert_eq!(error.kind, HostErrorKind::Forbidden);
    assert_eq!(
        error.message,
        "organization rulesets of example-org are unavailable: organization rulesets need the Team plan or admin (403: Upgrade to GitHub Team to enable this feature.)"
    );
}

#[test]
fn org_settings_carry_what_the_token_sees_and_none_for_the_rest() {
    let fake = Fake::default().fixture("orgs/example-org", "org.json");
    assert_eq!(
        host(&fake).org_settings("example-org").unwrap(),
        OrgSettings {
            two_factor_requirement_enabled: Some(true),
            default_repository_permission: Some("read".to_owned()),
            members_can_create_public_repositories: Some(false),
            plan_hint: Some("team".to_owned()),
            web_commit_signoff_required: Some(false),
        }
    );
    let fake = Fake::default().fixture("orgs/example-org", "org_outsider.json");
    assert_eq!(
        host(&fake).org_settings("example-org").unwrap(),
        OrgSettings::default(),
        "unseen fields are None, never false"
    );
    let fake = Fake::default().http("orgs/nowhere", 404, "Not Found");
    assert_eq!(
        err(host(&fake).org_settings("nowhere")).message,
        "organization nowhere was not found (404: Not Found)"
    );
}

#[test]
fn org_owners_are_the_logins_of_the_admin_members() {
    let fake = Fake::default().json(
        "orgs/example-org/members?role=admin&per_page=100&page=1",
        serde_json::json!([
            {"login": "alice", "id": 1, "type": "User", "site_admin": false},
            {"login": "bob", "id": 2, "type": "User", "site_admin": false}
        ]),
    );
    assert_eq!(
        host(&fake).org_owners("example-org").unwrap(),
        ["alice", "bob"]
    );
    assert_eq!(
        fake.calls(),
        ["orgs/example-org/members?role=admin&per_page=100&page=1"]
    );
    let fake = Fake::default().http(
        "orgs/example-org/members?role=admin&per_page=100&page=1",
        403,
        "Must have admin rights",
    );
    assert_eq!(
        err(host(&fake).org_owners("example-org")).message,
        "Reading owners of organization example-org is forbidden (403: Must have admin rights)"
    );
}
