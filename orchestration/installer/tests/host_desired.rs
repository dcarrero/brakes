//! The desired state of a remote item and the verb a pending item gets (#902;
//! SPEC-engine.md, Desired state of a remote item): `desired::change` reads the
//! host once through a recording fake transport and never writes.
use brakes::{
    Result,
    host::{
        CallBudget, HostErrorKind, RepoId, authorize,
        desired::{Change, Desired, RemoteWrite, Supersession, change, ruleset_from_file, write},
        github::GitHub,
        types::{
            BranchProtectionSpec, DeploymentBranchPolicy, EnvironmentSpec, Label,
            RepositorySettingsPatch,
        },
    },
    remote::{Api, HttpError},
};
use serde_json::{Value, json};
use std::{cell::RefCell, collections::BTreeMap};

const BASE: &str = "repos/example-owner/example";

#[derive(Default)]
struct Fake {
    replies: BTreeMap<String, std::result::Result<Value, (u16, String)>>,
    calls: RefCell<Vec<String>>,
    bodies: RefCell<Vec<(String, Option<Value>)>>,
}
impl Fake {
    fn reply(mut self, path: &str, value: Value) -> Self {
        self.replies.insert(path.to_owned(), Ok(value));
        self
    }
    fn fail(mut self, path: &str, status: u16, message: &str) -> Self {
        self.replies
            .insert(path.to_owned(), Err((status, message.to_owned())));
        self
    }
}
impl Api for Fake {
    fn get(&self, path: &str) -> Result<Value> {
        self.calls.borrow_mut().push(format!("GET {path}"));
        match self.replies.get(path) {
            Some(Ok(value)) => Ok(value.clone()),
            Some(Err((status, message))) => Err(HttpError {
                status: *status,
                message: message.clone(),
            }
            .into()),
            None => Err(format!("unexpected GET {path}").into()),
        }
    }
    fn send(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value> {
        let call = format!("{method} {path}");
        self.calls.borrow_mut().push(call.clone());
        self.bodies.borrow_mut().push((call.clone(), body.cloned()));
        match self.replies.get(&call) {
            Some(Ok(value)) => Ok(value.clone()),
            _ => Err(format!("unexpected {call}").into()),
        }
    }
}

fn verb(fake: &Fake, desired: &Desired) -> std::result::Result<Change, HostErrorKind> {
    let host = GitHub::new(fake, CallBudget::new(100));
    let repo = RepoId::parse("example-owner/example").unwrap();
    let answer = change(&host, &repo, desired).map_err(|e| e.kind);
    assert!(
        fake.calls.borrow().iter().all(|c| c.starts_with("GET ")),
        "a write was sent: {:?}",
        fake.calls.borrow()
    );
    answer
}

const RULESET_FILE: &str = r#"{
  "name": "main",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
  "bypass_actors": [],
  "rules": [
    { "type": "deletion" },
    { "type": "required_status_checks", "parameters": { "strict_required_status_checks_policy": true, "required_status_checks": [ { "context": "required" } ] } }
  ]
}"#;

fn rulesets_page() -> String {
    format!("{BASE}/rulesets?per_page=100&page=1")
}

#[test]
fn ruleset_from_file_reads_the_committed_ruleset() {
    let ruleset = ruleset_from_file(RULESET_FILE, ".github/rulesets/main.json").unwrap();
    assert_eq!(ruleset.name, "main");
    assert_eq!(ruleset.id, None);
    assert_eq!(ruleset.include, ["~DEFAULT_BRANCH"]);
    assert_eq!(ruleset.required_status_checks, ["required"]);
    let error = ruleset_from_file("{", "x.json").unwrap_err();
    assert!(error.to_string().contains("x.json"), "{error}");
}

#[test]
fn a_ruleset_is_created_when_none_has_its_name_and_updated_otherwise() {
    let desired = Desired::Ruleset(ruleset_from_file(RULESET_FILE, "main.json").unwrap());
    let absent = Fake::default().reply(&rulesets_page(), json!([]));
    assert_eq!(verb(&absent, &desired), Ok(Change::Create));
    let mut detail: Value = serde_json::from_str(RULESET_FILE).unwrap();
    detail["id"] = json!(7);
    let present = Fake::default()
        .reply(&rulesets_page(), json!([{ "id": 7, "name": "main" }]))
        .reply(&format!("{BASE}/rulesets/7"), detail);
    assert_eq!(verb(&present, &desired), Ok(Change::Update));
}

fn label(name: &str) -> Label {
    Label {
        name: name.to_owned(),
        color: "0e8a16".to_owned(),
        description: None,
    }
}

#[test]
fn labels_are_created_when_none_exists_and_updated_otherwise() {
    let desired = Desired::Labels(vec![label("status:ready"), label("bug")]);
    let page = format!("{BASE}/labels?per_page=100&page=1");
    let none = Fake::default().reply(&page, json!([{ "name": "other", "color": "ffffff" }]));
    assert_eq!(verb(&none, &desired), Ok(Change::Create));
    let some = Fake::default().reply(&page, json!([{ "name": "BUG", "color": "ffffff" }]));
    assert_eq!(verb(&some, &desired), Ok(Change::Update));
}

#[test]
fn settings_and_required_checks_are_updates_and_read_nothing() {
    let fake = Fake::default();
    let settings = Desired::Settings(RepositorySettingsPatch {
        allow_squash_merge: Some(true),
        ..RepositorySettingsPatch::default()
    });
    assert_eq!(verb(&fake, &settings), Ok(Change::Update));
    let checks = Desired::RequiredChecks {
        branch: "main".to_owned(),
        checks: vec!["required".to_owned()],
        keep_others: false,
    };
    assert_eq!(verb(&fake, &checks), Ok(Change::Update));
    assert!(fake.calls.borrow().is_empty());
}

#[test]
fn retiring_classic_protection_is_a_removal() {
    let fake = Fake::default();
    let retire = Desired::RetireProtection {
        branch: "main".to_owned(),
        superseded_by: Supersession::None,
    };
    assert_eq!(verb(&fake, &retire), Ok(Change::Remove));
    assert!(fake.calls.borrow().is_empty());
}

#[test]
fn an_environment_is_created_when_absent_and_updated_otherwise() {
    let desired = Desired::Environment(EnvironmentSpec {
        name: "production".to_owned(),
        deployment_branch_policy: DeploymentBranchPolicy::ProtectedBranches,
        reviewers: Vec::new(),
        wait_timer_minutes: None,
    });
    let page = format!("{BASE}/environments?per_page=100&page=1");
    let absent = Fake::default().reply(&page, json!({ "environments": [] }));
    assert_eq!(verb(&absent, &desired), Ok(Change::Create));
    let present = Fake::default().reply(
        &page,
        json!({ "environments": [{ "id": 1, "name": "production", "deployment_branch_policy": null }] }),
    );
    assert_eq!(verb(&present, &desired), Ok(Change::Update));
}

#[test]
fn branch_protection_is_created_when_the_branch_has_none_and_updated_otherwise() {
    let desired = Desired::BranchProtection {
        branch: "main".to_owned(),
        spec: BranchProtectionSpec {
            required_status_checks: vec!["required".to_owned()],
            strict: true,
            enforce_admins: true,
            required_approving_review_count: None,
            required_linear_history: true,
            allow_force_pushes: false,
            allow_deletions: false,
        },
    };
    let path = format!("{BASE}/branches/main/protection");
    let absent = Fake::default().fail(&path, 404, "Branch not protected");
    assert_eq!(verb(&absent, &desired), Ok(Change::Create));
    let present = Fake::default().reply(
        &path,
        json!({ "required_status_checks": { "strict": true, "contexts": ["verify"] }, "enforce_admins": { "enabled": true } }),
    );
    assert_eq!(verb(&present, &desired), Ok(Change::Update));
}

#[test]
fn a_failed_read_is_the_host_error() {
    let desired = Desired::Ruleset(ruleset_from_file(RULESET_FILE, "main.json").unwrap());
    let fake = Fake::default().fail(&rulesets_page(), 502, "Bad Gateway");
    assert_eq!(verb(&fake, &desired), Err(HostErrorKind::Transport));
}

// --- the dispatch of `apply --remote` (#903) ------------------------------------------

fn write_with(
    fake: &Fake,
    desired: Desired,
) -> std::result::Result<brakes::host::types::WriteReport, brakes::host::HostError> {
    let host = GitHub::new(fake, CallBudget::new(100));
    let token = authorize::write(&RepoId::parse("example-owner/example").unwrap(), true).unwrap();
    write(
        &host,
        &token,
        &RemoteWrite {
            id: "item".to_owned(),
            desired,
        },
    )
}

fn writes(fake: &Fake) -> Vec<String> {
    fake.calls
        .borrow()
        .iter()
        .filter(|c| !c.starts_with("GET "))
        .cloned()
        .collect()
}

#[test]
fn a_desired_ruleset_is_created_through_put_ruleset() {
    let fake = Fake::default()
        .reply(&rulesets_page(), json!([]))
        .reply(&format!("POST {BASE}/rulesets"), json!({ "id": 9 }));
    let report = write_with(
        &fake,
        Desired::Ruleset(ruleset_from_file(RULESET_FILE, "main.json").unwrap()),
    )
    .unwrap();
    assert_eq!(report.created, ["main"]);
    assert_eq!(writes(&fake), [format!("POST {BASE}/rulesets")]);
}

#[test]
fn retiring_absent_classic_protection_sends_nothing() {
    let fake = Fake::default().fail(
        &format!("{BASE}/branches/main/protection"),
        404,
        "Branch not protected",
    );
    let report = write_with(
        &fake,
        Desired::RetireProtection {
            branch: "main".to_owned(),
            superseded_by: Supersession::None,
        },
    )
    .unwrap();
    assert_eq!(report.unchanged, ["main"]);
    assert!(writes(&fake).is_empty());
}

/// An active ruleset on `refs/heads/main` requiring `verify` (with an
/// integration id) and `lint`, and a pull-request rule left as read.
fn requiring_ruleset() -> Value {
    json!({
        "id": 7, "name": "main", "target": "branch", "enforcement": "active",
        "conditions": { "ref_name": { "include": ["refs/heads/main"], "exclude": [] } },
        "bypass_actors": [],
        "rules": [
            { "type": "pull_request", "parameters": { "required_approving_review_count": 0 } },
            { "type": "required_status_checks", "parameters": {
                "strict_required_status_checks_policy": true,
                "required_status_checks": [ { "context": "verify", "integration_id": 15368 }, { "context": "lint" } ] } }
        ]
    })
}

fn sent_checks(fake: &Fake) -> Value {
    let bodies = fake.bodies.borrow();
    let (call, body) = bodies.last().unwrap();
    assert_eq!(call, &format!("PUT {BASE}/rulesets/7"));
    let body = body.clone().unwrap();
    let rule = body["rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["type"] == "required_status_checks")
        .unwrap()
        .clone();
    assert_eq!(
        rule["parameters"]["strict_required_status_checks_policy"],
        true
    );
    assert_eq!(
        body["rules"][0],
        json!({ "type": "pull_request", "parameters": { "required_approving_review_count": 0 } })
    );
    rule["parameters"]["required_status_checks"].clone()
}

fn ruleset_fake() -> Fake {
    Fake::default()
        .reply(&rulesets_page(), json!([{ "id": 7, "name": "main" }]))
        .reply(&format!("{BASE}/rulesets/7"), requiring_ruleset())
        .reply(&format!("PUT {BASE}/rulesets/7"), json!({ "id": 7 }))
}

#[test]
fn required_checks_replace_the_list_of_the_applying_ruleset() {
    let fake = ruleset_fake();
    let report = write_with(
        &fake,
        Desired::RequiredChecks {
            branch: "main".to_owned(),
            checks: vec!["required".to_owned()],
            keep_others: false,
        },
    )
    .unwrap();
    assert_eq!(report.updated, ["main"]);
    assert_eq!(sent_checks(&fake), json!([{ "context": "required" }]));
}

#[test]
fn required_checks_extend_the_list_keeping_integration_ids() {
    let fake = ruleset_fake();
    write_with(
        &fake,
        Desired::RequiredChecks {
            branch: "main".to_owned(),
            checks: vec!["agentic-required".to_owned(), "lint".to_owned()],
            keep_others: true,
        },
    )
    .unwrap();
    assert_eq!(
        sent_checks(&fake),
        json!([{ "context": "verify", "integration_id": 15368 }, { "context": "lint" }, { "context": "agentic-required" }])
    );
}

#[test]
fn required_checks_never_rewrite_classic_protection_from_a_partial_read() {
    let fake = Fake::default().reply(&rulesets_page(), json!([])).reply(
        &format!("{BASE}/branches/main/protection"),
        json!({
            "required_status_checks": { "strict": true, "contexts": ["verify"] },
            "enforce_admins": { "enabled": true }
        }),
    );
    let error = write_with(
        &fake,
        Desired::RequiredChecks {
            branch: "main".to_owned(),
            checks: vec!["required".to_owned()],
            keep_others: false,
        },
    )
    .unwrap_err();
    assert_eq!(error.kind, HostErrorKind::WriteRefused);
    assert!(
        error.message.contains("classic protection"),
        "{}",
        error.message
    );
    assert!(error.message.contains("restrictions"), "{}", error.message);
    assert!(writes(&fake).is_empty());
}

#[test]
fn required_checks_without_ruleset_or_protection_and_with_two_rulesets_refuse() {
    let none = Fake::default().reply(&rulesets_page(), json!([])).fail(
        &format!("{BASE}/branches/main/protection"),
        404,
        "Branch not protected",
    );
    let desired = Desired::RequiredChecks {
        branch: "main".to_owned(),
        checks: vec!["required".to_owned()],
        keep_others: false,
    };
    let error = write_with(&none, desired.clone()).unwrap_err();
    assert_eq!(error.kind, HostErrorKind::WriteRefused);
    assert!(
        error
            .message
            .contains("no ruleset or classic protection requires checks on main"),
        "{}",
        error.message
    );
    let mut second = requiring_ruleset();
    second["id"] = json!(8);
    second["name"] = json!("other");
    let two = Fake::default()
        .reply(
            &rulesets_page(),
            json!([{ "id": 7, "name": "main" }, { "id": 8, "name": "other" }]),
        )
        .reply(&format!("{BASE}/rulesets/7"), requiring_ruleset())
        .reply(&format!("{BASE}/rulesets/8"), second);
    let error = write_with(&two, desired).unwrap_err();
    assert_eq!(error.kind, HostErrorKind::WriteRefused);
    assert!(
        error.message.contains("\"main\"") && error.message.contains("\"other\""),
        "{}",
        error.message
    );
    assert!(writes(&none).is_empty() && writes(&two).is_empty());
}

// #1149: classic protection requiring the old `verify` beside a ruleset that
// requires only the aggregate `required` (a ci-baseline pilot).

/// Classic protection of `main` requiring `verify`, as GitHub returns it.
fn classic_requiring_verify() -> Value {
    json!({
        "required_status_checks": { "strict": true, "contexts": ["verify"],
            "checks": [{ "context": "verify", "app_id": 15368 }] },
        "enforce_admins": { "enabled": true },
        "required_linear_history": { "enabled": false },
        "allow_force_pushes": { "enabled": false },
        "allow_deletions": { "enabled": false },
    })
}

/// The active ruleset on `refs/heads/main` requiring only `context`.
fn ruleset_requiring(context: &str) -> Value {
    json!({
        "id": 7, "name": "main", "target": "branch", "enforcement": "active",
        "conditions": { "ref_name": { "include": ["refs/heads/main"], "exclude": [] } },
        "bypass_actors": [],
        "rules": [{ "type": "required_status_checks", "parameters": {
            "strict_required_status_checks_policy": true,
            "required_status_checks": [{ "context": context, "integration_id": 15368 }] } }]
    })
}

fn retire_fake(ruleset_context: &str) -> Fake {
    Fake::default()
        .reply(
            &format!("{BASE}/branches/main/protection"),
            classic_requiring_verify(),
        )
        .reply(&rulesets_page(), json!([{ "id": 7, "name": "main" }]))
        .reply(
            &format!("{BASE}/rulesets/7"),
            ruleset_requiring(ruleset_context),
        )
        .reply(
            &format!("DELETE {BASE}/branches/main/protection"),
            Value::Null,
        )
}

fn retire(superseded_by: Supersession) -> Desired {
    Desired::RetireProtection {
        branch: "main".to_owned(),
        superseded_by,
    }
}

#[test]
fn retiring_classic_protection_superseded_by_the_required_aggregate_deletes_it() {
    let fake = retire_fake("required");
    let report = write_with(&fake, retire(Supersession::By("required".to_owned()))).unwrap();
    assert_eq!(report.removed, ["main"]);
    assert_eq!(
        writes(&fake),
        [format!("DELETE {BASE}/branches/main/protection")]
    );
}

#[test]
fn without_supersession_a_context_no_ruleset_requires_keeps_classic_protection() {
    let fake = retire_fake("required");
    let error = write_with(&fake, retire(Supersession::None)).unwrap_err();
    assert_eq!(error.kind, HostErrorKind::WriteRefused);
    assert_eq!(
        error.message,
        "Remote write refused: classic protection of branch main in example-owner/example is not retired, because no active ruleset that applies to main requires verify"
    );
    assert!(writes(&fake).is_empty());
}

#[test]
fn an_aggregate_that_does_not_supersede_says_why_and_keeps_classic_protection() {
    let fake = retire_fake("required");
    let why = "required does not run commands.verify (bash scripts/verificar.sh)";
    let error = write_with(&fake, retire(Supersession::Short(why.to_owned()))).unwrap_err();
    assert_eq!(error.kind, HostErrorKind::WriteRefused);
    assert!(
        error.message.ends_with(&format!("requires verify; {why}")),
        "{}",
        error.message
    );
    assert!(writes(&fake).is_empty());
}

#[test]
fn the_aggregate_supersedes_nothing_while_no_active_ruleset_requires_it() {
    let fake = retire_fake("lint");
    let error = write_with(&fake, retire(Supersession::By("required".to_owned()))).unwrap_err();
    assert_eq!(error.kind, HostErrorKind::WriteRefused);
    assert!(
        error.message.ends_with("requires verify"),
        "{}",
        error.message
    );
    assert!(writes(&fake).is_empty());
}
