//! `features` of the GitHub host adapter (#680): every field probed by its
//! endpoint, never by the plan name, over a recording fake transport and the
//! sanitised fixtures under `tests/fixtures/github/`.
use brakes::{
    Result,
    host::{
        Availability, CallBudget, Features, Host, HostErrorKind, RepoId, Visibility, github::GitHub,
    },
    remote::{Api, HttpError, RateLimit},
};
use serde_json::{Value, json};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    path::Path,
};

const BASE: &str = "repos/example-owner/example";
const UPGRADE: &str =
    "Upgrade to GitHub Pro or make this repository public to enable this feature.";

enum Reply {
    Json(Value),
    Http(u16, &'static str),
}

#[derive(Default)]
struct Fake {
    replies: BTreeMap<String, Reply>,
    calls: RefCell<Vec<String>>,
    rate: Cell<Option<RateLimit>>,
}
impl Fake {
    fn json(mut self, path: impl Into<String>, value: Value) -> Self {
        self.replies.insert(path.into(), Reply::Json(value));
        self
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
fn repo() -> RepoId {
    RepoId::parse("example-owner/example").unwrap()
}
fn available() -> Availability {
    Availability::Available
}
fn unavailable(reason: &str) -> Availability {
    Availability::Unavailable {
        reason: reason.to_owned(),
    }
}
fn unknown(reason: &str) -> Availability {
    Availability::Unknown {
        reason: reason.to_owned(),
    }
}

/// Every probe answering as on a repository where everything is observed:
/// the base the matrix tests change one endpoint of.
fn everything_available() -> Fake {
    let mut repository = fixture("repository.json");
    repository["security_and_analysis"] = json!({"secret_scanning": {"status": "enabled"}, "secret_scanning_push_protection": {"status": "disabled"}});
    Fake::default()
        .json(BASE, repository)
        .json("user", fixture("user.json"))
        .json(format!("{BASE}/rulesets"), fixture("rulesets.json"))
        .json(
            format!("{BASE}/environments"),
            fixture("environments_reviewers.json"),
        )
        .json(
            format!("{BASE}/branches/main/protection"),
            fixture("branch_protection.json"),
        )
        .json(format!("{BASE}/vulnerability-alerts"), Value::Null)
        .json(
            format!("{BASE}/contents/.github/workflows/actions.lock?ref=main"),
            fixture("contents_text_file.json"),
        )
        .json(
            format!("{BASE}/rules/branches/main"),
            fixture("rules_branch_merge_queue.json"),
        )
}
fn features(fake: &Fake) -> Features {
    GitHub::new(fake, CallBudget::default())
        .features(&repo())
        .unwrap()
}

#[test]
fn every_field_is_available_when_every_endpoint_answers_and_the_calls_are_the_probes() {
    let fake = everything_available();
    let f = features(&fake);
    assert_eq!(
        f,
        Features {
            visibility: Visibility::Private,
            plan_hint: Some("free".to_owned()),
            rulesets: available(),
            environments: available(),
            branch_protection: available(),
            required_reviewers: available(),
            dependabot_alerts: available(),
            secret_scanning: available(),
            workflow_lockfile: available(),
            merge_queue: available(),
        }
    );
    assert_eq!(
        fake.calls(),
        [
            BASE.to_owned(),
            "user".to_owned(),
            format!("{BASE}/rulesets"),
            format!("{BASE}/environments"),
            format!("{BASE}/branches/main/protection"),
            format!("{BASE}/vulnerability-alerts"),
            format!("{BASE}/contents/.github/workflows/actions.lock?ref=main"),
            format!("{BASE}/rules/branches/main"),
        ]
    );
}

// --- rulesets ---------------------------------------------------------------------

#[test]
fn rulesets_403_upgrade_is_unavailable_and_carries_merge_queue_with_it() {
    let fake = everything_available().http(format!("{BASE}/rulesets"), 403, UPGRADE);
    let f = features(&fake);
    let reason = format!("403: {UPGRADE}");
    assert_eq!(f.rulesets, unavailable(&reason));
    assert_eq!(f.merge_queue, unavailable(&reason));
    assert!(
        !fake
            .calls()
            .contains(&format!("{BASE}/rules/branches/main")),
        "no rules read when rulesets are unavailable"
    );
}

#[test]
fn rulesets_403_without_a_plan_is_unknown() {
    let fake = everything_available().http(
        format!("{BASE}/rulesets"),
        403,
        "Resource not accessible by integration",
    );
    let f = features(&fake);
    let reason = "403: Resource not accessible by integration";
    assert_eq!(f.rulesets, unknown(reason));
    assert_eq!(f.merge_queue, unknown(reason));
}

// --- environments and required reviewers -------------------------------------------

#[test]
fn environments_answers_and_required_reviewers_are_observed_or_unknown() {
    let fake =
        everything_available().json(format!("{BASE}/environments"), fixture("environments.json"));
    let f = features(&fake);
    assert_eq!(f.environments, available());
    assert_eq!(
        f.required_reviewers,
        unknown(
            "200: no environment has a required_reviewers rule, so the feature was not observed"
        )
    );
}

#[test]
fn environments_403_upgrade_is_unavailable_with_required_reviewers() {
    let fake = everything_available().http(format!("{BASE}/environments"), 403, UPGRADE);
    let f = features(&fake);
    let reason = format!("403: {UPGRADE}");
    assert_eq!(f.environments, unavailable(&reason));
    assert_eq!(f.required_reviewers, unavailable(&reason));
}

#[test]
fn environments_404_without_a_plan_is_unknown_with_required_reviewers() {
    let fake = everything_available().http(format!("{BASE}/environments"), 404, "Not Found");
    let f = features(&fake);
    assert_eq!(f.environments, unknown("404: Not Found"));
    assert_eq!(f.required_reviewers, unknown("404: Not Found"));
}

// --- branch protection -------------------------------------------------------------

#[test]
fn branch_protection_404_branch_not_protected_is_available() {
    let fake = everything_available().http(
        format!("{BASE}/branches/main/protection"),
        404,
        "Branch not protected",
    );
    assert_eq!(features(&fake).branch_protection, available());
}

#[test]
fn branch_protection_403_upgrade_is_unavailable_as_in_a_free_organization() {
    let fake =
        everything_available().http(format!("{BASE}/branches/main/protection"), 403, UPGRADE);
    assert_eq!(
        features(&fake).branch_protection,
        unavailable(&format!("403: {UPGRADE}"))
    );
}

#[test]
fn branch_protection_404_branch_not_found_is_unknown() {
    let fake = everything_available().http(
        format!("{BASE}/branches/main/protection"),
        404,
        "Branch not found",
    );
    assert_eq!(
        features(&fake).branch_protection,
        unknown("404: Branch not found")
    );
}

// --- Dependabot alerts (vulnerability-alerts) --------------------------------------

#[test]
fn dependabot_alerts_204_and_404_disabled_are_available() {
    let fake = everything_available().http(
        format!("{BASE}/vulnerability-alerts"),
        404,
        "Vulnerability alerts are disabled.",
    );
    assert_eq!(features(&fake).dependabot_alerts, available());
}

#[test]
fn dependabot_alerts_403_is_unknown_unless_it_names_a_plan() {
    let fake = everything_available().http(
        format!("{BASE}/vulnerability-alerts"),
        403,
        "Must have admin rights to Repository.",
    );
    assert_eq!(
        features(&fake).dependabot_alerts,
        unknown("403: Must have admin rights to Repository.")
    );
    let fake = everything_available().http(format!("{BASE}/vulnerability-alerts"), 403, UPGRADE);
    assert_eq!(
        features(&fake).dependabot_alerts,
        unavailable(&format!("403: {UPGRADE}"))
    );
}

// --- secret scanning -----------------------------------------------------------------

#[test]
fn secret_scanning_reads_security_and_analysis_of_the_repository() {
    let mut repository = fixture("repository.json");
    repository["security_and_analysis"] =
        json!({"dependabot_security_updates": {"status": "disabled"}});
    let fake = everything_available().json(BASE, repository);
    assert_eq!(
        features(&fake).secret_scanning,
        unavailable("200: security_and_analysis carries no secret_scanning status")
    );
    let fake = everything_available().json(BASE, fixture("repository.json"));
    assert_eq!(
        features(&fake).secret_scanning,
        unknown("200: security_and_analysis is not visible to this token")
    );
}

// --- workflow lockfile -------------------------------------------------------------

#[test]
fn workflow_lockfile_present_or_absent_is_available_and_403_follows_the_message() {
    let path = format!("{BASE}/contents/.github/workflows/actions.lock?ref=main");
    let fake = everything_available().http(&path, 404, "Not Found");
    assert_eq!(features(&fake).workflow_lockfile, available());
    let fake = everything_available().http(&path, 403, UPGRADE);
    assert_eq!(
        features(&fake).workflow_lockfile,
        unavailable(&format!("403: {UPGRADE}"))
    );
    let fake = everything_available().http(&path, 500, "Server Error");
    assert_eq!(
        features(&fake).workflow_lockfile,
        unknown("500: Server Error")
    );
}

// --- merge queue ---------------------------------------------------------------------

#[test]
fn merge_queue_is_unknown_when_no_rule_of_the_default_branch_is_a_merge_queue() {
    let fake = everything_available().json(format!("{BASE}/rules/branches/main"), json!([]));
    assert_eq!(
        features(&fake).merge_queue,
        unknown(
            "200: no rule of branch main is a merge_queue rule, so the feature was not observed"
        )
    );
}

// --- the plan hint never decides ---------------------------------------------------

#[test]
fn plan_free_with_rulesets_200_is_available() {
    let fake = everything_available();
    let f = features(&fake);
    assert_eq!(f.plan_hint.as_deref(), Some("free"));
    assert_eq!(f.rulesets, available());
}

#[test]
fn plan_pro_with_rulesets_403_upgrade_is_unavailable() {
    let fake = everything_available()
        .json(
            "user",
            json!({"login": "example-owner", "plan": {"name": "pro"}}),
        )
        .http(format!("{BASE}/rulesets"), 403, UPGRADE);
    let f = features(&fake);
    assert_eq!(f.plan_hint.as_deref(), Some("pro"));
    assert_eq!(f.rulesets, unavailable(&format!("403: {UPGRADE}")));
}

#[test]
fn plan_hint_is_none_for_another_user_and_read_from_the_organization() {
    let fake = everything_available().json(
        "user",
        json!({"login": "someone-else", "plan": {"name": "pro"}}),
    );
    assert_eq!(features(&fake).plan_hint, None);

    let mut repository = fixture("repository.json");
    repository["owner"] = json!({"login": "example-org", "type": "Organization"});
    let org_base = "repos/example-org/example";
    let fake = Fake::default()
        .json(org_base, repository)
        .http("orgs/example-org", 404, "Not Found")
        .json(format!("{org_base}/rulesets"), json!([]))
        .json(
            format!("{org_base}/environments"),
            fixture("environments.json"),
        )
        .http(format!("{org_base}/branches/main/protection"), 403, UPGRADE)
        .json(format!("{org_base}/vulnerability-alerts"), Value::Null)
        .http(
            format!("{org_base}/contents/.github/workflows/actions.lock?ref=main"),
            404,
            "Not Found",
        )
        .json(format!("{org_base}/rules/branches/main"), json!([]));
    let f = GitHub::new(&fake, CallBudget::default())
        .features(&RepoId::parse("example-org/example").unwrap())
        .unwrap();
    assert_eq!(
        f.plan_hint, None,
        "an unreadable organization plan is no hint"
    );
    assert_eq!(f.branch_protection, unavailable(&format!("403: {UPGRADE}")));
    assert!(fake.calls().contains(&"orgs/example-org".to_owned()));
    assert!(!fake.calls().contains(&"user".to_owned()));
}

// --- errors that stop the probe -----------------------------------------------------

#[test]
fn unauthenticated_and_rate_limited_stop_features_instead_of_becoming_verdicts() {
    let fake =
        everything_available().http(format!("{BASE}/rulesets"), 401, "Requires authentication");
    let error = GitHub::new(&fake, CallBudget::default())
        .features(&repo())
        .unwrap_err();
    assert_eq!(error.kind, HostErrorKind::Unauthenticated);

    let fake = everything_available().http(format!("{BASE}/environments"), 429, "slow down");
    let error = GitHub::new(&fake, CallBudget::default())
        .features(&repo())
        .unwrap_err();
    assert!(matches!(error.kind, HostErrorKind::RateLimited { .. }));

    let fake = everything_available();
    let error = GitHub::new(&fake, CallBudget::new(3))
        .features(&repo())
        .unwrap_err();
    assert_eq!(error.kind, HostErrorKind::RateLimited { reset_epoch: None });
    assert_eq!(fake.calls().len(), 3);
}

#[test]
fn a_repository_the_token_cannot_read_is_an_error_not_a_matrix() {
    let fake = Fake::default().http(BASE, 404, "Not Found");
    let error = GitHub::new(&fake, CallBudget::default())
        .features(&repo())
        .unwrap_err();
    assert_eq!(error.kind, HostErrorKind::NotFound);
    assert_eq!(
        error.message,
        "repository example-owner/example was not found (404: Not Found)"
    );
}

// --- determinism and the text form ------------------------------------------------

#[test]
fn two_runs_over_the_same_responses_are_byte_identical() {
    let first = serde_json::to_string_pretty(&features(&everything_available())).unwrap();
    let second = serde_json::to_string_pretty(&features(&everything_available())).unwrap();
    assert_eq!(first, second);
}

#[test]
fn the_text_form_prints_one_line_per_feature() {
    let fake = everything_available()
        .http(format!("{BASE}/rulesets"), 403, UPGRADE)
        .json(format!("{BASE}/environments"), fixture("environments.json"));
    assert_eq!(
        features(&fake).lines(),
        [
            "visibility: private".to_owned(),
            "plan_hint: free (never decides)".to_owned(),
            format!("rulesets: unavailable (403: {UPGRADE})"),
            "environments: available".to_owned(),
            "branch_protection: available".to_owned(),
            "required_reviewers: unknown (200: no environment has a required_reviewers rule, so the feature was not observed)".to_owned(),
            "dependabot_alerts: available".to_owned(),
            "secret_scanning: available".to_owned(),
            "workflow_lockfile: available".to_owned(),
            format!("merge_queue: unavailable (403: {UPGRADE})"),
        ]
    );
}

#[test]
fn a_plan_refusal_is_recognised_by_upgrade_or_by_a_plan_name_alone() {
    for message in [
        "Upgrade your plan to enable this feature.",
        "Rulesets require GitHub Team for private repositories.",
    ] {
        let fake = everything_available().http(format!("{BASE}/rulesets"), 403, message);
        assert_eq!(
            features(&fake).rulesets,
            unavailable(&format!("403: {message}")),
            "{message}"
        );
    }
}
