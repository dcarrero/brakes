//! The remote probe registry (#683, SPEC-host-adapter.md "Probe registry"): each
//! probe in `verified`, `pending`, `failed` and `unavailable` over the GitHub host
//! and a fake transport, evidence asserted and single-line; unknown ids and bad
//! arguments refused naming the id.
use brakes::{
    Result,
    engine::ProbeResult,
    host::{CallBudget, RepoId, github::GitHub, probes},
    remote::{Api, HttpError},
};
use serde_json::{Value, json};
use std::{cell::RefCell, collections::BTreeMap};

const BASE: &str = "repos/example-owner/example";

/// Serves canned replies by path; an unlisted path answers `fallback`.
struct Fake {
    replies: BTreeMap<String, std::result::Result<Value, (u16, String)>>,
    fallback: (u16, &'static str),
    calls: RefCell<Vec<String>>,
}
impl Fake {
    fn new() -> Self {
        Self {
            replies: BTreeMap::new(),
            fallback: (418, "unexpected path"),
            calls: RefCell::new(Vec::new()),
        }
    }
    /// Every path answers `status` with `message`.
    fn all(status: u16, message: &'static str) -> Self {
        Self {
            fallback: (status, message),
            ..Self::new()
        }
    }
    fn json(mut self, path: impl Into<String>, value: Value) -> Self {
        self.replies.insert(path.into(), Ok(value));
        self
    }
    fn http(mut self, path: impl Into<String>, status: u16, message: &str) -> Self {
        self.replies
            .insert(path.into(), Err((status, message.to_owned())));
        self
    }
}
impl Api for Fake {
    fn get(&self, path: &str) -> Result<Value> {
        self.calls.borrow_mut().push(path.to_owned());
        let reply = self.replies.get(path).cloned().unwrap_or_else(|| {
            // The unexpected-path fallback names the path, to debug a fixture.
            let (status, message) = self.fallback;
            Err((
                status,
                if status == 418 {
                    format!("{message} {path}")
                } else {
                    message.to_owned()
                },
            ))
        });
        reply.map_err(|(status, message)| HttpError { status, message }.into())
    }
}

fn repo() -> RepoId {
    RepoId::parse("example-owner/example").unwrap()
}
fn args(value: Value) -> BTreeMap<String, Value> {
    serde_json::from_value(value).unwrap()
}
fn run(fake: &Fake, id: &str, a: Value) -> ProbeResult {
    let host = GitHub::new(fake, CallBudget::default());
    let result = probes::run(&host, &repo(), id, &args(a));
    let text = match &result {
        ProbeResult::Verified(t)
        | ProbeResult::Pending(t)
        | ProbeResult::Failed(t)
        | ProbeResult::Unavailable(t)
        | ProbeResult::NotApplicable(t) => t,
    };
    assert!(
        !text.contains('\n') && !text.contains('\r'),
        "multi-line: {text:?}"
    );
    result
}
fn verified(text: &str) -> ProbeResult {
    ProbeResult::Verified(text.to_owned())
}
fn pending(text: &str) -> ProbeResult {
    ProbeResult::Pending(text.to_owned())
}

fn rulesets(fake: Fake, detail: Value) -> Fake {
    let id = detail["id"].as_u64().unwrap();
    fake.json(
        format!("{BASE}/rulesets?per_page=100&page=1"),
        json!([{ "id": id }]),
    )
    .json(format!("{BASE}/rulesets/{id}"), detail)
}
fn no_rulesets(fake: Fake) -> Fake {
    fake.json(format!("{BASE}/rulesets?per_page=100&page=1"), json!([]))
}
fn unprotected(fake: Fake, branch: &str) -> Fake {
    fake.http(
        format!("{BASE}/branches/{branch}/protection"),
        404,
        "Branch not protected",
    )
}
fn ruleset(checks: &[&str], bypass: Value) -> Value {
    let contexts: Vec<Value> = checks.iter().map(|c| json!({ "context": c })).collect();
    json!({
        "id": 42, "name": "main", "target": "branch", "enforcement": "active",
        "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
        "bypass_actors": bypass,
        "rules": [
            { "type": "deletion" },
            { "type": "required_status_checks", "parameters": { "required_status_checks": contexts } }
        ]
    })
}
fn repository(extra: Value) -> Value {
    let mut base = json!({"id": 1, "default_branch": "main", "visibility": "private",
        "archived": false, "fork": false});
    base.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    base
}

/// One declaration per registered probe, with valid arguments.
fn declarations() -> Vec<(&'static str, Value)> {
    vec![
        (
            "required-check",
            json!({"branch": "main", "check": "verify"}),
        ),
        (
            "ruleset-required-checks",
            json!({"branch": "main", "checks": ["required"]}),
        ),
        (
            "ruleset-present",
            json!({"name": "main", "branch": "main", "path": ".github/rulesets/main.json"}),
        ),
        (
            "check-run-reported",
            json!({"contexts": ["required"], "branch": "main"}),
        ),
        ("classic-protection-absent", json!({"branch": "main"})),
        (
            "labels-present",
            json!({"labels": [{"name": "bug", "color": "d73a4a", "description": "Broken"}]}),
        ),
        (
            "repo-settings",
            json!({"fields": {"allow_squash_merge": true}}),
        ),
        ("dependabot-alerts", json!({})),
        ("automated-security-fixes", json!({})),
        ("secret-scanning", json!({})),
        ("private-vulnerability-reporting", json!({})),
        ("code-scanning-default-setup", json!({})),
        ("environment-main-only", json!({})),
        (
            "secret-present",
            json!({"name": "DEPLOY_KEY", "scope": "repository"}),
        ),
        ("workflow-lockfile", json!({})),
        ("actions-pull-requests", json!({})),
        ("default-branch", json!({})),
        ("org-2fa-required", json!({"org": "example-org"})),
        ("repository-visibility", json!({"expected": "private"})),
        ("feature-available", json!({"feature": "rulesets"})),
        (
            "reusable-workflow-reachable",
            json!({"callee": "example-owner/agentic-project-setup"}),
        ),
    ]
}

// ---- registry ---------------------------------------------------------------------

/// The generic probes of the "configure new" contract (#725): registered so a
/// contract's steps load, answered `unavailable` until a runner reads them.
fn without_runner() -> Vec<(&'static str, Value)> {
    vec![
        ("app-installed", json!({"slug": "acme-agent"})),
        ("endpoint-answers", json!({"env": "DEPLOY_URL"})),
        (
            "secret-exists",
            json!({"name": "DEPLOY_TOKEN", "environment": "production"}),
        ),
    ]
}

#[test]
fn the_registry_lists_every_declared_id_and_each_has_a_schema() {
    let mut sorted: Vec<&str> = declarations()
        .iter()
        .chain(&without_runner())
        .map(|(id, _)| *id)
        .collect();
    sorted.sort();
    assert_eq!(probes::ids().collect::<Vec<_>>(), sorted);
    for (id, a) in declarations().into_iter().chain(without_runner()) {
        assert!(probes::schema(id).is_some(), "{id}");
        assert_eq!(probes::check(id, &args(a)), Ok(()), "{id}");
    }
}

#[test]
fn unknown_ids_and_bad_arguments_are_refused_naming_the_id() {
    let refused = |id: &str, a: Value| probes::check(id, &args(a)).unwrap_err();
    assert_eq!(
        refused("ruleset-presnt", json!({})),
        "remote probe `ruleset-presnt` is not in the host-adapter registry"
    );
    assert_eq!(
        refused("required-check", json!({"branch": "main"})),
        "remote probe `required-check` needs argument `check`"
    );
    assert_eq!(
        refused(
            "required-check",
            json!({"branch": "main", "check": "x", "required_check": "x"})
        ),
        "remote probe `required-check` has no argument `required_check`"
    );
    assert_eq!(
        refused(
            "check-run-reported",
            json!({"branch": "main", "contexts": "required"})
        ),
        "remote probe `check-run-reported`: argument `contexts` must be a list of texts"
    );
    assert_eq!(
        refused("repository-visibility", json!({"expected": "secret"})),
        "remote probe `repository-visibility`: argument `expected` must be private, public or internal"
    );
    assert_eq!(
        refused(
            "secret-present",
            json!({"name": "X", "scope": "everywhere"})
        ),
        "remote probe `secret-present`: argument `scope` must be repository, organization, dependabot or environment:<name>"
    );
    assert_eq!(
        refused("feature-available", json!({"feature": "billing"})),
        "remote probe `feature-available`: argument `feature` must be one of rulesets, environments, branch_protection, required_reviewers, dependabot_alerts, secret_scanning, workflow_lockfile, merge_queue"
    );
    assert_eq!(
        refused("repo-settings", json!({"fields": {"has_issues": true}})),
        "remote probe `repo-settings`: argument `fields` may hold only allow_squash_merge, allow_merge_commit, allow_rebase_merge, delete_branch_on_merge, allow_auto_merge, allow_update_branch, has_wiki, has_projects, web_commit_signoff_required, each true or false"
    );
    assert_eq!(
        refused("labels-present", json!({"labels": [{"name": "bug"}]})),
        "remote probe `labels-present`: argument `labels` must list objects with a text name and color"
    );
}

#[test]
fn running_an_unknown_id_or_bad_arguments_is_unavailable_and_reads_nothing() {
    let fake = Fake::new();
    assert_eq!(
        run(&fake, "nope", json!({})),
        ProbeResult::Unavailable(
            "remote probe `nope` is not in the host-adapter registry".to_owned()
        )
    );
    assert_eq!(
        run(&fake, "default-branch", json!({"expected": 3})),
        ProbeResult::Unavailable(
            "remote probe `default-branch`: argument `expected` must be a text".to_owned()
        )
    );
    assert!(fake.calls.borrow().is_empty());
}

#[test]
fn the_configure_new_probes_are_unavailable_and_read_nothing() {
    let fake = Fake::all(500, "Server Error");
    for (id, a) in without_runner() {
        assert_eq!(
            run(&fake, id, a),
            ProbeResult::Unavailable(format!("remote probe `{id}` has no runner yet")),
            "{id}"
        );
    }
    assert!(fake.calls.borrow().is_empty());
}

#[test]
fn every_probe_is_unavailable_with_gh_not_authenticated_on_401() {
    let fake = Fake::all(401, "Bad credentials");
    for (id, a) in declarations() {
        match run(&fake, id, a) {
            ProbeResult::Unavailable(text) => assert!(
                text.starts_with("gh not authenticated: GitHub CLI is not authenticated, so ")
                    && text.ends_with("(401: Bad credentials)"),
                "{id}: {text}"
            ),
            other => panic!("{id}: {other:?}"),
        }
    }
}

#[test]
fn every_probe_fails_with_the_host_error_on_a_server_error() {
    let fake = Fake::all(500, "Server Error");
    for (id, a) in declarations() {
        match run(&fake, id, a) {
            ProbeResult::Failed(text) => {
                assert!(
                    text.contains("could not be read (500: Server Error"),
                    "{id}: {text}"
                )
            }
            other => panic!("{id}: {other:?}"),
        }
    }
}

#[test]
fn a_plan_refusal_is_failed_with_githubs_message() {
    let fake = Fake::new().http(
        format!("{BASE}/rulesets?per_page=100&page=1"),
        403,
        "Upgrade to GitHub Pro or make this repository public to enable this feature.",
    );
    assert_eq!(
        run(&fake, "required-check", json!({"branch": "main", "check": "verify"})),
        ProbeResult::Failed("Reading rulesets of example-owner/example is forbidden (403: Upgrade to GitHub Pro or make this repository public to enable this feature.)".to_owned())
    );
}

#[test]
fn evidence_from_github_is_flattened_to_one_line() {
    let detail = ruleset(&["verify"], json!([]));
    let mut detail = detail;
    detail["name"] = json!("main\nINJECTED: line");
    let fake = rulesets(Fake::new(), detail).json(BASE, repository(json!({})));
    assert_eq!(
        run(
            &fake,
            "required-check",
            json!({"branch": "main", "check": "verify"})
        ),
        verified("ruleset 42 \"main INJECTED: line\" requires \"verify\"")
    );
}

// ---- required-check ---------------------------------------------------------------

#[test]
fn required_check_is_verified_by_a_ruleset_without_bypass_actors() {
    let fake =
        rulesets(Fake::new(), ruleset(&["verify"], json!([]))).json(BASE, repository(json!({})));
    assert_eq!(
        run(
            &fake,
            "required-check",
            json!({"branch": "main", "check": "verify"})
        ),
        verified("ruleset 42 \"main\" requires \"verify\"")
    );
}

#[test]
fn required_check_is_pending_when_the_ruleset_lacks_the_check_or_has_bypass_actors() {
    let fake = unprotected(
        rulesets(Fake::new(), ruleset(&["build"], json!([]))).json(BASE, repository(json!({}))),
        "main",
    );
    assert_eq!(
        run(
            &fake,
            "required-check",
            json!({"branch": "main", "check": "verify"})
        ),
        pending("no ruleset or classic protection requires \"verify\" on main")
    );
    let bypass = json!([{"actor_type": "RepositoryRole", "actor_id": 5, "bypass_mode": "always"}]);
    let fake = unprotected(
        rulesets(Fake::new(), ruleset(&["verify"], bypass)).json(BASE, repository(json!({}))),
        "main",
    );
    assert_eq!(
        run(
            &fake,
            "required-check",
            json!({"branch": "main", "check": "verify"})
        ),
        pending("ruleset 42 \"main\" requires \"verify\" but has bypass actors")
    );
}

#[test]
fn required_check_reads_classic_protection_and_needs_enforce_admins() {
    let protection = |admins: bool| {
        json!({"required_status_checks": {"strict": true, "contexts": ["verify"]},
            "enforce_admins": {"enabled": admins}})
    };
    let fake =
        no_rulesets(Fake::new()).json(format!("{BASE}/branches/main/protection"), protection(true));
    assert_eq!(
        run(
            &fake,
            "required-check",
            json!({"branch": "main", "check": "verify"})
        ),
        verified("classic protection of main requires \"verify\" for administrators too")
    );
    let fake = no_rulesets(Fake::new()).json(
        format!("{BASE}/branches/main/protection"),
        protection(false),
    );
    assert_eq!(
        run(
            &fake,
            "required-check",
            json!({"branch": "main", "check": "verify"})
        ),
        pending("classic protection of main requires \"verify\" but not for administrators")
    );
}

#[test]
fn a_ruleset_for_another_branch_or_in_evaluate_mode_does_not_apply() {
    let mut other = ruleset(&["verify"], json!([]));
    other["conditions"]["ref_name"]["include"] = json!(["refs/heads/release"]);
    let fake = unprotected(rulesets(Fake::new(), other), "main");
    assert_eq!(
        run(
            &fake,
            "required-check",
            json!({"branch": "main", "check": "verify"})
        ),
        pending("no ruleset or classic protection requires \"verify\" on main")
    );
    let mut evaluate = ruleset(&["verify"], json!([]));
    evaluate["enforcement"] = json!("evaluate");
    let fake = unprotected(
        rulesets(Fake::new(), evaluate).json(BASE, repository(json!({}))),
        "main",
    );
    assert!(matches!(
        run(
            &fake,
            "required-check",
            json!({"branch": "main", "check": "verify"})
        ),
        ProbeResult::Pending(_)
    ));
}

// ---- ruleset-required-checks --------------------------------------------------------

#[test]
fn ruleset_required_checks_compares_the_union_of_rulesets_and_classic_protection() {
    let a = json!({"branch": "main", "checks": ["required"]});
    let fake = unprotected(
        rulesets(Fake::new(), ruleset(&["required"], json!([]))).json(BASE, repository(json!({}))),
        "main",
    );
    assert_eq!(
        run(&fake, "ruleset-required-checks", a.clone()),
        verified("required on main: required")
    );
    let fake = no_rulesets(Fake::new()).json(
        format!("{BASE}/branches/main/protection"),
        json!({"required_status_checks": {"contexts": ["test / verify", "build"]}}),
    );
    assert_eq!(
        run(&fake, "ruleset-required-checks", a),
        pending("required on main: build, test / verify; expected: required")
    );
}

// ---- ruleset-present ----------------------------------------------------------------

fn declared_file(fake: Fake, body: &Value) -> Fake {
    use std::fmt::Write;
    let text = serde_json::to_string_pretty(body).unwrap();
    // base64 by hand, the encoding GitHub's contents API sends.
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::new();
    for chunk in text.as_bytes().chunks(3) {
        let n = chunk.iter().fold(0u32, |n, b| n << 8 | u32::from(*b)) << (8 * (3 - chunk.len()));
        for i in 0..4 {
            if i <= chunk.len() {
                let _ = encoded.write_char(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                encoded.push('=');
            }
        }
    }
    fake.json(
        format!("{BASE}/contents/.github/rulesets/main.json?ref=main"),
        json!({"type": "file", "path": ".github/rulesets/main.json", "sha": "f1",
            "size": text.len(), "encoding": "base64", "content": encoded}),
    )
}
fn file_body(checks: &[&str]) -> Value {
    let mut body = ruleset(checks, json!([]));
    body.as_object_mut().unwrap().remove("id");
    body
}
fn present() -> Value {
    json!({"name": "main", "branch": "main", "path": ".github/rulesets/main.json"})
}

#[test]
fn ruleset_present_is_verified_when_the_ruleset_equals_the_committed_file() {
    let fake = declared_file(
        rulesets(Fake::new(), ruleset(&["required"], json!([]))).json(BASE, repository(json!({}))),
        &file_body(&["required"]),
    );
    assert_eq!(
        run(&fake, "ruleset-present", present()),
        verified("ruleset 42 \"main\" is active on main and equals .github/rulesets/main.json")
    );
}

#[test]
fn ruleset_present_is_pending_naming_what_differs_or_what_is_missing() {
    let fake = declared_file(
        rulesets(Fake::new(), ruleset(&["build"], json!([]))).json(BASE, repository(json!({}))),
        &file_body(&["required"]),
    );
    assert_eq!(
        run(&fake, "ruleset-present", present()),
        pending(
            "ruleset 42 \"main\" differs from .github/rulesets/main.json in required_status_checks"
        )
    );
    let fake = no_rulesets(Fake::new());
    assert_eq!(
        run(&fake, "ruleset-present", present()),
        pending("no ruleset named \"main\"")
    );
    let fake = rulesets(Fake::new(), ruleset(&["required"], json!([]))).http(
        format!("{BASE}/contents/.github/rulesets/main.json?ref=main"),
        404,
        "Not Found",
    );
    assert_eq!(
        run(&fake, "ruleset-present", present()),
        pending(".github/rulesets/main.json is absent on main")
    );
}

// ---- check-run-reported -------------------------------------------------------------

#[test]
fn check_run_reported_looks_at_the_last_ten_commits_and_stops_when_all_are_found() {
    let fake = Fake::new()
        .json(
            format!("{BASE}/commits?sha=main&per_page=10"),
            json!([{"sha": "c3"}, {"sha": "c2"}, {"sha": "c1"}]),
        )
        .json(
            format!("{BASE}/commits/c3/check-runs?per_page=100&page=1"),
            json!({"check_runs": [{"id": 1, "name": "lint", "status": "completed"}]}),
        )
        .json(
            format!("{BASE}/commits/c2/check-runs?per_page=100&page=1"),
            json!({"check_runs": [{"id": 2, "name": "required", "status": "completed"}]}),
        );
    assert_eq!(
        run(
            &fake,
            "check-run-reported",
            json!({"contexts": ["required", "lint"], "branch": "main"})
        ),
        verified("reported on the last 10 commits of main: lint, required")
    );
    assert!(
        !fake.calls.borrow().iter().any(|c| c.contains("/c1/")),
        "stops once every context is found"
    );
    let fake = Fake::new()
        .json(
            format!("{BASE}/commits?sha=main&per_page=10"),
            json!([{"sha": "c1"}]),
        )
        .json(
            format!("{BASE}/commits/c1/check-runs?per_page=100&page=1"),
            json!({"check_runs": []}),
        );
    assert_eq!(
        run(
            &fake,
            "check-run-reported",
            json!({"contexts": ["required"], "branch": "main"})
        ),
        pending("not reported on the last 10 commits of main: required")
    );
}

// ---- classic-protection-absent ------------------------------------------------------

#[test]
fn classic_protection_absent_is_verified_on_not_protected_and_pending_on_protection() {
    let fake = unprotected(Fake::new(), "main");
    assert_eq!(
        run(
            &fake,
            "classic-protection-absent",
            json!({"branch": "main"})
        ),
        verified("no classic protection on main")
    );
    let fake = Fake::new().json(
        format!("{BASE}/branches/main/protection"),
        json!({"required_status_checks": {"contexts": ["build", "Rust (linux)"]}}),
    );
    assert_eq!(
        run(
            &fake,
            "classic-protection-absent",
            json!({"branch": "main"})
        ),
        pending("classic protection of main is in force (requires: Rust (linux), build)")
    );
}

// ---- labels-present -----------------------------------------------------------------

#[test]
fn labels_present_compares_names_case_insensitively_and_colors() {
    let declared = json!({"labels": [
        {"name": "bug", "color": "D73A4A", "description": "x"},
        {"name": "status:ready", "color": "0e8a16", "description": "y"},
        {"name": "risk:high", "color": "b60205", "description": "z"}
    ]});
    let fake = Fake::new().json(
        format!("{BASE}/labels?per_page=100&page=1"),
        json!([{"name": "Bug", "color": "d73a4a"}, {"name": "status:ready", "color": "0e8a16"},
               {"name": "risk:high", "color": "b60205"}]),
    );
    assert_eq!(
        run(&fake, "labels-present", declared.clone()),
        verified("3 labels present with their colors")
    );
    let fake = Fake::new().json(
        format!("{BASE}/labels?per_page=100&page=1"),
        json!([{"name": "bug", "color": "ffffff"}, {"name": "status:ready", "color": "0e8a16"}]),
    );
    assert_eq!(
        run(&fake, "labels-present", declared),
        pending("missing: risk:high; recolored: bug")
    );
}

// ---- repo-settings ------------------------------------------------------------------

#[test]
fn repo_settings_lists_each_field_that_differs_or_is_not_visible() {
    let fields = json!({"fields": {"allow_squash_merge": true, "allow_merge_commit": false,
        "allow_update_branch": true}});
    let fake = Fake::new().json(
        BASE,
        repository(
            json!({"allow_squash_merge": true, "allow_merge_commit": false,
            "allow_update_branch": true}),
        ),
    );
    assert_eq!(
        run(&fake, "repo-settings", fields.clone()),
        verified("3 settings as declared")
    );
    let fake = Fake::new().json(
        BASE,
        repository(json!({"allow_squash_merge": true, "allow_merge_commit": true})),
    );
    assert_eq!(
        run(&fake, "repo-settings", fields),
        pending(
            "allow_merge_commit is true, expected false; allow_update_branch is not visible, expected true"
        )
    );
}

// ---- security toggles ---------------------------------------------------------------

#[test]
fn dependabot_alerts_and_security_updates_read_their_endpoints() {
    let fake = Fake::new()
        .json(format!("{BASE}/vulnerability-alerts"), Value::Null)
        .http(format!("{BASE}/automated-security-fixes"), 404, "Not Found");
    assert_eq!(
        run(&fake, "dependabot-alerts", json!({})),
        verified("enabled")
    );
    assert_eq!(
        run(&fake, "automated-security-fixes", json!({})),
        pending("disabled")
    );
    let fake = Fake::new()
        .http(format!("{BASE}/vulnerability-alerts"), 404, "Not Found")
        .json(
            format!("{BASE}/automated-security-fixes"),
            json!({"enabled": true, "paused": false}),
        );
    assert_eq!(
        run(&fake, "dependabot-alerts", json!({})),
        pending("disabled")
    );
    assert_eq!(
        run(&fake, "automated-security-fixes", json!({})),
        verified("enabled")
    );
}

#[test]
fn private_vulnerability_reporting_is_not_applicable_where_github_answers_404() {
    let path = format!("{BASE}/private-vulnerability-reporting");
    let fake = Fake::new().json(&path, json!({"enabled": true}));
    assert_eq!(
        run(&fake, "private-vulnerability-reporting", json!({})),
        verified("enabled")
    );
    let fake = Fake::new().json(&path, json!({"enabled": false}));
    assert_eq!(
        run(&fake, "private-vulnerability-reporting", json!({})),
        pending("disabled")
    );
    let fake = Fake::new().http(&path, 404, "Not Found");
    assert_eq!(
        run(&fake, "private-vulnerability-reporting", json!({})),
        ProbeResult::NotApplicable(
            "private vulnerability reporting of example-owner/example was not found (404: Not Found)"
                .to_owned()
        )
    );
}

/// T10 (#798): the probe of security's `code-security` step.
#[test]
fn code_scanning_default_setup_is_verified_in_any_state_and_failed_with_the_plan_message() {
    let path = format!("{BASE}/code-scanning/default-setup");
    for state in ["configured", "not-configured"] {
        let fake = Fake::new().json(&path, json!({"state": state, "languages": []}));
        assert_eq!(
            run(&fake, "code-scanning-default-setup", json!({})),
            verified(&format!("code scanning available; default setup {state}"))
        );
    }
    let fake = Fake::new().http(
        &path,
        403,
        "Code Security must be enabled for this repository to use code scanning.",
    );
    assert_eq!(
        run(&fake, "code-scanning-default-setup", json!({})),
        ProbeResult::Failed(
            "Reading code scanning default setup of example-owner/example is forbidden (403: Code Security must be enabled for this repository to use code scanning.)"
                .to_owned()
        )
    );
    let fake = Fake::new().json(&path, json!({"languages": []}));
    assert!(matches!(
        run(&fake, "code-scanning-default-setup", json!({})),
        ProbeResult::Failed(text) if text.contains("missing text field state")
    ));
}

#[test]
fn secret_scanning_needs_scanning_and_push_protection_enabled() {
    // On a public repository: secret scanning is free, so off is `pending`.
    let both = |scanning: &str, push: &str| {
        repository(json!({"visibility": "public", "security_and_analysis": {
            "secret_scanning": {"status": scanning},
            "secret_scanning_push_protection": {"status": push}}}))
    };
    let fake = Fake::new().json(BASE, both("enabled", "enabled"));
    assert_eq!(
        run(&fake, "secret-scanning", json!({})),
        verified("secret scanning enabled, push protection enabled")
    );
    let fake = Fake::new().json(BASE, both("enabled", "disabled"));
    assert_eq!(
        run(&fake, "secret-scanning", json!({})),
        pending("secret scanning enabled, push protection disabled")
    );
    let fake = Fake::new().json(BASE, repository(json!({"visibility": "public"})));
    assert_eq!(
        run(&fake, "secret-scanning", json!({})),
        pending("secret scanning not reported, push protection not reported")
    );
}

/// #1136: on a repository that is not public, secret scanning needs Secret
/// Protection, which the installer never assumes (decision 2026-10-28, point
/// 11; #801's rule records the risk): `not-applicable`, never written, so
/// `apply --remote` meets no 422 and verify does not stay `pending`.
#[test]
fn secret_scanning_is_not_applicable_on_a_repository_that_is_not_public_unless_enabled() {
    let settings = |visibility: &str, scanning: &str, push: &str| {
        repository(json!({"visibility": visibility, "security_and_analysis": {
            "secret_scanning": {"status": scanning},
            "secret_scanning_push_protection": {"status": push}}}))
    };
    for visibility in ["private", "internal"] {
        let fake = Fake::new().json(BASE, settings(visibility, "disabled", "disabled"));
        assert_eq!(
            run(&fake, "secret-scanning", json!({})),
            ProbeResult::NotApplicable(format!(
                "secret scanning disabled, push protection disabled; a {visibility} repository needs Secret Protection (Team or Enterprise), which the installer never assumes (risk secret-scanning-unavailable-on-plan)"
            )),
            "{visibility}"
        );
    }
    let fake = Fake::new().json(BASE, repository(json!({})));
    assert!(matches!(
        run(&fake, "secret-scanning", json!({})),
        ProbeResult::NotApplicable(text) if text.starts_with("secret scanning not reported, push protection not reported; a private repository")
    ));
    // The risk the probe names is the one the auditor rule records.
    assert_eq!(
        brakes::auditor::catalogue::security_remote::SECRET_SCANNING_RISK,
        "secret-scanning-unavailable-on-plan"
    );
    // Enabled where the plan has it: verified, whatever the visibility.
    let fake = Fake::new().json(BASE, settings("private", "enabled", "enabled"));
    assert_eq!(
        run(&fake, "secret-scanning", json!({})),
        verified("secret scanning enabled, push protection enabled")
    );
}

// ---- environment-main-only ----------------------------------------------------------

#[test]
fn environment_main_only_accepts_protected_branches_or_only_the_default_branch() {
    let environments = |policy: Value| {
        Fake::new()
            .json(
                format!("{BASE}/environments?per_page=100&page=1"),
                json!({"environments": [{"id": 7, "name": "production",
                    "deployment_branch_policy": policy}]}),
            )
            .json(BASE, repository(json!({})))
    };
    let fake = environments(json!({"protected_branches": true, "custom_branch_policies": false}));
    assert_eq!(
        run(&fake, "environment-main-only", json!({})),
        verified("environment 7 \"production\" deploys from protected branches")
    );
    let fake = environments(Value::Null);
    assert_eq!(
        run(&fake, "environment-main-only", json!({})),
        pending("environment 7 \"production\" deploys from any branch")
    );
    let fake = Fake::new().json(
        format!("{BASE}/environments?per_page=100&page=1"),
        json!({"environments": []}),
    );
    assert_eq!(
        run(
            &fake,
            "environment-main-only",
            json!({"environment": "staging"})
        ),
        pending("environment \"staging\" is absent")
    );
}

#[test]
fn environment_main_only_accepts_a_custom_policy_of_the_default_branch_only() {
    let fake = Fake::new()
        .json(
            format!("{BASE}/environments?per_page=100&page=1"),
            json!({"environments": [{"id": 7, "name": "production",
                "deployment_branch_policy": {"protected_branches": false, "custom_branch_policies": true}}]}),
        )
        .json(
            format!("{BASE}/environments/production/deployment-branch-policies?per_page=100&page=1"),
            json!({"branch_policies": [{"name": "main", "type": "branch"}]}),
        )
        .json(BASE, repository(json!({})));
    assert_eq!(
        run(&fake, "environment-main-only", json!({})),
        verified("environment 7 \"production\" deploys from main only")
    );
}

// ---- secret-present -----------------------------------------------------------------

#[test]
fn secret_present_finds_the_name_in_the_scope_and_never_a_value() {
    let fake = Fake::new().json(
        format!("{BASE}/environments/production/secrets?per_page=100&page=1"),
        json!({"secrets": [{"name": "DEPLOY_KEY", "updated_at": "2026-10-01T00:00:00Z"}]}),
    );
    assert_eq!(
        run(
            &fake,
            "secret-present",
            json!({"name": "DEPLOY_KEY", "scope": "environment:production"})
        ),
        verified("DEPLOY_KEY updated 2026-10-01T00:00:00Z")
    );
    assert_eq!(
        run(
            &fake,
            "secret-present",
            json!({"name": "OTHER", "scope": "environment:production"})
        ),
        pending("OTHER is not listed in environment production")
    );
}

/// #940: the Dependabot secrets store, where Dependabot-triggered runs read secrets.
#[test]
fn secret_present_reads_the_dependabot_store() {
    let fake = Fake::new().json(
        format!("{BASE}/dependabot/secrets?per_page=100&page=1"),
        json!({"total_count": 1, "secrets": [{"name": "OPENAI_API_KEY", "updated_at": "2026-10-29T00:00:00Z"}]}),
    );
    assert_eq!(
        run(
            &fake,
            "secret-present",
            json!({"name": "OPENAI_API_KEY", "scope": "dependabot"})
        ),
        verified("OPENAI_API_KEY updated 2026-10-29T00:00:00Z")
    );
    assert_eq!(
        run(
            &fake,
            "secret-present",
            json!({"name": "OTHER", "scope": "dependabot"})
        ),
        pending("OTHER is not listed in the Dependabot secrets")
    );
}

// ---- actions-pull-requests (#946) ---------------------------------------------------

/// The repository setting that lets `agentic-implement`'s workflow token open its
/// pull request; read from the workflow permissions, never written.
#[test]
fn actions_pull_requests_reads_the_workflow_permissions() {
    let path = format!("{BASE}/actions/permissions/workflow");
    let allowed = Fake::new().json(
        &path,
        json!({"default_workflow_permissions": "read", "can_approve_pull_request_reviews": true}),
    );
    assert_eq!(
        run(&allowed, "actions-pull-requests", json!({})),
        verified("GitHub Actions may create pull requests")
    );
    let refused = Fake::new().json(
        &path,
        json!({"default_workflow_permissions": "read", "can_approve_pull_request_reviews": false}),
    );
    assert_eq!(
        run(&refused, "actions-pull-requests", json!({})),
        pending(
            "GitHub Actions may not create pull requests (can_approve_pull_request_reviews is false)"
        )
    );
    assert_eq!(*allowed.calls.borrow(), [path]);
}

// ---- workflow-lockfile, default-branch, visibility ----------------------------------

#[test]
fn workflow_lockfile_reads_the_default_branch() {
    let lock = format!("{BASE}/contents/.github/workflows/actions.lock?ref=main");
    let fake = Fake::new()
        .json(BASE, repository(json!({})))
        .json(&lock, json!({"type": "file", "sha": "b10b"}));
    assert_eq!(
        run(&fake, "workflow-lockfile", json!({})),
        verified("blob b10b")
    );
    let fake = Fake::new()
        .json(BASE, repository(json!({})))
        .http(&lock, 404, "Not Found");
    assert_eq!(
        run(&fake, "workflow-lockfile", json!({})),
        pending(".github/workflows/actions.lock is absent on main")
    );
}

#[test]
fn default_branch_and_visibility_compare_with_the_expected_value() {
    let fake = Fake::new().json(BASE, repository(json!({"default_branch": "trunk"})));
    assert_eq!(
        run(&fake, "default-branch", json!({"expected": "trunk"})),
        verified("trunk")
    );
    assert_eq!(
        run(&fake, "default-branch", json!({})),
        pending("trunk, expected main")
    );
    assert_eq!(
        run(
            &fake,
            "repository-visibility",
            json!({"expected": "private"})
        ),
        verified("private")
    );
    assert_eq!(
        run(
            &fake,
            "repository-visibility",
            json!({"expected": "public"})
        ),
        pending("private, expected public")
    );
}

// ---- org-2fa-required ---------------------------------------------------------------

#[test]
fn org_2fa_required_reads_the_organization_and_a_hidden_field_is_unavailable() {
    let org = |value: Value| {
        Fake::new().json(
            "orgs/example-org",
            json!({"login": "example-org", "two_factor_requirement_enabled": value}),
        )
    };
    let a = json!({"org": "example-org"});
    assert_eq!(
        run(&org(json!(true)), "org-2fa-required", a.clone()),
        verified("required")
    );
    assert_eq!(
        run(&org(json!(false)), "org-2fa-required", a.clone()),
        pending("not required")
    );
    assert_eq!(
        run(&org(Value::Null), "org-2fa-required", a),
        ProbeResult::Unavailable(
            "two-factor requirement of example-org is not visible to this token (needs an organization owner)"
                .to_owned()
        )
    );
}

// ---- feature-available --------------------------------------------------------------

#[test]
fn feature_available_maps_available_unavailable_and_unknown() {
    let features = |rulesets: std::result::Result<Value, (u16, &str)>| {
        let fake = Fake::new()
            .json(BASE, repository(json!({})))
            .json(format!("{BASE}/environments"), json!({"environments": []}))
            .http(
                format!("{BASE}/branches/main/protection"),
                404,
                "Branch not protected",
            )
            .json(format!("{BASE}/vulnerability-alerts"), Value::Null)
            .http(
                format!("{BASE}/contents/.github/workflows/actions.lock?ref=main"),
                404,
                "Not Found",
            )
            .json(format!("{BASE}/rules/branches/main"), json!([]));
        match rulesets {
            Ok(v) => fake.json(format!("{BASE}/rulesets"), v),
            Err((s, m)) => fake.http(format!("{BASE}/rulesets"), s, m),
        }
    };
    let a = json!({"feature": "rulesets"});
    assert_eq!(
        run(&features(Ok(json!([]))), "feature-available", a.clone()),
        verified("available")
    );
    assert_eq!(
        run(
            &features(Err((
                403,
                "Upgrade to GitHub Pro or make this repository public to enable this feature."
            ))),
            "feature-available",
            a.clone()
        ),
        pending(
            "unavailable (403: Upgrade to GitHub Pro or make this repository public to enable this feature.)"
        )
    );
    assert_eq!(
        run(&features(Err((404, "Not Found"))), "feature-available", a),
        ProbeResult::Unavailable("unknown (404: Not Found)".to_owned())
    );
}

// ---- reusable-workflow-reachable (#785) ---------------------------------------------

const CALLEE: &str = "repos/example-owner/agentic-project-setup";

#[test]
fn reusable_workflow_reachable_is_verified_when_the_callee_is_public() {
    let fake = Fake::new().json(CALLEE, repository(json!({"visibility": "public"})));
    assert_eq!(
        run(
            &fake,
            "reusable-workflow-reachable",
            json!({"callee": "example-owner/agentic-project-setup"})
        ),
        verified("example-owner/agentic-project-setup is public")
    );
}

#[test]
fn reusable_workflow_reachable_reads_the_access_level_of_a_private_callee_of_the_same_owner() {
    let access = format!("{CALLEE}/actions/permissions/access");
    let open = Fake::new()
        .json(CALLEE, repository(json!({})))
        .json(&access, json!({"access_level": "user"}));
    assert_eq!(
        run(
            &open,
            "reusable-workflow-reachable",
            json!({"callee": "example-owner/agentic-project-setup"})
        ),
        verified(
            "example-owner/agentic-project-setup is private and lets repositories of example-owner call its workflows (access level user)"
        )
    );
    let closed = Fake::new()
        .json(CALLEE, repository(json!({})))
        .json(&access, json!({"access_level": "none"}));
    assert_eq!(
        run(
            &closed,
            "reusable-workflow-reachable",
            json!({"callee": "example-owner/agentic-project-setup"})
        ),
        pending(
            "example-owner/agentic-project-setup is private with access level none: no other repository can call its workflows"
        )
    );
}

#[test]
fn reusable_workflow_reachable_is_pending_for_a_private_callee_of_another_owner() {
    let fake = Fake::new().json("repos/someone-else/tools", repository(json!({})));
    assert_eq!(
        run(
            &fake,
            "reusable-workflow-reachable",
            json!({"callee": "someone-else/tools"})
        ),
        pending(
            "someone-else/tools is private and owned by someone-else; a repository of example-owner cannot call it"
        )
    );
    assert_eq!(*fake.calls.borrow(), ["repos/someone-else/tools"]);
}

#[test]
fn reusable_workflow_reachable_refuses_a_callee_that_is_not_owner_slash_name() {
    assert_eq!(
        probes::check(
            "reusable-workflow-reachable",
            &args(json!({"callee": "not a repository"}))
        ),
        Err(
            "remote probe `reusable-workflow-reachable`: argument `callee` must be owner/name"
                .to_owned()
        )
    );
}
