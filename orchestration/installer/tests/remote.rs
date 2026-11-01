use brakes::{
    Result,
    remote::{Api, HttpError, inspect, inspect_report},
};
use serde_json::{Value, json};
use std::{cell::RefCell, collections::BTreeMap};

const REPO: &str = "example-owner/example";
const BASE: &str = "repos/example-owner/example";
struct Fake {
    responses: BTreeMap<String, Value>,
    calls: RefCell<Vec<String>>,
}
impl Api for Fake {
    fn get(&self, path: &str) -> Result<Value> {
        self.calls.borrow_mut().push(path.to_owned());
        let value = self
            .responses
            .get(path)
            .cloned()
            .ok_or_else(|| format!("unexpected GET {path}"))?;
        if let Some(status) = value["status"].as_str() {
            return Err(HttpError {
                status: status.parse().unwrap(),
                message: value["message"].as_str().unwrap().to_owned(),
            }
            .into());
        }
        Ok(value)
    }
}
fn ci() -> Value {
    json!({"required_checks": ["Rust (linux)", "test / verify"],
        "shards": {"count": 2,"command":"cargo nextest run --partition count:<i>/2"},
        "tiers": {"pull_request": {"inert_paths": ["docs/", "tasks/", "*.md"], "full_paths": ["orchestration/"]}, "main": {"paths": ["**"]}},
        "cycle_budget_minutes":10})
}
fn run(id: u64, event: &str) -> Value {
    json!({"id":id, "head_sha":format!("head-{id}"), "head_branch": if event == "push" {"trunk"} else {"feature"},
        "event":event,"status":"completed","conclusion":"success","pull_requests":[{"number":8}],
        "created_at":"2026-10-22T10:00:00Z"})
}
fn jobs() -> Value {
    jobs_with_shards(2)
}
fn jobs_with_shards(count: u64) -> Value {
    let mut list: Vec<Value> = (1..=count)
        .map(|i| {
            json!({
                "name": format!("Rust shard {i}/{count} (linux)"),
                "conclusion": "success",
                "started_at": "2026-10-22T10:00:01Z",
                "completed_at": "2026-10-22T10:02:00Z",
                "steps": [{"name": "Test CLI (shard)", "conclusion": "success"}]
            })
        })
        .collect();
    list.push(json!({
        "name": "Rust lint (linux)",
        "conclusion": "success",
        "started_at": "2026-10-22T10:00:01Z",
        "completed_at": "2026-10-22T10:02:00Z",
        "steps": [{"name": "Check lints", "conclusion": "success"}]
    }));
    json!({"total_count": list.len(), "jobs": list})
}
fn healthy() -> Fake {
    let mut responses = BTreeMap::new();
    responses.insert(BASE.to_owned(), json!({"default_branch":"trunk"}));
    responses.insert(format!("{BASE}/branches/trunk/protection"), json!({
        "required_status_checks":{"contexts":["Rust (linux)"],"checks":[{"context":"test / verify"}]},
        "enforce_admins":{"enabled":true}, "allow_force_pushes":{"enabled":false},"allow_deletions":{"enabled":false}}));
    responses.insert(
        format!("{BASE}/actions/runs?per_page=100"),
        json!({"workflow_runs":[run(2,"pull_request"),run(1,"push")]}),
    );
    responses.insert(
        format!("{BASE}/actions/runs/1/jobs?per_page=100&page=1"),
        jobs(),
    );
    responses.insert(
        format!("{BASE}/actions/runs/2/jobs?per_page=100&page=1"),
        jobs(),
    );
    responses.insert(
        format!("{BASE}/pulls/8/files?per_page=100&page=1"),
        json!([{"filename":"orchestration/src/main.rs"}]),
    );
    responses.insert(
        format!("{BASE}/pulls/8"),
        json!({"head":{"sha":"head-2"},"base":{"sha":"base-2"}}),
    );
    Fake {
        responses,
        calls: RefCell::new(Vec::new()),
    }
}

#[test]
fn healthy_protection_and_recent_ci_are_clean() {
    let api = healthy();
    assert_eq!(inspect(&api, REPO, &ci()), Vec::<String>::new());
    assert!(
        api.calls
            .borrow()
            .iter()
            .any(|s| s.contains("branches/trunk/protection"))
    );
    assert!(api.calls.borrow().iter().all(|s| s.starts_with(BASE)));
}
#[test]
fn protection_drift_reports_each_fact_as_one_sentence() {
    let mut api = healthy();
    let protection = api
        .responses
        .get_mut(&format!("{BASE}/branches/trunk/protection"))
        .unwrap();
    protection["required_status_checks"] = json!({"contexts":[]});
    protection["allow_force_pushes"]["enabled"] = json!(true);
    protection["allow_deletions"]["enabled"] = json!(true);
    protection["enforce_admins"]["enabled"] = json!(false);
    let findings = inspect(&api, REPO, &ci());
    for needle in [
        "Rust (linux)",
        "test / verify",
        "force pushes",
        "deletion",
        "administrators",
    ] {
        assert!(findings.iter().any(|s| s.contains(needle)), "{findings:?}");
    }
    assert!(
        findings
            .iter()
            .all(|s| !s.contains('\n') && s.ends_with('.'))
    );
}
#[test]
fn inaccessible_protection_does_not_hide_ci_findings() {
    let mut api = healthy();
    api.responses
        .remove(&format!("{BASE}/branches/trunk/protection"));
    api.responses
        .get_mut(&format!("{BASE}/actions/runs/1/jobs?per_page=100&page=1"))
        .unwrap()["jobs"][0]["completed_at"] = json!("2026-10-22T10:22:00Z");
    let findings = inspect(&api, REPO, &ci());
    assert!(
        findings
            .iter()
            .any(|s| s.contains("protection") && s.contains("could not")),
        "{findings:?}"
    );
    assert!(
        findings.iter().any(|s| s.contains("budget")),
        "{findings:?}"
    );
}
#[test]
fn missing_or_skipped_shards_on_main_are_reported() {
    for skipped in [false, true] {
        let mut api = healthy();
        let jobs = api
            .responses
            .get_mut(&format!("{BASE}/actions/runs/1/jobs?per_page=100&page=1"))
            .unwrap();
        if skipped {
            jobs["jobs"][1]["steps"][0]["conclusion"] = json!("skipped");
        } else {
            jobs["jobs"].as_array_mut().unwrap().remove(1);
            jobs["total_count"] = json!(2);
        }
        let findings = inspect(&api, REPO, &ci());
        assert!(findings.iter().any(|s| s.contains("shard")), "{findings:?}");
    }
}
#[test]
fn docs_pull_request_tier_checks_step_execution_rather_than_job_success() {
    let mut api = healthy();
    api.responses.insert(
        format!("{BASE}/pulls/8/files?per_page=100&page=1"),
        json!([{"filename":"docs/guide.md"}]),
    );
    let findings = inspect(&api, REPO, &ci());
    assert!(
        findings.iter().any(|s| s.contains("documentation")),
        "{findings:?}"
    );
    let jobs = api
        .responses
        .get_mut(&format!("{BASE}/actions/runs/2/jobs?per_page=100&page=1"))
        .unwrap();
    for job in jobs["jobs"].as_array_mut().unwrap() {
        job["steps"][0]["conclusion"] = json!("skipped");
    }
    assert_eq!(inspect(&api, REPO, &ci()), Vec::<String>::new());
}
#[test]
fn unknown_files_and_orchestration_markdown_require_full_pr_tier() {
    for file in ["unknown.config", "orchestration/README.md"] {
        let mut api = healthy();
        api.responses.insert(
            format!("{BASE}/pulls/8/files?per_page=100&page=1"),
            json!([{"filename":file}]),
        );
        let jobs = api
            .responses
            .get_mut(&format!("{BASE}/actions/runs/2/jobs?per_page=100&page=1"))
            .unwrap();
        jobs["jobs"][0]["steps"][0]["conclusion"] = json!("skipped");
        assert!(
            inspect(&api, REPO, &ci())
                .iter()
                .any(|s| s.contains("shard"))
        );
    }
}
#[test]
fn absent_runs_invalid_json_shapes_and_missing_policy_never_pass() {
    let mut api = healthy();
    api.responses.insert(
        format!("{BASE}/actions/runs?per_page=100"),
        json!({"workflow_runs":[]}),
    );
    assert!(!inspect(&api, REPO, &ci()).is_empty());
    for value in [
        json!(null),
        json!({}),
        json!({"required_checks": [],"shards":{"count":0}}),
    ] {
        assert!(!inspect(&healthy(), REPO, &value).is_empty());
    }
    api.responses.insert(BASE.to_owned(), json!([]));
    assert!(!inspect(&api, REPO, &ci()).is_empty());
}
#[test]
fn unapproved_organization_repositories_make_no_api_calls() {
    let api = healthy();
    assert!(!inspect(&api, "outside-org/other", &ci()).is_empty());
    assert!(api.calls.borrow().is_empty());
}

#[test]
fn explicitly_authorized_personal_organization_repos_use_only_repo_endpoints() {
    for repository in ["example-org/example-app", "example-org/other-app"] {
        let mut api = healthy();
        let prefix = format!("repos/{repository}");
        api.responses = api
            .responses
            .into_iter()
            .map(|(key, value)| (key.replacen(BASE, &prefix, 1), value))
            .collect();
        assert!(inspect(&api, repository, &ci()).is_empty());
        assert!(
            api.calls
                .borrow()
                .iter()
                .all(|path| path.starts_with(&prefix))
        );
    }
}

#[test]
fn jobs_are_paginated_and_incomplete_pages_are_a_finding() {
    let mut api = healthy();
    let mut first = vec![json!({"name":"other", "conclusion":"skipped"}); 100];
    first.extend(jobs()["jobs"].as_array().unwrap().clone());
    let last = first.split_off(100);
    api.responses.insert(
        format!("{BASE}/actions/runs/1/jobs?per_page=100&page=1"),
        json!({"total_count":103,"jobs":first}),
    );
    api.responses.insert(
        format!("{BASE}/actions/runs/1/jobs?per_page=100&page=2"),
        json!({"total_count":103,"jobs":last}),
    );
    assert!(inspect(&api, REPO, &ci()).is_empty());
    assert!(
        api.calls
            .borrow()
            .iter()
            .any(|p| p.ends_with("jobs?per_page=100&page=2"))
    );
    api.responses
        .remove(&format!("{BASE}/actions/runs/1/jobs?per_page=100&page=2"));
    assert!(
        inspect(&api, REPO, &ci())
            .iter()
            .any(|s| s.contains("could not be read completely"))
    );
}

#[test]
fn changed_files_are_paginated_and_renamed_code_still_requires_full_tier() {
    let mut api = healthy();
    api.responses.insert(
        format!("{BASE}/pulls/8/files?per_page=100&page=1"),
        json!(vec![json!({"filename":"README.md"}); 100]),
    );
    api.responses.insert(
        format!("{BASE}/pulls/8/files?per_page=100&page=2"),
        json!([{"filename":"src/main.rs"}]),
    );
    assert!(inspect(&api, REPO, &ci()).is_empty());
    assert!(
        api.calls
            .borrow()
            .iter()
            .any(|p| p.ends_with("files?per_page=100&page=2"))
    );
    api.responses.insert(
        format!("{BASE}/pulls/8/files?per_page=100&page=1"),
        json!([{"filename":"docs/old.md","previous_filename":"src/main.rs"}]),
    );
    assert!(inspect(&api, REPO, &ci()).is_empty());
}

#[test]
fn invalid_job_shapes_missing_timing_and_pending_runs_stay_unverified() {
    for response in [
        json!([]),
        json!({"jobs":[]}),
        json!({"total_count":1,"jobs":[]}),
    ] {
        let mut api = healthy();
        api.responses.insert(
            format!("{BASE}/actions/runs/1/jobs?per_page=100&page=1"),
            response,
        );
        assert!(
            inspect(&api, REPO, &ci())
                .iter()
                .any(|s| s.contains("could not be read completely"))
        );
    }
    let mut api = healthy();
    api.responses
        .get_mut(&format!("{BASE}/actions/runs/1/jobs?per_page=100&page=1"))
        .unwrap()["jobs"][0]["completed_at"] = json!(null);
    assert!(
        inspect(&api, REPO, &ci())
            .iter()
            .any(|s| s.contains("timing evidence"))
    );
    let mut api = healthy();
    api.responses
        .get_mut(&format!("{BASE}/actions/runs?per_page=100"))
        .unwrap()["workflow_runs"][0]["status"] = json!("in_progress");
    assert!(
        inspect(&api, REPO, &ci())
            .iter()
            .any(|s| s.contains("still incomplete"))
    );
}

#[test]
fn missing_skip_steps_and_unsupported_policy_cannot_pass() {
    let mut api = healthy();
    api.responses
        .get_mut(&format!("{BASE}/actions/runs/1/jobs?per_page=100&page=1"))
        .unwrap()["jobs"][0]["steps"] = json!([]);
    assert!(
        inspect(&api, REPO, &ci())
            .iter()
            .any(|s| s.contains("no test execution evidence"))
    );
    let mut policy = ci();
    policy["tiers"]["main"] = json!("sometimes runs");
    assert!(
        inspect(&healthy(), REPO, &policy)
            .iter()
            .any(|s| s.contains("tiers cannot be evaluated"))
    );
}

#[test]
fn branch_names_are_encoded_and_findings_cannot_inject_lines() {
    let mut api = healthy();
    api.responses.get_mut(BASE).unwrap()["default_branch"] = json!("release/current");
    let protection = api
        .responses
        .remove(&format!("{BASE}/branches/trunk/protection"))
        .unwrap();
    api.responses.insert(
        format!("{BASE}/branches/release%2Fcurrent/protection"),
        protection,
    );
    let mut policy = ci();
    policy["required_checks"] = json!(["unexpected\rcheck"]);
    let findings = inspect(&api, REPO, &policy);
    assert!(
        api.calls
            .borrow()
            .iter()
            .any(|p| p.contains("release%2Fcurrent"))
    );
    assert!(findings.iter().all(|s| !s.contains(['\n', '\r'])));
}

#[test]
fn latest_attempt_replaces_old_workflow_runs() {
    let mut api = healthy();
    let value = api
        .responses
        .get_mut(&format!("{BASE}/actions/runs?per_page=100"))
        .unwrap();
    value["workflow_runs"][1]["workflow_id"] = json!(40);
    let mut old = value["workflow_runs"][1].clone();
    old["id"] = json!(9);
    old["created_at"] = json!("2026-10-22T09:00:00Z");
    old["conclusion"] = json!("failure");
    value["workflow_runs"].as_array_mut().unwrap().push(old);
    assert!(inspect(&api, REPO, &ci()).is_empty());
    assert!(!api.calls.borrow().iter().any(|p| p.contains("runs/9/")));
}

#[test]
fn lint_tier_is_checked_independently_of_shards() {
    let mut api = healthy();
    api.responses
        .get_mut(&format!("{BASE}/actions/runs/1/jobs?per_page=100&page=1"))
        .unwrap()["jobs"][2]["steps"][0]["conclusion"] = json!("skipped");
    let findings = inspect(&api, REPO, &ci());
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert!(findings[0].starts_with("Lint in the latest default-branch"));

    let mut api = healthy();
    api.responses.insert(
        format!("{BASE}/pulls/8/files?per_page=100&page=1"),
        json!([{"filename":"README.md"}]),
    );
    let jobs = api
        .responses
        .get_mut(&format!("{BASE}/actions/runs/2/jobs?per_page=100&page=1"))
        .unwrap();
    for job in &mut jobs["jobs"].as_array_mut().unwrap()[..2] {
        job["steps"][0]["conclusion"] = json!("skipped");
    }
    let findings = inspect(&api, REPO, &ci());
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert!(findings[0].starts_with("Lint ran or lacks skip evidence"));
}

#[test]
fn pull_request_tier_is_bound_to_the_observed_run_commit() {
    let mut api = healthy();
    api.responses.get_mut(&format!("{BASE}/pulls/8")).unwrap()["head"]["sha"] = json!("newer-head");
    assert!(
        inspect(&api, REPO, &ci())
            .iter()
            .any(|s| s.contains("CI tier is unverified"))
    );
    assert!(!api.calls.borrow().iter().any(|p| p.contains("/files?")));
}

#[test]
fn pull_request_moving_during_file_pagination_cannot_certify_the_docs_tier() {
    struct Moving {
        api: Fake,
        reads: RefCell<u32>,
    }
    impl Api for Moving {
        fn get(&self, path: &str) -> Result<Value> {
            let mut value = self.api.get(path)?;
            if path == format!("{BASE}/pulls/8") {
                *self.reads.borrow_mut() += 1;
                if *self.reads.borrow() > 1 {
                    value["base"]["sha"] = json!("moved-base");
                }
            }
            Ok(value)
        }
    }
    let mut api = healthy();
    api.responses.insert(
        format!("{BASE}/pulls/8/files?per_page=100&page=1"),
        json!([{"filename":"README.md"}]),
    );
    let api = Moving {
        api,
        reads: RefCell::new(0),
    };
    assert!(
        inspect(&api, REPO, &ci())
            .iter()
            .any(|s| s.contains("CI tier is unverified"))
    );
}

fn docs_tier_ci() -> Value {
    json!({
        "required_checks": ["Rust (linux)", "test / verify"],
        "shards": {"count": 4, "command": "cargo nextest run --locked --partition count:<i>/4"},
        "tiers": {
            "pull_request": {"inert_paths": ["docs/", "tasks/", "*.md"], "full_paths": ["orchestration/"]},
            "main": {"paths": ["**"]}
        },
        "cycle_budget_minutes": 10
    })
}

fn docs_tier_setup() -> Fake {
    let mut responses = BTreeMap::new();
    responses.insert(BASE.to_owned(), json!({"default_branch": "trunk"}));
    responses.insert(
        format!("{BASE}/branches/trunk/protection"),
        json!({
            "required_status_checks": {"contexts": ["Rust (linux)"], "checks": [{"context": "test / verify"}]},
            "enforce_admins": {"enabled": true},
            "allow_force_pushes": {"enabled": false},
            "allow_deletions": {"enabled": false}
        }),
    );
    responses.insert(
        format!("{BASE}/actions/runs?per_page=100"),
        json!({"workflow_runs": [
            json!({"id": 2, "head_sha": "head-2", "head_branch": "feature", "event": "pull_request", "status": "completed", "conclusion": "success", "pull_requests": [{"number": 8}], "created_at": "2026-10-22T10:00:00Z"}),
            json!({"id": 1, "head_sha": "head-1", "head_branch": "trunk", "event": "push", "status": "completed", "conclusion": "success", "pull_requests": [], "created_at": "2026-10-22T10:00:00Z"})
        ]}),
    );
    let mut docs_jobs = vec![json!({
        "name": "Scope",
        "conclusion": "success",
        "started_at": "2026-10-22T10:00:00Z",
        "completed_at": "2026-10-22T10:00:05Z",
        "steps": [{"name": "Decide tier", "conclusion": "success"}],
        "outputs": {"tier": "docs"}
    })];
    for i in 1..=4 {
        docs_jobs.push(json!({
            "name": format!("Rust shard {i}/4 (linux)"),
            "conclusion": "success",
            "started_at": "2026-10-22T10:00:01Z",
            "completed_at": "2026-10-22T10:02:00Z",
            "steps": [{"name": "Documentation-only change; Rust shard skipped by the docs tier.", "conclusion": "success"}]
        }));
    }
    docs_jobs.push(json!({
        "name": "Rust lint (linux)",
        "conclusion": "success",
        "started_at": "2026-10-22T10:00:01Z",
        "completed_at": "2026-10-22T10:02:00Z",
        "steps": [{"name": "Documentation-only change; Rust lint skipped by the docs tier.", "conclusion": "success"}]
    }));
    docs_jobs.push(json!({
        "name": "Rust (linux)",
        "conclusion": "success",
        "started_at": "2026-10-22T10:00:01Z",
        "completed_at": "2026-10-22T10:02:00Z",
        "steps": [{"name": "Aggregate results", "conclusion": "success"}]
    }));
    responses.insert(
        format!("{BASE}/actions/runs/2/jobs?per_page=100&page=1"),
        json!({"total_count": docs_jobs.len(), "jobs": docs_jobs}),
    );
    responses.insert(
        format!("{BASE}/actions/runs/1/jobs?per_page=100&page=1"),
        jobs_with_shards(4),
    );
    responses.insert(
        format!("{BASE}/pulls/8/files?per_page=100&page=1"),
        json!([{"filename": "docs/guide.md"}]),
    );
    responses.insert(
        format!("{BASE}/pulls/8"),
        json!({"head": {"sha": "head-2"}, "base": {"sha": "base-2"}}),
    );
    Fake {
        responses,
        calls: RefCell::new(Vec::new()),
    }
}

#[test]
fn docs_tier_accepts_skipped_shards_and_prints_neutral_line() {
    let api = docs_tier_setup();
    let report = inspect_report(&api, REPO, &docs_tier_ci());
    assert!(report.findings.is_empty(), "{:?}", report.findings);
    assert_eq!(
        report.note,
        Some("Último ciclo: solo documentación, sin tests de Rust (correcto)".to_owned())
    );
}

#[test]
fn foreign_repository_tiers_use_their_declared_paths() {
    let mut policy = docs_tier_ci();
    policy["tiers"]["pull_request"] = json!({
        "inert_paths": ["handbook/", "*.md", "NOTICE"], "full_paths": ["app/"]
    });
    for (path, docs) in [
        ("handbook/guide.txt", true),
        ("orchestration/notes.md", true),
        ("NOTICE", true),
        ("app/notes.md", false),
        ("docs/guide.txt", false),
        ("handbookish/guide.txt", false),
    ] {
        let mut api = docs_tier_setup();
        api.responses.insert(
            format!("{BASE}/pulls/8/files?per_page=100&page=1"),
            json!([{"filename": path}]),
        );
        if !docs {
            api.responses.insert(
                format!("{BASE}/actions/runs/2/jobs?per_page=100&page=1"),
                jobs_with_shards(4),
            );
        }
        let findings = inspect(&api, REPO, &policy);
        assert!(findings.is_empty(), "{path}: {findings:?}");
    }
}

#[test]
fn tiers_require_explicit_valid_path_lists() {
    for tiers in [
        Value::Null,
        json!({"main": {"paths": ["**"]}}),
        json!({"pull_request": {"inert_paths": ["docs/"], "full_paths": []}}),
        json!({"pull_request": {"inert_paths": ["docs/"]}, "main": {"paths": ["**"]}}),
        json!({"pull_request": {"inert_paths": [42], "full_paths": []}, "main": {"paths": ["**"]}}),
        json!({"pull_request": {"inert_paths": [], "full_paths": []}, "main": {"paths": ["**"]}}),
        json!({"pull_request": {"inert_paths": ["../docs/"], "full_paths": []}, "main": {"paths": ["**"]}}),
        json!({"pull_request": {"inert_paths": ["docs/**"], "full_paths": []}, "main": {"paths": ["**"]}}),
        json!({"pull_request": {"inert_paths": ["docs/"], "full_paths": []}, "main": {"paths": ["src/"]}}),
    ] {
        let mut policy = ci();
        policy["tiers"] = tiers;
        assert!(
            inspect(&healthy(), REPO, &policy)
                .iter()
                .any(|s| s.contains("tiers cannot be evaluated"))
        );
    }
}

#[test]
fn only_explicit_branch_not_protected_404_is_an_unprotected_finding() {
    for (status, message, unprotected) in [
        (404, "Branch not protected", true),
        (404, "Not Found", false),
        (403, "Branch not protected", false),
    ] {
        let mut api = healthy();
        api.responses.insert(
            format!("{BASE}/branches/trunk/protection"),
            json!({"status": status.to_string(), "message": message}),
        );
        let findings = inspect(&api, REPO, &ci());
        if unprotected {
            assert_eq!(findings, ["Default branch is not protected."]);
        } else {
            assert_eq!(
                findings,
                [
                    "The default branch protection could not be read, so required checks and push restrictions are unverified."
                ]
            );
        }
    }
}

/// The 403 a private repository on a plan without protection answers (#1164:
/// first seen on an organisation's Free plan in the #1157 rollout).
const PLAN_REFUSAL: &str =
    "Upgrade to GitHub Pro or make this repository public to enable this feature.";

#[test]
fn a_plan_refused_protection_read_names_the_plan_and_the_missing_barrier() {
    let mut api = healthy();
    api.responses.insert(
        format!("{BASE}/branches/trunk/protection"),
        json!({"status": "403", "message": PLAN_REFUSAL}),
    );
    let findings = inspect(&api, REPO, &ci());
    assert_eq!(
        findings,
        [format!(
            "The default branch protection requires plan Team: the plan refuses branch protection and rulesets on this private repository (HTTP 403: {PLAN_REFUSAL}), so there is no server-side merge barrier and the session hook is the only barrier."
        )]
    );
}

#[test]
fn full_tier_skipped_shard_is_a_finding() {
    let mut api = healthy();
    api.responses.insert(
        format!("{BASE}/pulls/8/files?per_page=100&page=1"),
        json!([{"filename": "orchestration/src/main.rs"}]),
    );
    let jobs = api
        .responses
        .get_mut(&format!("{BASE}/actions/runs/2/jobs?per_page=100&page=1"))
        .unwrap();
    jobs["jobs"][0]["conclusion"] = json!("skipped");
    jobs["jobs"][0]["steps"] = json!([{
        "name": "Documentation-only change; Rust shard skipped by the docs tier.",
        "conclusion": "success"
    }]);
    let report = inspect_report(&api, REPO, &ci());
    assert!(
        report
            .findings
            .iter()
            .any(|s| s.contains("shard") && s.contains("skipped")),
        "{:?}",
        report.findings
    );
    assert!(report.note.is_none(), "{:?}", report.note);
}

#[test]
fn in_progress_cycle_says_en_curso_once() {
    let mut api = healthy();
    api.responses
        .get_mut(&format!("{BASE}/actions/runs?per_page=100"))
        .unwrap()["workflow_runs"][0]["status"] = json!("in_progress");
    let report = inspect_report(&api, REPO, &ci());
    assert_eq!(
        report.note,
        Some("Último ciclo pull-request: en curso".to_owned())
    );
    assert!(
        report
            .findings
            .iter()
            .filter(|s| s.contains("incomplete"))
            .count()
            <= 1,
        "{:?}",
        report.findings
    );
}

#[test]
fn scope_claim_disagreeing_with_doctor_is_a_finding() {
    let mut api = docs_tier_setup();
    let jobs = api
        .responses
        .get_mut(&format!("{BASE}/actions/runs/2/jobs?per_page=100&page=1"))
        .unwrap();
    jobs["jobs"][0]["outputs"]["tier"] = json!("full");
    let report = inspect_report(&api, REPO, &docs_tier_ci());
    assert!(
        report
            .findings
            .iter()
            .any(|s| s.contains("Scope") && s.contains("full") && s.contains("doctor")),
        "{:?}",
        report.findings
    );
}

// --- #1109: with ci-baseline installed, what ci-baseline and repo-baseline render ------

/// Read-only `gh api` replies of a pilot repository, recorded on
/// 2026-10-30 after the #948 pilot and trimmed to
/// the fields `inspect_report` reads: classic protection of `main` (it still
/// requires the old `verify`; no ruleset yet, `rules/branches/main` answered
/// `[]`), the latest runs, the jobs of the pilot pull request's two runs and of
/// the latest push to `main`. The repository has ci-baseline and no `ci.*` keys.
mod pilot {
    use super::*;
    use brakes::remote::{CiBaselinePolicy, Policy, inspect_policy};

    const REPO: &str = "example-owner/pilot";
    const BASE: &str = "repos/example-owner/pilot";

    fn recorded(name: &str) -> Value {
        let path = format!(
            "{}/tests/fixtures/remote/pilot/{name}.json",
            env!("CARGO_MANIFEST_DIR")
        );
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    /// The recorded host, with `rules` as the reply of `rules/branches/main`.
    fn host(protection: Option<Value>, rules: Value, ci_conclusion: &str) -> Fake {
        let mut responses = BTreeMap::new();
        responses.insert(BASE.to_owned(), json!({"default_branch": "main"}));
        responses.insert(
            format!("{BASE}/branches/main/protection"),
            protection.unwrap_or(json!({"status": "404", "message": "Branch not protected"})),
        );
        responses.insert(format!("{BASE}/rules/branches/main"), rules);
        let mut runs = recorded("runs");
        for run in runs["workflow_runs"].as_array_mut().unwrap() {
            if run["name"] == "CI (brakes)" {
                run["conclusion"] = json!(ci_conclusion);
            }
        }
        responses.insert(format!("{BASE}/actions/runs?per_page=100"), runs);
        let mut ci_jobs = recorded("jobs-ci");
        if ci_conclusion == "success" {
            for job in ci_jobs["jobs"].as_array_mut().unwrap() {
                if job["conclusion"] == "failure" {
                    job["conclusion"] = json!("success");
                }
            }
        }
        responses.insert(
            format!("{BASE}/actions/runs/40993864399/jobs?per_page=100&page=1"),
            ci_jobs,
        );
        responses.insert(
            format!("{BASE}/actions/runs/40993864351/jobs?per_page=100&page=1"),
            recorded("jobs-verify-pr"),
        );
        responses.insert(
            format!("{BASE}/actions/runs/40689773178/jobs?per_page=100&page=1"),
            recorded("jobs-push"),
        );
        Fake {
            responses,
            calls: RefCell::new(Vec::new()),
        }
    }

    fn ci_baseline(required: &[&str]) -> Policy<'static> {
        Policy::CiBaseline(CiBaselinePolicy {
            required: required.iter().map(|s| (*s).to_owned()).collect(),
            shards: None,
            cycle_budget_minutes: None,
        })
    }

    /// The rules GitHub reports for `main` once the rendered ruleset is active.
    fn ruleset_rules(contexts: &[&str]) -> Value {
        let checks: Vec<Value> = contexts.iter().map(|c| json!({"context": c})).collect();
        json!([
            {"type": "deletion", "ruleset_id": 7},
            {"type": "non_fast_forward", "ruleset_id": 7},
            {"type": "required_status_checks", "ruleset_id": 7,
             "parameters": {"strict_required_status_checks_policy": true, "required_status_checks": checks}}
        ])
    }

    #[test]
    fn without_ci_baseline_the_recorded_repository_keeps_todays_findings() {
        let api = host(Some(recorded("protection")), json!([]), "failure");
        let findings = inspect_report(&api, REPO, &json!({})).findings;
        for expected in [
            "The project has no valid declared required CI checks.",
            "The CI shard policy needs a positive count up to 256 and a declared command.",
            "The CI cycle budget is missing or invalid.",
        ] {
            assert!(
                findings.contains(&expected.to_owned()),
                "{expected}: {findings:#?}"
            );
        }
        assert!(
            findings
                .iter()
                .any(|f| f.starts_with("The declared CI tiers cannot be evaluated")),
            "{findings:#?}"
        );
    }

    #[test]
    fn with_ci_baseline_the_pilot_state_names_only_what_is_really_missing() {
        // Recorded as found: classic protection still requires `verify`, and the
        // pilot pull request's CI is red until the owner adds `human-approved`.
        let api = host(Some(recorded("protection")), json!([]), "failure");
        let findings = inspect_policy(&api, REPO, &ci_baseline(&["required"])).findings;
        assert_eq!(
            findings,
            [
                "The default branch no longer requires CI check 'required'.",
                "A workflow in the latest pull-request CI cycle did not succeed.",
            ],
            "{findings:#?}"
        );
    }

    #[test]
    fn with_ci_baseline_an_active_ruleset_and_green_cycles_have_no_finding() {
        let api = host(None, ruleset_rules(&["required"]), "success");
        let findings = inspect_policy(&api, REPO, &ci_baseline(&["required"])).findings;
        assert_eq!(findings, Vec::<String>::new());
        assert!(
            api.calls
                .borrow()
                .iter()
                .any(|c| c == &format!("{BASE}/rules/branches/main"))
        );
    }

    #[test]
    fn with_ci_baseline_a_ruleset_must_require_the_checks_and_forbid_push_and_deletion() {
        let api = host(
            None,
            json!([{"type": "required_linear_history"}]),
            "success",
        );
        let findings = inspect_policy(&api, REPO, &ci_baseline(&["required"])).findings;
        assert_eq!(
            findings,
            [
                "The default branch no longer requires CI check 'required'.",
                "The default branch does not explicitly forbid force pushes.",
                "The default branch does not explicitly forbid branch deletion.",
            ]
        );
        let api = host(None, json!([]), "success");
        let findings = inspect_policy(&api, REPO, &ci_baseline(&["required"])).findings;
        assert_eq!(findings, ["Default branch is not protected."]);
    }

    #[test]
    fn with_ci_baseline_a_plan_refused_protection_and_ruleset_read_names_the_plan() {
        let refused = json!({"status": "403", "message": super::PLAN_REFUSAL});
        let expected = format!(
            "The default branch protection requires plan Team: the plan refuses branch protection and rulesets on this private repository (HTTP 403: {}), so there is no server-side merge barrier and the session hook is the only barrier.",
            super::PLAN_REFUSAL
        );
        for rules in [refused.clone(), json!([])] {
            let api = host(Some(refused.clone()), rules, "success");
            let findings = inspect_policy(&api, REPO, &ci_baseline(&["required"])).findings;
            assert_eq!(findings, std::slice::from_ref(&expected));
        }
        // An applying rule is still judged, plan refusal of the classic read or not.
        let api = host(Some(refused), ruleset_rules(&["required"]), "success");
        let findings = inspect_policy(&api, REPO, &ci_baseline(&["required"])).findings;
        assert_eq!(findings, Vec::<String>::new());
    }

    #[test]
    fn with_ci_baseline_its_shard_jobs_are_test_evidence() {
        let mut api = host(None, ruleset_rules(&["required"]), "success");
        let shard = |i: u64| {
            json!({"name": format!("shard {i}/2"), "conclusion": "success", "status": "completed",
                   "started_at": "2026-10-30T02:49:10Z", "completed_at": "2026-10-30T02:50:10Z",
                   "steps": [{"name": "Run declared shard", "conclusion": "success"}]})
        };
        for run in ["40993864399", "40689773178"] {
            let path = format!("{BASE}/actions/runs/{run}/jobs?per_page=100&page=1");
            let mut jobs = api.responses[&path].clone();
            let list = jobs["jobs"].as_array_mut().unwrap();
            list.push(shard(1));
            list.push(shard(2));
            jobs["total_count"] = json!(list.len());
            api.responses.insert(path, jobs);
        }
        let policy = Policy::CiBaseline(CiBaselinePolicy {
            required: vec!["required".to_owned()],
            shards: Some(2),
            cycle_budget_minutes: None,
        });
        assert_eq!(
            inspect_policy(&api, REPO, &policy).findings,
            Vec::<String>::new()
        );
    }

    #[test]
    fn with_ci_baseline_declared_shards_and_budget_are_still_checked() {
        let api = host(None, ruleset_rules(&["required"]), "success");
        let policy = Policy::CiBaseline(CiBaselinePolicy {
            required: vec!["required".to_owned()],
            shards: Some(2),
            cycle_budget_minutes: Some(1.0),
        });
        let findings = inspect_policy(&api, REPO, &policy).findings;
        assert!(
            findings
                .iter()
                .any(|f| f.contains("of the 2 declared shards")),
            "{findings:#?}"
        );
        assert!(
            findings.iter().any(|f| f.contains("minute budget")),
            "{findings:#?}"
        );
    }
}

// --- #1109: which policy `doctor --remote` reads -----------------------------------------

mod policy {
    use brakes::remote::{CiBaselinePolicy, policy_for};
    use serde_json::json;
    use std::fs;

    fn write(root: &std::path::Path, path: &str, text: &str) {
        let path = root.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    const ANSWERS: &str =
        r#"{"module": "ci-baseline", "version": "1.0.0", "answers": {"aggregate_check": "gate"}}"#;

    #[test]
    fn without_ci_baseline_answers_the_declared_policy_stands() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            policy_for(dir.path(), &json!({"required_checks": ["x"]})).unwrap(),
            None
        );
    }

    #[test]
    fn the_rendered_ruleset_names_the_required_checks_and_declared_shards_and_budget_count() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), ".agent-setup/modules/ci-baseline.json", ANSWERS);
        write(
            dir.path(),
            ".github/rulesets/main.json",
            &json!({"rules": [{"type": "deletion"},
                {"type": "required_status_checks", "parameters": {"required_status_checks": [{"context": "required"}]}}]})
            .to_string(),
        );
        let ci = json!({"required_checks": ["stale"], "tiers": {"main": {"paths": ["**"]}},
                        "shards": {"count": 3, "command": "x"}, "cycle_budget_minutes": 12});
        assert_eq!(
            policy_for(dir.path(), &ci).unwrap(),
            Some(CiBaselinePolicy {
                required: vec!["required".to_owned()],
                shards: Some(3),
                cycle_budget_minutes: Some(12.0),
            })
        );
    }

    /// #1126: an install that keeps every default writes no answers file; the
    /// lock alone says ci-baseline is installed, and its defaults apply.
    #[test]
    fn ci_baseline_in_the_lock_without_answers_uses_its_defaults() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".agent-setup/lock.json",
            &json!({"schema": 2, "version": "0.5.0", "personal_owner": "example-owner",
                    "modules": {"ci-baseline": {"version": "1.0.0"}, "setup-core": {"version": "1.3.0"}},
                    "files": {}})
            .to_string(),
        );
        let ci = json!({"required_checks": ["stale"], "tiers": {"main": {"paths": ["**"]}}});
        assert_eq!(
            policy_for(dir.path(), &ci).unwrap(),
            Some(CiBaselinePolicy {
                required: vec!["required".to_owned()],
                shards: None,
                cycle_budget_minutes: None,
            })
        );
        // A lock without ci-baseline keeps the declared policy.
        write(
            dir.path(),
            ".agent-setup/lock.json",
            &json!({"schema": 2, "version": "0.5.0", "personal_owner": "example-owner",
                    "modules": {"setup-core": {"version": "1.3.0"}}, "files": {}})
            .to_string(),
        );
        assert_eq!(policy_for(dir.path(), &ci).unwrap(), None);
    }

    #[test]
    fn without_a_ruleset_the_aggregate_check_answer_is_required_and_one_shard_is_none() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), ".agent-setup/modules/ci-baseline.json", ANSWERS);
        assert_eq!(
            policy_for(dir.path(), &json!({"shards": {"count": 1, "command": "x"}})).unwrap(),
            Some(CiBaselinePolicy {
                required: vec!["gate".to_owned()],
                shards: None,
                cycle_budget_minutes: None,
            })
        );
    }
}
