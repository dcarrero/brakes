//! The aggregate `required` job (SPEC-ci-baseline.md, "Aggregate job: exact logic", #771):
//! the shell fragment is run with `bash` and `jq` over every combination of `SCOPE`,
//! `TIER` and per-job results with and without membership in `SKIPPABLE`; exit codes
//! are asserted against the four rules and the printed lines are pinned exactly.
//! A missing `bash` or `jq` fails these tests; it never skips them. Rule 3 reads who
//! added `human-approved` through `gh api` (#1255); a `gh` stand-in on `PATH` serves
//! the issue events of each case and records its arguments, so nothing reaches a host.
mod common;

use brakes::modules::ci_baseline::{AGGREGATE_CHECK, REQUIRED_SH};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};
use tempfile::TempDir;

fn fragment() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../templates/ci-baseline/fragments/required.sh")
}

/// A job entry as `toJSON(needs)` renders it: `{ "result": ..., "outputs": {} }`.
fn job(result: Option<&str>) -> Value {
    match result {
        Some(result) => json!({ "result": result, "outputs": {} }),
        None => json!({ "outputs": {} }),
    }
}

/// The `needs` context of the generated workflow: `scope` with its outputs plus the
/// verification jobs given.
fn needs(scope: &str, tier: &str, skippable: &[&str], jobs: &[(&str, Option<&str>)]) -> Value {
    let mut map = serde_json::Map::new();
    map.insert(
        "scope".to_owned(),
        json!({
            "result": scope,
            "outputs": { "tier": tier, "skippable": serde_json::to_string(skippable).expect("json") }
        }),
    );
    for (id, result) in jobs {
        map.insert((*id).to_owned(), job(*result));
    }
    Value::Object(map)
}

/// Every input the fragment reads. The test process may run inside a workflow
/// that exports some of them (this repository's CI sets `EVENT`), so each run
/// starts with all of them unset and sets only the ones the case gives.
const INPUTS: [&str; 14] = [
    "SCOPE",
    "TIER",
    "SKIPPABLE",
    "NEEDS",
    "EVENT",
    "PROTECTED",
    "PR_LABELS",
    "PR_NUMBER",
    "REPOSITORY",
    "GH_TOKEN",
    "EVENT_ACTION",
    "EVENT_LABEL",
    "SENDER_LOGIN",
    "SENDER_TYPE",
];

/// The person who adds the label in the default event list.
const PERSON: &str = "octo-person";

/// A `labeled` event as `GET …/issues/{n}/events` returns it.
fn labeled(id: u64, at: &str, label: &str, login: &str, kind: &str, via_app: bool) -> Value {
    json!({
        "id": id,
        "event": "labeled",
        "created_at": at,
        "actor": { "login": login, "type": kind },
        "label": { "name": label, "color": "0e8a16" },
        "performed_via_github_app": if via_app { json!({ "slug": "agents" }) } else { Value::Null },
    })
}

/// One page of events, as `gh api --paginate` prints it.
fn page(events: &[Value]) -> String {
    serde_json::to_string(events).expect("json")
}

/// The default event list: a person added `human-approved`.
fn person_events() -> String {
    page(&[labeled(
        1,
        "2026-11-01T10:00:00Z",
        "human-approved",
        PERSON,
        "User",
        false,
    )])
}

/// What one run of the fragment printed, and the arguments `gh` received, if any.
struct Gate {
    _temp: TempDir,
    output: Output,
    gh_args: Option<String>,
}

/// Runs the fragment as the `required` job does: every input through `env:`, with
/// `PR_NUMBER=7`, `REPOSITORY=o/r` and a fake `GH_TOKEN` unless the case sets them,
/// and a `gh` that prints `events` (fails when `None`).
fn gate_env(vars: &[(&str, Option<&str>)], events: Option<&str>) -> Gate {
    let temp = tempfile::tempdir().expect("temp dir");
    let dir = temp.path();
    fs::create_dir_all(dir.join("bin")).expect("bin");
    if let Some(events) = events {
        fs::write(dir.join("events"), events).expect("events");
    }
    common::write_executable(
        &dir.join("bin/gh"),
        &format!(
            "#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >> '{0}/gh-args'\n[ -f '{0}/events' ] || exit 1\ncat '{0}/events'\n",
            dir.display()
        ),
    );
    let mut command = Command::new("bash");
    command.arg(fragment());
    for name in INPUTS {
        command.env_remove(name);
    }
    command.env(
        "PATH",
        format!(
            "{}:{}",
            dir.join("bin").display(),
            std::env::var("PATH").expect("PATH")
        ),
    );
    command.env("PR_NUMBER", "7");
    command.env("REPOSITORY", "o/r");
    command.env("GH_TOKEN", "fake-job-token");
    for (name, value) in vars {
        match value {
            Some(value) => command.env(name, value),
            None => command.env_remove(name),
        };
    }
    let output = command
        .output()
        .expect("bash is required to run the aggregate shell");
    let gh_args = fs::read_to_string(dir.join("gh-args")).ok();
    Gate {
        _temp: temp,
        output,
        gh_args,
    }
}

/// [`gate_env`] with the default event list, a person's label.
fn run_env(vars: &[(&str, Option<&str>)]) -> Output {
    gate_env(vars, Some(&person_events())).output
}

fn run(scope: &str, tier: &str, skippable: &[&str], jobs: &[(&str, Option<&str>)]) -> Output {
    let skippable_json = serde_json::to_string(skippable).expect("json");
    let needs_json = needs(scope, tier, skippable, jobs).to_string();
    run_env(&[
        ("SCOPE", Some(scope)),
        ("TIER", Some(tier)),
        ("SKIPPABLE", Some(&skippable_json)),
        ("NEEDS", Some(&needs_json)),
    ])
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn lines(output: &Output) -> Vec<String> {
    stdout(output).lines().map(str::to_owned).collect()
}

fn assert_pass(output: &Output) {
    assert!(
        output.status.success(),
        "expected exit 0, got {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        stdout(output),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_fail(output: &Output) {
    assert_eq!(
        output.status.code(),
        Some(1),
        "expected exit 1\nstdout:\n{}\nstderr:\n{}",
        stdout(output),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout(output).lines().any(|l| l.starts_with("::error::")),
        "a failure must carry an ::error:: line\n{}",
        stdout(output)
    );
}

#[test]
fn tools_are_present() {
    for tool in ["bash", "jq"] {
        let status = Command::new(tool).arg("--version").output();
        assert!(
            status.is_ok_and(|o| o.status.success()),
            "{tool} must be installed to run the aggregate shell; the suite never skips this"
        );
    }
}

#[test]
fn aggregate_check_is_required() {
    assert_eq!(AGGREGATE_CHECK, "required");
}

#[test]
fn fragment_is_embedded_verbatim() {
    let on_disk = fs::read_to_string(fragment()).expect("fragment present");
    assert_eq!(REQUIRED_SH, on_disk);
    assert!(REQUIRED_SH.contains("set -euo pipefail"));
    assert!(REQUIRED_SH.contains("jq "), "the shell decides with jq");
    for forbidden in ["grep -v", "continue-on-error", "|| true"] {
        assert!(
            !REQUIRED_SH.contains(forbidden),
            "the aggregate shell must not contain `{forbidden}`"
        );
    }
}

#[test]
fn fragment_parses_under_bash() {
    let output = Command::new("bash")
        .arg("-n")
        .arg(fragment())
        .output()
        .expect("bash");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn all_success_under_full_passes() {
    let output = run(
        "success",
        "full",
        &[],
        &[
            ("checks", Some("success")),
            ("workflow-lint", Some("success")),
        ],
    );
    assert_pass(&output);
    assert_eq!(
        lines(&output),
        [
            "checks: success",
            "workflow-lint: success",
            "required: 2 jobs passed under tier full",
        ]
    );
}

#[test]
fn docs_tier_skipped_and_listed_passes() {
    let output = run(
        "success",
        "docs",
        &["checks"],
        &[
            ("checks", Some("skipped")),
            ("workflow-lint", Some("success")),
        ],
    );
    assert_pass(&output);
    assert_eq!(
        lines(&output),
        [
            "checks: skipped on purpose (listed as skippable under tier docs)",
            "workflow-lint: success",
            "required: 2 jobs passed under tier docs",
        ]
    );
}

#[test]
fn skipped_under_full_and_unlisted_fails() {
    let output = run(
        "success",
        "full",
        &[],
        &[
            ("checks", Some("skipped")),
            ("workflow-lint", Some("success")),
        ],
    );
    assert_fail(&output);
    assert_eq!(
        lines(&output),
        [
            "::error::checks: skipped, but scope did not list it as skippable under tier full",
            "workflow-lint: success",
            "required: 1 of 2 jobs did not pass under tier full; refusing to pass",
        ]
    );
}

#[test]
fn listed_skip_passes_under_full_too() {
    // A pull request that touches no `.github/**` path lists `workflow-lint` under tier full.
    let output = run(
        "success",
        "full",
        &["workflow-lint"],
        &[
            ("checks", Some("success")),
            ("workflow-lint", Some("skipped")),
        ],
    );
    assert_pass(&output);
    assert_eq!(
        lines(&output)[1],
        "workflow-lint: skipped on purpose (listed as skippable under tier full)"
    );
}

#[test]
fn skipped_under_docs_but_unlisted_fails() {
    let output = run(
        "success",
        "docs",
        &["checks"],
        &[
            ("checks", Some("skipped")),
            ("workflow-lint", Some("skipped")),
        ],
    );
    assert_fail(&output);
    assert_eq!(
        lines(&output),
        [
            "checks: skipped on purpose (listed as skippable under tier docs)",
            "::error::workflow-lint: skipped, but scope did not list it as skippable under tier docs",
            "required: 1 of 2 jobs did not pass under tier docs; refusing to pass",
        ]
    );
}

#[test]
fn failure_and_cancelled_fail_even_when_listed() {
    for result in ["failure", "cancelled"] {
        for skippable in [&[][..], &["checks"][..]] {
            let output = run(
                "success",
                "docs",
                skippable,
                &[("checks", Some(result)), ("workflow-lint", Some("success"))],
            );
            assert_fail(&output);
            assert_eq!(lines(&output)[0], format!("::error::checks: {result}"));
        }
    }
}

#[test]
fn unknown_result_fails_naming_it() {
    let output = run(
        "success",
        "full",
        &["checks"],
        &[
            ("checks", Some("neutral")),
            ("workflow-lint", Some("success")),
        ],
    );
    assert_fail(&output);
    assert_eq!(lines(&output)[0], "::error::checks: neutral");
}

#[test]
fn job_without_result_fails() {
    let output = run(
        "success",
        "full",
        &[],
        &[("checks", None), ("workflow-lint", Some("success"))],
    );
    assert_fail(&output);
    assert_eq!(lines(&output)[0], "::error::checks: no result in needs");
}

#[test]
fn every_failing_job_is_named() {
    let output = run(
        "success",
        "full",
        &[],
        &[
            ("checks", Some("failure")),
            ("shard 1/2", Some("cancelled")),
            ("workflow-lint", Some("skipped")),
        ],
    );
    assert_fail(&output);
    assert_eq!(
        lines(&output),
        [
            "::error::checks: failure",
            "::error::shard 1/2: cancelled",
            "::error::workflow-lint: skipped, but scope did not list it as skippable under tier full",
            "required: 3 of 3 jobs did not pass under tier full; refusing to pass",
        ]
    );
}

#[test]
fn scope_not_success_fails_before_anything_else() {
    for scope in ["failure", "cancelled", "skipped"] {
        let output = run(
            scope,
            "full",
            &[],
            &[
                ("checks", Some("success")),
                ("workflow-lint", Some("success")),
            ],
        );
        assert_fail(&output);
        assert_eq!(
            lines(&output),
            [format!(
                "::error::scope did not run; refusing to pass (scope result: {scope})"
            )]
        );
    }
}

#[test]
fn missing_scope_input_fails() {
    let needs_json = needs("success", "full", &[], &[("checks", Some("success"))]).to_string();
    for value in [None, Some("")] {
        let output = run_env(&[
            ("SCOPE", value),
            ("TIER", Some("full")),
            ("SKIPPABLE", Some("[]")),
            ("NEEDS", Some(&needs_json)),
        ]);
        assert_fail(&output);
        assert_eq!(
            lines(&output),
            ["::error::scope did not run; refusing to pass (scope result: missing)"]
        );
    }
}

#[test]
fn unknown_tier_fails() {
    for tier in ["", "unknown", "FULL", "docs "] {
        let output = run(
            "success",
            tier,
            &[],
            &[
                ("checks", Some("success")),
                ("workflow-lint", Some("success")),
            ],
        );
        assert_fail(&output);
        assert_eq!(
            lines(&output),
            [format!(
                "::error::scope did not decide a tier (tier: '{tier}')"
            )]
        );
    }
}

#[test]
fn malformed_skippable_fails() {
    let needs_json = needs("success", "docs", &[], &[("checks", Some("success"))]).to_string();
    for value in [None, Some(""), Some("checks"), Some("{}"), Some("[1]")] {
        let output = run_env(&[
            ("SCOPE", Some("success")),
            ("TIER", Some("docs")),
            ("SKIPPABLE", value),
            ("NEEDS", Some(&needs_json)),
        ]);
        assert_fail(&output);
        assert_eq!(
            lines(&output),
            [format!(
                "::error::scope did not list skippable jobs as a JSON array of job ids (skippable: '{}')",
                value.unwrap_or("")
            )]
        );
    }
}

#[test]
fn malformed_needs_fails() {
    for value in [None, Some(""), Some("[]"), Some("not json")] {
        let output = run_env(&[
            ("SCOPE", Some("success")),
            ("TIER", Some("full")),
            ("SKIPPABLE", Some("[]")),
            ("NEEDS", value),
        ]);
        assert_fail(&output);
        assert_eq!(
            lines(&output),
            ["::error::needs is not a JSON object; refusing to pass"]
        );
    }
}

#[test]
fn needs_without_a_verification_job_fails() {
    let output = run("success", "full", &[], &[]);
    assert_fail(&output);
    assert_eq!(
        lines(&output),
        ["::error::needs lists no job besides scope; refusing to pass"]
    );
}

/// The reference decision: the four rules of the spec, written once more in Rust so
/// the matrix below cannot agree with the shell by accident.
fn expected(scope: &str, tier: &str, jobs: &[(&str, &str, bool)]) -> bool {
    scope == "success"
        && (tier == "full" || tier == "docs")
        && !jobs.is_empty()
        && jobs
            .iter()
            .all(|(_, result, listed)| *result == "success" || (*result == "skipped" && *listed))
}

const SCOPES: [&str; 4] = ["success", "failure", "cancelled", "skipped"];
const TIERS: [&str; 3] = ["full", "docs", ""];
const RESULTS: [&str; 5] = ["success", "failure", "cancelled", "skipped", "neutral"];

/// Every combination of `SCOPE`, `TIER` and, for two verification jobs, each result
/// with and without membership in `SKIPPABLE`: 4 x 3 x (5 x 2)^2 = 1200 runs.
#[test]
fn full_matrix_agrees_with_the_rules() {
    let mut cases = Vec::new();
    for scope in SCOPES {
        for tier in TIERS {
            for a in RESULTS {
                for a_listed in [false, true] {
                    for b in RESULTS {
                        for b_listed in [false, true] {
                            cases.push((scope, tier, a, a_listed, b, b_listed));
                        }
                    }
                }
            }
        }
    }
    assert_eq!(cases.len(), 1200);
    let workers = 8;
    let chunk = cases.len().div_ceil(workers);
    let mismatches: Vec<String> = std::thread::scope(|s| {
        let handles: Vec<_> = cases
            .chunks(chunk)
            .map(|slice| {
                s.spawn(move || {
                    let mut bad = Vec::new();
                    for (scope, tier, a, a_listed, b, b_listed) in slice {
                        let mut skippable = Vec::new();
                        if *a_listed {
                            skippable.push("checks");
                        }
                        if *b_listed {
                            skippable.push("workflow-lint");
                        }
                        let output = run(
                            scope,
                            tier,
                            &skippable,
                            &[("checks", Some(*a)), ("workflow-lint", Some(*b))],
                        );
                        let want = expected(
                            scope,
                            tier,
                            &[("checks", a, *a_listed), ("workflow-lint", b, *b_listed)],
                        );
                        let got = output.status.code();
                        let errors = stdout(&output)
                            .lines()
                            .filter(|l| l.starts_with("::error::"))
                            .count();
                        let consistent = if want {
                            got == Some(0) && errors == 0
                        } else {
                            got == Some(1) && errors > 0
                        };
                        if !consistent {
                            bad.push(format!(
                                "SCOPE={scope} TIER={tier:?} checks={a}/{a_listed} workflow-lint={b}/{b_listed}: want pass={want}, got exit {got:?} with {errors} error lines\n{}",
                                stdout(&output)
                            ));
                        }
                    }
                    bad
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().expect("matrix worker"))
            .collect()
    });
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

// ---- T14 (#943): rule 3, the protected-paths gate ----

const WORKFLOW: &str = ".github/workflows/ci.yml";
const HELDOUT: &str = "tests/heldout/test_gate.py";

/// Runs the fragment for a pull request (or `event`) whose verification jobs all
/// passed, with `PROTECTED` and `PR_LABELS` as given (`None` leaves one unset).
fn run_gate(event: &str, protected: Option<&str>, labels: Option<&str>) -> Output {
    let needs_json = needs(
        "success",
        "full",
        &[],
        &[
            ("checks", Some("success")),
            ("workflow-lint", Some("success")),
        ],
    )
    .to_string();
    run_env(&[
        ("SCOPE", Some("success")),
        ("TIER", Some("full")),
        ("SKIPPABLE", Some("[]")),
        ("NEEDS", Some(&needs_json)),
        ("EVENT", Some(event)),
        ("PROTECTED", protected),
        ("PR_LABELS", labels),
    ])
}

fn json_list(items: &[&str]) -> String {
    serde_json::to_string(items).expect("json")
}

#[test]
fn human_approved_is_the_label_the_gate_reads() {
    use brakes::modules::ci_baseline::aggregate::{HUMAN_APPROVED, UNKNOWN_PROTECTED};
    assert_eq!(HUMAN_APPROVED, "human-approved");
    assert_eq!(UNKNOWN_PROTECTED, "<unknown>");
    assert!(REQUIRED_SH.contains(HUMAN_APPROVED));
    assert!(REQUIRED_SH.contains(UNKNOWN_PROTECTED));
}

#[test]
fn a_protected_path_without_the_label_fails_naming_every_path() {
    for labels in [json_list(&[]), json_list(&["bug", "human-approved-later"])] {
        let output = run_gate(
            "pull_request",
            Some(&json_list(&[WORKFLOW, HELDOUT])),
            Some(&labels),
        );
        assert_fail(&output);
        assert_eq!(
            lines(&output),
            [format!(
                "::error::Protected path changed without human approval: {WORKFLOW}, {HELDOUT}"
            )]
        );
    }
}

#[test]
fn a_protected_path_with_the_label_passes_and_says_so() {
    let output = run_gate(
        "pull_request",
        Some(&json_list(&[WORKFLOW])),
        Some(&json_list(&["documentation", "human-approved"])),
    );
    assert_pass(&output);
    assert_eq!(
        lines(&output),
        [
            format!("protected: {WORKFLOW} (label human-approved added by {PERSON})"),
            "checks: success".to_owned(),
            "workflow-lint: success".to_owned(),
            "required: 2 jobs passed under tier full".to_owned(),
        ]
    );
}

#[test]
fn unknown_protected_paths_fail_closed_without_the_label() {
    for labels in [Some(json_list(&[])), Some(json_list(&["bug"])), None] {
        let output = run_gate(
            "pull_request",
            Some(&json_list(&["<unknown>"])),
            labels.as_deref(),
        );
        assert_fail(&output);
        assert_eq!(
            lines(&output),
            ["::error::Protected paths could not be computed; refusing to pass"]
        );
    }
}

#[test]
fn a_protected_list_that_cannot_be_read_counts_as_unknown() {
    // The scope job always writes a JSON array; anything else means it could not.
    for protected in [None, Some(""), Some("not json"), Some("{}"), Some("[1]")] {
        let output = run_gate("pull_request", protected, Some(&json_list(&[])));
        assert_fail(&output);
        assert_eq!(
            lines(&output),
            ["::error::Protected paths could not be computed; refusing to pass"],
            "PROTECTED={protected:?}"
        );
    }
}

#[test]
fn labels_that_cannot_be_read_never_count_as_approval() {
    for labels in [
        None,
        Some(""),
        Some("human-approved"),
        Some("{\"human-approved\": true}"),
        Some("null"),
    ] {
        let output = run_gate("pull_request", Some(&json_list(&[WORKFLOW])), labels);
        assert_fail(&output);
        assert_eq!(
            lines(&output),
            [format!(
                "::error::Protected path changed without human approval: {WORKFLOW}"
            )],
            "PR_LABELS={labels:?}"
        );
    }
}

#[test]
fn no_protected_path_is_unaffected_by_the_labels() {
    for labels in [None, Some(json_list(&[])), Some(json_list(&["bug"]))] {
        let output = run_gate("pull_request", Some("[]"), labels.as_deref());
        assert_pass(&output);
        assert_eq!(
            lines(&output),
            [
                "protected: none",
                "checks: success",
                "workflow-lint: success",
                "required: 2 jobs passed under tier full",
            ]
        );
    }
}

#[test]
fn the_rule_applies_to_pull_requests_only() {
    // The scope job lists changed files on pull requests only; a push to the default
    // branch is the merge of a pull request that already passed this rule.
    for event in ["push", "workflow_dispatch", "merge_group", ""] {
        let output = run_gate(event, Some(&json_list(&[WORKFLOW])), None);
        assert_pass(&output);
        assert_eq!(
            lines(&output),
            [
                "checks: success",
                "workflow-lint: success",
                "required: 2 jobs passed under tier full",
            ],
            "EVENT={event:?}"
        );
    }
}

#[test]
fn rules_one_and_two_still_come_first() {
    let needs_json = needs("failure", "full", &[], &[("checks", Some("success"))]).to_string();
    let protected = json_list(&[WORKFLOW]);
    let output = run_env(&[
        ("SCOPE", Some("failure")),
        ("TIER", Some("full")),
        ("SKIPPABLE", Some("[]")),
        ("NEEDS", Some(&needs_json)),
        ("EVENT", Some("pull_request")),
        ("PROTECTED", Some(&protected)),
        ("PR_LABELS", Some("[]")),
    ]);
    assert_fail(&output);
    assert_eq!(
        lines(&output),
        ["::error::scope did not run; refusing to pass (scope result: failure)"]
    );
}

#[test]
fn a_failed_job_still_fails_with_the_label() {
    let needs_json = needs("success", "full", &[], &[("checks", Some("failure"))]).to_string();
    let protected = json_list(&[WORKFLOW]);
    let labels = json_list(&["human-approved"]);
    let output = run_env(&[
        ("SCOPE", Some("success")),
        ("TIER", Some("full")),
        ("SKIPPABLE", Some("[]")),
        ("NEEDS", Some(&needs_json)),
        ("EVENT", Some("pull_request")),
        ("PROTECTED", Some(&protected)),
        ("PR_LABELS", Some(&labels)),
    ]);
    assert_fail(&output);
    assert_eq!(
        lines(&output),
        [
            format!("protected: {WORKFLOW} (label human-approved added by {PERSON})"),
            "::error::checks: failure".to_owned(),
            "required: 1 of 1 jobs did not pass under tier full; refusing to pass".to_owned(),
        ]
    );
}

/// qa T8 (#1005): a changed screenshot baseline without the label is red, naming it.
#[test]
fn a_changed_screenshot_baseline_without_the_label_fails_naming_it() {
    let png = "qa/web/smoke.spec.ts-snapshots/home-chromium-linux.png";
    let output = run_gate(
        "pull_request",
        Some(&json_list(&[png])),
        Some(&json_list(&["bug"])),
    );
    assert_fail(&output);
    assert_eq!(
        lines(&output),
        [format!(
            "::error::Protected path changed without human approval: {png}"
        )]
    );
}

/// Every event x protected list x labels x verification result: 4 x 6 x 5 x 2 = 240
/// runs, each against rule 3 written once more in Rust.
#[test]
fn protected_paths_matrix_agrees_with_rule_three() {
    let events = ["pull_request", "push", "merge_group", "workflow_dispatch"];
    // (PROTECTED, whether it names a path, whether it is unknown)
    let protected = [
        ("[]", false, false),
        (r#"[".github/workflows/ci.yml"]"#, true, false),
        (
            r#"[".agent-setup/lock.json","tests/heldout/a.py"]"#,
            true,
            false,
        ),
        // qa T8 (#1005): a changed screenshot baseline the scope job listed.
        (
            r#"["qa/web/smoke.spec.ts-snapshots/home-chromium-linux.png"]"#,
            true,
            false,
        ),
        (r#"["<unknown>"]"#, true, true),
        ("garbage", true, true),
    ];
    // (PR_LABELS, whether it carries the label)
    let labels = [
        ("[]", false),
        (r#"["human-approved"]"#, true),
        (r#"["bug","human-approved"]"#, true),
        (r#"["Human-Approved"]"#, false),
        ("garbage", false),
    ];
    let mut bad = Vec::new();
    let mut runs = 0;
    for event in events {
        for (list, named, unknown) in protected {
            for (label_json, approved) in labels {
                for result in ["success", "failure"] {
                    runs += 1;
                    let needs_json =
                        needs("success", "full", &[], &[("checks", Some(result))]).to_string();
                    let output = run_env(&[
                        ("SCOPE", Some("success")),
                        ("TIER", Some("full")),
                        ("SKIPPABLE", Some("[]")),
                        ("NEEDS", Some(&needs_json)),
                        ("EVENT", Some(event)),
                        ("PROTECTED", Some(list)),
                        ("PR_LABELS", Some(label_json)),
                    ]);
                    let gated = event == "pull_request" && named && !approved;
                    let want = !gated && result == "success";
                    let text = stdout(&output);
                    let consistent = if want {
                        output.status.code() == Some(0)
                    } else {
                        output.status.code() == Some(1) && text.contains("::error::")
                    };
                    let message_ok = !gated
                        || text.lines().next()
                            == Some(if unknown {
                                "::error::Protected paths could not be computed; refusing to pass"
                            } else {
                                "::error::Protected path changed without human approval: "
                            })
                        || (!unknown
                            && text.starts_with(
                                "::error::Protected path changed without human approval: ",
                            ));
                    if !consistent || !message_ok {
                        bad.push(format!(
                            "EVENT={event} PROTECTED={list} PR_LABELS={label_json} checks={result}: want pass={want}\n{text}"
                        ));
                    }
                }
            }
        }
    }
    assert_eq!(runs, 240);
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

// ---- #1255: `human-approved` counts only when a person added it ----

/// A pull request that changed a workflow, carries the label, and whose jobs passed;
/// `extra` adds or overrides inputs, `events` is what `gh api` prints.
fn approval(extra: &[(&str, Option<&str>)], events: Option<&str>) -> Gate {
    let needs_json = needs("success", "full", &[], &[("checks", Some("success"))]).to_string();
    let protected = json_list(&[WORKFLOW]);
    let labels = json_list(&["bug", "human-approved"]);
    let mut vars: Vec<(&str, Option<&str>)> = vec![
        ("SCOPE", Some("success")),
        ("TIER", Some("full")),
        ("SKIPPABLE", Some("[]")),
        ("NEEDS", Some(&needs_json)),
        ("EVENT", Some("pull_request")),
        ("PROTECTED", Some(&protected)),
        ("PR_LABELS", Some(&labels)),
    ];
    vars.extend_from_slice(extra);
    gate_env(&vars, events)
}

fn not_a_person(login: &str, kind: &str) -> String {
    format!(
        "::error::Label human-approved was last added by {login} ({kind}), not by a person; a person must remove it and add it again"
    )
}

#[test]
fn a_label_added_by_a_person_passes_naming_them() {
    let gate = approval(&[], Some(&person_events()));
    assert_pass(&gate.output);
    assert_eq!(
        lines(&gate.output),
        [
            format!("protected: {WORKFLOW} (label human-approved added by {PERSON})"),
            "checks: success".to_owned(),
            "required: 1 jobs passed under tier full".to_owned(),
        ]
    );
}

#[test]
fn the_events_are_read_for_this_pull_request_with_every_page() {
    let gate = approval(&[], Some(&person_events()));
    assert_eq!(
        gate.gh_args.as_deref(),
        Some("api --paginate repos/o/r/issues/7/events?per_page=100\n")
    );
    assert!(
        !gate.gh_args.unwrap_or_default().contains("fake-job-token"),
        "the token reaches gh through GH_TOKEN, never an argument"
    );
}

#[test]
fn a_label_added_by_the_app_fails() {
    let events = page(&[labeled(
        1,
        "2026-11-01T10:00:00Z",
        "human-approved",
        "agents[bot]",
        "Bot",
        false,
    )]);
    let gate = approval(&[], Some(&events));
    assert_fail(&gate.output);
    assert_eq!(lines(&gate.output), [not_a_person("agents[bot]", "Bot")]);
}

#[test]
fn a_bot_login_fails_whatever_its_type() {
    let events = page(&[labeled(
        1,
        "2026-11-01T10:00:00Z",
        "human-approved",
        "renovate[bot]",
        "User",
        false,
    )]);
    let gate = approval(&[], Some(&events));
    assert_fail(&gate.output);
    assert_eq!(lines(&gate.output), [not_a_person("renovate[bot]", "User")]);
}

#[test]
fn a_user_acting_through_an_app_fails() {
    let events = page(&[labeled(
        1,
        "2026-11-01T10:00:00Z",
        "human-approved",
        PERSON,
        "User",
        true,
    )]);
    let gate = approval(&[], Some(&events));
    assert_fail(&gate.output);
    assert_eq!(
        lines(&gate.output),
        [format!(
            "::error::Label human-approved was last added by {PERSON} (User), via an App, not by a person; a person must remove it and add it again"
        )]
    );
}

#[test]
fn the_most_recent_labeled_event_decides_across_pages() {
    // A person approved, the label was removed, and the App added it again on page 2.
    let removed = json!({
        "id": 2, "event": "unlabeled", "created_at": "2026-11-01T11:00:00Z",
        "actor": { "login": "agents[bot]", "type": "Bot" },
        "label": { "name": "human-approved", "color": "0e8a16" },
        "performed_via_github_app": Value::Null,
    });
    let first = page(&[
        labeled(
            1,
            "2026-11-01T10:00:00Z",
            "human-approved",
            PERSON,
            "User",
            false,
        ),
        removed,
    ]);
    let second = page(&[labeled(
        3,
        "2026-11-01T12:00:00Z",
        "human-approved",
        "agents[bot]",
        "Bot",
        false,
    )]);
    let gate = approval(&[], Some(&format!("{first}\n{second}\n")));
    assert_fail(&gate.output);
    assert_eq!(lines(&gate.output), [not_a_person("agents[bot]", "Bot")]);

    // The reverse order: the App's label first, a person's last.
    let events = page(&[
        labeled(
            1,
            "2026-11-01T10:00:00Z",
            "human-approved",
            "agents[bot]",
            "Bot",
            false,
        ),
        labeled(
            3,
            "2026-11-01T12:00:00Z",
            "human-approved",
            PERSON,
            "User",
            false,
        ),
    ]);
    assert_pass(&approval(&[], Some(&events)).output);
}

#[test]
fn the_latest_is_chosen_by_time_not_by_position() {
    let events = page(&[
        labeled(
            5,
            "2026-11-01T12:00:00Z",
            "human-approved",
            "agents[bot]",
            "Bot",
            false,
        ),
        labeled(
            4,
            "2026-11-01T10:00:00Z",
            "human-approved",
            PERSON,
            "User",
            false,
        ),
    ]);
    let gate = approval(&[], Some(&events));
    assert_fail(&gate.output);
    assert_eq!(lines(&gate.output), [not_a_person("agents[bot]", "Bot")]);
}

#[test]
fn other_labels_and_other_events_do_not_count() {
    let events = page(&[
        labeled(
            1,
            "2026-11-01T10:00:00Z",
            "Human-Approved",
            PERSON,
            "User",
            false,
        ),
        labeled(
            2,
            "2026-11-01T11:00:00Z",
            "bug",
            "agents[bot]",
            "Bot",
            false,
        ),
        json!({
            "id": 3, "event": "commented", "created_at": "2026-11-01T12:00:00Z",
            "actor": { "login": "agents[bot]", "type": "Bot" },
            "performed_via_github_app": Value::Null,
        }),
    ]);
    let gate = approval(&[], Some(&events));
    assert_pass(&gate.output);
    assert_eq!(
        lines(&gate.output)[0],
        format!("protected: {WORKFLOW} (label human-approved added by {PERSON})")
    );
}

#[test]
fn events_that_cannot_be_read_fail_closed() {
    for events in [None, Some(""), Some("not json"), Some("{}"), Some("[1]")] {
        let gate = approval(&[], events);
        assert_fail(&gate.output);
        assert_eq!(
            lines(&gate.output),
            ["::error::Could not read who added the label human-approved; refusing to pass"],
            "events={events:?}"
        );
    }
}

#[test]
fn no_labeled_event_fails_closed() {
    for events in ["[]", "[]\n[]\n"] {
        let gate = approval(&[], Some(events));
        assert_fail(&gate.output);
        assert_eq!(
            lines(&gate.output),
            ["::error::No labeled event for human-approved was found; refusing to pass"]
        );
    }
}

#[test]
fn a_missing_pull_request_number_or_repository_fails_closed() {
    for missing in ["PR_NUMBER", "REPOSITORY"] {
        let gate = approval(&[(missing, None)], Some(&person_events()));
        assert_fail(&gate.output);
        assert_eq!(
            lines(&gate.output),
            ["::error::Could not read who added the label human-approved; refusing to pass"],
            "{missing} unset"
        );
        assert_eq!(gate.gh_args, None, "{missing} unset: gh is not called");
    }
}

#[test]
fn a_run_triggered_by_the_app_adding_the_label_fails_even_if_the_events_lag() {
    let gate = approval(
        &[
            ("EVENT_ACTION", Some("labeled")),
            ("EVENT_LABEL", Some("human-approved")),
            ("SENDER_LOGIN", Some("agents[bot]")),
            ("SENDER_TYPE", Some("Bot")),
        ],
        Some(&person_events()),
    );
    assert_fail(&gate.output);
    assert_eq!(lines(&gate.output), [not_a_person("agents[bot]", "Bot")]);
}

#[test]
fn a_run_triggered_by_the_label_without_a_readable_sender_fails() {
    let gate = approval(
        &[
            ("EVENT_ACTION", Some("labeled")),
            ("EVENT_LABEL", Some("human-approved")),
        ],
        Some(&person_events()),
    );
    assert_fail(&gate.output);
    assert_eq!(lines(&gate.output), [not_a_person("-", "-")]);
}

#[test]
fn the_sender_counts_only_for_the_label_itself() {
    // The App added another label: the run's sender is the App, the approval a person's.
    let other = approval(
        &[
            ("EVENT_ACTION", Some("labeled")),
            ("EVENT_LABEL", Some("bug")),
            ("SENDER_LOGIN", Some("agents[bot]")),
            ("SENDER_TYPE", Some("Bot")),
        ],
        Some(&person_events()),
    );
    assert_pass(&other.output);
    // A push by the App re-runs the gate; the person's label still counts.
    let push = approval(
        &[
            ("EVENT_ACTION", Some("synchronize")),
            ("SENDER_LOGIN", Some("agents[bot]")),
            ("SENDER_TYPE", Some("Bot")),
        ],
        Some(&person_events()),
    );
    assert_pass(&push.output);
    // The person adding it: both checks pass.
    let added = approval(
        &[
            ("EVENT_ACTION", Some("labeled")),
            ("EVENT_LABEL", Some("Human-Approved")),
            ("SENDER_LOGIN", Some(PERSON)),
            ("SENDER_TYPE", Some("User")),
        ],
        Some(&person_events()),
    );
    assert_pass(&added.output);
}

#[test]
fn a_hostile_login_is_printed_inert() {
    let events = page(&[labeled(
        1,
        "2026-11-01T10:00:00Z",
        "human-approved",
        "evil\n::notice::x%0A",
        "Bot",
        false,
    )]);
    let gate = approval(&[], Some(&events));
    assert_fail(&gate.output);
    assert_eq!(lines(&gate.output), [not_a_person("evilnoticex0A", "Bot")]);
}

#[test]
fn the_events_are_not_read_without_the_label() {
    for protected in [json_list(&[WORKFLOW]), "[]".to_owned()] {
        let gate = run_gate_with_gh(Some(&protected), &json_list(&["bug"]), &person_events());
        assert_eq!(gate.gh_args, None, "PROTECTED={protected}");
    }
}

/// Other jobs accept a change because the label is present (qa-contracts' breaking
/// change, #1016), so the label is checked whenever it is on the pull request, a
/// protected path or not.
#[test]
fn the_label_is_checked_even_when_no_protected_path_changed() {
    let by_person = run_gate_with_gh(
        Some("[]"),
        &json_list(&["human-approved"]),
        &person_events(),
    );
    assert_pass(&by_person.output);
    assert_eq!(
        lines(&by_person.output)[0],
        format!("protected: none (label human-approved added by {PERSON})")
    );
    let events = page(&[labeled(
        1,
        "2026-11-01T10:00:00Z",
        "human-approved",
        "agents[bot]",
        "Bot",
        false,
    )]);
    let by_app = run_gate_with_gh(Some("[]"), &json_list(&["human-approved"]), &events);
    assert_fail(&by_app.output);
    assert_eq!(lines(&by_app.output), [not_a_person("agents[bot]", "Bot")]);
}

fn run_gate_with_gh(protected: Option<&str>, labels: &str, events: &str) -> Gate {
    let needs_json = needs("success", "full", &[], &[("checks", Some("success"))]).to_string();
    gate_env(
        &[
            ("SCOPE", Some("success")),
            ("TIER", Some("full")),
            ("SKIPPABLE", Some("[]")),
            ("NEEDS", Some(&needs_json)),
            ("EVENT", Some("pull_request")),
            ("PROTECTED", protected),
            ("PR_LABELS", Some(labels)),
        ],
        Some(events),
    )
}

/// T12 (#784): a change under one app skips the other app's checks on purpose
/// and `required` passes; the same skip without the scope's sanction fails.
#[test]
fn an_unchanged_app_skipped_on_purpose_passes_and_unsanctioned_fails() {
    let jobs = [
        ("backend-checks", Some("success")),
        ("web-checks", Some("skipped")),
        ("workflow-lint", Some("skipped")),
    ];
    let output = run(
        "success",
        "full",
        &["workflow-lint", "macos", "web-checks"],
        &jobs,
    );
    assert_pass(&output);
    assert!(
        lines(&output).contains(
            &"web-checks: skipped on purpose (listed as skippable under tier full)".to_owned()
        ),
        "{:?}",
        lines(&output)
    );
    // A path outside every app runs both: a skip then is not sanctioned.
    assert_fail(&run("success", "full", &["workflow-lint", "macos"], &jobs));
}

/// The push-only macOS job skipped on a pull request is sanctioned by scope.
#[test]
fn macos_skipped_on_a_pull_request_passes_when_listed() {
    let output = run(
        "success",
        "full",
        &["workflow-lint", "macos"],
        &[
            ("checks", Some("success")),
            ("macos", Some("skipped")),
            ("workflow-lint", Some("skipped")),
        ],
    );
    assert_pass(&output);
}

#[test]
fn a_contributed_app_job_skipped_with_its_unchanged_app_passes_only_when_listed() {
    // #1097: scope lists a contributed job whose app is unchanged, as it lists
    // `<app>-checks`; the aggregate's rule is unchanged.
    let listed = run(
        "success",
        "full",
        &["web-checks", "web-qa-api"],
        &[
            ("backend-checks", Some("success")),
            ("web-checks", Some("skipped")),
            ("backend-qa-api", Some("success")),
            ("web-qa-api", Some("skipped")),
        ],
    );
    assert_pass(&listed);
    assert!(
        lines(&listed).contains(
            &"web-qa-api: skipped on purpose (listed as skippable under tier full)".to_owned()
        ),
        "{:?}",
        lines(&listed)
    );
    let unlisted = run(
        "success",
        "full",
        &["web-checks"],
        &[
            ("web-checks", Some("skipped")),
            ("web-qa-api", Some("skipped")),
        ],
    );
    assert_fail(&unlisted);
    assert!(
        lines(&unlisted).contains(
            &"::error::web-qa-api: skipped, but scope did not list it as skippable under tier full"
                .to_owned()
        )
    );
}
