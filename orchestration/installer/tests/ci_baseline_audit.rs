//! ci-baseline T7 (#777; SPEC-ci-baseline.md, "Auditor rules this module
//! enables" and "How `doctor` reports the static rules"): the YAML walker of
//! `auditor/workflows.rs` and the static `ci.*` rules over every file under
//! `.github/workflows/`, reported as `doctor` warnings, never as readiness.
use brakes::auditor::workflows;
use brakes::modules::ci_baseline::audit;
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, path::Path};
use tempfile::TempDir;

mod configured;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/ci-baseline");

fn fixture(name: &str) -> String {
    fs::read_to_string(Path::new(FIXTURES).join(name)).expect(name)
}

const DEPENDABOT_ACTIONS: &str = "version: 2\nupdates:\n  - package-ecosystem: github-actions\n    directory: /\n    schedule:\n      interval: weekly\n";

/// A checkout with `files` (repository path → text) and nothing else.
fn repo(files: &[(&str, &str)]) -> TempDir {
    let dir = TempDir::new().unwrap();
    for (path, text) in files {
        let path = dir.path().join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
    dir
}

/// The `ci.*` findings for `workflows` (file name under `.github/workflows/` →
/// text) with Dependabot updating actions, a profile and optional answers.
fn findings(workflows: &[(&str, &str)], profile: Value, answers: Option<Value>) -> Vec<String> {
    let mut files: Vec<(String, String)> = workflows
        .iter()
        .map(|(n, t)| (format!(".github/workflows/{n}"), (*t).to_owned()))
        .collect();
    files.push((
        ".github/dependabot.yml".to_owned(),
        DEPENDABOT_ACTIONS.to_owned(),
    ));
    let refs: Vec<(&str, &str)> = files
        .iter()
        .map(|(p, t)| (p.as_str(), t.as_str()))
        .collect();
    let dir = repo(&refs);
    let answers: Option<BTreeMap<String, Value>> =
        answers.map(|a| serde_json::from_value(a).unwrap());
    audit::findings(dir.path(), &profile, answers.as_ref())
}

fn rule_lines<'a>(all: &'a [String], rule: &str) -> Vec<&'a str> {
    let prefix = format!("WARNING: {rule}: ");
    all.iter()
        .filter(|l| l.starts_with(&prefix))
        .map(String::as_str)
        .collect()
}

// --- the walker -------------------------------------------------------------

#[test]
fn the_walker_reads_jobs_needs_conditions_runners_and_uses() {
    let wf = workflows::parse(&fixture("sharded-rust.yml")).unwrap();
    assert!(wf.triggers.contains(&"pull_request".to_owned()));
    assert!(wf.triggers.contains(&"push".to_owned()));
    let ids: Vec<&str> = wf.jobs.iter().map(|j| j.id.as_str()).collect();
    assert_eq!(
        ids,
        ["scope", "lint", "shard", "linux", "macos", "linux-x86_64"]
    );
    let linux = wf.job("linux").unwrap();
    assert_eq!(linux.name.as_deref(), Some("Rust (linux)"));
    assert_eq!(linux.condition.as_deref(), Some("always()"));
    assert_eq!(linux.needs, ["scope", "lint", "shard"]);
    assert_eq!(linux.timeout_minutes.as_deref(), Some("5"));
    assert_eq!(linux.runs_on, ["example-linux-2"]);
    let x86 = wf.job("linux-x86_64").unwrap();
    assert_eq!(
        x86.condition.as_deref(),
        Some("github.event_name == 'push'")
    );
    assert!(!x86.continue_on_error);
    let checkout = &x86.steps[0];
    assert_eq!(
        checkout.uses.as_deref(),
        Some("actions/checkout@11d5960a326750d5838078e36cf38b85af677262")
    );
    assert_eq!(
        checkout.with.get("persist-credentials").map(String::as_str),
        Some("false")
    );
    let permissions = wf.permissions.as_ref().unwrap();
    assert_eq!(
        permissions,
        &workflows::Permissions::Scopes(BTreeMap::from([(
            "contents".to_owned(),
            "read".to_owned()
        )]))
    );
}

#[test]
fn the_walker_reads_reusable_callers_lists_and_scalar_permissions() {
    let text = "on: [push, pull_request]\npermissions: read-all\njobs:\n  call:\n    uses: org/repo/.github/workflows/x.yml@v1\n    continue-on-error: true\n    needs: build\n  build:\n    runs-on: [self-hosted, linux]\n    steps:\n      - run: make\n";
    let wf = workflows::parse(text).unwrap();
    assert_eq!(wf.triggers, ["push", "pull_request"]);
    assert_eq!(
        wf.permissions,
        Some(workflows::Permissions::Scalar("read-all".to_owned()))
    );
    let call = wf.job("call").unwrap();
    assert_eq!(
        call.uses.as_deref(),
        Some("org/repo/.github/workflows/x.yml@v1")
    );
    assert!(call.continue_on_error);
    assert_eq!(call.needs, ["build"]);
    assert_eq!(wf.job("build").unwrap().runs_on, ["self-hosted", "linux"]);
}

#[test]
fn unparseable_yaml_is_an_error_never_a_panic() {
    for text in [
        fixture("broken.yml"),
        String::new(),
        "- a list\n".to_owned(),
        "jobs: [1, 2]\n".to_owned(),
    ] {
        assert!(workflows::parse(&text).is_err(), "{text:?}");
    }
}

#[test]
fn dependabot_ecosystems_are_read() {
    assert_eq!(
        workflows::dependabot_ecosystems(DEPENDABOT_ACTIONS).unwrap(),
        ["github-actions"]
    );
    assert!(workflows::dependabot_ecosystems("updates: {\n").is_err());
}

// --- the fixtures -------------------------------------------------------------

fn rust_profile() -> Value {
    json!({"commands": {"verify": "make verify"}, "ci": {"required_checks": ["Rust (linux)", "Rust (macos)", "promote"]}})
}

#[test]
fn a_sharded_rust_workflow_passes_the_static_rules_but_workflow_lint() {
    let all = findings(
        &[("rust.yml", &fixture("sharded-rust.yml"))],
        rust_profile(),
        Some(json!({"workflow": "existing", "aggregate_check": "Rust (linux)"})),
    );
    assert_eq!(
        all,
        [
            "WARNING: ci.workflow-lint: Workflow lint absent",
            "WARNING: ci.heldout-present: No held-out test job: the agent can edit every test it is measured against",
            "WARNING: ci.protected-paths-gate: Protected paths are not gated: a workflow or held-out change can merge without a human",
            "WARNING: ci.project-ci-stale: .agent-setup/project.json ci.required_checks disagree with the ci-baseline answers; the answers govern (Decision 4)",
        ]
    );
}

#[test]
fn a_jq_verify_workflow_has_no_aggregate_and_persists_credentials() {
    let all = findings(
        &[("verify.yml", &fixture("jq-verify.yml"))],
        json!({"commands": {"verify": "make verify"}}),
        None,
    );
    assert_eq!(
        all,
        [
            "WARNING: ci.aggregate-present: No aggregate job: required checks can hang or skip",
            "WARNING: ci.permissions-least: Checkout in job verify of .github/workflows/verify.yml persists credentials",
            "WARNING: ci.workflow-lint: Workflow lint absent",
            "WARNING: ci.heldout-present: No held-out test job: the agent can edit every test it is measured against",
            "WARNING: ci.protected-paths-gate: Protected paths are not gated: a workflow or held-out change can merge without a human",
        ]
    );
}

#[test]
fn a_monorepo_ci_has_its_aggregate_and_the_other_gaps_named() {
    let all = findings(
        &[("ci.yml", &fixture("monorepo-ci.yml"))],
        json!({"commands": {"verify": "make verify"}}),
        Some(json!({"workflow": "existing", "aggregate_check": "all-checks-passed"})),
    );
    assert_eq!(
        all,
        [
            "WARNING: ci.job-timeouts: Job web has no timeout-minutes",
            "WARNING: ci.permissions-least: Workflow .github/workflows/ci.yml grants more than contents: read at top level",
            "WARNING: ci.permissions-least: Checkout in job detect-changes of .github/workflows/ci.yml persists credentials",
            "WARNING: posture.actions-pinned: Unpinned action actions/checkout@v4 in .github/workflows/ci.yml",
            "WARNING: ci.workflow-lint: Workflow lint absent",
            "WARNING: ci.hosted-macos: Hosted macOS on pull requests bills at a premium multiple",
            "WARNING: ci.heldout-present: No held-out test job: the agent can edit every test it is measured against",
            "WARNING: ci.protected-paths-gate: Protected paths are not gated: a workflow or held-out change can merge without a human",
        ]
    );
}

#[test]
fn a_grep_v_pass_gate_is_no_aggregate() {
    let all = findings(
        &[("guard.yml", &fixture("grep-v-pass.yml"))],
        json!({}),
        None,
    );
    assert_eq!(
        rule_lines(&all, "ci.aggregate-present"),
        ["WARNING: ci.aggregate-present: No aggregate job: required checks can hang or skip"]
    );
}

#[test]
fn an_unparseable_workflow_is_unverified_for_each_rule_it_feeds() {
    let all = findings(&[("broken.yml", &fixture("broken.yml"))], json!({}), None);
    let rules = [
        "ci.aggregate-present",
        "ci.job-timeouts",
        "ci.permissions-least",
        "posture.actions-pinned",
        "ci.workflow-lint",
        "ci.no-self-hosted-label",
        "ci.hosted-macos",
        "ci.heldout-present",
        "ci.protected-paths-gate",
    ];
    assert_eq!(all.len(), rules.len(), "{all:#?}");
    for (line, rule) in all.iter().zip(rules) {
        let prefix = format!("WARNING: {rule}: unverified: .github/workflows/broken.yml: ");
        assert!(line.starts_with(&prefix), "{line}");
    }
}

#[test]
fn an_unparseable_file_does_not_hide_a_satisfied_rule_elsewhere() {
    let all = findings(
        &[
            ("broken.yml", &fixture("broken.yml")),
            ("rust.yml", &fixture("sharded-rust.yml")),
        ],
        rust_profile(),
        Some(json!({"workflow": "existing", "aggregate_check": "Rust (linux)"})),
    );
    assert!(
        rule_lines(&all, "ci.aggregate-present").is_empty(),
        "{all:#?}"
    );
    assert_eq!(rule_lines(&all, "ci.job-timeouts").len(), 1);
    assert!(rule_lines(&all, "ci.job-timeouts")[0].contains("unverified"));
}

// --- ci.aggregate-present: the three ways a job is covered ------------------------

const GATE: &str = "  gate:\n    name: gate\n    if: always()\n    needs: [build]\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    steps:\n      - run: 'true'\n";
const HEAD: &str = "on: [pull_request, push]\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    steps:\n      - run: make\n";

fn aggregate(extra_job: &str, profile: Value) -> Vec<String> {
    let text = format!("{HEAD}{extra_job}{GATE}");
    let all = findings(&[("ci.yml", &text)], profile, None);
    rule_lines(&all, "ci.aggregate-present")
        .into_iter()
        .map(str::to_owned)
        .collect()
}

#[test]
fn a_job_in_the_transitive_needs_is_covered() {
    let lint = "  lint:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    steps:\n      - run: make lint\n";
    let text = format!(
        "{}{lint}{}",
        HEAD.replace(
            "    steps:\n      - run: make\n",
            "    needs: lint\n    steps:\n      - run: make\n"
        ),
        GATE
    );
    let all = findings(&[("ci.yml", &text)], json!({}), None);
    assert!(
        rule_lines(&all, "ci.aggregate-present").is_empty(),
        "{all:#?}"
    );
}

#[test]
fn an_uncovered_job_fails_the_aggregate() {
    let extra = "  release:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    steps:\n      - run: make release\n";
    assert_eq!(
        aggregate(extra, json!({})),
        ["WARNING: ci.aggregate-present: No aggregate job: required checks can hang or skip"]
    );
}

#[test]
fn a_push_only_job_is_covered() {
    let extra = "  release:\n    if: github.event_name == 'push'\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    steps:\n      - run: make release\n";
    assert!(aggregate(extra, json!({})).is_empty());
}

#[test]
fn a_job_that_also_runs_on_pull_requests_is_not_push_only() {
    let extra = "  release:\n    if: github.event_name == 'push' || github.event_name == 'pull_request'\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    steps:\n      - run: make release\n";
    assert_eq!(aggregate(extra, json!({})).len(), 1);
}

/// #1160: a `||` nested inside a parenthesised conjunct leaves the top-level
/// `github.event_name == 'push'` conjunct in force.
#[test]
fn a_push_conjunct_beside_a_nested_alternative_is_push_only() {
    let extra = "  deploy:\n    if: >-\n      always() && !cancelled() &&\n      github.event_name == 'push' && github.ref == 'refs/heads/main' &&\n      (needs.build.outputs.a == 'true' || needs.build.outputs.b == 'true')\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    steps:\n      - run: make deploy\n";
    assert!(aggregate(extra, json!({})).is_empty());
}

/// The push conjunct must be top level: inside a parenthesised alternative
/// the job also runs on pull requests.
#[test]
fn a_push_test_inside_a_nested_alternative_is_not_push_only() {
    let extra = "  deploy:\n    if: (github.event_name == 'push' || github.event_name == 'pull_request') && always()\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    steps:\n      - run: make deploy\n";
    assert_eq!(aggregate(extra, json!({})).len(), 1);
    let quoted = "  deploy:\n    if: github.event_name == 'push' && contains(github.ref, '&& x || y')\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    steps:\n      - run: make deploy\n";
    assert!(aggregate(quoted, json!({})).is_empty());
}

/// #1160: a job downstream of the aggregate (it needs it, directly or
/// transitively) cannot gate a pull request the aggregate already judged.
#[test]
fn a_job_downstream_of_the_aggregate_is_covered() {
    let deploy = "  deploy:\n    needs: [gate]\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    steps:\n      - run: make deploy\n";
    let notify = "  notify:\n    needs: [deploy]\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    steps:\n      - run: make notify\n";
    let text = format!("{HEAD}{GATE}{deploy}{notify}");
    let all = findings(
        &[("ci.yml", &text)],
        json!({}),
        Some(json!({"workflow": "existing", "aggregate_check": "gate"})),
    );
    assert!(
        rule_lines(&all, "ci.aggregate-present").is_empty(),
        "{all:#?}"
    );
}

#[test]
fn a_job_that_is_another_required_check_is_covered() {
    let extra = "  mac:\n    name: Mac\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    steps:\n      - run: make mac\n";
    assert!(aggregate(extra, json!({"ci": {"required_checks": ["gate", "Mac"]}})).is_empty());
    assert_eq!(aggregate(extra, json!({})).len(), 1);
}

#[test]
fn the_answered_aggregate_must_be_the_one_that_covers() {
    let all = findings(
        &[("ci.yml", &format!("{HEAD}{GATE}"))],
        json!({}),
        Some(json!({"workflow": "existing", "aggregate_check": "other"})),
    );
    assert_eq!(rule_lines(&all, "ci.aggregate-present").len(), 1);
    let all = findings(
        &[("ci.yml", &format!("{HEAD}{GATE}"))],
        json!({}),
        Some(json!({"workflow": "existing", "aggregate_check": "gate"})),
    );
    assert!(rule_lines(&all, "ci.aggregate-present").is_empty());
}

// --- the remaining rules ---------------------------------------------------------

#[test]
fn reusable_workflow_callers_need_no_timeout_but_a_pin() {
    let text = format!(
        "{HEAD}  call:\n    uses: org/repo/.github/workflows/x.yml@v1\n  local:\n    uses: ./.github/workflows/y.yml\n{}",
        GATE.replace("needs: [build]", "needs: [build, call, local]")
    );
    let all = findings(&[("ci.yml", &text)], json!({}), None);
    assert!(rule_lines(&all, "ci.job-timeouts").is_empty(), "{all:#?}");
    assert_eq!(
        rule_lines(&all, "posture.actions-pinned"),
        [
            "WARNING: posture.actions-pinned: Unpinned action org/repo/.github/workflows/x.yml@v1 in .github/workflows/ci.yml"
        ]
    );
}

#[test]
fn permissions_beyond_contents_read_fail() {
    for permissions in [
        "permissions: read-all",
        "permissions:\n  contents: write",
        "permissions:\n  contents: read\n  pull-requests: read",
    ] {
        let text = format!("{}{GATE}", HEAD.replace("permissions: {}", permissions));
        let all = findings(&[("ci.yml", &text)], json!({}), None);
        assert_eq!(
            rule_lines(&all, "ci.permissions-least"),
            [
                "WARNING: ci.permissions-least: Workflow .github/workflows/ci.yml grants more than contents: read at top level"
            ],
            "{permissions}"
        );
    }
    let text = format!(
        "{}{GATE}",
        HEAD.replace(
            "permissions: {}",
            "permissions:\n  contents: read\n  actions: none"
        )
    );
    let all = findings(&[("ci.yml", &text)], json!({}), None);
    assert!(rule_lines(&all, "ci.permissions-least").is_empty());
}

#[test]
fn a_quoted_false_persist_credentials_passes() {
    let text = format!(
        "{}{GATE}",
        HEAD.replace(
            "      - run: make\n",
            "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4\n        with:\n          persist-credentials: \"false\"\n      - run: make\n"
        )
    );
    let all = findings(&[("ci.yml", &text)], json!({}), None);
    assert!(
        rule_lines(&all, "ci.permissions-least").is_empty(),
        "{all:#?}"
    );
    assert!(
        rule_lines(&all, "posture.actions-pinned").is_empty(),
        "{all:#?}"
    );
}

#[test]
fn self_hosted_labels_and_hosted_macos_on_pull_requests_are_named() {
    let text = format!(
        "{}{GATE}",
        HEAD.replace("    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    steps:\n      - run: make\n",
            "    runs-on: [self-hosted, macos-14]\n    timeout-minutes: 5\n    steps:\n      - run: make\n")
    );
    let all = findings(&[("ci.yml", &text)], json!({}), None);
    assert_eq!(
        rule_lines(&all, "ci.no-self-hosted-label"),
        ["WARNING: ci.no-self-hosted-label: Job build runs on a self-hosted label"]
    );
    assert_eq!(
        rule_lines(&all, "ci.hosted-macos"),
        ["WARNING: ci.hosted-macos: Hosted macOS on pull requests bills at a premium multiple"]
    );
    // Push-only macOS bills only after a change reaches main.
    let push_only = text.replace("on: [pull_request, push]", "on: [push]");
    let all = findings(&[("ci.yml", &push_only)], json!({}), None);
    assert!(rule_lines(&all, "ci.hosted-macos").is_empty());
}

#[test]
fn a_workflow_lint_job_satisfies_the_static_part() {
    let text = format!(
        "{HEAD}  workflow-lint:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    steps:\n      - run: actionlint\n{}",
        GATE.replace("needs: [build]", "needs: [build, workflow-lint]")
    );
    let all = findings(&[("ci.yml", &text)], json!({}), None);
    assert!(rule_lines(&all, "ci.workflow-lint").is_empty(), "{all:#?}");
}

#[test]
fn dependabot_without_github_actions_is_named() {
    let workflow = format!("{HEAD}{GATE}");
    for dependabot in [
        None,
        Some("version: 2\nupdates:\n  - package-ecosystem: cargo\n    directory: /\n"),
    ] {
        let mut files = vec![(".github/workflows/ci.yml", workflow.as_str())];
        files.extend(dependabot.map(|d| (".github/dependabot.yml", d)));
        let dir = repo(&files);
        let all = audit::findings(dir.path(), &json!({}), None);
        assert_eq!(
            rule_lines(&all, "ci.dependabot-actions"),
            [
                "WARNING: ci.dependabot-actions: Dependabot does not update the github-actions ecosystem"
            ]
        );
    }
    let dir = repo(&[
        (".github/workflows/ci.yml", &workflow),
        (".github/dependabot.yml", "updates: {\n"),
    ]);
    let all = audit::findings(dir.path(), &json!({}), None);
    let lines = rule_lines(&all, "ci.dependabot-actions");
    assert_eq!(lines.len(), 1);
    assert!(
        lines[0]
            .starts_with("WARNING: ci.dependabot-actions: unverified: .github/dependabot.yml: "),
        "{}",
        lines[0]
    );
}

#[test]
fn an_answered_command_null_in_the_profile_is_missing() {
    let workflow = format!("{HEAD}{GATE}");
    let all = findings(
        &[("ci.yml", &workflow)],
        json!({"commands": {"verify": "make verify", "test": null}}),
        Some(json!({"workflow": "generate", "commands": ["lint", "test", "verify"]})),
    );
    assert_eq!(
        rule_lines(&all, "ci.command-missing"),
        [
            "WARNING: ci.command-missing: Verification command missing: commands.lint",
            "WARNING: ci.command-missing: Verification command missing: commands.test",
        ]
    );
}

#[test]
fn a_repository_without_workflows_or_answers_has_no_ci_findings() {
    let dir = repo(&[]);
    assert!(audit::findings(dir.path(), &json!({}), None).is_empty());
}

// --- Decision 4: the stale `project.json` `ci` fields --------------------------------

#[test]
fn stale_ci_fields_are_one_warning_naming_them() {
    let workflow = format!("{HEAD}{GATE}");
    let stale = |profile: Value, answers: Value| {
        let all = findings(&[("ci.yml", &workflow)], profile, Some(answers));
        rule_lines(&all, "ci.project-ci-stale")
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    let existing = json!({"workflow": "existing", "aggregate_check": "gate"});
    let linux = configured::linux_runner().label;
    assert_eq!(
        stale(
            json!({"ci": {"runners": {"linux": linux, "macos": "self-hosted mac"}, "required_checks": ["gate"], "tiers": false}}),
            existing.clone()
        ),
        [
            "WARNING: ci.project-ci-stale: .agent-setup/project.json ci.runners, ci.tiers disagree with the ci-baseline answers; the answers govern (Decision 4)"
        ]
    );
    assert!(
        stale(
            json!({"ci": {"runners": {"linux": linux}, "required_checks": ["gate"], "tiers": {"pull_request": "docs"}}}),
            existing.clone()
        )
        .is_empty()
    );
    assert!(stale(json!({}), existing.clone()).is_empty());
    assert!(
        stale(
            json!({"ci": {"runners": {"linux": "github-hosted ubuntu-24.04"}}}),
            json!({"runner": "github", "workflow": "existing", "aggregate_check": "gate"})
        )
        .is_empty()
    );
}

// --- doctor --------------------------------------------------------------------------

#[test]
fn doctor_on_this_repository_under_existing_reports_the_stale_fields_not_the_aggregate() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let profile = fs::read_to_string(root.join(".agent-setup/project.json")).unwrap();
    // This repository's aggregate, or the import's (`export/.github/workflows/ci.yml`,
    // laid over it by the export), which the new repository's ruleset requires.
    let aggregate = if root.join("export").is_dir() {
        "Rust (linux)"
    } else {
        "required"
    };
    let mut files: Vec<(String, String)> = vec![
        (".agent-setup/project.json".to_owned(), profile),
        (
            ".agent-setup/modules/ci-baseline.json".to_owned(),
            json!({"module": "ci-baseline", "version": "1.0.0", "answers": {"workflow": "existing", "aggregate_check": aggregate}}).to_string(),
        ),
    ];
    for entry in fs::read_dir(root.join(".github/workflows")).unwrap() {
        let entry = entry.unwrap();
        files.push((
            format!(".github/workflows/{}", entry.file_name().to_string_lossy()),
            fs::read_to_string(entry.path()).unwrap(),
        ));
    }
    let refs: Vec<(&str, &str)> = files
        .iter()
        .map(|(p, t)| (p.as_str(), t.as_str()))
        .collect();
    let dir = repo(&refs);
    let diagnosis = brakes::diagnose_at(
        dir.path(),
        chrono::NaiveDate::from_ymd_opt(2026, 10, 28).unwrap(),
    )
    .unwrap();
    let ci: Vec<&String> = diagnosis
        .findings
        .iter()
        .filter(|f| f.starts_with("WARNING: ci."))
        .collect();
    assert!(
        !ci.iter()
            .any(|f| f.starts_with("WARNING: ci.aggregate-present")),
        "{ci:#?}"
    );
    // #779: workflow-lint.yml lints our workflows and goldens.
    assert!(
        !ci.iter()
            .any(|f| f.starts_with("WARNING: ci.workflow-lint")),
        "{ci:#?}"
    );
    // The stale fields follow the tree's profile: this repository's, or the
    // import's overlay (`export/.agent-setup/project.json`, laid over it by the
    // export, which never carries `export/`), whose required check is the aggregate;
    // the import also declares `neutrality`, a required check of its own workflow.
    let declared: Value = serde_json::from_str(&files[0].1).unwrap();
    let only_aggregate = declared["ci"]["required_checks"] == json!([aggregate]);
    let stale = if root.join("export").is_dir() || !only_aggregate {
        "ci.runners, ci.required_checks"
    } else {
        "ci.runners"
    };
    assert!(
        ci.contains(&&format!("WARNING: ci.project-ci-stale: .agent-setup/project.json {stale} disagree with the ci-baseline answers; the answers govern (Decision 4)")),
        "{ci:#?}"
    );
    // Warnings only: the ci.* rules never decide readiness.
    assert!(
        diagnosis
            .printed_findings()
            .iter()
            .all(|f| !f.starts_with("NOT READY: ci."))
    );
}

// --- T8 (#779): this repository lints its own workflows and goldens ------------------

fn our_workflow_lint() -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    fs::read_to_string(root.join(".github/workflows/workflow-lint.yml"))
        .expect(".github/workflows/workflow-lint.yml")
}

#[test]
fn this_repository_has_a_workflow_lint_job_that_passes_every_static_rule() {
    let text = our_workflow_lint();
    let all = findings(&[("workflow-lint.yml", &text)], json!({}), None);
    assert!(all.iter().all(|f| !f.contains("workflow-lint")), "{all:#?}");
}

#[test]
fn our_workflow_lint_installs_actionlint_from_the_security_pin_with_its_fragment() {
    use brakes::modules::security::pins::ACTIONLINT;
    let text = our_workflow_lint();
    for (url, sha) in [ACTIONLINT.amd64, ACTIONLINT.arm64] {
        assert!(text.contains(&format!("\"{url}\"")), "{url}");
        assert!(text.contains(&format!("\"{sha}\"")), "{sha}");
    }
    assert!(text.contains(&format!("TOOL_VERSION: \"{}\"", ACTIONLINT.version)));
    let fragment = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../templates/security/fragments/install-tool.sh"),
    )
    .unwrap();
    let wf = workflows::parse(&text).unwrap();
    let job = wf.job("workflow-lint").expect("a workflow-lint job");
    assert!(
        job.steps
            .iter()
            .any(|s| s.run.as_deref() == Some(fragment.as_str())),
        "the install step runs security's install-tool.sh verbatim"
    );
}

#[test]
fn our_workflow_lint_runs_zizmor_at_the_pinned_version_over_workflows_and_goldens() {
    use brakes::modules::stack_packs::PinTable;
    let pins = PinTable::embedded().unwrap();
    let wf = workflows::parse(&our_workflow_lint()).unwrap();
    let job = wf.job("workflow-lint").unwrap();
    let action = &pins.actions["zizmorcore/zizmor-action"];
    let zizmor = job
        .steps
        .iter()
        .find(|s| s.uses.as_deref() == Some(&format!("zizmorcore/zizmor-action@{}", action.sha)))
        .expect("zizmor-action pinned by the stack-packs SHA");
    assert_eq!(zizmor.with["version"], pins.tools["zizmor"].version);
    assert_eq!(zizmor.with["persona"], "regular");
    assert_eq!(zizmor.with["min-severity"], "medium");
    let targets = [
        ".github/workflows",
        "templates/security/goldens/*.yml",
        "templates/agent-guardrails/goldens/*.yml",
        "templates/qa/goldens/*.yml",
    ];
    for target in targets {
        assert!(
            zizmor.with["inputs"]
                .split_whitespace()
                .any(|t| t == target),
            "{target}"
        );
    }
    let actionlint = job
        .steps
        .iter()
        .filter_map(|s| s.run.as_deref())
        .find(|r| r.starts_with("actionlint"))
        .expect("an actionlint step");
    let linted = ".github/workflows/*.yml templates/ci-baseline/goldens/*.yml templates/security/goldens/*.yml templates/agent-guardrails/goldens/*.yml templates/qa/goldens/*.yml";
    assert_eq!(actionlint.trim(), format!("actionlint {linted}"));
}

/// The zizmor steps of a workflow-lint file: (inputs, online audits on).
fn zizmor_steps(text: &str) -> Vec<(Vec<String>, bool)> {
    let wf = workflows::parse(text).unwrap();
    let job = wf.job("workflow-lint").unwrap();
    job.steps
        .iter()
        .filter(|s| {
            s.uses
                .as_deref()
                .is_some_and(|u| u.starts_with("zizmorcore/zizmor-action@"))
        })
        .map(|s| {
            let inputs = s.with["inputs"]
                .split_whitespace()
                .map(str::to_owned)
                .collect();
            let online = s.with.get("online-audits").is_none_or(|v| v != "false");
            (inputs, online)
        })
        .collect()
}

/// #1200: the test configuration's reusable callee is synthetic, so zizmor's online
/// audits (impostor-commit lists the callee's tags) cannot run over `caller.yml`.
/// Every ci-baseline golden is still audited: `caller.yml` offline in a step of its
/// own, every other golden by name in the online step. Both this repository's lint
/// and the import's overlay hold to it.
#[test]
fn zizmor_audits_every_ci_baseline_golden_and_caller_yml_only_offline() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let dir = root.join("templates/ci-baseline/goldens");
    let mut goldens: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.ends_with(".yml"))
        .map(|n| format!("templates/ci-baseline/goldens/{n}"))
        .collect();
    goldens.sort();
    assert!(goldens.len() > 1, "{goldens:?}");
    // The import's overlay exists only here; in the exported tree it is the
    // repository's own `workflow-lint.yml`.
    let mut files = vec![".github/workflows/workflow-lint.yml"];
    if root.join("export").is_dir() {
        files.push("export/.github/workflows/workflow-lint.yml");
    }
    for file in files {
        let steps = zizmor_steps(&fs::read_to_string(root.join(file)).unwrap());
        let online: Vec<&String> = steps.iter().filter(|s| s.1).flat_map(|s| &s.0).collect();
        let offline: Vec<&String> = steps.iter().filter(|s| !s.1).flat_map(|s| &s.0).collect();
        for golden in &goldens {
            if golden.ends_with("/caller.yml") {
                assert!(!online.contains(&golden), "{file}: {golden} online");
                assert_eq!(offline, [golden], "{file}: the offline step");
            } else {
                assert!(online.contains(&golden), "{file}: {golden} not audited");
            }
        }
        assert!(
            !online
                .iter()
                .any(|t| t.starts_with("templates/ci-baseline/goldens/*")),
            "{file}: the online step globs caller.yml in"
        );
    }
}

// --- T15 (#944): ci.heldout-present and ci.protected-paths-gate -------------------

const HELDOUT_PRESENT: &str = "WARNING: ci.heldout-present: No held-out test job: the agent can edit every test it is measured against";
const GATE_ABSENT: &str = "WARNING: ci.protected-paths-gate: Protected paths are not gated: a workflow or held-out change can merge without a human";

fn golden(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../templates/ci-baseline/goldens")
        .join(name);
    fs::read_to_string(&path).expect(name)
}

/// The `ci.*` findings of a checkout with `workflows` and `extra` files.
fn findings_with(
    workflows: &[(&str, &str)],
    extra: &[(&str, &str)],
    answers: Option<Value>,
) -> Vec<String> {
    let mut files: Vec<(String, String)> = workflows
        .iter()
        .map(|(n, t)| (format!(".github/workflows/{n}"), (*t).to_owned()))
        .chain(
            extra
                .iter()
                .map(|(p, t)| ((*p).to_owned(), (*t).to_owned())),
        )
        .collect();
    files.push((
        ".github/dependabot.yml".to_owned(),
        DEPENDABOT_ACTIONS.to_owned(),
    ));
    let refs: Vec<(&str, &str)> = files
        .iter()
        .map(|(p, t)| (p.as_str(), t.as_str()))
        .collect();
    let dir = repo(&refs);
    let answers: Option<BTreeMap<String, Value>> =
        answers.map(|a| serde_json::from_value(a).unwrap());
    audit::findings(dir.path(), &json!({}), answers.as_ref())
}

fn brakes(all: &[String]) -> Vec<&str> {
    all.iter()
        .map(String::as_str)
        .filter(|l| {
            l.starts_with("WARNING: ci.heldout-present")
                || l.starts_with("WARNING: ci.protected-paths-gate")
        })
        .collect()
}

const KEPT_TEST: (&str, &str) = ("tests/heldout/test_kept.py", "import unittest\n");

#[test]
fn the_walker_reads_step_env() {
    let wf = workflows::parse(&golden("heldout.yml")).unwrap();
    let required = wf.job("required").unwrap();
    let env = &required.steps[0].env;
    assert_eq!(
        env.get("PROTECTED").map(String::as_str),
        Some("${{ needs.scope.outputs.protected }}")
    );
    assert!(env.contains_key("PR_LABELS"));
}

#[test]
fn each_fixture_shape_passes_with_the_heldout_job_and_the_gate() {
    let existing = golden("existing-heldout.yml");
    for (file, text, answers) in [
        (
            "rust.yml",
            fixture("sharded-rust.yml"),
            json!({"workflow": "existing", "aggregate_check": "Rust (linux)"}),
        ),
        (
            "ci.yml",
            fixture("monorepo-ci.yml"),
            json!({"workflow": "existing", "aggregate_check": "all-checks-passed"}),
        ),
    ] {
        let all = findings_with(
            &[(file, &text), ("agentic-security.yml", &existing)],
            &[KEPT_TEST],
            Some(answers),
        );
        assert!(brakes(&all).is_empty(), "{file}: {all:#?}");
    }
    // A jq verify.yml of its own beside the generated workflow.
    let all = findings_with(
        &[
            ("verify.yml", &fixture("jq-verify.yml")),
            ("ci.yml", &golden("heldout.yml")),
        ],
        &[KEPT_TEST],
        None,
    );
    assert!(brakes(&all).is_empty(), "{all:#?}");
}

#[test]
fn the_default_workflow_wires_a_pending_heldout_job_that_needs_tests_to_pass() {
    // #1362: the default install renders the job before any held-out test exists;
    // the rule still fails until the directory holds one.
    let ci = golden("single.yml");
    let none = findings_with(&[("ci.yml", &ci)], &[], None);
    assert_eq!(brakes(&none), [HELDOUT_PRESENT]);
    let kept = findings_with(&[("ci.yml", &ci)], &[KEPT_TEST], None);
    assert!(brakes(&kept).is_empty(), "{kept:#?}");
}

#[test]
fn a_heldout_job_without_tests_in_the_directory_fails() {
    let ci = golden("heldout.yml");
    let none = findings_with(&[("ci.yml", &ci)], &[], None);
    assert_eq!(brakes(&none), [HELDOUT_PRESENT]);
    // A directory with only an empty subdirectory has no test either.
    let dir = repo(&[(".github/workflows/ci.yml", ci.as_str())]);
    fs::create_dir_all(dir.path().join("tests/heldout/empty")).unwrap();
    let all = audit::findings(dir.path(), &json!({}), None);
    assert_eq!(brakes(&all), [HELDOUT_PRESENT]);
}

#[test]
fn a_heldout_job_outside_the_aggregate_needs_fails() {
    let ci = golden("heldout.yml").replace(
        "    needs: [scope, checks, heldout, workflow-lint]",
        "    needs: [scope, checks, workflow-lint]",
    );
    let all = findings_with(&[("ci.yml", &ci)], &[KEPT_TEST], None);
    assert_eq!(brakes(&all), [HELDOUT_PRESENT]);
}

#[test]
fn the_answered_heldout_dir_is_the_one_read() {
    let ci = golden("heldout.yml");
    let answers = json!({"heldout_dir": "./qa/heldout/"});
    let elsewhere = findings_with(&[("ci.yml", &ci)], &[KEPT_TEST], Some(answers.clone()));
    assert_eq!(brakes(&elsewhere), [HELDOUT_PRESENT]);
    let there = findings_with(
        &[("ci.yml", &ci)],
        &[("qa/heldout/kept_test.rs", "")],
        Some(answers),
    );
    assert!(brakes(&there).is_empty(), "{there:#?}");
}

/// An answered `protected_paths` entry that still carries a `<…>` placeholder is
/// matched literally by the scope job and protects nothing (#1229).
#[test]
fn an_answered_protected_path_with_a_placeholder_is_a_gate_finding() {
    let ci = golden("heldout.yml");
    let answers =
        json!({"protected_paths": [".github/workflows/**", "<heldout_dir>/**", "<web_dir>/x/**"]});
    let all = findings_with(&[("ci.yml", &ci)], &[KEPT_TEST], Some(answers));
    assert_eq!(
        brakes(&all),
        [
            "WARNING: ci.protected-paths-gate: protected_paths entry <heldout_dir>/** carries an unresolved placeholder; the scope job matches it literally",
            "WARNING: ci.protected-paths-gate: protected_paths entry <web_dir>/x/** carries an unresolved placeholder; the scope job matches it literally",
        ]
    );
    let resolved = json!({"protected_paths": [".github/workflows/**", "tests/heldout/**"]});
    let all = findings_with(&[("ci.yml", &ci)], &[KEPT_TEST], Some(resolved));
    assert!(brakes(&all).is_empty(), "{all:#?}");
}

#[test]
fn a_gate_without_the_label_triggers_or_the_inputs_fails() {
    let ci = golden("heldout.yml");
    for broken in [
        ci.replace(
            "types: [opened, synchronize, reopened, labeled, unlabeled]",
            "types: [opened, synchronize, reopened]",
        ),
        ci.replace(
            "types: [opened, synchronize, reopened, labeled, unlabeled]",
            "types: [opened, synchronize, reopened, labeled]",
        ),
        ci.replace(
            "          PR_LABELS: \"${{ toJSON(github.event.pull_request.labels.*.name) }}\"\n",
            "",
        ),
        ci.replace(
            "          PROTECTED: \"${{ needs.scope.outputs.protected }}\"\n",
            "",
        ),
        ci.replace("    if: always()\n", ""),
    ] {
        assert_ne!(broken, ci);
        let all = findings_with(&[("ci.yml", &broken)], &[KEPT_TEST], None);
        assert!(brakes(&all).contains(&GATE_ABSENT), "{all:#?}");
    }
}

/// #1255: a gate that reads the labels but not who added them lets a label an App
/// or a bot added count; the finding names it apart from a missing gate.
const GATE_UNCHECKED: &str = "WARNING: ci.protected-paths-gate: The protected-paths gate reads the label but not who added it: a human-approved an App or bot added would count";

#[test]
fn a_gate_that_does_not_read_who_added_the_label_is_a_finding() {
    let ci = golden("heldout.yml");
    assert!(
        brakes(&findings_with(&[("ci.yml", &ci)], &[KEPT_TEST], None)).is_empty(),
        "the generated gate checks the actor"
    );
    for broken in [
        // A hand-written gate that never reads the issue events.
        ci.replace(
            "\"repos/${REPOSITORY}/issues/${PR_NUMBER}/events?per_page=100\"",
            "\"repos/${REPOSITORY}/pulls/${PR_NUMBER}\"",
        ),
        // Or reads them with a token that cannot.
        ci.replace(
            "    permissions:\n      issues: read\n      pull-requests: read\n",
            "",
        ),
    ] {
        assert_ne!(broken, ci);
        let all = findings_with(&[("ci.yml", &broken)], &[KEPT_TEST], None);
        assert_eq!(brakes(&all), [GATE_UNCHECKED], "{all:#?}");
    }
    // A workflow-level grant serves the job too.
    let top = ci
        .replace(
            "    permissions:\n      issues: read\n      pull-requests: read\n",
            "",
        )
        .replacen(
            "permissions:\n  contents: read\n",
            "permissions:\n  contents: read\n  pull-requests: read\n",
            1,
        );
    assert_ne!(top, ci);
    let all = findings_with(&[("ci.yml", &top)], &[KEPT_TEST], None);
    assert!(!brakes(&all).contains(&GATE_UNCHECKED), "{all:#?}");
}

// --- ci.command-missing in a monorepo (#1037) ---------------------------------------

/// A monorepo checkout: the stack-packs answers record `apps` (id → path,
/// stack), each with its own profile `profiles` (id → JSON, or `None` for
/// none); the root profile declares nothing.
fn monorepo_findings(
    apps: &[(&str, &str, &str)],
    profiles: &[(&str, Option<&str>)],
    answered: Value,
) -> Vec<String> {
    let mut raw = serde_json::Map::new();
    for (id, path, stack) in apps {
        raw.insert(format!("apps.{id}.path"), json!(path));
        raw.insert(format!("apps.{id}.stack"), json!(stack));
    }
    let stack_packs =
        json!({"module": "stack-packs", "version": "1.0.0", "answers": raw}).to_string();
    let mut files: Vec<(String, String)> = vec![(
        ".agent-setup/modules/stack-packs.json".to_owned(),
        stack_packs,
    )];
    for (id, profile) in profiles {
        let path = apps.iter().find(|(a, _, _)| a == id).unwrap().1;
        files.push((format!("{path}/README.md"), String::new()));
        if let Some(text) = profile {
            files.push((
                format!("{path}/.agent-setup/project.json"),
                (*text).to_owned(),
            ));
        }
    }
    let refs: Vec<(&str, &str)> = files
        .iter()
        .map(|(p, t)| (p.as_str(), t.as_str()))
        .collect();
    let dir = repo(&refs);
    let answers: BTreeMap<String, Value> =
        serde_json::from_value(json!({"workflow": "generate", "commands": answered})).unwrap();
    audit::findings(dir.path(), &json!({"commands": {}}), Some(&answers))
}

const APPS: &[(&str, &str, &str)] = &[
    ("backend", "apps/backend", "python-uv"),
    ("web", "apps/web", "node"),
];

#[test]
fn a_monorepo_whose_apps_declare_their_commands_has_no_command_missing() {
    let all = monorepo_findings(
        APPS,
        &[
            (
                "backend",
                Some(r#"{"commands": {"lint": "ruff check .", "test": "pytest"}}"#),
            ),
            (
                "web",
                Some(r#"{"commands": {"test": "npm test", "build": "npm run build"}}"#),
            ),
        ],
        json!(["lint", "test", "build"]),
    );
    assert_eq!(rule_lines(&all, "ci.command-missing"), Vec::<&str>::new());
}

#[test]
fn a_monorepo_reports_a_command_no_app_declares_and_an_app_that_runs_nothing() {
    let all = monorepo_findings(
        APPS,
        &[
            ("backend", Some(r#"{"commands": {"test": "pytest"}}"#)),
            ("web", Some(r#"{"commands": {"lint": null}}"#)),
        ],
        json!(["lint", "test", "build"]),
    );
    assert_eq!(
        rule_lines(&all, "ci.command-missing"),
        [
            "WARNING: ci.command-missing: Verification command missing: commands.lint is declared by no app",
            "WARNING: ci.command-missing: Verification command missing: commands.build is declared by no app",
            "WARNING: ci.command-missing: Verification command missing: app web declares none of commands.lint, commands.test, commands.build in apps/web/.agent-setup/project.json",
        ]
    );
}

/// The root `checks` job runs the root profile's commands (#1165): a command
/// only the root declares is not missing.
#[test]
fn a_monorepo_root_profile_declares_the_commands_its_job_runs() {
    let dir = repo(&[
        (
            ".agent-setup/modules/stack-packs.json",
            r#"{"module": "stack-packs", "version": "1.0.0", "answers": {"apps.backend.path": "apps/backend", "apps.backend.stack": "python-uv", "apps.web.path": "apps/web", "apps.web.stack": "node"}}"#,
        ),
        ("apps/backend/README.md", ""),
        (
            "apps/backend/.agent-setup/project.json",
            r#"{"commands": {"test": "pytest"}}"#,
        ),
        ("apps/web/README.md", ""),
        (
            "apps/web/.agent-setup/project.json",
            r#"{"commands": {"test": "npm test"}}"#,
        ),
    ]);
    let answers: BTreeMap<String, Value> = serde_json::from_value(
        json!({"workflow": "generate", "commands": ["lint", "test", "build"]}),
    )
    .unwrap();
    let root = json!({"commands": {"lint": "make lint"}});
    let all = audit::findings(dir.path(), &root, Some(&answers));
    assert_eq!(
        rule_lines(&all, "ci.command-missing"),
        [
            "WARNING: ci.command-missing: Verification command missing: commands.build is declared by no app"
        ]
    );
}

#[test]
fn a_monorepo_app_without_a_profile_is_named() {
    let all = monorepo_findings(
        APPS,
        &[
            ("backend", Some(r#"{"commands": {"test": "pytest"}}"#)),
            ("web", None),
        ],
        json!(["test"]),
    );
    assert_eq!(
        rule_lines(&all, "ci.command-missing"),
        [
            "WARNING: ci.command-missing: Verification command missing: app web has no apps/web/.agent-setup/project.json"
        ]
    );
}

#[test]
fn a_single_app_at_the_root_keeps_the_root_profile_finding() {
    let all = monorepo_findings(&[("root", ".", "rust")], &[], json!(["lint", "test"]));
    assert_eq!(
        rule_lines(&all, "ci.command-missing"),
        [
            "WARNING: ci.command-missing: Verification command missing: commands.lint",
            "WARNING: ci.command-missing: Verification command missing: commands.test",
        ]
    );
}

// --- T16 (#980): ci.heldout-properties ------------------------------------------------

const NO_SEED: &str = "WARNING: ci.heldout-properties: Held-out properties job present but no seed is exported: the run is deterministic and memorisable";
const NO_JOB: &str = "WARNING: ci.heldout-properties: heldout_properties is true and no heldout-properties job is in the aggregate";
const UNWIRED: &str = "WARNING: ci.heldout-properties: Held-out properties job is not in the aggregate: a red run does not block the merge";

fn properties_lines(all: &[String]) -> Vec<&str> {
    rule_lines(all, "ci.heldout-properties")
}

fn answered_on() -> Value {
    json!({"heldout": true, "heldout_properties": true})
}

#[test]
fn heldout_properties_is_silent_where_it_does_not_apply() {
    let all = findings_with(&[("ci.yml", &golden("heldout.yml"))], &[KEPT_TEST], None);
    assert!(properties_lines(&all).is_empty(), "{all:#?}");
    // Answered true but heldout false: the answer is not read.
    let off = findings_with(
        &[("ci.yml", &golden("heldout.yml"))],
        &[KEPT_TEST],
        Some(json!({"heldout": false, "heldout_properties": true})),
    );
    assert!(properties_lines(&off).is_empty(), "{off:#?}");
}

#[test]
fn the_generated_properties_jobs_pass() {
    for (name, ci, answers) in [
        ("heldout-properties-rust.yml", "ci.yml", None),
        (
            "heldout-properties-python-uv.yml",
            "ci.yml",
            Some(answered_on()),
        ),
        (
            "existing-heldout-properties-rust.yml",
            "agentic-security.yml",
            Some(
                json!({"workflow": "existing", "aggregate_check": "Rust (linux)", "heldout": true, "heldout_properties": true}),
            ),
        ),
    ] {
        let all = findings_with(&[(ci, &golden(name))], &[KEPT_TEST], answers);
        assert!(properties_lines(&all).is_empty(), "{name}: {all:#?}");
    }
}

#[test]
fn a_properties_job_that_exports_no_seed_fails() {
    let ci = golden("heldout-properties-rust.yml");
    for removed in [
        "          HELDOUT_SEED: \"${{ steps.seed.outputs.seed }}\"\n",
        "          HELDOUT_EXAMPLES: \"200\"\n",
    ] {
        let broken = ci.replace(removed, "");
        assert_ne!(broken, ci);
        let all = findings_with(&[("ci.yml", &broken)], &[KEPT_TEST], None);
        assert_eq!(properties_lines(&all), [NO_SEED], "{removed}");
    }
}

#[test]
fn answered_true_without_the_job_fails() {
    let all = findings_with(
        &[("ci.yml", &golden("heldout.yml"))],
        &[KEPT_TEST],
        Some(answered_on()),
    );
    assert_eq!(properties_lines(&all), [NO_JOB]);
    // Present but outside the aggregate: the answered text.
    let unwired = golden("heldout-properties-rust.yml").replace(
        "    needs: [scope, checks, heldout, heldout-properties, workflow-lint]",
        "    needs: [scope, checks, heldout, workflow-lint]",
    );
    let all = findings_with(&[("ci.yml", &unwired)], &[KEPT_TEST], Some(answered_on()));
    assert_eq!(properties_lines(&all), [NO_JOB]);
}

#[test]
fn an_unanswered_job_outside_the_aggregate_fails() {
    let unwired = golden("heldout-properties-rust.yml").replace(
        "    needs: [scope, checks, heldout, heldout-properties, workflow-lint]",
        "    needs: [scope, checks, heldout, workflow-lint]",
    );
    assert_ne!(unwired, golden("heldout-properties-rust.yml"));
    let all = findings_with(&[("ci.yml", &unwired)], &[KEPT_TEST], None);
    assert_eq!(properties_lines(&all), [UNWIRED]);
}

#[test]
fn answered_true_with_an_unreadable_workflow_is_unverified() {
    let all = findings_with(
        &[("broken.yml", &fixture("broken.yml"))],
        &[KEPT_TEST],
        Some(answered_on()),
    );
    let lines = properties_lines(&all);
    assert_eq!(lines.len(), 1, "{all:#?}");
    assert!(
        lines[0].starts_with(
            "WARNING: ci.heldout-properties: unverified: .github/workflows/broken.yml: "
        ),
        "{lines:?}"
    );
}
