//! The audit of the project's own CI (#23, part of #19): what the brakes need from
//! it, each finding with the patch it proposes as a unified diff. `doctor` never
//! applies one: `--propose` prints them, and the workflow file keeps its bytes.
//! One fixture per defect under `tests/fixtures/ci-audit/`, each diff a golden
//! under `tests/golden/ci-audit/`; a proposed patch, applied, settles its finding.
use brakes::auditor::ci_audit::{Proposal, proposals};
use std::{fs, path::Path, process::Command};

const FIXTURES: &str = "tests/fixtures/ci-audit";
const GOLDENS: &str = "tests/golden/ci-audit";
const WORKFLOW: &str = ".github/workflows/ci.yml";

fn manifest() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn fixture(name: &str) -> String {
    fs::read_to_string(manifest().join(FIXTURES).join(format!("{name}.yml"))).unwrap()
}

/// A Rust repository at the root declaring lint, test and build, with `workflow`
/// as its only CI.
fn repo(workflow: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    fs::create_dir_all(root.join(".agent-setup/modules")).unwrap();
    fs::create_dir_all(root.join(".github/workflows")).unwrap();
    fs::write(
        root.join(".agent-setup/project.json"),
        r#"{
  "purpose": "A synthetic repository for the CI audit.",
  "commands": {
    "verify": null, "lint": "cargo clippy --all-targets", "test": "cargo test", "build": "cargo build",
    "preprod_up": null, "preprod_seed": null, "preprod_url": null, "preprod_down": null,
    "verify_deploy": null, "deploy_status": null
  },
  "generated_paths": [],
  "environment_notes": [],
  "acceptance": {"scenarios_dir": null, "synthetic_profiles": null, "unsure_routes_to": null},
  "deploy_environments": [],
  "environment_manifests": {}
}"#,
    )
    .unwrap();
    fs::write(
        root.join(".agent-setup/modules/stack-packs.json"),
        r#"{"module": "stack-packs", "version": "1.0.0", "answers": {"apps.root.path": ".", "apps.root.stack": "rust", "apps.root.container": false}}"#,
    )
    .unwrap();
    fs::write(root.join(WORKFLOW), workflow).unwrap();
    dir
}

/// The lock of an install with `security`, whose `diff-coverage` judges the
/// uploaded data, and `modules` beside it.
fn installed(dir: &Path, modules: &[&str]) {
    let modules: serde_json::Map<String, serde_json::Value> = modules
        .iter()
        .chain(&["security"])
        .map(|m| {
            (
                (*m).to_owned(),
                serde_json::json!({"version": "1.0.0", "answers_digest": null}),
            )
        })
        .collect();
    fs::write(
        dir.join(".agent-setup/lock.json"),
        serde_json::json!({"schema": 2, "modules": modules, "files": {}}).to_string(),
    )
    .unwrap();
}

/// `repo`'s profile with `commands` (name, value) replaced.
fn declare(dir: &Path, commands: &[(&str, Option<&str>)]) {
    let path = dir.join(".agent-setup/project.json");
    let mut profile: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    for (name, value) in commands {
        profile["commands"][*name] = serde_json::json!(value);
    }
    fs::write(&path, profile.to_string()).unwrap();
}

/// A seed `ci-baseline` renders (`templates/ci-baseline/goldens/seed/`).
fn seed(name: &str) -> String {
    fs::read_to_string(
        manifest()
            .join("../../templates/ci-baseline/goldens/seed")
            .join(name),
    )
    .unwrap()
}

fn golden(name: &str, text: &str) {
    let path = manifest().join(GOLDENS).join(name);
    if std::env::var_os("UPDATE_GOLDENS").is_some() {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, text).unwrap();
    }
    let expected = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}; run with UPDATE_GOLDENS=1", path.display()));
    assert!(text == expected, "{name} differs from the golden:\n{text}");
}

fn summary(found: &[Proposal]) -> Vec<String> {
    found
        .iter()
        .map(|p| format!("{} {}: {}", p.rule, p.file, p.text))
        .collect()
}

/// Acceptance criterion 1 of #19: on a freshly seeded repository the audit has
/// nothing to say. The seed reads each command at run time (`.commands[$name]`
/// with `NAME` in the step's env), runs `test` or else `verify`, and, for
/// python-uv, the pack's measured pytest in place of the declared test.
#[test]
fn a_freshly_rendered_seed_has_nothing_to_propose() {
    // Each golden with the build its render declared: the python-uv seed has no build job.
    for (file, stack, security, build) in [
        ("seed-rust-security.yml", "rust", true, Some("cargo build")),
        ("seed-rust.yml", "rust", false, Some("cargo build")),
        ("seed-python-uv-security.yml", "python-uv", true, None),
    ] {
        let dir = repo(&seed(file));
        fs::write(
            dir.path().join(".agent-setup/modules/stack-packs.json"),
            format!(
                r#"{{"module": "stack-packs", "version": "1.0.0", "answers": {{"apps.root.path": ".", "apps.root.stack": "{stack}", "apps.root.container": false}}}}"#
            ),
        )
        .unwrap();
        declare(
            dir.path(),
            &[
                ("verify", Some("cargo test --locked")),
                ("test", Some("cargo test --locked")),
                ("build", build),
            ],
        );
        if security {
            installed(dir.path(), &["ci-baseline", "stack-packs"]);
        }
        assert_eq!(
            summary(&proposals(dir.path())),
            Vec::<String>::new(),
            "{file}"
        );
    }
}

#[test]
fn verify_needs_a_job_only_when_test_is_not_declared() {
    // ci-baseline's own selection: lint; test, or verify when test is null; build.
    let dir = repo(&fixture("clean"));
    declare(dir.path(), &[("verify", Some("make verify"))]);
    assert_eq!(summary(&proposals(dir.path())), Vec::<String>::new());
    declare(dir.path(), &[("test", None)]);
    assert_eq!(
        summary(&proposals(dir.path())),
        [
            "ci.command-missing .github/workflows/ci.yml: commands.verify is declared and no job of the project's CI runs it"
        ]
    );
}

#[test]
fn a_hard_coded_ci_still_needs_each_selected_command_literally() {
    // Reading `.commands[...]` counts only for the command the step's env names.
    let ci = fixture("missing-build-job").replace(
        "      - name: Lint\n        run: cargo clippy --all-targets\n",
        "      - name: Lint\n        env:\n          NAME: lint\n        run: cmd=\"$(jq -r --arg name \"$NAME\" '.commands[$name]' .agent-setup/project.json)\" && bash -c \"$cmd\"\n",
    );
    let dir = repo(&ci);
    assert_eq!(
        summary(&proposals(dir.path())),
        [
            "ci.command-missing .github/workflows/ci.yml: commands.build is declared and no job of the project's CI runs it"
        ]
    );
}

#[test]
fn without_security_no_upload_is_asked_for() {
    // Nothing judges coverage without `security`: the seed then uploads none.
    let dir = repo(&fixture("no-coverage-upload"));
    fs::write(
        dir.path().join(".agent-setup/lock.json"),
        "{\"schema\": 2, \"modules\": {}, \"files\": {}}",
    )
    .unwrap();
    assert_eq!(summary(&proposals(dir.path())), Vec::<String>::new());
}

#[test]
fn a_clean_ci_has_nothing_to_propose() {
    let dir = repo(&fixture("clean"));
    assert_eq!(summary(&proposals(dir.path())), Vec::<String>::new());
}

/// The defect's one finding, its diff against the golden, and the finding gone
/// once the patch is applied.
fn defect(name: &str, rule: &str, text: &str) {
    let dir = repo(&fixture(name));
    installed(dir.path(), &[]);
    let found = proposals(dir.path());
    assert_eq!(
        summary(&found),
        vec![format!("{rule} {WORKFLOW}: {text}")],
        "{name}"
    );
    let patch = found[0]
        .patch
        .as_ref()
        .unwrap_or_else(|| panic!("{name}: no patch"));
    golden(&format!("{name}.diff"), &patch.diff);
    fs::write(dir.path().join(WORKFLOW), &patch.after).unwrap();
    let after = summary(&proposals(dir.path()));
    assert!(
        after.iter().all(|line| !line.starts_with(rule)),
        "{name}: the patch leaves {after:?}"
    );
}

#[test]
fn a_job_without_a_timeout_gets_one_after_runs_on() {
    defect(
        "no-timeout",
        "ci.job-timeouts",
        "Job build has no timeout-minutes",
    );
}

#[test]
fn a_commented_job_key_in_a_long_workflow_gets_its_timeout() {
    // The job key carries a comment, and 5000 lines of padding make the diff
    // table cost what a whole-file one would (#23 review).
    let padding: String = (0..5000).map(|i| format!("# line {i}\n")).collect();
    let text = format!(
        "{padding}{}",
        fixture("no-timeout").replace("  build:\n", "  build: # the release build\n")
    );
    let dir = repo(&text);
    let found = proposals(dir.path());
    assert_eq!(
        summary(&found),
        ["ci.job-timeouts .github/workflows/ci.yml: Job build has no timeout-minutes"]
    );
    let diff = &found[0].patch.as_ref().unwrap().diff;
    assert!(
        diff.contains(
            "   build: # the release build\n     runs-on: ubuntu-24.04\n+    timeout-minutes: 15\n"
        ),
        "{diff}"
    );
}

#[test]
fn a_workflow_without_permissions_gets_contents_read() {
    defect(
        "no-permissions",
        "ci.permissions-least",
        "no top-level permissions: every job's token gets the repository default",
    );
}

#[test]
fn a_pull_request_workflow_without_concurrency_cancels_superseded_runs() {
    defect(
        "no-concurrency",
        "ci.concurrency",
        "no concurrency group: a superseded pull-request run keeps running",
    );
}

#[test]
fn an_action_the_pin_table_knows_is_pinned_by_sha() {
    defect(
        "unpinned",
        "posture.actions-pinned",
        "actions/checkout@v4 is not pinned by SHA",
    );
}

#[test]
fn a_ci_that_never_runs_on_pull_requests_gets_the_trigger() {
    defect(
        "push-only",
        "ci.pull-request-trigger",
        "no workflow of the project runs on pull_request: the brakes have nothing to judge",
    );
}

#[test]
fn a_declared_command_without_a_job_gets_one() {
    defect(
        "missing-build-job",
        "ci.command-missing",
        "commands.build is declared and no job of the project's CI runs it",
    );
}

#[test]
fn a_test_job_without_the_upload_measures_its_run_and_uploads() {
    defect(
        "no-coverage-upload",
        "ci.coverage-upload",
        "app root (rust): no job uploads agentic-coverage-root-<job>, so diff-coverage has nothing to judge",
    );
}

#[test]
fn pull_request_target_checking_out_the_head_loses_the_ref() {
    defect(
        "pr-target-head",
        "ci.pull-request-target-head",
        "job build checks out the pull request's head under pull_request_target, with the base's token and secrets",
    );
}

#[test]
fn untrusted_text_in_run_moves_to_the_environment() {
    defect(
        "untrusted-run",
        "ci.untrusted-interpolation",
        "job build interpolates github.event.pull_request.title into run:",
    );
}

#[test]
fn a_workflow_brakes_manages_is_not_the_projects_ci() {
    let dir = repo(&fixture("no-timeout"));
    fs::write(
        dir.path().join(".agent-setup/lock.json"),
        r#"{"schema": 2, "files": {".github/workflows/ci.yml": {"module": "ci-baseline", "class": "managed", "digest": "x"}}}"#,
    )
    .unwrap();
    assert_eq!(summary(&proposals(dir.path())), Vec::<String>::new());
}

#[test]
fn a_pack_without_coverage_is_exempt_and_says_why() {
    let dir = repo(&fixture("no-coverage-upload"));
    installed(dir.path(), &[]);
    fs::write(
        dir.path().join(".agent-setup/modules/stack-packs.json"),
        r#"{"module": "stack-packs", "version": "1.0.0", "answers": {"apps.root.path": ".", "apps.root.stack": "go", "apps.root.container": false}}"#,
    )
    .unwrap();
    let found = proposals(dir.path());
    let coverage: Vec<&Proposal> = found
        .iter()
        .filter(|p| p.rule == "ci.coverage-upload")
        .collect();
    assert_eq!(coverage.len(), 1, "{:?}", summary(&found));
    assert!(coverage[0].patch.is_none());
    assert!(
        coverage[0]
            .text
            .starts_with("app root (go) is not judged: `go test -coverprofile`"),
        "{}",
        coverage[0].text
    );
}

fn brakes(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_brakes"))
        .args(args)
        .output()
        .unwrap()
}

/// `repo`, as a git checkout: `doctor` reads a repository.
fn checkout(workflow: &str) -> tempfile::TempDir {
    let dir = repo(workflow);
    let init = Command::new("git")
        .args(["init", "-q"])
        .current_dir(dir.path())
        .status()
        .unwrap();
    assert!(init.success());
    dir
}

#[test]
fn doctor_propose_prints_the_diff_and_writes_nothing() {
    let dir = checkout(&fixture("no-timeout"));
    let path = dir.path().join(WORKFLOW);
    let before = fs::read(&path).unwrap();
    let out = brakes(&["doctor", dir.path().to_str().unwrap(), "--propose"]);
    let stdout = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains(
            "PROPOSE ci.job-timeouts .github/workflows/ci.yml: Job build has no timeout-minutes\n\
             --- a/.github/workflows/ci.yml\n+++ b/.github/workflows/ci.yml\n"
        ),
        "{stdout}"
    );
    assert!(stdout.contains("+    timeout-minutes: 15\n"), "{stdout}");
    assert!(stdout.contains("Nothing was written."), "{stdout}");
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[test]
fn doctor_without_propose_names_the_count_and_the_flag() {
    let dir = checkout(&fixture("no-timeout"));
    let root = dir.path().to_str().unwrap();
    let out = brakes(&["doctor", root]);
    let stdout = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains(&format!(
            "PROPOSE 1 finding on the project's CI: brakes doctor {root} --propose prints it with the patches; nothing is applied"
        )),
        "{stdout}"
    );
    assert!(!stdout.contains("--- a/"), "{stdout}");
}

#[test]
fn propose_is_only_available_with_doctor() {
    let dir = repo(&fixture("clean"));
    let out = brakes(&["install", dir.path().to_str().unwrap(), "--propose"]);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--propose is only available with doctor"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
