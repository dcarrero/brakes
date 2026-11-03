//! `brakes ci init` (#24, part of #19): the guided setup of a repository without
//! CI. It records the detected apps and the proposed commands first, then plans
//! stack-packs, ci-baseline and security together, so the seed workflow is
//! complete on its first and only write: the test job uploads its coverage data
//! and `diff-coverage` judges it. Every write goes through the engine's plan.
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};
use tempfile::TempDir;

struct Repo {
    _temp: TempDir,
    root: PathBuf,
}

impl Repo {
    /// A git repository whose origin the synthetic configuration allows.
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("toy");
        fs::create_dir(&root).unwrap();
        for args in [
            vec!["init", "-q"],
            vec![
                "remote",
                "add",
                "origin",
                "https://github.com/example-owner/toy",
            ],
        ] {
            assert!(
                Command::new("git")
                    .args(&args)
                    .current_dir(&root)
                    .status()
                    .unwrap()
                    .success()
            );
        }
        Self { _temp: temp, root }
    }

    /// A Rust crate at the root: the evidence stack-packs detects.
    fn rust() -> Self {
        let repo = Self::new();
        repo.write(
            "Cargo.toml",
            "[package]\nname = \"toy\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        repo.write("Cargo.lock", "version = 4\n");
        repo.write("src/main.rs", "fn main() {}\n");
        repo
    }

    fn write(&self, path: &str, text: &str) {
        let path = self.root.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    fn read(&self, path: &str) -> String {
        fs::read_to_string(self.root.join(path)).unwrap_or_else(|e| panic!("{path}: {e}"))
    }

    fn exists(&self, path: &str) -> bool {
        self.root.join(path).exists()
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_brakes"))
            .args(args)
            .current_dir(&self.root)
            .output()
            .unwrap()
    }

    fn run_with_input(&self, args: &[&str], input: &str) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_brakes"))
            .args(args)
            .current_dir(&self.root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Every file under `root`, relative, outside `.git/`.
fn files(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.file_name().is_some_and(|n| n == ".git") {
                continue;
            }
            if path.is_dir() {
                stack.push(path);
            } else {
                out.push(
                    path.strip_prefix(root)
                        .unwrap()
                        .to_string_lossy()
                        .into_owned(),
                );
            }
        }
    }
    out.sort();
    out
}

#[test]
fn the_plan_shows_the_profile_the_seed_and_the_judges_and_writes_nothing() {
    let repo = Repo::rust();
    let before = files(&repo.root);
    let out = repo.run(&["ci", "init", ".", "--no-input"]);
    let text = stdout(&out);
    assert_eq!(out.status.code(), Some(0), "{text}{}", stderr(&out));
    for line in [
        "PLAN .agent-setup/project.json",
        "PLAN .agent-setup/modules/stack-packs.json [answers:stack-packs]",
        "PLAN .github/workflows/ci.yml [seed:ci-baseline]",
        "PLAN .github/workflows/agentic-security.yml [managed:ci-baseline]",
        "PLAN .github/workflows/agentic-coverage.yml [managed:security]",
        "Plan only; no writes. Review before using --apply.",
    ] {
        assert!(text.contains(line), "missing `{line}` in:\n{text}");
    }
    assert_eq!(files(&repo.root), before, "a plan writes nothing");
}

#[test]
fn each_step_is_explained_in_one_line_before_the_plan() {
    let repo = Repo::rust();
    let text = stdout(&repo.run(&["ci", "init", ".", "--no-input"]));
    for line in [
        "STEP 1/4 apps: root (rust at .), detected from Cargo.toml, Cargo.lock",
        "STEP 2/4 commands of root: test = `cargo test --workspace --locked` (proposed for rust; your CI runs it, brakes never does)",
        "STEP 3/4 runner: ",
        "STEP 4/4 workflows: .github/workflows/ci.yml is a seed, yours from now on; brakes owns only the judges",
    ] {
        assert!(text.contains(line), "missing `{line}` in:\n{text}");
    }
    let plan = text.find("PLAN ").unwrap();
    assert!(text.find("STEP 4/4").unwrap() < plan, "{text}");
}

#[test]
fn apply_writes_a_seed_whose_test_job_uploads_coverage_and_feeds_diff_coverage() {
    let repo = Repo::rust();
    let out = repo.run(&["ci", "init", ".", "--no-input", "--apply"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}{}",
        stdout(&out),
        stderr(&out)
    );
    let profile: serde_json::Value =
        serde_json::from_str(&repo.read(".agent-setup/project.json")).unwrap();
    assert_eq!(
        profile["commands"]["test"], "cargo test --workspace --locked",
        "the proposal fills the null command"
    );
    let seed = repo.read(".github/workflows/ci.yml");
    assert!(seed.contains("name: agentic-coverage-root-test"), "{seed}");
    assert!(
        seed.contains("uses: ./.github/workflows/agentic-coverage.yml"),
        "{seed}"
    );
    assert!(repo.exists(".github/workflows/agentic-coverage.yml"));
    assert!(repo.exists(".github/workflows/agentic-security.yml"));
    let lock = repo.read(".agent-setup/lock.json");
    assert!(lock.contains("\"stack-packs\""), "{lock}");
    assert!(lock.contains("\"security\""), "{lock}");
}

#[test]
fn after_apply_doctor_no_longer_fails_for_a_missing_workflow() {
    let repo = Repo::rust();
    let before = stdout(&repo.run(&["doctor", "."]));
    assert!(
        before.contains("ci-health.workflow-exists] no workflow under .github/workflows"),
        "{before}"
    );
    assert!(
        repo.run(&["ci", "init", ".", "--no-input", "--apply"])
            .status
            .success()
    );
    let after = stdout(&repo.run(&["doctor", "."]));
    assert!(
        !after
            .lines()
            .any(|l| l.starts_with("FAIL") && l.contains("ci-health.workflow-exists")),
        "{after}"
    );
}

#[test]
fn the_missing_workflow_finding_points_to_the_guided_setup() {
    let repo = Repo::rust();
    let text = stdout(&repo.run(&["doctor", "."]));
    assert!(
        text.contains(
            "[basic:ci-health.workflow-exists] no workflow under .github/workflows → run `brakes ci init .`; module ci-baseline"
        ),
        "{text}"
    );
}

#[test]
fn apply_ends_with_what_to_commit_and_how_to_see_it_green() {
    let repo = Repo::rust();
    let text = stdout(&repo.run(&["ci", "init", ".", "--no-input", "--apply"]));
    for line in [
        "NEXT git add -A && git commit -m \"ci: the project's CI, seeded by brakes\" (every file the plan wrote, seeds included)",
        "NEXT open a pull request; `gh pr checks` shows `required` (your CI) and `agentic-required` (the judges) green",
        "NEXT `brakes apply . --remote` makes both required on the default branch",
    ] {
        assert!(text.contains(line), "missing `{line}` in:\n{text}");
    }
}

#[test]
fn a_repository_with_its_own_workflow_is_audited_not_seeded() {
    let repo = Repo::rust();
    repo.write(
        ".github/workflows/tests.yml",
        "name: tests\non: pull_request\njobs: {}\n",
    );
    let out = repo.run(&["ci", "init", ".", "--no-input"]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        stderr(&out).trim(),
        "REFUSED: ci init: this repository already has a CI (.github/workflows/tests.yml); brakes audits it instead of seeding another: answer ci-baseline `workflow: existing` and run `brakes doctor . --propose`"
    );
}

#[test]
fn a_repository_without_a_detected_stack_is_refused_by_name() {
    let repo = Repo::new();
    repo.write("README.md", "# toy\n");
    let out = repo.run(&["ci", "init", ".", "--no-input"]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        stderr(&out).trim(),
        "REFUSED: ci init: no stack detected and none recorded; record the apps with `brakes configure . stack-packs` or an answers file (--answers), then run it again"
    );
}

#[test]
fn an_app_with_no_command_to_run_is_refused_rather_than_invented() {
    let repo = Repo::rust();
    // Every proposal declined with `-`: nothing is left for the seed to run.
    let out = repo.run_with_input(&["ci", "init", ".", "--interactive"], "y\n-\n-\n-\n-\n");
    assert_eq!(out.status.code(), Some(2), "{}", stdout(&out));
    assert_eq!(
        stderr(&out).trim(),
        "REFUSED: ci init: no command to run for app root; declare commands.test (or verify, lint, build) in .agent-setup/project.json"
    );
}

#[test]
fn interactively_it_asks_only_what_it_cannot_detect() {
    let repo = Repo::rust();
    // The app is confirmed; the four proposals are accepted with an empty line.
    let out = repo.run_with_input(&["ci", "init", ".", "--interactive"], "y\n\n\n\n\n");
    let text = stdout(&out);
    assert_eq!(out.status.code(), Some(0), "{text}{}", stderr(&out));
    assert!(
        text.contains("Record app root (rust at .)? [Y/n] "),
        "{text}"
    );
    assert!(
        text.contains("commands.test of root [cargo test --workspace --locked]: "),
        "{text}"
    );
    assert!(text.contains("PLAN .github/workflows/ci.yml [seed:ci-baseline]"));
}

#[test]
fn a_declared_command_is_kept_and_never_asked_again() {
    let repo = Repo::rust();
    repo.write(
        ".agent-setup/project.json",
        "{\"purpose\": \"A toy.\", \"commands\": {\"build\": null, \"test\": \"make check\", \"lint\": null, \"verify\": null}}",
    );
    let out = repo.run_with_input(
        &["ci", "init", ".", "--interactive", "--apply"],
        "y\n\n\n\n",
    );
    let text = stdout(&out);
    assert!(out.status.success(), "{text}{}", stderr(&out));
    assert!(!text.contains("commands.test of root"), "{text}");
    assert!(
        text.contains(
            "STEP 2/4 commands of root: test = `make check` (declared in .agent-setup/project.json)"
        ),
        "{text}"
    );
    let profile: serde_json::Value =
        serde_json::from_str(&repo.read(".agent-setup/project.json")).unwrap();
    assert_eq!(profile["commands"]["test"], "make check");
}

#[test]
fn an_answered_command_replaces_the_proposal() {
    let repo = Repo::rust();
    let out = repo.run_with_input(
        &["ci", "init", ".", "--interactive", "--apply"],
        "y\n\nmake test\n\n\n",
    );
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    let profile: serde_json::Value =
        serde_json::from_str(&repo.read(".agent-setup/project.json")).unwrap();
    assert_eq!(profile["commands"]["test"], "make test");
}

#[test]
fn a_declined_app_leaves_nothing_to_seed() {
    let repo = Repo::rust();
    let out = repo.run_with_input(&["ci", "init", ".", "--interactive"], "n\n");
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("ci init: no app to set up"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn apps_an_answers_file_records_are_set_up_without_detection_asking() {
    let repo = Repo::rust();
    let answers = repo.root.join("..").join("answers.json");
    fs::write(
        &answers,
        r#"{"modules": {"stack-packs": {"apps.core.path": ".", "apps.core.stack": "rust", "apps.core.container": false}}}"#,
    )
    .unwrap();
    let out = repo.run(&[
        "ci",
        "init",
        ".",
        "--no-input",
        "--answers",
        answers.to_str().unwrap(),
    ]);
    let text = stdout(&out);
    assert_eq!(out.status.code(), Some(0), "{text}{}", stderr(&out));
    assert!(
        text.contains("STEP 1/4 apps: core (rust at .), recorded by stack-packs"),
        "{text}"
    );
    assert!(!text.contains("apps: root"), "{text}");
}

#[test]
fn ci_takes_only_init() {
    let repo = Repo::rust();
    let out = repo.run(&["ci", "fix", "."]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("brakes ci init <project>"),
        "{}",
        stderr(&out)
    );
}

/// #55: the guided setup's plan ends, as `install`'s does, by saying the apply
/// would be refused and why; a plan the write scope accepts says nothing.
#[test]
fn the_plan_says_when_the_apply_would_be_refused() {
    let repo = Repo::rust();
    let text = stdout(&repo.run(&["ci", "init", ".", "--no-input"]));
    assert!(!text.contains("APPLY REFUSED"), "{text}");
    assert!(
        Command::new("git")
            .args(["remote", "set-url", "origin", "../toy-origin"])
            .current_dir(&repo.root)
            .status()
            .unwrap()
            .success()
    );
    let out = repo.run(&["ci", "init", ".", "--no-input"]);
    let text = stdout(&out);
    assert_eq!(out.status.code(), Some(0), "{text}{}", stderr(&out));
    assert!(
        text.lines().last().is_some_and(
            |l| l.starts_with("APPLY REFUSED: Remote is not a GitHub URL: ../toy-origin;")
        ),
        "{text}"
    );
}
