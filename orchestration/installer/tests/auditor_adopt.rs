//! `adopt <repo> [--apply]` (SPEC-auditor.md, "adopt — contract"; #738): a plan
//! for a repository the installer never touched, made of `ADD`, `SEED`, `STEP`
//! and `PROPOSE` lines only, from the engine's own install plan of the modules
//! the audit names. Nothing is written; `--apply` is refused in this slice.
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};
use tempfile::TempDir;

mod configured;

const LATER: &str = "adopt --apply lands in a later slice";
const VERBS: [&str; 4] = ["ADD ", "SEED ", "STEP ", "PROPOSE "];

struct Repo {
    _temp: TempDir,
    root: PathBuf,
}
impl Repo {
    /// An unmanaged repository with `origin` at `remote` and a README and
    /// AGENTS.md of its own.
    fn new(remote: &str) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("project");
        fs::create_dir(&root).unwrap();
        git(&root, &["init", "-q"]);
        git(&root, &["remote", "add", "origin", remote]);
        let repo = Self { _temp: temp, root };
        repo.write("README.md", "# Project\n");
        repo.write("AGENTS.md", "# Agents\n\nThe project's own rules.\n");
        repo
    }
    fn personal() -> Self {
        Self::new("git@github.com:example-owner/adopt-fixture.git")
    }
    /// The collisions the contract names: a dependency-update configuration,
    /// a PR template and a workflow with a job named `required`; and a
    /// CODEOWNERS that no module renders without an answer, so it is no
    /// collision. The profile declares `verify`, which `ci-baseline` needs to
    /// reach the workflows (it is only read, never run).
    fn with_collisions(self) -> Self {
        self.write(".github/CODEOWNERS", "* @someone\n");
        self.write(
            ".agent-setup/project.json",
            r#"{"purpose": "Fixture.", "commands": {"verify": "make verify"}, "conventions": [], "generated_paths": [], "environment_notes": []}
"#,
        );
        self.write(
            ".github/dependabot.yml",
            "version: 2\nupdates:\n  - package-ecosystem: github-actions\n    directory: /\n    schedule:\n      interval: daily\n",
        );
        self.write(".github/pull_request_template.md", "## What\n");
        self.write(
            ".github/workflows/ci.yml",
            "name: CI\non: [push]\njobs:\n  required:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n",
        );
        self
    }
    fn write(&self, path: &str, text: &str) {
        let path = self.root.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_brakes"))
            .args(args)
            .arg(&self.root)
            .output()
            .unwrap()
    }
    /// Every file outside `.git`, with its content.
    fn tree(&self) -> BTreeMap<PathBuf, Vec<u8>> {
        fn walk(dir: &Path, root: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
            for entry in fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.file_name().is_some_and(|n| n == ".git") {
                    continue;
                }
                if path.is_dir() {
                    walk(&path, root, out);
                } else {
                    let relative = path.strip_prefix(root).unwrap().to_owned();
                    out.insert(relative, fs::read(&path).unwrap());
                }
            }
        }
        let mut out = BTreeMap::new();
        walk(&self.root, &self.root, &mut out);
        out
    }
}

fn git(root: &Path, args: &[&str]) {
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .status()
            .unwrap()
            .success()
    );
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// The plan lines: everything but the closing line.
fn plan_lines(output: &Output) -> Vec<String> {
    let text = stdout(output);
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    lines.pop();
    lines
}

fn assert_only_additive(output: &Output) {
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let lines = plan_lines(output);
    assert!(!lines.is_empty(), "{output:?}");
    for line in &lines {
        assert!(
            VERBS.iter().any(|verb| line.starts_with(verb)),
            "not an adopt verb: {line}"
        );
    }
}

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "lists setup-core or its guides; product-boundary T7a"
)]
#[test]
fn unmanaged_repository_plans_only_additive_verbs_and_writes_nothing() {
    let repo = Repo::personal();
    let before = repo.tree();
    let output = repo.run(&["adopt"]);
    assert_only_additive(&output);
    let text = stdout(&output);
    assert!(
        text.contains("ADD [managed-block:setup-core] AGENTS.md\n"),
        "{text}"
    );
    assert!(text.contains("SEED .agent-setup/project.json"), "{text}");
    assert!(text.contains("SEED docs/agent-setup/"), "{text}");
    assert!(
        !text.contains("SEED .agent-setup/lock.json"),
        "the lock is not a seed: {text}"
    );
    assert!(
        text.lines()
            .last()
            .is_some_and(|l| l.starts_with("Plan only; no writes.")),
        "{text}"
    );
    assert_eq!(repo.tree(), before, "adopt wrote a file");
}

#[test]
fn collisions_become_proposals_and_nothing_is_written() {
    let repo = Repo::personal().with_collisions();
    let before = repo.tree();
    let output = repo.run(&["adopt"]);
    assert_only_additive(&output);
    let text = stdout(&output);
    assert!(!text.contains(".github/CODEOWNERS"), "{text}");
    // The project's own CI is never a collision (#21): `workflow: seed` writes
    // no seed beside it and the judges go to `agentic-security.yml`.
    let ci = ".github/workflows/ci.yml";
    assert!(
        !text.contains(&format!(" {ci}")),
        "{ci} is planned:\n{text}"
    );
    assert!(
        text.contains("SEED .github/workflows/agentic-security.yml"),
        "{text}"
    );
    for path in [".github/dependabot.yml", ".github/pull_request_template.md"] {
        assert!(
            text.contains(&format!("PROPOSE {path}: ")),
            "no proposal for {path}:\n{text}"
        );
        assert!(
            !text.contains(&format!("SEED {path}")) && !text.contains(&format!("ADD {path}")),
            "{path} would be written:\n{text}"
        );
    }
    assert!(
        text.lines()
            .filter(|l| l.starts_with("PROPOSE "))
            .all(|l| l.contains(" → ")),
        "{text}"
    );
    assert_eq!(repo.tree(), before, "adopt wrote a file");
}

#[test]
fn apply_is_refused_with_the_later_slice_sentence() {
    let repo = Repo::personal();
    let before = repo.tree();
    let output = repo.run(&["adopt", "--apply"]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        format!("REFUSED: {LATER}\n")
    );
    assert!(stdout(&output).is_empty());
    assert_eq!(repo.tree(), before);
}

#[test]
fn outside_the_write_scope_is_planned_and_refused_on_apply() {
    let repo = Repo::new("git@github.com:someone-else/project.git");
    let before = repo.tree();
    assert_only_additive(&repo.run(&["adopt"]));
    let output = repo.run(&["adopt", "--apply"]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "REFUSED: Non-personal remote owner refused: someone-else\n"
    );
    assert_eq!(repo.tree(), before);
}

#[test]
fn a_denylisted_identity_is_refused_even_to_plan() {
    let repo = Repo::new(&format!(
        "git@github.com:{}/project.git",
        configured::denied()
    ));
    let output = repo.run(&["adopt"]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(stdout(&output).is_empty());
}

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "lists setup-core or its guides; product-boundary T7a"
)]
#[test]
fn json_matches_the_golden_file() {
    let repo = Repo::personal().with_collisions();
    let output = repo.run(&["adopt", "--json"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let json = stdout(&output);
    let golden = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/auditor/adopt.json");
    let expected = fs::read_to_string(&golden).unwrap_or_default();
    assert_eq!(
        json,
        expected,
        "adopt --json drifted from {}; actual:\n{json}",
        golden.display()
    );
    let value: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(value["schema"], 1);
    assert_eq!(value["apply"], LATER);
}

#[test]
fn a_second_adopt_on_an_adopted_repository_plans_nothing_and_lists_open_proposals() {
    let repo = Repo::personal().with_collisions();
    let planned: Value = serde_json::from_str(&stdout(&repo.run(&["adopt", "--json"]))).unwrap();
    let mut install = vec!["install", "--apply"];
    for module in planned["modules"].as_array().unwrap() {
        install.extend(["--module", module.as_str().unwrap()]);
    }
    let installed = repo.run(&install);
    assert!(installed.status.success(), "{installed:?}");
    let before = repo.tree();
    let output = repo.run(&["adopt"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let text = stdout(&output);
    let lines = plan_lines(&output);
    assert!(
        lines
            .iter()
            .all(|l| l.starts_with("STEP ") || l.starts_with("PROPOSE ")),
        "an adopted repository plans nothing:\n{text}"
    );
    assert!(text.contains("PROPOSE .github/dependabot.yml: "), "{text}");
    // A seed the install wrote is in place, not an open proposal.
    assert!(
        !text.contains("PROPOSE .agent-setup/service.yaml"),
        "{text}"
    );
    assert!(text.ends_with("No changes.\n"), "{text}");
    assert_eq!(repo.tree(), before);
}
