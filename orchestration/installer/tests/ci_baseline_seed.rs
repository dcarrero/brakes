//! ci-baseline `workflow: seed` (#21, part of #19; decision 2026-11-02): the
//! project's CI is a seed written once and owned by the project, one job per
//! declared command, the test job uploading coverage with its stack pack's
//! recipe (#20), and the aggregate `required`; the brakes' own workflow,
//! `agentic-security.yml`, only judges and reports through `agentic-required`.
use serde_json::{Value, json};
use std::{fs, path::PathBuf, process::Command};
use tempfile::TempDir;

const SEED: &str = ".github/workflows/ci.yml";
const JUDGES: &str = ".github/workflows/agentic-security.yml";
const GOLDENS: &str = "../../templates/ci-baseline/goldens/seed";

struct Repo {
    _temp: TempDir,
    root: PathBuf,
}

impl Repo {
    /// A personal repository with `commands` declared and one app at the root.
    fn new(stack: &str, commands: Value) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("project");
        fs::create_dir(&root).unwrap();
        assert!(
            Command::new("git")
                .args(["init", "-q"])
                .arg(&root)
                .status()
                .unwrap()
                .success()
        );
        let repo = Self { _temp: temp, root };
        let result = repo.cli(&["install", "<repo>", "--new-personal", "--apply"]);
        assert!(result.status.success(), "{result:?}");
        let path = repo.root.join(".agent-setup/project.json");
        let mut profile: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        for (name, command) in commands.as_object().unwrap() {
            profile["commands"][name] = command.clone();
        }
        fs::write(
            &path,
            serde_json::to_string_pretty(&profile).unwrap() + "\n",
        )
        .unwrap();
        let manifests: &[(&str, &str)] = match stack {
            "rust" => &[
                (
                    "Cargo.toml",
                    "[package]\nname = \"p\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
                ),
                ("Cargo.lock", "version = 4\n"),
            ],
            "python-uv" => &[
                (
                    "pyproject.toml",
                    "[project]\nname = \"p\"\nversion = \"0.1.0\"\n",
                ),
                ("uv.lock", "version = 1\n"),
            ],
            "go" => &[
                ("go.mod", "module example.test/p\n\ngo 1.24\n"),
                ("go.sum", ""),
            ],
            _ => &[],
        };
        for (file, text) in manifests {
            repo.write(file, text);
        }
        repo.answers(
            "stack-packs",
            json!({
                "apps.root.path": ".",
                "apps.root.stack": stack,
                "apps.root.container": false,
                "apps.root.toolchain": false,
            }),
        );
        repo
    }

    /// Records `module`'s answers as `configure` would.
    fn answers(&self, module: &str, raw: Value) -> &Self {
        let path = self
            .root
            .join(format!(".agent-setup/modules/{module}.json"));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let file = json!({"module": module, "version": "1.0.0", "answers": raw});
        fs::write(path, serde_json::to_string_pretty(&file).unwrap()).unwrap();
        self
    }

    fn write(&self, path: &str, text: &str) -> &Self {
        let full = self.root.join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, text).unwrap();
        self
    }

    fn read(&self, path: &str) -> Option<String> {
        fs::read_to_string(self.root.join(path)).ok()
    }

    fn cli(&self, args: &[&str]) -> std::process::Output {
        let root = self.root.to_string_lossy().into_owned();
        Command::new(env!("CARGO_BIN_EXE_brakes"))
            .args(
                args.iter()
                    .map(|a| if *a == "<repo>" { root.as_str() } else { a }),
            )
            .output()
            .unwrap()
    }

    /// `install` with `modules`, applied; the standard output.
    fn install(&self, modules: &[&str], apply: bool) -> String {
        let mut args = vec!["install", "<repo>"];
        for module in modules {
            args.extend(["--module", module]);
        }
        if apply {
            args.push("--apply");
        }
        let result = self.cli(&args);
        assert!(result.status.success(), "{result:?}");
        String::from_utf8_lossy(&result.stdout).into_owned()
    }
}

fn golden(name: &str, text: &str) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(GOLDENS)
        .join(name);
    if std::env::var_os("UPDATE_GOLDENS").is_some() {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, text).unwrap();
    }
    let expected = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}; run with UPDATE_GOLDENS=1", path.display()));
    assert!(text == expected, "{name} differs from the golden:\n{text}");
}

const RUST: &[(&str, &str)] = &[
    ("test", "cargo test --locked"),
    ("lint", "cargo clippy --locked -- -D warnings"),
    ("build", "cargo build --locked"),
];

fn rust_repo() -> Repo {
    Repo::new(
        "rust",
        Value::Object(
            RUST.iter()
                .map(|(k, v)| ((*k).to_owned(), json!(v)))
                .collect(),
        ),
    )
}

#[test]
fn a_fresh_install_seeds_the_project_ci_and_renders_only_the_judges() {
    let repo = rust_repo();
    let out = repo.install(&["stack-packs", "ci-baseline"], true);
    assert!(
        out.lines()
            .any(|l| l == format!("WRITE {SEED} [seed:ci-baseline]")),
        "{out}"
    );
    assert!(
        out.lines()
            .any(|l| l == format!("WRITE {JUDGES} [managed:ci-baseline]")),
        "{out}"
    );
    let seed = repo.read(SEED).unwrap();
    golden("seed-rust.yml", &seed);
    for job in ["  lint:", "  test:", "  build:", "  required:"] {
        assert!(seed.contains(&format!("\n{job}\n")), "{job}\n{seed}");
    }
    let judges = repo.read(JUDGES).unwrap();
    assert!(judges.contains("\n  agentic-required:\n"), "{judges}");
    assert!(judges.contains("\n  workflow-lint:\n"), "{judges}");
    // No job brakes owns runs a declared command.
    assert!(!judges.contains("Run declared"), "{judges}");
    assert!(!judges.contains(".commands[$name]"), "{judges}");
    assert!(!judges.contains("\n  checks:\n"), "{judges}");
}

#[test]
fn a_second_plan_skips_the_seed_and_keeps_the_projects_edit() {
    let repo = rust_repo();
    repo.install(&["stack-packs", "ci-baseline"], true);
    let edited = format!("{}# the project's own line\n", repo.read(SEED).unwrap());
    repo.write(SEED, &edited);
    let out = repo.install(&[], true);
    assert!(
        out.lines()
            .any(|l| l == format!("SKIP {SEED} [seed:ci-baseline]")),
        "{out}"
    );
    assert_eq!(repo.read(SEED).unwrap(), edited);
    let lock: Value = serde_json::from_str(&repo.read(".agent-setup/lock.json").unwrap()).unwrap();
    assert_eq!(lock["files"][SEED]["class"], "seed", "{lock}");
}

#[test]
fn with_security_the_test_job_uploads_coverage_and_the_seed_calls_the_judge() {
    let repo = rust_repo();
    repo.install(&["stack-packs", "security", "ci-baseline"], true);
    let seed = repo.read(SEED).unwrap();
    golden("seed-rust-security.yml", &seed);
    assert!(seed.contains("name: agentic-coverage-root-test"), "{seed}");
    assert!(
        seed.contains(
            "  diff-coverage:\n    name: diff-coverage\n    needs: test\n    uses: ./.github/workflows/agentic-coverage.yml\n"
        ),
        "{seed}"
    );
    assert!(
        seed.contains("    needs: [lint, test, build, diff-coverage]\n    if: always()\n"),
        "{seed}"
    );
}

#[test]
fn under_the_seed_the_coverage_note_says_the_seed_already_uploads_and_calls_the_judge() {
    // #26: the seed writes the upload and the diff-coverage call itself, so the plan
    // does not ask the project to add them; it names how to audit a ci.yml that predates them.
    let repo = rust_repo();
    let plan = repo.install(&["stack-packs", "security", "ci-baseline"], false);
    assert!(
        plan.lines().any(|l| l
            == "NOTE [security] diff-coverage: the seed .github/workflows/ci.yml uploads agentic-coverage-root-<job> from the test job of root and calls .github/workflows/agentic-coverage.yml; for a ci.yml written before, `brakes doctor . --propose` shows what is missing"),
        "{plan}"
    );
    assert!(
        !plan.contains("call .github/workflows/agentic-coverage.yml from a job named"),
        "{plan}"
    );
}

#[test]
fn a_python_root_runs_pytest_under_coverage_in_its_test_job() {
    let repo = Repo::new(
        "python-uv",
        json!({"test": "uv run pytest", "lint": "uv run ruff check"}),
    );
    repo.install(&["stack-packs", "security", "ci-baseline"], true);
    let seed = repo.read(SEED).unwrap();
    golden("seed-python-uv-security.yml", &seed);
    assert!(seed.contains("include-hidden-files: \"true\""), "{seed}");
}

#[test]
fn a_pack_without_coverage_runs_the_declared_test_and_says_why() {
    let repo = Repo::new("go", json!({"test": "go test ./..."}));
    repo.install(&["stack-packs", "security", "ci-baseline"], true);
    let seed = repo.read(SEED).unwrap();
    assert!(
        seed.contains("# root (go): no coverage upload: `go test -coverprofile`"),
        "{seed}"
    );
    assert!(seed.contains("Run declared test"), "{seed}");
    assert!(!seed.contains("\n  diff-coverage:\n"), "{seed}");
}

#[test]
fn the_ruleset_requires_the_seeds_required_and_agentic_required() {
    let repo = rust_repo();
    repo.install(&["stack-packs", "repo-baseline", "ci-baseline"], true);
    let ruleset: Value =
        serde_json::from_str(&repo.read(".github/rulesets/main.json").unwrap()).unwrap();
    let contexts: Vec<&str> = ruleset["rules"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["type"] == "required_status_checks")
        .flat_map(|r| {
            r["parameters"]["required_status_checks"]
                .as_array()
                .unwrap()
        })
        .map(|c| c["context"].as_str().unwrap())
        .collect();
    assert_eq!(contexts, ["required", "agentic-required"], "{ruleset}");
}

/// A monorepo: each app's commands run in its own jobs, in its directory, from
/// its own profile, and each app's test job uploads its own coverage.
#[test]
fn a_monorepo_seeds_jobs_per_app_in_its_directory() {
    let repo = rust_repo();
    repo.write(
        "api/Cargo.toml",
        "[package]\nname = \"api\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    );
    repo.write("api/Cargo.lock", "version = 4\n");
    repo.write(
        "api/.agent-setup/project.json",
        r#"{"commands": {"test": "cargo test --locked"}}"#,
    );
    repo.answers(
        "stack-packs",
        json!({
            "apps.root.path": ".", "apps.root.stack": "rust",
            "apps.root.container": false, "apps.root.toolchain": false,
            "apps.api.path": "api", "apps.api.stack": "rust",
            "apps.api.container": false, "apps.api.toolchain": false,
        }),
    );
    repo.install(&["stack-packs", "security", "ci-baseline"], true);
    let seed = repo.read(SEED).unwrap();
    for job in ["root-lint", "root-test", "root-build", "api-test"] {
        assert!(seed.contains(&format!("\n  {job}:\n")), "{job}\n{seed}");
    }
    assert!(
        seed.contains("name: agentic-coverage-api-api-test"),
        "{seed}"
    );
    assert!(seed.contains("path: api/lcov.info"), "{seed}");
    assert!(seed.contains("working-directory: api"), "{seed}");
    assert!(
        seed.contains("    needs: [api-test, root-test]\n"),
        "{seed}"
    );
    assert!(!seed.contains("working-directory: \".\""), "{seed}");
}

/// The seed checks no label: `agentic-required` alone keeps `human-approved` on
/// protected paths, so it renders and is required even with nothing to judge.
#[test]
fn without_held_out_tests_or_contributors_the_judges_still_guard_protected_paths() {
    let repo = rust_repo();
    repo.answers("ci-baseline", json!({"heldout": false}));
    repo.install(&["stack-packs", "repo-baseline", "ci-baseline"], true);
    let judges = repo.read(JUDGES).unwrap();
    assert!(judges.contains("PROTECTED_PATHS"), "{judges}");
    assert!(judges.contains("\n  agentic-required:\n"), "{judges}");
    let ruleset = repo.read(".github/rulesets/main.json").unwrap();
    assert!(ruleset.contains("\"agentic-required\""), "{ruleset}");
}

#[test]
fn a_repository_with_workflows_of_its_own_gets_no_seed_and_a_note() {
    let repo = rust_repo();
    repo.write(
        ".github/workflows/tests.yml",
        "name: tests\non: pull_request\njobs: {}\n",
    );
    let out = repo.install(&["stack-packs", "ci-baseline"], true);
    assert!(repo.read(SEED).is_none(), "{out}");
    assert!(
        out.contains(
            "NOTE [ci-baseline] workflow seed writes no .github/workflows/ci.yml: the project has workflows of its own (.github/workflows/tests.yml); answer workflow=existing"
        ),
        "{out}"
    );
}

#[test]
fn an_install_that_generated_its_workflow_keeps_generate_until_it_migrates() {
    let repo = rust_repo();
    repo.answers("ci-baseline", json!({"workflow": "generate"}));
    repo.install(&["stack-packs", "ci-baseline"], true);
    let generated = repo.read(SEED).unwrap();
    assert!(
        generated.contains("Generated by brakes ci-baseline"),
        "{generated}"
    );
    // An install from before `seed` recorded no `workflow` answer.
    repo.answers("ci-baseline", json!({}));
    let out = repo.install(&[], true);
    assert_eq!(repo.read(SEED).unwrap(), generated, "{out}");
    assert!(!out.contains(&format!("DELETE {SEED}")), "{out}");
    assert!(
        out.contains("NOTE [ci-baseline] workflow generate is deprecated"),
        "{out}"
    );
}

/// `seed-required.sh` under bash with `needs` as GitHub serialises it.
fn required(needs: &str) -> std::process::Output {
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../templates/ci-baseline/fragments/seed-required.sh");
    Command::new("bash")
        .arg(script)
        .env("NEEDS", needs)
        .output()
        .unwrap()
}

#[test]
fn the_seeds_required_passes_only_when_every_job_succeeded() {
    let ok = required(r#"{"lint":{"result":"success"},"test":{"result":"success"}}"#);
    assert!(ok.status.success(), "{ok:?}");
    for (needs, line) in [
        (
            r#"{"lint":{"result":"success"},"test":{"result":"failure"}}"#,
            "::error::required: test: failure",
        ),
        (
            r#"{"test":{"result":"skipped"}}"#,
            "::error::required: test: skipped",
        ),
        (
            r#"{"test":{"result":"cancelled"}}"#,
            "::error::required: test: cancelled",
        ),
        (
            "{}",
            "::error::required: cannot read the results of the jobs it needs",
        ),
        (
            "not json",
            "::error::required: cannot read the results of the jobs it needs",
        ),
    ] {
        let out = required(needs);
        assert!(!out.status.success(), "{needs}: {out:?}");
        assert!(
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .any(|l| l == line),
            "{needs}: {out:?}"
        );
    }
}

// --- #25: the migration from `workflow: generate` to seed + judges ---------------

const GENERATED_BESIDE: &str = ".github/workflows/agentic-ci.yml";

/// A repository installed with `workflow: generate`; `beside` puts a workflow
/// of its own first, so the generated one is `agentic-ci.yml`.
fn generated(beside: bool) -> Repo {
    let repo = rust_repo();
    if beside {
        repo.write(
            ".github/workflows/neutrality.yml",
            "name: Neutrality\non: pull_request\njobs: {}\n",
        );
    }
    repo.answers("ci-baseline", json!({"workflow": "generate"}));
    repo.install(&["stack-packs", "ci-baseline", "security"], true);
    repo
}

fn lock_class(repo: &Repo, path: &str) -> Option<String> {
    let lock: Value = serde_json::from_str(&repo.read(".agent-setup/lock.json").unwrap()).unwrap();
    lock["files"][path]["class"].as_str().map(str::to_owned)
}

/// Every workflow the lock records as `managed`: none may read a declared command.
fn managed_workflows_run_no_command(repo: &Repo) {
    let lock: Value = serde_json::from_str(&repo.read(".agent-setup/lock.json").unwrap()).unwrap();
    for (path, entry) in lock["files"].as_object().unwrap() {
        if path.starts_with(".github/workflows/") && entry["class"] == "managed" {
            let text = repo.read(path).unwrap();
            assert!(
                !text.contains(".commands") && !text.contains("commands."),
                "{path} reads a declared command:\n{text}"
            );
        }
    }
}

#[test]
fn a_generated_ci_yml_answered_seed_becomes_the_seed_and_the_judges_take_over() {
    let repo = generated(false);
    assert_eq!(lock_class(&repo, SEED).as_deref(), Some("managed"));
    repo.answers("ci-baseline", json!({"workflow": "seed"}));
    let plan = repo.install(&[], false);
    assert!(
        plan.contains(&format!("PLAN {SEED} [seed:ci-baseline]")),
        "{plan}"
    );
    // Expand before contract: the plan names the remote step to take before the merge.
    assert!(
        plan.contains("generate-to-seed — Before the pull request that moves to seed merges, the default branch requires agentic-required"),
        "{plan}"
    );
    let out = repo.install(&[], true);
    let seed = repo.read(SEED).unwrap();
    assert!(
        seed.contains("Seeded by brakes ci-baseline"),
        "{out}\n{seed}"
    );
    assert!(seed.contains("name: agentic-coverage-root-test"), "{seed}");
    assert_eq!(lock_class(&repo, SEED).as_deref(), Some("seed"));
    assert!(repo.read(JUDGES).unwrap().contains("agentic-required"));
    assert!(
        repo.read(".github/workflows/agentic-coverage.yml")
            .is_some()
    );
    managed_workflows_run_no_command(&repo);
    // From then on the seed is the project's: a later plan skips it.
    let again = repo.install(&[], false);
    assert!(
        again.contains(&format!("PLAN SKIP {SEED} [seed:ci-baseline]")),
        "{again}"
    );
    assert!(!again.contains("generate-to-seed"), "{again}");
}

#[test]
fn a_generated_ci_yml_edited_by_hand_refuses_the_migration() {
    let repo = generated(false);
    let text = repo.read(SEED).unwrap();
    repo.write(SEED, &format!("{text}# a local edit\n"));
    repo.answers("ci-baseline", json!({"workflow": "seed"}));
    let result = repo.cli(&["install", "<repo>", "--apply"]);
    assert!(!result.status.success());
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr.contains(&format!(
            "Locally changed managed content cannot become a seed: {SEED}"
        )),
        "{stderr}"
    );
    assert!(repo.read(SEED).unwrap().ends_with("# a local edit\n"));
}

#[test]
fn a_generated_agentic_ci_yml_is_retired_and_the_seed_written_beside_the_projects_workflows() {
    let repo = generated(true);
    assert_eq!(
        lock_class(&repo, GENERATED_BESIDE).as_deref(),
        Some("managed")
    );
    assert!(repo.read(SEED).is_none());
    repo.answers("ci-baseline", json!({"workflow": "seed"}));
    let plan = repo.install(&[], false);
    assert!(plan.contains("generate-to-seed"), "{plan}");
    // The switch to `existing` keeps the generated workflow; `seed` retires it in this plan.
    for step in ["existing-checks-required", "retire-generated-workflow"] {
        assert!(!plan.contains(step), "{plan}");
    }
    let out = repo.install(&[], true);
    assert!(
        out.contains(&format!("WRITE {SEED} [seed:ci-baseline]")),
        "{out}"
    );
    assert!(out.contains(&format!("DELETE {GENERATED_BESIDE}")), "{out}");
    assert!(repo.read(GENERATED_BESIDE).is_none());
    assert_eq!(
        repo.read(".github/workflows/neutrality.yml").unwrap(),
        "name: Neutrality\non: pull_request\njobs: {}\n"
    );
    assert!(!out.contains("workflow seed writes no"), "{out}");
    managed_workflows_run_no_command(&repo);
}

#[test]
fn an_edited_generated_agentic_ci_yml_refuses_its_retirement() {
    let repo = generated(true);
    let text = repo.read(GENERATED_BESIDE).unwrap();
    repo.write(GENERATED_BESIDE, &format!("{text}# a local edit\n"));
    repo.answers("ci-baseline", json!({"workflow": "seed"}));
    let result = repo.cli(&["install", "<repo>", "--apply"]);
    assert!(!result.status.success());
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr.contains(&format!(
            "Locally changed retired managed content: {GENERATED_BESIDE}"
        )),
        "{stderr}"
    );
    assert!(repo.read(SEED).is_none());
}

#[test]
fn a_ci_yml_of_the_projects_own_beside_a_generated_workflow_gets_no_seed() {
    let repo = generated(true);
    repo.write(SEED, "name: mine\non: pull_request\njobs: {}\n");
    repo.answers("ci-baseline", json!({"workflow": "seed"}));
    let result = repo.cli(&["install", "<repo>"]);
    let out = String::from_utf8_lossy(&result.stdout);
    assert!(
        out.contains("workflow seed writes no .github/workflows/ci.yml"),
        "{out}"
    );
    assert!(
        !out.contains(&format!("PLAN {SEED} [seed:ci-baseline]")),
        "{out}"
    );
}
