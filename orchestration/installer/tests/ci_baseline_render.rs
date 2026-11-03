//! ci-baseline T1 (#770; SPEC-ci-baseline.md, Answers, Composition, Interplay
//! with repo-baseline): the answers and their refusals, the runner labels the
//! renderer owns, `AGGREGATE_CHECK`, the module registration and the additive
//! `Module::ci_jobs` default.
mod configured;
mod support;
use brakes::engine::answers::{self, Answers};
use brakes::engine::{self, CiTier, Context, Lock, Module, Ownership, Rendered};
use brakes::host::desired::{Desired, Supersession};
use brakes::modules::ci_baseline::{
    self, AGGREGATE_CHECK, CiBaseline, CiBaselineAnswers, Command as Cmd, MacosRunner, Runner,
    WorkflowMode, render::runner_label, reusable, scope,
};
use brakes::modules::security::pins::{ACTIONLINT, INSTALL_TOOL};
use brakes::modules::{self, StackPacks, qa::Qa};
use brakes::{Source, profile_for};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, path::PathBuf, process::Command};
use support::SetupCore;
use tempfile::TempDir;

fn empty_lock() -> Lock {
    Lock {
        schema: 2,
        version: "test".to_owned(),
        source_commit: None,
        source_dirty: false,
        personal_owner: "example-owner".to_owned(),
        modules: Default::default(),
        files: Default::default(),
    }
}

/// stack-packs' recorded answers, validated, as the engine resolves them for a
/// plan; `qa`'s too when they are recorded (the module is then active).
fn recorded_stack_packs(root: &std::path::Path) -> BTreeMap<String, Answers> {
    let raw = answers::recorded(root, "stack-packs")
        .unwrap()
        .map(|file| file.answers)
        .unwrap_or_default();
    let validated = StackPacks
        .questions()
        .validate("stack-packs", &raw, answers::DEFAULT_TIER)
        .unwrap();
    let mut resolved = BTreeMap::from([("stack-packs".to_owned(), validated)]);
    if let Some(file) = answers::recorded(root, "qa").unwrap() {
        let qa = Qa
            .questions()
            .validate("qa", &file.answers, answers::DEFAULT_TIER)
            .unwrap();
        resolved.insert("qa".to_owned(), qa);
    }
    resolved
}

/// The note every plan under `generate` prints first (#21); `ci_baseline_seed.rs` checks it.
const DEPRECATED: &str = "workflow generate is deprecated";

/// `raw` with `workflow: generate` unless it answers `workflow`: these tests pin
/// the deprecated generated workflow, whose output must not change until it
/// migrates (#21, #25); `ci_baseline_seed.rs` covers the default `seed`.
fn generate(mut raw: Value) -> Value {
    if let Some(map) = raw.as_object_mut() {
        map.entry("workflow").or_insert_with(|| json!("generate"));
    }
    raw
}

struct Repo {
    _temp: TempDir,
    root: PathBuf,
}

impl Repo {
    /// A personal repository with `project.json` installed and the given
    /// `commands.*` declared (every other command stays `null`).
    fn with_commands(commands: Value) -> Self {
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
        // Pinned to the deprecated generated workflow, as `generate` pins the
        // in-process helpers (#21).
        let ci = repo.root.join(answers::path("ci-baseline"));
        fs::create_dir_all(ci.parent().unwrap()).unwrap();
        let file = json!({"module": "ci-baseline", "version": "1.0.0", "answers": {"workflow": "generate"}});
        fs::write(ci, serde_json::to_string_pretty(&file).unwrap()).unwrap();
        repo
    }

    fn file(&self, path: &str) -> &Self {
        let full = self.root.join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, "").unwrap();
        self
    }

    /// Records stack-packs answers as `configure stack-packs` would.
    fn stack_packs(&self, raw: Value) -> &Self {
        let path = self.root.join(answers::path("stack-packs"));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let file = json!({"module": "stack-packs", "version": "1.0.0", "answers": raw});
        fs::write(path, serde_json::to_string_pretty(&file).unwrap()).unwrap();
        self
    }

    /// Records qa answers as `configure qa` would: the module is then active.
    fn qa(&self, raw: Value) -> &Self {
        let path = self.root.join(answers::path("qa"));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let file = json!({"module": "qa", "version": "1.0.0", "answers": raw});
        fs::write(path, serde_json::to_string_pretty(&file).unwrap()).unwrap();
        self
    }

    /// The loaded answers for `raw`, as `render` sees them.
    fn load(&self, raw: Value) -> brakes::Result<CiBaselineAnswers> {
        let raw: Answers = serde_json::from_value(generate(raw)).unwrap();
        let validated =
            CiBaseline
                .questions()
                .validate("ci-baseline", &raw, answers::DEFAULT_TIER)?;
        let profile = profile_for(&self.root)?;
        let source = Source::embedded();
        let previous = empty_lock();
        let resolved = recorded_stack_packs(&self.root);
        let cx = Context::new(
            &self.root,
            &profile,
            &source,
            &previous,
            &validated,
            &CiBaseline,
            &resolved,
        );
        CiBaselineAnswers::load(&cx)
    }

    /// What `CiBaseline::render` returns for `raw`, with stack-packs' recorded answers.
    fn render(&self, raw: Value) -> brakes::Result<Vec<Rendered>> {
        let raw: Answers = serde_json::from_value(generate(raw)).unwrap();
        let validated =
            CiBaseline
                .questions()
                .validate("ci-baseline", &raw, answers::DEFAULT_TIER)?;
        let profile = profile_for(&self.root)?;
        let source = Source::embedded();
        let previous = empty_lock();
        let resolved = recorded_stack_packs(&self.root);
        let cx = Context::new(
            &self.root,
            &profile,
            &source,
            &previous,
            &validated,
            &CiBaseline,
            &resolved,
        );
        CiBaseline.render(&cx)
    }

    /// What `CiBaseline::notes` returns for `raw`.
    fn notes(&self, raw: Value) -> Vec<String> {
        let raw: Answers = serde_json::from_value(generate(raw)).unwrap();
        let validated = CiBaseline
            .questions()
            .validate("ci-baseline", &raw, answers::DEFAULT_TIER)
            .unwrap();
        let profile = profile_for(&self.root).unwrap();
        let source = Source::embedded();
        let previous = empty_lock();
        let resolved = recorded_stack_packs(&self.root);
        let cx = Context::new(
            &self.root,
            &profile,
            &source,
            &previous,
            &validated,
            &CiBaseline,
            &resolved,
        );
        CiBaseline
            .notes(&cx)
            .unwrap()
            .into_iter()
            .filter(|n| !n.starts_with(DEPRECATED))
            .collect()
    }

    /// The rendered text at `path`, which must be a `managed` file.
    fn rendered(&self, raw: Value, path: &str) -> Option<String> {
        let rendered = self.render(raw).unwrap();
        let item = rendered.into_iter().find(|r| r.path == path)?;
        assert_eq!(item.class, Ownership::Managed);
        assert_eq!(item.scaffold, None);
        item.content
    }

    /// The rendered workflow text.
    fn workflow(&self, raw: Value) -> String {
        self.rendered(raw, ".github/workflows/ci.yml").unwrap()
    }

    /// Sets `ci.<key>` in `project.json`.
    fn ci(&self, key: &str, value: Value) -> &Self {
        let path = self.root.join(".agent-setup/project.json");
        let mut profile: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        if !profile["ci"].is_object() {
            profile["ci"] = json!({});
        }
        profile["ci"][key] = value;
        fs::write(
            &path,
            serde_json::to_string_pretty(&profile).unwrap() + "\n",
        )
        .unwrap();
        self
    }

    fn refusal(&self, raw: Value) -> String {
        self.load(raw).unwrap_err().to_string()
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
}

#[test]
fn the_aggregate_check_is_required() {
    assert_eq!(AGGREGATE_CHECK, "required");
}

#[test]
fn defaults_follow_the_answer_table() {
    let repo = Repo::with_commands(json!({"test": "cargo test", "lint": "cargo clippy"}));
    let answers = repo.load(json!({})).unwrap();
    assert_eq!(
        answers,
        CiBaselineAnswers {
            workflow: WorkflowMode::Generate,
            aggregate_check: AGGREGATE_CHECK.to_owned(),
            commands: vec![Cmd::Lint, Cmd::Test],
            runner: Runner::Configured,
            tiers: true,
            inert_paths: scope::DEFAULT_INERT_PATHS
                .iter()
                .map(|p| (*p).to_owned())
                .collect(),
            macos: false,
            macos_runner: None,
            merge_queue: false,
            minutes_budget: 2000,
            protected_paths: scope::DEFAULT_PROTECTED_PATHS
                .iter()
                .map(|p| (*p).to_owned())
                .collect(),
            heldout_dir: ci_baseline::DEFAULT_HELDOUT_DIR.to_owned(),
            // #1362: on by default when generating, pending without a command.
            heldout: true,
            heldout_command: None,
            heldout_properties_command: None,
            heldout_examples: 200,
            apps: Vec::new(),
            macos_apps: Vec::new(),
            root_commands: None,
            reusable_sha: None,
        }
    );
}

#[test]
fn commands_derive_lint_test_build_and_verify_only_when_test_is_null() {
    let repo = Repo::with_commands(json!({
        "lint": "make lint", "test": "make test", "verify": "make verify", "build": "make build",
    }));
    assert_eq!(
        repo.load(json!({})).unwrap().commands,
        [Cmd::Lint, Cmd::Test, Cmd::Build]
    );
    let repo = Repo::with_commands(json!({"verify": "make verify"}));
    assert_eq!(repo.load(json!({})).unwrap().commands, [Cmd::Verify]);
}

#[test]
fn an_answered_command_list_wins_over_the_derivation() {
    let repo = Repo::with_commands(json!({"lint": "make lint", "test": "make test"}));
    let answers = repo.load(json!({"commands": ["test", "lint"]})).unwrap();
    assert_eq!(answers.commands, [Cmd::Test, Cmd::Lint]);
}

#[test]
fn an_empty_commands_derivation_refuses() {
    let repo = Repo::with_commands(json!({}));
    assert_eq!(
        repo.refusal(json!({})),
        "ci-baseline: no verification command to run; declare commands.verify or commands.test in .agent-setup/project.json"
    );
}

#[test]
fn workflow_existing_renders_nothing_and_needs_no_command() {
    let repo = Repo::with_commands(json!({}));
    let answers = repo
        .load(json!({"workflow": "existing", "aggregate_check": "Rust (linux)"}))
        .unwrap();
    assert_eq!(answers.workflow, WorkflowMode::Existing);
    assert_eq!(answers.aggregate_check, "Rust (linux)");
    assert!(answers.commands.is_empty());
}

#[test]
fn workflow_existing_without_an_answer_keeps_required() {
    let repo = Repo::with_commands(json!({}));
    let answers = repo.load(json!({"workflow": "existing"})).unwrap();
    assert_eq!(answers.aggregate_check, AGGREGATE_CHECK);
}

#[test]
fn aggregate_check_given_with_workflow_generate_is_dropped() {
    let repo = Repo::with_commands(json!({"test": "make test"}));
    let answers = repo
        .load(json!({"workflow": "generate", "aggregate_check": "Rust (linux)"}))
        .unwrap();
    assert_eq!(answers.aggregate_check, AGGREGATE_CHECK);
}

#[test]
fn configure_drops_aggregate_check_under_generate_and_records_required() {
    let repo = Repo::with_commands(json!({"test": "make test"}));
    repo.file("Cargo.toml").file("Cargo.lock");
    let result = repo.cli(&[
        "configure",
        "<repo>",
        "stack-packs",
        "--set",
        "apps.root.path=.",
        "--set",
        "apps.root.stack=rust",
        "--apply",
    ]);
    assert!(result.status.success(), "{result:?}");
    let result = repo.cli(&[
        "configure",
        "<repo>",
        "ci-baseline",
        "--set",
        "aggregate_check=Rust (linux)",
        "--apply",
    ]);
    assert!(result.status.success(), "{result:?}");
    let text = fs::read_to_string(repo.root.join(answers::path("ci-baseline"))).unwrap();
    let file: Value = serde_json::from_str(&text).unwrap();
    assert!(file["answers"].get("aggregate_check").is_none(), "{text}");
    assert_eq!(file["answers"]["workflow"], json!("generate"));
    let recorded: Value = file["answers"].clone();
    assert_eq!(repo.load(recorded).unwrap().aggregate_check, "required");
}

#[test]
fn runner_outside_the_enum_refuses() {
    let repo = Repo::with_commands(json!({"test": "make test"}));
    for label in [
        "self-hosted".to_owned(),
        configured::linux_runner().label,
        "ubuntu-24.04".to_owned(),
        "macos-14".to_owned(),
    ] {
        let refusal = repo.refusal(json!({"runner": label}));
        assert!(
            refusal.starts_with("Module ci-baseline: answer `runner`"),
            "{label}: {refusal}"
        );
    }
}

#[test]
fn macos_runner_outside_the_enum_refuses() {
    let repo = Repo::with_commands(json!({"test": "make test"}));
    let refusal = repo.refusal(json!({"macos": true, "macos_runner": "self-hosted"}));
    assert!(
        refusal.starts_with("Module ci-baseline: answer `macos_runner`"),
        "{refusal}"
    );
}

#[test]
fn only_two_runner_labels_render() {
    let labels: Vec<(Runner, &str)> = Runner::ALL.iter().map(|r| (*r, runner_label(*r))).collect();
    let label = configured::linux_runner().label;
    assert_eq!(
        labels,
        [
            (Runner::Configured, label.as_str()),
            (Runner::Github, "ubuntu-24.04")
        ]
    );
    let repo = Repo::with_commands(json!({"test": "make test"}));
    assert_eq!(
        repo.load(json!({"runner": "github"})).unwrap().runner,
        Runner::Github
    );
}

#[test]
fn macos_refuses_when_no_pack_declares_a_macos_target() {
    let repo = Repo::with_commands(json!({"test": "make test"}));
    repo.file("Cargo.toml").file("Cargo.lock");
    repo.stack_packs(json!({"apps.root.path": ".", "apps.root.stack": "rust"}));
    assert_eq!(
        repo.refusal(json!({"macos": true})),
        "ci-baseline: macos is true but no stack pack declares a macOS target; record a swift-ios app in stack-packs or set macos=false"
    );
    let repo = Repo::with_commands(json!({"test": "make test"}));
    assert_eq!(
        repo.refusal(json!({"macos": true})),
        "ci-baseline: macos is true but no stack pack declares a macOS target; record a swift-ios app in stack-packs or set macos=false"
    );
}

#[test]
fn macos_is_accepted_with_a_macos_capable_pack_and_defaults_to_the_configured_runner() {
    let repo = Repo::with_commands(json!({"test": "make test"}));
    repo.file("ios/Package.swift").write(
        "ios/.agent-setup/project.json",
        r#"{"commands": {"test": "swift test"}}"#,
    );
    repo.stack_packs(json!({
        "apps.ios.path": "ios", "apps.ios.stack": "swift-ios", "apps.ios.force": true,
    }));
    let answers = repo.load(json!({"macos": true})).unwrap();
    assert!(answers.macos);
    assert_eq!(answers.macos_runner, Some(MacosRunner::Configured));
}

#[test]
fn the_module_is_registered_last_and_requires_stack_packs() {
    let ids: Vec<&str> = modules::all().iter().map(|m| m.id()).collect();
    assert_eq!(ids.last(), Some(&"ci-baseline"));
    assert_eq!(CiBaseline.id(), ci_baseline::CI_BASELINE);
    assert_eq!(CiBaseline.version(), "1.0.0");
    assert_eq!(CiBaseline.requires(), ["stack-packs"]);
}

#[test]
fn ci_jobs_defaults_to_none_for_modules_that_contribute_nothing() {
    let repo = Repo::with_commands(json!({"test": "make test"}));
    let profile = profile_for(&repo.root).unwrap();
    let source = Source::embedded();
    let previous = empty_lock();
    let answers = Answers::new();
    let resolved = Default::default();
    let cx = Context::new(
        &repo.root,
        &profile,
        &source,
        &previous,
        &answers,
        &CiBaseline,
        &resolved,
    );
    assert!(SetupCore.ci_jobs(&cx).is_empty());
    assert!(StackPacks.ci_jobs(&cx).is_empty());
    assert!(CiBaseline.ci_jobs(&cx).is_empty());
}

#[test]
fn tiers_spell_as_the_scope_job_prints_them() {
    assert_eq!(CiTier::Full.as_str(), scope::TIER_FULL);
    assert_eq!(CiTier::Docs.as_str(), scope::TIER_DOCS);
}

// ---- T4 (#774): the rendered workflow and its goldens ----

const GOLDENS: &str = "../../templates/ci-baseline/goldens";

/// Compares `text` with the golden byte for byte; `UPDATE_GOLDENS=1` rewrites it.
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

/// The goldens of `workflow: generate`; `existing-*.yml` is the separate
/// `agentic-security.yml` and is checked by its own tests.
fn every_golden() -> Vec<(String, String)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(GOLDENS);
    let mut out: Vec<(String, String)> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "yml"))
        .filter(|p| {
            !p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("existing-")
        })
        .map(|p| {
            (
                p.file_name().unwrap().to_string_lossy().into_owned(),
                fs::read_to_string(&p).unwrap(),
            )
        })
        .collect();
    out.sort();
    out
}

/// A rust repository at `.` with lint, test and build declared.
fn rust_repo(test: &str) -> Repo {
    let repo = Repo::with_commands(json!({
        "lint": "cargo clippy --workspace --all-targets --locked -- -D warnings",
        "test": test,
        "build": "cargo build --locked",
    }));
    repo.file("Cargo.toml").file("Cargo.lock");
    repo.stack_packs(json!({"apps.root.path": ".", "apps.root.stack": "rust"}));
    repo
}

#[test]
fn single_repository_workflow_matches_the_golden() {
    let repo = rust_repo("cargo test --locked");
    golden("single.yml", &repo.workflow(json!({})));
}

#[test]
fn sharded_workflow_matches_the_golden() {
    let repo = rust_repo("cargo nextest run --locked");
    repo.ci(
        "shards",
        json!({"count": 4, "command": "cargo nextest run --locked --partition count:<i>/4"}),
    )
    .ci("cycle_budget_minutes", json!(12));
    golden("sharded.yml", &repo.workflow(json!({})));
}

#[test]
fn two_renders_are_identical() {
    let repo = rust_repo("cargo test --locked");
    assert_eq!(repo.workflow(json!({})), repo.workflow(json!({})));
}

#[test]
fn the_goldens_exist() {
    let names: Vec<String> = every_golden().into_iter().map(|(n, _)| n).collect();
    assert_eq!(
        names,
        [
            "brownfield.yml",
            "caller.yml",
            "heldout-properties-python-uv.yml",
            "heldout-properties-rust.yml",
            "heldout.yml",
            "macos.yml",
            "monorepo.yml",
            "qa-web.yml",
            "sharded.yml",
            "single.yml"
        ]
    );
}

#[test]
fn every_uses_in_a_golden_is_pinned_by_a_40_hex_sha() {
    for (name, text) in every_golden() {
        for line in text.lines().filter(|l| l.contains("uses:")) {
            let spec = line.split("uses:").nth(1).unwrap().trim();
            let (action, rest) = spec
                .split_once('@')
                .unwrap_or_else(|| panic!("{name}: {line}"));
            let sha = rest.split_whitespace().next().unwrap_or("");
            assert!(!action.is_empty(), "{name}: {line}");
            assert!(
                sha.len() == 40
                    && sha
                        .chars()
                        .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
                "{name}: unpinned {line}"
            );
            // An action names the version its SHA was recorded at; the reusable
            // callee (#785) is a commit of this repository, which has no tag.
            if !action.ends_with("/.github/workflows/_reusable-verify.yml") {
                assert!(rest.contains(" # "), "{name}: no version comment in {line}");
            }
        }
    }
}

#[test]
fn no_golden_carries_a_forbidden_construct() {
    for (name, text) in every_golden() {
        for forbidden in [
            "self-hosted",
            "pull_request_target",
            "continue-on-error",
            "|| true",
            "grep -v",
        ] {
            assert!(!text.contains(forbidden), "{name} contains {forbidden}");
        }
    }
}

/// The job blocks of a golden: id -> its lines.
fn jobs(text: &str) -> Vec<(String, Vec<String>)> {
    let body = text.split_once("\njobs:\n").unwrap().1;
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    for line in body.lines() {
        if let Some(id) = line.strip_prefix("  ").filter(|l| !l.starts_with(' ')) {
            out.push((id.trim_end_matches(':').to_owned(), Vec::new()));
        } else {
            out.last_mut().unwrap().1.push(line.to_owned());
        }
    }
    out
}

#[test]
fn every_job_is_hardened() {
    for (name, text) in every_golden() {
        assert!(
            text.contains("\npermissions:\n  contents: read\n"),
            "{name}"
        );
        assert!(
            text.contains("  cancel-in-progress: ${{ github.event_name == 'pull_request' }}\n"),
            "{name}"
        );
        let jobs = jobs(&text);
        assert!(jobs.len() >= 4, "{name}: {jobs:?}");
        for (id, lines) in &jobs {
            // A job that calls the reusable workflow (#785) has no runner, timeout
            // or steps of its own: the callee owns them (it is checked by
            // `the_reusable_callee_is_its_render` and its own timeout).
            if lines.iter().any(|l| l.starts_with("    uses: ")) {
                assert!(
                    !lines.iter().any(|l| l.starts_with("    runs-on:")
                        || l.starts_with("    steps:")
                        || l.contains("permissions")),
                    "{name}: calling job {id} has a body of its own"
                );
                continue;
            }
            let field = |key: &str| {
                lines
                    .iter()
                    .find_map(|l| l.strip_prefix(&format!("    {key}: ")))
                    .unwrap_or_else(|| panic!("{name}: job {id} has no {key}"))
                    .to_owned()
            };
            // The macOS job alone leaves Linux: the configured macOS runner,
            // pushes only (#784).
            let runner = if id == "macos" {
                configured::macos_runner().label
            } else {
                configured::linux_runner().label
            };
            assert_eq!(field("runs-on"), runner, "{name}: {id}");
            let timeout: u32 = field("timeout-minutes").parse().unwrap();
            // The pending held-out job only lists a directory (#1362).
            let pending = lines
                .iter()
                .any(|l| l.contains("Check held-out tests are pending"));
            let expected = match (name.as_str(), id.as_str()) {
                (_, "scope" | "workflow-lint" | "required") => 5,
                (_, "heldout") if pending => 5,
                (_, "macos") => 40,
                (_, "heldout-properties") => 20,
                ("sharded.yml", _) => 18,
                _ => 15,
            };
            assert_eq!(timeout, expected, "{name}: {id}");
            // The aggregate alone reads who added `human-approved` (#1255): exactly
            // issues and pull-requests read, nothing else; every other job keeps the
            // workflow's `contents: read`.
            let permissions = lines
                .iter()
                .position(|l| l.trim() == "permissions:")
                .map(|at| {
                    lines[at + 1..]
                        .iter()
                        .take_while(|l| l.starts_with("      "))
                        .map(|l| l.trim().to_owned())
                        .collect::<Vec<_>>()
                });
            if id == "required" || id == "agentic-required" {
                assert_eq!(
                    permissions,
                    Some(vec![
                        "issues: read".to_owned(),
                        "pull-requests: read".to_owned()
                    ]),
                    "{name}: job {id} reads the issue events and nothing more"
                );
                assert_eq!(
                    lines.iter().filter(|l| l.contains("permissions")).count(),
                    1,
                    "{name}: job {id}"
                );
            } else {
                assert!(
                    !lines.iter().any(|l| l.contains("permissions")),
                    "{name}: job {id} widens permissions"
                );
            }
            let checkouts = lines
                .iter()
                .filter(|l| l.contains("uses: actions/checkout@"))
                .count();
            let unpersisted = lines
                .iter()
                .filter(|l| l.trim() == "persist-credentials: \"false\"")
                .count();
            assert_eq!(checkouts, unpersisted, "{name}: job {id}");
        }
        let (_, required) = jobs.iter().find(|(id, _)| id == "required").unwrap();
        let needs: Vec<&str> = jobs
            .iter()
            .map(|(id, _)| id.as_str())
            .filter(|id| *id != "required")
            .collect();
        assert!(
            required.contains(&format!("    needs: [{}]", needs.join(", "))),
            "{name}: required needs {needs:?}"
        );
        assert!(required.contains(&"    if: always()".to_owned()), "{name}");
    }
}

#[test]
fn untrusted_values_reach_shell_only_through_env() {
    for (name, text) in every_golden() {
        let mut in_run = false;
        for line in text.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("run: |") {
                in_run = true;
                continue;
            }
            if in_run && !line.starts_with("          ") && !line.is_empty() {
                in_run = false;
            }
            if in_run {
                assert!(
                    !line.contains("${{"),
                    "{name}: expression inside run: {line}"
                );
            }
        }
    }
}

#[test]
fn the_sharded_golden_runs_lint_and_a_fail_slow_matrix() {
    let text = every_golden()
        .into_iter()
        .find(|(n, _)| n == "sharded.yml")
        .unwrap()
        .1;
    let ids: Vec<String> = jobs(&text).into_iter().map(|(id, _)| id).collect();
    assert_eq!(
        ids,
        [
            "scope",
            "lint",
            "shard",
            "heldout",
            "workflow-lint",
            "required"
        ]
    );
    assert!(text.contains("      fail-fast: false\n"));
    assert!(text.contains("        shard: [1, 2, 3, 4]\n"));
    assert!(text.contains("    name: \"shard ${{ matrix.shard }}/4\"\n"));
    assert!(
        !text.contains("NAME: test"),
        "shards replace the declared test"
    );
    assert!(text.contains("NAME: build"));
    assert!(text.contains("DOCS_SKIPPABLE: |-\n            lint\n            shard\n"));
}

#[test]
fn the_single_golden_runs_every_declared_command_in_one_job() {
    let text = every_golden()
        .into_iter()
        .find(|(n, _)| n == "single.yml")
        .unwrap()
        .1;
    let ids: Vec<String> = jobs(&text).into_iter().map(|(id, _)| id).collect();
    assert_eq!(
        ids,
        ["scope", "checks", "heldout", "workflow-lint", "required"]
    );
    let names: Vec<&str> = text
        .lines()
        .filter_map(|l| l.trim().strip_prefix("- name: Run declared "))
        .collect();
    assert_eq!(names, ["lint", "test", "build"]);
    assert!(
        text.contains("uses: dtolnay/rust-toolchain@"),
        "ci_setup steps of the pack"
    );
    assert!(text.contains("persona: regular"));
    assert!(text.contains("min-severity: medium"));
    assert!(text.contains("advanced-security: \"false\""));
    assert!(text.contains("\n  push:\n    branches: [main]\n  workflow_dispatch:\n"));
    assert!(!text.contains("merge_group"));
}

#[test]
fn no_sha_literal_in_the_ci_baseline_sources() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/modules/ci_baseline");
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let text = fs::read_to_string(&path).unwrap();
        let mut run = 0;
        for c in text.chars() {
            run = if c.is_ascii_hexdigit() { run + 1 } else { 0 };
            assert!(run < 40, "{} carries a SHA literal", path.display());
        }
    }
}

#[test]
fn runner_and_merge_queue_answers_reach_the_workflow() {
    let repo = rust_repo("cargo test --locked");
    let text = repo.workflow(json!({"runner": "github", "merge_queue": true}));
    assert!(!text.contains(&configured::linux_runner().label));
    // scope, checks, heldout (#1362), workflow-lint, required.
    assert_eq!(text.matches("    runs-on: ubuntu-24.04\n").count(), 5);
    assert!(text.contains("  workflow_dispatch:\n  merge_group:\npermissions:\n"));
}

/// Sets `commands.<name>` of `project.json` to `null`.
fn null_command(repo: &Repo, name: &str) {
    let path = repo.root.join(".agent-setup/project.json");
    let mut profile: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    profile["commands"][name] = Value::Null;
    fs::write(&path, serde_json::to_string_pretty(&profile).unwrap()).unwrap();
}

const TEST_NULL_NOTE: &str = "Verification command missing: commands.test is null in .agent-setup/project.json; the workflow renders without its step until it is declared";

#[test]
fn an_answered_command_that_is_null_renders_without_its_step_and_notes_it() {
    let repo = rust_repo("cargo test --locked");
    null_command(&repo, "test");
    let text = repo.workflow(json!({"commands": ["lint", "test"]}));
    assert!(text.contains("- name: Run declared lint\n"));
    assert!(!text.contains("Run declared test"));
    assert!(!text.contains("NAME: test"));
    assert_eq!(
        repo.notes(json!({"commands": ["lint", "test"]})),
        [TEST_NULL_NOTE]
    );
    assert!(repo.notes(json!({"commands": ["lint"]})).is_empty());
}

#[test]
fn answered_commands_that_are_all_null_refuse() {
    let repo = rust_repo("cargo test --locked");
    null_command(&repo, "test");
    assert_eq!(
        repo.refusal(json!({"commands": ["test"]})),
        "ci-baseline: no verification command to run; declare commands.verify or commands.test in .agent-setup/project.json"
    );
}

/// The first module emitting plan notes: the line closes the CLI plan, and the
/// plan still applies.
#[test]
fn the_plan_notes_a_null_answered_command_at_the_cli() {
    let repo = rust_repo("cargo test --locked");
    null_command(&repo, "test");
    let path = repo.root.join(answers::path("ci-baseline"));
    let file = json!({"module": "ci-baseline", "version": "1.0.0", "answers": {"workflow": "generate", "commands": ["lint", "test"]}});
    fs::write(path, serde_json::to_string_pretty(&file).unwrap()).unwrap();
    let note = format!("NOTE [ci-baseline] {TEST_NULL_NOTE}");
    let result = repo.cli(&[
        "install",
        "<repo>",
        "--module",
        "stack-packs",
        "--module",
        "ci-baseline",
    ]);
    let out = String::from_utf8_lossy(&result.stdout).into_owned();
    assert!(result.status.success(), "{result:?}");
    // After every plan line, before the closing summary.
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(
        lines[lines.len() - 2..],
        [
            note.as_str(),
            "Plan only; no writes. Review before using --apply."
        ],
        "{out}"
    );
    let result = repo.cli(&[
        "install",
        "<repo>",
        "--module",
        "stack-packs",
        "--module",
        "ci-baseline",
        "--apply",
    ]);
    let out = String::from_utf8_lossy(&result.stdout).into_owned();
    assert!(result.status.success(), "{result:?}");
    assert!(out.lines().any(|l| l == note), "{out}");
    let written = fs::read_to_string(repo.root.join(".github/workflows/ci.yml")).unwrap();
    assert!(written.contains("Run declared lint") && !written.contains("Run declared test"));
}

#[test]
fn workflow_existing_renders_no_file() {
    let repo = rust_repo("cargo test --locked");
    assert!(
        repo.render(json!({"workflow": "existing"}))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn install_writes_the_managed_workflow_and_a_second_plan_has_no_changes() {
    let repo = rust_repo("cargo test --locked");
    // Rendered before the install: afterwards `ci.yml` is on disk and the
    // helper's empty lock would see it as a foreign workflow.
    let expected = repo.workflow(json!({}));
    let result = repo.cli(&[
        "install",
        "<repo>",
        "--module",
        "stack-packs",
        "--module",
        "ci-baseline",
        "--apply",
    ]);
    let out = String::from_utf8_lossy(&result.stdout).into_owned();
    assert!(result.status.success(), "{result:?}");
    for path in [".github/workflows/ci.yml", ".github/actionlint.yaml"] {
        assert!(
            out.lines()
                .any(|l| l == format!("WRITE {path} [managed:ci-baseline]")),
            "{out}"
        );
    }
    let written = fs::read_to_string(repo.root.join(".github/workflows/ci.yml")).unwrap();
    assert_eq!(written, expected);
    // #1362: the pending held-out job writes nothing under the held-out directory.
    assert!(!repo.root.join("tests/heldout").exists(), "{out}");
    let again = repo.cli(&["install", "<repo>"]);
    let out = String::from_utf8_lossy(&again.stdout).into_owned();
    assert!(again.status.success(), "{again:?}");
    assert!(out.lines().any(|l| l == "No changes."), "{out}");
}

/// The declared-command and shard fragments under bash with a real profile.
fn run_fragment(fragment: &str, profile: Value, env: &[(&str, &str)]) -> std::process::Output {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join(".agent-setup")).unwrap();
    fs::write(
        dir.path().join(".agent-setup/project.json"),
        profile.to_string(),
    )
    .unwrap();
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../templates/ci-baseline/fragments")
        .join(fragment);
    let mut command = Command::new("bash");
    command.arg(script).current_dir(dir.path());
    for (k, v) in env {
        command.env(k, v);
    }
    command.output().expect("bash and jq run the fragments")
}

#[test]
fn a_declared_command_runs_from_the_profile_and_a_missing_one_fails_red() {
    let profile = json!({"commands": {"test": "echo ran-test", "lint": null}});
    let ok = run_fragment("declared.sh", profile.clone(), &[("NAME", "test")]);
    assert!(ok.status.success(), "{ok:?}");
    assert_eq!(
        String::from_utf8_lossy(&ok.stdout),
        "test: echo ran-test\nran-test\n"
    );
    let missing = run_fragment("declared.sh", profile.clone(), &[("NAME", "lint")]);
    assert_eq!(missing.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&missing.stdout),
        "::error::Verification command missing: commands.lint is not declared in .agent-setup/project.json\n"
    );
    let failing = run_fragment(
        "declared.sh",
        json!({"commands": {"test": "false; echo unreachable"}}),
        &[("NAME", "test")],
    );
    assert!(!failing.status.success());
    assert_eq!(
        String::from_utf8_lossy(&failing.stdout),
        "test: false; echo unreachable\n",
        "the declared command stops at its first failure"
    );
}

#[test]
fn a_shard_substitutes_its_index_and_a_missing_command_fails_red() {
    let profile = json!({"ci": {"shards": {"count": 4, "command": "echo part <i> of 4"}}});
    let ok = run_fragment("shard.sh", profile, &[("SHARD", "3"), ("COUNT", "4")]);
    assert!(ok.status.success(), "{ok:?}");
    assert_eq!(
        String::from_utf8_lossy(&ok.stdout),
        "shard 3/4: echo part 3 of 4\npart 3 of 4\n"
    );
    let missing = run_fragment(
        "shard.sh",
        json!({"ci": {}}),
        &[("SHARD", "1"), ("COUNT", "4")],
    );
    assert_eq!(missing.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&missing.stdout),
        "::error::Verification command missing: ci.shards.command is not declared in .agent-setup/project.json\n"
    );
}

/// actionlint knows GitHub-hosted labels only: with the configured runner the
/// module declares the label in `.github/actionlint.yaml`; on its own it renders
/// the file for no other reason and suppresses no finding (the one ignore, for
/// `cache-mode`, appears only with a model job or `unattended`: agent_guardrails.rs,
/// #969, #970).
#[test]
fn actionlint_config_declares_the_configured_label_only_on_the_configured_runner() {
    let repo = rust_repo("cargo test --locked");
    let paths = |raw: Value| -> Vec<String> {
        repo.render(raw)
            .unwrap()
            .into_iter()
            .map(|r| r.path)
            .collect()
    };
    assert_eq!(
        paths(json!({})),
        [".github/actionlint.yaml", ".github/workflows/ci.yml"]
    );
    assert_eq!(
        paths(json!({"runner": "github"})),
        [".github/workflows/ci.yml"]
    );
    golden(
        "actionlint.yaml",
        &repo.rendered(json!({}), ".github/actionlint.yaml").unwrap(),
    );
    for (name, text) in every_golden() {
        assert!(!text.contains("-ignore"), "{name} suppresses a finding");
    }
}

/// actionlint is a checksum-pinned binary from security's pin table, installed
/// by security's fragment; no third-party wrapper action.
#[test]
fn actionlint_is_installed_from_the_security_pin_table() {
    for (name, text) in every_golden() {
        assert!(!text.contains("raven-actions"), "{name}");
        for (key, value) in ACTIONLINT.env() {
            assert!(
                text.contains(&format!("          {key}: ")) && text.contains(&value),
                "{name}: {key}={value} missing"
            );
        }
        assert!(
            text.contains(
                brakes::modules::security::embed::without_comment_lines(INSTALL_TOOL)
                    .lines()
                    .nth(1)
                    .unwrap()
            ),
            "{name}"
        );
        assert!(
            text.contains(
                "      - name: Lint workflows with actionlint\n        run: actionlint\n"
            ),
            "{name}"
        );
    }
}

// ci-baseline T5 (#775; SPEC-ci-baseline.md, Brownfield migration): foreign
// workflows, the sticky filename, the `required`-job refusal, the switch as a
// remote item (decision #848), a project-owned actionlint configuration,
// `workflow: existing` and `remove`.

/// A single-job verify workflow: one job that reads `commands.verify` with `jq`.
const VERIFY_YML: &str = "name: verify
on:
  pull_request:
  push:
    branches: [main]
jobs:
  verify:
    name: verify
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@0000000000000000000000000000000000000000 # v4
      - name: required
        run: bash -euo pipefail -c \"$(jq -r .commands.verify .agent-setup/project.json)\"
";

impl Repo {
    fn write(&self, path: &str, text: &str) -> &Self {
        let full = self.root.join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, text).unwrap();
        self
    }

    fn read(&self, path: &str) -> Option<String> {
        fs::read_to_string(self.root.join(path)).ok()
    }

    /// `install --module stack-packs --module ci-baseline` with `--apply`.
    fn install(&self) -> std::process::Output {
        self.cli(&[
            "install",
            "<repo>",
            "--module",
            "stack-packs",
            "--module",
            "ci-baseline",
            "--apply",
        ])
    }

    fn lock_entry(&self, path: &str) -> Value {
        let lock: Value =
            serde_json::from_str(&self.read(".agent-setup/lock.json").unwrap()).unwrap();
        lock["files"][path].clone()
    }
}

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// The brownfield shape: a rust repository with its own `verify.yml`.
fn brownfield_repo() -> Repo {
    let repo = rust_repo("cargo test --locked");
    repo.write(".github/workflows/verify.yml", VERIFY_YML);
    repo
}

#[test]
fn brownfield_writes_agentic_ci_protects_verify_and_declares_the_switch() {
    let repo = brownfield_repo();
    let result = repo.install();
    let out = stdout(&result);
    assert!(result.status.success(), "{result:?}");
    assert!(
        out.lines()
            .any(|l| l == "WRITE .github/workflows/agentic-ci.yml [managed:ci-baseline]"),
        "{out}"
    );
    assert!(!out.contains(".github/workflows/ci.yml"), "{out}");
    assert!(!out.contains("WRITE .github/workflows/verify.yml"), "{out}");
    assert!(
        out.lines().any(|l| l
            == "STEP [blocked:ci-baseline] switch-required-check — Remote item: the default branch requires only the required check"),
        "{out}"
    );
    assert!(
        out.lines()
            .any(|l| l
                == "STEP [unavailable:ci-baseline] check-reported — CI reports required on main"),
        "{out}"
    );
    assert_eq!(
        repo.read(".github/workflows/verify.yml").unwrap(),
        VERIFY_YML
    );
    assert_eq!(
        repo.lock_entry(".github/workflows/verify.yml"),
        json!({"module": "ci-baseline", "class": "never-touch"})
    );
    assert_eq!(
        repo.lock_entry("github:switch-required-check"),
        json!({"module": "ci-baseline", "class": "remote"})
    );
    assert!(repo.lock_entry("github:check-reported").is_null());
    let written = repo.read(".github/workflows/agentic-ci.yml").unwrap();
    assert!(written.starts_with("name: CI (brakes)\n"), "{written}");
    golden("brownfield.yml", &written);
    let again = repo.cli(&["install", "<repo>"]);
    assert!(again.status.success(), "{again:?}");
    assert!(
        stdout(&again).lines().any(|l| l == "No changes."),
        "{again:?}"
    );
}

// #1149 (decision 2026-10-30): the switch retires the old required checks with
// classic protection only when `required` runs every declared command.

impl Repo {
    /// `install` of stack-packs, ci-baseline and repo-baseline with `--apply`.
    fn install_with_ruleset(&self) {
        let result = self.cli(&[
            "install",
            "<repo>",
            "--module",
            "stack-packs",
            "--module",
            "ci-baseline",
            "--module",
            "repo-baseline",
            "--apply",
        ]);
        assert!(result.status.success(), "{result:?}");
    }

    /// What the installed repo-baseline declares about the aggregate when it
    /// retires classic protection, as `apply --remote` reads it.
    fn retire_supersession(&self) -> Supersession {
        let profile = profile_for(&self.root).unwrap();
        let lock = Lock::parse(
            &self.read(".agent-setup/lock.json").unwrap(),
            modules::core_version(),
            &|_| true,
        )
        .unwrap();
        let active: Vec<&dyn Module> = modules::all()
            .into_iter()
            .filter(|m| lock.modules.contains_key(m.id()))
            .collect();
        let writes =
            engine::remote_writes(&self.root, &Source::embedded(), &profile, &active, &lock)
                .unwrap();
        match writes
            .into_iter()
            .find(|(_, w)| w.id == "classic-protection-retire")
            .map(|(_, w)| w.desired)
        {
            Some(Desired::RetireProtection { superseded_by, .. }) => superseded_by,
            other => panic!("{other:?}"),
        }
    }

    /// Sets `commands.<name>` in `project.json`.
    fn command(&self, name: &str, command: &str) -> &Self {
        let path = self.root.join(".agent-setup/project.json");
        let mut profile: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        profile["commands"][name] = json!(command);
        fs::write(
            &path,
            serde_json::to_string_pretty(&profile).unwrap() + "\n",
        )
        .unwrap();
        self
    }
}

#[test]
fn the_aggregate_does_not_supersede_a_declared_verify_it_does_not_run() {
    let repo = brownfield_repo();
    repo.command("verify", "bash scripts/verificar.sh");
    repo.install_with_ruleset();
    assert_eq!(
        repo.retire_supersession(),
        Supersession::Short(
            "the aggregate check required does not supersede them: .github/workflows/agentic-ci.yml does not run commands.verify (bash scripts/verificar.sh); fold it in with brakes configure <repo> ci-baseline --set commands=lint,test,verify,build --apply, then merge and apply --remote again".to_owned()
        )
    );
}

#[test]
fn the_aggregate_supersedes_the_old_checks_once_it_runs_every_declared_command() {
    let repo = brownfield_repo();
    repo.command("verify", "bash scripts/verificar.sh");
    repo.install_with_ruleset();
    let result = repo.cli(&[
        "configure",
        "<repo>",
        "ci-baseline",
        "--set",
        "commands=lint,test,verify,build",
        "--apply",
    ]);
    assert!(result.status.success(), "{result:?}");
    assert_eq!(
        repo.retire_supersession(),
        Supersession::By(AGGREGATE_CHECK.to_owned())
    );
}

#[test]
fn a_declared_verify_equal_to_an_answered_command_is_run() {
    let repo = brownfield_repo();
    repo.command("verify", "cargo test --locked");
    repo.install_with_ruleset();
    assert_eq!(
        repo.retire_supersession(),
        Supersession::By(AGGREGATE_CHECK.to_owned())
    );
}

#[test]
fn without_the_switch_the_aggregate_supersedes_nothing() {
    let repo = rust_repo("cargo test --locked");
    repo.install_with_ruleset();
    assert_eq!(repo.retire_supersession(), Supersession::None);
}

#[test]
fn brownfield_differs_from_the_single_golden_only_in_its_name() {
    let single = rust_repo("cargo test --locked").workflow(json!({}));
    let repo = brownfield_repo();
    let brownfield = repo
        .rendered(json!({}), ".github/workflows/agentic-ci.yml")
        .unwrap();
    assert_eq!(
        brownfield.replacen("name: CI (brakes)\n", "name: CI\n", 1),
        single
    );
}

/// ci-baseline's manual steps and remote writes for `repo` under
/// `workflow: generate`, through the module as the engine calls it.
fn generate_steps_and_writes(
    repo: &Repo,
) -> (
    Vec<engine::ManualStep>,
    Vec<brakes::host::desired::RemoteWrite>,
) {
    let validated = CiBaseline
        .questions()
        .validate(
            "ci-baseline",
            &serde_json::from_value(generate(json!({}))).unwrap(),
            answers::DEFAULT_TIER,
        )
        .unwrap();
    let profile = profile_for(&repo.root).unwrap();
    let source = Source::embedded();
    let previous = empty_lock();
    let resolved = recorded_stack_packs(&repo.root);
    let cx = Context::new(
        &repo.root,
        &profile,
        &source,
        &previous,
        &validated,
        &CiBaseline,
        &resolved,
    );
    (
        CiBaseline.manual_steps(&cx),
        CiBaseline.remote_writes(&cx).unwrap(),
    )
}

/// #1373: a declared `ci.required_checks` that names the aggregate is the
/// post-switch state, so the switch requires the declared checks, not only
/// `required`, in its instructions, its probe and its desired state.
#[test]
fn a_declared_list_naming_the_aggregate_is_what_the_switch_requires() {
    let repo = brownfield_repo();
    repo.ci("required_checks", json!(["required", "neutrality"]));
    let (steps, writes) = generate_steps_and_writes(&repo);
    let switch = steps
        .iter()
        .find(|s| s.id == "switch-required-check")
        .unwrap();
    assert!(
        switch.instructions.contains(
            "gh api -X PATCH repos/{owner}/{repo}/branches/main/protection/required_status_checks -f 'contexts[]=required' -f 'contexts[]=neutrality'"
        ),
        "{}",
        switch.instructions
    );
    assert!(
        switch
            .instructions
            .contains("[{\"context\": \"required\"}, {\"context\": \"neutrality\"}]"),
        "{}",
        switch.instructions
    );
    match &switch.probe {
        brakes::engine::Probe::Remote { id, args } => {
            assert_eq!(id, "ruleset-required-checks");
            assert_eq!(args["checks"], json!(["required", "neutrality"]));
        }
        other => panic!("{other:?}"),
    }
    let write = writes
        .iter()
        .find(|w| w.id == "switch-required-check")
        .unwrap();
    assert_eq!(
        write.desired,
        Desired::RequiredChecks {
            branch: "main".to_owned(),
            checks: vec!["required".to_owned(), "neutrality".to_owned()],
            keep_others: false,
        }
    );
}

/// #1373: a declared list without the aggregate is what the switch
/// supersedes; the switch still requires `required` alone (#1299).
#[test]
fn a_declared_list_without_the_aggregate_leaves_the_switch_on_required_alone() {
    let repo = brownfield_repo();
    repo.ci(
        "required_checks",
        json!(["Orchestration / verify", "build"]),
    );
    let (steps, writes) = generate_steps_and_writes(&repo);
    let switch = steps
        .iter()
        .find(|s| s.id == "switch-required-check")
        .unwrap();
    match &switch.probe {
        brakes::engine::Probe::Remote { args, .. } => {
            assert_eq!(args["checks"], json!(["required"]));
        }
        other => panic!("{other:?}"),
    }
    let write = writes
        .iter()
        .find(|w| w.id == "switch-required-check")
        .unwrap();
    assert_eq!(
        write.desired,
        Desired::RequiredChecks {
            branch: "main".to_owned(),
            checks: vec!["required".to_owned()],
            keep_others: false,
        }
    );
}

#[test]
fn the_switch_instructions_are_the_exact_gh_commands() {
    let repo = brownfield_repo();
    repo.install();
    let doctor = repo.cli(&["doctor", "<repo>", "--json"]);
    let text = stdout(&doctor);
    assert!(text.contains("switch-required-check"), "{doctor:?}");
    let (steps, _) = generate_steps_and_writes(&repo);
    let switch = steps
        .iter()
        .find(|s| s.id == "switch-required-check")
        .unwrap();
    assert_eq!(switch.after.as_deref(), Some("check-reported"));
    assert!(
        switch
            .instructions
            .contains("gh api -X PUT repos/{owner}/{repo}/rulesets/<id> --input -")
    );
    assert!(switch.instructions.contains(
        "gh api -X PATCH repos/{owner}/{repo}/branches/main/protection/required_status_checks -f 'contexts[]=required'"
    ));
    match &switch.probe {
        brakes::engine::Probe::Remote { id, args } => {
            assert_eq!(id, "ruleset-required-checks");
            assert_eq!(args["checks"], json!(["required"]));
            assert_eq!(args["branch"], json!("main"));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_foreign_workflow_with_a_required_job_refuses_naming_the_file() {
    let repo = rust_repo("cargo test --locked");
    repo.write(
        ".github/workflows/gate.yaml",
        "on: push\njobs:\n  required:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: true\n",
    );
    let result = repo.install();
    assert!(!result.status.success(), "{result:?}");
    assert!(
        stderr(&result)
            .contains("ci-baseline: .github/workflows/gate.yaml already has a job named required"),
        "{result:?}"
    );
    assert!(repo.read(".github/workflows/agentic-ci.yml").is_none());
}

#[test]
fn the_required_job_scan_reads_job_ids_and_job_names_only() {
    use ci_baseline::brownfield::has_required_job as scan;
    assert!(scan("jobs:\n  required:\n    runs-on: x\n"));
    assert!(scan(
        "jobs:\n    \"required\": # gate\n        runs-on: x\n"
    ));
    assert!(scan("jobs:\n  gate:\n    name: required\n    runs-on: x\n"));
    assert!(scan("jobs:\n  gate:\n    name: 'required' # the gate\n"));
    // A step, an output or a key outside `jobs:` is not a job.
    assert!(!scan(VERIFY_YML));
    assert!(!scan("on:\n  required:\njobs:\n  a:\n    runs-on: x\n"));
    assert!(!scan(
        "jobs:\n  a:\n    outputs:\n      required: x\n    steps:\n      - name: required\n"
    ));
    assert!(!scan("jobs:\n  a:\n    name: required-checks\n"));
}

#[test]
fn the_brownfield_path_is_sticky_and_a_later_workflow_is_only_protected() {
    let repo = rust_repo("cargo test --locked");
    assert!(repo.install().status.success());
    assert!(repo.read(".github/workflows/ci.yml").is_some());
    repo.write(
        ".github/workflows/deploy.yml",
        "on: push\njobs:\n  deploy:\n    runs-on: x\n",
    );
    let result = repo.install();
    let out = stdout(&result);
    assert!(result.status.success(), "{result:?}");
    assert!(!out.contains("agentic-ci.yml"), "{out}");
    assert!(!out.contains("switch-required-check"), "{out}");
    assert_eq!(
        repo.lock_entry(".github/workflows/deploy.yml"),
        json!({"module": "ci-baseline", "class": "never-touch"})
    );
    assert!(repo.read(".github/workflows/ci.yml").is_some());

    let brown = brownfield_repo();
    assert!(brown.install().status.success());
    fs::remove_file(brown.root.join(".github/workflows/verify.yml")).unwrap();
    let result = brown.cli(&["install", "<repo>"]);
    let out = stdout(&result);
    assert!(result.status.success(), "{result:?}");
    assert!(!out.contains("ci.yml ["), "{out}");
    assert!(
        brown.read(".github/workflows/agentic-ci.yml").is_some(),
        "{out}"
    );
    assert!(
        out.contains("STEP [blocked:ci-baseline] switch-required-check"),
        "{out}"
    );
}

/// A production deploy job of the project's own, on a custom self-hosted label
/// (#1167): the job must not change.
const SELF_HOSTED_DEPLOY: &str = "name: CI\non: push\npermissions: {}\njobs:\n  test:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: make test\n  deploy:\n    runs-on: [self-hosted, prod-deploy]\n    steps:\n      - run: make deploy\n";

/// The labels under `self-hosted-runner.labels` of `text`, as written.
fn declared_labels(text: &str) -> Vec<String> {
    text.lines()
        .skip_while(|l| *l != "  labels:")
        .skip(1)
        .take_while(|l| l.starts_with("    - "))
        .map(|l| l["    - ".len()..].to_owned())
        .collect()
}

/// actionlint lints the project's own workflows too, so the custom labels their
/// self-hosted jobs already run on are declared, read from those workflows and
/// never invented; the workflows stay untouched (#1167).
#[test]
fn actionlint_config_declares_the_self_hosted_labels_the_existing_workflows_run_on() {
    let repo = rust_repo("cargo test --locked");
    repo.write(".github/workflows/ci.yml", SELF_HOSTED_DEPLOY);
    // With a GitHub-hosted runner the label alone renders the file.
    let config = repo
        .rendered(json!({"runner": "github"}), ".github/actionlint.yaml")
        .expect("the label of the existing deploy job renders actionlint.yaml");
    assert_eq!(declared_labels(&config), ["prod-deploy"], "{config}");
    assert!(!config.contains("\npaths:"), "{config}");
    // With the configured runner it follows the configured label.
    let config = repo.rendered(json!({}), ".github/actionlint.yaml").unwrap();
    assert_eq!(
        declared_labels(&config).last().map(String::as_str),
        Some("prod-deploy"),
        "{config}"
    );
    // The project's workflow is listed never-touch, not rendered.
    let rendered = repo.render(json!({})).unwrap();
    let own = rendered
        .iter()
        .find(|r| r.path == ".github/workflows/ci.yml")
        .unwrap();
    assert_eq!(own.class, Ownership::NeverTouch);
}

/// actionlint's own self-hosted labels, GitHub-hosted labels and expressions
/// are left out; each label once, sorted;
/// the `{group, labels}` form counts; a workflow that does not parse adds none.
#[test]
fn only_custom_labels_of_self_hosted_jobs_are_declared() {
    let repo = rust_repo("cargo test --locked");
    repo.write(
        ".github/workflows/deploy.yaml",
        "on: push\njobs:\n  a:\n    runs-on: [self-hosted, Linux, X64, zeta-box]\n    steps: [{run: x}]\n  b:\n    runs-on:\n      group: prod\n      labels: [self-hosted, alpha, zeta-box]\n    steps: [{run: x}]\n  c:\n    runs-on: ${{ matrix.os }}\n    steps: [{run: x}]\n  d:\n    runs-on: [self-hosted, \"${{ inputs.box }}\"]\n    steps: [{run: x}]\n  e:\n    runs-on: ubuntu-24.04\n    steps: [{run: x}]\n  f:\n    runs-on: [self-hosted, \"a\\nb: c\"]\n    steps: [{run: x}]\n",
    );
    repo.write(".github/workflows/broken.yml", "jobs: [: :\n");
    let config = repo
        .rendered(json!({"runner": "github"}), ".github/actionlint.yaml")
        .unwrap();
    assert_eq!(declared_labels(&config), ["alpha", "zeta-box"], "{config}");
}

/// A label the project's workflows run on is declared however `runs-on` is
/// written (#1215): a scalar (`runs-on: example-mac`, the label ci-baseline itself
/// renders for `macos`), a list without `self-hosted`, the `{group, labels}`
/// form without it; GitHub-hosted labels actionlint 1.7.12 knows are not,
/// whatever their case.
#[test]
fn custom_labels_are_declared_in_every_runs_on_form() {
    let repo = rust_repo("cargo test --locked");
    repo.write(
        ".github/workflows/ci.yml",
        "on: workflow_dispatch\njobs:\n  ios:\n    runs-on: example-mac\n    steps: [{run: x}]\n  quoted:\n    runs-on: 'mac-mini'\n    steps: [{run: x}]\n  list:\n    runs-on: [edge-box, Linux]\n    steps: [{run: x}]\n  group:\n    runs-on:\n      group: prod\n      labels: big-box\n    steps: [{run: x}]\n  hosted:\n    runs-on: ubuntu-24.04\n    steps: [{run: x}]\n  hosted-list:\n    runs-on: [macos-15, Windows-Latest, ubuntu-24.04-arm]\n    steps: [{run: x}]\n  matrix:\n    runs-on: ${{ matrix.os }}\n    steps: [{run: x}]\n",
    );
    let config = repo
        .rendered(json!({"runner": "github"}), ".github/actionlint.yaml")
        .expect("the scalar label renders actionlint.yaml");
    assert_eq!(
        declared_labels(&config),
        ["big-box", "edge-box", "example-mac", "mac-mini"],
        "{config}"
    );
}

/// The known-label list is actionlint's of the pinned release: a bump of the
/// pin fails here until the list is re-read from that release (#1215).
#[test]
fn the_known_labels_are_those_of_the_pinned_actionlint() {
    use brakes::modules::ci_baseline::brownfield::ACTIONLINT_KNOWN_RELEASE;
    use brakes::modules::security::pins::{ACTIONLINT, ACTIONLINT_HOOK};
    assert_eq!(ACTIONLINT_KNOWN_RELEASE, ACTIONLINT.version);
    assert_eq!(ACTIONLINT_KNOWN_RELEASE, ACTIONLINT_HOOK.version);
}

/// A project whose workflows run only on GitHub-hosted labels gets no
/// actionlint configuration from them.
#[test]
fn github_hosted_labels_alone_render_no_actionlint_config() {
    let repo = rust_repo("cargo test --locked");
    repo.write(
        ".github/workflows/ci.yml",
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps: [{run: x}]\n  b:\n    runs-on: [macos-26, windows-11-arm]\n    steps: [{run: x}]\n",
    );
    assert_eq!(
        repo.rendered(json!({"runner": "github"}), ".github/actionlint.yaml"),
        None
    );
}

/// Declaring the label to actionlint changes nothing for the auditor: the job
/// is still self-hosted and `ci.no-self-hosted-label` still reports it.
#[test]
fn the_self_hosted_job_is_still_reported_after_install() {
    let repo = rust_repo("cargo test --locked");
    repo.write(".github/workflows/ci.yml", SELF_HOSTED_DEPLOY);
    let result = repo.install();
    assert!(result.status.success(), "{result:?}");
    assert_eq!(
        repo.read(".github/workflows/ci.yml").unwrap(),
        SELF_HOSTED_DEPLOY
    );
    assert!(
        declared_labels(&repo.read(".github/actionlint.yaml").unwrap())
            .contains(&"prod-deploy".to_owned())
    );
    let doctor = stdout(&repo.cli(&["doctor", "<repo>"]));
    assert!(
        doctor.contains("WARNING: ci.no-self-hosted-label: Job deploy runs on a self-hosted label"),
        "{doctor}"
    );
}

#[test]
fn a_project_owned_actionlint_config_is_protected_not_refused() {
    let repo = rust_repo("cargo test --locked");
    let own = "self-hosted-runner:\n  labels: [my-runner]\n";
    repo.write(".github/actionlint.yaml", own);
    let result = repo.install();
    let out = stdout(&result);
    assert!(result.status.success(), "{result:?}");
    assert!(!out.contains("actionlint.yaml ["), "{out}");
    assert_eq!(repo.read(".github/actionlint.yaml").unwrap(), own);
    assert_eq!(
        repo.lock_entry(".github/actionlint.yaml"),
        json!({"module": "ci-baseline", "class": "never-touch"})
    );
    // No workflow of its own: greenfield, no switch.
    assert!(
        out.lines()
            .any(|l| l == "WRITE .github/workflows/ci.yml [managed:ci-baseline]"),
        "{out}"
    );
    let again = repo.cli(&["install", "<repo>"]);
    assert!(
        stdout(&again).lines().any(|l| l == "No changes."),
        "{again:?}"
    );

    let yml = rust_repo("cargo test --locked");
    yml.write(".github/actionlint.yml", own);
    assert!(yml.install().status.success());
    assert!(yml.read(".github/actionlint.yaml").is_none());
    assert_eq!(
        yml.lock_entry(".github/actionlint.yml"),
        json!({"module": "ci-baseline", "class": "never-touch"})
    );
}

/// Records `workflow: existing` with `check` through `configure`.
fn configure_existing(repo: &Repo, check: &str) -> String {
    let result = repo.cli(&[
        "configure",
        "<repo>",
        "stack-packs",
        "--set",
        "apps.root.path=.",
        "--set",
        "apps.root.stack=rust",
        "--apply",
    ]);
    assert!(result.status.success(), "{result:?}");
    let set = format!("aggregate_check={check}");
    let result = repo.cli(&[
        "configure",
        "<repo>",
        "ci-baseline",
        "--set",
        "workflow=existing",
        "--set",
        &set,
        "--apply",
    ]);
    assert!(result.status.success(), "{result:?}");
    stdout(&result)
}

#[test]
fn workflow_existing_records_the_check_and_renders_nothing() {
    for (check, workflow) in [
        ("Rust (linux)", ".github/workflows/orchestration.yml"),
        ("all-checks-passed", ".github/workflows/ci.yml"),
    ] {
        let repo = rust_repo("cargo test --locked");
        let own = "on: push\njobs:\n  gate:\n    name: gate\n    runs-on: x\n";
        repo.write(workflow, own);
        let out = configure_existing(&repo, check);
        let text = repo.read(&answers::path("ci-baseline")).unwrap();
        let file: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(file["answers"]["aggregate_check"], json!(check), "{text}");
        assert_eq!(file["answers"]["workflow"], json!("existing"), "{text}");
        assert!(!out.contains("[managed:ci-baseline]"), "{out}");
        assert!(
            !out.lines()
                .any(|l| l.starts_with("STEP [") && l.contains(":ci-baseline]")),
            "{out}"
        );
        assert_eq!(repo.read(workflow).unwrap(), own);
        assert!(repo.read(".github/workflows/agentic-ci.yml").is_none());
        assert!(repo.lock_entry(workflow).is_null());
    }
}

#[test]
fn an_edited_brownfield_workflow_refuses() {
    let repo = brownfield_repo();
    assert!(repo.install().status.success());
    let path = ".github/workflows/agentic-ci.yml";
    let edited = repo.read(path).unwrap() + "# local edit\n";
    repo.write(path, &edited);
    let result = repo.cli(&["install", "<repo>", "--apply"]);
    assert!(!result.status.success(), "{result:?}");
    assert!(
        stderr(&result).contains(&format!(
            "Locally changed or missing managed content: {path}"
        )),
        "{result:?}"
    );
    let removed = repo.cli(&["remove", "<repo>", "ci-baseline", "--apply"]);
    assert!(!removed.status.success(), "{removed:?}");
    assert!(stderr(&removed).contains(path), "{removed:?}");
    assert_eq!(repo.read(path).unwrap(), edited);
}

#[test]
fn remove_deletes_the_managed_workflow_and_leaves_every_existing_one() {
    let repo = brownfield_repo();
    let deploy = "on: push\njobs:\n  deploy:\n    runs-on: x\n";
    repo.write(".github/workflows/deploy.yaml", deploy);
    assert!(repo.install().status.success());
    let result = repo.cli(&["remove", "<repo>", "ci-baseline", "--apply"]);
    let out = stdout(&result);
    assert!(result.status.success(), "{result:?}");
    assert!(
        out.lines()
            .any(|l| l == "DELETE .github/workflows/agentic-ci.yml [managed:ci-baseline]"),
        "{out}"
    );
    for kept in [
        "KEEP .github/workflows/verify.yml [never-touch:ci-baseline]",
        "KEEP .github/workflows/deploy.yaml [never-touch:ci-baseline]",
        "KEEP github:switch-required-check [remote:ci-baseline]",
    ] {
        assert!(out.lines().any(|l| l == kept), "{kept}\n{out}");
    }
    assert!(repo.read(".github/workflows/agentic-ci.yml").is_none());
    assert_eq!(
        repo.read(".github/workflows/verify.yml").unwrap(),
        VERIFY_YML
    );
    assert_eq!(repo.read(".github/workflows/deploy.yaml").unwrap(), deploy);
}

// ---- T14 (#943): the protected-paths gate in the rendered workflows ----

const PR_TRIGGER: &str =
    "  pull_request:\n    types: [opened, synchronize, reopened, labeled, unlabeled]\n";

/// The gate's wiring, asserted on any rendered workflow whose aggregate is `aggregate`.
fn assert_gated(name: &str, text: &str, aggregate: &str) {
    assert!(
        text.contains(PR_TRIGGER),
        "{name}: label changes must re-run the workflow"
    );
    assert!(
        text.contains("      protected: \"${{ steps.scope.outputs.protected }}\"\n"),
        "{name}: the scope job's third output"
    );
    assert!(text.contains("          PROTECTED_PATHS: |-\n"), "{name}");
    let jobs = jobs(text);
    let (_, lines) = jobs
        .iter()
        .find(|(id, _)| id == aggregate)
        .unwrap_or_else(|| panic!("{name}: no {aggregate} job"));
    for env in [
        "          EVENT: \"${{ github.event_name }}\"",
        "          PROTECTED: \"${{ needs.scope.outputs.protected }}\"",
        "          PR_LABELS: \"${{ toJSON(github.event.pull_request.labels.*.name) }}\"",
    ] {
        assert!(
            lines.iter().any(|l| l == env),
            "{name}: {aggregate} lacks `{env}`"
        );
    }
}

#[test]
fn every_ci_baseline_golden_carries_the_gate() {
    for (name, text) in every_golden() {
        assert_gated(&name, &text, "required");
    }
}

#[test]
fn the_existing_goldens_carry_the_gate_in_agentic_required() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../templates");
    for golden in [
        "security/goldens/existing.yml",
        "agent-guardrails/goldens/cross-review-existing.yml",
        "ci-baseline/goldens/existing-heldout.yml",
        "ci-baseline/goldens/existing-heldout-properties-rust.yml",
        "ci-baseline/goldens/existing-heldout-properties-python-uv.yml",
    ] {
        let text = fs::read_to_string(root.join(golden)).unwrap();
        assert_gated(golden, &text, "agentic-required");
    }
}

#[test]
fn the_protected_paths_answer_reaches_the_scope_job() {
    let repo = rust_repo("cargo test --locked");
    let text = repo.workflow(json!({"protected_paths": [".github/**", "migrations/**"]}));
    assert!(
        text.contains(
            "          PROTECTED_PATHS: |-\n            .github/**\n            migrations/**\n"
        ),
        "{text}"
    );
    let defaults = repo.workflow(json!({}));
    let expected = format!(
        "          PROTECTED_PATHS: |-\n{}",
        scope::DEFAULT_PROTECTED_PATHS
            .iter()
            .map(|p| format!("            {p}\n"))
            .collect::<String>()
    );
    assert!(defaults.contains(&expected), "{defaults}");
}

#[test]
fn the_protected_paths_answer_is_asked_under_any_tier_answer() {
    let repo = rust_repo("cargo test --locked");
    let answers = repo
        .load(json!({"tiers": false, "protected_paths": ["infra/**"]}))
        .unwrap();
    assert_eq!(answers.protected_paths, ["infra/**"]);
    assert!(answers.inert_paths.is_empty());
}

// ---- T15 (#944): held-out tests ----

const HELDOUT_COMMAND: &str = "python3 -m unittest discover -s tests/heldout -v";
const HELDOUT_MISSING: &str =
    "ci-baseline: heldout_command missing; the held-out tests are the point of the job";

/// The job ids of a rendered workflow, in order.
fn job_ids(text: &str) -> Vec<String> {
    jobs(text).into_iter().map(|(id, _)| id).collect()
}

/// The `needs:` line of job `id`.
fn needs_of(text: &str, id: &str) -> String {
    jobs(text)
        .into_iter()
        .find(|(j, _)| j == id)
        .unwrap_or_else(|| panic!("no job {id}"))
        .1
        .into_iter()
        .find(|l| l.trim_start().starts_with("needs:"))
        .unwrap_or_default()
}

#[test]
fn heldout_defaults_to_true_when_generating_and_to_the_directory_under_existing() {
    let repo = rust_repo("cargo test --locked");
    // #1362: on by default when generating, pending until a command is answered.
    let fresh = repo.load(json!({})).unwrap();
    assert!(fresh.heldout);
    assert_eq!(fresh.heldout_command, None);
    // Under existing the directory still decides: no silent new required check.
    assert!(!repo.load(json!({"workflow": "existing"})).unwrap().heldout);
    repo.file("tests/heldout/test_kept.py");
    let answers = repo
        .load(json!({"heldout_command": HELDOUT_COMMAND}))
        .unwrap();
    assert!(answers.heldout);
    assert_eq!(answers.heldout_command.as_deref(), Some(HELDOUT_COMMAND));
    let off = repo
        .load(json!({"heldout": false, "heldout_command": HELDOUT_COMMAND}))
        .unwrap();
    assert!(!off.heldout);
    assert_eq!(off.heldout_command, None);
}

#[test]
fn heldout_without_a_command_refuses_with_the_spec_text() {
    let repo = rust_repo("cargo test --locked");
    repo.file("tests/heldout/test_kept.py");
    assert_eq!(repo.refusal(json!({})), HELDOUT_MISSING);
    assert_eq!(
        repo.refusal(json!({"heldout_command": "  "})),
        HELDOUT_MISSING
    );
    let fresh = rust_repo("cargo test --locked");
    assert_eq!(fresh.refusal(json!({"heldout": true})), HELDOUT_MISSING);
}

#[test]
fn a_heldout_command_with_an_expression_refuses() {
    let repo = rust_repo("cargo test --locked");
    assert_eq!(
        repo.refusal(json!({"heldout": true, "heldout_command": "make ${{ github.ref }}"})),
        "ci-baseline: heldout_command contains `${{`, which GitHub would evaluate; write the command without it"
    );
}

#[test]
fn heldout_dir_must_be_a_relative_path_inside_the_repository() {
    let repo = rust_repo("cargo test --locked");
    for dir in [
        "../heldout",
        "tests/../../x",
        "/abs/heldout",
        "tests//heldout",
        "./",
        ".",
        "tests/./heldout",
        "tests/held out",
        "tests/*",
        "tests\\heldout",
    ] {
        assert_eq!(
            repo.refusal(json!({"heldout_dir": dir})),
            format!("ci-baseline: heldout_dir {dir} is not a relative path inside the repository"),
            "{dir}"
        );
    }
}

#[test]
fn heldout_dir_drops_a_leading_dot_slash_and_a_trailing_slash() {
    let repo = rust_repo("cargo test --locked");
    let answers = repo.load(json!({"heldout_dir": "./qa/heldout/"})).unwrap();
    assert_eq!(answers.heldout_dir, "qa/heldout");
}

#[test]
fn the_protected_paths_default_follows_heldout_dir() {
    let repo = rust_repo("cargo test --locked");
    let answers = repo.load(json!({"heldout_dir": "qa/heldout"})).unwrap();
    let mut expected: Vec<String> = scope::DEFAULT_PROTECTED_PATHS
        .iter()
        .map(|p| (*p).to_owned())
        .collect();
    *expected.last_mut().unwrap() = "qa/heldout/**".to_owned();
    assert_eq!(answers.protected_paths, expected);
    let text = repo.workflow(json!({"heldout_dir": "qa/heldout"}));
    assert!(text.contains("            qa/heldout/**\n"), "{text}");
    assert!(!text.contains("tests/heldout/**"), "{text}");
    // An answered list is kept as answered.
    let answered = repo
        .load(json!({"heldout_dir": "qa/heldout", "protected_paths": ["infra/**"]}))
        .unwrap();
    assert_eq!(answered.protected_paths, ["infra/**"]);
}

#[test]
fn the_heldout_job_runs_only_its_command_and_is_in_required_needs() {
    let repo = rust_repo("cargo test --locked");
    repo.file("tests/heldout/test_kept.py");
    let text = repo.workflow(json!({"heldout_command": HELDOUT_COMMAND}));
    golden("heldout.yml", &text);
    assert_eq!(
        job_ids(&text),
        ["scope", "checks", "heldout", "workflow-lint", "required"]
    );
    assert_eq!(
        needs_of(&text, "required"),
        "    needs: [scope, checks, heldout, workflow-lint]"
    );
    let (_, lines) = jobs(&text)
        .into_iter()
        .find(|(id, _)| id == "heldout")
        .unwrap();
    let body = lines.join("\n");
    assert!(body.contains("    timeout-minutes: 15"), "{body}");
    assert!(
        body.contains("    if: needs.scope.outputs.tier != 'docs'"),
        "{body}"
    );
    assert!(
        body.contains(&format!("          HELDOUT_COMMAND: {HELDOUT_COMMAND}")),
        "{body}"
    );
    // Its only run step besides the stack-pack setup is the held-out one: no
    // declared command runs in it.
    assert!(!body.contains("Run declared"), "{body}");
    assert!(
        text.contains("          DOCS_SKIPPABLE: |-\n            checks\n            heldout\n"),
        "{text}"
    );
    // Same setup as checks: every step of checks before its declared runs.
    let (_, checks) = jobs(&text)
        .into_iter()
        .find(|(id, _)| id == "checks")
        .unwrap();
    let setup: Vec<&String> = checks
        .iter()
        .skip_while(|l| !l.contains("steps:"))
        .take_while(|l| !l.contains("Run declared"))
        .collect();
    let heldout_steps: Vec<&String> = lines.iter().skip_while(|l| !l.contains("steps:")).collect();
    assert!(setup.len() > 2, "{setup:?}");
    assert_eq!(&heldout_steps[..setup.len()], &setup[..]);
}

#[test]
fn the_heldout_fragment_runs_the_command_and_fails_red() {
    let fragment = "heldout.sh";
    let ok = run_fragment(
        fragment,
        json!({}),
        &[("HELDOUT_COMMAND", "echo kept | cat")],
    );
    assert!(ok.status.success(), "{ok:?}");
    assert!(stdout(&ok).contains("heldout: echo kept | cat"), "{ok:?}");
    let red = run_fragment(fragment, json!({}), &[("HELDOUT_COMMAND", "false | cat")]);
    assert!(!red.status.success(), "pipefail: {red:?}");
    let empty = run_fragment(fragment, json!({}), &[("HELDOUT_COMMAND", "")]);
    assert!(!empty.status.success(), "{empty:?}");
}

#[test]
fn heldout_false_opts_out_of_the_job() {
    let repo = rust_repo("cargo test --locked");
    let off = repo.workflow(json!({"heldout": false}));
    assert!(!job_ids(&off).contains(&"heldout".to_owned()), "{off}");
    repo.file("tests/heldout/test_kept.py");
    let off = repo.workflow(json!({"heldout": false}));
    assert!(!job_ids(&off).contains(&"heldout".to_owned()), "{off}");
}

// ---- #1362: held-out tests on by default, pending until the first test ----

#[test]
fn a_default_install_renders_the_pending_heldout_job_in_required_needs() {
    let repo = rust_repo("cargo test --locked");
    let text = repo.workflow(json!({}));
    // The default install is the single-repository golden.
    golden("single.yml", &text);
    assert_eq!(
        job_ids(&text),
        ["scope", "checks", "heldout", "workflow-lint", "required"]
    );
    assert_eq!(
        needs_of(&text, "required"),
        "    needs: [scope, checks, heldout, workflow-lint]"
    );
    let body = jobs(&text)
        .into_iter()
        .find(|(id, _)| id == "heldout")
        .unwrap()
        .1
        .join("\n");
    assert!(body.contains("Check held-out tests are pending"), "{body}");
    assert!(
        body.contains("          HELDOUT_DIR: tests/heldout"),
        "{body}"
    );
    assert!(!body.contains("HELDOUT_COMMAND"), "{body}");
}

#[test]
fn a_pending_heldout_job_follows_the_answered_directory_and_writes_nothing() {
    let repo = rust_repo("cargo test --locked");
    let rendered = repo.render(json!({"heldout_dir": "qa/held-out"})).unwrap();
    let paths: Vec<&str> = rendered.iter().map(|r| r.path.as_str()).collect();
    assert_eq!(
        paths,
        [".github/actionlint.yaml", ".github/workflows/ci.yml"]
    );
    let text = repo.workflow(json!({"heldout_dir": "qa/held-out"}));
    assert!(
        text.contains("          HELDOUT_DIR: qa/held-out\n"),
        "{text}"
    );
    // An answered command is no longer pending: the command's job.
    let answered = repo.workflow(json!({"heldout_command": HELDOUT_COMMAND}));
    assert!(answered.contains("Run held-out tests"), "{answered}");
    assert!(!answered.contains("HELDOUT_DIR"), "{answered}");
}

#[test]
fn an_empty_directory_stays_pending_and_any_file_in_it_refuses() {
    let repo = rust_repo("cargo test --locked");
    fs::create_dir_all(repo.root.join("tests/heldout/nested")).unwrap();
    let pending = repo.load(json!({})).unwrap();
    assert!(pending.heldout);
    assert_eq!(pending.heldout_command, None);
    repo.file("tests/heldout/nested/test_kept.py");
    assert_eq!(repo.refusal(json!({})), HELDOUT_MISSING);
}

/// #17: the held-out path is read through the scope guard: a symlink in any of
/// its components refuses the plan, so nothing outside the repository is read.
#[cfg(unix)]
#[test]
fn a_symlink_in_the_heldout_path_refuses_the_plan() {
    use std::os::unix::fs::symlink;
    let outside = tempfile::tempdir().unwrap();
    fs::create_dir_all(outside.path().join("heldout")).unwrap();
    for linked in ["tests", "tests/heldout"] {
        let repo = rust_repo("cargo test --locked");
        let link = repo.root.join(linked);
        fs::create_dir_all(link.parent().unwrap()).unwrap();
        let target = if linked == "tests" {
            outside.path().to_path_buf()
        } else {
            outside.path().join("heldout")
        };
        symlink(target, &link).unwrap();
        let refused = format!("Symlink refused: {}", link.display());
        assert_eq!(repo.refusal(json!({})), refused, "{linked}");
        assert_eq!(
            repo.refusal(json!({"workflow": "existing"})),
            refused,
            "{linked}"
        );
    }
}

/// #17: what `heldout-pending.sh` counts as a file, the plan counts too: a
/// regular file at `heldout_dir`, a link under it and a directory it cannot
/// read each refuse the pending job, and each turns the fragment red.
#[cfg(unix)]
#[test]
fn the_plan_and_the_pending_fragment_agree_on_links_files_and_unreadable_directories() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let red = |repo: &Repo| {
        let out = run_pending(&repo.root, Some("tests/heldout"));
        assert!(!out.status.success(), "{out:?}");
    };
    let repo = rust_repo("cargo test --locked");
    repo.file("tests/heldout");
    assert_eq!(repo.refusal(json!({})), HELDOUT_MISSING);
    red(&repo);

    let repo = rust_repo("cargo test --locked");
    fs::create_dir_all(repo.root.join("tests/heldout/empty")).unwrap();
    symlink(
        repo.root.join("tests/heldout/empty"),
        repo.root.join("tests/heldout/link"),
    )
    .unwrap();
    assert_eq!(repo.refusal(json!({})), HELDOUT_MISSING);
    red(&repo);

    let repo = rust_repo("cargo test --locked");
    let locked = repo.root.join("tests/heldout/locked");
    fs::create_dir_all(&locked).unwrap();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
    // A process that reads it anyway (root) cannot show the case.
    if fs::read_dir(&locked).is_err() {
        assert_eq!(repo.refusal(json!({})), HELDOUT_MISSING);
        red(&repo);
    }
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn under_workflow_existing_a_default_install_still_renders_nothing() {
    let repo = rust_repo("cargo test --locked");
    let rendered = repo.render(json!({"workflow": "existing"})).unwrap();
    assert!(
        rendered.is_empty(),
        "{:?}",
        rendered.iter().map(|r| &r.path).collect::<Vec<_>>()
    );
}

/// `heldout-pending.sh` under bash in `dir`, with `HELDOUT_DIR` when given.
fn run_pending(dir: &std::path::Path, held: Option<&str>) -> std::process::Output {
    let mut command = Command::new("bash");
    command
        .arg(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../templates/ci-baseline/fragments/heldout-pending.sh"),
        )
        .current_dir(dir)
        .env_remove("HELDOUT_DIR");
    if let Some(held) = held {
        command.env("HELDOUT_DIR", held);
    }
    command.output().unwrap()
}

#[test]
fn the_pending_fragment_passes_only_while_the_directory_holds_no_file() {
    let dir = tempfile::tempdir().unwrap();
    let missing = run_pending(dir.path(), Some("tests/heldout"));
    assert!(missing.status.success(), "{missing:?}");
    assert!(
        stdout(&missing).contains("heldout: no held-out tests yet under tests/heldout"),
        "{missing:?}"
    );
    fs::create_dir_all(dir.path().join("tests/heldout/deep")).unwrap();
    let empty = run_pending(dir.path(), Some("tests/heldout"));
    assert!(empty.status.success(), "{empty:?}");
    fs::write(dir.path().join("tests/heldout/README.md"), "how\n").unwrap();
    fs::write(dir.path().join("tests/heldout/deep/test_x.py"), "").unwrap();
    let red = run_pending(dir.path(), Some("tests/heldout"));
    assert!(!red.status.success(), "{red:?}");
    assert_eq!(
        stdout(&red),
        "heldout: tests/heldout holds tests and heldout_command is not answered; answer it so the job runs them\n\
         tests/heldout/README.md\ntests/heldout/deep/test_x.py\n"
    );
    let unset = run_pending(dir.path(), None);
    assert!(!unset.status.success(), "{unset:?}");
}

#[test]
fn under_workflow_existing_the_heldout_job_joins_agentic_required() {
    let repo = rust_repo("cargo test --locked");
    repo.file("tests/heldout/test_kept.py");
    let text = repo
        .rendered(
            json!({"workflow": "existing", "aggregate_check": "Rust (linux)", "heldout_command": HELDOUT_COMMAND}),
            ".github/workflows/agentic-security.yml",
        )
        .unwrap();
    golden("existing-heldout.yml", &text);
    assert_eq!(job_ids(&text), ["scope", "heldout", "agentic-required"]);
    assert_eq!(
        needs_of(&text, "agentic-required"),
        "    needs: [scope, heldout]"
    );
    assert!(
        text.contains("          DOCS_SKIPPABLE: heldout\n"),
        "{text}"
    );
    // Without the job nothing renders under existing, as before.
    assert!(
        repo.render(json!({"workflow": "existing", "heldout": false}))
            .unwrap()
            .iter()
            .all(|r| r.path != ".github/workflows/agentic-security.yml")
    );
}

#[test]
fn under_workflow_existing_the_heldout_job_brings_the_agentic_required_steps() {
    let repo = rust_repo("cargo test --locked");
    repo.file("tests/heldout/test_kept.py");
    let raw: Answers =
        serde_json::from_value(json!({"workflow": "existing", "heldout_command": HELDOUT_COMMAND}))
            .unwrap();
    let validated = CiBaseline
        .questions()
        .validate("ci-baseline", &raw, answers::DEFAULT_TIER)
        .unwrap();
    let profile = profile_for(&repo.root).unwrap();
    let source = Source::embedded();
    let previous = empty_lock();
    let resolved = recorded_stack_packs(&repo.root);
    let cx = Context::new(
        &repo.root,
        &profile,
        &source,
        &previous,
        &validated,
        &CiBaseline,
        &resolved,
    );
    let steps: Vec<String> = CiBaseline
        .manual_steps(&cx)
        .into_iter()
        .map(|s| s.id)
        .collect();
    assert_eq!(
        steps,
        ["agentic-required-reported", "add-agentic-required-check"]
    );
}

#[test]
fn heldout_is_a_built_in_job_no_module_may_contribute() {
    assert!(ci_baseline::compose::BUILT_IN_JOBS.contains(&"heldout"));
    assert!(
        scope::SKIPPABLE.contains(&("heldout", scope::SkipWhen::TierDocs)),
        "{:?}",
        scope::SKIPPABLE
    );
}

// --- T12: monorepo app jobs and the macOS job (#784) -------------------------------

/// A monorepo: a python-uv backend and a node web app, each with its own
/// profile (Decision 8); the root profile declares nothing.
fn monorepo() -> Repo {
    monorepo_declaring(json!({}))
}

/// `monorepo()` whose root profile declares `root` (#1165).
fn monorepo_declaring(root: Value) -> Repo {
    let repo = Repo::with_commands(root);
    repo.write(
        "apps/backend/pyproject.toml",
        "[project]\nname = \"backend\"\n",
    )
    .write("apps/backend/uv.lock", "")
    .write(
        "apps/backend/.agent-setup/project.json",
        r#"{"commands": {"lint": "uv run ruff check .", "test": "uv run pytest"}}"#,
    )
    .write("apps/web/package.json", "{}")
    .write("apps/web/package-lock.json", "{}")
    .write(
        "apps/web/.agent-setup/project.json",
        r#"{"commands": {"test": "npm test", "build": "npm run build"}}"#,
    );
    repo.stack_packs(json!({
        "apps.backend.path": "apps/backend", "apps.backend.stack": "python-uv",
        "apps.backend.toolchain_version": "3.13",
        "apps.web.path": "apps/web", "apps.web.stack": "node",
        "apps.web.toolchain_version": "24",
    }));
    repo
}

/// A rust repository at `.` with an iOS app at `ios/` (the swift-ios pack
/// declares the macOS target).
fn macos_repo() -> Repo {
    let repo = rust_repo("cargo test --locked");
    repo.write("ios/Package.swift", "// swift-tools-version:6.0\n")
        .write(
            "ios/.agent-setup/project.json",
            r#"{"commands": {"test": "swift test"}}"#,
        );
    repo.stack_packs(json!({
        "apps.root.path": ".", "apps.root.stack": "rust",
        "apps.ios.path": "ios", "apps.ios.stack": "swift-ios",
    }));
    repo
}

/// `monorepo()` with a foreign `verify.yml`: the brownfield switch is declared.
fn brownfield_monorepo() -> Repo {
    let repo = monorepo();
    repo.write(".github/workflows/verify.yml", VERIFY_YML);
    repo
}

#[test]
fn a_monorepo_aggregate_supersedes_the_old_checks_when_each_app_runs_its_declared_commands() {
    // #1149: each app's own profile is compared, not the root's (which declares nothing).
    let repo = brownfield_monorepo();
    repo.install_with_ruleset();
    assert_eq!(
        repo.retire_supersession(),
        Supersession::By(AGGREGATE_CHECK.to_owned())
    );
}

#[test]
fn a_monorepo_app_with_a_declared_command_the_aggregate_does_not_run_refuses_naming_it() {
    let repo = brownfield_monorepo();
    repo.write(
        "apps/web/.agent-setup/project.json",
        r#"{"commands": {"test": "npm test", "verify": "npm run e2e", "build": "npm run build"}}"#,
    );
    repo.install_with_ruleset();
    assert_eq!(
        repo.retire_supersession(),
        Supersession::Short(
            "the aggregate check required does not supersede them: .github/workflows/agentic-ci.yml does not run apps/web/commands.verify (npm run e2e); fold it in with brakes configure <repo> ci-baseline --set commands=lint,test,verify,build --apply, then merge and apply --remote again".to_owned()
        )
    );
}

#[test]
fn monorepo_workflow_matches_the_golden() {
    golden("monorepo.yml", &monorepo().workflow(json!({})));
}

#[test]
fn macos_workflow_matches_the_golden() {
    golden("macos.yml", &macos_repo().workflow(json!({"macos": true})));
}

#[test]
fn the_monorepo_golden_runs_each_app_in_its_directory_from_its_own_profile() {
    let text = monorepo().workflow(json!({}));
    let jobs = jobs(&text);
    let ids: Vec<&str> = jobs.iter().map(|(id, _)| id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "scope",
            "backend-checks",
            "web-checks",
            "heldout",
            "workflow-lint",
            "required"
        ]
    );
    for (id, dir, commands) in [
        ("backend-checks", "apps/backend", vec!["lint", "test"]),
        ("web-checks", "apps/web", vec!["test", "build"]),
    ] {
        let (_, lines) = jobs.iter().find(|(j, _)| j == id).unwrap();
        assert!(
            lines.contains(&format!(
                "    if: contains(fromJSON(needs.scope.outputs.skippable), '{id}') == false"
            )),
            "{id}: {lines:#?}"
        );
        let declared: Vec<&str> = lines
            .iter()
            .filter_map(|l| l.strip_prefix("      - name: Run declared "))
            .collect();
        assert_eq!(declared, commands, "{id}");
        for (i, line) in lines.iter().enumerate() {
            if line.starts_with("      - name: Run declared ") {
                assert_eq!(
                    lines[i + 1],
                    format!("        working-directory: {dir}"),
                    "{id}: every declared step runs in {dir}"
                );
            }
        }
    }
    // The scope job knows the apps and may skip each app's checks under docs.
    assert!(
        text.contains(
            "          APPS: |-\n            backend=apps/backend\n            web=apps/web\n"
        ),
        "{text}"
    );
    assert!(
        text.contains(
            "          DOCS_SKIPPABLE: |-\n            backend-checks\n            web-checks\n"
        ),
        "{text}"
    );
}

#[test]
fn the_macos_golden_runs_the_macos_target_app_on_the_configured_mac_on_pushes_only() {
    let text = macos_repo().workflow(json!({"macos": true}));
    let jobs = jobs(&text);
    let ids: Vec<&str> = jobs.iter().map(|(id, _)| id.as_str()).collect();
    // One Linux app at `.` keeps the single-app `checks` job; the iOS app has
    // no Linux job: its commands run in `macos`.
    assert_eq!(
        ids,
        [
            "scope",
            "checks",
            "heldout",
            "macos",
            "workflow-lint",
            "required"
        ]
    );
    let (_, macos) = jobs.iter().find(|(id, _)| id == "macos").unwrap();
    assert!(
        macos.contains(&"    if: github.event_name == 'push'".to_owned()),
        "{macos:#?}"
    );
    let mac = configured::macos_runner();
    assert!(macos.contains(&format!("    runs-on: {}", mac.label)));
    assert!(macos.contains(&"    timeout-minutes: 40".to_owned()));
    assert!(macos.contains(&"      - name: Run declared test".to_owned()));
    assert!(macos.contains(&"        working-directory: ios".to_owned()));
    assert!(
        !macos.iter().any(|l| l.contains("Rust toolchain")),
        "{macos:#?}"
    );
    // The root app's job runs at the root, with no working directory, and
    // sets up no Swift: the macOS-target pack is set up in `macos` alone.
    let (_, root) = jobs.iter().find(|(id, _)| id == "checks").unwrap();
    assert!(
        !root.iter().any(|l| l.contains("working-directory")),
        "{root:#?}"
    );
    assert!(
        text.contains("          APPS: \"\"\n")
            && text.contains(
                "          DOCS_SKIPPABLE: |-\n            checks\n            heldout\n"
            ),
        "{text}"
    );
    // actionlint learns the macOS label beside the Linux one.
    let config = macos_repo()
        .rendered(json!({"macos": true}), ".github/actionlint.yaml")
        .unwrap();
    assert!(
        config.ends_with(&format!(
            "  labels:\n    - {}\n    - {}\n",
            configured::linux_runner().label,
            mac.label
        )),
        "{config}"
    );
}

#[test]
fn a_github_hosted_macos_runner_renders_its_label_and_is_flagged() {
    let repo = macos_repo();
    let raw = json!({"macos": true, "macos_runner": "github-hosted"});
    let text = repo.workflow(raw.clone());
    assert!(text.contains("    runs-on: macos-15\n"), "{text}");
    let mac = configured::macos_runner();
    assert!(!text.contains(&mac.label), "{text}");
    let config = repo
        .rendered(raw.clone(), ".github/actionlint.yaml")
        .unwrap();
    assert!(!config.contains(&mac.label), "{config}");
    // The flag: the auditor's warning from the answers, whatever the workflow says.
    let raw: Answers = serde_json::from_value(generate(raw)).unwrap();
    let findings = ci_baseline::audit::findings(
        &repo.root,
        &profile_for(&repo.root).unwrap().value,
        Some(&raw),
    );
    assert!(
        findings.contains(&format!("WARNING: ci.hosted-macos: Hosted macOS answered (macos_runner github-hosted) bills at a premium multiple on every push to main; {} is the default", mac.name)),
        "{findings:#?}"
    );
}

#[test]
fn a_macos_target_app_without_macos_is_noted_and_runs_nowhere() {
    let repo = macos_repo();
    let text = repo.workflow(json!({}));
    assert!(!text.contains("  macos:\n"), "{text}");
    assert!(!text.contains("ios-checks"), "{text}");
    assert_eq!(
        repo.notes(json!({})),
        [
            "app ios (swift-ios) declares a macOS target and macos is false; its commands run nowhere until macos=true"
        ]
    );
}

#[test]
fn an_app_declaring_none_of_the_answered_commands_refuses() {
    let repo = monorepo();
    assert_eq!(
        repo.refusal(json!({"commands": ["lint"]})),
        "ci-baseline: app web declares none of the answered commands (lint) in apps/web/.agent-setup/project.json; declare one there or remove the app from stack-packs"
    );
}

#[test]
fn monorepo_commands_derive_from_every_app_profile() {
    // The root profile declares nothing: the apps' profiles derive the set.
    let answers = monorepo().load(json!({})).unwrap();
    assert_eq!(answers.commands, [Cmd::Lint, Cmd::Test, Cmd::Build]);
}

// --- #1165: the root profile's commands in monorepo mode ---------------------------

/// A brownfield root profile beside the apps' (#1165): a
/// script suite as `verify`, and `test` and `lint` over every app.
fn rooted_monorepo() -> Repo {
    monorepo_declaring(json!({
        "verify": "python3 -B -m unittest discover -s scripts/ci/tests -v",
        "test": "make test",
        "lint": "make lint",
    }))
}

/// The steps `Run declared <name>` of `lines`, in order.
fn declared_steps(lines: &[String]) -> Vec<&str> {
    lines
        .iter()
        .filter_map(|l| l.strip_prefix("      - name: Run declared "))
        .collect()
}

#[test]
fn a_root_profile_with_commands_runs_them_in_a_root_checks_job() {
    let text = rooted_monorepo().workflow(json!({}));
    let jobs = jobs(&text);
    let ids: Vec<&str> = jobs.iter().map(|(id, _)| id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "scope",
            "backend-checks",
            "web-checks",
            "checks",
            "heldout",
            "workflow-lint",
            "required"
        ]
    );
    let lines = |id: &str| jobs.iter().find(|(j, _)| j == id).unwrap().1.clone();
    let checks = lines("checks");
    // The derived set is lint, test, build; the root declares lint and test.
    assert_eq!(declared_steps(&checks), ["lint", "test"], "{checks:#?}");
    for (i, line) in checks.iter().enumerate() {
        if line.starts_with("      - name: Run declared ") {
            assert!(
                !checks[i + 1].contains("working-directory"),
                "the root job runs at the root: {checks:#?}"
            );
        }
    }
    assert!(
        checks.contains(&"    if: needs.scope.outputs.tier != 'docs'".to_owned()),
        "{checks:#?}"
    );
    // Every Linux app's setup, since a root command may drive any of them.
    for app in ["backend-checks", "web-checks"] {
        for uses in lines(app).iter().filter(|l| l.contains("uses: ")) {
            assert!(checks.contains(uses), "{app}: {uses} missing in checks");
        }
    }
    assert!(
        text.contains(
            "          DOCS_SKIPPABLE: |-\n            backend-checks\n            web-checks\n            checks\n"
        ),
        "{text}"
    );
    let required = lines("required");
    let needs = required
        .iter()
        .find(|l| l.starts_with("    needs: "))
        .unwrap();
    assert!(
        needs.contains("checks,") || needs.contains("checks]"),
        "{needs}"
    );
    assert!(needs.contains("web-checks"), "{needs}");
}

#[test]
fn monorepo_commands_derive_from_the_root_profile_too() {
    // The apps declare only test; the root's lint joins the derived set.
    let repo = monorepo_declaring(json!({"lint": "make lint"}));
    repo.write(
        "apps/backend/.agent-setup/project.json",
        r#"{"commands": {"test": "uv run pytest"}}"#,
    )
    .write(
        "apps/web/.agent-setup/project.json",
        r#"{"commands": {"test": "npm test"}}"#,
    );
    let answers = repo.load(json!({})).unwrap();
    assert_eq!(answers.commands, [Cmd::Lint, Cmd::Test]);
    assert_eq!(answers.root_commands, Some(vec![Cmd::Lint]));
    let answers = monorepo_declaring(json!({"verify": "make verify"}))
        .load(json!({"commands": ["lint", "test", "verify", "build"]}))
        .unwrap();
    assert_eq!(answers.root_commands, Some(vec![Cmd::Verify]));
    // An app at the root takes its profile: no root job.
    let repo = monorepo_declaring(json!({"test": "cargo test"}));
    repo.write("Cargo.toml", "").write("Cargo.lock", "");
    repo.stack_packs(json!({
        "apps.root.path": ".", "apps.root.stack": "rust",
        "apps.web.path": "apps/web", "apps.web.stack": "node",
    }));
    let text = repo.workflow(json!({}));
    assert!(!jobs(&text).iter().any(|(id, _)| id == "checks"), "{text}");
}

#[test]
fn a_root_command_required_does_not_run_is_a_plan_note_with_the_fix() {
    let repo = rooted_monorepo();
    assert_eq!(
        repo.notes(json!({})),
        [
            "Verification command not run: .agent-setup/project.json declares commands.verify (python3 -B -m unittest discover -s scripts/ci/tests -v), which required does not run; fold it in with brakes configure <repo> ci-baseline --set commands=lint,test,verify,build --apply"
        ]
    );
    // Answered with it, the root job runs it and nothing is noted.
    let answered = json!({"commands": ["lint", "test", "verify", "build"]});
    assert!(repo.notes(answered.clone()).is_empty());
    let text = repo.workflow(answered);
    let jobs = jobs(&text);
    let checks = &jobs.iter().find(|(j, _)| j == "checks").unwrap().1;
    assert_eq!(declared_steps(checks), ["lint", "test", "verify"]);
}

#[test]
fn a_root_command_no_job_runs_keeps_the_aggregate_from_superseding_the_old_checks() {
    // #1149 in monorepo mode compares the root profile as it compares each app's.
    let repo = rooted_monorepo();
    repo.write(".github/workflows/verify.yml", VERIFY_YML);
    repo.install_with_ruleset();
    assert_eq!(
        repo.retire_supersession(),
        Supersession::Short(
            "the aggregate check required does not supersede them: .github/workflows/agentic-ci.yml does not run commands.verify (python3 -B -m unittest discover -s scripts/ci/tests -v); fold it in with brakes configure <repo> ci-baseline --set commands=lint,test,verify,build --apply, then merge and apply --remote again".to_owned()
        )
    );
}

// --- T13: the reusable workflow and its callers (#785) ------------------------------

const CALLEE: &str = ".github/workflows/_reusable-verify.yml";
/// A real commit of this repository (main's merge of #994): CI runs zizmor's
/// online `impostor-commit` audit over the goldens, which rejects a commit
/// that does not belong to the repository the `uses:` names.
const SHA: &str = "bcdc074fc1344779e6c8c3b5617cbaf4a2ff762f";

impl Repo {
    /// What `render` returns for `raw` when the checkout's origin is `repository`.
    fn render_as(&self, raw: Value, repository: &str) -> brakes::Result<Vec<Rendered>> {
        let raw: Answers = serde_json::from_value(generate(raw)).unwrap();
        let validated =
            CiBaseline
                .questions()
                .validate("ci-baseline", &raw, answers::DEFAULT_TIER)?;
        let profile = profile_for(&self.root)?;
        let source = Source::embedded();
        let previous = empty_lock();
        let resolved = recorded_stack_packs(&self.root);
        let cx = Context::new(
            &self.root,
            &profile,
            &source,
            &previous,
            &validated,
            &CiBaseline,
            &resolved,
        )
        .with_repository(Some(repository));
        CiBaseline.render(&cx)
    }
    fn workflow_as(&self, raw: Value, repository: &str) -> String {
        self.render_as(raw, repository)
            .unwrap()
            .into_iter()
            .find(|r| r.path == ".github/workflows/ci.yml")
            .unwrap()
            .content
            .unwrap()
    }
    /// Notes and manual steps for `raw` when the origin is `repository`.
    fn notes_and_steps_as(&self, raw: Value, repository: &str) -> (Vec<String>, Vec<String>) {
        let raw: Answers = serde_json::from_value(generate(raw)).unwrap();
        let validated = CiBaseline
            .questions()
            .validate("ci-baseline", &raw, answers::DEFAULT_TIER)
            .unwrap();
        let profile = profile_for(&self.root).unwrap();
        let source = Source::embedded();
        let previous = empty_lock();
        let resolved = recorded_stack_packs(&self.root);
        let cx = Context::new(
            &self.root,
            &profile,
            &source,
            &previous,
            &validated,
            &CiBaseline,
            &resolved,
        )
        .with_repository(Some(repository));
        let steps = CiBaseline
            .manual_steps(&cx)
            .into_iter()
            .map(|s| format!("{} {:?}", s.id, s.probe))
            .collect();
        (
            CiBaseline
                .notes(&cx)
                .unwrap()
                .into_iter()
                .filter(|n| !n.starts_with(DEPRECATED))
                .collect(),
            steps,
        )
    }
}

/// A caller owned by the callee's owner, so the private callee is reachable.
fn same_owner_caller() -> String {
    let callee = configured::reusable_callee();
    let (owner, _) = callee.split_once('/').unwrap();
    format!("{owner}/example")
}

fn reusable() -> Value {
    json!({"reusable": true, "reusable_sha": SHA})
}

/// The callee the import ships is the render with no configured runner, byte for
/// byte: its pins come from the shared table, its setup from the packs, and its
/// labels are GitHub's (product-boundary T9b, #1202). Here that file is the
/// `export/` overlay; in the imported tree, which has no `export/`, it is the
/// callee itself. This repository's own callee is its render under its own
/// configuration (`this_repository.rs`).
#[test]
fn the_imported_callee_is_its_render_without_a_configured_runner() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let path = if root.join("export").is_dir() {
        root.join("export").join(CALLEE)
    } else {
        root.join(CALLEE)
    };
    let text = ci_baseline::reusable::callee_with(None).unwrap();
    assert!(
        text.contains("default: '\"ubuntu-24.04\"'\n")
            && text.contains("LABELS: \"\\\"ubuntu-24.04\\\"\"\n"),
        "{text}"
    );
    if std::env::var_os("UPDATE_GOLDENS").is_some() {
        fs::write(&path, &text).unwrap();
    }
    assert!(
        fs::read_to_string(&path).unwrap() == text,
        "{CALLEE} differs from its render; run with UPDATE_GOLDENS=1"
    );
    assert!(text.contains("on:\n  workflow_call:\n"), "{text}");
    for input in [
        "commands",
        "profile-path",
        "working-directory",
        "stack",
        "runs-on",
        "tier",
    ] {
        assert!(text.contains(&format!("\n      {input}:\n")), "{input}");
    }
    assert!(text.contains("\n    outputs:\n      result:\n"), "{text}");
    assert!(
        text.contains("\npermissions:\n  contents: read\n"),
        "{text}"
    );
}

#[test]
fn the_caller_workflow_matches_the_golden() {
    let repo = rust_repo("cargo test --locked");
    golden(
        "caller.yml",
        &repo.workflow_as(reusable(), &same_owner_caller()),
    );
}

#[test]
fn the_caller_keeps_scope_workflow_lint_and_required_local_and_pins_the_callee() {
    let repo = rust_repo("cargo test --locked");
    let text = repo.workflow_as(reusable(), &same_owner_caller());
    let jobs = jobs(&text);
    let ids: Vec<&str> = jobs.iter().map(|(id, _)| id.as_str()).collect();
    assert_eq!(
        ids,
        ["scope", "checks", "heldout", "workflow-lint", "required"]
    );
    let (_, checks) = jobs.iter().find(|(id, _)| id == "checks").unwrap();
    assert!(
        checks.contains(&format!(
            "    uses: {}/.github/workflows/_reusable-verify.yml@{SHA}",
            configured::reusable_callee()
        )),
        "{checks:#?}"
    );
    assert!(checks.contains(&"    if: needs.scope.outputs.tier != 'docs'".to_owned()));
    assert!(
        !checks
            .iter()
            .any(|l| l.starts_with("    runs-on:") || l.starts_with("    steps:"))
    );
    for line in [
        "      commands: \"[\\\"lint\\\",\\\"test\\\",\\\"build\\\"]\"".to_owned(),
        "      stack: rust".to_owned(),
        format!(
            "      runs-on: \"\\\"{}\\\"\"",
            configured::linux_runner().label
        ),
        "      tier: \"${{ needs.scope.outputs.tier }}\"".to_owned(),
    ] {
        assert!(checks.contains(&line), "{line}\n{checks:#?}");
    }
    let (_, required) = jobs.iter().find(|(id, _)| id == "required").unwrap();
    assert!(required.contains(&"    needs: [scope, checks, heldout, workflow-lint]".to_owned()));
}

#[test]
fn the_caller_declares_the_reachability_step_with_its_probe() {
    let repo = rust_repo("cargo test --locked");
    let (notes, steps) = repo.notes_and_steps_as(reusable(), &same_owner_caller());
    assert!(notes.is_empty(), "{notes:?}");
    assert_eq!(steps.len(), 1, "{steps:?}");
    assert!(steps[0].starts_with("reusable-reachable "), "{steps:?}");
    assert!(
        steps[0].contains("reusable-workflow-reachable"),
        "{steps:?}"
    );
    assert!(
        steps[0].contains(&configured::reusable_callee()),
        "{steps:?}"
    );
}

#[test]
fn a_cross_owner_caller_falls_back_to_the_single_repo_workflow_with_a_note() {
    let repo = rust_repo("cargo test --locked");
    assert_eq!(
        repo.workflow_as(reusable(), "acme/shop"),
        repo.workflow(json!({})),
        "the single-repo workflow, unchanged"
    );
    let (notes, steps) = repo.notes_and_steps_as(reusable(), "acme/shop");
    assert_eq!(
        notes,
        [format!(
            "reusable is true but acme/shop cannot call {}, a private repository of another owner; the single-repo workflow renders instead",
            configured::reusable_callee()
        )]
    );
    assert!(steps.is_empty(), "{steps:?}");
}

/// Without a configured callee nothing is called: `reusable: true` gets the
/// single-repo workflow and a note saying why (#1201).
#[test]
fn without_a_configured_callee_reusable_falls_back_with_a_note() {
    let repo = rust_repo("cargo test --locked");
    let raw: Answers = serde_json::from_value(generate(reusable())).unwrap();
    let validated = CiBaseline
        .questions()
        .validate("ci-baseline", &raw, answers::DEFAULT_TIER)
        .unwrap();
    let profile = profile_for(&repo.root).unwrap();
    let source = Source::embedded();
    let previous = empty_lock();
    let resolved = recorded_stack_packs(&repo.root);
    let caller = same_owner_caller();
    let cx = Context::new(
        &repo.root,
        &profile,
        &source,
        &previous,
        &validated,
        &CiBaseline,
        &resolved,
    )
    .with_repository(Some(&caller));
    let answers = CiBaselineAnswers::load(&cx).unwrap();
    assert!(matches!(
        reusable::decide_with(Some(&configured::reusable_callee()), &cx, &answers),
        Ok(reusable::Decision::Call(_))
    ));
    assert_eq!(
        reusable::decide_with(None, &cx, &answers).unwrap(),
        reusable::Decision::Fallback(
            "reusable is true but no reusable_callee is configured; the single-repo workflow renders instead"
                .to_owned()
        )
    );
}

#[test]
fn an_app_whose_setup_differs_from_the_callee_falls_back_with_a_note() {
    // nextest adds a setup step the callee does not carry.
    let repo = rust_repo("cargo nextest run --locked");
    assert_eq!(
        repo.workflow_as(reusable(), &same_owner_caller()),
        repo.workflow(json!({}))
    );
    let (notes, _) = repo.notes_and_steps_as(reusable(), &same_owner_caller());
    assert_eq!(
        notes,
        [
            "reusable is true but the setup of app root (rust) differs from the reusable workflow's; the single-repo workflow renders instead"
        ]
    );
}

#[test]
fn reusable_needs_a_pinned_sha_and_a_single_app() {
    let repo = rust_repo("cargo test --locked");
    for sha in [None, Some("main"), Some("0123")] {
        let raw = match sha {
            None => json!({"reusable": true}),
            Some(s) => json!({"reusable": true, "reusable_sha": s}),
        };
        assert_eq!(
            repo.refusal(raw),
            format!(
                "ci-baseline: reusable is true but reusable_sha is not a 40-hex commit of {}; pin the callee by SHA, never by a branch or tag",
                configured::reusable_callee()
            )
        );
    }
    let mono = monorepo();
    assert_eq!(
        mono.refusal(reusable()),
        "ci-baseline: reusable is true but the repository has several apps; the reusable workflow runs one app at the root, so set reusable=false"
    );
}

fn fragment(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../templates/ci-baseline/fragments")
        .join(name)
}

fn bash(script: &str, dir: &std::path::Path, env: &[(&str, &str)]) -> std::process::Output {
    Command::new("bash")
        .arg(fragment(script))
        .current_dir(dir)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap())
        .envs(env.iter().copied())
        .output()
        .unwrap()
}

#[test]
fn the_callee_checks_its_inputs_before_anything_runs() {
    let dir = tempfile::tempdir().unwrap();
    let good: Vec<(&str, &str)> = vec![
        ("STACK", "rust"),
        ("RUNS_ON", "\"example-linux-2\""),
        ("TIER", "full"),
        ("COMMANDS", "[\"lint\",\"test\"]"),
        ("WORKING_DIRECTORY", "."),
        ("PROFILE_PATH", ".agent-setup/project.json"),
        ("STACKS", "rust python-uv node go"),
        ("LABELS", "\"example-linux-2\" \"ubuntu-24.04\""),
    ];
    let out = bash("reusable-inputs.sh", dir.path(), &good);
    assert!(out.status.success(), "{out:?}");
    for (key, bad) in [
        ("STACK", "swift-ios"),
        ("RUNS_ON", "\"self-hosted\""),
        ("TIER", "partial"),
        ("COMMANDS", "[\"deploy\"]"),
        ("COMMANDS", "[]"),
        ("WORKING_DIRECTORY", "../other"),
        ("PROFILE_PATH", "/etc/passwd"),
    ] {
        let env: Vec<(&str, &str)> = good
            .iter()
            .map(|(k, v)| if *k == key { (*k, bad) } else { (*k, *v) })
            .collect();
        let out = bash("reusable-inputs.sh", dir.path(), &env);
        assert!(!out.status.success(), "{key}={bad} passed: {out:?}");
        assert!(
            String::from_utf8_lossy(&out.stdout).starts_with("::error::"),
            "{key}={bad}: {out:?}"
        );
    }
}

#[test]
fn the_callee_runs_each_declared_command_and_fails_red_on_a_missing_one() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join(".agent-setup")).unwrap();
    fs::write(
        dir.path().join(".agent-setup/project.json"),
        r#"{"commands": {"lint": "echo linted > lint.out", "test": "echo tested > test.out", "build": null}}"#,
    )
    .unwrap();
    let profile = ("PROFILE_PATH", ".agent-setup/project.json");
    let out = bash(
        "reusable-verify.sh",
        dir.path(),
        &[("COMMANDS", "[\"lint\",\"test\"]"), profile],
    );
    assert!(out.status.success(), "{out:?}");
    assert!(dir.path().join("lint.out").is_file() && dir.path().join("test.out").is_file());
    let out = bash(
        "reusable-verify.sh",
        dir.path(),
        &[("COMMANDS", "[\"lint\",\"build\"]"), profile],
    );
    assert!(!out.status.success(), "{out:?}");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains(
            "::error::Verification command missing: commands.build is not declared in .agent-setup/project.json"
        ),
        "{out:?}"
    );
}

// --- T16 (#980): held-out properties with a fresh recorded seed ------------------

const PY_PROPERTIES: &str =
    r#"uv run --frozen pytest -q tests/heldout/properties --hypothesis-seed="$HELDOUT_SEED""#;
const RS_PROPERTIES: &str = "cargo test --locked --test heldout_properties";

/// A python-uv repository at `.` with lint and test declared.
fn python_repo() -> Repo {
    let repo = Repo::with_commands(json!({
        "lint": "uv run --frozen ruff check .",
        "test": "uv run --frozen pytest -q",
    }));
    repo.write("pyproject.toml", "[project]\nname = \"sample\"\n")
        .write("uv.lock", "");
    repo.stack_packs(
        json!({"apps.root.path": ".", "apps.root.stack": "python-uv",
        "apps.root.toolchain_version": "3.13"}),
    );
    repo
}

/// A node repository at `.`: its pack declares no property recipe.
fn node_repo() -> Repo {
    let repo = Repo::with_commands(json!({"test": "npm test"}));
    repo.write("package.json", "{}")
        .write("package-lock.json", "{}");
    repo.stack_packs(json!({"apps.root.path": ".", "apps.root.stack": "node"}));
    repo
}

fn properties(command: &str) -> Value {
    json!({
        "heldout": true,
        "heldout_command": HELDOUT_COMMAND,
        "heldout_properties": true,
        "heldout_properties_command": command,
    })
}

/// The lines of job `id`.
fn job_body(text: &str, id: &str) -> String {
    jobs(text)
        .into_iter()
        .find(|(j, _)| j == id)
        .unwrap_or_else(|| panic!("no job {id}:\n{text}"))
        .1
        .join("\n")
}

#[test]
fn heldout_properties_is_off_by_default_and_examples_default_to_200() {
    let repo = rust_repo("cargo test --locked");
    let answers = repo
        .load(json!({"heldout": true, "heldout_command": HELDOUT_COMMAND}))
        .unwrap();
    assert_eq!(answers.heldout_properties_command, None);
    assert_eq!(answers.heldout_examples, 200);
    let on = repo.load(properties(RS_PROPERTIES)).unwrap();
    assert_eq!(
        on.heldout_properties_command.as_deref(),
        Some(RS_PROPERTIES)
    );
    assert_eq!(on.heldout_examples, 200);
    let more = repo
        .load(json!({"heldout": true, "heldout_command": HELDOUT_COMMAND,
            "heldout_properties": true, "heldout_properties_command": RS_PROPERTIES,
            "heldout_examples": 1000}))
        .unwrap();
    assert_eq!(more.heldout_examples, 1000);
}

#[test]
fn heldout_examples_outside_its_range_refuses() {
    let repo = rust_repo("cargo test --locked");
    for n in [99, 100_001] {
        let mut raw = properties(RS_PROPERTIES);
        raw["heldout_examples"] = json!(n);
        assert!(repo.load(raw).is_err(), "{n}");
    }
}

#[test]
fn heldout_properties_is_read_only_when_heldout_is_true() {
    let repo = rust_repo("cargo test --locked");
    let mut raw = properties(RS_PROPERTIES);
    raw["heldout"] = json!(false);
    let answers = repo.load(raw.clone()).unwrap();
    assert_eq!(answers.heldout_properties_command, None);
    assert!(!job_ids(&repo.workflow(raw)).contains(&"heldout-properties".to_owned()));
}

#[test]
fn heldout_properties_without_a_command_refuses() {
    let repo = rust_repo("cargo test --locked");
    let missing = "ci-baseline: heldout_properties_command missing; the properties under the held-out directory are the point of the job";
    let mut raw = properties(RS_PROPERTIES);
    raw.as_object_mut()
        .unwrap()
        .remove("heldout_properties_command");
    assert_eq!(repo.refusal(raw), missing);
    assert_eq!(repo.refusal(properties("  ")), missing);
}

#[test]
fn a_heldout_properties_command_with_an_expression_refuses() {
    let repo = rust_repo("cargo test --locked");
    assert_eq!(
        repo.refusal(properties("cargo test ${{ github.ref }}")),
        "ci-baseline: heldout_properties_command contains `${{`, which GitHub would evaluate; write the command without it"
    );
}

#[test]
fn heldout_properties_refuses_on_a_pack_without_a_property_recipe() {
    assert_eq!(
        node_repo().refusal(properties("npx vitest run tests/heldout")),
        "ci-baseline: heldout_properties needs a stack pack with a property recipe; node has none"
    );
}

#[test]
fn the_rust_properties_job_exports_the_proptest_seed_and_cases() {
    let repo = rust_repo("cargo test --locked");
    let text = repo.workflow(properties(RS_PROPERTIES));
    golden("heldout-properties-rust.yml", &text);
    assert_eq!(
        job_ids(&text),
        [
            "scope",
            "checks",
            "heldout",
            "heldout-properties",
            "workflow-lint",
            "required"
        ]
    );
    assert_eq!(
        needs_of(&text, "required"),
        "    needs: [scope, checks, heldout, heldout-properties, workflow-lint]"
    );
    assert!(
        text.contains("          DOCS_SKIPPABLE: |-\n            checks\n            heldout\n            heldout-properties\n"),
        "{text}"
    );
    let body = job_body(&text, "heldout-properties");
    for line in [
        "    timeout-minutes: 20",
        "    if: needs.scope.outputs.tier != 'docs'",
        "      - id: seed",
        "        name: Draw the held-out seed",
        "          HELDOUT_SEED: \"${{ steps.seed.outputs.seed }}\"",
        "          HELDOUT_EXAMPLES: \"200\"",
        "          PROPTEST_RNG_SEED: \"${{ steps.seed.outputs.seed }}\"",
        "          PROPTEST_CASES: \"200\"",
        &format!("          HELDOUT_PROPERTIES_COMMAND: {RS_PROPERTIES}"),
        "        if: failure()",
        "          name: heldout-properties-failures",
        "          retention-days: \"7\"",
        "            **/proptest-regressions/",
        "            **/*.proptest-regressions",
    ] {
        assert!(body.lines().any(|l| l == line), "{line}\n{body}");
    }
    assert!(!body.contains("Run declared"), "{body}");
    // Same setup as checks.
    let checks = job_body(&text, "checks");
    let setup: Vec<&str> = checks
        .lines()
        .skip_while(|l| !l.contains("steps:"))
        .take_while(|l| !l.contains("Run declared"))
        .collect();
    let steps: Vec<&str> = body.lines().skip_while(|l| !l.contains("steps:")).collect();
    assert!(setup.len() > 2, "{setup:?}");
    assert_eq!(&steps[..setup.len()], &setup[..]);
}

#[test]
fn the_python_properties_job_passes_the_seed_and_seeds_the_conftest() {
    let repo = python_repo();
    let raw = properties(PY_PROPERTIES);
    let text = repo.workflow(raw.clone());
    golden("heldout-properties-python-uv.yml", &text);
    let body = job_body(&text, "heldout-properties");
    assert!(
        body.contains("--hypothesis-seed=\\\"$HELDOUT_SEED\\\""),
        "{body}"
    );
    assert!(!body.contains("PROPTEST"), "{body}");
    assert!(
        body.contains("          HELDOUT_EXAMPLES: \"200\""),
        "{body}"
    );
    let rendered = repo.render(raw).unwrap();
    let conftest = rendered
        .iter()
        .find(|r| r.path == "tests/heldout/conftest.py")
        .expect("the conftest seed");
    assert_eq!(conftest.class, Ownership::Seed);
    let content = conftest.content.as_deref().unwrap();
    assert!(
        content.contains("settings.load_profile(\"heldout\")"),
        "{content}"
    );
    assert!(content.contains("HELDOUT_EXAMPLES"), "{content}");
    // An answered directory moves it; rust seeds nothing.
    let mut moved = properties(PY_PROPERTIES);
    moved["heldout_dir"] = json!("qa/heldout");
    assert!(
        repo.render(moved)
            .unwrap()
            .iter()
            .any(|r| r.path == "qa/heldout/conftest.py" && r.class == Ownership::Seed)
    );
    let rust = rust_repo("cargo test --locked");
    assert!(
        rust.render(properties(RS_PROPERTIES))
            .unwrap()
            .iter()
            .all(|r| !r.path.ends_with("conftest.py"))
    );
    // Off: no conftest.
    assert!(
        repo.render(json!({"heldout": true, "heldout_command": HELDOUT_COMMAND}))
            .unwrap()
            .iter()
            .all(|r| !r.path.ends_with("conftest.py"))
    );
}

#[test]
fn install_writes_the_conftest_seed_only_when_absent() {
    let fresh = python_repo();
    fresh.file("tests/heldout/test_kept.py");
    let path = answers::path("ci-baseline");
    let file =
        json!({"module": "ci-baseline", "version": "1.0.0", "answers": properties(PY_PROPERTIES)});
    fresh.write(&path, &serde_json::to_string_pretty(&file).unwrap());
    let out = fresh.install();
    assert!(out.status.success(), "{out:?}");
    assert!(
        stdout(&out)
            .lines()
            .any(|l| l == "WRITE tests/heldout/conftest.py [seed:ci-baseline]"),
        "{}",
        stdout(&out)
    );
    let kept = python_repo();
    let own = "# the project's own conftest\n";
    kept.write("tests/heldout/conftest.py", own);
    kept.write(&path, &serde_json::to_string_pretty(&file).unwrap());
    let out = kept.install();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(kept.read("tests/heldout/conftest.py").unwrap(), own);
}

#[test]
fn under_workflow_existing_the_properties_job_joins_agentic_required() {
    for (repo, command, name) in [
        (
            rust_repo("cargo test --locked"),
            RS_PROPERTIES,
            "existing-heldout-properties-rust.yml",
        ),
        (
            python_repo(),
            PY_PROPERTIES,
            "existing-heldout-properties-python-uv.yml",
        ),
    ] {
        let mut raw = properties(command);
        raw["workflow"] = json!("existing");
        raw["aggregate_check"] = json!("Rust (linux)");
        let text = repo
            .rendered(raw, ".github/workflows/agentic-security.yml")
            .unwrap();
        golden(name, &text);
        assert_eq!(
            job_ids(&text),
            ["scope", "heldout", "heldout-properties", "agentic-required"],
            "{name}"
        );
        assert_eq!(
            needs_of(&text, "agentic-required"),
            "    needs: [scope, heldout, heldout-properties]"
        );
    }
}

/// `timeout-minutes` of each job of `text`, in workflow order.
fn timeouts(text: &str) -> Vec<(String, String)> {
    jobs(text)
        .into_iter()
        .filter_map(|(id, lines)| {
            let timeout = lines
                .iter()
                .find_map(|l| l.trim().strip_prefix("timeout-minutes: "))?
                .to_owned();
            Some((id, timeout))
        })
        .collect()
}

/// The timeouts of the budget-derived jobs: checks, heldout, heldout-properties.
fn verification_timeouts(repo: &Repo) -> Vec<(String, String)> {
    let text = repo.workflow(properties(RS_PROPERTIES));
    timeouts(&text)
        .into_iter()
        .filter(|(id, _)| ["checks", "heldout", "heldout-properties"].contains(&id.as_str()))
        .collect()
}

fn triple(checks: &str, heldout: &str, properties: &str) -> Vec<(String, String)> {
    [
        ("checks", checks),
        ("heldout", heldout),
        ("heldout-properties", properties),
    ]
    .into_iter()
    .map(|(a, b)| (a.to_owned(), b.to_owned()))
    .collect()
}

/// #1228: the held-out jobs derive from the budget like `checks`;
/// heldout-properties never drops below its 20 minutes.
#[test]
fn the_heldout_jobs_follow_the_cycle_budget() {
    let repo = rust_repo("cargo test --locked");
    assert_eq!(verification_timeouts(&repo), triple("15", "15", "20"));
    repo.ci("cycle_budget_minutes", json!(10));
    assert_eq!(verification_timeouts(&repo), triple("15", "15", "20"));
    repo.ci("cycle_budget_minutes", json!(18));
    assert_eq!(verification_timeouts(&repo), triple("27", "27", "27"));
}

/// #1228: every budget-derived timeout is capped at GitHub's 360-minute job
/// maximum, and the plan notes the jobs it capped with their uncapped value;
/// a budget landing exactly on 360 is not noted.
#[test]
fn budget_derived_timeouts_are_capped_at_360_and_noted() {
    let repo = rust_repo("cargo test --locked");
    let over = |notes: &[String]| -> Vec<String> {
        notes
            .iter()
            .filter(|n| n.contains("360-minute"))
            .cloned()
            .collect()
    };
    repo.ci("cycle_budget_minutes", json!(240));
    assert_eq!(verification_timeouts(&repo), triple("360", "360", "360"));
    assert_eq!(
        over(&repo.notes(properties(RS_PROPERTIES))),
        Vec::<String>::new()
    );
    repo.ci("cycle_budget_minutes", json!(300));
    assert_eq!(verification_timeouts(&repo), triple("360", "360", "360"));
    assert_eq!(
        over(&repo.notes(properties(RS_PROPERTIES))),
        [
            "ci.cycle_budget_minutes 300 derives timeouts above GitHub's 360-minute job maximum (checks 450, heldout 450, heldout-properties 450); those jobs render timeout-minutes: 360"
        ]
    );
    // scope, workflow-lint and required keep their fixed 5.
    let text = repo.workflow(properties(RS_PROPERTIES));
    for (id, timeout) in timeouts(&text) {
        if ["scope", "workflow-lint", "required"].contains(&id.as_str()) {
            assert_eq!(timeout, "5", "{id}");
        }
    }
}

#[test]
fn heldout_properties_is_a_built_in_job_skippable_under_tier_docs() {
    assert!(ci_baseline::compose::BUILT_IN_JOBS.contains(&"heldout-properties"));
    assert!(scope::SKIPPABLE.contains(&("heldout-properties", scope::SkipWhen::TierDocs)));
}

/// `heldout-seed.sh` under bash with `GITHUB_OUTPUT` and `GITHUB_STEP_SUMMARY`
/// as files: its stdout, the output file and the summary.
fn draw_seed() -> (std::process::Output, String, String) {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("output");
    let summary = dir.path().join("summary");
    let out = run_fragment(
        "heldout-seed.sh",
        json!({}),
        &[
            ("GITHUB_OUTPUT", output.to_str().unwrap()),
            ("GITHUB_STEP_SUMMARY", summary.to_str().unwrap()),
        ],
    );
    (
        out,
        fs::read_to_string(output).unwrap_or_default(),
        fs::read_to_string(summary).unwrap_or_default(),
    )
}

#[test]
fn the_seed_fragment_prints_records_and_exports_a_fresh_32_bit_seed() {
    let (out, output, summary) = draw_seed();
    assert!(out.status.success(), "{out:?}");
    let printed = stdout(&out);
    let seed: u64 = printed
        .lines()
        .find_map(|l| l.strip_prefix("seed: "))
        .unwrap_or_else(|| panic!("no seed: line in {printed}"))
        .parse()
        .unwrap();
    assert!(seed <= u64::from(u32::MAX), "{seed}");
    assert_eq!(output, format!("seed={seed}\n"));
    assert!(summary.contains(&format!("seed: {seed}")), "{summary}");
    let (_, again, _) = draw_seed();
    assert_ne!(output, again, "two runs drew the same seed");
}

#[test]
fn the_seed_fragment_fails_red_without_an_output_file() {
    // Removed explicitly: under GitHub Actions the test runner has its own.
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../templates/ci-baseline/fragments/heldout-seed.sh");
    let out = Command::new("bash")
        .arg(script)
        .env_remove("GITHUB_OUTPUT")
        .output()
        .unwrap();
    assert!(!out.status.success(), "{out:?}");
}

#[test]
fn the_properties_fragment_needs_the_seed_and_the_examples() {
    let fixture = r#"test -n "$HELDOUT_SEED" && test -n "$HELDOUT_EXAMPLES" && echo "ran $HELDOUT_SEED $HELDOUT_EXAMPLES""#;
    let fragment = "heldout-properties.sh";
    let ok = run_fragment(
        fragment,
        json!({}),
        &[
            ("HELDOUT_PROPERTIES_COMMAND", fixture),
            ("HELDOUT_SEED", "42"),
            ("HELDOUT_EXAMPLES", "200"),
        ],
    );
    assert!(ok.status.success(), "{ok:?}");
    assert!(stdout(&ok).contains("ran 42 200"), "{ok:?}");
    for missing in [
        "HELDOUT_SEED",
        "HELDOUT_EXAMPLES",
        "HELDOUT_PROPERTIES_COMMAND",
    ] {
        let env: Vec<(&str, &str)> = [
            ("HELDOUT_PROPERTIES_COMMAND", fixture),
            ("HELDOUT_SEED", "42"),
            ("HELDOUT_EXAMPLES", "200"),
        ]
        .into_iter()
        .filter(|(k, _)| *k != missing)
        .collect();
        let red = run_fragment(fragment, json!({}), &env);
        assert!(!red.status.success(), "{missing}: {red:?}");
    }
    // A failing property names the seed to replay.
    let red = run_fragment(
        fragment,
        json!({}),
        &[
            ("HELDOUT_PROPERTIES_COMMAND", "false | cat"),
            ("HELDOUT_SEED", "42"),
            ("HELDOUT_EXAMPLES", "200"),
        ],
    );
    assert!(!red.status.success(), "pipefail: {red:?}");
    assert!(stdout(&red).contains("HELDOUT_SEED=42"), "{red:?}");
}

// ---- qa T8 (#1005): the screenshot baseline in the derived protected_paths ----

/// The default protected paths followed by `extra`.
fn defaults_and(extra: &[&str]) -> Vec<String> {
    scope::DEFAULT_PROTECTED_PATHS
        .iter()
        .chain(extra)
        .map(|p| (*p).to_owned())
        .collect()
}

#[test]
fn a_seeded_web_protects_its_snapshots_under_qa_web() {
    let repo = rust_repo("cargo test --locked");
    repo.qa(json!({"api": false, "web": "seeded", "web_start": "npm start"}));
    let answers = repo.load(json!({})).unwrap();
    assert_eq!(
        answers.protected_paths,
        defaults_and(&["qa/web/*-snapshots/**"])
    );
}

#[test]
fn a_project_web_protects_every_snapshots_directory() {
    let repo = rust_repo("cargo test --locked");
    repo.file("playwright.config.ts");
    repo.qa(json!({"api": false, "web": "project", "web_start": "npm run dev"}));
    let answers = repo.load(json!({})).unwrap();
    assert_eq!(
        answers.protected_paths,
        defaults_and(&["**/*-snapshots/**"])
    );
}

#[test]
fn an_answered_web_dir_and_qa_dir_move_the_glob() {
    let repo = rust_repo("cargo test --locked");
    repo.qa(
        json!({"api": false, "qa_dir": "./checks/", "web": "seeded", "web_start": "npm start"}),
    );
    assert_eq!(
        repo.load(json!({})).unwrap().protected_paths,
        defaults_and(&["checks/web/*-snapshots/**"])
    );
    repo.qa(json!({"api": false, "web": "seeded", "web_start": "npm start", "web_dir": "frontend/e2e/"}));
    assert_eq!(
        repo.load(json!({})).unwrap().protected_paths,
        defaults_and(&["frontend/e2e/*-snapshots/**"])
    );
}

#[test]
fn no_web_or_no_qa_adds_nothing() {
    let repo = rust_repo("cargo test --locked");
    let defaults = defaults_and(&[]);
    assert_eq!(repo.load(json!({})).unwrap().protected_paths, defaults);
    for qa in [
        json!({"api": false}),
        json!({"api": false, "web": "none"}),
        json!({"api": true, "api_start": "cargo run"}),
    ] {
        repo.qa(qa.clone());
        assert_eq!(
            repo.load(json!({})).unwrap().protected_paths,
            defaults,
            "{qa}"
        );
    }
}

#[test]
fn an_answered_protected_paths_list_is_never_modified() {
    let repo = rust_repo("cargo test --locked");
    repo.qa(json!({"api": false, "web": "seeded", "web_start": "npm start"}));
    let answers = repo.load(json!({"protected_paths": ["infra/**"]})).unwrap();
    assert_eq!(answers.protected_paths, ["infra/**"]);
}

#[test]
fn each_monorepo_app_with_a_web_protects_its_own_snapshots() {
    let repo = monorepo();
    repo.write("apps/web/playwright.config.ts", "");
    repo.qa(json!({"api": false, "apps": ["backend", "web"],
                   "apps.backend.api": false, "apps.web.api": false,
                   "apps.backend.web": "seeded", "apps.backend.web_start": "uv run serve",
                   "apps.web.web": "project", "apps.web.web_start": "npm run dev"}));
    assert_eq!(
        repo.load(json!({})).unwrap().protected_paths,
        defaults_and(&[
            "apps/backend/qa/web/*-snapshots/**",
            "apps/web/*-snapshots/**"
        ])
    );
}

#[test]
fn the_snapshot_glob_reaches_the_scope_job_and_matches_the_golden() {
    let repo = rust_repo("cargo test --locked");
    repo.qa(json!({"api": false, "web": "seeded", "web_start": "npm start"}));
    let text = repo.workflow(json!({}));
    assert!(
        text.contains("            tests/heldout/**\n            qa/web/*-snapshots/**\n"),
        "{text}"
    );
    golden("qa-web.yml", &text);
}

#[test]
fn a_derived_web_protects_its_snapshots_without_a_web_answer() {
    // T4 (#1001): `@playwright/test` and a root config derive `web: project`.
    let repo = rust_repo("cargo test --locked");
    repo.write(
        "package.json",
        r#"{"devDependencies": {"@playwright/test": "1.56.1"}}"#,
    )
    .write("playwright.config.ts", "export default {};\n");
    repo.qa(json!({"api": false, "web_start": "npm run dev"}));
    assert_eq!(
        repo.load(json!({})).unwrap().protected_paths,
        defaults_and(&["**/*-snapshots/**"])
    );
    // A front-end framework without Playwright derives `web: seeded`.
    let repo = rust_repo("cargo test --locked");
    repo.write("package.json", r#"{"dependencies": {"react": "19.0.0"}}"#);
    repo.qa(json!({"api": false, "web_start": "npm run dev"}));
    assert_eq!(
        repo.load(json!({})).unwrap().protected_paths,
        defaults_and(&["qa/web/*-snapshots/**"])
    );
    // An answered `web: none` wins over the derivation.
    repo.qa(json!({"api": false, "web": "none"}));
    assert_eq!(
        repo.load(json!({})).unwrap().protected_paths,
        defaults_and(&[])
    );
}

#[test]
fn a_derived_monorepo_app_web_protects_its_own_snapshots() {
    let repo = monorepo();
    repo.write(
        "apps/web/package.json",
        r#"{"devDependencies": {"@playwright/test": "1.56.1"}}"#,
    )
    .write("apps/web/playwright.config.ts", "");
    repo.qa(json!({"api": false, "apps": ["web"], "apps.web.api": false,
                   "apps.web.web_start": "npm run dev"}));
    assert_eq!(
        repo.load(json!({})).unwrap().protected_paths,
        defaults_and(&["apps/web/*-snapshots/**"])
    );
}

// --- #1170: services a declared command needs ----------------------------------------

const PG_IMAGE: &str =
    "postgres:17-alpine@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn postgres_declaration() -> Value {
    json!({
        "postgres": {
            "image": PG_IMAGE,
            "env": {"POSTGRES_USER": "test", "POSTGRES_PASSWORD": "test", "POSTGRES_DB": "test"},
            "ports": ["5432:5432"],
            "health_cmd": "pg_isready -U test"
        }
    })
}

/// The YAML of job `id` parsed back, as GitHub reads it.
fn parsed_job(text: &str, id: &str) -> yaml_rust2::Yaml {
    let docs = yaml_rust2::YamlLoader::load_from_str(text).unwrap();
    docs[0]["jobs"][id].clone()
}

fn assert_postgres(job: &yaml_rust2::Yaml, id: &str) {
    let service = &job["services"]["postgres"];
    assert_eq!(service["image"].as_str(), Some(PG_IMAGE), "{id}: {job:?}");
    assert_eq!(service["env"]["POSTGRES_DB"].as_str(), Some("test"), "{id}");
    assert_eq!(service["ports"][0].as_str(), Some("5432:5432"), "{id}");
    assert_eq!(
        service["options"].as_str(),
        Some(
            "--health-cmd \"pg_isready -U test\" --health-interval 5s --health-timeout 5s --health-retries 20"
        ),
        "{id}"
    );
    assert_eq!(
        job["env"]["TEST_DATABASE_URL"].as_str(),
        Some("postgresql://test:test@localhost:5432/test"),
        "{id}"
    );
}

#[test]
fn a_root_profile_declaring_a_service_gives_it_to_checks_and_each_shard() {
    let repo = rust_repo("cargo test --locked");
    repo.ci("services", postgres_declaration()).ci(
        "env",
        json!({"TEST_DATABASE_URL": "postgresql://test:test@localhost:5432/test"}),
    );
    let text = repo.workflow(json!({}));
    assert_postgres(&parsed_job(&text, "checks"), "checks");
    assert!(parsed_job(&text, "scope")["services"].is_badvalue());
    repo.ci(
        "shards",
        json!({"count": 2, "command": "cargo test -- --shard {shard}/{count}"}),
    );
    let text = repo.workflow(json!({}));
    assert_postgres(&parsed_job(&text, "shard"), "shard");
}

#[test]
fn a_monorepo_app_declaring_a_service_gives_it_to_its_own_job_only() {
    let repo = monorepo();
    repo.write(
        "apps/backend/.agent-setup/project.json",
        &json!({
            "commands": {"lint": "uv run ruff check .", "test": "uv run pytest"},
            "ci": {
                "services": postgres_declaration(),
                "env": {"TEST_DATABASE_URL": "postgresql://test:test@localhost:5432/test"}
            }
        })
        .to_string(),
    );
    let text = repo.workflow(json!({}));
    assert_postgres(&parsed_job(&text, "backend-checks"), "backend-checks");
    let web = parsed_job(&text, "web-checks");
    assert!(
        web["services"].is_badvalue() && web["env"].is_badvalue(),
        "{web:?}"
    );
}

#[test]
fn an_image_without_a_digest_or_a_value_with_an_expression_refuses() {
    let repo = rust_repo("cargo test --locked");
    repo.ci("services", json!({"postgres": {"image": "postgres:17"}}));
    assert_eq!(
        repo.render(json!({})).err().unwrap().to_string(),
        "ci-baseline: service postgres in .agent-setup/project.json is not pinned by digest: postgres:17; declare postgres:17@sha256:<digest>"
    );
    repo.ci("services", postgres_declaration())
        .ci("env", json!({"TEST_DATABASE_URL": "${{ secrets.DB }}"}));
    assert_eq!(
        repo.render(json!({})).err().unwrap().to_string(),
        "ci-baseline: ci.env.TEST_DATABASE_URL in .agent-setup/project.json holds an expression; ci.services and ci.env take literal values, never a secret"
    );
    repo.ci("env", json!({})).ci(
        "services",
        json!({"postgres": {"image": PG_IMAGE, "ports": ["x"]}}),
    );
    assert!(
        repo.render(json!({}))
            .err()
            .unwrap()
            .to_string()
            .starts_with("ci-baseline: ci.services.postgres.ports in .agent-setup/project.json is not a valid declaration"),
    );
}

#[test]
fn without_a_declaration_the_goldens_carry_no_service() {
    for (name, text) in every_golden() {
        assert!(!text.contains("\n    services:"), "{name}");
    }
}

#[test]
fn a_foreign_workflow_job_with_services_is_noted_never_copied() {
    let repo = rust_repo("cargo test --locked");
    repo.write(
        ".github/workflows/legacy.yml",
        "name: legacy\non: push\njobs:\n  tests:\n    runs-on: ubuntu-24.04\n    services:\n      db:\n        image: postgres:17\n    steps:\n      - run: make test\n",
    );
    let notes = repo.notes(json!({}));
    assert!(
        notes.contains(&".github/workflows/legacy.yml job tests starts services (db); declare what the generated jobs need under ci.services in .agent-setup/project.json".to_owned()),
        "{notes:#?}"
    );
    let text = repo
        .rendered(json!({}), ".github/workflows/agentic-ci.yml")
        .unwrap();
    assert!(!text.contains("services:"), "{text}");
}

#[test]
fn a_root_declaration_with_a_reusable_checks_refuses() {
    let repo = rust_repo("cargo test --locked");
    repo.ci("services", postgres_declaration());
    assert_eq!(
        repo.render_as(reusable(), &same_owner_caller())
            .err()
            .unwrap()
            .to_string(),
        "ci-baseline: ci.services and ci.env need checks to run in this workflow; reusable: true calls a workflow that cannot carry them"
    );
}

// ---- #1354: generate → existing keeps the generated workflow until it is retired ----

const GENERATED: &str = ".github/workflows/agentic-ci.yml";

impl Repo {
    fn configure_ci(&self, sets: &[&str]) -> std::process::Output {
        let mut args = vec!["configure", "<repo>", "ci-baseline"];
        for set in sets {
            args.extend(["--set", set]);
        }
        args.push("--apply");
        self.cli(&args)
    }
}

#[test]
fn switching_to_existing_keeps_the_generated_workflow_until_it_is_retired() {
    let repo = brownfield_repo();
    assert!(repo.install().status.success());
    let generated = repo.read(GENERATED).unwrap();

    // Step 1: both aggregates keep reporting on the default branch.
    let result = repo.configure_ci(&["workflow=existing", "aggregate_check=verify"]);
    assert!(result.status.success(), "{result:?}");
    let out = stdout(&result);
    assert!(!out.contains(&format!("DELETE {GENERATED}")), "{out}");
    assert_eq!(repo.read(GENERATED).unwrap(), generated);
    assert_eq!(repo.lock_entry(GENERATED)["class"], "managed");
    let doctor = stdout(&repo.cli(&["doctor", "<repo>"]));
    assert!(
        doctor
            .lines()
            .any(|l| l.starts_with("STEP [")
                && l.contains(":ci-baseline] retire-generated-workflow — ")),
        "{doctor}"
    );
    let again = repo.cli(&["install", "<repo>"]);
    assert!(
        stdout(&again).lines().any(|l| l == "No changes."),
        "{again:?}"
    );

    // Step 2: once the ruleset requires the new checks, the answer retires it.
    let result = repo.configure_ci(&["retire_generated=true"]);
    assert!(result.status.success(), "{result:?}");
    let out = stdout(&result);
    assert!(
        out.lines()
            .any(|l| l == format!("DELETE {GENERATED} [managed:ci-baseline]")),
        "{out}"
    );
    assert!(repo.read(GENERATED).is_none());
    let doctor = stdout(&repo.cli(&["doctor", "<repo>"]));
    assert!(!doctor.contains("retire-generated-workflow"), "{doctor}");
}

#[test]
fn a_repository_installed_as_existing_never_sees_the_retirement_step() {
    let repo = brownfield_repo();
    let answers = repo.root.join("answers.json");
    fs::write(
        &answers,
        json!({"modules": {"ci-baseline": {"workflow": "existing", "aggregate_check": "verify"}}})
            .to_string(),
    )
    .unwrap();
    let result = repo.cli(&[
        "install",
        "<repo>",
        "--module",
        "stack-packs",
        "--module",
        "ci-baseline",
        "--answers",
        answers.to_str().unwrap(),
        "--apply",
    ]);
    assert!(result.status.success(), "{result:?}");
    assert!(repo.read(GENERATED).is_none());
    let doctor = stdout(&repo.cli(&["doctor", "<repo>"]));
    assert!(!doctor.contains("retire-generated-workflow"), "{doctor}");
}

// ---- #1362: ci-baseline's shells are embedded without comment-only lines (#1088) ----

#[test]
fn every_embedded_ci_baseline_shell_is_its_fragment_without_comment_only_lines() {
    use brakes::modules::ci_baseline::render::{
        DECLARED_SH, HELDOUT_PENDING_SH, HELDOUT_SH, SHARD_SH,
    };
    use brakes::modules::security::embed::without_comment_lines;
    let body = |shell: &str| -> String {
        without_comment_lines(shell)
            .lines()
            .map(|l| {
                if l.is_empty() {
                    "\n".to_owned()
                } else {
                    format!("          {l}\n")
                }
            })
            .collect()
    };
    let goldens: BTreeMap<String, String> = every_golden().into_iter().collect();
    for (golden, name, shell) in [
        ("single.yml", "scope.sh", scope::FRAGMENT),
        ("single.yml", "declared.sh", DECLARED_SH),
        ("single.yml", "heldout-pending.sh", HELDOUT_PENDING_SH),
        ("single.yml", "required.sh", ci_baseline::REQUIRED_SH),
        ("sharded.yml", "shard.sh", SHARD_SH),
        ("heldout.yml", "heldout.sh", HELDOUT_SH),
    ] {
        let text = &goldens[golden];
        assert_ne!(without_comment_lines(shell), shell, "{name} has comments");
        assert!(text.contains(&body(shell)), "{golden}: {name}");
    }
    // No comment-only line reaches a `run:` body of any golden.
    for (name, text) in &goldens {
        assert!(
            !text.lines().any(|l| l.starts_with("          #")
                && !l.starts_with("          #!")
                && !l.starts_with("          # shellcheck ")),
            "{name}"
        );
    }
}
