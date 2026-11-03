//! stack-packs detection (SPEC-stack-packs.md, Commands; Evidence and
//! proposals; #758): `propose` reads files only, prints evidence and proposals
//! for `null` fields, `configure <repo> stack-packs` with no flags prints the
//! block and writes nothing, and `doctor` reports `stack.unconfigured` while no
//! answers record a detected stack. The fixtures under
//! `tests/fixtures/stack-packs/` are generic shapes: a Rust workspace at the
//! root, a pnpm monorepo with a uv service, a Go module under a Rust workspace.
use brakes::engine::answers::Answers;
use brakes::modules::stack_packs::detect;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::TempDir;

struct Repo {
    _temp: TempDir,
    root: PathBuf,
}

impl Repo {
    /// A git repository holding a copy of the fixture `name` (`None`: empty).
    fn new(fixture: Option<&str>) -> Self {
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
        if let Some(name) = fixture {
            let source = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/stack-packs")
                .join(name);
            copy_tree(&source, &root);
        }
        Self { _temp: temp, root }
    }

    /// The same repository with the baseline installed, as `configure` needs.
    fn installed(fixture: Option<&str>) -> Self {
        let repo = Self::new(fixture);
        let result = repo.cli(&["install", "<repo>", "--new-personal", "--apply"]);
        assert!(result.status.success(), "{result:?}");
        repo
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

    fn stdout(&self, args: &[&str]) -> String {
        let result = self.cli(args);
        assert!(result.status.success(), "{result:?}");
        String::from_utf8(result.stdout).unwrap()
    }

    fn file(&self, path: &str, content: &str) -> &Self {
        let full = self.root.join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, content).unwrap();
        self
    }

    fn block(&self) -> String {
        detect::proposal_block(&self.root).unwrap()
    }

    fn read(&self, path: &str) -> String {
        fs::read_to_string(self.root.join(path)).unwrap()
    }

    /// Every file under the root but `.git`, with its bytes.
    fn tree(&self) -> BTreeMap<PathBuf, Vec<u8>> {
        let mut files = BTreeMap::new();
        collect(&self.root, &self.root, &mut files);
        files
    }

    /// Sets `commands.<name>` in the root `project.json`.
    fn declare(&self, name: &str, command: &str) {
        let path = self.root.join(".agent-setup/project.json");
        let mut profile: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        profile["commands"][name] = json!(command);
        fs::write(
            &path,
            serde_json::to_string_pretty(&profile).unwrap() + "\n",
        )
        .unwrap();
    }
}

fn copy_tree(from: &Path, to: &Path) {
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            fs::create_dir_all(&target).unwrap();
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn collect(root: &Path, dir: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
    for entry in fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        if entry.file_name() == ".git" {
            continue;
        }
        if entry.file_type().unwrap().is_dir() {
            collect(root, &entry.path(), files);
        } else {
            let path = entry.path();
            files.insert(
                path.strip_prefix(root).unwrap().to_path_buf(),
                fs::read(&path).unwrap(),
            );
        }
    }
}

const RUST_ROOT: &str = r#"stack-packs: proposals (nothing written; confirm with --set or --answers)
  app `root` at `.`: stack rust
    evidence: Cargo.toml (workspace, rust-version = "1.85"), Cargo.lock
    commands (project.json fields already declared are kept; proposed only for null):
      build:  proposed  "cargo build --workspace --all-targets --locked"
      test:   proposed  "cargo test --workspace --locked"
      lint:   proposed  "cargo clippy --workspace --all-targets --locked -- -D warnings"
      verify: proposed  "cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked"
    seeds on apply: Dockerfile, .dockerignore
"#;

const NODE_MONOREPO: &str = r#"stack-packs: proposals (nothing written; confirm with --set or --answers)
  app `root` at `.`: stack node
    evidence: package.json (packageManager = "pnpm@9.12.0", engines.node = ">=22", scripts: build, lint, test), pnpm-lock.yaml
    commands (project.json fields already declared are kept; proposed only for null):
      build:  proposed  "pnpm run build"
      test:   proposed  "pnpm test"
      lint:   proposed  "pnpm run lint"
      verify: proposed  "pnpm run lint && pnpm test"
    seeds on apply: .nvmrc, Dockerfile, .dockerignore
    info: no known test runner (vitest, jest, @playwright/test in devDependencies, or node --test in scripts.test); qa asks for it
  app `api` at `services/api`: stack python-uv
    evidence: pyproject.toml (requires-python = ">=3.12"), uv.lock, .python-version (3.12)
    commands (project.json fields already declared are kept; proposed only for null):
      test:   proposed  "uv run --frozen pytest -q"
      lint:   proposed  "uv run --frozen ruff check ."
      verify: proposed  "uv run --frozen ruff check . && uv run --frozen pytest -q"
    seeds on apply: services/api/.python-version, services/api/Dockerfile, services/api/.dockerignore
"#;

const GO_UNDER_RUST: &str = r#"stack-packs: proposals (nothing written; confirm with --set or --answers)
  app `root` at `.`: stack rust
    evidence: Cargo.toml (workspace), Cargo.lock
    commands (project.json fields already declared are kept; proposed only for null):
      build:  proposed  "cargo build --workspace --all-targets --locked"
      test:   proposed  "cargo test --workspace --locked"
      lint:   proposed  "cargo clippy --workspace --all-targets --locked -- -D warnings"
      verify: proposed  "cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked"
    seeds on apply: Dockerfile, .dockerignore
  app `probe` at `tools/probe`: stack go
    evidence: go.mod (go 1.23, toolchain go1.23.4), go.sum
    commands (project.json fields already declared are kept; proposed only for null):
      build:  proposed  "go build ./..."
      test:   proposed  "go test ./..."
      lint:   proposed  "go vet ./..."
      verify: proposed  "go mod verify && go vet ./... && go test ./..."
    seeds on apply: tools/probe/Dockerfile, tools/probe/.dockerignore
"#;

/// Four apps under `apps/` (slice 3, #768): the device packs beside the two
/// server packs; the Xcode project shares one scheme, the Gradle build has
/// its wrapper with a checksum.
const FOUR_APP_MONOREPO: &str = r#"stack-packs: proposals (nothing written; confirm with --set or --answers)
  app `android` at `apps/android`: stack kotlin-android
    evidence: settings.gradle.kts, build.gradle.kts, gradlew, gradle/wrapper/gradle-wrapper.properties (gradle 9.6.0, distributionSha256Sum)
    commands (project.json fields already declared are kept; proposed only for null):
      test:   proposed  "./gradlew test"
      verify: proposed  "./gradlew test"
    seeds on apply: apps/android/.java-version
  app `backend` at `apps/backend`: stack python-uv
    evidence: pyproject.toml (requires-python = ">=3.13"), uv.lock
    commands (project.json fields already declared are kept; proposed only for null):
      test:   proposed  "uv run --frozen pytest -q"
      lint:   proposed  "uv run --frozen ruff check ."
      verify: proposed  "uv run --frozen ruff check . && uv run --frozen pytest -q"
    seeds on apply: apps/backend/.python-version, apps/backend/Dockerfile, apps/backend/.dockerignore
  app `ios` at `apps/ios`: stack swift-ios
    evidence: App.xcodeproj (shared schemes: App)
    commands (project.json fields already declared are kept; proposed only for null):
      test:   proposed  "xcodebuild test -scheme App"
      verify: proposed  "xcodebuild test -scheme App"
    seeds on apply: apps/ios/.xcode-version
  app `web` at `apps/web`: stack node
    evidence: package.json (scripts: build, lint, test, test runner: vitest), package-lock.json
    commands (project.json fields already declared are kept; proposed only for null):
      build:  proposed  "npm run build"
      test:   proposed  "npm test"
      lint:   proposed  "npm run lint"
      verify: proposed  "npm run lint && npm test"
    seeds on apply: apps/web/.nvmrc, apps/web/Dockerfile, apps/web/.dockerignore
"#;

const EMPTY: &str = "stack-packs: proposals (nothing written; confirm with --set or --answers)
  no stack evidence found
";

/// A dbt project at the root (slice 4, #769) with packages, their lock and a
/// `.sqlfluff` declaring the dialect and the dbt templater.
const DBT_PROJECT: &str = r#"stack-packs: proposals (nothing written; confirm with --set or --answers)
  app `root` at `.`: stack sql-dbt
    evidence: dbt_project.yml (name = "analytics", profile = "analytics", require-dbt-version = ">=1.12.0"), packages.yml, package-lock.yml, .sqlfluff (dialect = postgres, templater = dbt)
    commands (project.json fields already declared are kept; proposed only for null):
      test:   proposed  "dbt build"
      lint:   proposed  "sqlfluff lint"
      verify: proposed  "sqlfluff lint && dbt build"
    seeds on apply: .python-version
"#;

const NO_SQLFLUFF: &str = "    info: sqlfluff lint is not proposed: no .sqlfluff declares the dialect and the templater; add one or declare commands.lint\n";

const NO_SCHEME: &str = "    info: xcodebuild test needs a scheme and none is proposed: share exactly one scheme in the project, or declare commands.test with -scheme <name>\n";

#[test]
fn each_fixture_yields_its_golden_block() {
    for (fixture, golden) in [
        (Some("rust-root"), RUST_ROOT),
        (Some("node-monorepo"), NODE_MONOREPO),
        (Some("go-under-rust"), GO_UNDER_RUST),
        (Some("four-app-monorepo"), FOUR_APP_MONOREPO),
        (Some("dbt-project"), DBT_PROJECT),
        (None, EMPTY),
    ] {
        assert_eq!(Repo::new(fixture).block(), golden, "fixture {fixture:?}");
    }
}

#[test]
fn a_swift_package_without_an_xcode_project_proposes_swiftpm() {
    let repo = Repo::new(None);
    repo.file("Package.swift", "// swift-tools-version:6.0\n")
        .file(".xcode-version", "27.1\n");
    assert_eq!(
        repo.block(),
        r#"stack-packs: proposals (nothing written; confirm with --set or --answers)
  app `root` at `.`: stack swift-ios
    evidence: Package.swift, .xcode-version (27.1)
    commands (project.json fields already declared are kept; proposed only for null):
      build:  proposed  "swift build"
      test:   proposed  "swift test"
      verify: proposed  "swift test"
    seeds on apply: .xcode-version
"#
    );
}

#[test]
fn an_xcode_project_without_exactly_one_shared_scheme_proposes_no_test_and_says_why() {
    let repo = Repo::new(None);
    repo.file("ios/App.xcodeproj/project.pbxproj", "// !$*UTF8*$!\n");
    let block = repo.block();
    assert!(
        block.contains("  app `ios` at `ios`: stack swift-ios\n    evidence: App.xcodeproj (no shared schemes)\n    seeds on apply: ios/.xcode-version\n"),
        "{block}"
    );
    assert!(block.contains(NO_SCHEME), "{block}");
    assert!(!block.contains("proposed  \""), "{block}");
    assert!(!block.contains("commands ("), "{block}");
    repo.file("ios/App.xcodeproj/xcshareddata/xcschemes/App.xcscheme", "")
        .file(
            "ios/App.xcodeproj/xcshareddata/xcschemes/AppUITests.xcscheme",
            "",
        );
    let block = repo.block();
    assert!(
        block.contains("    evidence: App.xcodeproj (shared schemes: App, AppUITests)\n"),
        "{block}"
    );
    assert!(block.contains(NO_SCHEME), "{block}");
    // Two projects: no scheme is picked either, even with one scheme each.
    let repo = Repo::new(None);
    repo.file("A.xcodeproj/xcshareddata/xcschemes/A.xcscheme", "")
        .file("B.xcodeproj/xcshareddata/xcschemes/B.xcscheme", "")
        .file("Package.swift", "");
    let block = repo.block();
    assert!(
        block.contains(
            "    evidence: A.xcodeproj (shared schemes: A), B.xcodeproj (shared schemes: B), Package.swift\n"
        ),
        "{block}"
    );
    assert!(block.contains(NO_SCHEME), "{block}");
    assert!(!block.contains("swift test"), "{block}");
}

#[test]
fn a_gradle_build_without_the_wrapper_is_not_proposed_and_the_wrapper_fields_are_evidence() {
    let repo = Repo::new(None);
    repo.file("settings.gradle.kts", "rootProject.name = \"x\"\n");
    assert_eq!(
        repo.block(),
        "stack-packs: proposals (nothing written; confirm with --set or --answers)
  no stack evidence found
  not proposed: kotlin-android (no gradlew found)
"
    );
    repo.file("gradlew", "#!/bin/sh\n")
        .file(
            "gradle/wrapper/gradle-wrapper.properties",
            "distributionUrl=https\\://services.gradle.org/distributions/gradle-9.6.0-all.zip\n",
        )
        .file(".java-version", "17\n");
    let block = repo.block();
    assert!(
        block.contains(
            "    evidence: settings.gradle.kts, gradlew, gradle/wrapper/gradle-wrapper.properties (gradle 9.6.0, no distributionSha256Sum), .java-version (17)\n"
        ),
        "{block}"
    );
    assert!(
        block.contains("      test:   proposed  \"./gradlew test\"\n      verify: proposed  \"./gradlew test\"\n    seeds on apply: .java-version\n"),
        "{block}"
    );
}

#[test]
fn a_dbt_project_without_sqlfluff_config_proposes_no_lint_and_keeps_declared_commands() {
    let repo = Repo::installed(Some("dbt-project"));
    fs::remove_file(repo.root.join(".sqlfluff")).unwrap();
    repo.file(".python-version", "3.13\n");
    repo.declare("test", "dbt build --fail-fast");
    let block = repo.block();
    assert!(
        block.contains(
            "    evidence: dbt_project.yml (name = \"analytics\", profile = \"analytics\", require-dbt-version = \">=1.12.0\"), packages.yml, package-lock.yml, .python-version (3.13)\n"
        ),
        "{block}"
    );
    assert!(
        block.contains("      test:   declared  \"dbt build --fail-fast\"\n      verify: proposed  \"dbt build\"\n"),
        "{block}"
    );
    assert!(!block.contains("lint:"), "{block}");
    assert!(block.contains(NO_SQLFLUFF), "{block}");
    assert_eq!(block.matches("dbt build --fail-fast").count(), 1, "{block}");
    // `container: true` refuses on the data pack as on the device packs.
    let before = repo.tree();
    let result = repo.cli(&[
        "configure",
        "<repo>",
        "stack-packs",
        "--set",
        "apps.root.path=.",
        "--set",
        "apps.root.stack=sql-dbt",
        "--set",
        "apps.root.container=true",
        "--apply",
    ]);
    assert_eq!(result.status.code(), Some(2), "{result:?}");
    assert_eq!(
        String::from_utf8_lossy(&result.stderr),
        "REFUSED: stack-packs: app `root` declares container: true but stack `sql-dbt` builds no container image\n"
    );
    assert_eq!(repo.tree(), before);
}

#[test]
fn recording_the_device_apps_marks_them_and_a_container_on_either_refuses() {
    let repo = Repo::installed(Some("four-app-monorepo"));
    let before = repo.tree();
    for (id, path, stack) in [
        ("ios", "apps/ios", "swift-ios"),
        ("android", "apps/android", "kotlin-android"),
    ] {
        let result = repo.cli(&[
            "configure",
            "<repo>",
            "stack-packs",
            "--set",
            &format!("apps.{id}.path={path}"),
            "--set",
            &format!("apps.{id}.stack={stack}"),
            "--set",
            &format!("apps.{id}.container=true"),
            "--apply",
        ]);
        assert_eq!(result.status.code(), Some(2), "{result:?}");
        assert_eq!(
            String::from_utf8_lossy(&result.stderr),
            format!(
                "REFUSED: stack-packs: app `{id}` declares container: true but stack `{stack}` builds no container image\n"
            )
        );
    }
    assert_eq!(repo.tree(), before);
    let result = repo.cli(&[
        "configure",
        "<repo>",
        "stack-packs",
        "--set",
        "apps.ios.path=apps/ios",
        "--set",
        "apps.ios.stack=swift-ios",
        "--set",
        "apps.ios.toolchain_version=27.1",
        "--set",
        "apps.android.path=apps/android",
        "--set",
        "apps.android.stack=kotlin-android",
        "--set",
        "apps.android.toolchain_version=17",
        "--apply",
    ]);
    assert!(result.status.success(), "{result:?}");
    let block = repo.block();
    assert!(
        block.contains("  app `ios` at `apps/ios`: stack swift-ios (recorded)\n"),
        "{block}"
    );
    assert!(
        block.contains("  app `android` at `apps/android`: stack kotlin-android (recorded)\n"),
        "{block}"
    );
    assert!(repo.root.join("apps/ios/.xcode-version").is_file());
    assert_eq!(repo.read("apps/android/.java-version"), "17\n");
}

#[test]
fn configure_without_flags_prints_the_block_and_writes_nothing() {
    for (fixture, golden) in [
        (Some("rust-root"), RUST_ROOT),
        (Some("node-monorepo"), NODE_MONOREPO),
        (Some("go-under-rust"), GO_UNDER_RUST),
        (Some("four-app-monorepo"), FOUR_APP_MONOREPO),
        (Some("dbt-project"), DBT_PROJECT),
        (None, EMPTY),
    ] {
        let repo = Repo::installed(fixture);
        let before = repo.tree();
        let out = repo.stdout(&["configure", "<repo>", "stack-packs"]);
        assert!(out.ends_with(golden), "fixture {fixture:?}:\n{out}");
        assert_eq!(repo.tree(), before, "fixture {fixture:?} changed the tree");
    }
}

#[test]
fn configure_with_set_prints_no_proposal_block() {
    let repo = Repo::installed(Some("rust-root"));
    let out = repo.stdout(&[
        "configure",
        "<repo>",
        "stack-packs",
        "--set",
        "apps.root.stack=rust",
        "--set",
        "apps.root.path=.",
    ]);
    assert!(!out.contains("stack-packs: proposals"), "{out}");
}

#[test]
fn a_declared_command_is_kept_and_never_proposed_over() {
    let repo = Repo::installed(Some("rust-root"));
    repo.declare("verify", "bash scripts/check.sh");
    repo.declare("lint", "cargo clippy --all-targets");
    let block = repo.block();
    assert!(
        block.contains("      verify: declared  \"bash scripts/check.sh\"\n"),
        "{block}"
    );
    assert!(
        block.contains("      lint:   declared  \"cargo clippy --all-targets\"\n"),
        "{block}"
    );
    assert!(
        block.contains("      test:   proposed  \"cargo test --workspace --locked\"\n"),
        "{block}"
    );
    assert_eq!(block.matches("bash scripts/check.sh").count(), 1, "{block}");
}

#[test]
fn an_app_profile_declares_the_commands_of_its_app() {
    let repo = Repo::new(Some("node-monorepo"));
    repo.file(
        "services/api/.agent-setup/project.json",
        r#"{"commands": {"test": "uv run --frozen pytest", "lint": null}}"#,
    );
    let block = repo.block();
    assert!(
        block.contains("      test:   declared  \"uv run --frozen pytest\"\n"),
        "{block}"
    );
    assert!(
        block.contains("      lint:   proposed  \"uv run --frozen ruff check .\"\n"),
        "{block}"
    );
}

#[test]
fn node_proposes_lint_and_build_only_for_scripts_that_exist() {
    let repo = Repo::new(None);
    repo.file("package.json", r#"{"scripts": {"test": "node --test"}}"#)
        .file("package-lock.json", "{}");
    assert_eq!(
        repo.block(),
        r#"stack-packs: proposals (nothing written; confirm with --set or --answers)
  app `root` at `.`: stack node
    evidence: package.json (scripts: test, test runner: node:test), package-lock.json
    commands (project.json fields already declared are kept; proposed only for null):
      test:   proposed  "npm test"
      verify: proposed  "npm test"
    seeds on apply: .nvmrc, Dockerfile, .dockerignore
"#
    );
}

#[test]
fn two_node_lockfiles_refuse_naming_both() {
    let repo = Repo::new(None);
    repo.file("package.json", "{}")
        .file("package-lock.json", "{}")
        .file("yarn.lock", "");
    assert_eq!(
        detect::proposal_block(&repo.root).unwrap_err().to_string(),
        "stack-packs: both package-lock.json and yarn.lock are present; keep the lockfile of one package manager (at `.`)"
    );
}

#[test]
fn a_decided_but_absent_language_is_not_proposed() {
    let repo = Repo::installed(Some("go-under-rust"));
    fs::create_dir_all(repo.root.join("services/worker")).unwrap();
    let result = repo.cli(&[
        "configure",
        "<repo>",
        "stack-packs",
        "--set",
        "apps.worker.stack=python-uv",
        "--set",
        "apps.worker.path=services/worker",
        "--set",
        "apps.worker.force=true",
        "--set",
        "apps.worker.toolchain_version=3.13",
        "--apply",
    ]);
    assert!(result.status.success(), "{result:?}");
    let block = repo.block();
    assert!(!block.contains("python-uv"), "{block}");
    assert!(!block.contains("services/worker"), "{block}");
}

#[test]
fn partial_evidence_at_a_scanned_path_is_named_as_not_proposed() {
    let repo = Repo::new(None);
    repo.file("pyproject.toml", "[project]\nname = \"x\"\n");
    assert_eq!(
        repo.block(),
        "stack-packs: proposals (nothing written; confirm with --set or --answers)
  no stack evidence found
  not proposed: python-uv (no uv.lock found)
"
    );
}

#[test]
fn a_recorded_app_is_marked_and_nested_stacks_are_still_proposed() {
    let repo = Repo::installed(Some("go-under-rust"));
    let result = repo.cli(&[
        "configure",
        "<repo>",
        "stack-packs",
        "--set",
        "apps.root.stack=rust",
        "--set",
        "apps.root.path=.",
        "--apply",
    ]);
    assert!(result.status.success(), "{result:?}");
    let block = repo.block();
    assert!(
        block.contains("  app `root` at `.`: stack rust (recorded)\n"),
        "{block}"
    );
    assert!(
        block.contains("  app `probe` at `tools/probe`: stack go\n"),
        "{block}"
    );
}

#[test]
fn a_directory_inside_a_declared_app_is_not_rescanned_for_the_root() {
    let repo = Repo::new(Some("node-monorepo"));
    // A nested Go module inside the declared `api` app belongs to that app.
    repo.file(
        "services/api/tools/gen/go.mod",
        "module example.com/gen\n\ngo 1.23\n",
    )
    .file("services/api/tools/gen/go.sum", "");
    let answers: Answers = serde_json::from_value(json!({
        "apps.api.path": "services/api",
        "apps.api.stack": "python-uv",
    }))
    .unwrap();
    let detection = detect::propose(&repo.root, &answers).unwrap();
    let found: Vec<(String, String, bool)> = detection
        .proposals
        .iter()
        .map(|p| (p.path.clone(), p.stack.to_string(), p.recorded))
        .collect();
    assert_eq!(
        found,
        [
            (".".to_owned(), "node".to_owned(), false),
            ("services/api".to_owned(), "python-uv".to_owned(), true),
        ]
    );
}

#[test]
fn doctor_reports_stack_unconfigured_until_answers_record_the_stack() {
    let repo = Repo::installed(Some("rust-root"));
    let result = repo.cli(&["doctor", "<repo>"]);
    let out = String::from_utf8_lossy(&result.stdout).into_owned();
    assert!(
        out.contains(
            "WARNING: stack.unconfigured: a stack is detected that no stack-packs answers record\n"
        ),
        "{out}"
    );
    assert!(out.contains(RUST_ROOT), "{out}");
    let result = repo.cli(&[
        "configure",
        "<repo>",
        "stack-packs",
        "--set",
        "apps.root.stack=rust",
        "--set",
        "apps.root.path=.",
        "--apply",
    ]);
    assert!(result.status.success(), "{result:?}");
    let result = repo.cli(&["doctor", "<repo>"]);
    let out = String::from_utf8_lossy(&result.stdout).into_owned();
    assert!(!out.contains("stack.unconfigured"), "{out}");
}

#[test]
fn doctor_on_a_repository_without_stack_evidence_reports_nothing() {
    let repo = Repo::installed(None);
    let result = repo.cli(&["doctor", "<repo>"]);
    let out = String::from_utf8_lossy(&result.stdout).into_owned();
    // The pin-table age (#763) depends on the real clock, not on detection.
    let stack: Vec<&str> = out
        .lines()
        .filter(|l| l.contains("stack.") && !l.starts_with("WARNING: stack.pin-table-stale:"))
        .collect();
    assert!(stack.is_empty(), "{out}");
}

#[test]
fn the_walk_skips_fixtures_dependencies_and_hidden_directories() {
    let repo = Repo::new(None);
    for dir in [
        "tests/fixtures/sample",
        "pkg/testdata/sample",
        "node_modules/dep",
        "target/sample",
        ".cache/sample",
    ] {
        repo.file(&format!("{dir}/Cargo.toml"), "[package]\n")
            .file(&format!("{dir}/Cargo.lock"), "");
    }
    assert_eq!(repo.block(), EMPTY);
}

#[test]
fn configure_refuses_two_node_lockfiles_before_applying_anything() {
    let repo = Repo::installed(None);
    repo.file("package.json", "{}")
        .file("package-lock.json", "{}")
        .file("yarn.lock", "");
    let before = repo.tree();
    let result = repo.cli(&["configure", "<repo>", "stack-packs", "--apply"]);
    assert_eq!(result.status.code(), Some(2), "{result:?}");
    assert!(
        String::from_utf8_lossy(&result.stderr)
            .contains("both package-lock.json and yarn.lock are present"),
        "{result:?}"
    );
    assert_eq!(repo.tree(), before);
}

#[test]
fn an_invalid_package_json_is_named_in_the_evidence() {
    let repo = Repo::new(None);
    repo.file("package.json", "{ not json")
        .file("package-lock.json", "{}");
    assert!(
        repo.block()
            .contains("    evidence: package.json (not valid JSON), package-lock.json\n"),
        "{}",
        repo.block()
    );
}

// --accept-commands (SPEC-stack-packs.md, Decision 5; decision 2026-10-28,
// point 8; #762): the diff first, only `null` `commands.*` fields, a field
// that is not `null` refuses naming it, every other byte kept.

const RUST_TEST: &str = "cargo test --workspace --locked";
const RUST_LINT: &str = "cargo clippy --workspace --all-targets --locked -- -D warnings";
const RUST_BUILD: &str = "cargo build --workspace --all-targets --locked";

/// `text` with the `null` of `"name": null` replaced by the JSON string `command`.
fn filled(text: &str, fills: &[(&str, &str)]) -> String {
    fills.iter().fold(text.to_owned(), |text, (name, command)| {
        let slot = format!("\"{name}\": null");
        assert_eq!(text.matches(&slot).count(), 1, "{slot} in {text}");
        text.replace(&slot, &format!("\"{name}\": {}", json!(command)))
    })
}

#[test]
fn accept_commands_without_apply_prints_the_diff_and_writes_nothing() {
    let repo = Repo::installed(Some("rust-root"));
    repo.declare("verify", "bash scripts/check.sh");
    let before = repo.tree();
    let out = repo.stdout(&["configure", "<repo>", "stack-packs", "--accept-commands"]);
    assert_eq!(
        out,
        format!(
            "stack-packs: accept commands of app `root` at `.` (stack rust)\n\
             --- .agent-setup/project.json\n\
             +++ .agent-setup/project.json\n\
             -    \"build\": null,\n\
             +    \"build\": \"{RUST_BUILD}\",\n\
             -    \"lint\": null,\n\
             +    \"lint\": \"{RUST_LINT}\",\n\
             -    \"test\": null,\n\
             +    \"test\": \"{RUST_TEST}\",\n\
             PLAN .agent-setup/project.json\n\
             Plan only; no writes. Review before using --apply.\n"
        )
    );
    assert_eq!(repo.tree(), before);
}

/// #55: `--accept-commands` plans like every other plan: when its `--apply`
/// would be refused, the last line says so and why.
#[test]
fn accept_commands_without_apply_says_when_the_apply_would_be_refused() {
    let repo = Repo::installed(Some("rust-root"));
    repo.declare("verify", "bash scripts/check.sh");
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&repo.root)
            .args(["remote", "add", "origin", "../project-origin"])
            .status()
            .unwrap()
            .success()
    );
    let out = repo.stdout(&["configure", "<repo>", "stack-packs", "--accept-commands"]);
    assert!(
        out.lines().last().is_some_and(
            |l| l.starts_with("APPLY REFUSED: Remote is not a GitHub URL: ../project-origin;")
        ),
        "{out}"
    );
}

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "lists setup-core or its guides; product-boundary T7a"
)]
#[test]
fn accept_commands_with_apply_fills_only_the_null_fields() {
    let repo = Repo::installed(Some("rust-root"));
    repo.declare("verify", "bash scripts/check.sh");
    let profile = repo.root.join(".agent-setup/project.json");
    let text = fs::read_to_string(&profile).unwrap();
    let mut before = repo.tree();
    let out = repo.stdout(&[
        "configure",
        "<repo>",
        "stack-packs",
        "--accept-commands",
        "--apply",
    ]);
    assert!(
        out.ends_with(
            "WRITE .agent-setup/project.json\nApplied; fill/review project profile and run doctor.\n"
        ),
        "{out}"
    );
    let expected = filled(
        &text,
        &[
            ("build", RUST_BUILD),
            ("lint", RUST_LINT),
            ("test", RUST_TEST),
        ],
    );
    assert_eq!(fs::read_to_string(&profile).unwrap(), expected);
    // No other file changed, and the declared `verify` was never touched.
    before.insert(
        PathBuf::from(".agent-setup/project.json"),
        expected.into_bytes(),
    );
    assert_eq!(repo.tree(), before);
    let again = repo.stdout(&["configure", "<repo>", "stack-packs", "--accept-commands"]);
    assert!(again.ends_with("No changes.\n"), "{again}");
    // The declared commands reach the managed instructions through `install`.
    let install = repo.stdout(&["install", "<repo>"]);
    assert!(
        install.contains("PLAN AGENTS.md [managed-block:setup-core]\n"),
        "{install}"
    );
}

#[test]
fn accept_commands_keeps_every_other_byte_of_a_hand_formatted_profile() {
    let repo = Repo::new(Some("rust-root"));
    let text = "{ \"purpose\":\"x\",\n  \"commands\" : {\"verify\": \"v\",\"test\":null , \"lint\" :\n null,\n\"build\": \"b\", \"note\": \"null\"},\n \"extra\": {\"test\": null}, \"conventions\": [], \"generated_paths\": [], \"environment_notes\": []\n}\n";
    repo.file(".agent-setup/project.json", text);
    let accepted = detect::accept_commands(&repo.root, None).unwrap();
    assert_eq!(accepted.path, ".agent-setup/project.json");
    assert_eq!(accepted.before.as_deref(), Some(text));
    assert_eq!(
        accepted.after,
        format!(
            "{{ \"purpose\":\"x\",\n  \"commands\" : {{\"verify\": \"v\",\"test\":\"{RUST_TEST}\" , \"lint\" :\n \"{RUST_LINT}\",\n\"build\": \"b\", \"note\": \"null\"}},\n \"extra\": {{\"test\": null}}, \"conventions\": [], \"generated_paths\": [], \"environment_notes\": []\n}}\n"
        )
    );
}

#[test]
fn accept_commands_creates_a_missing_app_profile_from_the_default() {
    let repo = Repo::installed(Some("node-monorepo"));
    let out = repo.stdout(&[
        "configure",
        "<repo>",
        "stack-packs",
        "--accept-commands",
        "api",
        "--apply",
    ]);
    assert!(
        out.starts_with(
            "stack-packs: accept commands of app `api` at `services/api` (stack python-uv)\n\
             --- /dev/null\n\
             +++ services/api/.agent-setup/project.json\n\
             +{\n"
        ),
        "{out}"
    );
    assert!(
        out.ends_with("WRITE services/api/.agent-setup/project.json\nApplied; fill/review project profile and run doctor.\n"),
        "{out}"
    );
    let written =
        fs::read_to_string(repo.root.join("services/api/.agent-setup/project.json")).unwrap();
    assert_eq!(
        written,
        filled(
            brakes::profile::default_json(),
            &[
                (
                    "verify",
                    "uv run --frozen ruff check . && uv run --frozen pytest -q"
                ),
                ("test", "uv run --frozen pytest -q"),
                ("lint", "uv run --frozen ruff check ."),
            ],
        )
    );
    // The root profile is another app's: untouched.
    let root = repo.stdout(&["configure", "<repo>", "stack-packs", "--accept-commands"]);
    assert!(root.contains("app `root` at `.` (stack node)"), "{root}");
}

#[test]
fn accept_commands_refuses_a_field_that_is_not_null_naming_it() {
    let repo = Repo::installed(Some("node-monorepo"));
    repo.file(
        "services/api/.agent-setup/project.json",
        r#"{"commands": {"verify": null, "test": false, "lint": null}}"#,
    );
    let before = repo.tree();
    let result = repo.cli(&[
        "configure",
        "<repo>",
        "stack-packs",
        "--accept-commands",
        "api",
        "--apply",
    ]);
    assert_eq!(result.status.code(), Some(2), "{result:?}");
    assert_eq!(
        String::from_utf8_lossy(&result.stderr),
        "REFUSED: stack-packs: commands.test in services/api/.agent-setup/project.json is declared (false); --accept-commands fills only null fields\n"
    );
    assert_eq!(repo.tree(), before);
}

#[test]
fn accept_commands_refuses_a_field_absent_from_the_profile_naming_it() {
    let repo = Repo::new(Some("node-monorepo"));
    repo.file(
        "services/api/.agent-setup/project.json",
        r#"{"commands": {"verify": null, "lint": null}}"#,
    );
    assert_eq!(
        detect::accept_commands(&repo.root, Some("api"))
            .unwrap_err()
            .to_string(),
        "stack-packs: commands.test is absent from services/api/.agent-setup/project.json; declare it as null to accept its proposal"
    );
}

#[test]
fn accept_commands_with_every_field_declared_changes_nothing() {
    let repo = Repo::installed(Some("rust-root"));
    for (name, command) in [
        ("verify", "v"),
        ("test", "t"),
        ("lint", "l"),
        ("build", "b"),
    ] {
        repo.declare(name, command);
    }
    let before = repo.tree();
    let out = repo.stdout(&[
        "configure",
        "<repo>",
        "stack-packs",
        "--accept-commands",
        "--apply",
    ]);
    assert_eq!(
        out,
        "stack-packs: accept commands of app `root` at `.` (stack rust)\nNo changes.\n"
    );
    assert_eq!(repo.tree(), before);
}

#[test]
fn accept_commands_refuses_an_unknown_app_and_a_root_without_proposal() {
    let repo = Repo::new(Some("node-monorepo"));
    assert_eq!(
        detect::accept_commands(&repo.root, Some("web"))
            .unwrap_err()
            .to_string(),
        "stack-packs: no proposal for app `web`; `configure <repo> stack-packs` lists them"
    );
    let empty = Repo::new(None);
    assert_eq!(
        detect::accept_commands(&empty.root, None)
            .unwrap_err()
            .to_string(),
        "stack-packs: no proposal at `.`; name an app with --accept-commands <app-id>"
    );
}

#[test]
fn accept_commands_is_only_available_with_configure_stack_packs() {
    let repo = Repo::installed(Some("rust-root"));
    let message = "REFUSED: --accept-commands is only available with configure <project> stack-packs, without --set, --answers or --preset\n";
    for args in [
        &["install", "<repo>", "--accept-commands"][..],
        &["configure", "<repo>", "setup-core", "--accept-commands"],
        &[
            "configure",
            "<repo>",
            "stack-packs",
            "--accept-commands",
            "--set",
            "apps.root.stack=rust",
        ],
    ] {
        let result = repo.cli(args);
        assert_eq!(result.status.code(), Some(2), "{args:?}: {result:?}");
        assert_eq!(String::from_utf8_lossy(&result.stderr), message, "{args:?}");
    }
}

/// The Playwright project `qa` seeds (`web: seeded`) and the lockfile its
/// manual step `qa-web-lockfile` requires (#1238).
const QA_WEB_PACKAGE: &str =
    r#"{"name": "qa-web", "private": true, "devDependencies": {"@playwright/test": "1.56.1"}}"#;
const QA_WEB_LOCK: &str = r#"{"name": "qa-web", "lockfileVersion": 3, "packages": {}}"#;

/// `rust-root` installed, stack-packs recording `stack_packs`, qa recording
/// `qa` (when given), and qa's seeded project with its lockfile at `qa/web`.
fn with_qa_web(stack_packs: &str, qa: Option<&str>) -> Repo {
    let repo = Repo::installed(Some("rust-root"));
    repo.file(
        ".agent-setup/modules/stack-packs.json",
        &format!(r#"{{"module": "stack-packs", "version": "1.0.0", "answers": {stack_packs}}}"#),
    )
    .file("qa/web/package.json", QA_WEB_PACKAGE)
    .file("qa/web/package-lock.json", QA_WEB_LOCK);
    if let Some(qa) = qa {
        repo.file(
            ".agent-setup/modules/qa.json",
            &format!(r#"{{"module": "qa", "version": "1.0.0", "answers": {qa}}}"#),
        );
    }
    repo
}

const ROOT_RUST: &str =
    r#"{"apps.root.path": ".", "apps.root.stack": "rust", "apps.root.container": false}"#;

#[test]
fn qa_seeded_web_dir_with_its_lockfile_is_not_an_unrecorded_app() {
    let repo = with_qa_web(
        ROOT_RUST,
        Some(r#"{"web": "seeded", "web_start": "npm run dev"}"#),
    );
    assert_eq!(detect::unconfigured(&repo.root).unwrap(), None);
    let result = repo.cli(&["doctor", "<repo>"]);
    let out = String::from_utf8_lossy(&result.stdout).into_owned();
    assert!(!out.contains("stack.unconfigured"), "{out}");
    assert!(!repo.block().contains("qa/web"), "{}", repo.block());
}

#[test]
fn an_app_web_dir_climbing_to_qa_web_is_not_an_unrecorded_app() {
    // the rollout's shape (#1238): the web app's seeded project leaves it with `../../qa/web`.
    let repo = with_qa_web(
        r#"{"apps.root.path": ".", "apps.root.stack": "rust", "apps.root.container": false,
            "apps.web.path": "apps/web", "apps.web.stack": "node", "apps.web.container": false}"#,
        Some(
            r#"{"apps": ["web"], "apps.web.web": "seeded", "apps.web.web_start": "npm run dev", "apps.web.web_dir": "../../qa/web"}"#,
        ),
    );
    repo.file(
        "apps/web/package.json",
        r#"{"name": "web", "private": true, "dependencies": {"react": "19.0.0"}, "devDependencies": {"vitest": "3.0.0"}}"#,
    )
    .file(
        "apps/web/package-lock.json",
        r#"{"name": "web", "lockfileVersion": 3, "packages": {}}"#,
    );
    assert_eq!(detect::unconfigured(&repo.root).unwrap(), None);
}

#[test]
fn a_node_project_at_qa_web_that_qa_does_not_seed_is_still_proposed() {
    // Without qa's answers (or with `web: none`) the directory is the project's own.
    let repo = with_qa_web(ROOT_RUST, None);
    let found = detect::unconfigured(&repo.root).unwrap().unwrap();
    assert!(found.contains("at `qa/web`: stack node"), "{found}");
    repo.file(
        ".agent-setup/modules/qa.json",
        r#"{"module": "qa", "version": "1.0.0", "answers": {"web": "none"}}"#,
    );
    let found = detect::unconfigured(&repo.root).unwrap().unwrap();
    assert!(found.contains("at `qa/web`: stack node"), "{found}");
}
