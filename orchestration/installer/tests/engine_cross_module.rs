//! Cross-module answers (#842; SPEC-engine.md, Cross-module answers): a module
//! reads the answers of a module it requires as the engine resolved them for
//! this plan, never the recorded file the same plan replaces.
use brakes::engine::answers::{self, Answers};
use brakes::engine::{Context, Lock, Module};
use brakes::modules::ci_baseline::{CiBaseline, CiBaselineAnswers};
use brakes::{Source, profile_for};
use std::collections::BTreeMap;
use std::{fs, path::PathBuf, process::Command};
use tempfile::TempDir;

struct Repo {
    _temp: TempDir,
    root: PathBuf,
}

impl Repo {
    /// A personal repository installed with `--new-personal`, `commands.test` declared.
    fn new() -> Self {
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
        repo.ok(&["install", "<repo>", "--new-personal", "--apply"]);
        let path = repo.root.join(".agent-setup/project.json");
        let mut profile: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        profile["commands"]["test"] = "make test".into();
        fs::write(
            &path,
            serde_json::to_string_pretty(&profile).unwrap() + "\n",
        )
        .unwrap();
        repo
    }

    fn file(&self, path: &str) -> &Self {
        let full = self.root.join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, "").unwrap();
        self
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

    fn ok(&self, args: &[&str]) -> String {
        let out = self.cli(args);
        assert!(out.status.success(), "{args:?}: {out:?}");
        String::from_utf8(out.stdout).unwrap()
    }
}

/// stack-packs records a swift-ios app and ci-baseline `macos=true`; both installed.
fn ios_repo() -> Repo {
    let repo = Repo::new();
    repo.file("ios/Package.swift")
        // The project's own Xcode pin: the seed is skipped, no version asked (#1161).
        .file("ios/.xcode-version")
        .file("api/Cargo.toml")
        .file("api/Cargo.lock");
    // The macOS job runs the app's own declared commands (Decision 8, #784).
    fs::create_dir_all(repo.root.join("ios/.agent-setup")).unwrap();
    fs::write(
        repo.root.join("ios/.agent-setup/project.json"),
        r#"{"commands": {"test": "swift test"}}"#,
    )
    .unwrap();
    repo.ok(&[
        "configure",
        "<repo>",
        "stack-packs",
        "--set",
        "apps.ios.path=ios",
        "--set",
        "apps.ios.stack=swift-ios",
        "--set",
        "apps.ios.force=true",
        "--apply",
    ]);
    repo.ok(&[
        "configure",
        "<repo>",
        "ci-baseline",
        "--set",
        "macos=true",
        "--apply",
    ]);
    repo
}

#[test]
fn configuring_stack_packs_plans_ci_baseline_from_the_new_answers() {
    let repo = ios_repo();
    // The new answers leave no macOS target: ci-baseline must see them and refuse,
    // although the recorded stack-packs file still holds the swift-ios app.
    let out = repo.cli(&[
        "configure",
        "<repo>",
        "stack-packs",
        "--set",
        "apps.ios.path=api",
        "--set",
        "apps.ios.stack=rust",
    ]);
    assert!(!out.status.success(), "{out:?}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains(
            "ci-baseline: macos is true but no stack pack declares a macOS target; record a swift-ios app in stack-packs or set macos=false"
        ),
        "{out:?}"
    );
    let recorded = answers::recorded(&repo.root, "stack-packs")
        .unwrap()
        .unwrap();
    assert_eq!(recorded.answers["apps.ios.stack"], "swift-ios");
}

#[test]
fn reading_the_answers_of_a_module_not_required_refuses_by_name() {
    let repo = Repo::new();
    let profile = profile_for(&repo.root).unwrap();
    let source = Source::embedded();
    let previous = Lock {
        schema: 2,
        version: "test".to_owned(),
        source_commit: None,
        source_dirty: false,
        personal_owner: "example-owner".to_owned(),
        modules: Default::default(),
        files: Default::default(),
    };
    let own = Answers::new();
    let resolved = BTreeMap::from([
        ("stack-packs".to_owned(), Answers::new()),
        ("security".to_owned(), Answers::new()),
    ]);
    let cx = Context::new(
        &repo.root,
        &profile,
        &source,
        &previous,
        &own,
        &CiBaseline,
        &resolved,
    );
    assert!(cx.answers_of("stack-packs").unwrap().is_empty());
    assert_eq!(
        cx.answers_of("security").unwrap_err().to_string(),
        "Module ci-baseline reads the answers of module security, which it does not require; add security to its requires"
    );
    assert!(CiBaselineAnswers::load(&cx).is_ok());
    assert_eq!(CiBaseline.requires(), ["stack-packs"]);
    let none = BTreeMap::new();
    let cx = Context::new(
        &repo.root,
        &profile,
        &source,
        &previous,
        &own,
        &CiBaseline,
        &none,
    );
    assert_eq!(
        cx.answers_of("stack-packs").unwrap_err().to_string(),
        "Module ci-baseline reads the answers of module stack-packs, which is not active in this plan"
    );
}
