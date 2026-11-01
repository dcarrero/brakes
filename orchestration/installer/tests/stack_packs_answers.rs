//! stack-packs recorded answers (SPEC-stack-packs.md, Recorded answers; #757):
//! the flat `apps.<id>.<field>` namespace, the rules of the question table,
//! the defaults, `packs(cx)` and the module registration.
mod support;
use brakes::engine::answers::{self, Answers};
use brakes::engine::{Context, Lock, Module};
use brakes::modules::stack_packs::{
    self, BaseImageFamily, PackageManager, StackId, StackPacks, StackPacksAnswers,
};
use brakes::modules::{self};
use brakes::{LOCK, Source, profile_for, questions};
use serde_json::{Value, json};
use std::{fs, path::PathBuf, process::Command};
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

struct Repo {
    _temp: TempDir,
    root: PathBuf,
}

impl Repo {
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
        Self { _temp: temp, root }
    }

    fn file(&self, path: &str) -> &Self {
        let full = self.root.join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, "").unwrap();
        self
    }

    fn dir(&self, path: &str) -> &Self {
        fs::create_dir_all(self.root.join(path)).unwrap();
        self
    }

    /// A rust app's evidence at `path` (`.` for the root).
    fn rust_at(&self, path: &str) -> &Self {
        let prefix = if path == "." {
            String::new()
        } else {
            format!("{path}/")
        };
        self.file(&format!("{prefix}Cargo.toml"))
            .file(&format!("{prefix}Cargo.lock"))
    }

    /// The loaded answers for `raw`, as `packs(cx)` and `render` see them.
    fn load(&self, raw: Value) -> brakes::Result<StackPacksAnswers> {
        let raw: Answers = serde_json::from_value(raw).unwrap();
        let validated =
            StackPacks
                .questions()
                .validate("stack-packs", &raw, answers::DEFAULT_TIER)?;
        let profile = profile_for(&self.root)?;
        let source = Source::embedded();
        let previous = empty_lock();
        let resolved = Default::default();
        let cx = Context::new(
            &self.root,
            &profile,
            &source,
            &previous,
            &validated,
            &StackPacks,
            &resolved,
        );
        StackPacksAnswers::load(&cx)
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

    fn configure(&self, sets: &[&str]) -> brakes::Result<questions::Configured> {
        brakes::configure(
            &self.root,
            &Source::embedded(),
            "stack-packs",
            &questions::Inputs {
                sets: sets.iter().map(|s| (*s).to_owned()).collect(),
                ..Default::default()
            },
        )
    }
}

#[test]
fn a_single_rust_app_at_the_root_gets_the_owner_defaults() {
    let repo = Repo::new();
    repo.rust_at(".");
    let loaded = repo
        .load(json!({"apps.root.stack": "rust", "apps.root.path": "."}))
        .unwrap();
    assert_eq!(loaded.base_image_family, BaseImageFamily::Distroless);
    let root = &loaded.apps["root"];
    assert_eq!(root.app.path, ".");
    assert_eq!(root.app.stack, StackId::Rust);
    assert!(root.app.container, "rust is container-capable");
    assert!(
        !root.app.toolchain,
        "rust leaves the toolchain off by default"
    );
    assert_eq!(root.port, Some(8080));
    assert_eq!(root.healthcheck.as_deref(), Some("default"));
    assert_eq!(root.bin.as_deref(), Some("project"));
    assert!(!root.force);
}

#[test]
fn defaults_follow_the_pack_and_explicit_answers_win() {
    let repo = Repo::new();
    repo.file("web/package.json").file("web/pnpm-lock.yaml");
    repo.file("api/pyproject.toml").file("api/uv.lock");
    let loaded = repo
        .load(json!({
            "apps.web.path": "web", "apps.web.stack": "node",
            "apps.api.path": "api/", "apps.api.stack": "python-uv",
            "apps.api.container": false, "apps.api.toolchain": false,
            "base_image_family": "official-slim",
        }))
        .unwrap();
    assert_eq!(loaded.base_image_family, BaseImageFamily::OfficialSlim);
    let web = &loaded.apps["web"];
    assert!(
        web.app.toolchain,
        "toolchain defaults to true except for rust"
    );
    assert_eq!(web.app.package_manager, Some(PackageManager::Pnpm));
    assert_eq!(web.port, Some(3000));
    assert_eq!(web.bin, None, "bin is only for rust and go");
    let api = &loaded.apps["api"];
    assert_eq!(api.app.path, "api", "a trailing slash is normalised");
    assert!(!api.app.container && !api.app.toolchain);
    assert_eq!((api.port.as_ref(), api.healthcheck.as_ref()), (None, None));
}

#[test]
fn nested_app_paths_are_allowed() {
    let repo = Repo::new();
    repo.rust_at(".")
        .file("tools/gen/go.mod")
        .file("tools/gen/go.sum");
    let loaded = repo
        .load(json!({
            "apps.root.path": ".", "apps.root.stack": "rust",
            "apps.gen.path": "tools/gen", "apps.gen.stack": "go",
        }))
        .unwrap();
    assert_eq!(loaded.apps.len(), 2);
    assert_eq!(loaded.apps["gen"].bin.as_deref(), Some("gen"));
}

#[test]
fn every_rule_of_the_question_table_refuses_with_its_message() {
    let repo = Repo::new();
    repo.rust_at(".").rust_at("a").rust_at("b").dir("empty");
    repo.file("ios/Package.swift").file("notadir");
    repo.file("android/settings.gradle.kts")
        .file("android/gradlew");
    repo.file("dbt/dbt_project.yml");
    std::os::unix::fs::symlink(repo.root.join("a"), repo.root.join("link")).unwrap();
    for (raw, message) in [
        (
            json!({"apps.x.stack": "rust"}),
            "stack-packs: app `x` has no `path`; set apps.x.path",
        ),
        (
            json!({"apps.x.path": "."}),
            "stack-packs: app `x` has no `stack`; set apps.x.stack",
        ),
        (
            json!({"apps.x.path": "/etc", "apps.x.stack": "rust"}),
            "stack-packs: app `x` path `/etc` must be relative and inside the repository",
        ),
        (
            json!({"apps.x.path": "a/../..", "apps.x.stack": "rust"}),
            "stack-packs: app `x` path `a/../..` must be relative and inside the repository",
        ),
        (
            json!({"apps.x.path": "", "apps.x.stack": "rust"}),
            "Module stack-packs: answer `apps.x.path` must have at least 1 character",
        ),
        (
            json!({"apps.x.path": "missing", "apps.x.stack": "rust"}),
            "stack-packs: app `x` path `missing` does not exist",
        ),
        (
            json!({"apps.x.path": "notadir", "apps.x.stack": "rust"}),
            "stack-packs: app `x` path `notadir` is not a directory",
        ),
        (
            json!({"apps.x.path": "link", "apps.x.stack": "rust"}),
            "stack-packs: app `x` path `link` is a symlink",
        ),
        (
            json!({"apps.x.path": ".", "apps.x.stack": "rust",
                   "apps.y.path": ".", "apps.y.stack": "rust"}),
            "stack-packs: apps `x` and `y` share path `.`",
        ),
        (
            json!({"apps.x.path": "a", "apps.x.stack": "rust",
                   "apps.y.path": "a/", "apps.y.stack": "rust"}),
            "stack-packs: apps `x` and `y` share path `a`",
        ),
        (
            json!({"apps.x.path": "a", "apps.x.stack": "cobol"}),
            "Module stack-packs: answer `apps.x.stack` must be one of: rust, python-uv, node, go, kotlin-android, swift-ios, sql-dbt",
        ),
        (
            json!({"apps.x.path": "empty", "apps.x.stack": "rust"}),
            "stack-packs: app `x` is not a `rust` app: `empty/Cargo.toml` is missing; set apps.x.force=true to record it anyway",
        ),
        (
            json!({"apps.x.path": "empty", "apps.x.stack": "node"}),
            "stack-packs: app `x` is not a `node` app: `empty/package.json` is missing; set apps.x.force=true to record it anyway",
        ),
        (
            json!({"apps.x.path": "a", "apps.x.stack": "kotlin-android"}),
            "stack-packs: app `x` is not a `kotlin-android` app: none of `a/settings.gradle.kts`, `a/build.gradle.kts` is present; set apps.x.force=true to record it anyway",
        ),
        (
            json!({"apps.x.path": "ios", "apps.x.stack": "swift-ios", "apps.x.container": true}),
            "stack-packs: app `x` declares container: true but stack `swift-ios` builds no container image",
        ),
        (
            json!({"apps.x.path": "android", "apps.x.stack": "kotlin-android", "apps.x.container": true}),
            "stack-packs: app `x` declares container: true but stack `kotlin-android` builds no container image",
        ),
        (
            json!({"apps.x.path": "dbt", "apps.x.stack": "sql-dbt", "apps.x.container": true}),
            "stack-packs: app `x` declares container: true but stack `sql-dbt` builds no container image",
        ),
        (
            json!({"apps.x.path": "empty", "apps.x.stack": "sql-dbt"}),
            "stack-packs: app `x` is not a `sql-dbt` app: `empty/dbt_project.yml` is missing; set apps.x.force=true to record it anyway",
        ),
        (
            json!({"apps.x.path": "empty", "apps.x.stack": "swift-ios"}),
            "stack-packs: app `x` is not a `swift-ios` app: none of `empty/*.xcodeproj`, `empty/Package.swift` is present; set apps.x.force=true to record it anyway",
        ),
        (
            json!({"apps.x.path": "a", "apps.x.stack": "rust", "apps.x.container": false,
                   "apps.x.port": 8000}),
            "stack-packs: app `x` sets `port` but container is false",
        ),
        (
            json!({"apps.x.path": "a", "apps.x.stack": "rust", "apps.x.container": false,
                   "apps.x.healthcheck": "none"}),
            "stack-packs: app `x` sets `healthcheck` but container is false",
        ),
        (
            json!({"apps.x.path": "a", "apps.x.stack": "rust", "apps.x.container": false,
                   "apps.x.bin": "srv"}),
            "stack-packs: app `x` sets `bin` but container is false",
        ),
        (
            json!({"apps.x.path": "ios", "apps.x.stack": "swift-ios", "apps.x.bin": "srv"}),
            "stack-packs: app `x` sets `bin` but stack `swift-ios` builds no binary",
        ),
        (
            json!({"apps.x.path": "a", "apps.x.stack": "rust", "apps.x.port": 0}),
            "Module stack-packs: answer `apps.x.port` must be at least 1",
        ),
        (
            json!({"apps.x.path": "a", "apps.x.stack": "rust", "apps.x.port": 65536}),
            "Module stack-packs: answer `apps.x.port` must be at most 65535",
        ),
        (
            json!({"apps.x.path": "a", "apps.x.stack": "rust", "apps.x.colour": "red"}),
            "Module stack-packs: answer `apps.x.colour` is not a question of this module",
        ),
        (
            json!({"base_image_family": "alpine"}),
            "Module stack-packs: answer `base_image_family` must be one of: dhi, distroless, official-slim",
        ),
    ] {
        assert_eq!(repo.refusal(raw.clone()), message, "{raw}");
    }
}

#[test]
fn force_records_an_app_whose_evidence_is_missing() {
    let repo = Repo::new();
    repo.dir("empty");
    let loaded = repo
        .load(json!({"apps.x.path": "empty", "apps.x.stack": "rust", "apps.x.force": true}))
        .unwrap();
    assert!(loaded.apps["x"].force);
}

#[test]
fn container_false_is_accepted_on_a_pack_without_images() {
    let repo = Repo::new();
    repo.file("ios/Package.swift");
    let loaded = repo
        .load(json!({"apps.ios.path": "ios", "apps.ios.stack": "swift-ios"}))
        .unwrap();
    assert!(!loaded.apps["ios"].app.container);
    assert_eq!(loaded.apps["ios"].port, None);
}

#[test]
fn packs_pairs_every_app_with_its_pack_in_app_id_order() {
    let repo = Repo::new();
    repo.rust_at(".")
        .file("web/package.json")
        .file("web/package-lock.json");
    let raw: Answers = serde_json::from_value(json!({
        "apps.web.path": "web", "apps.web.stack": "node",
        "apps.root.path": ".", "apps.root.stack": "rust",
    }))
    .unwrap();
    let validated = StackPacks
        .questions()
        .validate("stack-packs", &raw, answers::DEFAULT_TIER)
        .unwrap();
    let profile = profile_for(&repo.root).unwrap();
    let source = Source::embedded();
    let previous = empty_lock();
    let resolved = Default::default();
    let cx = Context::new(
        &repo.root,
        &profile,
        &source,
        &previous,
        &validated,
        &StackPacks,
        &resolved,
    );
    let packs = stack_packs::packs(&cx).unwrap();
    let ids: Vec<(&str, StackId)> = packs
        .iter()
        .map(|(app, pack)| (app.id.as_str(), pack.id))
        .collect();
    assert_eq!(ids, [("root", StackId::Rust), ("web", StackId::Node)]);
    assert_eq!(packs[1].0.package_manager, Some(PackageManager::Npm));
}

#[test]
fn the_module_is_registered_after_setup_core_and_requires_nothing() {
    let ids: Vec<&str> = modules::all().iter().map(|m| m.id()).collect();
    let first = crate::support::with_core(&["stack-packs"]);
    assert_eq!(ids[..first.len()], first[..]);
    assert_eq!(StackPacks.version(), "1.0.0");
    assert!(StackPacks.requires().is_empty());
    assert_eq!(SetupCore.id(), "setup-core");
}

#[test]
fn configure_writes_the_sorted_answers_file_and_a_second_install_changes_nothing() {
    let repo = Repo::new();
    assert!(
        repo.cli(&["install", "<repo>", "--new-personal", "--apply"])
            .status
            .success()
    );
    repo.rust_at(".");
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
    let path = answers::path("stack-packs");
    let text = fs::read_to_string(repo.root.join(&path)).unwrap();
    assert_eq!(
        text,
        concat!(
            "{\n",
            "  \"module\": \"stack-packs\",\n",
            "  \"version\": \"1.0.0\",\n",
            "  \"answers\": {\n",
            "    \"apps.root.path\": \".\",\n",
            "    \"apps.root.stack\": \"rust\",\n",
            "    \"base_image_family\": \"distroless\"\n",
            "  }\n",
            "}\n",
        )
    );
    let lock: Value =
        serde_json::from_str(&fs::read_to_string(repo.root.join(LOCK)).unwrap()).unwrap();
    assert_eq!(lock["modules"]["stack-packs"]["version"], json!("1.0.0"));
    let result = repo.cli(&["install", "<repo>"]);
    assert!(result.status.success(), "{result:?}");
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("No changes."),
        "{result:?}"
    );
}

#[test]
fn configure_refuses_a_rule_without_writing() {
    let repo = Repo::new();
    assert!(
        repo.cli(&["install", "<repo>", "--new-personal", "--apply"])
            .status
            .success()
    );
    repo.dir("empty");
    assert_eq!(
        repo.configure(&["apps.root.stack=rust", "apps.root.path=empty"])
            .unwrap_err()
            .to_string(),
        "stack-packs: app `root` is not a `rust` app: `empty/Cargo.toml` is missing; set apps.root.force=true to record it anyway"
    );
    assert!(!repo.root.join(answers::path("stack-packs")).exists());
}

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "asserts setup-core's own content or id; product-boundary T7b"
)]
#[test]
fn configuring_setup_core_does_not_add_stack_packs_to_the_lock() {
    let repo = Repo::new();
    assert!(
        repo.cli(&["install", "<repo>", "--new-personal", "--apply"])
            .status
            .success()
    );
    let result = repo.cli(&["configure", "<repo>", "setup-core", "--apply"]);
    assert!(result.status.success(), "{result:?}");
    let lock: Value =
        serde_json::from_str(&fs::read_to_string(repo.root.join(LOCK)).unwrap()).unwrap();
    assert!(lock["modules"].get("setup-core").is_some(), "{lock}");
    assert!(lock["modules"].get("stack-packs").is_none(), "{lock}");
}

#[test]
fn dhi_refuses_at_render_naming_the_missing_image() {
    let repo = Repo::new();
    assert!(
        repo.cli(&["install", "<repo>", "--new-personal", "--apply"])
            .status
            .success()
    );
    repo.rust_at(".");
    let refusal = repo
        .configure(&[
            "apps.root.stack=rust",
            "apps.root.path=.",
            "base_image_family=dhi",
        ])
        .unwrap_err()
        .to_string();
    assert_eq!(
        refusal,
        "stack-packs: image `dhi.cc` is not in templates/stack-packs/pins.json; add it with its digest before rendering"
    );
    // Without a container there is no runtime image to resolve.
    repo.configure(&[
        "apps.root.stack=rust",
        "apps.root.path=.",
        "apps.root.container=false",
        "base_image_family=dhi",
    ])
    .unwrap();
}

/// `macos_target` reaches ci-baseline through `packs(cx)`: true only when a
/// `swift-ios` app is recorded (#768; ci-baseline's `macos` answer refuses otherwise).
#[test]
fn a_macos_target_is_declared_through_packs_only_when_swift_ios_is_recorded() {
    let repo = Repo::new();
    repo.file("apps/ios/Package.swift")
        .file("apps/android/settings.gradle.kts")
        .file("apps/android/gradlew");
    let macos_of = |raw: Value| {
        let raw: Answers = serde_json::from_value(raw).unwrap();
        let validated = StackPacks
            .questions()
            .validate("stack-packs", &raw, answers::DEFAULT_TIER)
            .unwrap();
        let profile = profile_for(&repo.root).unwrap();
        let source = Source::embedded();
        let previous = empty_lock();
        let resolved = Default::default();
        let cx = Context::new(
            &repo.root,
            &profile,
            &source,
            &previous,
            &validated,
            &StackPacks,
            &resolved,
        );
        stack_packs::packs(&cx)
            .unwrap()
            .iter()
            .filter(|(_, pack)| pack.macos_target)
            .map(|(app, _)| app.id.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        macos_of(json!({
            "apps.android.path": "apps/android", "apps.android.stack": "kotlin-android",
        })),
        Vec::<String>::new()
    );
    assert_eq!(
        macos_of(json!({
            "apps.android.path": "apps/android", "apps.android.stack": "kotlin-android",
            "apps.ios.path": "apps/ios", "apps.ios.stack": "swift-ios",
        })),
        ["ios"]
    );
}
