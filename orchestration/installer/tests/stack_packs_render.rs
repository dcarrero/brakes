//! stack-packs toolchain seeds and never-touch manifests (SPEC-stack-packs.md,
//! Project Structure and Testing: Seeds; #759): per app, the pin file is a
//! `seed` under the `<path>/` prefix and the manifest the pack reads is
//! `never-touch`. Toolchain tests set `container: false` so their lists stay
//! exact; the container seeds (#760) are asserted as text rules below.
mod support;
use brakes::engine::answers::{self, Answers};
use brakes::engine::{self, Context, Lock, Module, Ownership, Rendered};
use brakes::modules::stack_packs::{PinTable, StackPacks, seeds};
use brakes::{Source, profile_for};
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

    fn write(&self, path: &str, content: &str) -> &Self {
        let full = self.root.join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, content).unwrap();
        self
    }

    fn file(&self, path: &str) -> &Self {
        self.write(path, "")
    }

    /// `(path, class, content)` of every rendered item, in render order.
    fn render(&self, raw: Value) -> Vec<(String, Ownership, Option<String>)> {
        self.render_items(raw)
            .into_iter()
            .map(|item| (item.path, item.class, item.content))
            .collect()
    }

    fn render_items(&self, raw: Value) -> Vec<Rendered> {
        self.try_render(raw).unwrap()
    }

    fn try_render(&self, raw: Value) -> brakes::Result<Vec<Rendered>> {
        let raw: Answers = serde_json::from_value(raw).unwrap();
        let validated = StackPacks
            .questions()
            .validate("stack-packs", &raw, answers::DEFAULT_TIER)
            .unwrap();
        let profile = profile_for(&self.root).unwrap();
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
        StackPacks.render(&cx)
    }

    fn cli(&self, args: &[&str]) -> String {
        let root = self.root.to_string_lossy().into_owned();
        let output = Command::new(env!("CARGO_BIN_EXE_brakes"))
            .args(
                args.iter()
                    .map(|a| if *a == "<repo>" { root.as_str() } else { a }),
            )
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        String::from_utf8(output.stdout).unwrap()
    }

    fn read(&self, path: &str) -> String {
        fs::read_to_string(self.root.join(path)).unwrap()
    }
}

fn seed(path: &str, content: &str) -> (String, Ownership, Option<String>) {
    (path.to_owned(), Ownership::Seed, Some(content.to_owned()))
}

fn never_touch(path: &str) -> (String, Ownership, Option<String>) {
    (path.to_owned(), Ownership::NeverTouch, None)
}

const RUST_TOOLCHAIN: &str = "\
# brakes stack-packs (rust) — seed: yours to edit.
[toolchain]
channel = \"1.99\"
components = [\"clippy\", \"rustfmt\"]
";

#[test]
fn a_rust_app_at_the_root_seeds_the_channel_without_a_prefix() {
    let repo = Repo::new();
    repo.file("Cargo.toml").file("Cargo.lock");
    assert_eq!(
        repo.render(json!({
            "apps.root.path": ".", "apps.root.stack": "rust",
            "apps.root.container": false, "apps.root.toolchain": true,
            "apps.root.toolchain_version": "1.99",
        })),
        vec![
            seed("rust-toolchain.toml", RUST_TOOLCHAIN),
            never_touch("Cargo.toml")
        ]
    );
}

#[test]
fn every_app_carries_its_path_prefix() {
    let repo = Repo::new();
    repo.file("apps/backend/pyproject.toml")
        .file("apps/backend/uv.lock");
    repo.file("apps/web/package.json")
        .file("apps/web/package-lock.json");
    repo.file("tools/agent/Cargo.toml")
        .file("tools/agent/Cargo.lock");
    assert_eq!(
        repo.render(json!({
            "apps.backend.path": "apps/backend", "apps.backend.stack": "python-uv",
            "apps.backend.container": false, "apps.backend.toolchain_version": "3.13",
            "apps.web.path": "apps/web", "apps.web.stack": "node",
            "apps.web.container": false, "apps.web.toolchain_version": "24",
            "apps.agent.path": "tools/agent", "apps.agent.stack": "rust",
            "apps.agent.container": false, "apps.agent.toolchain": true,
            "apps.agent.toolchain_version": "1.99",
        })),
        vec![
            seed("tools/agent/rust-toolchain.toml", RUST_TOOLCHAIN),
            never_touch("tools/agent/Cargo.toml"),
            seed("apps/backend/.python-version", "3.13\n"),
            never_touch("apps/backend/pyproject.toml"),
            seed("apps/web/.nvmrc", "24\n"),
            never_touch("apps/web/package.json"),
        ]
    );
}

#[test]
fn toolchain_false_renders_no_pin_file() {
    let repo = Repo::new();
    repo.file("Cargo.toml").file("Cargo.lock");
    repo.file("api/pyproject.toml").file("api/uv.lock");
    assert_eq!(
        repo.render(json!({
            // rust leaves the toolchain off by default; python-uv is set off.
            "apps.root.path": ".", "apps.root.stack": "rust",
            "apps.root.container": false,
            "apps.api.path": "api", "apps.api.stack": "python-uv",
            "apps.api.container": false, "apps.api.toolchain": false,
        })),
        vec![never_touch("api/pyproject.toml"), never_touch("Cargo.toml")]
    );
}

#[test]
fn go_never_renders_into_go_mod() {
    let repo = Repo::new();
    repo.file("svc/go.mod").file("svc/go.sum");
    assert_eq!(
        repo.render(json!({
            "apps.svc.path": "svc", "apps.svc.stack": "go",
            "apps.svc.container": false, "apps.svc.toolchain": true,
        })),
        vec![never_touch("svc/go.mod")]
    );
}

#[test]
fn two_renders_are_byte_identical() {
    let repo = Repo::new();
    repo.file("Cargo.toml").file("Cargo.lock");
    repo.file("web/package.json").file("web/pnpm-lock.yaml");
    let raw = json!({
        "apps.root.path": ".", "apps.root.stack": "rust", "apps.root.toolchain": true,
        "apps.root.toolchain_version": "1.99",
        "apps.web.path": "web", "apps.web.stack": "node", "apps.web.toolchain_version": "24",
    });
    assert_eq!(repo.render(raw.clone()), repo.render(raw));
}

#[test]
fn an_existing_pin_file_is_skipped_and_left_intact() {
    let repo = Repo::new();
    repo.cli(&["install", "<repo>", "--new-personal", "--apply"]);
    repo.file("api/pyproject.toml").file("api/uv.lock");
    repo.write("api/.python-version", "3.12\n");
    let plan = repo.cli(&[
        "configure",
        "<repo>",
        "stack-packs",
        "--set",
        "apps.api.path=api",
        "--set",
        "apps.api.stack=python-uv",
        "--set",
        "apps.api.container=false",
    ]);
    assert!(
        plan.contains("PLAN SKIP api/.python-version [seed:stack-packs]\n"),
        "{plan}"
    );
    assert!(!plan.contains("PLAN api/.python-version"), "{plan}");
    assert!(!plan.contains("api/pyproject.toml"), "{plan}");
    assert_eq!(repo.read("api/.python-version"), "3.12\n");
}

#[test]
fn plan_apply_plan_seeds_once_records_the_manifest_and_then_changes_nothing() {
    let repo = Repo::new();
    repo.cli(&["install", "<repo>", "--new-personal", "--apply"]);
    repo.write("Cargo.toml", "[package]\nname = \"demo\"\n")
        .file("Cargo.lock");
    let applied = repo.cli(&[
        "configure",
        "<repo>",
        "stack-packs",
        "--set",
        "apps.root.path=.",
        "--set",
        "apps.root.stack=rust",
        "--set",
        "apps.root.container=false",
        "--set",
        "apps.root.toolchain=true",
        "--set",
        "apps.root.toolchain_version=1.99",
        "--apply",
    ]);
    assert!(
        applied.contains("WRITE rust-toolchain.toml [seed:stack-packs]\n"),
        "{applied}"
    );
    assert_eq!(repo.read("rust-toolchain.toml"), RUST_TOOLCHAIN);
    assert_eq!(repo.read("Cargo.toml"), "[package]\nname = \"demo\"\n");
    let lock: Value = serde_json::from_str(&repo.read(".agent-setup/lock.json")).unwrap();
    assert_eq!(
        lock["files"]["Cargo.toml"],
        json!({"module": "stack-packs", "class": "never-touch"})
    );
    let again = repo.cli(&["install", "<repo>"]);
    assert!(again.ends_with("No changes.\n"), "{again}");
    assert!(
        again.contains("PLAN SKIP rust-toolchain.toml [seed:stack-packs]\n"),
        "{again}"
    );
}

#[test]
fn a_template_key_missing_from_the_pin_table_refuses() {
    let pins = PinTable::embedded().unwrap();
    assert_eq!(
        seeds::fill("{{tools.zig}}\n", &pins)
            .unwrap_err()
            .to_string(),
        "stack-packs: tool `zig` is not in templates/stack-packs/pins.json; add it with its version before rendering"
    );
    assert_eq!(
        seeds::fill("{{tools.rust\n", &pins)
            .unwrap_err()
            .to_string(),
        "stack-packs: a template has an unclosed `{{tools.` placeholder"
    );
}

/// Writes the manifest stack-packs declares never-touch.
struct ManifestWriter;
impl Module for ManifestWriter {
    fn id(&self) -> &'static str {
        "manifest-writer"
    }
    fn version(&self) -> &'static str {
        "0.1.0"
    }
    fn render(&self, _cx: &Context<'_>) -> brakes::Result<Vec<Rendered>> {
        Ok(vec![Rendered {
            path: "Cargo.toml".to_owned(),
            class: Ownership::Managed,
            content: Some("[package]\nname = \"rewritten\"\n".to_owned()),
            scaffold: None,
        }])
    }
}

#[test]
fn a_module_writing_a_protected_manifest_refuses() {
    let repo = Repo::new();
    repo.cli(&["install", "<repo>", "--new-personal", "--apply"]);
    repo.write("Cargo.toml", "[package]\nname = \"demo\"\n")
        .file("Cargo.lock");
    repo.cli(&[
        "configure",
        "<repo>",
        "stack-packs",
        "--set",
        "apps.root.path=.",
        "--set",
        "apps.root.stack=rust",
        "--set",
        "apps.root.container=false",
        "--apply",
    ]);
    let profile = profile_for(&repo.root).unwrap();
    let source = Source::embedded();
    let modules: [&dyn Module; 3] = [&SetupCore, &StackPacks, &ManifestWriter];
    let refusal = engine::plan(&repo.root, &source, &profile, &modules, &|_| true)
        .unwrap_err()
        .to_string();
    assert_eq!(
        refusal,
        "Module manifest-writer: path declared never-touch is rendered: Cargo.toml"
    );
    assert_eq!(repo.read("Cargo.toml"), "[package]\nname = \"demo\"\n");
}

// ---- Container seeds (SPEC-stack-packs.md, Container seed; #760) ----

/// Content of the rendered item at `path`.
fn content_of(items: &[(String, Ownership, Option<String>)], path: &str) -> String {
    let (_, class, content) = items
        .iter()
        .find(|(p, _, _)| p == path)
        .unwrap_or_else(|| panic!("{path} not rendered: {items:?}"));
    assert_eq!(*class, Ownership::Seed, "{path}");
    content.clone().unwrap()
}

/// A repository with one container app of `stack` at `app/`.
fn container_app(stack: &str, extra: Value) -> (Repo, String, String) {
    let repo = Repo::new();
    match stack {
        "rust" => repo.file("app/Cargo.toml").file("app/Cargo.lock"),
        "python-uv" => repo.file("app/pyproject.toml").file("app/uv.lock"),
        "node" => repo.file("app/package.json").file("app/package-lock.json"),
        "go" => repo.file("app/go.mod").file("app/go.sum"),
        other => panic!("{other}"),
    };
    // The Dockerfile is under test; the toolchain seed has its own tests.
    let mut raw = json!({"apps.app.path": "app", "apps.app.stack": stack,
        "apps.app.toolchain": false});
    for (key, value) in extra.as_object().unwrap() {
        raw[key] = value.clone();
    }
    let items = repo.render(raw);
    let dockerfile = content_of(&items, "app/Dockerfile");
    let dockerignore = content_of(&items, "app/.dockerignore");
    (repo, dockerfile, dockerignore)
}

fn instructions<'a>(dockerfile: &'a str, keyword: &str) -> Vec<&'a str> {
    dockerfile
        .lines()
        .filter(|line| line.split_whitespace().next() == Some(keyword))
        .collect()
}

/// The text rules every pack's seed satisfies.
fn assert_container_rules(stack: &str, dockerfile: &str, dockerignore: &str, healthcheck: bool) {
    let pins = PinTable::embedded().unwrap();
    let froms = instructions(dockerfile, "FROM");
    assert_eq!(froms.len(), 2, "{stack}: multi-stage\n{dockerfile}");
    for from in &froms {
        assert!(from.contains("@sha256:"), "{stack}: {from}");
    }
    assert!(!dockerfile.contains("latest"), "{stack}\n{dockerfile}");
    assert!(froms[0].ends_with(" AS build"), "{stack}: {}", froms[0]);
    let build = pins.image(&format!("{stack}.build")).unwrap().pinned();
    assert_eq!(froms[0], format!("FROM {build} AS build"), "{stack}");
    assert!(
        dockerfile.contains("RUN --mount=type=cache,"),
        "{stack}: BuildKit cache mount\n{dockerfile}"
    );
    assert!(
        !dockerfile.contains("{{"),
        "{stack}: unfilled\n{dockerfile}"
    );
    let runtime = dockerfile.split(froms[1]).nth(1).unwrap();
    assert!(runtime.contains("\nWORKDIR /app\n"), "{stack}\n{runtime}");
    for copy in instructions(runtime, "COPY") {
        assert!(copy.contains("--chown=0:0 --chmod=0775"), "{stack}: {copy}");
    }
    assert_eq!(instructions(runtime, "USER"), ["USER 10001:0"], "{stack}");
    assert!(runtime.contains("\nENV HOME=/tmp\n"), "{stack}\n{runtime}");
    assert_eq!(instructions(runtime, "EXPOSE").len(), 1, "{stack}");
    let checks = instructions(runtime, "HEALTHCHECK");
    if healthcheck {
        assert_eq!(checks.len(), 1, "{stack}\n{runtime}");
        assert!(
            checks[0].contains(" CMD [\""),
            "{stack}: exec form: {}",
            checks[0]
        );
    } else {
        assert!(checks.is_empty(), "{stack}\n{runtime}");
    }
    let entrypoints = instructions(runtime, "ENTRYPOINT");
    assert_eq!(entrypoints.len(), 1, "{stack}");
    assert!(
        entrypoints[0].starts_with("ENTRYPOINT [\""),
        "{stack}: {}",
        entrypoints[0]
    );
    assert!(instructions(dockerfile, "VOLUME").is_empty(), "{stack}");
    assert!(
        dockerfile.contains("Seed: yours to edit; Dependabot bumps the digests."),
        "{stack}\n{dockerfile}"
    );
    assert!(
        dockerfile.starts_with(&format!("# brakes stack-packs ({stack})")),
        "{stack}\n{dockerfile}"
    );
    assert!(dockerfile.contains("# OpenShift:"), "{stack}\n{dockerfile}");
    let ignored: Vec<&str> = dockerignore.lines().collect();
    for entry in [".git", ".agent-setup", "**/.env*"] {
        assert!(ignored.contains(&entry), "{stack}: {entry}\n{dockerignore}");
    }
}

#[test]
fn every_first_wave_pack_seeds_a_dockerfile_that_keeps_the_rules() {
    for stack in ["rust", "python-uv", "node", "go"] {
        let (_repo, dockerfile, dockerignore) = container_app(stack, json!({}));
        assert_container_rules(stack, &dockerfile, &dockerignore, true);
    }
}

#[test]
fn healthcheck_none_renders_no_healthcheck() {
    for stack in ["rust", "python-uv", "node", "go"] {
        let (_repo, dockerfile, dockerignore) =
            container_app(stack, json!({"apps.app.healthcheck": "none"}));
        assert_container_rules(stack, &dockerfile, &dockerignore, false);
    }
}

#[test]
fn the_runtime_image_follows_the_pack_runtime_and_the_family() {
    let pins = PinTable::embedded().unwrap();
    for (stack, runtime) in [
        ("rust", "distroless.cc"),
        ("python-uv", "distroless.python"),
        ("node", "distroless.node"),
        ("go", "distroless.static"),
    ] {
        let (_repo, dockerfile, _) = container_app(stack, json!({}));
        let line = format!("FROM {}\n", pins.image(runtime).unwrap().pinned());
        assert!(dockerfile.contains(&line), "{stack}: {line}\n{dockerfile}");
    }
}

#[test]
fn port_bin_and_a_custom_healthcheck_are_filled() {
    let (_repo, dockerfile, _) = container_app(
        "go",
        json!({"apps.app.port": 9090, "apps.app.bin": "server"}),
    );
    assert!(dockerfile.contains("\nEXPOSE 9090\n"), "{dockerfile}");
    assert!(dockerfile.contains("-o /out/server"), "{dockerfile}");
    assert!(
        dockerfile.contains("\nENTRYPOINT [\"/app/server\"]\n"),
        "{dockerfile}"
    );
    assert!(
        dockerfile.contains("CMD [\"/app/server\", \"--healthcheck\"]\n"),
        "{dockerfile}"
    );
    // `bin` defaults to the app directory name.
    let (_repo, dockerfile, _) = container_app("rust", json!({}));
    assert!(dockerfile.contains("--bin app "), "{dockerfile}");
    assert!(dockerfile.contains("\nEXPOSE 8080\n"), "{dockerfile}");
    let (_repo, dockerfile, _) = container_app(
        "python-uv",
        json!({"apps.app.healthcheck": "[\"/usr/bin/python3\", \"-m\", \"app.health\"]"}),
    );
    assert!(
        dockerfile.contains(" CMD [\"/usr/bin/python3\", \"-m\", \"app.health\"]\n"),
        "{dockerfile}"
    );
    let (_repo, dockerfile, _) = container_app("python-uv", json!({}));
    assert!(dockerfile.contains("127.0.0.1:8000/"), "{dockerfile}");
}

#[test]
fn a_shell_form_healthcheck_refuses() {
    let repo = Repo::new();
    repo.file("app/package.json").file("app/package-lock.json");
    let refusal = repo
        .try_render(json!({
            "apps.app.path": "app", "apps.app.stack": "node", "apps.app.toolchain": false,
            "apps.app.healthcheck": "curl -f http://localhost:3000/",
        }))
        .err()
        .unwrap()
        .to_string();
    assert_eq!(
        refusal,
        "stack-packs: app `app` healthcheck must be `default`, `none` or an exec-form JSON array such as [\"/app/bin\", \"--healthcheck\"]; the runtime image has no shell"
    );
}

#[test]
fn node_installs_with_the_lockfile_package_manager() {
    for (lockfile, install) in [
        ("package-lock.json", "npm ci"),
        (
            "pnpm-lock.yaml",
            "corepack enable && pnpm install --frozen-lockfile",
        ),
        ("yarn.lock", "corepack enable && yarn install --immutable"),
    ] {
        let repo = Repo::new();
        repo.file("web/package.json")
            .file(&format!("web/{lockfile}"));
        let items = repo.render(
            json!({"apps.web.path": "web", "apps.web.stack": "node", "apps.web.toolchain": false}),
        );
        let dockerfile = content_of(&items, "web/Dockerfile");
        assert!(
            dockerfile.contains(&format!("    {install}\n")),
            "{lockfile}\n{dockerfile}"
        );
    }
    let repo = Repo::new();
    repo.file("web/package.json").file("web/bun.lock");
    let refusal = repo
        .try_render(
            json!({"apps.web.path": "web", "apps.web.stack": "node", "apps.web.toolchain": false}),
        )
        .err()
        .unwrap()
        .to_string();
    assert_eq!(
        refusal,
        "stack-packs: app `web` uses bun, which has no pinned build image; set apps.web.container=false or seed the Dockerfile by hand"
    );
}

#[test]
fn dockerignore_carries_the_spec_list_and_the_generated_paths_inside_the_app() {
    let repo = Repo::new();
    repo.file("Cargo.toml").file("Cargo.lock");
    repo.cli(&["install", "<repo>", "--new-personal", "--apply"]);
    let mut profile: Value = serde_json::from_str(&repo.read(".agent-setup/project.json")).unwrap();
    profile["generated_paths"] = json!(["docs/agent-setup/", "api/gen/", "api/schema.json"]);
    repo.write(".agent-setup/project.json", &profile.to_string());
    repo.file("api/pyproject.toml").file("api/uv.lock");
    let items = repo.render(json!({
        "apps.root.path": ".", "apps.root.stack": "rust",
        "apps.api.path": "api", "apps.api.stack": "python-uv", "apps.api.toolchain": false,
    }));
    let root = content_of(&items, ".dockerignore");
    let api = content_of(&items, "api/.dockerignore");
    for list in [&root, &api] {
        for entry in [
            ".git",
            ".agent-setup",
            "**/.env*",
            "target",
            "node_modules",
            ".venv",
            "**/__pycache__",
            "*.md",
            "tests",
        ] {
            assert!(list.lines().any(|l| l == entry), "{entry}\n{list}");
        }
    }
    for entry in ["docs/agent-setup", "api/gen", "api/schema.json"] {
        assert!(root.lines().any(|l| l == entry), "{entry}\n{root}");
    }
    assert!(api.lines().any(|l| l == "gen"), "{api}");
    assert!(api.lines().any(|l| l == "schema.json"), "{api}");
    assert!(!api.contains("docs/agent-setup"), "{api}");
    // python-uv keeps the README a pyproject may declare.
    assert!(api.lines().any(|l| l == "!README.md"), "{api}");
}

#[test]
fn a_four_app_monorepo_seeds_containers_for_server_apps_only() {
    let repo = Repo::new();
    repo.cli(&["install", "<repo>", "--new-personal", "--apply"]);
    repo.file("apps/backend/pyproject.toml")
        .file("apps/backend/uv.lock");
    repo.file("apps/web/package.json")
        .file("apps/web/package-lock.json");
    repo.file("apps/ios/Project.xcodeproj/project.pbxproj")
        .file("apps/ios/Package.swift");
    repo.file("apps/android/build.gradle.kts")
        .file("apps/android/settings.gradle.kts")
        .file("apps/android/gradlew");
    // The repository runs Python 3.12 and Node 22: the seeds follow it, not the pin table (#1161).
    repo.write(".tool-versions", "python 3.12\nnodejs 22\n");
    let applied = repo.cli(&[
        "configure",
        "<repo>",
        "stack-packs",
        "--set",
        "apps.backend.path=apps/backend",
        "--set",
        "apps.backend.stack=python-uv",
        "--set",
        "apps.backend.port=8000",
        "--set",
        "apps.web.path=apps/web",
        "--set",
        "apps.web.stack=node",
        "--set",
        "apps.web.port=3000",
        "--set",
        "apps.ios.path=apps/ios",
        "--set",
        "apps.ios.stack=swift-ios",
        "--set",
        "apps.ios.container=false",
        "--set",
        "apps.ios.toolchain=false",
        "--set",
        "apps.android.path=apps/android",
        "--set",
        "apps.android.stack=kotlin-android",
        "--set",
        "apps.android.container=false",
        "--set",
        "apps.android.toolchain=false",
        "--apply",
    ]);
    for path in [
        "apps/backend/Dockerfile",
        "apps/backend/.dockerignore",
        "apps/backend/.python-version",
        "apps/web/Dockerfile",
        "apps/web/.dockerignore",
        "apps/web/.nvmrc",
    ] {
        assert!(
            applied.contains(&format!("WRITE {path} [seed:stack-packs]\n")),
            "{path}\n{applied}"
        );
        assert!(repo.root.join(path).is_file(), "{path}");
    }
    assert_eq!(repo.read("apps/backend/.python-version"), "3.12\n");
    assert_eq!(repo.read("apps/web/.nvmrc"), "22\n");
    assert!(!applied.contains("apps/ios/"), "{applied}");
    assert!(!applied.contains("apps/android/"), "{applied}");
    let again = repo.cli(&["install", "<repo>"]);
    assert!(again.ends_with("No changes.\n"), "{again}");
    assert!(
        again.contains("PLAN SKIP apps/backend/Dockerfile [seed:stack-packs]\n"),
        "{again}"
    );
}

#[test]
fn device_apps_seed_their_toolchain_pins_and_protect_their_manifests() {
    let repo = Repo::new();
    repo.file("apps/ios/Package.swift");
    repo.file("apps/android/settings.gradle.kts")
        .file("apps/android/gradlew");
    assert_eq!(
        repo.render(json!({
            "apps.ios.path": "apps/ios", "apps.ios.stack": "swift-ios",
            "apps.ios.toolchain_version": "27.1",
            "apps.android.path": "apps/android", "apps.android.stack": "kotlin-android",
            "apps.android.toolchain_version": "17",
        })),
        vec![
            seed("apps/android/.java-version", "17\n"),
            never_touch("apps/android/settings.gradle.kts"),
            never_touch("apps/android/build.gradle.kts"),
            never_touch("apps/android/gradle/wrapper/gradle-wrapper.properties"),
            seed("apps/ios/.xcode-version", "27.1\n"),
            never_touch("apps/ios/Package.swift"),
        ]
    );
}

#[test]
fn a_dbt_app_seeds_python_version_and_protects_its_project_and_package_files() {
    let repo = Repo::new();
    repo.file("analytics/dbt_project.yml");
    assert_eq!(
        repo.render(json!({
            "apps.analytics.path": "analytics", "apps.analytics.stack": "sql-dbt",
            "apps.analytics.toolchain_version": "3.13",
        })),
        vec![
            seed("analytics/.python-version", "3.13\n"),
            never_touch("analytics/dbt_project.yml"),
            never_touch("analytics/packages.yml"),
            never_touch("analytics/dependencies.yml"),
        ]
    );
}
