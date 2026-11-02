//! The four packs as data (SPEC-stack-packs.md, "Evidence and proposals", "CI
//! setup as data"): proposals per the spec table, `ci_setup` against goldens,
//! every `uses:` pinned from the table, every cache save on the default branch
//! only, no declared project command run by a setup step; the test-runner
//! profile and the instrumentation recipe per pack ("Test-runner profile",
//! "Instrumentation recipe"), node's by the runner its `package.json` names;
//! the coverage recipe and its metric over recorded reports ("Coverage recipe");
//! the per-file diff report, the property recipe and the mutation recipe
//! against reports and results recorded with the pinned tools ("Property
//! recipe", "Mutation recipe").
use brakes::modules::stack_packs::{
    App, ContainerSupport, CoverageInstall, CoverageRecipe, DEFAULT_BRANCH_CONDITION, Evidence,
    MutationScope, OtelKind, PackageManager, PinTable, StackId, StackPack, detect,
    packs::{self, node::NodeRunner},
};
use std::{collections::BTreeMap, fs, path::Path, process::Command};

fn pins() -> PinTable {
    PinTable::embedded().unwrap()
}

fn app(stack: StackId, path: &str) -> App {
    App {
        id: if path == "." {
            "root".to_owned()
        } else {
            path.rsplit('/').next().unwrap().to_owned()
        },
        path: path.to_owned(),
        stack,
        container: true,
        toolchain: stack != StackId::Rust,
        package_manager: None,
        declared: BTreeMap::new(),
    }
}

fn declared(mut app: App, pairs: &[(&str, &str)]) -> App {
    app.declared = pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    app
}

/// Every `ci_setup` case the goldens pin, by golden name.
fn cases() -> Vec<(&'static str, App)> {
    let mut rust_root = app(StackId::Rust, ".");
    rust_root.toolchain = false;
    let rust_nextest = declared(
        {
            let mut a = app(StackId::Rust, "services/api");
            a.toolchain = true;
            a
        },
        &[
            ("test", "cargo nextest run --workspace --locked"),
            ("lint", "cargo clippy --workspace --locked -- -D warnings"),
        ],
    );
    let mut node_pnpm = app(StackId::Node, "apps/web");
    node_pnpm.package_manager = Some(PackageManager::Pnpm);
    let mut node_npm = app(StackId::Node, ".");
    node_npm.package_manager = Some(PackageManager::Npm);
    let mut python_no_seed = app(StackId::PythonUv, "apps/backend");
    python_no_seed.toolchain = false;
    let mut android_no_seed = device(StackId::KotlinAndroid, "apps/android");
    android_no_seed.toolchain = false;
    let mut ios_no_seed = device(StackId::SwiftIos, "apps/ios");
    ios_no_seed.toolchain = false;
    let mut dbt_no_seed = device(StackId::SqlDbt, "analytics/dbt");
    dbt_no_seed.toolchain = false;
    vec![
        ("rust-root", rust_root),
        ("rust-nextest-app", rust_nextest),
        ("python-uv-app", app(StackId::PythonUv, "apps/backend")),
        ("python-uv-no-toolchain", python_no_seed),
        ("node-npm-root", node_npm),
        ("node-pnpm-app", node_pnpm),
        ("go-app", app(StackId::Go, "services/worker")),
        (
            "kotlin-android-app",
            device(StackId::KotlinAndroid, "apps/android"),
        ),
        ("kotlin-android-no-toolchain", android_no_seed),
        ("swift-ios-app", device(StackId::SwiftIos, "apps/ios")),
        ("swift-ios-no-toolchain", ios_no_seed),
        ("sql-dbt-app", device(StackId::SqlDbt, "analytics/dbt")),
        ("sql-dbt-no-toolchain", dbt_no_seed),
    ]
}

/// A device app: no container, the toolchain seed on.
fn device(stack: StackId, path: &str) -> App {
    let mut a = app(stack, path);
    a.container = false;
    a
}

#[test]
fn the_seven_stacks_have_a_pack_and_the_four_are_filled() {
    for id in StackId::ALL {
        assert_eq!(packs::pack(id).id, id);
    }
    assert_eq!(packs::ALL.len(), 7);
    for pack in packs::FIRST_WAVE {
        assert!(pack.proposed.test.is_some(), "{}: test proposal", pack.id);
        assert!(
            pack.proposed.verify.is_some(),
            "{}: verify proposal",
            pack.id
        );
        assert!(!pack.evidence.is_empty(), "{}: evidence", pack.id);
        assert!(
            matches!(pack.container, ContainerSupport::Capable { .. }),
            "{}: container-capable",
            pack.id
        );
    }
}

#[test]
fn proposals_match_the_spec_table() {
    let rust = packs::pack(StackId::Rust);
    assert_eq!(
        rust.evidence,
        &[Evidence::AllOf(&["Cargo.toml", "Cargo.lock"])]
    );
    assert_eq!(
        rust.proposed.build,
        Some("cargo build --workspace --all-targets --locked")
    );
    assert_eq!(rust.proposed.test, Some("cargo test --workspace --locked"));
    assert_eq!(
        rust.proposed.lint,
        Some("cargo clippy --workspace --all-targets --locked -- -D warnings")
    );
    assert_eq!(rust.proposed.verify, Some("{{lint}} && {{test}}"));
    assert_eq!(
        rust.lockfile.map(|l| (l.file, l.strict_flag)),
        Some(("Cargo.lock", "--locked"))
    );
    assert_eq!(
        rust.toolchain_seed.map(|s| s.path),
        Some("rust-toolchain.toml")
    );

    let python = packs::pack(StackId::PythonUv);
    assert_eq!(
        python.evidence,
        &[Evidence::AllOf(&["pyproject.toml", "uv.lock"])]
    );
    assert_eq!(python.proposed.build, None);
    assert_eq!(python.proposed.test, Some("uv run --frozen pytest -q"));
    assert_eq!(python.proposed.lint, Some("uv run --frozen ruff check ."));
    assert_eq!(python.proposed.verify, Some("{{lint}} && {{test}}"));
    assert_eq!(
        python.lockfile.map(|l| (l.file, l.strict_flag)),
        Some(("uv.lock", "--frozen"))
    );
    assert_eq!(
        python.toolchain_seed.map(|s| s.path),
        Some(".python-version")
    );

    let node = packs::pack(StackId::Node);
    assert_eq!(
        node.evidence,
        &[
            Evidence::AllOf(&["package.json"]),
            Evidence::AnyOf(&[
                "package-lock.json",
                "pnpm-lock.yaml",
                "yarn.lock",
                "bun.lock"
            ]),
        ]
    );
    assert_eq!(node.proposed.build, Some("{{pm}} run build"));
    assert_eq!(node.proposed.test, Some("{{pm}} test"));
    assert_eq!(node.proposed.lint, Some("{{pm}} run lint"));
    assert_eq!(node.proposed.verify, Some("{{lint}} && {{test}}"));
    assert_eq!(node.toolchain_seed.map(|s| s.path), Some(".nvmrc"));
    assert_eq!(
        node.lockfile.map(|l| (l.file, l.strict_flag)),
        Some(("package-lock.json", "ci"))
    );

    let go = packs::pack(StackId::Go);
    assert_eq!(go.evidence, &[Evidence::AllOf(&["go.mod", "go.sum"])]);
    assert_eq!(go.proposed.build, Some("go build ./..."));
    assert_eq!(go.proposed.test, Some("go test ./..."));
    assert_eq!(go.proposed.lint, Some("go vet ./..."));
    assert_eq!(
        go.proposed.verify,
        Some("go mod verify && {{lint}} && {{test}}")
    );
    assert_eq!(
        go.lockfile.map(|l| (l.file, l.strict_flag)),
        Some(("go.sum", "-mod=readonly"))
    );
    assert_eq!(
        go.toolchain_seed, None,
        "the toolchain directive lives in go.mod"
    );

    // Device packs (slice 3, #768): Gradle through its checked-in wrapper,
    // Xcode through the scheme the project shares; neither has a lockfile
    // with a strict install flag, neither builds a container.
    let android = packs::pack(StackId::KotlinAndroid);
    assert_eq!(
        android.evidence,
        &[
            Evidence::AnyOf(&["settings.gradle.kts", "build.gradle.kts"]),
            Evidence::AllOf(&["gradlew"]),
        ]
    );
    assert_eq!(android.proposed.build, None);
    assert_eq!(android.proposed.test, Some("./gradlew test"));
    assert_eq!(android.proposed.lint, None);
    assert_eq!(android.proposed.verify, Some("{{lint}} && {{test}}"));
    assert_eq!(android.lockfile, None);
    assert_eq!(
        android.toolchain_seed.map(|s| s.path),
        Some(".java-version")
    );

    let ios = packs::pack(StackId::SwiftIos);
    assert_eq!(
        ios.evidence,
        &[Evidence::AnyOf(&["*.xcodeproj", "Package.swift"])]
    );
    assert_eq!(ios.proposed.build, None);
    assert_eq!(
        ios.proposed.test,
        Some("xcodebuild test -scheme {{scheme}}")
    );
    assert_eq!(ios.proposed.lint, None);
    assert_eq!(ios.proposed.verify, Some("{{lint}} && {{test}}"));
    assert_eq!(ios.lockfile, None);
    assert_eq!(ios.toolchain_seed.map(|s| s.path), Some(".xcode-version"));
    assert_eq!(packs::swift_ios::SWIFTPM.build, Some("swift build"));
    assert_eq!(packs::swift_ios::SWIFTPM.test, Some("swift test"));
    assert_eq!(packs::swift_ios::SWIFTPM.lint, None);
    assert_eq!(
        packs::swift_ios::SWIFTPM.verify,
        Some("{{lint}} && {{test}}")
    );

    // Data pack (slice 4, #769): a dbt project; `sqlfluff lint` is proposed
    // only when a `.sqlfluff` declares the dialect (detection decides).
    let dbt = packs::pack(StackId::SqlDbt);
    assert_eq!(dbt.evidence, &[Evidence::AllOf(&["dbt_project.yml"])]);
    assert_eq!(dbt.proposed.build, None);
    assert_eq!(dbt.proposed.test, Some("dbt build"));
    assert_eq!(dbt.proposed.lint, Some("sqlfluff lint"));
    assert_eq!(dbt.proposed.verify, Some("{{lint}} && {{test}}"));
    assert_eq!(dbt.lockfile, None);
    assert_eq!(dbt.toolchain_seed.map(|s| s.path), Some(".python-version"));
    assert_eq!(dbt.dependabot_ecosystem, "pip");
    assert_eq!(dbt.container, ContainerSupport::NotApplicable);
    assert!(!dbt.macos_target);
}

#[test]
fn device_proposals_compose_without_a_lint_command() {
    let android = packs::proposals(
        packs::pack(StackId::KotlinAndroid),
        &device(StackId::KotlinAndroid, "apps/android"),
    );
    assert_eq!(android["test"], "./gradlew test");
    assert_eq!(android["verify"], "./gradlew test");
    assert!(!android.contains_key("build"));
    assert!(!android.contains_key("lint"));
    let swiftpm = packs::proposals_from(
        &packs::swift_ios::SWIFTPM,
        &device(StackId::SwiftIos, "apps/ios"),
    );
    assert_eq!(swiftpm["build"], "swift build");
    assert_eq!(swiftpm["test"], "swift test");
    assert_eq!(swiftpm["verify"], "swift test");
}

#[test]
fn proposals_compose_lint_test_and_the_package_manager() {
    let rust = packs::proposals(packs::pack(StackId::Rust), &app(StackId::Rust, "."));
    assert_eq!(
        rust["verify"],
        "cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked"
    );
    let go = packs::proposals(packs::pack(StackId::Go), &app(StackId::Go, "svc"));
    assert_eq!(
        go["verify"],
        "go mod verify && go vet ./... && go test ./..."
    );
    let python = packs::proposals(packs::pack(StackId::PythonUv), &app(StackId::PythonUv, "."));
    assert!(!python.contains_key("build"));
    assert_eq!(
        python["verify"],
        "uv run --frozen ruff check . && uv run --frozen pytest -q"
    );
    let mut web = app(StackId::Node, "apps/web");
    web.package_manager = Some(PackageManager::Pnpm);
    let node = packs::proposals(packs::pack(StackId::Node), &web);
    assert_eq!(node["test"], "pnpm test");
    assert_eq!(node["lint"], "pnpm run lint");
    assert_eq!(node["build"], "pnpm run build");
    assert_eq!(node["verify"], "pnpm run lint && pnpm test");
}

#[test]
fn the_package_manager_comes_from_the_lockfile_present() {
    assert_eq!(PackageManager::from_lockfiles(&[]).unwrap(), None);
    assert_eq!(
        PackageManager::from_lockfiles(&["package.json", "package-lock.json"]).unwrap(),
        Some(PackageManager::Npm)
    );
    assert_eq!(
        PackageManager::from_lockfiles(&["pnpm-lock.yaml"]).unwrap(),
        Some(PackageManager::Pnpm)
    );
    assert_eq!(
        PackageManager::from_lockfiles(&["yarn.lock"]).unwrap(),
        Some(PackageManager::Yarn)
    );
    assert_eq!(
        PackageManager::from_lockfiles(&["bun.lock"]).unwrap(),
        Some(PackageManager::Bun)
    );
    assert_eq!(
        PackageManager::from_lockfiles(&["pnpm-lock.yaml", "package-lock.json"])
            .unwrap_err()
            .to_string(),
        "stack-packs: both package-lock.json and pnpm-lock.yaml are present; keep the lockfile of one package manager"
    );
    assert_eq!(
        (
            PackageManager::Npm.lockfile(),
            PackageManager::Npm.install()
        ),
        ("package-lock.json", "npm ci")
    );
    assert_eq!(
        (
            PackageManager::Pnpm.lockfile(),
            PackageManager::Pnpm.install()
        ),
        ("pnpm-lock.yaml", "pnpm install --frozen-lockfile")
    );
    assert_eq!(
        (
            PackageManager::Yarn.lockfile(),
            PackageManager::Yarn.install()
        ),
        ("yarn.lock", "yarn install --immutable")
    );
    assert_eq!(
        (
            PackageManager::Bun.lockfile(),
            PackageManager::Bun.install()
        ),
        ("bun.lock", "bun install --frozen-lockfile")
    );
}

#[test]
fn dependabot_ecosystems_and_macos_targets() {
    let ecosystems: Vec<_> = StackId::ALL
        .iter()
        .map(|id| (id.as_str(), packs::pack(*id).dependabot_ecosystem))
        .collect();
    assert_eq!(
        ecosystems,
        [
            ("rust", "cargo"),
            ("python-uv", "uv"),
            ("node", "npm"),
            ("go", "gomod"),
            ("kotlin-android", "gradle"),
            ("swift-ios", "swift"),
            ("sql-dbt", "pip"),
        ]
    );
    for id in StackId::ALL {
        assert_eq!(
            packs::pack(id).macos_target,
            id == StackId::SwiftIos,
            "{id}"
        );
    }
}

#[test]
fn a_container_on_a_device_or_data_pack_refuses() {
    for id in [StackId::KotlinAndroid, StackId::SwiftIos, StackId::SqlDbt] {
        let pack = packs::pack(id);
        assert_eq!(pack.container, ContainerSupport::NotApplicable);
        let a = app(id, "apps/x");
        assert_eq!(
            packs::check_container(&a, pack).unwrap_err().to_string(),
            format!(
                "stack-packs: app `x` declares container: true but stack `{id}` builds no container image"
            )
        );
        let mut off = a.clone();
        off.container = false;
        assert!(packs::check_container(&off, pack).is_ok());
        let steps = (pack.ci_setup)(&off, &pins()).unwrap();
        assert!(!steps.is_empty(), "{id}: setup steps");
    }
    for pack in packs::FIRST_WAVE {
        assert!(packs::check_container(&app(pack.id, "."), pack).is_ok());
    }
}

#[test]
fn ci_setup_matches_the_goldens() {
    let table = pins();
    for (name, app) in cases() {
        let steps = (packs::pack(app.stack).ci_setup)(&app, &table).unwrap();
        let json = serde_json::to_string_pretty(&steps).unwrap() + "\n";
        let golden = format!(
            "{}/tests/golden/stack_packs/ci_setup/{name}.json",
            env!("CARGO_MANIFEST_DIR")
        );
        if std::env::var_os("UPDATE_GOLDENS").is_some() {
            fs::create_dir_all(std::path::Path::new(&golden).parent().unwrap()).unwrap();
            fs::write(&golden, &json).unwrap();
        }
        let expected = fs::read_to_string(&golden)
            .unwrap_or_else(|e| panic!("{golden}: {e}; actual:\n{json}"));
        assert_eq!(json, expected, "{name}: ci_setup drifted from {golden}");
        let again = (packs::pack(app.stack).ci_setup)(&app, &table).unwrap();
        assert_eq!(steps, again, "{name}: deterministic");
    }
}

#[test]
fn every_uses_is_pinned_every_save_is_default_branch_only_and_nothing_declared_runs() {
    let table = pins();
    for (name, app) in cases() {
        let app = declared(
            app,
            &[
                ("test", "cargo nextest run --workspace --locked"),
                ("lint", "make lint"),
                ("verify", "bash scripts/verificar.sh"),
            ],
        );
        let steps = (packs::pack(app.stack).ci_setup)(&app, &table).unwrap();
        assert!(!steps.is_empty(), "{name}");
        for step in &steps {
            if let Some(action) = &step.uses {
                let pinned = table.action(&action.repo).unwrap();
                assert_eq!(
                    action, &pinned,
                    "{name}: `{}` is not the table's pin",
                    step.name
                );
                assert_eq!(action.sha.len(), 40);
            } else {
                assert!(
                    step.run.is_some(),
                    "{name}: `{}` neither uses nor runs",
                    step.name
                );
            }
            let saves = step
                .uses
                .as_ref()
                .is_some_and(|a| a.repo == "actions/cache/save")
                || step.with.contains_key("save-if")
                || step.with.contains_key("cache-read-only");
            if saves {
                // `save-if` gates the save; `cache-read-only` is its negation.
                let guarded = step.condition.as_deref() == Some(DEFAULT_BRANCH_CONDITION)
                    || step
                        .with
                        .get("save-if")
                        .is_some_and(|v| v.contains(DEFAULT_BRANCH_CONDITION))
                    || step
                        .with
                        .get("cache-read-only")
                        .is_some_and(|v| v == &format!("${{{{ !({DEFAULT_BRANCH_CONDITION}) }}}}"));
                assert!(
                    guarded,
                    "{name}: `{}` saves off the default branch",
                    step.name
                );
            }
            if let Some(run) = &step.run {
                for command in app.declared.values() {
                    assert!(
                        !run.contains(command),
                        "{name}: `{}` runs `{command}`",
                        step.name
                    );
                }
                assert_eq!(
                    step.working_directory,
                    app.working_directory(),
                    "{name}: `{}` runs outside the app",
                    step.name
                );
            }
        }
        let restores = steps
            .iter()
            .filter(|s| {
                s.uses
                    .as_ref()
                    .is_some_and(|a| a.repo == "actions/cache/restore")
            })
            .count();
        let saves = steps
            .iter()
            .filter(|s| {
                s.uses
                    .as_ref()
                    .is_some_and(|a| a.repo == "actions/cache/save")
            })
            .count();
        assert_eq!(restores, saves, "{name}: restore and save come in pairs");
        if app.stack == StackId::Rust {
            let setup = steps.iter().any(|s| {
                s.uses
                    .as_ref()
                    .is_some_and(|a| a.repo == "actions/setup-node")
                    || s.with.contains_key("enable-cache")
                    || s.with.contains_key("cache")
            });
            assert!(!setup, "{name}: a rust pack carries no other stack's setup");
            assert!(
                steps.iter().any(|s| s
                    .with
                    .get("tool")
                    .is_some_and(|t| t.starts_with("nextest@"))),
                "{name}: nextest declared, so installed"
            );
        }
    }
}

#[test]
fn setup_actions_disable_their_own_cache_and_the_pair_restores_then_saves() {
    let table = pins();
    for (name, app) in cases() {
        let steps = (packs::pack(app.stack).ci_setup)(&app, &table).unwrap();
        let mut restore_at = None;
        let mut save_at = None;
        for (i, step) in steps.iter().enumerate() {
            match step.uses.as_ref().map(|a| a.repo.as_str()) {
                Some("astral-sh/setup-uv") => assert_eq!(step.with["enable-cache"], "false"),
                // setup-go's `cache` is a boolean; setup-node's names a package
                // manager, and `package-manager-cache` turns it off (#1166).
                Some("actions/setup-go") => assert_eq!(step.with["cache"], "false"),
                Some("actions/setup-node") => {
                    assert_eq!(step.with["package-manager-cache"], "false", "{name}");
                    assert!(!step.with.contains_key("cache"), "{name}");
                }
                Some("actions/cache/restore") => restore_at = Some(i),
                Some("actions/cache/save") => {
                    save_at = Some(i);
                    let restore = &steps[restore_at.expect("restore before save")];
                    assert_eq!(step.with["key"], restore.with["key"], "{name}");
                    assert_eq!(step.with["path"], restore.with["path"], "{name}");
                }
                _ => {}
            }
        }
        if let (Some(r), Some(s)) = (restore_at, save_at) {
            let installs = steps[r + 1..s].iter().any(|st| st.run.is_some());
            assert!(
                installs,
                "{name}: the install runs between restore and save"
            );
        }
    }
}

#[test]
fn rust_installs_nextest_only_when_a_declared_command_uses_it() {
    let table = pins();
    let rust = packs::pack(StackId::Rust);
    let plain = (rust.ci_setup)(&app(StackId::Rust, "."), &table).unwrap();
    assert!(plain.iter().all(|s| !s.with.contains_key("tool")));
    assert_eq!(
        plain[0].with.get("toolchain").map(String::as_str),
        Some("1.99")
    );
    let mut seeded = app(StackId::Rust, ".");
    seeded.toolchain = true;
    let seeded = (rust.ci_setup)(&seeded, &table).unwrap();
    // The pinned action refuses an empty `toolchain` input; the seed still
    // decides which toolchain cargo runs through rustup's directory override.
    assert_eq!(
        seeded[0].with.get("toolchain").map(String::as_str),
        Some("1.99")
    );
    let with_nextest = (rust.ci_setup)(
        &declared(
            app(StackId::Rust, "."),
            &[("verify", "cargo nextest run --locked")],
        ),
        &table,
    )
    .unwrap();
    assert_eq!(
        with_nextest.last().unwrap().with["tool"],
        format!("nextest@{}", table.tool("nextest").unwrap().version)
    );
}

#[test]
fn node_without_a_package_manager_refuses() {
    let a = app(StackId::Node, "apps/web");
    assert_eq!(
        (packs::pack(StackId::Node).ci_setup)(&a, &pins())
            .unwrap_err()
            .to_string(),
        "stack-packs: app `web` is node but names no package manager; one of package-lock.json, pnpm-lock.yaml, yarn.lock, bun.lock must be present at `apps/web`"
    );
}

#[test]
fn a_missing_pin_refuses_through_ci_setup() {
    let mut table = pins();
    table.actions.remove("actions/setup-go");
    let err = (packs::pack(StackId::Go).ci_setup)(&app(StackId::Go, "."), &table).unwrap_err();
    assert_eq!(
        err.to_string(),
        "stack-packs: action `actions/setup-go` is not in templates/stack-packs/pins.json; add it with its sha before rendering"
    );
}

#[test]
fn packs_are_data_with_no_string_inside() {
    // A `const StackPack` compiles only if every field is `'static` data; this
    // pins the four first-wave ids and the stub ids as the spec lists them.
    const IDS: [StackId; 4] = [StackId::Rust, StackId::PythonUv, StackId::Node, StackId::Go];
    const DEVICE_IDS: [StackId; 2] = [StackId::KotlinAndroid, StackId::SwiftIos];
    let first: Vec<StackId> = packs::FIRST_WAVE.iter().map(|p| p.id).collect();
    assert_eq!(first, IDS);
    let devices: Vec<StackId> = packs::DEVICES.iter().map(|p| p.id).collect();
    assert_eq!(devices, DEVICE_IDS);
    let rest: Vec<StackId> = packs::ALL
        .iter()
        .map(|p: &&StackPack| p.id)
        .filter(|id| !IDS.contains(id) && !DEVICE_IDS.contains(id))
        .collect();
    assert_eq!(rest, [StackId::SqlDbt], "the data pack; no stub is left");
    for pack in packs::ALL {
        assert!(
            pack.proposed.test.is_some(),
            "{}: every pack proposes a test",
            pack.id
        );
    }
}

#[test]
fn dbt_setup_installs_python_and_the_pinned_tools_with_a_gated_pip_cache() {
    let table = pins();
    let steps =
        (packs::pack(StackId::SqlDbt).ci_setup)(&device(StackId::SqlDbt, "analytics/dbt"), &table)
            .unwrap();
    assert_eq!(steps.len(), 4);
    assert_eq!(
        steps[0].uses,
        Some(table.action("actions/setup-python").unwrap())
    );
    assert_eq!(
        steps[0].with["python-version-file"],
        "analytics/dbt/.python-version"
    );
    assert!(
        !steps[0].with.contains_key("cache"),
        "no built-in cache: it saves on every run"
    );
    assert_eq!(
        steps[1].uses,
        Some(table.action("actions/cache/restore").unwrap())
    );
    assert_eq!(steps[1].with["path"], "~/.cache/pip");
    assert_eq!(
        steps[1].with["key"],
        "${{ runner.os }}-pip-dbt-core-1.12.6-sqlfluff-4.4.0"
    );
    assert_eq!(
        steps[2].run.as_deref(),
        Some(
            "python -m pip install dbt-core==1.12.6 sqlfluff==4.4.0 sqlfluff-templater-dbt==4.4.0"
        )
    );
    assert_eq!(steps[2].working_directory.as_deref(), Some("analytics/dbt"));
    assert_eq!(
        steps[3].uses,
        Some(table.action("actions/cache/save").unwrap())
    );
    assert_eq!(
        steps[3].condition.as_deref(),
        Some(DEFAULT_BRANCH_CONDITION)
    );
    let mut unseeded = device(StackId::SqlDbt, ".");
    unseeded.toolchain = false;
    let unseeded = (packs::pack(StackId::SqlDbt).ci_setup)(&unseeded, &table).unwrap();
    assert_eq!(
        unseeded[0].with["python-version"],
        table.tool("python").unwrap().version
    );
    assert!(!unseeded[0].with.contains_key("python-version-file"));
    assert_eq!(unseeded[2].working_directory, None);
}

#[test]
fn device_setup_installs_java_and_gradle_from_the_table_and_selects_xcode() {
    let table = pins();
    let android = (packs::pack(StackId::KotlinAndroid).ci_setup)(
        &device(StackId::KotlinAndroid, "apps/android"),
        &table,
    )
    .unwrap();
    assert_eq!(android.len(), 2);
    assert_eq!(
        android[0].uses,
        Some(table.action("actions/setup-java").unwrap())
    );
    assert_eq!(android[0].with["distribution"], "temurin");
    assert_eq!(
        android[0].with["java-version-file"],
        "apps/android/.java-version"
    );
    assert!(!android[0].with.contains_key("java-version"));
    assert_eq!(
        android[1].uses,
        Some(table.action("gradle/actions/setup-gradle").unwrap())
    );
    assert_eq!(
        android[1].with["cache-read-only"],
        format!("${{{{ !({DEFAULT_BRANCH_CONDITION}) }}}}")
    );
    assert_eq!(android[1].with["validate-wrappers"], "true");
    let mut unseeded = device(StackId::KotlinAndroid, ".");
    unseeded.toolchain = false;
    let unseeded = (packs::pack(StackId::KotlinAndroid).ci_setup)(&unseeded, &table).unwrap();
    assert_eq!(
        unseeded[0].with["java-version"],
        table.tool("java").unwrap().version
    );
    assert!(!unseeded[0].with.contains_key("java-version-file"));

    let ios =
        (packs::pack(StackId::SwiftIos).ci_setup)(&device(StackId::SwiftIos, "apps/ios"), &table)
            .unwrap();
    assert_eq!(ios.len(), 1);
    assert_eq!(ios[0].uses, None);
    assert_eq!(
        ios[0].run.as_deref(),
        Some(
            "sudo xcode-select -s \"/Applications/Xcode_$(cat .xcode-version).app\" && xcodebuild -version"
        )
    );
    assert_eq!(ios[0].working_directory.as_deref(), Some("apps/ios"));
    let mut unseeded = device(StackId::SwiftIos, ".");
    unseeded.toolchain = false;
    let unseeded = (packs::pack(StackId::SwiftIos).ci_setup)(&unseeded, &table).unwrap();
    assert_eq!(
        unseeded[0].run.as_deref(),
        Some(
            format!(
                "sudo xcode-select -s /Applications/Xcode_{}.app && xcodebuild -version",
                table.tool("xcode").unwrap().version
            )
            .as_str()
        )
    );
    assert_eq!(unseeded[0].working_directory, None);
}

/// The repository root, where `docs/agent-setup` and `templates` live.
fn repo_root() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
}

/// GitHub's heading anchors in `text`: lower-case, spaces to `-`, other
/// punctuation but `-` and `_` dropped.
fn anchors(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            line.trim_start_matches('#')
                .strip_prefix(' ')
                .filter(|_| line.starts_with('#'))
        })
        .map(|heading| {
            heading
                .to_lowercase()
                .chars()
                .filter_map(|c| match c {
                    ' ' => Some('-'),
                    c if c.is_alphanumeric() || c == '-' || c == '_' => Some(c),
                    _ => None,
                })
                .collect()
        })
        .collect()
}

#[test]
fn the_four_packs_carry_a_test_runner_profile_and_an_instrumentation_recipe() {
    for pack in packs::FIRST_WAVE {
        let otel = pack
            .otel
            .unwrap_or_else(|| panic!("{}: otel recipe", pack.id));
        assert!(!otel.packages.is_empty(), "{}: otel packages", pack.id);
        assert_eq!(
            otel.env,
            [
                "OTEL_SERVICE_NAME",
                "OTEL_EXPORTER_OTLP_ENDPOINT",
                "OTEL_RESOURCE_ATTRIBUTES"
            ],
            "{}: otel env",
            pack.id
        );
        // The guide is setup-core's (#1247): named with the feature only.
        let guide = format!("docs/agent-setup/observability.md#{}", pack.id);
        assert_eq!(
            otel.guide,
            cfg!(feature = "setup-core").then_some(guide.as_str()),
            "{}: guide",
            pack.id
        );
        if pack.id == StackId::Node {
            // The runner is per app: `NodeRunner::profile` after detection.
            assert_eq!(pack.test_runner, None);
            continue;
        }
        let profile = pack
            .test_runner
            .unwrap_or_else(|| panic!("{}: test runner", pack.id));
        assert!(!profile.one_test.is_empty(), "{}: one_test", pack.id);
        assert_eq!(
            profile.shard.is_some(),
            pack.id == StackId::Rust,
            "{}: shard only for rust (nextest)",
            pack.id
        );
    }
    for runner in NodeRunner::ALL {
        let profile = runner.profile();
        assert!(!profile.one_test.is_empty(), "{runner}: one_test");
        assert_eq!(profile.shard, None, "{runner}: shard");
    }
    let kinds: Vec<OtelKind> = packs::FIRST_WAVE
        .iter()
        .map(|p| p.otel.unwrap().kind)
        .collect();
    assert_eq!(
        kinds,
        [
            OtelKind::Sdk,
            OtelKind::ZeroCode,
            OtelKind::ZeroCode,
            OtelKind::Sdk
        ]
    );
    // Data pack: one test by dbt's node selection; the list through `dbt ls`.
    let dbt = packs::pack(StackId::SqlDbt).test_runner.unwrap();
    assert_eq!(dbt.one_test, "dbt test --select '{{name}}'");
    assert_eq!(dbt.list_tests, Some("dbt ls --resource-type test"));
    assert_eq!(dbt.shard, None);
    assert_eq!(packs::pack(StackId::SqlDbt).otel, None);
    assert_eq!(packs::pack(StackId::SqlDbt).coverage, None);
    // Device packs: one test by Gradle's `--tests` filter or xcodebuild's
    // `-only-testing`; no sharding, no instrumentation recipe (slice 3).
    let android = packs::pack(StackId::KotlinAndroid).test_runner.unwrap();
    assert_eq!(android.one_test, "./gradlew test --tests '{{name}}'");
    assert_eq!(android.shard, None);
    let ios = packs::pack(StackId::SwiftIos).test_runner.unwrap();
    assert_eq!(
        ios.one_test,
        "xcodebuild test -scheme {{scheme}} -only-testing '{{name}}'"
    );
    assert_eq!(
        ios.list_tests,
        Some("xcodebuild test -scheme {{scheme}} -enumerate-tests")
    );
    assert_eq!(ios.shard, None);
    for device in packs::DEVICES {
        assert_eq!(device.otel, None, "{}", device.id);
        assert_eq!(device.coverage, None, "{}", device.id);
    }
}

#[test]
fn the_profiles_match_the_spec() {
    let rust = packs::pack(StackId::Rust).test_runner.unwrap();
    assert_eq!(rust.one_test, "cargo test --locked {{name}} -- --exact");
    assert_eq!(
        rust.shard,
        Some("cargo nextest run --locked --partition count:{{i}}/{{n}}")
    );
    assert_eq!(rust.list_tests, Some("cargo test --locked -- --list"));
    let python = packs::pack(StackId::PythonUv).test_runner.unwrap();
    assert_eq!(python.one_test, "uv run --frozen pytest {{nodeid}}");
    assert_eq!(python.junit, Some("--junitxml={{out}}"));
    let go = packs::pack(StackId::Go).test_runner.unwrap();
    assert_eq!(go.one_test, "go test ./... -run '^{{name}}$'");
    assert_eq!(go.junit, None);
}

#[test]
#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "asserts setup-core's own content or id; product-boundary T7b"
)]
fn every_guide_anchor_exists_in_the_installed_guide_and_its_template() {
    for (file, guide_of) in [("observability.md", true), ("testing.md", false)] {
        for dir in ["docs/agent-setup", "templates"] {
            let text = fs::read_to_string(repo_root().join(dir).join(file)).unwrap();
            let found = anchors(&text);
            for pack in packs::FIRST_WAVE {
                let anchor = match (guide_of, pack.otel) {
                    (true, Some(otel)) => otel.guide.unwrap().split_once('#').unwrap().1.to_owned(),
                    _ => pack.id.to_string(),
                };
                assert!(
                    found.contains(&anchor),
                    "{dir}/{file}: no heading for #{anchor}"
                );
            }
        }
    }
}

/// A node app at the root with `package.json` and an npm lockfile.
fn node_repo(package_json: &str) -> tempfile::TempDir {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("package.json"), package_json).unwrap();
    fs::write(temp.path().join("package-lock.json"), "{}").unwrap();
    temp
}

#[test]
fn the_node_runner_comes_from_dev_dependencies_or_node_test() {
    let cases = [
        (
            r#"{"devDependencies": {"vitest": "^2.1.0"}}"#,
            Some(NodeRunner::Vitest),
        ),
        (
            r#"{"devDependencies": {"jest": "^29.7.0"}}"#,
            Some(NodeRunner::Jest),
        ),
        (
            r#"{"scripts": {"test": "node --test"}}"#,
            Some(NodeRunner::NodeTest),
        ),
        (
            r#"{"devDependencies": {"@playwright/test": "^1.48.0"}}"#,
            Some(NodeRunner::Playwright),
        ),
        // Unit before end-to-end; vitest before jest before node:test.
        (
            r#"{"devDependencies": {"@playwright/test": "1", "jest": "29", "vitest": "2"}}"#,
            Some(NodeRunner::Vitest),
        ),
        (
            r#"{"scripts": {"test": "node --test"}, "devDependencies": {"@playwright/test": "1", "jest": "29"}}"#,
            Some(NodeRunner::Jest),
        ),
        (
            r#"{"scripts": {"test": "node --test"}, "devDependencies": {"@playwright/test": "1"}}"#,
            Some(NodeRunner::NodeTest),
        ),
        // A runner named only under `dependencies` is not detected.
        (
            r#"{"dependencies": {"vitest": "2"}, "scripts": {"test": "mocha"}}"#,
            None,
        ),
        ("{}", None),
        ("{ not json", None),
    ];
    for (manifest, expected) in cases {
        let repo = node_repo(manifest);
        assert_eq!(
            detect::node_runner(repo.path(), ".").unwrap(),
            expected,
            "{manifest}"
        );
    }
    let profiles: Vec<&str> = [
        (r#"{"devDependencies": {"vitest": "2"}}"#),
        (r#"{"devDependencies": {"jest": "29"}}"#),
        (r#"{"scripts": {"test": "node --test"}}"#),
    ]
    .into_iter()
    .map(|manifest| {
        let repo = node_repo(manifest);
        detect::node_runner(repo.path(), ".")
            .unwrap()
            .unwrap()
            .profile()
            .one_test
    })
    .collect();
    assert_eq!(
        profiles,
        [
            "{{exec}} vitest run -t '{{name}}'",
            "{{exec}} jest -t '{{name}}'",
            "node --test --test-name-pattern='{{name}}'",
        ]
    );
}

#[test]
fn a_node_app_with_no_known_runner_gets_an_info_line_and_a_known_one_its_name() {
    let unknown = node_repo(r#"{"scripts": {"test": "mocha"}}"#);
    let block = detect::proposal_block(unknown.path()).unwrap();
    assert!(
        block.contains(
            "    info: no known test runner (vitest, jest, @playwright/test in devDependencies, or node --test in scripts.test); qa asks for it\n"
        ),
        "{block}"
    );
    let vitest = node_repo(r#"{"devDependencies": {"vitest": "2"}}"#);
    let block = detect::proposal_block(vitest.path()).unwrap();
    assert!(
        block.contains("    evidence: package.json (test runner: vitest), package-lock.json\n"),
        "{block}"
    );
    assert!(!block.contains("info:"), "{block}");
}

#[test]
fn the_package_manager_runs_a_node_runner_binary() {
    let execs: Vec<&str> = PackageManager::ALL.iter().map(|pm| pm.exec()).collect();
    assert_eq!(execs, ["npx", "pnpm exec", "yarn", "bunx"]);
}

#[test]
fn coverage_is_declared_for_rust_and_python_uv_only() {
    for id in StackId::ALL {
        assert_eq!(
            packs::pack(id).coverage.is_some(),
            matches!(id, StackId::Rust | StackId::PythonUv),
            "{id}: coverage"
        );
    }
}

#[test]
fn the_coverage_recipes_match_the_spec() {
    let table = pins();
    let python = packs::pack(StackId::PythonUv).coverage.unwrap();
    assert_eq!(python.tool, "coverage-py");
    assert_eq!(python.install, CoverageInstall::InCommand);
    assert_eq!(python.report, "coverage.json");
    assert_eq!(
        python.render_command(&table, None).unwrap(),
        "COVERAGE_CORE=sysmon uv run --frozen --all-extras --with coverage==7.17.0 --with pytest-cov==7.1.0 python -m pytest -q --cov --cov-report= \
         && uv run --frozen --all-extras --with coverage==7.17.0 coverage json -q -i -o coverage.json"
    );
    assert_eq!(python.install_step(&table).unwrap(), None);

    let rust = packs::pack(StackId::Rust).coverage.unwrap();
    assert_eq!(rust.tool, "cargo-llvm-cov");
    assert_eq!(
        rust.install,
        CoverageInstall::InstallAction("cargo-llvm-cov")
    );
    assert_eq!(rust.report, "coverage.json");
    assert_eq!(
        rust.render_command(&table, None).unwrap(),
        "cargo llvm-cov --locked --workspace --json --summary-only --output-path coverage.json"
    );
    let step = rust.install_step(&table).unwrap().unwrap();
    assert_eq!(step.name, "Install cargo-llvm-cov");
    assert_eq!(
        step.uses,
        Some(table.action("taiki-e/install-action").unwrap())
    );
    assert_eq!(step.with["tool"], "cargo-llvm-cov@0.9.1");
    assert_eq!(step.run, None);
}

#[test]
fn a_missing_coverage_pin_refuses_naming_it() {
    let mut table = pins();
    table.tools.remove("cargo-llvm-cov");
    let rust = packs::pack(StackId::Rust).coverage.unwrap();
    assert_eq!(
        rust.install_step(&table).unwrap_err().to_string(),
        "stack-packs: tool `cargo-llvm-cov` is not in templates/stack-packs/pins.json; add it with its version before rendering"
    );
    table.tools.remove("coverage-py");
    let python = packs::pack(StackId::PythonUv).coverage.unwrap();
    assert!(
        python
            .render_command(&table, None)
            .unwrap_err()
            .to_string()
            .contains("tool `coverage-py` is not in")
    );
}

/// The recipe's `metric` run with `jq` over `report`: the one number the
/// ratchet compares. Parsed, since jq releases print floats to different digits.
fn metric(stack: StackId, report: &str) -> f64 {
    let recipe = packs::pack(stack).coverage.unwrap();
    let output = Command::new("jq")
        .args(["-e", recipe.metric])
        .arg(report)
        .output()
        .expect("jq is on PATH");
    assert!(
        output.status.success(),
        "{stack}: jq failed on {report}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

fn assert_percent(measured: f64, covered: f64, total: f64) {
    let expected = covered * 100.0 / total;
    assert!(
        (measured - expected).abs() < 1e-9,
        "measured {measured}, expected {covered}/{total} = {expected}"
    );
}

fn recorded(name: &str) -> String {
    format!(
        "{}/tests/fixtures/stack-packs/coverage/{name}",
        env!("CARGO_MANIFEST_DIR")
    )
}

#[test]
fn the_metric_is_the_line_percentage_of_the_recorded_reports() {
    // cargo-llvm-cov 0.9.1: 6 of 11 lines (`data[0].totals.lines`).
    assert_percent(
        metric(StackId::Rust, &recorded("cargo-llvm-cov-0.9.1.json")),
        6.0,
        11.0,
    );
    // coverage.py 7.17.0: 6 of 9 statements.
    assert_percent(
        metric(StackId::PythonUv, &recorded("coverage-py-7.17.0.json")),
        6.0,
        9.0,
    );
    // With `branch = true`, `percent_covered` is 54.5 (branches mixed in);
    // the metric stays the line percentage.
    let branch = recorded("coverage-py-7.17.0-branch.json");
    let mixed = Command::new("jq")
        .args([
            "-r",
            r#""\(.meta.branch_coverage) \(.totals.percent_covered * 100 | round)""#,
        ])
        .arg(&branch)
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&mixed.stdout), "true 5455\n");
    assert_percent(metric(StackId::PythonUv, &branch), 6.0, 9.0);
}

#[test]
fn an_empty_python_measurement_is_zero_not_a_division_error() {
    let dir = tempfile::tempdir().unwrap();
    let report = dir.path().join("coverage.json");
    fs::write(
        &report,
        r#"{"totals": {"covered_lines": 0, "num_statements": 0, "percent_covered": 100.0}}"#,
    )
    .unwrap();
    assert_eq!(metric(StackId::PythonUv, report.to_str().unwrap()), 0.0);
}

#[test]
fn the_diff_reports_are_cobertura_for_python_uv_and_lcov_for_rust() {
    let table = pins();
    let python = packs::pack(StackId::PythonUv).coverage.unwrap();
    assert_eq!(python.diff_report, "coverage.xml");
    assert_eq!(
        python.render_diff_command(&table, None).unwrap(),
        "COVERAGE_CORE=sysmon uv run --frozen --all-extras --with coverage==7.17.0 --with pytest-cov==7.1.0 python -m pytest -q --cov --cov-report= \
         && uv run --frozen --all-extras --with coverage==7.17.0 coverage xml -q -i -o coverage.xml"
    );
    let rust = packs::pack(StackId::Rust).coverage.unwrap();
    assert_eq!(rust.diff_report, "lcov.info");
    assert_eq!(
        rust.render_diff_command(&table, None).unwrap(),
        "cargo llvm-cov --locked --workspace --lcov --output-path lcov.info"
    );
}

#[test]
fn an_answered_test_selection_replaces_the_pack_default() {
    // #1177: rust's `--workspace` gives way to the answer; python-uv appends it to pytest.
    let table = pins();
    let rust = packs::pack(StackId::Rust).coverage.unwrap();
    assert_eq!(rust.default_tests, "--workspace");
    assert_eq!(
        rust.render_diff_command(&table, Some("-p brakes")).unwrap(),
        "cargo llvm-cov --locked -p brakes --lcov --output-path lcov.info"
    );
    assert_eq!(
        rust.render_command(&table, Some("-p brakes")).unwrap(),
        "cargo llvm-cov --locked -p brakes --json --summary-only --output-path coverage.json"
    );
    let python = packs::pack(StackId::PythonUv).coverage.unwrap();
    assert_eq!(python.default_tests, "");
    assert_eq!(
        python
            .render_diff_command(&table, Some("tests/unit"))
            .unwrap(),
        "COVERAGE_CORE=sysmon uv run --frozen --all-extras --with coverage==7.17.0 --with pytest-cov==7.1.0 python -m pytest -q --cov --cov-report= tests/unit \
         && uv run --frozen --all-extras --with coverage==7.17.0 coverage xml -q -i -o coverage.xml"
    );
}

#[test]
fn the_combine_commands_merge_the_project_ci_parts() {
    // #1349: coverage_source project-ci; the project's own test jobs upload the data.
    let table = pins();
    let python = packs::pack(StackId::PythonUv).coverage.unwrap();
    assert_eq!(
        python
            .render_combine(&table, "/w/.coverage-parts/api")
            .unwrap(),
        "find /w/.coverage-parts/api -type f -name '.coverage*' -print0 | sort -z \
         | xargs -0 uv run --frozen --all-extras --with coverage==7.17.0 coverage combine --keep \
         && uv run --frozen --all-extras --with coverage==7.17.0 coverage xml -q -i -o coverage.xml"
    );
    let rust = packs::pack(StackId::Rust).coverage.unwrap();
    let merge = rust
        .render_combine(&table, "/w/.coverage-parts/root")
        .unwrap();
    assert!(
        merge
            .starts_with("# shellcheck disable=SC2016\nfind /w/.coverage-parts/root -type f -name '*.info' | sort | xargs awk "),
        "{merge}"
    );
    assert!(merge.ends_with("> lcov.info"), "{merge}");
}

#[test]
fn a_pin_placeholder_renders_every_occurrence_and_refuses_a_missing_key() {
    // #1342: `{{pin:<key>}}` names another tool's pinned version.
    let table = pins();
    let python = packs::pack(StackId::PythonUv).coverage.unwrap();
    let twice = CoverageRecipe {
        command: "a {{pin:pytest-cov}} b {{pin:diff-cover}} {{version}}",
        ..python
    };
    assert_eq!(
        twice.render_command(&table, None).unwrap(),
        "a 7.1.0 b 10.6.0 7.17.0"
    );
    let missing = CoverageRecipe {
        command: "uv run --with x=={{pin:absent-tool}} pytest",
        ..python
    };
    assert_eq!(
        missing
            .render_command(&table, None)
            .unwrap_err()
            .to_string(),
        "stack-packs: tool `absent-tool` is not in templates/stack-packs/pins.json; add it with its version before rendering"
    );
    // An unterminated placeholder is left as written, never a panic.
    let open = CoverageRecipe {
        command: "x {{pin:pytest-cov",
        ..python
    };
    assert_eq!(
        open.render_command(&table, None).unwrap(),
        "x {{pin:pytest-cov"
    );
}

#[test]
fn the_recorded_diff_reports_list_executed_lines_per_file() {
    // coverage.py 7.17.0 `coverage xml`: Cobertura, one <class> per measured
    // file with a hit count per line; diff-cover 10.6.0 read it (85 %).
    let xml = fs::read_to_string(recorded("coverage-py-7.17.0.xml")).unwrap();
    assert!(xml.contains(r#"<coverage version="7.17.0""#));
    assert!(xml.contains(r#"filename="src/sample/__init__.py""#));
    assert!(xml.contains(r#"<line number="2" hits="1"/>"#));
    assert!(xml.contains(r#"<line number="6" hits="0"/>"#));
    // cargo-llvm-cov 0.9.1 `--lcov`: SF per file, DA:<line>,<hits>;
    // diff-cover 10.6.0 read it (66 %, below 80, exit 1).
    let lcov = fs::read_to_string(recorded("cargo-llvm-cov-0.9.1.lcov")).unwrap();
    assert!(lcov.starts_with("SF:/work/sample/src/lib.rs\n"));
    assert!(lcov.lines().any(|l| l == "DA:22,1"));
    assert!(lcov.lines().any(|l| l == "DA:26,0"));
    assert!(lcov.trim_end().ends_with("end_of_record"));
}

#[test]
fn properties_are_declared_for_rust_and_python_uv_only() {
    for id in StackId::ALL {
        assert_eq!(
            packs::pack(id).properties.is_some(),
            matches!(id, StackId::Rust | StackId::PythonUv),
            "{id}: properties"
        );
    }
}

#[test]
fn the_rust_property_recipe_seeds_proptest_through_the_environment() {
    let rust = packs::pack(StackId::Rust).properties.unwrap();
    assert_eq!(
        rust.seed_env,
        &[
            ("PROPTEST_RNG_SEED", "{{seed}}"),
            ("PROPTEST_CASES", "{{examples}}")
        ]
    );
    assert_eq!(rust.seed_file, None);
    assert_eq!(
        rust.guide_command,
        "cargo test --locked --test heldout_properties"
    );
    assert!(rust.corpus.starts_with("proptest-regressions/"));
}

#[test]
fn the_python_property_recipe_seeds_a_heldout_hypothesis_profile() {
    let python = packs::pack(StackId::PythonUv).properties.unwrap();
    assert!(python.seed_env.is_empty());
    let seed = python.seed_file.unwrap();
    assert_eq!(seed.path, "{{heldout_dir}}/conftest.py");
    let template = seed.template;
    assert!(template.contains(
        r#"settings.register_profile(
    "heldout",
    parent=settings.get_profile("ci"),
    derandomize=False,
    max_examples=int(os.environ.get("HELDOUT_EXAMPLES", "200")),
)"#
    ));
    assert!(template.contains(r#"settings.load_profile("heldout")"#));
    assert_eq!(
        python.guide_command,
        r#"uv run --frozen pytest -q {{heldout_dir}}/properties --hypothesis-seed="$HELDOUT_SEED""#
    );
    assert!(python.corpus.contains("@reproduce_failure"));
}

#[test]
fn mutation_is_declared_for_rust_and_python_uv_only() {
    for id in StackId::ALL {
        assert_eq!(
            packs::pack(id).mutation.is_some(),
            matches!(id, StackId::Rust | StackId::PythonUv),
            "{id}: mutation"
        );
    }
}

#[test]
fn the_rust_mutation_recipe_runs_cargo_mutants_on_the_diff() {
    let table = pins();
    let rust = packs::pack(StackId::Rust).mutation.unwrap();
    assert_eq!(rust.tool, "cargo-mutants");
    assert_eq!(
        rust.install,
        CoverageInstall::InstallAction("cargo-mutants")
    );
    assert_eq!(rust.scope, MutationScope::Diff);
    assert_eq!(
        rust.render_command(&table).unwrap(),
        "cargo mutants --no-shuffle --in-diff git.diff"
    );
    assert_eq!(rust.render_stats(&table).unwrap(), None);
    assert_eq!(rust.results, "mutants.out");
    let step = rust.install_step(&table).unwrap().unwrap();
    assert_eq!(step.name, "Install cargo-mutants");
    assert_eq!(
        step.uses,
        Some(table.action("taiki-e/install-action").unwrap())
    );
    assert_eq!(step.with["tool"], "cargo-mutants@27.1.0");
}

#[test]
fn the_python_mutation_recipe_runs_mutmut_per_changed_file() {
    let table = pins();
    let python = packs::pack(StackId::PythonUv).mutation.unwrap();
    assert_eq!(python.tool, "mutmut");
    assert_eq!(python.install, CoverageInstall::InCommand);
    assert_eq!(python.scope, MutationScope::ChangedFiles);
    assert_eq!(
        python.render_command(&table).unwrap(),
        r#"uv run --frozen --all-extras --with mutmut==3.8.1 mutmut run "{{module}}*""#
    );
    assert_eq!(
        python.render_stats(&table).unwrap().as_deref(),
        Some("uv run --frozen --all-extras --with mutmut==3.8.1 mutmut export-cicd-stats")
    );
    assert_eq!(python.results, "mutants/mutmut-cicd-stats.json");
    assert_eq!(python.install_step(&table).unwrap(), None);
}

#[test]
fn a_missing_mutation_pin_refuses_naming_it() {
    let mut table = pins();
    table.tools.remove("cargo-mutants");
    table.tools.remove("mutmut");
    let rust = packs::pack(StackId::Rust).mutation.unwrap();
    assert_eq!(
        rust.install_step(&table).unwrap_err().to_string(),
        "stack-packs: tool `cargo-mutants` is not in templates/stack-packs/pins.json; add it with its version before rendering"
    );
    let python = packs::pack(StackId::PythonUv).mutation.unwrap();
    assert!(
        python
            .render_command(&table)
            .unwrap_err()
            .to_string()
            .contains("tool `mutmut` is not in")
    );
}

fn recorded_mutation(name: &str) -> String {
    format!(
        "{}/tests/fixtures/stack-packs/mutation/{name}",
        env!("CARGO_MANIFEST_DIR")
    )
}

#[test]
fn the_recorded_mutation_results_carry_the_counts_the_recipe_names() {
    // cargo-mutants 27.1.0 `--in-diff`: one line per mutant in each outcome
    // file under `results`; 4 caught, 6 missed (exit 2).
    let dir = recorded_mutation("cargo-mutants-27.1.0");
    let count = |file: &str| {
        fs::read_to_string(Path::new(&dir).join(file))
            .unwrap()
            .lines()
            .count()
    };
    assert_eq!(
        [
            count("caught.txt"),
            count("missed.txt"),
            count("timeout.txt"),
            count("unviable.txt")
        ],
        [4, 6, 0, 0]
    );
    // mutmut 3.8.1 `export-cicd-stats`: the file `results` names.
    let python = packs::pack(StackId::PythonUv).mutation.unwrap();
    assert!(python.results.ends_with("mutmut-cicd-stats.json"));
    let stats: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(recorded_mutation("mutmut-3.8.1-cicd-stats.json")).unwrap(),
    )
    .unwrap();
    for (key, value) in [
        ("killed", 5),
        ("survived", 3),
        ("total", 8),
        ("skipped", 0),
        ("timeout", 0),
    ] {
        assert_eq!(stats[key], value, "{key}");
    }
}

/// The rustup components a command needs: `cargo clippy` needs `clippy` and
/// `cargo fmt` needs `rustfmt`, which a `minimal` profile leaves out (the pinned
/// dtolnay/rust-toolchain installs `--profile minimal` plus its `components`).
fn components_needed(command: &str) -> Vec<&'static str> {
    [("cargo clippy", "clippy"), ("cargo fmt", "rustfmt")]
        .into_iter()
        .filter(|(tool, _)| command.contains(tool))
        .map(|(_, component)| component)
        .collect()
}

#[test]
fn every_component_a_proposed_or_declared_command_uses_is_installed() {
    // #1108: `checks` ran `cargo clippy` on a toolchain installed without clippy.
    let table = pins();
    for (name, app) in cases().into_iter().chain([(
        "rust-fmt-declared",
        declared(app(StackId::Rust, "."), &[("lint", "cargo fmt --check")]),
    )]) {
        let pack = packs::pack(app.stack);
        let proposed = [
            pack.proposed.build,
            pack.proposed.test,
            pack.proposed.lint,
            pack.proposed.verify,
        ];
        let commands: Vec<&str> = proposed
            .into_iter()
            .flatten()
            .chain(app.declared.values().map(String::as_str))
            .collect();
        let steps = (pack.ci_setup)(&app, &table).unwrap();
        let installed: Vec<&str> = steps
            .iter()
            .filter_map(|s| s.with.get("components"))
            .flat_map(|c| c.split(',').map(str::trim))
            .collect();
        let seed = pack.toolchain_seed.map_or("", |s| s.template);
        for component in commands.iter().flat_map(|c| components_needed(c)) {
            assert!(
                installed.contains(&component),
                "{name}: ci_setup does not install {component}: {steps:?}"
            );
            assert!(
                seed.contains(&format!("\"{component}\"")),
                "{name}: the toolchain seed does not declare {component}"
            );
        }
    }
}
