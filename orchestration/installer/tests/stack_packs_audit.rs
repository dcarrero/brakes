//! stack-packs T8 (#763; SPEC-stack-packs.md, "Auditor rules declared by this
//! module" and "How `doctor` reports the static rules"): the static `stack.*`
//! rules over the recorded apps, their files and their Dockerfiles, and the
//! pin-table staleness from a fixed clock. Every finding is a `doctor`
//! warning; nothing here reads the network.
use brakes::engine::Rendered;
use brakes::modules::stack_packs::{
    App, AppAnswers, BaseImageFamily, PIN_VERIFICATION_DAYS, PinTable, StackId, audit, container,
};
use chrono::{Days, NaiveDate};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, path::Path};
use tempfile::TempDir;

const DIGEST: &str = "sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab";

fn day(text: &str) -> NaiveDate {
    NaiveDate::parse_from_str(text, "%Y-%m-%d").unwrap()
}

/// A checkout with `files` (repository path → text) and nothing else.
fn repo(files: &[(&str, &str)]) -> TempDir {
    let dir = TempDir::new().unwrap();
    for (path, text) in files {
        let path = dir.path().join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
    dir
}

/// The recorded stack-packs answers file for `answers`.
fn answers(answers: Value) -> String {
    json!({"module": "stack-packs", "version": "1.0.0", "answers": answers}).to_string()
}

/// The `stack.*` findings of the checkout, pin staleness excluded (a fresh clock).
fn findings(dir: &TempDir) -> Vec<String> {
    let fresh = PinTable::embedded().unwrap().last_verified;
    audit::diagnose(dir.path(), fresh).unwrap()
}

/// A root `rust` app `api`, plus `files`.
fn rust_root(files: &[(&str, &str)]) -> TempDir {
    let recorded = answers(json!({"apps.api.path": ".", "apps.api.stack": "rust"}));
    let mut all = vec![
        (".agent-setup/modules/stack-packs.json", recorded.as_str()),
        ("Cargo.toml", "[package]\nname = \"api\"\n"),
    ];
    all.extend_from_slice(files);
    repo(&all)
}

/// This repository's own profile with `commands` replaced: a valid root profile.
fn profile(commands: Value) -> String {
    let own = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.agent-setup/project.json");
    let mut profile: Value = serde_json::from_str(&fs::read_to_string(own).unwrap()).unwrap();
    profile["commands"] = commands;
    profile.to_string()
}

const LOCK_AND_PIN: [(&str, &str); 2] = [
    ("Cargo.lock", "version = 4\n"),
    ("rust-toolchain.toml", "[toolchain]\nchannel = \"1.99\"\n"),
];

#[test]
fn a_repository_without_answers_has_no_app_finding() {
    let dir = repo(&[("Cargo.toml", "[package]\n")]);
    assert_eq!(findings(&dir), Vec::<String>::new());
}

#[test]
fn lockfile_present_reports_an_app_without_its_lockfile() {
    let dir = rust_root(&[("rust-toolchain.toml", "")]);
    assert_eq!(
        findings(&dir),
        ["WARNING: stack.lockfile-present: app `api` (rust at .) has no Cargo.lock"]
    );
    let dir = rust_root(&LOCK_AND_PIN);
    assert_eq!(findings(&dir), Vec::<String>::new());
}

#[test]
fn lockfile_present_names_every_node_lockfile_under_the_app_path() {
    let recorded = answers(
        json!({"apps.web.path": "apps/web", "apps.web.stack": "node",
        "apps.web.container": false}),
    );
    let dir = repo(&[
        (".agent-setup/modules/stack-packs.json", &recorded),
        ("apps/web/package.json", "{}"),
        ("apps/web/.nvmrc", "24\n"),
    ]);
    assert_eq!(
        findings(&dir),
        [
            "WARNING: stack.lockfile-present: app `web` (node at apps/web) has no package-lock.json, pnpm-lock.yaml, yarn.lock or bun.lock"
        ]
    );
    fs::write(dir.path().join("apps/web/pnpm-lock.yaml"), "").unwrap();
    assert_eq!(findings(&dir), Vec::<String>::new());
}

#[test]
fn lockfile_not_enforced_reports_a_declared_command_without_the_strict_flag() {
    let profile = profile(json!({"test": "cargo test --workspace", "verify": null}));
    let mut files = LOCK_AND_PIN.to_vec();
    files.push((".agent-setup/project.json", &profile));
    let dir = rust_root(&files);
    assert_eq!(
        findings(&dir),
        [
            "WARNING: stack.lockfile-not-enforced: app `api` declares test `cargo test --workspace` without `--locked`"
        ]
    );
}

#[test]
fn lockfile_not_enforced_is_silent_with_the_flag_or_a_script() {
    let profile = profile(json!({
        "test": "cargo test --workspace --locked",
        "verify": "bash scripts/verify.sh",
    }));
    let mut files = LOCK_AND_PIN.to_vec();
    files.push((".agent-setup/project.json", &profile));
    let dir = rust_root(&files);
    assert_eq!(findings(&dir), Vec::<String>::new());
}

#[test]
fn lockfile_not_enforced_reads_the_per_app_profile_and_the_package_manager() {
    let recorded = answers(json!({"apps.web.path": "web", "apps.web.stack": "node",
        "apps.web.container": false}));
    let profile = json!({"commands": {"test": "pnpm install && pnpm test"}}).to_string();
    let dir = repo(&[
        (".agent-setup/modules/stack-packs.json", &recorded),
        ("web/package.json", "{}"),
        ("web/pnpm-lock.yaml", ""),
        ("web/.nvmrc", "24\n"),
        ("web/.agent-setup/project.json", &profile),
    ]);
    assert_eq!(
        findings(&dir),
        [
            "WARNING: stack.lockfile-not-enforced: app `web` declares test `pnpm install && pnpm test` without `--frozen-lockfile`"
        ]
    );
    let strict = json!({"commands": {"test": "pnpm install --frozen-lockfile && pnpm test"}});
    fs::write(
        dir.path().join("web/.agent-setup/project.json"),
        strict.to_string(),
    )
    .unwrap();
    assert_eq!(findings(&dir), Vec::<String>::new());
}

#[test]
fn toolchain_pinned_reports_an_app_without_a_pin_file() {
    let dir = rust_root(&[("Cargo.lock", "")]);
    assert_eq!(
        findings(&dir),
        [
            "WARNING: stack.toolchain-pinned: app `api` (rust at .) has no toolchain pin (rust-toolchain.toml)"
        ]
    );
}

#[test]
fn toolchain_pinned_accepts_a_go_mod_toolchain_line() {
    let recorded = answers(json!({"apps.svc.path": "svc", "apps.svc.stack": "go",
        "apps.svc.container": false}));
    let dir = repo(&[
        (".agent-setup/modules/stack-packs.json", &recorded),
        ("svc/go.mod", "module example.com/svc\n\ngo 1.25\n"),
        ("svc/go.sum", ""),
    ]);
    assert_eq!(
        findings(&dir),
        [
            "WARNING: stack.toolchain-pinned: app `svc` (go at svc) has no toolchain pin (go.mod toolchain)"
        ]
    );
    fs::write(
        dir.path().join("svc/go.mod"),
        "module example.com/svc\n\ngo 1.25\n\ntoolchain go1.25.3\n",
    )
    .unwrap();
    assert_eq!(findings(&dir), Vec::<String>::new());
}

#[test]
fn toolchain_pinned_reads_the_device_pins() {
    let recorded = answers(json!({
        "apps.ios.path": "ios", "apps.ios.stack": "swift-ios",
        "apps.android.path": "android", "apps.android.stack": "kotlin-android",
    }));
    let dir = repo(&[
        (".agent-setup/modules/stack-packs.json", &recorded),
        ("ios/Package.swift", ""),
        ("android/settings.gradle.kts", ""),
        ("android/gradlew", ""),
    ]);
    assert_eq!(
        findings(&dir),
        [
            "WARNING: stack.toolchain-pinned: app `android` (kotlin-android at android) has no toolchain pin (.java-version, distributionSha256Sum in gradle/wrapper/gradle-wrapper.properties)",
            "WARNING: stack.toolchain-pinned: app `ios` (swift-ios at ios) has no toolchain pin (.xcode-version)",
        ]
    );
    fs::write(dir.path().join("android/.java-version"), "17\n").unwrap();
    fs::create_dir_all(dir.path().join("android/gradle/wrapper")).unwrap();
    let wrapper = dir
        .path()
        .join("android/gradle/wrapper/gradle-wrapper.properties");
    fs::write(
        &wrapper,
        "distributionUrl=https\\://services.gradle.org/distributions/gradle-9.6.0-bin.zip\n",
    )
    .unwrap();
    fs::write(dir.path().join("ios/.xcode-version"), "27.1\n").unwrap();
    assert_eq!(
        findings(&dir),
        [
            "WARNING: stack.toolchain-pinned: app `android` (kotlin-android at android) has no toolchain pin (distributionSha256Sum in gradle/wrapper/gradle-wrapper.properties)",
        ]
    );
    fs::write(
        &wrapper,
        "distributionUrl=https\\://services.gradle.org/distributions/gradle-9.6.0-bin.zip\ndistributionSha256Sum=0000000000000000000000000000000000000000000000000000000000000000\n",
    )
    .unwrap();
    assert_eq!(findings(&dir), Vec::<String>::new());
}

#[test]
fn toolchain_pinned_reads_the_dbt_python_pin() {
    let recorded = answers(json!({"apps.dbt.path": "dbt", "apps.dbt.stack": "sql-dbt"}));
    let dir = repo(&[
        (".agent-setup/modules/stack-packs.json", &recorded),
        ("dbt/dbt_project.yml", "name: x\n"),
    ]);
    assert_eq!(
        findings(&dir),
        [
            "WARNING: stack.toolchain-pinned: app `dbt` (sql-dbt at dbt) has no toolchain pin (.python-version)"
        ]
    );
    fs::write(dir.path().join("dbt/.python-version"), "3.13\n").unwrap();
    assert_eq!(findings(&dir), Vec::<String>::new());
}

/// A Dockerfile that passes every image rule.
fn clean_dockerfile() -> String {
    format!(
        "FROM docker.io/library/rust:1.99@{DIGEST} AS build\n\
         COPY . .\n\
         FROM build AS test\n\
         FROM gcr.io/distroless/cc-debian12:nonroot@{DIGEST}\n\
         COPY --from=build --chown=0:0 --chmod=0775 /out/api /app/api\n\
         USER 10001:0\n"
    )
}

#[test]
fn image_rules_are_silent_on_a_pinned_nonroot_group_zero_image() {
    assert_eq!(
        audit::dockerfile("Dockerfile", &clean_dockerfile()),
        Vec::<String>::new()
    );
}

#[test]
fn image_by_digest_reports_a_tag_without_digest_and_latest() {
    let text = format!(
        "FROM --platform=$BUILDPLATFORM rust:1.99 AS build\n\
         FROM gcr.io/distroless/cc:latest@{DIGEST}\n\
         USER 10001:0\n"
    );
    assert_eq!(
        audit::dockerfile("apps/api/Dockerfile", &text),
        [
            "WARNING: stack.image-by-digest: apps/api/Dockerfile FROM rust:1.99 has no @sha256: digest",
            &format!(
                "WARNING: stack.image-by-digest: apps/api/Dockerfile FROM gcr.io/distroless/cc:latest@{DIGEST} uses latest"
            ),
        ]
    );
}

#[test]
fn image_nonroot_reports_a_final_stage_without_user_or_as_root() {
    let base = format!("FROM gcr.io/distroless/static@{DIGEST}\n");
    assert_eq!(
        audit::dockerfile("Dockerfile", &base),
        ["WARNING: stack.image-nonroot: Dockerfile final stage has no USER"]
    );
    for user in ["root", "0", "0:0", "root:root"] {
        assert_eq!(
            audit::dockerfile("Dockerfile", &format!("{base}USER {user}\n")),
            [format!(
                "WARNING: stack.image-nonroot: Dockerfile final stage runs as root (USER {user})"
            )]
        );
    }
    // A USER of an earlier stage does not carry into the final one.
    let earlier = format!("FROM rust@{DIGEST} AS build\nUSER 10001\n{base}");
    assert_eq!(
        audit::dockerfile("Dockerfile", &earlier),
        ["WARNING: stack.image-nonroot: Dockerfile final stage has no USER"]
    );
}

#[test]
fn image_arbitrary_uid_reports_a_named_user_and_a_copy_outside_group_zero() {
    let text = format!(
        "FROM gcr.io/distroless/static@{DIGEST}\n\
         COPY --chown=10001:10001 app /app/app\n\
         ADD config.toml /app/\n\
         COPY --chown=0:root data /data\n\
         USER nonroot\n"
    );
    assert_eq!(
        audit::dockerfile("Dockerfile", &text),
        [
            "WARNING: stack.image-arbitrary-uid: Dockerfile final stage runs as named user `nonroot`, which needs /etc/passwd; use a numeric UID in group 0",
            "WARNING: stack.image-arbitrary-uid: Dockerfile final stage copies without group 0 ownership: COPY --chown=10001:10001 app /app/app",
            "WARNING: stack.image-arbitrary-uid: Dockerfile final stage copies without group 0 ownership: ADD config.toml /app/",
        ]
    );
}

#[test]
fn dockerfile_instructions_join_continuations_and_skip_comments() {
    let text = format!(
        "# FROM ubuntu\nfrom \\\n  gcr.io/distroless/static@{DIGEST}\ncopy --chown=0:0 \\\n  a /a\nuser 10001:0\n"
    );
    assert_eq!(audit::dockerfile("Dockerfile", &text), Vec::<String>::new());
}

#[test]
fn image_rules_read_every_dockerfile_under_an_app_path_once() {
    let recorded = answers(json!({
        "apps.api.path": ".", "apps.api.stack": "rust", "apps.api.container": false,
        "apps.web.path": "web", "apps.web.stack": "node", "apps.web.container": false,
    }));
    let unpinned = "FROM node:24\nUSER 10001:0\n";
    let dir = repo(&[
        (".agent-setup/modules/stack-packs.json", &recorded),
        ("Cargo.toml", ""),
        ("Cargo.lock", ""),
        ("rust-toolchain.toml", ""),
        ("web/package.json", "{}"),
        ("web/package-lock.json", "{}"),
        ("web/.nvmrc", "24\n"),
        ("web/Dockerfile", unpinned),
        ("web/deploy/worker.Dockerfile", unpinned),
        ("web/node_modules/pkg/Dockerfile", unpinned),
        ("README.md", "FROM node:24\n"),
    ]);
    assert_eq!(
        findings(&dir),
        [
            "WARNING: stack.image-by-digest: web/Dockerfile FROM node:24 has no @sha256: digest",
            "WARNING: stack.image-by-digest: web/deploy/worker.Dockerfile FROM node:24 has no @sha256: digest",
        ]
    );
}

/// #16: a Dockerfile at or under a path the profile declares in
/// `excluded_paths` is not the project's: no image rule reads it, and a real
/// Dockerfile at the root is still judged.
#[test]
fn image_rules_skip_the_profiles_excluded_paths() {
    let profile = json!({
        "purpose": "p",
        "commands": {"verify": "cargo test --locked"},
        "excluded_paths": ["templates", "tests/fixtures/svc/"],
    })
    .to_string();
    let unpinned = "FROM node:24\nUSER 10001:0\n";
    let mut files = vec![
        (".agent-setup/project.json", profile.as_str()),
        ("templates/go/Dockerfile", "FROM {{image.build}}\n"),
        ("templates/pins/Dockerfile", "FROM scratch\n"),
        ("tests/fixtures/svc/Dockerfile", unpinned),
    ];
    files.extend_from_slice(&LOCK_AND_PIN);
    assert_eq!(findings(&rust_root(&files)), Vec::<String>::new());
    files.push(("Dockerfile", unpinned));
    files.push(("templates.d/Dockerfile", unpinned));
    assert_eq!(
        findings(&rust_root(&files)),
        [
            "WARNING: stack.image-by-digest: Dockerfile FROM node:24 has no @sha256: digest",
            "WARNING: stack.image-by-digest: templates.d/Dockerfile FROM node:24 has no @sha256: digest",
        ]
    );
}

#[test]
fn no_healthcheck_reports_a_container_app_with_healthcheck_none() {
    let recorded = answers(json!({"apps.api.path": ".", "apps.api.stack": "rust",
        "apps.api.healthcheck": "none"}));
    let mut files = LOCK_AND_PIN.to_vec();
    files.push((".agent-setup/modules/stack-packs.json", &recorded));
    files.push(("Cargo.toml", ""));
    let dir = repo(&files);
    assert_eq!(
        findings(&dir),
        [
            "WARNING: stack.no-healthcheck: app `api` sets healthcheck none; its container has no HEALTHCHECK"
        ]
    );
}

/// The Dockerfile the module seeds for a container app of `stack`.
fn seeded(stack: StackId) -> String {
    let app = AppAnswers {
        app: App {
            id: "api".to_owned(),
            path: ".".to_owned(),
            stack,
            container: true,
            toolchain: true,
            package_manager: (stack == StackId::Node)
                .then_some(brakes::modules::stack_packs::PackageManager::Npm),
            declared: BTreeMap::new(),
        },
        port: Some(8080),
        healthcheck: Some("default".to_owned()),
        bin: matches!(stack, StackId::Rust | StackId::Go).then(|| "api".to_owned()),
        force: false,
        toolchain_version: None,
    };
    let pins = PinTable::embedded().unwrap();
    let rendered: Vec<Rendered> =
        container::seeds(&app, BaseImageFamily::Distroless, &pins, &[]).unwrap();
    rendered
        .into_iter()
        .find(|r| r.path == "Dockerfile")
        .and_then(|r| r.content)
        .unwrap()
}

#[test]
fn the_seeded_dockerfiles_pass_every_image_rule() {
    for stack in [StackId::Rust, StackId::PythonUv, StackId::Node, StackId::Go] {
        assert_eq!(
            audit::dockerfile("Dockerfile", &seeded(stack)),
            Vec::<String>::new(),
            "{stack}"
        );
    }
}

const TABLE: &str = r#"{"last_verified": "2026-10-01", "actions": {}, "images": {}, "tools": {}}"#;

#[test]
fn pin_table_stale_uses_the_given_clock_29_days_silent_31_reported() {
    let dir = repo(&[("templates/stack-packs/pins.json", TABLE)]);
    let verified = day("2026-10-01");
    let at = |days| verified + Days::new(days);
    assert_eq!(
        audit::pin_table_stale(dir.path(), at(29), PIN_VERIFICATION_DAYS),
        None
    );
    assert_eq!(
        audit::pin_table_stale(dir.path(), at(30), PIN_VERIFICATION_DAYS),
        None
    );
    assert_eq!(
        audit::pin_table_stale(dir.path(), at(31), PIN_VERIFICATION_DAYS).as_deref(),
        Some(
            "WARNING: stack.pin-table-stale: pin table last verified 2026-10-01, 31 days ago (limit 30)"
        )
    );
}

#[test]
fn pin_table_stale_reads_the_embedded_table_outside_this_repository() {
    let dir = repo(&[]);
    let embedded = PinTable::embedded().unwrap().last_verified;
    assert_eq!(
        audit::pin_table_stale(dir.path(), embedded + Days::new(29), 30),
        None
    );
    assert_eq!(
        audit::pin_table_stale(dir.path(), embedded + Days::new(31), 30),
        Some(format!(
            "WARNING: stack.pin-table-stale: pin table last verified {embedded}, 31 days ago (limit 30)"
        ))
    );
}

#[test]
fn a_table_without_last_verified_refuses_to_load() {
    let missing = r#"{"actions": {}, "images": {}, "tools": {}}"#;
    let error = PinTable::parse(missing).unwrap_err().to_string();
    assert!(error.contains("last_verified"), "{error}");
    let dir = repo(&[("templates/stack-packs/pins.json", missing)]);
    let finding = audit::pin_table_stale(dir.path(), day("2026-11-01"), 30).unwrap();
    assert!(
        finding.starts_with(
            "WARNING: stack.pin-table-stale: unverified: templates/stack-packs/pins.json: "
        ),
        "{finding}"
    );
}

#[test]
fn doctor_reports_the_stack_findings_as_warnings() {
    let dir = rust_root(&[("Cargo.lock", "")]);
    let late = PinTable::embedded().unwrap().last_verified + Days::new(31);
    let findings = brakes::doctor_at(dir.path(), late).unwrap();
    let stack: Vec<&String> = findings
        .iter()
        .filter(|f| f.contains("stack.") && !f.contains("stack.unconfigured"))
        .collect();
    assert_eq!(stack.len(), 2, "{findings:#?}");
    assert!(stack.iter().all(|f| f.starts_with("WARNING: stack.")));
    assert!(stack[0].contains("stack.toolchain-pinned"));
    assert!(stack[1].contains("stack.pin-table-stale"));
}

/// #1163: the node pack's own accepted proposal (`npm test`, `npm run build`)
/// passes its own Basic rule; the strict flag belongs to the install `ci_setup`
/// runs (`npm ci`), so only a declared install without it reports.
#[test]
fn a_node_app_that_accepted_the_packs_proposal_passes_lockfile_not_enforced() {
    let recorded = answers(json!({"apps.web.path": "web", "apps.web.stack": "node",
        "apps.web.container": false}));
    let manifest = json!({"scripts": {"test": "vitest run", "build": "vite build"}}).to_string();
    let dir = repo(&[
        (".agent-setup/modules/stack-packs.json", &recorded),
        ("web/package.json", &manifest),
        ("web/package-lock.json", "{}"),
        ("web/.nvmrc", "22\n"),
    ]);
    let accepted =
        brakes::modules::stack_packs::detect::accept_commands(dir.path(), Some("web")).unwrap();
    fs::create_dir_all(dir.path().join("web/.agent-setup")).unwrap();
    fs::write(dir.path().join(&accepted.path), &accepted.after).unwrap();
    assert!(
        accepted.after.contains("\"test\": \"npm test\""),
        "{}",
        accepted.after
    );
    assert_eq!(findings(&dir), Vec::<String>::new());
}

#[test]
fn a_node_install_without_its_strict_flag_still_reports() {
    let recorded = answers(json!({"apps.web.path": "web", "apps.web.stack": "node",
        "apps.web.container": false}));
    let cases = [
        ("npm install && npm test", Some("ci")),
        ("npm i && npm test", Some("ci")),
        ("npm ci && npm test", None),
        ("npm run build && npm test", None),
    ];
    for (command, flag) in cases {
        let profile = json!({"commands": {"test": command}}).to_string();
        let dir = repo(&[
            (".agent-setup/modules/stack-packs.json", &recorded),
            ("web/package.json", "{}"),
            ("web/package-lock.json", "{}"),
            ("web/.nvmrc", "22\n"),
            ("web/.agent-setup/project.json", &profile),
        ]);
        let expected: Vec<String> = flag
            .map(|flag| {
                format!(
                    "WARNING: stack.lockfile-not-enforced: app `web` declares test `{command}` without `{flag}`"
                )
            })
            .into_iter()
            .collect();
        assert_eq!(findings(&dir), expected, "{command}");
    }
}
