//! The packs, one `const StackPack` per stack, and the pure helpers they share.
//! Every pack is filled: the four first-wave packs, the two device packs and
//! the data pack.
use crate::{Result, refuse};
use std::collections::BTreeMap;

use super::{
    App, ContainerSupport, DEFAULT_BRANCH_CONDITION, PackageManager, PinTable, ProposedCommands,
    StackId, StackPack, Step,
};

pub mod go;
pub mod kotlin_android;
pub mod node;
pub mod python_uv;
pub mod rust;
pub mod sql_dbt;
pub mod swift_ios;

/// The variables every instrumentation recipe reads (SPEC-stack-packs.md,
/// Instrumentation recipe); the OpenTelemetry SDKs read them by these names.
pub const OTEL_ENV: &[&str] = &[
    "OTEL_SERVICE_NAME",
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "OTEL_RESOURCE_ATTRIBUTES",
];

/// Every pack, in `StackId` order.
pub const ALL: [&StackPack; 7] = [
    &rust::RUST,
    &python_uv::PYTHON_UV,
    &node::NODE,
    &go::GO,
    &kotlin_android::KOTLIN_ANDROID,
    &swift_ios::SWIFT_IOS,
    &sql_dbt::SQL_DBT,
];

/// The packs filled by 7 November: evidence, proposals, lockfile, `ci_setup`.
pub const FIRST_WAVE: [&StackPack; 4] = [&rust::RUST, &python_uv::PYTHON_UV, &node::NODE, &go::GO];

/// The device packs (slice 3, #768): no container, a toolchain seed, setup
/// steps; `swift-ios` is the macOS target.
pub const DEVICES: [&StackPack; 2] = [&kotlin_android::KOTLIN_ANDROID, &swift_ios::SWIFT_IOS];

pub fn pack(id: StackId) -> &'static StackPack {
    ALL.iter()
        .copied()
        .find(|pack| pack.id == id)
        .expect("every StackId has a pack")
}

/// `container: true` on a pack that builds no image refuses.
pub fn check_container(app: &App, pack: &StackPack) -> Result<()> {
    if app.container && pack.container == ContainerSupport::NotApplicable {
        return refuse(format!(
            "stack-packs: app `{}` declares container: true but stack `{}` builds no container image",
            app.id, pack.id
        ));
    }
    Ok(())
}

/// The pack's proposals for `app`, composed: `{{pm}}` is the package manager,
/// `{{wd}}` the app path, `{{lint}}` and `{{test}}` the resolved siblings.
/// Only commands the pack proposes appear; a declared command is never
/// proposed over (detection applies that rule with the profile in hand).
pub fn proposals(pack: &StackPack, app: &App) -> BTreeMap<&'static str, String> {
    proposals_from(&pack.proposed, app)
}

/// `proposals` over any command set: a pack's, or `swift_ios::SWIFTPM` for a
/// Swift package without an Xcode project.
pub fn proposals_from(proposed: &ProposedCommands, app: &App) -> BTreeMap<&'static str, String> {
    let pm = app.package_manager.unwrap_or(PackageManager::Npm).as_str();
    let fill = |template: &str| template.replace("{{pm}}", pm).replace("{{wd}}", &app.path);
    let build = proposed.build.map(fill);
    let test = proposed.test.map(fill);
    let lint = proposed.lint.map(fill);
    let verify = proposed.verify.map(|template| {
        let template = match &lint {
            Some(_) => template.to_owned(),
            None => template.replace("{{lint}} && ", ""),
        };
        fill(&template)
            .replace("{{lint}}", lint.as_deref().unwrap_or(""))
            .replace("{{test}}", test.as_deref().unwrap_or(""))
    });
    [
        ("build", build),
        ("test", test),
        ("lint", lint),
        ("verify", verify),
    ]
    .into_iter()
    .filter_map(|(name, command)| command.map(|c| (name, c)))
    .collect()
}

/// `actions/cache/restore` and `actions/cache/save` on the same path and key;
/// the save carries the default-branch condition (SPEC-ci-baseline.md).
pub(crate) fn cache_pair(
    pins: &PinTable,
    what: &str,
    path: &str,
    key: &str,
) -> Result<(Step, Step)> {
    let restore = Step::new(format!("Restore {what}"))
        .uses(pins.action("actions/cache/restore")?)
        .with("path", path)
        .with("key", key);
    let save = Step::new(format!("Save {what}"))
        .uses(pins.action("actions/cache/save")?)
        .with("path", path)
        .with("key", key)
        .only_on_default_branch();
    Ok((restore, save))
}

/// `${{ runner.os }}-<tool>-${{ hashFiles('<prefix><file>') }}`.
pub(crate) fn cache_key(tool: &str, app: &App, file: &str) -> String {
    format!(
        "${{{{ runner.os }}}}-{tool}-${{{{ hashFiles('{}{file}') }}}}",
        app.prefix()
    )
}

/// The `save-if` value for actions that gate their own save.
pub(crate) fn save_if() -> String {
    format!("${{{{ {DEFAULT_BRANCH_CONDITION} }}}}")
}

/// A `run:` step inside the app directory.
pub(crate) fn run_in(app: &App, name: &str, command: &str) -> Step {
    let step = Step::new(name).run(command);
    match app.working_directory() {
        Some(dir) => step.working_directory(dir),
        None => step,
    }
}
