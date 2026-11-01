//! The files `render` declares per app: the toolchain pin file as `seed` and
//! the manifest the pack reads as `never-touch`, both under the app's `<path>/`
//! prefix (SPEC-stack-packs.md, Project Structure). Nothing is read here; the
//! engine decides `SKIP` for a seed whose path exists.
use crate::{
    Result,
    engine::{Ownership, Rendered},
    refuse,
};

use super::{App, PinTable, StackId, packs::pack, versions};
use std::path::Path;

/// The manifests a pack reads and never edits. A device or data pack reads
/// several (the Gradle files and the wrapper's properties; dbt's project and
/// packages files); each is declared, present or not.
pub const fn manifests(stack: StackId) -> &'static [&'static str] {
    match stack {
        StackId::Rust => &["Cargo.toml"],
        StackId::PythonUv => &["pyproject.toml"],
        StackId::Node => &["package.json"],
        StackId::Go => &["go.mod"],
        StackId::KotlinAndroid => &[
            "settings.gradle.kts",
            "build.gradle.kts",
            "gradle/wrapper/gradle-wrapper.properties",
        ],
        StackId::SwiftIos => &["Package.swift"],
        StackId::SqlDbt => &["dbt_project.yml", "packages.yml", "dependencies.yml"],
    }
}

/// The toolchain seed (when `toolchain` is on and the pack has one), then the
/// never-touch manifests, for one app. The seed's version is the owner's
/// `toolchain_version` or the repository's own (`versions`, #1161); a seed
/// already present is not re-read, the engine skips it.
pub fn toolchain(
    root: &Path,
    app: &App,
    toolchain_version: Option<&str>,
    pins: &PinTable,
) -> Result<Vec<Rendered>> {
    let prefix = app.prefix();
    let mut rendered = Vec::new();
    if let (true, Some(seed)) = (app.toolchain, pack(app.stack).toolchain_seed) {
        let path = format!("{prefix}{}", seed.path);
        let content = if root.join(&path).exists() {
            fill(seed.template, pins)?
        } else {
            let version = versions::seed_version(root, app, seed.path, toolchain_version, pins)?;
            fill_version(seed.template, &version)?
        };
        rendered.push(Rendered {
            path,
            class: Ownership::Seed,
            content: Some(content),
            scaffold: None,
        });
    }
    for manifest in manifests(app.stack) {
        rendered.push(Rendered {
            path: format!("{prefix}{manifest}"),
            class: Ownership::NeverTouch,
            content: None,
            scaffold: None,
        });
    }
    Ok(rendered)
}

/// Replaces every `{{tools.<key>}}` with the pinned version of `<key>`; a key
/// missing from the table refuses through `PinTable::tool`.
pub fn fill(template: &str, pins: &PinTable) -> Result<String> {
    const OPEN: &str = "{{tools.";
    let mut text = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find(OPEN) {
        let after = &rest[start + OPEN.len()..];
        let Some(end) = after.find("}}") else {
            return refuse("stack-packs: a template has an unclosed `{{tools.` placeholder");
        };
        text.push_str(&rest[..start]);
        text.push_str(&pins.tool(&after[..end])?.version);
        rest = &after[end + 2..];
    }
    text.push_str(rest);
    Ok(text)
}

/// The seed template with its one `{{tools.<key>}}` placeholder replaced by
/// `version`; a template without exactly one placeholder refuses.
pub fn fill_version(template: &str, version: &str) -> Result<String> {
    const OPEN: &str = "{{tools.";
    let Some(start) = template.find(OPEN) else {
        return refuse("stack-packs: a toolchain seed template has no `{{tools.` placeholder");
    };
    let Some(end) = template[start..].find("}}") else {
        return refuse("stack-packs: a template has an unclosed `{{tools.` placeholder");
    };
    let rest = &template[start + end + 2..];
    if rest.contains(OPEN) {
        return refuse("stack-packs: a toolchain seed template has two `{{tools.` placeholders");
    }
    Ok(format!("{}{version}{rest}", &template[..start]))
}
