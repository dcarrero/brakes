//! The recorded answers of `stack-packs` (SPEC-stack-packs.md, Recorded
//! answers): a flat `apps.<id>.<field>` namespace plus `base_image_family`.
//! The engine types each key through the pattern questions below; this file
//! applies the rules of the question table and the owner's defaults. Consumers
//! call `required_packs(cx)` and never parse the file.
use crate::{Result, engine::Context, engine::Schema, refuse};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::{Component, Path},
};

use super::{
    App, ContainerSupport, Evidence, PackageManager, StackId, StackPack,
    detect::file_present as present, packs::check_container, packs::pack,
};

/// An app id as the answers key spells it: `apps.<id>.path`.
pub type AppId = String;

/// The runtime `FROM` family (Decision 4; `distroless` by owner decision while
/// DHI pull authentication is unconfirmed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BaseImageFamily {
    Dhi,
    Distroless,
    OfficialSlim,
}

impl BaseImageFamily {
    pub const ALL: [BaseImageFamily; 3] = [
        BaseImageFamily::Dhi,
        BaseImageFamily::Distroless,
        BaseImageFamily::OfficialSlim,
    ];
    pub const DEFAULT: BaseImageFamily = BaseImageFamily::Distroless;
    pub const fn as_str(self) -> &'static str {
        match self {
            BaseImageFamily::Dhi => "dhi",
            BaseImageFamily::Distroless => "distroless",
            BaseImageFamily::OfficialSlim => "official-slim",
        }
    }
}

/// One app with every default resolved. `port`, `healthcheck` and `bin` are
/// `Some` only when the app builds a container (`bin` only for rust and go).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppAnswers {
    pub app: App,
    pub port: Option<u16>,
    /// `default`, `none` or a command.
    pub healthcheck: Option<String>,
    pub bin: Option<String>,
    /// Recorded without the pack's evidence at `path`.
    pub force: bool,
    /// The version the toolchain seed writes, over the repository's evidence.
    pub toolchain_version: Option<String>,
}

/// The module's answers, loaded and validated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StackPacksAnswers {
    pub apps: BTreeMap<AppId, AppAnswers>,
    pub base_image_family: BaseImageFamily,
}

/// The question schema: one pattern question per app field, typed by the
/// engine, and `base_image_family` with its default.
pub fn schema() -> Schema {
    let stacks: Vec<&str> = StackId::ALL.iter().map(|id| id.as_str()).collect();
    let families: Vec<&str> = BaseImageFamily::ALL.iter().map(|f| f.as_str()).collect();
    Schema::parse(&json!([
        {"id": "base_image_family", "type": "string", "enum": families,
         "default": BaseImageFamily::DEFAULT.as_str(),
         "description": "Runtime image family of every container seed."},
        {"id": "apps.*.path", "type": "string", "minLength": 1,
         "description": "App directory, relative to the repository root; `.` for the root."},
        {"id": "apps.*.stack", "type": "string", "enum": stacks,
         "description": "The pack that describes the app."},
        {"id": "apps.*.container", "type": "boolean",
         "description": "Seed a Dockerfile; defaults to true when the pack builds an image."},
        {"id": "apps.*.toolchain", "type": "boolean",
         "description": "Seed the toolchain pin file; defaults to false for rust, true otherwise."},
        {"id": "apps.*.port", "type": "integer", "minimum": 1, "maximum": 65535,
         "description": "EXPOSE and healthcheck port (container only); defaults to the pack's."},
        {"id": "apps.*.healthcheck", "type": "string", "minLength": 1,
         "description": "`default`, `none` or a command (container only)."},
        {"id": "apps.*.bin", "type": "string", "minLength": 1,
         "description": "Binary the container runs (rust and go only); defaults to the app directory name."},
        {"id": "apps.*.toolchain_version", "type": "string",
         "minLength": 1,
         "description": "Version the toolchain seed writes; defaults to the one the repository's files agree on."},
        {"id": "apps.*.force", "type": "boolean",
         "description": "Record the app although the pack's evidence is missing at its path."},
    ]))
    .expect("the stack-packs schema parses")
}

impl StackPacksAnswers {
    /// The validated answers in `cx`, with the rules of the question table
    /// applied against the repository and the defaults filled.
    pub fn load(cx: &Context<'_>) -> Result<Self> {
        let base_image_family = match cx.answers.get("base_image_family").and_then(Value::as_str) {
            Some(text) => *BaseImageFamily::ALL
                .iter()
                .find(|family| family.as_str() == text)
                .expect("the engine validated the enum"),
            None => BaseImageFamily::DEFAULT,
        };
        let mut raw: BTreeMap<&str, BTreeMap<&str, &Value>> = BTreeMap::new();
        for (key, value) in cx.answers {
            if let Some(rest) = key.strip_prefix("apps.")
                && let Some((id, field)) = rest.split_once('.')
            {
                raw.entry(id).or_default().insert(field, value);
            }
        }
        let mut apps = BTreeMap::new();
        let mut paths: BTreeMap<String, &str> = BTreeMap::new();
        for (id, fields) in &raw {
            let app = load_app(cx, id, fields)?;
            if let Some(other) = paths.insert(app.app.path.clone(), id) {
                return refuse(format!(
                    "stack-packs: apps `{other}` and `{id}` share path `{}`",
                    app.app.path
                ));
            }
            apps.insert((*id).to_owned(), app);
        }
        Ok(Self {
            apps,
            base_image_family,
        })
    }
}

/// Every app with its pack, in app id order: the one accessor consumers call.
pub fn packs(cx: &Context<'_>) -> Result<Vec<(App, &'static StackPack)>> {
    Ok(StackPacksAnswers::load(cx)?
        .apps
        .into_values()
        .map(|answers| {
            let pack = pack(answers.app.stack);
            (answers.app, pack)
        })
        .collect())
}

/// `packs` over stack-packs' answers as the engine resolved them for this plan,
/// for a module that requires `stack-packs` (`Context::answers_of`); the
/// consumer never reads the recorded file, which the plan may be replacing.
pub fn required_packs(cx: &Context<'_>) -> Result<Vec<(App, &'static StackPack)>> {
    let answers = cx.answers_of(super::STACK_PACKS)?;
    packs(&Context { answers, ..*cx })
}

/// `packs` over stack-packs' answers when `stack-packs` is active in this plan,
/// and none otherwise: the soft read of a module that does not require it
/// (`Context::answers_if_active`, #863), such as repo-baseline's Dependabot entries.
pub fn active_packs(cx: &Context<'_>) -> Result<Vec<(App, &'static StackPack)>> {
    match cx.answers_if_active(super::STACK_PACKS) {
        Some(answers) => packs(&Context { answers, ..*cx }),
        None => Ok(Vec::new()),
    }
}

fn load_app(cx: &Context<'_>, id: &str, fields: &BTreeMap<&str, &Value>) -> Result<AppAnswers> {
    let text = |field: &str| fields.get(field).and_then(|v| v.as_str());
    let flag = |field: &str| fields.get(field).and_then(|v| v.as_bool());
    let Some(raw_path) = text("path") else {
        return refuse(format!(
            "stack-packs: app `{id}` has no `path`; set apps.{id}.path"
        ));
    };
    let Some(stack) = text("stack") else {
        return refuse(format!(
            "stack-packs: app `{id}` has no `stack`; set apps.{id}.stack"
        ));
    };
    let stack: StackId = stack.parse()?;
    let path = app_path(cx.root, id, raw_path)?;
    let pack = pack(stack);
    let force = flag("force").unwrap_or(false);
    let prefix = if path == "." {
        String::new()
    } else {
        format!("{path}/")
    };
    if !force {
        check_evidence(cx.root, id, &prefix, pack)?;
    }
    let capable = matches!(pack.container, ContainerSupport::Capable { .. });
    let container = flag("container").unwrap_or(capable);
    let app = App {
        id: id.to_owned(),
        path: path.clone(),
        stack,
        container,
        toolchain: flag("toolchain").unwrap_or(stack != StackId::Rust),
        package_manager: (stack == StackId::Node)
            .then(|| {
                PackageManager::ALL
                    .into_iter()
                    .find(|pm| cx.root.join(format!("{prefix}{}", pm.lockfile())).is_file())
            })
            .flatten(),
        declared: declared(cx, &path),
    };
    check_container(&app, pack)?;
    let builds_binary = matches!(stack, StackId::Rust | StackId::Go);
    if !builds_binary && fields.contains_key("bin") {
        return refuse(format!(
            "stack-packs: app `{id}` sets `bin` but stack `{stack}` builds no binary"
        ));
    }
    let toolchain_version = text("toolchain_version").map(str::to_owned);
    if let Some(version) = &toolchain_version {
        if super::versions::single_version(version).as_deref() != Some(version.as_str()) {
            return refuse(format!(
                "stack-packs: app `{id}` toolchain_version `{version}` is not a dotted version such as 22 or 3.12"
            ));
        }
        if pack.toolchain_seed.is_none() {
            return refuse(format!(
                "stack-packs: app `{id}` sets `toolchain_version` but stack `{stack}` seeds no toolchain file"
            ));
        }
        if !app.toolchain {
            return refuse(format!(
                "stack-packs: app `{id}` sets `toolchain_version` but toolchain is false"
            ));
        }
    }
    for field in ["port", "healthcheck", "bin"] {
        if !container && fields.contains_key(field) {
            return refuse(format!(
                "stack-packs: app `{id}` sets `{field}` but container is false"
            ));
        }
    }
    let (port, healthcheck, bin) = match pack.container {
        ContainerSupport::Capable { port_default, .. } if container => (
            Some(
                fields
                    .get("port")
                    .and_then(|v| v.as_u64())
                    .map_or(port_default, |port| port as u16),
            ),
            Some(text("healthcheck").unwrap_or("default").to_owned()),
            builds_binary.then(|| {
                text("bin")
                    .map(str::to_owned)
                    .unwrap_or_else(|| directory_name(cx.root, &path))
            }),
        ),
        _ => (None, None, None),
    };
    Ok(AppAnswers {
        app,
        port,
        healthcheck,
        bin,
        force,
        toolchain_version,
    })
}

/// `raw` normalised (no trailing `/`, no `./` prefix) after the path rules:
/// relative, inside the root, an existing directory reached through no symlink.
fn app_path(root: &Path, id: &str, raw: &str) -> Result<String> {
    let trimmed = raw.trim_end_matches('/');
    let trimmed = trimmed.strip_prefix("./").unwrap_or(trimmed);
    let path = if trimmed.is_empty() { "." } else { trimmed };
    let inside = Path::new(path)
        .components()
        .all(|c| matches!(c, Component::Normal(_)))
        || path == ".";
    if !inside {
        return refuse(format!(
            "stack-packs: app `{id}` path `{raw}` must be relative and inside the repository"
        ));
    }
    let mut current = root.to_path_buf();
    for component in Path::new(path).components() {
        current.push(component);
        let Ok(meta) = std::fs::symlink_metadata(&current) else {
            return refuse(format!(
                "stack-packs: app `{id}` path `{raw}` does not exist"
            ));
        };
        if meta.file_type().is_symlink() {
            return refuse(format!("stack-packs: app `{id}` path `{raw}` is a symlink"));
        }
    }
    if !current.is_dir() {
        return refuse(format!(
            "stack-packs: app `{id}` path `{raw}` is not a directory"
        ));
    }
    Ok(path.to_owned())
}

/// The pack's evidence at the app path, naming the first missing file.
fn check_evidence(root: &Path, id: &str, prefix: &str, pack: &StackPack) -> Result<()> {
    let stack = pack.id;
    let force = format!("set apps.{id}.force=true to record it anyway");
    for evidence in pack.evidence {
        match evidence {
            Evidence::AllOf(files) => {
                if let Some(missing) = files.iter().find(|f| !present(root, prefix, f)) {
                    return refuse(format!(
                        "stack-packs: app `{id}` is not a `{stack}` app: `{prefix}{missing}` is missing; {force}"
                    ));
                }
            }
            Evidence::AnyOf(files) => {
                if !files.iter().any(|f| present(root, prefix, f)) {
                    let names: Vec<String> =
                        files.iter().map(|f| format!("`{prefix}{f}`")).collect();
                    return refuse(format!(
                        "stack-packs: app `{id}` is not a `{stack}` app: none of {} is present; {force}",
                        names.join(", ")
                    ));
                }
            }
        }
    }
    Ok(())
}

/// The declared `commands.*` the app's `ci_setup` reads: the root profile's for
/// the root app; per-app profiles join with `--accept-commands` (T7).
fn declared(cx: &Context<'_>, path: &str) -> BTreeMap<String, String> {
    if path != "." {
        return BTreeMap::new();
    }
    cx.profile.value["commands"]
        .as_object()
        .map(|commands| {
            commands
                .iter()
                .filter_map(|(name, value)| Some((name.clone(), value.as_str()?.to_owned())))
                .collect()
        })
        .unwrap_or_default()
}

/// The app directory's own name: the default `bin`.
fn directory_name(root: &Path, path: &str) -> String {
    let full = if path == "." {
        root.to_path_buf()
    } else {
        root.join(path)
    };
    full.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "app".to_owned())
}
