//! The container seed of an app with `container: true` (SPEC-stack-packs.md,
//! Container seed): `<path>/Dockerfile` and `<path>/.dockerignore`, both
//! `seed`, from the pack's template. Pure: the images come from the pin table
//! (`<pack>.build` and `<family>.<runtime>`), the rest from the app's answers.
//! The runtime images have no shell, so every `HEALTHCHECK` is exec form.
use crate::{
    Result,
    engine::{Ownership, Rendered},
    refuse,
};

use super::{
    AppAnswers, BaseImageFamily, ContainerSupport, Healthcheck, PackageManager, PinTable, StackId,
    packs::pack, seeds::fill,
};

const HEALTHCHECK_FLAGS: &str = "--interval=30s --timeout=3s --start-period=10s";

/// The Dockerfile and `.dockerignore` templates of a container-capable pack.
const fn templates(stack: StackId) -> Option<(&'static str, &'static str)> {
    match stack {
        StackId::Rust => Some((
            include_str!("../../../../../templates/stack-packs/rust/Dockerfile"),
            include_str!("../../../../../templates/stack-packs/rust/dockerignore"),
        )),
        StackId::PythonUv => Some((
            include_str!("../../../../../templates/stack-packs/python-uv/Dockerfile"),
            include_str!("../../../../../templates/stack-packs/python-uv/dockerignore"),
        )),
        StackId::Node => Some((
            include_str!("../../../../../templates/stack-packs/node/Dockerfile"),
            include_str!("../../../../../templates/stack-packs/node/dockerignore"),
        )),
        StackId::Go => Some((
            include_str!("../../../../../templates/stack-packs/go/Dockerfile"),
            include_str!("../../../../../templates/stack-packs/go/dockerignore"),
        )),
        StackId::KotlinAndroid | StackId::SwiftIos | StackId::SqlDbt => None,
    }
}

/// The two seeds of one app; empty when the app builds no container.
/// `generated_paths` are the project's, relative to the repository root.
pub fn seeds(
    answers: &AppAnswers,
    family: BaseImageFamily,
    pins: &PinTable,
    generated_paths: &[String],
) -> Result<Vec<Rendered>> {
    let app = &answers.app;
    let (
        true,
        ContainerSupport::Capable {
            runtime,
            healthcheck_default,
            ..
        },
        Some((dockerfile, dockerignore)),
    ) = (
        app.container,
        pack(app.stack).container,
        templates(app.stack),
    )
    else {
        return Ok(Vec::new());
    };
    let runtime_image = pins.image(&format!("{}.{}", family.as_str(), runtime.as_str()))?;
    let build_image = pins.image(&format!("{}.build", app.stack.as_str()))?;
    let port = answers.port.unwrap_or_default().to_string();
    let bin = answers.bin.as_deref().unwrap_or("app");
    let command = match answers.healthcheck.as_deref().unwrap_or("default") {
        "none" => None,
        "default" => match healthcheck_default {
            Healthcheck::BinaryFlag(flag) => Some(format!("[\"/app/{bin}\", \"{flag}\"]")),
            Healthcheck::Command(command) => Some(command.to_owned()),
            Healthcheck::None => None,
        },
        custom if custom.starts_with('[') && custom.ends_with(']') => Some(custom.to_owned()),
        _ => {
            return refuse(format!(
                "stack-packs: app `{}` healthcheck must be `default`, `none` or an exec-form JSON array such as [\"/app/bin\", \"--healthcheck\"]; the runtime image has no shell",
                app.id
            ));
        }
    };
    let healthcheck = match command {
        Some(command) => format!("HEALTHCHECK {HEALTHCHECK_FLAGS} CMD {command}\n"),
        None => String::new(),
    };
    let (install, cache) = node_install(answers)?;
    let text = dockerfile
        .replace("{{healthcheck}}\n", &healthcheck)
        .replace("{{image.build}}", &build_image.pinned())
        .replace("{{image.runtime}}", &runtime_image.pinned())
        .replace("{{install}}", install)
        .replace("{{cache}}", cache)
        .replace("{{port}}", &port)
        .replace("{{bin}}", bin);
    let text = fill(&text, pins)?;
    if text.contains("{{") {
        return refuse(format!(
            "stack-packs: the {} Dockerfile template has a placeholder this module does not fill",
            app.stack
        ));
    }
    let prefix = app.prefix();
    Ok(vec![
        Rendered {
            path: format!("{prefix}Dockerfile"),
            class: Ownership::Seed,
            content: Some(text),
            scaffold: None,
        },
        Rendered {
            path: format!("{prefix}.dockerignore"),
            class: Ownership::Seed,
            content: Some(ignore_list(dockerignore, &prefix, generated_paths)),
            scaffold: None,
        },
    ])
}

/// The node build stage's lockfile-strict install and the cache it mounts;
/// empty for other packs. pnpm and yarn come through corepack, bundled with
/// the pinned node image; bun has no pinned image and refuses.
fn node_install(answers: &AppAnswers) -> Result<(&'static str, &'static str)> {
    let app = &answers.app;
    if app.stack != StackId::Node {
        return Ok(("", ""));
    }
    match app.package_manager {
        Some(PackageManager::Npm) => Ok(("npm ci", "/root/.npm")),
        Some(PackageManager::Pnpm) => Ok((
            "corepack enable && pnpm install --frozen-lockfile",
            "/root/.local/share/pnpm/store",
        )),
        Some(PackageManager::Yarn) => Ok((
            "corepack enable && yarn install --immutable",
            "/root/.yarn/berry/cache",
        )),
        Some(PackageManager::Bun) => refuse(format!(
            "stack-packs: app `{id}` uses bun, which has no pinned build image; set apps.{id}.container=false or seed the Dockerfile by hand",
            id = app.id
        )),
        None => refuse(format!(
            "stack-packs: app `{}` is node but names no package manager; a lockfile must be present at `{}`",
            app.id, app.path
        )),
    }
}

/// The pack's list plus the generated paths inside the app's build context,
/// relative to it (the root app takes them all), without a trailing `/`.
fn ignore_list(template: &str, prefix: &str, generated_paths: &[String]) -> String {
    let mut text = template.to_owned();
    for path in generated_paths {
        if let Some(inside) = path.strip_prefix(prefix) {
            let entry = inside.trim_end_matches('/');
            if !entry.is_empty() && !text.lines().any(|line| line == entry) {
                text.push_str(entry);
                text.push('\n');
            }
        }
    }
    text
}
