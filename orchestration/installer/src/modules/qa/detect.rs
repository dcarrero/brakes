//! The derived `api` and `web` of one directory (SPEC-qa.md, Answers): the
//! files that say a service or a web application lives there, each with the
//! evidence the plan prints. One function, so the auditor's `qa.*` rules (T11)
//! decide `required for` exactly as the module derives its defaults.
//!
//! Reads are line-wise (`pyproject.toml`, `uv.lock`, `Cargo.toml`, `*.go`) or
//! through the JSON the crate already parses (`package.json`); no manifest
//! parser, no new crate, no command, never the network.
use super::{PLAYWRIGHT_CONFIGS, Web};
use crate::{Result, read};
use serde_json::Value;
use std::path::Path;

/// Frameworks that serve HTTP: a manifest that names one is an API (the
/// spec's first table). Go's are `net/http` handlers, found in `*.go` files.
pub const PYTHON_SERVICES: [&str; 3] = ["fastapi", "flask", "django"];
pub const RUST_SERVICES: [&str; 2] = ["axum", "actix-web"];
pub const NODE_SERVICES: [&str; 2] = ["express", "fastify"];
/// Front-end frameworks: a `package.json` that names one among its
/// `dependencies` is a web application (`web: seeded` unless the project
/// already runs Playwright).
pub const WEB_FRAMEWORKS: [&str; 6] = [
    "react",
    "vue",
    "svelte",
    "@angular/core",
    "solid-js",
    "preact",
];
/// The dependency that says the project runs its own Playwright.
pub const PLAYWRIGHT: &str = "@playwright/test";
/// How deep under the directory `*.go` files are read for handlers.
const GO_DEPTH: usize = 4;
/// Directories never read for `*.go` files.
const GO_SKIP: [&str; 4] = ["vendor", "node_modules", "testdata", "target"];

/// What the files under one directory say; evidence paths are relative to the
/// repository root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Derivation {
    /// `Some(evidence)` when the directory serves an API.
    pub api: Option<String>,
    pub web: Web,
    /// `Some` exactly when `web` is not `None`.
    pub web_evidence: Option<String>,
}

impl Derivation {
    /// No service and no web application: what a directory with no recorded
    /// app derives.
    pub const fn none() -> Self {
        Self {
            api: None,
            web: Web::None,
            web_evidence: None,
        }
    }
}

/// The derivation of `dir` (`.` for the root) under `root`. `seeds_dockerfile`
/// is true when `stack-packs` renders a Dockerfile there in the same plan (its
/// `container` app), so the result does not change once the seed is written.
pub fn derive(root: &Path, dir: &str, seeds_dockerfile: bool) -> Result<Derivation> {
    let at = |file: &str| {
        if dir == "." {
            file.to_owned()
        } else {
            format!("{}/{file}", dir.trim_end_matches('/'))
        }
    };
    let package = read(root, &at("package.json"))?.and_then(|t| serde_json::from_str(&t).ok());
    let api = if root.join(at("Dockerfile")).is_file() {
        Some(at("Dockerfile"))
    } else if seeds_dockerfile {
        Some(format!("{}, seeded by stack-packs", at("Dockerfile")))
    } else {
        service(root, dir, &at, package.as_ref())?
    };
    let config = PLAYWRIGHT_CONFIGS
        .into_iter()
        .find(|c| root.join(at(c)).is_file());
    let names = |field: &str, name: &str| {
        package
            .as_ref()
            .is_some_and(|p: &Value| p[field].get(name).is_some())
    };
    let playwright = names("dependencies", PLAYWRIGHT) || names("devDependencies", PLAYWRIGHT);
    let (web, web_evidence) = match config {
        Some(config) if playwright => (
            Web::Project,
            Some(format!(
                "{} names {PLAYWRIGHT} and {} exists",
                at("package.json"),
                at(config)
            )),
        ),
        _ => match WEB_FRAMEWORKS
            .into_iter()
            .find(|f| names("dependencies", f))
        {
            Some(framework) => (
                Web::Seeded,
                Some(format!("{} names {framework}", at("package.json"))),
            ),
            None => (Web::None, None),
        },
    };
    Ok(Derivation {
        api,
        web,
        web_evidence,
    })
}

/// A line-wise reader: the framework a manifest's text names, if any.
type Names = fn(&str) -> Option<&'static str>;

/// The first manifest that names a service framework, as evidence.
fn service(
    root: &Path,
    dir: &str,
    at: &dyn Fn(&str) -> String,
    package: Option<&Value>,
) -> Result<Option<String>> {
    if let Some(found) = package.and_then(|p| {
        NODE_SERVICES
            .into_iter()
            .find(|f| p["dependencies"].get(f).is_some())
    }) {
        return Ok(Some(format!("{} names {found}", at("package.json"))));
    }
    let checks: [(&str, Names); 3] = [
        ("pyproject.toml", pyproject_names),
        ("uv.lock", uv_lock_names),
        ("Cargo.toml", cargo_names),
    ];
    for (file, names) in checks {
        if let Some(found) = read(root, &at(file))?.as_deref().and_then(names) {
            return Ok(Some(format!("{} names {found}", at(file))));
        }
    }
    let base = if dir == "." {
        root.to_path_buf()
    } else {
        root.join(dir)
    };
    Ok(go_handlers(&base, GO_DEPTH)
        .and_then(|file| file.strip_prefix(root).ok().map(Path::to_path_buf))
        .map(|file| format!("{} registers net/http handlers", file.to_string_lossy())))
}

/// A Python distribution name as PEP 503 compares it.
fn normalise(name: &str) -> String {
    name.to_ascii_lowercase().replace(['_', '.'], "-")
}

/// The leading distribution name of a requirement (`fastapi[standard]>=1`).
fn requirement_name(text: &str) -> &str {
    let end = text
        .find(|c: char| !(c.is_ascii_alphanumeric() || "-_.".contains(c)))
        .unwrap_or(text.len());
    &text[..end]
}

fn python_service(name: &str) -> Option<&'static str> {
    let name = normalise(name);
    PYTHON_SERVICES.into_iter().find(|s| *s == name)
}

/// A quoted requirement (`"fastapi>=0.115"`, PEP 621) or a `name = …` key
/// (Poetry) that names a Python service framework.
fn pyproject_names(text: &str) -> Option<&'static str> {
    text.lines().find_map(|line| {
        let line = line.trim();
        let quoted = line
            .split('"')
            .skip(1)
            .step_by(2)
            .find_map(|s| python_service(requirement_name(s)));
        quoted.or_else(|| {
            let (key, _) = line.split_once('=')?;
            python_service(key.trim()).filter(|_| requirement_name(key.trim()) == key.trim())
        })
    })
}

/// A `name = "…"` line of `uv.lock` that names a Python service framework.
fn uv_lock_names(text: &str) -> Option<&'static str> {
    text.lines().find_map(|line| {
        let value = line.trim().strip_prefix("name = \"")?.strip_suffix('"')?;
        python_service(value)
    })
}

/// A dependency of a `[dependencies]`-like table (never `dev-` or `build-`)
/// that names a Rust service framework: `axum = …`, `axum.workspace = true` or
/// a `[dependencies.axum]` table.
fn cargo_names(text: &str) -> Option<&'static str> {
    let mut in_dependencies = false;
    let runtime = |table: &str| {
        let table = table.trim();
        let last = table.rsplit('.').next().unwrap_or(table);
        last == "dependencies" && !table.ends_with("dev-dependencies")
    };
    for line in text.lines().map(str::trim) {
        if let Some(header) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            in_dependencies = runtime(header);
            if let Some((table, name)) = header.rsplit_once('.')
                && runtime(table)
                && let Some(found) = RUST_SERVICES.into_iter().find(|s| *s == name.trim())
            {
                return Some(found);
            }
            continue;
        }
        if !in_dependencies {
            continue;
        }
        if let Some(found) = RUST_SERVICES.into_iter().find(|s| {
            line.strip_prefix(s).is_some_and(|rest| {
                let rest = rest.trim_start();
                rest.starts_with('=') || rest.starts_with('.')
            })
        }) {
            return Some(found);
        }
    }
    None
}

/// The first non-test `*.go` file under `dir`, in path order, that imports
/// `net/http` and registers a handler; symlinks and unreadable files are skipped.
fn go_handlers(dir: &Path, depth: usize) -> Option<std::path::PathBuf> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    entries.sort();
    for path in entries {
        let Some(name) = path.file_name().map(|n| n.to_string_lossy().into_owned()) else {
            continue;
        };
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.is_dir() {
            if depth > 0
                && !name.starts_with('.')
                && !GO_SKIP.contains(&name.as_str())
                && let Some(found) = go_handlers(&path, depth - 1)
            {
                return Some(found);
            }
        } else if meta.is_file() && name.ends_with(".go") && !name.ends_with("_test.go") {
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            if text.contains("\"net/http\"")
                && (text.contains("HandleFunc(") || text.contains(".Handle("))
            {
                return Some(path);
            }
        }
    }
    None
}
