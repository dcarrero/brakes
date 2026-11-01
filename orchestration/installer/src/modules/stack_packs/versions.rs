//! The version a toolchain seed writes (SPEC-stack-packs.md, "Version of the
//! toolchain seed"; #1161, #1168): the owner's `apps.<id>.toolchain_version`,
//! else the one version the repository's own files agree on. Disagreeing or
//! absent evidence refuses naming the answers that settle it; the pin table is
//! never seeded silently. Files only: nothing runs, nothing reads the network.
use crate::{Result, auditor::workflows, refuse};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use super::{App, PinTable, StackId, audit};

/// Where one pack's version shows in a repository.
struct Sources {
    /// The pin-table key of the toolchain, shown for reference in a refusal.
    tool: &'static str,
    /// What a refusal calls the toolchain.
    label: &'static str,
    tool_versions: &'static [&'static str],
    version_files: &'static [&'static str],
    /// `(manifest, field)`: `engines.node` of `package.json`, `requires-python`.
    manifest: Option<(&'static str, &'static str)>,
    images: &'static [&'static str],
    /// `(action, with key)`.
    steps: &'static [(&'static str, &'static str)],
    /// `Xcode_<v>.app` in a step's `run` or `env`.
    xcode_app: bool,
}

const PYTHON: Sources = Sources {
    tool: "python",
    label: "Python",
    tool_versions: &["python"],
    version_files: &[],
    manifest: Some(("pyproject.toml", "requires-python")),
    images: &["python"],
    steps: &[
        ("actions/setup-python", "python-version"),
        ("astral-sh/setup-uv", "python-version"),
    ],
    xcode_app: false,
};

fn sources(stack: StackId) -> Option<Sources> {
    Some(match stack {
        StackId::Node => Sources {
            tool: "node",
            label: "Node",
            tool_versions: &["nodejs", "node"],
            version_files: &[".node-version"],
            manifest: Some(("package.json", "engines.node")),
            images: &["node"],
            steps: &[("actions/setup-node", "node-version")],
            xcode_app: false,
        },
        StackId::PythonUv | StackId::SqlDbt => PYTHON,
        StackId::Rust => Sources {
            tool: "rust",
            label: "Rust",
            tool_versions: &["rust"],
            version_files: &[],
            manifest: None,
            images: &["rust"],
            steps: &[("dtolnay/rust-toolchain", "toolchain")],
            xcode_app: false,
        },
        StackId::KotlinAndroid => Sources {
            tool: "java",
            label: "Java",
            tool_versions: &["java"],
            version_files: &[],
            manifest: None,
            images: &["eclipse-temurin", "openjdk"],
            steps: &[("actions/setup-java", "java-version")],
            xcode_app: false,
        },
        StackId::SwiftIos => Sources {
            tool: "xcode",
            label: "Xcode",
            tool_versions: &[],
            version_files: &[],
            manifest: None,
            images: &[],
            steps: &[("maxim-lobanov/setup-xcode", "xcode-version")],
            xcode_app: true,
        },
        StackId::Go => return None,
    })
}

/// The version `text` names, or `None` for a range, a word, an expression or
/// a list: `22`, `22.x`, `3.12.*`, `==3.12`, `^22.1`, `~22.1`, `v22` name one;
/// `>=3.12`, `~=3.12`, `20 || 22`, `stable`, `${{ matrix.node }}` do not.
pub fn single_version(text: &str) -> Option<String> {
    let text = text.trim().trim_matches(|c| c == '"' || c == '\'');
    if text.starts_with("~=") {
        return None;
    }
    let text = ["==", "=", "^", "~", "v"]
        .iter()
        .find_map(|prefix| text.strip_prefix(prefix))
        .unwrap_or(text);
    let text = [".*", ".x", ".X"]
        .iter()
        .find_map(|suffix| text.strip_suffix(suffix))
        .unwrap_or(text);
    let valid = !text.is_empty()
        && text
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()));
    valid.then(|| text.to_owned())
}

/// The leading version of an image tag: `22` of `22-alpine`, `3.12` of
/// `3.12-slim`; `lts` or `latest` name none.
fn tag_version(tag: &str) -> Option<String> {
    let lead: String = tag
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    single_version(lead.trim_end_matches('.'))
}

/// Two versions agree when equal or one is a dotted prefix of the other.
fn agree(a: &str, b: &str) -> bool {
    a == b || a.starts_with(&format!("{b}.")) || b.starts_with(&format!("{a}."))
}

fn prefix(path: &str) -> String {
    if path == "." {
        String::new()
    } else {
        format!("{path}/")
    }
}

/// Every version the repository names for `app`'s toolchain, each with the
/// files that name it.
fn evidence(root: &Path, app: &App, s: &Sources) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let mut found: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut add = |version: Option<String>, file: String| {
        if let Some(version) = version {
            found.entry(version).or_default().insert(file);
        }
    };
    let mut dirs = vec![prefix(&app.path)];
    if app.path != "." {
        dirs.push(String::new());
    }
    for dir in &dirs {
        for file in s.version_files {
            let rel = format!("{dir}{file}");
            if let Some(text) = crate::read(root, &rel)? {
                add(single_version(text.lines().next().unwrap_or("")), rel);
            }
        }
        let rel = format!("{dir}.tool-versions");
        if let Some(text) = crate::read(root, &rel)? {
            for line in text.lines() {
                let mut words = line.split_whitespace();
                if let (Some(name), Some(version)) = (words.next(), words.next())
                    && s.tool_versions.contains(&name)
                {
                    // asdf's `java temurin-17.0.2+8`: the distribution goes first.
                    let version = version.rsplit('-').next().unwrap_or(version);
                    let version = version.split('+').next().unwrap_or(version);
                    add(single_version(version), rel.clone());
                }
            }
        }
    }
    if let Some((manifest, field)) = s.manifest {
        let rel = format!("{}{manifest}", prefix(&app.path));
        if let Some(text) = crate::read(root, &rel)? {
            let value = if manifest.ends_with(".json") {
                serde_json::from_str::<Value>(&text).ok().and_then(|json| {
                    field
                        .split('.')
                        .try_fold(&json, |v, k| v.get(k))
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
            } else {
                text.lines().find_map(|line| {
                    let value = line.trim().strip_prefix(field)?.trim_start();
                    Some(value.strip_prefix('=')?.trim().to_owned())
                })
            };
            add(value.and_then(|v| single_version(&v)), rel);
        }
    }
    if !s.images.is_empty() {
        let mut dockerfiles = BTreeSet::new();
        audit::collect_dockerfiles(root, &app.path, &mut dockerfiles);
        for rel in dockerfiles {
            let Ok(text) = fs::read_to_string(root.join(&rel)) else {
                continue;
            };
            for (keyword, args) in audit::instructions(&text) {
                if keyword != "FROM" {
                    continue;
                }
                let Some(image) = args.split_whitespace().find(|w| !w.starts_with("--")) else {
                    continue;
                };
                let image = image.split('@').next().unwrap_or(image);
                let name = image.rsplit('/').next().unwrap_or(image);
                if let Some((repository, tag)) = name.split_once(':')
                    && s.images.contains(&repository)
                {
                    add(tag_version(tag), rel.clone());
                }
            }
        }
    }
    let dir = root.join(".github/workflows");
    let mut files: Vec<String> = fs::read_dir(&dir)
        .map(|entries| {
            entries
                .flatten()
                .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.ends_with(".yml") || n.ends_with(".yaml"))
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    for name in files {
        let rel = format!(".github/workflows/{name}");
        let Some(text) = crate::read(root, &rel)? else {
            continue;
        };
        // A workflow that does not parse is the auditor's to report.
        let Ok(workflow) = workflows::parse(&text) else {
            continue;
        };
        for step in workflow.jobs.iter().flat_map(|job| &job.steps) {
            let action = step
                .uses
                .as_deref()
                .and_then(|uses| uses.split('@').next())
                .unwrap_or("");
            for (wanted, key) in s.steps {
                if action == *wanted
                    && let Some(value) = step.with.get(*key)
                {
                    add(single_version(value), rel.clone());
                }
            }
            if s.xcode_app {
                for text in step.run.iter().chain(step.env.values()) {
                    let mut rest = text.as_str();
                    while let Some(at) = rest.find("Xcode_") {
                        rest = &rest[at + "Xcode_".len()..];
                        if let Some(end) = rest.find(".app") {
                            add(single_version(&rest[..end]), rel.clone());
                        }
                    }
                }
            }
        }
    }
    Ok(found)
}

/// The version `app`'s seed writes: `answer` when the owner gave one, else
/// the one version the evidence agrees on (the most specific of them).
pub fn seed_version(
    root: &Path,
    app: &App,
    seed_path: &str,
    answer: Option<&str>,
    pins: &PinTable,
) -> Result<String> {
    if let Some(answer) = answer {
        return Ok(answer.to_owned());
    }
    let Some(s) = sources(app.stack) else {
        return refuse(format!(
            "stack-packs: app `{}` ({}) has no toolchain seed",
            app.id, app.stack
        ));
    };
    let found = evidence(root, app, &s)?;
    let versions: Vec<&String> = found.keys().collect();
    let all_agree = versions
        .iter()
        .all(|a| versions.iter().all(|b| agree(a, b)));
    let seed = format!("{}{seed_path}", prefix(&app.path));
    let settle = format!(
        "set apps.{id}.toolchain_version=<version> (the pin table has {pin}) or apps.{id}.toolchain=false",
        id = app.id,
        pin = pins.tool(s.tool)?.version
    );
    if versions.is_empty() {
        return refuse(format!(
            "stack-packs: app `{}` ({}): no {} version found in the repository to seed `{seed}` from; {settle}",
            app.id, app.stack, s.label
        ));
    }
    if !all_agree {
        let named: Vec<String> = found
            .iter()
            .map(|(version, files)| {
                format!(
                    "{version} ({})",
                    files.iter().cloned().collect::<Vec<_>>().join(", ")
                )
            })
            .collect();
        return refuse(format!(
            "stack-packs: app `{}` ({}): the repository names different {} versions for `{seed}`: {}; {settle}",
            app.id,
            app.stack,
            s.label,
            named.join(", ")
        ));
    }
    Ok(versions
        .into_iter()
        .max_by_key(|v| v.split('.').count())
        .expect("not empty")
        .clone())
}
