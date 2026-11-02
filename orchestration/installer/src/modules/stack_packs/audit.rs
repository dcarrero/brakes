//! The static `stack.*` rules (SPEC-stack-packs.md, "Auditor rules declared by
//! this module" and "How `doctor` reports the static rules"): evaluated locally
//! over the apps the recorded answers name, the files at their paths and every
//! Dockerfile under them, plus the age of the pin table. Like the `ci.*` and
//! `security.*` rules the auditor's registry judges them from these findings at
//! the levels the owner allocated (#873; `no-healthcheck` and `pin-table-stale`
//! stay warnings with no level): a failed rule is a
//! `WARNING: stack.<rule-id>: <text>` finding, a passed rule nothing. Nothing
//! here runs a command or reads the network. `stack.unconfigured` lives in
//! `detect`, next to the proposal block it prints.
use super::{
    ContainerSupport, PIN_VERIFICATION_DAYS, PINS_PATH, PackageManager, PinTable, STACK_PACKS,
    StackId, detect, packs::pack,
};
use crate::{
    Result,
    auditor::workflows::{unverified, warn},
    engine::answers,
};
use chrono::NaiveDate;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path},
};

const LOCKFILE_PRESENT: &str = "stack.lockfile-present";
const LOCKFILE_NOT_ENFORCED: &str = "stack.lockfile-not-enforced";
const TOOLCHAIN_PINNED: &str = "stack.toolchain-pinned";
const IMAGE_BY_DIGEST: &str = "stack.image-by-digest";
const IMAGE_NONROOT: &str = "stack.image-nonroot";
const IMAGE_ARBITRARY_UID: &str = "stack.image-arbitrary-uid";
const NO_HEALTHCHECK: &str = "stack.no-healthcheck";
const PIN_TABLE_STALE: &str = "stack.pin-table-stale";

/// The declared commands `stack.lockfile-not-enforced` reads.
const ENFORCED_COMMANDS: [&str; 2] = ["test", "verify"];

/// One app as the recorded answers name it; the engine validates the rest.
pub(crate) struct RecordedApp {
    pub(crate) id: String,
    pub(crate) path: String,
    pub(crate) stack: StackId,
    container: bool,
    healthcheck_none: bool,
}

impl RecordedApp {
    fn prefix(&self) -> String {
        if self.path == "." {
            String::new()
        } else {
            format!("{}/", self.path)
        }
    }
    fn has(&self, root: &Path, file: &str) -> bool {
        root.join(format!("{}{file}", self.prefix())).is_file()
    }
    fn label(&self) -> String {
        format!("app `{}` ({} at {})", self.id, self.stack, self.path)
    }
}

/// `doctor`'s `stack.*` findings for the checkout at `root` on `today`: the
/// app rules in the spec's order, then every Dockerfile under an app path in
/// path order, then `no-healthcheck`, then the pin-table age.
pub fn diagnose(root: &Path, today: NaiveDate) -> Result<Vec<String>> {
    let apps = recorded_apps(root)?;
    let mut out = Vec::new();
    for app in &apps {
        out.extend(lockfile_present(root, app));
    }
    for app in &apps {
        out.extend(lockfile_not_enforced(root, app)?);
    }
    for app in &apps {
        out.extend(toolchain_pinned(root, app));
    }
    let mut dockerfiles = BTreeSet::new();
    for app in &apps {
        collect_dockerfiles(root, &app.path, &mut dockerfiles);
    }
    for path in &dockerfiles {
        match fs::read_to_string(root.join(path)) {
            Ok(text) => out.extend(dockerfile(path, &text)),
            Err(error) => out.push(unverified(IMAGE_BY_DIGEST, path, &error.to_string())),
        }
    }
    for app in apps.iter().filter(|a| a.container && a.healthcheck_none) {
        out.push(warn(
            NO_HEALTHCHECK,
            format!(
                "app `{}` sets healthcheck none; its container has no HEALTHCHECK",
                app.id
            ),
        ));
    }
    out.extend(pin_table_stale(root, today, PIN_VERIFICATION_DAYS));
    Ok(out)
}

/// `stack.pin-table-stale` on `today`: the checkout's table in this
/// repository (it carries `templates/stack-packs/pins.json`), the embedded one
/// elsewhere. A table that does not load is reported `unverified`.
pub fn pin_table_stale(root: &Path, today: NaiveDate, limit_days: u32) -> Option<String> {
    let table = if root.join(PINS_PATH).is_file() {
        PinTable::from_checkout(root)
    } else {
        PinTable::embedded()
    };
    match table {
        Ok(table) => table
            .stale_finding(today, limit_days)
            .map(|text| format!("WARNING: {text}")),
        Err(error) => Some(unverified(PIN_TABLE_STALE, PINS_PATH, &error.to_string())),
    }
}

/// The image rules over one Dockerfile's text, `path` naming it: every `FROM`
/// of an image (not `scratch`, not an earlier stage) by digest and not
/// `latest`; the final stage's `USER` numeric and not root; every `COPY` and
/// `ADD` of the final stage owned by group 0 (`--chown=<user>:0`).
pub fn dockerfile(path: &str, text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut stages: BTreeSet<String> = BTreeSet::new();
    let mut final_stage: Vec<(String, String)> = Vec::new();
    for (keyword, args) in instructions(text) {
        if keyword != "FROM" {
            final_stage.push((keyword, args));
            continue;
        }
        final_stage.clear();
        let mut words = args.split_whitespace().filter(|w| !w.starts_with("--"));
        let image = words.next().unwrap_or_default();
        if let (Some(r#as), Some(name)) = (words.next(), words.next())
            && r#as.eq_ignore_ascii_case("as")
        {
            stages.insert(name.to_ascii_lowercase());
        }
        let lower = image.to_ascii_lowercase();
        if lower == "scratch" || stages.contains(&lower) {
            continue;
        }
        match image.split_once("@sha256:") {
            None => out.push(warn(
                IMAGE_BY_DIGEST,
                format!("{path} FROM {image} has no @sha256: digest"),
            )),
            Some((reference, _)) if tag(reference) == Some("latest") => out.push(warn(
                IMAGE_BY_DIGEST,
                format!("{path} FROM {image} uses latest"),
            )),
            Some(_) => {}
        }
    }
    let user = final_stage
        .iter()
        .rev()
        .find(|(keyword, _)| keyword == "USER")
        .map(|(_, args)| args.as_str());
    match user {
        None => out.push(warn(
            IMAGE_NONROOT,
            format!("{path} final stage has no USER"),
        )),
        Some(user) => {
            let name = user.split(':').next().unwrap_or_default();
            if name == "root" || name == "0" {
                out.push(warn(
                    IMAGE_NONROOT,
                    format!("{path} final stage runs as root (USER {user})"),
                ));
            } else if !name.chars().all(|c| c.is_ascii_digit()) {
                out.push(warn(
                    IMAGE_ARBITRARY_UID,
                    format!(
                        "{path} final stage runs as named user `{name}`, which needs /etc/passwd; use a numeric UID in group 0"
                    ),
                ));
            }
        }
    }
    for (keyword, args) in final_stage
        .iter()
        .filter(|(keyword, _)| keyword == "COPY" || keyword == "ADD")
    {
        let group_zero = args
            .split_whitespace()
            .filter_map(|w| w.strip_prefix("--chown="))
            .any(|owner| matches!(owner.split_once(':'), Some((_, "0" | "root"))));
        if !group_zero {
            out.push(warn(
                IMAGE_ARBITRARY_UID,
                format!("{path} final stage copies without group 0 ownership: {keyword} {args}"),
            ));
        }
    }
    out
}

/// The tag of `registry/repository:tag`, if any (a registry port is not one).
fn tag(reference: &str) -> Option<&str> {
    reference
        .rsplit('/')
        .next()
        .and_then(|name| name.split_once(':'))
        .map(|(_, tag)| tag)
}

/// The instructions of a Dockerfile: keyword upper-cased and arguments with
/// whitespace collapsed, continuation lines joined, comment lines skipped.
pub(super) fn instructions(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut current = String::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || (trimmed.is_empty() && current.is_empty()) {
            continue;
        }
        match trimmed.strip_suffix('\\') {
            Some(head) => {
                current.push_str(head);
                current.push(' ');
            }
            None => {
                current.push_str(trimmed);
                let mut words = current.split_whitespace();
                if let Some(keyword) = words.next() {
                    out.push((
                        keyword.to_ascii_uppercase(),
                        words.collect::<Vec<_>>().join(" "),
                    ));
                }
                current.clear();
            }
        }
    }
    out
}

/// The apps the recorded answers name with a known stack and a path inside
/// the checkout, in app id order.
/// Shared with ci-baseline's `ci.command-missing` (#1037), which reads the same
/// apps the per-app jobs are built from.
pub(crate) fn recorded_apps(root: &Path) -> Result<Vec<RecordedApp>> {
    let Some(file) = answers::recorded(root, STACK_PACKS)? else {
        return Ok(Vec::new());
    };
    let mut fields: BTreeMap<&str, BTreeMap<&str, &Value>> = BTreeMap::new();
    for (key, value) in &file.answers {
        if let Some((id, field)) = key
            .strip_prefix("apps.")
            .and_then(|rest| rest.split_once('.'))
        {
            fields.entry(id).or_default().insert(field, value);
        }
    }
    Ok(fields
        .into_iter()
        .filter_map(|(id, fields)| {
            let path = detect::normalise(fields.get("path")?.as_str()?);
            let inside = path == "."
                || Path::new(&path)
                    .components()
                    .all(|c| matches!(c, Component::Normal(_)));
            // A symlinked app path would lead the Dockerfile walk outside the checkout.
            let real_dir = fs::symlink_metadata(root.join(&path)).is_ok_and(|m| m.is_dir());
            if !inside || !real_dir {
                return None;
            }
            let stack: StackId = fields.get("stack")?.as_str()?.parse().ok()?;
            let capable = matches!(pack(stack).container, ContainerSupport::Capable { .. });
            Some(RecordedApp {
                id: id.to_owned(),
                path,
                stack,
                container: fields
                    .get("container")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(capable),
                healthcheck_none: fields.get("healthcheck").and_then(|v| v.as_str())
                    == Some("none"),
            })
        })
        .collect())
}

fn lockfile_present(root: &Path, app: &RecordedApp) -> Option<String> {
    let lockfile = pack(app.stack).lockfile?;
    let expected: Vec<&str> = if app.stack == StackId::Node {
        PackageManager::ALL.iter().map(|pm| pm.lockfile()).collect()
    } else {
        vec![lockfile.file]
    };
    if expected.iter().any(|file| app.has(root, file)) {
        return None;
    }
    let names = match expected.split_last() {
        Some((last, [])) => (*last).to_owned(),
        Some((last, rest)) => format!("{} or {last}", rest.join(", ")),
        None => return None,
    };
    Some(warn(
        LOCKFILE_PRESENT,
        format!("{} has no {names}", app.label()),
    ))
}

/// A declared `test`/`verify` that runs the app's tool without its strict
/// lockfile flag; for node, only a command that installs (`<pm> install`,
/// `<pm> i`). A command that never names the tool (a script) is left alone.
fn lockfile_not_enforced(root: &Path, app: &RecordedApp) -> Result<Vec<String>> {
    let Some(lockfile) = pack(app.stack).lockfile else {
        return Ok(Vec::new());
    };
    let (tool, flag) = match app.stack {
        StackId::Rust => ("cargo", lockfile.strict_flag),
        StackId::PythonUv => ("uv", lockfile.strict_flag),
        StackId::Go => ("go", lockfile.strict_flag),
        StackId::Node => {
            let pm = PackageManager::ALL
                .into_iter()
                .find(|pm| app.has(root, pm.lockfile()))
                .unwrap_or(PackageManager::Npm);
            let flag = pm
                .install()
                .rsplit(' ')
                .next()
                .unwrap_or(lockfile.strict_flag);
            (pm.as_str(), flag)
        }
        _ => return Ok(Vec::new()),
    };
    let declared = detect::declared_commands(root, &app.path)?;
    Ok(ENFORCED_COMMANDS
        .iter()
        .filter_map(|name| {
            let command = declared.get(*name)?;
            let words: Vec<&str> = command
                .split(|c: char| c.is_whitespace() || ";&|()".contains(c))
                .filter(|w| !w.is_empty())
                .collect();
            let strict = words
                .iter()
                .any(|w| *w == flag || w.strip_prefix(flag).is_some_and(|r| r.starts_with('=')));
            // node's strict flag belongs to the install (`npm ci`, `--frozen-lockfile`),
            // which `ci_setup` runs first: `npm test` and `npm run <x>` carry none (#1163).
            let judged = if app.stack == StackId::Node {
                words
                    .windows(2)
                    .any(|pair| pair[0] == tool && matches!(pair[1], "install" | "i"))
            } else {
                words.contains(&tool)
            };
            (judged && !strict).then(|| {
                warn(
                    LOCKFILE_NOT_ENFORCED,
                    format!(
                        "app `{}` declares {name} `{command}` without `{flag}`",
                        app.id
                    ),
                )
            })
        })
        .collect())
}

/// A pin file (or `go.mod` line) per stack; `kotlin-android` has two, the JDK
/// the build runs on and the wrapper's checksum of the Gradle distribution it
/// downloads (Gradle user guide, "Gradle Wrapper Reference", Verification of
/// downloaded Gradle distributions), and the finding names the missing ones.
fn toolchain_pinned(root: &Path, app: &RecordedApp) -> Option<String> {
    let line_in = |file: &str, start: &str| {
        fs::read_to_string(root.join(format!("{}{file}", app.prefix())))
            .is_ok_and(|text| text.lines().any(|l| l.trim_start().starts_with(start)))
    };
    let wrapper = "gradle/wrapper/gradle-wrapper.properties";
    let pins: Vec<(bool, String)> = match app.stack {
        StackId::Rust => vec![(
            app.has(root, "rust-toolchain.toml") || app.has(root, "rust-toolchain"),
            "rust-toolchain.toml".to_owned(),
        )],
        StackId::PythonUv => vec![(
            app.has(root, ".python-version"),
            ".python-version".to_owned(),
        )],
        StackId::Node => vec![(
            app.has(root, ".nvmrc") || app.has(root, ".node-version"),
            ".nvmrc or .node-version".to_owned(),
        )],
        StackId::Go => vec![(
            line_in("go.mod", "toolchain "),
            "go.mod toolchain".to_owned(),
        )],
        StackId::KotlinAndroid => vec![
            (app.has(root, ".java-version"), ".java-version".to_owned()),
            (
                line_in(wrapper, "distributionSha256Sum="),
                format!("distributionSha256Sum in {wrapper}"),
            ),
        ],
        StackId::SwiftIos => vec![(app.has(root, ".xcode-version"), ".xcode-version".to_owned())],
        StackId::SqlDbt => vec![(
            app.has(root, ".python-version"),
            ".python-version".to_owned(),
        )],
    };
    let missing: Vec<String> = pins
        .into_iter()
        .filter_map(|(present, name)| (!present).then_some(name))
        .collect();
    (!missing.is_empty()).then(|| {
        warn(
            TOOLCHAIN_PINNED,
            format!(
                "{} has no toolchain pin ({})",
                app.label(),
                missing.join(", ")
            ),
        )
    })
}

/// Every Dockerfile (`Dockerfile`, `Dockerfile.<x>`, `<x>.Dockerfile`) under
/// `dir`, skipping hidden directories, the walk's skipped ones, symlinks and
/// the profile's `excluded_paths` (#16).
pub(super) fn collect_dockerfiles(root: &Path, dir: &str, found: &mut BTreeSet<String>) {
    let excluded = crate::profile::excluded_paths_at(root);
    walk_dockerfiles(root, dir, &excluded, found);
}

fn walk_dockerfiles(root: &Path, dir: &str, excluded: &[String], found: &mut BTreeSet<String>) {
    let Ok(entries) = fs::read_dir(root.join(dir)) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let rel = if dir == "." {
            name.clone()
        } else {
            format!("{dir}/{name}")
        };
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir() {
            if !name.starts_with('.')
                && !detect::SKIPPED.contains(&name.as_str())
                && !crate::profile::is_excluded(excluded, &rel)
            {
                walk_dockerfiles(root, &rel, excluded, found);
            }
        } else if kind.is_file()
            && !crate::profile::is_excluded(excluded, &rel)
            && (name == "Dockerfile"
                || name.starts_with("Dockerfile.")
                || name.ends_with(".Dockerfile"))
        {
            found.insert(rel);
        }
    }
}
