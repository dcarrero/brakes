//! Detection that proposes (SPEC-stack-packs.md, Evidence and proposals): the
//! files that exist suggest packs, a few manifest fields read by hand are the
//! evidence, and the pack's commands are proposed for the `null` fields of the
//! app's profile only. Filesystem reads only: no command, no network, no TOML
//! dependency, and nothing is written. `configure <repo> stack-packs` with no
//! flags prints the block; `doctor` reports it as `stack.unconfigured` while no
//! answers record a detected stack.
use crate::{
    PROFILE, Result, engine::answers, engine::answers::Answers, modules::qa, profile::profile_for,
};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use super::{
    App, ContainerSupport, Evidence, PackageManager, STACK_PACKS, StackId, StackPack,
    packs::{ALL, node::NodeRunner, proposals, proposals_from, swift_ios::SWIFTPM},
};

/// Directories the root walk never enters: tool output, dependency caches, test
/// fixtures (`fixtures`, Go's `testdata`) and hidden directories (`.git`,
/// `.venv`, `.agent-setup`). A declared app path is scanned wherever it is.
pub(super) const SKIPPED: [&str; 9] = [
    "target",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "__pycache__",
    "venv",
    "fixtures",
    "testdata",
];

const HEADER: &str = "stack-packs: proposals (nothing written; confirm with --set or --answers)";
const NO_RUNNER: &str = "no known test runner (vitest, jest, @playwright/test in devDependencies, or node --test in scripts.test); qa asks for it";
const NO_SCHEME: &str = "xcodebuild test needs a scheme and none is proposed: share exactly one scheme in the project, or declare commands.test with -scheme <name>";
const GRADLE_WRAPPER: &str = "gradle/wrapper/gradle-wrapper.properties";
const NO_SQLFLUFF: &str = "sqlfluff lint is not proposed: no .sqlfluff declares the dialect and the templater; add one or declare commands.lint";
const COMMANDS: [&str; 4] = ["build", "test", "lint", "verify"];

/// A command line of a proposal: kept as the profile declares it, or proposed
/// by the pack for a `null` field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommandLine {
    Declared(String),
    Proposed(String),
}

/// One pack whose evidence is complete at one path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proposal {
    /// The recorded id of the app at `path`, else `root` or the directory name.
    pub id: String,
    pub path: String,
    pub stack: StackId,
    /// The answers record this stack at this path.
    pub recorded: bool,
    pub evidence: Vec<String>,
    pub commands: Vec<(&'static str, CommandLine)>,
    pub seeds: Vec<String>,
    /// Lines the block prints as `info:` (a node app with no known test runner).
    pub info: Vec<String>,
}

/// A pack with some of its evidence at the root or a declared app path, named
/// with the first file missing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotProposed {
    pub stack: StackId,
    pub path: String,
    pub missing: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Detection {
    pub proposals: Vec<Proposal>,
    pub not_proposed: Vec<NotProposed>,
}

/// A recorded app as detection needs it: raw answers, unvalidated, so a stale
/// answers file never stops a read-only report.
struct Declared<'a> {
    id: &'a str,
    stack: Option<&'a str>,
    container: Option<bool>,
    toolchain: Option<bool>,
}

/// Scans the root (walking it) and each declared app path (that directory
/// only); a directory inside a declared app other than `.` is not re-scanned
/// for the root, and neither is a web directory `qa` seeds (#1238). Every
/// pack is detected.
pub fn propose(root: &Path, answers: &Answers) -> Result<Detection> {
    let mut declared: BTreeMap<String, Declared<'_>> = BTreeMap::new();
    let mut ids: BTreeMap<&str, BTreeMap<&str, &Value>> = BTreeMap::new();
    for (key, value) in answers {
        if let Some((id, field)) = key
            .strip_prefix("apps.")
            .and_then(|rest| rest.split_once('.'))
        {
            ids.entry(id).or_default().insert(field, value);
        }
    }
    for (id, fields) in &ids {
        if let Some(path) = fields.get("path").and_then(|v| v.as_str()) {
            declared.insert(
                normalise(path),
                Declared {
                    id,
                    stack: fields.get("stack").and_then(|v| v.as_str()),
                    container: fields.get("container").and_then(|v| v.as_bool()),
                    toolchain: fields.get("toolchain").and_then(|v| v.as_bool()),
                },
            );
        }
    }
    let seeded = qa::audit::seeded_web_dirs(root);
    let mut dirs = vec![".".to_owned()];
    walk(root, "", &declared, &seeded, &mut dirs)?;
    dirs.extend(
        declared
            .keys()
            .filter(|path| path.as_str() != "." && root.join(path).is_dir())
            .cloned(),
    );
    let mut detection = Detection::default();
    let mut used: BTreeSet<String> = declared.values().map(|d| d.id.to_owned()).collect();
    for dir in dirs {
        let scanned = dir == "." || declared.contains_key(&dir);
        for pack in ALL {
            match missing(root, &dir, pack) {
                None => {
                    let proposal = proposal(root, &dir, pack, declared.get(&dir), &mut used)?;
                    detection.proposals.push(proposal);
                }
                Some((true, file)) if scanned => detection.not_proposed.push(NotProposed {
                    stack: pack.id,
                    path: dir.clone(),
                    missing: file,
                }),
                Some(_) => {}
            }
        }
    }
    Ok(detection)
}

impl Detection {
    /// The block `configure` prints and `doctor` carries.
    pub fn block(&self) -> String {
        let mut out = format!("{HEADER}\n");
        if self.proposals.is_empty() {
            out.push_str("  no stack evidence found\n");
        }
        for p in &self.proposals {
            let recorded = if p.recorded { " (recorded)" } else { "" };
            out.push_str(&format!(
                "  app `{}` at `{}`: stack {}{recorded}\n    evidence: {}\n",
                p.id,
                p.path,
                p.stack,
                p.evidence.join(", ")
            ));
            if !p.commands.is_empty() {
                out.push_str("    commands (project.json fields already declared are kept; proposed only for null):\n");
            }
            for (name, line) in &p.commands {
                let (kind, command) = match line {
                    CommandLine::Declared(c) => ("declared", c),
                    CommandLine::Proposed(c) => ("proposed", c),
                };
                out.push_str(&format!(
                    "      {:<8}{kind:<10}\"{command}\"\n",
                    format!("{name}:")
                ));
            }
            if !p.seeds.is_empty() {
                out.push_str(&format!("    seeds on apply: {}\n", p.seeds.join(", ")));
            }
            for line in &p.info {
                out.push_str(&format!("    info: {line}\n"));
            }
        }
        if !self.not_proposed.is_empty() {
            let names: Vec<String> = self
                .not_proposed
                .iter()
                .map(|n| match n.path.as_str() {
                    "." => format!("{} (no {} found)", n.stack, n.missing),
                    path => format!("{} at `{path}` (no {} found)", n.stack, n.missing),
                })
                .collect();
            out.push_str(&format!("  not proposed: {}\n", names.join(", ")));
        }
        out
    }
}

/// The proposal block for `root` against its recorded answers.
pub fn proposal_block(root: &Path) -> Result<String> {
    Ok(propose(root, &recorded(root)?)?.block())
}

/// `stack.unconfigured` (a warning): some detected stack is not recorded by the
/// answers; the proposal block is the evidence. A detection refusal (two node
/// lockfiles) is reported in its place, so `doctor` keeps going.
pub fn unconfigured(root: &Path) -> Result<Option<String>> {
    let detection = match propose(root, &recorded(root)?) {
        Ok(detection) => detection,
        Err(error) => {
            return Ok(Some(format!(
                "WARNING: stack.unconfigured: detection refused: {error}"
            )));
        }
    };
    Ok(detection
        .proposals
        .iter()
        .any(|p| !p.recorded)
        .then(|| {
            format!(
                "WARNING: stack.unconfigured: a stack is detected that no stack-packs answers record\n{}",
                detection.block().trim_end()
            )
        }))
}

fn recorded(root: &Path) -> Result<Answers> {
    Ok(answers::recorded(root, STACK_PACKS)?
        .map(|file| file.answers)
        .unwrap_or_default())
}

/// `raw` as the answers normalise an app path: no `./`, no trailing `/`.
pub(super) fn normalise(raw: &str) -> String {
    let trimmed = raw.trim_end_matches('/');
    let trimmed = trimmed.strip_prefix("./").unwrap_or(trimmed);
    if trimmed.is_empty() { "." } else { trimmed }.to_owned()
}

/// Every directory under `rel` (sorted, symlinks not followed), skipping the
/// subtrees of declared apps other than `.` and of `seeded`, the web
/// directories `qa` seeds: a test harness, not an app (#1238).
fn walk(
    root: &Path,
    rel: &str,
    declared: &BTreeMap<String, Declared<'_>>,
    seeded: &[String],
    dirs: &mut Vec<String>,
) -> Result<()> {
    let mut entries: Vec<_> =
        fs::read_dir(root.join(rel).join("."))?.collect::<std::io::Result<_>>()?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !entry.file_type()?.is_dir() || name.starts_with('.') || SKIPPED.contains(&name.as_str())
        {
            continue;
        }
        let path = format!("{rel}{name}");
        if declared.contains_key(&path) || seeded.contains(&path) {
            continue;
        }
        dirs.push(path.clone());
        walk(root, &format!("{path}/"), declared, seeded, dirs)?;
    }
    Ok(())
}

fn prefix(dir: &str) -> String {
    if dir == "." {
        String::new()
    } else {
        format!("{dir}/")
    }
}

fn present(root: &Path, dir: &str, file: &str) -> bool {
    file_present(root, &prefix(dir), file)
}

/// A pack's evidence file at `prefix`: a regular file of that name, or, for
/// `*.<ext>`, any directory entry with that suffix (an `.xcodeproj` is a
/// directory). Shared with the answers' evidence check.
pub(super) fn file_present(root: &Path, prefix: &str, file: &str) -> bool {
    match file.strip_prefix('*') {
        Some(suffix) => entries_with_suffix(root, prefix, suffix)
            .map(|names| !names.is_empty())
            .unwrap_or(false),
        None => root.join(format!("{prefix}{file}")).is_file(),
    }
}

/// The entries of the directory at `prefix` whose name ends with `suffix`,
/// sorted; `None` when the directory cannot be read.
fn entries_with_suffix(root: &Path, prefix: &str, suffix: &str) -> Option<Vec<String>> {
    let entries = fs::read_dir(root.join(prefix).join(".")).ok()?;
    let mut names: Vec<String> = entries
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(suffix))
        .collect();
    names.sort();
    Some(names)
}

/// `None` when the pack's evidence is complete at `dir`; otherwise whether any
/// of it is present and the first file missing.
fn missing(root: &Path, dir: &str, pack: &StackPack) -> Option<(bool, String)> {
    let mut any = false;
    let mut first = None;
    for evidence in pack.evidence {
        match evidence {
            Evidence::AllOf(files) => {
                for file in *files {
                    if present(root, dir, file) {
                        any = true;
                    } else {
                        first.get_or_insert_with(|| (*file).to_owned());
                    }
                }
            }
            Evidence::AnyOf(files) => {
                if files.iter().any(|f| present(root, dir, f)) {
                    any = true;
                } else {
                    first.get_or_insert_with(|| files.join(" or "));
                }
            }
        }
    }
    first.map(|file| (any, file))
}

/// What the manifests at an app path say: the evidence strings, the node
/// package manager (from its lockfile) and the node scripts that exist.
#[derive(Default)]
struct Manifests {
    evidence: Vec<String>,
    package_manager: Option<PackageManager>,
    scripts: Vec<&'static str>,
    runner: Option<NodeRunner>,
    /// A swift-ios app has an Xcode project (else it is a Swift package).
    xcode_project: bool,
    /// The one scheme the one Xcode project shares, if exactly one.
    scheme: Option<String>,
    /// A sql-dbt app has a `.sqlfluff` (dialect and templater) to lint with.
    sqlfluff: bool,
}

/// Reads the few fields the spec names, by hand: `[workspace]` and
/// `rust-version`, `requires-python` and `.python-version`, `packageManager`,
/// `engines.node` and `scripts.*`, the `go` and `toolchain` directives, the
/// Gradle wrapper's distribution version and checksum and `.java-version`,
/// the shared schemes of each Xcode project and `.xcode-version`, `name`,
/// `profile` and `require-dbt-version` of `dbt_project.yml`, the packages
/// files and `.sqlfluff`'s `dialect` and `templater`.
fn manifests(root: &Path, dir: &str, stack: StackId) -> Result<Manifests> {
    let read = |file: &str| -> Result<Option<String>> {
        crate::read(root, &format!("{}{file}", prefix(dir)))
    };
    let mut found = Manifests::default();
    match stack {
        StackId::Rust => {
            let manifest = read("Cargo.toml")?.unwrap_or_default();
            let mut fields = Vec::new();
            if manifest.lines().any(|line| line.trim() == "[workspace]") {
                fields.push("workspace".to_owned());
            }
            fields.extend(toml_string(&manifest, "rust-version"));
            found.evidence.push(annotated("Cargo.toml", &fields));
            found.evidence.push("Cargo.lock".to_owned());
        }
        StackId::PythonUv => {
            let manifest = read("pyproject.toml")?.unwrap_or_default();
            let fields: Vec<String> = toml_string(&manifest, "requires-python")
                .into_iter()
                .collect();
            found.evidence.push(annotated("pyproject.toml", &fields));
            found.evidence.push("uv.lock".to_owned());
            if let Some(version) = read(".python-version")? {
                found
                    .evidence
                    .push(format!(".python-version ({})", version.trim()));
            }
        }
        StackId::Node => {
            let lockfiles: Vec<&str> = PackageManager::ALL
                .iter()
                .map(|pm| pm.lockfile())
                .filter(|file| present(root, dir, file))
                .collect();
            found.package_manager = PackageManager::from_lockfiles(&lockfiles)
                .map_err(|error| format!("{error} (at `{dir}`)"))?;
            let text = read("package.json")?.unwrap_or_default();
            let mut fields = Vec::new();
            match serde_json::from_str::<Value>(&text) {
                Ok(manifest) => {
                    if let Some(pm) = manifest["packageManager"].as_str() {
                        fields.push(format!("packageManager = \"{pm}\""));
                    }
                    if let Some(node) = manifest["engines"]["node"].as_str() {
                        fields.push(format!("engines.node = \"{node}\""));
                    }
                    if let Some(scripts) = manifest["scripts"].as_object() {
                        found.scripts = ["build", "lint", "test"]
                            .into_iter()
                            .filter(|name| scripts.contains_key(*name))
                            .collect();
                    }
                    if !found.scripts.is_empty() {
                        fields.push(format!("scripts: {}", found.scripts.join(", ")));
                    }
                    found.runner = runner_of(&manifest);
                    if let Some(runner) = found.runner {
                        fields.push(format!("test runner: {runner}"));
                    }
                }
                Err(_) => fields.push("not valid JSON".to_owned()),
            }
            found.evidence.push(annotated("package.json", &fields));
            found
                .evidence
                .extend(lockfiles.iter().map(|f| (*f).to_owned()));
        }
        StackId::Go => {
            let manifest = read("go.mod")?.unwrap_or_default();
            let fields: Vec<String> = manifest
                .lines()
                .map(str::trim)
                .filter(|line| line.starts_with("go ") || line.starts_with("toolchain "))
                .map(str::to_owned)
                .collect();
            found.evidence.push(annotated("go.mod", &fields));
            found.evidence.push("go.sum".to_owned());
        }
        StackId::KotlinAndroid => {
            for file in ["settings.gradle.kts", "build.gradle.kts", "gradlew"] {
                if present(root, dir, file) {
                    found.evidence.push(file.to_owned());
                }
            }
            if let Some(text) = read(GRADLE_WRAPPER)? {
                let mut fields: Vec<String> = gradle_version(&text)
                    .map(|version| format!("gradle {version}"))
                    .into_iter()
                    .collect();
                let checksum = text
                    .lines()
                    .any(|line| line.trim_start().starts_with("distributionSha256Sum="));
                fields.push(if checksum {
                    "distributionSha256Sum".to_owned()
                } else {
                    "no distributionSha256Sum".to_owned()
                });
                found.evidence.push(annotated(GRADLE_WRAPPER, &fields));
            }
            if let Some(version) = read(".java-version")? {
                found
                    .evidence
                    .push(format!(".java-version ({})", version.trim()));
            }
        }
        StackId::SwiftIos => {
            let projects =
                entries_with_suffix(root, &prefix(dir), ".xcodeproj").unwrap_or_default();
            let mut schemes_of_one = None;
            for project in &projects {
                let schemes = entries_with_suffix(
                    root,
                    &format!("{}{project}/xcshareddata/xcschemes/", prefix(dir)),
                    ".xcscheme",
                )
                .unwrap_or_default();
                let names: Vec<String> = schemes
                    .iter()
                    .map(|s| s.trim_end_matches(".xcscheme").to_owned())
                    .collect();
                let field = if names.is_empty() {
                    "no shared schemes".to_owned()
                } else {
                    format!("shared schemes: {}", names.join(", "))
                };
                found.evidence.push(annotated(project, &[field]));
                if let [one] = names.as_slice() {
                    schemes_of_one = Some(one.clone());
                }
            }
            found.xcode_project = !projects.is_empty();
            found.scheme = schemes_of_one.filter(|_| projects.len() == 1);
            if present(root, dir, "Package.swift") {
                found.evidence.push("Package.swift".to_owned());
            }
            if let Some(version) = read(".xcode-version")? {
                found
                    .evidence
                    .push(format!(".xcode-version ({})", version.trim()));
            }
        }
        StackId::SqlDbt => {
            let project = read("dbt_project.yml")?.unwrap_or_default();
            let fields: Vec<String> = ["name", "profile", "require-dbt-version"]
                .into_iter()
                .filter_map(|key| yaml_scalar(&project, key))
                .collect();
            found.evidence.push(annotated("dbt_project.yml", &fields));
            for file in ["packages.yml", "dependencies.yml", "package-lock.yml"] {
                if present(root, dir, file) {
                    found.evidence.push(file.to_owned());
                }
            }
            if let Some(config) = read(".sqlfluff")? {
                let fields: Vec<String> = ["dialect", "templater"]
                    .into_iter()
                    .filter_map(|key| ini_value(&config, key))
                    .collect();
                found.evidence.push(annotated(".sqlfluff", &fields));
                found.sqlfluff = true;
            }
            if let Some(version) = read(".python-version")? {
                found
                    .evidence
                    .push(format!(".python-version ({})", version.trim()));
            }
        }
    }
    Ok(found)
}

/// The first top-level `key: value` of a YAML text as `key = "value"`, quotes
/// stripped; matched by hand (no YAML dependency), so nested keys and
/// block values are skipped.
fn yaml_scalar(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let value = line.strip_prefix(key)?.strip_prefix(':')?.trim();
        let value = value.split(" #").next()?.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
            .unwrap_or(value);
        (!value.is_empty() && !value.starts_with('[') && !value.starts_with('{'))
            .then(|| format!("{key} = \"{value}\""))
    })
}

/// The first `key = value` line of an INI text as `key = value`.
fn ini_value(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let value = line
            .trim()
            .strip_prefix(key)?
            .trim_start()
            .strip_prefix('=')?
            .trim();
        (!value.is_empty()).then(|| format!("{key} = {value}"))
    })
}

/// The Gradle version of the wrapper's `distributionUrl`
/// (`…/gradle-<version>-bin.zip` or `-all.zip`), if the line is there.
fn gradle_version(properties: &str) -> Option<String> {
    let url = properties.lines().find_map(|line| {
        line.trim_start()
            .strip_prefix("distributionUrl")?
            .trim_start()
            .strip_prefix('=')
    })?;
    let file = url.trim().rsplit('/').next()?;
    let version = file
        .strip_prefix("gradle-")?
        .trim_end_matches(".zip")
        .trim_end_matches("-bin")
        .trim_end_matches("-all");
    (!version.is_empty()).then(|| version.to_owned())
}

fn proposal(
    root: &Path,
    dir: &str,
    pack: &StackPack,
    declared: Option<&Declared<'_>>,
    used: &mut BTreeSet<String>,
) -> Result<Proposal> {
    let Manifests {
        evidence,
        package_manager,
        scripts,
        runner,
        xcode_project,
        scheme,
        sqlfluff,
    } = manifests(root, dir, pack.id)?;
    let app = App {
        id: String::new(),
        path: dir.to_owned(),
        stack: pack.id,
        container: false,
        toolchain: false,
        package_manager,
        declared: BTreeMap::new(),
    };
    let mut proposed = proposals(pack, &app);
    if pack.id == StackId::Node {
        // `lint` and `build` only for scripts that exist; `verify` follows `lint`.
        for name in ["build", "lint"] {
            if !scripts.contains(&name) {
                proposed.remove(name);
            }
        }
        if let (false, Some(test)) = (proposed.contains_key("lint"), proposed.get("test")) {
            proposed.insert("verify", test.clone());
        }
    }
    let mut info = Vec::new();
    if pack.id == StackId::SqlDbt && !sqlfluff {
        // `sqlfluff lint` refuses without a dialect; the project's `.sqlfluff`
        // carries it and the dbt templater.
        proposed.remove("lint");
        if let Some(test) = proposed.get("test") {
            proposed.insert("verify", test.clone());
        }
        info.push(NO_SQLFLUFF.to_owned());
    }
    if pack.id == StackId::SwiftIos {
        // A scheme is never invented: the one the project shares fills
        // `{{scheme}}`; a package without a project needs none.
        match (xcode_project, &scheme) {
            (false, _) => proposed = proposals_from(&SWIFTPM, &app),
            (true, Some(scheme)) => {
                for command in proposed.values_mut() {
                    *command = command.replace("{{scheme}}", scheme);
                }
            }
            (true, None) => {
                proposed.clear();
                info.push(NO_SCHEME.to_owned());
            }
        }
    }
    let profile = declared_commands(root, dir)?;
    let commands = COMMANDS
        .into_iter()
        .filter_map(|name| match profile.get(name) {
            Some(command) => Some((name, CommandLine::Declared(command.clone()))),
            None => proposed
                .remove(name)
                .map(|command| (name, CommandLine::Proposed(command))),
        })
        .collect();
    let recorded = declared.is_some_and(|d| d.stack == Some(pack.id.as_str()));
    let capable = matches!(pack.container, ContainerSupport::Capable { .. });
    let toolchain = declared
        .filter(|_| recorded)
        .and_then(|d| d.toolchain)
        .unwrap_or(pack.id != StackId::Rust);
    let container = declared
        .filter(|_| recorded)
        .and_then(|d| d.container)
        .unwrap_or(capable);
    let mut seeds = Vec::new();
    if let (true, Some(seed)) = (toolchain, pack.toolchain_seed) {
        seeds.push(format!("{}{}", prefix(dir), seed.path));
    }
    if container && capable {
        seeds.push(format!("{}Dockerfile", prefix(dir)));
        seeds.push(format!("{}.dockerignore", prefix(dir)));
    }
    if pack.id == StackId::Node && runner.is_none() {
        info.push(NO_RUNNER.to_owned());
    }
    Ok(Proposal {
        id: app_id(dir, pack.id, declared, used),
        path: dir.to_owned(),
        stack: pack.id,
        recorded,
        evidence,
        commands,
        seeds,
        info,
    })
}

/// The test runner of the node app at `dir` (data for `qa`): the first of
/// `NodeRunner::ALL` its `package.json` names, by `devDependencies` name or,
/// for `node:test`, `node --test` in `scripts.test`. `None` when it names none,
/// is absent or is not valid JSON; `qa` then asks.
pub fn node_runner(root: &Path, dir: &str) -> Result<Option<NodeRunner>> {
    let text = crate::read(root, &format!("{}package.json", prefix(dir)))?;
    Ok(text
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .and_then(|manifest| runner_of(&manifest)))
}

fn runner_of(manifest: &Value) -> Option<NodeRunner> {
    let dev = manifest["devDependencies"].as_object();
    let test = manifest["scripts"]["test"].as_str().unwrap_or("");
    NodeRunner::ALL
        .into_iter()
        .find(|runner| match runner.dev_dependency() {
            Some(name) => dev.is_some_and(|dev| dev.contains_key(name)),
            None => test.contains("node --test"),
        })
}

/// The recorded id at `dir`, else `root` or the directory name (characters an
/// answers key cannot hold become `-`), suffixed with the stack when taken.
fn app_id(
    dir: &str,
    stack: StackId,
    declared: Option<&Declared<'_>>,
    used: &mut BTreeSet<String>,
) -> String {
    if let Some(d) = declared {
        return d.id.to_owned();
    }
    let base: String = match dir {
        "." => "root".to_owned(),
        _ => dir
            .rsplit('/')
            .next()
            .unwrap_or(dir)
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                    c
                } else {
                    '-'
                }
            })
            .collect(),
    };
    let id = if used.contains(&base) {
        format!("{base}-{stack}")
    } else {
        base
    };
    used.insert(id.clone());
    id
}

/// `file (a, b)`, or the bare name when no field was read.
fn annotated(file: &str, fields: &[String]) -> String {
    if fields.is_empty() {
        file.to_owned()
    } else {
        format!("{file} ({})", fields.join(", "))
    }
}

/// The first `key = "value"` line of a TOML text, as `key = "value"`; matched
/// by hand (no TOML dependency), so `key.workspace = true` does not match.
fn toml_string(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let value = line
            .trim()
            .strip_prefix(key)?
            .trim_start()
            .strip_prefix('=')?;
        Some(format!("{key} = {}", value.trim()))
    })
}

/// The declared (non-null) `commands.*` of the app's profile: the root
/// `project.json` for `.`, `<path>/.agent-setup/project.json` for an app
/// (decision 2026-10-28, per-app profiles).
pub(super) fn declared_commands(root: &Path, dir: &str) -> Result<BTreeMap<String, String>> {
    let commands = if dir == "." {
        profile_for(root)?.value["commands"].clone()
    } else {
        match crate::read(root, &format!("{dir}/{PROFILE}"))? {
            Some(text) => serde_json::from_str::<Value>(&text)?["commands"].clone(),
            None => Value::Null,
        }
    };
    Ok(commands
        .as_object()
        .map(|object| {
            object
                .iter()
                .filter_map(|(name, value)| Some((name.clone(), value.as_str()?.to_owned())))
                .collect()
        })
        .unwrap_or_default())
}

/// What `configure <repo> stack-packs --accept-commands [<app-id>]` writes: the
/// app's profile, its text before (`None`: absent) and after.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accepted {
    /// `accept commands of app …` line naming the proposal accepted.
    pub heading: String,
    pub path: String,
    pub before: Option<String>,
    pub after: String,
}

impl Accepted {
    /// The heading and, when the profile changes, a line diff of it.
    pub fn diff(&self) -> String {
        let mut out = format!("{}\n", self.heading);
        if !self.changed() {
            return out;
        }
        let from = if self.before.is_some() {
            self.path.as_str()
        } else {
            "/dev/null"
        };
        out.push_str(&format!("--- {from}\n+++ {}\n", self.path));
        // Filling a `null` never adds or removes a line: changed lines pair up.
        let before: Vec<&str> = self.before.as_deref().unwrap_or("").lines().collect();
        for (i, line) in self.after.lines().enumerate() {
            match before.get(i) {
                Some(old) if *old == line => {}
                Some(old) => out.push_str(&format!("-{old}\n+{line}\n")),
                None => out.push_str(&format!("+{line}\n")),
            }
        }
        out
    }

    pub fn changed(&self) -> bool {
        self.before.as_deref() != Some(self.after.as_str())
    }
}

/// Fills the `null` `commands.*` fields of the app's profile with the commands
/// detection proposes for it: the root `project.json` without `app`, else
/// `<path>/.agent-setup/project.json` of the proposal with that id (created
/// from the default profile when absent). Nothing is written here.
pub fn accept_commands(root: &Path, app: Option<&str>) -> Result<Accepted> {
    let detection = propose(root, &recorded(root)?)?;
    let chosen: Vec<&Proposal> = detection
        .proposals
        .iter()
        .filter(|p| app.map_or(p.path == ".", |id| p.id == id))
        .collect();
    let proposal = match (chosen.as_slice(), app) {
        ([one], _) => *one,
        ([], Some(id)) => {
            return crate::refuse(format!(
                "stack-packs: no proposal for app `{id}`; `configure <repo> stack-packs` lists them"
            ));
        }
        ([], None) => {
            return crate::refuse(
                "stack-packs: no proposal at `.`; name an app with --accept-commands <app-id>",
            );
        }
        (many, _) => {
            let ids: Vec<&str> = many.iter().map(|p| p.id.as_str()).collect();
            return crate::refuse(format!(
                "stack-packs: several stacks are proposed at `.` ({}); name one with --accept-commands <app-id>",
                ids.join(", ")
            ));
        }
    };
    let path = match proposal.path.as_str() {
        "." => PROFILE.to_owned(),
        dir => format!("{dir}/{PROFILE}"),
    };
    let fills: Vec<(&str, &str)> = proposal
        .commands
        .iter()
        .filter_map(|(name, line)| match line {
            CommandLine::Proposed(command) => Some((*name, command.as_str())),
            CommandLine::Declared(_) => None,
        })
        .collect();
    let before = crate::read(root, &path)?;
    let text = before.as_deref().unwrap_or(crate::profile::default_json());
    let after = crate::profile::fill_null_commands(text, &path, &fills)?;
    Ok(Accepted {
        heading: format!(
            "stack-packs: accept commands of app `{}` at `{}` (stack {})",
            proposal.id, proposal.path, proposal.stack
        ),
        path,
        before,
        after,
    })
}
