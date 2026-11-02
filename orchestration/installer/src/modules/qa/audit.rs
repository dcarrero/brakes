//! The static Bronze `qa.*` rules (`SPEC-qa.md`, "Auditor rules this module
//! enables" and "How `doctor` reports the static rules"; T10, #1008):
//! evaluated locally over every workflow under `.github/workflows/`, owned or
//! not, through the walker of `auditor/workflows.rs`, and line-wise over the
//! `.hurl` files, every `package.json` within three directory levels and the
//! Playwright configs beside them (`node_modules` never entered). A failed rule
//! is `WARNING: qa.<rule-id>: <text>`, an unreadable file
//! `WARNING: qa.<rule-id>: unverified: <file>: <reason>`, a passed rule nothing;
//! the auditor's registry judges them from these findings at the spec's levels
//! (`auditor::catalogue::modules`), never `NOT READY`, never the exit code.
//!
//! `qa.hurl-no-literal-host` applies where a `.hurl` file exists; the other
//! three where a QA job exists: a workflow job whose `run:` calls
//! `hurl --test` or `playwright test`.
//!
//! The Silver rules (T11, #1009) are reported first, in the spec's order:
//! `qa.api-smoke-present` where a service is declared (qa's recorded answers,
//! else T4's derivation over the root, or `commands.verify` naming `hurl`),
//! `qa.web-smoke-present` where a web app is, `qa.screenshot-baseline-present`
//! for each spec that calls `toHaveScreenshot`, `qa.snapshots-protected` for
//! each `*-snapshots/` directory. The protected paths are ci-baseline's
//! answered list, else its derived default with the globs of
//! `qa::protected::{web_dirs, protected_glob}` (T8), and the gate of
//! `ci.protected-paths-gate` must hold. `qa.main-green` (T19) is not evaluated
//! here.
use super::{
    DEFAULT_QA_DIR, QA, Qa, QaAnswers, Web, contracts, detect,
    hurl::host_finding,
    protected::{self, protected_glob, web_dirs},
};
use crate::{
    Source,
    auditor::{
        Cx, LocalFiles,
        catalogue::{
            ci_health::{self, RECENT_RUNS},
            posture::unread,
        },
        rules::Outcome,
        workflows::{Job, Parsed, Workflow, read_all, unverified, warn},
    },
    engine::{Answers, Context, Lock, Module, answers},
    modules::{
        StackPacks,
        ci_baseline::{
            CI_BASELINE, DEFAULT_HELDOUT_DIR, audit::protected_paths_gated,
            scope::default_protected_paths,
        },
        security::audit::{self as security_audit, SCREENSHOT_TARGET},
        stack_packs::STACK_PACKS,
    },
    profile_for, read,
};
use serde_json::Value;
use std::{collections::BTreeMap, fs, path::Path};

pub const HURL_NO_LITERAL_HOST: &str = "qa.hurl-no-literal-host";
pub const TOOLS_PINNED: &str = "qa.tools-pinned";
pub const NO_SNAPSHOT_UPDATE_IN_CI: &str = "qa.no-snapshot-update-in-ci";
pub const REPORT_ARTIFACT: &str = "qa.report-artifact";
pub const API_SMOKE_PRESENT: &str = "qa.api-smoke-present";
pub const WEB_SMOKE_PRESENT: &str = "qa.web-smoke-present";
pub const SCREENSHOT_BASELINE_PRESENT: &str = "qa.screenshot-baseline-present";
pub const SNAPSHOTS_PROTECTED: &str = "qa.snapshots-protected";
pub const CONTRACT_LINT: &str = "qa.contract-lint";
pub const CONTRACT_COMPATIBLE: &str = "qa.contract-compatible";

/// The finding texts of the Silver rules (the spec's).
pub const API_SMOKE_TEXT: &str = "No API smoke test: no .hurl file runs in the aggregate";
pub const WEB_SMOKE_TEXT: &str = "No web journey: no Playwright test runs in the aggregate";
pub const BASELINE_TEXT: &str =
    "Screenshot comparison without a committed baseline: the first run only writes images";
pub const PROTECTED_TEXT: &str =
    "Screenshot baselines are not a protected path: an agent can regenerate them to pass";

/// The finding text of `qa.no-snapshot-update-in-ci` (the spec's), followed by
/// where the update is.
pub const SNAPSHOT_UPDATE_TEXT: &str =
    "CI updates screenshot baselines: a broken screen can pass by rewriting its evidence";

/// Directories no search enters.
const SKIPPED_DIRS: [&str; 4] = ["node_modules", "target", "vendor", ".git"];
/// How deep `package.json` and Playwright configs are looked for (the root is 0).
const PACKAGE_DEPTH: usize = 3;
/// How deep `.hurl` files, specs and `*-snapshots/` directories are looked for.
const HURL_DEPTH: usize = 8;
/// The Playwright configuration file names.
const PLAYWRIGHT_CONFIGS: [&str; 3] = super::PLAYWRIGHT_CONFIGS;
const PLAYWRIGHT_PACKAGE: &str = "@playwright/test";
const ASYNCAPI_PACKAGE: &str = "@asyncapi/cli";
/// What marks the embedded `contracts-check.sh` in a `run:`.
const CONTRACTS_CHECK: &str = "contracts-check.sh";

/// `doctor`'s `qa.*` findings for the checkout at `root`, in the spec's rule
/// order, then file order.
pub fn diagnose(root: &Path) -> Vec<String> {
    let workflows = read_all(&LocalFiles::new(root));
    let mut out = silver(root, &workflows);
    for file in files(root, HURL_DEPTH, &|name| name.ends_with(".hurl")) {
        match read(root, &file) {
            Ok(Some(text)) => {
                out.extend(host_finding(&file, &text).map(|f| warn(HURL_NO_LITERAL_HOST, f)))
            }
            Ok(None) => {}
            Err(e) => out.push(unverified(HURL_NO_LITERAL_HOST, &file, &e.to_string())),
        }
    }
    let unread: Vec<(&str, &str)> = workflows
        .iter()
        .filter_map(|(path, wf)| wf.as_ref().err().map(|e| (path.as_str(), e.as_str())))
        .collect();
    if !has_qa_job(&workflows) {
        // Not required where no QA job exists; a workflow that cannot be read
        // may hold one, so the three rules are unverified for it.
        for rule in [TOOLS_PINNED, NO_SNAPSHOT_UPDATE_IN_CI, REPORT_ARTIFACT] {
            out.extend(unread.iter().map(|(path, e)| unverified(rule, path, e)));
        }
        return out;
    }
    let packages = packages(root);
    out.extend(tools_pinned(&workflows, &packages, &unread));
    out.extend(no_snapshot_update(root, &workflows, &unread));
    out.extend(report_artifact(&workflows, &unread));
    out
}

/// True when a readable workflow has a QA job.
pub fn has_qa_job(workflows: &Parsed) -> bool {
    workflows
        .iter()
        .filter_map(|(_, wf)| wf.as_ref().ok())
        .any(|wf| wf.jobs.iter().any(is_qa_job))
}

/// A job one of whose `run:` scripts calls `hurl --test` or `playwright test`.
pub fn is_qa_job(job: &Job) -> bool {
    job.steps
        .iter()
        .filter_map(|s| s.run.as_deref())
        .flat_map(str::lines)
        .any(|line| {
            calls_hurl_test(line)
                || calls_playwright_test(line)
                || calls_contract_lint(line)
                || calls_contract_compat(line)
        })
}

/// A word pair `first second` among the words of `line`, `first` a command
/// (`asyncapi` also as the package `npx` runs, `@asyncapi/cli[@<version>]`).
fn pair(line: &str, first: &str, second: &str) -> bool {
    words(line).windows(2).any(|w| {
        let command = is_command(w[0], first)
            || (first == "asyncapi"
                && w[0].trim_matches(['"', '\'']).starts_with(ASYNCAPI_PACKAGE));
        command && w[1] == second
    })
}

/// A contract linter, or the embedded `contracts-check.sh`.
pub fn calls_contract_lint(line: &str) -> bool {
    line.contains(CONTRACTS_CHECK)
        || pair(line, "vacuum", "lint")
        || pair(line, "spectral", "lint")
        || pair(line, "redocly", "lint")
        || pair(line, "asyncapi", "validate")
}

/// A comparison that can fail a run: `oasdiff breaking` with `--fail-on`,
/// `asyncapi diff`, or the embedded `contracts-check.sh`.
pub fn calls_contract_compat(line: &str) -> bool {
    line.contains(CONTRACTS_CHECK)
        || (pair(line, "oasdiff", "breaking") && line.contains("--fail-on"))
        || pair(line, "asyncapi", "diff")
}

/// True when a readable workflow has a job linting or comparing a contract.
pub fn has_contract_job(workflows: &Parsed) -> bool {
    has_job(workflows, calls_contract_lint) || has_job(workflows, calls_contract_compat)
}

fn words(line: &str) -> Vec<&str> {
    line.split(|c: char| c.is_whitespace() || c == ';' || c == '|' || c == '&')
        .filter(|w| !w.is_empty())
        .collect()
}

/// The word is the command `name`, alone or as the last segment of a path.
fn is_command(word: &str, name: &str) -> bool {
    word == name || word.rsplit_once('/').is_some_and(|(_, last)| last == name)
}

fn calls_hurl_test(line: &str) -> bool {
    let words = words(line);
    words.iter().any(|w| is_command(w, "hurl")) && words.contains(&"--test")
}

fn calls_playwright_test(line: &str) -> bool {
    words(line)
        .windows(2)
        .any(|pair| is_command(pair[0], "playwright") && pair[1] == "test")
}

/// Every `package.json` within [`PACKAGE_DEPTH`] levels, with its parse.
fn packages(root: &Path) -> Vec<(String, Result<Value, String>)> {
    files(root, PACKAGE_DEPTH, &|name| name == "package.json")
        .into_iter()
        .filter_map(|file| {
            let parsed = match read(root, &file) {
                Ok(Some(text)) => serde_json::from_str(&text).map_err(|e| e.to_string()),
                Ok(None) => return None,
                Err(e) => Err(e.to_string()),
            };
            Some((file, parsed))
        })
        .collect()
}

/// `qa.tools-pinned`: Hurl installed by a checksum-verified `run:` and never
/// by a marketplace action or `curl … | sh`; `@playwright/test` at an exact
/// version; `playwright install` with no version other than the package's.
fn tools_pinned(
    workflows: &Parsed,
    packages: &[(String, Result<Value, String>)],
    unread: &[(&str, &str)],
) -> Vec<String> {
    let unpinned = |name: &str, file: &str| {
        warn(
            TOOLS_PINNED,
            format!("QA tool {name} in {file} is not pinned by checksum or exact version"),
        )
    };
    let mut out = Vec::new();
    let mut exact = Vec::new();
    for (file, parsed) in packages {
        match parsed {
            Err(e) => out.push(unverified(TOOLS_PINNED, file, e)),
            Ok(package) => {
                for field in ["dependencies", "devDependencies"] {
                    if let Some(version) = package[field].get(PLAYWRIGHT_PACKAGE) {
                        match version.as_str().filter(|v| exact_version(v)) {
                            Some(v) => exact.push(v.to_owned()),
                            None => out.push(unpinned(PLAYWRIGHT_PACKAGE, file)),
                        }
                    }
                    if package[field]
                        .get(ASYNCAPI_PACKAGE)
                        .is_some_and(|v| !v.as_str().is_some_and(exact_version))
                    {
                        out.push(unpinned(ASYNCAPI_PACKAGE, file));
                    }
                }
            }
        }
    }
    for (path, wf) in workflows {
        let Ok(wf) = wf else { continue };
        for step in wf.jobs.iter().flat_map(|j| &j.steps) {
            if step
                .uses
                .as_deref()
                .is_some_and(|u| u.to_ascii_lowercase().contains("hurl"))
            {
                out.push(unpinned("hurl", path));
            }
            let Some(run) = step.run.as_deref() else {
                continue;
            };
            for tool in ["hurl", "vacuum", "oasdiff"] {
                if installs(run, tool) && (pipes_to_shell(run) || !verifies_checksum(run)) {
                    out.push(unpinned(tool, path));
                }
            }
            if run.lines().any(|line| asyncapi_unpinned(line, &step.env)) {
                out.push(unpinned(ASYNCAPI_PACKAGE, path));
            }
            if run
                .lines()
                .any(|line| install_version(line).is_some_and(|v| !exact.iter().any(|e| e == v)))
            {
                out.push(unpinned("playwright", path));
            }
        }
    }
    out.extend(
        unread
            .iter()
            .map(|(path, e)| unverified(TOOLS_PINNED, path, e)),
    );
    dedup(out)
}

/// `1.2.3` or `1.2.3-beta.1`: no range, tag or wildcard.
fn exact_version(version: &str) -> bool {
    let core = version.split_once(['-', '+']).map_or(version, |(c, _)| c);
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

/// A `run:` that downloads `tool`: a line names it and fetches with `curl` or `wget`.
fn installs(run: &str, tool: &str) -> bool {
    run.lines().any(|line| {
        let words = words(line);
        let lower = line.to_ascii_lowercase();
        lower.contains(tool)
            && words
                .iter()
                .any(|w| is_command(w, "curl") || is_command(w, "wget"))
    })
}

fn pipes_to_shell(run: &str) -> bool {
    run.lines().any(|line| {
        line.split('|')
            .skip(1)
            .filter_map(|segment| words(segment).first().copied())
            .any(|w| {
                ["sh", "bash", "zsh"]
                    .iter()
                    .any(|shell| is_command(w, shell))
            })
    })
}

fn verifies_checksum(run: &str) -> bool {
    run.lines()
        .flat_map(words)
        .any(|w| is_command(w, "sha256sum") || is_command(w, "shasum"))
}

/// A line that installs or runs `@asyncapi/cli` without an exact version,
/// inline (`@asyncapi/cli@6.2.1`) or through a variable of the step's `env:`.
fn asyncapi_unpinned(line: &str, env: &BTreeMap<String, String>) -> bool {
    let named: Vec<String> = words(line)
        .into_iter()
        .map(|w| w.trim_matches(['"', '\'']).to_owned())
        .filter(|w| w.starts_with(ASYNCAPI_PACKAGE))
        .collect();
    named.iter().any(|word| {
        let Some(version) = word.strip_prefix(&format!("{ASYNCAPI_PACKAGE}@")) else {
            return true;
        };
        let version = match version.strip_prefix('$') {
            Some(var) => env
                .get(var.trim_start_matches('{').trim_end_matches('}'))
                .map(String::as_str)
                .unwrap_or(""),
            None => version,
        };
        !exact_version(version)
    })
}

/// The version of `playwright@<version> install`, if a line names one.
fn install_version(line: &str) -> Option<&str> {
    let words = words(line);
    words.windows(2).find_map(|pair| {
        let version = pair[0].strip_prefix("playwright@")?;
        (pair[1] == "install").then_some(version)
    })
}

/// `qa.no-snapshot-update-in-ci`: no `run:` passes `--update-snapshots` or sets
/// `UPDATE_SNAPSHOTS`, no step `env:` sets it, and no Playwright config sets
/// `updateSnapshots` to anything but `'missing'` or `'none'`.
fn no_snapshot_update(root: &Path, workflows: &Parsed, unread: &[(&str, &str)]) -> Vec<String> {
    let found = |file: &str| {
        warn(
            NO_SNAPSHOT_UPDATE_IN_CI,
            format!("{SNAPSHOT_UPDATE_TEXT} ({file})"),
        )
    };
    let mut out = Vec::new();
    for (path, wf) in workflows {
        let Ok(wf) = wf else { continue };
        if updates_snapshots(wf) {
            out.push(found(path));
        }
    }
    out.extend(
        unread
            .iter()
            .map(|(path, e)| unverified(NO_SNAPSHOT_UPDATE_IN_CI, path, e)),
    );
    for file in files(root, PACKAGE_DEPTH, &|name| {
        PLAYWRIGHT_CONFIGS.contains(&name)
    }) {
        match read(root, &file) {
            Ok(Some(text)) if text.lines().any(config_updates_snapshots) => out.push(found(&file)),
            Ok(_) => {}
            Err(e) => out.push(unverified(NO_SNAPSHOT_UPDATE_IN_CI, &file, &e.to_string())),
        }
    }
    out
}

fn updates_snapshots(wf: &Workflow) -> bool {
    wf.jobs.iter().flat_map(|j| &j.steps).any(|step| {
        step.env.contains_key("UPDATE_SNAPSHOTS")
            || step.run.as_deref().is_some_and(|run| {
                run.contains("--update-snapshots") || run.contains("UPDATE_SNAPSHOTS=")
            })
    })
}

/// A config line `updateSnapshots: <value>` whose value is not `'missing'` or
/// `'none'`.
fn config_updates_snapshots(line: &str) -> bool {
    let Some((_, value)) = line.split_once("updateSnapshots") else {
        return false;
    };
    let Some(value) = value.trim_start().strip_prefix(':') else {
        return false;
    };
    let value = value
        .trim()
        .trim_end_matches(',')
        .trim()
        .trim_matches(['\'', '"', '`']);
    !matches!(value, "missing" | "none")
}

/// `qa.report-artifact`: each QA job uploads `playwright-report/` or a JUnit
/// file with `actions/upload-artifact`.
fn report_artifact(workflows: &Parsed, unread: &[(&str, &str)]) -> Vec<String> {
    let mut out = Vec::new();
    for (_, wf) in workflows {
        let Ok(wf) = wf else { continue };
        for job in wf.jobs.iter().filter(|j| is_qa_job(j)) {
            if !uploads_report(job) {
                out.push(warn(
                    REPORT_ARTIFACT,
                    format!(
                        "QA job {} keeps no report: failures cannot be inspected",
                        job.id
                    ),
                ));
            }
        }
    }
    out.extend(
        unread
            .iter()
            .map(|(path, e)| unverified(REPORT_ARTIFACT, path, e)),
    );
    out
}

fn uploads_report(job: &Job) -> bool {
    job.steps.iter().any(|step| {
        step.uses
            .as_deref()
            .is_some_and(|u| u.starts_with("actions/upload-artifact@"))
            && step.with.get("path").is_some_and(|path| {
                path.lines().any(|p| {
                    let p = p.trim().to_ascii_lowercase();
                    p.contains("playwright-report")
                        || p.contains("junit")
                        || p.contains("qa/contracts")
                })
            })
    })
}

/// The repository paths of the files under `root` whose name `wanted` accepts,
/// at most `depth` directories down, in path order; hidden directories and
/// [`SKIPPED_DIRS`] are never entered, symbolic links never followed, and the
/// profile's `excluded_paths` are not the project's files (#16).
fn files(root: &Path, depth: usize, wanted: &dyn Fn(&str) -> bool) -> Vec<String> {
    fn walk(
        root: &Path,
        dir: &str,
        depth: usize,
        wanted: &dyn Fn(&str) -> bool,
        out: &mut Vec<String>,
    ) {
        let full = if dir.is_empty() {
            root.to_path_buf()
        } else {
            root.join(dir)
        };
        let Ok(entries) = fs::read_dir(full) else {
            return;
        };
        let mut entries: Vec<_> = entries.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let path = if dir.is_empty() {
                name.clone()
            } else {
                format!("{dir}/{name}")
            };
            if kind.is_file() && wanted(&name) {
                out.push(path);
            } else if kind.is_dir()
                && depth > 0
                && !name.starts_with('.')
                && !SKIPPED_DIRS.contains(&name.as_str())
            {
                walk(root, &path, depth - 1, wanted, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, "", depth, wanted, &mut out);
    let excluded = crate::profile::excluded_paths_at(root);
    out.retain(|path| !crate::profile::is_excluded(&excluded, path));
    out
}

/// `items` without repeats, first occurrence kept.
fn dedup(items: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    items
        .into_iter()
        .filter(|i| seen.insert(i.clone()))
        .collect()
}

// --- the Silver rules (T11, #1009) ---------------------------------------------------

/// The Silver findings, in the spec's rule order.
fn silver(root: &Path, workflows: &Parsed) -> Vec<String> {
    let declared = Declared::of(root);
    let mut out = Vec::new();
    if declared.api && !api_smoke(root, workflows) {
        out.push(warn(API_SMOKE_PRESENT, API_SMOKE_TEXT));
    }
    if declared.web && !web_smoke(root, workflows) {
        out.push(warn(WEB_SMOKE_PRESENT, WEB_SMOKE_TEXT));
    }
    let inventory = security_audit::inventory(root);
    for spec in screenshot_specs(root) {
        let target = format!("{SCREENSHOT_TARGET}{spec}");
        if security_audit::registration(inventory.as_ref(), &target).is_some() {
            // A declared exclusion: `excluded` prints it (#1171).
            continue;
        }
        if !has_png(&root.join(format!("{spec}-snapshots"))) {
            out.push(warn(
                SCREENSHOT_BASELINE_PRESENT,
                format!("{BASELINE_TEXT} ({spec})"),
            ));
        }
    }
    out.extend(contract_rules(root, &declared, workflows));
    let snapshots = snapshot_dirs(root);
    if !snapshots.is_empty() {
        let gated = workflows
            .iter()
            .filter_map(|(_, wf)| wf.as_ref().ok())
            .any(protected_paths_gated);
        let patterns = protected_paths(root, &declared);
        for dir in snapshots {
            let probe = format!("{dir}/x.png");
            if !gated || !patterns.iter().any(|p| case_match(p, &probe)) {
                out.push(warn(
                    SNAPSHOTS_PROTECTED,
                    format!("{PROTECTED_TEXT} ({dir})"),
                ));
            }
        }
    }
    out
}

/// What the repository declares: from qa's recorded answers when they load
/// (T4's derivation included), else from T4's derivation over the root and
/// `commands.verify`.
struct Declared {
    api: bool,
    web: bool,
    /// qa's answers, when recorded and loadable.
    qa: Option<QaAnswers>,
}

impl Declared {
    fn of(root: &Path) -> Self {
        if let Some(qa) = recorded_qa(root) {
            let api = qa.api || qa.apps.values().any(|a| a.api);
            let web = qa.web != Web::None || qa.apps.values().any(|a| a.web != Web::None);
            return Self {
                api,
                web,
                qa: Some(qa),
            };
        }
        let found = detect::derive(root, ".", false).ok();
        let verify_hurl = read(root, ".agent-setup/project.json")
            .ok()
            .flatten()
            .and_then(|t| serde_json::from_str::<Value>(&t).ok())
            .and_then(|p| p["commands"]["verify"].as_str().map(calls_hurl_test))
            .unwrap_or(false);
        Self {
            api: verify_hurl || found.as_ref().is_some_and(|f| f.api.is_some()),
            web: found.is_some_and(|f| f.web != Web::None),
            qa: None,
        }
    }
}

/// The recorded answers of `module`, validated by its schema; `None` when
/// absent or invalid.
fn validated(root: &Path, module: &dyn Module) -> Option<Answers> {
    let file = answers::recorded(root, module.id()).ok()??;
    module
        .questions()
        .validate(module.id(), &file.answers, file.tier())
        .ok()
}

/// The web directories qa's recorded answers seed (`web: seeded`), read as
/// `qa` resolves them; none when qa records none or they do not load. What
/// `stack-packs` detection leaves out of its walk (#1238).
pub fn seeded_web_dirs(root: &Path) -> Vec<String> {
    recorded_qa(root)
        .map(|qa| protected::seeded_web_dirs(&qa))
        .unwrap_or_default()
}

/// qa's recorded answers loaded as `qa` loads them in a plan, with
/// stack-packs' and ci-baseline's recorded answers resolved beside them;
/// `None` when qa records none or they do not load.
fn recorded_qa(root: &Path) -> Option<QaAnswers> {
    let qa = validated(root, &Qa)?;
    let profile = profile_for(root).ok()?;
    let mut resolved = BTreeMap::new();
    resolved.insert(STACK_PACKS.to_owned(), validated(root, &StackPacks)?);
    let ci = answers::recorded(root, CI_BASELINE)
        .ok()
        .flatten()
        .map(|f| f.answers)
        .unwrap_or_default();
    resolved.insert(CI_BASELINE.to_owned(), ci);
    resolved.insert(QA.to_owned(), qa.clone());
    let source = Source::embedded();
    let lock = Lock {
        schema: crate::engine::lock::SCHEMA,
        version: String::new(),
        source_commit: None,
        source_dirty: false,
        personal_owner: crate::config::current_owner(),
        modules: BTreeMap::new(),
        files: BTreeMap::new(),
    };
    let cx = Context::new(root, &profile, &source, &lock, &qa, &Qa, &resolved);
    QaAnswers::load(&cx).ok()
}

/// ci-baseline's protected paths: its answered `protected_paths`, never
/// extended, else the derived default for its `heldout_dir` with the snapshot
/// globs of qa's web directories (T8's derivation, `qa::protected`). An
/// absent answers file is ci-baseline's defaults, as its own rules read it;
/// a repository without ci-baseline has no gate, which the rule also needs.
fn protected_paths(root: &Path, declared: &Declared) -> Vec<String> {
    let ci = answers::recorded(root, CI_BASELINE).ok().flatten();
    let answered = ci.as_ref().and_then(|f| f.answers.get("protected_paths"));
    if let Some(list) = answered.and_then(Value::as_array) {
        return list
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
    }
    let heldout = ci
        .as_ref()
        .and_then(|f| f.answers.get("heldout_dir"))
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_HELDOUT_DIR);
    let mut paths = default_protected_paths(heldout);
    if let Some(qa) = &declared.qa {
        paths.extend(web_dirs(qa).iter().map(|d| protected_glob(d)));
    }
    paths
}

/// `pattern` matched as the `scope` job's shell `case` does: `*` crosses
/// `/`, `?` is one character; a leading `**/` is optional.
pub fn case_match(pattern: &str, path: &str) -> bool {
    fn go(p: &[u8], s: &[u8]) -> bool {
        match p.split_first() {
            None => s.is_empty(),
            Some((b'*', rest)) => (0..=s.len()).any(|i| go(rest, &s[i..])),
            Some((b'?', rest)) => !s.is_empty() && go(rest, &s[1..]),
            Some((c, rest)) => s.first() == Some(c) && go(rest, &s[1..]),
        }
    }
    go(pattern.as_bytes(), path.as_bytes())
        || pattern
            .strip_prefix("**/")
            .is_some_and(|rest| go(rest.as_bytes(), path.as_bytes()))
}

/// The jobs an `if: always()` job of `wf` needs, directly or through others.
fn aggregated(wf: &Workflow) -> std::collections::BTreeSet<&str> {
    let mut needed = std::collections::BTreeSet::new();
    for gate in wf.jobs.iter().filter(|j| {
        j.condition
            .as_deref()
            .is_some_and(|c| c.contains("always()"))
    }) {
        let mut stack: Vec<&str> = gate.needs.iter().map(String::as_str).collect();
        while let Some(id) = stack.pop() {
            if needed.insert(id)
                && let Some(job) = wf.job(id)
            {
                stack.extend(job.needs.iter().map(String::as_str));
            }
        }
    }
    needed
}

/// A job of some workflow that `calls` accepts and an aggregate needs.
fn in_aggregate(workflows: &Parsed, calls: fn(&str) -> bool) -> bool {
    workflows
        .iter()
        .filter_map(|(_, wf)| wf.as_ref().ok())
        .any(|wf| {
            let needed = aggregated(wf);
            wf.jobs.iter().any(|job| {
                needed.contains(job.id.as_str())
                    && job
                        .steps
                        .iter()
                        .filter_map(|s| s.run.as_deref())
                        .flat_map(str::lines)
                        .any(calls)
            })
        })
}

/// True when a readable workflow has a job calling `hurl --test`.
pub fn has_hurl_job(workflows: &Parsed) -> bool {
    has_job(workflows, calls_hurl_test)
}

/// True when a readable workflow has a job calling `playwright test`.
pub fn has_playwright_job(workflows: &Parsed) -> bool {
    has_job(workflows, calls_playwright_test)
}

fn has_job(workflows: &Parsed, calls: fn(&str) -> bool) -> bool {
    workflows
        .iter()
        .filter_map(|(_, wf)| wf.as_ref().ok())
        .flat_map(|wf| &wf.jobs)
        .flat_map(|j| &j.steps)
        .filter_map(|s| s.run.as_deref())
        .flat_map(str::lines)
        .any(calls)
}

/// `qa.api-smoke-present`: a `.hurl` file outside `node_modules` and a job
/// calling `hurl --test` that an aggregate needs.
fn api_smoke(root: &Path, workflows: &Parsed) -> bool {
    !files(root, HURL_DEPTH, &|name| name.ends_with(".hurl")).is_empty()
        && in_aggregate(workflows, calls_hurl_test)
}

/// `qa.web-smoke-present`: a spec under a Playwright config's `testDir` and a
/// job calling `playwright test` that an aggregate needs.
fn web_smoke(root: &Path, workflows: &Parsed) -> bool {
    let specs = specs(root);
    let configs = files(root, PACKAGE_DEPTH, &|name| {
        PLAYWRIGHT_CONFIGS.contains(&name)
    });
    let under_test_dir = configs.iter().any(|config| {
        let dir = config.rsplit_once('/').map_or("", |(d, _)| d);
        let test_dir = read(root, config)
            .ok()
            .flatten()
            .and_then(|text| text.lines().find_map(test_dir))
            .unwrap_or_else(|| ".".to_owned());
        let base = normalise(&format!("{dir}/{test_dir}"));
        specs
            .iter()
            .any(|s| base.is_empty() || s.starts_with(&format!("{base}/")))
    });
    under_test_dir && in_aggregate(workflows, calls_playwright_test)
}

/// The value of a `testDir: '<dir>'` line.
fn test_dir(line: &str) -> Option<String> {
    let (_, rest) = line.split_once("testDir")?;
    let rest = rest.trim_start().strip_prefix(':')?.trim();
    let quote = rest.chars().next().filter(|c| "'\"`".contains(*c))?;
    let value = rest[1..].split(quote).next()?;
    Some(value.to_owned())
}

/// `a/./b/../c` as `a/c`; the root is the empty string.
fn normalise(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            part => parts.push(part),
        }
    }
    parts.join("/")
}

/// Every `*.spec.{ts,js}` file outside `node_modules`, in path order.
/// The spec files that call `toHaveScreenshot`, in path order: what
/// `qa.screenshot-baseline-present` judges.
pub fn screenshot_specs(root: &Path) -> Vec<String> {
    specs(root)
        .into_iter()
        .filter(|spec| {
            read(root, spec)
                .ok()
                .flatten()
                .is_some_and(|text| text.contains("toHaveScreenshot"))
        })
        .collect()
}

/// The declared exclusions of `qa.screenshot-baseline-present` at `root`: a
/// spec an `allowlist` entry with target `screenshot-baseline-present#<spec>`
/// registers (#1171), as `doctor` prints them.
pub fn excluded(root: &Path) -> Vec<String> {
    let inventory = security_audit::inventory(root);
    screenshot_specs(root)
        .into_iter()
        .filter_map(|spec| {
            security_audit::registration(inventory.as_ref(), &format!("{SCREENSHOT_TARGET}{spec}"))
                .map(|entry| {
                    security_audit::exclusion_line(SCREENSHOT_BASELINE_PRESENT, &spec, entry)
                })
        })
        .collect()
}

fn specs(root: &Path) -> Vec<String> {
    files(root, HURL_DEPTH, &|name| {
        name.ends_with(".spec.ts") || name.ends_with(".spec.js")
    })
}

/// Every directory named `*-snapshots` outside `node_modules`, in path order.
fn snapshot_dirs(root: &Path) -> Vec<String> {
    fn walk(root: &Path, dir: &str, depth: usize, out: &mut Vec<String>) {
        let full = if dir.is_empty() {
            root.to_path_buf()
        } else {
            root.join(dir)
        };
        let Ok(entries) = fs::read_dir(full) else {
            return;
        };
        let mut entries: Vec<_> = entries.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !entry.file_type().is_ok_and(|k| k.is_dir())
                || name.starts_with('.')
                || SKIPPED_DIRS.contains(&name.as_str())
            {
                continue;
            }
            let path = if dir.is_empty() {
                name.clone()
            } else {
                format!("{dir}/{name}")
            };
            if name.ends_with("-snapshots") {
                out.push(path);
            } else if depth > 0 {
                walk(root, &path, depth - 1, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, "", HURL_DEPTH, &mut out);
    out
}

/// A `.png` file directly in `dir` or below it.
fn has_png(dir: &Path) -> bool {
    let Ok(entries) = fs::read_dir(dir) else {
        return false;
    };
    entries.flatten().any(|entry| match entry.file_type() {
        Ok(kind) if kind.is_file() => entry.file_name().to_string_lossy().ends_with(".png"),
        Ok(kind) if kind.is_dir() => has_png(&entry.path()),
        _ => false,
    })
}

// --- the contract rules (T17, #1016) ----------------------------------------------

pub const CONTRACT_LINT_TEXT: &str = "is not linted in the aggregate";
pub const CONTRACT_COMPATIBLE_TEXT: &str =
    "has no backwards-compatibility check against the base branch";

/// `qa.contract-lint` and `qa.contract-compatible` for each contract: every
/// OpenAPI 3 or AsyncAPI document the derivation's walk finds from the root,
/// with every contract qa's answers list, less the published copies they
/// declare. Answers add contracts but never remove a live one (#1182). A job an
/// aggregate needs must call the linter (or the comparison) and name the
/// contract, in a `run:` or a step's `env:`; a loaded `contract_compat_by`
/// command is its target's comparison.
fn contract_rules(root: &Path, declared: &Declared, workflows: &Parsed) -> Vec<String> {
    let targets: Vec<(&str, &contracts::Contracts)> = match &declared.qa {
        Some(qa) => std::iter::once((".", &qa.contracts))
            .chain(qa.apps.values().map(|a| (a.path.as_str(), &a.contracts)))
            .collect(),
        None => Vec::new(),
    };
    let skip: Vec<String> = match &declared.qa {
        Some(qa) => std::iter::once(qa.qa_dir.clone())
            .chain(
                qa.apps
                    .values()
                    .map(|a| super::seeds::join(&a.path, &qa.qa_dir)),
            )
            .collect(),
        None => vec![DEFAULT_QA_DIR.to_owned()],
    };
    let published: Vec<String> = targets
        .iter()
        .flat_map(|(base, c)| c.published_copies().map(|p| super::seeds::join(base, p)))
        .collect();
    // The target's contracts a declared command compares.
    let compared: Vec<String> = targets
        .iter()
        .filter(|(_, c)| c.compat_by.is_some())
        .flat_map(|(base, c)| c.live().map(|p| super::seeds::join(base, p)))
        .collect();
    let mut contracts: Vec<String> = contracts::documents(root, &skip)
        .into_iter()
        .filter(|(_, kind)| *kind != contracts::Kind::Swagger)
        .map(|(path, _)| path)
        .chain(
            targets
                .iter()
                .flat_map(|(base, c)| c.live().map(|p| super::seeds::join(base, p))),
        )
        .filter(|path| !published.contains(path))
        .collect();
    contracts.sort();
    contracts.dedup();
    let mut lint = Vec::new();
    let mut compatible = Vec::new();
    for contract in &contracts {
        if !contract_job(workflows, contract, calls_contract_lint) {
            lint.push(warn(
                CONTRACT_LINT,
                format!("Contract {contract} {CONTRACT_LINT_TEXT}"),
            ));
        }
        if !compared.contains(contract) && !contract_job(workflows, contract, calls_contract_compat)
        {
            compatible.push(warn(
                CONTRACT_COMPATIBLE,
                format!("Contract {contract} {CONTRACT_COMPATIBLE_TEXT}"),
            ));
        }
    }
    lint.extend(compatible);
    lint
}

/// A job an aggregate needs whose `run:` lines `calls` accepts and that names
/// `contract` in a `run:` or as a step's `env:` value, either relative to the
/// step's `working-directory` (an app job, #1115).
fn contract_job(workflows: &Parsed, contract: &str, calls: fn(&str) -> bool) -> bool {
    let names = |job: &Job| {
        job.steps.iter().any(|step| {
            // The contract as the step sees it: relative to its directory.
            let seen = match step
                .working_directory
                .as_deref()
                .map(|d| d.trim_end_matches('/'))
            {
                None | Some(".") | Some("") => Some(contract),
                Some(dir) => contract
                    .strip_prefix(dir.trim_start_matches("./"))
                    .and_then(|rest| rest.strip_prefix('/')),
            };
            let Some(seen) = seen else {
                return false;
            };
            step.run.as_deref().is_some_and(|r| r.contains(seen))
                || step.env.values().any(|v| {
                    // One path, or a comma-separated list of them (#1182).
                    v.split(',')
                        .any(|item| item.trim().trim_start_matches("./") == seen)
                })
        })
    };
    workflows
        .iter()
        .filter_map(|(_, wf)| wf.as_ref().ok())
        .any(|wf| {
            let needed = aggregated(wf);
            wf.jobs.iter().any(|job| {
                needed.contains(job.id.as_str())
                    && names(job)
                    && job
                        .steps
                        .iter()
                        .filter_map(|s| s.run.as_deref())
                        .flat_map(str::lines)
                        .any(calls)
            })
        })
}

// --- qa.main-green (Silver, remote; T19 #1018) ----------------------------------------

/// The conclusive push runs of a workflow read for the run in which a QA job ran
/// (a path filter can skip it); each costs one call for its jobs.
pub const MAIN_GREEN_RUNS: usize = 3;

/// Whether the run's job `run_job` is the workflow's job displayed as `name`: the same
/// name, a matrix instance of it (`name (…)`), or, for a name built from an
/// expression, one starting with its literal part.
fn same_job(run_job: &str, name: &str) -> bool {
    if run_job == name || run_job.starts_with(&format!("{name} (")) {
        return true;
    }
    match name.split_once("${{") {
        Some((literal, _)) => !literal.trim().is_empty() && run_job.starts_with(literal),
        None => false,
    }
}

/// `qa.main-green`: in the latest conclusive push run on the default branch in which
/// each QA job ran (not skipped or cancelled; the newest [`MAIN_GREEN_RUNS`] of its
/// workflow are read), every instance of the job that ran concluded `success`. The listing is the one
/// ci-health and `ci.main-red` read (cached); each run's jobs cost one call unless
/// another rule read them. Failed with every red job; `unavailable` when a job has
/// not run or the host cannot be read.
pub fn main_green(cx: &Cx<'_>) -> Outcome {
    let mut targets: Vec<(String, Vec<(String, String)>)> = Vec::new();
    for (path, parsed) in read_all(cx.files) {
        let Ok(wf) = parsed else { continue };
        let jobs: Vec<(String, String)> = wf
            .jobs
            .iter()
            .filter(|j| is_qa_job(j))
            .map(|j| (j.id.clone(), j.name.clone().unwrap_or_else(|| j.id.clone())))
            .collect();
        if !jobs.is_empty() {
            targets.push((wf.name.clone().unwrap_or(path), jobs));
        }
    }
    let runs = match ci_health::latest(cx, true, RECENT_RUNS) {
        Ok(runs) => runs,
        Err(outcome) => return outcome,
    };
    let main = cx.default_branch;
    let (mut green, mut red, mut unknown) = (Vec::new(), Vec::new(), Vec::new());
    for (workflow, jobs) in targets {
        let candidates: Vec<_> = runs
            .iter()
            .filter(|r| r.name == workflow && ci_health::conclusive(r))
            .take(MAIN_GREEN_RUNS)
            .collect();
        if candidates.is_empty() {
            unknown.extend(jobs.iter().map(|(id, _)| {
                format!("QA job {id} has not run on {main}: no completed push run of {workflow} among the latest {RECENT_RUNS}")
            }));
            continue;
        }
        let mut pending = jobs;
        for run in &candidates {
            if pending.is_empty() {
                break;
            }
            let run_jobs = match cx.host.jobs(cx.repo, run.id) {
                Ok(run_jobs) => run_jobs,
                Err(e) => return unread(&e),
            };
            pending.retain(|(id, name)| {
                // Every instance that ran (a matrix has several) counts: one red is red.
                let ran: Vec<_> = run_jobs
                    .iter()
                    .filter(|j| {
                        same_job(&j.name, name)
                            && !matches!(j.conclusion.as_deref(), Some("skipped" | "cancelled"))
                    })
                    .collect();
                if ran.is_empty() {
                    return true;
                }
                match ran
                    .iter()
                    .find(|j| j.conclusion.as_deref() != Some("success"))
                {
                    None => green.push(format!(
                        "QA job {id} succeeded in run {} of {workflow} on {main}",
                        run.id
                    )),
                    Some(job) => red.push(format!(
                        "QA job {id} red on {main}: run {} of {workflow} concluded {}",
                        run.id,
                        job.conclusion.as_deref().unwrap_or("without a conclusion")
                    )),
                }
                false
            });
        }
        unknown.extend(pending.iter().map(|(id, _)| {
            format!(
                "QA job {id} has not run on {main}: skipped or cancelled in the latest {} conclusive push runs of {workflow}",
                candidates.len()
            )
        }));
    }
    if !red.is_empty() {
        Outcome::failed(red)
    } else if let Some(reason) = unknown.into_iter().next() {
        Outcome::unavailable(reason)
    } else {
        Outcome::passed(green)
    }
}
