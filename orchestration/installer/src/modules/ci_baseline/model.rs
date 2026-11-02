//! The data the renderer assembles (`Workflow`, `Job`, `Skippable`) and the
//! module's answers, loaded and checked (SPEC-ci-baseline.md, Answers). `Step`
//! and `ActionRef` are stack-packs' types (owner decision); `CiTier` belongs to
//! the composition contract beside `Module` in the engine.
use crate::{
    Result,
    engine::Context,
    host::desired::Supersession,
    modules::{qa, stack_packs},
    refuse,
};
use serde_json::Value;

pub use super::scope::SkipWhen;
pub use crate::engine::CiTier;
pub use crate::modules::stack_packs::{ActionRef, Step};

use super::{
    AGGREGATE_CHECK,
    scope::{DEFAULT_HELDOUT_DIR, DEFAULT_INERT_PATHS, default_protected_paths},
};

/// One generated workflow file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Workflow {
    /// Repository-relative path: `.github/workflows/ci.yml`, brownfield
    /// `.github/workflows/agentic-ci.yml`, or under `workflow: existing`
    /// `.github/workflows/agentic-security.yml`.
    pub path: String,
    pub name: String,
    pub merge_queue: bool,
    /// In order; the aggregate (`required`, or `agentic-required` in the
    /// separate workflow) is last and needs every other job.
    pub jobs: Vec<Job>,
    /// Jobs other modules contribute, written verbatim before the aggregate.
    pub contributed: Vec<super::compose::Contributed>,
}

/// One job of the generated workflow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Job {
    pub id: String,
    /// The display name, the check name GitHub reports.
    pub name: String,
    /// The runner label, from `render::runner_label`; never free text.
    pub runs_on: String,
    pub timeout_minutes: u32,
    pub needs: Vec<String>,
    pub condition: Option<String>,
    /// `fail-fast: false` over one matrix key (the shards).
    pub matrix: Option<Matrix>,
    /// Job outputs, in order: name and expression.
    pub outputs: Vec<(String, String)>,
    pub steps: Vec<Step>,
    pub skippable: Skippable,
    /// A job that calls a reusable workflow (#785): `uses:` and `with:` in place
    /// of `runs-on`, `timeout-minutes` and `steps`, which the callee owns.
    pub call: Option<Call>,
    /// The `services:` and `env:` its app's profile declares (#1170).
    pub services: super::services::Services,
    /// The job's own `permissions:` for `GITHUB_TOKEN`, in order; empty keeps the
    /// workflow's `contents: read`. A job's block replaces the workflow's.
    pub permissions: Vec<(String, String)>,
}

/// The `uses:` of a calling job and its `with:` inputs, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Call {
    pub uses: String,
    pub with: Vec<(String, String)>,
}

/// A one-key matrix; every generated matrix is `fail-fast: false`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Matrix {
    pub key: String,
    pub values: Vec<u32>,
}

/// Whether the scope job may list a job as skippable in a run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Skippable {
    /// Must report `success`; a `skipped` fails the aggregate.
    Never,
    When(SkipWhen),
}

/// `workflow`: render the baseline, or record and audit the project's own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkflowMode {
    Generate,
    Existing,
}

impl WorkflowMode {
    pub const ALL: [WorkflowMode; 2] = [WorkflowMode::Generate, WorkflowMode::Existing];
    pub const fn as_str(self) -> &'static str {
        match self {
            WorkflowMode::Generate => "generate",
            WorkflowMode::Existing => "existing",
        }
    }
}

/// A declared command the generated workflow runs, read at run time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Lint,
    Test,
    Verify,
    Build,
}

impl Command {
    pub const ALL: [Command; 4] = [
        Command::Lint,
        Command::Test,
        Command::Verify,
        Command::Build,
    ];
    /// The `commands.<name>` key of `project.json`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Command::Lint => "lint",
            Command::Test => "test",
            Command::Verify => "verify",
            Command::Build => "build",
        }
    }
}

/// The Linux runner: the user's own (`runners.linux` of the configuration, its
/// `name` the answer value) or GitHub-hosted. The label strings belong to the
/// renderer (`render::runner_label`); an answer can only pick a variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Runner {
    Configured,
    Github,
}

impl Runner {
    pub const ALL: [Runner; 2] = [Runner::Configured, Runner::Github];
    /// The variants an answer may name: the configured runner only when one is
    /// configured.
    pub fn available() -> Vec<Runner> {
        Self::available_with(crate::config::linux_runner().is_some())
    }
    /// `available` with the configuration's answer explicit.
    pub fn available_with(configured: bool) -> Vec<Runner> {
        Self::ALL
            .into_iter()
            .filter(|r| *r != Runner::Configured || configured)
            .collect()
    }
    /// The answer's default: the configured runner, else GitHub-hosted.
    pub fn default_choice() -> Runner {
        Self::default_with(crate::config::linux_runner().is_some())
    }
    /// `default_choice` with the configuration's answer explicit.
    pub fn default_with(configured: bool) -> Runner {
        if configured {
            Runner::Configured
        } else {
            Runner::Github
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Runner::Configured => {
                crate::config::linux_runner().map_or("configured", |r| r.name.as_str())
            }
            Runner::Github => "github",
        }
    }
}

/// Where the push-only macOS job runs: the user's own (`runners.macos`) or
/// GitHub-hosted, which is always an auditor warning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MacosRunner {
    Configured,
    GithubHosted,
}

impl MacosRunner {
    pub const ALL: [MacosRunner; 2] = [MacosRunner::Configured, MacosRunner::GithubHosted];
    /// The variants an answer may name: the configured runner only when one is
    /// configured.
    pub fn available() -> Vec<MacosRunner> {
        Self::available_with(crate::config::macos_runner().is_some())
    }
    /// `available` with the configuration's answer explicit.
    pub fn available_with(configured: bool) -> Vec<MacosRunner> {
        Self::ALL
            .into_iter()
            .filter(|r| *r != MacosRunner::Configured || configured)
            .collect()
    }
    /// The answer's default: the configured runner, else GitHub-hosted.
    pub fn default_choice() -> MacosRunner {
        Self::default_with(crate::config::macos_runner().is_some())
    }
    /// `default_choice` with the configuration's answer explicit.
    pub fn default_with(configured: bool) -> MacosRunner {
        if configured {
            MacosRunner::Configured
        } else {
            MacosRunner::GithubHosted
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            MacosRunner::Configured => {
                crate::config::macos_runner().map_or("configured", |r| r.name.as_str())
            }
            MacosRunner::GithubHosted => "github-hosted",
        }
    }
}

/// The module's answers with every default and derivation resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CiBaselineAnswers {
    pub workflow: WorkflowMode,
    /// The check the ruleset requires: `AGGREGATE_CHECK` when generating.
    pub aggregate_check: String,
    /// Run order; empty only under `workflow == existing`.
    pub commands: Vec<Command>,
    pub runner: Runner,
    pub tiers: bool,
    /// Empty when `tiers` is false.
    pub inert_paths: Vec<String>,
    pub macos: bool,
    /// `Some` exactly when `macos` is true.
    pub macos_runner: Option<MacosRunner>,
    pub merge_queue: bool,
    pub minutes_budget: u32,
    /// Globs whose change in a pull request needs the `human-approved` label;
    /// unanswered, the defaults with `<heldout_dir>/**`, then `qa`'s
    /// `*-snapshots/` globs (`qa::protected`).
    pub protected_paths: Vec<String>,
    /// The held-out directory, normalised: no leading `./`, no trailing `/`.
    pub heldout_dir: String,
    /// Unanswered, `true` under `generate` (#1362); under `existing`, whether
    /// `heldout_dir` exists at plan time.
    pub heldout: bool,
    /// The command the `heldout` job runs; `None` when `heldout` is false, or
    /// while the job is pending (#1362): `heldout` and the command unanswered
    /// under `generate`, on a `heldout_dir` that holds no file.
    pub heldout_command: Option<String>,
    /// `Some` exactly when `heldout` and `heldout_properties` are true: the
    /// command the `heldout-properties` job runs (#980).
    pub heldout_properties_command: Option<String>,
    /// The minimum number of examples per property (`HELDOUT_EXAMPLES`).
    pub heldout_examples: u32,
    /// Monorepo mode (#784): one entry per Linux app, in app id order, with the
    /// answered commands its own profile declares; empty for a single app at `.`.
    pub apps: Vec<AppCommands>,
    /// The apps of a pack with a macOS target, when `macos` is true: what the
    /// push-only `macos` job runs; empty otherwise.
    pub macos_apps: Vec<AppCommands>,
    /// Monorepo mode without an app at `.` (#1165): `Some` with the answered
    /// commands the root profile declares, which the root `checks` job runs
    /// (none renders no job); `None` when the root profile is no job's.
    pub root_commands: Option<Vec<Command>>,
    /// `Some(sha)` when `reusable` is true: the callee commit `checks` pins.
    pub reusable_sha: Option<String>,
}

/// One app's job: its id, its directory and the answered commands its profile
/// (`<path>/.agent-setup/project.json`, Decision 8) declares, in run order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppCommands {
    pub id: String,
    pub path: String,
    pub commands: Vec<Command>,
}

/// The profile of an app: `.agent-setup/project.json` under its path (Decision
/// 8). Read at render time only to decide which steps exist; the workflow reads
/// it again at run time.
fn app_profile(root: &std::path::Path, id: &str, path: &str) -> Result<Value> {
    let file = format!("{path}/.agent-setup/project.json");
    let Some(text) = crate::read(root, &file)? else {
        return refuse(format!(
            "ci-baseline: app {id} has no {file}; each app declares its commands there (Decision 8)"
        ));
    };
    serde_json::from_str(&text)
        .or_else(|_| refuse(format!("ci-baseline: {file} of app {id} is not JSON")))
}

/// The answered `commands` an app's profile declares, or the refusal naming it.
fn app_commands(
    root: &std::path::Path,
    id: &str,
    path: &str,
    commands: &[Command],
) -> Result<AppCommands> {
    let profile = app_profile(root, id, path)?;
    let declared: Vec<Command> = commands
        .iter()
        .copied()
        .filter(|c| profile["commands"][c.as_str()].is_string())
        .collect();
    if declared.is_empty() {
        let names: Vec<&str> = commands.iter().map(|c| c.as_str()).collect();
        return refuse(format!(
            "ci-baseline: app {id} declares none of the answered commands ({}) in {path}/.agent-setup/project.json; declare one there or remove the app from stack-packs",
            names.join(", ")
        ));
    }
    Ok(AppCommands {
        id: id.to_owned(),
        path: path.to_owned(),
        commands: declared,
    })
}

/// Monorepo mode: more than one Linux app, or one that is not at the root.
pub fn is_monorepo(linux_apps: &[(stack_packs::App, &'static stack_packs::StackPack)]) -> bool {
    linux_apps.len() > 1 || linux_apps.iter().any(|(app, _)| app.path != ".")
}

/// The variant of `all` spelled `text`; the engine validated the enum already.
fn pick<T: Copy>(all: &[T], name: fn(T) -> &'static str, text: Option<&str>, default: T) -> T {
    text.and_then(|text| all.iter().copied().find(|v| name(*v) == text))
        .unwrap_or(default)
}

impl CiBaselineAnswers {
    /// The validated answers in `cx` with the module's rules applied: the
    /// commands derived from the profile when unanswered (an empty set
    /// refuses) and `macos` only with a macOS-capable stack pack.
    pub fn load(cx: &Context<'_>) -> Result<Self> {
        let a = cx.answers;
        let text = |id: &str| a.get(id).and_then(Value::as_str);
        let flag = |id: &str, default: bool| a.get(id).and_then(Value::as_bool).unwrap_or(default);
        let strings = |id: &str| -> Option<Vec<String>> {
            a.get(id)?.as_array().map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
        };
        let workflow = pick(
            &WorkflowMode::ALL,
            WorkflowMode::as_str,
            text("workflow"),
            WorkflowMode::Generate,
        );
        // The engine drops `aggregate_check` unless `workflow == existing`.
        let aggregate_check = text("aggregate_check")
            .unwrap_or(AGGREGATE_CHECK)
            .to_owned();
        // First: without a macOS target `macos` cannot mean anything, whatever
        // else the apps declare.
        let macos = flag("macos", false);
        if macos && !macos_target(cx)? {
            return refuse(
                "ci-baseline: macos is true but no stack pack declares a macOS target; record a swift-ios app in stack-packs or set macos=false",
            );
        }
        let generate = workflow == WorkflowMode::Generate;
        let packs = if generate {
            stack_packs::required_packs(cx)?
        } else {
            Vec::new()
        };
        let (macos_packs, linux_packs): (Vec<_>, Vec<_>) =
            packs.into_iter().partition(|(_, pack)| pack.macos_target);
        let monorepo = generate && is_monorepo(&linux_packs);
        // Monorepo mode without an app at `.`: the root profile's own commands
        // run in the root `checks` job (#1165), never dropped in silence.
        let root_job = monorepo
            && !linux_packs
                .iter()
                .chain(&macos_packs)
                .any(|(app, _)| app.path == ".");
        // Each Linux app's profile in monorepo mode, read once.
        let profiles: Vec<(String, String, Value)> = if monorepo {
            linux_packs
                .iter()
                .map(|(app, _)| {
                    Ok((
                        app.id.clone(),
                        app.path.clone(),
                        app_profile(cx.root, &app.id, &app.path)?,
                    ))
                })
                .collect::<Result<_>>()?
        } else {
            Vec::new()
        };
        let commands = match workflow {
            WorkflowMode::Existing => Vec::new(),
            WorkflowMode::Generate => match strings("commands") {
                Some(names) => names
                    .iter()
                    .map(|n| pick(&Command::ALL, Command::as_str, Some(n), Command::Test))
                    .collect(),
                // Monorepo: every app's profile, and the root's when its job runs.
                None if monorepo => derive(|c| {
                    (root_job && is_declared(cx, c))
                        || profiles
                            .iter()
                            .any(|(_, _, p)| p["commands"][c.as_str()].is_string())
                }),
                None => derive(|c| is_declared(cx, c)),
            },
        };
        // A null answered command renders no step (a plan note says so); with
        // none declared at all there would be nothing to verify. In monorepo
        // mode each app must declare one of them (its job would verify nothing).
        if generate && !monorepo && !commands.iter().any(|c| is_declared(cx, *c)) {
            return refuse(
                "ci-baseline: no verification command to run; declare commands.verify or commands.test in .agent-setup/project.json",
            );
        }
        if monorepo && shard_count(cx).is_some() {
            return refuse(
                "ci-baseline: ci.shards applies to a single app at the root; a monorepo runs one job per app, so remove ci.shards from .agent-setup/project.json",
            );
        }
        let apps = profiles
            .iter()
            .map(|(id, path, _)| app_commands(cx.root, id, path, &commands))
            .collect::<Result<Vec<_>>>()?;
        let root_commands = root_job.then(|| {
            commands
                .iter()
                .copied()
                .filter(|c| is_declared(cx, *c))
                .collect()
        });
        let tiers = flag("tiers", true);
        // The macOS apps run the answered commands their own profiles declare.
        let macos_apps = if macos && generate {
            macos_packs
                .iter()
                .map(|(app, _)| app_commands(cx.root, &app.id, &app.path, &commands))
                .collect::<Result<Vec<_>>>()?
        } else {
            Vec::new()
        };
        let reusable_sha = if workflow == WorkflowMode::Generate && flag("reusable", false) {
            Some(reusable_sha(cx, text("reusable_sha"))?)
        } else {
            None
        };
        let heldout_dir = heldout_dir(text("heldout_dir").unwrap_or(DEFAULT_HELDOUT_DIR))?;
        let answered_heldout = a.get("heldout").and_then(Value::as_bool);
        // Under existing the directory still decides: no silent new required check.
        let heldout = answered_heldout.unwrap_or_else(|| {
            workflow == WorkflowMode::Generate || cx.root.join(&heldout_dir).is_dir()
        });
        // No held-out tests yet (#1362): the default job is pending, never an
        // invented command; a test in the directory needs the answer.
        let pending = heldout
            && answered_heldout.is_none()
            && workflow == WorkflowMode::Generate
            && text("heldout_command").is_none()
            && !holds_files(&cx.root.join(&heldout_dir));
        let heldout_command = if heldout && !pending {
            Some(heldout_command(text("heldout_command"))?)
        } else {
            None
        };
        // Read only when `heldout`: a schema `when` on the derived answer would drop it.
        let heldout_properties_command = if heldout && flag("heldout_properties", false) {
            let command = answered_command(
                "heldout_properties_command",
                text("heldout_properties_command"),
                "the properties under the held-out directory are the point of the job",
            )?;
            property_recipes(cx)?;
            Some(command)
        } else {
            None
        };
        Ok(Self {
            workflow,
            aggregate_check,
            commands,
            runner: pick(
                &Runner::available(),
                Runner::as_str,
                text("runner"),
                Runner::default_choice(),
            ),
            tiers,
            inert_paths: if tiers {
                strings("inert_paths").unwrap_or_else(|| {
                    DEFAULT_INERT_PATHS
                        .iter()
                        .map(|p| (*p).to_owned())
                        .collect()
                })
            } else {
                Vec::new()
            },
            macos,
            macos_runner: macos.then(|| {
                pick(
                    &MacosRunner::available(),
                    MacosRunner::as_str,
                    text("macos_runner"),
                    MacosRunner::default_choice(),
                )
            }),
            merge_queue: flag("merge_queue", false),
            minutes_budget: a
                .get("minutes_budget")
                .and_then(Value::as_u64)
                .map_or(2000, |n| n as u32),
            // Unanswered: the defaults, then `qa`'s screenshot baselines when
            // it is active with a web app (a soft read, SPEC-qa.md T8 #1005).
            protected_paths: strings("protected_paths").unwrap_or_else(|| {
                let mut paths = default_protected_paths(&heldout_dir);
                paths.extend(qa::protected::snapshot_globs(cx));
                paths
            }),
            heldout_dir,
            heldout,
            heldout_command,
            heldout_properties_command,
            heldout_examples: a
                .get("heldout_examples")
                .and_then(Value::as_u64)
                .map_or(DEFAULT_HELDOUT_EXAMPLES, |n| n as u32),
            apps,
            macos_apps,
            root_commands,
            reusable_sha,
        })
    }
}

/// `ci.shards.count` of the profile when it asks for more than one shard.
pub fn shard_count(cx: &Context<'_>) -> Option<u32> {
    cx.profile.value["ci"]["shards"]["count"]
        .as_u64()
        .filter(|n| (2..=256).contains(n))
        .map(|n| n as u32)
}

/// The answered callee commit: 40 hex digits, and only for one app at the root.
fn reusable_sha(cx: &Context<'_>, answer: Option<&str>) -> Result<String> {
    let Some(sha) = answer.filter(|s| s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit()))
    else {
        let callee = crate::config::reusable_callee().unwrap_or("the configured reusable_callee");
        return refuse(format!(
            "ci-baseline: reusable is true but reusable_sha is not a 40-hex commit of {callee}; pin the callee by SHA, never by a branch or tag"
        ));
    };
    let packs = stack_packs::required_packs(cx)?;
    if packs.len() > 1 || packs.iter().any(|(app, _)| app.path != ".") {
        return refuse(
            "ci-baseline: reusable is true but the repository has several apps; the reusable workflow runs one app at the root, so set reusable=false",
        );
    }
    Ok(sha.to_ascii_lowercase())
}

/// `dir` without a leading `./` or a trailing `/`, when what is left is a
/// relative path inside the repository: segments that are neither empty, `.`
/// nor `..`, of letters, digits, `.`, `_` and `-`. It reaches YAML, CODEOWNERS
/// and agent deny rules, so nothing that could be read as a glob or climb out.
pub fn heldout_dir(dir: &str) -> Result<String> {
    let trimmed = dir.strip_prefix("./").unwrap_or(dir);
    let trimmed = trimmed.strip_suffix('/').unwrap_or(trimmed);
    let valid = trimmed.split('/').all(|segment| {
        !matches!(segment, "" | "." | "..")
            && segment
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
    });
    if !valid {
        return refuse(format!(
            "ci-baseline: heldout_dir {dir} is not a relative path inside the repository"
        ));
    }
    Ok(trimmed.to_owned())
}

/// True when `dir` holds a file at any depth (#1362): a pending held-out job
/// passes only on a directory without one, as `heldout-pending.sh` checks.
fn holds_files(dir: &std::path::Path) -> bool {
    std::fs::read_dir(dir).is_ok_and(|entries| {
        entries
            .flatten()
            .any(|entry| !entry.path().is_dir() || holds_files(&entry.path()))
    })
}

/// The default of the `heldout_examples` answer (coordinator, unsourced).
pub const DEFAULT_HELDOUT_EXAMPLES: u32 = 200;

/// The answered held-out command: never invented, never an expression GitHub
/// would evaluate when the workflow runs.
fn heldout_command(answer: Option<&str>) -> Result<String> {
    answered_command(
        "heldout_command",
        answer,
        "the held-out tests are the point of the job",
    )
}

/// The answer `id`: a command never invented and never an expression GitHub
/// would evaluate when the workflow runs.
fn answered_command(id: &str, answer: Option<&str>, why: &str) -> Result<String> {
    let Some(command) = answer.filter(|c| !c.trim().is_empty()) else {
        return refuse(format!("ci-baseline: {id} missing; {why}"));
    };
    if command.contains("${{") {
        return refuse(format!(
            "ci-baseline: {id} contains `${{{{`, which GitHub would evaluate; write the command without it"
        ));
    }
    Ok(command.to_owned())
}

/// The property recipes of the Linux packs that declare one, in app order;
/// refuses naming the packs when none does (`go` and `node` until their
/// packs declare the recipe; SPEC-stack-packs.md, "Property recipe").
pub fn property_recipes(cx: &Context<'_>) -> Result<Vec<stack_packs::PropertyRecipe>> {
    let packs = stack_packs::required_packs(cx)?;
    let linux: Vec<_> = packs.iter().filter(|(_, p)| !p.macos_target).collect();
    let recipes: Vec<_> = linux.iter().filter_map(|(_, p)| p.properties).collect();
    if recipes.is_empty() {
        let mut names: Vec<&str> = linux.iter().map(|(app, _)| app.stack.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        let names = if names.is_empty() {
            "no stack pack is recorded, so none".to_owned()
        } else {
            format!(
                "{} {}",
                names.join(", "),
                if names.len() == 1 { "has" } else { "have" }
            )
        };
        return refuse(format!(
            "ci-baseline: heldout_properties needs a stack pack with a property recipe; {names} none"
        ));
    }
    Ok(recipes)
}

/// True when `commands.<name>` of the profile is a command, not `null` or absent.
pub fn is_declared(cx: &Context<'_>, command: Command) -> bool {
    cx.profile.value["commands"][command.as_str()].is_string()
}

/// `lint`, `test`, `build` where declared, in that order; `verify` in place of
/// `test` when `test` is null.
fn derive(declared: impl Fn(Command) -> bool) -> Vec<Command> {
    let test = if declared(Command::Test) {
        Some(Command::Test)
    } else {
        declared(Command::Verify).then_some(Command::Verify)
    };
    [
        declared(Command::Lint).then_some(Command::Lint),
        test,
        declared(Command::Build).then_some(Command::Build),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// True when a pack of stack-packs' answers, as resolved for this plan,
/// declares a macOS target.
fn macos_target(cx: &Context<'_>) -> Result<bool> {
    Ok(stack_packs::required_packs(cx)?
        .iter()
        .any(|(_, pack)| pack.macos_target))
}

/// ci-baseline's context seen from any module's: its resolved answers, the
/// contributed jobs of the plan; `None` when ci-baseline is not active.
fn ci_context<'a>(cx: &Context<'a>) -> Option<Context<'a>> {
    let answers = cx.answers_if_active(super::CI_BASELINE)?;
    Some(
        Context::new(
            cx.root,
            cx.profile,
            cx.source,
            cx.previous,
            answers,
            &super::CiBaseline,
            cx.resolved,
        )
        .with_repository(cx.repository)
        .with_contributed_jobs(cx.ci_jobs)
        .with_tier(cx.tier),
    )
}

/// The checks the default branch requires for ci-baseline (#1159), from any
/// module's context; `None` when ci-baseline is not active. Generating:
/// `[required]`. Under `workflow: existing`: `[aggregate_check]`, followed by
/// `agentic-required` when `agentic-security.yml` renders (a module
/// contributes a job or the held-out job runs).
pub fn required_checks(cx: &Context<'_>) -> Result<Option<Vec<String>>> {
    let Some(ci) = ci_context(cx) else {
        return Ok(None);
    };
    let existing =
        ci.answers.get("workflow").and_then(Value::as_str) == Some(WorkflowMode::Existing.as_str());
    if !existing {
        return Ok(Some(vec![AGGREGATE_CHECK.to_owned()]));
    }
    let loaded = CiBaselineAnswers::load(&ci)?;
    let mut checks = vec![loaded.aggregate_check];
    if loaded.heldout || !super::compose::contributed(&ci)?.is_empty() {
        checks.push(super::CONTRIBUTED_AGGREGATE_CHECK.to_owned());
    }
    Ok(Some(checks))
}

/// True when ci-baseline is active and renders `github:switch-required-check`
/// (`workflow: generate` with the generated workflow at `agentic-ci.yml`), whose
/// write leaves `required` the only required check of the default branch, so
/// `repo-baseline` renders that and not a declared `ci.required_checks` (#1299).
/// False when the declared list names `required`: it is then the post-switch
/// state, which the switch keeps (#1373).
pub fn switches_required_check(cx: &Context<'_>) -> Result<bool> {
    let Some(ci) = ci_context(cx) else {
        return Ok(false);
    };
    if super::brownfield::switch_checks(&cx.profile.value) != [AGGREGATE_CHECK] {
        return Ok(false);
    }
    let existing =
        ci.answers.get("workflow").and_then(Value::as_str) == Some(WorkflowMode::Existing.as_str());
    if existing {
        return Ok(false);
    }
    let foreign = super::brownfield::foreign_workflows(&ci)?;
    Ok(super::brownfield::workflow_path(&ci, &foreign) == super::brownfield::BROWNFIELD_PATH)
}

/// What the aggregate check supersedes when `repo-baseline` retires classic
/// protection (decision 2026-10-30, #1149), from any module's context: nothing
/// unless ci-baseline is active and the installed lock records its brownfield
/// switch; then `By(required)` when the generated workflow runs every command
/// the profile declares (each non-null `commands.<name>` is answered, or its
/// text equals an answered one's), else `Short` naming those it does not run.
pub fn supersession(cx: &Context<'_>) -> Result<Supersession> {
    let switch = format!("github:{}", super::brownfield::SWITCH);
    let switched = cx
        .previous
        .files
        .get(&switch)
        .is_some_and(|entry| entry.module == super::CI_BASELINE);
    let Some(ci) = ci_context(cx) else {
        return Ok(Supersession::None);
    };
    if !switched {
        return Ok(Supersession::None);
    }
    let loaded = CiBaselineAnswers::load(&ci)?;
    let mut unrun = Vec::new();
    if loaded.apps.is_empty() || loaded.root_commands.is_some() {
        unrun.extend(unrun_commands(&cx.profile.value, "", &loaded.commands));
    }
    for app in &loaded.apps {
        let profile = app_profile(cx.root, &app.id, &app.path)?;
        let prefix = format!("{}/", app.path);
        unrun.extend(unrun_commands(&profile, &prefix, &loaded.commands));
    }
    if unrun.is_empty() {
        return Ok(Supersession::By(AGGREGATE_CHECK.to_owned()));
    }
    let named: Vec<String> = unrun
        .iter()
        .map(|(name, text)| format!("{name} ({text})"))
        .collect();
    Ok(Supersession::Short(format!(
        "the aggregate check {AGGREGATE_CHECK} does not supersede them: {} does not run {}; fold it in with brakes configure <repo> ci-baseline --set commands={} --apply, then merge and apply --remote again",
        super::brownfield::BROWNFIELD_PATH,
        named.join(", "),
        folded(&loaded.commands, &unrun)
    )))
}

/// The `commands` answer that folds `unrun` in: the answered ones and those
/// `unrun` names, in run order, comma-separated.
fn folded(answered: &[Command], unrun: &[(String, String)]) -> String {
    Command::ALL
        .iter()
        .filter(|c| {
            answered.contains(c)
                || unrun
                    .iter()
                    .any(|(name, _)| name.ends_with(&format!("commands.{}", c.as_str())))
        })
        .map(|c| c.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

/// Monorepo mode (#1165): one plan note per command the root profile declares
/// that the root `checks` job does not run, naming the answer that folds it in.
pub fn root_unrun_notes(cx: &Context<'_>, answers: &CiBaselineAnswers) -> Vec<String> {
    if answers.root_commands.is_none() {
        return Vec::new();
    }
    let unrun = unrun_commands(&cx.profile.value, "", &answers.commands);
    let fold = folded(&answers.commands, &unrun);
    unrun
        .iter()
        .map(|(name, text)| {
            format!(
                "Verification command not run: .agent-setup/project.json declares {name} ({text}), which {AGGREGATE_CHECK} does not run; fold it in with brakes configure <repo> ci-baseline --set commands={fold} --apply"
            )
        })
        .collect()
}

/// The commands `profile` declares that none of `answered` runs, as
/// (`<prefix>commands.<name>`, its text): neither answered nor equal in text
/// to an answered command `profile` declares.
fn unrun_commands(profile: &Value, prefix: &str, answered: &[Command]) -> Vec<(String, String)> {
    let text = |c: Command| profile["commands"][c.as_str()].as_str();
    Command::ALL
        .iter()
        .filter(|c| !answered.contains(c))
        .filter_map(|c| {
            let declared = text(*c)?;
            (!answered.iter().any(|a| text(*a) == Some(declared))).then(|| {
                (
                    format!("{prefix}commands.{}", c.as_str()),
                    declared.to_owned(),
                )
            })
        })
        .collect()
}
