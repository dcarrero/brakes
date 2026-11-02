//! What the generated workflow spells (SPEC-ci-baseline.md, "The generated
//! workflow", Hardening, Pins). `workflow` assembles the model from the answers,
//! the profile and stack-packs' `ci_setup` steps; `to_yaml` writes it with fixed
//! two-space indentation. The runner labels live here alone: an answer picks a
//! `Runner`, never a label, so `self-hosted` cannot be generated. Every `uses:`
//! comes from the shared pin table; the shells are embedded verbatim.
use super::{
    AGGREGATE_CHECK, CI_BASELINE_VERSION, CONTRIBUTED_AGGREGATE_CHECK, REQUIRED_SH,
    aggregate::AGGREGATE_PERMISSIONS,
    brownfield::{SEPARATE_NAME, SEPARATE_PATH},
    compose::{self, Contributed},
    model::{
        AppCommands, CiBaselineAnswers, Command, Job, MacosRunner, Matrix, Runner, Skippable, Step,
        Workflow, WorkflowMode, is_declared, shard_count,
    },
    scope::{self, SkipWhen},
};
use crate::{
    Result,
    engine::Context,
    modules::security::embed::without_comment_lines,
    modules::security::pins::{ACTIONLINT, INSTALL_TOOL},
    modules::stack_packs::{PinTable, required_packs},
    refuse,
};
use std::fmt::Write as _;

/// The generated workflow in a repository without workflows of its own.
pub const WORKFLOW_PATH: &str = ".github/workflows/ci.yml";
/// actionlint's configuration, rendered when the runner is not GitHub-hosted.
pub const ACTIONLINT_CONFIG_PATH: &str = ".github/actionlint.yaml";
/// The branch whose pushes run the workflow.
pub const DEFAULT_BRANCH: &str = "main";
/// `timeout-minutes` of the verification jobs without a declared cycle budget.
pub const CHECKS_TIMEOUT: u32 = 15;
/// The job of the held-out tests.
pub const HELDOUT_JOB: &str = "heldout";
/// The job of the held-out properties (#980).
pub const HELDOUT_PROPERTIES_JOB: &str = "heldout-properties";
/// `timeout-minutes` of the held-out properties job.
pub const HELDOUT_PROPERTIES_TIMEOUT: u32 = 20;
/// The artifact of a failed properties run: proptest's persisted failures.
pub const HELDOUT_PROPERTIES_ARTIFACT: &str = "heldout-properties-failures";
/// `timeout-minutes` of scope, workflow-lint and required.
pub const SHORT_TIMEOUT: u32 = 5;
/// The push-only macOS job (#784).
pub const MACOS_JOB: &str = "macos";
/// `timeout-minutes` of the macOS job.
pub const MACOS_TIMEOUT: u32 = 40;

const HEADER: &str = include_str!("../../../../../templates/ci-baseline/fragments/header.yml");
const ACTIONLINT_CONFIG: &str =
    include_str!("../../../../../templates/ci-baseline/fragments/actionlint.yaml");
/// The step that runs one declared command, read at run time.
pub const DECLARED_SH: &str =
    include_str!("../../../../../templates/ci-baseline/fragments/declared.sh");
/// The step that runs the held-out tests' command.
pub const HELDOUT_SH: &str =
    include_str!("../../../../../templates/ci-baseline/fragments/heldout.sh");
/// The step that draws, prints and records the held-out seed.
/// The pending held-out job's timeout (#1362): it only lists a directory.
pub const HELDOUT_PENDING_TIMEOUT: u32 = 5;
/// The held-out job's step while no held-out test exists (#1362).
pub const HELDOUT_PENDING_SH: &str =
    include_str!("../../../../../templates/ci-baseline/fragments/heldout-pending.sh");
pub const HELDOUT_SEED_SH: &str =
    include_str!("../../../../../templates/ci-baseline/fragments/heldout-seed.sh");
/// The step that runs the held-out properties' command with the seed.
pub const HELDOUT_PROPERTIES_SH: &str =
    include_str!("../../../../../templates/ci-baseline/fragments/heldout-properties.sh");
/// The step that runs one shard of `ci.shards.command`.
pub const SHARD_SH: &str = include_str!("../../../../../templates/ci-baseline/fragments/shard.sh");

use crate::config::NamedRunner;

/// The GitHub-hosted labels the renderer owns.
const GITHUB_LINUX: &str = "ubuntu-24.04";
const GITHUB_MACOS: &str = "macos-15";

/// The `runs-on` label of the Linux jobs: the configured runner's label, else
/// GitHub-hosted (also when `Configured` is asked for and none is configured).
pub fn runner_label(runner: Runner) -> &'static str {
    runner_label_with(runner, crate::config::linux_runner())
}

/// `runner_label` with the configured runner explicit.
pub fn runner_label_with(runner: Runner, configured: Option<&NamedRunner>) -> &str {
    match (runner, configured) {
        (Runner::Configured, Some(r)) => &r.label,
        _ => GITHUB_LINUX,
    }
}

/// The `runs-on` label of the push-only macOS job: the configured runner by
/// default, a GitHub-hosted image only when answered or when none is configured
/// (decision 2026-10-28, point 5; always an auditor warning).
pub fn macos_label(runner: MacosRunner) -> &'static str {
    macos_label_with(runner, crate::config::macos_runner())
}

/// `macos_label` with the configured runner explicit.
pub fn macos_label_with(runner: MacosRunner, configured: Option<&NamedRunner>) -> &str {
    match (runner, configured) {
        (MacosRunner::Configured, Some(r)) => &r.label,
        _ => GITHUB_MACOS,
    }
}

/// The one message `.github/actionlint.yaml` ignores: actionlint 1.7.12 rejects
/// the `cache-mode` job key GitHub enforces (rhysd/actionlint#762; "CI hardening
/// for agent workflows", 2026-10-29). The ignore leaves with the actionlint bump
/// that accepts the key.
pub const CACHE_MODE_IGNORE: &str = "unexpected key \"cache-mode\"";
const RUNNER_BLOCK: &str = "self-hosted-runner:\n  labels:\n    - {{labels}}\n";
const IGNORE_BLOCK: &str = "paths:\n  .github/workflows/**/*.{yml,yaml}:\n    ignore:\n      # actionlint 1.7.12 rejects the `cache-mode` job key GitHub enforces\n      # (rhysd/actionlint#762); the ignore leaves with the actionlint bump that accepts it.\n      - '{{ignore}}'\n";

/// `.github/actionlint.yaml` when the repository needs one: the labels actionlint
/// does not know (the configured runners' labels for the Linux jobs and the macOS job,
/// #784, then `existing`, the custom labels the project's own jobs
/// already run on, #1167, #1215), and [`CACHE_MODE_IGNORE`] when a job of `workflow` declares
/// `cache-mode` or `other_cache_mode` says another rendered workflow does
/// (agent-guardrails' `agentic-implement.yml`, #970); `None` when neither
/// applies. No other finding is ever suppressed.
pub fn actionlint_config(
    runner: Runner,
    macos: Option<MacosRunner>,
    workflow: &str,
    other_cache_mode: bool,
    existing: &[String],
) -> Option<String> {
    let mut blocks = String::new();
    let mut labels: Vec<String> = [
        (runner == Runner::Configured && crate::config::linux_runner().is_some())
            .then(|| runner_label(runner)),
        (macos == Some(MacosRunner::Configured) && crate::config::macos_runner().is_some())
            .then(|| macos_label(MacosRunner::Configured)),
    ]
    .into_iter()
    .flatten()
    .map(str::to_owned)
    .collect();
    for label in existing {
        if !labels.contains(label) {
            labels.push(label.clone());
        }
    }
    if !labels.is_empty() {
        let labels: Vec<String> = labels.iter().map(|l| scalar(l)).collect();
        blocks.push_str(&RUNNER_BLOCK.replace("{{labels}}", &labels.join("\n    - ")));
    }
    if other_cache_mode || workflow.contains("\n    cache-mode:") {
        blocks.push_str(&IGNORE_BLOCK.replace("{{ignore}}", CACHE_MODE_IGNORE));
    }
    (!blocks.is_empty()).then(|| {
        ACTIONLINT_CONFIG
            .replace("{{version}}", CI_BASELINE_VERSION)
            .replace("{{blocks}}", &blocks)
    })
}

/// One measurement of the suite: `ceil(ci.cycle_budget_minutes * 1.5)` when the
/// profile declares a finite positive budget. The checks jobs' timeout, and the
/// unit of security's coverage jobs (#1213).
pub fn measurement_minutes(cx: &Context<'_>) -> Option<u32> {
    cx.profile.value["ci"]["cycle_budget_minutes"]
        .as_f64()
        .filter(|m| m.is_finite() && *m > 0.0)
        .map(|m| (m * 1.5).ceil() as u32)
}

/// GitHub's job maximum: the default `timeout-minutes`, the execution limit of
/// a GitHub-hosted job and a step's maximum on every runner (GitHub Docs,
/// "Workflow syntax" and "Actions limits"). Every budget-derived timeout is
/// capped here (#1228).
pub const JOB_TIMEOUT_MAX: u32 = 360;

/// The jobs that take [`checks_timeout`], beside each `<app>-checks`.
const BUDGET_JOBS: [&str; 4] = ["checks", "lint", "shard", HELDOUT_JOB];

/// `minutes` within [`JOB_TIMEOUT_MAX`].
pub fn within_job_max(minutes: u32) -> u32 {
    minutes.min(JOB_TIMEOUT_MAX)
}

/// The plan note for the budget-derived `timeouts` (job id, uncapped minutes)
/// above [`JOB_TIMEOUT_MAX`], in the order given; `None` when none is.
pub fn over_job_max_note(cx: &Context<'_>, timeouts: &[(String, u32)]) -> Option<String> {
    let over: Vec<String> = timeouts
        .iter()
        .filter(|(_, minutes)| *minutes > JOB_TIMEOUT_MAX)
        .map(|(id, minutes)| format!("{id} {minutes}"))
        .collect();
    (!over.is_empty()).then(|| {
        format!(
            "ci.cycle_budget_minutes {} derives timeouts above GitHub's {JOB_TIMEOUT_MAX}-minute job maximum ({}); those jobs render timeout-minutes: {JOB_TIMEOUT_MAX}",
            cx.profile.value["ci"]["cycle_budget_minutes"],
            over.join(", ")
        )
    })
}

/// [`measurement_minutes`] when declared, else `CHECKS_TIMEOUT`; uncapped.
pub(super) fn checks_timeout(cx: &Context<'_>) -> u32 {
    measurement_minutes(cx).unwrap_or(CHECKS_TIMEOUT)
}

/// `heldout-properties`: `max(20, one measurement)` when declared, else 20; uncapped.
fn heldout_properties_timeout(cx: &Context<'_>) -> u32 {
    measurement_minutes(cx).map_or(HELDOUT_PROPERTIES_TIMEOUT, |m| {
        HELDOUT_PROPERTIES_TIMEOUT.max(m)
    })
}

/// The budget-derived jobs of `workflow` with their uncapped timeouts, in
/// workflow order: every job whose timeout follows the budget (#1228).
pub fn budget_timeouts(cx: &Context<'_>, workflow: &Workflow) -> Vec<(String, u32)> {
    if measurement_minutes(cx).is_none() {
        return Vec::new();
    }
    workflow
        .jobs
        .iter()
        .filter(|job| job.call.is_none())
        .filter_map(|job| {
            let minutes = if job.id == HELDOUT_PROPERTIES_JOB {
                heldout_properties_timeout(cx)
            } else if BUDGET_JOBS.contains(&job.id.as_str()) || job.id.ends_with("-checks") {
                checks_timeout(cx)
            } else {
                return None;
            };
            Some((job.id.clone(), minutes))
        })
        .collect()
}

fn expr(text: &str) -> String {
    format!("${{{{ {text} }}}}")
}

fn declared(command: Command) -> Step {
    Step::new(format!("Run declared {}", command.as_str()))
        .env("NAME", command.as_str())
        .run(without_comment_lines(DECLARED_SH))
}

/// The declared-command steps of one app, run in its directory so the
/// fragment reads the app's own profile.
fn app_steps(app: &AppCommands) -> Vec<Step> {
    app.commands
        .iter()
        .map(|c| {
            let step = declared(*c);
            if app.path == "." {
                step
            } else {
                step.working_directory(app.path.clone())
            }
        })
        .collect()
}

/// The job of the root profile's commands in monorepo mode (#1165), the id of
/// single mode's: an app's job always ends in `-checks`, so none can take it.
pub const ROOT_JOB: &str = "checks";

/// The id of an app's job in monorepo mode.
pub fn app_job(id: &str) -> String {
    format!("{id}-checks")
}

/// The model of the workflow. Under `workflow: existing` it is the separate
/// `agentic-security.yml` (scope, the contributed jobs, `agentic-required`), or
/// `None` when no module contributes a job.
pub fn workflow(cx: &Context<'_>, answers: &CiBaselineAnswers) -> Result<Option<Workflow>> {
    // Checked before anything else: a collision refuses even when nothing renders.
    let contributed = compose::contributed(cx)?;
    // Under `seed` and `existing` the project's CI runs the commands: this is the
    // separate workflow of the judges alone (#21).
    let existing = answers.workflow.project_owns_ci();
    // Under `seed` the judges always render: `agentic-required` alone checks
    // `human-approved` on protected paths, which the seed does not (#21).
    if answers.workflow == WorkflowMode::Existing && contributed.is_empty() && !answers.heldout {
        return Ok(None);
    }
    if answers.workflow == WorkflowMode::Existing
        && answers.aggregate_check == CONTRIBUTED_AGGREGATE_CHECK
    {
        return refuse(format!(
            "ci-baseline: aggregate_check {CONTRIBUTED_AGGREGATE_CHECK} is the check of {SEPARATE_PATH}; answer the project's own required check"
        ));
    }
    let pins = PinTable::embedded()?;
    let label = runner_label(answers.runner);
    let checkout = Step::new("Check out")
        .uses(pins.action("actions/checkout")?)
        .with("persist-credentials", "false");
    let mut setup = vec![checkout.clone()];
    // Linux jobs set up the Linux apps; a pack with a macOS target is set up
    // in the macOS job alone (#784).
    let packs = if !existing || answers.heldout {
        required_packs(cx)?
    } else {
        Vec::new()
    };
    let mut app_setup = std::collections::BTreeMap::new();
    for (app, pack) in &packs {
        let steps = (pack.ci_setup)(app, &pins)?;
        if !pack.macos_target {
            setup.extend(steps.iter().cloned());
        }
        app_setup.insert(app.id.clone(), steps);
    }
    let shards = shard_count(cx);
    let timeout = within_job_max(checks_timeout(cx));
    // The root profile's services (#1170) go to the jobs that run its commands.
    let root_services = super::services::of_root(cx)?;
    let job = |id: &str, timeout_minutes: u32, steps: Vec<Step>| Job {
        call: None,
        services: Default::default(),
        id: id.to_owned(),
        name: id.to_owned(),
        runs_on: label.to_owned(),
        timeout_minutes,
        needs: vec!["scope".to_owned()],
        condition: None,
        matrix: None,
        outputs: Vec::new(),
        steps,
        skippable: Skippable::Never,
        permissions: Vec::new(),
    };
    let verification = |id: &str, steps: Vec<Step>| Job {
        condition: Some(format!(
            "needs.scope.outputs.tier != '{}'",
            scope::TIER_DOCS
        )),
        skippable: Skippable::When(SkipWhen::TierDocs),
        services: root_services.clone(),
        ..job(id, timeout, setup.iter().cloned().chain(steps).collect())
    };

    // The root profile's own commands in monorepo mode (#1165).
    let root_commands = answers.root_commands.as_deref().unwrap_or_default();
    let root_job = !existing && !root_commands.is_empty();
    // Contributed jobs of one app (#1097): handed to scope with the lines that
    // read them, only when there are some, so other workflows are unchanged.
    let app_jobs: Vec<String> = contributed
        .iter()
        .filter_map(|c| c.app.as_ref().map(|app| format!("{}={app}", c.id)))
        .collect();
    let scope_step = Step::new("Decide the tier and the skippable jobs")
        .id("scope")
        .env("EVENT", expr("github.event_name"))
        .env("BASE_SHA", expr("github.event.pull_request.base.sha"))
        .env("HEAD_SHA", expr("github.event.pull_request.head.sha"))
        .env("INERT_PATHS", answers.inert_paths.join("\n"))
        .env(
            "DOCS_SKIPPABLE",
            (if existing {
                Vec::new()
            } else if !answers.apps.is_empty() {
                answers
                    .apps
                    .iter()
                    .map(|a| app_job(&a.id))
                    .chain(root_job.then(|| ROOT_JOB.to_owned()))
                    .collect()
            } else {
                scope::docs_skippable(shards.unwrap_or(1))
            })
            .into_iter()
            .chain(answers.heldout.then(|| HELDOUT_JOB.to_owned()))
            .chain(
                answers
                    .heldout_properties_command
                    .as_ref()
                    .map(|_| HELDOUT_PROPERTIES_JOB.to_owned()),
            )
            .chain(
                contributed
                    .iter()
                    .filter(|c| c.docs_skippable)
                    .map(|c| c.id.clone()),
            )
            .collect::<Vec<_>>()
            .join("\n"),
        )
        .env(
            "APPS",
            answers
                .apps
                .iter()
                .map(|a| format!("{}={}", a.id, a.path))
                .collect::<Vec<_>>()
                .join("\n"),
        )
        .env("PROTECTED_PATHS", answers.protected_paths.join("\n"));
    let scope_step = if app_jobs.is_empty() {
        scope_step
    } else {
        scope_step.env("APP_JOBS", app_jobs.join("\n"))
    }
    .run(without_comment_lines(&scope::script(!app_jobs.is_empty())));
    let mut jobs = vec![Job {
        needs: Vec::new(),
        outputs: ["tier", "skippable", "protected"]
            .map(|o| (o.to_owned(), expr(&format!("steps.scope.outputs.{o}"))))
            .to_vec(),
        ..job(
            "scope",
            SHORT_TIMEOUT,
            vec![checkout.clone().with("fetch-depth", "0"), scope_step],
        )
    }];
    // Monorepo mode (#784): one job per app, in its directory, with its own
    // setup; skipped on purpose when scope lists it (tier docs, or the app
    // unchanged).
    for app in &answers.apps {
        let id = app_job(&app.id);
        let steps = std::iter::once(checkout.clone())
            .chain(app_setup.get(&app.id).into_iter().flatten().cloned())
            .chain(app_steps(app))
            .collect();
        jobs.push(Job {
            condition: Some(format!(
                "contains(fromJSON(needs.scope.outputs.skippable), '{id}') == false"
            )),
            skippable: Skippable::When(SkipWhen::AppUnchanged),
            services: super::services::of_dir(cx, &app.path)?,
            ..job(&id, timeout, steps)
        });
    }
    // Monorepo mode (#1165): the root profile's commands at the root, with every
    // Linux app's setup, skipped only under tier docs like single mode's.
    if root_job {
        jobs.push(verification(
            ROOT_JOB,
            root_commands.iter().copied().map(declared).collect(),
        ));
    }
    // The project verifies its own commands under `workflow: existing`.
    if !existing && answers.apps.is_empty() {
        // An answered command that is null renders no step; `notes` says so.
        let commands = answers
            .commands
            .iter()
            .copied()
            .filter(|c| is_declared(cx, *c));
        // `reusable: true` (#785): `checks` calls the callee this repository
        // hosts, which owns the runner, the timeout and the steps.
        let call = super::reusable::decide(cx, answers)?;
        match (shards, call) {
            (None, super::reusable::Decision::Call(_)) if !root_services.is_empty() => {
                return refuse(
                    "ci-baseline: ci.services and ci.env need checks to run in this workflow; reusable: true calls a workflow that cannot carry them",
                );
            }
            (None, super::reusable::Decision::Call(call)) => jobs.push(Job {
                call: Some(call),
                services: Default::default(),
                ..verification("checks", Vec::new())
            }),
            (None, _) => jobs.push(verification("checks", commands.map(declared).collect())),
            (Some(count), _) => {
                // The shards replace the test run; every other declared command
                // runs in `lint`.
                let rest: Vec<Step> = commands
                    .filter(|c| !matches!(c, Command::Test | Command::Verify))
                    .map(declared)
                    .collect();
                if !rest.is_empty() {
                    jobs.push(verification("lint", rest));
                }
                let shard = Step::new("Run declared shard")
                    .env("SHARD", expr("matrix.shard"))
                    .env("COUNT", count.to_string())
                    .run(without_comment_lines(SHARD_SH));
                jobs.push(Job {
                    name: format!("shard {}/{count}", expr("matrix.shard")),
                    matrix: Some(Matrix {
                        key: "shard".to_owned(),
                        values: (1..=count).collect(),
                    }),
                    ..verification("shard", vec![shard])
                });
            }
        }
    }
    // The held-out tests run in either mode: under `existing` they join
    // `agentic-required`, since the project's own workflow cannot carry them.
    if let Some(command) = &answers.heldout_command {
        let run = Step::new("Run held-out tests")
            .env("HELDOUT_COMMAND", command)
            .run(without_comment_lines(HELDOUT_SH));
        jobs.push(Job {
            timeout_minutes: timeout,
            ..verification(HELDOUT_JOB, vec![run])
        });
    } else if answers.heldout {
        // Pending (#1362): passes, saying so, only while the directory holds no
        // file. It runs `find` alone, so it sets up no stack and no service.
        let run = Step::new("Check held-out tests are pending")
            .env("HELDOUT_DIR", &answers.heldout_dir)
            .run(without_comment_lines(HELDOUT_PENDING_SH));
        jobs.push(Job {
            condition: Some(format!(
                "needs.scope.outputs.tier != '{}'",
                scope::TIER_DOCS
            )),
            skippable: Skippable::When(SkipWhen::TierDocs),
            ..job(
                HELDOUT_JOB,
                HELDOUT_PENDING_TIMEOUT,
                vec![checkout.clone(), run],
            )
        });
    }
    // The held-out properties (#980): a fresh seed per run, printed and
    // recorded, mapped into the runner's environment in the YAML itself.
    if let Some(command) = &answers.heldout_properties_command {
        let seed = expr("steps.seed.outputs.seed");
        let examples = answers.heldout_examples.to_string();
        let draw = Step::new("Draw the held-out seed")
            .id("seed")
            .run(without_comment_lines(HELDOUT_SEED_SH));
        let run = super::model::property_recipes(cx)?
            .iter()
            .flat_map(|recipe| recipe.seed_env.iter())
            .fold(
                Step::new("Run held-out properties")
                    .env("HELDOUT_SEED", seed.clone())
                    .env("HELDOUT_EXAMPLES", examples.clone())
                    .env("HELDOUT_PROPERTIES_COMMAND", command),
                |step, (name, value)| {
                    step.env(
                        *name,
                        value
                            .replace("{{seed}}", &seed)
                            .replace("{{examples}}", &examples),
                    )
                },
            )
            .run(without_comment_lines(HELDOUT_PROPERTIES_SH));
        let mut upload = Step::new("Upload persisted property failures")
            .uses(pins.action("actions/upload-artifact")?)
            .with("name", HELDOUT_PROPERTIES_ARTIFACT)
            .with(
                "path",
                "**/proptest-regressions/\n**/*.proptest-regressions\n",
            )
            .with("if-no-files-found", "ignore")
            .with("retention-days", "7");
        upload.condition = Some("failure()".to_owned());
        jobs.push(Job {
            timeout_minutes: within_job_max(heldout_properties_timeout(cx)),
            ..verification(HELDOUT_PROPERTIES_JOB, vec![draw, run, upload])
        });
    }
    // The push-only macOS job (#784): the macOS-target apps, each in its
    // directory with its pack's setup; skipped and sanctioned on other events.
    if let (Some(runner), false) = (answers.macos_runner, answers.macos_apps.is_empty()) {
        let steps = std::iter::once(checkout.clone())
            .chain(answers.macos_apps.iter().flat_map(|app| {
                app_setup
                    .get(&app.id)
                    .into_iter()
                    .flatten()
                    .cloned()
                    .chain(app_steps(app))
                    .collect::<Vec<_>>()
            }))
            .collect();
        jobs.push(Job {
            runs_on: macos_label(runner).to_owned(),
            condition: Some("github.event_name == 'push'".to_owned()),
            skippable: Skippable::When(SkipWhen::NotPush),
            ..job(MACOS_JOB, MACOS_TIMEOUT, steps)
        });
    }
    // workflow-lint is a judge: under `existing` the project's own workflow
    // already carries one, under `seed` the seed does not (#21).
    if answers.workflow != WorkflowMode::Existing {
        let tool = |key: &str| -> Result<String> { Ok(pins.tool(key)?.version.clone()) };
        // actionlint is a checksum-pinned binary from security's table, installed
        // by security's fragment; it reads `.github/actionlint.yaml` for the label.
        let install_actionlint = ACTIONLINT
            .env()
            .into_iter()
            .fold(Step::new("Install actionlint"), |step, (k, v)| {
                step.env(k, v)
            })
            .run(without_comment_lines(INSTALL_TOOL));
        jobs.push(Job {
            condition: Some(
                "contains(fromJSON(needs.scope.outputs.skippable), 'workflow-lint') == false"
                    .to_owned(),
            ),
            skippable: Skippable::When(SkipWhen::NoWorkflowChange),
            ..job(
                "workflow-lint",
                SHORT_TIMEOUT,
                vec![
                    checkout,
                    install_actionlint,
                    Step::new("Lint workflows with actionlint").run("actionlint"),
                    Step::new("Audit workflows with zizmor")
                        .uses(pins.action("zizmorcore/zizmor-action")?)
                        .with("version", tool("zizmor")?)
                        .with("persona", "regular")
                        .with("min-severity", "medium")
                        .with("advanced-security", "false")
                        .with("annotations", "true"),
                ],
            )
        });
    }
    let needs = jobs
        .iter()
        .map(|j| j.id.clone())
        .chain(contributed.iter().map(|c| c.id.clone()))
        .collect();
    jobs.push(Job {
        needs,
        condition: Some("always()".to_owned()),
        // Rule 3 reads who added `human-approved` from the pull request's issue
        // events (#1255); the job checks nothing out.
        permissions: AGGREGATE_PERMISSIONS
            .iter()
            .map(|(scope, access)| ((*scope).to_owned(), (*access).to_owned()))
            .collect(),
        ..job(
            if existing {
                CONTRIBUTED_AGGREGATE_CHECK
            } else {
                AGGREGATE_CHECK
            },
            SHORT_TIMEOUT,
            vec![
                Step::new("Decide the required check")
                    .env("SCOPE", expr("needs.scope.result"))
                    .env("TIER", expr("needs.scope.outputs.tier"))
                    .env("SKIPPABLE", expr("needs.scope.outputs.skippable"))
                    .env("NEEDS", expr("toJSON(needs)"))
                    .env("EVENT", expr("github.event_name"))
                    .env("PROTECTED", expr("needs.scope.outputs.protected"))
                    .env(
                        "PR_LABELS",
                        expr("toJSON(github.event.pull_request.labels.*.name)"),
                    )
                    .env("PR_NUMBER", expr("github.event.pull_request.number"))
                    .env("REPOSITORY", expr("github.repository"))
                    .env("GH_TOKEN", expr("github.token"))
                    .env("EVENT_ACTION", expr("github.event.action"))
                    .env("EVENT_LABEL", expr("github.event.label.name"))
                    .env("SENDER_LOGIN", expr("github.event.sender.login"))
                    .env("SENDER_TYPE", expr("github.event.sender.type"))
                    .run(without_comment_lines(REQUIRED_SH)),
            ],
        )
    });
    let (path, name) = if existing {
        (SEPARATE_PATH, SEPARATE_NAME)
    } else {
        (WORKFLOW_PATH, "CI")
    };
    Ok(Some(Workflow {
        path: path.to_owned(),
        name: name.to_owned(),
        merge_queue: answers.merge_queue,
        jobs,
        contributed,
    }))
}

/// A scalar as YAML reads it back as the same string: plain when it is a word
/// YAML cannot mistake for anything else, double-quoted otherwise.
fn scalar(text: &str) -> String {
    let plain = text.starts_with(|c: char| c.is_ascii_alphabetic())
        && !text.ends_with(' ')
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || " -_./".contains(c))
        && !["true", "false", "yes", "no", "on", "off", "null", "y", "n"]
            .contains(&text.to_ascii_lowercase().as_str());
    if plain {
        text.to_owned()
    } else {
        let escaped = text.replace('\\', "\\\\").replace('"', "\\\"");
        format!("\"{escaped}\"")
    }
}

/// `key: value` at `indent`; a multi-line value becomes a literal block,
/// clipped when it ends with a newline and stripped otherwise.
fn field(out: &mut String, indent: usize, key: &str, value: &str) {
    let pad = " ".repeat(indent);
    if !value.contains('\n') {
        let _ = writeln!(out, "{pad}{key}: {}", scalar(value));
        return;
    }
    let (body, chomp) = match value.strip_suffix('\n') {
        Some(body) => (body, "|"),
        None => (value, "|-"),
    };
    let _ = writeln!(out, "{pad}{key}: {chomp}");
    for line in body.lines() {
        if line.is_empty() {
            out.push('\n');
        } else {
            let _ = writeln!(out, "{pad}  {line}");
        }
    }
}

/// `key:` and one `field` per entry below it; nothing when there is no entry.
fn map<'a>(
    out: &mut String,
    indent: usize,
    key: &str,
    entries: impl IntoIterator<Item = (&'a String, &'a String)>,
) {
    let mut entries = entries.into_iter().peekable();
    if entries.peek().is_none() {
        return;
    }
    let _ = writeln!(out, "{}{key}:", " ".repeat(indent));
    for (k, v) in entries {
        field(out, indent + 2, k, v);
    }
}

/// One `steps:` item, at the indentation of a job's steps.
pub fn step(out: &mut String, step: &Step) {
    let mut lines = String::new();
    if let Some(id) = &step.id {
        field(&mut lines, 0, "id", id);
    }
    field(&mut lines, 0, "name", &step.name);
    if let Some(condition) = &step.condition {
        let _ = writeln!(lines, "if: {condition}");
    }
    if let Some(action) = &step.uses {
        let _ = writeln!(lines, "uses: {}", action.uses());
    }
    if let Some(dir) = &step.working_directory {
        field(&mut lines, 0, "working-directory", dir);
    }
    map(&mut lines, 0, "with", &step.with);
    map(&mut lines, 0, "env", &step.env);
    if let Some(run) = &step.run {
        field(&mut lines, 0, "run", run);
    }
    for (i, line) in lines.lines().enumerate() {
        let lead = if i == 0 { "      - " } else { "        " };
        if line.is_empty() {
            out.push('\n');
        } else {
            let _ = writeln!(out, "{lead}{line}");
        }
    }
}

/// A contributed job: its id, then its body indented under it, verbatim.
fn contributed_job(out: &mut String, job: &Contributed) {
    let _ = writeln!(out, "  {}:", job.id);
    for line in job.yaml.lines() {
        if line.is_empty() {
            out.push('\n');
        } else {
            let _ = writeln!(out, "    {line}");
        }
    }
}

/// The workflow text: the header fragment, then every job in order.
pub fn to_yaml(workflow: &Workflow) -> String {
    to_yaml_with(HEADER, workflow)
}

/// `to_yaml` under another header fragment (the seed's, #21).
pub(super) fn to_yaml_with(header: &str, workflow: &Workflow) -> String {
    let mut out = header
        .replace("{{name}}", &workflow.name)
        .replace("{{version}}", CI_BASELINE_VERSION)
        .replace("{{default_branch}}", DEFAULT_BRANCH)
        .replace(
            "{{merge_group}}",
            if workflow.merge_queue {
                "  merge_group:\n"
            } else {
                ""
            },
        );
    out.push_str("jobs:\n");
    let aggregate = workflow.jobs.len().saturating_sub(1);
    for (i, job) in workflow.jobs.iter().enumerate() {
        if i == aggregate {
            for c in &workflow.contributed {
                contributed_job(&mut out, c);
            }
        }
        let _ = writeln!(out, "  {}:", job.id);
        field(&mut out, 4, "name", &job.name);
        match job.needs.as_slice() {
            [] => {}
            [one] => {
                let _ = writeln!(out, "    needs: {one}");
            }
            many => {
                let _ = writeln!(out, "    needs: [{}]", many.join(", "));
            }
        }
        if let Some(condition) = &job.condition {
            let _ = writeln!(out, "    if: {condition}");
        }
        if let Some(call) = &job.call {
            let _ = writeln!(out, "    uses: {}", call.uses);
            map(&mut out, 4, "with", call.with.iter().map(|(k, v)| (k, v)));
            continue;
        }
        map(
            &mut out,
            4,
            "permissions",
            job.permissions.iter().map(|(k, v)| (k, v)),
        );
        let _ = writeln!(out, "    runs-on: {}", job.runs_on);
        let _ = writeln!(out, "    timeout-minutes: {}", job.timeout_minutes);
        if let Some(matrix) = &job.matrix {
            let values: Vec<String> = matrix.values.iter().map(u32::to_string).collect();
            let _ = writeln!(
                out,
                "    strategy:\n      fail-fast: false\n      matrix:\n        {}: [{}]",
                matrix.key,
                values.join(", ")
            );
        }
        map(
            &mut out,
            4,
            "outputs",
            job.outputs.iter().map(|(k, v)| (k, v)),
        );
        for line in super::services::yaml(&job.services).lines() {
            let _ = writeln!(out, "    {line}");
        }
        out.push_str("    steps:\n");
        for s in &job.steps {
            step(&mut out, s);
        }
    }
    out
}

#[cfg(test)]
mod runner_tests {
    use super::*;
    use crate::modules::ci_baseline::{MacosRunner, Runner};

    #[test]
    fn with_no_runner_configured_only_github_hosted_runners_exist_and_render() {
        assert_eq!(Runner::available_with(false), vec![Runner::Github]);
        assert_eq!(Runner::default_with(false), Runner::Github);
        assert_eq!(
            MacosRunner::available_with(false),
            vec![MacosRunner::GithubHosted]
        );
        assert_eq!(MacosRunner::default_with(false), MacosRunner::GithubHosted);
        assert_eq!(runner_label_with(Runner::Configured, None), "ubuntu-24.04");
        assert_eq!(macos_label_with(MacosRunner::Configured, None), "macos-15");
    }

    #[test]
    fn a_configured_runner_is_offered_by_default_and_renders_its_label() {
        let linux = NamedRunner {
            name: "custom".into(),
            label: "custom-2".into(),
        };
        let mac = NamedRunner {
            name: "macfarm".into(),
            label: "mac-1".into(),
        };
        assert_eq!(Runner::available_with(true), Runner::ALL.to_vec());
        assert_eq!(Runner::default_with(true), Runner::Configured);
        assert_eq!(MacosRunner::default_with(true), MacosRunner::Configured);
        assert_eq!(
            runner_label_with(Runner::Configured, Some(&linux)),
            "custom-2"
        );
        assert_eq!(
            runner_label_with(Runner::Github, Some(&linux)),
            "ubuntu-24.04"
        );
        assert_eq!(
            macos_label_with(MacosRunner::Configured, Some(&mac)),
            "mac-1"
        );
        assert_eq!(
            macos_label_with(MacosRunner::GithubHosted, Some(&mac)),
            "macos-15"
        );
    }
}
