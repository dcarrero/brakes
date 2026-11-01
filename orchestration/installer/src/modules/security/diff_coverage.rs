//! `diff-coverage` (SPEC-security.md, "Changed-line coverage", slice 3b; #978;
//! decision "Testing brakes moved into the 7 November scope", points 1 and 2):
//! every line a pull request changes is executed by a test, and a source file it
//! modifies had a test executing it at the merge base. Contributed through
//! `ci_jobs` like the other jobs, skippable under tier `docs`, every step
//! conditioned on a pull request (never the job, so a push passes with no step);
//! the shell is `templates/security/fragments/diff-coverage.sh`.
//!
//! The base report is one cache entry per commit, `coverage-report-<sha>`,
//! holding `.coverage-base/<app>/<report>` for every judged app: saved on pushes
//! to the default branch by `coverage-ratchet` when it is answered, else by this
//! job itself (#1130); restored here by the merge-base SHA, and recomputed per app
//! at the merge base on a miss. Every app whose pack has a per-file report is
//! judged in its own directory (the spec's Open question 14, closed).
use super::embed::without_comment_lines;
use super::jobs::{BYPASS_VARIABLE, coverage_timeout, fill, indent, runner, step_yaml};
use crate::{
    Result,
    engine::{CiJob, CiTier, Context},
    modules::stack_packs::{
        App, CoverageRecipe, DEFAULT_BRANCH_CONDITION, PinTable, StackId, Step, packs,
        required_packs,
    },
    refuse,
};
use serde_json::Value;

pub const DIFF_COVERAGE: &str = "diff-coverage";
/// Where the base report is restored and saved: outside every app directory,
/// so it never overwrites the head report.
pub const BASE_DIR: &str = ".coverage-base";
/// The default of `coverage_changed_lines_min` (Open question 10's proposal; unsourced).
pub const DEFAULT_MIN: u64 = 80;

const JOB: &str = include_str!("../../../../../templates/security/fragments/diff-coverage.yml");
/// Steps 2 and 3 of the job.
pub const DIFF_COVERAGE_SH: &str =
    include_str!("../../../../../templates/security/fragments/diff-coverage.sh");
/// The heredoc delimiter that writes the shell; no line of it equals this.
const HEREDOC: &str = "DIFF_COVERAGE_SH";
/// The judging steps: a pull request, and no bypass granted.
const PR_RUN: &str = "github.event_name == 'pull_request' && steps.bypass.outputs.id == ''";

/// A push to the default branch, where the base report is kept for later pull requests.
fn push_to_default() -> String {
    format!("github.event_name == 'push' && {DEFAULT_BRANCH_CONDITION}")
}

/// A pull request, or a push to the default branch when this job keeps the base report.
fn either_event() -> String {
    format!(
        "(github.event_name == 'pull_request' || ({}))",
        push_to_default()
    )
}

/// Every app this job judges, its minimum, and whether it saves the base report itself.
pub struct Judged {
    pub apps: Vec<(App, CoverageRecipe)>,
    pub min: u64,
    /// `coverage_ratchet` is not `true`: nobody else saves the base report.
    pub saves: bool,
}

/// The report format, the judged source extension and what an absent file
/// means: cargo-llvm-cov lists every source compiled into the tests, coverage.py
/// only those it imported unless `[tool.coverage.run] source` is set.
fn stack_shell(stack: StackId) -> Option<(&'static str, &'static str, &'static str)> {
    match stack {
        StackId::Rust => Some(("lcov", "rs", "fail")),
        StackId::PythonUv => Some(("cobertura", "py", "warn")),
        _ => None,
    }
}

/// The pattern answer naming the tests coverage measures for one app (#1177).
pub const TEST_ARGS: &str = "coverage_test_args";

/// `coverage_test_args.<app id>` for `app`: the test selection the project
/// answered, in place of the pack's `default_tests`; `None` when unanswered.
pub fn test_args<'a>(cx: &'a Context<'_>, app: &App) -> Option<&'a str> {
    cx.answers
        .get(&format!("{TEST_ARGS}.{}", app.id))
        .and_then(Value::as_str)
}

/// Refuses a `coverage_test_args.<id>` that names no app whose pack declares
/// coverage, spans lines, or holds an expression: it is baked into a `run:`
/// and an `env:` value, where `${{` would be evaluated.
pub fn check_test_args(cx: &Context<'_>) -> Result<()> {
    let prefix = format!("{TEST_ARGS}.");
    let answered: Vec<(&str, &str)> = cx
        .answers
        .iter()
        .filter_map(|(key, value)| Some((key.strip_prefix(&prefix)?, value.as_str()?)))
        .collect();
    if answered.is_empty() {
        return Ok(());
    }
    let covered: Vec<String> = required_packs(cx)?
        .into_iter()
        .filter(|(_, pack)| pack.coverage.is_some())
        .map(|(app, _)| app.id)
        .collect();
    for (id, args) in answered {
        if !covered.iter().any(|c| c == id) {
            return refuse(format!(
                "Module security: {TEST_ARGS}.{id} names no app whose stack pack declares coverage (python-uv, rust)"
            ));
        }
        if args.contains(['\n', '\r', '\0']) {
            return refuse(format!(
                "Module security: {TEST_ARGS}.{id} must be one line"
            ));
        }
        if args.contains("${{") {
            return refuse(format!(
                "Module security: {TEST_ARGS}.{id} must not contain ${{{{; it is baked into the workflow"
            ));
        }
    }
    Ok(())
}

/// The apps of the plan whose pack declares a per-file report, in stack-packs' order.
pub fn covered_apps(cx: &Context<'_>) -> Result<Vec<(App, CoverageRecipe)>> {
    Ok(required_packs(cx)?
        .into_iter()
        .filter(|(app, _)| stack_shell(app.stack).is_some())
        .filter_map(|(app, pack)| pack.coverage.map(|recipe| (app, recipe)))
        .collect())
}

/// `diff-coverage` as this plan needs it, or `None`. `coverage_changed_lines`
/// unanswered is derived: on wherever an app's pack has a per-file report.
/// Answered `true` with no such app refuses.
pub fn judged(cx: &Context<'_>) -> Result<Option<Judged>> {
    let answer = cx
        .answers
        .get("coverage_changed_lines")
        .and_then(Value::as_bool);
    check_test_args(cx)?;
    if answer == Some(false) {
        return Ok(None);
    }
    let apps = covered_apps(cx)?;
    if apps.is_empty() {
        if answer == Some(true) {
            return refuse(
                "Module security: coverage_changed_lines needs an app whose stack pack declares a per-file coverage report (python-uv, rust)",
            );
        }
        return Ok(None);
    }
    let min = cx
        .answers
        .get("coverage_changed_lines_min")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_MIN);
    let saves = cx.answers.get("coverage_ratchet").and_then(Value::as_bool) != Some(true);
    Ok(Some(Judged { apps, min, saves }))
}

/// The cache key of the base reports: the commit they were measured at.
pub fn cache_key(sha_expression: &str) -> String {
    format!("coverage-report-${{{{ {sha_expression} }}}}")
}

/// Where an app's base report is kept, relative to the repository root.
fn base_report(app: &App, recipe: &CoverageRecipe) -> String {
    format!("{BASE_DIR}/{}/{}", app.id, recipe.diff_report)
}

/// The save of `.coverage-base` under the pushed commit, push-only.
fn save_step(pins: &PinTable) -> Result<Step> {
    let mut save = Step::new("Save the per-file coverage reports")
        .uses(pins.action("actions/cache/save")?)
        .with("key", cache_key("github.sha"))
        .with("path", BASE_DIR);
    save.condition = Some(push_to_default());
    Ok(save)
}

/// What `coverage-ratchet` adds when it is answered and this job judges apps:
/// per app, the per-file report written into `.coverage-base/<app>/`, then one
/// save under the pushed commit; all on a push to the default branch.
pub fn ratchet_save_steps(cx: &Context<'_>, pins: &PinTable) -> Result<Vec<Step>> {
    let Some(judged) = judged(cx)? else {
        return Ok(Vec::new());
    };
    let mut steps = Vec::new();
    for (app, recipe) in &judged.apps {
        let report = recipe.diff_report;
        let kept = format!("$GITHUB_WORKSPACE/{BASE_DIR}/{}", app.id);
        let mut write =
            Step::new(format!("Write the per-file coverage report of {}", app.id)).run(format!(
                "{}\nmkdir -p \"{kept}\"\ncp {report} \"{kept}/{report}\"",
                recipe.render_diff_command(pins, test_args(cx, app))?
            ));
        write.working_directory = app.working_directory();
        write.condition = Some(push_to_default());
        steps.push(write);
    }
    steps.push(save_step(pins)?);
    Ok(steps)
}

/// The job, or `None` when no app is judged.
pub fn job(cx: &Context<'_>, pins: &PinTable) -> Result<Option<CiJob>> {
    let Some(judged) = judged(cx)? else {
        return Ok(None);
    };
    // Setup and measurement also run on a push when this job keeps the base report.
    let measure_run = if judged.saves {
        format!("{} && steps.bypass.outputs.id == ''", either_event())
    } else {
        PR_RUN.to_owned()
    };
    let mut steps: Vec<Step> = Vec::new();
    let push = |steps: &mut Vec<Step>, mut step: Step, run: &str| {
        step.condition = match step.condition.take() {
            None => Some(run.to_owned()),
            // A cache save of the pack's setup is left out, as before.
            Some(c) if c == DEFAULT_BRANCH_CONDITION => return,
            Some(c) => Some(format!("{run} && ({c})")),
        };
        if !steps.contains(&step) {
            steps.push(step);
        }
    };
    for (app, recipe) in &judged.apps {
        for step in (packs::pack(app.stack).ci_setup)(app, pins)? {
            push(&mut steps, step, &measure_run);
        }
        if let Some(install) = recipe.install_step(pins)? {
            push(&mut steps, install, &measure_run);
        }
    }
    // diff-cover is a Python tool run with uvx on both packs (SPEC-security.md).
    if !steps.iter().any(|s| {
        s.uses
            .as_ref()
            .is_some_and(|a| a.repo == "astral-sh/setup-uv")
    }) {
        push(
            &mut steps,
            Step::new("Install uv").uses(pins.action("astral-sh/setup-uv")?),
            PR_RUN,
        );
    }
    push(
        &mut steps,
        Step::new("Find the merge base")
            .id("merge-base")
            .env("BASE_REF", "${{ github.base_ref }}")
            .run("echo \"sha=$(git merge-base \"origin/$BASE_REF\" HEAD)\" >> \"$GITHUB_OUTPUT\""),
        PR_RUN,
    );
    push(
        &mut steps,
        Step::new("Restore the base coverage report")
            .uses(pins.action("actions/cache/restore")?)
            .with("key", cache_key("steps.merge-base.outputs.sha"))
            .with("path", BASE_DIR),
        PR_RUN,
    );
    for (app, recipe) in &judged.apps {
        let mut measure = Step::new(format!("Measure coverage of {}", app.id))
            .id(format!("measure-{}", app.id))
            .run(recipe.render_diff_command(pins, test_args(cx, app))?);
        measure.working_directory = app.working_directory();
        push(&mut steps, measure, &measure_run);
    }
    if judged.saves {
        let keep: Vec<String> = judged
            .apps
            .iter()
            .map(|(app, recipe)| {
                format!(
                    "mkdir -p {BASE_DIR}/{}\ncp {}{} {}",
                    app.id,
                    app.prefix(),
                    recipe.diff_report,
                    base_report(app, recipe)
                )
            })
            .collect();
        let mut kept = Step::new("Keep the per-file coverage reports").run(keep.join("\n"));
        kept.condition = Some(push_to_default());
        steps.push(kept);
        steps.push(save_step(pins)?);
    }
    // Judged even when an earlier verdict fails: each app and each rule stands
    // alone; an app whose measurement failed is reported once, by that step (#1170).
    let judging = format!("${{{{ !cancelled() && {PR_RUN} }}}}");
    // The shell is embedded once and run by every judging step, so the job
    // stays well under the workflow reader's size cap. Written under the
    // judging steps' base condition (#1169): after one app's failed measurement
    // the other apps are still judged, and a missing script (exit 127) would
    // hide the cause.
    let mut write = Step::new("Write diff-coverage.sh").run(format!(
        "cat > \"$RUNNER_TEMP/diff-coverage.sh\" <<'{HEREDOC}'\n{}{HEREDOC}",
        without_comment_lines(DIFF_COVERAGE_SH)
    ));
    write.condition = Some(judging.clone());
    steps.push(write);
    let diff_cover = format!("uvx diff-cover=={}", pins.tool("diff-cover")?.version);
    for (app, recipe) in &judged.apps {
        let judging = format!(
            "${{{{ !cancelled() && {PR_RUN} && steps.measure-{}.outcome == 'success' }}}}",
            app.id
        );
        let (format, ext, absent) =
            stack_shell(app.stack).expect("covered_apps keeps the supported stacks");
        let report = format!("{}{}", app.prefix(), recipe.diff_report);
        let common = |name: String, mode: &str| {
            let mut step = Step::new(name)
                .env("BASE_REF", "${{ github.base_ref }}")
                .env("PR_NUMBER", "${{ github.event.pull_request.number }}")
                .env("APP_ID", app.id.clone())
                .env("DIFF_REPORT", report.clone())
                .env("DIFF_FORMAT", format)
                .run(format!("bash \"$RUNNER_TEMP/diff-coverage.sh\" {mode}"));
            step.condition = Some(judging.clone());
            step
        };
        steps.push(
            common(format!("Check the changed lines of {}", app.id), "changed")
                .env("MIN", judged.min.to_string())
                .env("DIFF_COVER", diff_cover.clone()),
        );
        let mut characterization = common(
            format!("Characterization first of {}", app.id),
            "characterization",
        )
        .env("APP_PATH", app.path.clone())
        .env("APP_DIR", app.path.clone())
        .env("BASE_REPORT", base_report(app, recipe))
        .env(
            "DIFF_COMMAND",
            recipe.render_diff_command(pins, test_args(cx, app))?,
        )
        .env("SOURCE_EXT", ext);
        // A narrowed rust selection leaves the other members out of the
        // report: absent there means not measured, not unexecuted (#1177).
        characterization = if app.stack == StackId::Rust && test_args(cx, app).is_some() {
            characterization.env("ABSENT", "warn").env(
                "ABSENT_HINT",
                format!("it is outside {TEST_ARGS}.{}, so it is not judged", app.id),
            )
        } else {
            characterization.env("ABSENT", absent)
        };
        // The app at the root leaves the other apps' files to them.
        let others: Vec<&str> = judged
            .apps
            .iter()
            .filter(|(other, _)| other.id != app.id)
            .map(|(other, _)| other.path.as_str())
            .collect();
        if app.path == "." && !others.is_empty() {
            characterization = characterization.env("EXCLUDE_PATHS", others.join("\n"));
        }
        steps.push(characterization);
    }
    let steps: String = steps.iter().map(step_yaml).collect();
    let checkout_if = if judged.saves {
        either_event()
    } else {
        "github.event_name == 'pull_request'".to_owned()
    };
    let pairs = [
        ("runner", runner(cx)?.to_owned()),
        ("checkout", pins.action("actions/checkout")?.uses()),
        ("checkout_if", checkout_if),
        (
            "bypass_max_days",
            cx.answers
                .get("bypass_max_days")
                .and_then(Value::as_u64)
                .unwrap_or(30)
                .to_string(),
        ),
        (
            "bypass_variable",
            indent(&without_comment_lines(BYPASS_VARIABLE), 6),
        ),
        ("steps", steps.trim_end().to_owned()),
        // The head, and the merge base again when no base report is cached:
        // always on the pull request that installs the job (#1213).
        ("timeout", coverage_timeout(cx, 2)),
    ];
    let services =
        crate::modules::ci_baseline::services::of_apps(cx, judged.apps.iter().map(|(app, _)| app))?;
    Ok(Some(CiJob {
        id: DIFF_COVERAGE.to_owned(),
        yaml: crate::modules::ci_baseline::services::into_job(&fill(JOB, &pairs), &services),
        skippable_under: vec![CiTier::Docs],
        // Judged against the merge base for the whole pull request, as coverage-ratchet.
        app: None,
    }))
}
