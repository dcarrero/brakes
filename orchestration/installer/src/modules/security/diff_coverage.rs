//! `diff-coverage` (SPEC-security.md, "Changed-line coverage", slice 3b; #978;
//! decision "Testing brakes moved into the 7 November scope", points 1 and 2):
//! every line a pull request changes is executed by a test, and a source file it
//! modifies had a test executing it at the merge base. The shell is
//! `templates/security/fragments/diff-coverage.sh`.
//!
//! It only judges (decision of 2026-11-02, #22): the project's own test jobs run
//! the tests under coverage and upload the data as `agentic-coverage-<app>-<job>`
//! (the stack pack's `CoverageUpload`, #20); the reusable workflow
//! `.github/workflows/agentic-coverage.yml`, which the project's CI calls from a
//! job named `diff-coverage`, downloads and combines it, judges, and on pushes to
//! the default branch keeps the base report: one cache entry per commit,
//! `coverage-report-<sha>`, holding `.coverage-base/<app>/<report>` for every
//! judged app. A missing base report warns; nothing ever runs the tests here.
//! `coverage-ratchet`, when answered, is a second job of the same workflow.
use super::embed::without_comment_lines;
use super::jobs::{BYPASS_VARIABLE, coverage_runner, fill, indent, step_yaml};
use crate::{
    Result,
    engine::Context,
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

/// A pull request, or a push to the default branch, where the base report is kept.
fn either_event() -> String {
    format!(
        "(github.event_name == 'pull_request' || ({}))",
        push_to_default()
    )
}

/// The retired answer (#22): accepted and ignored for one version, with a note.
pub const SOURCE: &str = "coverage_source";
/// The values `coverage_source` still accepts.
pub const SOURCES: [&str; 2] = ["job", "project-ci"];
/// The reusable workflow the project's CI calls.
pub const REUSABLE: &str = ".github/workflows/agentic-coverage.yml";
/// Where the downloaded parts land, outside every app directory.
pub const PARTS_DIR: &str = ".coverage-parts";
/// Where the project finds the recipe its test jobs follow: the guide `security` manages.
const RECIPE_GUIDE: &str = "docs/agent-setup/security-gates.md";

/// The artifact name prefix the project's test jobs upload for `app`.
pub fn artifact_prefix(app: &App) -> String {
    format!("agentic-coverage-{}-", app.id)
}

/// Every app this job judges and its minimum.
pub struct Judged {
    pub apps: Vec<(App, CoverageRecipe)>,
    pub min: u64,
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
    Ok(Some(Judged { apps, min }))
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

const REUSABLE_HEAD: &str = "# Managed by brakes (security, #22). Your CI calls it after the test jobs\n\
# that upload agentic-coverage-<app>-* artifacts; it judges them and runs no test.\n\
name: agentic-coverage\n\
on:\n  workflow_call:\n\
permissions:\n  contents: read\n\
jobs:\n";

/// `.github/workflows/agentic-coverage.yml`: `diff-coverage` when apps are
/// judged and `coverage-ratchet` when it is answered; `None` with neither.
pub fn reusable(cx: &Context<'_>, pins: &PinTable) -> Result<Option<String>> {
    let judged = judged(cx)?;
    let ratchet = super::jobs::coverage(cx)?;
    if judged.is_none() && ratchet.is_none() {
        return Ok(None);
    }
    let mut out = REUSABLE_HEAD.to_owned();
    if let Some(judged) = &judged {
        out.push_str(&format!(
            "  {DIFF_COVERAGE}:\n{}\n",
            indent(body(cx, pins, judged)?.trim_end(), 4)
        ));
    }
    if let Some(coverage) = &ratchet {
        out.push_str(&format!(
            "  {}:\n{}\n",
            super::jobs::COVERAGE_RATCHET,
            indent(super::jobs::ratchet_body(cx, pins, coverage)?.trim_end(), 4)
        ));
    }
    Ok(Some(out))
}

/// The plan notes: `coverage_source` retired when answered, then what the
/// project's CI must do for each app the reusable workflow reads.
pub fn project_ci_notes(cx: &Context<'_>) -> Result<Vec<String>> {
    let mut notes = Vec::new();
    if let Some(answered) = cx.answers.get(SOURCE).and_then(Value::as_str) {
        notes.push(format!(
            "{SOURCE} {answered} is retired and ignored: diff-coverage only reads the coverage data your CI uploads; remove the answer"
        ));
    }
    let mut apps: Vec<(App, CoverageRecipe)> = judged(cx)?.map(|j| j.apps).unwrap_or_default();
    for (app, recipe) in super::jobs::coverage(cx)?
        .map(|c| c.apps)
        .unwrap_or_default()
    {
        if !apps.iter().any(|(a, _)| a.id == app.id) {
            apps.push((app, recipe));
        }
    }
    // Under `workflow: seed` with no workflow of the project's own, the seed
    // writes the upload and the call itself (#21); the note says so (#26).
    let ci = crate::modules::ci_baseline::CI_BASELINE;
    let seeded = crate::modules::ci_baseline::model::workflow_mode(cx.answers_of(ci)?, cx.previous)
        == crate::modules::ci_baseline::WorkflowMode::Seed
        && crate::modules::ci_baseline::brownfield::foreign_workflows(cx)?.is_empty();
    notes.extend(apps.iter().map(|(app, recipe)| {
        if seeded {
            return format!(
                "{DIFF_COVERAGE}: the seed .github/workflows/ci.yml uploads {prefix}<job> from the test job of {id} \
                 and calls {REUSABLE}; for a ci.yml written before, `brakes doctor . --propose` shows what is missing",
                prefix = artifact_prefix(app),
                id = app.id,
            );
        }
        format!(
            "{DIFF_COVERAGE}: upload {prefix}<job> from every test job of {id} with {data} ({RECIPE_GUIDE}), \
             call {REUSABLE} from a job named {DIFF_COVERAGE} that needs them, and make your aggregate need it",
            prefix = artifact_prefix(app),
            id = app.id,
            data = data_name(recipe),
        )
    }));
    Ok(notes)
}

/// What the project's test job uploads, in words.
fn data_name(recipe: &CoverageRecipe) -> &'static str {
    if recipe.diff_report == "lcov.info" {
        "its LCOV report (*.info)"
    } else {
        "its coverage.py data file (.coverage*)"
    }
}

/// The download and combine steps of `app`: the parts its test jobs uploaded,
/// combined into `diff_report` in the app directory. The combine step has the
/// id `{id_prefix}-<app>` and outputs `skip=true` when there is nothing of the
/// app to read: a push whose CI ran no test job of it, or a pull request that
/// changes nothing under its path (`MERGE_BASE`). Any other missing data fails,
/// naming the artifact and the recipe; it never measures.
pub(super) fn combine_steps(
    app: &App,
    recipe: &CoverageRecipe,
    pins: &PinTable,
    id_prefix: &str,
    merge_base: &str,
) -> Result<Vec<Step>> {
    let parts = format!("{PARTS_DIR}/{}", app.id);
    let download = Step::new(format!("Download the coverage of {}", app.id))
        .uses(pins.action("actions/download-artifact")?)
        .with("pattern", format!("{}*", artifact_prefix(app)))
        .with("path", parts.clone());
    let absolute = format!("\"$GITHUB_WORKSPACE/{parts}\"");
    let mut combine = Step::new(format!("Combine the coverage of {}", app.id))
        .id(format!("{id_prefix}-{}", app.id))
        .env("MERGE_BASE", merge_base)
        .env("APP_PATH", app.path.clone())
        .run(format!(
            "if [ -z \"$(find {absolute} -type f 2> /dev/null)\" ]; then\n  \
             if [ \"$GITHUB_EVENT_NAME\" = push ]; then\n    \
             echo \"{id}: no test job uploaded coverage on this push; its previous base report is kept\"\n    \
             echo \"skip=true\" >> \"$GITHUB_OUTPUT\"\n    exit 0\n  fi\n  \
             if [ -n \"$MERGE_BASE\" ] && [ -z \"$(git -C \"$GITHUB_WORKSPACE\" diff --name-only \"$MERGE_BASE\" HEAD -- \"$APP_PATH\")\" ]; then\n    \
             echo \"{id}: no test job uploaded coverage and the pull request changes nothing under $APP_PATH; not judged\"\n    \
             echo \"skip=true\" >> \"$GITHUB_OUTPUT\"\n    exit 0\n  fi\n  \
             echo \"::error::No coverage data: this run uploaded no {prefix}* artifact; upload {data} from every test job of {id} as {RECIPE_GUIDE} shows for {stack}. brakes never runs the tests to measure them\"\n  \
             exit 1\nfi\n{combine}",
            id = app.id,
            prefix = artifact_prefix(app),
            data = data_name(recipe),
            stack = app.stack,
            combine = recipe.render_combine(pins, &absolute)?
        ));
    combine.working_directory = app.working_directory();
    Ok(vec![download, combine])
}

/// The job body, rendered from the fragment.
fn body(cx: &Context<'_>, pins: &PinTable, judged: &Judged) -> Result<String> {
    // Setup and combine also run on a push to the default branch, which keeps the base report.
    let measure_run = format!("{} && steps.bypass.outputs.id == ''", either_event());
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
    // Only coverage.py needs the project's environment to combine.
    for (app, _) in &judged.apps {
        if app.stack != StackId::PythonUv {
            continue;
        }
        for step in (packs::pack(app.stack).ci_setup)(app, pins)? {
            push(&mut steps, step, &measure_run);
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
        for step in combine_steps(
            app,
            recipe,
            pins,
            "measure",
            "${{ steps.merge-base.outputs.sha }}",
        )? {
            push(&mut steps, step, &measure_run);
        }
    }
    // The pushed commit's entry starts from its parent's, so an app no test
    // job measured on this push keeps the report it had (#1349).
    let mut previous = Step::new("Restore the previous base report")
        .uses(pins.action("actions/cache/restore")?)
        .with("key", cache_key("github.event.before"))
        .with("path", BASE_DIR);
    previous.condition = Some(push_to_default());
    steps.push(previous);
    let keep: Vec<String> = judged
        .apps
        .iter()
        .map(|(app, recipe)| {
            let copy = format!(
                "mkdir -p {BASE_DIR}/{}\ncp {}{} {}",
                app.id,
                app.prefix(),
                recipe.diff_report,
                base_report(app, recipe)
            );
            format!(
                "if [ -f {}{} ]; then\n{}\nfi",
                app.prefix(),
                recipe.diff_report,
                indent(&copy, 2)
            )
        })
        .collect();
    let mut kept = Step::new("Keep the per-file coverage reports").run(keep.join("\n"));
    kept.condition = Some(push_to_default());
    steps.push(kept);
    steps.push(save_step(pins)?);
    // Judged even when an earlier verdict fails: each app and each rule stands
    // alone; an app whose combine failed is reported once, by that step (#1170).
    let judging = format!("${{{{ !cancelled() && {PR_RUN} }}}}");
    // The shell is embedded once and run by every judging step, so the job
    // stays well under the workflow reader's size cap. Written under the
    // judging steps' base condition (#1169): after one app's failed combine
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
            "${{{{ !cancelled() && {PR_RUN} && steps.measure-{id}.outcome == 'success' && steps.measure-{id}.outputs.skip != 'true' }}}}",
            id = app.id
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
        // A missing base report warns: recomputing it would run the tests (#22).
        let mut characterization = common(
            format!("Characterization first of {}", app.id),
            "characterization",
        )
        .env("APP_PATH", app.path.clone())
        .env("BASE_REPORT", base_report(app, recipe))
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
    let pairs = [
        ("coverage_runner", coverage_runner(cx)?),
        ("checkout", pins.action("actions/checkout")?.uses()),
        ("checkout_if", either_event()),
        ("bypass_max_days", bypass_max_days(cx)),
        (
            "bypass_variable",
            indent(&without_comment_lines(BYPASS_VARIABLE), 6),
        ),
        ("steps", steps.trim_end().to_owned()),
        ("timeout", COMBINE_TIMEOUT.to_string()),
    ];
    Ok(fill(JOB, &pairs))
}

/// `bypass_max_days`, 30 unless answered.
pub(super) fn bypass_max_days(cx: &Context<'_>) -> String {
    cx.answers
        .get("bypass_max_days")
        .and_then(Value::as_u64)
        .unwrap_or(30)
        .to_string()
}

/// The reusable jobs' timeout: they download, combine and judge, no test.
pub const COMBINE_TIMEOUT: u32 = 15;
