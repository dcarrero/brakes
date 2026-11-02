//! The seed CI workflow (#21; decision 2026-11-02, "brakes never runs the
//! project's commands in CI"): `.github/workflows/ci.yml`, written once under
//! `workflow: seed` and owned by the project from then on. One job per declared
//! command (lint, test or verify, build), per app in a monorepo; the test job
//! measures and uploads coverage with its stack pack's recipe (#20) when
//! `security` judges the app; `diff-coverage` calls the reusable workflow
//! `security` renders; `required` aggregates them. Nothing here runs in a job
//! `brakes` owns.
use super::{
    model::{CiBaselineAnswers, Command, Job, Skippable, Workflow, app_profile, derive},
    render::{DECLARED_SH, SHORT_TIMEOUT, WORKFLOW_PATH, checks_timeout, runner_label},
    services,
};
use crate::{
    Result,
    engine::Context,
    modules::{
        security::{SECURITY, embed::without_comment_lines},
        stack_packs::{App, CoverageRecipe, PinTable, StackPack, Step, required_packs},
    },
    refuse,
};
use serde_json::Value;

const HEADER: &str = include_str!("../../../../../templates/ci-baseline/fragments/seed-header.yml");
/// The seed's aggregate: passes only when every job it needs succeeded.
pub const SEED_REQUIRED_SH: &str =
    include_str!("../../../../../templates/ci-baseline/fragments/seed-required.sh");
/// The seed's job that calls `security`'s reusable coverage judge.
pub const DIFF_COVERAGE_JOB: &str = "diff-coverage";

/// The pack's coverage recipe when `security` is active and judges changed
/// lines (`coverage_changed_lines` not answered `false`), else `None`.
fn judged(cx: &Context<'_>, pack: &StackPack) -> Option<CoverageRecipe> {
    let security = cx.answers_if_active(SECURITY)?;
    let off = security
        .get("coverage_changed_lines")
        .and_then(Value::as_bool)
        == Some(false);
    if off { None } else { pack.coverage }
}

/// The answered test selection of `app` (`security`'s `coverage_test_args.<id>`).
fn test_args(cx: &Context<'_>, app: &App) -> Option<String> {
    cx.answers_if_active(SECURITY)?
        .get(&format!("coverage_test_args.{}", app.id))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// The step that runs one declared command, read at run time in `dir`.
fn declared(command: Command, dir: Option<&str>) -> Step {
    let step = Step::new(format!("Run declared {}", command.as_str()))
        .env("NAME", command.as_str())
        .run(without_comment_lines(DECLARED_SH));
    match dir {
        Some(dir) => step.working_directory(dir.to_owned()),
        None => step,
    }
}

/// The apps whose packs have no coverage upload, with the reason (a header line each).
fn notes_without_upload(packs: &[(App, &'static StackPack)]) -> Vec<String> {
    packs
        .iter()
        .filter_map(|(app, pack)| {
            pack.no_coverage
                .map(|reason| format!("# {} ({}): no coverage upload: {reason}", app.id, app.stack))
        })
        .collect()
}

/// The seed's text, or a refusal when no command is declared to run.
pub fn render(cx: &Context<'_>, answers: &CiBaselineAnswers) -> Result<String> {
    let pins = PinTable::embedded()?;
    let label = runner_label(answers.runner).to_owned();
    let timeout = super::render::within_job_max(checks_timeout(cx));
    let checkout = Step::new("Check out")
        .uses(pins.action("actions/checkout")?)
        .with("persist-credentials", "false");
    let (macos, linux): (Vec<_>, Vec<_>) = required_packs(cx)?
        .into_iter()
        .partition(|(_, pack)| pack.macos_target);
    let job = |id: String, steps: Vec<Step>, services: services::Services| Job {
        name: id.clone(),
        id,
        runs_on: label.clone(),
        timeout_minutes: timeout,
        needs: Vec::new(),
        condition: None,
        matrix: None,
        outputs: Vec::new(),
        steps,
        skippable: Skippable::Never,
        call: None,
        services,
        permissions: Vec::new(),
    };
    let mut jobs = Vec::new();
    let mut coverage_jobs = Vec::new();
    // The jobs of one set of commands: `prefix` names them, `dir` is where the
    // profile is read, `apps` the apps set up (and measured) in them.
    let mut add = |prefix: &str,
                   dir: Option<&str>,
                   commands: &[Command],
                   apps: &[(App, &'static StackPack)],
                   services: services::Services|
     -> Result<()> {
        let mut setup = vec![checkout.clone()];
        for (app, pack) in apps {
            setup.extend((pack.ci_setup)(app, &pins)?);
        }
        for command in commands {
            let id = format!("{prefix}{}", command.as_str());
            let mut steps = setup.clone();
            let measured = matches!(command, Command::Test | Command::Verify)
                && apps.len() == 1
                && dir.is_none_or(|d| apps[0].0.path == d);
            let recipe = apps
                .first()
                .filter(|_| measured)
                .and_then(|(app, pack)| Some((app, judged(cx, pack)?)));
            match recipe {
                Some((app, recipe)) => {
                    // The declared-command fragment between the recipe's lines:
                    // its shebang would only be a comment there.
                    let shell = without_comment_lines(DECLARED_SH);
                    let shell = shell
                        .strip_prefix("#!/usr/bin/env bash\n")
                        .unwrap_or(&shell);
                    let mut upload = recipe.upload_steps(
                        app,
                        &id,
                        shell.trim_end(),
                        &pins,
                        test_args(cx, app).as_deref(),
                    )?;
                    for step in &mut upload {
                        if step.run.as_deref().is_some_and(|r| r.contains("\"$NAME\"")) {
                            step.env
                                .insert("NAME".to_owned(), command.as_str().to_owned());
                        }
                    }
                    steps.extend(upload);
                    coverage_jobs.push(id.clone());
                }
                _ => steps.push(declared(*command, dir)),
            }
            jobs.push(job(id, steps, services.clone()));
        }
        Ok(())
    };
    let root_declared = derive(|c| super::model::is_declared(cx, c));
    let monorepo = super::model::is_monorepo(&linux);
    if !monorepo {
        if root_declared.is_empty() {
            return refuse(
                "ci-baseline: the seed has no command to run; declare commands.verify or commands.test in .agent-setup/project.json",
            );
        }
        add("", None, &root_declared, &linux, services::of_root(cx)?)?;
    } else {
        for (app, pack) in &linux {
            let profile = app_profile(cx.root, &app.id, &app.path)?;
            let commands = derive(|c| profile["commands"][c.as_str()].is_string());
            if !commands
                .iter()
                .any(|c| matches!(c, Command::Test | Command::Verify))
            {
                return refuse(format!(
                    "ci-baseline: app {} declares neither commands.test nor commands.verify in {}/.agent-setup/project.json; the seed would not test it",
                    app.id, app.path
                ));
            }
            add(
                &format!("{}-", app.id),
                app.working_directory().as_deref(),
                &commands,
                &[(app.clone(), *pack)],
                services::of_dir(cx, &app.path)?,
            )?;
        }
        // The root profile's own commands when no app sits at `.` (#1165).
        if !linux.iter().any(|(app, _)| app.path == ".") && !root_declared.is_empty() {
            add("", None, &root_declared, &linux, services::of_root(cx)?)?;
        }
    }
    if !coverage_jobs.is_empty() {
        jobs.push(Job {
            needs: coverage_jobs,
            call: Some(super::model::Call {
                uses: format!("./{}", crate::modules::security::diff_coverage::REUSABLE),
                with: Vec::new(),
            }),
            ..job(DIFF_COVERAGE_JOB.to_owned(), Vec::new(), Default::default())
        });
    }
    let needs = jobs.iter().map(|j| j.id.clone()).collect();
    jobs.push(Job {
        needs,
        condition: Some("always()".to_owned()),
        timeout_minutes: SHORT_TIMEOUT,
        ..job(
            super::AGGREGATE_CHECK.to_owned(),
            vec![
                Step::new("Decide the required check")
                    .env("NEEDS", "${{ toJSON(needs) }}")
                    .run(without_comment_lines(SEED_REQUIRED_SH)),
            ],
            Default::default(),
        )
    });
    let mut notes = notes_without_upload(&linux);
    for (app, _) in &macos {
        notes.push(format!(
            "# {} ({}): a macOS target; add its job on your macOS runner",
            app.id, app.stack
        ));
    }
    let notes: String = notes.iter().map(|n| format!("{n}\n")).collect();
    let workflow = Workflow {
        path: WORKFLOW_PATH.to_owned(),
        name: "CI".to_owned(),
        merge_queue: answers.merge_queue,
        jobs,
        contributed: Vec::new(),
    };
    Ok(super::render::to_yaml_with(
        &HEADER.replace("{{notes}}", &notes),
        &workflow,
    ))
}
