//! The work `qa` cannot do itself (`SPEC-qa.md`, Manual steps with probes):
//! commit the seeded web's lockfile, generate the screenshot baseline on Linux
//! in the pinned Playwright image, and wait for `qa-api` to report on the
//! default branch. The baseline step exists only for `web: seeded`, whose
//! baseline name the seed fixes (`seeds::BASELINE`), so the engine's
//! `file-exists` probe suffices (Decision 6, resolved by the plan); under
//! `web: project` the auditor's `qa.screenshot-baseline-present` covers the
//! project's own tests. Each listed app of a monorepo gets its own steps,
//! ids prefixed with the app id (T13, #1011).
use super::{AppQa, QaAnswers, Web, jobs::job_id, seeds};
use crate::{
    Result,
    engine::manual::{ManualStep, Owner, Probe},
    modules::{
        ci_baseline::brownfield::remote, repo_baseline::steps::default_branch,
        stack_packs::PinTable,
    },
};
use serde_json::json;
use std::path::Path;

pub const LOCKFILE_STEP: &str = "qa-web-lockfile";
pub const BASELINE_STEP: &str = "qa-web-baseline";
pub const API_REPORTED_STEP: &str = "qa-api-reported";
/// The job whose check run `qa-api-reported` waits for.
pub const API_JOB: &str = "qa-api";

/// `text` as one single-quoted shell word.
fn sh_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

/// The steps of every target, the root first and then each listed app in app
/// id order; an app's step ids and job carry its id (`<app>-qa-web-lockfile`,
/// `<app>-qa-api`) and its paths start at its directory (T13, #1011).
pub fn steps(root: &Path, answers: &QaAnswers, pins: &PinTable) -> Result<Vec<ManualStep>> {
    let base = answers.root_target();
    let mut steps = target_steps(root, &base, None, pins)?;
    for (id, app) in &answers.apps {
        steps.extend(target_steps(root, app, Some(id), pins)?);
    }
    Ok(steps)
}

/// The steps of one target; `app` prefixes its ids.
fn target_steps(
    root: &Path,
    target: &AppQa,
    app: Option<&str>,
    pins: &PinTable,
) -> Result<Vec<ManualStep>> {
    let id = |step: &str| match app {
        Some(app) => format!("{app}-{step}"),
        None => step.to_owned(),
    };
    let mut steps = Vec::new();
    if target.web == Web::Seeded {
        let web_dir = &seeds::join(&target.path, &target.web_dir);
        let web_start = target.web_start.as_deref().unwrap_or_default();
        let image = pins.image("playwright")?.pinned();
        steps.push(ManualStep {
            id: id(LOCKFILE_STEP),
            title: "Commit the web lockfile".to_owned(),
            owner: Owner::Project,
            instructions: format!("cd {web_dir} && npm install && git add package-lock.json"),
            probe: Probe::FileExists {
                path: seeds::join(web_dir, "package-lock.json"),
            },
            after: None,
        });
        steps.push(ManualStep {
            id: id(BASELINE_STEP),
            title: "Generate the screenshot baseline on Linux".to_owned(),
            owner: Owner::Project,
            instructions: format!(
                "docker run --rm -v \"$PWD\":/work -w /work/{web_dir} -e QA_WEB_START={} -e QA_WEB_URL={} {image} npx playwright test --update-snapshots\n\
                 git add {web_dir}/*-snapshots/ && git commit -m 'qa: screenshot baseline'\n\
                 # Generate the baseline on Linux, in the pinned image, so it matches the runner; review every image before committing.",
                sh_quote(web_start),
                sh_quote(&target.web_url),
            ),
            probe: Probe::FileExists {
                path: seeds::join(web_dir, seeds::BASELINE),
            },
            after: Some(id(LOCKFILE_STEP)),
        });
    }
    if target.api {
        let branch = default_branch(root);
        let job = job_id(app, "api");
        steps.push(ManualStep {
            id: id(API_REPORTED_STEP),
            title: format!("CI reports {job} on {branch}"),
            owner: Owner::Platform,
            instructions: format!(
                "Nothing to run: wait until {job} has reported green once on {branch}; until then required is red on purpose."
            ),
            probe: remote(
                "check-run-reported",
                json!({ "contexts": [job], "branch": branch }),
            ),
            after: None,
        });
    }
    Ok(steps)
}
