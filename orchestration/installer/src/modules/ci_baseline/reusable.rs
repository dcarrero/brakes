//! The reusable verify workflow and its callers (SPEC-ci-baseline.md, "Reusable
//! workflow", slice 4; #785). The configured `reusable_callee` hosts
//! `_reusable-verify.yml`, rendered here from the stack packs' setup and the shared
//! pin table, so the committed file and the render cannot drift (a test compares
//! them; #1201 made the callee configuration). A caller
//! keeps `scope`, `workflow-lint` and `required` local; only `checks` calls the
//! callee, pinned by the answered commit, and only when the caller can reach it
//! and the app's setup is the one the callee carries; otherwise the
//! single-repo workflow renders and a plan note says why.
use super::{
    CI_BASELINE_VERSION,
    brownfield::remote,
    model::{Call, CiBaselineAnswers, Command, Runner, is_declared},
    render::{runner_label, runner_label_with, step},
};
use crate::{
    Result,
    config::NamedRunner,
    engine::{
        Context,
        manual::{ManualStep, Owner},
    },
    modules::stack_packs::{App, PackageManager, PinTable, StackId, packs::pack, required_packs},
};
use serde_json::json;

/// The callee, at the root of the configured `reusable_callee`.
pub const CALLEE_PATH: &str = ".github/workflows/_reusable-verify.yml";
/// The stacks the callee sets up: the first-wave packs.
pub const STACKS: [StackId; 4] = [StackId::Rust, StackId::PythonUv, StackId::Node, StackId::Go];
/// The manual step that verifies the caller can reach the callee.
pub const REACHABLE_STEP: &str = "reusable-reachable";
/// The probe behind it (host-adapter registry).
pub const REACHABLE_PROBE: &str = "reusable-workflow-reachable";

const HEAD: &str = include_str!("../../../../../templates/ci-baseline/fragments/reusable-head.yml");
const INPUTS_SH: &str =
    include_str!("../../../../../templates/ci-baseline/fragments/reusable-inputs.sh");
const VERIFY_SH: &str =
    include_str!("../../../../../templates/ci-baseline/fragments/reusable-verify.sh");
/// The callee's working directory, as its setup steps read it.
const WORKING_DIRECTORY: &str = "${{ inputs.working-directory }}";

/// What `reusable: true` renders for one repository.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// `reusable` is false: the single-repo workflow, no note.
    Off,
    /// `checks` calls the callee.
    Call(Call),
    /// The single-repo workflow, with the plan note that says why.
    Fallback(String),
}

/// The app the callee sets up for `stack`: the pack's defaults at the
/// callee's working directory (npm for node), nothing declared.
fn canonical(stack: StackId) -> App {
    App {
        id: "app".to_owned(),
        path: WORKING_DIRECTORY.to_owned(),
        stack,
        container: false,
        toolchain: stack != StackId::Rust,
        package_manager: (stack == StackId::Node).then_some(PackageManager::Npm),
        declared: Default::default(),
    }
}

/// The setup steps the callee runs for `stack`, each gated on the input.
fn callee_setup(stack: StackId, pins: &PinTable) -> Result<Vec<crate::modules::stack_packs::Step>> {
    let gate = format!("inputs.stack == '{}'", stack.as_str());
    Ok((pack(stack).ci_setup)(&canonical(stack), pins)?
        .into_iter()
        .map(|mut s| {
            s.condition = Some(match s.condition.take() {
                Some(c) => format!("{gate} && ({c})"),
                None => gate.clone(),
            });
            s
        })
        .collect())
}

/// `_reusable-verify.yml` under the configuration in effect.
pub fn callee() -> Result<String> {
    callee_with(crate::config::linux_runner())
}

/// [`callee`] with the configured Linux runner explicit: its label is the default
/// and, with GitHub's, the only one the input check accepts; none renders GitHub's
/// alone (the callee the import ships, #1202).
pub fn callee_with(linux: Option<&NamedRunner>) -> Result<String> {
    use crate::modules::stack_packs::Step;
    let pins = PinTable::embedded()?;
    let stacks: Vec<&str> = STACKS.iter().map(|s| s.as_str()).collect();
    let labels: Vec<String> = Runner::available_with(linux.is_some())
        .iter()
        .map(|r| format!("\"{}\"", runner_label_with(*r, linux)))
        .collect();
    let input = |name: &str| format!("${{{{ inputs.{name} }}}}");
    let mut steps = vec![
        Step::new("Check the inputs")
            .env("STACK", input("stack"))
            .env("RUNS_ON", input("runs-on"))
            .env("TIER", input("tier"))
            .env("COMMANDS", input("commands"))
            .env("WORKING_DIRECTORY", input("working-directory"))
            .env("PROFILE_PATH", input("profile-path"))
            .env("STACKS", stacks.join(" "))
            .env("LABELS", labels.join(" "))
            .run(crate::modules::security::embed::without_comment_lines(
                INPUTS_SH,
            )),
        Step::new("Check out")
            .uses(pins.action("actions/checkout")?)
            .with("persist-credentials", "false"),
    ];
    for stack in STACKS {
        steps.extend(callee_setup(stack, &pins)?);
    }
    steps.push(
        Step::new("Run the declared commands")
            .working_directory(WORKING_DIRECTORY)
            .env("COMMANDS", input("commands"))
            .env("PROFILE_PATH", input("profile-path"))
            .run(crate::modules::security::embed::without_comment_lines(
                VERIFY_SH,
            )),
    );
    let mut result = Step::new("Report the result")
        .id("result")
        .env("STATUS", "${{ job.status }}")
        .run("echo \"result=$STATUS\" >> \"$GITHUB_OUTPUT\"");
    result.condition = Some("always()".to_owned());
    steps.push(result);
    let mut out = HEAD
        .replace("{{version}}", CI_BASELINE_VERSION)
        .replace("{{default_label}}", &format!("'{}'", labels[0]));
    for s in &steps {
        step(&mut out, s);
    }
    Ok(out)
}

/// Whether and how `checks` calls the configured callee for `answers` in `cx`.
pub fn decide(cx: &Context<'_>, answers: &CiBaselineAnswers) -> Result<Decision> {
    decide_with(crate::config::reusable_callee(), cx, answers)
}

/// [`decide`] with the callee explicit (`owner/name`); none calls nothing.
pub fn decide_with(
    callee: Option<&str>,
    cx: &Context<'_>,
    answers: &CiBaselineAnswers,
) -> Result<Decision> {
    let Some(sha) = &answers.reusable_sha else {
        return Ok(Decision::Off);
    };
    let Some(callee) = callee else {
        return Ok(Decision::Fallback(
            "reusable is true but no reusable_callee is configured; the single-repo workflow renders instead"
                .to_owned(),
        ));
    };
    let owner = callee.split('/').next().unwrap_or_default();
    let repository = cx.repository().unwrap_or("this repository");
    if cx.repository().and_then(|r| r.split('/').next()) != Some(owner) {
        return Ok(Decision::Fallback(format!(
            "reusable is true but {repository} cannot call {callee}, a private repository of another owner; the single-repo workflow renders instead"
        )));
    }
    let pins = PinTable::embedded()?;
    let packs = required_packs(cx)?;
    let Some((app, _)) = packs.first() else {
        return Ok(Decision::Fallback(
            "reusable is true but stack-packs records no app; the single-repo workflow renders instead"
                .to_owned(),
        ));
    };
    let same_setup = STACKS.contains(&app.stack) && {
        let at_callee = App {
            path: WORKING_DIRECTORY.to_owned(),
            ..app.clone()
        };
        let mine = (pack(app.stack).ci_setup)(&at_callee, &pins)?;
        let theirs = (pack(app.stack).ci_setup)(&canonical(app.stack), &pins)?;
        mine == theirs
    };
    if !same_setup {
        return Ok(Decision::Fallback(format!(
            "reusable is true but the setup of app {} ({}) differs from the reusable workflow's; the single-repo workflow renders instead",
            app.id, app.stack
        )));
    }
    let commands: Vec<&str> = answers
        .commands
        .iter()
        .copied()
        .filter(|c| is_declared(cx, *c))
        .map(Command::as_str)
        .collect();
    Ok(Decision::Call(Call {
        uses: format!("{callee}/{CALLEE_PATH}@{sha}"),
        with: vec![
            (
                "commands".to_owned(),
                serde_json::to_string(&commands).unwrap_or_default(),
            ),
            ("stack".to_owned(), app.stack.as_str().to_owned()),
            (
                "runs-on".to_owned(),
                format!("\"{}\"", runner_label(answers.runner)),
            ),
            (
                "tier".to_owned(),
                "${{ needs.scope.outputs.tier }}".to_owned(),
            ),
        ],
    }))
}

/// The manual step whose probe verifies the caller can reach `callee`.
pub fn step_reachable(callee: &str) -> ManualStep {
    ManualStep {
        id: REACHABLE_STEP.to_owned(),
        title: format!("This repository can call the reusable verify workflow of {callee}"),
        owner: Owner::Owner,
        instructions: format!(
            "gh api -X PUT repos/{callee}/actions/permissions/access -f access_level=user\n\
             # or make {callee} public; until then checks fails with \"workflow was not found\"."
        ),
        probe: remote(REACHABLE_PROBE, json!({ "callee": callee })),
        after: None,
    }
}
