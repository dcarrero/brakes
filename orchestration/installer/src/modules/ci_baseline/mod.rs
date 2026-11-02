//! The `ci-baseline` module (SPEC-ci-baseline.md): one hardened CI workflow from the
//! declared commands, reporting through the single aggregate check `required`.
pub mod aggregate;
pub mod audit;
pub mod brownfield;
pub mod compose;
pub mod model;
pub mod render;
pub mod reusable;
pub mod scope;
pub mod seed;
pub mod services;

pub use aggregate::{AGGREGATE_CHECK, CONTRIBUTED_AGGREGATE_CHECK, REQUIRED_SH};
pub use model::{
    ActionRef, CiBaselineAnswers, CiTier, Command, Job, MacosRunner, Matrix, Runner, Skippable,
    Step, Workflow, WorkflowMode, workflow_mode,
};
pub use scope::DEFAULT_HELDOUT_DIR;

use crate::{
    Result,
    engine::{Context, ManualStep, Module, Ownership, Rendered, Schema},
    modules::agent_guardrails::{AGENT_GUARDRAILS, unattended},
    modules::stack_packs::STACK_PACKS,
};
use serde_json::json;

/// Module id as the lock and the answers file record it.
pub const CI_BASELINE: &str = "ci-baseline";
pub const CI_BASELINE_VERSION: &str = "1.0.0";

pub struct CiBaseline;

/// The question table of the spec, in asking order (`when` reads earlier
/// answers). There is no `apps` answer: the apps come from `stack_packs::packs`.
pub fn schema() -> Schema {
    let names = |all: &[&'static str]| all.to_vec();
    Schema::parse(&json!([
        {"id": "workflow", "type": "string",
         "enum": names(&WorkflowMode::ALL.map(WorkflowMode::as_str)),
         "description": "`seed` writes the project's CI once (`ci.yml`, yours from then on) and renders only the judges; `existing` records the project's own workflow and audits it; `generate` (deprecated) renders one workflow that runs the commands. Unanswered: `generate` where the lock records a generated workflow, else `seed`."},
        {"id": "aggregate_check", "type": "string", "minLength": 1, "default": AGGREGATE_CHECK,
         "when": "workflow == existing",
         "description": "The check name the ruleset requires; fixed to `required` when generating."},
        {"id": "retire_generated", "type": "boolean", "default": false, "when": "workflow == existing",
         "description": "After a switch from `generate`, deletes `agentic-ci.yml`; answer it once the default branch requires the project's aggregate and `agentic-required` (#1354)."},
        {"id": "commands", "type": "array", "minItems": 1,
         "items": {"type": "string", "enum": names(&Command::ALL.map(Command::as_str))},
         "when": "workflow == generate",
         "description": "Declared commands to run, in order; derived from project.json when unanswered."},
        {"id": "runner", "type": "string",
         "enum": names(&Runner::available().into_iter().map(Runner::as_str).collect::<Vec<_>>()), "default": Runner::default_choice().as_str(),
         "description": "Linux runner provider; the renderer owns the label."},
        {"id": "tiers", "type": "boolean", "default": true,
         "description": "Docs-only pull requests skip the verification jobs."},
        {"id": "inert_paths", "type": "array", "items": {"type": "string"},
         "default": scope::DEFAULT_INERT_PATHS, "when": "tiers",
         "description": "The only paths whose exclusive change means tier `docs`."},
        {"id": "macos", "type": "boolean", "default": false,
         "description": "Adds the push-only macos job; needs a stack pack with a macOS target."},
        {"id": "macos_runner", "type": "string",
         "enum": names(&MacosRunner::available().into_iter().map(MacosRunner::as_str).collect::<Vec<_>>()), "default": MacosRunner::default_choice().as_str(),
         "when": "macos",
         "description": "Where the macos job runs; `github-hosted` is always an auditor warning."},
        {"id": "merge_queue", "type": "boolean", "default": false,
         "description": "Adds `on: merge_group`."},
        {"id": "minutes_budget", "type": "integer", "minimum": 1, "default": 2000,
         "description": "Monthly billed-minute threshold the auditor compares against."},
        {"id": "heldout_dir", "type": "string", "minLength": 1, "default": scope::DEFAULT_HELDOUT_DIR,
         "description": "The held-out test directory: a relative path inside the repository that agents may not edit."},
        {"id": "heldout", "type": "boolean",
         "description": "Adds the `heldout` job; default: true under `workflow: generate` (pending until `heldout_command` is answered), whether `heldout_dir` exists under `existing`; false opts out."},
        {"id": "reusable", "type": "boolean", "default": false, "when": "workflow == generate",
         "description": "`checks` calls the reusable verify workflow the configured reusable_callee hosts, pinned by `reusable_sha`; the single-repo workflow when none is configured or the caller cannot reach it."},
        {"id": "reusable_sha", "type": "string", "when": "reusable",
         "description": "The 40-hex commit of the configured reusable_callee whose `_reusable-verify.yml` the caller pins; never a branch or tag."},
        {"id": "heldout_command", "type": "string",
         "description": "The full command that runs only the held-out tests; required when `heldout` is answered true or `heldout_dir` holds a file, never invented."},
        {"id": "protected_paths", "type": "array", "items": {"type": "string"},
         "description": "Paths whose change in a pull request needs the `human-approved` label before `required` passes; default: the workflows, rulesets, CODEOWNERS, the lock and `<heldout_dir>/**`."},
        {"id": "heldout_properties", "type": "boolean", "default": false,
         "description": "Adds the `heldout-properties` job: property-based tests under `heldout_dir` with a fresh recorded seed; read only when `heldout`."},
        {"id": "heldout_properties_command", "type": "string",
         "description": "The full command that runs only the properties under `heldout_dir` and honours `HELDOUT_SEED`; required when `heldout_properties`, never invented."},
        {"id": "heldout_examples", "type": "integer", "minimum": 100, "maximum": 100000, "default": 200,
         "when": "heldout_properties",
         "description": "The minimum number of examples per property, exported as `HELDOUT_EXAMPLES`."},
    ]))
    .expect("the ci-baseline schema parses")
}

/// The runner configuration the property recipes seed under `heldout_dir`
/// (python-uv's `conftest.py`, #980): `seed`, written only when absent, so
/// the project owns it from then on and it stays a protected path.
fn seed_files(cx: &Context<'_>, answers: &CiBaselineAnswers) -> Result<Vec<Rendered>> {
    let mut seen = std::collections::BTreeSet::new();
    Ok(model::property_recipes(cx)?
        .into_iter()
        .filter_map(|recipe| recipe.seed_file)
        .map(|file| {
            (
                file.path.replace("{{heldout_dir}}", &answers.heldout_dir),
                file.template,
            )
        })
        .filter(|(path, _)| seen.insert(path.clone()))
        .map(|(path, template)| Rendered {
            path,
            class: Ownership::Seed,
            content: Some(template.to_owned()),
            scaffold: None,
        })
        .collect())
}

/// The notes of the mode (#21): under `seed` with workflows of the project's
/// own, that no seed is written; under `generate`, that it is deprecated.
fn seed_notes(cx: &Context<'_>, answers: &CiBaselineAnswers) -> Result<Vec<String>> {
    Ok(match answers.workflow {
        WorkflowMode::Seed => {
            let foreign = brownfield::foreign_workflows(cx)?;
            if brownfield::seed_allowed(cx, &foreign) {
                Vec::new()
            } else {
                vec![format!(
                    "workflow seed writes no {}: the project has workflows of its own ({}); answer workflow=existing and aggregate_check=<the check your CI reports> so brakes audits that CI",
                    render::WORKFLOW_PATH,
                    foreign.join(", ")
                )]
            }
        }
        WorkflowMode::Generate => vec![
            "workflow generate is deprecated: it runs the declared commands in a workflow brakes owns; answer workflow=seed (the project owns its CI) or workflow=existing (decision 2026-11-02)".to_owned(),
        ],
        WorkflowMode::Existing => Vec::new(),
    })
}

impl Module for CiBaseline {
    fn id(&self) -> &'static str {
        CI_BASELINE
    }
    fn version(&self) -> &'static str {
        CI_BASELINE_VERSION
    }
    fn requires(&self) -> &'static [&'static str] {
        &[STACK_PACKS]
    }
    fn questions(&self) -> Schema {
        schema()
    }
    /// The workflow and, on a configured runner, actionlint's label configuration, both
    /// `managed`; nothing under `workflow: existing`. Brownfield (#775): the
    /// foreign workflows and a project-owned actionlint configuration are
    /// `never-touch`, and `agentic-ci.yml` brings the switch remote item.
    /// Under `workflow: existing` with contributed jobs (#895), the separate
    /// `agentic-security.yml` with the same `never-touch` listing and the remote
    /// item that requires `agentic-required`.
    /// It loads the answers, so every rule refuses at `configure` and `install`.
    fn render(&self, cx: &Context<'_>) -> Result<Vec<Rendered>> {
        let answers = CiBaselineAnswers::load(cx)?;
        // Step 1 of a switch to `existing` (#1354); `None` under `generate`.
        let kept = if answers.workflow == WorkflowMode::Existing {
            brownfield::kept_generated(cx)?
        } else {
            None
        };
        let foreign = brownfield::foreign_workflows(cx)?;
        // The project's CI, written once (#21): only where it has none of its own.
        // A migration from a generated workflow replaces it with the seed (#25).
        let seed =
            if answers.workflow == WorkflowMode::Seed && brownfield::seed_allowed(cx, &foreign) {
                Some(Rendered {
                    path: render::WORKFLOW_PATH.to_owned(),
                    class: Ownership::Seed,
                    content: Some(seed::render(cx, &answers)?),
                    scaffold: None,
                })
            } else {
                None
            };
        let Some(mut workflow) = render::workflow(cx, &answers)? else {
            return Ok(kept.into_iter().chain(seed).collect());
        };
        let existing = answers.workflow.project_owns_ci();
        if existing {
            brownfield::refuse_contributed_job(cx.root, &foreign)?;
        } else {
            brownfield::refuse_required_job(cx.root, &foreign)?;
        }
        let actionlint = brownfield::foreign_actionlint(cx);
        let path = if existing {
            brownfield::SEPARATE_PATH
        } else {
            brownfield::workflow_path(cx, &foreign)
        };
        if path == brownfield::BROWNFIELD_PATH {
            workflow.path = path.to_owned();
            workflow.name = brownfield::BROWNFIELD_NAME.to_owned();
        }
        let yaml = render::to_yaml(&workflow);
        // agentic-implement.yml declares `cache-mode` too; it is rendered when
        // agent-guardrails answers `unattended` true (a soft read, #970).
        let unattended = cx
            .answers_if_active(AGENT_GUARDRAILS)
            .is_some_and(unattended::enabled);
        // The labels the project's own workflows run on, which workflow-lint lints too (#1167, #1215).
        let mut labels = brownfield::custom_labels(cx.root, &foreign);
        // security's coverage jobs on the configured large runner (#1344).
        let large = cx
            .answers_if_active(crate::modules::security::SECURITY)
            .and_then(|a| a.get("coverage_runner"))
            .and_then(serde_json::Value::as_str)
            == Some("large");
        if let Some(r) = crate::config::linux_large_runner().filter(|_| large)
            && !labels.contains(&r.label)
        {
            labels.push(r.label.clone());
        }
        let config = render::actionlint_config(
            answers.runner,
            answers.macos_runner,
            &yaml,
            unattended,
            &labels,
        )
        .filter(|_| actionlint.is_empty())
        .map(|text| (render::ACTIONLINT_CONFIG_PATH.to_owned(), text));
        let mut rendered: Vec<Rendered> = config
            .into_iter()
            .chain([(workflow.path.clone(), yaml)])
            .map(|(path, text)| Rendered {
                path,
                class: Ownership::Managed,
                content: Some(text),
                scaffold: None,
            })
            .collect();
        if answers.heldout_properties_command.is_some() {
            rendered.extend(seed_files(cx, &answers)?);
        }
        rendered.extend(brownfield::never_touch(&foreign));
        rendered.extend(brownfield::never_touch(&actionlint));
        if path == brownfield::BROWNFIELD_PATH {
            rendered.extend(brownfield::remote_items());
        }
        if existing {
            rendered.extend(brownfield::separate_remote_items());
        }
        rendered.extend(kept);
        rendered.extend(seed);
        Ok(rendered)
    }
    /// The switch and its gate when the workflow is `agentic-ci.yml`; under
    /// `workflow: existing`, the `agentic-required` item and its gate when a
    /// module contributes a job or the held-out job runs (#944); none for a
    /// greenfield `ci.yml`.
    /// The desired state of the switch and of the `agentic-required` addition (#902).
    fn remote_writes(&self, cx: &Context<'_>) -> Result<Vec<crate::host::desired::RemoteWrite>> {
        Ok(brownfield::remote_writes(
            cx.root,
            &brownfield::switch_checks(&cx.profile.value),
        ))
    }
    fn manual_steps(&self, cx: &Context<'_>) -> Vec<ManualStep> {
        if workflow_mode(cx.answers, cx.previous).project_owns_ci() {
            let contributed = compose::contributed(cx).unwrap_or_default();
            let loaded = CiBaselineAnswers::load(cx).ok();
            let heldout = loaded.as_ref().is_some_and(|a| a.heldout);
            let seed = loaded.is_some_and(|a| a.workflow == WorkflowMode::Seed);
            let mut steps = if contributed.is_empty() && !heldout && !seed {
                Vec::new()
            } else {
                brownfield::separate_steps(cx.root)
            };
            // Expand before contract (#25): require agentic-required before the merge.
            if seed && brownfield::recorded_generated(cx).is_some() {
                steps.insert(0, brownfield::migration_step(cx.root));
            }
            // Only the switch to `existing` keeps the generated workflow (#1354);
            // `seed` retires it in the migrating plan itself (#25).
            if !seed && brownfield::keeps_generated(cx) {
                let checks = model::required_checks(cx)
                    .ok()
                    .flatten()
                    .unwrap_or_default();
                steps.extend(brownfield::retire_steps(cx.root, &checks));
            }
            return steps;
        }
        // The callee must let this repository in (#785): its probe reads it.
        let reachable = CiBaselineAnswers::load(cx)
            .ok()
            .filter(|a| matches!(reusable::decide(cx, a), Ok(reusable::Decision::Call(_))))
            .and_then(|_| crate::config::reusable_callee())
            .map(reusable::step_reachable);
        let foreign = brownfield::foreign_workflows(cx).unwrap_or_default();
        if brownfield::workflow_path(cx, &foreign) != brownfield::BROWNFIELD_PATH {
            return reachable.into_iter().collect();
        }
        brownfield::steps(cx.root, &brownfield::switch_checks(&cx.profile.value))
            .into_iter()
            .chain(reachable)
            .collect()
    }
    /// The plan notes, in this order (SPEC-ci-baseline.md, "Null answered
    /// commands" and Composition): one line per answered command that is
    /// `null` in the profile, in answered order, the idle macOS apps, the
    /// reusable fallback, the foreign jobs that start services (#1170), a budget
    /// whose timeouts exceed GitHub's job maximum (#1228), then one
    /// `JOB [<module>] <id> → <workflow path>` line per inserted contributed
    /// job, in module order; under `workflow: existing` only the `JOB` lines,
    /// naming `agentic-security.yml`.
    fn notes(&self, cx: &Context<'_>) -> Result<Vec<String>> {
        let answers = CiBaselineAnswers::load(cx)?;
        let Some(workflow) = render::workflow(cx, &answers)? else {
            return Ok(Vec::new());
        };
        // Monorepo mode reads each app's profile; the root one declares nothing.
        let missing = answers
            .commands
            .iter()
            .filter(|_| answers.apps.is_empty())
            .filter(|c| !model::is_declared(cx, **c))
            .map(|c| {
                format!(
                    "Verification command missing: commands.{} is null in .agent-setup/project.json; the workflow renders without its step until it is declared",
                    c.as_str()
                )
            });
        // Monorepo mode: what the root profile declares and `required` does not run (#1165).
        let root = model::root_unrun_notes(cx, &answers);
        let path = match answers.workflow {
            WorkflowMode::Existing | WorkflowMode::Seed => brownfield::SEPARATE_PATH,
            WorkflowMode::Generate => {
                brownfield::workflow_path(cx, &brownfield::foreign_workflows(cx)?)
            }
        };
        let jobs = workflow
            .contributed
            .iter()
            .map(|job| format!("JOB [{}] {} → {path}", job.module, job.id));
        // A macOS-target app with macos off runs nowhere (#784): say so.
        let idle: Vec<String> = if answers.workflow == WorkflowMode::Generate && !answers.macos {
            crate::modules::stack_packs::required_packs(cx)?
                .into_iter()
                .filter(|(_, pack)| pack.macos_target)
                .map(|(app, _)| {
                    format!(
                        "app {} ({}) declares a macOS target and macos is false; its commands run nowhere until macos=true",
                        app.id, app.stack
                    )
                })
                .collect()
        } else {
            Vec::new()
        };
        // Why `reusable: true` rendered the single-repo workflow (#785).
        let fallback = match reusable::decide(cx, &answers)? {
            reusable::Decision::Fallback(note) => Some(note),
            _ => None,
        };
        // A budget above GitHub's job maximum, capped (#1228).
        let capped = render::over_job_max_note(cx, &render::budget_timeouts(cx, &workflow));
        // A foreign job that starts services is evidence to declare, never to copy (#1170).
        let evidence = if answers.workflow == WorkflowMode::Generate {
            let dirs: Vec<String> = crate::modules::stack_packs::required_packs(cx)?
                .into_iter()
                .filter(|(_, pack)| !pack.macos_target)
                .map(|(app, _)| app.path)
                .collect();
            services::evidence_notes(cx, &brownfield::foreign_workflows(cx)?, &dirs)?
        } else {
            Vec::new()
        };
        Ok(seed_notes(cx, &answers)?
            .into_iter()
            .chain(missing)
            .chain(root)
            .chain(idle)
            .chain(fallback)
            .chain(evidence)
            .chain(capped)
            .chain(jobs)
            .collect())
    }
}
