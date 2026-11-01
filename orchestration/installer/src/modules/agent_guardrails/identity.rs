//! The agents' identity and spend caps (SPEC-agent-guardrails.md, "Manual step,
//! later slice", as built; #750): the owner steps for the GitHub App agents act
//! through (the App in every profile since #1255, its CI secrets in P2 and P3),
//! probed by name only (`app-installed` has no runner yet,
//! so the step is `unavailable`; the secrets through `secret-present`), and the
//! two Silver rules over every workflow of the repository, hand-written ones
//! included: `agents.workflow-caps` (an agent job has `timeout-minutes`, a
//! `concurrency` group and, for Claude, `--max-turns`) and `agents.identity` (no
//! agent job references a secret named like a personal access token; a
//! heuristic, said so). No budget is required: `--max-budget-usd` waits for its
//! amount (spec, Open questions 7) and Codex exposes no turn or budget cap.
use super::audit::{IDENTITY, WORKFLOW_CAPS};
use super::unattended::{AGENT_ACTIONS, agent_action, agent_jobs, runs_agent};
use crate::auditor::workflows::{self, Step, Workflow, warn};
use crate::engine::answers::{Kind, Question};
use crate::engine::manual::{ManualStep, Owner, Probe};
use serde_json::json;
use std::collections::BTreeSet;
use std::path::Path;

pub const AGENT_APP_ID: &str = "AGENT_APP_ID";
pub const AGENT_APP_PRIVATE_KEY: &str = "AGENT_APP_PRIVATE_KEY";
/// The answer naming the App (its slug) for the `app-installed` probe.
pub const SLUG: &str = "agent_app_slug";

pub fn question() -> Question {
    Question {
        description:
            "The slug of the GitHub App agents act through, for the agent-app step's probe."
                .to_owned(),
        min_length: Some(1),
        ..Question::new(SLUG, Kind::String)
    }
}

/// The owner steps: the App in every profile (#1255), then, in P2 and P3 where
/// agent jobs run in CI (`teams`), its id and private key as repository secrets,
/// checked by name and never read.
pub fn steps(slug: Option<&str>, teams: bool) -> Vec<ManualStep> {
    let step = |id: &str, title: String, instructions: String, probe| ManualStep {
        id: id.to_owned(),
        title,
        owner: Owner::Owner,
        instructions,
        probe,
        after: None,
    };
    let secret = |name: &str| Probe::Remote {
        id: "secret-present".to_owned(),
        args: [
            ("name".to_owned(), json!(name)),
            ("scope".to_owned(), json!("repository")),
        ]
        .into(),
    };
    let mut steps = vec![step(
        "agent-app",
        "Create the agents' GitHub App and install it on selected repositories".to_owned(),
        format!(
            "One GitHub App per owner account or organization for agents (decision #1255), created from templates/agent-identity/app-manifest.json: permissions Contents, Pull requests and Issues read and write; Checks, Commit statuses, Actions read and Metadata read; no Workflows, no Administration, no Secrets, no Environments, no webhook. Install it on selected repositories only, never all repositories. For local agent sessions keep its private key in the macOS Keychain and mint tokens with templates/agent-identity/installation-token.sh; for agent jobs in CI (P2, P3) store its id and private key as the secrets {AGENT_APP_ID} and {AGENT_APP_PRIVATE_KEY} (the installer checks the names, never a value). The ruleset keeps bypass_actors empty: the App is never a bypass actor."
        ),
        Probe::Remote {
            id: "app-installed".to_owned(),
            args: slug
                .map(|s| [("slug".to_owned(), json!(s))].into())
                .unwrap_or_default(),
        },
    )];
    if !teams {
        return steps;
    }
    steps.extend([
        step(
            "agent-app-id-present",
            format!("Create the {AGENT_APP_ID} secret"),
            format!(
                "gh secret set {AGENT_APP_ID} --repo <owner>/<repo>: the App's id; the installer never reads it."
            ),
            secret(AGENT_APP_ID),
        ),
        step(
            "agent-app-key-present",
            format!("Create the {AGENT_APP_PRIVATE_KEY} secret"),
            format!(
                "gh secret set {AGENT_APP_PRIVATE_KEY} --repo <owner>/<repo> < app.pem: the App's private key; the installer never reads it."
            ),
            secret(AGENT_APP_PRIVATE_KEY),
        ),
    ]);
    steps
}

/// `each` over every workflow under `.github/workflows/` that parses; an
/// unparsable one is another rule's finding (`ci.workflow-lint`).
fn over_workflows(root: &Path, each: impl Fn(&str, &Workflow) -> Vec<String>) -> Vec<String> {
    workflows::read_all(&crate::auditor::LocalFiles::new(root))
        .into_iter()
        .filter_map(|(path, parsed)| Some(each(&path, &parsed.ok()?)))
        .flatten()
        .collect()
}

/// A step that runs a Claude agent: the action, or a `run:` starting the CLI;
/// Codex steps are not, and have no turn cap to ask for.
fn claude_step(step: &Step) -> bool {
    let codex = agent_action(step.uses.as_deref()) == Some(AGENT_ACTIONS[1])
        || step
            .run
            .as_deref()
            .is_some_and(|run| run.contains("codex exec"));
    runs_agent(step) && !codex
}

fn turn_capped(step: &Step) -> bool {
    step.with.contains_key("max_turns")
        || step
            .with
            .get("claude_args")
            .is_some_and(|a| a.contains("--max-turns"))
        || step
            .run
            .as_deref()
            .is_some_and(|r| r.contains("--max-turns"))
}

/// `agents.workflow-caps`: every agent job of every workflow is capped.
pub fn workflow_caps(root: &Path) -> Vec<String> {
    over_workflows(root, |path, wf| {
        let mut out = Vec::new();
        for job in agent_jobs(wf) {
            let id = &job.id;
            let mut say =
                |text: String| out.push(warn(WORKFLOW_CAPS, format!("{path}: job {id} {text}")));
            if job.timeout_minutes.is_none() {
                say("runs an agent without timeout-minutes".to_owned());
            }
            if job.concurrency.is_none() && wf.concurrency.is_none() {
                say("runs an agent without a concurrency group".to_owned());
            }
            for step in job
                .steps
                .iter()
                .filter(|s| claude_step(s) && !turn_capped(s))
            {
                say(format!(
                    "runs {} without --max-turns",
                    agent_action(step.uses.as_deref()).unwrap_or("claude")
                ));
            }
        }
        out
    })
}

/// A secret named like a personal access token: `*_PAT`, `PAT`, `GH_PAT` or
/// `GH_TOKEN` (`GITHUB_TOKEN` is the job's own).
fn pat_like(name: &str) -> bool {
    name.ends_with("_PAT") || matches!(name, "PAT" | "GH_PAT" | "GH_TOKEN")
}

/// The names after `secrets.` in `text`.
fn secret_names(text: &str) -> impl Iterator<Item = &str> {
    text.match_indices("secrets.").map(|(at, marker)| {
        let rest = &text[at + marker.len()..];
        let end = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(rest.len());
        &rest[..end]
    })
}

/// `agents.identity`: no agent job references a secret named like a personal
/// access token, in a step's `with`, `env` or `run`. A heuristic, said so.
pub fn identity(root: &Path) -> Vec<String> {
    over_workflows(root, |path, wf| {
        let mut out = Vec::new();
        for job in agent_jobs(wf) {
            let texts = job.steps.iter().flat_map(|step| {
                step.with
                    .values()
                    .chain(step.env.values())
                    .chain(step.run.iter())
            });
            let names: BTreeSet<&str> = texts
                .flat_map(|text| secret_names(text))
                .filter(|name| pat_like(name))
                .collect();
            for name in names {
                out.push(warn(IDENTITY, format!(
                    "{path}: job {} references secrets.{name}, named like a personal access token (a heuristic); agents act through the App of step agent-app",
                    job.id
                )));
            }
        }
        out
    })
}
