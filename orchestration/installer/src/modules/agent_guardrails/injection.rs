//! `agents.workflow-injection` (#972; SPEC-agent-guardrails.md, "CI hardening for
//! agent workflows"; `docs/decisions.md`, same title, point 6). Bronze, all profiles,
//! static: every job of every workflow that runs an agent, detected as
//! `agents.unattended-gated` detects it (plus a job whose only agent is
//! `anthropics/claude-code-base-action`, the action one check names), whatever the
//! trigger, is checked for the ways untrusted text reaches a model that holds a
//! token, a secret or a way out. Each finding names the file, the job and the check:
//! `WARNING: agents.workflow-injection: <file>#<job>: <check>`; never `NOT READY`.
//!
//! As built (#972): an interpolation counts in the `run:` of any step of the job
//! and in any `with:` input of an agent step; permissions are the job's, or the
//! workflow's when the job declares none; `cache-mode` likewise.
use super::{
    audit::WORKFLOW_INJECTION,
    unattended::{BYPASS_FLAGS, JOB_TOKENS, agent_action, agent_jobs, runs_agent},
};
use crate::auditor::workflows::{Job, Permissions, Step, Workflow, warn};

/// Triggers that run a workflow on another repository's text or code with this
/// repository's token and secrets.
const UNTRUSTED_TRIGGERS: [&str; 2] = ["pull_request_target", "workflow_run"];
/// The last segments of `github.event.*` paths GitHub lists as attacker-controlled
/// ("Security hardening for GitHub Actions", untrusted input).
const UNTRUSTED_ENDINGS: [&str; 10] = [
    "body",
    "default_branch",
    "email",
    "head_ref",
    "label",
    "message",
    "name",
    "page_name",
    "ref",
    "title",
];
/// Inputs whose wildcard lets any actor, or any bot, start the agent.
const ACTOR_LISTS: [&str; 3] = ["allowed_bots", "allow-users", "allow-bot-users"];
const BASE_ACTION: &str = "anthropics/claude-code-base-action";
const CODEX: &str = "openai/codex-action";
const CODEX_STRATEGIES: [&str; 2] = ["drop-sudo", "unprivileged-user"];
const ALLOWED_TOOLS: [&str; 2] = ["--allowedTools", "--allowed-tools"];

/// The repository of a `uses:`, lower-cased, without the ref.
fn repository(uses: Option<&str>) -> Option<String> {
    Some(uses?.split('@').next()?.to_ascii_lowercase())
}

fn is_base_action(step: &Step) -> bool {
    repository(step.uses.as_deref()).is_some_and(|r| r == BASE_ACTION)
}

/// A step that runs an agent for this rule: the detection of
/// `agents.unattended-gated`, or the base action.
fn agent_step(step: &Step) -> bool {
    runs_agent(step) || is_base_action(step)
}

/// The jobs in scope, in file order.
fn jobs(wf: &Workflow) -> Vec<&Job> {
    let detected = agent_jobs(wf);
    wf.jobs
        .iter()
        .filter(|j| {
            detected.iter().any(|d| std::ptr::eq(*d, *j)) || j.steps.iter().any(is_base_action)
        })
        .collect()
}

/// In scope: some job of the workflow runs an agent.
pub fn in_scope(wf: &Workflow) -> bool {
    !jobs(wf).is_empty()
}

/// Every `${{ … }}` in `text` that reads an untrusted context, as written.
fn untrusted_expressions(text: &str) -> Vec<String> {
    text.split("${{")
        .skip(1)
        .filter_map(|rest| rest.split_once("}}").map(|(inner, _)| inner))
        .filter(|inner| reads_untrusted(inner))
        .map(|inner| format!("${{{{{inner}}}}}"))
        .collect()
}

/// `github.head_ref`, a whole `github.event`, or a `github.event.*` path whose last
/// segment is an untrusted ending; `github.event_name` and its kin are not events.
fn reads_untrusted(expr: &str) -> bool {
    let ident = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '-';
    let starts = |at: usize| at == 0 || !expr[..at].ends_with(|c: char| ident(c) || c == '.');
    let mentions = |name: &str| {
        expr.match_indices(name)
            .any(|(at, _)| starts(at) && !expr[at + name.len()..].starts_with(|c: char| ident(c)))
    };
    if mentions("github.head_ref") {
        return true;
    }
    expr.match_indices("github.event").any(|(at, word)| {
        let rest = &expr[at + word.len()..];
        if !starts(at) || rest.starts_with(|c: char| ident(c)) {
            return false;
        }
        let path: String = rest
            .chars()
            .take_while(|c| ident(*c) || matches!(c, '.' | '[' | ']' | '\'' | '"' | '*'))
            .collect();
        // `['x']` and `["x"]` are `.x`; a numeric index or `*` is no segment.
        let path = path
            .replace("['", ".")
            .replace("[\"", ".")
            .replace("']", "")
            .replace("\"]", "");
        let last = path
            .split('.')
            .map(|segment| segment.split('[').next().unwrap_or(""))
            .rfind(|segment| !segment.is_empty() && *segment != "*");
        match last {
            None => true,
            Some(segment) => UNTRUSTED_ENDINGS.contains(&segment),
        }
    })
}

/// `Bash` with no parenthesised pattern among the tools after `--allowedTools`.
fn bare_bash(text: &str) -> bool {
    text.lines().any(|line| {
        ALLOWED_TOOLS.iter().any(|flag| {
            line.split_once(flag).is_some_and(|(_, rest)| {
                rest.split_whitespace()
                    .take_while(|word| !word.starts_with("--"))
                    .flat_map(|word| word.split(','))
                    .map(|tool| tool.trim_matches(|c| c == '"' || c == '\''))
                    .any(|tool| tool == "Bash")
            })
        })
    })
}

/// The findings of `agents.workflow-injection` for one workflow, or none.
pub fn findings(path: &str, wf: &Workflow) -> Vec<String> {
    let mut out = Vec::new();
    for job in jobs(wf) {
        let mut say = |check: String| {
            out.push(warn(
                WORKFLOW_INJECTION,
                format!("{path}#{}: {check}", job.id),
            ));
        };
        for trigger in UNTRUSTED_TRIGGERS {
            if wf.triggers.iter().any(|t| t == trigger) {
                say(format!(
                    "triggers on {trigger}; the agent would run on text and code from outside with this repository's token and secrets"
                ));
            }
        }
        for step in &job.steps {
            for expr in untrusted_expressions(step.run.as_deref().unwrap_or("")) {
                say(format!("a run: interpolates {expr}; pass it through env:"));
            }
            if agent_step(step) {
                for (input, value) in &step.with {
                    for expr in untrusted_expressions(value) {
                        say(format!(
                            "input {input} of the agent step interpolates {expr}; pass it through env: and a file"
                        ));
                    }
                }
            }
        }
        match job.permissions.as_ref().or(wf.permissions.as_ref()) {
            None => say(
                "declares no permissions at job or workflow level; the agent would hold the default token"
                    .to_owned(),
            ),
            Some(Permissions::Scalar(all)) => {
                if all.contains("write") {
                    say(format!(
                        "grants {all}; the agent holds the job's token, so its job only reads"
                    ));
                }
            }
            Some(Permissions::Scopes(scopes)) => {
                for (scope, access) in scopes {
                    if access == "write" {
                        say(format!(
                            "grants {scope}: {access}; the agent holds the job's token, so its job only reads"
                        ));
                    }
                }
            }
        }
        for (at, step) in job.steps.iter().enumerate() {
            let repo = repository(step.uses.as_deref());
            if agent_step(step) {
                if step.with.contains_key("allowed_non_write_users") {
                    say(
                        "sets allowed_non_write_users; only people with write access start the agent"
                            .to_owned(),
                    );
                }
                for input in ACTOR_LISTS {
                    if let Some(value) = step.with.get(input).filter(|v| v.contains('*')) {
                        say(format!(
                            "sets {input} to {value}; name the actors, never all of them"
                        ));
                    }
                }
                if let Some(value) = step
                    .with
                    .get("allow-bots")
                    .filter(|v| v.trim().eq_ignore_ascii_case("true"))
                {
                    say(format!(
                        "sets allow-bots to {value}; name the actors, never all of them"
                    ));
                }
                if let Some(token) = step
                    .with
                    .get("github_token")
                    .filter(|t| !JOB_TOKENS.contains(&t.trim()))
                {
                    say(format!(
                        "gives the agent github_token {token}; only the job's own token"
                    ));
                }
                let texts: Vec<&str> = step
                    .with
                    .values()
                    .chain(step.run.as_ref())
                    .map(String::as_str)
                    .collect();
                for flag in BYPASS_FLAGS {
                    if texts.iter().any(|t| t.contains(flag)) {
                        say(format!(
                            "runs the agent with {flag}; its permission checks stay on"
                        ));
                    }
                }
                if texts.iter().any(|t| bare_bash(t)) {
                    say(
                        "allows Bash without a pattern in --allowedTools; name the commands, Bash(<command> *)"
                            .to_owned(),
                    );
                }
                if agent_action(step.uses.as_deref()) == Some(CODEX) {
                    if let Some(strategy) = step
                        .with
                        .get("safety-strategy")
                        .filter(|s| !CODEX_STRATEGIES.contains(&s.trim()))
                    {
                        say(format!(
                            "runs {CODEX} with safety-strategy {strategy}; keep drop-sudo or unprivileged-user"
                        ));
                    }
                    if at + 1 < job.steps.len() {
                        say(format!(
                            "runs a step after {CODEX}; Codex is the last step of its job"
                        ));
                    }
                }
            }
            let uses = step.uses.as_deref().unwrap_or("");
            if repo
                .as_deref()
                .is_some_and(|r| r == "actions/cache" || r.starts_with("actions/cache/"))
            {
                say(format!("uses {uses}; no cache near an agent"));
            }
            if step.with.contains_key("cache") {
                say(format!("passes cache: to {uses}; no cache near an agent"));
            }
            if repo.as_deref() == Some("actions/checkout")
                && step
                    .with
                    .get("persist-credentials")
                    .is_none_or(|v| v.trim() != "false")
            {
                say("checks out without persist-credentials: false".to_owned());
            }
            if step
                .with
                .get("show_full_output")
                .is_some_and(|v| v.trim().eq_ignore_ascii_case("true"))
            {
                say(
                    "sets show_full_output: true; the agent's full output would reach the run log"
                        .to_owned(),
                );
            }
            if is_base_action(step) {
                say(format!(
                    "uses {BASE_ACTION}; use anthropics/claude-code-action, which keeps the actor checks"
                ));
            }
        }
        if job
            .cache_mode
            .as_ref()
            .or(wf.cache_mode.as_ref())
            .map(|m| m.trim())
            != Some("none")
        {
            say(
                "has no cache-mode: none; no cache entry may reach the agent or leave it"
                    .to_owned(),
            );
        }
    }
    out
}
