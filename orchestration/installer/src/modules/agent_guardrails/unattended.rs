//! Unattended issue → pull request (#946; SPEC-agent-guardrails.md, "Unattended issue →
//! pull request"). When `unattended` is true the module renders
//! `.github/workflows/agentic-implement.yml` (`managed`): a person with write access
//! labels an issue `unattended_label` and two jobs run.
//!
//! - `implement` runs `anthropics/claude-code-action` (pinned by the pin table's SHA,
//!   `CLAUDE_CODE_OAUTH_TOKEN`) with a token that can only read: `contents: read,
//!   issues: read`. The agent works on `agent/<issue>` and commits; its commits leave the
//!   job as a git bundle. The action writes its token into the checkout's remote, so the
//!   job's token is the agent's: a read-only one cannot push, label, approve or merge.
//! - `publish` runs no agent: `contents: write, pull-requests: write`, it verifies that
//!   the bundle descends from the base, pushes `agent/<issue>` and opens the pull request.
//! - Both jobs declare `cache-mode: none` and neither caches ("CI hardening for agent
//!   workflows", point 4, #970): no entry reaches the agent and none leaves it.
//!
//! The prompt is the project's (`unattended_prompt`, required, never invented: it names
//! the project's own implement entry point), followed by the issue and the branch
//! contract. Caps: `timeout-minutes`, `--max-turns`, per-issue `concurrency`; no budget
//! is rendered until measured (spec, Open questions 7). The action's own checks stay:
//! the labeller must be a human with write access (no `allowed_non_write_users`, no
//! `allowed_bots`).
//!
//! GitHub facts this design rests on, read 2026-10-29:
//! - A pull request opened with `GITHUB_TOKEN` creates its `pull_request` runs in an
//!   approval-required state; a person with write access starts them ("Approve workflows
//!   to run"), for `opened`, `synchronize` and `reopened` (re-read 2026-10-29, #970; no
//!   dispatch or App token is added):
//!   https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow
//! - `GITHUB_TOKEN` opens pull requests only when the repository allows GitHub Actions to
//!   create and approve them (off by default in personal repositories), read by
//!   `GET /repos/{owner}/{repo}/actions/permissions/workflow`:
//!   https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository
//!   and https://docs.github.com/en/rest/actions/permissions#get-default-workflow-permissions-for-a-repository
//! - `anthropics/claude-code-action` v1.0.264 (the pin): with `prompt` on an `issues`
//!   event it runs in agent mode (src/modes/detector.ts), refuses a non-human actor
//!   unless `allowed_bots` lists it (src/github/validation/actor.ts) and an actor without
//!   write access unless `allowed_non_write_users` lists it (src/entrypoints/prepare.ts);
//!   it puts its token in the origin URL (src/github/operations/git-config.ts);
//!   `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB` in the job's `env:` scrubs Anthropic and Actions
//!   secrets from the agent's subprocesses (action.yml, docs/security.md); `max_turns` is
//!   deprecated for `--max-turns` in `claude_args` (docs/usage.md). Sources at
//!   https://github.com/anthropics/claude-code-action/tree/d70510b174a1244958df0b03166a54912811f3e6
use super::{
    AGENT_GUARDRAILS, EGRESS_SH, MODEL_COPY_SH, MODEL_DUMMY_TOKEN, MODEL_USER,
    audit::UNATTENDED_GATED,
    pins::{CLAUDE, CLAUDE_GIT_EMAIL, CLAUDE_GIT_NAME},
    render, review,
};
use crate::{
    Result,
    auditor::workflows::{Job, Permissions, Step, Workflow, warn},
    engine::{
        Context, Rendered,
        answers::{Answers, Kind, Question, When},
        lock::Ownership,
        manual::{ManualStep, Owner, Probe},
    },
    modules::stack_packs::PinTable,
    refuse,
};
use serde_json::{Value, json};

pub const WORKFLOW_PATH: &str = ".github/workflows/agentic-implement.yml";
const TEMPLATE: &str =
    include_str!("../../../../../templates/agent-guardrails/agentic-implement.yml");
/// The agent job's cap (spec): the rule refuses more.
pub const TIMEOUT_MINUTES: u32 = 45;
/// The publish job runs git and gh only.
pub const PUBLISH_TIMEOUT_MINUTES: u32 = 10;
pub const DEFAULT_LABEL: &str = "agent:ready";
pub const DEFAULT_MAX_TURNS: i64 = 60;
/// GitHub's longest label name.
const MAX_LABEL: usize = 50;
/// What the agent may run without the project's own allow rules; the project's
/// `.claude/settings.json` adds its commands and its deny rules always win. No `gh`:
/// the issue reaches the agent as written when it was labelled (`ISSUE_DIR`), never
/// later edits or comments by others.
const TOOLS: &str = "Read,Grep,Glob,Edit,Write,Bash(git add *),Bash(git commit *)";
/// Never: a planted git hook or configuration would run code at the next commit.
const DENIED_TOOLS: &str = "Edit(./.git/**),Write(./.git/**)";
/// Never: what any Claude run denies besides (`review::CLAUDE_DENIED`).
fn denied_tools() -> String {
    format!("{DENIED_TOOLS},{}", review::CLAUDE_DENIED)
}
/// Where the issue's title and body as labelled are written, outside the checkout.
const ISSUE_DIR: &str = "/home/agent-model/context";
/// The agent actions the rule recognises, by repository (any case, any sub-path).
pub(super) const AGENT_ACTIONS: [&str; 2] =
    ["anthropics/claude-code-action", "openai/codex-action"];
/// Commands in a `run:` step that start an agent CLI.
const AGENT_COMMANDS: [&str; 4] = [
    "claude -p",
    "claude --print",
    "@anthropic-ai/claude-code",
    "codex exec",
];
/// Flags that switch the agent's permission checks off.
pub(super) const BYPASS_FLAGS: [&str; 2] = ["--dangerously-skip-permissions", "bypassPermissions"];
/// Inputs that let actors without write access, or bots, past the action's check.
const WIDENING_INPUTS: [&str; 5] = [
    "allowed_non_write_users",
    "allowed_bots",
    "allow-users",
    "allow-bots",
    "allow-bot-users",
];
/// The token inputs an agent step may receive: the job's own, whose scopes the rule reads.
pub(super) const JOB_TOKENS: [&str; 2] = ["${{ github.token }}", "${{ secrets.GITHUB_TOKEN }}"];

/// The four questions, after the reviewer's: `unattended` and three gated on it.
pub fn questions() -> Vec<Question> {
    let gated = |id: &str, kind: Kind, description: &str| Question {
        description: description.to_owned(),
        when: Some(When::Truthy("unattended".to_owned())),
        ..Question::new(id, kind)
    };
    vec![
        Question {
            description: "Render agentic-implement.yml: an issue labelled by a person with write access becomes an agent's pull request.".to_owned(),
            default: Some(json!(false)),
            ..Question::new("unattended", Kind::Boolean)
        },
        Question {
            default: Some(json!(DEFAULT_LABEL)),
            min_length: Some(1),
            max_length: Some(MAX_LABEL),
            ..gated("unattended_label", Kind::String, "The issue label that starts the unattended agent.")
        },
        Question {
            required: true,
            min_length: Some(1),
            ..gated(
                "unattended_prompt",
                Kind::String,
                "The project's own implement entry point (a command or skill its agent rules declare); the installer never invents one.",
            )
        },
        Question {
            default: Some(json!(DEFAULT_MAX_TURNS)),
            minimum: Some(5),
            maximum: Some(200),
            ..gated("unattended_max_turns", Kind::Integer, "The agent's turn cap (--max-turns).")
        },
    ]
}

/// True when the answers enable the workflow.
pub fn enabled(answers: &Answers) -> bool {
    answers.get("unattended").and_then(Value::as_bool) == Some(true)
}

/// The label, refused unless it is plain text: it is written inside a workflow expression.
fn label(answers: &Answers) -> Result<&str> {
    let label = answers
        .get("unattended_label")
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_LABEL);
    let plain = |c: char| c.is_ascii_alphanumeric() || " :._/-".contains(c);
    if label.trim().is_empty() || !label.chars().all(plain) {
        return refuse(format!(
            "Module {AGENT_GUARDRAILS}: unattended_label `{label}` may hold only letters, digits, spaces and : . _ / -"
        ));
    }
    Ok(label)
}

/// The project's prompt, refused when absent or when it carries a workflow expression,
/// which GitHub would evaluate before the agent reads it.
fn prompt(answers: &Answers) -> Result<&str> {
    let Some(prompt) = answers
        .get("unattended_prompt")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|p| !p.is_empty())
    else {
        return refuse(format!(
            "Module {AGENT_GUARDRAILS}: unattended is true but unattended_prompt has no value; answer it with the project's own implement entry point (configure --set unattended_prompt=…)"
        ));
    };
    if prompt
        .chars()
        .any(|c| c.is_control() && c != '\n' && c != '\t')
    {
        return refuse(format!(
            "Module {AGENT_GUARDRAILS}: unattended_prompt contains a control character; only line breaks and tabs are kept"
        ));
    }
    if prompt.contains("${{") {
        return refuse(format!(
            "Module {AGENT_GUARDRAILS}: unattended_prompt contains `${{{{`, a workflow expression; write the prompt as plain text"
        ));
    }
    Ok(prompt)
}

fn max_turns(answers: &Answers) -> i64 {
    answers
        .get("unattended_max_turns")
        .and_then(Value::as_i64)
        .unwrap_or(DEFAULT_MAX_TURNS)
}

/// The text the agent receives: the project's prompt, then the issue and the branch contract.
fn full_prompt(project: &str) -> String {
    format!(
        "{project}\n\nIssue #${{{{ github.event.issue.number }}}} (${{{{ github.event.issue.html_url }}}}): its title and body as they were when labelled are in {ISSUE_DIR}/issue.md.\nYou are on the branch agent/${{{{ github.event.issue.number }}}}. Commit your work there; do not push and do not open a pull request: this workflow publishes the branch and opens the pull request when you finish."
    )
}

/// `text` with every non-empty line indented by `n` spaces, without a final newline.
fn indent(text: &str, n: usize) -> String {
    let pad = " ".repeat(n);
    text.lines()
        .map(|line| {
            if line.is_empty() {
                String::new()
            } else {
                format!("{pad}{line}")
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The workflow for `answers` on `runner`; refuses on a missing prompt or a bad label.
pub fn workflow(answers: &Answers, runner: &str, pins: &PinTable) -> Result<String> {
    review::confirmed(&CLAUDE)?;
    let label = label(answers)?;
    let prompt = prompt(answers)?;
    let flags = format!(
        "--max-turns {} --allowedTools \"{TOOLS}\" --disallowedTools \"{}\" --add-dir {ISSUE_DIR}",
        max_turns(answers),
        denied_tools()
    );
    let run = format!(
        "set -euo pipefail\nresume=\"model-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \\n')\"\necho \"::stop-commands::$resume\"\nstatus=0\n{} || status=$?\necho \"::$resume::\"\nexit \"$status\"",
        review::claude_command(&flags)
    );
    let condition = "";
    Ok(render(
        TEMPLATE,
        &[
            ("label", label),
            ("runner", runner),
            ("timeout", &TIMEOUT_MINUTES.to_string()),
            ("publish_timeout", &PUBLISH_TIMEOUT_MINUTES.to_string()),
            ("checkout", &pins.action("actions/checkout")?.uses()),
            ("egress_env", &review::egress_env(false, None, 10)),
            (
                "check_env",
                &review::egress_env(true, Some("/v1/messages"), 10),
            ),
            ("egress", &indent(EGRESS_SH, 10)),
            ("actor", &review::claude_actor_check("", 6, condition)),
            ("bwrap", &review::bwrap_prepare(6, condition)),
            ("install", &review::claude_install(pins, 6, condition)?),
            (
                "proxy",
                &review::model_proxy(
                    "CLAUDE_CODE_OAUTH_TOKEN",
                    CLAUDE.secret,
                    "anthropic",
                    6,
                    condition,
                ),
            ),
            ("model_user", MODEL_USER),
            ("git_name", CLAUDE_GIT_NAME),
            ("git_email", CLAUDE_GIT_EMAIL),
            ("copy", &indent(MODEL_COPY_SH, 10)),
            ("dummy_token", MODEL_DUMMY_TOKEN),
            ("prompt", &indent(&full_prompt(prompt), 12)),
            ("agent_run", &indent(&run, 10)),
            ("upload", &pins.action("actions/upload-artifact")?.uses()),
            (
                "download",
                &pins.action("actions/download-artifact")?.uses(),
            ),
        ],
    ))
}

/// The rendered workflow when `unattended` is true; nothing otherwise.
pub fn rendered(cx: &Context<'_>) -> Result<Option<Rendered>> {
    if !enabled(cx.answers) {
        return Ok(None);
    }
    let pins = PinTable::embedded()?;
    let content = workflow(cx.answers, review::answered_runner(cx)?, &pins)?;
    Ok(Some(Rendered {
        path: WORKFLOW_PATH.to_owned(),
        class: Ownership::Managed,
        content: Some(content),
        scaffold: None,
    }))
}

/// The owner's two steps when `unattended` is true: the agent's credential (unless the
/// Claude reviewer already asks for the same secret in the same store) and the
/// repository setting that lets the workflow token open pull requests.
pub fn steps(answers: &Answers) -> Vec<ManualStep> {
    if !enabled(answers) {
        return Vec::new();
    }
    let mut steps = Vec::new();
    if review::reviewer(answers).map(|r| r.family) != Some(CLAUDE.family) {
        let secret = CLAUDE.secret;
        steps.push(ManualStep {
            id: "unattended-secret-present".to_owned(),
            title: format!("Create the {secret} secret for agentic-implement in the Actions secrets"),
            owner: Owner::Owner,
            instructions: format!(
                "gh secret set {secret} --repo <owner>/<repo>: the unattended agent's credential (claude setup-token); the installer never reads it. Until it exists, agentic-implement fails with the action's own missing-secret message."
            ),
            probe: Probe::Remote {
                id: "secret-present".to_owned(),
                args: [
                    ("name".to_owned(), json!(secret)),
                    ("scope".to_owned(), json!("repository")),
                ]
                .into(),
            },
            after: None,
        });
    }
    steps.push(ManualStep {
        id: "actions-open-pull-requests".to_owned(),
        title: "Allow GitHub Actions to create pull requests".to_owned(),
        owner: Owner::Owner,
        instructions: "Settings → Actions → General → Workflow permissions: tick \"Allow GitHub Actions to create and approve pull requests\" (gh api -X PUT repos/<owner>/<repo>/actions/permissions/workflow -F can_approve_pull_request_reviews=true -f default_workflow_permissions=read). The same switch lets every workflow token approve pull requests: an approval by github-actions[bot] is never a code owner's, so a ruleset that counts plain approvals must also require code-owner review or keep the human-approved gate. Until it is on, publish fails at gh pr create and the branch agent/<issue> stays without a pull request.".to_owned(),
        probe: Probe::Remote {
            id: "actions-pull-requests".to_owned(),
            args: Default::default(),
        },
        after: None,
    });
    steps
}

// ---- agents.unattended-gated -------------------------------------------------------

/// The agent action a step or job uses, if any: its repository in any case, or a
/// sub-path of it (`…/base-action`).
pub(super) fn agent_action(uses: Option<&str>) -> Option<&'static str> {
    let path = uses?.split('@').next()?.to_ascii_lowercase();
    AGENT_ACTIONS
        .into_iter()
        .find(|a| path == *a || path.starts_with(&format!("{a}/")))
}

/// A step that runs an agent: its action, or a `run:` that starts an agent CLI.
pub(super) fn runs_agent(step: &Step) -> bool {
    agent_action(step.uses.as_deref()).is_some()
        || step
            .run
            .as_deref()
            .is_some_and(|run| AGENT_COMMANDS.iter().any(|c| run.contains(c)))
}

pub(super) fn agent_jobs(wf: &Workflow) -> Vec<&Job> {
    wf.jobs
        .iter()
        .filter(|j| agent_action(j.uses.as_deref()).is_some() || j.steps.iter().any(runs_agent))
        .collect()
}

/// `if: github.event.label.name == '<literal>'`, alone or joined by `&&` only; never
/// `||`, `!` or `always()`, which would let another event through.
fn label_gated(condition: Option<&str>) -> bool {
    let Some(condition) = condition else {
        return false;
    };
    let condition = condition
        .trim()
        .trim_start_matches("${{")
        .trim_end_matches("}}");
    let positive = condition.split("&&").any(|part| {
        part.trim()
            .strip_prefix("github.event.label.name == '")
            .is_some_and(|rest| rest.ends_with('\'') && !rest[..rest.len() - 1].contains('\''))
    });
    positive
        && !condition.contains("||")
        && !condition.contains('!')
        && !condition.contains("always()")
}

/// In scope: triggered by `issues` (all types, or `labeled` among them) and running an
/// agent in some job (an agent action, or a `run:` that starts an agent CLI).
pub fn in_scope(wf: &Workflow) -> bool {
    let labeled = wf.triggers.iter().any(|t| t == "issues")
        && wf
            .trigger_types
            .get("issues")
            .is_none_or(|types| types.iter().any(|t| t == "labeled"));
    labeled && !agent_jobs(wf).is_empty()
}

/// The findings of `agents.unattended-gated` for one workflow in scope, or none.
pub fn gated(path: &str, wf: &Workflow) -> Vec<String> {
    if !in_scope(wf) {
        return Vec::new();
    }
    let mut out: Vec<String> = Vec::new();
    let mut say = |text: String| out.push(warn(UNATTENDED_GATED, format!("{path}: {text}")));
    for trigger in wf.triggers.iter().filter(|t| *t != "issues") {
        say(format!(
            "also triggers on {trigger}; an unattended agent runs on issues.labeled alone"
        ));
    }
    for job in agent_jobs(wf) {
        let id = &job.id;
        if !label_gated(job.condition.as_deref()) {
            say(format!(
                "job {id} runs the agent on any issue event; gate it with if: github.event.label.name == '<label>'"
            ));
        }
        match job.timeout_minutes.as_deref().map(str::parse::<u32>) {
            Some(Ok(minutes)) if minutes <= TIMEOUT_MINUTES => {}
            _ => say(format!(
                "job {id} has no timeout-minutes of at most {TIMEOUT_MINUTES}"
            )),
        }
        let per_issue = |group: &Option<String>| {
            group
                .as_deref()
                .is_some_and(|g| g.contains("github.event.issue.number"))
        };
        if !per_issue(&job.concurrency) && !per_issue(&wf.concurrency) {
            say(format!(
                "job {id} has no concurrency group per issue (github.event.issue.number)"
            ));
        }
        match job.permissions.as_ref().or(wf.permissions.as_ref()) {
            Some(Permissions::Scopes(scopes)) => {
                for (scope, access) in scopes {
                    if access != "read" && access != "none" {
                        say(format!(
                            "job {id} grants {scope}: {access}; the agent holds the job's token, so its job only reads and another job without an agent writes"
                        ));
                    }
                }
            }
            _ => say(format!(
                "job {id} declares no permission scopes; declare them, read-only"
            )),
        }
        for step in job.steps.iter().filter(|s| runs_agent(s)) {
            let args = [step.with.get("claude_args"), step.run.as_ref()];
            for flag in BYPASS_FLAGS {
                if args.iter().flatten().any(|a| a.contains(flag)) {
                    say(format!(
                        "job {id} runs the agent with {flag}; its permission checks stay on"
                    ));
                }
            }
            let Some(action) = agent_action(step.uses.as_deref()) else {
                continue;
            };
            if let Some(token) = step.with.get("github_token")
                && !JOB_TOKENS.contains(&token.trim())
            {
                say(format!(
                    "job {id} gives the agent github_token {token}; only the job's own token, whose scopes this rule reads"
                ));
            }
            if action == CLAUDE.action
                && !step.with.contains_key("max_turns")
                && !step
                    .with
                    .get("claude_args")
                    .is_some_and(|a| a.contains("--max-turns"))
            {
                say(format!("job {id} runs {action} without --max-turns"));
            }
            for input in WIDENING_INPUTS {
                let widened = step
                    .with
                    .get(input)
                    .is_some_and(|v| !v.trim().is_empty() && v.trim() != "false");
                if widened {
                    say(format!(
                        "job {id} sets {input}; only people with write access start the agent"
                    ));
                }
            }
        }
    }
    out
}
