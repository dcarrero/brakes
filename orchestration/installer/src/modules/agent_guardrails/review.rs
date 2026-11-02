//! `cross-review` (#940; SPEC-agent-guardrails.md, "Cross-family review as a
//! required check", amended by "CI hardening for agent workflows", #969): when
//! `review_family` is not `none`, the module contributes two jobs to `ci-baseline`'s
//! aggregate through `Module::ci_jobs`, so the other model family's review is part
//! of the one required check (`required`, or `agentic-required` under
//! `workflow: existing`) and never a check of its own.
//!
//! `cross-review-model` holds `contents: read` and nothing more, `cache-mode: none`,
//! and runs the model as its last step: it refuses a fork, checks out the head
//! without persisted credentials, restores the instruction files from the base
//! (`cross-review-restore.sh`), writes the pull request's description to a file
//! (never into the prompt) and runs the reviewer's action pinned by the pin table's
//! SHA with the managed prompt and the answer's JSON schema; the answer is its job
//! output `verdict`. The model never holds a write token: the pinned Claude action
//! writes the job's token into the checkout's `origin` URL, so that token is the
//! model's.
//!
//! `cross-review` keeps the id and the contract: it runs no model, checks out
//! nothing, receives no vendor secret and holds `pull-requests: write` alone, with
//! `cache-mode: none`; its one step, the gate (`cross-review-gate.sh`), reads the
//! verdict through `env:`, fails closed on an empty, oversized, credential-shaped or
//! malformed verdict before posting anything, posts one comment and decides with its
//! exit code. The workflow's top level stays `contents: read`.
//!
//! Pull requests only, without breaking the aggregate: a job skipped by an event
//! condition is not one the scope job lists as skippable, so `required` would fail
//! on every push to the default branch. Both jobs therefore run on every event and
//! each of their steps carries `if: github.event_name == 'pull_request'`; the jobs'
//! own `if:` is the tier, as for every contributed job skippable under `docs`. A
//! failed `cross-review-model` leaves `cross-review` skipped, which the aggregate
//! fails because only `scope` sanctions a skip.
use super::{
    ACTOR_CHECK_SH, AGENT_GUARDRAILS, BWRAP_PREPARE_SH, EGRESS_SH, MODEL_COPY_SH,
    MODEL_DUMMY_TOKEN, MODEL_PROXY_PY, MODEL_USER,
    pins::{DEEPSEEK_MODEL, Fact, REVIEWERS, Reviewer},
    render,
};
use crate::{
    Result,
    engine::{
        CiJob, CiTier, Context,
        answers::Answers,
        manual::{ManualStep, Owner, Probe},
    },
    modules::{
        ci_baseline::{CI_BASELINE, Runner, render::runner_label},
        stack_packs::PinTable,
    },
    refuse,
};
use serde_json::{Value, json};

/// The gate job: the id the aggregate and `agents.cross-review` know.
pub const CROSS_REVIEW: &str = "cross-review";
/// The model job, which the gate job needs.
pub const CROSS_REVIEW_MODEL: &str = "cross-review-model";
/// The model job's timeout, its cap on every reviewer.
pub const TIMEOUT_MINUTES: u32 = 15;
/// The gate job's timeout: one `gh pr comment`.
pub const GATE_TIMEOUT_MINUTES: u32 = 5;
/// The largest verdict the gate posts, in bytes (the decision's figure; GitHub's
/// own cap on a job output is 1 MB).
pub const VERDICT_MAX_BYTES: u32 = 60_000;
/// The turn cap where the action has one (spec, Open questions 7: kept, never raised by default).
pub const MAX_TURNS: u32 = 30;
pub const REVIEW_FAMILIES: [&str; 4] = ["codex", "claude", "deepseek", "none"];
pub const REVIEW_BLOCKING: [&str; 2] = ["p0-p1", "p0"];
/// The longest environment name GitHub accepts.
pub const MAX_ENVIRONMENT: usize = 255;

const MODEL_JOB: &str =
    include_str!("../../../../../templates/agent-guardrails/cross-review-model.yml");
const GATE_JOB: &str = include_str!("../../../../../templates/agent-guardrails/cross-review.yml");
/// The restore step's shell, embedded verbatim.
pub const RESTORE_SH: &str =
    include_str!("../../../../../templates/agent-guardrails/cross-review-restore.sh");
/// The managed prompt, the same for both families.
pub const PROMPT: &str =
    include_str!("../../../../../templates/agent-guardrails/cross-review-prompt.md");
/// The JSON schema of the reviewer's answer, on one line.
pub const SCHEMA: &str =
    include_str!("../../../../../templates/agent-guardrails/cross-review-schema.json");
/// The gate step's shell, embedded verbatim.
pub const GATE_SH: &str =
    include_str!("../../../../../templates/agent-guardrails/cross-review-gate.sh");
/// The DeepSeek reviewer's step budget (#1240): the runner counts the change and
/// gives the `review` agent `20 + files + ceil(lines / 1000)` steps, from
/// `OPENCODE_STEP_FLOOR` up to `OPENCODE_STEP_MAX` (decision "The DeepSeek judge",
/// amended #1240 and #1256).
pub const OPENCODE_BUDGET_SH: &str =
    include_str!("../../../../../templates/agent-guardrails/opencode-budget.sh");
/// The hard cap of the DeepSeek reviewer's step budget: it bounds one review's cost and
/// keeps the run inside the job's `TIMEOUT_MINUTES` (#1240).
pub const OPENCODE_STEP_MAX: u32 = 100;
/// The least DeepSeek step budget: small changes read the code around their diff
/// and used up to 35 steps on a pilot repository, where the formula gave them 27
/// and 28 (#1256). The other reviewers keep `MAX_TURNS`.
pub const OPENCODE_STEP_FLOOR: u32 = 60;
/// The DeepSeek reviewer's verdict step: OpenCode's answer checked against the
/// schema before it becomes the job's `verdict` (#1134).
pub const OPENCODE_VERDICT_SH: &str =
    include_str!("../../../../../templates/agent-guardrails/opencode-verdict.sh");
/// What the DeepSeek reviewer's prompt asks of its final message: the shape
/// `opencode-verdict.sh` accepts (#1141; DeepSeek V4 Pro reasons in prose first).
pub const OPENCODE_ANSWER_SHAPE: &str = "End your final message with that object in one ```json fenced block and write nothing after it; anything before the block is ignored.";
/// The one bot whose pull requests are reviewed: Dependabot's (owner decision
/// through the coordinator on #957). No other bot or non-writer is allowed.
pub const DEPENDABOT: &str = "dependabot[bot]";
/// Read-only tools the Claude reviewer may run without a prompt.
const CLAUDE_TOOLS: &str = "Read,Grep,Glob,Bash(git diff *),Bash(git log *),Bash(git show *)";

/// The reviewer the answers select; `None` for `review_family: none`.
pub fn reviewer(answers: &Answers) -> Option<&'static Reviewer> {
    let family = answers
        .get("review_family")
        .and_then(Value::as_str)
        .unwrap_or("codex");
    REVIEWERS.iter().find(|r| r.family == family)
}

/// The severities that block, as the gate reads them: `P0 P1` (default) or `P0`.
pub fn blocking(answers: &Answers) -> &'static str {
    match answers.get("review_blocking").and_then(Value::as_str) {
        Some("p0") => "P0",
        _ => "P0 P1",
    }
}

/// The GitHub environment `cross-review-model` runs in, from `review_environment`
/// (#1320; owner, 2026-11-01): `None` when unanswered. The name is written into
/// the workflow, so only `1..=MAX_ENVIRONMENT` letters, digits and `. _ -` pass
/// (GitHub's own limit is 255 characters, "Managing environments for deployment").
pub fn environment(answers: &Answers) -> Result<Option<&str>> {
    let Some(name) = answers.get("review_environment").and_then(Value::as_str) else {
        return Ok(None);
    };
    let plain = |c: char| c.is_ascii_alphanumeric() || "._-".contains(c);
    if name.is_empty() || name.len() > MAX_ENVIRONMENT || !name.chars().all(plain) {
        return refuse(format!(
            "Module {AGENT_GUARDRAILS}: review_environment `{name}` must be 1 to {MAX_ENVIRONMENT} letters, digits and . _ -"
        ));
    }
    Ok(Some(name))
}

/// The facts the render reads, all confirmed.
pub struct Confirmed {
    pub secret_input: &'static str,
    pub prompt_input: &'static str,
    pub findings_output: &'static str,
    pub bot_allowlist: &'static str,
    pub schema: &'static str,
    pub turn_limit: Option<&'static str>,
    pub github_hosted: bool,
    pub extra_read_scope: Option<&'static str>,
}

/// The reviewer's facts, or a refusal naming the first one not confirmed.
pub fn confirmed(reviewer: &Reviewer) -> Result<Confirmed> {
    fn get<T: Copy>(family: &str, name: &str, fact: Fact<T>) -> Result<T> {
        match fact {
            Fact::Confirmed(value) => Ok(value),
            Fact::Unconfirmed => refuse(format!(
                "Module {AGENT_GUARDRAILS}: reviewer {family}: {name} is not confirmed in the vendor facts; verify it against the vendor's documentation before rendering {CROSS_REVIEW}"
            )),
        }
    }
    let f = reviewer.family;
    let confirmed = Confirmed {
        secret_input: get(f, "secret_input", reviewer.secret_input)?,
        prompt_input: get(f, "prompt_input", reviewer.prompt_input)?,
        findings_output: get(f, "findings_output", reviewer.findings_output)?,
        bot_allowlist: get(f, "bot_allowlist", reviewer.bot_allowlist)?,
        schema: get(f, "schema", reviewer.schema)?,
        turn_limit: get(f, "turn_limit", reviewer.turn_limit)?,
        github_hosted: get(f, "github_hosted", reviewer.github_hosted)?,
        extra_read_scope: get(f, "extra_read_scope", reviewer.extra_read_scope)?,
    };
    get(f, "fails_on_findings", reviewer.fails_on_findings)?;
    Ok(confirmed)
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

/// The `with:` inputs of the Codex reviewer's step, at the indentation of the job
/// body: Codex runs as the model's user through the action's `unprivileged-user`
/// strategy, on that user's copy (#971), its key a dummy (#1095).
fn codex_inputs(facts: &Confirmed, prompt: &str, pins: &PinTable) -> Result<String> {
    let lines = [
        // The action's proxy holds a dummy key; its upstream is the runner's
        // filtering proxy, which holds the real one (#1095).
        format!("      {}: {MODEL_DUMMY_TOKEN}", facts.secret_input),
        "      responses-api-endpoint: \"http://127.0.0.1:${{ env.MODEL_PROXY_PORT }}/v1/responses\""
            .to_owned(),
        format!("      {}: \"{DEPENDABOT}\"", facts.bot_allowlist),
        format!("      codex-version: \"{}\"", pins.tool("codex")?.version),
        "      permission-profile: \":read-only\"".to_owned(),
        "      safety-strategy: unprivileged-user".to_owned(),
        format!("      codex-user: {MODEL_USER}"),
        format!("      working-directory: /home/{MODEL_USER}/work"),
        format!(
            "      {}: /home/{MODEL_USER}/context/schema.json",
            facts.schema
        ),
        format!("      {}: |\n{}", facts.prompt_input, indent(prompt, 8)),
    ];
    Ok(lines.join("\n"))
}

/// The egress step's `env:` lines: the model's user, and for the proof run again
/// right before the model (`check`), the credential proxy at `probe` (a path).
pub(super) fn egress_env(check: bool, probe: Option<&str>, n: usize) -> String {
    let pad = " ".repeat(n);
    let mut lines = vec![format!("{pad}EGRESS_USER: {MODEL_USER}")];
    if check {
        lines.push(format!("{pad}EGRESS_MODE: check"));
        if let Some(path) = probe {
            lines.push(format!(
                "{pad}EGRESS_PROBE_URL: \"http://127.0.0.1:${{{{ env.MODEL_PROXY_PORT }}}}{path}\""
            ));
        }
    }
    lines.join("\n")
}

/// The step that prepares bubblewrap for the scrub (`bwrap-prepare.sh`).
pub(super) fn bwrap_prepare(n: usize, condition: &str) -> String {
    let pad = " ".repeat(n);
    format!(
        "{pad}- name: Prepare the agent's subprocess isolation\n{condition}{pad}  env:\n{pad}    MODEL_USER: {MODEL_USER}\n{pad}  run: |\n{}",
        indent(BWRAP_PREPARE_SH, n + 4)
    )
}

/// The step that starts `model-proxy.py` as the runner for `provider` with the real
/// key on its stdin (the secret `secret`, through the step's `env` `variable`), and
/// hands its port to the later steps (`MODEL_PROXY_PORT`).
pub(super) fn model_proxy(
    variable: &str,
    secret: &str,
    provider: &str,
    n: usize,
    condition: &str,
) -> String {
    let pad = " ".repeat(n);
    let run = format!(
        "set -euo pipefail\nproxy=\"$RUNNER_TEMP/model-proxy.py\"\nport_file=\"$RUNNER_TEMP/model-proxy-port\"\ncat >\"$proxy\" <<'PROXY'\n{}PROXY\nrm -f \"$port_file\"\n(exec env -u {variable} nohup python3 \"$proxy\" \"$port_file\" {provider} <<<\"${variable}\" >\"$RUNNER_TEMP/model-proxy.log\" 2>&1) &\nfor _ in $(seq 1 40); do\n  [ -s \"$port_file\" ] && break\n  sleep 0.25\ndone\nif [ ! -s \"$port_file\" ]; then\n  echo \"::error::model-proxy did not start (is the {secret} secret set?)\"\n  cat \"$RUNNER_TEMP/model-proxy.log\"\n  exit 1\nfi\necho \"MODEL_PROXY_PORT=$(cat \"$port_file\")\" >>\"$GITHUB_ENV\"",
        MODEL_PROXY_PY
    );
    format!(
        "{pad}- name: Keep the model's credential with the runner\n{condition}{pad}  env:\n{pad}    {variable}: \"${{{{ secrets.{secret} }}}}\"\n{pad}  run: |\n{}",
        indent(&run, n + 4)
    )
}

/// The command line that runs the Claude CLI as the model's user through the proxy,
/// holding the dummy token, with the defence-in-depth environment; `flags` follow `-p`.
pub(super) fn claude_command(flags: &str) -> String {
    format!(
        "sudo --preserve-env=CLAUDE_CODE_OAUTH_TOKEN,PROMPT,SCHEMA -u {MODEL_USER} -H -- env \\\n  ANTHROPIC_BASE_URL=\"http://127.0.0.1:$MODEL_PROXY_PORT\" CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1 \\\n  CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 \\\n  sh -c 'cd /home/{MODEL_USER}/work && exec claude -p \"$PROMPT\" {flags}'"
    )
}

/// What every Claude run denies besides its own rules: /proc for the file tools, and
/// git's options that write files (security review of #1084).
pub(super) const CLAUDE_DENIED: &str =
    "Read(//proc/**),Grep(//proc/**),Glob(//proc/**),Bash(git * --output*),Bash(git * -o *)";

/// The step that installs the pinned Claude Code CLI as the runner, before the model.
pub(super) fn claude_install(pins: &PinTable, n: usize, condition: &str) -> Result<String> {
    let pad = " ".repeat(n);
    let version = &pins.tool("claude-code")?.version;
    Ok(format!(
        "{pad}- name: Install Claude Code {version}\n{condition}{pad}  run: sudo npm install -g --no-fund --no-audit \"@anthropic-ai/claude-code@{version}\""
    ))
}

/// The actor checks of `claude-code-action`, kept for the CLI, letting `bot` past.
pub(super) fn claude_actor_check(bot: &str, n: usize, condition: &str) -> String {
    let pad = " ".repeat(n);
    format!(
        "{pad}- name: Check the actor as the Claude action did\n{condition}{pad}  env:\n{pad}    ACTOR: \"${{{{ github.actor }}}}\"\n{pad}    ALLOWED_BOT: \"{bot}\"\n{pad}    GH_REPO: \"${{{{ github.repository }}}}\"\n{pad}    GH_TOKEN: \"${{{{ github.token }}}}\"\n{pad}  run: |\n{}",
        indent(ACTOR_CHECK_SH, n + 4)
    )
}

/// The Claude reviewer: the CLI as the model's user through the proxy, its JSON
/// answer's `structured_output` as the step output the job's `verdict` reads; its
/// output stays between `::stop-commands::` markers.
fn claude_review(reviewer: &Reviewer, facts: &Confirmed, prompt: &str) -> String {
    let schema = SCHEMA.trim_end();
    let turns = facts
        .turn_limit
        .map(|flag| format!("{flag} {MAX_TURNS} "))
        .unwrap_or_default();
    let flags = format!(
        "--output-format json {turns}--allowedTools \"{CLAUDE_TOOLS}\" --disallowedTools \"{CLAUDE_DENIED}\" {} \"$SCHEMA\"",
        facts.schema
    );
    let run = format!(
        "set -euo pipefail\nresume=\"model-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \\n')\"\necho \"::stop-commands::$resume\"\nstatus=0\n# The runner, not the model's user, writes the answer's file.\n# shellcheck disable=SC2024\n{} \\\n  >\"$RUNNER_TEMP/claude-review.json\" || status=$?\necho \"::$resume::\"\nif [ \"$status\" != 0 ]; then\n  # Why it failed, never the model's text.\n  jq -r '\"claude: \\(.terminal_reason // \"no result\") \\(.api_error_status // \"\")\"' \"$RUNNER_TEMP/claude-review.json\" || true\n  exit \"$status\"\nfi\nverdict=$(jq -c '.{} // empty' \"$RUNNER_TEMP/claude-review.json\")\ndelimiter=\"verdict-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \\n')\"\nprintf '{}<<%s\\n%s\\n%s\\n' \"$delimiter\" \"$verdict\" \"$delimiter\" >>\"$GITHUB_OUTPUT\"",
        claude_command(&flags),
        facts.findings_output,
        facts.findings_output
    );
    format!(
        "  - id: review\n    name: Review with {}\n    if: github.event_name == 'pull_request'\n    env:\n      CLAUDE_CODE_OAUTH_TOKEN: {MODEL_DUMMY_TOKEN}\n      PROMPT: |\n{}\n      SCHEMA: '{schema}'\n    run: |\n{}",
        reviewer.family,
        indent(prompt, 8),
        indent(&run, 6)
    )
}

/// OpenCode's switches the DeepSeek reviewer runs with: the checkout's own
/// configuration and every feature that reaches the network or loads more code off.
const OPENCODE_FLAGS: [&str; 7] = [
    "OPENCODE_DISABLE_PROJECT_CONFIG",
    "OPENCODE_DISABLE_MODELS_FETCH",
    "OPENCODE_DISABLE_AUTOUPDATE",
    "OPENCODE_DISABLE_LSP_DOWNLOAD",
    "OPENCODE_DISABLE_DEFAULT_PLUGINS",
    "OPENCODE_DISABLE_CLAUDE_CODE",
    "OPENCODE_DISABLE_EXTERNAL_SKILLS",
];

/// The verdict's schema as the job writes it for the reviewer (the description step):
/// the DeepSeek proxy lets `response_format` through only around it, and the verdict
/// step's structured request carries it (#1144).
const VERDICT_SCHEMA_FILE: &str = "$RUNNER_TEMP/cross-review/schema.json";

/// The placeholder the review step replaces with the proxy's base URL at run time.
const PROXY_BASE_URL: &str = "MODEL_PROXY_BASE_URL";

/// The OpenCode configuration of the DeepSeek reviewer, on one line: one
/// OpenAI-compatible provider at the proxy with a dummy key, the one model, and a
/// `review` agent with the turn cap and read-only permissions (decision "The
/// DeepSeek judge", point 5).
pub fn opencode_config() -> String {
    let permission = json!({
        "*": "deny",
        "read": "allow",
        "grep": "allow",
        "glob": "allow",
        "list": "allow",
        "bash": {"*": "deny", "git diff *": "allow", "git log *": "allow", "git show *": "allow"},
        // The pull request's description is in the context directory; nothing else
        // outside the checkout is read (#1144: a review that could not read it
        // stopped without a verdict). OpenCode asks for `<dir>/*`.
        // #1223: and the output OpenCode cut at 2000 lines or 50 KB, which it saves
        // under its data directory and tells the model to read with offset and limit
        // (`packages/opencode/src/tool/truncate.ts` at v1.19.5). OpenCode allows that
        // directory by default, but the last matching rule wins and `*` came later.
        "external_directory": {
            "*": "deny",
            format!("/home/{MODEL_USER}/context/*"): "allow",
            format!("/home/{MODEL_USER}/.local/share/opencode/tool-output/*"): "allow",
        },
        "webfetch": "deny",
        "websearch": "deny",
        "edit": "deny",
        "task": "deny",
    });
    let model = format!("deepinfra/{DEEPSEEK_MODEL}");
    json!({
        "$schema": "https://opencode.ai/config.json",
        "provider": {"deepinfra": {
            "npm": "@ai-sdk/openai-compatible",
            "name": "DeepInfra through model-proxy",
            "options": {"baseURL": PROXY_BASE_URL, "apiKey": "{env:DEEPINFRA_API_KEY}"},
            "models": {DEEPSEEK_MODEL: {"name": "DeepSeek V4 Pro"}},
        }},
        "enabled_providers": ["deepinfra"],
        "model": model,
        "small_model": model,
        "share": "disabled",
        "autoupdate": false,
        "snapshot": false,
        "permission": permission,
        "agent": {"review": {
            "mode": "primary",
            "description": "cross-review: read the diff, answer with the verdict",
            "steps": MAX_TURNS,
            "permission": permission,
        }},
    })
    .to_string()
}

/// The step that installs the pinned OpenCode CLI as the runner, before the model.
fn opencode_install(pins: &PinTable, n: usize, condition: &str) -> Result<String> {
    let pad = " ".repeat(n);
    let version = &pins.tool("opencode")?.version;
    Ok(format!(
        "{pad}- name: Install OpenCode {version}\n{condition}{pad}  run: sudo npm install -g --no-fund --no-audit \"opencode-ai@{version}\""
    ))
}

/// The step that installs the pinned ripgrep for OpenCode's `grep` and `glob` (#1301),
/// as the runner, before the model. OpenCode 1.19.5 takes `rg` from `PATH`, else
/// downloads ripgrep 15.1.0 from GitHub (packages/core/src/ripgrep/binary.ts at
/// v1.19.5), which the model's user cannot reach; so both tools failed on every
/// review. `install-tool.sh` checks the archive against the pin table's digest, and
/// the binary goes to `/usr/local/bin`, on `sudo`'s `secure_path`, where the model's
/// user finds it.
fn ripgrep_install(pins: &PinTable, n: usize, condition: &str) -> Result<String> {
    let pad = " ".repeat(n);
    let version = &pins.tool("ripgrep")?.version;
    let mut env = pins.tool_binary("ripgrep")?;
    env.sort();
    let env: String = env
        .iter()
        .map(|(key, value)| {
            format!(
                "{pad}    {key}: {}\n",
                serde_json::Value::from(value.as_str())
            )
        })
        .collect();
    let run = format!(
        "{}sudo install -m 0755 \"${{RUNNER_TEMP}}/brakes-bin/rg\" /usr/local/bin/rg\n/usr/local/bin/rg --version\n",
        crate::modules::security::INSTALL_TOOL
    );
    Ok(format!(
        "{pad}- name: Install ripgrep {version} for OpenCode\n{condition}{pad}  env:\n{env}{pad}  run: |\n{}",
        indent(&run, n + 4)
    ))
}

/// The DeepSeek reviewer: OpenCode as the model's user through the proxy, with that
/// user's own home and XDG directories (the runner's `XDG_CONFIG_HOME` would otherwise
/// reach it: EACCES on `/home/runner/.config/opencode`, real run of #1137), and a
/// step budget the runner counts from the change (`opencode-budget.sh`, #1240); its
/// last answer, checked against the schema (`opencode-verdict.sh`), is the step output
/// `verdict`; its output stays between `::stop-commands::` markers.
fn opencode_review(reviewer: &Reviewer, prompt: &str) -> String {
    let schema = SCHEMA.trim_end();
    let prompt = format!(
        "{prompt}\nThe JSON schema of the object:\n\n    {schema}\n\n{OPENCODE_ANSWER_SHAPE}\n"
    );
    let flags: String = OPENCODE_FLAGS
        .iter()
        .map(|flag| format!("      {flag}: \"1\"\n"))
        .collect();
    let preserve = ["DEEPINFRA_API_KEY", "PROMPT"]
        .into_iter()
        .chain(OPENCODE_FLAGS)
        .collect::<Vec<_>>()
        .join(",");
    let run = format!(
        "set -euo pipefail\n# The step budget follows the change (#1240), counted by the runner in its checkout.\ncat >\"$RUNNER_TEMP/opencode-budget.sh\" <<'BUDGET'\n{OPENCODE_BUDGET_SH}BUDGET\ncap=$(REPO_DIR=\"$GITHUB_WORKSPACE\" OPENCODE_STEP_FLOOR={OPENCODE_STEP_FLOOR} OPENCODE_STEP_MAX={OPENCODE_STEP_MAX} bash \"$RUNNER_TEMP/opencode-budget.sh\")\nconfig=$(jq -c --arg url \"http://127.0.0.1:$MODEL_PROXY_PORT/v1/openai\" --argjson steps \"$cap\" '.provider.deepinfra.options.baseURL = $url | .agent.review.steps = $steps' <<<\"$OPENCODE_REVIEW_CONFIG\")\nevents=\"$RUNNER_TEMP/opencode-review.jsonl\"\nresume=\"model-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \\n')\"\necho \"::stop-commands::$resume\"\nstatus=0\n# The runner, not the model's user, writes the events' file.\n# shellcheck disable=SC2024\nsudo --preserve-env={preserve} -u {MODEL_USER} -H -- env \\\n  HOME=/home/{MODEL_USER} XDG_CONFIG_HOME=/home/{MODEL_USER}/.config XDG_DATA_HOME=/home/{MODEL_USER}/.local/share \\\n  XDG_CACHE_HOME=/home/{MODEL_USER}/.cache XDG_STATE_HOME=/home/{MODEL_USER}/.local/state \\\n  OPENCODE_CONFIG_CONTENT=\"$config\" GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 \\\n  sh -c 'cd /home/{MODEL_USER}/work && exec opencode run --format json --agent review \"$PROMPT\"' \\\n  >\"$events\" || status=$?\necho \"::$resume::\"\nif [ \"$status\" != 0 ] && [ ! -s \"$events\" ]; then\n  echo \"::error::cross-review: deepseek exited $status before answering; refusing to pass\"\n  exit \"$status\"\nfi\ncat >\"$RUNNER_TEMP/opencode-verdict.sh\" <<'VERDICT'\n{OPENCODE_VERDICT_SH}VERDICT\nOPENCODE_EVENTS=\"$events\" OPENCODE_STEP_CAP=\"$cap\" VERDICT_SCHEMA_FILE=\"{VERDICT_SCHEMA_FILE}\" bash \"$RUNNER_TEMP/opencode-verdict.sh\"\nif [ \"$status\" != 0 ]; then\n  echo \"::error::cross-review: deepseek exited $status; refusing to pass\"\n  exit \"$status\"\nfi"
    );
    format!(
        "  - id: review\n    name: Review with {}\n    if: github.event_name == 'pull_request'\n    env:\n      DEEPINFRA_API_KEY: {MODEL_DUMMY_TOKEN}\n      BASE_SHA: \"${{{{ github.event.pull_request.base.sha }}}}\"\n      HEAD_SHA: \"${{{{ github.event.pull_request.head.sha }}}}\"\n{flags}      OPENCODE_REVIEW_CONFIG: '{}'\n      PROMPT: |\n{}\n    run: |\n{}",
        reviewer.family,
        opencode_config(),
        indent(&prompt, 8),
        indent(&run, 6)
    )
}

/// The two jobs for `reviewer`, blocking at `blocking` (`P0 P1` or `P0`):
/// `cross-review-model` on `runner` unless the reviewer needs a GitHub-hosted one,
/// then `cross-review`, the gate, on the answered `runner` (it runs no sandbox).
/// `cross-review-model` declares `environment` when one is answered; the gate
/// holds no secret and declares none. Refuses on an unconfirmed fact.
pub fn jobs(
    reviewer: &Reviewer,
    blocking: &str,
    runner: &str,
    environment: Option<&str>,
    pins: &PinTable,
) -> Result<Vec<CiJob>> {
    let facts = confirmed(reviewer)?;
    let model_runner = if facts.github_hosted {
        runner_label(Runner::Github)
    } else {
        runner
    };
    let prompt = render(PROMPT, &[("blocking", &blocking.replace(' ', " or "))]);
    let condition = "    if: github.event_name == 'pull_request'\n";
    let (probe, prepare, review) = if reviewer.family == "codex" {
        let with = codex_inputs(&facts, &prompt, pins)?;
        let review = format!(
            "  - id: review\n    name: Review with {}\n    if: github.event_name == 'pull_request'\n    uses: {}\n    with:\n{with}",
            reviewer.family,
            pins.action(reviewer.action)?.uses()
        );
        let prepare = model_proxy("OPENAI_API_KEY", reviewer.secret, "openai", 2, condition);
        (Some("/v1/responses"), prepare, review)
    } else if reviewer.family == "deepseek" {
        let prepare = [
            claude_actor_check(DEPENDABOT, 2, condition),
            opencode_install(pins, 2, condition)?,
            ripgrep_install(pins, 2, condition)?,
            model_proxy(
                "DEEPINFRA_API_KEY",
                reviewer.secret,
                &format!("deepinfra \"{VERDICT_SCHEMA_FILE}\""),
                2,
                condition,
            ),
        ]
        .join("\n");
        (
            Some("/v1/openai/chat/completions"),
            prepare,
            opencode_review(reviewer, &prompt),
        )
    } else {
        let prepare = [
            claude_actor_check(DEPENDABOT, 2, condition),
            bwrap_prepare(2, condition),
            claude_install(pins, 2, condition)?,
            model_proxy(
                "CLAUDE_CODE_OAUTH_TOKEN",
                reviewer.secret,
                "anthropic",
                2,
                condition,
            ),
        ]
        .join("\n");
        (
            Some("/v1/messages"),
            prepare,
            claude_review(reviewer, &facts, &prompt),
        )
    };
    // `contents: read`, plus the one read scope the action's preparation needs,
    // when the vendor facts record one; never a write scope.
    let permissions = match facts.extra_read_scope {
        Some(scope) => format!("  contents: read\n  {scope}: read"),
        None => "  contents: read".to_owned(),
    };
    let model = render(
        MODEL_JOB,
        &[
            ("runner", model_runner),
            ("timeout", &TIMEOUT_MINUTES.to_string()),
            (
                "environment",
                &environment.map_or(String::new(), |e| format!("environment: {e}\n")),
            ),
            ("permissions", &permissions),
            ("output", facts.findings_output),
            ("checkout", &pins.action("actions/checkout")?.uses()),
            ("egress_env", &egress_env(false, None, 6)),
            ("check_env", &egress_env(true, probe, 6)),
            ("egress", &indent(EGRESS_SH, 6)),
            ("restore", &indent(RESTORE_SH, 6)),
            ("prepare", &prepare),
            ("model_user", MODEL_USER),
            ("schema", SCHEMA.trim_end()),
            ("copy", &indent(MODEL_COPY_SH, 6)),
            ("review", &review),
        ],
    );
    let gate = render(
        GATE_JOB,
        &[
            ("runner", runner),
            ("timeout", &GATE_TIMEOUT_MINUTES.to_string()),
            ("blocking", blocking),
            ("family", reviewer.family),
            ("max_bytes", &VERDICT_MAX_BYTES.to_string()),
            ("gate", &indent(GATE_SH, 6)),
        ],
    );
    let job = |id: &str, yaml: String| CiJob {
        id: id.to_owned(),
        yaml,
        skippable_under: vec![CiTier::Docs],
        app: None,
    };
    Ok(vec![
        job(CROSS_REVIEW_MODEL, model),
        job(CROSS_REVIEW, gate),
    ])
}

/// The jobs this module contributes: `cross-review-model` and `cross-review`
/// unless `review_family` is `none`.
pub fn contributed(cx: &Context<'_>) -> Result<Vec<CiJob>> {
    let Some(reviewer) = reviewer(cx.answers) else {
        return Ok(Vec::new());
    };
    let pins = PinTable::embedded()?;
    jobs(
        reviewer,
        blocking(cx.answers),
        answered_runner(cx)?,
        environment(cx.answers)?,
        &pins,
    )
}

/// The runner label `ci-baseline`'s `runner` answer names (the configured runner by default).
pub fn answered_runner(cx: &Context<'_>) -> Result<&'static str> {
    let answer = cx
        .answers_of(CI_BASELINE)?
        .get("runner")
        .and_then(Value::as_str);
    let runner = Runner::available()
        .into_iter()
        .find(|r| Some(r.as_str()) == answer)
        .unwrap_or_else(Runner::default_choice);
    Ok(runner_label(runner))
}

/// One step per store the reviewer's secret must be in, each probed by name only
/// (host-adapter's `secret-present`): the Actions secrets, for pull requests of
/// people and agents (the repository's, or `review_environment`'s since #1320),
/// and Dependabot's, which Dependabot's own pull requests read and nothing else
/// (owner decision through the coordinator on #957). None without a reviewer.
/// Each step names both commands, so either explains the pair.
pub fn steps(answers: &Answers) -> Vec<ManualStep> {
    let Some(reviewer) = reviewer(answers) else {
        return Vec::new();
    };
    let secret = reviewer.secret;
    // An invalid name refuses the plan in `render`; here it is only text.
    let environment = answers.get("review_environment").and_then(Value::as_str);
    let (actions_scope, actions_store, actions_command) = match environment {
        Some(e) => (
            format!("environment:{e}"),
            format!("{e} environment's"),
            format!("gh secret set {secret} --env {e} --repo <owner>/<repo> (environment {e})"),
        ),
        None => (
            "repository".to_owned(),
            "Actions".to_owned(),
            format!("gh secret set {secret} --repo <owner>/<repo> (Actions)"),
        ),
    };
    let instructions = format!(
        "{actions_command} and gh secret set {secret} --app dependabot --repo <owner>/<repo> (Dependabot, for Dependabot's pull requests): the {} reviewer's credential, in both stores; the installer never reads it. Until it exists, cross-review fails with the action's own missing-secret message.",
        reviewer.family
    );
    [
        ("review-secret-present", actions_scope, actions_store),
        (
            "review-dependabot-secret-present",
            "dependabot".to_owned(),
            "Dependabot".to_owned(),
        ),
    ]
    .into_iter()
    .map(|(id, scope, store)| ManualStep {
        id: id.to_owned(),
        title: format!("Create the {secret} secret for cross-review in the {store} secrets"),
        owner: Owner::Owner,
        instructions: instructions.clone(),
        probe: Probe::Remote {
            id: "secret-present".to_owned(),
            args: [
                ("name".to_owned(), json!(secret)),
                ("scope".to_owned(), json!(scope)),
            ]
            .into(),
        },
        after: None,
    })
    .collect()
}
