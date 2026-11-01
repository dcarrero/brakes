//! The vendor facts of the two reviewer actions `cross-review` runs (#940;
//! SPEC-agent-guardrails.md, "Cross-family review as a required check"). The spec
//! fixes the contract (the other family, the exit code as the gate, caps, the secret
//! as a name); the vendor strings live here, each read from the vendor's own
//! documentation at the pinned commit on the date recorded, with its sources. The
//! commit SHAs themselves are the shared pin table's (`templates/stack-packs/pins.json`),
//! as is the Codex CLI version (`tools.codex`). A fact not confirmed is
//! [`Fact::Unconfirmed`] and refuses the render (`review::confirmed`), never a guess.

/// One vendor fact: read in the vendor's documentation, or not yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fact<T> {
    Confirmed(T),
    Unconfirmed,
}

/// What `cross-review` needs to know about a reviewer's action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reviewer {
    /// The `review_family` answer that selects it.
    pub family: &'static str,
    /// Its key in the pin table: the action's repository (pinned by SHA), or, for a
    /// CLI the job installs itself, the tool (pinned by exact version).
    pub action: &'static str,
    /// The repository secret the job reads; a name, never a value.
    pub secret: &'static str,
    /// The input that takes the secret.
    pub secret_input: Fact<&'static str>,
    /// The input that takes the prompt text.
    pub prompt_input: Fact<&'static str>,
    /// The step output that carries the reviewer's JSON answer.
    pub findings_output: Fact<&'static str>,
    /// The input that lets named bots past the action's write-access check.
    pub bot_allowlist: Fact<&'static str>,
    /// How the JSON schema of the answer is passed: an input name, or a CLI flag.
    pub schema: Fact<&'static str>,
    /// The turn-limit flag, or `None` when the action has none (then
    /// `timeout-minutes` is the only cap the job can render).
    pub turn_limit: Fact<Option<&'static str>>,
    /// Whether the action fails its step on findings by itself. Neither does,
    /// so the job's gate step parses the answer.
    pub fails_on_findings: Fact<bool>,
    /// Whether its sandbox needs a GitHub-hosted runner.
    pub github_hosted: Fact<bool>,
    /// The read scope the action needs beyond `contents: read` to prepare in
    /// `cross-review-model`, or `None` when none ("CI hardening for agent
    /// workflows", point 1: `pull-requests: read` only if the action cannot prepare
    /// without it, with the failing run as evidence).
    pub extra_read_scope: Fact<Option<&'static str>>,
    /// Where the facts were read.
    pub sources: &'static [&'static str],
    /// When they were read, `YYYY-MM-DD`.
    pub verified: &'static str,
}

/// `openai/codex-action` v1.13 (commit of 2026-10-05), read 2026-10-29.
/// - `openai-api-key`, `prompt`, `output-schema-file` (a schema file's path), output
///   `final-message`, `codex-version`, `permission-profile` (`:read-only`, Codex
///   CLI 0.138.0 or later): action.yml and README "Inputs"/"Outputs".
/// - `allow-bot-users`: bot usernames past the write-access check, `*` not
///   supported, the `[bot]` suffix optional (action.yml).
/// - No turn or budget input; `codex exec` has no turn limit (the CLI's sources
///   have none), so `timeout-minutes` is the cap.
/// - `codex exec` exits non-zero on failure, not on findings.
/// - With `safety-strategy: unprivileged-user` and `codex-user`, the inline
///   `output-schema` cannot work: the action creates its temporary directory as
///   that user (mode 0700, `sudo -u <user> mktemp -d`) and then writes the schema
///   into it as the runner (`src/runCodexExec.ts`, `resolveOutputSchema`); a real
///   run failed with `EACCES` (2026-10-30, #971). `output-schema-file` names a file
///   the user reads instead; the final message is read back as that user
///   (`finalizeExecution`).
/// - The step "Enable Linux user namespaces for bubblewrap" runs only when
///   `runner.environment == 'github-hosted'`; on other runners the sandbox needs
///   them enabled beforehand (README "Operating system support").
/// - Preparation reads GitHub once, in "Check repository write access" with
///   `github.token` (action.yml; `allow-users`, `allow-bots`, `allow-bot-users`
///   gate it): a collaborator-permission read, which `metadata: read` serves and
///   every job token has. No `github-token` input exists. So `contents: read`
///   prepares it; no failing run was observed (read 2026-10-29; the real run of
///   the two-job workflow on a personal repository is pending the owner's secret).
pub const CODEX: Reviewer = Reviewer {
    family: "codex",
    action: "openai/codex-action",
    secret: "OPENAI_API_KEY",
    secret_input: Fact::Confirmed("openai-api-key"),
    prompt_input: Fact::Confirmed("prompt"),
    findings_output: Fact::Confirmed("final-message"),
    bot_allowlist: Fact::Confirmed("allow-bot-users"),
    schema: Fact::Confirmed("output-schema-file"),
    turn_limit: Fact::Confirmed(None),
    fails_on_findings: Fact::Confirmed(false),
    github_hosted: Fact::Confirmed(true),
    extra_read_scope: Fact::Confirmed(None),
    sources: &[
        "https://github.com/openai/codex-action/blob/bdf19a4a223ec2549a3e2274a0cf61556bc07675/action.yml",
        "https://github.com/openai/codex-action/blob/bdf19a4a223ec2549a3e2274a0cf61556bc07675/README.md",
        "https://github.com/openai/codex-action/blob/bdf19a4a223ec2549a3e2274a0cf61556bc07675/src/runCodexExec.ts",
        "https://developers.openai.com/codex/permissions",
    ],
    verified: "2026-10-29",
};

/// `anthropics/claude-code-action` v1.0.264 (commit of 2026-10-27), read 2026-10-29.
/// - `claude_code_oauth_token`, `prompt`, `claude_args`; `--json-schema` in
///   `claude_args` fills the output `structured_output`: action.yml, docs/usage.md.
/// - `--max-turns` replaces the deprecated `max_turns` input (docs/usage.md);
///   `--max-turns` and `--max-budget-usd` are print-mode flags of the CLI reference.
/// - `github_token` lets the action work without the Claude GitHub App, whose OIDC
///   exchange needs `id-token: write` (docs/faq.md).
/// - `allowed_bots`: bot usernames allowed to trigger it, e.g.
///   `dependabot[bot]`; empty allows none (action.yml, docs/usage.md).
/// - The output `conclusion` reports the execution, not findings.
/// - Preparation with a `prompt` (agent mode, `src/modes/agent/index.ts`) calls
///   GitHub for `checkHumanActor` (`users.getByUsername`,
///   `src/github/validation/actor.ts`) and `checkWritePermissions`
///   (`repos.getCollaboratorPermissionLevel`, `src/github/validation/permissions.ts`),
///   creates no tracking comment, fetches no pull-request data and checks out no
///   branch; it writes the job's token into git's remote URL (`configureGitAuth`,
///   `src/github/operations/git-config.ts`), which is why that token must not
///   write. Both reads are served by `metadata: read`, which every job token has,
///   so `contents: read` prepares it; no failing run was observed (read 2026-10-29;
///   the real run on a personal repository is pending the owner's secret).
/// - `docs/security.md` restores `.claude/`, `.mcp.json`, `.claude.json`,
///   `.gitmodules`, `.ripgreprc`, `CLAUDE.md`, `CLAUDE.local.md` and `.husky/`
///   from the base and nothing else: `AGENTS.md` is this module's to restore
///   (`cross-review-restore.sh`).
pub const CLAUDE: Reviewer = Reviewer {
    family: "claude",
    action: "anthropics/claude-code-action",
    secret: "CLAUDE_CODE_OAUTH_TOKEN",
    secret_input: Fact::Confirmed("claude_code_oauth_token"),
    prompt_input: Fact::Confirmed("prompt"),
    findings_output: Fact::Confirmed("structured_output"),
    bot_allowlist: Fact::Confirmed("allowed_bots"),
    schema: Fact::Confirmed("--json-schema"),
    turn_limit: Fact::Confirmed(Some("--max-turns")),
    fails_on_findings: Fact::Confirmed(false),
    github_hosted: Fact::Confirmed(false),
    extra_read_scope: Fact::Confirmed(None),
    sources: &[
        "https://github.com/anthropics/claude-code-action/blob/d70510b174a1244958df0b03166a54912811f3e6/action.yml",
        "https://github.com/anthropics/claude-code-action/blob/d70510b174a1244958df0b03166a54912811f3e6/docs/usage.md",
        "https://github.com/anthropics/claude-code-action/blob/d70510b174a1244958df0b03166a54912811f3e6/docs/faq.md",
        "https://github.com/anthropics/claude-code-action/blob/d70510b174a1244958df0b03166a54912811f3e6/docs/security.md",
        "https://github.com/anthropics/claude-code-action/blob/d70510b174a1244958df0b03166a54912811f3e6/src/modes/agent/index.ts",
        "https://github.com/anthropics/claude-code-action/blob/d70510b174a1244958df0b03166a54912811f3e6/src/github/validation/actor.ts",
        "https://github.com/anthropics/claude-code-action/blob/d70510b174a1244958df0b03166a54912811f3e6/src/github/validation/permissions.ts",
        "https://code.claude.com/docs/en/cli-reference",
    ],
    verified: "2026-10-29",
};

/// DeepSeek V4 Pro on DeepInfra, run by the OpenCode CLI `opencode-ai` 1.19.5 (tag
/// `v1.19.5`, commit `810c0eba1a7348036f8bdf61e6632d0c36c6876c`), read 2026-10-30
/// (#1134; decision "The DeepSeek judge"). No action: the job installs the CLI.
/// - The key is the provider's `options.apiKey` (`{env:…}`), a dummy here; the
///   provider is `@ai-sdk/openai-compatible`, bundled in the binary
///   (`packages/opencode/src/provider/provider.ts`, `BUNDLED_PROVIDERS`), its
///   `baseURL` the runner's proxy (https://opencode.ai/docs/providers/).
/// - The prompt is `opencode run`'s message; `--format json` prints one JSON event per
///   line, the answer in the `text` events' `part.text`; a failed call is an `error`
///   event and exit status 1 (https://opencode.ai/docs/cli/; measured, spike #1137,
///   CI run 41030515183).
/// - No strict structured output: the schema goes into the prompt and the job checks
///   the answer itself (`opencode-verdict.sh`); the step output is `verdict`.
/// - The turn cap is the agent's `steps` ("Maximum number of agentic iterations before
///   forcing text-only response", `packages/core/src/v1/config/agent.ts`).
/// - Its permissions deny by name (`"deny"` beats `--auto`;
///   https://opencode.ai/docs/permissions/); `OPENCODE_DISABLE_PROJECT_CONFIG` skips the
///   checkout's `opencode.json`, `.opencode/` and instruction files
///   (`packages/opencode/src/config/config.ts`, `config/paths.ts`,
///   `session/instruction.ts`); `OPENCODE_DISABLE_MODELS_FETCH` keeps it on the bundled
///   models snapshot (`packages/core/src/models-dev.ts`).
/// - It never fails on findings, needs no GitHub token and no hosted runner; the actor
///   check Claude's path keeps lets Dependabot past.
/// - DeepInfra: base `https://api.deepinfra.com/v1/openai`, `Authorization: Bearer`,
///   the one chat path `/chat/completions` (https://docs.deepinfra.com/chat/overview);
///   model `deepseek-ai/DeepSeek-V4-Pro` (https://deepinfra.com/deepseek-ai/DeepSeek-V4-Pro).
pub const DEEPSEEK: Reviewer = Reviewer {
    family: "deepseek",
    action: "opencode",
    secret: "DEEPINFRA_API_KEY",
    secret_input: Fact::Confirmed("provider.deepinfra.options.apiKey"),
    prompt_input: Fact::Confirmed("opencode run"),
    findings_output: Fact::Confirmed("verdict"),
    bot_allowlist: Fact::Confirmed("ALLOWED_BOT"),
    schema: Fact::Confirmed("prompt"),
    turn_limit: Fact::Confirmed(Some("steps")),
    fails_on_findings: Fact::Confirmed(false),
    github_hosted: Fact::Confirmed(false),
    extra_read_scope: Fact::Confirmed(None),
    sources: &[
        "https://opencode.ai/docs/cli/",
        "https://opencode.ai/docs/providers/",
        "https://opencode.ai/docs/permissions/",
        "https://github.com/anomalyco/opencode/blob/810c0eba1a7348036f8bdf61e6632d0c36c6876c/packages/core/src/v1/config/agent.ts",
        "https://github.com/anomalyco/opencode/blob/810c0eba1a7348036f8bdf61e6632d0c36c6876c/packages/opencode/src/config/config.ts",
        "https://docs.deepinfra.com/chat/overview",
        "https://deepinfra.com/deepseek-ai/DeepSeek-V4-Pro",
    ],
    verified: "2026-10-30",
};

/// The model the DeepSeek judge uses, and the only one the proxy lets it spend the key on.
pub const DEEPSEEK_MODEL: &str = "deepseek-ai/DeepSeek-V4-Pro";

/// The reviewers, in the order of the `review_family` answer.
pub const REVIEWERS: [Reviewer; 3] = [CODEX, CLAUDE, DEEPSEEK];

/// GitHub's facts the two-job shape rests on, read 2026-10-29 in "Workflow syntax
/// for GitHub Actions", `jobs.<job_id>.outputs`: "Outputs can be a maximum of 1 MB
/// per job", and "Outputs containing secrets are redacted on the runner and not
/// sent to GitHub Actions", so a verdict that quotes the reviewer's secret reaches
/// the gate empty and the gate fails closed. `cache-mode` (`read`, `write`,
/// `write-only`, `none`; workflow or job level) is "enforced with scoped cache
/// tokens" in the dependency-caching reference.
pub const GITHUB_SOURCES: &[&str] = &[
    "https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax",
    "https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching",
];

/// What the model's own user may reach (#971): nothing but loopback. Measured
/// 2026-10-29 and 2026-10-30 on `ubuntu-24.04` (image 20261026.354.1) and
/// a self-hosted Linux runner (ubuntu24 20261021.1.0), unconfined and then confined to
/// `agent-model` (draft PRs #1075 and #1089; CI runs 40970362279, 40973339266
/// and 40978736006).
/// - The installs (npm, the Claude Code and Codex CLIs, `apt`) run as the runner,
///   outside the limit.
/// - Codex, run by `openai/codex-action` with `safety-strategy: unprivileged-user`,
///   reaches the OpenAI API through the action's Responses API proxy, which runs as
///   the runner; Codex's own attempts at `chatgpt.com` were refused without stopping
///   it. Since #1095 that proxy holds a dummy key and its upstream
///   (`responses-api-endpoint`) is `model-proxy.py` in OpenAI mode: the action's
///   proxy accepts a loopback `http://127.0.0.1` upstream and already refuses every
///   request but `POST /v1/responses`; Codex 0.165.0 sent one shape, with no query, no
///   `OpenAI-Beta`, the body keys of `OPENAI_KEYS` in `model-proxy.py` and no tools
///   (draft PR #1096, CI run 40984402028;
///   https://github.com/openai/codex/blob/main/codex-rs/responses-api-proxy/README.md).
/// - The Claude Code CLI 2.1.312 with a dummy token and `ANTHROPIC_BASE_URL` at the
///   runner's loopback proxy (`model-proxy.py`) sent only `POST /v1/messages`, which
///   the proxy forwarded with the real credential (the fake upstream key drew a 401).
///   Documented in "Other LLM gateways" (read 2026-10-30): with only the base URL
///   set, "requests still route through the gateway" under the subscription login;
///   https://code.claude.com/docs/en/llm-gateway and
///   https://code.claude.com/docs/en/llm-gateway-protocol.
/// - Neither image has `ipset`. Both have passwordless `sudo`, `iptables`/`ip6tables`
///   1.8.10 (nf_tables), `dig`, `curl`, `setfacl`, `python3` 3.12, `resolvectl`,
///   systemd-resolved and D-Bus, and `apparmor_parser` with the userns restriction
///   on; a profile for `/usr/bin/bwrap` lets bubblewrap create user namespaces for
///   `agent-model` with that restriction left on.
pub const MODEL_EGRESS_HOSTS: &[&str] = &[];
/// The identity `anthropics/claude-code-action` commits with by default (`bot_name`
/// and `bot_id` in action.yml at the pin, `src/github/operations/git-config.ts`):
/// kept for the Claude Code CLI in `implement`.
pub const CLAUDE_GIT_NAME: &str = "claude[bot]";
pub const CLAUDE_GIT_EMAIL: &str = "41898282+claude[bot]@users.noreply.github.com";
