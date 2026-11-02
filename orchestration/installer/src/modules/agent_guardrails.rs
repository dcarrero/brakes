//! agent-guardrails: the deterministic layer around agents (SPEC-agent-guardrails.md).
//! The module (#739) asks its questions and renders four `managed` paths: the
//! Stop→verify hook (#735), the settings fragment the project merges into
//! `.claude/settings.json`, the guide and the MCP allowlist (#743); and three
//! `seed` paths (#743): `.mcp.json`, `.worktreeinclude` and
//! `docs/agent-setup/technical-debt.md`; and the agent environment files the
//! `agent_environments` answer names (#749, `environments`). Since #748 the
//! same object is the module's `managed-entries` of `.claude/settings.json`: the
//! installer registers the deny rules, the Stop entry and, where `merge-guard`
//! is active, its `PreToolUse` entry, and owns nothing else in that file;
//! `doctor` warns when a hand-edit drops them (`doctor`, #744).
//!
//! In `modules::all()` since #744: like every module, it is active only when
//! recorded in the lock or requested with `install --module`, and the plan
//! refuses it unless `repo-baseline` and `ci-baseline` are active too.
//!
//! The installer renders the hook and never executes it: the hook runs the
//! project's `verify` at agent time (docs/decisions.md, 2026-10-28, points 1 and 6).
//! `.claude/settings.json` stays the project's but for those entries (#442,
//! amended by "Installer owns the entries it adds to `.claude/settings.json`:
//! ownership class `managed-entries`", 2026-10-29).
use crate::{
    Result,
    engine::{
        CiJob, Context, Module, Rendered,
        answers::{Answers, Kind, Question, Schema, When},
        lock::Ownership,
        manual::ManualStep,
    },
    modules::{ci_baseline, merge_guard},
    refuse,
};
use serde_json::{Value, json};

pub mod audit;
pub mod doctor;
pub mod environments;
pub mod identity;
pub mod injection;
pub mod mcp;
pub mod pins;
pub mod review;
pub mod unattended;

pub const AGENT_GUARDRAILS: &str = "agent-guardrails";
pub const AGENT_GUARDRAILS_VERSION: &str = "1.0.0";

/// The user every model job runs its model as: no sudo, its own egress limit and its
/// own copy of the checkout (SPEC-agent-guardrails.md, "Egress allowlist", as built
/// #971).
pub const MODEL_USER: &str = "agent-model";
/// The egress step's shell, embedded verbatim: creates `MODEL_USER`, closes that
/// uid's outbound traffic but for the job's hosts, and proves it.
pub const EGRESS_SH: &str = include_str!("../../../../templates/agent-guardrails/egress.sh");
/// The step that gives the model its own copy of the checkout and its context.
pub const MODEL_COPY_SH: &str =
    include_str!("../../../../templates/agent-guardrails/model-copy.sh");
/// The loopback proxy that holds the Claude credential as the runner (#971).
pub const MODEL_PROXY_PY: &str =
    include_str!("../../../../templates/agent-guardrails/model-proxy.py");
/// Bubblewrap for the scrub, through an AppArmor profile for bwrap alone.
pub const BWRAP_PREPARE_SH: &str =
    include_str!("../../../../templates/agent-guardrails/bwrap-prepare.sh");
/// The token the Claude CLI holds: not a credential; the proxy supplies the real one.
pub const MODEL_DUMMY_TOKEN: &str = "agent-model-holds-no-credential";
/// The actor checks `anthropics/claude-code-action` made, kept for the Claude CLI.
pub const ACTOR_CHECK_SH: &str =
    include_str!("../../../../templates/agent-guardrails/actor-check.sh");

/// The hook as versioned under `templates/agent-guardrails/`; `{{verify}}` and
/// `{{verify_timeout}}` are its only placeholders.
pub const STOP_VERIFY_SH: &str =
    include_str!("../../../../templates/agent-guardrails/stop_verify.sh");
/// Where the rendered hook lives in a target repository.
pub const STOP_VERIFY_PATH: &str = ".claude/hooks/stop_verify.sh";
/// The readable statement of the entries the installer registers (#748).
pub const SETTINGS_FRAGMENT_PATH: &str = ".agent-setup/claude-settings.json";
/// The host's settings file: the installer owns only the entries it adds there.
pub const SETTINGS_PATH: &str = ".claude/settings.json";
pub const GUIDE: &str = include_str!("../../../../templates/agent-guardrails/guardrails.md");
pub const GUIDE_PATH: &str = "docs/agent-setup/guardrails.md";
/// Policy, rendered from answers: changes go through `configure` (spec decision 3).
pub const MCP_ALLOWLIST_PATH: &str = ".agent-setup/mcp-allowlist.json";
/// Seeds: written once where absent; afterwards the project's.
pub const MCP_JSON_PATH: &str = ".mcp.json";
/// OpenCode's project configuration: the installer owns only its deny patterns (#751).
pub const OPENCODE_JSON_PATH: &str = "opencode.json";
pub const WORKTREEINCLUDE_PATH: &str = ".worktreeinclude";
pub const WORKTREEINCLUDE: &str =
    include_str!("../../../../templates/agent-guardrails/worktreeinclude");
pub const TECHNICAL_DEBT_PATH: &str = "docs/agent-setup/technical-debt.md";
/// The `AGENTS.md` line that points agents at [`TECHNICAL_DEBT_PATH`]. With
/// `setup-core` compiled in it is part of that module's managed block; without
/// it this module renders the line in a managed block of its own (spec
/// SPEC-product-boundary.md, Decided (coordinator) 6).
pub const TECHNICAL_DEBT_LINE: &str = "Before imitating neighbouring code, read `docs/agent-setup/technical-debt.md`: it lists the patterns not to copy.";
pub const TECHNICAL_DEBT: &str =
    include_str!("../../../../templates/agent-guardrails/technical-debt.md");

/// Every deny entry is a non-negotiable, not a preference: the list stays small.
/// Twenty-one defaults in P2/P3 (twenty in P1) leave room for two `secret_paths`
/// entries (#965; 25 since the held-out `Read` entry, #982).
pub const MAX_DENY_RULES: usize = 25;
/// The installer's lock: never edited by an agent, in every profile.
const LOCK_PATH: &str = ".agent-setup/lock.json";
/// Stands for ci-baseline's held-out directory in `protected_paths` entries, as
/// the spec writes it (#945).
const HELDOUT_PLACEHOLDER: &str = "<heldout_dir>";
/// `.env.example` and `.env.template` stay readable: agents read them to learn
/// variable names, and a deny rule has no exception syntax (spec, Open Questions 1).
const SECRET_READS: &[&str] = &[
    ".env",
    ".env.local",
    ".env.development",
    ".env.production",
    ".env.test",
    ".env.staging",
    "secrets/**",
    "*.pem",
    "*.key",
    "*.p12",
    "id_rsa*",
    "id_ed25519*",
    "local.properties",
    "keystore.properties",
];
const SECRET_EDITS: &[&str] = &[".env", ".env.local", "secrets/**"];
/// Where every deny rule is anchored (#1309 for the secrets, #1314 for the lock,
/// the protected paths, `spec_dir` and the held-out directory): `//` is the
/// filesystem root, so `//**/<path>` holds for any path the session can reach,
/// the project and a git worktree beside it alike, where `./<path>` holds only
/// under the session's directory
/// (https://code.claude.com/docs/en/permissions#how-path-patterns-match).
/// A `Read` deny also blocks Edit and Write on the path, and `Write(path)` rules
/// never match, so no `Write` rule is rendered.
const ANYWHERE: &str = "//**/";
const AGENT_ENVIRONMENTS: &[&str] = &["copilot", "codex", "devcontainer"];

/// Replaces every `{{key}}` of `pairs` in `template`, verbatim and in order; pure.
/// Values are not escaped: the hook template reads `verify` through a quoted heredoc,
/// so any command is baked in as written.
pub fn render(template: &str, pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .fold(template.to_owned(), |text, (key, value)| {
            text.replace(&format!("{{{{{key}}}}}"), value)
        })
}

/// The Stop hook with `verify_command` baked in and `timeout_secs` as its own
/// timeout. `None` (the project declared no `verify`) renders the branch that
/// exits 0 with a `systemMessage` and runs nothing.
pub fn render_stop_hook(verify_command: Option<&str>, timeout_secs: u64) -> String {
    render(
        STOP_VERIFY_SH,
        &[
            ("verify", verify_command.unwrap_or("")),
            ("verify_timeout", &timeout_secs.to_string()),
        ],
    )
}

/// The module. The maturity profile is the engine's (`install --profile`,
/// recorded with the answers): it resolves the per-profile defaults before
/// `render` and `manual_steps` read the answers (#872).
#[derive(Clone, Copy, Debug, Default)]
pub struct AgentGuardrails;

/// `protected_paths` by profile: the lock and the held-out directory everywhere
/// (owner, 2026-10-29, #945); workflows too in P2 and P3 (owner, 2026-10-28, point 10).
fn protected_paths_default() -> Value {
    let heldout = format!("{HELDOUT_PLACEHOLDER}/**");
    let with_workflows = json!([LOCK_PATH, heldout, ".github/workflows/**"]);
    json!({ "P1": [LOCK_PATH, heldout], "P2": with_workflows, "P3": with_workflows })
}

/// The held-out directory: ci-baseline's `heldout_dir` answer, validated and
/// normalised as ci-baseline does, else its default `tests/heldout` (#945).
pub fn heldout_dir(cx: &Context<'_>) -> Result<String> {
    let answer = cx
        .answers_of(ci_baseline::CI_BASELINE)?
        .get("heldout_dir")
        .and_then(Value::as_str);
    ci_baseline::model::heldout_dir(answer.unwrap_or(ci_baseline::DEFAULT_HELDOUT_DIR))
}

/// The deny entries for the held-out directory, `Edit` then `Read`: the tests an
/// agent is measured against are never tests it can edit (owner, 2026-10-29) nor
/// open or search (`Read` covers Read, Grep and Glob; #982).
pub fn heldout_deny(heldout_dir: &str) -> [String; 2] {
    [
        format!("Edit({ANYWHERE}{heldout_dir}/**)"),
        format!("Read({ANYWHERE}{heldout_dir}/**)"),
    ]
}

fn question(id: &str, kind: Kind, description: &str, default: Value) -> Question {
    Question {
        description: description.to_owned(),
        default: Some(default),
        ..Question::new(id, kind)
    }
}

fn names(options: &[&str]) -> Vec<String> {
    options.iter().map(|s| (*s).to_owned()).collect()
}

/// Repository-relative paths the answers name; `..`, absolute and empty entries refuse.
fn repository_paths<'a>(answers: &'a Answers, id: &str) -> Result<Vec<&'a str>> {
    let paths: Vec<&str> = answers
        .get(id)
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    for path in &paths {
        if path.is_empty() || path.starts_with('/') || path.split('/').any(|seg| seg == "..") {
            return refuse(format!(
                "Module {AGENT_GUARDRAILS}: {id} entry `{path}` leaves the repository"
            ));
        }
    }
    Ok(paths)
}

/// The project's specification directory (`spec_dir`, optional, #986), with a
/// leading `./` and a trailing `/` dropped; validated as `protected_paths` entries are.
fn spec_dir(answers: &Answers) -> Result<Option<String>> {
    let Some(raw) = answers.get("spec_dir").and_then(Value::as_str) else {
        return Ok(None);
    };
    let dir = raw.strip_prefix("./").unwrap_or(raw).trim_end_matches('/');
    if dir.is_empty() || dir.starts_with('/') || dir.split('/').any(|seg| seg == "..") {
        return refuse(format!(
            "Module {AGENT_GUARDRAILS}: spec_dir entry `{raw}` leaves the repository"
        ));
    }
    Ok(Some(dir.to_owned()))
}

/// The deny list: the spec's secrets, the lock and the held-out directory, then
/// one `Edit` per protected path (`<heldout_dir>` replaced by `heldout_dir`), one
/// for `spec_dir` when answered, and a `Read` and an `Edit` per secret path,
/// without duplicates, in that order.
pub fn deny_rules(answers: &Answers, heldout_dir: &str) -> Result<Vec<String>> {
    let mut rules: Vec<String> = SECRET_READS
        .iter()
        .map(|p| format!("Read({ANYWHERE}{p})"))
        .collect();
    rules.extend(SECRET_EDITS.iter().map(|p| format!("Edit({ANYWHERE}{p})")));
    rules.push(format!("Edit({ANYWHERE}{LOCK_PATH})"));
    rules.extend(heldout_deny(heldout_dir));
    for path in repository_paths(answers, "protected_paths")? {
        let path = path.replace(HELDOUT_PLACEHOLDER, heldout_dir);
        rules.push(format!("Edit({ANYWHERE}{path})"));
    }
    if let Some(dir) = spec_dir(answers)? {
        rules.push(format!("Edit({ANYWHERE}{dir}/**)"));
    }
    for path in repository_paths(answers, "secret_paths")? {
        rules.push(format!("Read({ANYWHERE}{path})"));
        rules.push(format!("Edit({ANYWHERE}{path})"));
    }
    let mut unique: Vec<String> = Vec::with_capacity(rules.len());
    for rule in rules {
        if !unique.contains(&rule) {
            unique.push(rule);
        }
    }
    if unique.len() > MAX_DENY_RULES {
        return refuse(format!(
            "Module {AGENT_GUARDRAILS}: the deny list would have {} entries; at most {MAX_DENY_RULES} are allowed",
            unique.len()
        ));
    }
    Ok(unique)
}

/// The deny list as OpenCode's `permission` key: `Read(//**/<p>)` and
/// `Edit(//**/<p>)` (#1309, #1314) become `read` and `edit` patterns set to `deny`. OpenCode matches a pattern
/// against the repository-relative path and its `*` crosses `/` (observed with
/// OpenCode 1.18.35 in a session, #751; https://opencode.ai/docs/permissions/),
/// so `./**/<rest>` becomes `<rest>` and `*/<rest>`, and any other `**` a `*`.
pub fn opencode_permission(deny: &[String]) -> Value {
    let mut permission = json!({});
    for rule in deny {
        let Some((tool, path)) = rule
            .strip_suffix(')')
            .and_then(|r| r.split_once('('))
            .and_then(|(tool, path)| Some((tool, path.strip_prefix(ANYWHERE)?)))
        else {
            continue;
        };
        let tool = match tool {
            "Read" => "read",
            "Edit" => "edit",
            _ => continue,
        };
        let path = path.replace("**", "*");
        let patterns = [path.clone(), format!("*/{path}")];
        for pattern in patterns {
            permission[tool][pattern] = json!("deny");
        }
    }
    permission
}

/// The entries the installer owns in `opencode.json` (`managed-entries`, object
/// members): the deny patterns under `permission`, nothing else; the project's
/// keys, `$schema` included, stay its own.
fn opencode_entries(deny: &[String]) -> Value {
    json!({ "permission": opencode_permission(deny) })
}

/// The entries registered in `.claude/settings.json`: `permissions.deny`; with
/// `stop_verify`, the Stop entry whose timeout leaves the hook 30 s to report;
/// with `merge_guard`, that module's `PreToolUse` entry (#748) and the explicit
/// ask rule the person approves `human-approved` through (#1146). No `allow`,
/// `sandbox` or `defaultMode`, and no other `ask` entry: those are the project's.
pub fn settings_fragment(answers: &Answers, heldout_dir: &str, merge_guard: bool) -> Result<Value> {
    let mut fragment = json!({ "permissions": { "deny": deny_rules(answers, heldout_dir)? } });
    if stop_verify(answers) {
        fragment["hooks"]["Stop"] = json!([ { "hooks": [ {
            "type": "command",
            "command": format!("sh \"$CLAUDE_PROJECT_DIR/{STOP_VERIFY_PATH}\""),
            "timeout": verify_timeout(answers) + 30,
            "statusMessage": "Running verify",
        } ] } ]);
    }
    if merge_guard {
        fragment["hooks"]["PreToolUse"] = json!([merge_guard::hook_entry()]);
        fragment["permissions"]["ask"] = json!([merge_guard::APPROVAL_ASK_RULE]);
    }
    Ok(fragment)
}

fn stop_verify(answers: &Answers) -> bool {
    answers.get("stop_verify").and_then(Value::as_bool) != Some(false)
}

fn verify_timeout(answers: &Answers) -> u64 {
    answers
        .get("verify_timeout")
        .and_then(Value::as_u64)
        .unwrap_or(600)
}

/// `mcp_custom.*.<field>`: one custom MCP server per name, validated by
/// `mcp::custom` (spec, "Custom MCP servers"). Patterns carry no default.
fn custom_questions() -> Vec<Question> {
    mcp::CUSTOM_FIELDS
        .iter()
        .map(|field| {
            let id = format!("{}.*.{field}", mcp::CUSTOM);
            let (kind, description) = match *field {
                "purpose" => (Kind::String, "Why this MCP server is needed: the need no CLI or API covers."),
                "permissions" => (
                    Kind::Enum(names(&["read-only", "read-write"])),
                    "read-only (default) or read-write, reported at Silver until justified.",
                ),
                "transport" => (Kind::Enum(names(&["stdio", "http"])), "stdio or http."),
                "command" => (Kind::String, "stdio: the command, a package runner with an exact version, docker with a digest, or ./path."),
                "args" => (Kind::ArrayOfString, "stdio: the command's arguments."),
                _ => (Kind::String, "http: the https URL, without credentials."),
            };
            let min_length = matches!(kind, Kind::String).then_some(1);
            Question {
                description: description.to_owned(),
                min_length,
                ..Question::new(&id, kind)
            }
        })
        .collect()
}

impl Module for AgentGuardrails {
    fn id(&self) -> &'static str {
        AGENT_GUARDRAILS
    }
    fn version(&self) -> &'static str {
        AGENT_GUARDRAILS_VERSION
    }
    /// As the capability map states: the required check and the PR template come
    /// from `repo-baseline`, the workflow that runs `verify` from `ci-baseline`.
    fn requires(&self) -> &'static [&'static str] {
        &["repo-baseline", "ci-baseline"]
    }
    /// `<heldout_dir>` in `protected_paths` becomes ci-baseline's held-out
    /// directory, so the recorded answers name the path enforced (#1229).
    fn settle(&self, cx: &Context<'_>, answers: &mut Answers) -> Result<()> {
        let Some(paths) = answers
            .get_mut("protected_paths")
            .and_then(Value::as_array_mut)
        else {
            return Ok(());
        };
        if !paths
            .iter()
            .any(|p| p.as_str().is_some_and(|p| p.contains(HELDOUT_PLACEHOLDER)))
        {
            return Ok(());
        }
        let dir = heldout_dir(cx)?;
        for path in paths.iter_mut() {
            if let Some(text) = path.as_str().filter(|p| p.contains(HELDOUT_PLACEHOLDER)) {
                *path = Value::String(text.replace(HELDOUT_PLACEHOLDER, &dir));
            }
        }
        Ok(())
    }
    fn questions(&self) -> Schema {
        let timeout = Question {
            minimum: Some(30),
            maximum: Some(3600),
            ..question(
                "verify_timeout",
                Kind::Integer,
                "Seconds the Stop hook lets verify run before it blocks as failed.",
                json!(600),
            )
        };
        Schema {
            questions: vec![
                question(
                    "stop_verify",
                    Kind::Boolean,
                    "Run the declared verify when a Claude Code agent stops, and send it back on red.",
                    json!(true),
                ),
                timeout,
                question(
                    "protected_paths",
                    Kind::ArrayOfString,
                    "Repository paths agents may not edit (one Edit deny rule each; <heldout_dir> is ci-baseline's held-out directory).",
                    protected_paths_default(),
                ),
                question(
                    "secret_paths",
                    Kind::ArrayOfString,
                    "Further repository paths agents may neither read nor edit.",
                    json!([]),
                ),
                Question {
                    description: "Directory where the project keeps its specifications, if any; agents may not edit it (one Edit deny rule)."
                        .to_owned(),
                    min_length: Some(1),
                    ..Question::new("spec_dir", Kind::String)
                },
                question(
                    "review_family",
                    Kind::Enum(names(&review::REVIEW_FAMILIES)),
                    "The other model family that reviews every pull request inside the required check: codex, claude, deepseek (DeepSeek V4 Pro on DeepInfra) or none.",
                    json!("codex"),
                ),
                question(
                    "review_blocking",
                    Kind::Enum(names(&review::REVIEW_BLOCKING)),
                    "Review findings that fail the required check: p0-p1 or p0.",
                    json!("p0-p1"),
                ),
                Question {
                    description: "GitHub environment the reviewer's model job runs in, so its key is an environment secret (for example ci-review, with no branch restriction); unset, the key is a repository secret."
                        .to_owned(),
                    when: Some(When::Ne("review_family".to_owned(), "none".to_owned())),
                    ..Question::new("review_environment", Kind::String)
                },
            ]
            .into_iter()
            .chain(unattended::questions())
            .chain([
                question(
                    "agent_environments",
                    Kind::ArrayOfEnum(names(AGENT_ENVIRONMENTS)),
                    "Agent environments to render setup files for: copilot, codex, devcontainer.",
                    json!([]),
                ),
                identity::question(),
                question(
                    "mcp_servers",
                    Kind::ArrayOfEnum(names(mcp::CATALOGUE)),
                    "Read-only MCP servers of the catalogue to allow and seed.",
                    json!([]),
                ),
            ])
            .chain(custom_questions())
            .collect(),
        }
    }
    /// The reviewer's secret for `cross-review` (#940), the agent's secret and
    /// the pull-request setting for `agentic-implement` (#946), the agents' App in
    /// every profile and its secrets in P2 and P3 (#750, #1255). Registration in
    /// `.claude/settings.json` is a `managed-entries` write since #748.
    fn manual_steps(&self, cx: &Context<'_>) -> Vec<ManualStep> {
        let mut steps = review::steps(cx.answers);
        steps.extend(unattended::steps(cx.answers));
        // The agents' App (#750): every profile since #1255; its CI secrets in P2
        // and P3, where agent jobs run in CI.
        steps.extend(identity::steps(
            cx.answers.get(identity::SLUG).and_then(Value::as_str),
            cx.tier() != crate::engine::answers::DEFAULT_TIER,
        ));
        steps
    }
    /// `cross-review` unless `review_family` is `none` (#940). Empty only when
    /// `render` refuses in the same plan.
    fn ci_jobs(&self, cx: &Context<'_>) -> Vec<CiJob> {
        review::contributed(cx).unwrap_or_default()
    }
    fn render(&self, cx: &Context<'_>) -> Result<Vec<Rendered>> {
        let rendered = |path: &str, class: Ownership, content: String| Rendered {
            path: path.to_owned(),
            class,
            content: Some(content),
            scaffold: None,
        };
        let managed = |path: &str, content: String| rendered(path, Ownership::Managed, content);
        let seed = |path: &str, content: String| rendered(path, Ownership::Seed, content);
        let json_text =
            |value: &Value| -> Result<String> { Ok(serde_json::to_string_pretty(value)? + "\n") };
        // `ci_jobs` cannot refuse; rendering the job here makes an unconfirmed
        // vendor fact or a missing pin refuse the plan.
        review::contributed(cx)?;
        let mut out = Vec::new();
        if stop_verify(cx.answers) {
            let verify = cx.profile.value["commands"]["verify"].as_str();
            out.push(managed(
                STOP_VERIFY_PATH,
                render_stop_hook(verify, verify_timeout(cx.answers)),
            ));
        }
        // The fragment file and the registered entries are one object (#748):
        // merge-guard's hook entry joins it where that module is active.
        let merge_guard = cx.answers_if_active(merge_guard::MERGE_GUARD).is_some();
        let entries = json_text(&settings_fragment(
            cx.answers,
            &heldout_dir(cx)?,
            merge_guard,
        )?)?;
        out.push(managed(SETTINGS_FRAGMENT_PATH, entries.clone()));
        out.push(rendered(SETTINGS_PATH, Ownership::ManagedEntries, entries));
        out.push(managed(GUIDE_PATH, GUIDE.to_owned()));
        out.push(managed(
            MCP_ALLOWLIST_PATH,
            json_text(&mcp::allowlist(cx.answers)?)?,
        ));
        out.push(seed(MCP_JSON_PATH, json_text(&mcp::mcp_json(cx.answers)?)?));
        out.push(rendered(
            OPENCODE_JSON_PATH,
            Ownership::ManagedEntries,
            json_text(&opencode_entries(&deny_rules(
                cx.answers,
                &heldout_dir(cx)?,
            )?))?,
        ));
        out.push(seed(WORKTREEINCLUDE_PATH, WORKTREEINCLUDE.to_owned()));
        out.push(seed(TECHNICAL_DEBT_PATH, TECHNICAL_DEBT.to_owned()));
        #[cfg(not(feature = "setup-core"))]
        {
            let block = format!("{}\n{TECHNICAL_DEBT_LINE}\n{}", crate::BEGIN, crate::END);
            out.push(Rendered {
                path: "AGENTS.md".to_owned(),
                class: Ownership::ManagedBlock,
                scaffold: Some(format!("{block}\n")),
                content: Some(block),
            });
        }
        out.extend(environments::render_all(cx)?);
        out.extend(unattended::rendered(cx)?);
        Ok(out)
    }
}
