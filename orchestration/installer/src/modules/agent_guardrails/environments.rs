//! Agent environment files, one set per `agent_environments` entry (#749;
//! SPEC-agent-guardrails.md, Project Structure, later rows):
//!
//! - `copilot` → `.github/workflows/copilot-setup-steps.yml` (`managed`): the one
//!   job GitHub Copilot's coding agent runs before it starts, named
//!   `copilot-setup-steps`, with the stack packs' CI setup steps and never `verify`
//!   (https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/customize-the-agent-environment).
//! - `codex` → `scripts/agent-env-setup.sh` (`seed`): the same steps in `sh`, for
//!   the Codex cloud environment's setup script, which Codex keeps in its settings
//!   (https://developers.openai.com/codex/cloud/environments).
//! - `devcontainer` → `.devcontainer/{devcontainer.json,Dockerfile,init-firewall.sh}`
//!   (`seed`): Claude Code in a non-root container with default-deny egress
//!   (`NET_ADMIN`/`NET_RAW`), no host secret mounts
//!   (https://code.claude.com/docs/en/devcontainer, https://containers.dev/implementors/json_reference/).
//!
//! The steps and the egress hosts come from stack-packs when it is active in the
//! plan (`active_packs`); every `uses:` and `FROM` comes from its pin table. YAML
//! and JSON are built as `serde_json` values; the YAML writer below spells them in
//! block style.
use super::{AGENT_GUARDRAILS, mcp, render};
use crate::{
    Result,
    engine::{Context, Rendered, answers::Answers, lock::Ownership},
    modules::stack_packs::{PinTable, Step, active_packs},
    refuse,
};
use serde_json::{Value, json};
use std::fmt::Write as _;

pub const COPILOT_SETUP_PATH: &str = ".github/workflows/copilot-setup-steps.yml";
pub const CODEX_SETUP_PATH: &str = "scripts/agent-env-setup.sh";
pub const DEVCONTAINER_JSON_PATH: &str = ".devcontainer/devcontainer.json";
pub const DEVCONTAINER_DOCKERFILE_PATH: &str = ".devcontainer/Dockerfile";
pub const INIT_FIREWALL_PATH: &str = ".devcontainer/init-firewall.sh";

/// The hosts every devcontainer allows before the stack packs' and the MCP
/// remote hosts (spec, Project Structure): GitHub, the Claude API, and the
/// claude.ai subscription sign-in with its OAuth token exchange and refresh
/// (https://code.claude.com/docs/en/network-config#network-access-requirements).
pub const BASE_HOSTS: [&str; 5] = [
    "github.com",
    "api.github.com",
    "api.anthropic.com",
    "claude.ai",
    "platform.claude.com",
];

/// Claude Code in the container: the pin table's `tools.claude-code`, the version
/// the model jobs install too (one pin, #971), installed through npm at that exact
/// version, as the docs advise when builds must be reproducible.
fn claude_code_package(pins: &PinTable) -> Result<String> {
    Ok(format!(
        "@anthropic-ai/claude-code@{}",
        pins.tool("claude-code")?.version
    ))
}
/// The pin-table image the container starts from: it carries node for npm.
const DEVCONTAINER_IMAGE: &str = "node.build";
/// The non-root user of that image.
const CONTAINER_USER: &str = "node";

const CODEX_SETUP: &str = include_str!("../../../../../templates/agent-guardrails/codex-setup.sh");
const DOCKERFILE: &str =
    include_str!("../../../../../templates/agent-guardrails/devcontainer/Dockerfile");
const INIT_FIREWALL: &str =
    include_str!("../../../../../templates/agent-guardrails/devcontainer/init-firewall.sh");

/// The environments the answer names, once each.
fn environments(answers: &Answers) -> Vec<&str> {
    let mut out: Vec<&str> = Vec::new();
    for name in answers
        .get("agent_environments")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        if !out.contains(&name) {
            out.push(name);
        }
    }
    out
}

/// The rendered environment files; nothing when `agent_environments` is empty.
pub fn render_all(cx: &Context<'_>) -> Result<Vec<Rendered>> {
    let chosen = environments(cx.answers);
    if chosen.is_empty() {
        return Ok(Vec::new());
    }
    let pins = PinTable::embedded()?;
    let packs = active_packs(cx)?;
    let mut steps = Vec::new();
    for (app, pack) in &packs {
        steps.extend((pack.ci_setup)(app, &pins)?);
    }
    let file = |path: &str, class: Ownership, content: String| Rendered {
        path: path.to_owned(),
        class,
        content: Some(content),
        scaffold: None,
    };
    let mut out = Vec::new();
    if chosen.contains(&"copilot") {
        let workflow = copilot_workflow(&pins, &steps)?;
        out.push(file(
            COPILOT_SETUP_PATH,
            Ownership::Managed,
            to_yaml(&workflow),
        ));
    }
    if chosen.contains(&"codex") {
        let script = render(CODEX_SETUP, &[("steps", &sh_steps(&steps))]);
        out.push(file(CODEX_SETUP_PATH, Ownership::Seed, script));
    }
    if chosen.contains(&"devcontainer") {
        let mut hosts: Vec<String> = BASE_HOSTS.iter().map(|h| (*h).to_owned()).collect();
        for (_, pack) in &packs {
            hosts.extend(pack.egress_hosts.iter().map(|h| (*h).to_owned()));
        }
        hosts.extend(mcp_remote_hosts(cx.answers)?);
        let mut unique: Vec<String> = Vec::new();
        for host in hosts {
            if !unique.contains(&host) {
                unique.push(host);
            }
        }
        let json = serde_json::to_string_pretty(&devcontainer_json())? + "\n";
        out.push(file(DEVCONTAINER_JSON_PATH, Ownership::Seed, json));
        let image = pins.image(DEVCONTAINER_IMAGE)?.pinned();
        let dockerfile = render(
            DOCKERFILE,
            &[
                ("image", &image),
                ("claude_code", &claude_code_package(&pins)?),
            ],
        );
        out.push(file(
            DEVCONTAINER_DOCKERFILE_PATH,
            Ownership::Seed,
            dockerfile,
        ));
        let firewall = render(INIT_FIREWALL, &[("hosts", &unique.join("\n"))]);
        out.push(file(INIT_FIREWALL_PATH, Ownership::Seed, firewall));
    }
    Ok(out)
}

/// The hosts of the allowlist's http servers, in its order.
fn mcp_remote_hosts(answers: &Answers) -> Result<Vec<String>> {
    let allowlist = mcp::allowlist(answers)?;
    let mut hosts = Vec::new();
    for server in allowlist["servers"].as_array().into_iter().flatten() {
        if let Some(text) = server["match"]["url"].as_str() {
            // The firewall script runs as root and spells each host in a shell
            // string: only DNS name characters pass.
            match url::Url::parse(text)?.host_str() {
                Some(host)
                    if host
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') =>
                {
                    hosts.push(host.to_owned())
                }
                _ => {
                    return refuse(format!(
                        "Module {AGENT_GUARDRAILS}: MCP server url `{text}` has no DNS host name the devcontainer firewall can allow"
                    ));
                }
            }
        }
    }
    Ok(hosts)
}

/// The workflow as data: the documented triggers (manual, and on a change to the
/// file itself), one job with the documented keys only.
fn copilot_workflow(pins: &PinTable, steps: &[Step]) -> Result<Value> {
    let checkout = Step::new("Check out")
        .uses(pins.action("actions/checkout")?)
        .with("persist-credentials", "false");
    let steps: Vec<Value> = std::iter::once(&checkout)
        .chain(steps)
        .map(step_value)
        .collect::<Result<_>>()?;
    let on_change = json!({ "paths": [COPILOT_SETUP_PATH] });
    Ok(json!({
        "name": "Copilot Setup Steps",
        "on": {
            "workflow_dispatch": {},
            "push": on_change,
            "pull_request": on_change,
        },
        "jobs": { "copilot-setup-steps": {
            "runs-on": "ubuntu-latest",
            "timeout-minutes": 30,
            "permissions": { "contents": "read" },
            "steps": steps,
        } },
    }))
}

/// A step as YAML reads it: `uses` is the pinned `repo@sha # version` form.
fn step_value(step: &Step) -> Result<Value> {
    let mut value = serde_json::to_value(step)?;
    if let Some(action) = &step.uses {
        value["uses"] = json!(action.uses());
    }
    Ok(value)
}

/// The order keys are written in; others follow alphabetically.
const KEY_ORDER: &[&str] = &[
    "name",
    "on",
    "permissions",
    "jobs",
    "runs-on",
    "timeout-minutes",
    "steps",
    "id",
    "if",
    "uses",
    "working-directory",
    "with",
    "env",
    "run",
];

fn rank(key: &str) -> usize {
    KEY_ORDER
        .iter()
        .position(|k| *k == key)
        .unwrap_or(KEY_ORDER.len())
}

/// A string YAML reads back as the same string: plain when unambiguous,
/// JSON-quoted (a valid YAML double-quoted scalar) otherwise.
fn scalar(text: &str) -> String {
    let plain = text.starts_with(|c: char| c.is_ascii_alphabetic())
        && !text.ends_with(' ')
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || " -_./".contains(c))
        && !["true", "false", "yes", "no", "on", "off", "null", "y", "n"]
            .contains(&text.to_ascii_lowercase().as_str());
    if plain {
        text.to_owned()
    } else {
        Value::String(text.to_owned()).to_string()
    }
}

/// `value` after `key:` on one line, or `None` when it needs a block.
fn inline(key: &str, value: &Value) -> Option<String> {
    match value {
        Value::Object(map) if map.is_empty() => Some("{}".to_owned()),
        Value::Array(items) if items.is_empty() => Some("[]".to_owned()),
        Value::Object(_) | Value::Array(_) => None,
        Value::String(text) if text.contains('\n') => None,
        // The pin's version comment stays a comment, as Dependabot writes it.
        Value::String(text) if key == "uses" => Some(text.clone()),
        Value::String(text) => Some(scalar(text)),
        other => Some(other.to_string()),
    }
}

fn mapping(out: &mut String, indent: usize, map: &serde_json::Map<String, Value>) {
    let pad = " ".repeat(indent);
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort_by_key(|k| (rank(k), k.as_str()));
    for key in keys {
        let value = &map[key];
        let name = scalar(key);
        if let Some(text) = inline(key, value) {
            let _ = writeln!(out, "{pad}{name}: {text}");
            continue;
        }
        match value {
            Value::String(text) => {
                let (body, chomp) = match text.strip_suffix('\n') {
                    Some(body) => (body, "|"),
                    None => (text.as_str(), "|-"),
                };
                let _ = writeln!(out, "{pad}{name}: {chomp}");
                for line in body.lines() {
                    if line.is_empty() {
                        out.push('\n');
                    } else {
                        let _ = writeln!(out, "{pad}  {line}");
                    }
                }
            }
            Value::Object(inner) => {
                let _ = writeln!(out, "{pad}{name}:");
                mapping(out, indent + 2, inner);
            }
            Value::Array(items) => {
                let _ = writeln!(out, "{pad}{name}:");
                for item in items {
                    sequence_item(out, indent + 2, item);
                }
            }
            _ => unreachable!("scalars are inline"),
        }
    }
}

/// `- item` at `indent`: a mapping item starts on the dash line.
fn sequence_item(out: &mut String, indent: usize, item: &Value) {
    let pad = " ".repeat(indent);
    match item {
        Value::Object(map) if !map.is_empty() => {
            let mut body = String::new();
            mapping(&mut body, indent + 2, map);
            let inner = " ".repeat(indent + 2);
            let first = body.strip_prefix(&inner).unwrap_or(&body);
            let _ = write!(out, "{pad}- {first}");
        }
        other => {
            let text = inline("", other).unwrap_or_else(|| other.to_string());
            let _ = writeln!(out, "{pad}- {text}");
        }
    }
}

/// The workflow in block-style YAML with a header naming its owner.
pub fn to_yaml(workflow: &Value) -> String {
    let mut out =
        String::from("# Managed by brakes (agent-guardrails): change it through `configure`.\n");
    if let Value::Object(map) = workflow {
        mapping(&mut out, 0, map);
    }
    out
}

fn sh_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

/// The steps in `sh`: each `run` step in a subshell with its directory and
/// environment; an action step as a comment.
fn sh_steps(steps: &[Step]) -> String {
    let mut out = String::new();
    for step in steps {
        if out.is_empty() {
            let _ = writeln!(out, "# {}", step.name);
        } else {
            let _ = writeln!(out, "\n# {}", step.name);
        }
        let Some(run) = &step.run else {
            let action = step.uses.as_ref().map_or("", |a| a.repo.as_str());
            let _ = writeln!(out, "# Skipped: a GitHub Actions step ({action}).");
            continue;
        };
        out.push_str("(\n");
        if let Some(dir) = &step.working_directory {
            let _ = writeln!(out, "  cd {}", sh_quote(dir));
        }
        for (key, value) in &step.env {
            let _ = writeln!(out, "  export {key}={}", sh_quote(value));
        }
        for line in run.lines() {
            let _ = writeln!(out, "  {line}");
        }
        out.push_str(")\n");
    }
    if out.is_empty() {
        out.push_str("# No stack pack is recorded: nothing to set up.\n");
    }
    out.trim_end().to_owned()
}

/// `devcontainer.json`: built from the Dockerfile beside it, the firewall's two
/// capabilities, a non-root user, Claude Code's state in a named volume and no
/// host mount besides the workspace the tool provides.
fn devcontainer_json() -> Value {
    let home = format!("/home/{CONTAINER_USER}");
    json!({
        "name": "Claude Code",
        "build": { "dockerfile": "Dockerfile" },
        "runArgs": ["--cap-add=NET_ADMIN", "--cap-add=NET_RAW"],
        "remoteUser": CONTAINER_USER,
        "mounts": [format!("source=claude-code-config-${{devcontainerId}},target={home}/.claude,type=volume")],
        "containerEnv": {
            "CLAUDE_CONFIG_DIR": format!("{home}/.claude"),
            "DISABLE_AUTOUPDATER": "1",
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        },
        "postStartCommand": "sudo /usr/local/bin/init-firewall.sh",
        "waitFor": "postStartCommand",
    })
}
