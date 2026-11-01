//! The MCP catalogue, the allowlist (`managed`) and the `.mcp.json` seed rendered
//! from the `mcp_servers` answer (#743).
//!
//! Policy (owner, 2026-10-28; docs/decisions.md, "Agents reach hosted tools through
//! their CLI or API; MCP only when none exists"): agents reach a hosted tool through
//! its CLI or API when one exists (GitHub through `gh`, Sentry through its API or CLI),
//! so the catalogue holds only `docs`. An MCP server is allowed only as a recorded
//! entry with purpose and permissions, read-only by default; the allowlist is
//! `managed`, so a change goes through `configure`. Credentials would be `${ENV}`
//! references that Claude Code expands at load time; no value is ever rendered.
//!
//! `docs` is Context7: `npx -y @upstash/context7-mcp`, lookup tools only; its API key is
//! optional and read from `CONTEXT7_API_KEY` (upstash/context7, packages/mcp/README.md,
//! verified 2026-10-28). Stdio servers run a pinned exact version and the allowlist
//! matches that exact form (owner, 2026-10-28; spec, Allowlist). A bump is a catalogue
//! change in its own PR.
//!
//! Custom servers are the pattern questions `mcp_custom.<name>.<field>` (spec,
//! "Custom MCP servers"; decision #757 for patterns; #746): the engine types each
//! key, [`custom`] validates each server (purpose and transport required,
//! permissions read-only by default, a pinned version for stdio, no credential in
//! an http URL) and every refusal names the server.
use super::AGENT_GUARDRAILS;
use crate::{Result, engine::answers::Answers, refuse};
use serde_json::{Map, Value, json};

/// Context7's pinned package: `dist-tags.latest` of registry.npmjs.org/@upstash/context7-mcp,
/// published 2026-10-19, resolved read-only on 2026-10-28.
pub const CONTEXT7_PACKAGE: &str = "@upstash/context7-mcp@4.4.4";

/// The catalogue, in the order the question lists it.
pub const CATALOGUE: &[&str] = &["docs"];

/// One catalogue server: its allowlist entry and its `.mcp.json` entry.
fn entry(name: &str) -> Result<(Value, Value)> {
    let (mut allow, server) = match name {
        "docs" => (
            json!({
                "purpose": "Library documentation lookup",
                "transport": "stdio",
                "match": { "command_in": ["npx"], "args_contains": CONTEXT7_PACKAGE },
            }),
            json!({ "command": "npx", "args": ["-y", CONTEXT7_PACKAGE] }),
        ),
        other => {
            return refuse(format!(
                "Module {AGENT_GUARDRAILS}: mcp_servers entry `{other}` is not in the read-only catalogue ({})",
                CATALOGUE.join(", ")
            ));
        }
    };
    allow["name"] = json!(name);
    allow["permissions"] = json!("read-only");
    Ok((allow, server))
}

/// The servers `mcp_servers` names, once each, in the answer's order.
fn chosen(answers: &Answers) -> Result<Vec<(String, Value, Value)>> {
    let mut out: Vec<(String, Value, Value)> = Vec::new();
    let names = answers
        .get("mcp_servers")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        .unwrap_or_default();
    for name in names {
        if out.iter().any(|(n, _, _)| n == name) {
            continue;
        }
        let (allow, server) = entry(name)?;
        out.push((name.to_owned(), allow, server));
    }
    Ok(out)
}

/// The prefix of the custom servers' pattern questions.
pub const CUSTOM: &str = "mcp_custom";
/// The fields a custom server may record, as `mcp_custom.*.<field>`.
pub const CUSTOM_FIELDS: [&str; 6] = [
    "purpose",
    "permissions",
    "transport",
    "command",
    "args",
    "url",
];
/// Package runners whose package argument must carry an exact version.
const RUNNERS: [&str; 4] = ["npx", "bunx", "pnpm", "uvx"];

fn refuse_server<T>(name: &str, text: impl std::fmt::Display) -> Result<T> {
    refuse(format!(
        "Module {AGENT_GUARDRAILS}: {CUSTOM} server `{name}` {text}"
    ))
}

/// `x.y.z` with an optional `-prerelease` or `+build` of `[A-Za-z0-9.-]`.
fn exact_version(text: &str) -> bool {
    let (core, rest) = match text.find(['-', '+']) {
        Some(at) => text.split_at(at),
        None => (text, ""),
    };
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        && rest
            .bytes()
            .skip(1)
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

/// The argument that pins a stdio server's version: the package of a runner with
/// an exact version, or a `docker` image with a digest. `Ok(None)` for a
/// repository-relative command; any other command cannot be pinned.
fn pinned_argument<'a>(name: &str, command: &str, args: &'a [String]) -> Result<Option<&'a str>> {
    if command.starts_with("./") {
        return Ok(None);
    }
    let operands: Vec<&str> = args
        .iter()
        .map(String::as_str)
        .filter(|a| !a.starts_with('-'))
        .collect();
    let pinned = if command == "docker" {
        operands.into_iter().find(|a| a.contains("@sha256:"))
    } else if RUNNERS.contains(&command) {
        let package = operands
            .into_iter()
            .find(|a| !(command == "pnpm" && *a == "dlx"));
        package.filter(|p| {
            let by_at = p.rfind('@').filter(|at| *at > 0).map(|at| &p[at + 1..]);
            let by_eq = (command == "uvx")
                .then(|| p.split_once("==").map(|(_, v)| v))
                .flatten();
            by_at.or(by_eq).is_some_and(exact_version)
        })
    } else {
        return refuse_server(
            name,
            format!(
                "runs `{command}`, whose version cannot be pinned; run it through npx, bunx, pnpm dlx or uvx with an exact version, docker with a digest, or a repository path (./…)"
            ),
        );
    };
    match pinned {
        Some(argument) => Ok(Some(argument)),
        None => refuse_server(
            name,
            format!(
                "runs `{command}` without a pinned version; name the package with an exact version (<package>@x.y.z) or the image with a digest (@sha256:…)"
            ),
        ),
    }
}

/// An http URL: https, or http on the loopback host; no user information, no query.
fn check_url(name: &str, url: &str) -> Result<()> {
    let rest = url.strip_prefix("https://").or_else(|| {
        url.strip_prefix("http://")
            .filter(|r| r.starts_with("localhost") || r.starts_with("127.0.0.1"))
    });
    let Some(rest) = rest else {
        return refuse_server(name, "url must be https:// (or http:// on localhost)");
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.contains('@') {
        return refuse_server(
            name,
            "url carries user information; credentials never go in answers",
        );
    }
    if url.contains('?') {
        return refuse_server(name, "url carries a query; credentials never go in answers");
    }
    Ok(())
}

/// The recorded custom servers, sorted by name, each validated: its allowlist
/// entry and its `.mcp.json` entry.
pub fn custom(answers: &Answers) -> Result<Vec<(String, Value, Value)>> {
    let mut servers: std::collections::BTreeMap<&str, Map<String, Value>> = Default::default();
    for (key, value) in answers {
        let mut parts = key.splitn(3, '.');
        if let (Some(CUSTOM), Some(name), Some(field)) = (parts.next(), parts.next(), parts.next())
        {
            servers
                .entry(name)
                .or_default()
                .insert(field.to_owned(), value.clone());
        }
    }
    let mut out = Vec::new();
    for (name, fields) in servers {
        let text = |field: &str| fields.get(field).and_then(Value::as_str);
        if CATALOGUE.contains(&name) {
            return refuse_server(
                name,
                "takes a catalogue name; choose another name or use mcp_servers",
            );
        }
        let Some(purpose) = text("purpose").filter(|p| !p.trim().is_empty()) else {
            return refuse_server(name, format!("has no purpose; set {CUSTOM}.{name}.purpose"));
        };
        let permissions = text("permissions").unwrap_or("read-only");
        let (allow_match, server) = match text("transport") {
            Some("stdio") => {
                if fields.contains_key("url") {
                    return refuse_server(name, "is stdio and takes no url");
                }
                let Some(command) = text("command") else {
                    return refuse_server(
                        name,
                        format!("is stdio and needs {CUSTOM}.{name}.command"),
                    );
                };
                let args: Vec<String> = fields
                    .get("args")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default();
                let mut matcher = json!({ "command_in": [command] });
                if let Some(argument) = pinned_argument(name, command, &args)? {
                    matcher["args_contains"] = json!(argument);
                }
                (matcher, json!({ "command": command, "args": args }))
            }
            Some("http") => {
                if fields.contains_key("command") || fields.contains_key("args") {
                    return refuse_server(name, "is http and takes no command or args");
                }
                let Some(url) = text("url") else {
                    return refuse_server(name, format!("is http and needs {CUSTOM}.{name}.url"));
                };
                check_url(name, url)?;
                (json!({ "url": url }), json!({ "type": "http", "url": url }))
            }
            _ => {
                return refuse_server(
                    name,
                    format!("has no transport; set {CUSTOM}.{name}.transport to stdio or http"),
                );
            }
        };
        let allow = json!({
            "name": name,
            "purpose": purpose,
            "permissions": permissions,
            "transport": text("transport"),
            "match": allow_match,
        });
        out.push((name.to_owned(), allow, server));
    }
    Ok(out)
}

/// The catalogue servers chosen, then the recorded custom ones.
fn all(answers: &Answers) -> Result<Vec<(String, Value, Value)>> {
    let mut out = chosen(answers)?;
    out.extend(custom(answers)?);
    Ok(out)
}

/// `.agent-setup/mcp-allowlist.json`: schema 1, the chosen catalogue entries then
/// the custom servers.
pub fn allowlist(answers: &Answers) -> Result<Value> {
    let servers: Vec<Value> = all(answers)?.into_iter().map(|(_, a, _)| a).collect();
    Ok(json!({ "schema": 1, "servers": servers }))
}

/// `.mcp.json`: `mcpServers` from the chosen catalogue entries and the custom
/// servers; empty by default.
pub fn mcp_json(answers: &Answers) -> Result<Value> {
    let servers: Map<String, Value> = all(answers)?
        .into_iter()
        .map(|(name, _, server)| (name, server))
        .collect();
    Ok(json!({ "mcpServers": servers }))
}
