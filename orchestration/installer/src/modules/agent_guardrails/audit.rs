//! The static `agents.*` rules (SPEC-agent-guardrails.md, "Doctor and auditor
//! rules"; #746). Their data ([`RULES`]: id, level, profiles, `local`) is exported
//! for the auditor, whose registry judges them from `doctor`'s
//! `WARNING: agents.<rule>: <text>` findings at those levels since the owner's
//! allocation (#873); the findings never change readiness, as the `ci.*`,
//! `security.*` and `stack.*` rules do. A level above the rule's own is named
//! in the text (`Silver: …`) and never fails the rule.
//!
//! [`diagnose`] holds the rules about the repository's content, evaluated in every
//! checkout, managed or not: `agents.mcp-allowlist`, `agents.readable-secrets`,
//! `agents.unattended-gated` over every workflow an issue label starts an agent
//! from, `agents.workflow-caps` and `agents.identity` over every agent job (#750),
//! and `agents.workflow-injection` over every workflow job that runs an agent (#972).
//! The rules about what the module renders (`agents.deny-secrets`,
//! `agents.stop-verify`, `agents.protected-paths`, `agents.technical-debt`,
//! `agents.cross-review`, `agents.heldout-denied`) run
//! where it is installed, from [`super::doctor::findings`]. Nothing here reads or
//! prints a secret value: a `.properties` finding names the key, never the value.
use super::{MCP_ALLOWLIST_PATH, MCP_JSON_PATH, WORKTREEINCLUDE_PATH};
use crate::auditor::{
    rules::{Level, Profile},
    workflows::{unverified, warn},
};
use serde_json::Value;
use std::{fs, path::Path};

pub const DENY_SECRETS: &str = "agents.deny-secrets";
pub const STOP_VERIFY: &str = "agents.stop-verify";
pub const PROTECTED_PATHS: &str = "agents.protected-paths";
pub const MCP_ALLOWLIST: &str = "agents.mcp-allowlist";
pub const TECHNICAL_DEBT: &str = "agents.technical-debt";
pub const READABLE_SECRETS: &str = "agents.readable-secrets";
pub const CROSS_REVIEW: &str = "agents.cross-review";
pub const UNATTENDED_GATED: &str = "agents.unattended-gated";
pub const HELDOUT_DENIED: &str = "agents.heldout-denied";
pub const WORKFLOW_CAPS: &str = "agents.workflow-caps";
pub const IDENTITY: &str = "agents.identity";
pub const WORKFLOW_INJECTION: &str = "agents.workflow-injection";

/// One rule as the spec's table states it. `local`: readable without the
/// network, so `--fleet` can evaluate it through the contents API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleData {
    pub id: &'static str,
    pub level: Level,
    pub profiles: &'static [Profile],
    pub local: bool,
}

const ALL: &[Profile] = &[Profile::P1, Profile::P2, Profile::P3];
const TEAMS: &[Profile] = &[Profile::P2, Profile::P3];

/// The rules this module implements, in the spec's order but for
/// `agents.cross-review` (#940), `agents.unattended-gated` (#946),
/// `agents.heldout-denied` (#945), `agents.workflow-caps` and `agents.identity`
/// (#750), and `agents.workflow-injection` (#972), appended.
pub const RULES: [RuleData; 12] = [
    rule(DENY_SECRETS, Level::Basic, ALL),
    rule(STOP_VERIFY, Level::Bronze, ALL),
    rule(PROTECTED_PATHS, Level::Bronze, TEAMS),
    rule(MCP_ALLOWLIST, Level::Bronze, ALL),
    rule(TECHNICAL_DEBT, Level::Bronze, ALL),
    rule(READABLE_SECRETS, Level::Basic, ALL),
    rule(CROSS_REVIEW, Level::Silver, ALL),
    rule(UNATTENDED_GATED, Level::Silver, ALL),
    rule(HELDOUT_DENIED, Level::Silver, ALL),
    rule(WORKFLOW_CAPS, Level::Silver, ALL),
    rule(IDENTITY, Level::Silver, TEAMS),
    rule(WORKFLOW_INJECTION, Level::Bronze, ALL),
];

/// ci-baseline's `heldout` is true in this checkout: a workflow has the job it
/// renders exactly then (`heldout`). What `agents.heldout-denied` requires, read
/// the same way by `doctor` and the auditor (#945).
pub fn heldout_enabled(files: &dyn crate::auditor::Files) -> bool {
    crate::auditor::workflows::read_all(files)
        .into_iter()
        .filter_map(|(_, parsed)| parsed.ok())
        .any(|wf| {
            wf.job(crate::modules::ci_baseline::render::HELDOUT_JOB)
                .is_some()
        })
}

const fn rule(id: &'static str, level: Level, profiles: &'static [Profile]) -> RuleData {
    RuleData {
        id,
        level,
        profiles,
        local: true,
    }
}

/// The repository-content rules for the checkout at `root`.
pub fn diagnose(root: &Path) -> Vec<String> {
    let mut out = mcp_allowlist(root);
    out.extend(readable_secrets(root));
    out.extend(unattended_gated(root));
    out.extend(super::identity::workflow_caps(root));
    out.extend(super::identity::identity(root));
    out.extend(workflow_injection(root));
    out
}

/// `agents.workflow-injection` over every parsed workflow (#972); an unparsable one
/// is another rule's finding (`ci.workflow-lint`).
fn workflow_injection(root: &Path) -> Vec<String> {
    crate::auditor::workflows::read_all(&crate::auditor::LocalFiles::new(root))
        .into_iter()
        .filter_map(|(path, parsed)| Some(super::injection::findings(&path, &parsed.ok()?)))
        .flatten()
        .collect()
}

/// `agents.unattended-gated` over every parsed workflow; an unparsable one is
/// another rule's finding (`ci.workflow-lint`).
fn unattended_gated(root: &Path) -> Vec<String> {
    crate::auditor::workflows::read_all(&crate::auditor::LocalFiles::new(root))
        .into_iter()
        .filter_map(|(path, parsed)| Some(super::unattended::gated(&path, &parsed.ok()?)))
        .flatten()
        .collect()
}

/// A file read for a rule: `Ok(None)` when absent, `Err` with the reason when
/// unreadable or not JSON.
fn json_file(root: &Path, path: &str) -> Result<Option<Value>, String> {
    match crate::read(root, path) {
        Ok(None) => Ok(None),
        Ok(Some(text)) => serde_json::from_str(&text)
            .map(Some)
            .map_err(|_| "invalid JSON".to_owned()),
        Err(e) => Err(e.to_string()),
    }
}

/// Every `.mcp.json` server matches one allowlist entry; a `read-write` entry is
/// a Silver finding naming it and its purpose.
fn mcp_allowlist(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let entries = match json_file(root, MCP_ALLOWLIST_PATH) {
        Ok(value) => value
            .and_then(|v| v["servers"].as_array().cloned())
            .unwrap_or_default(),
        Err(reason) => return vec![unverified(MCP_ALLOWLIST, MCP_ALLOWLIST_PATH, &reason)],
    };
    match json_file(root, MCP_JSON_PATH) {
        Err(reason) => out.push(unverified(MCP_ALLOWLIST, MCP_JSON_PATH, &reason)),
        Ok(None) => {}
        Ok(Some(value)) => {
            if let Some(servers) = value["mcpServers"].as_object() {
                for (name, server) in servers {
                    if !entries.iter().any(|e| allows(e, name, server)) {
                        out.push(warn(MCP_ALLOWLIST, format!(
                            "{MCP_JSON_PATH} server `{name}` is not in {MCP_ALLOWLIST_PATH}; declare it with configure --set mcp_servers or remove it"
                        )));
                    }
                }
            }
        }
    }
    for entry in &entries {
        if entry["permissions"] == "read-write" {
            let name = entry["name"].as_str().unwrap_or("?");
            let purpose = entry["purpose"].as_str().unwrap_or("").trim();
            let purpose = if purpose.is_empty() {
                "none written"
            } else {
                purpose
            };
            out.push(warn(
                MCP_ALLOWLIST,
                format!(
                    "Silver: {MCP_ALLOWLIST_PATH} server `{name}` is read-write; purpose: {purpose}"
                ),
            ));
        }
    }
    out
}

/// An allowlist entry allows a server of the same name whose command and
/// arguments satisfy its `match`, when it has one: the command is one of
/// `command_in`, one argument equals `args_contains` as a whole and the `url`
/// equals `url` (spec, Allowlist; Custom MCP servers).
fn allows(entry: &Value, name: &str, server: &Value) -> bool {
    if entry["name"].as_str() != Some(name) {
        return false;
    }
    let matcher = &entry["match"];
    if let Some(commands) = matcher["command_in"].as_array() {
        let command = server["command"].as_str();
        if !commands.iter().any(|c| c.as_str() == command) {
            return false;
        }
    }
    if let Some(url) = matcher["url"].as_str()
        && server["url"].as_str() != Some(url)
    {
        return false;
    }
    if let Some(wanted) = matcher["args_contains"].as_str() {
        let args = server["args"].as_array().cloned().unwrap_or_default();
        if !args.iter().any(|a| a.as_str() == Some(wanted)) {
            return false;
        }
    }
    true
}

/// A repository path the spec counts as a secret: `.env` and `.env.*` (except
/// `.example`/`.template`), `secrets/**`, key files and Android properties files.
fn secret_path(path: &str) -> bool {
    let path = path.trim_start_matches('/');
    let base = path
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or(path);
    let env = base == ".env"
        || base == ".env*"
        || (base.starts_with(".env.")
            && !base.ends_with(".example")
            && !base.ends_with(".template"));
    env || path == "secrets"
        || path.starts_with("secrets/")
        || [".pem", ".key", ".p12"]
            .iter()
            .any(|ext| base.ends_with(ext))
        || base.starts_with("id_rsa")
        || base == "local.properties"
        || base == "keystore.properties"
}

/// The key of a `.properties` line that names a credential, if it does: one
/// ending in `password`, `secret`, `token` or `key` right before the `=`
/// (`storePassword=`, `signing.key =`), so `keyAlias=` is not one.
fn credential_key(line: &str) -> Option<&str> {
    let line = line.trim();
    if line.starts_with('#') || line.starts_with('!') {
        return None;
    }
    let (key, _) = line.split_once('=')?;
    let key = key.trim();
    let lower = key.to_ascii_lowercase();
    ["password", "secret", "token", "key"]
        .iter()
        .any(|word| lower.ends_with(word))
        .then_some(key)
}

/// No tracked secret path, no credential line in a tracked `.properties` file,
/// and no secret listed in `.worktreeinclude`.
fn readable_secrets(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    match crate::scope::git(root, &["ls-files", "-z"]) {
        Err(e) => out.push(unverified(READABLE_SECRETS, "git ls-files", &e.to_string())),
        Ok(listing) => {
            let mut tracked: Vec<&str> = listing.split('\0').filter(|p| !p.is_empty()).collect();
            tracked.sort_unstable();
            for path in tracked.iter().filter(|p| secret_path(p)) {
                out.push(warn(
                    READABLE_SECRETS,
                    format!("{path} is tracked; secrets must not be readable in the checkout"),
                ));
            }
            for path in tracked.iter().filter(|p| p.ends_with(".properties")) {
                let Ok(text) = fs::read_to_string(root.join(path)) else {
                    continue;
                };
                if let Some(key) = text.lines().find_map(credential_key) {
                    out.push(warn(
                        READABLE_SECRETS,
                        format!("{path} has a `{key}` line; keep credentials out of tracked files"),
                    ));
                }
            }
        }
    }
    if let Ok(Some(text)) = crate::read(root, WORKTREEINCLUDE_PATH) {
        for line in text.lines().map(str::trim) {
            if !line.is_empty() && !line.starts_with('#') && secret_path(line) {
                out.push(warn(
                    READABLE_SECRETS,
                    format!(
                        "{WORKTREEINCLUDE_PATH} lists {line}; worktrees must not multiply secrets"
                    ),
                ));
            }
        }
    }
    out
}
