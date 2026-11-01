//! The merge-guard rule of `doctor` (`SPEC-merge-guard.md`, doctor lines): the
//! registration warning, always, and the mode line with the server's evidence,
//! only with `--remote`. Today's managed-file drift finding covers the hook itself.

use super::Mode;
use super::protection::{Kind, Protection, mode_for, read};
use crate::Result;
use crate::engine::manual::{self, NoRunner, ProbeResult};
use crate::modules::merge_guard::{HOOK_PATH, MERGE_GUARD, registration_probe};
use crate::remote::{Api, in_scope};
use serde_json::{Value, json};
use std::path::Path;

pub const UNREGISTERED: &str = "WARNING: Merge guard hook is not registered in .claude/settings.json (PreToolUse, matcher Bash, onFailure block)";

/// Whether `.claude/settings.json` registers the hook: the `hook-registered`
/// step's probe answers `verified` (#696).
fn registered(root: &Path) -> bool {
    matches!(
        manual::run(root, &registration_probe(), &NoRunner),
        ProbeResult::Verified(_)
    )
}

/// The warning when the hook is installed but `.claude/settings.json` does not
/// register it, as the `hook-registered` step's probe reads it. Registration is
/// the project's (#442); an unreadable settings file registers nothing for the
/// host either.
pub fn registration(root: &Path) -> Result<Option<String>> {
    if !root.join(HOOK_PATH).is_file() {
        return Ok(None);
    }
    Ok((!registered(root)).then(|| UNREGISTERED.to_owned()))
}

/// The server's protection of `repository`, or why it could not be read; read
/// once per `doctor --remote` for both the mode line and the rule object.
pub fn probe(api: &dyn Api, repository: &str) -> std::result::Result<Protection, String> {
    if !in_scope(repository) {
        return Err("the repository is outside the authorized personal scope".into());
    }
    read(api, repository).map_err(|error| error.to_string())
}

/// The mode a probe earns: unreadable is `full`.
fn mode_of(probed: &std::result::Result<Protection, String>) -> Mode {
    probed.as_ref().map_or(Mode::Full, mode_for)
}

fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::Full => "full",
        Mode::Light => "light",
    }
}

/// `Merge guard for <owner>/<repo>: <mode> — <evidence>`; a server that cannot
/// be read is `full`, with the reason.
pub fn mode_line(api: &dyn Api, repository: &str) -> String {
    line(repository, &probe(api, repository))
}

/// [`mode_line`] over a probe already taken.
pub fn line(repository: &str, probed: &std::result::Result<Protection, String>) -> String {
    let evidence = match probed {
        Ok(protection) => protection.evidence(),
        Err(error) => format!(
            "the server protection could not be read ({error}); treat the hook as the only barrier"
        ),
    };
    format!(
        "Merge guard for {repository}: {} — {evidence}",
        mode_name(mode_of(probed))
    )
}

/// The rule object `doctor --json` emits (SPEC-merge-guard.md, Data model):
/// the hook's local state always; `server`, `mode` and `probed_at` only with a
/// probe (`--remote`), `null` otherwise. `unchanged` compares the hook with the
/// digest the lock records for it.
pub fn rule(
    root: &Path,
    repository: Option<&str>,
    remote: Option<(&std::result::Result<Protection, String>, &str)>,
) -> Result<Value> {
    let hook = crate::read(root, HOOK_PATH)?;
    let recorded = crate::read(root, crate::LOCK)?
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .and_then(|lock| {
            lock["files"][HOOK_PATH]["digest"]
                .as_str()
                .map(str::to_owned)
        });
    let unchanged = hook
        .as_deref()
        .is_some_and(|text| recorded.as_deref() == Some(&crate::digest(text)));
    let server = remote.map(|(probed, _)| match probed {
        Ok(p) => json!({
            "protected": mode_for(p) == Mode::Light,
            "kind": match p.kind {
                Kind::Ruleset => "ruleset",
                Kind::Classic => "classic",
                Kind::None => "none",
            },
            "required": p.required,
            "admins_enforced": p.admins_enforced,
            "bypass_actors": p.bypass_actors,
        }),
        Err(error) => json!({"protected": false, "error": error}),
    });
    Ok(json!({
        "rule": MERGE_GUARD,
        "repository": repository,
        "hook": {
            "present": hook.is_some(),
            "unchanged": unchanged,
            "registered": registered(root),
        },
        "server": server,
        "mode": remote.map(|(probed, _)| mode_name(mode_of(probed))),
        "probed_at": remote.map(|(_, at)| at),
    }))
}
