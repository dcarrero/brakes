//! The server-side protection of a repository's default branch, read through
//! `remote::Api` (`SPEC-merge-guard.md`, Data model), and the mode it earns.
//!
//! Protected means a required status check enforced for everyone (owner decision
//! 2026-10-28): an active ruleset with required checks and no bypass actors, or
//! classic protection with required contexts and `enforce_admins`. `mode_for` is
//! pure so that `doctor` and the hook's light mode can never disagree.
//!
//! Light mode (#695) reads the same evidence through [`probed_mode`]: a cache
//! file per repository, fresh for [`CACHE_TTL`], else one synchronous probe
//! under [`PROBE_BUDGET`] whose result is written atomically. Location and TTL
//! are the owner's decision of 2026-10-28; changing either is ask-first.

use super::Mode;
use crate::remote::{Api, HttpError, decode_response, in_scope, segment};
use crate::{Result, refuse};
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime};

/// How long a probe result stands (decision 2026-10-28).
pub const CACHE_TTL: Duration = Duration::from_secs(15 * 60);
/// The whole probe, every `gh api` read of it, within 30 s.
pub const PROBE_BUDGET: Duration = Duration::from_secs(30);
/// The only host the probe reads, as `remote::Gh` does.
pub const HOST: &str = "github.com";
/// A cache file larger than this is unreadable, hence a miss.
const CACHE_LIMIT: u64 = 64 * 1024;

/// Where the required check is declared, if anywhere.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Kind {
    Ruleset,
    Classic,
    None,
}

/// What the server says about the default branch.
#[derive(Clone, Debug, PartialEq)]
pub struct Protection {
    pub kind: Kind,
    /// Required status check names, in the server's order, without duplicates.
    pub required: Vec<String>,
    /// Classic `enforce_admins.enabled`; rulesets express this as no bypass actors.
    pub admins_enforced: bool,
    /// Ruleset bypass actors as `<actor_type> [<actor_id>]`.
    pub bypass_actors: Vec<String>,
    /// The server answered HTTP 403 naming the plan: no protection is possible.
    pub plan_forbids: bool,
}

impl Protection {
    fn none(plan_forbids: bool) -> Self {
        Protection {
            kind: Kind::None,
            required: Vec::new(),
            admins_enforced: false,
            bypass_actors: Vec::new(),
            plan_forbids,
        }
    }

    /// The evidence `doctor` prints after the mode.
    pub fn evidence(&self) -> String {
        let required = self.required.join(", ");
        match self.kind {
            Kind::None if self.plan_forbids => "no server-side protection (HTTP 403: plan does not allow it on a private repository); the hook is the only barrier".to_owned(),
            Kind::None => "no server-side protection (the default branch is not protected); the hook is the only barrier".to_owned(),
            Kind::Classic | Kind::Ruleset if self.required.is_empty() => {
                "no required checks on the default branch; the hook is the only barrier".to_owned()
            }
            Kind::Classic if self.admins_enforced => {
                format!("classic protection, required: {required}, admins enforced")
            }
            Kind::Classic => format!(
                "required: {required}, admins not enforced (an admin can merge on red; ask the owner to enforce)"
            ),
            Kind::Ruleset if self.bypass_actors.is_empty() => {
                format!("ruleset protection, required: {required}, no bypass actors")
            }
            Kind::Ruleset => format!(
                "ruleset protection, required: {required}, bypass actors: {} (they can merge on red; ask the owner to remove them)",
                self.bypass_actors.join(", ")
            ),
        }
    }
}

/// `light` only when the server enforces a required check for everyone.
pub fn mode_for(protection: &Protection) -> Mode {
    let protected = !protection.required.is_empty()
        && match protection.kind {
            Kind::Ruleset => protection.bypass_actors.is_empty(),
            Kind::Classic => protection.admins_enforced,
            Kind::None => false,
        };
    if protected { Mode::Light } else { Mode::Full }
}

/// Reads the default branch's rulesets, then its classic protection. Only GETs;
/// a 403 naming the plan is evidence of no protection, any other failure is an error.
pub fn read(api: &dyn Api, repository: &str) -> Result<Protection> {
    let base = format!("repos/{repository}");
    let metadata = api.get(&base)?;
    let Some(branch) = metadata["default_branch"]
        .as_str()
        .filter(|b| !b.is_empty())
    else {
        return refuse("the default branch is unknown");
    };
    let branch = segment(branch);
    let rules = match api.get(&format!("{base}/rules/branches/{branch}")) {
        Ok(rules) => rules,
        Err(error) if plan_forbids(error.as_ref()) => Value::Array(Vec::new()),
        Err(error) => return Err(error),
    };
    if let Some(protection) = ruleset(api, &base, &rules)? {
        return Ok(protection);
    }
    let classic = match api.get(&format!("{base}/branches/{branch}/protection")) {
        Ok(classic) => classic,
        Err(error) if plan_forbids(error.as_ref()) => return Ok(Protection::none(true)),
        Err(error)
            if error
                .downcast_ref::<HttpError>()
                .is_some_and(|e| e.status == 404 && e.message == "Branch not protected") =>
        {
            return Ok(Protection::none(false));
        }
        Err(error) => return Err(error),
    };
    let checks = &classic["required_status_checks"];
    let names = checks["contexts"]
        .as_array()
        .into_iter()
        .flatten()
        .chain(
            checks["checks"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|c| &c["context"]),
        )
        .filter_map(Value::as_str);
    Ok(Protection {
        kind: Kind::Classic,
        required: unique(names),
        admins_enforced: classic["enforce_admins"]["enabled"].as_bool() == Some(true),
        bypass_actors: Vec::new(),
        plan_forbids: false,
    })
}

/// The active rulesets requiring status checks on the branch, if any: their
/// checks and bypass actors united. Unreadable bypass actors are an error.
fn ruleset(api: &dyn Api, base: &str, rules: &Value) -> Result<Option<Protection>> {
    let rules: Vec<&Value> = rules
        .as_array()
        .ok_or("the branch rules are not a list")?
        .iter()
        .filter(|r| r["type"] == "required_status_checks")
        .collect();
    let mut ids: Vec<u64> = rules
        .iter()
        .map(|r| {
            r["ruleset_id"]
                .as_u64()
                .ok_or("a branch rule names no ruleset")
        })
        .collect::<std::result::Result<_, _>>()?;
    ids.sort_unstable();
    ids.dedup();
    let mut active = Vec::new();
    let mut bypass = Vec::new();
    for id in ids {
        let detail = api.get(&format!("{base}/rulesets/{id}"))?;
        if detail["enforcement"] != "active" {
            continue;
        }
        let Some(actors) = detail["bypass_actors"].as_array() else {
            return refuse(format!(
                "the bypass actors of ruleset {id} are not readable"
            ));
        };
        active.push(id);
        bypass.extend(actors.iter().map(|a| {
            let kind = a["actor_type"].as_str().unwrap_or("unknown");
            match a["actor_id"].as_u64() {
                Some(id) => format!("{kind} {id}"),
                None => kind.to_owned(),
            }
        }));
    }
    let names = rules
        .iter()
        .filter(|r| {
            r["ruleset_id"]
                .as_u64()
                .is_some_and(|id| active.contains(&id))
        })
        .flat_map(|r| {
            r["parameters"]["required_status_checks"]
                .as_array()
                .into_iter()
                .flatten()
        })
        .filter_map(|c| c["context"].as_str());
    let required = unique(names);
    if required.is_empty() {
        return Ok(None);
    }
    Ok(Some(Protection {
        kind: Kind::Ruleset,
        required,
        admins_enforced: false,
        bypass_actors: unique(bypass.iter().map(String::as_str)),
        plan_forbids: false,
    }))
}

fn plan_forbids(error: &(dyn std::error::Error + 'static)) -> bool {
    error
        .downcast_ref::<HttpError>()
        .is_some_and(|e| e.status == 403 && e.message.starts_with("Upgrade to GitHub"))
}

fn unique<'a>(names: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut seen = Vec::new();
    for name in names {
        if !seen.iter().any(|s: &String| s == name) {
            seen.push(name.to_owned());
        }
    }
    seen
}

/// The server's evidence for `repository` on github.com as light mode reads it:
/// the cached probe within [`CACHE_TTL`], else a fresh probe whose result is
/// cached. `None` (no evidence, so `full`) for a repository outside the
/// personal scope, without a cache location, or when the probe fails; a
/// failed probe writes nothing.
pub fn probed_mode(repository: &str) -> Option<Mode> {
    let path = cache_path(repository)?;
    let now = SystemTime::now();
    let protected = match read_cache(&path, now) {
        Some(protected) => protected,
        None => {
            let api = Probe {
                deadline: Instant::now() + PROBE_BUDGET,
            };
            let protection = read(&api, repository).ok()?;
            let protected = mode_for(&protection) == Mode::Light;
            write_cache(&path, now, protected, &protection.evidence());
            protected
        }
    };
    Some(if protected { Mode::Light } else { Mode::Full })
}

/// `${XDG_CACHE_HOME:-$HOME/.cache}/brakes/merge-guard/github.com/<owner>/<repo>.json`.
/// Only absolute bases count (XDG base directories), so a relative variable
/// can never place the cache in the working tree.
fn cache_path(repository: &str) -> Option<PathBuf> {
    let (owner, name) = repository.split_once('/')?;
    if !in_scope(repository) || [owner, name].iter().any(|s| s.starts_with('.')) {
        return None;
    }
    let absolute = |var: &str| {
        std::env::var_os(var)
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
    };
    let base = absolute("XDG_CACHE_HOME").or_else(|| absolute("HOME").map(|h| h.join(".cache")))?;
    Some(
        base.join("brakes/merge-guard")
            .join(HOST)
            .join(owner)
            .join(format!("{name}.json")),
    )
}

/// `protected` from a cache file probed within the TTL before `now`; anything
/// else (missing, too large, not the shape, stale or dated in the future) is a miss.
fn read_cache(path: &Path, now: SystemTime) -> Option<bool> {
    if std::fs::metadata(path).ok()?.len() > CACHE_LIMIT {
        return None;
    }
    let cache: Value = serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()?;
    cache["evidence"].as_str()?;
    let protected = cache["protected"].as_bool()?;
    let probed_at = DateTime::parse_from_rfc3339(cache["probed_at"].as_str()?).ok()?;
    let age = now.duration_since(SystemTime::from(probed_at)).ok()?;
    (age < CACHE_TTL).then_some(protected)
}

/// Writes the cache through a temp file and a rename, so a reader never sees
/// half a file. A failure leaves no cache: the next merge probes again.
fn write_cache(path: &Path, now: SystemTime, protected: bool, evidence: &str) {
    let Some(dir) = path.parent() else { return };
    let body = json!({
        "probed_at": DateTime::<Utc>::from(now).to_rfc3339_opts(SecondsFormat::Secs, true),
        "protected": protected,
        "evidence": evidence,
    });
    let temp = dir.join(format!(
        ".{}.{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("cache"),
        std::process::id()
    ));
    let written = std::fs::create_dir_all(dir)
        .and_then(|()| std::fs::write(&temp, body.to_string()))
        .and_then(|()| std::fs::rename(&temp, path));
    if written.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
}

/// `gh api` GETs for the probe, all within one deadline. `AGENTIC_TEST_GH`
/// replaces `gh` as for `gh pr checks`; the environment hygiene is `remote::Gh`'s.
struct Probe {
    deadline: Instant,
}

impl Api for Probe {
    fn get(&self, path: &str) -> Result<Value> {
        let gh = std::env::var_os("AGENTIC_TEST_GH").unwrap_or_else(|| "gh".into());
        let mut command = Command::new(gh);
        command
            .args([
                "api",
                "--include",
                "--hostname",
                HOST,
                "--method",
                "GET",
                path,
            ])
            .env_remove("GH_REPO")
            .env_remove("GH_HOST")
            .env_remove("GH_DEBUG");
        let out = super::checks::run(command, self.deadline, "the protection probe")?;
        decode_response(out.status.success(), &out.stdout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> SystemTime {
        SystemTime::from(DateTime::parse_from_rfc3339(text).unwrap())
    }

    #[test]
    fn the_cache_is_fresh_for_fifteen_minutes_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("o/r.json");
        write_cache(
            &path,
            at("2026-10-29T10:00:00Z"),
            true,
            "classic protection",
        );
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&text).unwrap(),
            json!({"probed_at": "2026-10-29T10:00:00Z", "protected": true,
                   "evidence": "classic protection"})
        );
        assert_eq!(read_cache(&path, at("2026-10-29T10:00:00Z")), Some(true));
        assert_eq!(read_cache(&path, at("2026-10-29T10:14:59Z")), Some(true));
        assert_eq!(read_cache(&path, at("2026-10-29T10:15:00Z")), None);
        assert_eq!(read_cache(&path, at("2026-10-29T09:59:59Z")), None);
        std::fs::write(&path, " ".repeat(CACHE_LIMIT as usize + 1)).unwrap();
        assert_eq!(read_cache(&path, at("2026-10-29T10:00:00Z")), None);
    }

    #[test]
    fn only_personal_repositories_have_a_cache_path() {
        for repository in [
            "org/other-app",
            "example-owner/..",
            "example-owner",
            "a/b/c",
        ] {
            assert_eq!(cache_path(repository), None, "{repository}");
        }
    }
}
