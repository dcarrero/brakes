//! The person's approval through the agent host's own prompt (coordinator for
//! the owner, 2026-10-30, #1146; decision "The person approves `human-approved`
//! through the agent host's own prompt"). One canonical command is routed to the
//! person instead of denied, and only where the host is known to prompt the
//! person whatever the permission mode: every other route keeps the #941 deny
//! (`labels.rs`, `SPEC-merge-guard.md`).
//!
//! The barrier is the host's explicit ask rule, which the model cannot answer;
//! this module only narrows what reaches it to one readable shape.
use std::path::{Path, PathBuf};

use serde_json::Value;

/// The Claude Code rule the project's `.claude/settings.json` carries under
/// `permissions.ask`. A `*` may stand anywhere in a Bash rule and the rule
/// matches every subcommand of a compound command
/// (https://code.claude.com/docs/en/permissions.md, "Wildcard patterns" and
/// "Compound commands", read 2026-10-30); the guard denies every match but the
/// canonical form, so the prompt only ever shows that form.
pub const APPROVAL_ASK_RULE: &str = "Bash(gh pr edit * --add-label human-approved)";

/// Whether an agent host prompts the person for an explicit ask rule in every
/// permission mode, with where that was read. Only a host whose answer is
/// `true` gets the rule, and the guard opens the route only under Claude Code.
pub struct HostPrompt {
    pub host: &'static str,
    pub unconditional: bool,
    pub sources: &'static [&'static str],
    pub verified: &'static str,
}

/// The facts per agent host (read 2026-10-30, documentation only; the real
/// session proof under `bypassPermissions` is pending after #1146 merges).
pub const HOST_PROMPTS: [HostPrompt; 3] = [
    // "Claude Code doesn't auto-approve the following in any mode, including
    // `bypassPermissions`: … Tools matched by an explicit ask rule"; "Rules are
    // evaluated in order: deny, then ask, then allow"; "a matching ask rule still
    // prompts even when the hook returned "allow" or "ask""; under `claude -p`
    // "the few calls that would still prompt are denied instead", and `dontAsk`
    // denies calls matching explicit ask rules.
    HostPrompt {
        host: "claude-code",
        unconditional: true,
        sources: &[
            "https://code.claude.com/docs/en/permission-modes.md",
            "https://code.claude.com/docs/en/permissions.md",
            "https://code.claude.com/docs/en/hooks.md",
        ],
        verified: "2026-10-30",
    },
    // Rules decide `allow`, `prompt` or `forbidden`; the page does not say what
    // `prompt` does under `approval_policy = never` or
    // `--dangerously-bypass-approvals-and-sandbox`: not shown unconditional.
    HostPrompt {
        host: "codex",
        unconditional: false,
        sources: &["https://learn.chatgpt.com/docs/agent-configuration/rules"],
        verified: "2026-10-30",
    },
    // `--auto` "automatically approve[s] permission requests that are not
    // explicitly denied", `opencode run` included: `ask` is not unconditional.
    HostPrompt {
        host: "opencode",
        unconditional: false,
        sources: &["https://opencode.ai/docs/permissions/"],
        verified: "2026-10-30",
    },
];

/// The whole command is `gh pr edit <number> [--repo <owner>/<repo>] --add-label
/// human-approved`, single-spaced, with nothing before, after or around it.
pub fn canonical(command: &str) -> bool {
    let words: Vec<&str> = command.split(' ').collect();
    match words.as_slice() {
        ["gh", "pr", "edit", number, "--add-label", "human-approved"] => pr_number(number),
        [
            "gh",
            "pr",
            "edit",
            number,
            "--repo",
            repo,
            "--add-label",
            "human-approved",
        ] => pr_number(number) && repository(repo),
        _ => false,
    }
}

/// Digits, no leading zero.
fn pr_number(word: &str) -> bool {
    !word.is_empty() && !word.starts_with('0') && word.bytes().all(|b| b.is_ascii_digit())
}

/// `owner/repo` in GitHub's name characters.
fn repository(word: &str) -> bool {
    let Some((owner, name)) = word.split_once('/') else {
        return false;
    };
    let ok = |part: &str, extra: &[u8]| {
        !part.is_empty()
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || extra.contains(&b))
    };
    ok(owner, b"") && ok(name, b"._") && name != "." && name != ".."
}

/// The real interactive session in which the person saw the prompt for the
/// canonical form (#1152). `None` until the controlled experiment of #1152
/// records one: a session under `bypassPermissions` set the label with no prompt
/// shown in a target repository, so the route stays closed until then.
pub const PROMPT_EVIDENCE: Option<&str> = None;

/// Claude Code's managed settings files, which outrank every other layer.
pub const MANAGED_SETTINGS: [&str; 2] = [
    "/Library/Application Support/ClaudeCode/managed-settings.json",
    "/etc/claude-code/managed-settings.json",
];

/// Whether the person will be prompted for the canonical command: a real
/// session proved the prompt (`evidence`), the hook runs under Claude Code
/// (`CLAUDE_PROJECT_DIR` absolute), outside CI, the project's settings carry the
/// exact ask rule, and no layer the guard can see answers prompts for the
/// person ([`answering_layer`]). `env` reads one variable; `mode` is the hook
/// payload's `permission_mode`; `managed` are the managed settings files.
pub fn person_prompts(
    env: &dyn Fn(&str) -> Option<String>,
    evidence: Option<&str>,
    mode: Option<&str>,
    managed: &[&Path],
) -> bool {
    if evidence.is_none()
        || env("CI").is_some()
        || env("GITHUB_ACTIONS").is_some()
        || app_session(env)
    {
        return false;
    }
    let Some(project) = env("CLAUDE_PROJECT_DIR") else {
        return false;
    };
    let project = Path::new(&project);
    if !project.is_absolute() {
        return false;
    }
    let registered = std::fs::read_to_string(project.join(".claude/settings.json"))
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .and_then(|settings| {
            settings["permissions"]["ask"]
                .as_array()
                .map(|rules| rules.iter().any(|r| r.as_str() == Some(APPROVAL_ASK_RULE)))
        })
        .unwrap_or(false);
    registered && answering_layer(env, project, mode, managed).is_none()
}

/// The prefix GitHub gives installation access tokens of a GitHub App ("GitHub
/// issues tokens that begin with a prefix to indicate the token's type": `ghs_`,
/// https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github,
/// read 2026-11-01).
pub const APP_TOKEN_PREFIX: &str = "ghs_";

/// Whether the session runs on the agents' GitHub App (#1255): `GH_TOKEN` or
/// `GITHUB_TOKEN` is an installation token. A label the session adds is then the
/// App's, which the required check never counts, so the route of #1146 is closed
/// for it whatever the evidence: retiring the route needs no other change than
/// switching the sessions to the App.
pub fn app_session(env: &dyn Fn(&str) -> Option<String>) -> bool {
    ["GH_TOKEN", "GITHUB_TOKEN"]
        .iter()
        .any(|name| env(name).is_some_and(|token| token.starts_with(APP_TOKEN_PREFIX)))
}

/// The first layer the guard can see that may answer a prompt for the person
/// (#1152), named for the record: a bypass mode in the payload, or a settings
/// file (managed, user, project, local) that exists and has a non-empty
/// `hooks.PermissionRequest`, `skipDangerousModePermissionPrompt: true` or
/// `permissions.defaultMode` `bypassPermissions`, or cannot be read. A missing
/// file is no layer.
pub fn answering_layer(
    env: &dyn Fn(&str) -> Option<String>,
    project: &Path,
    mode: Option<&str>,
    managed: &[&Path],
) -> Option<String> {
    if mode == Some("bypassPermissions") {
        return Some("permission_mode bypassPermissions".to_owned());
    }
    let user = env("CLAUDE_CONFIG_DIR")
        .map(PathBuf::from)
        .or_else(|| env("HOME").map(|home| Path::new(&home).join(".claude")))
        .map(|dir| dir.join("settings.json"));
    let files = managed
        .iter()
        .map(|path| path.to_path_buf())
        .chain(user)
        .chain([
            project.join(".claude/settings.json"),
            project.join(".claude/settings.local.json"),
        ]);
    for file in files {
        let text = match std::fs::read_to_string(&file) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Some(format!("{} unreadable", file.display())),
        };
        let Ok(settings) = serde_json::from_str::<Value>(&text) else {
            return Some(format!("{} unreadable", file.display()));
        };
        let hooks = settings["hooks"]["PermissionRequest"]
            .as_array()
            .is_some_and(|entries| !entries.is_empty());
        let skip = settings["skipDangerousModePermissionPrompt"] == Value::Bool(true);
        let bypass = settings["permissions"]["defaultMode"] == "bypassPermissions";
        if hooks || skip || bypass {
            return Some(file.display().to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_canonical_shape_is_canonical() {
        assert!(canonical("gh pr edit 12 --add-label human-approved"));
        assert!(canonical(
            "gh pr edit 3 --repo a-b/c.d_e --add-label human-approved"
        ));
        for command in [
            "gh pr edit 0 --add-label human-approved",
            "gh pr edit 12 --repo o/.. --add-label human-approved",
            "gh pr edit 12 --repo o_x/r --add-label human-approved",
            "gh pr edit 12 --repo /r --add-label human-approved",
            "gh pr edit 12 --add-label human-approved\n",
            "gh pr edit 12\t--add-label human-approved",
        ] {
            assert!(!canonical(command), "{command:?}");
        }
    }

    /// A project with the ask rule, a user directory, and the environment of a
    /// Claude Code hook outside CI pointing at both.
    struct Session {
        _dir: tempfile::TempDir,
        project: std::path::PathBuf,
        home: std::path::PathBuf,
    }

    impl Session {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let project = dir.path().join("project");
            let home = dir.path().join("home");
            std::fs::create_dir_all(project.join(".claude")).unwrap();
            std::fs::create_dir_all(home.join(".claude")).unwrap();
            let session = Session {
                _dir: dir,
                project,
                home,
            };
            session.write(
                ".claude/settings.json",
                &serde_json::json!({"permissions": {"ask": [APPROVAL_ASK_RULE]}}).to_string(),
            );
            session
        }

        /// Writes `text` at `path` under the project.
        fn write(&self, path: &str, text: &str) {
            std::fs::write(self.project.join(path), text).unwrap();
        }

        fn env(&self) -> impl Fn(&str) -> Option<String> + '_ {
            move |name| match name {
                "CLAUDE_PROJECT_DIR" => Some(self.project.to_str().unwrap().to_owned()),
                "HOME" => Some(self.home.to_str().unwrap().to_owned()),
                _ => None,
            }
        }

        fn prompts(&self, evidence: Option<&str>, mode: Option<&str>, managed: &[&Path]) -> bool {
            person_prompts(&self.env(), evidence, mode, managed)
        }
    }

    const PROVEN: Option<&str> = Some("test session");

    #[test]
    fn the_route_is_closed_until_a_real_session_proves_the_prompt() {
        assert_eq!(PROMPT_EVIDENCE, None);
        let session = Session::new();
        assert!(!session.prompts(None, None, &[]));
        assert!(!session.prompts(PROMPT_EVIDENCE, Some("default"), &[]));
        // With evidence and nothing that answers for the person, it opens.
        assert!(session.prompts(PROVEN, None, &[]));
        assert!(session.prompts(PROVEN, Some("default"), &[]));
        assert!(session.prompts(PROVEN, Some("acceptEdits"), &[]));
    }

    /// #1255: a session whose token is an App installation token (`ghs_`) acts as
    /// the agents' App, and a label it adds never counts, so the route stays closed
    /// whatever the evidence; a person's token leaves it as before.
    #[test]
    fn an_app_session_never_prompts() {
        let session = Session::new();
        for (name, token) in [("GH_TOKEN", "ghs_abc123"), ("GITHUB_TOKEN", "ghs_abc123")] {
            let env = |var: &str| {
                if var == name {
                    Some(token.to_owned())
                } else {
                    session.env()(var)
                }
            };
            assert!(app_session(&env), "{name}");
            assert!(!person_prompts(&env, PROVEN, None, &[]), "{name}");
        }
        for token in [
            "ghp_abc",
            "github_pat_abc",
            "gho_abc",
            "ghu_abc",
            "",
            "xghs_abc",
        ] {
            let env = |var: &str| {
                if var == "GH_TOKEN" {
                    Some(token.to_owned())
                } else {
                    session.env()(var)
                }
            };
            assert!(!app_session(&env), "{token}");
            assert!(person_prompts(&env, PROVEN, None, &[]), "{token}");
        }
    }

    #[test]
    fn answering_layers_close_the_route() {
        let hook = serde_json::json!({"hooks": {"PermissionRequest": [
            {"matcher": "*", "hooks": [{"type": "command", "command": "answer"}]}
        ]}})
        .to_string();
        let rule_and = |extra: serde_json::Value| {
            let mut settings = serde_json::json!({"permissions": {"ask": [APPROVAL_ASK_RULE]}});
            for (key, value) in extra.as_object().unwrap() {
                if key == "permissions" {
                    for (k, v) in value.as_object().unwrap() {
                        settings["permissions"][k] = v.clone();
                    }
                } else {
                    settings[key] = value.clone();
                }
            }
            settings.to_string()
        };
        // The project, local and user layers, one answering setting each.
        for (path, text) in [
            (
                ".claude/settings.json",
                rule_and(serde_json::from_str(&hook).unwrap()),
            ),
            (".claude/settings.local.json", hook.clone()),
            (
                ".claude/settings.local.json",
                serde_json::json!({"skipDangerousModePermissionPrompt": true}).to_string(),
            ),
            (
                ".claude/settings.json",
                rule_and(serde_json::json!({"permissions": {"defaultMode": "bypassPermissions"}})),
            ),
            (".claude/settings.local.json", "{\"hooks\": ".to_owned()),
        ] {
            let session = Session::new();
            session.write(path, &text);
            assert!(!session.prompts(PROVEN, None, &[]), "{path}: {text}");
        }
        for text in [
            hook.clone(),
            serde_json::json!({"skipDangerousModePermissionPrompt": true}).to_string(),
            serde_json::json!({"permissions": {"defaultMode": "bypassPermissions"}}).to_string(),
            "not json".to_owned(),
        ] {
            let session = Session::new();
            std::fs::write(session.home.join(".claude/settings.json"), &text).unwrap();
            assert!(!session.prompts(PROVEN, None, &[]), "user: {text}");
        }
        // CLAUDE_CONFIG_DIR replaces ~/.claude for the user layer.
        let session = Session::new();
        let config = session.home.join("config");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(config.join("settings.json"), &hook).unwrap();
        let env = |name: &str| match name {
            "CLAUDE_CONFIG_DIR" => Some(config.to_str().unwrap().to_owned()),
            other => session.env()(other),
        };
        assert!(!person_prompts(&env, PROVEN, None, &[]));
        // The managed layer.
        let session = Session::new();
        let managed = session.home.join("managed-settings.json");
        std::fs::write(&managed, &hook).unwrap();
        assert!(!session.prompts(PROVEN, None, &[managed.as_path()]));
        let absent = session.home.join("absent.json");
        assert!(session.prompts(PROVEN, None, &[absent.as_path()]));
        // The session's own mode, from the hook payload.
        let session = Session::new();
        assert!(!session.prompts(PROVEN, Some("bypassPermissions"), &[]));
        // An empty PermissionRequest list, `false` flags and other modes answer nothing.
        session.write(
            ".claude/settings.local.json",
            &serde_json::json!({"hooks": {"PermissionRequest": [], "PreToolUse": [{"matcher": "Bash"}]},
                "skipDangerousModePermissionPrompt": false,
                "permissions": {"defaultMode": "default"}})
            .to_string(),
        );
        assert!(session.prompts(PROVEN, None, &[]));
    }

    #[test]
    fn only_hosts_with_an_unconditional_prompt_get_the_route() {
        let open: Vec<_> = HOST_PROMPTS
            .iter()
            .filter(|h| h.unconditional)
            .map(|h| h.host)
            .collect();
        assert_eq!(open, ["claude-code"]);
        assert!(HOST_PROMPTS.iter().all(|h| !h.sources.is_empty()));
    }
}
