//! `brakes guard pre-bash`, the never-merge-on-red hook, with a fake `gh`.
//!
//! The 26 non-wrapper tests are copied from `orchestration/tests/guard.rs` (frozen)
//! with their assertions unchanged; the wrapper tests move with the wrapper (#692).

mod common;
mod configured;

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use brakes::guard::approval::PROMPT_EVIDENCE;
use serde_json::{Value, json};

struct Fixture {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    calls: PathBuf,
    fake: PathBuf,
}

fn git(dir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run git");
    assert!(status.success(), "git {args:?}");
}

/// The deny reason of a hook run, or None when it allows the command.
fn decision(out: std::process::Output) -> Option<String> {
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    if stdout.trim().is_empty() {
        return None;
    }
    let value: Value = serde_json::from_str(&stdout).unwrap();
    let output = &value["hookSpecificOutput"];
    assert_eq!(output["hookEventName"], "PreToolUse");
    assert_eq!(output["permissionDecision"], "deny");
    Some(
        output["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .to_owned(),
    )
}

impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let fixture = Fixture {
            calls: root.join("calls.log"),
            fake: root.join("gh"),
            root,
            _tmp: tmp,
        };
        // The session's own checkout and another project, as two clones.
        fixture.repo("session", "https://github.com/me/session.git");
        fixture.repo("other", "git@github.com:org/other-app.git");
        fixture.set_checks(&json!([{"name": "test / verify", "bucket": "pass"}]), 0);
        fixture
    }

    fn repo(&self, name: &str, origin: &str) -> PathBuf {
        let dir = self.root.join(name);
        fs::create_dir_all(&dir).unwrap();
        git(&dir, &["init", "-q"]);
        git(&dir, &["remote", "add", "origin", origin]);
        dir
    }

    fn write_fake(&self, body: &str) {
        common::write_executable(&self.fake, &format!("#!/bin/sh\n{body}"));
    }

    fn set_checks(&self, checks: &Value, exit_code: i32) {
        self.write_fake(&format!(
            "echo \"$@\" >> '{}'\necho '{checks}'\nexit {exit_code}\n",
            self.calls.display()
        ));
    }

    /// Answers per repository: red for org/other-app, green for anything else.
    fn red_only_in_other(&self) {
        self.write_fake(&format!(
            "echo \"$@\" >> '{}'\ncase \"$*\" in\n  *org/other-app*) echo '[{{\"name\":\"build\",\"bucket\":\"fail\"}}]';;\n  *) echo '[{{\"name\":\"build\",\"bucket\":\"pass\"}}]';;\nesac\n",
            self.calls.display()
        ));
    }

    fn calls(&self) -> String {
        fs::read_to_string(&self.calls).unwrap_or_default()
    }

    fn run(&self, payload: &str) -> Option<String> {
        self.run_with(payload, None)
    }

    fn run_with(&self, payload: &str, gh_repo: Option<&str>) -> Option<String> {
        let vars: Vec<_> = gh_repo.map(|repo| ("GH_REPO", repo)).into_iter().collect();
        self.run_env(payload, &vars)
    }

    /// Runs the hook with `vars` added to a hermetic environment.
    fn run_env(&self, payload: &str, vars: &[(&str, &str)]) -> Option<String> {
        decision(self.output(payload, vars))
    }

    /// The hook's whole output, stderr included, in the hermetic environment.
    fn output(&self, payload: &str, vars: &[(&str, &str)]) -> std::process::Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_brakes"));
        command
            .args(["guard", "pre-bash"])
            .env("AGENTIC_TEST_GH", &self.fake)
            .env("GIT_CEILING_DIRECTORIES", &self.root)
            .env("HOME", &self.root)
            .env_remove("AGENTIC_MERGE_GUARD_MODE")
            .env_remove("XDG_CACHE_HOME")
            .env_remove("GH_HOST")
            .env_remove("GH_REPO")
            // The approval route (#1146) opens only for a Claude Code project
            // outside CI; every test states those itself.
            .env_remove("CLAUDE_PROJECT_DIR")
            .env_remove("CI")
            .env_remove("GITHUB_ACTIONS")
            // An App installation token closes the route (#1255); every test
            // that wants one states it.
            .env_remove("GH_TOKEN")
            .env_remove("GITHUB_TOKEN")
            .envs(vars.iter().copied());
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("run built CLI");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(payload.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    /// Runs the guard as a session whose directory is the `session` clone.
    fn guard(&self, command: &str) -> Option<String> {
        let payload = json!({
            "tool_input": {"command": command},
            "cwd": self.root.join("session"),
        });
        self.run(&payload.to_string())
    }

    /// As `guard`, with `AGENTIC_MERGE_GUARD_MODE` set to `mode`.
    fn guard_in_mode(&self, command: &str, mode: &str) -> Option<String> {
        let payload = json!({
            "tool_input": {"command": command},
            "cwd": self.root.join("session"),
        });
        self.run_env(&payload.to_string(), &[("AGENTIC_MERGE_GUARD_MODE", mode)])
    }
}

#[test]
fn merge_allowed_only_when_every_check_is_pass_or_skipping() {
    let f = Fixture::new();
    f.set_checks(
        &json!([{"name": "build", "bucket": "pass"},
                {"name": "Rust (linux x86_64)", "bucket": "skipping"}]),
        0,
    );
    assert_eq!(f.guard("gh pr merge 274 --squash"), None);
    assert!(
        f.calls()
            .contains("pr checks 274 --repo me/session --json name,bucket"),
        "{}",
        f.calls()
    );
}

#[test]
fn merge_denied_on_fail_cancel_or_pending() {
    let f = Fixture::new();
    for bucket in ["fail", "cancel", "pending"] {
        f.set_checks(
            &json!([{"name": "build", "bucket": "pass"},
                    {"name": "Rust (linux)", "bucket": bucket}]),
            8,
        );
        let reason = f.guard("gh pr merge 274 --squash --subject 'x y'").unwrap();
        assert!(
            reason.contains(&format!("Rust (linux): {bucket}")),
            "{reason}"
        );
    }
}

#[test]
fn merge_denied_without_checks_or_when_gh_fails() {
    let f = Fixture::new();
    f.set_checks(&json!([]), 0);
    assert!(
        f.guard("gh pr merge --squash")
            .unwrap()
            .contains("No CI checks")
    );
    f.write_fake("echo boom >&2\nexit 1\n");
    let reason = f.guard("gh pr merge 1").unwrap();
    assert!(reason.contains("merge guard failed"), "{reason}");
    assert!(reason.contains("boom"), "{reason}");
}

#[test]
fn selector_and_repo_are_passed_to_checks() {
    let f = Fixture::new();
    f.guard("GH_TOKEN=x gh pr merge --subject 'a b' feature-x -R owner/repo --squash");
    assert!(
        f.calls()
            .contains("pr checks feature-x --repo owner/repo --json name,bucket"),
        "{}",
        f.calls()
    );
}

#[test]
fn admin_merge_api_merge_and_protection_changes_are_denied() {
    let f = Fixture::new();
    assert!(
        f.guard("gh pr merge 3 --admin --squash")
            .unwrap()
            .contains("--admin")
    );
    assert!(
        f.guard("gh api -X PUT repos/o/r/pulls/3/merge")
            .unwrap()
            .contains("gh api")
    );
    for command in [
        "gh api -X DELETE repos/o/r/branches/main/protection",
        "gh api --method PUT repos/o/r/branches/main/protection --input p.json",
        "gh api repos/o/r/branches/main/protection/enforce_admins -X DELETE",
        "cd ../other && gh api -X PUT repos/{owner}/{repo}/pulls/3/merge",
    ] {
        let reason = f.guard(command).unwrap();
        assert!(
            reason.contains("owner's to change") || reason.contains("gh api"),
            "{command}: {reason}"
        );
    }
    assert!(!f.calls().contains("checks"), "{}", f.calls());
}

#[test]
fn ruleset_changes_are_denied_in_both_modes() {
    let f = Fixture::new();
    let ruleset_change = "Rulesets on this repository are the owner's to change. They enforce \
                          the rule never to merge on red; ask the owner instead.";
    for mode in [None, Some("full"), Some("light")] {
        for command in [
            "gh api -X POST repos/o/r/rulesets --input r.json",
            "gh api --method PUT repos/o/r/rulesets/12",
            "gh api -X DELETE orgs/o/rulesets/3",
            "gh api repos/{owner}/{repo}/rulesets/12 --method=PATCH -f enforcement=disabled",
        ] {
            let reason = match mode {
                None => f.guard(command),
                Some(mode) => f.guard_in_mode(command, mode),
            };
            assert_eq!(
                reason.as_deref(),
                Some(ruleset_change),
                "{command} in {mode:?}"
            );
        }
    }
    assert_eq!(f.guard("gh api repos/o/r/rulesets"), None);
    assert_eq!(f.guard("gh api orgs/o/rulesets/3 -X GET"), None);
    assert_eq!(f.guard("gh ruleset list"), None);
    assert_eq!(f.guard("gh api -X POST repos/o/r/rulesets-notes"), None);
    assert!(!f.calls().contains("checks"), "{}", f.calls());
}

const APPLY_REMOTE: &str = "Agent sessions may not run `brakes apply --remote` (decision \
                            \"Installer applies repository settings, rulesets, environments and \
                            branch protection\", 2026-10-28, #848); the owner runs it by hand.";
const APPLY_UNKNOWN: &str = "The merge guard cannot tell whether this command runs `brakes \
                             apply --remote`, so it refuses it; spell the arguments out, and leave \
                             `apply --remote` to the owner, who runs it by hand.";

#[test]
fn apply_remote_is_denied_in_both_modes() {
    let f = Fixture::new();
    for mode in [None, Some("full"), Some("light")] {
        for command in [
            "brakes apply . --remote",
            "brakes --remote apply .",
            "brakes apply --remote=yes .",
            "/usr/local/bin/brakes apply ~/aps --remote",
            "./orchestration/target/debug/brakes apply . --remote",
            "\"$HOME/.cargo/bin/brakes\" apply . --remote",
            "cargo run -- apply . --remote",
            "cargo run --manifest-path orchestration/Cargo.toml --locked -p brakes -- apply . --remote",
            "cargo r -q -- --remote apply .",
            "env RUST_LOG=debug brakes apply . --remote",
            "GH_TOKEN=x brakes apply . --remote",
            "command brakes apply . --remote",
            "sh -c 'brakes apply . --remote'",
            "bash -lc \"cd ~/aps && cargo run -- apply . --remote\"",
            "eval 'brakes apply . --remote'",
            "echo $(brakes apply . --remote)",
            "cargo test && brakes apply . --remote",
            "ls; brakes apply . --remote",
            "true | brakes apply . --remote",
            "timeout 600 brakes apply . --remote",
            "timeout 600 cargo run -- apply . --remote",
            "\"$BIN\" apply . --remote",
        ] {
            let reason = match mode {
                None => f.guard(command),
                Some(mode) => f.guard_in_mode(command, mode),
            };
            assert_eq!(
                reason.as_deref(),
                Some(APPLY_REMOTE),
                "{command} in {mode:?}"
            );
        }
    }
    assert!(f.calls().is_empty(), "{}", f.calls());
}

/// The owner's build still refuses `apply --remote` through the binary's former
/// name, which stays installed on machines set up before the rename (#1067).
#[cfg(feature = "setup-core")]
#[test]
fn apply_remote_through_the_former_binary_name_is_denied() {
    let f = Fixture::new();
    for command in [
        "agentic-setup apply . --remote",
        "timeout 600 agentic-setup apply . --remote",
    ] {
        assert_eq!(f.guard(command).as_deref(), Some(APPLY_REMOTE), "{command}");
    }
}

#[test]
fn installer_commands_without_apply_remote_pass() {
    let f = Fixture::new();
    for command in [
        "brakes apply .",
        "brakes plan . --remote",
        "brakes doctor . --remote",
        "brakes doctor \"$PWD\" --remote --json",
        "brakes install . --apply",
        "brakes configure . stack-packs --set apps.web.port=8080 --apply",
        "brakes guard pre-bash",
        "brakes --help",
        "cargo run -- doctor . --remote",
        "cargo run -- apply .",
        "cargo run -- serve --port $PORT",
        "cargo run --bin web -- \"$@\"",
        "cargo test --manifest-path orchestration/Cargo.toml --locked -p brakes",
        "grep -rn brakes docs/",
        "timeout 60 brakes doctor . --remote",
        "git commit -m \"brakes apply --remote is the owner's\"",
        "echo 'brakes apply . --remote'",
        "cat <<'EOF' > note.md\nbrakes apply . --remote\nEOF",
    ] {
        assert_eq!(f.guard(command), None, "{command}");
        assert_eq!(f.guard_in_mode(command, "light"), None, "{command}");
    }
}

#[test]
fn undecidable_installer_arguments_fail_closed() {
    let f = Fixture::new();
    for mode in [None, Some("full"), Some("light")] {
        for command in [
            "brakes \"$@\"",
            "brakes apply . $FLAGS",
            "brakes $OP . --remote",
            "cargo run -- apply . `cat flags`",
            "cargo run -- $OP . --remote",
            "echo . | xargs brakes apply",
            "timeout 9 brakes $OP . --remote",
        ] {
            let reason = match mode {
                None => f.guard(command),
                Some(mode) => f.guard_in_mode(command, mode),
            };
            assert_eq!(
                reason.as_deref(),
                Some(APPLY_UNKNOWN),
                "{command} in {mode:?}"
            );
        }
    }
    let reason = f.guard("brakes apply . --remote 'unterminated").unwrap();
    assert!(reason.contains("merge guard failed"), "{reason}");
}

const LABEL_CHANGE: &str = "The label `human-approved` records a person's approval of a change \
                            to a protected path (workflows, rulesets, CODEOWNERS, the installer \
                            lock, held-out tests); agent sessions may not set, remove or redefine \
                            it. Ask the owner.";
/// #1255: the reason for the canonical form in a session on the agents' App.
const LABEL_APP_SESSION: &str = "This session acts as the agents' GitHub App: a `human-approved` it \
                                 adds never counts, because the required check accepts the label only \
                                 from a person. Add it on GitHub under your own login.";
const LABEL_UNKNOWN: &str = "The merge guard cannot tell whether this command sets \
                             `human-approved`; spell the label out, or ask the owner.";

/// Runs `command` with no mode variable, then with `full` and `light`, and
/// asserts the same decision each time.
fn assert_in_every_mode(f: &Fixture, command: &str, expected: Option<&str>) {
    for mode in [None, Some("full"), Some("light")] {
        let reason = match mode {
            None => f.guard(command),
            Some(mode) => f.guard_in_mode(command, mode),
        };
        assert_eq!(reason.as_deref(), expected, "{command} in {mode:?}");
    }
}

#[test]
fn human_approved_label_writes_are_denied_in_both_modes() {
    let f = Fixture::new();
    fs::write(
        f.root.join("session/labels.json"),
        r#"{"labels":["bug","human-approved"]}"#,
    )
    .unwrap();
    fs::write(
        f.root.join("session/mutation.graphql"),
        "mutation { addLabelsToLabelable(input: {labelableId: \"PR_1\", labelIds: [\"human-approved\"]}) { clientMutationId } }",
    )
    .unwrap();
    for command in [
        "gh pr edit 3 --add-label human-approved",
        "gh pr edit 3 --add-label=human-approved",
        "gh pr edit 3 --add-label bug,human-approved",
        "gh pr edit 3 --add-label \"bug, Human-Approved\"",
        "gh pr edit --remove-label human-approved 3",
        "gh pr edit 3 --add-label human-\"approved\"",
        "gh issue edit 3 --add-label human-approved -R o/r",
        "gh issue edit 3 34 --remove-label=HUMAN-APPROVED",
        "gh -R o/r pr edit 3 --add-label human-approved",
        "gh pr create --title t --body b -l human-approved",
        "gh pr create --label=bug,human-approved",
        "gh pr create -dlhuman-approved",
        "gh label edit human-approved --color ff0000",
        "gh label edit bug --name human-approved",
        "gh label edit bug -n Human-Approved",
        "gh label delete human-approved --yes",
        "gh api -X POST repos/o/r/issues/3/labels -f 'labels[]=human-approved'",
        "gh api repos/{owner}/{repo}/issues/3/labels -F labels[]=human-approved",
        "gh api --method PUT repos/o/r/issues/3/labels --input labels.json",
        "gh api repos/o/r/issues/3/labels -F labels[]=@labels.json",
        "gh api -X DELETE repos/o/r/issues/3/labels/human-approved",
        "gh api -X PATCH repos/o/r/issues/3 -f 'labels[]=human-approved'",
        "gh api -X PATCH repos/o/r/labels/bug -f new_name=human-approved",
        "gh api -X DELETE repos/o/r/labels/human-approved",
        "gh api graphql -F query=@mutation.graphql",
        "gh api graphql -f query='mutation { updateLabel(input: {id: \"L\", name: \"human-approved\"}) { clientMutationId } }'",
        "gh alias set ok 'pr edit --add-label human-approved'",
        "sh -c 'gh pr edit 3 --add-label human-approved'",
        "bash -lc \"cd ~/x && gh pr edit 3 --add-label human-approved\"",
        "eval 'gh pr edit 3 --add-label human-approved'",
        "echo $(gh pr edit 3 --add-label human-approved)",
        "echo \"`gh issue edit 3 --add-label human-approved`\"",
        "cargo test && gh pr edit 3 --add-label human-approved",
        "false || gh issue edit 3 --remove-label human-approved",
        "ls | gh pr edit 3 --add-label human-approved",
        "ls; gh pr edit 3 --add-label human-approved",
        "env GH_TOKEN=x gh pr edit 3 --add-label human-approved",
        "GH_REPO=o/r gh pr edit 3 --add-label human-approved",
        "command gh label delete human-approved --yes",
        "timeout 60 gh pr edit 3 --add-label human-approved",
    ] {
        assert_in_every_mode(&f, command, Some(LABEL_CHANGE));
    }
    assert!(f.calls().is_empty(), "{}", f.calls());
}

#[test]
fn unreadable_label_writes_fail_closed() {
    let f = Fixture::new();
    // Larger than the guard reads: unreadable, so it cannot tell.
    fs::write(f.root.join("session/big.json"), "x".repeat((1 << 20) + 1)).unwrap();
    for command in [
        "gh pr edit \"$N\" --add-label \"$L\"",
        "gh pr edit 3 --add-label $(cat label)",
        "gh pr edit 3 --add-label",
        "gh issue edit 3 --remove-label \"bug,$EXTRA\"",
        "gh pr create -l \"$L\"",
        "gh label edit \"$NAME\" --color 000000",
        "gh label edit bug --name \"$NEW\"",
        "gh label delete \"$L\" --yes",
        "gh api -X POST repos/o/r/issues/3/labels --input -",
        "gh api -X POST repos/o/r/issues/3/labels --input \"$FILE\"",
        "gh api -X POST repos/o/r/issues/3/labels --input missing.json",
        "gh api -X POST repos/o/r/issues/3/labels --input big.json",
        "gh api -X POST repos/o/r/issues/3/labels -f \"labels[]=$L\"",
        "gh api -X POST repos/o/r/issues/3/labels -F labels[]=@-",
        "gh api -X PATCH repos/o/r/issues/3 -F body=@missing.md",
        "gh api -X POST \"$URL\" -f 'labels[]=human-approved'",
        "gh api graphql -f query=\"$Q\"",
        "gh api graphql -F query=@missing.graphql",
        "gh api graphql -f query='mutation { addLabelsToLabelable(input: {labelableId: \"PR_1\", labelIds: [\"LA_1\"]}) { clientMutationId } }'",
        "echo human-approved | xargs gh pr edit 3 --add-label",
        "echo 3 | xargs gh pr edit --add-label bug",
        "echo x | xargs gh api -X POST repos/o/r/issues/3/labels -f 'labels[]=bug'",
        "echo bug | xargs gh label delete",
        "sh -c 'gh pr edit 3 --add-label \"$1\"' _ human-approved",
    ] {
        assert_in_every_mode(&f, command, Some(LABEL_UNKNOWN));
    }
    let reason = f.guard("gh pr edit 3 --add-label 'human-approved").unwrap();
    assert!(reason.contains("merge guard failed"), "{reason}");
    assert!(f.calls().is_empty(), "{}", f.calls());
}

/// The Claude Code ask rule the person's approval goes through (#1146).
const APPROVAL_ASK_RULE: &str = "Bash(gh pr edit * --add-label human-approved)";

/// The decision and reason of a hook run, or None when it prints nothing.
fn verdict(out: std::process::Output) -> Option<(String, String)> {
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    if stdout.trim().is_empty() {
        return None;
    }
    let value: Value = serde_json::from_str(&stdout).unwrap();
    let output = &value["hookSpecificOutput"];
    assert_eq!(output["hookEventName"], "PreToolUse");
    Some((
        output["permissionDecision"].as_str().unwrap().to_owned(),
        output["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .to_owned(),
    ))
}

impl Fixture {
    /// A Claude Code project directory whose `.claude/settings.json` is `settings`.
    fn claude_project(&self, name: &str, settings: &str) -> PathBuf {
        let dir = self.root.join(name);
        fs::create_dir_all(dir.join(".claude")).unwrap();
        fs::write(dir.join(".claude/settings.json"), settings).unwrap();
        dir
    }

    /// The session guard's decision and reason with `vars`, in every mode,
    /// asserted equal across modes.
    fn approval(&self, command: &str, vars: &[(&str, &str)]) -> Option<(String, String)> {
        let payload = json!({
            "tool_input": {"command": command},
            "cwd": self.root.join("session"),
        })
        .to_string();
        let mut seen = None;
        for mode in [None, Some("full"), Some("light")] {
            let mut all = vars.to_vec();
            if let Some(mode) = mode {
                all.push(("AGENTIC_MERGE_GUARD_MODE", mode));
            }
            let got = verdict(self.output(&payload, &all));
            if mode.is_some() {
                assert_eq!(got, seen, "{command} in {mode:?}");
            }
            seen = got;
        }
        seen
    }
}

fn registered() -> String {
    json!({"permissions": {"allow": ["Bash(gh *)"], "ask": ["Bash(git push *)", APPROVAL_ASK_RULE]}})
        .to_string()
}

/// #1255: in a session that runs on the agents' App, the canonical form is denied
/// with its own reason (a label the App adds never counts in CI); every other label
/// write keeps the reason of #941.
#[test]
fn an_app_session_is_told_its_label_never_counts() {
    let f = Fixture::new();
    let project = f.claude_project("claude", &registered());
    let project = project.to_str().unwrap();
    for token_var in ["GH_TOKEN", "GITHUB_TOKEN"] {
        let vars = [
            ("CLAUDE_PROJECT_DIR", project),
            (token_var, "ghs_faketoken"),
        ];
        assert_eq!(
            f.approval("gh pr edit 12 --add-label human-approved", &vars),
            Some(("deny".to_owned(), LABEL_APP_SESSION.to_owned())),
            "{token_var}"
        );
        assert_eq!(
            f.approval("gh pr edit 12 --remove-label human-approved", &vars),
            Some(("deny".to_owned(), LABEL_CHANGE.to_owned())),
            "{token_var}"
        );
    }
    // A person's token keeps the #1152 behaviour: denied with the label reason.
    assert_eq!(
        f.approval(
            "gh pr edit 12 --add-label human-approved",
            &[("CLAUDE_PROJECT_DIR", project), ("GH_TOKEN", "ghp_person")]
        ),
        Some(("deny".to_owned(), LABEL_CHANGE.to_owned()))
    );
}

/// #28: the guide `agent-guardrails` renders says what the guard does. While no
/// real session has proved the prompt, it states that the canonical form is
/// denied too, and never promises that the ask rule puts it to the person.
#[test]
fn the_rendered_guide_states_the_canonical_approval_is_denied_until_proven() {
    assert_eq!(PROMPT_EVIDENCE, None);
    // Rendered verbatim at `GUIDE_PATH` by every agent-guardrails plan.
    let row = brakes::modules::agent_guardrails::GUIDE
        .lines()
        .find(|l| l.starts_with("| `human-approved` is set only by a person |"))
        .expect("the human-approved row");
    assert!(!row.contains("puts to you"), "{row}");
    // A brake over what it can read, never "every route" (#28 review).
    assert!(!row.contains("every route"), "{row}");
    assert!(row.contains("a brake and not a barrier"), "{row}");
    assert!(
        row.contains(
            "`gh pr edit <n> [--repo <owner>/<repo>] --add-label human-approved` included"
        ),
        "{row}"
    );
    assert!(
        row.contains("a session on your own token counts as you"),
        "{row}"
    );
    assert!(
        row.contains("set the label on GitHub under your own login"),
        "{row}"
    );
}

#[test]
fn canonical_approval_is_denied_until_proven() {
    // #1152: no real session has shown the person the prompt yet, so the
    // canonical form is denied even with the rule registered under Claude Code.
    assert_eq!(PROMPT_EVIDENCE, None);
    let f = Fixture::new();
    let project = f.claude_project("claude", &registered());
    let project = project.to_str().unwrap();
    let deny = Some(("deny".to_owned(), LABEL_CHANGE.to_owned()));
    for command in [
        "gh pr edit 12 --add-label human-approved",
        "gh pr edit 12 --repo o/r --add-label human-approved",
        "gh pr edit 1146 --repo example-owner/example-project --add-label human-approved",
        "gh pr edit 7 --repo my-org/my.repo_name --add-label human-approved",
    ] {
        assert_eq!(
            f.approval(command, &[("CLAUDE_PROJECT_DIR", project)]),
            deny,
            "{command}"
        );
        // Not a Claude Code hook, or a relative project: the deny of #941.
        assert_eq!(f.approval(command, &[]), deny, "{command}");
        assert_eq!(
            f.approval(command, &[("CLAUDE_PROJECT_DIR", "claude")]),
            deny,
            "{command}"
        );
        assert_eq!(
            f.approval(command, &[("CLAUDE_PROJECT_DIR", "")]),
            deny,
            "{command}"
        );
        // Headless: an unattended or CI job never reaches a person.
        for ci in ["CI", "GITHUB_ACTIONS"] {
            for value in ["true", "1", ""] {
                assert_eq!(
                    f.approval(command, &[("CLAUDE_PROJECT_DIR", project), (ci, value)]),
                    deny,
                    "{command} with {ci}={value:?}"
                );
            }
        }
    }
    // The rule must be the exact explicit ask rule of the project's settings.
    for (name, settings) in [
        (
            "no-rule",
            json!({"permissions": {"ask": ["Bash(git push *)"]}}).to_string(),
        ),
        (
            "allow-only",
            json!({"permissions": {"allow": [APPROVAL_ASK_RULE]}}).to_string(),
        ),
        (
            "deny-list",
            json!({"permissions": {"deny": [APPROVAL_ASK_RULE]}}).to_string(),
        ),
        (
            "near",
            json!({"permissions": {"ask": ["Bash(gh pr edit *)"]}}).to_string(),
        ),
        (
            "spaced",
            json!({"permissions": {"ask": [format!(" {APPROVAL_ASK_RULE}")]}}).to_string(),
        ),
        (
            "string",
            json!({"permissions": {"ask": APPROVAL_ASK_RULE}}).to_string(),
        ),
        (
            "unreadable",
            format!("{{\"permissions\": {{\"ask\": [\"{APPROVAL_ASK_RULE}\"]"),
        ),
    ] {
        let dir = f.claude_project(name, &settings);
        assert_eq!(
            f.approval(
                "gh pr edit 12 --add-label human-approved",
                &[("CLAUDE_PROJECT_DIR", dir.to_str().unwrap())]
            ),
            deny,
            "{name}"
        );
    }
    let missing = f.root.join("missing");
    assert_eq!(
        f.approval(
            "gh pr edit 12 --add-label human-approved",
            &[("CLAUDE_PROJECT_DIR", missing.to_str().unwrap())]
        ),
        deny
    );
    assert!(f.calls().is_empty(), "{}", f.calls());
}

#[test]
fn approval_variants_stay_denied() {
    let f = Fixture::new();
    let project = f.claude_project("claude", &registered());
    let claude = [("CLAUDE_PROJECT_DIR", project.to_str().unwrap())];
    for command in [
        "gh pr edit 12 --remove-label human-approved",
        "gh pr edit 12 --add-label human-approved --remove-label status:in-review",
        "gh pr edit 12 --add-label status:in-review --add-label human-approved",
        "gh pr edit 12 --add-label bug,human-approved",
        "gh pr edit 12 --add-label human-approved,bug",
        "gh pr edit 12 --add-label Human-Approved",
        "gh pr edit 12 --add-label=human-approved",
        "gh pr edit 12 --add-label 'human-approved'",
        "gh pr edit 12 --add-label \"human-approved\"",
        "gh pr edit 12 -R o/r --add-label human-approved",
        "gh pr edit 12 --repo=o/r --add-label human-approved",
        "gh pr edit 12 --add-label human-approved --repo o/r",
        "gh pr edit --add-label human-approved 12",
        "gh -R o/r pr edit 12 --add-label human-approved",
        "gh pr edit 12  --add-label human-approved",
        "gh pr edit 12 --add-label human-approved ",
        " gh pr edit 12 --add-label human-approved",
        "gh pr edit 012 --add-label human-approved",
        "gh pr edit 12 --repo o/r/x --add-label human-approved",
        "gh pr edit 12 --repo o --add-label human-approved",
        "gh pr edit https://github.com/o/r/pull/12 --add-label human-approved",
        "gh pr edit feature-branch --add-label human-approved",
        "gh pr edit $N --add-label human-approved",
        "gh pr edit 12 --repo $REPO --add-label human-approved",
        "gh pr edit 12 --add-label $LABEL",
        "gh pr edit 12 --add-label human-approved --title x",
        "GH_REPO=o/r gh pr edit 12 --add-label human-approved",
        "env gh pr edit 12 --add-label human-approved",
        "command gh pr edit 12 --add-label human-approved",
        "timeout 60 gh pr edit 12 --add-label human-approved",
        "/usr/local/bin/gh pr edit 12 --add-label human-approved",
        "sh -c 'gh pr edit 12 --add-label human-approved'",
        "eval 'gh pr edit 12 --add-label human-approved'",
        "echo $(gh pr edit 12 --add-label human-approved)",
        "gh pr edit 12 --add-label human-approved && gh pr merge 12",
        "gh pr edit 12 --add-label human-approved; gh pr edit 13 --add-label human-approved",
        "gh pr edit 12 --add-label human-approved || true",
        "gh pr edit 12 --add-label human-approved | cat",
        "gh pr edit 12 --add-label human-approved &",
        "gh pr edit 12 --add-label human-approved > out.txt",
        "gh pr edit 12 --add-label human-approved\ngh pr edit 13 --add-label human-approved",
        "cd /tmp && gh pr edit 12 --add-label human-approved",
        "gh issue edit 12 --add-label human-approved",
        "gh pr create --label human-approved",
        "gh api -X POST repos/o/r/issues/12/labels -f 'labels[]=human-approved'",
        "gh api graphql -f query='mutation { updateLabel(input: {id: \"L\", name: \"human-approved\"}) { clientMutationId } }'",
        "gh label edit bug --name human-approved",
        "gh label delete human-approved --yes",
    ] {
        let without = f.approval(command, &[]);
        let with = f.approval(command, &claude);
        assert_eq!(with, without, "{command}");
        let (decision, reason) = with.unwrap_or_else(|| panic!("{command} allowed"));
        assert_eq!(decision, "deny", "{command}");
        assert!(
            reason == LABEL_CHANGE || reason == LABEL_UNKNOWN || reason.starts_with("Never merge"),
            "{command}: {reason}"
        );
    }
}

#[test]
fn label_reads_creates_and_mentions_pass() {
    let f = Fixture::new();
    fs::write(f.root.join("session/bug.json"), r#"{"labels":["bug"]}"#).unwrap();
    for command in [
        "gh label create human-approved --color 0e8a16 --description \"Set by a person\"",
        "gh label create human-approved --force",
        "gh api -X POST repos/o/r/labels -f name=human-approved -f color=0e8a16",
        "gh pr edit 3 --add-label bug --title \"needs human-approved\"",
        "gh pr edit 3 --remove-label status:in-progress --add-label status:in-review",
        "gh issue edit 941 --add-label status:in-review --body \"$BODY\"",
        "gh pr create --title t --body 'Needs `human-approved` from the owner' --label bug",
        "gh pr view 3 --json labels",
        "gh label list --search human-approved",
        "gh pr list --label human-approved",
        "gh api repos/o/r/issues/3/labels",
        "gh api repos/o/r/labels/human-approved",
        "gh issue comment 3 --body 'add human-approved please'",
        "gh api -X POST repos/o/r/issues/3/comments -f body=\"human-approved is the owner's\"",
        "gh api -X POST repos/o/r/issues/3/labels -f 'labels[]=bug'",
        "gh api -X POST repos/o/r/issues/3/labels --input bug.json",
        "gh api -X PUT repos/o/r/issues/3/labels -f 'labels[]=bug'",
        "gh api -X DELETE repos/o/r/issues/3/labels",
        "gh api -X PATCH repos/o/r/issues/3 -f title=x",
        "gh api graphql -f query='query { repository(owner: \"o\", name: \"r\") { labels(first: 5) { nodes { name } } } }' -F n=$N",
        "git commit -m \"feat: deny gh pr edit --add-label human-approved\"",
        "cat <<'EOF' > note.md\ngh pr edit 3 --add-label human-approved\ngh label delete human-approved\nEOF",
        "echo 'gh label delete human-approved'",
        "timeout 60 gh pr view 3",
    ] {
        assert_in_every_mode(&f, command, None);
    }
    assert!(f.calls().is_empty(), "{}", f.calls());
}

#[test]
fn env_can_force_full_but_never_light() {
    let f = Fixture::new();
    fs::create_dir_all(f.root.join("plain")).unwrap();
    // An undecidable merge: full mode denies it, whatever the variable says.
    for mode in ["full", "light", "LIGHT", ""] {
        let reason = f
            .guard_in_mode("cd ../plain && gh pr merge 7", mode)
            .unwrap();
        assert!(reason.contains("pass -R owner/repo"), "{mode}: {reason}");
    }
    // A red merge stays red under `light`.
    f.set_checks(&json!([{"name": "build", "bucket": "fail"}]), 8);
    let reason = f.guard_in_mode("gh pr merge 274", "light").unwrap();
    assert!(reason.contains("build: fail"), "{reason}");
}

#[test]
fn reads_and_unrelated_commands_pass() {
    let f = Fixture::new();
    assert_eq!(f.guard("gh api repos/o/r/branches/main/protection"), None);
    assert_eq!(f.guard("gh pr view 274 --json mergeStateStatus"), None);
    assert_eq!(f.guard("git merge --ff-only origin/main"), None);
    assert_eq!(f.guard("cd /nowhere && ls"), None);
    assert!(f.calls().is_empty(), "{}", f.calls());
}

#[test]
fn cd_into_another_repository_checks_that_repository() {
    let f = Fixture::new();
    let other = f.root.join("other");
    assert_eq!(
        f.guard(&format!(
            "cd {} && gh pr merge 292 --squash",
            other.display()
        )),
        None
    );
    assert!(
        f.calls().contains("pr checks 292 --repo org/other-app"),
        "{}",
        f.calls()
    );
    // A relative `cd` resolves against the session directory.
    f.guard("cd ../other; gh pr merge 293");
    assert!(
        f.calls().contains("pr checks 293 --repo org/other-app"),
        "{}",
        f.calls()
    );
}

#[test]
fn repo_flag_wins_over_cd() {
    let f = Fixture::new();
    f.guard("cd ../other && gh pr merge 5 --repo=x/y");
    assert!(
        f.calls().contains("pr checks 5 --repo x/y"),
        "{}",
        f.calls()
    );
    f.guard("cd ../other && gh pr -R a/b merge 6");
    assert!(
        f.calls().contains("pr checks 6 --repo a/b"),
        "{}",
        f.calls()
    );
}

#[test]
fn gh_repo_wins_over_the_directory_as_in_gh() {
    let f = Fixture::new();
    f.guard("cd ../other && GH_REPO=p/q gh pr merge 8");
    assert!(
        f.calls().contains("pr checks 8 --repo p/q"),
        "{}",
        f.calls()
    );
    let payload = json!({
        "tool_input": {"command": "cd ../other && gh pr merge 9"},
        "cwd": f.root.join("session"),
    });
    f.run_with(&payload.to_string(), Some("s/t"));
    assert!(
        f.calls().contains("pr checks 9 --repo s/t"),
        "{}",
        f.calls()
    );
}

#[test]
fn unresolvable_cd_denies() {
    let f = Fixture::new();
    fs::create_dir_all(f.root.join("plain")).unwrap();
    for command in [
        "cd ../plain && gh pr merge 7",
        "cd ../missing && gh pr merge 7",
        "cd \"$OTHER\" && gh pr merge 7",
        "cd && gh pr merge 7",
    ] {
        let reason = f.guard(command).unwrap();
        assert!(reason.contains("pass -R owner/repo"), "{command}: {reason}");
    }
    assert!(f.calls().is_empty(), "{}", f.calls());
}

#[test]
fn green_pr_here_does_not_let_a_red_pr_elsewhere_through() {
    let f = Fixture::new();
    f.red_only_in_other();
    assert_eq!(f.guard("gh pr merge 292"), None);
    let reason = f.guard("cd ../other && gh pr merge 292 --squash").unwrap();
    assert!(reason.contains("build: fail"), "{reason}");
}

#[test]
fn conditional_cd_leaves_the_later_merge_directory_unknown() {
    let f = Fixture::new();
    for command in [
        "false && cd ../other; gh pr merge 1",
        "true || cd ../other; gh pr merge 1",
        "false && cd ../other\ngh pr merge 1",
        "false && true && cd ../other; gh pr merge 1",
        "false &&\n cd ../other; gh pr merge 1",
        "cd ../other; false && cd ../session; gh pr merge 1",
    ] {
        let reason = f.guard(command).unwrap_or_default();
        assert!(reason.contains("pass -R owner/repo"), "{command}: {reason}");
    }
    assert!(f.calls().is_empty(), "{}", f.calls());
}

#[test]
fn pipeline_cd_leaves_the_later_merge_directory_unknown() {
    let f = Fixture::new();
    for command in [
        "cd ../other | cat; gh pr merge 1",
        "echo x | cd ../other; gh pr merge 1",
        "cd ../other | cat\ngh pr merge 1",
        "cd ../other & gh pr merge 1",
        "cd ../other && true & gh pr merge 1",
        "cd ../other; cd ../session | cat; gh pr merge 1",
    ] {
        let reason = f.guard(command).unwrap_or_default();
        assert!(reason.contains("pass -R owner/repo"), "{command}: {reason}");
    }
    assert!(f.calls().is_empty(), "{}", f.calls());
}

#[test]
fn shell_wrappers_inherit_repository_prefixes_and_directory() {
    let f = Fixture::new();
    f.red_only_in_other();
    for command in [
        "GH_REPO=org/other-app bash -c 'gh pr merge 1'",
        "GH_REPO=org/other-app sh -ec 'gh pr merge 1'",
        "env GH_REPO=org/other-app bash -c 'gh pr merge 1'",
        "GH_REPO=org/other-app eval 'gh pr merge 1'",
        "cd ../other; bash -c 'gh pr merge 1'",
        "cd ../other && bash -c 'gh pr merge 1'",
    ] {
        let reason = f.guard(command).unwrap_or_default();
        assert!(reason.contains("build: fail"), "{command}: {reason}");
    }
    assert!(!f.calls().contains("--repo me/session"), "{}", f.calls());
}

#[test]
fn shell_wrappers_inherit_host_prefixes() {
    let f = Fixture::new();
    f.write_fake("case \"$GH_HOST\" in\n  other.example) echo '[{\"name\":\"build\",\"bucket\":\"fail\"}]';;\n  *) echo '[{\"name\":\"build\",\"bucket\":\"pass\"}]';;\nesac\n");
    for command in [
        "GH_HOST=other.example bash -c 'gh pr merge 1 -R me/session'",
        "GH_HOST=other.example GH_REPO=me/session sh -c 'gh pr merge 1'",
        "GH_HOST=other.example eval 'gh pr merge 1 -R me/session'",
    ] {
        let reason = f.guard(command).unwrap_or_default();
        assert!(reason.contains("build: fail"), "{command}: {reason}");
    }
}

#[test]
fn shell_prefixes_are_scoped_and_unknown_values_deny() {
    let f = Fixture::new();
    f.red_only_in_other();
    for command in [
        "GH_REPO=org/other-app bash -c 'true'; gh pr merge 1",
        "GH_HOST=other.example bash -c 'true'; gh pr merge 1",
        "GH_REPO=org/other-app bash -c 'gh pr merge 1 -R me/session'",
        "GH_REPO=org/other-app bash -c 'GH_REPO=me/session sh -c \"gh pr merge 1\"'",
    ] {
        assert_eq!(f.guard(command), None, "{command}");
    }
    for command in [
        "GH_REPO=\"$TARGET\" bash -c 'gh pr merge 1'",
        "GH_HOST=\"$TARGET\" bash -c 'gh pr merge 1 -R me/session'",
        "false && export GH_REPO=me/session; gh pr merge 1",
        "export GH_HOST=other.example | cat; gh pr merge 1 -R me/session",
    ] {
        let reason = f.guard(command).unwrap_or_default();
        assert!(reason.contains("pass -R owner/repo"), "{command}: {reason}");
    }
}

#[test]
fn merge_option_values_cannot_override_the_repository() {
    let f = Fixture::new();
    f.red_only_in_other();
    for option in [
        "--subject",
        "--body",
        "--body-file",
        "-t",
        "-b",
        "-F",
        "-A",
        "--author-email",
        "--match-head-commit",
    ] {
        for value in ["-Rme/session", "--repo=me/session"] {
            let command = format!("cd ../other; gh pr merge 1 {option} '{value}'");
            let reason = f.guard(&command).unwrap_or_default();
            assert!(reason.contains("build: fail"), "{command}: {reason}");
        }
    }
    assert!(!f.calls().contains("--repo me/session"), "{}", f.calls());
}

#[test]
fn unknown_merge_options_fail_closed() {
    let f = Fixture::new();
    for command in [
        "gh pr merge 1 --future-option '-Rme/session'",
        "gh pr merge --future-option value 1 -R me/session",
        "gh pr merge 1 --future-option=value",
    ] {
        let reason = f.guard(command).unwrap_or_default();
        assert!(reason.contains("pass -R owner/repo"), "{command}: {reason}");
    }
    assert!(f.calls().is_empty(), "{}", f.calls());
}

#[test]
fn real_repository_options_and_attached_data_keep_their_roles() {
    let f = Fixture::new();
    f.red_only_in_other();
    for command in [
        "gh pr merge 1 --subject '-Rme/session' -R org/other-app",
        "gh pr merge 1 --body='-Rme/session' --repo org/other-app",
        "gh pr merge 1 -t-Rme/session --repo=org/other-app",
        "gh pr merge 1 -b--repo=me/session -Rorg/other-app",
        "gh -R me/session pr merge 1 -R org/other-app",
    ] {
        let reason = f.guard(command).unwrap_or_default();
        assert!(reason.contains("build: fail"), "{command}: {reason}");
    }
    for command in [
        "gh pr merge 1 --subject '--admin'",
        "gh pr merge 1 --body='--admin'",
        "false && cd ../other; gh pr merge 1 -R me/session",
    ] {
        assert_eq!(f.guard(command), None, "{command}");
    }
}

#[test]
fn heredoc_and_quoted_text_mentioning_a_merge_is_not_a_merge() {
    let f = Fixture::new();
    f.set_checks(&json!([{"name": "build", "bucket": "fail"}]), 1);
    for command in [
        "gh issue create --title t --body-file - <<'EOF'\nThe guard denied `gh pr merge 3 --admin`.\ngh pr merge 3\ngh api -X PUT repos/o/r/pulls/3/merge\nEOF",
        "cat <<-EOF > note.md\n\tgh pr merge 4\n\tEOF\necho done",
        "gh issue comment 1 --body 'run gh pr merge 3 --admin && gh pr merge 4'",
        "echo \"gh pr merge 5; gh api -X DELETE repos/o/r/branches/main/protection\"",
        "git commit -m \"fix: never gh pr merge on red\"",
    ] {
        assert_eq!(f.guard(command), None, "{command}");
    }
    assert!(f.calls().is_empty(), "{}", f.calls());
    // A real merge after a heredoc is still a merge.
    let reason = f.guard("cat <<EOF > x\ntext\nEOF\ngh pr merge 9").unwrap();
    assert!(reason.contains("build: fail"), "{reason}");
}

#[test]
fn merges_hidden_in_substitutions_or_chains_are_checked() {
    let f = Fixture::new();
    f.set_checks(&json!([{"name": "build", "bucket": "fail"}]), 1);
    for command in [
        "echo $(gh pr merge 1)",
        "echo \"`gh pr merge 2`\"",
        "true||gh pr merge 3",
        "ls | gh pr merge 4 2>&1",
        "env GH_TOKEN=x gh pr merge 5",
    ] {
        let reason = f.guard(command).unwrap_or_default();
        assert!(reason.contains("build: fail"), "{command}: {reason}");
    }
}

#[test]
fn guard_errors_deny_merges_and_spare_other_commands() {
    let f = Fixture::new();
    let reason = f.guard("gh pr merge 1 --body 'unterminated").unwrap();
    assert!(reason.contains("merge guard failed"), "{reason}");
    assert_eq!(f.guard("echo 'unterminated"), None);
    let reason = f.run("not json").unwrap();
    assert!(reason.contains("merge guard failed"), "{reason}");
}

// The limits of docs/decisions.md ("Never merge on red", known limits) fail
// closed: each either checks the repository gh would use or denies.

#[test]
fn a_cd_inside_a_group_does_not_leave_the_group() {
    let f = Fixture::new();
    f.red_only_in_other();
    assert_eq!(f.guard("( cd ../other && ls ) && gh pr merge 1"), None);
    assert!(
        f.calls().contains("pr checks 1 --repo me/session"),
        "{}",
        f.calls()
    );
    // A `)` without its `(`, a `case` pattern, leaves nothing known.
    let reason = f
        .guard("case x in x) cd ../other;; esac; gh pr merge 2")
        .unwrap();
    assert!(reason.contains("pass -R owner/repo"), "{reason}");
    let reason = f
        .guard("if test -d ../other; then cd ../other; fi; gh pr merge 3")
        .unwrap();
    assert!(reason.contains("pass -R owner/repo"), "{reason}");
}

#[test]
fn gh_repo_set_in_the_line_is_followed_or_denied() {
    let f = Fixture::new();
    f.red_only_in_other();
    let reason = f
        .guard("export GH_REPO=org/other-app && gh pr merge 4")
        .unwrap();
    assert!(reason.contains("build: fail"), "{reason}");
    for command in [
        "export GH_REPO; gh pr merge 5",
        "GH_REPO=org/other-app; gh pr merge 5",
        "declare -x GH_REPO=org/other-app; gh pr merge 5",
        "export GH_REPO=\"$TARGET\"; gh pr merge 5",
        "env -u GH_REPO gh pr merge 5",
    ] {
        let reason = f.guard(command).unwrap();
        assert!(reason.contains("pass -R owner/repo"), "{command}: {reason}");
    }
    // -R still wins.
    assert_eq!(f.guard("export GH_REPO; gh pr merge 6 -R me/session"), None);
    // `unset` returns to the directory.
    assert_eq!(
        f.guard("export GH_REPO=org/other-app; unset GH_REPO; gh pr merge 7"),
        None
    );
}

#[test]
fn shell_c_eval_and_unknown_wrappers_are_checked() {
    let f = Fixture::new();
    f.red_only_in_other();
    for command in [
        "bash -c 'cd ../other && gh pr merge 8'",
        "sh -ec \"cd ../other; gh pr merge 8\"",
        "eval 'cd ../other && gh pr merge 8'",
        "cd ../other && timeout 60 gh pr merge 8",
        "cd ../other && nice -n 5 gh pr merge 8 --squash",
    ] {
        let reason = f.guard(command).unwrap_or_default();
        assert!(reason.contains("build: fail"), "{command}: {reason}");
    }
    // A child shell's `cd` does not move this one.
    assert_eq!(f.guard("bash -c 'cd ../other' && gh pr merge 9"), None);
    // `xargs` supplies the pull request: the guard cannot see which.
    let reason = f.guard("echo 9 | xargs gh pr merge --squash").unwrap();
    assert!(reason.contains("pass -R owner/repo"), "{reason}");
}

#[test]
fn a_default_repository_or_a_second_remote_is_not_guessed() {
    let f = Fixture::new();
    f.red_only_in_other();
    let reason = f
        .guard("gh repo set-default org/other-app && gh pr merge 10")
        .unwrap();
    assert!(reason.contains("pass -R owner/repo"), "{reason}");
    // gh prefers `upstream` over `origin`: two repositories are not guessed.
    let session = f.root.join("session");
    git(
        &session,
        &[
            "remote",
            "add",
            "upstream",
            "https://github.com/org/other-app",
        ],
    );
    let reason = f.guard("gh pr merge 11").unwrap();
    assert!(reason.contains("pass -R owner/repo"), "{reason}");
    // What `gh repo set-default` recorded decides.
    git(&session, &["config", "remote.upstream.gh-resolved", "base"]);
    let reason = f.guard("gh pr merge 12").unwrap();
    assert!(reason.contains("build: fail"), "{reason}");
    git(
        &session,
        &["config", "remote.upstream.gh-resolved", "me/session"],
    );
    assert_eq!(f.guard("gh pr merge 13"), None);
    assert!(
        f.calls().contains("pr checks 13 --repo me/session"),
        "{}",
        f.calls()
    );
}

// The subcommand itself: listed by --help for the wrapper, runnable anywhere,
// and silent in processes for a command without `gh`.

#[test]
fn help_lists_guard_pre_bash() {
    let out = Command::new(env!("CARGO_BIN_EXE_brakes"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(out.status.success());
    let help = String::from_utf8(out.stdout).unwrap();
    assert!(help.contains("guard pre-bash"), "{help}");
    for args in [
        &["guard"][..],
        &["guard", "post-bash"],
        &["guard", "pre-bash", "x"],
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_brakes"))
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("usage: brakes guard pre-bash"),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn guard_runs_outside_a_personal_scope() {
    let f = Fixture::new();
    f.set_checks(&json!([{"name": "build", "bucket": "fail"}]), 1);
    // Not a git repository, and a directory the installer's scope would refuse:
    // the hook is read-only and decides anyway.
    let plain = f.root.join("plain");
    let corporate = f.root.join(format!("{}-workspace", configured::denied()));
    fs::create_dir_all(&plain).unwrap();
    fs::create_dir_all(&corporate).unwrap();
    for cwd in [&plain, &corporate] {
        let run = |command: &str| {
            f.run(&json!({"tool_input": {"command": command}, "cwd": cwd}).to_string())
        };
        let reason = run("gh pr merge 1 -R o/r").unwrap();
        assert!(
            reason.contains("build: fail"),
            "{}: {reason}",
            cwd.display()
        );
        let reason = run("gh pr merge 1").unwrap();
        assert!(
            reason.contains("pass -R owner/repo"),
            "{}: {reason}",
            cwd.display()
        );
        assert_eq!(run("ls -la"), None, "{}", cwd.display());
        assert!(run("gh pr merge 2 --admin").unwrap().contains("--admin"));
    }
    // A payload without `cwd` falls back to the process directory, which is not
    // a repository either: nothing refuses, the guard decides.
    let reason = f
        .run(r#"{"tool_input":{"command":"gh pr merge 3 -R o/r"}}"#)
        .unwrap();
    assert!(reason.contains("build: fail"), "{reason}");
}

#[test]
fn non_gh_commands_start_no_process() {
    let f = Fixture::new();
    for command in [
        "ls",
        "cargo test --locked",
        "git merge --ff-only origin/main",
        "echo 'gh pr merge 1'",
        "cd ../other && make",
    ] {
        assert_eq!(f.guard(command), None, "{command}");
    }
    assert!(f.calls().is_empty(), "{}", f.calls());
    // Nothing is written in the home either: the cache belongs to light mode (#695).
    assert!(!f.root.join(".cache").exists());
    assert!(!f.root.join(".local").exists());
}

// Light mode (#695): a fresh cached probe saying the server enforces the
// required check lets the server decide what the guard cannot tell.

/// Classic protection requiring `all-checks-passed` for administrators too.
const CLASSIC_PROTECTED: &str = r#"{"required_status_checks":{"contexts":["all-checks-passed"]},"enforce_admins":{"enabled":true}}"#;
const UPGRADE: &str =
    r#"{"message":"Upgrade to GitHub Pro or make this repository public to enable this feature."}"#;
const PROTECTED: &str = "example-owner/protected";
const NOTE: &str = "the server enforces the required check on example-owner/protected";

/// What the fake `gh api` answers for the protection probe.
struct Server<'a> {
    /// `rules/branches/main`: status line and body.
    rules: (&'a str, &'a str),
    /// `rulesets/<id>`.
    ruleset: &'a str,
    /// `branches/main/protection`: status line and body.
    classic: (&'a str, &'a str),
}

const PROTECTED_SERVER: Server = Server {
    rules: ("200 OK", "[]"),
    ruleset: "{}",
    classic: ("200 OK", CLASSIC_PROTECTED),
};

impl Fixture {
    fn cache(&self, repository: &str) -> PathBuf {
        self.root
            .join(".cache/brakes/merge-guard/github.com")
            .join(format!("{repository}.json"))
    }

    /// A fake `gh` that answers the probe as `server` does and `pr checks`
    /// with `checks` and `exit_code`; every call is logged.
    fn serve(&self, server: &Server, checks: &Value, exit_code: i32) {
        let answer = |(status, body): (&str, &str)| {
            let fails = if status.starts_with("200") { 0 } else { 1 };
            format!("printf 'HTTP/2.0 {status}\\r\\n\\r\\n%s' '{body}'; exit {fails}")
        };
        self.write_fake(&format!(
            "echo \"$@\" >> '{calls}'\ncase \"$*\" in\n  api*/protection) {classic};;\n  api*/rules/branches/*) {rules};;\n  api*/rulesets/*) {ruleset};;\n  api*) {meta};;\n  *) echo '{checks}'; exit {exit_code};;\nesac\n",
            calls = self.calls.display(),
            classic = answer(server.classic),
            rules = answer(server.rules),
            ruleset = answer(("200 OK", server.ruleset)),
            meta = answer(("200 OK", r#"{"default_branch":"main"}"#)),
        ));
    }

    /// Runs the hook in the clone `dir` with `vars`: the decision and stderr.
    fn hook_in(&self, dir: &str, command: &str, vars: &[(&str, &str)]) -> (Option<String>, String) {
        let payload = json!({"tool_input": {"command": command}, "cwd": self.root.join(dir)});
        let out = self.output(&payload.to_string(), vars);
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        (decision(out), stderr)
    }

    fn protected_repo(&self) {
        self.repo(
            "protected",
            "https://github.com/example-owner/protected.git",
        );
        fs::create_dir_all(self.root.join("plain")).unwrap();
    }

    fn probes(&self) -> usize {
        self.calls()
            .lines()
            .filter(|l| l.starts_with("api "))
            .count()
    }
}

#[test]
fn light_mode_requires_a_fresh_protected_probe() {
    let f = Fixture::new();
    f.protected_repo();
    f.serve(
        &PROTECTED_SERVER,
        &json!([{"name": "b", "bucket": "pass"}]),
        0,
    );
    let undecidable = "echo 9 | xargs gh pr merge";
    // No cache: the probe runs, the cache is written, the server decides.
    let (reason, stderr) = f.hook_in("protected", undecidable, &[]);
    assert_eq!(reason, None, "{stderr}");
    assert!(f.probes() > 0, "{}", f.calls());
    let cache: Value =
        serde_json::from_str(&fs::read_to_string(f.cache(PROTECTED)).unwrap()).unwrap();
    assert_eq!(cache["protected"], true);
    assert_eq!(
        cache["evidence"],
        "classic protection, required: all-checks-passed, admins enforced"
    );
    assert!(
        cache["probed_at"].as_str().unwrap().ends_with('Z'),
        "{cache}"
    );
    let siblings: Vec<_> = fs::read_dir(f.cache(PROTECTED).parent().unwrap())
        .unwrap()
        .collect();
    assert_eq!(siblings.len(), 1, "no temp file is left: {siblings:?}");
    // A fresh cache: no probe.
    fs::remove_file(&f.calls).ok();
    assert_eq!(f.hook_in("protected", undecidable, &[]).0, None);
    assert_eq!(f.probes(), 0, "{}", f.calls());
    // A stale or unreadable cache re-probes.
    for stale in [
        json!({"probed_at": "2020-01-01T00:00:00Z", "protected": true, "evidence": "x"})
            .to_string(),
        json!({"probed_at": "2999-01-01T00:00:00Z", "protected": true, "evidence": "x"})
            .to_string(),
        json!({"protected": true, "evidence": "x"}).to_string(),
        "not json".to_owned(),
    ] {
        fs::write(f.cache(PROTECTED), &stale).unwrap();
        fs::remove_file(&f.calls).ok();
        assert_eq!(f.hook_in("protected", undecidable, &[]).0, None, "{stale}");
        assert!(f.probes() > 0, "{stale}: {}", f.calls());
        let cache: Value =
            serde_json::from_str(&fs::read_to_string(f.cache(PROTECTED)).unwrap()).unwrap();
        assert!(
            cache["probed_at"].as_str().unwrap() < "2999",
            "{stale}: {cache}"
        );
    }
    // `AGENTIC_MERGE_GUARD_MODE=full` wins over a fresh protected cache, unprobed.
    fs::remove_file(&f.calls).ok();
    let (reason, _) = f.hook_in(
        "protected",
        undecidable,
        &[("AGENTIC_MERGE_GUARD_MODE", "full")],
    );
    assert!(reason.unwrap().contains("pass -R owner/repo"));
    assert_eq!(f.probes(), 0, "{}", f.calls());
    // A probe failure (exit != 0 without an answer, non-JSON) is full and writes nothing.
    for fake in [
        "exit 1\n",
        "printf 'HTTP/2.0 200 OK\\r\\n\\r\\nnot json'\n",
        "echo 'no headers'\n",
    ] {
        fs::remove_file(f.cache(PROTECTED)).unwrap_or(());
        f.write_fake(&format!("echo \"$@\" >> '{}'\n{fake}", f.calls.display()));
        let (reason, _) = f.hook_in("protected", undecidable, &[]);
        assert!(reason.unwrap().contains("pass -R owner/repo"), "{fake}");
        assert!(!f.cache(PROTECTED).exists(), "{fake}");
    }
}

#[test]
fn the_cache_lives_under_an_absolute_xdg_cache_home_only() {
    let f = Fixture::new();
    f.protected_repo();
    f.serve(&PROTECTED_SERVER, &json!([]), 0);
    let xdg = f.root.join("xdg");
    let xdg_text = xdg.to_str().unwrap();
    assert_eq!(
        f.hook_in(
            "protected",
            "echo 9 | xargs gh pr merge",
            &[("XDG_CACHE_HOME", xdg_text)]
        )
        .0,
        None
    );
    assert!(
        xdg.join("brakes/merge-guard/github.com/example-owner/protected.json")
            .is_file()
    );
    assert!(!f.cache(PROTECTED).exists());
    // A relative XDG_CACHE_HOME is ignored (XDG base directories): never the repository tree.
    assert_eq!(
        f.hook_in(
            "protected",
            "echo 9 | xargs gh pr merge",
            &[("XDG_CACHE_HOME", "rel")]
        )
        .0,
        None
    );
    assert!(f.cache(PROTECTED).is_file());
    assert!(!f.root.join("protected/rel").exists());
    assert!(!f.root.join("rel").exists());
}

#[test]
fn light_mode_still_denies_red_admin_and_api() {
    let f = Fixture::new();
    f.protected_repo();
    for mode in [None, Some("full")] {
        let vars: Vec<_> = mode
            .map(|m| ("AGENTIC_MERGE_GUARD_MODE", m))
            .into_iter()
            .collect();
        let deny = |command: &str| f.hook_in("protected", command, &vars).0;
        // Make the cache fresh and protected first.
        f.serve(
            &PROTECTED_SERVER,
            &json!([{"name": "b", "bucket": "pass"}]),
            0,
        );
        assert_eq!(
            f.hook_in("protected", "echo 9 | xargs gh pr merge", &[]).0,
            None
        );
        assert!(f.cache(PROTECTED).is_file());
        assert!(
            deny("gh pr merge 3 --admin --squash")
                .unwrap()
                .contains("--admin")
        );
        for command in [
            "gh api -X PUT repos/o/r/pulls/3/merge",
            "gh api -X DELETE repos/o/r/branches/main/protection",
            "gh api --method PUT repos/o/r/branches/main/protection --input p.json",
            "gh api repos/o/r/branches/main/protection/enforce_admins -X DELETE",
            "cd ../plain && gh api -X PUT repos/{owner}/{repo}/pulls/3/merge",
            "gh api -X POST repos/o/r/rulesets --input r.json",
            "gh api -X DELETE orgs/o/rulesets/3",
        ] {
            let reason = deny(command).unwrap_or_default();
            assert!(
                reason.contains("owner's to change") || reason.contains("gh api"),
                "{mode:?} {command}: {reason}"
            );
        }
        for bucket in ["fail", "cancel", "pending"] {
            f.serve(
                &PROTECTED_SERVER,
                &json!([{"name": "build", "bucket": "pass"}, {"name": "Rust (linux)", "bucket": bucket}]),
                8,
            );
            let reason = deny("gh pr merge 274 --squash --subject 'x y'").unwrap_or_default();
            assert!(
                reason.contains(&format!("Rust (linux): {bucket}")),
                "{mode:?}: {reason}"
            );
            assert!(reason.contains(PROTECTED), "{reason}");
        }
        f.serve(&PROTECTED_SERVER, &json!([]), 0);
        assert!(
            deny("gh pr merge --squash")
                .unwrap_or_default()
                .contains("No CI checks")
        );
        let reason = deny("brakes apply . --remote").unwrap_or_default();
        assert!(reason.contains("apply --remote"), "{reason}");
        assert_eq!(
            deny("gh pr edit 3 --add-label human-approved").as_deref(),
            Some(LABEL_CHANGE)
        );
        fs::remove_file(f.cache(PROTECTED)).unwrap();
    }
}

#[test]
fn light_mode_lets_the_server_decide_undecidable_merges() {
    let f = Fixture::new();
    f.protected_repo();
    let commands = [
        (
            "cd ../gone && gh pr merge -R example-owner/protected",
            "merge guard: which directory the merge runs in unknown;",
        ),
        (
            "echo 9 | xargs gh pr merge",
            "merge guard: which pull request a wrapped `gh pr merge` merges unknown;",
        ),
        (
            "gh pr merge 5",
            "merge guard: the check results (boom) unknown;",
        ),
    ];
    // `gh pr checks` fails (exit 1, no list); the probe answers protected.
    let failing_checks = || {
        f.serve(&PROTECTED_SERVER, &json!([]), 0);
        let script = fs::read_to_string(&f.fake)
            .unwrap()
            .replace("*) echo '[]'; exit 0;;", "*) echo boom >&2; exit 1;;");
        fs::write(&f.fake, script).unwrap();
    };
    failing_checks();
    for (command, what) in commands {
        let (reason, stderr) = f.hook_in("protected", command, &[]);
        assert_eq!(reason, None, "{command}: {stderr}");
        assert!(stderr.contains(what), "{command}: {stderr}");
        assert!(
            stderr.contains(&format!(" unknown; {NOTE}\n")),
            "{command}: {stderr}"
        );
    }
    // The same commands in full mode keep today's denial.
    for (command, _) in commands {
        let (reason, _) = f.hook_in(
            "protected",
            command,
            &[("AGENTIC_MERGE_GUARD_MODE", "full")],
        );
        let reason = reason.unwrap_or_default();
        assert!(
            reason.contains("pass -R owner/repo") || reason.contains("merge guard failed (boom)"),
            "{command}: {reason}"
        );
    }
    // A denial later in the same line is still found after an allowed undecidable merge.
    f.repo("red", "https://github.com/example-owner/red.git");
    f.write_fake(&format!(
        "echo \"$@\" >> '{}'\ncase \"$*\" in\n  *pr\\ checks*example-owner/red*) echo '[{{\"name\":\"build\",\"bucket\":\"fail\"}}]';;\n  *pr\\ checks*) echo boom >&2; exit 1;;\nesac\n",
        f.calls.display()
    ));
    let reason = f
        .hook_in(
            "protected",
            "echo 9 | xargs gh pr merge; gh pr merge 8 -R example-owner/red",
            &[],
        )
        .0
        .unwrap_or_default();
    assert!(reason.contains("build: fail"), "{reason}");
}

#[test]
fn an_undetermined_target_stays_full_in_a_protected_session() {
    let f = Fixture::new();
    f.protected_repo();
    f.serve(&PROTECTED_SERVER, &json!([]), 0);
    // The session's repository is protected and its probe is fresh.
    assert_eq!(
        f.hook_in("protected", "echo 9 | xargs gh pr merge", &[]).0,
        None
    );
    assert!(f.cache(PROTECTED).is_file());
    fs::remove_file(&f.calls).ok();
    // A merge whose own target is not determined has no known server: full.
    for command in [
        "cd ../plain && gh pr merge 7",
        "gh pr merge 1 --future-option",
        "GH_REPO=$X gh pr merge 1",
    ] {
        let (reason, stderr) = f.hook_in("protected", command, &[]);
        let reason = reason.unwrap_or_default();
        assert!(reason.contains("pass -R owner/repo"), "{command}: {reason}");
        assert!(
            !stderr.contains("the server enforces"),
            "{command}: {stderr}"
        );
    }
    assert_eq!(f.probes(), 0, "{}", f.calls());
}

#[test]
fn unprotected_or_403_repositories_stay_full() {
    let f = Fixture::new();
    f.repo("free", "https://github.com/example-org/free-app.git");
    f.repo("classic", "https://github.com/example-owner/classic.git");
    f.repo("bypass", "https://github.com/example-owner/bypass.git");
    fs::create_dir_all(f.root.join("plain")).unwrap();
    let not_admins =
        r#"{"required_status_checks":{"contexts":["verify"]},"enforce_admins":{"enabled":false}}"#;
    let rules = r#"[{"type":"required_status_checks","ruleset_id":1,"parameters":{"required_status_checks":[{"context":"verify"}]}}]"#;
    let bypass = r#"{"enforcement":"active","bypass_actors":[{"actor_type":"RepositoryRole","actor_id":5}]}"#;
    for (dir, repository, server) in [
        (
            "free",
            "example-org/free-app",
            Server {
                rules: ("403 Forbidden", UPGRADE),
                ruleset: "{}",
                classic: ("403 Forbidden", UPGRADE),
            },
        ),
        (
            "classic",
            "example-owner/classic",
            Server {
                rules: ("200 OK", "[]"),
                ruleset: "{}",
                classic: ("200 OK", not_admins),
            },
        ),
        (
            "bypass",
            "example-owner/bypass",
            Server {
                rules: ("200 OK", rules),
                ruleset: bypass,
                classic: ("404 Not Found", r#"{"message":"Branch not protected"}"#),
            },
        ),
    ] {
        f.serve(&server, &json!([]), 0);
        for _ in 0..2 {
            let (reason, _) = f.hook_in(dir, "echo 9 | xargs gh pr merge", &[]);
            assert!(
                reason.unwrap_or_default().contains("pass -R owner/repo"),
                "{dir}"
            );
        }
        let cache: Value =
            serde_json::from_str(&fs::read_to_string(f.cache(repository)).unwrap()).unwrap();
        assert_eq!(cache["protected"], false, "{dir}: {cache}");
    }
    // A repository outside the personal scope is never probed: full.
    fs::remove_file(&f.calls).ok();
    f.serve(&PROTECTED_SERVER, &json!([]), 0);
    let (reason, _) = f.hook_in("session", "echo 9 | xargs gh pr merge", &[]);
    assert!(reason.unwrap_or_default().contains("pass -R owner/repo"));
    assert_eq!(f.probes(), 0, "{}", f.calls());
    // Neither is a merge whose GH_HOST is another host.
    f.protected_repo();
    let (reason, _) = f.hook_in(
        "protected",
        "cd ../plain && GH_HOST=ghe.example.com gh pr merge 7",
        &[],
    );
    assert!(reason.unwrap_or_default().contains("pass -R owner/repo"));
    assert_eq!(f.probes(), 0, "{}", f.calls());
}

#[test]
fn latency_of_a_non_gh_command() {
    let f = Fixture::new();
    f.protected_repo();
    f.serve(&PROTECTED_SERVER, &json!([]), 0);
    let mut best = std::time::Duration::MAX;
    for _ in 0..3 {
        let start = std::time::Instant::now();
        assert_eq!(f.hook_in("protected", "ls -la", &[]).0, None);
        best = best.min(start.elapsed());
    }
    assert!(best < std::time::Duration::from_millis(200), "{best:?}");
    assert!(f.calls().is_empty(), "{}", f.calls());
    assert!(!f.root.join(".cache").exists());
}

// The hook wrapper, .claude/hooks/merge_guard.sh: it finds the binary, or
// denies only what could merge. Ported from the supervisor's suite with the
// `brakes` entries added in front of the `agentic-run` ones (#692).

const WRAPPER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../.claude/hooks/merge_guard.sh"
);

/// A fake binary whose guard denies every command with `reason`; without
/// `guard` it is a binary from before the guard existed.
fn fake_guard(path: &Path, reason: &str, guard: bool) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let help = if guard {
        "Guard: fake guard pre-bash"
    } else {
        "Usage: fake"
    };
    let deny = json!({"hookSpecificOutput": {"hookEventName": "PreToolUse",
        "permissionDecision": "deny", "permissionDecisionReason": reason}});
    common::write_executable(
        path,
        &format!(
            "#!/bin/sh\ncase \"$1\" in\n  --help) echo '{help}';;\n  guard) cat >/dev/null; echo '{deny}';;\n  *) exit 2;;\nesac\n"
        ),
    );
}

impl Fixture {
    /// A PATH with only the tools the wrapper needs, and no guard binary.
    fn tools(&self) -> PathBuf {
        let bin = self.root.join("tools");
        if !bin.exists() {
            fs::create_dir_all(&bin).unwrap();
            for tool in ["cat", "grep", "git"] {
                let out = Command::new("sh")
                    .args(["-c", &format!("command -v {tool}")])
                    .output()
                    .unwrap();
                let found = String::from_utf8(out.stdout).unwrap();
                #[cfg(unix)]
                std::os::unix::fs::symlink(found.trim(), bin.join(tool)).unwrap();
            }
        }
        bin
    }

    /// A state build of `name`, as `agentic-build-*` leaves it.
    fn state_build(&self, build: &str, name: &str) -> PathBuf {
        self.root
            .join(".local/state")
            .join(build)
            .join("orchestration/target/release")
            .join(name)
    }

    /// Runs the wrapper with only `env` (variable, path) set beyond PATH and HOME.
    fn wrapper(&self, command: &str, env: &[(&str, &Path)]) -> Option<String> {
        self.wrapper_output(command, env).0
    }

    /// The wrapper's decision and its stderr.
    fn wrapper_output(&self, command: &str, env: &[(&str, &Path)]) -> (Option<String>, String) {
        let payload = json!({
            "tool_input": {"command": command, "description": "x"},
            "cwd": self.root.join("session"),
        });
        let mut run = Command::new("/bin/sh");
        run.arg(WRAPPER)
            .env_clear()
            .env("PATH", self.tools())
            .env("HOME", &self.root)
            .env("AGENTIC_TEST_GH", &self.fake)
            .env("GIT_CEILING_DIRECTORIES", &self.root);
        for (name, value) in env {
            run.env(name, value);
        }
        let mut child = run
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("run sh");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(payload.to_string().as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        (decision(output), stderr)
    }
}

#[test]
fn wrapper_without_the_binary_denies_label_writes() {
    let f = Fixture::new();
    for command in [
        "gh pr edit 3 --add-label 'Human-Approved",
        "echo x\ngh label delete human-approved 'x",
        "gh pr edit 3 --remove-label human-approved",
        "gh api repos/o/r/issues/3/labels -f labels[]=human-approved",
        "gh\tpr edit 3 --add-label\thuman-approved",
        "gh pr edit 3 --add-label human-approved",
        // A literal backslash-n is not a line break, as in `mentions_label`.
        r"gh pr edit 3 --body 'a\nb' --add-label human-approved",
    ] {
        let reason = f.wrapper(command, &[]).unwrap_or_default();
        assert!(reason.contains("not found"), "{command}: {reason}");
        assert!(
            reason.contains("may not set, remove or redefine the label `human-approved`"),
            "{command}: {reason}"
        );
        assert!(reason.contains("cargo install"), "{command}: {reason}");
    }
    for command in [
        "gh pr edit 3\necho human-approved",
        "echo human-approved gh",
        "gh pr edit 3 --add-label human-approved-x",
        "gh pr edit 3 --add-label bug",
        "git commit -m \"human-approved\"",
    ] {
        assert_eq!(f.wrapper(command, &[]), None, "{command}");
    }
}

#[test]
fn wrapper_warns_on_stderr_only_on_the_fallback() {
    let f = Fixture::new();
    for command in ["ls -la", "gh pr merge 1"] {
        let (_, stderr) = f.wrapper_output(command, &[]);
        assert!(
            stderr.contains("merge guard: the guard binary"),
            "{command}: {stderr}"
        );
        assert!(stderr.contains("loose fallback"), "{command}: {stderr}");
        assert!(stderr.contains("cargo install"), "{command}: {stderr}");
    }
    let guard = f.root.join("pinned/brakes");
    fake_guard(&guard, "found", true);
    let (decision, stderr) = f.wrapper_output("ls", &[("AGENTIC_SETUP_BIN", &guard)]);
    assert_eq!(decision.as_deref(), Some("found"));
    assert_eq!(stderr, "");
}

#[test]
fn wrapper_finds_a_cargo_installed_binary() {
    let f = Fixture::new();
    fake_guard(&f.root.join(".cargo/bin/brakes"), "home cargo brakes", true);
    assert_eq!(f.wrapper("ls", &[]).as_deref(), Some("home cargo brakes"));
    // CARGO_HOME replaces $HOME/.cargo: the guard there is run.
    let cargo_home = f.root.join("cargo-home");
    fake_guard(&cargo_home.join("bin/brakes"), "CARGO_HOME brakes", true);
    assert_eq!(
        f.wrapper("ls", &[("CARGO_HOME", &cargo_home)]).as_deref(),
        Some("CARGO_HOME brakes")
    );
    // With CARGO_HOME set elsewhere, $HOME/.cargo/bin is not looked at.
    let empty = f.root.join("empty-cargo-home");
    let reason = f
        .wrapper("gh pr merge 1", &[("CARGO_HOME", &empty)])
        .unwrap();
    assert!(reason.contains("not found"), "{reason}");
}

#[test]
fn wrapper_without_the_binary_denies_only_merges() {
    let f = Fixture::new();
    for command in [
        "gh pr merge 1 --squash",
        "cd ../other && gh -R org/other-app pr merge 2",
        "/usr/local/bin/gh pr merge",
        "gh api -X PUT repos/o/r/pulls/3/merge",
        "git status\ngh pr merge 4",
    ] {
        let reason = f.wrapper(command, &[]).unwrap_or_default();
        assert!(reason.contains("not found"), "{command}: {reason}");
        assert!(reason.contains("cargo install"), "{command}: {reason}");
        assert!(reason.contains("brakes"), "{command}: {reason}");
    }
    for command in [
        "ls -la",
        "cargo test --locked",
        "gh pr view 274 --json mergeStateStatus",
        "gh pr list",
        "gh api repos/o/r/pulls/3",
        "git merge --ff-only origin/main",
        "gh api -X DELETE repos/o/r/branches/main/protection",
    ] {
        assert_eq!(f.wrapper(command, &[]), None, "{command}");
    }
    // A binary from before the guard does not count, under either name.
    let old_setup = f.root.join("old/brakes");
    let old_run = f.root.join("old/agentic-run");
    fake_guard(&old_setup, "old brakes ran", false);
    fake_guard(&old_run, "old agentic-run ran", false);
    let old: &[(&str, &Path)] = &[
        ("AGENTIC_SETUP_BIN", &old_setup),
        ("AGENTIC_RUN_BIN", &old_run),
    ];
    let reason = f.wrapper("gh pr merge 5", old).unwrap();
    assert!(reason.contains("not found"), "{reason}");
    assert_eq!(f.wrapper("ls", old), None);
}

#[test]
fn wrapper_without_the_binary_denies_apply_remote() {
    let f = Fixture::new();
    for command in ["brakes apply . --remote", "cargo run -- --remote apply ."] {
        let reason = f.wrapper(command, &[]).unwrap_or_default();
        assert!(reason.contains("not found"), "{command}: {reason}");
        assert!(
            reason.contains("agent sessions may not run `brakes apply --remote`"),
            "{command}: {reason}"
        );
        assert!(reason.contains("cargo install"), "{command}: {reason}");
    }
    for command in ["brakes apply .", "brakes doctor . --remote"] {
        assert_eq!(f.wrapper(command, &[]), None, "{command}");
    }
}

#[test]
fn wrapper_runs_the_guard_it_finds() {
    let f = Fixture::new();
    f.red_only_in_other();
    let real = Path::new(env!("CARGO_BIN_EXE_brakes"));
    // The real guard decides, by the target's checks, found under either name.
    for variable in ["AGENTIC_SETUP_BIN", "AGENTIC_RUN_BIN"] {
        let env: &[(&str, &Path)] = &[(variable, real)];
        assert_eq!(f.wrapper("gh pr merge 1", env), None, "{variable}");
        let reason = f.wrapper("cd ../other && gh pr merge 1", env).unwrap();
        assert!(reason.contains("build: fail"), "{variable}: {reason}");
        assert_eq!(
            f.wrapper("cat <<'EOF'\ngh pr merge 1\nEOF", env),
            None,
            "{variable}"
        );
    }
    // The newest state build that has the guard, for each name.
    for name in ["agentic-run", "brakes"] {
        let build = |dir: &str| f.state_build(dir, name);
        fake_guard(&build("agentic-build-old"), &format!("older {name}"), true);
        fake_guard(&build("agentic-build-new"), &format!("newer {name}"), true);
        fake_guard(&build("agentic-build-pre"), "build without guard", false);
        let now = std::time::SystemTime::now();
        for (dir, secs) in [
            ("agentic-build-old", 300),
            ("agentic-build-new", 200),
            ("agentic-build-pre", 100),
        ] {
            fs::File::options()
                .write(true)
                .open(build(dir))
                .unwrap()
                .set_modified(now - std::time::Duration::from_secs(secs))
                .unwrap();
        }
        assert_eq!(
            f.wrapper("ls", &[]).as_deref(),
            Some(format!("newer {name}").as_str())
        );
    }
}

#[test]
fn wrapper_prefers_brakes_then_its_former_name_then_agentic_run() {
    // The lookup order of SPEC-merge-guard.md, "The wrapper"; the former name
    // `agentic-setup` for one release (#1067).
    const NAMES: [(&str, &str); 3] = [
        ("brakes", "BRAKES_BIN"),
        ("agentic-setup", "AGENTIC_SETUP_BIN"),
        ("agentic-run", "AGENTIC_RUN_BIN"),
    ];
    const ENTRIES: [&str; 12] = [
        "BRAKES_BIN",
        "brakes on PATH",
        "brakes in CARGO_HOME",
        "brakes state build",
        "AGENTIC_SETUP_BIN",
        "agentic-setup on PATH",
        "agentic-setup in CARGO_HOME",
        "agentic-setup state build",
        "AGENTIC_RUN_BIN",
        "agentic-run on PATH",
        "agentic-run in CARGO_HOME",
        "agentic-run state build",
    ];
    /// Places entry `index` as a fake guard named after it; returns its variable.
    fn place(f: &Fixture, index: usize, guard: bool) -> Option<(&'static str, PathBuf)> {
        let (name, variable) = NAMES[index / 4];
        let (path, variable) = match index % 4 {
            0 => (f.root.join("pinned").join(name), Some(variable)),
            1 => (f.tools().join(name), None),
            2 => (f.root.join(".cargo/bin").join(name), None),
            _ => (f.state_build("agentic-build-1", name), None),
        };
        fake_guard(&path, ENTRIES[index], guard);
        variable.map(|variable| (variable, path))
    }
    let run = |f: &Fixture, env: &[(&'static str, PathBuf)]| {
        let env: Vec<(&str, &Path)> = env.iter().map(|(k, v)| (*k, v.as_path())).collect();
        f.wrapper("gh pr merge 1", &env).unwrap()
    };
    // Every suffix of the list, all answering: its first entry wins, so each entry
    // precedes every later one (a total order in 23 runs, not 132 pairs; #1295).
    for (first, earlier) in ENTRIES.iter().enumerate() {
        let f = Fixture::new();
        let env: Vec<_> = (first..ENTRIES.len())
            .filter_map(|index| place(&f, index, true))
            .collect();
        assert_eq!(
            run(&f, &env),
            *earlier,
            "{earlier} before every later entry"
        );
        // The first one lacks `guard pre-bash`: it is skipped for the next.
        if let Some(later) = ENTRIES.get(first + 1) {
            let f = Fixture::new();
            let env: Vec<_> = (first..ENTRIES.len())
                .filter_map(|index| place(&f, index, index != first))
                .collect();
            assert_eq!(run(&f, &env), *later, "{earlier} skipped");
        }
    }
    // Every entry present but none with the guard: the fallback, naming brakes.
    let f = Fixture::new();
    let env: Vec<_> = (0..ENTRIES.len())
        .filter_map(|index| place(&f, index, false))
        .collect();
    let reason = run(&f, &env);
    assert!(reason.contains("not found"), "{reason}");
    assert!(reason.contains("cargo install"), "{reason}");
    assert!(reason.contains("brakes"), "{reason}");
}

// Secret `.env` files (#1309): the permission rules cover the file tools and the
// file commands Claude Code recognizes in Bash, not an interpreter that opens the
// file itself (https://code.claude.com/docs/en/permissions#what-read-and-edit-rules-cover),
// so the guard denies a command that names one, in every mode, and so does the
// wrapper without the binary.

const ENV_READ: &str = "Agent sessions may not read, copy or source a secret `.env` file \
                        (#1309): this command names one. `.env.example` and `.env.template` \
                        give the variable names; a value comes from a person.";

/// Commands that name a secret `.env` file, anywhere on the filesystem.
const NAMES_SECRET_ENV: [&str; 16] = [
    "cat .env",
    "cat ~/aps-1309/.env",
    "cat /tmp/x/.env.local",
    "python3 -c \"print(open('/Users/me/aps-1/.env').read())\"",
    "node -e 'console.log(require(\"fs\").readFileSync(\".env.production\",\"utf8\"))'",
    "source .env && cargo test",
    ". ./.env",
    "cp ../repo/.env.staging /tmp/out",
    "awk 1 app/.env.development",
    "ls\nless .env.test",
    "docker run --env-file=.env image",
    "cat .env*",
    "cat config/.env.*",
    "sh -c 'cat \"$HOME/work/.env\"'",
    "echo x; xxd .env",
    "base64 <.env",
];

/// Commands that name no secret `.env` file.
const NAMES_NO_SECRET_ENV: [&str; 10] = [
    "cat .env.example",
    "cat app/.env.template",
    "cat .envrc",
    "echo $NODE_ENV",
    "grep -rn process.env.API_URL src",
    "python3 -c 'import os; print(os.environ)'",
    "ls docs/.environment",
    "grep -n '\\.env' README.md",
    "cargo test --locked",
    "git log --oneline -3",
];

#[test]
fn commands_naming_a_secret_env_file_are_denied_in_every_mode() {
    let f = Fixture::new();
    for mode in [None, Some("full"), Some("light")] {
        for command in NAMES_SECRET_ENV {
            let reason = match mode {
                None => f.guard(command),
                Some(mode) => f.guard_in_mode(command, mode),
            };
            assert_eq!(reason.as_deref(), Some(ENV_READ), "{command} in {mode:?}");
        }
        for command in NAMES_NO_SECRET_ENV {
            let reason = match mode {
                None => f.guard(command),
                Some(mode) => f.guard_in_mode(command, mode),
            };
            assert_eq!(reason, None, "{command} in {mode:?}");
        }
    }
    assert!(f.calls().is_empty(), "{}", f.calls());
}

#[test]
fn wrapper_without_the_binary_denies_commands_naming_a_secret_env_file() {
    let f = Fixture::new();
    for command in NAMES_SECRET_ENV {
        let reason = f.wrapper(command, &[]).unwrap_or_default();
        assert!(reason.contains("not found"), "{command}: {reason}");
        assert!(reason.contains("secret `.env` file"), "{command}: {reason}");
    }
    for command in NAMES_NO_SECRET_ENV {
        assert_eq!(f.wrapper(command, &[]), None, "{command}");
    }
}
