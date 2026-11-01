//! Never merge on red: the Claude Code PreToolUse hook for Bash, as
//! `brakes guard pre-bash`.
//!
//! The owner's rule (2026-10-19): a pull request merges only when every check is
//! `pass` or `skipping`. The server-side required check is the primary mechanism;
//! this hook anticipates it, and where the plan allows no protection the hook is
//! the only barrier. The lexer and the merge options are copied from the frozen
//! supervisor (`orchestration/src/guard.rs`); this module holds what every deny
//! shares: the reason texts, the fallback `mentions_merge`, the deny JSON and the
//! mode the decision is taken in (`SPEC-merge-guard.md`).
//!
//! Every deny reason lives here because tests in this crate, in the supervisor and
//! in product repositories' sessions match on them.

use std::io::{self, Read};
use std::path::PathBuf;
use std::process::ExitCode;

use serde_json::{Value, json};

pub mod approval;
mod checks;
pub mod doctor;
mod labels;
pub mod lexer;
mod merge_options;
pub mod protection;
mod review;

/// `brakes guard <args>`: the PreToolUse hook. Reads the payload on stdin,
/// prints a deny line or nothing, and exits 0 whatever it decided (the decision is
/// the JSON; `onFailure: block` covers a crash). Any other arguments are a usage
/// error, exit 2, as `agentic-run guard` does.
pub fn cli(args: &[std::ffi::OsString]) -> ExitCode {
    if args.len() != 1 || args[0] != "pre-bash" {
        eprintln!("usage: brakes guard pre-bash");
        return ExitCode::from(2);
    }
    let mut input = String::new();
    let payload = io::stdin()
        .read_to_string(&mut input)
        .ok()
        .and_then(|_| serde_json::from_str::<Value>(&input).ok());
    let Some(payload) = payload else {
        deny(UNREADABLE_PAYLOAD);
        return ExitCode::SUCCESS;
    };
    let command = payload["tool_input"]["command"].as_str().unwrap_or("");
    if names_secret_env(command) {
        deny(ENV_READ);
        return ExitCode::SUCCESS;
    }
    let cwd = payload["cwd"]
        .as_str()
        .map(PathBuf::from)
        .or_else(|| std::env::current_dir().ok());
    // The person's approval (#1146): the one canonical form, where the host
    // prompts the person, only behind a real session's evidence and with no
    // layer answering for the person (#1152); anything else goes through the
    // #941 rule below.
    let managed = approval::MANAGED_SETTINGS.map(std::path::Path::new);
    // A session on the agents' App (#1255): its label never counts, so say so.
    if approval::canonical(command) && approval::app_session(&|name| std::env::var(name).ok()) {
        deny(LABEL_APP_SESSION);
        return ExitCode::SUCCESS;
    }
    if approval::canonical(command)
        && approval::person_prompts(
            &|name| std::env::var(name).ok(),
            approval::PROMPT_EVIDENCE,
            payload["permission_mode"].as_str(),
            &managed,
        )
    {
        println!("{}", decision_json("ask", LABEL_ASK));
        return ExitCode::SUCCESS;
    }
    match review::pre_bash(command, cwd) {
        Ok(None) => {}
        Ok(Some(reason)) => deny(&reason),
        Err(error)
            if mentions_merge(command)
                || mentions_remote_apply(command)
                || mentions_label(command) =>
        {
            deny(&failed(&error))
        }
        Err(error) => eprintln!("merge guard: {error}"),
    }
    ExitCode::SUCCESS
}

fn deny(reason: &str) {
    println!("{}", deny_json(reason));
}

/// Merge options that take a value, in `--flag value` and `--flag=value` forms.
pub const MERGE_VALUE_FLAGS: [&str; 11] = [
    "-b",
    "--body",
    "-F",
    "--body-file",
    "-t",
    "--subject",
    "-A",
    "--author-email",
    "--match-head-commit",
    "-R",
    "--repo",
];

/// `gh pr merge --admin`.
pub const ADMIN_MERGE: &str =
    "`gh pr merge --admin` bypasses branch protection; never merge on red.";
/// A `gh api` write on `…/pulls/<n>/merge`.
pub const API_MERGE: &str = "Merging through `gh api` bypasses the merge guard. Use `gh pr merge` \
                             once every check is pass or skipping.";
/// A `gh api` write on `…/branches/<name>/protection…`.
pub const PROTECTION_CHANGE: &str = "Branch protection on this repository is the owner's to \
                                     change. It enforces the rule never to merge on red; ask the \
                                     owner instead.";
/// A `gh api` write on `…/rulesets…`, repository or organization (denied from #691).
pub const RULESET_CHANGE: &str = "Rulesets on this repository are the owner's to change. They \
                                  enforce the rule never to merge on red; ask the owner instead.";
/// `brakes apply --remote` from an agent session (decision 2026-10-28, #848, point 4).
pub const APPLY_REMOTE: &str = "Agent sessions may not run `brakes apply --remote` \
                                (decision \"Installer applies repository settings, rulesets, \
                                environments and branch protection\", 2026-10-28, #848); the \
                                owner runs it by hand.";
/// An installer command whose arguments the guard cannot read (#850).
pub const APPLY_UNKNOWN: &str = "The merge guard cannot tell whether this command runs \
                                 `brakes apply --remote`, so it refuses it; spell the \
                                 arguments out, and leave `apply --remote` to the owner, who \
                                 runs it by hand.";
/// A command that sets, removes or redefines the `human-approved` label (owner, 2026-10-29).
pub const LABEL_CHANGE: &str = "The label `human-approved` records a person's approval of a \
                                change to a protected path (workflows, rulesets, CODEOWNERS, the \
                                installer lock, held-out tests); agent sessions may not set, \
                                remove or redefine it. Ask the owner.";
/// The canonical approval, routed to the person's prompt (#1146).
pub const LABEL_ASK: &str = "Adding `human-approved` records YOUR approval, as a person, of a \
                             change to a protected path. Approve only if you reviewed the pull \
                             request yourself; the agent cannot answer this prompt.";
/// The canonical approval in a session on the agents' GitHub App (#1255).
pub const LABEL_APP_SESSION: &str = "This session acts as the agents' GitHub App: a `human-approved` it \
                                     adds never counts, because the required check accepts the label only \
                                     from a person. Add it on GitHub under your own login.";
/// A label write whose labels the guard cannot read (#941).
pub const LABEL_UNKNOWN: &str = "The merge guard cannot tell whether this command sets \
                                 `human-approved`; spell the label out, or ask the owner.";
/// `gh pr checks` reported an empty list.
pub const NO_CHECKS: &str = "No CI checks are reported for this pull request; never merge on red.";
/// The hook payload on stdin was not JSON.
pub const UNREADABLE_PAYLOAD: &str =
    "merge guard failed (unreadable hook payload); refusing the command";

/// The target repository or pull request cannot be told from the command line.
pub fn cannot_tell(what: &str) -> String {
    format!(
        "The merge guard cannot tell {what}, so it cannot check the right pull request; \
         pass -R owner/repo and the PR number."
    )
}

/// At least one check of the target is not `pass` or `skipping`; `red` is sorted.
pub fn not_green(repo: &str, red: &[String]) -> String {
    format!(
        "Never merge on red (owner rule, 2026-10-19). Not green in {repo}: {}. Wait for the \
         fix, rebase and re-run.",
        red.join("; ")
    )
}

/// The guard itself failed (`gh` error, timeout, parse error): it refuses.
pub fn failed(error: &str) -> String {
    format!("merge guard failed ({error}); refusing the command")
}

/// The one JSON line that denies a command, as Claude Code reads it.
pub fn deny_json(reason: &str) -> String {
    decision_json("deny", reason)
}

/// One PreToolUse decision line (`deny`, or `ask` for the approval of #1146).
fn decision_json(decision: &str, reason: &str) -> String {
    json!({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": decision,
        "permissionDecisionReason": reason,
    }})
    .to_string()
}

/// A command that names a secret `.env` file (#1309).
pub const ENV_READ: &str = "Agent sessions may not read, copy or source a secret `.env` file \
                            (#1309): this command names one. `.env.example` and `.env.template` \
                            give the variable names; a value comes from a person.";

/// The `.env` files agent-guardrails denies, after `.env` itself.
const SECRET_ENV_SUFFIXES: [&str; 6] = [
    "",
    ".local",
    ".development",
    ".production",
    ".test",
    ".staging",
];

/// Whether `command` names a secret `.env` file (#1309): `.env` or one of its
/// denied suffixes as a whole path component, or followed by a glob (`.env*`,
/// `.env.*`). The permission rules cover the file tools and the file commands
/// Claude Code recognizes in Bash, not an interpreter that opens the file
/// itself (https://code.claude.com/docs/en/permissions#what-read-and-edit-rules-cover);
/// this catches the plain naming, wherever the file is. `process.env`,
/// `.env.example`, `.envrc` and a regular expression's `\.env` are not names.
pub fn names_secret_env(command: &str) -> bool {
    let word = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.');
    command.match_indices(".env").any(|(at, _)| {
        let before = command[..at].chars().next_back();
        if before.is_some_and(|c| word(c) || matches!(c, '\\' | '$')) {
            return false;
        }
        let rest = &command[at + ".env".len()..];
        let tail_len = rest.find(|c: char| !word(c)).unwrap_or(rest.len());
        let (tail, next) = (&rest[..tail_len], rest[tail_len..].chars().next());
        SECRET_ENV_SUFFIXES.contains(&tail) || next.is_some_and(|c| matches!(c, '*' | '?' | '['))
    })
}

/// The fallback when the command cannot be parsed: a line naming `gh` and then
/// `merge` or `protection`.
pub fn mentions_merge(command: &str) -> bool {
    command.lines().any(|line| {
        let words: Vec<_> = line
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .collect();
        words.iter().position(|w| *w == "gh").is_some_and(|at| {
            words[at..]
                .iter()
                .any(|w| *w == "merge" || *w == "protection")
        })
    })
}

/// The fallback for `brakes apply --remote` when the command cannot be
/// parsed: a line with the words `apply` and `--remote`.
pub fn mentions_remote_apply(command: &str) -> bool {
    command.lines().any(|line| {
        let words: Vec<_> = line
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-')
            .collect();
        words.contains(&"apply") && words.contains(&"--remote")
    })
}

/// The fallback for the `human-approved` label when the command cannot be
/// parsed: a line naming `gh` and then the label, in any case.
pub fn mentions_label(command: &str) -> bool {
    command.lines().any(|line| {
        let line = line.to_ascii_lowercase();
        let words: Vec<_> = line
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-')
            .collect();
        words
            .iter()
            .position(|w| *w == "gh")
            .is_some_and(|at| words[at..].contains(&"human-approved"))
    })
}

/// Where the merge-guard decision comes from for one target repository.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Mode {
    /// No server-side required check is known to protect the target: the hook is the barrier.
    Full,
    /// The server enforces the required check (probe within TTL): the hook anticipates it.
    Light,
}

/// The environment variable that can force `full`; it never selects `light`.
pub const MODE_ENV: &str = "AGENTIC_MERGE_GUARD_MODE";

impl Mode {
    /// The mode for one target repository: the server's evidence (`probed`,
    /// `None` without a fresh probe) unless `env` (the value of [`MODE_ENV`]) forces
    /// `full`. The environment can only tighten: any other value, `light`
    /// included, is ignored, and without evidence the mode is `full`.
    pub fn resolve(env: Option<&str>, probed: Option<Mode>) -> Mode {
        match (env, probed) {
            (Some("full"), _) | (_, None) => Mode::Full,
            (_, Some(mode)) => mode,
        }
    }
}

/// What the guard could not tell about a merge (the directory, the
/// repository, the pull request, or a failing `gh pr checks`) and the reason
/// full mode denies it with.
#[derive(Clone, Debug, PartialEq)]
pub struct Undecidable {
    what: String,
    denial: String,
}

impl Undecidable {
    /// The target cannot be told: full mode denies with [`cannot_tell`].
    pub fn target(what: &str) -> Self {
        Undecidable {
            what: what.to_owned(),
            denial: cannot_tell(what),
        }
    }

    /// `gh pr checks` failed: full mode denies with [`failed`], as before light mode.
    pub fn checks(error: &str) -> Self {
        Undecidable {
            what: format!("the check results ({error})"),
            denial: failed(error),
        }
    }
}

impl std::fmt::Display for Undecidable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} unknown", self.what)
    }
}

/// Light mode lets an undecidable merge through only because the server of
/// `repository` decides; the reason is logged, never swallowed. A denial on
/// evidence is never weakened.
pub fn decide(
    mode: Mode,
    repository: &str,
    outcome: Result<Option<String>, Undecidable>,
) -> Option<String> {
    match (mode, outcome) {
        (_, Ok(reason)) => reason,
        (Mode::Full, Err(why)) => Some(why.denial),
        (Mode::Light, Err(why)) => {
            eprintln!("merge guard: {why}; the server enforces the required check on {repository}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn mentions_merge_needs_gh_then_merge_or_protection_on_one_line() {
        assert!(mentions_merge("gh pr merge 1 --body 'unterminated"));
        assert!(mentions_merge(
            "echo x\ngh api -X DELETE repos/o/r/branches/main/protection"
        ));
        assert!(mentions_merge("timeout 60 gh pr merge"));
        assert!(!mentions_merge("echo 'unterminated"));
        assert!(!mentions_merge("git merge --ff-only origin/main"));
        assert!(!mentions_merge("merge then gh"));
        assert!(!mentions_merge("gh pr view 1\ngit merge x"));
        assert!(!mentions_merge("ghx merge"));
    }

    #[test]
    fn mentions_remote_apply_needs_apply_and_remote_on_one_line() {
        assert!(mentions_remote_apply("brakes apply . --remote 'x"));
        assert!(mentions_remote_apply("cargo run -- --remote apply ."));
        assert!(!mentions_remote_apply("brakes apply .\necho --remote"));
        assert!(!mentions_remote_apply("brakes doctor . --remote"));
        assert!(!mentions_remote_apply("git apply --remote-x"));
    }

    #[test]
    fn mentions_label_needs_gh_then_the_label_on_one_line() {
        assert!(mentions_label("gh pr edit 3 --add-label 'Human-Approved"));
        assert!(mentions_label("echo x\ngh label delete human-approved 'x"));
        assert!(!mentions_label("gh pr edit 3\necho human-approved"));
        assert!(!mentions_label("human-approved gh"));
        assert!(!mentions_label("gh pr edit 3 --add-label human-approved-x"));
    }

    #[test]
    fn deny_json_is_the_pre_tool_use_shape_on_one_line() {
        let text = deny_json(ADMIN_MERGE);
        assert!(!text.contains('\n'), "{text}");
        let value: Value = serde_json::from_str(&text).unwrap();
        let output = &value["hookSpecificOutput"];
        assert_eq!(output["hookEventName"], "PreToolUse");
        assert_eq!(output["permissionDecision"], "deny");
        assert_eq!(output["permissionDecisionReason"], ADMIN_MERGE);
    }

    #[test]
    fn reason_texts_are_the_supervisors() {
        assert_eq!(
            ADMIN_MERGE,
            "`gh pr merge --admin` bypasses branch protection; never merge on red."
        );
        assert_eq!(
            API_MERGE,
            "Merging through `gh api` bypasses the merge guard. Use `gh pr merge` once every \
             check is pass or skipping."
        );
        assert_eq!(
            PROTECTION_CHANGE,
            "Branch protection on this repository is the owner's to change. It enforces the \
             rule never to merge on red; ask the owner instead."
        );
        assert_eq!(
            RULESET_CHANGE,
            "Rulesets on this repository are the owner's to change. They enforce the rule \
             never to merge on red; ask the owner instead."
        );
        assert_eq!(
            LABEL_CHANGE,
            "The label `human-approved` records a person's approval of a change to a \
             protected path (workflows, rulesets, CODEOWNERS, the installer lock, held-out \
             tests); agent sessions may not set, remove or redefine it. Ask the owner."
        );
        assert_eq!(
            LABEL_UNKNOWN,
            "The merge guard cannot tell whether this command sets `human-approved`; spell \
             the label out, or ask the owner."
        );
        assert_eq!(
            NO_CHECKS,
            "No CI checks are reported for this pull request; never merge on red."
        );
        assert_eq!(
            UNREADABLE_PAYLOAD,
            "merge guard failed (unreadable hook payload); refusing the command"
        );
        assert_eq!(
            cannot_tell("which directory the merge runs in"),
            "The merge guard cannot tell which directory the merge runs in, so it cannot \
             check the right pull request; pass -R owner/repo and the PR number."
        );
        assert_eq!(
            not_green("o/r", &["build: fail".into(), "test: pending".into()]),
            "Never merge on red (owner rule, 2026-10-19). Not green in o/r: build: fail; \
             test: pending. Wait for the fix, rebase and re-run."
        );
        assert_eq!(
            failed("boom"),
            "merge guard failed (boom); refusing the command"
        );
    }

    #[test]
    fn full_mode_denies_what_it_cannot_tell_and_light_lets_the_server_decide() {
        let gap = || Err(Undecidable::target("which directory the merge runs in"));
        assert_eq!(
            decide(Mode::Full, "o/r", gap()),
            Some(cannot_tell("which directory the merge runs in"))
        );
        assert_eq!(decide(Mode::Light, "o/r", gap()), None);
        let red = || Err(Undecidable::checks("boom"));
        assert_eq!(decide(Mode::Full, "o/r", red()), Some(failed("boom")));
        assert_eq!(decide(Mode::Light, "o/r", red()), None);
        // A denial on evidence is never weakened by the mode.
        for mode in [Mode::Full, Mode::Light] {
            assert_eq!(
                decide(mode, "o/r", Ok(Some(ADMIN_MERGE.into()))).as_deref(),
                Some(ADMIN_MERGE)
            );
            assert_eq!(decide(mode, "o/r", Ok(None)), None);
        }
        assert_eq!(
            Undecidable::target("which host GH_HOST names").to_string(),
            "which host GH_HOST names unknown"
        );
        assert_eq!(
            Undecidable::checks("boom").to_string(),
            "the check results (boom) unknown"
        );
    }

    #[test]
    fn the_environment_can_only_tighten_the_mode() {
        for env in [None, Some("full"), Some("light"), Some("")] {
            assert_eq!(Mode::resolve(env, None), Mode::Full, "{env:?}");
            assert_eq!(Mode::resolve(env, Some(Mode::Full)), Mode::Full, "{env:?}");
        }
        assert_eq!(Mode::resolve(None, Some(Mode::Light)), Mode::Light);
        assert_eq!(Mode::resolve(Some("light"), Some(Mode::Light)), Mode::Light);
        assert_eq!(Mode::resolve(Some("full"), Some(Mode::Light)), Mode::Full);
    }

    #[test]
    fn merge_options_consume_values_and_fail_closed() {
        use merge_options::MergeOptions;
        let words = |line: &str| -> Vec<String> { line.split(' ').map(str::to_owned).collect() };
        let args = words("pr merge 1 --subject -Rme/session -R org/other-app --squash");
        let options = MergeOptions::parse(&args).unwrap();
        assert_eq!(options.repo, Some("org/other-app"));
        assert_eq!(options.selector, Some("1"));
        assert!(!options.admin);
        let args = words("pr merge --body=--admin --repo=x/y -Rz/w");
        let options = MergeOptions::parse(&args).unwrap();
        assert_eq!(options.repo, Some("z/w"));
        assert_eq!(options.selector, None);
        assert!(!options.admin);
        assert!(
            MergeOptions::parse(&words("pr merge 3 --admin"))
                .unwrap()
                .admin
        );
        let error = |line: &str| MergeOptions::parse(&words(line)).err();
        assert_eq!(
            error("pr merge 1 --future-option -Rme/session"),
            Some("the repository selected by an unknown merge option")
        );
        assert_eq!(
            error("pr merge 1 2"),
            Some("which pull request the merge arguments select")
        );
        assert_eq!(
            error("pr merge 1 --body"),
            Some("the value of a merge option")
        );
    }
}
