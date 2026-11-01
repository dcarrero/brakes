//! The review of one command line: which repository a `gh pr merge` targets,
//! which `gh api` writes the server would refuse anyway, and whether it runs
//! `brakes apply --remote` (#850).
//!
//! Copied from the supervisor (`orchestration/src/guard.rs`, frozen). The
//! substitutions: the lexer and the merge options come from the sibling
//! modules, the reason texts from `super`, `gh pr checks` from `checks.rs`, and
//! `git config` runs on `std::process::Command`.
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::labels::review_labels;
use super::lexer::{Item, Separator, parse};
use super::merge_options::MergeOptions;
use super::protection::{HOST, probed_mode};
use super::{
    ADMIN_MERGE, API_MERGE, APPLY_REMOTE, APPLY_UNKNOWN, MERGE_VALUE_FLAGS, Mode, NO_CHECKS,
    PROTECTION_CHANGE, RULESET_CHANGE,
};
use super::{Undecidable, decide, not_green};

const GREEN: [&str; 2] = ["pass", "skipping"];
pub(super) const WRITE_METHODS: [&str; 4] = ["POST", "PUT", "PATCH", "DELETE"];
/// Words before the command itself that run it unchanged.
const WRAPPERS: [&str; 5] = ["command", "env", "exec", "nohup", "time"];

/// Where the next command runs, as far as the guard can tell.
#[derive(Clone, Debug, PartialEq)]
pub(super) enum Dir {
    Known(PathBuf),
    Unknown,
}

/// A repository-selecting environment variable as the next command sees it.
#[derive(Clone, Debug, PartialEq)]
pub(super) enum EnvValue {
    /// As in the hook's own environment.
    Inherited,
    Set(String),
    Unset,
    Unknown,
}

/// The shell state that decides which repository a merge targets.
#[derive(Clone, Debug, PartialEq)]
struct Shell {
    dir: Dir,
    gh_repo: EnvValue,
    gh_host: EnvValue,
}

impl Shell {
    fn forget_changes(&mut self, before: &Self) {
        if self.dir != before.dir {
            self.dir = Dir::Unknown;
        }
        if self.gh_repo != before.gh_repo {
            self.gh_repo = EnvValue::Unknown;
        }
        if self.gh_host != before.gh_host {
            self.gh_host = EnvValue::Unknown;
        }
    }

    fn unknown() -> Self {
        Shell {
            dir: Dir::Unknown,
            gh_repo: EnvValue::Unknown,
            gh_host: EnvValue::Unknown,
        }
    }
}

const SHELLS: [&str; 5] = ["sh", "bash", "zsh", "dash", "ksh"];
/// Installer operations other than `apply`: never a remote write.
const OTHER_OPERATIONS: [&str; 7] = [
    "install",
    "doctor",
    "configure",
    "remove",
    "presets",
    "plan",
    "guard",
];
/// Installer options that take a value, so the value is not the operation.
const INSTALLER_VALUE_FLAGS: [&str; 5] = ["--source", "--module", "--set", "--preset", "--answers"];

pub(super) fn pre_bash(command: &str, cwd: Option<PathBuf>) -> Result<Option<String>, String> {
    let items = parse(command)?;
    let mut shell = Shell {
        dir: cwd.map_or(Dir::Unknown, Dir::Known),
        gh_repo: EnvValue::Inherited,
        gh_host: EnvValue::Inherited,
    };
    review(&items, &mut shell)
}

/// A `( … )` group restores the state it started with; a `)` without its `(`
/// (a `case` pattern) leaves nothing known.
fn review(items: &[Item], shell: &mut Shell) -> Result<Option<String>, String> {
    let mut groups = Vec::new();
    let mut conditional = false;
    let mut pipeline = false;
    let mut sequence_start = shell.clone();
    for (index, item) in items.iter().enumerate() {
        let reason = match item {
            Item::Subshell(inner) => review(inner, &mut shell.clone())?,
            Item::Command(words) => {
                let before = shell.clone();
                let reason = review_command(words, shell)?;
                // A short-circuited command may never run. Pipeline/background
                // commands need not affect this shell, even when they succeed.
                let isolated = matches!(
                    items.get(index + 1),
                    Some(Item::Separator(Separator::Pipeline | Separator::Background))
                );
                if conditional || pipeline || isolated {
                    shell.forget_changes(&before);
                }
                reason
            }
            Item::Separator(separator) => {
                // `&` backgrounds the whole preceding AND/OR list, including
                // state changes before its first && or ||.
                if matches!(separator, Separator::Background) {
                    shell.forget_changes(&sequence_start);
                }
                match separator {
                    Separator::Sequence | Separator::Background => {
                        conditional = false;
                        pipeline = false;
                        sequence_start = shell.clone();
                    }
                    Separator::Conditional => {
                        conditional = true;
                        pipeline = false;
                    }
                    Separator::Pipeline => pipeline = true,
                }
                None
            }
            Item::Open => {
                groups.push((shell.clone(), sequence_start.clone()));
                sequence_start = shell.clone();
                None
            }
            Item::Close => {
                (*shell, sequence_start) = groups
                    .pop()
                    .unwrap_or_else(|| (Shell::unknown(), Shell::unknown()));
                None
            }
        };
        if reason.is_some() {
            return Ok(reason);
        }
    }
    Ok(None)
}

fn is_assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty()
            && !name.starts_with(|c: char| c.is_ascii_digit())
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

fn basename(word: &str) -> &str {
    Path::new(word)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
}

/// A literal environment value; one that needs expanding is unknown.
fn env_value(value: &str) -> EnvValue {
    if value.contains(['$', '`']) {
        EnvValue::Unknown
    } else if value.is_empty() {
        EnvValue::Unset
    } else {
        EnvValue::Set(value.to_owned())
    }
}

/// A state change in a branch or loop body may or may not happen.
fn review_command(words: &[String], shell: &mut Shell) -> Result<Option<String>, String> {
    let before = shell.clone();
    let mut argv = words;
    let mut conditional = false;
    while let Some(word) = argv.first() {
        match word.as_str() {
            "then" | "else" | "elif" | "do" => conditional = true,
            "if" | "while" | "until" | "!" | "{" => {}
            _ => break,
        }
        argv = &argv[1..];
    }
    let reason = review_simple(argv, shell)?;
    if conditional {
        shell.forget_changes(&before);
    }
    Ok(reason)
}

fn review_simple(words: &[String], shell: &mut Shell) -> Result<Option<String>, String> {
    let mut argv = words;
    let mut prefix = None;
    let mut host_prefix = None;
    loop {
        match argv.first() {
            Some(word) if is_assignment(word) => {
                if let Some(value) = word.strip_prefix("GH_REPO=") {
                    prefix = Some(env_value(value));
                }
                if let Some(value) = word.strip_prefix("GH_HOST=") {
                    host_prefix = Some(env_value(value));
                }
            }
            Some(word) if WRAPPERS.contains(&word.as_str()) => {}
            _ => break,
        }
        argv = &argv[1..];
    }
    if argv.is_empty() {
        // `GH_REPO=x` alone: whether gh sees it depends on an earlier export.
        if prefix.is_some() {
            shell.gh_repo = EnvValue::Unknown;
        }
        if host_prefix.is_some() {
            shell.gh_host = EnvValue::Unknown;
        }
        return Ok(None);
    }
    // Prefixes belong to the invoked command, including scripts evaluated by
    // shell wrappers. They must not leak into the next outer command.
    let mut effective = shell.clone();
    if let Some(value) = &prefix {
        effective.gh_repo = value.clone();
    }
    if let Some(value) = &host_prefix {
        effective.gh_host = value.clone();
    }
    let reason = review_program(argv, &mut effective)?;
    if prefix.is_some() {
        effective.gh_repo = shell.gh_repo.clone();
    }
    if host_prefix.is_some() {
        effective.gh_host = shell.gh_host.clone();
    }
    *shell = effective;
    Ok(reason)
}

fn review_program(argv: &[String], shell: &mut Shell) -> Result<Option<String>, String> {
    let program = &argv[0];
    let args = &argv[1..];
    match program.as_str() {
        "cd" | "pushd" => {
            shell.dir = change_dir(&shell.dir, args.iter().find(|a| !a.starts_with('-')));
            return Ok(None);
        }
        "popd" => {
            shell.dir = Dir::Unknown;
            return Ok(None);
        }
        "export" | "declare" | "typeset" | "readonly" | "local" => {
            // Only a plain `export GH_REPO=value` is followed; any other
            // form (`export GH_REPO`, `-n`, `declare`) leaves it unknown.
            let plain = program == "export" && !args.iter().any(|a| a.starts_with('-'));
            for arg in args {
                for (name, state) in [
                    ("GH_REPO", &mut shell.gh_repo),
                    ("GH_HOST", &mut shell.gh_host),
                ] {
                    match arg.strip_prefix(&format!("{name}=")) {
                        Some(value) if plain => *state = env_value(value),
                        _ if arg.starts_with(name) => *state = EnvValue::Unknown,
                        _ => {}
                    }
                }
            }
            return Ok(None);
        }
        "unset" => {
            if args.iter().any(|a| a == "GH_REPO") {
                shell.gh_repo = EnvValue::Unset;
            }
            if args.iter().any(|a| a == "GH_HOST") {
                shell.gh_host = EnvValue::Unset;
            }
            return Ok(None);
        }
        // `eval` runs its words in this shell; `sh -c` in a child.
        "eval" => return review(&parse(&args.join(" "))?, shell),
        _ => {}
    }
    if SHELLS.contains(&basename(program)) {
        let script = args
            .iter()
            .skip_while(|a| !(a.starts_with('-') && !a.starts_with("--") && a.contains('c')))
            .skip(1)
            .find(|a| !a.starts_with('-'));
        return match script {
            Some(script) => review(&parse(script)?, &mut shell.clone()),
            None => Ok(None),
        };
    }
    match basename(program) {
        "gh" => return Ok(review_gh(args, shell, false)),
        name if is_installer(name) => return Ok(review_installer(args, true, false)),
        "cargo" => return Ok(review_cargo(args, false)),
        // `"$BIN" apply . --remote`: the program is not known, the words are.
        _ if expands(program) && applies_remote(args) => return Ok(Some(APPLY_REMOTE.into())),
        _ => {}
    }
    // `timeout 600 brakes …`, `xargs cargo run -- …`: a wrapper the
    // guard does not know, which may supply arguments of its own.
    if let Some(at) = args
        .iter()
        .position(|a| is_installer(basename(a)) || basename(a) == "cargo")
    {
        let rest = &args[at + 1..];
        let reason = if basename(&args[at]) == "cargo" {
            review_cargo(rest, true)
        } else {
            review_installer(rest, false, true)
        };
        if reason.is_some() {
            return Ok(reason);
        }
    }
    // `timeout 60 gh …`, `env -u X gh …`, `xargs gh …`: a wrapper the guard
    // does not know. Its options may change the directory or `GH_REPO`.
    let Some(at) = args.iter().position(|a| basename(a) == "gh") else {
        return Ok(None);
    };
    let before = &args[..at];
    let uncertain = before.iter().any(|a| {
        a.contains("GH_REPO") && !a.starts_with("GH_REPO=")
            || a.contains("GH_HOST") && !a.starts_with("GH_HOST=")
            || a.starts_with("-C")
            || a.starts_with("--chdir")
    });
    let mut effective = if uncertain {
        Shell::unknown()
    } else {
        shell.clone()
    };
    for arg in before {
        if let Some(value) = arg.strip_prefix("GH_REPO=") {
            effective.gh_repo = env_value(value);
        }
        if let Some(value) = arg.strip_prefix("GH_HOST=") {
            effective.gh_host = env_value(value);
        }
    }
    Ok(review_gh(&args[at + 1..], &mut effective, true))
}

/// The deny reason of a `gh` command, if any. `wrapped` is a `gh` run by an
/// unknown command, which may supply the pull request itself (`xargs`).
fn review_gh(args: &[String], shell: &mut Shell, wrapped: bool) -> Option<String> {
    let reason = match positionals(args).as_slice() {
        ["api", ..] => review_api(args),
        ["pr", "merge", ..] => review_merge(args, shell, wrapped),
        // A new default repository applies to the commands after it.
        ["repo", "set-default", ..] => {
            shell.dir = Dir::Unknown;
            None
        }
        _ => None,
    };
    reason.or_else(|| review_labels(args, &shell.dir, wrapped))
}

/// The words of a `gh` command that are not flags or flag values.
pub(super) fn positionals(args: &[String]) -> Vec<&str> {
    let mut out = Vec::new();
    let mut skip = false;
    for arg in args {
        if skip {
            skip = false;
        } else if MERGE_VALUE_FLAGS.contains(&arg.as_str()) {
            skip = true;
        } else if !arg.starts_with('-') {
            out.push(arg.as_str());
        }
    }
    out
}

fn change_dir(dir: &Dir, target: Option<&String>) -> Dir {
    let Some(target) = target else {
        return Dir::Unknown;
    };
    if target.contains(['$', '`', '*', '?']) || target.starts_with("~") && !target.starts_with("~/")
    {
        return Dir::Unknown;
    }
    let path = if let Some(rest) = target.strip_prefix("~/") {
        match std::env::var_os("HOME") {
            Some(home) => PathBuf::from(home).join(rest),
            None => return Dir::Unknown,
        }
    } else {
        PathBuf::from(target)
    };
    if path.is_absolute() {
        return Dir::Known(path);
    }
    match dir {
        Dir::Known(base) => Dir::Known(base.join(path)),
        Dir::Unknown => Dir::Unknown,
    }
}

pub(super) fn api_method(args: &[String]) -> String {
    for (index, arg) in args.iter().enumerate() {
        if (arg == "-X" || arg == "--method") && index + 1 < args.len() {
            return args[index + 1].to_uppercase();
        }
        if let Some(method) = arg.strip_prefix("--method=") {
            return method.to_uppercase();
        }
        if let Some(method) = arg.strip_prefix("-X").filter(|m| !m.is_empty()) {
            return method.to_uppercase();
        }
    }
    // gh api switches to POST when fields are given.
    if args.iter().any(|a| {
        matches!(
            a.as_str(),
            "-f" | "-F" | "--field" | "--raw-field" | "--input"
        )
    }) {
        "POST".into()
    } else {
        "GET".into()
    }
}

/// A word the shell expands, so the guard cannot read its value.
pub(super) fn expands(word: &str) -> bool {
    word.contains(['$', '`'])
}

/// The words `apply` and `--remote` (or `--remote=…`), anywhere and in any order.
fn applies_remote(args: &[String]) -> bool {
    args.iter().any(|a| a == "apply") && names_remote(args)
}

fn names_remote(args: &[String]) -> bool {
    args.iter()
        .any(|a| a == "--remote" || a.starts_with("--remote="))
}

/// The installer run with `args`: `apply --remote` is the owner's to run by
/// hand, in every mode (decision 2026-10-28, #848). `known` is a program word
/// that is the installer itself; `cargo run` and a word after an unknown
/// command may be another program. `wrapped` is a run by an unknown command,
/// which may add arguments the guard cannot see (`xargs`).
fn review_installer(args: &[String], known: bool, wrapped: bool) -> Option<String> {
    if applies_remote(args) {
        return Some(APPLY_REMOTE.into());
    }
    let mut words = args.iter();
    let mut operation = None;
    while let Some(word) = words.next() {
        if INSTALLER_VALUE_FLAGS.contains(&word.as_str()) {
            words.next();
        } else if !word.starts_with('-') {
            operation = Some(word.as_str());
            break;
        }
    }
    if operation.is_some_and(|op| OTHER_OPERATIONS.contains(&op)) {
        return None;
    }
    let apply = args.iter().any(|a| a == "apply");
    let expanded = args.iter().any(|a| expands(a));
    let unknown = wrapped && apply || expanded && (known || apply || names_remote(args));
    unknown.then(|| APPLY_UNKNOWN.into())
}

/// `cargo run … -- <args>` (or `cargo r`), whichever package it builds.
fn review_cargo(args: &[String], wrapped: bool) -> Option<String> {
    let dash = args.iter().position(|a| a == "--")?;
    let runs = args[..dash]
        .iter()
        .any(|a| a == "run" || a == "r" || expands(a));
    if runs {
        review_installer(&args[dash + 1..], false, wrapped)
    } else {
        None
    }
}

/// `/pulls/<number>/merge` as a whole path segment.
fn merges_pull(target: &str) -> bool {
    target.match_indices("/pulls/").any(|(at, m)| {
        let rest = &target[at + m.len()..];
        let digits = rest.chars().take_while(char::is_ascii_digit).count();
        digits > 0
            && rest[digits..]
                .strip_prefix("/merge")
                .is_some_and(|after| !after.starts_with(|c: char| c.is_alphanumeric() || c == '_'))
    })
}

/// `/branches/<name>/protection`.
fn touches_protection(target: &str) -> bool {
    target.match_indices("/branches/").any(|(at, m)| {
        let rest = &target[at + m.len()..];
        let name = rest
            .chars()
            .take_while(|c| *c != '/' && !c.is_whitespace())
            .count();
        name > 0 && rest[name..].starts_with("/protection")
    })
}

/// `/rulesets` as a whole path segment, repository or organization.
fn touches_rulesets(target: &str) -> bool {
    target.match_indices("/rulesets").any(|(at, m)| {
        !target[at + m.len()..].starts_with(|c: char| c.is_alphanumeric() || c == '_' || c == '-')
    })
}

/// A denial the server would make: never weakened by the mode.
fn review_api(args: &[String]) -> Option<String> {
    let target = args
        .iter()
        .filter(|a| !a.starts_with('-'))
        .cloned()
        .collect::<Vec<_>>()
        .join(" ");
    let writes = WRITE_METHODS.contains(&api_method(args).as_str());
    if writes && merges_pull(&target) {
        return Some(API_MERGE.into());
    }
    if writes && touches_rulesets(&target) {
        return Some(RULESET_CHANGE.into());
    }
    if writes && touches_protection(&target) {
        return Some(PROTECTION_CHANGE.into());
    }
    None
}

/// What a merge the guard cannot decide gets in the mode of its `target`, the
/// repository it is determined to merge into. Light needs that repository's
/// fresh server evidence on github.com; an undetermined target has no known
/// server and stays `full`. `AGENTIC_MERGE_GUARD_MODE=full` skips the probe.
fn undecidable(why: Undecidable, target: Option<String>, host: &EnvValue) -> Option<String> {
    let env = std::env::var(super::MODE_ENV).ok();
    let probed = match &target {
        Some(target) if env.as_deref() != Some("full") && on_github_com(host) => {
            probed_mode(target)
        }
        _ => None,
    };
    let mode = Mode::resolve(env.as_deref(), probed);
    decide(mode, target.as_deref().unwrap_or("?"), Err(why))
}

/// Whether `gh` would talk to github.com, the only host the probe reads.
fn on_github_com(host: &EnvValue) -> bool {
    match host {
        EnvValue::Set(host) => host == HOST,
        EnvValue::Unset => true,
        EnvValue::Inherited => std::env::var("GH_HOST").map_or(true, |h| h.is_empty() || h == HOST),
        EnvValue::Unknown => false,
    }
}

/// The deny reason of a `gh pr merge`, if any.
fn review_merge(args: &[String], shell: &Shell, wrapped: bool) -> Option<String> {
    let host = &shell.gh_host;
    let gap =
        |what: &str, target: Option<String>| undecidable(Undecidable::target(what), target, host);
    let options = match MergeOptions::parse(args) {
        Ok(options) => options,
        Err(what) => return gap(what, None),
    };
    if options.admin {
        return Some(ADMIN_MERGE.into());
    }
    let selector = options.selector;
    let dir = &shell.dir;
    let gh_repo = match shell.gh_repo.clone() {
        EnvValue::Inherited => env_value(&std::env::var("GH_REPO").unwrap_or_default()),
        other => other,
    };
    // The repository gh merges into, as `-R`, `GH_REPO` and the directory
    // decide it; `Err` names what is unknown.
    let target = || -> Result<String, String> {
        if let Some(repo) = options.repo {
            return Ok(repo.to_owned());
        }
        match &gh_repo {
            EnvValue::Set(repo) => Ok(repo.clone()),
            EnvValue::Unknown => Err("which repository GH_REPO names".into()),
            EnvValue::Unset | EnvValue::Inherited => match dir {
                Dir::Known(path) => dir_repo(path)
                    .ok_or_else(|| format!("the GitHub repository of {}", path.display())),
                Dir::Unknown => Err("which directory the merge runs in".into()),
            },
        }
    };
    if wrapped && selector.is_none() {
        return gap(
            "which pull request a wrapped `gh pr merge` merges",
            target().ok(),
        );
    }
    let repo = match target() {
        Ok(repo) => repo,
        Err(what) => return gap(&what, None),
    };
    let run_dir = match dir {
        Dir::Known(path) if path.is_dir() => Some(path),
        // Without a selector, gh reads the current branch of the directory.
        _ if selector.is_none() => {
            return gap("which directory the merge runs in", Some(repo));
        }
        _ => None,
    };
    if *host == EnvValue::Unknown {
        return gap("which host GH_HOST names", Some(repo));
    }
    let checks = match super::checks::checks(selector, &repo, run_dir, host) {
        Ok(checks) => checks,
        Err(error) => return undecidable(Undecidable::checks(&error), Some(repo), host),
    };
    if checks.is_empty() {
        return Some(NO_CHECKS.into());
    }
    let mut red: Vec<String> = checks
        .iter()
        .filter(|c| !GREEN.contains(&c["bucket"].as_str().unwrap_or("")))
        .map(|c| {
            format!(
                "{}: {}",
                c["name"].as_str().unwrap_or("?"),
                c["bucket"].as_str().unwrap_or("?")
            )
        })
        .collect();
    red.sort();
    if red.is_empty() {
        return None;
    }
    Some(not_green(&repo, &red))
}

/// The `owner/repo` gh resolves in a directory: the remote `gh repo
/// set-default` marked, or else the only GitHub repository among its remotes.
/// gh prefers `upstream` over `origin`, so two different repositories are not
/// guessed.
fn dir_repo(dir: &Path) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["config", "--get-regexp", r"^remote\..*\.(url|gh-resolved)$"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let mut urls = Vec::new();
    let mut resolved = Vec::new();
    for line in text.lines() {
        let (key, value) = line.split_once(' ')?;
        let (remote, field) = key.strip_prefix("remote.")?.rsplit_once('.')?;
        if field == "url" {
            urls.push((remote, value));
        } else {
            resolved.push((remote, value));
        }
    }
    let repos = |remote: Option<&str>| {
        urls.iter()
            .filter(|(r, _)| remote.is_none_or(|name| *r == name))
            .filter_map(|(_, url)| github_repo(url))
            .collect::<std::collections::BTreeSet<_>>()
    };
    let repos = match resolved.as_slice() {
        [] => repos(None),
        [(remote, "base")] => repos(Some(remote)),
        [(_, full)] => github_repo(&format!("https://github.com/{full}"))
            .into_iter()
            .collect(),
        _ => return None,
    };
    let mut repos = repos.into_iter();
    match (repos.next(), repos.next()) {
        (Some(repo), None) => Some(repo),
        _ => None,
    }
}

fn github_repo(url: &str) -> Option<String> {
    let path = [
        "git@github.com:",
        "ssh://git@github.com/",
        "https://github.com/",
    ]
    .iter()
    .find_map(|prefix| url.strip_prefix(prefix))?;
    let path = path.trim_end_matches('/');
    let path = path.strip_suffix(".git").unwrap_or(path);
    let (owner, repo) = path.split_once('/')?;
    let valid = |s: &str| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    };
    (valid(owner) && valid(repo)).then(|| format!("{owner}/{repo}"))
}

/// The installer's binary, by its name or a former one (#1067): the guard refuses
/// `apply --remote` through either.
fn is_installer(name: &str) -> bool {
    name == "brakes" || crate::legacy::BINARIES.contains(&name)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn github_urls_resolve_to_owner_and_repo() {
        assert_eq!(
            github_repo("git@github.com:o/r.git").as_deref(),
            Some("o/r")
        );
        assert_eq!(
            github_repo("https://github.com/o/r").as_deref(),
            Some("o/r")
        );
        assert_eq!(
            github_repo("ssh://git@github.com/o/r.git").as_deref(),
            Some("o/r")
        );
        assert_eq!(github_repo("https://gitlab.com/o/r"), None);
        assert_eq!(github_repo("https://github.com/o"), None);
    }

    #[test]
    fn endpoints_are_matched_as_segments() {
        assert!(merges_pull("repos/o/r/pulls/3/merge"));
        assert!(!merges_pull("repos/o/r/pulls/3/merges"));
        assert!(!merges_pull("repos/o/r/pulls/x/merge"));
        assert!(touches_protection("repos/o/r/branches/main/protection/x"));
        assert!(!touches_protection("repos/o/r/branches//protection"));
        assert!(touches_rulesets("repos/o/r/rulesets"));
        assert!(touches_rulesets("orgs/o/rulesets/3"));
        assert!(touches_rulesets(
            "/repos/o/r/rulesets?includes_parents=false"
        ));
        assert!(!touches_rulesets("repos/o/r/rulesets-notes"));
        assert!(!touches_rulesets("repos/o/r/rules/branches/main"));
    }
}
