//! N1: no forbidden token in the tree, its paths or its commit messages, checked
//! against `neutrality/forbidden.hmac` (keyed hashes; the list itself is not in the
//! repository), plus the home rule in plaintext. Fail-closed: a missing key, a key
//! that did not key the list, a missing list or a shallow clone fail.
//!
//! The tree test needs `NEUTRALITY_HMAC_KEY`, so it is ignored by the plain
//! `cargo test --locked`; the required `neutrality` job runs
//! `cargo test --locked --test neutrality -- --include-ignored`. A hit names the file
//! and line (or the commit), never the token.

#[path = "neutrality/keyed.rs"]
mod keyed;

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

/// The product's home: the only context its first word may appear in.
const HOME: &str = "gemba-app/brakes";
const KEYED_LIST: &str = "neutrality/forbidden.hmac";

fn git(root: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .map_err(|e| format!("git: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git {}: {}",
            args.first().unwrap_or(&""),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Every finding in the repository at `root`, as `path:line`, `commit <id>` or, for a
/// path that itself carries a token, `tracked path <n>` (its 1-based position in
/// `git ls-files`), so no finding or error repeats a token; empty when clean. An error
/// is a check that could not run, and fails like a finding.
fn check_repository(
    root: &Path,
    key: Option<&str>,
    range: Option<&str>,
) -> Result<Vec<String>, String> {
    let key = keyed::key(key)?;
    let list =
        fs::read_to_string(root.join(KEYED_LIST)).map_err(|e| format!("{KEYED_LIST}: {e}"))?;
    let mut checker = keyed::Checker::new(&key, keyed::parse(&list)?)?;
    let mut hits = |text: &str| {
        let mut lines = checker.lines(text);
        lines.extend(keyed::home_lines(text, HOME));
        lines.sort_unstable();
        lines.dedup();
        lines
    };
    let mut findings = Vec::new();

    for (n, path) in git(root, &["ls-files", "-z"])?
        .split('\0')
        .filter(|p| !p.is_empty())
        .enumerate()
    {
        // A path that carries a token is named by its position in `git ls-files`.
        let name = if hits(path).is_empty() {
            path.to_owned()
        } else {
            findings.push(format!("tracked path {} (its name)", n + 1));
            format!("tracked path {}", n + 1)
        };
        if path == KEYED_LIST {
            continue;
        }
        let file = root.join(path);
        let meta = fs::symlink_metadata(&file).map_err(|e| format!("{name}: {e}"))?;
        let text = if meta.is_symlink() {
            fs::read_link(&file)
                .map_err(|e| format!("{name}: {e}"))?
                .to_string_lossy()
                .into_owned()
        } else if meta.is_dir() {
            continue;
        } else {
            String::from_utf8_lossy(&fs::read(&file).map_err(|e| format!("{name}: {e}"))?)
                .into_owned()
        };
        findings.extend(hits(&text).into_iter().map(|line| format!("{name}:{line}")));
    }

    if git(root, &["rev-parse", "--is-shallow-repository"])?.trim() != "false" {
        return Err("a shallow clone: fetch the full history (fetch-depth: 0)".into());
    }
    let log = git(
        root,
        &["log", "--format=%H%x00%B%x01", range.unwrap_or("HEAD")],
    )?;
    for entry in log.split('\x01').map(str::trim).filter(|e| !e.is_empty()) {
        let (id, body) = entry.split_once('\0').unwrap_or((entry, ""));
        if !hits(body).is_empty() {
            findings.push(format!("commit {}", &id[..id.len().min(12)]));
        }
    }
    Ok(findings)
}

fn report(result: Result<Vec<String>, String>) -> Result<(), String> {
    let findings = result?;
    if findings.is_empty() {
        return Ok(());
    }
    Err(format!(
        "{} forbidden occurrences (tokens are never named; the owner's private scan names them):\n{}",
        findings.len(),
        findings.join("\n")
    ))
}

#[test]
#[ignore = "needs NEUTRALITY_HMAC_KEY; the `neutrality` job runs it with --include-ignored"]
fn the_tree_paths_and_history_carry_no_forbidden_token() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let key = std::env::var("NEUTRALITY_HMAC_KEY").ok();
    let range = std::env::var("NEUTRALITY_RANGE").ok();
    if let Err(e) = report(check_repository(&root, key.as_deref(), range.as_deref())) {
        panic!("{e}");
    }
}

// --- the check itself, over throwaway repositories with a synthetic list ---------

const KEY: &str = "synthetic-test-key";
const TOKEN: &str = "zorblax";

fn repository(files: &[(&str, &str)], message: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let list = keyed::render(KEY.as_bytes(), &[(keyed::Kind::Substring, TOKEN)]).unwrap();
    for (path, text) in [(KEYED_LIST, list.as_str())].iter().chain(files) {
        let path = root.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
    let id = ["-c", "user.name=t", "-c", "user.email=t@example.invalid"];
    git(root, &["init", "-q", "-b", "main"]).unwrap();
    git(root, &[&id[..], &["add", "-A"]].concat()).unwrap();
    git(root, &[&id[..], &["commit", "-q", "-m", message]].concat()).unwrap();
    dir
}

#[test]
fn a_clean_repository_passes() {
    let repo = repository(&[("src/a.rs", "fn main() {}\n")], "Initial import");
    assert_eq!(check_repository(repo.path(), Some(KEY), None), Ok(vec![]));
}

#[test]
fn a_planted_token_fails_with_file_and_line_without_the_token() {
    let repo = repository(
        &[("src/a.rs", "fn main() {}\n\nlet t = OldZorblaxTech;\n")],
        "Initial import",
    );
    let err = report(check_repository(repo.path(), Some(KEY), None)).unwrap_err();
    assert!(err.contains("src/a.rs:3"), "{err}");
    assert!(
        !err.to_lowercase().contains(TOKEN),
        "the token leaked: {err}"
    );
}

#[test]
fn a_planted_token_in_a_path_or_a_commit_message_fails_without_the_token() {
    let repo = repository(
        &[("docs/the-zorblax-notes.md", "ok\nZorblax\n")],
        "Add zorblax notes",
    );
    let findings = check_repository(repo.path(), Some(KEY), None).unwrap();
    assert_eq!(findings.len(), 3, "{findings:?}");
    assert_eq!(
        findings[..2],
        ["tracked path 1 (its name)", "tracked path 1:2"]
    );
    assert!(findings[2].starts_with("commit "), "{findings:?}");
    assert!(findings.iter().all(|f| !f.contains(TOKEN)));
}

#[test]
fn a_missing_or_empty_key_fails() {
    let repo = repository(&[("src/a.rs", "fn main() {}\n")], "Initial import");
    for key in [None, Some(""), Some("  \n")] {
        let err = check_repository(repo.path(), key, None).unwrap_err();
        assert!(err.contains("NEUTRALITY_HMAC_KEY"), "{err}");
    }
}

#[test]
fn a_key_that_did_not_key_the_list_fails() {
    let repo = repository(&[("src/a.rs", "fn main() {}\n")], "Initial import");
    assert!(check_repository(repo.path(), Some("another-key"), None).is_err());
}

#[test]
fn a_missing_keyed_list_fails() {
    let repo = repository(&[("src/a.rs", "fn main() {}\n")], "Initial import");
    fs::remove_file(repo.path().join(KEYED_LIST)).unwrap();
    assert!(check_repository(repo.path(), Some(KEY), None).is_err());
}

#[test]
fn the_exact_home_passes_and_any_other_use_of_its_word_fails() {
    // Built from HOME so this file never carries the bare word.
    let word = HOME.split('-').next().unwrap();
    let elsewhere = format!("{word}-app/other\n");
    let upper = format!("the {} letter\n", word.to_uppercase());
    let home = format!("see https://github.com/{HOME}\n");
    let repo = repository(
        &[
            ("README.md", home.as_str()),
            ("a.md", elsewhere.as_str()),
            ("b.md", upper.as_str()),
        ],
        "Initial import",
    );
    let findings = check_repository(repo.path(), Some(KEY), None).unwrap();
    assert_eq!(findings, ["a.md:1", "b.md:1"]);
}
