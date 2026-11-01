//! The DeepSeek reviewer's step budget (#1240; SPEC-agent-guardrails.md, "CI hardening
//! for agent workflows", DeepSeek; decision "The DeepSeek judge", amended #1240). A
//! fixed 30 steps could not finish the installer's own 63-file pull request, and the
//! completeness rule (#1223) rightly blocked it. The review step now counts the change
//! in the runner's checkout and gives the agent `20 + files + ceil(lines / 1000)`
//! steps, never below the floor and never above the hard cap. These tests run the
//! script against real git repositories in a temporary directory. Needs bash and git.
use brakes::modules::agent_guardrails::review::{
    MAX_TURNS, OPENCODE_BUDGET_SH, OPENCODE_STEP_FLOOR, OPENCODE_STEP_MAX, TIMEOUT_MINUTES,
};
use std::{fs, path::Path, process::Command};

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["-c", "user.name=t", "-c", "user.email=t@example.invalid"])
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {out:?}");
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

/// A repository with one base commit, and a head commit made by `change`; returns the
/// two SHAs.
fn repo(dir: &Path, change: impl FnOnce(&Path)) -> (String, String) {
    git(dir, &["init", "-q", "-b", "main"]);
    fs::write(dir.join("README.md"), "base\n").unwrap();
    git(dir, &["add", "-A"]);
    git(dir, &["commit", "-q", "-m", "base"]);
    let base = git(dir, &["rev-parse", "HEAD"]);
    change(dir);
    git(dir, &["add", "-A"]);
    git(dir, &["commit", "-q", "-m", "head"]);
    let head = git(dir, &["rev-parse", "HEAD"]);
    (base, head)
}

/// Writes `files` new files of `lines` lines each.
fn add_files(dir: &Path, files: usize, lines: usize) {
    for i in 0..files {
        let body: String = (0..lines).map(|l| format!("line {l}\n")).collect();
        fs::write(dir.join(format!("file-{i}.txt")), body).unwrap();
    }
}

struct Budget {
    ok: bool,
    stdout: String,
    stderr: String,
}

fn budget(dir: &Path, base: &str, head: &str) -> Budget {
    let out = Command::new("bash")
        .arg("-c")
        .arg(OPENCODE_BUDGET_SH)
        .env("REPO_DIR", dir)
        .env("BASE_SHA", base)
        .env("HEAD_SHA", head)
        .env("OPENCODE_STEP_FLOOR", OPENCODE_STEP_FLOOR.to_string())
        .env("OPENCODE_STEP_MAX", OPENCODE_STEP_MAX.to_string())
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    Budget {
        ok: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

#[test]
fn the_floor_and_the_cap_are_the_decisions_figures() {
    // #1256: the floor is the DeepSeek budget's own; the other reviewers keep 30.
    assert_eq!(OPENCODE_STEP_FLOOR, 60);
    assert_eq!(MAX_TURNS, 30);
    assert_eq!(OPENCODE_STEP_MAX, 100);
}

#[test]
fn the_cap_at_the_slowest_measured_step_fits_the_job_timeout() {
    // #1240 and #1256 measured 4 to 6 seconds a step; two minutes cover the setup and
    // the structured verdict request (a whole 4-step job took about 40 seconds).
    const { assert!(OPENCODE_STEP_MAX * 6 + 2 * 60 <= TIMEOUT_MINUTES * 60) };
}

#[test]
fn the_small_changes_that_overran_on_a_pilot_get_the_floor() {
    // A pilot repository's pull requests of 6 files, 258 lines and 7 files, 632 lines used
    // 30 and 35 steps; the formula gives them 27 and 28.
    for (files, lines) in [(6, 43), (7, 90)] {
        let dir = tempfile::tempdir().unwrap();
        let (base, head) = repo(dir.path(), |d| add_files(d, files, lines));
        let run = budget(dir.path(), &base, &head);
        assert!(run.ok, "{}", run.stderr);
        assert_eq!(run.stdout, "60\n", "{files} files");
    }
}

#[test]
fn a_small_change_keeps_the_floor() {
    let dir = tempfile::tempdir().unwrap();
    let (base, head) = repo(dir.path(), |d| add_files(d, 3, 10));
    let run = budget(dir.path(), &base, &head);
    assert!(run.ok, "{}", run.stderr);
    assert_eq!(run.stdout, "60\n");
    assert!(
        run.stderr.contains(
            "cross-review: deepseek step budget 60 (3 files, 30 lines changed; floor 60, cap 100)"
        ),
        "{}",
        run.stderr
    );
}

#[test]
fn the_budget_grows_by_one_step_per_file_and_per_thousand_lines() {
    // 40 files of 60 lines: 20 + 40 + ceil(2400 / 1000) = 63.
    let dir = tempfile::tempdir().unwrap();
    let (base, head) = repo(dir.path(), |d| add_files(d, 40, 60));
    let run = budget(dir.path(), &base, &head);
    assert!(run.ok, "{}", run.stderr);
    assert_eq!(run.stdout, "63\n");
}

#[test]
fn deleted_lines_count_too() {
    // The base's README (1 line) removed and 40 files of 25 lines added:
    // 41 files, 1001 lines: 20 + 41 + 2 = 63.
    let dir = tempfile::tempdir().unwrap();
    let (base, head) = repo(dir.path(), |d| {
        fs::remove_file(d.join("README.md")).unwrap();
        add_files(d, 40, 25);
    });
    let run = budget(dir.path(), &base, &head);
    assert!(run.ok, "{}", run.stderr);
    assert_eq!(run.stdout, "63\n");
}

#[test]
fn the_measured_installer_pull_request_fits_under_the_cap() {
    // The shape of #1240's pull request: 63 files, about 6 500 changed lines, one
    // generated file of about 3 500: 20 + 63 + 7 = 90.
    let dir = tempfile::tempdir().unwrap();
    let (base, head) = repo(dir.path(), |d| {
        add_files(d, 62, 48);
        let big: String = (0..3500).map(|l| format!("generated {l}\n")).collect();
        fs::write(d.join("generated.yml"), big).unwrap();
    });
    let run = budget(dir.path(), &base, &head);
    assert!(run.ok, "{}", run.stderr);
    assert_eq!(run.stdout, "90\n");
}

#[test]
fn a_change_larger_than_the_cap_gets_the_cap_and_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let (base, head) = repo(dir.path(), |d| add_files(d, 120, 2));
    let run = budget(dir.path(), &base, &head);
    assert!(run.ok, "{}", run.stderr);
    assert_eq!(run.stdout, "100\n");
    assert!(
        run.stderr.contains(
            "cross-review: deepseek step budget 100 (120 files, 240 lines changed; floor 60, cap 100)"
        ),
        "{}",
        run.stderr
    );
}

#[test]
fn a_binary_file_counts_as_a_file_without_lines() {
    let dir = tempfile::tempdir().unwrap();
    let (base, head) = repo(dir.path(), |d| {
        fs::write(d.join("blob.bin"), [0u8, 159, 146, 150, 0, 1, 2, 3]).unwrap();
    });
    let run = budget(dir.path(), &base, &head);
    assert!(run.ok, "{}", run.stderr);
    assert!(
        run.stderr.contains("(1 files, 0 lines changed;"),
        "{}",
        run.stderr
    );
}

#[test]
fn the_repository_cannot_run_a_diff_driver_through_the_count() {
    // A diff driver needs configuration the pull request cannot write, but the count
    // asks git for none anyway (`--no-ext-diff --no-textconv`).
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("driver-ran");
    let (base, head) = repo(dir.path(), |d| {
        fs::write(d.join(".gitattributes"), "*.txt diff=probe\n").unwrap();
        add_files(d, 2, 5);
    });
    let command = format!("touch {}", marker.display());
    git(dir.path(), &["config", "diff.probe.textconv", &command]);
    git(dir.path(), &["config", "diff.probe.command", &command]);
    git(dir.path(), &["config", "diff.external", &command]);
    let run = budget(dir.path(), &base, &head);
    assert!(run.ok, "{}", run.stderr);
    assert!(!marker.exists(), "a diff driver ran");
}

#[test]
fn an_unknown_commit_fails_closed_without_a_budget() {
    let dir = tempfile::tempdir().unwrap();
    let (base, _) = repo(dir.path(), |d| add_files(d, 1, 1));
    let run = budget(
        dir.path(),
        &base,
        "0123456789abcdef0123456789abcdef01234567",
    );
    assert!(!run.ok);
    assert_eq!(run.stdout, "");
    assert!(
        run.stderr
            .contains("::error::cross-review: could not count the change"),
        "{}",
        run.stderr
    );
}

#[test]
fn a_revision_that_is_not_a_commit_sha_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (base, _) = repo(dir.path(), |d| add_files(d, 1, 1));
    for head in ["HEAD", "--output=/tmp/x", "main", ""] {
        let run = budget(dir.path(), &base, head);
        assert!(!run.ok, "{head}");
        assert_eq!(run.stdout, "", "{head}");
    }
}

#[test]
fn missing_bounds_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let (base, head) = repo(dir.path(), |d| add_files(d, 1, 1));
    for unset in ["OPENCODE_STEP_FLOOR", "OPENCODE_STEP_MAX", "REPO_DIR"] {
        let out = Command::new("bash")
            .arg("-c")
            .arg(OPENCODE_BUDGET_SH)
            .env("REPO_DIR", dir.path())
            .env("BASE_SHA", &base)
            .env("HEAD_SHA", &head)
            .env("OPENCODE_STEP_FLOOR", "30")
            .env("OPENCODE_STEP_MAX", "100")
            .env_remove(unset)
            .output()
            .unwrap();
        assert!(!out.status.success(), "{unset}");
        assert!(out.stdout.is_empty(), "{unset}");
    }
}
