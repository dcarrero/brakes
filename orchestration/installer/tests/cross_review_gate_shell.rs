//! The gate of the `cross-review` job runs under `bash` (SPEC-agent-guardrails.md,
//! "Cross-family review as a required check"; #940): neither reviewer action fails
//! on findings by itself, so this step reads the reviewer's structured output, posts
//! one pull-request comment and makes the exit code the gate. A `gh` stand-in on
//! `PATH` records the comment; nothing reaches a real host. Needs bash and jq.
mod common;

use serde_json::{Value, json};
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};
use tempfile::TempDir;

const GATE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../templates/agent-guardrails/cross-review-gate.sh"
);

struct Run {
    _temp: TempDir,
    output: Output,
    comment: Option<String>,
    gh_args: Option<String>,
}

impl Run {
    fn stdout(&self) -> String {
        String::from_utf8_lossy(&self.output.stdout).into_owned()
    }
    fn errors(&self) -> Vec<String> {
        self.stdout()
            .lines()
            .filter(|l| l.starts_with("::error"))
            .map(str::to_owned)
            .collect()
    }
    fn passed(&self) -> bool {
        self.output.status.success()
    }
}

/// A `gh` that copies the `--body-file` it is given and its arguments under `dir`,
/// and exits 1 when `fail`.
fn fake_gh(dir: &Path, fail: bool) {
    let script = format!(
        "#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" > '{0}/gh-args'\nwhile [ $# -gt 0 ]; do\n  if [ \"$1\" = --body-file ]; then cp \"$2\" '{0}/comment'; fi\n  shift\ndone\nexit {1}\n",
        dir.display(),
        u8::from(fail)
    );
    let path = dir.join("bin/gh");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    common::write_executable(&path, &script);
}

fn gate(findings: &str, blocking: &str, gh_fails: bool) -> Run {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().to_path_buf();
    fake_gh(&dir, gh_fails);
    let path = format!(
        "{}:{}",
        dir.join("bin").display(),
        std::env::var("PATH").unwrap()
    );
    let output = Command::new("bash")
        .arg(GATE)
        .env("PATH", path)
        .env("FINDINGS", findings)
        .env("BLOCKING", blocking)
        .env("REVIEWER", "codex")
        .env("PR_NUMBER", "17")
        .env("RUNNER_TEMP", &dir)
        .output()
        .expect("bash is on PATH");
    let read = |name: &str| fs::read_to_string(dir.join(name)).ok();
    Run {
        comment: read("comment"),
        gh_args: read("gh-args"),
        output,
        _temp: temp,
    }
}

fn finding(severity: &str, title: &str) -> Value {
    json!({ "severity": severity, "path": "src/lib.rs", "line": 12, "title": title,
            "detail": "Why it matters." })
}

fn report(findings: Vec<Value>) -> String {
    json!({ "summary": "Reviewed the diff.", "reviewed_all": true, "not_reviewed": [],
            "findings": findings })
    .to_string()
}

/// A verdict whose reviewer says what it covered (#1223).
fn covered(reviewed_all: Value, not_reviewed: Value, findings: Vec<Value>) -> String {
    json!({ "summary": "Reviewed part of the diff.", "reviewed_all": reviewed_all,
            "not_reviewed": not_reviewed, "findings": findings })
    .to_string()
}

#[test]
fn no_findings_passes_and_posts_one_comment_on_the_pull_request() {
    let run = gate(&report(vec![]), "P0 P1", false);
    assert!(run.passed(), "{}", run.stdout());
    assert!(run.errors().is_empty());
    assert!(run.gh_args.unwrap().starts_with("pr comment 17 "));
    let comment = run.comment.expect("a comment is posted");
    assert!(comment.contains("Reviewed the diff."), "{comment}");
    assert!(comment.contains("No findings."), "{comment}");
}

#[test]
fn a_p1_finding_fails_under_p0_p1_with_one_error_line_each() {
    let findings = vec![
        finding("P1", "Test weakened"),
        finding("P2", "Naming"),
        finding("P0", "Data loss"),
    ];
    let run = gate(&report(findings), "P0 P1", false);
    assert!(!run.passed());
    assert_eq!(
        run.errors(),
        vec![
            "::error::P1 src/lib.rs:12 Test weakened",
            "::error::P0 src/lib.rs:12 Data loss",
        ]
    );
    assert!(
        run.stdout()
            .contains("cross-review: 2 blocking findings (P0 P1)")
    );
    let comment = run.comment.unwrap();
    assert!(comment.contains("**P1** (blocking)"), "{comment}");
    assert!(
        comment.contains("**P2** `src/lib.rs:12` Naming"),
        "{comment}"
    );
}

#[test]
fn a_p1_finding_passes_when_only_p0_blocks() {
    let run = gate(&report(vec![finding("P1", "Test weakened")]), "P0", false);
    assert!(run.passed(), "{}", run.stdout());
    assert!(run.errors().is_empty());
    assert!(
        run.stdout()
            .contains("cross-review: 0 blocking findings (P0)")
    );
}

#[test]
fn output_that_is_not_the_findings_object_fails_closed() {
    for findings in [
        "Looks good to me!",
        "{}",
        r#"{"summary":"ok"}"#,
        r#"{"summary":"ok","findings":"none"}"#,
        r#"{"summary":"ok","findings":[{"title":"no severity"}]}"#,
        // #1223: the coverage is part of the verdict, for every reviewer.
        r#"{"summary":"ok","findings":[]}"#,
        r#"{"summary":"ok","reviewed_all":true,"findings":[]}"#,
        r#"{"summary":"ok","not_reviewed":[],"findings":[]}"#,
        r#"{"summary":"ok","reviewed_all":"yes","not_reviewed":[],"findings":[]}"#,
        r#"{"summary":"ok","reviewed_all":true,"not_reviewed":"none","findings":[]}"#,
        r#"{"summary":"ok","reviewed_all":true,"not_reviewed":[3],"findings":[]}"#,
    ] {
        let run = gate(findings, "P0 P1", false);
        assert!(!run.passed(), "{findings:?} passed");
        assert_eq!(
            run.errors(),
            vec!["::error::cross-review: codex returned no findings object; refusing to pass"],
            "{findings:?}"
        );
        assert!(run.comment.is_none(), "{findings:?} posted a comment");
    }
}

// "CI hardening for agent workflows" (2026-10-29): the gate runs in a job of its own
// with the write token, so a verdict is refused before any `gh` call when it is
// empty (GitHub drops a job output that contains a secret), over 60 000 bytes or
// carries a credential-shaped token; the message names the check, never the text.

#[test]
fn an_empty_verdict_fails_closed_before_posting() {
    for findings in ["", "   ", "\n"] {
        let run = gate(findings, "P0 P1", false);
        assert!(!run.passed(), "{findings:?} passed");
        assert_eq!(
            run.errors(),
            vec![
                "::error::cross-review: codex returned an empty verdict (GitHub drops a job output that contains a secret); refusing to pass"
            ],
            "{findings:?}"
        );
        assert!(run.gh_args.is_none(), "{findings:?} called gh");
    }
}

/// A valid report padded to exactly `bytes` bytes.
fn report_of_bytes(bytes: usize) -> String {
    let frame = report(vec![]);
    let pad = "x".repeat(bytes - frame.len());
    json!({ "summary": format!("Reviewed the diff.{pad}"), "reviewed_all": true,
            "not_reviewed": [], "findings": [] })
    .to_string()
}

#[test]
fn a_verdict_over_60_000_bytes_fails_closed_before_posting() {
    let limit = report_of_bytes(60_000);
    assert_eq!(limit.len(), 60_000);
    let run = gate(&limit, "P0 P1", false);
    assert!(run.passed(), "{}", run.stdout());
    assert!(run.comment.is_some());

    let over = report_of_bytes(60_001);
    assert_eq!(over.len(), 60_001);
    let run = gate(&over, "P0 P1", false);
    assert!(!run.passed());
    assert_eq!(
        run.errors(),
        vec![
            "::error::cross-review: codex returned a verdict of 60001 bytes, over the 60000 allowed; refusing to pass"
        ]
    );
    assert!(run.gh_args.is_none(), "gh was called");
    assert!(!run.stdout().contains("xxxx"), "the text was printed");
}

const CREDENTIAL_ERROR: &str =
    "::error::cross-review: the verdict carries a credential-shaped token; refusing to post it";

#[test]
fn a_verdict_carrying_a_credential_shaped_token_fails_closed_before_posting() {
    let twenty = "A1b2C3d4E5f6G7h8I9j0";
    let shaped = [
        format!("sk-ant-api03-{twenty}"),
        format!("sk-{twenty}"),
        format!("ghp_{twenty}"),
        format!("gho_{twenty}"),
        format!("ghs_{twenty}"),
        format!("ghu_{twenty}"),
        format!("github_pat_{twenty}"),
        format!("xoxb-{twenty}"),
        "AKIAIOSFODNN7EXAMPLE".to_owned(),
        "AKIA0123456789ABCDEF".to_owned(),
        "-----BEGIN PRIVATE KEY-----".to_owned(),
        "-----BEGIN RSA PRIVATE KEY-----".to_owned(),
        "-----BEGIN OPENSSH PRIVATE KEY-----".to_owned(),
    ];
    for token in &shaped {
        for (place, report) in [
            (
                "summary",
                json!({ "summary": format!("The key {token} leaked."), "findings": [] }),
            ),
            (
                "detail",
                json!({ "summary": "Reviewed.", "findings": [{ "severity": "P3", "path": "a.rs", "line": 1, "title": "t", "detail": format!("see\n{token}\nabove") }] }),
            ),
            (
                "title",
                json!({ "summary": "Reviewed.", "findings": [{ "severity": "P0", "path": "a.rs", "line": 1, "title": format!("({token})"), "detail": "d" }] }),
            ),
            ("malformed", json!({ "summary": token, "findings": "none" })),
        ] {
            let run = gate(&report.to_string(), "P0 P1", false);
            assert!(!run.passed(), "{token} in {place} passed");
            assert_eq!(run.errors(), vec![CREDENTIAL_ERROR], "{token} in {place}");
            assert!(run.gh_args.is_none(), "{token} in {place} called gh");
            assert!(
                !run.stdout().contains(token.as_str()),
                "{token} in {place} was printed"
            );
        }
    }
}

#[test]
fn text_that_only_resembles_a_credential_is_posted() {
    for text in [
        "Prefer sk-prefixed keys from the environment",
        "ghp_ tokens must never be logged",
        "task-1234567890123456789012 is the job id",
        "AKIA followed by lower-case akiaiosfodnn7example is not a key id",
        "A line that says PRIVATE KEY without the BEGIN marker",
        "github_pat_short",
    ] {
        let report = json!({ "summary": text, "reviewed_all": true, "not_reviewed": [],
                            "findings": [] })
        .to_string();
        let run = gate(&report, "P0 P1", false);
        assert!(run.passed(), "{text:?}: {}", run.stdout());
        assert!(run.comment.is_some(), "{text:?} posted nothing");
    }
}

#[test]
fn reviewer_text_cannot_inject_a_workflow_command() {
    let hostile = finding("P0", "Bad\n::add-mask::secret\r%0A");
    let run = gate(&report(vec![hostile]), "P0 P1", false);
    assert!(!run.passed());
    assert_eq!(
        run.errors(),
        vec!["::error::P0 src/lib.rs:12 Bad%0A::add-mask::secret%0D%250A"]
    );
    assert!(!run.stdout().lines().any(|l| l.starts_with("::add-mask")));
}

#[test]
fn a_comment_that_cannot_be_posted_warns_and_the_findings_still_decide() {
    let clean = gate(&report(vec![]), "P0 P1", true);
    assert!(clean.passed(), "{}", clean.stdout());
    assert!(
        clean
            .stdout()
            .contains("::warning::cross-review: could not post the findings comment on #17")
    );
    let blocked = gate(&report(vec![finding("P0", "Data loss")]), "P0 P1", true);
    assert!(!blocked.passed());
}

#[test]
fn an_unknown_blocking_level_refuses() {
    let run = gate(&report(vec![]), "P0 P7", false);
    assert!(!run.passed());
    assert_eq!(
        run.errors(),
        vec!["::error::cross-review: BLOCKING must list P0 to P3, got 'P0 P7'"]
    );
}

// #1223: a reviewer that says it did not review everything never passes, whatever it
// found in the part it read (measured on #1175: no findings, "the review is
// incomplete" in the summary, and the check passed).

#[test]
fn an_incomplete_review_blocks_as_one_p0_naming_what_was_skipped() {
    for blocking in ["P0 P1", "P0"] {
        let verdict = covered(
            json!(false),
            json!([
                ".github/workflows/agentic-ci.yml",
                "scripts/sync.sh:2400-2744"
            ]),
            vec![],
        );
        let run = gate(&verdict, blocking, false);
        assert!(!run.passed(), "{blocking}: passed");
        assert_eq!(
            run.errors(),
            vec![
                "::error::cross-review: codex did not review .github/workflows/agentic-ci.yml, scripts/sync.sh:2400-2744",
                "::error::P0 :0 Review incomplete",
            ],
            "{blocking}"
        );
        assert!(
            run.stdout()
                .contains(&format!("cross-review: 1 blocking findings ({blocking})")),
            "{}",
            run.stdout()
        );
        let comment = run.comment.expect("the verdict is still posted");
        assert!(
            comment.contains("**P0** (blocking) `:0` Review incomplete"),
            "{comment}"
        );
        assert!(
            comment.contains(
                "Not reviewed: .github/workflows/agentic-ci.yml, scripts/sync.sh:2400-2744"
            ),
            "{comment}"
        );
        assert!(!comment.contains("No findings."), "{comment}");
    }
}

#[test]
fn an_incomplete_review_keeps_its_own_findings_and_adds_the_p0() {
    let verdict = covered(json!(false), json!(["b.rs"]), vec![finding("P2", "Naming")]);
    let run = gate(&verdict, "P0 P1", false);
    assert!(!run.passed());
    let comment = run.comment.unwrap();
    assert!(
        comment.contains("**P2** `src/lib.rs:12` Naming"),
        "{comment}"
    );
    assert!(comment.contains("Review incomplete"), "{comment}");
}

#[test]
fn a_skipped_list_or_a_false_flag_alone_is_incomplete_too() {
    // Contradictory answers fail closed: either half saying "not everything" blocks.
    let listed = gate(
        &covered(json!(true), json!(["a.rs"]), vec![]),
        "P0 P1",
        false,
    );
    assert!(!listed.passed());
    assert!(
        listed
            .errors()
            .contains(&"::error::P0 :0 Review incomplete".to_owned())
    );
    let unnamed = gate(&covered(json!(false), json!([]), vec![]), "P0 P1", false);
    assert!(!unnamed.passed());
    assert!(
        unnamed.errors().contains(
            &"::error::cross-review: codex did not review everything and named nothing it skipped"
                .to_owned()
        ),
        "{:?}",
        unnamed.errors()
    );
    assert!(
        unnamed
            .comment
            .unwrap()
            .contains("Not reviewed: unnamed by the reviewer"),
    );
}

#[test]
fn skipped_names_cannot_inject_a_workflow_command() {
    let verdict = covered(json!(false), json!(["a\n::add-mask::x%"]), vec![]);
    let run = gate(&verdict, "P0", false);
    assert!(!run.passed());
    assert!(
        !run.stdout().lines().any(|l| l.starts_with("::add-mask")),
        "{}",
        run.stdout()
    );
}
