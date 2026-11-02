//! The gate shells run under `bash` (SPEC-security.md; #788): the agreement
//! test runs the Rust check and `exceptions-check.sh` over the same fixture
//! matrix and asserts identical verdicts and identical finding texts (owner
//! decision 2026-10-28: two implementations tested to agree); the bypass
//! matrix does the same for `bypass-variable.sh` and `exceptions::bypass`.
//! Needs bash and jq only; nothing is downloaded.
use brakes::auditor::rules::Criticality;
use brakes::modules::security::exceptions::{
    self, DEFAULT_BYPASS_MAX_DAYS, Grant, INVENTORY, SECRETS_GATE, bypass, check,
};
use brakes::modules::security::pii;
use chrono::NaiveDate;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};
use tempfile::TempDir;

const TODAY: &str = "2026-11-10";
const FRAGMENTS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../templates/security/fragments"
);

fn today() -> NaiveDate {
    NaiveDate::parse_from_str(TODAY, "%Y-%m-%d").unwrap()
}

fn fragment(name: &str) -> PathBuf {
    Path::new(FRAGMENTS).join(name)
}

fn matrix() -> Vec<PathBuf> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/security/exceptions");
    let mut cases: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    cases.sort();
    cases
}

fn run(script: &str, args: &[&str], bypass_variable: Option<&str>) -> Output {
    let mut command = Command::new("bash");
    command
        .arg(fragment(script))
        .args(args)
        .env("SECURITY_TODAY", TODAY)
        .env(
            "SECURITY_BYPASS_MAX_DAYS",
            DEFAULT_BYPASS_MAX_DAYS.to_string(),
        )
        .env_remove("GITHUB_OUTPUT")
        .env_remove("BASE_SHA")
        .env_remove("SECURITY_BYPASS");
    if let Some(value) = bypass_variable {
        command.env("SECURITY_BYPASS", value);
    }
    command.output().expect("bash is on PATH")
}

fn lines(output: &Output) -> Vec<String> {
    assert!(
        output.stderr.is_empty(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout.clone())
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect()
}

/// The PII fixture matrix (T12, #800): each case a checkout with its
/// `.agent-setup/project.json` (the criticality) and, mostly, a `pii.yaml`.
fn pii_matrix() -> Vec<PathBuf> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/security/pii");
    let mut cases: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    cases.sort();
    cases
}

fn criticality_of(root: &Path) -> Option<Criticality> {
    let text = fs::read_to_string(root.join(".agent-setup/project.json")).unwrap();
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    value["criticality"].as_str().and_then(Criticality::parse)
}

#[test]
fn pii_check_agrees_with_the_rust_check_on_every_fixture() {
    let cases = pii_matrix();
    assert_eq!(cases.len(), 10, "{cases:?}");
    for case in &cases {
        let rust = pii::check(case, criticality_of(case)).unwrap();
        let output = run("pii-check.sh", &[case.to_str().unwrap()], None);
        let printed = lines(&output);
        assert_eq!(printed, rust.lines(), "{}", case.display());
        assert_eq!(
            output.status.code().unwrap(),
            if rust.passed() { 0 } else { 1 },
            "{}",
            case.display()
        );
    }
}

#[test]
fn pii_check_reads_the_criticality_from_the_environment_when_given() {
    let case = pii_matrix()
        .into_iter()
        .find(|c| c.ends_with("valid-not-required"))
        .unwrap();
    let mut command = Command::new("bash");
    command
        .arg(fragment("pii-check.sh"))
        .arg(&case)
        .env("SECURITY_CRITICALITY", "personal-data-or-payments");
    let output = command.output().unwrap();
    assert_eq!(lines(&output), ["pii: required, 4 fields"]);
    assert!(output.status.success());
}

#[test]
fn the_pii_matrix_states_are_the_ones_the_spec_names() {
    let text = |case: &str| {
        let root = pii_matrix()
            .into_iter()
            .find(|c| c.ends_with(case))
            .unwrap();
        pii::check(&root, criticality_of(&root)).unwrap().lines()
    };
    assert_eq!(text("valid"), ["pii: required, 4 fields"]);
    assert_eq!(text("valid-not-required"), ["pii: not required, 4 fields"]);
    assert_eq!(
        text("empty-under-criticality"),
        [
            "::error::.agent-setup/pii.yaml controller is not declared",
            "::error::.agent-setup/pii.yaml dsar_contact is not declared",
            "::error::.agent-setup/pii.yaml declares no fields; criticality personal-data-or-payments needs at least one",
            "pii: required, 0 fields",
        ]
    );
    assert_eq!(
        text("missing-key"),
        [
            "::error::Field users.email is missing lawful_basis",
            "::error::Field fields[1] is missing path",
            "pii: required, 2 fields",
        ]
    );
    assert_eq!(
        text("credentials-without-logs"),
        [
            "::error::Field users.password_hash is credentials and must exclude logs and traces",
            "pii: required, 1 fields",
        ]
    );
    assert_eq!(
        text("unknown-values"),
        [
            "::error::.agent-setup/pii.yaml has an unsupported schema 2",
            "::error::.agent-setup/pii.yaml sla_days must be a positive integer",
            "::error::Field users.email has an unknown category email",
            "::error::Field users.email has an unknown lawful_basis because",
            "::error::Field users.email has an unknown erasure forget",
            "::error::Field users.email excludes from an unknown consumer metrics",
            "::error::Field invoices.vat_id exclude_from is not an inline list",
            "::error::Field invoices.vat_id is retain-legal and its purpose names no obligation",
            "pii: required, 2 fields",
        ]
    );
    assert_eq!(
        text("outside-the-shape"),
        [
            "::error::.agent-setup/pii.yaml is unverified: line 9 is outside the seeded shape",
            "pii: required, 0 fields",
        ]
    );
    assert_eq!(
        text("absent-required"),
        [
            "::error::.agent-setup/pii.yaml is missing: criticality personal-data-or-payments needs a PII declaration",
            "pii: required, absent",
        ]
    );
    assert_eq!(text("absent-not-required"), ["pii: not required, absent"]);
    assert_eq!(text("absent-undeclared"), ["pii: not required, absent"]);
}

#[test]
fn jq_is_present_because_both_fragments_need_it() {
    let status = Command::new("jq")
        .arg("--version")
        .output()
        .expect("jq is on PATH");
    assert!(status.status.success());
}

#[test]
fn exceptions_check_agrees_with_the_rust_check_on_every_fixture() {
    let cases = matrix();
    assert_eq!(cases.len(), 31);
    for case in &cases {
        let name = case.file_name().unwrap().to_string_lossy();
        let rust = check(case, today(), DEFAULT_BYPASS_MAX_DAYS).unwrap();
        let mut expected: Vec<String> = rust
            .findings
            .iter()
            .map(|f| format!("::error::{f}"))
            .collect();
        expected.push(rust.claim());
        let output = run("exceptions-check.sh", &[case.to_str().unwrap()], None);
        assert_eq!(lines(&output), expected, "case {name}");
        assert_eq!(
            output.status.code(),
            Some(if rust.passed() { 0 } else { 1 }),
            "case {name}"
        );
    }
}

/// #1194: the shell twin carries the same Semgrep defaults as the Rust check,
/// as one JSON array on one line.
#[test]
fn exceptions_check_carries_the_rust_semgrep_defaults() {
    let script = fs::read_to_string(fragment("exceptions-check.sh")).unwrap();
    let line = script
        .lines()
        .find_map(|l| l.strip_prefix("semgrep_defaults='"))
        .expect("exceptions-check.sh defines semgrep_defaults");
    let list: Vec<String> = serde_json::from_str(line.strip_suffix('\'').unwrap()).unwrap();
    assert_eq!(list, exceptions::SEMGREP_DEFAULTS);
}

#[test]
fn exceptions_check_defaults_to_the_current_directory_and_prints_the_claim_last() {
    let case = matrix().into_iter().find(|c| c.ends_with("valid")).unwrap();
    let output = Command::new("bash")
        .arg(fragment("exceptions-check.sh"))
        .current_dir(&case)
        .env("SECURITY_TODAY", TODAY)
        .output()
        .unwrap();
    assert_eq!(
        lines(&output),
        ["exceptions: 7 active, 0 expired, 0 unregistered"]
    );
    assert!(output.status.success());
}

#[test]
fn the_unverified_shape_case_fails_the_gate_in_both_implementations() {
    for name in [
        "trivy-unverified",
        "osv-unverified",
        "gitleaks-toml-unverified",
    ] {
        let case = matrix().into_iter().find(|c| c.ends_with(name)).unwrap();
        let output = run("exceptions-check.sh", &[case.to_str().unwrap()], None);
        assert_eq!(output.status.code(), Some(1), "{name}");
        let printed = lines(&output);
        assert!(
            printed[0].contains("is unverified: line "),
            "{name}: {printed:?}"
        );
        assert!(
            !check(&case, today(), DEFAULT_BYPASS_MAX_DAYS)
                .unwrap()
                .passed()
        );
    }
}

// The bypass matrix.

fn entry(id: &str, kind: &str, target: &str, created: &str, expires: &str) -> String {
    format!(
        r##"{{ "id": "{id}", "kind": "{kind}", "target": "{target}", "reason": "fixture", "issue": "#731",
      "owner": "example-owner", "created": "{created}", "expires": "{expires}" }}"##
    )
}

/// A repository whose inventory holds one entry per bypass situation.
fn repository() -> TempDir {
    let dir = TempDir::new().unwrap();
    fs::create_dir_all(dir.path().join(".agent-setup")).unwrap();
    let entries = [
        entry(
            "osv-outage-2026-11",
            "job-bypass",
            "deps-scan",
            "2026-11-03",
            "2026-11-20",
        ),
        entry(
            "osv-outage-2026-10",
            "job-bypass",
            "deps-scan",
            "2026-10-01",
            "2026-10-20",
        ),
        entry(
            "fixture-key",
            "allowlist",
            ".gitleaksignore#a:b:1",
            "2026-11-01",
            "2027-05-01",
        ),
        entry(
            "sast-outage",
            "job-bypass",
            "sast-scan",
            "2026-11-03",
            "2026-11-20",
        ),
        entry(
            "too-long",
            "job-bypass",
            "deps-scan",
            "2026-11-01",
            "2026-12-15",
        ),
    ];
    fs::write(
        dir.path().join(INVENTORY),
        format!(
            "{{\n  \"schema\": 1,\n  \"exceptions\": [\n{}\n  ]\n}}\n",
            entries.join(",\n")
        ),
    )
    .unwrap();
    dir
}

fn agree(root: &Path, job: &str, variable: Option<&str>) -> (Vec<String>, i32) {
    let rust = bypass(
        root,
        job,
        variable.unwrap_or(""),
        today(),
        DEFAULT_BYPASS_MAX_DAYS,
    )
    .unwrap();
    let output = run(
        "bypass-variable.sh",
        &[job, root.to_str().unwrap()],
        variable,
    );
    let printed = lines(&output);
    assert_eq!(printed, rust.lines(), "job {job}, variable {variable:?}");
    let code = output.status.code().unwrap();
    assert_eq!(
        code,
        if rust.passed() { 0 } else { 1 },
        "job {job}, variable {variable:?}"
    );
    (printed, code)
}

#[test]
fn bypass_matrix_empty_active_expired_unknown_wrong_kind_wrong_job() {
    let repo = repository();
    let root = repo.path();
    assert_eq!(
        agree(root, "deps-scan", None),
        (vec!["bypass: none".to_string()], 0)
    );
    assert_eq!(
        agree(root, "deps-scan", Some("")),
        (vec!["bypass: none".to_string()], 0)
    );
    assert_eq!(
        agree(root, "deps-scan", Some("[]")),
        (vec!["bypass: none".to_string()], 0)
    );
    assert_eq!(
        agree(root, "deps-scan", Some(r#"["osv-outage-2026-11"]"#)),
        (
            vec![
                "::warning::bypass osv-outage-2026-11 until 2026-11-20 (#731)".to_string(),
                "bypass: osv-outage-2026-11".to_string(),
            ],
            0
        )
    );
    assert_eq!(
        agree(root, "deps-scan", Some(r#"["osv-outage-2026-10"]"#)),
        (
            vec!["::error::Bypass osv-outage-2026-10 expired on 2026-10-20; remove the variable or renew the exception".to_string()],
            1
        )
    );
    assert_eq!(
        agree(root, "deps-scan", Some(r#"["nobody"]"#)),
        (
            vec![
                "::error::Bypass nobody is not registered in .agent-setup/security-exceptions.json"
                    .to_string()
            ],
            1
        )
    );
    assert_eq!(
        agree(root, "deps-scan", Some(r#"["fixture-key"]"#)),
        (
            vec![
                "::error::Bypass fixture-key is a allowlist exception, not a job-bypass"
                    .to_string()
            ],
            1
        )
    );
    assert_eq!(
        agree(root, "deps-scan", Some(r#"["sast-outage"]"#)),
        (
            vec!["::error::Bypass sast-outage targets sast-scan, not deps-scan".to_string()],
            1
        )
    );
    assert_eq!(
        agree(root, "deps-scan", Some(r#"["too-long"]"#)),
        (
            vec![
                "::error::Bypass too-long is not a valid exception; see security-gate".to_string()
            ],
            1
        )
    );
}

#[test]
fn bypass_matrix_malformed_variable_several_ids_and_a_broken_inventory() {
    let repo = repository();
    let root = repo.path();
    for malformed in [
        "osv-outage-2026-11",
        r#"{"id": 1}"#,
        r#"["a", 1]"#,
        r#"[""]"#,
    ] {
        assert_eq!(
            agree(root, "deps-scan", Some(malformed)),
            (
                vec!["::error::SECURITY_BYPASS is not a JSON array of exception ids".to_string()],
                1
            ),
            "{malformed}"
        );
    }
    let (printed, code) = agree(
        root,
        "deps-scan",
        Some(r#"["osv-outage-2026-11", "nobody"]"#),
    );
    assert_eq!(code, 1);
    assert_eq!(
        printed,
        [
            "::error::Bypass nobody is not registered in .agent-setup/security-exceptions.json",
            "::warning::bypass osv-outage-2026-11 until 2026-11-20 (#731)",
            "bypass: osv-outage-2026-11",
        ]
    );
    let empty = TempDir::new().unwrap();
    assert_eq!(
        agree(empty.path(), "deps-scan", Some(r#"["osv-outage-2026-11"]"#)),
        (
            vec!["::error::Bypass osv-outage-2026-11 is not registered in .agent-setup/security-exceptions.json".to_string()],
            1
        )
    );
    assert_eq!(
        agree(empty.path(), "deps-scan", None),
        (vec!["bypass: none".to_string()], 0)
    );
    fs::create_dir_all(empty.path().join(".agent-setup")).unwrap();
    fs::write(empty.path().join(INVENTORY), "{ broken").unwrap();
    assert_eq!(
        agree(empty.path(), "deps-scan", Some(r#"["osv-outage-2026-11"]"#)),
        (
            vec!["::error::.agent-setup/security-exceptions.json does not parse".to_string()],
            1
        )
    );
}

#[test]
fn the_secrets_gate_never_honours_the_variable() {
    let repo = repository();
    for variable in [None, Some(r#"["osv-outage-2026-11"]"#)] {
        assert_eq!(
            agree(repo.path(), SECRETS_GATE, variable),
            (
                vec!["::error::security-gate admits no bypass variable".to_string()],
                1
            )
        );
    }
    let report = bypass(
        repo.path(),
        SECRETS_GATE,
        "",
        today(),
        DEFAULT_BYPASS_MAX_DAYS,
    )
    .unwrap();
    assert!(report.granted.is_empty());
}

#[test]
fn a_grant_is_written_to_github_output_when_the_job_sets_it() {
    let repo = repository();
    let output_file = repo.path().join("github-output");
    fs::write(&output_file, "").unwrap();
    let output = Command::new("bash")
        .arg(fragment("bypass-variable.sh"))
        .args(["deps-scan", repo.path().to_str().unwrap()])
        .env("SECURITY_TODAY", TODAY)
        .env("SECURITY_BYPASS", r#"["osv-outage-2026-11"]"#)
        .env("GITHUB_OUTPUT", &output_file)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        fs::read_to_string(&output_file).unwrap(),
        "id=osv-outage-2026-11\n"
    );
    let report = bypass(
        repo.path(),
        "deps-scan",
        r#"["osv-outage-2026-11"]"#,
        today(),
        30,
    )
    .unwrap();
    assert_eq!(
        report.granted,
        [Grant {
            id: "osv-outage-2026-11".into(),
            expires: "2026-11-20".into(),
            issue: "#731".into(),
        }]
    );
}

#[test]
fn bypass_requires_the_job_id() {
    let output = run("bypass-variable.sh", &[], None);
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("usage: bypass-variable.sh <job-id>"));
}

// The fragments themselves.

#[test]
fn neither_fragment_silences_a_failure() {
    for name in ["exceptions-check.sh", "bypass-variable.sh", "pii-check.sh"] {
        let text = fs::read_to_string(fragment(name)).unwrap();
        assert!(text.starts_with("#!/usr/bin/env bash\n"), "{name}");
        assert!(text.contains("\nset -euo pipefail\n"), "{name}");
        for forbidden in [
            "grep -v",
            "|| true",
            "continue-on-error:",
            "--ignore-unfixed",
        ] {
            assert!(!text.contains(forbidden), "{name} contains {forbidden:?}");
        }
        let syntax = Command::new("bash")
            .arg("-n")
            .arg(fragment(name))
            .output()
            .unwrap();
        assert!(
            syntax.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&syntax.stderr)
        );
    }
}

#[test]
fn shellcheck_is_clean_when_installed() {
    let Ok(probe) = Command::new("shellcheck").arg("--version").output() else {
        eprintln!("shellcheck not installed; skipped");
        return;
    };
    assert!(probe.status.success());
    for name in ["exceptions-check.sh", "bypass-variable.sh", "pii-check.sh"] {
        let output = Command::new("shellcheck")
            .arg(fragment(name))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

#[test]
fn constants_shared_with_the_fragments() {
    assert_eq!(exceptions::BYPASS_VARIABLE, "SECURITY_BYPASS");
    assert_eq!(SECRETS_GATE, "security-gate");
}

/// #973: a `binary-artifacts#<path>` target is an ordinary `allowlist` entry to
/// both checks (the 365-day bound, no new kind); neither reads the git index.
#[test]
fn a_binary_artifacts_allowlist_entry_is_accepted_by_both_checks_under_the_long_bound() {
    let case = matrix()
        .into_iter()
        .find(|c| c.ends_with("binary-registered"))
        .unwrap();
    let rust = check(&case, today(), DEFAULT_BYPASS_MAX_DAYS).unwrap();
    assert_eq!(
        rust.findings,
        ["Exception fixture-elf lasts 395 days; allowlist allows at most 365"]
    );
    assert_eq!(
        rust.claim(),
        "exceptions: 1 active, 0 expired, 0 unregistered"
    );
    let output = run("exceptions-check.sh", &[case.to_str().unwrap()], None);
    assert_eq!(
        lines(&output),
        [
            "::error::Exception fixture-elf lasts 395 days; allowlist allows at most 365",
            "exceptions: 1 active, 0 expired, 0 unregistered",
        ]
    );
}

/// #1217: an `accepted-risk` entry is a known kind with the 365-day bound to
/// both checks; no gate consumes it.
#[test]
fn an_accepted_risk_entry_is_accepted_by_both_checks_under_the_long_bound() {
    let case = matrix()
        .into_iter()
        .find(|c| c.ends_with("accepted-risk"))
        .unwrap();
    let rust = check(&case, today(), DEFAULT_BYPASS_MAX_DAYS).unwrap();
    assert_eq!(
        rust.findings,
        ["Exception too-long lasts 366 days; accepted-risk allows at most 365"]
    );
    assert_eq!(
        rust.claim(),
        "exceptions: 1 active, 0 expired, 0 unregistered"
    );
    let output = run("exceptions-check.sh", &[case.to_str().unwrap()], None);
    assert_eq!(
        lines(&output),
        [
            "::error::Exception too-long lasts 366 days; accepted-risk allows at most 365",
            "exceptions: 1 active, 0 expired, 0 unregistered",
        ]
    );
}

// ---- #799: a lowered coverage record needs an active `coverage-reset` ----

const RECORD: &str = ".agent-setup/coverage.json";

fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args([
            "-c",
            "user.name=fixture",
            "-c",
            "user.email=fixture@example.invalid",
        ])
        .args(["-c", "commit.gpgsign=false"])
        .args(args)
        .current_dir(root)
        .output()
        .expect("git is on PATH");
    assert!(output.status.success(), "git {args:?}: {output:?}");
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn inventory(entries: &[String]) -> String {
    format!(
        "{{\n  \"schema\": 1,\n  \"exceptions\": [\n{}\n  ]\n}}\n",
        entries.join(",\n")
    )
}

/// A git repository whose committed record is `base` (absent when `None`),
/// with `head` and `inventory` in the working tree; returns it and the base SHA.
fn coverage_repo(base: Option<&str>, head: Option<&str>, entries: &[String]) -> (TempDir, String) {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    fs::create_dir_all(root.join(".agent-setup")).unwrap();
    git(root, &["init", "-q"]);
    fs::write(root.join("README.md"), "fixture\n").unwrap();
    if let Some(base) = base {
        fs::write(root.join(RECORD), base).unwrap();
    }
    git(root, &["add", "-A"]);
    git(root, &["commit", "-q", "-m", "base"]);
    let sha = git(root, &["rev-parse", "HEAD"]);
    match head {
        Some(head) => fs::write(root.join(RECORD), head).unwrap(),
        None => {
            let _ = fs::remove_file(root.join(RECORD));
        }
    }
    if !entries.is_empty() {
        fs::write(root.join(INVENTORY), inventory(entries)).unwrap();
    }
    (dir, sha)
}

/// Runs both implementations against the repository with `BASE_SHA` set and
/// asserts the same lines and exit code; returns the lines and the code.
fn coverage_agree(root: &Path, sha: &str) -> (Vec<String>, i32) {
    let exists = Command::new("git")
        .args(["cat-file", "-e", &format!("{sha}:{RECORD}")])
        .current_dir(root)
        .status()
        .unwrap()
        .success();
    let base = exists.then(|| git(root, &["show", &format!("{sha}:{RECORD}")]));
    let pull_request = exceptions::PullRequest {
        coverage: base.as_deref(),
        ..Default::default()
    };
    let rust =
        exceptions::check_against(root, Some(&pull_request), today(), DEFAULT_BYPASS_MAX_DAYS)
            .unwrap();
    let mut expected: Vec<String> = rust
        .findings
        .iter()
        .map(|f| format!("::error::{f}"))
        .collect();
    expected.push(rust.claim());
    let output = Command::new("bash")
        .arg(fragment("exceptions-check.sh"))
        .arg(root)
        .env("SECURITY_TODAY", TODAY)
        .env("BASE_SHA", sha)
        .output()
        .unwrap();
    let printed = lines(&output);
    assert_eq!(printed, expected);
    let code = output.status.code().unwrap();
    assert_eq!(code, if rust.passed() { 0 } else { 1 });
    (printed, code)
}

fn reset(id: &str, target: &str, created: &str, expires: &str) -> String {
    entry(id, "coverage-reset", target, created, expires)
}

const BASE: &str =
    "{\n  \"schema\": 1,\n  \"apps\": {\n    \"api\": 80.50,\n    \"web\": 70\n  }\n}\n";

#[test]
fn a_lowered_record_without_a_coverage_reset_fails_in_both_implementations() {
    let head = "{\"schema\": 1, \"apps\": {\"api\": 79.25, \"web\": 70}}\n";
    let (repo, sha) = coverage_repo(Some(BASE), Some(head), &[]);
    assert_eq!(
        coverage_agree(repo.path(), &sha),
        (
            vec![
                "::error::.agent-setup/coverage.json lowers api from 80.5 to 79.25 without an active coverage-reset".to_owned(),
                "exceptions: 0 active, 0 expired, 0 unregistered".to_owned(),
            ],
            1
        )
    );
}

#[test]
fn a_lowered_record_with_an_active_coverage_reset_passes_in_both_implementations() {
    let head = "{\"schema\": 1, \"apps\": {\"api\": 60, \"web\": 70}}\n";
    let entries = [reset("reset-api", RECORD, "2026-11-01", "2026-11-20")];
    let (repo, sha) = coverage_repo(Some(BASE), Some(head), &entries);
    assert_eq!(
        coverage_agree(repo.path(), &sha),
        (
            vec!["exceptions: 1 active, 0 expired, 0 unregistered".to_owned()],
            0
        )
    );
}

#[test]
fn an_expired_or_misdirected_coverage_reset_does_not_cover_the_decrease() {
    let head = "{\"schema\": 1, \"apps\": {\"api\": 80.5, \"web\": 69.9}}\n";
    let lowered = "::error::.agent-setup/coverage.json lowers web from 70 to 69.9 without an active coverage-reset";
    let expired = [reset("old-reset", RECORD, "2026-10-01", "2026-10-20")];
    let (repo, sha) = coverage_repo(Some(BASE), Some(head), &expired);
    assert_eq!(
        coverage_agree(repo.path(), &sha),
        (
            vec![
                "::error::Exception old-reset expired on 2026-10-20".to_owned(),
                lowered.to_owned(),
                "exceptions: 0 active, 1 expired, 0 unregistered".to_owned(),
            ],
            1
        )
    );
    let elsewhere = [
        reset("other-file", "coverage.json", "2026-11-01", "2026-11-20"),
        entry(
            "wrong-kind",
            "job-bypass",
            RECORD,
            "2026-11-01",
            "2026-11-20",
        ),
    ];
    let (repo, sha) = coverage_repo(Some(BASE), Some(head), &elsewhere);
    assert_eq!(
        coverage_agree(repo.path(), &sha),
        (
            vec![
                lowered.to_owned(),
                "exceptions: 2 active, 0 expired, 0 unregistered".to_owned(),
            ],
            1
        )
    );
}

#[test]
fn a_removed_entry_or_a_deleted_record_lowers_every_app_it_held() {
    let head = "{\"schema\": 1, \"apps\": {\"api\": 81}}\n";
    let (repo, sha) = coverage_repo(Some(BASE), Some(head), &[]);
    assert_eq!(
        coverage_agree(repo.path(), &sha).0,
        [
            "::error::.agent-setup/coverage.json lowers web from 70 to absent without an active coverage-reset",
            "exceptions: 0 active, 0 expired, 0 unregistered",
        ]
    );
    let (repo, sha) = coverage_repo(Some(BASE), None, &[]);
    assert_eq!(
        coverage_agree(repo.path(), &sha).0,
        [
            "::error::.agent-setup/coverage.json lowers api from 80.5 to absent without an active coverage-reset",
            "::error::.agent-setup/coverage.json lowers web from 70 to absent without an active coverage-reset",
            "exceptions: 0 active, 0 expired, 0 unregistered",
        ]
    );
}

#[test]
fn a_raised_record_a_new_record_or_an_unparsed_base_is_not_a_decrease() {
    let raised = "{\"schema\": 1, \"apps\": {\"api\": 90, \"web\": 70, \"cli\": 0}}\n";
    let pass = (
        vec!["exceptions: 0 active, 0 expired, 0 unregistered".to_owned()],
        0,
    );
    let (repo, sha) = coverage_repo(Some(BASE), Some(raised), &[]);
    assert_eq!(coverage_agree(repo.path(), &sha), pass);
    let (repo, sha) = coverage_repo(None, Some(raised), &[]);
    assert_eq!(coverage_agree(repo.path(), &sha), pass);
    let (repo, sha) = coverage_repo(Some("{ broken"), Some(raised), &[]);
    assert_eq!(coverage_agree(repo.path(), &sha), pass);
}

#[test]
fn a_working_tree_record_that_does_not_parse_fails_against_a_parsed_base() {
    for head in [
        "{ broken",
        "{\"schema\": 1, \"apps\": {\"api\": \"80\"}}",
        "{\"schema\": 2, \"apps\": {}}",
    ] {
        let (repo, sha) = coverage_repo(Some(BASE), Some(head), &[]);
        assert_eq!(
            coverage_agree(repo.path(), &sha),
            (
                vec![
                    "::error::.agent-setup/coverage.json does not parse".to_owned(),
                    "exceptions: 0 active, 0 expired, 0 unregistered".to_owned(),
                ],
                1
            ),
            "{head}"
        );
    }
}

#[test]
fn without_a_base_sha_the_record_is_not_compared_and_doctor_never_compares() {
    let head = "{\"schema\": 1, \"apps\": {\"api\": 10, \"web\": 10}}\n";
    let (repo, _) = coverage_repo(Some(BASE), Some(head), &[]);
    let output = run(
        "exceptions-check.sh",
        &[repo.path().to_str().unwrap()],
        None,
    );
    assert_eq!(
        lines(&output),
        ["exceptions: 0 active, 0 expired, 0 unregistered"]
    );
    assert!(output.status.success());
    assert!(
        check(repo.path(), today(), DEFAULT_BYPASS_MAX_DAYS)
            .unwrap()
            .passed()
    );
}

#[test]
fn an_unavailable_base_commit_fails_closed_in_the_shell() {
    let (repo, _) = coverage_repo(Some(BASE), Some(BASE), &[]);
    let missing = "0123456789abcdef0123456789abcdef01234567";
    let output = Command::new("bash")
        .arg(fragment("exceptions-check.sh"))
        .arg(repo.path())
        .env("SECURITY_TODAY", TODAY)
        .env("BASE_SHA", missing)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        lines(&output),
        [
            format!(
                "::error::Base commit {missing} is not available; .agent-setup/coverage.json cannot be compared"
            ),
            "exceptions: 0 active, 0 expired, 0 unregistered".to_owned(),
        ]
    );
}

// ---- #799: coverage-ratchet.sh against the recorded reports of the two packs ----

const REPORTS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/stack-packs/coverage"
);

/// A repository with `record` and the two recorded reports, `api` (rust,
/// 54.55 %) and `web` (python-uv, 66.67 %), under their app directories.
fn ratchet_repo(record: Option<&str>) -> TempDir {
    use brakes::modules::stack_packs::packs::{python_uv::PYTHON_UV, rust::RUST};
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    for (app, report) in [
        ("api", "cargo-llvm-cov-0.9.1.json"),
        ("web", "coverage-py-7.17.0.json"),
    ] {
        fs::create_dir_all(root.join(app)).unwrap();
        fs::copy(
            Path::new(REPORTS).join(report),
            root.join(app).join("coverage.json"),
        )
        .unwrap();
    }
    fs::create_dir_all(root.join(".agent-setup")).unwrap();
    if let Some(record) = record {
        fs::write(root.join(RECORD), record).unwrap();
    }
    let apps = serde_json::json!([
        {"app": "api", "report": "api/coverage.json", "metric": RUST.coverage.unwrap().metric},
        {"app": "web", "report": "web/coverage.json", "metric": PYTHON_UV.coverage.unwrap().metric},
    ]);
    fs::write(root.join("apps.json"), apps.to_string()).unwrap();
    dir
}

fn ratchet(root: &Path, tolerance: &str) -> (Vec<String>, i32) {
    let apps = fs::read_to_string(root.join("apps.json")).unwrap();
    let output = Command::new("bash")
        .arg(fragment("coverage-ratchet.sh"))
        .arg(root)
        .env("COVERAGE_APPS", apps)
        .env("COVERAGE_TOLERANCE", tolerance)
        .output()
        .unwrap();
    (lines(&output), output.status.code().unwrap())
}

#[test]
fn the_ratchet_passes_within_tolerance_and_names_each_app() {
    let repo = ratchet_repo(Some(
        r#"{"schema": 1, "apps": {"api": 54.9, "web": 66.67}}"#,
    ));
    assert_eq!(
        ratchet(repo.path(), "0.5"),
        (
            vec![
                "coverage api: 54.55 (recorded 54.9)".to_owned(),
                "coverage web: 66.67 (recorded 66.67)".to_owned(),
            ],
            0
        )
    );
}

#[test]
fn below_the_record_minus_tolerance_fails_with_the_spec_text() {
    let repo = ratchet_repo(Some(r#"{"schema": 1, "apps": {"api": 55.10, "web": 60}}"#));
    assert_eq!(
        ratchet(repo.path(), "0.5"),
        (
            vec![
                "::error title=coverage api::Coverage 54.55 below recorded 55.1 (tolerance 0.5)"
                    .to_owned(),
                "::warning title=coverage web::Coverage 66.67; ratchet the record up".to_owned(),
            ],
            1
        )
    );
    // A tolerance of zero holds the record exactly.
    let repo = ratchet_repo(Some(
        r#"{"schema": 1, "apps": {"api": 54.6, "web": 66.67}}"#,
    ));
    assert_eq!(ratchet(repo.path(), "0").1, 1);
}

#[test]
fn the_seeded_zero_warns_to_ratchet_up_and_passes() {
    let repo = ratchet_repo(Some(r#"{"schema": 1, "apps": {"api": 0, "web": 0}}"#));
    assert_eq!(
        ratchet(repo.path(), "0.5"),
        (
            vec![
                "::warning title=coverage api::Coverage 54.55; ratchet the record up".to_owned(),
                "::warning title=coverage web::Coverage 66.67; ratchet the record up".to_owned(),
            ],
            0
        )
    );
}

#[test]
fn a_missing_record_entry_report_or_number_fails() {
    let repo = ratchet_repo(None);
    assert_eq!(
        ratchet(repo.path(), "0.5"),
        (
            vec!["::error::.agent-setup/coverage.json is absent".to_owned()],
            1
        )
    );
    let repo = ratchet_repo(Some(r#"{"schema": 1, "apps": {"api": "54"}}"#));
    assert_eq!(
        ratchet(repo.path(), "0.5"),
        (
            vec!["::error::.agent-setup/coverage.json does not parse".to_owned()],
            1
        )
    );
    let repo = ratchet_repo(Some(r#"{"schema": 1, "apps": {"api": 50}}"#));
    fs::remove_file(repo.path().join("api/coverage.json")).unwrap();
    fs::write(repo.path().join("web/coverage.json"), r#"{"totals": {}}"#).unwrap();
    assert_eq!(
        ratchet(repo.path(), "0.5"),
        (
            vec![
                "::error::Coverage report api/coverage.json of api is absent".to_owned(),
                "::error::Coverage metric of web is not a number".to_owned(),
            ],
            1
        )
    );
    let repo = ratchet_repo(Some(r#"{"schema": 1, "apps": {"api": 50}}"#));
    assert_eq!(
        ratchet(repo.path(), "0.5"),
        (
            vec![
                "::warning title=coverage api::Coverage 54.55; ratchet the record up".to_owned(),
                "::error::.agent-setup/coverage.json has no record for web".to_owned(),
            ],
            1
        )
    );
}

#[test]
fn the_ratchet_fragment_silences_nothing_and_is_shellcheck_clean() {
    let name = "coverage-ratchet.sh";
    let text = fs::read_to_string(fragment(name)).unwrap();
    assert!(text.starts_with("#!/usr/bin/env bash\n"));
    assert!(text.contains("\nset -euo pipefail\n"));
    for forbidden in ["|| true", "continue-on-error:"] {
        assert!(!text.contains(forbidden), "{forbidden}");
    }
    if let Ok(probe) = Command::new("shellcheck").arg("--version").output() {
        assert!(probe.status.success());
        let output = Command::new("shellcheck")
            .arg(fragment(name))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

// ---- #979: mutation-diff.sh -------------------------------------------------------
//
// The tools never run here: `MUTATION_COMMAND` and `MUTATION_STATS` are stand-ins
// that write the results the pinned tools wrote on 2026-10-29 (#977's recorded
// fixtures under `tests/fixtures/stack-packs/mutation/`) or synthetic ones.

const RECORDED: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/stack-packs/mutation"
);

fn mgit(root: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(["-c", "user.name=t", "-c", "user.email=t@example.invalid"])
        .args(["-c", "commit.gpgsign=false"])
        .args(args)
        .current_dir(root)
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {out:?}");
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

/// A repository with a base commit and a head commit that changes `changed`
/// (and adds nothing else); returns it with the base SHA.
fn diff_repo(files: &[(&str, &str)], changed: &[(&str, &str)]) -> (TempDir, String) {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    mgit(root, &["init", "-q", "-b", "main"]);
    let write = |path: &str, text: &str| {
        let full = root.join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, text).unwrap();
    };
    for (path, text) in files {
        write(path, text);
    }
    mgit(root, &["add", "-A"]);
    mgit(root, &["commit", "-q", "-m", "base"]);
    let base = mgit(root, &["rev-parse", "HEAD"]);
    for (path, text) in changed {
        write(path, text);
    }
    mgit(root, &["add", "-A"]);
    mgit(root, &["commit", "-q", "-m", "head"]);
    (dir, base)
}

fn mutation(dir: &Path, args: &[&str], base: &str, command: &str, stats: Option<&str>) -> Output {
    let mut cmd = Command::new("bash");
    cmd.arg(fragment("mutation-diff.sh"))
        .args(args)
        .current_dir(dir)
        .env("BASE_SHA", base)
        .env("MUTATION_COMMAND", command)
        .env("RECORDED", RECORDED)
        .env_remove("MUTATION_STATS");
    if let Some(stats) = stats {
        cmd.env("MUTATION_STATS", stats);
    }
    cmd.output().expect("bash is on PATH")
}

/// The verdict lines: claims and workflow commands, without the tool's output.
fn verdict(output: &Output) -> Vec<String> {
    String::from_utf8(output.stdout.clone())
        .unwrap()
        .lines()
        .filter(|l| l.starts_with("mutation:") || l.starts_with("::"))
        .map(str::to_owned)
        .collect()
}

const RUST_BASE: [(&str, &str); 2] = [
    ("Cargo.toml", "[package]\nname = \"sample\"\n"),
    ("src/lib.rs", "pub fn one() -> i32 {\n    1\n}\n"),
];
const RUST_HEAD: [(&str, &str); 1] = [(
    "src/lib.rs",
    "pub fn one() -> i32 {\n    1\n}\npub fn two() -> i32 {\n    2\n}\n",
)];

/// A stand-in for `cargo mutants` that writes `mutants.out` with these counts
/// and exits with `code`; like the tool, it starts from no `mutants.out`.
fn cargo_mutants(
    caught: usize,
    missed: usize,
    timeout: usize,
    unviable: usize,
    code: i32,
) -> String {
    let lines = |n: usize, kind: &str| {
        (0..n)
            .map(|i| format!("printf 'src/lib.rs:{i}:1: {kind} {i}\\n' >> mutants.out/{kind}.txt"))
            .collect::<Vec<_>>()
            .join("; ")
    };
    let writes = [
        lines(caught, "caught"),
        lines(missed, "missed"),
        lines(timeout, "timeout"),
        lines(unviable, "unviable"),
    ]
    .into_iter()
    .filter(|s| !s.is_empty())
    .collect::<Vec<_>>()
    .join("; ");
    format!(
        "rm -rf mutants.out; mkdir -p mutants.out; touch mutants.out/caught.txt mutants.out/missed.txt mutants.out/timeout.txt mutants.out/unviable.txt; {writes}; exit {code}"
    )
}

#[test]
fn rust_writes_the_merge_base_diff_with_b_prefixes_before_running_the_tool() {
    let (dir, base) = diff_repo(&RUST_BASE, &RUST_HEAD);
    let output = mutation(
        dir.path(),
        &["cargo-mutants", "80"],
        &base,
        "test -s git.diff && grep -q '^+++ b/src/lib.rs$' git.diff && grep -q '^+pub fn two' git.diff",
        None,
    );
    assert_eq!(
        verdict(&output),
        ["mutation: no mutants in the diff"],
        "{output:?}"
    );
    assert!(output.status.success());
}

#[test]
fn rust_scores_the_recorded_run_below_the_threshold() {
    let (dir, base) = diff_repo(&RUST_BASE, &RUST_HEAD);
    let output = mutation(
        dir.path(),
        &["cargo-mutants", "80"],
        &base,
        "mkdir -p mutants.out && cp \"$RECORDED\"/cargo-mutants-27.1.0/*.txt mutants.out/ && exit 2",
        None,
    );
    assert_eq!(
        verdict(&output),
        [
            "mutation: 40 % of 10 mutants killed",
            "::error::Mutation score 40 % on changed code, below 80 %"
        ]
    );
    assert_eq!(output.status.code(), Some(1));
}

#[test]
fn rust_passes_at_the_threshold_even_when_the_tool_reports_missed_mutants() {
    let (dir, base) = diff_repo(&RUST_BASE, &RUST_HEAD);
    let output = mutation(
        dir.path(),
        &["cargo-mutants", "80"],
        &base,
        &cargo_mutants(8, 2, 0, 0, 2),
        None,
    );
    assert_eq!(verdict(&output), ["mutation: 80 % of 10 mutants killed"]);
    assert!(output.status.success());
    let below = mutation(
        dir.path(),
        &["cargo-mutants", "81"],
        &base,
        &cargo_mutants(8, 2, 0, 0, 2),
        None,
    );
    assert_eq!(
        verdict(&below),
        [
            "mutation: 80 % of 10 mutants killed",
            "::error::Mutation score 80 % on changed code, below 81 %"
        ]
    );
    assert_eq!(below.status.code(), Some(1));
}

#[test]
fn rust_counts_timeouts_as_missed_and_excludes_unviable_mutants() {
    let (dir, base) = diff_repo(&RUST_BASE, &RUST_HEAD);
    let output = mutation(
        dir.path(),
        &["cargo-mutants", "80"],
        &base,
        &cargo_mutants(3, 0, 1, 5, 3),
        None,
    );
    assert_eq!(
        verdict(&output),
        [
            "mutation: 75 % of 4 mutants killed",
            "::error::Mutation score 75 % on changed code, below 80 %"
        ]
    );
    assert_eq!(output.status.code(), Some(1));
}

#[test]
fn rust_passes_when_the_diff_has_no_mutant() {
    let (dir, base) = diff_repo(&RUST_BASE, &[("README.md", "docs\n")]);
    for command in ["exit 0", &cargo_mutants(0, 0, 0, 2, 0)] {
        let output = mutation(dir.path(), &["cargo-mutants", "80"], &base, command, None);
        assert_eq!(
            verdict(&output),
            ["mutation: no mutants in the diff"],
            "{command}"
        );
        assert!(output.status.success(), "{command}");
    }
}

#[test]
fn rust_exit_codes_4_5_and_6_fail_with_their_meaning() {
    let (dir, base) = diff_repo(&RUST_BASE, &RUST_HEAD);
    for (code, text) in [
        (
            4,
            "::error::cargo mutants exited 4: the tests fail on the unmutated tree",
        ),
        (
            5,
            "::error::cargo mutants exited 5: the diff does not match the source tree",
        ),
        (
            6,
            "::error::cargo mutants exited 6: the diff could not be parsed",
        ),
        (1, "::error::cargo mutants exited 1"),
        (70, "::error::cargo mutants exited 70"),
    ] {
        let output = mutation(
            dir.path(),
            &["cargo-mutants", "80"],
            &base,
            &format!("echo 'tool message {code}' >&2; exit {code}"),
            None,
        );
        assert_eq!(verdict(&output), [text], "exit {code}");
        assert_eq!(output.status.code(), Some(code), "exit {code}");
        assert_eq!(
            String::from_utf8_lossy(&output.stderr).trim(),
            format!("tool message {code}"),
            "the tool's own message stays visible"
        );
    }
}

#[test]
fn the_module_pattern_is_mutmuts_module_name_of_the_path() {
    for (path, module) in [
        ("src/pkg/mod.py", "pkg.mod"),
        ("pkg/mod.py", "pkg.mod"),
        ("src/pkg/__init__.py", "pkg"),
        ("src/pkg/sub/deep.py", "pkg.sub.deep"),
        ("app.py", "app"),
        ("lib/srcutil.py", "lib.srcutil"),
    ] {
        let output = Command::new("bash")
            .arg(fragment("mutation-diff.sh"))
            .args(["module", path])
            .output()
            .unwrap();
        assert_eq!(lines(&output), [module], "{path}");
        assert!(output.status.success());
    }
}

const COVERED: &str = "[project]\nname = \"sample\"\n\n[tool.mutmut]\nsource_paths = [\"src\"]\nmutate_only_covered_lines = true  # mutation-diff\n";

fn python_base(pyproject: &str) -> Vec<(&str, &str)> {
    vec![
        ("pyproject.toml", pyproject),
        ("src/pkg/__init__.py", ""),
        ("src/pkg/mod.py", "def f():\n    return 1\n"),
        ("src/pkg/other.py", "def g():\n    return 1\n"),
        ("tests/test_mod.py", "def test_f():\n    pass\n"),
    ]
}

const PYTHON_HEAD: [(&str, &str); 2] = [
    ("src/pkg/mod.py", "def f():\n    return 2\n"),
    ("tests/test_mod.py", "def test_f():\n    assert True\n"),
];

/// A stand-in for `mutmut run "$MUTATION_MODULE*"`: records the pattern,
/// generates every file's meta as mutmut does, and fails as mutmut 3.8.1's
/// assertion does when the pattern matches no mutant.
const MUTMUT_RUN: &str = r#"echo "$MUTATION_MODULE*" >> runs.txt
mkdir -p mutants/src/pkg
for f in __init__ mod other; do echo '{}' > "mutants/src/pkg/$f.py.meta"; done
case "$MUTATION_MODULE" in
  pkg.mod) echo "    done" ;;
  *) echo "AssertionError: Filtered for specific mutants, but nothing matches" >&2; exit 1 ;;
esac"#;

/// A stand-in for `mutmut export-cicd-stats`: records the metas it would read
/// and writes the recorded stats.
const MUTMUT_STATS: &str = r#"find mutants -name '*.meta' | sort > metas.txt
cp "$RECORDED/mutmut-3.8.1-cicd-stats.json" mutants/mutmut-cicd-stats.json"#;

#[test]
fn python_runs_once_per_changed_file_and_scores_only_the_changed_files() {
    let (dir, base) = diff_repo(&python_base(COVERED), &PYTHON_HEAD);
    let output = mutation(
        dir.path(),
        &["mutmut", "80"],
        &base,
        MUTMUT_RUN,
        Some(MUTMUT_STATS),
    );
    assert_eq!(
        verdict(&output),
        [
            "mutation: no mutants in tests/test_mod.py",
            "mutation: 62 % of 8 mutants killed",
            "::error::Mutation score 62 % on changed code, below 80 %"
        ],
        "{output:?}"
    );
    assert_eq!(output.status.code(), Some(1));
    let read = |name: &str| fs::read_to_string(dir.path().join(name)).unwrap();
    assert_eq!(read("runs.txt"), "pkg.mod*\ntests.test_mod*\n");
    assert_eq!(read("metas.txt"), "mutants/src/pkg/mod.py.meta\n");
    let passing = mutation(
        dir.path(),
        &["mutmut", "60"],
        &base,
        MUTMUT_RUN,
        Some(MUTMUT_STATS),
    );
    assert_eq!(
        verdict(&passing),
        [
            "mutation: no mutants in tests/test_mod.py",
            "mutation: 62 % of 8 mutants killed"
        ]
    );
    assert!(passing.status.success());
}

#[test]
fn python_score_is_the_badge_formula_over_killed_timeout_total_and_skipped() {
    let (dir, base) = diff_repo(&python_base(COVERED), &PYTHON_HEAD);
    let stats = r#"echo '{"killed": 6, "survived": 1, "total": 10, "no_tests": 0, "skipped": 2, "suspicious": 0, "timeout": 1, "segfault": 0}' > mutants/mutmut-cicd-stats.json"#;
    let output = mutation(
        dir.path(),
        &["mutmut", "80"],
        &base,
        MUTMUT_RUN,
        Some(stats),
    );
    assert_eq!(
        verdict(&output)[1..],
        ["mutation: 87 % of 8 mutants killed"]
    );
    assert!(output.status.success());
}

#[test]
fn python_passes_when_no_python_file_changed_or_none_has_mutants() {
    let (dir, base) = diff_repo(&python_base(COVERED), &[("README.md", "docs\n")]);
    let output = mutation(
        dir.path(),
        &["mutmut", "80"],
        &base,
        "exit 9",
        Some("exit 9"),
    );
    assert_eq!(verdict(&output), ["mutation: no mutants in the diff"]);
    assert!(output.status.success());
    let (dir, base) = diff_repo(
        &python_base(COVERED),
        &[("tests/test_mod.py", "def test_f():\n    assert 1\n")],
    );
    let output = mutation(
        dir.path(),
        &["mutmut", "80"],
        &base,
        MUTMUT_RUN,
        Some("exit 9"),
    );
    assert_eq!(
        verdict(&output),
        [
            "mutation: no mutants in tests/test_mod.py",
            "mutation: no mutants in the diff"
        ]
    );
    assert!(output.status.success());
}

#[test]
fn python_fails_on_any_other_mutmut_failure() {
    let (dir, base) = diff_repo(&python_base(COVERED), &PYTHON_HEAD);
    let output = mutation(
        dir.path(),
        &["mutmut", "80"],
        &base,
        "echo 'Failed to run clean test'; exit 1",
        Some(MUTMUT_STATS),
    );
    assert_eq!(
        verdict(&output),
        ["::error::mutmut exited 1 on src/pkg/mod.py"]
    );
    assert_eq!(output.status.code(), Some(1));
}

#[test]
fn python_needs_mutate_only_covered_lines_in_mutmuts_own_configuration() {
    let error = "::error::mutmut reads mutate_only_covered_lines only from its configuration; set mutate_only_covered_lines = true under [tool.mutmut] in pyproject.toml (or [mutmut] in setup.cfg)";
    let unset = "[project]\nname = \"sample\"\n";
    let off = "[tool.mutmut]\nmutate_only_covered_lines = false\n";
    let elsewhere =
        "[tool.other]\nmutate_only_covered_lines = true\n[tool.mutmut]\nsource_paths = [\"src\"]\n";
    for (pyproject, setup_cfg, passes) in [
        (unset, None, false),
        (off, None, false),
        (elsewhere, None, false),
        // pyproject.toml's [tool.mutmut] wins: setup.cfg is then never read.
        (
            elsewhere,
            Some("[mutmut]\nmutate_only_covered_lines = true\n"),
            false,
        ),
        (
            unset,
            Some("[mutmut]\nmutate_only_covered_lines = True\n"),
            true,
        ),
        (unset, Some("[mutmut]\nmutate_only_covered_lines=1\n"), true),
        (
            unset,
            Some("[mutmut]\nmutate_only_covered_lines = no\n"),
            false,
        ),
        (COVERED, None, true),
    ] {
        let mut files = python_base(pyproject);
        if let Some(cfg) = setup_cfg {
            files.push(("setup.cfg", cfg));
        }
        let (dir, base) = diff_repo(&files, &PYTHON_HEAD);
        let output = mutation(
            dir.path(),
            &["mutmut", "80"],
            &base,
            MUTMUT_RUN,
            Some(MUTMUT_STATS),
        );
        let lines = verdict(&output);
        assert_eq!(
            lines.first().map(String::as_str) != Some(error),
            passes,
            "{pyproject:?} {setup_cfg:?}: {lines:?}"
        );
        if !passes {
            assert_eq!(lines, [error]);
            assert_eq!(output.status.code(), Some(1));
            assert!(!dir.path().join("runs.txt").exists(), "nothing ran");
        }
    }
}

#[test]
fn mutation_diff_silences_nothing_and_is_shellcheck_clean() {
    let text = fs::read_to_string(fragment("mutation-diff.sh")).unwrap();
    assert!(text.starts_with("#!/usr/bin/env bash\n"));
    assert!(text.contains("\nset -euo pipefail\n"));
    assert!(!text.contains("{{"), "the job template would substitute it");
    for forbidden in ["grep -v", "|| true", "continue-on-error:"] {
        assert!(!text.contains(forbidden), "contains {forbidden:?}");
    }
    let Ok(output) = Command::new("shellcheck")
        .arg(fragment("mutation-diff.sh"))
        .output()
    else {
        eprintln!("shellcheck not installed; skipped");
        return;
    };
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

// ---- #1088: the embedded (stripped) shells behave exactly as the fragments ----

/// `script` without its comment-only lines, written next to nothing else.
fn stripped(dir: &Path, script: &str) -> PathBuf {
    let text = fs::read_to_string(fragment(script)).unwrap();
    let out = dir.join(script);
    fs::write(
        &out,
        brakes::modules::security::embed::without_comment_lines(&text),
    )
    .unwrap();
    out
}

#[test]
fn the_stripped_exceptions_check_prints_what_the_fragment_prints_on_every_fixture() {
    let tmp = TempDir::new().unwrap();
    let script = stripped(tmp.path(), "exceptions-check.sh");
    for case in matrix() {
        let run_with = |path: &Path| {
            Command::new("bash")
                .arg(path)
                .arg(&case)
                .env("SECURITY_TODAY", TODAY)
                .env_remove("BASE_SHA")
                .output()
                .unwrap()
        };
        let original = run_with(&fragment("exceptions-check.sh"));
        let embedded = run_with(&script);
        assert_eq!(embedded.stdout, original.stdout, "{}", case.display());
        assert_eq!(
            embedded.status.code(),
            original.status.code(),
            "{}",
            case.display()
        );
    }
}

#[test]
fn the_stripped_bypass_variable_prints_what_the_fragment_prints() {
    let tmp = TempDir::new().unwrap();
    let script = stripped(tmp.path(), "bypass-variable.sh");
    let repo = repository();
    for variable in [
        "",
        r#"["osv-outage-2026-11"]"#,
        r#"["osv-outage-2026-10"]"#,
        r#"["nobody"]"#,
        "not json",
    ] {
        let run_with = |path: &Path| {
            Command::new("bash")
                .arg(path)
                .args(["deps-scan", repo.path().to_str().unwrap()])
                .env("SECURITY_TODAY", TODAY)
                .env("SECURITY_BYPASS", variable)
                .env_remove("GITHUB_OUTPUT")
                .output()
                .unwrap()
        };
        let original = run_with(&fragment("bypass-variable.sh"));
        let embedded = run_with(&script);
        assert_eq!(embedded.stdout, original.stdout, "{variable}");
        assert_eq!(embedded.status.code(), original.status.code(), "{variable}");
    }
}

// ---- #978: a `coverage-reset` for `diff-coverage#<n>` names the pull request that adds it ----

/// A git repository whose committed inventory holds `base` entries and whose
/// working tree holds `head` entries; returns it and the base SHA.
fn reset_repo(base: &[String], head: &[String]) -> (TempDir, String) {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    fs::create_dir_all(root.join(".agent-setup")).unwrap();
    git(root, &["init", "-q"]);
    if !base.is_empty() {
        fs::write(root.join(INVENTORY), inventory(base)).unwrap();
    }
    fs::write(root.join("README.md"), "fixture\n").unwrap();
    git(root, &["add", "-A"]);
    git(root, &["commit", "-q", "-m", "base"]);
    let sha = git(root, &["rev-parse", "HEAD"]);
    fs::write(root.join(INVENTORY), inventory(head)).unwrap();
    (dir, sha)
}

/// Both implementations with `BASE_SHA` and `PR_NUMBER` set: same lines, same exit code.
fn reset_agree(root: &Path, sha: &str, number: Option<u64>) -> (Vec<String>, i32) {
    let base_inventory = Command::new("git")
        .args(["cat-file", "-e", &format!("{sha}:{INVENTORY}")])
        .current_dir(root)
        .status()
        .unwrap()
        .success()
        .then(|| git(root, &["show", &format!("{sha}:{INVENTORY}")]));
    let pull_request = exceptions::PullRequest {
        coverage: None,
        inventory: base_inventory.as_deref(),
        number,
    };
    let rust =
        exceptions::check_against(root, Some(&pull_request), today(), DEFAULT_BYPASS_MAX_DAYS)
            .unwrap();
    let mut expected: Vec<String> = rust
        .findings
        .iter()
        .map(|f| format!("::error::{f}"))
        .collect();
    expected.push(rust.claim());
    let mut command = Command::new("bash");
    command
        .arg(fragment("exceptions-check.sh"))
        .arg(root)
        .env("SECURITY_TODAY", TODAY)
        .env("BASE_SHA", sha)
        .env_remove("PR_NUMBER");
    if let Some(n) = number {
        command.env("PR_NUMBER", n.to_string());
    }
    let output = command.output().unwrap();
    let printed = lines(&output);
    assert_eq!(printed, expected);
    let code = output.status.code().unwrap();
    assert_eq!(code, if rust.passed() { 0 } else { 1 });
    (printed, code)
}

#[test]
fn a_diff_coverage_reset_added_for_this_pull_request_is_accepted_by_both_checks() {
    let head = [reset(
        "dc-42",
        "diff-coverage#42",
        "2026-11-09",
        "2026-11-20",
    )];
    let (repo, sha) = reset_repo(&[], &head);
    assert_eq!(
        reset_agree(repo.path(), &sha, Some(42)),
        (
            vec!["exceptions: 1 active, 0 expired, 0 unregistered".to_owned()],
            0
        )
    );
}

#[test]
fn a_diff_coverage_reset_added_for_another_pull_request_is_unregistered_in_both_checks() {
    let head = [reset(
        "dc-41",
        "diff-coverage#41",
        "2026-11-09",
        "2026-11-20",
    )];
    let (repo, sha) = reset_repo(&[], &head);
    assert_eq!(
        reset_agree(repo.path(), &sha, Some(42)),
        (
            vec![
                "::error::Exception dc-41 targets diff-coverage#41; a coverage-reset added in pull request #42 must target diff-coverage#42".to_owned(),
                "exceptions: 1 active, 0 expired, 1 unregistered".to_owned(),
            ],
            1
        )
    );
    let malformed = [reset(
        "dc-x",
        "diff-coverage#abc",
        "2026-11-09",
        "2026-11-20",
    )];
    let (repo, sha) = reset_repo(&[], &malformed);
    assert_eq!(
        reset_agree(repo.path(), &sha, Some(42)).0[0],
        "::error::Exception dc-x targets diff-coverage#abc; a coverage-reset added in pull request #42 must target diff-coverage#42"
    );
}

#[test]
fn an_earlier_pull_requests_diff_coverage_reset_on_the_base_does_not_fail_a_later_one() {
    let earlier = [reset(
        "dc-41",
        "diff-coverage#41",
        "2026-11-09",
        "2026-11-20",
    )];
    let (repo, sha) = reset_repo(&earlier, &earlier);
    assert_eq!(
        reset_agree(repo.path(), &sha, Some(42)),
        (
            vec!["exceptions: 1 active, 0 expired, 0 unregistered".to_owned()],
            0
        )
    );
}

#[test]
fn without_a_pull_request_number_no_diff_coverage_target_is_judged() {
    let head = [reset(
        "dc-41",
        "diff-coverage#41",
        "2026-11-09",
        "2026-11-20",
    )];
    let (repo, sha) = reset_repo(&[], &head);
    assert_eq!(
        reset_agree(repo.path(), &sha, None),
        (
            vec!["exceptions: 1 active, 0 expired, 0 unregistered".to_owned()],
            0
        )
    );
    assert!(
        check(repo.path(), today(), DEFAULT_BYPASS_MAX_DAYS)
            .unwrap()
            .passed()
    );
}

#[test]
fn an_expired_diff_coverage_reset_for_this_pull_request_fails_as_expired_only() {
    let head = [reset(
        "dc-42",
        "diff-coverage#42",
        "2026-10-01",
        "2026-10-20",
    )];
    let (repo, sha) = reset_repo(&[], &head);
    assert_eq!(
        reset_agree(repo.path(), &sha, Some(42)),
        (
            vec![
                "::error::Exception dc-42 expired on 2026-10-20".to_owned(),
                "exceptions: 0 active, 1 expired, 0 unregistered".to_owned(),
            ],
            1
        )
    );
}

// ---- #978: diff-coverage.sh under bash, with a tempfile git history ----

const DIFF_FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/security/diff-coverage"
);

/// The two stacks of slice 3b as `diff-coverage.sh` receives them.
#[derive(Clone, Copy)]
enum Stack {
    Rust,
    PythonUv,
}

impl Stack {
    fn report(self) -> &'static str {
        match self {
            Stack::Rust => "lcov.info",
            Stack::PythonUv => "coverage.xml",
        }
    }
    fn fixture(self) -> PathBuf {
        Path::new(DIFF_FIXTURES).join(match self {
            Stack::Rust => "base.lcov",
            Stack::PythonUv => "base.xml",
        })
    }
    fn env(self) -> [(&'static str, &'static str); 3] {
        match self {
            Stack::Rust => [
                ("DIFF_FORMAT", "lcov"),
                ("SOURCE_EXT", "rs"),
                ("ABSENT", "fail"),
            ],
            Stack::PythonUv => [
                ("DIFF_FORMAT", "cobertura"),
                ("SOURCE_EXT", "py"),
                ("ABSENT", "warn"),
            ],
        }
    }
}

/// A repository whose `main` (also `origin/main`) holds `base` files, and a
/// pull-request commit on top that writes `changes`; returns it and the merge base.
fn pr_repo(base: &[(&str, &str)], changes: &[(&str, &str)]) -> (TempDir, String) {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    git(root, &["init", "-q", "-b", "main"]);
    for (path, text) in base {
        let full = root.join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, text).unwrap();
    }
    git(root, &["add", "-A"]);
    git(root, &["commit", "-q", "-m", "base"]);
    let sha = git(root, &["rev-parse", "HEAD"]);
    git(root, &["update-ref", "refs/remotes/origin/main", &sha]);
    git(root, &["checkout", "-q", "-b", "pr"]);
    for (path, text) in changes {
        let full = root.join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, text).unwrap();
    }
    git(root, &["add", "-A"]);
    git(root, &["commit", "-q", "--allow-empty", "-m", "pr"]);
    (dir, sha)
}

const DIFF_RUST_BASE: &[(&str, &str)] = &[
    ("src/lib.rs", "pub fn covered() {}\n"),
    ("src/dead.rs", "pub fn dead() {}\n"),
    ("src/other.rs", "pub fn other() {}\n"),
    ("tests/it.rs", "#[test]\nfn it() {}\n"),
    ("README.md", "# sample\n"),
];

const DIFF_PYTHON_BASE: &[(&str, &str)] = &[
    ("src/sample/__init__.py", "def covered():\n    return 1\n"),
    ("src/sample/dead.py", "def dead():\n    return 0\n"),
    ("src/sample/other.py", "def other():\n    return 2\n"),
    ("tests/test_sample.py", "def test_covered():\n    pass\n"),
];

/// Every variable `diff-coverage.sh` reads as its own input, from the
/// script's own `inputs=(…)` line, the one list it unsets (#1222).
fn diff_coverage_inputs() -> Vec<String> {
    let text = fs::read_to_string(fragment("diff-coverage.sh")).unwrap();
    let line = text
        .lines()
        .find_map(|l| l.strip_prefix("inputs=("))
        .expect("diff-coverage.sh declares inputs=(...)");
    let names = line.strip_suffix(')').expect("inputs=(...) on one line");
    names.split_whitespace().map(str::to_owned).collect()
}

/// The upper-case names the script reads: `$NAME`, `${NAME…}` and awk's
/// `ENVIRON["NAME"]`.
fn names_read_by(text: &str) -> std::collections::BTreeSet<String> {
    let name = |rest: &str| -> Option<String> {
        let n: String = rest
            .chars()
            .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_')
            .collect();
        n.starts_with(|c: char| c.is_ascii_uppercase()).then_some(n)
    };
    let mut read = std::collections::BTreeSet::new();
    for (i, _) in text.match_indices('$') {
        let rest = &text[i + 1..];
        if let Some(n) = name(rest.strip_prefix('{').unwrap_or(rest)) {
            read.insert(n);
        }
    }
    for (i, _) in text.match_indices("ENVIRON[\"") {
        if let Some(n) = name(&text[i + 9..]) {
            read.insert(n);
        }
    }
    read
}

/// `bash diff-coverage.sh <mode> <root>` with none of the script's inputs
/// inherited: the caller sets each one it means (#1222). The step that
/// measures this repository exports them, and the tests must not read them.
fn diff_coverage(mode: &str, root: &Path) -> Command {
    let mut command = Command::new("bash");
    command
        .arg(fragment("diff-coverage.sh"))
        .args([mode, root.to_str().unwrap()]);
    for name in diff_coverage_inputs() {
        command.env_remove(name);
    }
    command
}

/// Runs `diff-coverage.sh characterization` with the base report restored
/// from a fixture cache directory (`cached`) or recomputed by copying it.
fn characterize(root: &Path, stack: Stack, cached: bool, pr: Option<&str>) -> (Vec<String>, i32) {
    let cache = TempDir::new().unwrap();
    let base_report = cache.path().join(stack.report());
    if cached {
        fs::copy(stack.fixture(), &base_report).unwrap();
    }
    let mut command = diff_coverage("characterization", root);
    command
        .envs(stack.env())
        .env("SECURITY_TODAY", TODAY)
        .env("BASE_REF", "main")
        .env("APP_ID", "root")
        .env("DIFF_REPORT", stack.report())
        .env("BASE_REPORT", &base_report)
        .env(
            "DIFF_COMMAND",
            format!("cp '{}' '{}'", stack.fixture().display(), stack.report()),
        )
        .env_remove("PR_NUMBER");
    if let Some(n) = pr {
        command.env("PR_NUMBER", n);
    }
    let output = command.output().unwrap();
    (lines(&output), output.status.code().unwrap())
}

fn first_error(lines: &[String]) -> Option<&str> {
    lines
        .iter()
        .find(|l| l.starts_with("::error::"))
        .map(String::as_str)
}

#[test]
fn characterization_passes_a_file_executed_at_the_base_and_fails_one_never_executed() {
    let (repo, sha) = pr_repo(DIFF_RUST_BASE, &[("src/lib.rs", "pub fn covered() { }\n")]);
    assert_eq!(
        characterize(repo.path(), Stack::Rust, true, None),
        (
            vec![
                format!("base report: cache ({sha})"),
                format!(
                    "characterization root: 1 modified source files judged at {sha}, 0 without a test"
                ),
            ],
            0
        )
    );
    let (repo, sha) = pr_repo(DIFF_RUST_BASE, &[("src/dead.rs", "pub fn dead() { }\n")]);
    assert_eq!(
        characterize(repo.path(), Stack::Rust, true, None),
        (
            vec![
                format!("base report: cache ({sha})"),
                format!(
                    "::error::Characterization first: src/dead.rs had no test executing it at {sha}; add tests of its current behaviour in a separate pull request before changing it"
                ),
                format!(
                    "characterization root: 1 modified source files judged at {sha}, 1 without a test"
                ),
            ],
            1
        )
    );
}

#[test]
fn a_file_absent_from_the_base_report_fails_for_rust_and_warns_for_python() {
    let (repo, sha) = pr_repo(DIFF_RUST_BASE, &[("src/other.rs", "pub fn other() { }\n")]);
    let (printed, code) = characterize(repo.path(), Stack::Rust, true, None);
    assert_eq!(code, 1);
    assert_eq!(
        first_error(&printed),
        Some(format!("::error::Characterization first: src/other.rs had no test executing it at {sha}; add tests of its current behaviour in a separate pull request before changing it").as_str())
    );
    let (repo, sha) = pr_repo(
        DIFF_PYTHON_BASE,
        &[("src/sample/other.py", "def other():\n    return 3\n")],
    );
    assert_eq!(
        characterize(repo.path(), Stack::PythonUv, true, None),
        (
            vec![
                format!("base report: cache ({sha})"),
                "::warning::characterization: src/sample/other.py is not in the base report; set [tool.coverage.run] source so it can be judged".to_owned(),
                format!("characterization root: 1 modified source files judged at {sha}, 0 without a test"),
            ],
            0
        )
    );
}

#[test]
fn a_rust_file_outside_the_answered_test_selection_warns_with_the_hint() {
    // #1177: with coverage_test_args a rust report lists only the selected
    // packages' sources, so the step renders ABSENT=warn and its own hint.
    let (repo, sha) = pr_repo(DIFF_RUST_BASE, &[("src/other.rs", "pub fn other() { }\n")]);
    let cache = TempDir::new().unwrap();
    let base_report = cache.path().join(Stack::Rust.report());
    fs::copy(Stack::Rust.fixture(), &base_report).unwrap();
    let output = diff_coverage("characterization", repo.path())
        .envs(Stack::Rust.env())
        .env("ABSENT", "warn")
        .env(
            "ABSENT_HINT",
            "it is outside coverage_test_args.root, so it is not judged",
        )
        .env("SECURITY_TODAY", TODAY)
        .env("BASE_REF", "main")
        .env("APP_ID", "root")
        .env("DIFF_REPORT", Stack::Rust.report())
        .env("BASE_REPORT", &base_report)
        .env("DIFF_COMMAND", "false")
        .env_remove("PR_NUMBER")
        .output()
        .unwrap();
    assert_eq!(
        (lines(&output), output.status.code().unwrap()),
        (
            vec![
                format!("base report: cache ({sha})"),
                "::warning::characterization: src/other.rs is not in the base report; it is outside coverage_test_args.root, so it is not judged".to_owned(),
                format!("characterization root: 1 modified source files judged at {sha}, 0 without a test"),
            ],
            0
        )
    );
}

#[test]
fn cobertura_paths_are_matched_and_judged_like_lcov() {
    let (repo, sha) = pr_repo(
        DIFF_PYTHON_BASE,
        &[
            ("src/sample/__init__.py", "def covered():\n    return 10\n"),
            ("src/sample/dead.py", "def dead():\n    return 10\n"),
        ],
    );
    let (printed, code) = characterize(repo.path(), Stack::PythonUv, true, None);
    assert_eq!(code, 1);
    assert_eq!(
        printed[1..],
        [
            format!(
                "::error::Characterization first: src/sample/dead.py had no test executing it at {sha}; add tests of its current behaviour in a separate pull request before changing it"
            ),
            format!(
                "characterization root: 2 modified source files judged at {sha}, 1 without a test"
            ),
        ]
    );
}

#[test]
fn added_files_tests_only_changes_and_non_sources_are_not_judged() {
    for changes in [
        &[("src/new.rs", "pub fn new() {}\n")][..],
        &[("tests/it.rs", "#[test]\nfn it() { assert!(true) }\n")][..],
        &[("README.md", "# sample, edited\n")][..],
    ] {
        let (repo, sha) = pr_repo(DIFF_RUST_BASE, changes);
        assert_eq!(
            characterize(repo.path(), Stack::Rust, true, None),
            (
                vec![
                    format!("base report: cache ({sha})"),
                    format!(
                        "characterization root: 0 modified source files judged at {sha}, 0 without a test"
                    ),
                ],
                0
            ),
            "{changes:?}"
        );
    }
}

#[test]
fn the_base_report_is_recomputed_at_the_merge_base_when_the_cache_misses() {
    let (repo, sha) = pr_repo(DIFF_RUST_BASE, &[("src/dead.rs", "pub fn dead() { }\n")]);
    let (printed, code) = characterize(repo.path(), Stack::Rust, false, None);
    assert_eq!(code, 1);
    assert_eq!(printed[0], format!("base report: recomputed at {sha}"));
    assert!(first_error(&printed).unwrap().contains("src/dead.rs"));
    // The temporary worktree is gone afterwards.
    let worktrees = git(repo.path(), &["worktree", "list"]);
    assert_eq!(worktrees.lines().count(), 1, "{worktrees}");
}

#[test]
fn a_cache_miss_under_project_ci_warns_and_never_runs_the_tests() {
    // #1349: no DIFF_COMMAND under project-ci; recomputing would run the suite again.
    let (repo, sha) = pr_repo(DIFF_RUST_BASE, &[("src/dead.rs", "pub fn dead() { }\n")]);
    let cache = TempDir::new().unwrap();
    let output = diff_coverage("characterization", repo.path())
        .envs(Stack::Rust.env())
        .env("SECURITY_TODAY", TODAY)
        .env("BASE_REF", "main")
        .env("APP_ID", "root")
        .env("DIFF_REPORT", Stack::Rust.report())
        .env("BASE_REPORT", cache.path().join(Stack::Rust.report()))
        .output()
        .unwrap();
    let printed = lines(&output);
    assert_eq!(output.status.code(), Some(0), "{printed:?}");
    assert_eq!(
        printed,
        [format!(
            "::warning::root: no base report for {sha}; not judged"
        )]
    );
    assert!(!repo.path().join("ran-the-tests").exists());
    let worktrees = git(repo.path(), &["worktree", "list"]);
    assert_eq!(worktrees.lines().count(), 1, "{worktrees}");
}

#[test]
fn the_inputs_line_lists_exactly_the_variables_the_script_reads() {
    let text = fs::read_to_string(fragment("diff-coverage.sh")).unwrap();
    let declared: std::collections::BTreeSet<String> = diff_coverage_inputs().into_iter().collect();
    assert_eq!(names_read_by(&text), declared);
    // The scanner sees every form the script uses.
    assert_eq!(
        names_read_by("a=$A_1 b=${B:-x} c=\"$C\" ENVIRON[\"D\"] $lower $0 ${e}"),
        ["A_1", "B", "C", "D"].map(str::to_owned).into()
    );
}

#[test]
fn the_merge_base_command_runs_without_the_steps_own_variables() {
    // #1222: the measured tests of a repository that exercises this script
    // read APP_DIR and APP_PATH; they must not see the step's own values.
    let (repo, sha) = pr_repo(DIFF_RUST_BASE, &[("src/lib.rs", "pub fn covered() { }\n")]);
    let seen = TempDir::new().unwrap();
    let seen_env = seen.path().join("env");
    let output = diff_coverage("characterization", repo.path())
        .envs(Stack::Rust.env())
        .env("ABSENT_HINT", "a hint")
        .env("SECURITY_TODAY", TODAY)
        .env("BASE_REF", "main")
        .env("PR_NUMBER", "42")
        .env("APP_ID", "root")
        .env("APP_DIR", ".")
        .env("APP_PATH", ".")
        .env("EXCLUDE_PATHS", "apps/other")
        .env("MIN", "80")
        .env("DIFF_COVER", "diff-cover")
        .env("DIFF_REPORT", Stack::Rust.report())
        .env("BASE_REPORT", seen.path().join("absent.lcov"))
        .env(
            "DIFF_COMMAND",
            format!(
                "env > '{}' && cp '{}' '{}'",
                seen_env.display(),
                Stack::Rust.fixture().display(),
                Stack::Rust.report()
            ),
        )
        .output()
        .unwrap();
    assert_eq!(
        (lines(&output), output.status.code().unwrap()),
        (
            vec![
                format!("base report: recomputed at {sha}"),
                format!(
                    "characterization root: 1 modified source files judged at {sha}, 0 without a test"
                ),
            ],
            0
        )
    );
    let env = fs::read_to_string(seen_env).unwrap();
    let leaked: Vec<String> = diff_coverage_inputs()
        .into_iter()
        .filter(|name| env.lines().any(|l| l.starts_with(&format!("{name}="))))
        .collect();
    assert!(leaked.is_empty(), "leaked into DIFF_COMMAND: {leaked:?}");
}

#[test]
fn a_coverage_reset_for_this_pull_request_lets_both_modes_pass_and_no_other_does() {
    let entries = |e: &[String]| inventory(e);
    let (repo, sha) = pr_repo(DIFF_RUST_BASE, &[("src/dead.rs", "pub fn dead() { }\n")]);
    let write = |entries_text: String| {
        fs::create_dir_all(repo.path().join(".agent-setup")).unwrap();
        fs::write(repo.path().join(INVENTORY), entries_text).unwrap();
    };
    write(entries(&[reset(
        "dc-42",
        "diff-coverage#42",
        "2026-11-09",
        "2026-11-20",
    )]));
    assert_eq!(
        characterize(repo.path(), Stack::Rust, true, Some("42")),
        (
            vec![
                "::warning::coverage-reset dc-42 until 2026-11-20 (#731)".to_owned(),
                "bypass: dc-42".to_owned(),
            ],
            0
        )
    );
    write(entries(&[reset(
        "dc-41",
        "diff-coverage#41",
        "2026-11-09",
        "2026-11-20",
    )]));
    assert_eq!(
        characterize(repo.path(), Stack::Rust, true, Some("42")).1,
        1
    );
    write(entries(&[reset(
        "dc-42",
        "diff-coverage#42",
        "2026-10-01",
        "2026-10-20",
    )]));
    let (printed, code) = characterize(repo.path(), Stack::Rust, true, Some("42"));
    assert_eq!(code, 1);
    assert_eq!(printed[0], format!("base report: cache ({sha})"));
}

/// A fake `diff-cover` on PATH: records its arguments and writes `json` to the
/// path of `--format json:<path>`, then exits with `code`.
fn fake_diff_cover(bin: &Path, json: &str, code: i32) -> PathBuf {
    let script = bin.join("diff-cover");
    fs::write(
        &script,
        format!(
            "#!/usr/bin/env bash\nprintf '%s\\n' \"$@\" > \"$(dirname \"$0\")/args\"\nfor a in \"$@\"; do case $a in json:*) printf '%s' '{json}' > \"${{a#json:}}\";; esac; done\nexit {code}\n"
        ),
    )
    .unwrap();
    Command::new("chmod")
        .arg("+x")
        .arg(&script)
        .status()
        .unwrap();
    bin.join("args")
}

fn changed(root: &Path, json: &str, code: i32, pr: Option<&str>) -> (Vec<String>, i32, String) {
    let bin = TempDir::new().unwrap();
    let args = fake_diff_cover(bin.path(), json, code);
    fs::write(
        root.join("lcov.info"),
        "SF:/work/sample/src/lib.rs\nend_of_record\n",
    )
    .unwrap();
    let path = format!(
        "{}:{}",
        bin.path().display(),
        std::env::var("PATH").unwrap()
    );
    let mut command = diff_coverage("changed", root);
    command
        .env("PATH", path)
        .env("SECURITY_TODAY", TODAY)
        .env("BASE_REF", "main")
        .env("APP_ID", "root")
        .env("DIFF_REPORT", "lcov.info")
        .env("DIFF_FORMAT", "lcov")
        .env("MIN", "80")
        .env("DIFF_COVER", "diff-cover")
        .env_remove("PR_NUMBER");
    if let Some(n) = pr {
        command.env("PR_NUMBER", n);
    }
    let output = command.output().unwrap();
    let recorded = fs::read_to_string(args).unwrap_or_default();
    (lines(&output), output.status.code().unwrap(), recorded)
}

#[test]
fn changed_lines_at_the_threshold_pass_with_the_claim_and_below_fail() {
    let (repo, _) = pr_repo(DIFF_RUST_BASE, &[("src/lib.rs", "pub fn covered() { }\n")]);
    let (printed, code, args) = changed(
        repo.path(),
        r#"{"total_num_lines": 10, "total_percent_covered": 80, "num_changed_lines": 12}"#,
        0,
        None,
    );
    assert_eq!(
        (printed, code),
        (
            vec!["diff-coverage root: 80 % of 10 changed lines".to_owned()],
            0
        )
    );
    let args: Vec<&str> = args.lines().collect();
    assert_eq!(
        &args[..3],
        [
            "lcov.info",
            "--compare-branch=origin/main",
            "--fail-under=80"
        ]
    );
    assert_eq!(args[3], "--format");
    assert!(args[4].starts_with("json:"), "{args:?}");
    assert_eq!(
        changed(
            repo.path(),
            r#"{"total_num_lines": 10, "total_percent_covered": 79, "num_changed_lines": 12}"#,
            1,
            None
        )
        .0,
        [
            "diff-coverage root: 79 % of 10 changed lines",
            "::error::Changed lines of root covered 79 %, below 80 %",
        ]
    );
}

#[test]
fn no_measured_change_passes_and_a_missing_report_or_json_fails() {
    let (repo, _) = pr_repo(DIFF_RUST_BASE, &[("README.md", "# edited\n")]);
    assert_eq!(
        changed(
            repo.path(),
            r#"{"total_num_lines": 0, "total_percent_covered": 100, "num_changed_lines": 1}"#,
            0,
            None
        )
        .0,
        ["changed lines of root: none measured"]
    );
    let (printed, code, _) = changed(repo.path(), "", 2, None);
    assert_eq!(code, 1);
    assert_eq!(
        printed.last().unwrap(),
        "::error::diff-cover wrote no report (exit 2)"
    );
}

#[test]
fn a_coverage_reset_for_this_pull_request_passes_the_changed_lines_step() {
    let (repo, _) = pr_repo(DIFF_RUST_BASE, &[("src/lib.rs", "pub fn covered() { }\n")]);
    fs::create_dir_all(repo.path().join(".agent-setup")).unwrap();
    fs::write(
        repo.path().join(INVENTORY),
        inventory(&[reset(
            "dc-42",
            "diff-coverage#42",
            "2026-11-09",
            "2026-11-20",
        )]),
    )
    .unwrap();
    let (printed, code, args) = changed(
        repo.path(),
        r#"{"total_num_lines": 10, "total_percent_covered": 10}"#,
        1,
        Some("42"),
    );
    assert_eq!(
        (printed, code),
        (
            vec![
                "::warning::coverage-reset dc-42 until 2026-11-20 (#731)".to_owned(),
                "bypass: dc-42".to_owned()
            ],
            0
        )
    );
    assert!(args.is_empty(), "diff-cover does not run under a reset");
}

#[test]
fn diff_coverage_sh_silences_nothing_and_is_shellcheck_clean() {
    let text = fs::read_to_string(fragment("diff-coverage.sh")).unwrap();
    assert!(text.starts_with("#!/usr/bin/env bash\n"));
    assert!(text.contains("\nset -euo pipefail\n"));
    for forbidden in ["|| true", "continue-on-error:"] {
        assert!(!text.contains(forbidden), "{forbidden}");
    }
    if let Ok(probe) = Command::new("shellcheck").arg("--version").output() {
        assert!(probe.status.success());
        let output = Command::new("shellcheck")
            .arg(fragment("diff-coverage.sh"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

// ---- #1130: every covered app is judged in its own directory ----

/// `diff-coverage.sh characterization` for one app of a monorepo: its id, its
/// path, the paths excluded (other apps, for the app at `.`) and its report.
fn characterize_app(
    root: &Path,
    stack: Stack,
    app: (&str, &str, &str),
    report: &str,
    base: Option<&Path>,
) -> (Vec<String>, i32) {
    let (id, path, exclude) = app;
    let cache = TempDir::new().unwrap();
    let base_report = cache.path().join("report");
    if let Some(fixture) = base {
        fs::copy(fixture, &base_report).unwrap();
    }
    let fixture = base
        .map(Path::to_path_buf)
        .unwrap_or_else(|| Path::new(DIFF_FIXTURES).join("apps-api.lcov"));
    let report_name = Path::new(report)
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let output = diff_coverage("characterization", root)
        .envs(stack.env())
        .env("SECURITY_TODAY", TODAY)
        .env("BASE_REF", "main")
        .env("APP_ID", id)
        .env("APP_PATH", path)
        .env("EXCLUDE_PATHS", exclude)
        .env("APP_DIR", path)
        .env("DIFF_REPORT", report)
        .env("BASE_REPORT", &base_report)
        .env(
            "DIFF_COMMAND",
            format!("cp '{}' '{report_name}'", fixture.display()),
        )
        .env_remove("PR_NUMBER")
        .output()
        .unwrap();
    (lines(&output), output.status.code().unwrap())
}

const MONOREPO_BASE: &[(&str, &str)] = &[
    ("apps/api/src/lib.rs", "pub fn covered() {}\n"),
    ("apps/api/src/dead.rs", "pub fn dead() {}\n"),
    (
        "apps/web/src/sample/__init__.py",
        "def covered():\n    return 1\n",
    ),
    ("apps/web/src/sample/dead.py", "def dead():\n    return 0\n"),
    ("src/dead.rs", "pub fn root_dead() {}\n"),
];

const MONOREPO_CHANGES: &[(&str, &str)] = &[
    ("apps/api/src/dead.rs", "pub fn dead() { }\n"),
    ("apps/web/src/sample/dead.py", "def dead():\n    return 1\n"),
];

fn characterization_error(path: &str, sha: &str) -> String {
    format!(
        "::error::Characterization first: {path} had no test executing it at {sha}; add tests of its current behaviour in a separate pull request before changing it"
    )
}

#[test]
fn each_app_judges_only_its_own_modified_files_against_its_own_report() {
    let (repo, sha) = pr_repo(MONOREPO_BASE, MONOREPO_CHANGES);
    let api = Path::new(DIFF_FIXTURES).join("apps-api.lcov");
    assert_eq!(
        characterize_app(
            repo.path(),
            Stack::Rust,
            ("api", "apps/api", ""),
            "apps/api/lcov.info",
            Some(&api)
        ),
        (
            vec![
                format!("base report: cache ({sha})"),
                characterization_error("apps/api/src/dead.rs", &sha),
                format!(
                    "characterization api: 1 modified source files judged at {sha}, 1 without a test"
                ),
            ],
            1
        )
    );
    let web = Path::new(DIFF_FIXTURES).join("base.xml");
    assert_eq!(
        characterize_app(
            repo.path(),
            Stack::PythonUv,
            ("web", "apps/web", ""),
            "apps/web/coverage.xml",
            Some(&web)
        ),
        (
            vec![
                format!("base report: cache ({sha})"),
                characterization_error("apps/web/src/sample/dead.py", &sha),
                format!(
                    "characterization web: 1 modified source files judged at {sha}, 1 without a test"
                ),
            ],
            1
        )
    );
}

#[test]
fn the_root_app_excludes_the_other_apps_paths() {
    let mut changes = MONOREPO_CHANGES.to_vec();
    changes.push(("src/dead.rs", "pub fn root_dead() { }\n"));
    let (repo, sha) = pr_repo(MONOREPO_BASE, &changes);
    let root_report = Path::new(DIFF_FIXTURES).join("base.lcov");
    assert_eq!(
        characterize_app(
            repo.path(),
            Stack::Rust,
            ("root", ".", "apps/api\napps/web"),
            "lcov.info",
            Some(&root_report)
        ),
        (
            vec![
                format!("base report: cache ({sha})"),
                characterization_error("src/dead.rs", &sha),
                format!(
                    "characterization root: 1 modified source files judged at {sha}, 1 without a test"
                ),
            ],
            1
        )
    );
}

#[test]
fn an_app_in_a_subdirectory_recomputes_its_base_report_in_its_own_directory() {
    let (repo, sha) = pr_repo(MONOREPO_BASE, MONOREPO_CHANGES);
    let (printed, code) = characterize_app(
        repo.path(),
        Stack::Rust,
        ("api", "apps/api", ""),
        "apps/api/lcov.info",
        None,
    );
    assert_eq!(code, 1);
    assert_eq!(printed[0], format!("base report: recomputed at {sha}"));
    assert_eq!(
        printed[1],
        characterization_error("apps/api/src/dead.rs", &sha)
    );
}
