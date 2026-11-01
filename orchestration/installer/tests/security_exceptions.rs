//! The bypass inventory and the native exception files (SPEC-security.md,
//! "The bypass inventory"; #787): every state and every finding text of the
//! fixture matrix, asserted exactly, because the shell twin
//! (`exceptions-check.sh`, #788) and the auditor's rules repeat them.
use brakes::modules::security::exceptions::{
    self, DEFAULT_BYPASS_MAX_DAYS, Entry, INVENTORY, Inventory, Kind, LONG_BOUND_DAYS, NativeEntry,
    Report, Shape, State, check, state,
};
use chrono::NaiveDate;
use std::path::PathBuf;

const TODAY: &str = "2026-11-10";

fn today() -> NaiveDate {
    NaiveDate::parse_from_str(TODAY, "%Y-%m-%d").unwrap()
}

fn matrix() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/security/exceptions")
}

fn run(case: &str) -> Report {
    check(&matrix().join(case), today(), DEFAULT_BYPASS_MAX_DAYS).unwrap()
}

fn entry(json: serde_json::Value) -> Entry {
    let inventory =
        Inventory::parse(&serde_json::json!({"schema": 1, "exceptions": [json]}).to_string())
            .unwrap();
    inventory.exceptions.into_iter().next().unwrap()
}

fn complete(kind: &str, created: &str, expires: &str) -> Entry {
    entry(serde_json::json!({
        "id": "x", "kind": kind, "target": "deps-scan", "reason": "r", "issue": "#1",
        "owner": "o", "created": created, "expires": expires,
    }))
}

#[test]
fn the_matrix_is_the_one_the_shell_twin_runs() {
    let mut cases: Vec<String> = std::fs::read_dir(matrix())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    cases.sort();
    assert_eq!(cases.len(), 31, "{cases:?}");
}

#[test]
fn kinds_and_bounds_follow_the_owner_decisions_of_2026_10_28_and_2026_10_31() {
    assert_eq!(DEFAULT_BYPASS_MAX_DAYS, 30);
    assert_eq!(LONG_BOUND_DAYS, 365);
    assert_eq!(Kind::ALL.len(), 7);
    assert_eq!(Kind::AcceptedRisk.as_str(), "accepted-risk");
    for kind in Kind::ALL {
        assert_eq!(Kind::parse(kind.as_str()), Some(kind));
        let expected = match kind {
            Kind::Allowlist | Kind::RulesetBypassActor | Kind::AcceptedRisk => 365,
            _ => 30,
        };
        assert_eq!(kind.max_days(30), expected, "{kind:?}");
    }
    assert_eq!(Kind::parse("hotfix"), None);
    assert_eq!(exceptions::FIELDS.len(), 8);
    assert_eq!(INVENTORY, ".agent-setup/security-exceptions.json");
}

#[test]
fn state_of_a_complete_entry_is_active_within_the_bound_and_until_the_expiry_day() {
    let verdict = state(
        &complete("job-bypass", "2026-11-01", "2026-12-01"),
        today(),
        30,
    );
    assert_eq!(verdict.state, State::Active);
    assert!(verdict.findings.is_empty());
    let verdict = state(&complete("job-bypass", "2026-11-01", TODAY), today(), 30);
    assert_eq!(verdict.state, State::Active);
}

#[test]
fn state_reports_every_missing_field_by_name_before_anything_else() {
    let verdict = state(
        &entry(serde_json::json!({"kind": "job-bypass", "target": "", "owner": 3})),
        today(),
        30,
    );
    assert_eq!(verdict.state, State::Invalid);
    assert_eq!(
        verdict.findings,
        [
            "Exception exceptions[0] is missing id",
            "Exception exceptions[0] is missing target",
            "Exception exceptions[0] is missing reason",
            "Exception exceptions[0] is missing issue",
            "Exception exceptions[0] is missing owner",
            "Exception exceptions[0] is missing created",
            "Exception exceptions[0] is missing expires",
        ]
    );
}

#[test]
fn state_names_an_unknown_kind_bad_dates_and_a_bad_issue_reference() {
    let mut e = complete("hotfix", "2026-13-01", "2026-02-30");
    e.issue = Some("731".into());
    let verdict = state(&e, today(), 30);
    assert_eq!(verdict.state, State::Invalid);
    assert_eq!(
        verdict.findings,
        [
            "Exception x has an unknown kind hotfix",
            "Exception x has an invalid created date 2026-13-01",
            "Exception x has an invalid expires date 2026-02-30",
            "Exception x has an invalid issue reference 731",
        ]
    );
}

#[test]
fn state_is_expired_the_day_after_expires_and_invalid_over_the_bound() {
    let verdict = state(
        &complete("job-bypass", "2026-10-01", "2026-10-20"),
        today(),
        30,
    );
    assert_eq!(verdict.state, State::Expired);
    assert_eq!(verdict.findings, ["Exception x expired on 2026-10-20"]);
    let verdict = state(
        &complete("job-bypass", "2026-11-01", "2026-12-02"),
        today(),
        30,
    );
    assert_eq!(verdict.state, State::Invalid);
    assert_eq!(
        verdict.findings,
        ["Exception x lasts 31 days; job-bypass allows at most 30"]
    );
    let verdict = state(
        &complete("allowlist", "2026-11-01", "2027-11-02"),
        today(),
        30,
    );
    assert_eq!(
        verdict.findings,
        ["Exception x lasts 366 days; allowlist allows at most 365"]
    );
    let verdict = state(
        &complete("allowlist", "2026-11-01", "2027-11-01"),
        today(),
        30,
    );
    assert_eq!(verdict.state, State::Active);
    let verdict = state(
        &complete("job-bypass", "2026-11-05", "2026-11-01"),
        today(),
        30,
    );
    assert_eq!(
        verdict.findings,
        ["Exception x expires on 2026-11-01, before it was created on 2026-11-05"]
    );
}

#[test]
fn a_renewal_by_an_edited_date_is_not_detected_by_the_check() {
    // The guide forbids editing `expires`; only the file's git log shows it.
    // Asserted so nobody adds a heuristic here silently (SPEC-security.md).
    let report = run("renewal-edited-date");
    assert!(report.findings.is_empty(), "{:?}", report.findings);
    assert_eq!(
        report.claim(),
        "exceptions: 1 active, 0 expired, 0 unregistered"
    );
}

#[test]
fn trivy_ignore_yaml_reader_accepts_the_generated_shape_only() {
    let text = "# c\nvulnerabilities:\n  - id: CVE-1\n    paths:\n      - \"a/b\"\n    statement: 'see #7'\n    expired_at: 2026-12-01\n  - id: CVE-2\nmisconfigurations: []\n";
    assert_eq!(
        exceptions::trivy_ignore(text),
        Shape::Generated(vec![
            NativeEntry {
                file: ".trivyignore.yaml",
                id: "CVE-1".into(),
                expiry: Some("2026-12-01".into()),
                issue: true,
            },
            NativeEntry {
                file: ".trivyignore.yaml",
                id: "CVE-2".into(),
                expiry: None,
                issue: false,
            },
        ])
    );
    assert_eq!(
        exceptions::trivy_ignore("vulnerabilities:\n  - id: CVE-1\n    severity: HIGH\n"),
        Shape::Unverified { line: 3 }
    );
    assert_eq!(
        exceptions::trivy_ignore("vulnerabilities: [{id: CVE-1}]\n"),
        Shape::Unverified { line: 1 }
    );
    assert_eq!(
        exceptions::trivy_ignore("  - id: CVE-1\n"),
        Shape::Unverified { line: 1 }
    );
}

#[test]
fn osv_config_reader_accepts_the_generated_shape_only() {
    let text = "# c\n[[IgnoredVulns]]\nid = \"GO-1\"\nignoreUntil = 2026-12-01\nreason = \"see #7\"\n\n[[IgnoredVulns]]\nid = \"GO-2\"\nignoreUntil = \"2026-12-02\"\nreason = \"none\"\n";
    assert_eq!(
        exceptions::osv_config(text),
        Shape::Generated(vec![
            NativeEntry {
                file: "osv-scanner.toml",
                id: "GO-1".into(),
                expiry: Some("2026-12-01".into()),
                issue: true,
            },
            NativeEntry {
                file: "osv-scanner.toml",
                id: "GO-2".into(),
                expiry: Some("2026-12-02".into()),
                issue: false,
            },
        ])
    );
    assert_eq!(
        exceptions::osv_config("[[PackageOverrides]]\nname = \"x\"\n"),
        Shape::Unverified { line: 1 }
    );
    assert_eq!(
        exceptions::osv_config("[[IgnoredVulns]]\nreason = \"x\"\n"),
        Shape::Unverified { line: 1 }
    );
    assert_eq!(
        exceptions::osv_config("id = \"GO-1\"\n"),
        Shape::Unverified { line: 1 }
    );
}

#[test]
fn allowlist_readers_turn_entries_into_inventory_targets() {
    assert_eq!(
        exceptions::ignore_lines(".gitleaksignore", "# c\n\n a:b:1 \nc:d:2\n"),
        [".gitleaksignore#a:b:1", ".gitleaksignore#c:d:2"]
    );
    let toml = "[allowlist]\ndescription = \"d\"\npaths = [\n  '''t/.*''',\n  \"d/.*\"\n]\nregexes = []\n[[rules]]\nid = \"x\"\n";
    assert_eq!(
        exceptions::gitleaks_allowlist(toml),
        Shape::Generated(vec![
            ".gitleaks.toml#paths:t/.*".to_string(),
            ".gitleaks.toml#paths:d/.*".to_string(),
        ])
    );
    assert_eq!(
        exceptions::gitleaks_allowlist("[allowlist]\npaths = [\"a\"]\n"),
        Shape::Unverified { line: 2 }
    );
    assert_eq!(
        exceptions::gitleaks_allowlist("[allowlist]\npaths = [\n  'a',\n"),
        Shape::Unverified { line: 3 }
    );
}

// The matrix, case by case: the exact lines the gate prints.

#[test]
fn matrix_seeds_and_nothing_are_green_with_zero_counts() {
    for case in ["seeds-empty", "nothing"] {
        let report = run(case);
        assert!(report.findings.is_empty(), "{case}: {:?}", report.findings);
        assert_eq!(
            report.claim(),
            "exceptions: 0 active, 0 expired, 0 unregistered"
        );
    }
}

#[test]
fn matrix_valid_counts_inventory_and_native_entries_as_active() {
    let report = run("valid");
    assert!(report.findings.is_empty(), "{:?}", report.findings);
    assert_eq!(
        report.claim(),
        "exceptions: 7 active, 0 expired, 0 unregistered"
    );
    assert!(report.passed());
}

#[test]
fn matrix_missing_each_field() {
    let report = run("missing-each-field");
    assert_eq!(
        report.findings,
        [
            "Exception exceptions[0] is missing id",
            "Exception no-kind is missing kind",
            "Exception no-target is missing target",
            "Exception no-reason is missing reason",
            "Exception no-issue is missing issue",
            "Exception no-owner is missing owner",
            "Exception no-created is missing created",
            "Exception no-expires is missing expires",
            "Exception empty-and-typed is missing target",
            "Exception empty-and-typed is missing reason",
            "Exception empty-and-typed is missing owner",
        ]
    );
    assert_eq!(
        report.claim(),
        "exceptions: 0 active, 0 expired, 0 unregistered"
    );
}

#[test]
fn matrix_bad_date_bad_issue_unknown_kind_and_backwards() {
    assert_eq!(
        run("bad-date").findings,
        [
            "Exception month-13 has an invalid created date 2026-13-01",
            "Exception feb-30 has an invalid expires date 2026-02-30",
            "Exception slashes has an invalid created date 03/11/2026",
            "Exception both-bad has an invalid created date 2026-1-1",
            "Exception both-bad has an invalid expires date 20261120",
        ]
    );
    let report = run("bad-issue");
    assert_eq!(
        report.findings,
        [
            "Exception bare-number has an invalid issue reference 731",
            "Exception hash-only has an invalid issue reference #",
            "Exception gh-prefix has an invalid issue reference GH-731",
        ]
    );
    assert_eq!(report.active, 1);
    assert_eq!(
        run("unknown-kind").findings,
        ["Exception hotfix has an unknown kind hotfix"]
    );
    assert_eq!(
        run("expires-before-created").findings,
        ["Exception backwards expires on 2026-11-01, before it was created on 2026-11-05"]
    );
}

#[test]
fn matrix_expired_and_over_bound() {
    let report = run("expired");
    assert_eq!(
        report.findings,
        [
            "Exception osv-outage-2026-10 expired on 2026-10-20",
            "Exception ended-yesterday expired on 2026-11-09",
        ]
    );
    assert_eq!(
        report.claim(),
        "exceptions: 1 active, 2 expired, 0 unregistered"
    );
    let report = run("over-bound");
    assert_eq!(
        report.findings,
        [
            "Exception job-31 lasts 31 days; job-bypass allows at most 30",
            "Exception allow-366 lasts 366 days; allowlist allows at most 365",
            "Exception coverage-40 lasts 40 days; coverage-reset allows at most 30",
            "Exception continue-31 lasts 31 days; continue-on-error allows at most 30",
        ]
    );
    assert_eq!(
        report.claim(),
        "exceptions: 3 active, 0 expired, 0 unregistered"
    );
}

#[test]
fn matrix_inventory_shape_refusals() {
    for case in [
        "inventory-does-not-parse",
        "inventory-not-object",
        "entry-not-object",
    ] {
        assert_eq!(
            run(case).findings,
            [".agent-setup/security-exceptions.json does not parse"],
            "{case}"
        );
    }
    assert_eq!(
        run("inventory-unsupported-schema").findings,
        [".agent-setup/security-exceptions.json has an unsupported schema 2"]
    );
}

#[test]
fn matrix_trivyignore_yaml_and_the_plain_file() {
    assert_eq!(
        run("trivy-without-expired-at").findings,
        ["Exception CVE-2026-1234 in .trivyignore.yaml has no expired_at"]
    );
    let report = run("trivy-expired");
    assert_eq!(
        report.findings,
        ["Exception CVE-2026-1234 in .trivyignore.yaml expired on 2026-10-01"]
    );
    assert_eq!(
        report.claim(),
        "exceptions: 1 active, 1 expired, 0 unregistered"
    );
    let report = run("trivy-no-issue");
    assert_eq!(
        report.findings,
        [
            "Exception CVE-2026-1234 in .trivyignore.yaml has no issue in statement",
            "Exception CVE-2026-2222 in .trivyignore.yaml has no issue in statement",
            "Exception CVE-2026-3333 in .trivyignore.yaml has an invalid expired_at date 2026-13-01",
        ]
    );
    assert_eq!(report.active, 1);
    assert_eq!(
        run("trivy-unverified").findings,
        [".trivyignore.yaml is unverified: line 5 is outside the generated shape"]
    );
    assert_eq!(
        run("trivy-plain").findings,
        [".trivyignore cannot carry an expiry; use .trivyignore.yaml"]
    );
}

/// #1195: YAML ends an unquoted value at ` #`, so an issue reference after it
/// never reaches Trivy; the check reads the value as YAML does.
#[test]
fn matrix_an_unquoted_statement_ends_at_a_yaml_comment() {
    let report = run("trivy-unquoted-comment");
    assert_eq!(
        report.findings,
        ["Exception CVE-2026-1234 in .trivyignore.yaml has no issue in statement"]
    );
    assert_eq!(
        report.claim(),
        "exceptions: 2 active, 0 expired, 0 unregistered"
    );
}

/// #1194: a `.semgrepignore` replaces Semgrep's defaults, so the seed restates
/// them; an entry equal to a default ignores nothing Semgrep would scan without
/// the file and needs no inventory entry, every other entry does.
#[test]
fn matrix_semgrep_defaults_need_no_registration() {
    let report = run("semgrepignore-defaults");
    assert_eq!(
        report.findings,
        [
            ".semgrepignore entry docs/generated/ is not registered in .agent-setup/security-exceptions.json"
        ]
    );
    assert_eq!(
        report.claim(),
        "exceptions: 0 active, 0 expired, 1 unregistered"
    );
}

#[test]
fn matrix_osv_scanner_toml() {
    assert_eq!(
        run("osv-without-ignore-until").findings,
        ["Exception GO-2026-0001 in osv-scanner.toml has no ignoreUntil"]
    );
    let report = run("osv-expired");
    assert_eq!(
        report.findings,
        [
            "Exception GO-2026-0001 in osv-scanner.toml expired on 2026-11-09",
            "Exception GHSA-xxxx-yyyy-zzzz in osv-scanner.toml has no issue in reason",
        ]
    );
    assert_eq!(
        report.claim(),
        "exceptions: 0 active, 1 expired, 0 unregistered"
    );
    assert_eq!(
        run("osv-unverified").findings,
        ["osv-scanner.toml is unverified: line 6 is outside the generated shape"]
    );
}

#[test]
fn matrix_allowlist_registration() {
    let report = run("allowlist-unregistered");
    assert_eq!(
        report.findings,
        [
            ".gitleaksignore entry tests/fixtures/fake.pem:private-key:3 is not registered in .agent-setup/security-exceptions.json",
            ".gitleaksignore entry README.md:generic-api-key:12 is not registered in .agent-setup/security-exceptions.json",
            ".semgrepignore entry :include .gitignore is not registered in .agent-setup/security-exceptions.json",
            ".gitleaks.toml allowlist entry paths:tests/fixtures/.* is not registered in .agent-setup/security-exceptions.json",
            ".gitleaks.toml allowlist entry paths:docs/.* is not registered in .agent-setup/security-exceptions.json",
            ".gitleaks.toml allowlist entry regexes:EXAMPLE_KEY_[A-Z]+ is not registered in .agent-setup/security-exceptions.json",
        ]
    );
    assert_eq!(
        report.claim(),
        "exceptions: 0 active, 0 expired, 6 unregistered"
    );
    let report = run("allowlist-registered-expired");
    assert_eq!(
        report.findings,
        ["Exception fixture-key expired on 2026-11-01"]
    );
    assert_eq!(
        report.claim(),
        "exceptions: 0 active, 1 expired, 0 unregistered"
    );
    assert_eq!(
        run("gitleaks-toml-unverified").findings,
        [".gitleaks.toml is unverified: line 2 is outside the generated shape"]
    );
}

#[test]
fn matrix_mixed_counts_every_source_in_the_claim_line() {
    let report = run("mixed");
    assert_eq!(
        report.findings,
        [
            "Exception hotfix-october expired on 2026-10-15",
            "Exception half is missing reason",
            "Exception half is missing issue",
            "Exception half is missing owner",
            "Exception half is missing created",
            "Exception half is missing expires",
            "Exception CVE-2026-0001 in .trivyignore.yaml expired on 2026-01-01",
            ".gitleaksignore entry tests/fixtures/other.pem:private-key:1 is not registered in .agent-setup/security-exceptions.json",
        ]
    );
    assert_eq!(
        report.claim(),
        "exceptions: 4 active, 2 expired, 1 unregistered"
    );
    assert!(!report.passed());
}
