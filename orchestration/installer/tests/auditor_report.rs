//! What `doctor <repo>` shows of an audit (SPEC-auditor.md "Outputs", #716):
//! the text lines appended after today's lines, the `--json` schema-1
//! additions pinned by a golden file, the Markdown of `--report`, and today's
//! lines byte-identical to what `doctor` printed before the audit existed.
//! No test calls `gh`: the remote audit runs `GitHub` over a fake transport.
use brakes::{
    Result,
    auditor::{
        Cx, LocalFiles, Today, audit_checkout, checkout_identity,
        counters::{self, Counter, Counters},
        evaluate,
        measures::measure,
        offline_host,
        report::{Audited, Budget},
        rules::{Block, Level, Milestone, Outcome, Probe, Profile, Remediation, Required, Rule},
    },
    doctor_audit_json, doctor_json,
    host::{CallBudget, RepoId, github::GitHub},
    remote::{Api, HttpError},
};
use chrono::NaiveDate;
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

const BASE: &str = "repos/example-owner/example";

fn now() -> NaiveDate {
    NaiveDate::from_ymd_opt(2026, 10, 28).unwrap()
}
fn repo() -> RepoId {
    RepoId::parse("example-owner/example").unwrap()
}
fn manifest(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}
fn fixture() -> PathBuf {
    manifest("tests/fixtures/auditor/report")
}
fn github(name: &str) -> Value {
    serde_json::from_str(
        &fs::read_to_string(manifest(&format!("tests/fixtures/github/{name}"))).unwrap(),
    )
    .unwrap()
}

/// Serves the recorded `tests/fixtures/github/` replies the measures read and
/// answers 404 to anything else, as an unconfigured endpoint would.
struct Recorded;
impl Api for Recorded {
    fn get(&self, path: &str) -> Result<Value> {
        let rest = path.strip_prefix(BASE).unwrap_or(path);
        let reply = if rest.is_empty() {
            github("repository.json")
        } else if rest.starts_with("/collaborators?") {
            github("collaborators.json")
        } else if rest.starts_with("/pulls?") {
            github("pulls.json")
        } else if rest.starts_with("/environments?") {
            github("environments.json")
        } else if rest.starts_with("/environments/") {
            github("deployment_branch_policies.json")
        } else {
            return Err(HttpError {
                status: 404,
                message: format!("Not Found: {path}"),
            }
            .into());
        };
        Ok(reply)
    }
}

/// Today's `doctor` with nothing to report: what these tests render is the
/// audit. `REMOTE_CLEAN` is that of `doctor --remote`, as a remote audit runs.
const CLEAN: Today = Today {
    findings: &[],
    steps: &[],
    remote: false,
};
const REMOTE_CLEAN: Today = Today {
    remote: true,
    ..CLEAN
};

fn remote_audit(root: &Path) -> Audited {
    let host = GitHub::new(&Recorded, CallBudget::new(60));
    audit_checkout(
        root,
        &host,
        host.budget(),
        &repo(),
        now(),
        true,
        &REMOTE_CLEAN,
    )
    .unwrap()
}

// --- text lines ---------------------------------------------------------------------

fn fail(_: &Cx<'_>) -> Outcome {
    Outcome::failed(["no ruleset targets main", "protection allows force-push"])
}
fn pass(_: &Cx<'_>) -> Outcome {
    Outcome::passed(["checked"])
}

const fn rule(
    id: &'static str,
    block: Block,
    level: Level,
    profiles: &'static [Profile],
    remediation: Remediation,
    feasible_by: Milestone,
    evaluate: fn(&Cx<'_>) -> Outcome,
) -> Rule {
    Rule {
        id,
        title: "Test rule",
        block,
        checks: "Test rule.",
        how: Probe::Remote { id: "test" },
        level,
        required: Required {
            profiles,
            when: &[],
        },
        remediation,
        plan: None,
        feasible_by,
        evaluate,
    }
}
const ALL: &[Profile] = &[Profile::P1, Profile::P2, Profile::P3];

static RULES: &[Rule] = &[
    rule(
        "governance.example-pass",
        Block::Governance,
        Level::Basic,
        ALL,
        Remediation::Module {
            id: "repo-baseline",
        },
        Milestone::Nov7,
        pass,
    ),
    rule(
        "posture.example-fail",
        Block::Posture,
        Level::Basic,
        ALL,
        Remediation::Manual {
            step: "ruleset-main",
            instructions: "Apply the main ruleset.",
        },
        Milestone::Nov7,
        fail,
    ),
    rule(
        "dora.example-not-required",
        Block::Dora,
        Level::Basic,
        &[Profile::P3],
        Remediation::Command {
            text: "brakes install <repo>",
        },
        Milestone::Nov7,
        fail,
    ),
    rule(
        "operations.example-wait",
        Block::Operations,
        Level::Silver,
        ALL,
        Remediation::Module {
            id: "observability",
        },
        Milestone::WaitsFor("observability"),
        pass,
    ),
];

/// The test registry over the report fixture, without `--remote`.
fn offline(root: &Path) -> Audited {
    let host = offline_host();
    let files = LocalFiles::new(root);
    let repo = repo();
    let budget = CallBudget::new(60);
    let cx = Cx {
        host: &host,
        files: &files,
        repo: &repo,
        default_branch: "main",
        now: now(),
        budget: &budget,
        profile: Profile::P1,
        today: None,
    };
    let measured = measure(&cx, false).unwrap();
    let audit = evaluate(&cx, &measured.dimensions, RULES);
    Audited {
        repo: repo.to_string(),
        now: now(),
        measured,
        audit,
        counters: counters::count(&cx, false),
        budget: Budget {
            api_calls: 0,
            limit: 60,
            exhausted: false,
        },
    }
}

#[test]
fn text_lines_state_profile_level_failures_unavailable_evidence_and_the_next_gap() {
    let audited = offline(&fixture());
    assert_eq!(
        audited.lines(),
        [
            "AUDIT example-owner/example: profile P1 unverified (humans unavailable, cadence unavailable, services unavailable, criticality undeclared); required Bronze; reached none",
            "COUNTER post-merge-corrections: unavailable: not read without --remote",
            "COUNTER cost-per-change: unavailable: not read without --remote",
            "FAIL        [basic:posture.example-fail] no ruleset targets main; protection allows force-push → manual step ruleset-main: Apply the main ruleset.",
            "UNAVAILABLE [silver:operations.example-wait] waits for module observability",
            "NEXT Basic: 1 rule (posture.example-fail)",
        ]
    );
    assert_eq!(audited.exit_code(true), 3);
    assert_eq!(audited.exit_code(false), 1);
}

#[test]
fn the_audit_line_names_measured_dimensions_and_an_unexpired_acceptance() {
    let dir = tempfile::tempdir().unwrap();
    let profile = dir.path().join(".agent-setup/project.json");
    fs::create_dir_all(profile.parent().unwrap()).unwrap();
    fs::write(
        &profile,
        r#"{"purpose": "x", "commands": {"verify": "true"}, "criticality": "customers",
            "audit": {"accepted_level": {"level": "Basic", "expires": "2026-12-01"}}}"#,
    )
    .unwrap();
    // A workflow, so `ci-health.workflow-exists` (#724) waits on its runs.
    let workflow = dir.path().join(".github/workflows/ci.yml");
    fs::create_dir_all(workflow.parent().unwrap()).unwrap();
    fs::write(&workflow, "on: push\njobs: {}\n").unwrap();
    // The governance files (#728), so no local-file rule fails.
    for (path, text) in [
        (".agent-setup/service.yaml", "owner: example-owner\n"),
        (".github/pull_request_template.md", "Summary:\n"),
        (".github/ISSUE_TEMPLATE/task.yml", "name: Task\n"),
        (
            ".github/dependabot.yml",
            "updates:\n  - package-ecosystem: cargo\n    cooldown:\n      default-days: 7\n",
        ),
    ] {
        let file = dir.path().join(path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, text).unwrap();
    }
    let audited = remote_audit(dir.path());
    assert_eq!(
        audited.lines()[0],
        "AUDIT example-owner/example: profile P1 (1 human, cadence low, services single, customers); required Silver; reached none; accepted Basic until 2026-12-01"
    );
    // The fake transport answers 404, so the posture rules (#721) are
    // unavailable; nothing fails and the acceptance lowers code 4 to 0.
    assert!(!audited.lines().iter().any(|l| l.starts_with("FAIL")));
    assert_eq!(audited.exit_code(true), 0);
}

#[test]
fn an_expired_acceptance_is_printed_as_a_finding() {
    let dir = tempfile::tempdir().unwrap();
    let profile = dir.path().join(".agent-setup/project.json");
    fs::create_dir_all(profile.parent().unwrap()).unwrap();
    fs::write(
        &profile,
        r#"{"purpose": "x", "commands": {"verify": "true"},
            "audit": {"accepted_level": {"level": "Basic", "expires": "2026-10-27"}}}"#,
    )
    .unwrap();
    let lines = offline(dir.path()).lines();
    assert_eq!(
        lines[3],
        "FINDING audit.accepted_level expired on 2026-10-27"
    );
}

// --- counters (#983) -------------------------------------------------------------

#[test]
fn counter_lines_follow_the_audit_line_and_say_why_they_are_unavailable() {
    let lines = offline(&fixture()).lines();
    assert_eq!(
        lines[1..3],
        [
            "COUNTER post-merge-corrections: unavailable: not read without --remote",
            "COUNTER cost-per-change: unavailable: not read without --remote",
        ]
    );
}

/// A counter has no threshold and no level: any value leaves the reached
/// level, the gap and the exit code as they were.
#[test]
fn no_counter_value_changes_the_level_or_the_exit_code() {
    let audited = remote_audit(&fixture());
    let counter = |value, unit| Counter {
        value: Some(value),
        unit,
        evidence: vec!["sample".to_owned()],
        reason: None,
    };
    for (corrections, cost) in [(0.0, 0.0), (100.0, 600.0), (12.5, 14.0)] {
        let mut changed = audited.clone();
        changed.counters = Counters {
            post_merge_corrections: counter(corrections, "percent"),
            cost_per_change: counter(cost, "minutes"),
        };
        assert_eq!(changed.audit, audited.audit);
        for ready in [true, false] {
            assert_eq!(changed.exit_code(ready), audited.exit_code(ready));
        }
        let rest = |a: &Audited| -> Vec<String> {
            a.lines()
                .into_iter()
                .filter(|l| !l.starts_with("COUNTER "))
                .collect()
        };
        assert_eq!(rest(&changed), rest(&audited));
        assert_eq!(
            changed.lines()[1],
            format!("COUNTER post-merge-corrections: {corrections:.1} % (sample)")
        );
        assert_eq!(
            changed.lines()[2],
            format!("COUNTER cost-per-change: {cost:.1} min median (sample)")
        );
    }
}

// --- --json ---------------------------------------------------------------------------

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "lists setup-core or its guides; product-boundary T7a"
)]
#[test]
fn json_matches_the_schema_1_golden_file() {
    let audited = remote_audit(&fixture());
    let findings = vec!["WARNING: Merge guard hook is not registered".to_owned()];
    let json = doctor_audit_json(true, &findings, &[], &[], Some(&audited.json())).unwrap();
    let golden = manifest("tests/golden/auditor/doctor.json");
    // `UPDATE_GOLDENS=1` rewrites it, as the module goldens do; review the diff.
    if std::env::var_os("UPDATE_GOLDENS").is_some() {
        fs::write(&golden, &json).unwrap();
    }
    let expected = fs::read_to_string(&golden).unwrap();
    assert_eq!(
        json,
        expected,
        "doctor --json drifted from {}; actual:\n{json}",
        golden.display()
    );
    let value: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(value["schema"], json!(1));
    assert_eq!(value["level"]["standard"], json!("accepted"));
    assert_eq!(
        value["budget"]["api_calls"],
        json!(audited.budget.api_calls)
    );
}

#[test]
fn json_keeps_todays_keys_first_and_adds_only() {
    let audited = remote_audit(&fixture());
    let before = doctor_json(true, &[], &[], &[]).unwrap();
    let after = doctor_audit_json(true, &[], &[], &[], Some(&audited.json())).unwrap();
    let before: Value = serde_json::from_str(&before).unwrap();
    let after: Value = serde_json::from_str(&after).unwrap();
    for (key, value) in before.as_object().unwrap() {
        assert_eq!(&after[key], value, "{key} changed");
    }
    let added: Vec<&String> = after
        .as_object()
        .unwrap()
        .keys()
        .filter(|k| !before.as_object().unwrap().contains_key(*k))
        .collect();
    assert_eq!(
        added,
        [
            "audited_at",
            "blocks",
            "budget",
            "counters",
            "level",
            "next_level",
            "profile",
            "repo",
            "rules",
            "window_days"
        ]
    );
}

fn unavailable(_: &Cx<'_>) -> Outcome {
    Outcome::unavailable("token cannot read it")
}

#[test]
fn a_block_with_a_waiting_rule_is_partial_complete_otherwise() {
    // Operations: one rule waits, nothing else. Governance: one passes, one
    // waits. Posture: every rule produced evidence. Dora: none did, and none waits.
    static BLOCKS: &[Rule] = &[
        rule(
            "operations.waits",
            Block::Operations,
            Level::Silver,
            ALL,
            Remediation::Module {
                id: "observability",
            },
            Milestone::WaitsFor("observability"),
            pass,
        ),
        rule(
            "governance.passes",
            Block::Governance,
            Level::Bronze,
            ALL,
            Remediation::Module {
                id: "repo-baseline",
            },
            Milestone::Nov7,
            pass,
        ),
        rule(
            "governance.waits",
            Block::Governance,
            Level::Gold,
            ALL,
            Remediation::Module { id: "flags" },
            Milestone::WaitsFor("flags"),
            pass,
        ),
        rule(
            "posture.passes",
            Block::Posture,
            Level::Basic,
            ALL,
            Remediation::Module {
                id: "repo-baseline",
            },
            Milestone::Nov7,
            pass,
        ),
        rule(
            "dora.unread",
            Block::Dora,
            Level::Silver,
            ALL,
            Remediation::Module { id: "delivery" },
            Milestone::Nov7,
            unavailable,
        ),
    ];
    let root = fixture();
    let mut audited = offline(&root);
    let host = offline_host();
    let files = LocalFiles::new(&root);
    let repo = repo();
    let budget = CallBudget::new(60);
    let cx = Cx {
        host: &host,
        files: &files,
        repo: &repo,
        default_branch: "main",
        now: now(),
        budget: &budget,
        profile: Profile::P1,
        today: None,
    };
    audited.audit = evaluate(&cx, &audited.measured.dimensions, BLOCKS);
    assert_eq!(
        audited.json()["blocks"],
        json!({
            "baseline": "empty", "posture": "complete", "ci_health": "empty",
            "dora": "unavailable", "operations": "partial", "governance": "partial",
            "ci": "empty", "security": "empty", "stack": "empty", "agents": "empty",
            "qa": "empty",
        })
    );
    // The whole registry today: operations and governance both wait.
    let blocks = remote_audit(&fixture()).json()["blocks"].clone();
    assert_eq!(blocks["operations"], json!("partial"));
    assert_eq!(blocks["governance"], json!("partial"));
}

#[test]
fn the_markdown_summary_counts_waiting_rules_apart_from_unavailable_ones() {
    let markdown = offline(&fixture()).markdown();
    assert!(
        markdown.contains("| Gap | Unavailable | Waiting |"),
        "{markdown}"
    );
    // RULES: one rule waits for observability and none is otherwise unavailable.
    assert!(
        markdown.contains("| P1 unverified | Bronze | none | 1 | 0 | 1 |"),
        "{markdown}"
    );
}

#[test]
fn two_audits_with_the_same_now_are_byte_identical() {
    let first = serde_json::to_string(&remote_audit(&fixture()).json()).unwrap();
    let second = serde_json::to_string(&remote_audit(&fixture()).json()).unwrap();
    assert_eq!(first, second);
}

#[test]
fn now_fixes_every_window() {
    // The fixture's three PRs merged on 2026-10-28: inside the window ending
    // that day, outside the one ending 29 days later.
    let host = GitHub::new(&Recorded, CallBudget::new(60));
    let later = NaiveDate::from_ymd_opt(2026, 11, 26).unwrap();
    let audited = audit_checkout(
        &fixture(),
        &host,
        host.budget(),
        &repo(),
        later,
        true,
        &REMOTE_CLEAN,
    )
    .unwrap();
    let json = audited.json();
    assert_eq!(json["audited_at"], json!("2026-11-26"));
    assert_eq!(
        json["profile"]["measures"]["merge_cadence_per_week"]["evidence"],
        json!(["0 merged PRs 2026-10-29..2026-11-26"])
    );
    let audited = remote_audit(&fixture());
    assert_eq!(
        audited.json()["profile"]["measures"]["merge_cadence_per_week"]["evidence"],
        json!(["3 merged PRs 2026-09-30..2026-10-28"])
    );
}

#[test]
fn offline_audit_spends_no_call_and_reports_measures_unavailable() {
    let host = offline_host();
    let budget = CallBudget::new(60);
    let audited =
        audit_checkout(&fixture(), &host, &budget, &repo(), now(), false, &CLEAN).unwrap();
    let json = audited.json();
    assert_eq!(
        json["budget"],
        json!({"api_calls": 0, "limit": 60, "exhausted": false})
    );
    assert_eq!(json["profile"]["unverified"], json!(true));
    assert_eq!(
        json["profile"]["measures"]["humans_with_merge"]["evidence"],
        json!(["unavailable without --remote"])
    );
}

#[test]
fn a_checkout_without_origin_is_audited_as_local() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("project");
    fs::create_dir(&root).unwrap();
    git_init(&root);
    assert_eq!(checkout_identity(&root).to_string(), "local/project");
}

// --- --report ---------------------------------------------------------------------------

#[test]
fn markdown_of_one_repository_matches_the_golden_file() {
    let markdown = remote_audit(&fixture()).markdown();
    let golden = manifest("tests/golden/auditor/report.md");
    // `UPDATE_GOLDENS=1` rewrites it, as the JSON golden above; review the diff.
    if std::env::var_os("UPDATE_GOLDENS").is_some() {
        fs::write(&golden, &markdown).unwrap();
    }
    let expected = fs::read_to_string(&golden).unwrap();
    assert_eq!(
        markdown,
        expected,
        "--report drifted from {}; actual:\n{markdown}",
        golden.display()
    );
}

// --- today's lines -----------------------------------------------------------------------

fn git_init(root: &Path) {
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .arg(root)
            .status()
            .unwrap()
            .success()
    );
}
fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}
fn cli(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_brakes"))
        .args(args)
        .arg(root)
        .output()
        .unwrap()
}
/// Sets `source_dirty` false so readiness does not depend on the build checkout.
fn clean_lock(root: &Path) {
    let path = root.join(brakes::LOCK);
    let mut lock: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    lock["source_dirty"] = json!(false);
    fs::write(path, serde_json::to_vec(&lock).unwrap()).unwrap();
}

/// The lines before the audit section; asserts the section follows.
fn todays_lines(output: &Output) -> String {
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let start = stdout
        .find("\nAUDIT ")
        .map(|i| i + 1)
        .unwrap_or_else(|| panic!("no AUDIT line after today's lines:\n{stdout}"));
    // The pin-table age (#763) depends on the real clock, not on the set-up.
    stdout[..start]
        .lines()
        .filter(|line| !line.starts_with("WARNING: stack.pin-table-stale:"))
        .map(|line| format!("{line}\n"))
        .collect()
}

/// The golden files under `tests/golden/auditor/today/` were printed by the
/// binary of main before #716 (2973ba4) for the same set-up; #793 appended the
/// static `security.*` warnings (no workflow, a lockfile), and #696 the
/// `hook-registered` step of merge-guard on the installed cases, and #767
/// the `info:` line of a node app with no known test runner, and #798 the
/// `security.sast-gate` warning, nothing else.
#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "lists setup-core or its guides; product-boundary T7a"
)]
#[test]
fn todays_doctor_text_for_the_fixture_repositories_is_byte_identical() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("project");
    let golden = |case: &str| {
        fs::read_to_string(manifest(&format!("tests/golden/auditor/today/{case}.txt"))).unwrap()
    };
    for case in ["rust-root", "node-monorepo", "go-under-rust"] {
        let _ = fs::remove_dir_all(&root);
        copy_dir(
            &manifest(&format!("tests/fixtures/stack-packs/{case}")),
            &root,
        );
        git_init(&root);
        let output = cli(&root, &["doctor", "--new-personal"]);
        assert_eq!(todays_lines(&output), golden(case), "{case}");
        assert_eq!(output.status.code(), Some(1), "{case}");
    }

    let _ = fs::remove_dir_all(&root);
    copy_dir(&manifest("tests/fixtures/stack-packs/rust-root"), &root);
    git_init(&root);
    assert!(
        cli(&root, &["install", "--new-personal", "--apply"])
            .status
            .success()
    );
    clean_lock(&root);
    let output = cli(&root, &["doctor"]);
    assert_eq!(todays_lines(&output), golden("rust-root-installed"));
    assert_eq!(output.status.code(), Some(1));

    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).unwrap();
    git_init(&root);
    assert!(
        cli(&root, &["install", "--new-personal", "--apply"])
            .status
            .success()
    );
    let path = root.join(brakes::PROFILE);
    let mut profile: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    profile["purpose"] = json!("Example");
    profile["commands"]["verify"] = json!("never executed");
    profile["criticality"] = json!("internal");
    fs::write(&path, serde_json::to_vec(&profile).unwrap()).unwrap();
    assert!(cli(&root, &["install", "--apply"]).status.success());
    clean_lock(&root);
    let output = cli(&root, &["doctor"]);
    assert_eq!(todays_lines(&output), golden("ready"));
    // Ready, but the checkout has no workflow, so `ci-health.workflow-exists`
    // (#724) fails Basic from local evidence: code 3. Without `--remote` the
    // posture rules (#721) have no evidence either; never a silent pass.
    assert_eq!(output.status.code(), Some(3), "{output:?}");
}

// --- accepted risks (decision 2026-10-31, #1217) ---------------------------------------

/// The report fixture plus `.agent-setup/security-exceptions.json` holding `entries`.
fn with_inventory(entries: Value) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    copy_dir(&fixture(), dir.path());
    let path = dir.path().join(".agent-setup/security-exceptions.json");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        path,
        serde_json::to_string_pretty(&json!({"schema": 1, "exceptions": entries})).unwrap(),
    )
    .unwrap();
    dir
}

fn accepted_risk(target: &str, expires: &str) -> Value {
    json!({
        "id": "merge-alone", "kind": "accepted-risk", "target": target,
        "reason": "the owner merges alone", "issue": "#392",
        "owner": "example-owner", "created": "2026-10-01", "expires": expires
    })
}

const FAIL_LINE: &str = "FAIL        [basic:posture.example-fail] no ruleset targets main; protection allows force-push → manual step ruleset-main: Apply the main ruleset.";

#[test]
fn an_accepted_risk_prints_accepted_instead_of_fail_and_keeps_the_gap() {
    let dir = with_inventory(json!([accepted_risk("posture.example-fail", "2027-01-01")]));
    let audited = offline(dir.path());
    assert_eq!(
        audited.lines()[3..],
        [
            "ACCEPTED    [basic:posture.example-fail] no ruleset targets main; protection allows force-push → accepted risk merge-alone: the owner merges alone (#392, owner example-owner, until 2027-01-01)",
            "UNAVAILABLE [silver:operations.example-wait] waits for module observability",
            "NEXT Basic: 1 rule (posture.example-fail)",
        ]
    );
    // Never counted as passed: the level, the gap and the exit code stand.
    assert_eq!(audited.audit.reached, None);
    assert_eq!(audited.exit_code(true), 3);
    let json = audited.json();
    let rule = json["rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "posture.example-fail")
        .unwrap()
        .clone();
    assert_eq!(rule["status"], "failed");
    assert_eq!(
        rule["accepted_risk"],
        json!({"id": "merge-alone", "reason": "the owner merges alone", "issue": "#392", "owner": "example-owner", "expires": "2027-01-01"})
    );
    let other = json["rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "governance.example-pass")
        .unwrap()
        .clone();
    assert!(other.get("accepted_risk").is_none(), "{other}");
}

#[test]
fn an_expired_or_invalid_accepted_risk_accepts_nothing() {
    let mut invalid = accepted_risk("posture.example-fail", "2027-01-01");
    invalid.as_object_mut().unwrap().remove("issue");
    let too_long = accepted_risk("posture.example-fail", "2027-11-01");
    for entry in [
        accepted_risk("posture.example-fail", "2026-10-27"),
        invalid,
        too_long,
    ] {
        let dir = with_inventory(json!([entry]));
        let lines = offline(dir.path()).lines();
        assert_eq!(lines[3], FAIL_LINE, "{entry}");
        assert!(!lines.iter().any(|l| l.starts_with("ACCEPTED")), "{entry}");
    }
}

#[test]
fn several_rule_ids_are_accepted_and_an_unknown_one_is_a_finding() {
    let dir = with_inventory(json!([accepted_risk(
        "posture.typo, posture.example-fail",
        "2027-01-01"
    )]));
    let audited = offline(dir.path());
    let lines = audited.lines();
    assert_eq!(
        lines[3],
        "FINDING accepted risk merge-alone names unknown rule posture.typo"
    );
    assert!(
        lines[4].starts_with("ACCEPTED    [basic:posture.example-fail] "),
        "{lines:?}"
    );
    assert_eq!(
        audited.json()["level"]["findings"],
        json!(["accepted risk merge-alone names unknown rule posture.typo"])
    );
}

#[test]
fn an_accepted_risk_on_a_passing_rule_changes_nothing() {
    let dir = with_inventory(json!([accepted_risk(
        "governance.example-pass",
        "2027-01-01"
    )]));
    let audited = offline(dir.path());
    let lines = audited.lines();
    assert_eq!(lines[3], FAIL_LINE);
    assert!(!lines.iter().any(|l| l.starts_with("ACCEPTED")));
    assert!(audited.audit.accepted_risks.is_empty());
    assert!(
        audited.json()["rules"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r.get("accepted_risk").is_none())
    );
}
