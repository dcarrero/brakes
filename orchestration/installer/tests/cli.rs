use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
};
mod common;
mod configured;

use tempfile::TempDir;

struct Repo {
    _temp: TempDir,
    root: PathBuf,
}
impl Repo {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("project");
        fs::create_dir(&root).unwrap();
        assert!(
            Command::new("git")
                .args(["init", "-q"])
                .arg(&root)
                .status()
                .unwrap()
                .success()
        );
        Self { _temp: temp, root }
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_brakes"))
            .args(args)
            .arg(&self.root)
            .output()
            .unwrap()
    }
}

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "lists setup-core or its guides; product-boundary T7a"
)]
#[test]
fn installation_requires_declaration_and_defaults_to_plan() {
    let repo = Repo::new();
    // Planning is a read (#1259); writing to a repository without a remote needs the declaration.
    assert_eq!(repo.run(&["install", "--apply"]).status.code(), Some(2));
    assert!(!repo.root.join("AGENTS.md").exists());
    let result = repo.run(&["install", "--new-personal"]);
    assert!(result.status.success());
    assert!(String::from_utf8_lossy(&result.stdout).contains("PLAN AGENTS.md"));
    assert!(!repo.root.join("AGENTS.md").exists());
    assert!(repo.run(&["--new-personal", "install"]).status.success());
    assert!(repo.run(&["install", "--help"]).status.success());
}

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "lists setup-core or its guides; product-boundary T7a"
)]
#[test]
fn apply_installs_and_doctor_reports_incomplete_profile() {
    let repo = Repo::new();
    let result = repo.run(&["install", "--new-personal", "--apply"]);
    assert!(result.status.success(), "{:?}", result);
    assert!(repo.root.join(".agent-setup/lock.json").is_file());
    assert!(repo.root.join("docs/agent-setup/workflow.md").is_file());
    let result = repo.run(&["doctor"]);
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stdout).contains("Verification command missing"));
    assert!(!String::from_utf8_lossy(&result.stdout).contains("planning"));
    let result = repo.run(&["install"]);
    assert!(String::from_utf8_lossy(&result.stdout).contains("No changes."));
}

#[test]
fn remote_is_opt_in_and_install_cannot_request_it() {
    let repo = Repo::new();
    let result = repo.run(&["install", "--new-personal", "--remote", "--apply"]);
    assert_eq!(result.status.code(), Some(2));
    assert!(!repo.root.join("AGENTS.md").exists());
    assert!(
        repo.run(&["install", "--new-personal", "--apply"])
            .status
            .success()
    );
    let before = fs::read(repo.root.join(".agent-setup/lock.json")).unwrap();
    let result = repo.run(&["doctor", "--apply"]);
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(
        fs::read(repo.root.join(".agent-setup/lock.json")).unwrap(),
        before
    );
    let result = repo.run(&["doctor", "--remote"]);
    assert!(String::from_utf8_lossy(&result.stdout).contains("unambiguous GitHub origin"));
}

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "lists setup-core or its guides; product-boundary T7a"
)]
#[test]
fn stale_decisions_index_warns_without_failing_doctor() {
    let repo = Repo::new();
    assert!(
        repo.run(&["install", "--new-personal", "--apply"])
            .status
            .success()
    );
    let profile_path = repo.root.join(brakes::PROFILE);
    let mut profile: serde_json::Value =
        serde_json::from_slice(&fs::read(&profile_path).unwrap()).unwrap();
    profile["purpose"] = serde_json::json!("Example");
    profile["commands"]["verify"] = serde_json::json!("never executed");
    // Declared so no local rule fails; offline the posture rules (#721) have no
    // evidence, so a ready repository exits 4, never 1.
    profile["criticality"] = serde_json::json!("internal");
    profile["conventions"] = serde_json::json!([{"path": "docs/decisions.md", "adr": "docs/decisions.md#choice--accepted-2026-10-22"}]);
    fs::write(profile_path, serde_json::to_vec(&profile).unwrap()).unwrap();
    let decisions = repo.root.join("docs/decisions.md");
    fs::write(
        &decisions,
        "# Decisions\n\n## Choice — accepted, 2026-10-22\n",
    )
    .unwrap();
    assert!(repo.run(&["install", "--apply"]).status.success());
    // Isolate index readiness from the build checkout's release provenance.
    let lock_path = repo.root.join(brakes::LOCK);
    let mut lock: serde_json::Value =
        serde_json::from_slice(&fs::read(&lock_path).unwrap()).unwrap();
    lock["source_dirty"] = serde_json::json!(false);
    fs::write(lock_path, serde_json::to_vec(&lock).unwrap()).unwrap();
    with_workflow(&repo);
    assert_eq!(repo.run(&["doctor"]).status.code(), Some(4));

    fs::write(
        &decisions,
        "# Decisions\n\n## Choice — accepted, 2026-10-22\n\n## Another — accepted, 2026-10-23\n",
    )
    .unwrap();
    let before = fs::read(repo.root.join("AGENTS.md")).unwrap();
    let result = repo.run(&["doctor"]);
    // Ready, but the stale index is the Bronze rule `baseline.decisions-index-current` (#730).
    assert_eq!(result.status.code(), Some(3), "{result:?}");
    let output = String::from_utf8_lossy(&result.stdout);
    assert!(
        output.contains("WARNING: Decisions index stale:"),
        "{output}"
    );
    assert!(!output.contains("NOT READY:"), "{output}");
    assert_eq!(fs::read(repo.root.join("AGENTS.md")).unwrap(), before);
    fs::write(
        &decisions,
        "# Decisions\n\n## Choice — Superseded, 2026-10-22\n",
    )
    .unwrap();
    let result = repo.run(&["doctor"]);
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("Convention decision does not resolve")
    );
    fs::write(
        &decisions,
        "# Decisions\n\n## Choice — accepted, 2026-10-22\n\n## Another — accepted, 2026-10-23\n",
    )
    .unwrap();
    assert!(repo.run(&["install", "--apply"]).status.success());
    assert_eq!(fs::read(repo.root.join("AGENTS.md")).unwrap(), before);
    assert!(
        !String::from_utf8_lossy(&repo.run(&["doctor"]).stdout).contains("Decisions index stale")
    );
}

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "lists setup-core or its guides; product-boundary T7a"
)]
#[test]
fn remove_refuses_setup_core_an_unknown_module_and_a_missing_module_id() {
    let repo = Repo::new();
    assert!(
        repo.run(&["install", "--new-personal", "--apply"])
            .status
            .success()
    );
    let before = fs::read(repo.root.join(".agent-setup/lock.json")).unwrap();
    // `<repo>` precedes the module id, so the id is appended after the path.
    let run = |id: Option<&str>, apply: bool| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_brakes"));
        command.arg("remove").arg(&repo.root);
        if let Some(id) = id {
            command.arg(id);
        }
        if apply {
            command.arg("--apply");
        }
        command.output().unwrap()
    };
    let result = run(Some("setup-core"), true);
    assert_eq!(result.status.code(), Some(2), "{result:?}");
    assert_eq!(
        String::from_utf8_lossy(&result.stderr).trim(),
        "REFUSED: Cannot remove setup-core: it is the installer's own content"
    );
    let result = run(Some("nope"), true);
    assert_eq!(result.status.code(), Some(2), "{result:?}");
    assert_eq!(
        String::from_utf8_lossy(&result.stderr).trim(),
        "REFUSED: Unknown module id: nope"
    );
    let result = run(None, false);
    assert_eq!(result.status.code(), Some(2), "{result:?}");
    assert!(String::from_utf8_lossy(&result.stderr).contains("Usage:"));
    assert!(String::from_utf8_lossy(&result.stderr).contains("remove"));
    assert_eq!(
        fs::read(repo.root.join(".agent-setup/lock.json")).unwrap(),
        before
    );
    assert!(repo.root.join("AGENTS.md").exists());
    assert!(repo.root.join("docs/agent-setup/workflow.md").is_file());
}

// --- `host features` (#680) ---------------------------------------------------------

/// A `gh` on PATH that answers `gh api --include … <path>` from canned HTTP
/// responses, so `host` runs the real binary without the network.
struct FakeGh {
    temp: TempDir,
}
impl FakeGh {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("bin")).unwrap();
        fs::create_dir(temp.path().join("replies")).unwrap();
        let script = temp.path().join("bin/gh");
        common::write_executable(
            &script,
            "#!/bin/sh\nfor last; do :; done\nf=\"$FAKE_GH_REPLIES/$(printf %s \"$last\" | tr '/?=&.' '_____')\"\nif [ -f \"$f\" ]; then cat \"$f\"; head -1 \"$f\" | grep -q ' 2[0-9][0-9] ' && exit 0; exit 1; fi\nprintf 'HTTP/2.0 404 Not Found\\r\\n\\r\\n{\"message\":\"Not Found\"}'\nexit 1\n",
        );
        Self { temp }
    }
    fn reply(&self, path: &str, status: &str, body: &str) -> &Self {
        let name: String = path
            .chars()
            .map(|c| if "/?=&.".contains(c) { '_' } else { c })
            .collect();
        fs::write(
            self.temp.path().join("replies").join(name),
            format!("HTTP/2.0 {status}\r\nContent-Type: application/json\r\n\r\n{body}"),
        )
        .unwrap();
        self
    }
    fn fixture(&self, path: &str, name: &str) -> &Self {
        let body = fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/github")
                .join(name),
        )
        .unwrap();
        self.reply(path, "200 OK", &body)
    }
    fn run(&self, args: &[&str]) -> Output {
        let path = format!(
            "{}:{}",
            self.temp.path().join("bin").display(),
            std::env::var("PATH").unwrap_or_default()
        );
        Command::new(env!("CARGO_BIN_EXE_brakes"))
            .arg("host")
            .args(args)
            .env("PATH", path)
            .env("FAKE_GH_REPLIES", self.temp.path().join("replies"))
            .output()
            .unwrap()
    }
}

const HOST_BASE: &str = "repos/example-owner/example";
const UPGRADE_BODY: &str = r#"{"message": "Upgrade to GitHub Pro or make this repository public to enable this feature.", "status": "403"}"#;

/// A private repository of a user whose plan blocks rulesets and protection.
fn plan_gated() -> FakeGh {
    let gh = FakeGh::new();
    gh.fixture(HOST_BASE, "repository.json")
        .fixture("user", "user.json")
        .reply(
            &format!("{HOST_BASE}/rulesets"),
            "403 Forbidden",
            UPGRADE_BODY,
        )
        .fixture(&format!("{HOST_BASE}/environments"), "environments.json")
        .reply(
            &format!("{HOST_BASE}/branches/main/protection"),
            "403 Forbidden",
            UPGRADE_BODY,
        )
        .reply(
            &format!("{HOST_BASE}/vulnerability-alerts"),
            "404 Not Found",
            r#"{"message": "Vulnerability alerts are disabled.", "status": "404"}"#,
        );
    gh
}

#[test]
fn host_features_json_matches_the_golden_file_and_is_byte_identical() {
    let gh = plan_gated();
    let first = gh.run(&["features", "example-owner/example", "--json"]);
    assert_eq!(first.status.code(), Some(0), "{first:?}");
    let golden = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden/host_features.json"),
    )
    .unwrap();
    assert_eq!(String::from_utf8_lossy(&first.stdout), golden);
    let second = gh.run(&["--json", "features", "example-owner/example"]);
    assert_eq!(first.stdout, second.stdout);
}

#[test]
fn host_features_text_prints_one_line_per_feature() {
    let result = plan_gated().run(&["features", "example-owner/example"]);
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    let upgrade = "Upgrade to GitHub Pro or make this repository public to enable this feature.";
    assert_eq!(
        String::from_utf8_lossy(&result.stdout),
        format!(
            "repository: example-owner/example\n\
             visibility: private\n\
             plan_hint: free (never decides)\n\
             rulesets: unavailable (403: {upgrade})\n\
             environments: available\n\
             branch_protection: unavailable (403: {upgrade})\n\
             required_reviewers: unknown (200: no environment has a required_reviewers rule, so the feature was not observed)\n\
             dependabot_alerts: available\n\
             secret_scanning: unknown (200: security_and_analysis is not visible to this token)\n\
             workflow_lockfile: available\n\
             merge_queue: unavailable (403: {upgrade})\n"
        )
    );
}

#[test]
fn host_exit_codes_are_0_complete_1_refused_2_rate_limited() {
    let gh = FakeGh::new();
    for args in [
        &["features"][..],
        &["features", "a/b", "c/d"],
        &["features", "not-a-repository"],
        &["features", "example-owner/example", "--bogus"],
        &["unknown-subcommand"],
        &[],
    ] {
        let result = gh.run(args);
        assert_eq!(result.status.code(), Some(1), "{args:?}: {result:?}");
        assert!(
            String::from_utf8_lossy(&result.stderr).starts_with("REFUSED: "),
            "{args:?}: {result:?}"
        );
    }
    let word = configured::denied();
    let result = gh.run(&["features", &format!("{word}/anything")]);
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&result.stderr).trim(),
        format!(
            "REFUSED: {} repository refused, regardless of remote owner",
            configured::capitalised(&word)
        )
    );

    let gh = FakeGh::new();
    gh.reply(
        HOST_BASE,
        "401 Unauthorized",
        r#"{"message": "Requires authentication"}"#,
    );
    let result = gh.run(&["features", "example-owner/example"]);
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    assert_eq!(
        String::from_utf8_lossy(&result.stderr).trim(),
        "REFUSED: GitHub CLI is not authenticated, so repository example-owner/example could not be read (401: Requires authentication)"
    );
    assert!(result.stdout.is_empty());

    let gh = plan_gated();
    gh.reply(
        &format!("{HOST_BASE}/environments"),
        "429 Too Many Requests",
        r#"{"message": "slow down"}"#,
    );
    let result = gh.run(&["features", "example-owner/example", "--json"]);
    assert_eq!(result.status.code(), Some(2), "{result:?}");
    assert_eq!(
        String::from_utf8_lossy(&result.stderr).trim(),
        "INCOMPLETE: GitHub rate limit reached while reading features of example-owner/example (429: slow down)"
    );
    assert!(result.stdout.is_empty());

    assert_eq!(plan_gated().run(&["--help"]).status.code(), Some(0));
}

/// A repository `doctor` finds ready: profile completed, guides regenerated and
/// the lock's provenance isolated from the build checkout.
fn ready_repo(criticality: Option<&str>) -> Repo {
    let repo = Repo::new();
    assert!(
        repo.run(&["install", "--new-personal", "--apply"])
            .status
            .success()
    );
    let profile_path = repo.root.join(brakes::PROFILE);
    let mut profile: serde_json::Value =
        serde_json::from_slice(&fs::read(&profile_path).unwrap()).unwrap();
    profile["purpose"] = serde_json::json!("Example");
    profile["commands"]["verify"] = serde_json::json!("never executed");
    if let Some(criticality) = criticality {
        profile["criticality"] = serde_json::json!(criticality);
    }
    fs::write(profile_path, serde_json::to_vec(&profile).unwrap()).unwrap();
    assert!(repo.run(&["install", "--apply"]).status.success());
    let lock_path = repo.root.join(brakes::LOCK);
    let mut lock: serde_json::Value =
        serde_json::from_slice(&fs::read(&lock_path).unwrap()).unwrap();
    lock["source_dirty"] = serde_json::json!(false);
    fs::write(lock_path, serde_json::to_vec(&lock).unwrap()).unwrap();
    with_workflow(&repo);
    repo
}

/// A workflow, so `ci-health.workflow-exists` (#724) waits on its runs
/// offline instead of failing for want of CI, the governance files the
/// Bronze rules read (#728) and the merge guard's registration, whose warning
/// and step are Bronze rules (#730), so no local rule fails. The workflow and
/// Dependabot file also satisfy the static `ci.*` and `security.*` rules,
/// which count toward the levels since #873.
/// A workflow no static `ci.*` or `security.*` rule fails: least permissions,
/// timeouts, a workflow lint job, a full-history secrets job and an aggregate.
const CLEAN_WORKFLOW: &str = "on: push
permissions:
  contents: read
jobs:
  workflow-lint:
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - run: actionlint
  secrets:
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - run: \"gitleaks git && echo 'history: full'\"
  required:
    if: always()
    needs: [workflow-lint, secrets]
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - run: 'true'
";

fn with_workflow(repo: &Repo) {
    for (path, text) in [
        (
            ".claude/settings.json",
            r#"{"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "sh .claude/hooks/merge_guard.sh", "onFailure": "block"}]}]}}"#,
        ),
        (".github/workflows/ci.yml", CLEAN_WORKFLOW),
        (".agent-setup/service.yaml", "owner: example-owner\n"),
        (".github/pull_request_template.md", "Summary:\n"),
        (".github/ISSUE_TEMPLATE/task.yml", "name: Task\n"),
        (
            ".github/dependabot.yml",
            "updates:\n  - package-ecosystem: cargo\n    cooldown:\n      default-days: 7\n  - package-ecosystem: github-actions\n    cooldown:\n      default-days: 7\n",
        ),
    ] {
        let file = repo.root.join(path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, text).unwrap();
    }
}

#[test]
fn doctor_exit_code_4_offline_when_ready_and_only_remote_evidence_is_missing() {
    let result = ready_repo(Some("internal")).run(&["doctor"]);
    assert_eq!(result.status.code(), Some(4), "{result:?}");
    let out = String::from_utf8_lossy(&result.stdout);
    assert!(
        out.contains("\nAUDIT local/project: profile P1 unverified (humans unavailable, cadence unavailable, services unavailable, internal); required Bronze; reached none\n"),
        "{out}"
    );
    assert!(
        out.ends_with("NEXT Basic: 6 rules (baseline.branch-protection-matches, baseline.ci-policy-met, baseline.remote-readable, ci-health.workflow-exists, posture.default-branch-protected, posture.no-open-secret-scanning-alerts)\n"),
        "{out}"
    );
}

#[test]
fn doctor_exit_code_1_when_not_ready_whatever_the_level() {
    let repo = Repo::new();
    assert!(
        repo.run(&["install", "--new-personal", "--apply"])
            .status
            .success()
    );
    let result = repo.run(&["doctor"]);
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    assert!(String::from_utf8_lossy(&result.stdout).contains("\nAUDIT local/project: "));
}

#[test]
fn doctor_exit_code_2_when_refused() {
    let repo = ready_repo(Some("internal"));
    for args in [
        &["doctor", "--now", "28-10-2026"][..],
        &["doctor", "--now"][..],
        &["doctor", "--report"][..],
    ] {
        let result = repo.run(args);
        assert_eq!(result.status.code(), Some(2), "{args:?}: {result:?}");
        assert!(result.stdout.is_empty(), "{args:?}");
    }
    let result = repo.run(&["install", "--now", "2026-10-28"]);
    assert_eq!(result.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&result.stderr)
            .contains("--now and --report are only available with doctor")
    );
}

#[test]
fn doctor_exit_code_3_when_ready_but_a_required_rule_failed() {
    let result = ready_repo(None).run(&["doctor"]);
    assert_eq!(result.status.code(), Some(3), "{result:?}");
    let out = String::from_utf8_lossy(&result.stdout);
    assert!(
        out.contains("Configuration ready. Runtime/agent behavior has not been verified.\nAUDIT "),
        "{out}"
    );
    assert!(
        out.contains("FAIL        [basic:baseline.criticality-declared] "),
        "{out}"
    );
    assert!(
        out.ends_with("NEXT Basic: 7 rules (baseline.branch-protection-matches, baseline.ci-policy-met, baseline.criticality-declared, baseline.remote-readable, ci-health.workflow-exists, posture.default-branch-protected, posture.no-open-secret-scanning-alerts)\n"),
        "{out}"
    );
}

/// The mapping the binary uses for code 4, pinned on a hand-built audit; the
/// binary reaches it offline since the posture rules (#721).
#[test]
fn doctor_exit_code_4_when_ready_and_only_unavailable_evidence_blocks() {
    use brakes::auditor::{
        Audit, Evaluated, NextLevel,
        rules::{Level, Outcome, REGISTRY},
    };
    let rule = &REGISTRY[0];
    let audit = Audit {
        rules: vec![Evaluated {
            rule,
            required: true,
            outcome: Outcome::unavailable("token cannot read it (HTTP 403)"),
        }],
        reached: None,
        unverified_from: Some(Level::Basic),
        next: Some(NextLevel {
            level: Level::Basic,
            gap: vec![rule.id],
        }),
        accepted_risks: Vec::new(),
        risk_findings: Vec::new(),
    };
    assert_eq!(audit.exit_code(true, Level::Bronze), 4);
    assert_eq!(audit.exit_code(false, Level::Bronze), 1);
}

#[test]
fn doctor_json_with_the_same_now_is_byte_identical_and_dated_by_it() {
    let repo = ready_repo(None);
    let first = repo.run(&["doctor", "--json", "--now", "2026-10-28"]);
    let second = repo.run(&["doctor", "--json", "--now", "2026-10-28"]);
    assert_eq!(first.status.code(), Some(3), "{first:?}");
    assert_eq!(first.stdout, second.stdout);
    let value: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(value["audited_at"], "2026-10-28");
    assert_eq!(value["window_days"], 28);
    assert_eq!(value["level"]["required"], "Bronze");
    assert_eq!(value["level"]["reached"], serde_json::Value::Null);
    assert!(
        value["next_level"]["gap"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("baseline.criticality-declared")),
        "{value}"
    );
}

#[test]
fn doctor_report_writes_the_markdown_of_the_repository() {
    let repo = ready_repo(None);
    let path = repo._temp.path().join("audit.md");
    let result = repo.run(&[
        "doctor",
        "--now",
        "2026-10-28",
        "--report",
        path.to_str().unwrap(),
    ]);
    assert_eq!(result.status.code(), Some(3), "{result:?}");
    let markdown = fs::read_to_string(&path).unwrap();
    assert!(
        markdown.starts_with("# Audit local/project\n\nAudited at 2026-10-28 over a 28-day window"),
        "{markdown}"
    );
    assert!(
        markdown.contains("\nNEXT Basic: 7 rules (baseline.branch-protection-matches, baseline.ci-policy-met, baseline.criticality-declared, baseline.remote-readable, ci-health.workflow-exists, posture.default-branch-protected, posture.no-open-secret-scanning-alerts)\n"),
        "{markdown}"
    );
}

// --- `host repos` and `host org` (#681) ------------------------------------------------

/// The owner's own listing: `user` says who is authenticated, `user/repos`
/// carries the private repositories too.
fn own_repositories() -> FakeGh {
    let gh = FakeGh::new();
    gh.fixture("users/example-owner", "users_example_owner.json")
        .fixture("user", "user_owner_counts.json")
        .fixture(
            "user/repos?affiliation=owner&per_page=100&page=1",
            "user_repos.json",
        );
    gh
}

const ORG_REPOS_PAGE: &str = "orgs/example-org/repos?type=all&per_page=100&page=";

/// An organization of 150 repositories whose page 2 is rate-limited.
fn rate_limited_organization() -> FakeGh {
    let page: Vec<String> = (1..=100)
        .map(|i| {
            format!(
                r#"{{"full_name": "example-org/repo-{i:03}", "visibility": "private", "default_branch": "main", "archived": false, "fork": false, "pushed_at": null, "language": null}}"#
            )
        })
        .collect();
    let gh = FakeGh::new();
    gh.fixture("users/example-org", "users_example_org.json")
        .fixture("orgs/example-org", "org.json")
        .reply(
            &format!("{ORG_REPOS_PAGE}1"),
            "200 OK",
            &format!("[{}]", page.join(",")),
        )
        .reply(
            &format!("{ORG_REPOS_PAGE}2"),
            "429 Too Many Requests",
            r#"{"message": "slow down"}"#,
        );
    gh
}

fn golden(name: &str) -> String {
    fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/golden")
            .join(name),
    )
    .unwrap()
}

#[test]
fn host_repos_json_matches_the_golden_file_and_is_byte_identical() {
    let gh = own_repositories();
    let first = gh.run(&["repos", "example-owner", "--json"]);
    assert_eq!(first.status.code(), Some(0), "{first:?}");
    assert_eq!(
        String::from_utf8_lossy(&first.stdout),
        golden("host_repos.json")
    );
    let second = gh.run(&["--json", "repos", "example-owner"]);
    assert_eq!(first.stdout, second.stdout);
}

#[test]
fn host_repos_text_prints_one_line_per_repository_with_its_flags() {
    let result = own_repositories().run(&["repos", "example-owner"]);
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    assert_eq!(
        String::from_utf8_lossy(&result.stdout),
        "owner: example-owner (user)\n\
         example-owner/archived-notes public master archived\n\
         example-owner/example private main\n\
         example-owner/forked-tool public main fork\n\
         3 repositories\n"
    );
    assert!(result.stderr.is_empty(), "{result:?}");
}

#[test]
fn host_repos_partial_exits_2_and_prints_the_unread_count() {
    let result = rate_limited_organization().run(&["repos", "example-org"]);
    assert_eq!(result.status.code(), Some(2), "{result:?}");
    let stdout = String::from_utf8_lossy(&result.stdout);
    assert!(
        stdout
            .starts_with("owner: example-org (organization)\nexample-org/repo-001 private main\n")
    );
    assert!(stdout.ends_with("100 repositories\n"), "{stdout}");
    assert_eq!(
        String::from_utf8_lossy(&result.stderr),
        "INCOMPLETE: GitHub rate limit reached while reading repositories of example-org (429: slow down)\n\
         NOT READ: 50 repositories not read: example-org from page 2 on\n"
    );

    let result = rate_limited_organization().run(&["repos", "example-org", "--json"]);
    assert_eq!(result.status.code(), Some(2), "{result:?}");
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["repositories"].as_array().unwrap().len(), 100);
    assert_eq!(
        report["stopped"]["kind"],
        serde_json::json!({"rate_limited": {"reset_epoch": null}})
    );
    assert_eq!(
        report["unread"],
        serde_json::json!(["50 repositories not read: example-org from page 2 on"])
    );
}

#[test]
fn host_repos_call_budget_exhaustion_exits_2_the_same_way() {
    let gh = rate_limited_organization();
    let result = gh.run(&["repos", "--call-budget", "3", "example-org"]);
    assert_eq!(result.status.code(), Some(2), "{result:?}");
    assert_eq!(
        String::from_utf8_lossy(&result.stderr),
        "INCOMPLETE: call budget of 3 exhausted\n\
         NOT READ: 50 repositories not read: example-org from page 2 on\n"
    );
    for args in [
        &["repos", "example-org", "--call-budget"][..],
        &["repos", "example-org", "--call-budget", "zero"],
        &["repos", "example-org", "--call-budget", "0"],
        &["features", "example-owner/example", "--call-budget", "5"],
        &["org", "example-org", "--call-budget", "5"],
        &["repos"],
        &["repos", "a", "b"],
    ] {
        let result = gh.run(args);
        assert_eq!(result.status.code(), Some(1), "{args:?}: {result:?}");
    }
    let word = configured::capitalised(&configured::denied());
    let result = gh.run(&["repos", &word]);
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    assert!(String::from_utf8_lossy(&result.stderr).contains(&word));
}

fn organization() -> FakeGh {
    let gh = FakeGh::new();
    gh.fixture("orgs/example-org", "org.json")
        .fixture(
            "orgs/example-org/rulesets?per_page=100&page=1",
            "org_rulesets.json",
        )
        .fixture("orgs/example-org/rulesets/7", "org_ruleset_7.json");
    gh
}

#[test]
fn host_org_json_matches_the_golden_file_and_is_byte_identical() {
    let gh = organization();
    let first = gh.run(&["org", "example-org", "--json"]);
    assert_eq!(first.status.code(), Some(0), "{first:?}");
    assert_eq!(
        String::from_utf8_lossy(&first.stdout),
        golden("host_org.json")
    );
    let second = gh.run(&["--json", "org", "example-org"]);
    assert_eq!(first.stdout, second.stdout);
}

#[test]
fn host_org_text_says_unknown_for_unseen_fields_and_unavailable_rulesets() {
    let gh = FakeGh::new();
    gh.fixture("orgs/example-org", "org_outsider.json").reply(
        "orgs/example-org/rulesets?per_page=100&page=1",
        "403 Forbidden",
        r#"{"message": "Must have admin rights to Repository."}"#,
    );
    let result = gh.run(&["org", "example-org"]);
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    assert_eq!(
        String::from_utf8_lossy(&result.stdout),
        "organization: example-org\n\
         two_factor_requirement_enabled: unknown (not visible to this token)\n\
         default_repository_permission: unknown (not visible to this token)\n\
         members_can_create_public_repositories: unknown (not visible to this token)\n\
         web_commit_signoff_required: unknown (not visible to this token)\n\
         plan_hint: none\n\
         rulesets: unavailable (organization rulesets of example-org are unavailable: organization rulesets need the Team plan or admin (403: Must have admin rights to Repository.))\n"
    );

    let result = organization().run(&["org", "example-org"]);
    assert_eq!(
        String::from_utf8_lossy(&result.stdout),
        "organization: example-org\n\
         two_factor_requirement_enabled: true\n\
         default_repository_permission: read\n\
         members_can_create_public_repositories: false\n\
         web_commit_signoff_required: false\n\
         plan_hint: team (never decides)\n\
         rulesets: 1\n\
         ruleset default-branch: branch, active\n"
    );
    let result = FakeGh::new().run(&["org", "nowhere"]);
    assert_eq!(result.status.code(), Some(1), "{result:?}");
}

/// repo-baseline T7 (#710): `install --module repo-baseline [--profile P]` plans the
/// baseline with its tags, records the profile with the answers and refuses the flag
/// where it records nothing.
#[test]
fn lifecycle_install_module_repo_baseline_with_profile_plans_and_records_it() {
    let repo = Repo::new();
    assert!(
        repo.run(&["install", "--new-personal", "--apply"])
            .status
            .success()
    );
    let stdout = |out: &Output| String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = |out: &Output| String::from_utf8_lossy(&out.stderr).trim().to_owned();
    let plain = repo.run(&["install"]);
    assert!(!stdout(&plain).contains("repo-baseline"), "{plain:?}");
    let planned = repo.run(&["install", "--module", "repo-baseline", "--profile", "P2"]);
    assert!(planned.status.success(), "{planned:?}");
    let text = stdout(&planned);
    for line in [
        "PLAN .github/rulesets/main.json [managed:repo-baseline]",
        "PLAN .github/CODEOWNERS [seed:repo-baseline]",
        "PLAN .agent-setup/modules/repo-baseline.json [answers:repo-baseline]",
        "Plan only; no writes. Review before using --apply.",
    ] {
        assert!(text.contains(line), "{line}\n{text}");
    }
    assert!(!repo.root.join(".github/rulesets/main.json").exists());
    let applied = repo.run(&[
        "install",
        "--module",
        "repo-baseline",
        "--profile",
        "P2",
        "--apply",
    ]);
    assert!(applied.status.success(), "{applied:?}");
    let again = repo.run(&["install"]);
    assert!(stdout(&again).contains("No changes."), "{again:?}");
    for (args, message) in [
        (
            &["install", "--profile", "P2"][..],
            "REFUSED: --profile is only available with install --module",
        ),
        (
            &["doctor", "--profile", "P2"][..],
            "REFUSED: --profile is only available with install --module",
        ),
        (
            &["install", "--module", "repo-baseline", "--profile", "P4"][..],
            "REFUSED: Unknown profile: P4; use P1, P2 or P3",
        ),
    ] {
        let out = repo.run(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {out:?}");
        assert_eq!(stderr(&out), message, "{args:?}");
    }
    let missing = repo.run(&["install", "--module", "repo-baseline", "--profile"]);
    assert_eq!(missing.status.code(), Some(2), "{missing:?}");
}

// --- `host probe` (#683) ------------------------------------------------------------

fn protected_by_ruleset() -> FakeGh {
    let gh = FakeGh::new();
    gh.reply(
        &format!("{HOST_BASE}/rulesets?per_page=100&page=1"),
        "200 OK",
        r#"[{"id": 42}]"#,
    )
    .reply(
        &format!("{HOST_BASE}/rulesets/42"),
        "200 OK",
        r#"{"id": 42, "name": "main", "target": "branch", "enforcement": "active",
            "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
            "bypass_actors": [],
            "rules": [{"type": "required_status_checks", "parameters":
                {"required_status_checks": [{"context": "verify"}]}}]}"#,
    )
    .reply(
        &format!("{HOST_BASE}/branches/main/protection"),
        "404 Not Found",
        r#"{"message": "Branch not protected", "status": "404"}"#,
    );
    gh
}

#[test]
fn host_probe_json_matches_the_golden_file_and_is_byte_identical() {
    let gh = protected_by_ruleset();
    let args = [
        "probe",
        "example-owner/example",
        "required-check",
        "--arg",
        "branch=main",
        "--arg",
        "check=verify",
        "--json",
    ];
    let first = gh.run(&args);
    assert_eq!(first.status.code(), Some(0), "{first:?}");
    assert_eq!(
        String::from_utf8_lossy(&first.stdout),
        golden("host_probe.json")
    );
    assert_eq!(gh.run(&args).stdout, first.stdout);
}

#[test]
fn host_probe_text_prints_one_remote_line_in_the_engine_format() {
    let gh = protected_by_ruleset();
    let run = |check: &str| {
        gh.run(&[
            "probe",
            "example-owner/example",
            "required-check",
            "--arg",
            "branch=main",
            "--arg",
            &format!("check={check}"),
        ])
    };
    let verified = run("verify");
    assert_eq!(verified.status.code(), Some(0), "{verified:?}");
    assert_eq!(
        String::from_utf8_lossy(&verified.stdout),
        "REMOTE [verified:host-adapter] required-check — ruleset 42 \"main\" requires \"verify\"\n"
    );
    let pending = run("build");
    assert_eq!(pending.status.code(), Some(0), "{pending:?}");
    assert_eq!(
        String::from_utf8_lossy(&pending.stdout),
        "REMOTE [pending:host-adapter] required-check — no ruleset or classic protection requires \"build\" on main\n"
    );
}

#[test]
fn host_probe_takes_list_arguments_comma_separated() {
    let result = protected_by_ruleset().run(&[
        "probe",
        "example-owner/example",
        "ruleset-required-checks",
        "--arg",
        "branch=main",
        "--arg",
        "checks=verify",
    ]);
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    assert_eq!(
        String::from_utf8_lossy(&result.stdout),
        "REMOTE [verified:host-adapter] ruleset-required-checks — required on main: verify\n"
    );
}

#[test]
fn host_probe_unavailable_and_failed_answers_exit_1_and_still_print_the_line() {
    let gh = FakeGh::new();
    gh.reply(
        &format!("{HOST_BASE}/rulesets?per_page=100&page=1"),
        "401 Unauthorized",
        r#"{"message": "Bad credentials", "status": "401"}"#,
    );
    let result = gh.run(&[
        "probe",
        "example-owner/example",
        "required-check",
        "--arg",
        "branch=main",
        "--arg",
        "check=verify",
    ]);
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    assert_eq!(
        String::from_utf8_lossy(&result.stdout),
        "REMOTE [unavailable:host-adapter] required-check — gh not authenticated: GitHub CLI is not authenticated, so rulesets of example-owner/example could not be read (401: Bad credentials)\n"
    );
}

#[test]
fn host_probe_refuses_an_unknown_id_a_missing_argument_and_a_malformed_arg() {
    let gh = FakeGh::new();
    for (args, reason) in [
        (
            vec!["probe", "example-owner/example", "nope"],
            "REFUSED: remote probe `nope` is not in the host-adapter registry\n",
        ),
        (
            vec![
                "probe",
                "example-owner/example",
                "required-check",
                "--arg",
                "branch=main",
            ],
            "REFUSED: remote probe `required-check` needs argument `check`\n",
        ),
        (
            vec![
                "probe",
                "example-owner/example",
                "required-check",
                "--arg",
                "branch",
            ],
            "REFUSED: --arg needs key=value, got `branch`\n",
        ),
    ] {
        let result = gh.run(&args);
        assert_eq!(result.status.code(), Some(1), "{result:?}");
        assert!(result.stdout.is_empty(), "{result:?}");
        assert_eq!(String::from_utf8_lossy(&result.stderr), reason);
    }
}

// --- `apply <repo>` without `--remote` (#901) ------------------------------------------

/// `apply <repo>` runs the real binary against a `gh` on PATH that logs every
/// call and answers 404 to each: the diff is printed, nothing is written and
/// every call is a GET.
#[test]
fn apply_prints_the_remote_diff_through_gh_and_sends_only_reads() {
    let repo = Repo::new();
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&repo.root)
            .args([
                "remote",
                "add",
                "origin",
                "https://github.com/example-owner/example.git"
            ])
            .status()
            .unwrap()
            .success()
    );
    for args in [
        &["install", "--apply"][..],
        &["install", "--module", "repo-baseline", "--apply"][..],
    ] {
        let out = repo.run(args);
        assert!(out.status.success(), "{args:?}: {out:?}");
    }
    let gh = tempfile::tempdir().unwrap();
    let log = gh.path().join("calls.log");
    let script = gh.path().join("gh");
    common::write_executable(
        &script,
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$FAKE_GH_LOG\"\nprintf 'HTTP/2.0 404 Not Found\\r\\n\\r\\n{\"message\":\"Not Found\"}'\nexit 1\n",
    );
    let lock = fs::read(repo.root.join(".agent-setup/lock.json")).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_brakes"))
        .arg("apply")
        .arg(&repo.root)
        .env(
            "PATH",
            format!(
                "{}:{}",
                gh.path().display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .env("FAKE_GH_LOG", &log)
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8_lossy(&out.stdout);
    let remote: Vec<&str> = text.lines().filter(|l| l.starts_with("REMOTE ")).collect();
    assert_eq!(remote.len(), 6, "{text}");
    for item in [
        "classic-protection-retire",
        "dependabot-alerts",
        "dependabot-security-updates",
        "labels",
        "repo-settings",
        "ruleset-main",
    ] {
        assert!(
            text.contains(&format!("REMOTE github:{item} [repo-baseline] ")),
            "{item}\n{text}"
        );
    }
    assert!(
        text.contains(
            "REMOTE github:ruleset-main [repo-baseline] blocked — waits for step `check-reported`"
        ),
        "{text}"
    );
    assert!(
        text.ends_with("No remote changes.\n") || text.ends_with("Remote plan only; no writes.\n"),
        "{text}"
    );
    let calls = fs::read_to_string(&log).unwrap_or_default();
    assert!(!calls.is_empty(), "the probes read through gh");
    for call in calls.lines() {
        assert!(call.contains("example-owner/example"), "{call}");
        for method in ["POST", "PUT", "PATCH", "DELETE"] {
            assert!(!call.contains(method), "a write was sent: {call}");
        }
    }
    assert_eq!(
        fs::read(repo.root.join(".agent-setup/lock.json")).unwrap(),
        lock
    );
}

#[test]
fn apply_refuses_remote_and_the_flags_it_does_not_take() {
    let repo = Repo::new();
    assert!(
        repo.run(&["install", "--new-personal", "--apply"])
            .status
            .success()
    );
    for (args, message) in [
        (
            &["install", "--remote"][..],
            "REFUSED: --remote is only available with doctor and apply",
        ),
        (
            &["apply", "--apply"][..],
            "REFUSED: apply takes only <project>; it reads the remote items and writes nothing",
        ),
        (
            &["apply", "--new-personal"][..],
            "REFUSED: apply takes only <project>; it reads the remote items and writes nothing",
        ),
        (
            &["apply", "--json"][..],
            "REFUSED: --json is only available with doctor",
        ),
    ] {
        let out = repo.run(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {out:?}");
        assert_eq!(
            String::from_utf8_lossy(&out.stderr).trim(),
            message,
            "{args:?}"
        );
    }
}

// --- `apply <repo> --remote` (#903): refusals before any `gh` process --------------------

/// Runs the binary with `args` and `root` against a `gh` on PATH that logs every
/// call; returns the output and the logged calls.
fn run_with_logging_gh(args: &[&str], root: &std::path::Path) -> (Output, String) {
    let gh = tempfile::tempdir().unwrap();
    let log = gh.path().join("calls.log");
    let script = gh.path().join("gh");
    common::write_executable(
        &script,
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$FAKE_GH_LOG\"\nprintf 'HTTP/2.0 404 Not Found\\r\\n\\r\\n{\"message\":\"Not Found\"}'\nexit 1\n",
    );
    let out = Command::new(env!("CARGO_BIN_EXE_brakes"))
        .args(args)
        .arg(root)
        .env(
            "PATH",
            format!(
                "{}:{}",
                gh.path().display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .env("FAKE_GH_LOG", &log)
        .output()
        .unwrap();
    (out, fs::read_to_string(&log).unwrap_or_default())
}

fn with_remotes(remotes: &[(&str, &str)]) -> Repo {
    let repo = Repo::new();
    for (name, url) in remotes {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(&repo.root)
                .args(["remote", "add", name, url])
                .status()
                .unwrap()
                .success()
        );
    }
    repo
}

#[test]
fn apply_remote_refusals_stand_and_start_no_gh_process() {
    let word = configured::denied();
    let denied_origin = format!("https://github.com/{word}/example.git");
    let denied_named = configured::capitalised(&word);
    let cases: [(&[(&str, &str)], &str); 4] = [
        (
            &[("origin", "https://github.com/someone-else/example.git")],
            "someone-else",
        ),
        (&[("origin", denied_origin.as_str())], denied_named.as_str()),
        (
            &[("origin", "https://github.com/outside-org/other.git")],
            "outside-org",
        ),
        (
            &[
                ("upstream", "https://github.com/example-owner/one.git"),
                ("fork", "https://github.com/example-owner/two.git"),
            ],
            "",
        ),
    ];
    for (remotes, named) in cases {
        let repo = with_remotes(remotes);
        let (out, calls) = run_with_logging_gh(&["apply", "--remote"], &repo.root);
        assert_eq!(out.status.code(), Some(2), "{remotes:?}: {out:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.starts_with("REFUSED: "), "{stderr}");
        assert!(stderr.contains(named), "{named}: {stderr}");
        assert!(calls.is_empty(), "{remotes:?}: gh was called: {calls}");
    }
    // Two projects in one invocation are refused by the usage.
    let repo = with_remotes(&[("origin", "https://github.com/example-owner/example.git")]);
    let (out, calls) = run_with_logging_gh(&["apply", "--remote", "/tmp/other"], &repo.root);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(calls.is_empty(), "{calls}");
}

/// The write path end to end through the binary against a fake `gh` (never a
/// real host): a repository with repo-baseline installed and every read
/// answering 404. The writes sent are exactly those of the items the diff names
/// `create`, `update` or `remove`, each against the origin repository; the fake
/// accepts none, so nothing verifies and the run exits 1.
#[test]
fn apply_remote_through_gh_sends_exactly_the_diffed_writes() {
    let repo = with_remotes(&[("origin", "https://github.com/example-owner/example.git")]);
    for args in [
        &["install", "--apply"][..],
        &["install", "--module", "repo-baseline", "--apply"][..],
    ] {
        assert!(repo.run(args).status.success(), "{args:?}");
    }
    let (out, calls) = run_with_logging_gh(&["apply", "--remote"], &repo.root);
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "{text}");
    let writable: Vec<&str> = text
        .lines()
        .filter(|l| {
            l.starts_with("REMOTE ")
                && [" create — ", " update — ", " remove — "]
                    .iter()
                    .any(|v| l.contains(v))
        })
        .map(|l| l.split(' ').nth(1).unwrap())
        .collect();
    let written: Vec<&str> = text
        .lines()
        .filter(|l| l.starts_with("WRITE "))
        .map(|l| l.split(' ').nth(1).unwrap())
        .collect();
    let mut sorted = written.clone();
    sorted.sort();
    assert_eq!(sorted, writable, "{text}");
    assert!(!written.is_empty(), "{text}");
    assert!(
        text.contains("REMOTE github:ruleset-main [repo-baseline] blocked"),
        "{text}"
    );
    assert!(!written.contains(&"github:ruleset-main"), "{text}");
    assert!(
        text.lines().filter(|l| l.starts_with("VERIFY ")).count() == written.len(),
        "{text}"
    );
    assert!(text.trim_end().ends_with("items not verified."), "{text}");
    for call in calls.lines() {
        assert!(call.contains("repos/example-owner/example"), "{call}");
        assert!(!call.contains("DELETE"), "{call}");
    }
}

/// The README's first install: a profile with only `purpose` and `commands.verify`
/// plans and applies modules (#1258).
#[test]
fn a_minimal_profile_installs_modules() {
    let repo = Repo::new();
    let git = |args: &[&str]| {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(&repo.root)
                .args(args)
                .status()
                .unwrap()
                .success()
        )
    };
    git(&[
        "remote",
        "add",
        "origin",
        "https://github.com/example-owner/toy.git",
    ]);
    fs::create_dir(repo.root.join(".agent-setup")).unwrap();
    fs::write(
        repo.root.join(".agent-setup/project.json"),
        r#"{"purpose": "A toy library.", "commands": {"verify": "make check"}}"#,
    )
    .unwrap();
    for apply in [false, true] {
        let mut args = vec![
            "install",
            "--module",
            "stack-packs",
            "--module",
            "repo-baseline",
            "--module",
            "ci-baseline",
        ];
        if apply {
            args.push("--apply");
        }
        let result = repo.run(&args);
        let out = String::from_utf8_lossy(&result.stdout).into_owned()
            + &String::from_utf8_lossy(&result.stderr);
        assert!(result.status.success(), "{args:?}: {out}");
        assert!(!out.contains("REFUSED"), "{args:?}: {out}");
    }
    assert!(repo.root.join(".agent-setup/lock.json").is_file());
}

/// #55: a clone whose `origin` is a local path is outside the write scope. The plan
/// says the apply will refuse and why; the apply refuses naming the remote.
#[test]
fn a_local_path_origin_is_named_by_the_plan_and_by_the_apply_refusal() {
    let repo = Repo::new();
    let origin = repo._temp.path().join("origin");
    let origin = origin.to_str().unwrap();
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&repo.root)
            .args(["remote", "add", "origin", origin])
            .status()
            .unwrap()
            .success()
    );
    let refusal = format!("Remote is not a GitHub URL: {origin};");
    let plan = repo.run(&["install", "--no-input"]);
    let stdout = String::from_utf8_lossy(&plan.stdout);
    assert_eq!(plan.status.code(), Some(0), "{stdout}");
    let last = stdout.lines().last().unwrap_or_default();
    assert!(
        last.starts_with(&format!("APPLY REFUSED: {refusal}")),
        "{stdout}"
    );
    let applied = repo.run(&["install", "--apply", "--no-input"]);
    let stderr = String::from_utf8_lossy(&applied.stderr);
    assert_eq!(applied.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains(&format!("REFUSED: {refusal}")), "{stderr}");
    assert!(!stderr.contains("relative URL"), "{stderr}");
    assert!(!repo.root.join(".agent-setup").exists());
}

/// A plan the write scope accepts says nothing about it.
#[test]
fn a_plan_the_apply_would_accept_prints_no_apply_refusal() {
    let repo = Repo::new();
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&repo.root)
            .args([
                "remote",
                "add",
                "origin",
                "https://github.com/example-owner/app.git"
            ])
            .status()
            .unwrap()
            .success()
    );
    let plan = repo.run(&["install", "--no-input"]);
    let stdout = String::from_utf8_lossy(&plan.stdout);
    assert_eq!(plan.status.code(), Some(0), "{stdout}");
    assert!(!stdout.contains("APPLY REFUSED"), "{stdout}");
}
