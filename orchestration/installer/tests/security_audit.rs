//! security T7 (#793; SPEC-security.md, "Auditor rules this module enables" and
//! "How `doctor` reports the static rules"): the static `security.*` rules over
//! every workflow under `.github/workflows/` (the walker of
//! `auditor/workflows.rs`) and the exception files, reported as `doctor`
//! warnings, never as readiness, and pinned in `doctor --json` by a golden.
use brakes::auditor::workflows;
use brakes::modules::security::{self, audit, exceptions::DEFAULT_BYPASS_MAX_DAYS, pii};
use chrono::NaiveDate;
use serde_json::{Value, json};
use std::{fs, path::Path, process::Command};
use tempfile::TempDir;

const AUDIT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/security/audit");
const EXCEPTIONS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/security/exceptions"
);
const TODAY: &str = "2026-11-10";

fn today() -> NaiveDate {
    NaiveDate::parse_from_str(TODAY, "%Y-%m-%d").unwrap()
}

fn workflow(name: &str) -> String {
    fs::read_to_string(Path::new(AUDIT).join(name)).expect(name)
}

/// Copies every file under `from` into `to`, keeping relative paths.
fn copy_tree(from: &Path, to: &Path) {
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            fs::create_dir_all(&target).unwrap();
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn git(root: &Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?}");
}

/// A git checkout tracking `files` (repository path → bytes) and nothing else:
/// `security.binary-artifacts` reads the index, so every fixture is a checkout.
fn checkout(files: &[(&str, &[u8])]) -> TempDir {
    let dir = TempDir::new().unwrap();
    git(dir.path(), &["init", "-q"]);
    for (path, bytes) in files {
        let path = dir.path().join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    git(dir.path(), &["add", "-A"]);
    dir
}

/// A checkout with `files` (repository path → text) and nothing else.
fn repo(files: &[(&str, &str)]) -> TempDir {
    let bytes: Vec<(&str, &[u8])> = files.iter().map(|(p, t)| (*p, t.as_bytes())).collect();
    checkout(&bytes)
}

/// A checkout whose workflows are the named audit fixtures, plus `files`.
fn with_workflows(names: &[&str], files: &[(&str, &str)]) -> TempDir {
    let texts: Vec<(String, String)> = names
        .iter()
        .map(|n| (format!(".github/workflows/{n}"), workflow(n)))
        .collect();
    let mut all: Vec<(&str, &str)> = texts
        .iter()
        .map(|(p, t)| (p.as_str(), t.as_str()))
        .collect();
    all.extend_from_slice(files);
    repo(&all)
}

fn findings(root: &Path) -> Vec<String> {
    audit::findings(root, today(), DEFAULT_BYPASS_MAX_DAYS)
}

fn rule_lines<'a>(all: &'a [String], rule: &str) -> Vec<&'a str> {
    let prefix = format!("WARNING: {rule}: ");
    all.iter()
        .filter(|l| l.starts_with(&prefix))
        .map(String::as_str)
        .collect()
}

const RULES: [&str; 13] = [
    "security.secrets-gate",
    "security.secrets-full-history",
    "security.deps-gate",
    "security.scanner-unpinned",
    "security.trivy-compromised-version",
    "security.bypass-inventory-valid",
    "security.bypass-unregistered",
    "security.bypass-expired",
    "security.binary-artifacts",
    "security.sast-gate",
    "security.container-gate",
    "security.pii-declared",
    "security.mutation-gate",
];

/// Every finding belongs to one of the thirteen rules, as a warning.
fn assert_channel(all: &[String]) {
    for line in all {
        assert!(
            RULES
                .iter()
                .any(|r| line.starts_with(&format!("WARNING: {r}: "))),
            "{line}"
        );
    }
}

// --- the walker keeps what the rules read ------------------------------------

#[test]
fn the_walker_keeps_each_steps_run_script() {
    let wf = workflows::parse(&workflow("installers.yml")).unwrap();
    let scan = wf.job("scan").unwrap();
    assert_eq!(
        scan.steps[1].run.as_deref(),
        Some("pip install semgrep"),
        "{scan:?}"
    );
    assert!(scan.steps[3].run.as_deref().unwrap().contains("wget -q"));
    let wf = workflows::parse(&workflow("trivy-action.yml")).unwrap();
    assert_eq!(wf.job("trivy").unwrap().steps[1].run, None);
}

// --- the fixtures of the issue ------------------------------------------------

#[test]
fn the_self_audit_workflows_have_no_secrets_gate_and_nothing_else_but_the_lockfile_scan() {
    let dir = repo(&[("Cargo.lock", "")]);
    copy_tree(&Path::new(AUDIT).join("ours"), &{
        let w = dir.path().join(".github/workflows");
        fs::create_dir_all(&w).unwrap();
        w
    });
    let all = findings(dir.path());
    assert_eq!(
        all,
        [
            "WARNING: security.secrets-gate: No secrets gate: no gitleaks job and secret scanning off",
            "WARNING: security.deps-gate: No lockfile vulnerability scan in CI",
            "WARNING: security.sast-gate: No static analysis job in CI",
        ]
    );
}

#[test]
fn an_unmanaged_repository_with_none_of_it_only_lacks_the_secrets_gate() {
    let dir = repo(&[("README.md", "# x\n")]);
    assert_eq!(
        findings(dir.path()),
        [
            "WARNING: security.secrets-gate: No secrets gate: no gitleaks job and secret scanning off",
            "WARNING: security.sast-gate: No static analysis job in CI",
        ]
    );
}

#[test]
fn trivy_action_by_tag_is_unpinned_and_inside_the_compromise_window() {
    let dir = with_workflows(&["trivy-action.yml"], &[("Cargo.lock", "")]);
    let all = findings(dir.path());
    assert_channel(&all);
    assert_eq!(
        rule_lines(&all, "security.scanner-unpinned"),
        [
            "WARNING: security.scanner-unpinned: Scanner aquasecurity/trivy-action in .github/workflows/trivy-action.yml is not pinned by SHA or checksum"
        ]
    );
    assert_eq!(
        rule_lines(&all, "security.trivy-compromised-version"),
        [
            "WARNING: security.trivy-compromised-version: Trivy trivy-action@v0.28.0 is within the March 2026 compromise window"
        ]
    );
    // A Trivy fs scan is a lockfile scan; no secrets job, so no history finding.
    assert!(rule_lines(&all, "security.deps-gate").is_empty(), "{all:?}");
    assert!(rule_lines(&all, "security.secrets-full-history").is_empty());
    assert_eq!(rule_lines(&all, "security.secrets-gate").len(), 1);
}

#[test]
fn a_trivy_action_from_v0_35_0_or_by_sha_is_not_in_the_window() {
    let text = workflow("trivy-action.yml");
    for (uses, compromised) in [
        ("aquasecurity/trivy-action@v0.35.0", false),
        ("aquasecurity/trivy-action@0.34.2", true),
        (
            "aquasecurity/trivy-action@57a97c7e7821a5776cebc9bb87c984fa69cba8f1",
            false,
        ),
    ] {
        let dir = repo(&[(
            ".github/workflows/scan.yml",
            &text.replace("aquasecurity/trivy-action@v0.28.0", uses),
        )]);
        let all = findings(dir.path());
        assert_eq!(
            !rule_lines(&all, "security.trivy-compromised-version").is_empty(),
            compromised,
            "{uses}: {all:?}"
        );
    }
}

#[test]
fn installs_by_script_pip_or_unchecked_download_are_unpinned() {
    let dir = with_workflows(&["installers.yml"], &[]);
    let all = findings(dir.path());
    assert_channel(&all);
    let file = ".github/workflows/installers.yml";
    assert_eq!(
        rule_lines(&all, "security.scanner-unpinned"),
        [
            format!(
                "WARNING: security.scanner-unpinned: Scanner trivy in {file} is not pinned by SHA or checksum"
            ),
            format!(
                "WARNING: security.scanner-unpinned: Scanner semgrep in {file} is not pinned by SHA or checksum"
            ),
            format!(
                "WARNING: security.scanner-unpinned: Scanner gitleaks in {file} is not pinned by SHA or checksum"
            ),
        ]
    );
    assert_eq!(
        rule_lines(&all, "security.trivy-compromised-version"),
        [
            "WARNING: security.trivy-compromised-version: Trivy 0.69.5 is within the March 2026 compromise window"
        ]
    );
}

#[test]
fn a_gate_with_continue_on_error_or_a_vars_condition_is_an_unregistered_bypass() {
    let dir = with_workflows(&["continue-on-error.yml"], &[("Cargo.lock", "")]);
    let all = findings(dir.path());
    assert_channel(&all);
    assert_eq!(
        rule_lines(&all, "security.bypass-unregistered"),
        [
            "WARNING: security.bypass-unregistered: Bypass .github/workflows/continue-on-error.yml#gitleaks is not registered in security-exceptions.json",
            "WARNING: security.bypass-unregistered: Bypass SKIP_OSV is not registered in security-exceptions.json",
        ]
    );
    // gitleaks-action is a secrets gate and osv-scanner-action a lockfile scan,
    // both pinned by SHA; the action's history is not the managed shape.
    assert!(rule_lines(&all, "security.secrets-gate").is_empty());
    assert!(rule_lines(&all, "security.deps-gate").is_empty());
    assert!(rule_lines(&all, "security.scanner-unpinned").is_empty());
    assert_eq!(
        rule_lines(&all, "security.secrets-full-history"),
        [
            "WARNING: security.secrets-full-history: unverified: .github/workflows/continue-on-error.yml: the secrets job gitleaks is not the managed shape; its history is read from the run log (remote, unavailable)"
        ]
    );
}

#[test]
fn a_registered_continue_on_error_and_variable_are_not_findings() {
    let inventory = json!({"schema": 1, "exceptions": [
        {"id": "a", "kind": "continue-on-error", "target": ".github/workflows/continue-on-error.yml#gitleaks",
         "reason": "r", "issue": "#1", "owner": "o", "created": "2026-11-01", "expires": "2026-11-20"},
        {"id": "b", "kind": "repo-variable", "target": "SKIP_OSV",
         "reason": "r", "issue": "#1", "owner": "o", "created": "2026-11-01", "expires": "2026-11-20"},
    ]})
    .to_string();
    let dir = with_workflows(
        &["continue-on-error.yml"],
        &[(".agent-setup/security-exceptions.json", &inventory)],
    );
    let all = findings(dir.path());
    assert!(
        rule_lines(&all, "security.bypass-unregistered").is_empty(),
        "{all:?}"
    );
    assert!(rule_lines(&all, "security.bypass-inventory-valid").is_empty());
    assert!(rule_lines(&all, "security.bypass-expired").is_empty());
}

#[test]
fn the_managed_gate_passes_every_workflow_rule() {
    let dir = with_workflows(&["managed-gate.yml"], &[("Cargo.lock", "")]);
    assert_eq!(findings(dir.path()), Vec::<String>::new());
}

// --- T10 (#798): sast-gate and container-gate ------------------------------------

/// The full golden: the managed `sast` (Semgrep by image digest) and
/// `container-scan` (Trivy by checksum) jobs.
fn full_golden() -> String {
    fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../templates/security/goldens/full.yml"
    ))
    .unwrap()
}

/// SPEC-security.md Open question 16 (coordinator, 2026-10-29): the workflow
/// reader's cap is 256 KiB, so the full golden (security-gate, deps-scan,
/// sast, container-scan with their shells embedded, 81 KiB) is read and every
/// static rule verifies it: no finding at all, `unverified` included.
#[test]
fn the_full_golden_is_read_and_verified_by_every_rule() {
    let text = full_golden();
    assert!(
        text.len() > 64 * 1024,
        "the case the old cap refused: {} bytes",
        text.len()
    );
    workflows::parse(&text).expect("the full golden parses under the cap");
    let dir = repo(&[
        (".github/workflows/ci.yml", &text),
        ("Dockerfile", "FROM scratch\n"),
        ("Cargo.lock", ""),
    ]);
    assert_eq!(findings(dir.path()), Vec::<String>::new());
}

/// Every workflow golden the security module renders fits the reader with at
/// least twice its size to spare, so a slice that grows a job does not slip
/// back over the cap unnoticed.
#[test]
fn every_security_golden_fits_the_workflow_reader_with_margin() {
    let dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../templates/security/goldens"
    );
    let mut checked = Vec::new();
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "yml") {
            continue;
        }
        let text = fs::read_to_string(&path).unwrap();
        assert!(
            2 * text.len() <= workflows::MAX_BYTES,
            "{}: {} bytes, more than half the {}-byte cap",
            path.display(),
            text.len(),
            workflows::MAX_BYTES
        );
        workflows::parse(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        checked.push(path.file_name().unwrap().to_string_lossy().into_owned());
    }
    assert!(checked.len() >= 5, "{checked:?}");
    // #979: the largest goldens, with `mutation-diff`, are among them.
    for name in ["mutation-rust.yml", "mutation-python.yml"] {
        assert!(
            checked.iter().any(|c| c == name),
            "{name} not checked: {checked:?}"
        );
    }
}

#[test]
fn a_dockerfile_without_a_container_scan_is_container_gate() {
    let text = "WARNING: security.container-gate: Dockerfile present and no container scan in CI";
    for (dockerfile, expected) in [
        ("Dockerfile", true),
        ("apps/api/Dockerfile", true),
        ("services/a/b/Dockerfile", true),
        ("node_modules/x/Dockerfile", false),
        ("a/b/c/d/Dockerfile", false),
        ("Dockerfile.md", false),
    ] {
        let dir = with_workflows(&["managed-gate.yml"], &[(dockerfile, "FROM scratch\n")]);
        let all = findings(dir.path());
        assert_channel(&all);
        assert_eq!(
            rule_lines(&all, "security.container-gate"),
            if expected { vec![text] } else { vec![] },
            "{dockerfile}: {all:?}"
        );
    }
    // Without a Dockerfile the rule is not evaluated.
    let dir = with_workflows(&["managed-gate.yml"], &[]);
    assert!(rule_lines(&findings(dir.path()), "security.container-gate").is_empty());
}

/// The inventory of the #1171 tests: two template Dockerfiles registered, and
/// one entry naming a path the rule does not find.
fn container_inventory() -> String {
    json!({"schema": 1, "exceptions": [
        {"id": "pack-templates", "kind": "allowlist", "target": "container-gate#templates/go/Dockerfile",
         "reason": "a stack-pack template, never built here", "issue": "#1171", "owner": "o",
         "created": "2026-11-01", "expires": "2027-10-01"},
        {"id": "example", "kind": "allowlist", "target": "container-gate#examples/svc/Containerfile",
         "reason": "an example service", "issue": "#1171", "owner": "o",
         "created": "2026-11-01", "expires": "2027-10-01"},
        {"id": "gone", "kind": "allowlist", "target": "container-gate#templates/gone/Dockerfile",
         "reason": "removed", "issue": "#1171", "owner": "o",
         "created": "2026-11-01", "expires": "2027-10-01"},
    ]})
    .to_string()
}

/// #1171: a Dockerfile a declared `container-gate#<path>` entry registers is
/// not judged; the rule still fires for any other one, and each exclusion is a
/// printed line, never a silent skip.
#[test]
fn registered_dockerfiles_are_declared_exclusions_of_container_gate() {
    let inventory = container_inventory();
    let files = [
        ("templates/go/Dockerfile", "FROM scratch\n"),
        ("examples/svc/Containerfile", "FROM scratch\n"),
        (".agent-setup/security-exceptions.json", inventory.as_str()),
    ];
    let dir = with_workflows(&["managed-gate.yml"], &files);
    let all = findings(dir.path());
    assert_channel(&all);
    assert_eq!(
        rule_lines(&all, "security.container-gate"),
        Vec::<&str>::new(),
        "{all:?}"
    );
    assert_eq!(
        rule_lines(&all, "security.bypass-inventory-valid"),
        [
            "WARNING: security.bypass-inventory-valid: Exception gone registers container-gate#templates/gone/Dockerfile, which the rule does not find"
        ]
    );
    assert_eq!(
        audit::excluded(dir.path()),
        [
            "EXCLUDED [security.container-gate] examples/svc/Containerfile — example (#1171, until 2027-10-01): an example service",
            "EXCLUDED [security.container-gate] templates/go/Dockerfile — pack-templates (#1171, until 2027-10-01): a stack-pack template, never built here",
        ]
    );
    // An unregistered Dockerfile beside them is still judged.
    let mut more = files.to_vec();
    more.push(("apps/api/Dockerfile", "FROM scratch\n"));
    let dir = with_workflows(&["managed-gate.yml"], &more);
    assert_eq!(
        rule_lines(&findings(dir.path()), "security.container-gate"),
        ["WARNING: security.container-gate: Dockerfile present and no container scan in CI"]
    );
    // A registration of a file that is not a Dockerfile excludes nothing and is stale.
    let wrong = json!({"schema": 1, "exceptions": [
        {"id": "readme", "kind": "allowlist", "target": "container-gate#README.md",
         "reason": "r", "issue": "#1171", "owner": "o", "created": "2026-11-01", "expires": "2027-10-01"},
    ]})
    .to_string();
    let dir = with_workflows(
        &["managed-gate.yml"],
        &[
            ("README.md", "x\n"),
            (".agent-setup/security-exceptions.json", wrong.as_str()),
        ],
    );
    assert_eq!(
        rule_lines(&findings(dir.path()), "security.bypass-inventory-valid"),
        [
            "WARNING: security.bypass-inventory-valid: Exception readme registers container-gate#README.md, which the rule does not find"
        ]
    );
    assert!(audit::excluded(dir.path()).is_empty());
}

/// #1171: `doctor` prints each exclusion after the manual steps, never as a
/// finding, and `--json` carries them in `excluded`.
#[test]
fn doctor_prints_declared_exclusions_and_json_carries_them() {
    let dir = cli_repo();
    let before = doctor(&dir, &["--json"]);
    let document: Value = serde_json::from_slice(&before.stdout).unwrap();
    assert!(document.get("excluded").is_none(), "{document}");
    fs::create_dir_all(dir.path().join("templates/go")).unwrap();
    fs::write(dir.path().join("templates/go/Dockerfile"), "FROM scratch\n").unwrap();
    let path = dir.path().join(".agent-setup/security-exceptions.json");
    let mut inventory: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    inventory["exceptions"].as_array_mut().unwrap().push(json!(
        {"id": "pack-templates", "kind": "allowlist", "target": "container-gate#templates/go/Dockerfile",
         "reason": "a template", "issue": "#1171", "owner": "o", "created": "2026-11-01", "expires": "2027-10-01"}
    ));
    fs::write(&path, inventory.to_string()).unwrap();
    let line = "EXCLUDED [security.container-gate] templates/go/Dockerfile — pack-templates (#1171, until 2027-10-01): a template";
    let out = doctor(&dir, &[]);
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.lines().any(|l| l == line), "{text}");
    assert!(!text.contains("WARNING: security.container-gate"), "{text}");
    assert_eq!(out.status.code(), before.status.code());
    let document: Value = serde_json::from_slice(&doctor(&dir, &["--json"]).stdout).unwrap();
    assert_eq!(document["excluded"], json!([line]));
    assert!(
        !document["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f.as_str().is_some_and(|f| f.starts_with("EXCLUDED"))),
        "{document}"
    );
}

#[test]
fn trivy_or_grype_jobs_satisfy_container_gate_however_installed() {
    let scan = |step: &str| {
        format!(
            "name: Scan\non: [push]\npermissions:\n  contents: read\njobs:\n  scan:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 10\n    steps:\n{step}"
        )
    };
    for (step, satisfied) in [
        (
            "      - run: trivy image --exit-code 1 ghcr.io/o/r@sha256:0\n",
            true,
        ),
        (
            "      - run: trivy fs --scanners vuln,misconfig,secret .\n",
            true,
        ),
        ("      - run: trivy config .\n", true),
        ("      - run: grype dir:.\n", true),
        (
            "      - uses: aquasecurity/trivy-action@57a97c7e7821a5776cebc9bb87c984fa69cba8f1\n        with:\n          scan-type: image\n",
            true,
        ),
        (
            "      - uses: anchore/scan-action@57a97c7e7821a5776cebc9bb87c984fa69cba8f1\n",
            true,
        ),
        ("      - run: echo no scan here\n", false),
    ] {
        let dir = repo(&[
            (".github/workflows/scan.yml", &scan(step)),
            ("Dockerfile", "FROM scratch\n"),
        ]);
        let all = findings(dir.path());
        assert_eq!(
            rule_lines(&all, "security.container-gate").is_empty(),
            satisfied,
            "{step}: {all:?}"
        );
    }
}

#[test]
fn semgrep_or_codeql_jobs_satisfy_sast_gate_however_installed() {
    let scan = |step: &str| {
        format!(
            "name: Scan\non: [push]\npermissions:\n  contents: read\njobs:\n  scan:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 10\n    steps:\n{step}"
        )
    };
    for (step, satisfied) in [
        ("      - run: semgrep ci\n", true),
        (
            "      - run: docker run --rm semgrep/semgrep semgrep scan --config auto\n",
            true,
        ),
        (
            "      - uses: github/codeql-action/init@9b3254085494b55a0f7c4c2b3d2d52cc712ce370\n      - uses: github/codeql-action/analyze@9b3254085494b55a0f7c4c2b3d2d52cc712ce370\n",
            true,
        ),
        (
            "      - uses: semgrep/semgrep-action@57a97c7e7821a5776cebc9bb87c984fa69cba8f1\n",
            true,
        ),
        ("      - run: cargo clippy -- -D warnings\n", false),
        ("      - run: echo no scanner here\n", false),
    ] {
        let dir = repo(&[(".github/workflows/scan.yml", &scan(step))]);
        let all = findings(dir.path());
        assert_eq!(
            rule_lines(&all, "security.sast-gate").is_empty(),
            satisfied,
            "{step}: {all:?}"
        );
    }
}

// --- T12 (#800): security.pii-declared ---------------------------------------------

const PII: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/security/pii");

/// The managed gate plus a PII fixture's `.agent-setup/`, with the runbook when `runbook`.
fn pii_repo(case: &str, runbook: bool) -> TempDir {
    let files: Vec<(&str, &str)> = if runbook {
        vec![("docs/runbooks/dsar.md", "# Runbook\n")]
    } else {
        Vec::new()
    };
    let dir = with_workflows(&["managed-gate.yml"], &files);
    copy_tree(&Path::new(PII).join(case), dir.path());
    dir
}

fn pii_lines(case: &str, runbook: bool) -> Vec<String> {
    let dir = pii_repo(case, runbook);
    let all = findings(dir.path());
    assert_channel(&all);
    rule_lines(&all, "security.pii-declared")
        .into_iter()
        .map(str::to_owned)
        .collect()
}

#[test]
fn pii_declared_is_evaluated_only_under_personal_data_or_payments() {
    assert!(pii_lines("valid", true).is_empty());
    assert!(pii_lines("absent-not-required", false).is_empty());
    assert!(pii_lines("absent-undeclared", false).is_empty());
    assert!(
        pii_lines("valid-not-required", false).is_empty(),
        "customers: not evaluated"
    );
}

#[test]
fn pii_declared_names_the_missing_declaration_the_empty_one_and_the_check_findings() {
    let none = "WARNING: security.pii-declared: criticality is personal-data-or-payments and no pii.yaml declares the fields";
    let runbook = "WARNING: security.pii-declared: criticality is personal-data-or-payments and docs/runbooks/dsar.md is missing";
    assert_eq!(pii_lines("absent-required", false), [none, runbook]);
    assert_eq!(pii_lines("absent-required", true), [none]);
    assert_eq!(
        pii_lines("empty-under-criticality", true),
        [
            "WARNING: security.pii-declared: .agent-setup/pii.yaml controller is not declared",
            "WARNING: security.pii-declared: .agent-setup/pii.yaml dsar_contact is not declared",
            "WARNING: security.pii-declared: .agent-setup/pii.yaml declares no fields; criticality personal-data-or-payments needs at least one",
        ]
    );
    assert_eq!(
        pii_lines("credentials-without-logs", true),
        [
            "WARNING: security.pii-declared: Field users.password_hash is credentials and must exclude logs and traces"
        ]
    );
    assert_eq!(
        pii_lines("missing-key", true),
        [
            "WARNING: security.pii-declared: Field users.email is missing lawful_basis",
            "WARNING: security.pii-declared: Field fields[1] is missing path",
        ]
    );
    assert_eq!(
        pii_lines("outside-the-shape", true),
        [
            "WARNING: security.pii-declared: unverified: .agent-setup/pii.yaml: line 9 is outside the seeded shape"
        ]
    );
}

/// #1236: the runbook seeded before `pii.yaml` declared fields (from the seed
/// declaration, or from an empty one) is reported until it is re-seeded; one
/// rendered from the declaration, or edited, is not.
#[test]
fn pii_declared_reports_a_runbook_seeded_before_the_fields_were_declared() {
    let stale = "WARNING: security.pii-declared: docs/runbooks/dsar.md is still the runbook seeded before .agent-setup/pii.yaml declared its fields; delete it and run install to re-seed it from the declaration";
    let lines_with = |runbook: &str| {
        let dir = pii_repo("valid", false);
        fs::create_dir_all(dir.path().join("docs/runbooks")).unwrap();
        fs::write(dir.path().join("docs/runbooks/dsar.md"), runbook).unwrap();
        let all = findings(dir.path());
        assert_channel(&all);
        (
            rule_lines(&all, "security.pii-declared")
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>(),
            dir,
        )
    };
    let empty = TempDir::new().unwrap();
    let from_seed = security::dsar_runbook(empty.path());
    assert_eq!(lines_with(&from_seed).0, [stale]);
    let from_nothing = pii::runbook(&pii::Declaration::default());
    assert_eq!(lines_with(&from_nothing).0, [stale]);
    let (_, dir) = lines_with("# Runbook\n");
    let declared = security::dsar_runbook(dir.path());
    assert!(
        lines_with(&declared).0.is_empty(),
        "re-seeded from the declaration"
    );
    assert!(
        lines_with(&format!("{from_seed}\nEdited.\n")).0.is_empty(),
        "edited"
    );
}

#[test]
fn one_expired_entry_is_bypass_expired_only() {
    let dir = with_workflows(&["managed-gate.yml"], &[]);
    copy_tree(&Path::new(AUDIT).join("one-expired"), dir.path());
    assert_eq!(
        findings(dir.path()),
        ["WARNING: security.bypass-expired: Exception osv-outage-2026-10 expired on 2026-10-20"]
    );
}

// --- the exception files: the T2 check, split by rule ---------------------------

fn exceptions(case: &str) -> Vec<String> {
    let dir = with_workflows(&["managed-gate.yml"], &[]);
    copy_tree(&Path::new(EXCEPTIONS).join(case), dir.path());
    findings(dir.path())
}

#[test]
fn incomplete_or_unparseable_inventories_are_bypass_inventory_valid() {
    let all = exceptions("inventory-does-not-parse");
    assert_eq!(
        all,
        [
            "WARNING: security.bypass-inventory-valid: .agent-setup/security-exceptions.json does not parse"
        ]
    );
    let all = exceptions("missing-each-field");
    assert!(!all.is_empty());
    assert_eq!(
        rule_lines(&all, "security.bypass-inventory-valid").len(),
        all.len(),
        "{all:?}"
    );
    assert!(
        all.iter().any(|l| l.ends_with(" is missing expires")),
        "{all:?}"
    );
}

#[test]
fn an_entry_over_its_bound_is_bypass_expired() {
    let all = exceptions("over-bound");
    assert_eq!(
        all,
        [
            "WARNING: security.bypass-expired: Exception job-31 lasts 31 days; job-bypass allows at most 30",
            "WARNING: security.bypass-expired: Exception allow-366 lasts 366 days; allowlist allows at most 365",
            "WARNING: security.bypass-expired: Exception coverage-40 lasts 40 days; coverage-reset allows at most 30",
            "WARNING: security.bypass-expired: Exception continue-31 lasts 31 days; continue-on-error allows at most 30",
        ]
    );
}

#[test]
fn unregistered_allowlists_and_a_plain_trivyignore_are_bypass_unregistered() {
    let all = exceptions("allowlist-unregistered");
    assert!(!all.is_empty());
    assert_eq!(
        rule_lines(&all, "security.bypass-unregistered").len(),
        all.len(),
        "{all:?}"
    );
    let all = exceptions("trivy-plain");
    assert!(all.contains(
        &"WARNING: security.bypass-unregistered: .trivyignore cannot carry an expiry; use .trivyignore.yaml"
            .to_owned()
    ), "{all:?}");
}

#[test]
fn a_native_file_outside_the_shape_is_unverified_for_the_rules_it_feeds() {
    let all = exceptions("trivy-unverified");
    assert_eq!(all.len(), 2, "{all:?}");
    assert!(all[0].starts_with(
        "WARNING: security.bypass-inventory-valid: unverified: .trivyignore.yaml: line "
    ));
    assert!(
        all[1]
            .starts_with("WARNING: security.bypass-expired: unverified: .trivyignore.yaml: line ")
    );
    let all = exceptions("gitleaks-toml-unverified");
    assert_eq!(all.len(), 1, "{all:?}");
    assert!(
        all[0].starts_with(
            "WARNING: security.bypass-unregistered: unverified: .gitleaks.toml: line "
        )
    );
}

#[test]
fn bypass_max_days_from_the_answers_tightens_the_bound() {
    let inventory = json!({"schema": 1, "exceptions": [
        {"id": "ten", "kind": "job-bypass", "target": "deps-scan",
         "reason": "r", "issue": "#1", "owner": "o", "created": "2026-11-01", "expires": "2026-11-11"},
    ]})
    .to_string();
    let answers =
        json!({"module": "security", "version": "1.0.0", "answers": {"bypass_max_days": 7}})
            .to_string();
    let dir = with_workflows(
        &["managed-gate.yml"],
        &[
            (".agent-setup/security-exceptions.json", &inventory),
            (".agent-setup/modules/security.json", &answers),
        ],
    );
    assert!(findings(dir.path()).is_empty());
    assert_eq!(
        audit::diagnose(dir.path(), today()),
        [
            "WARNING: security.bypass-expired: Exception ten lasts 10 days; job-bypass allows at most 7"
        ]
    );
}

// --- unreadable workflows -------------------------------------------------------

#[test]
fn unparseable_yaml_is_unverified_never_a_panic() {
    let dir = with_workflows(&["broken.yml"], &[("Cargo.lock", "")]);
    let all = findings(dir.path());
    assert_channel(&all);
    let rules: Vec<&str> = all.iter().map(|l| l.split(": ").nth(1).unwrap()).collect();
    assert_eq!(
        rules,
        [
            "security.secrets-gate",
            "security.secrets-full-history",
            "security.deps-gate",
            "security.scanner-unpinned",
            "security.trivy-compromised-version",
            "security.bypass-unregistered",
            "security.sast-gate",
        ],
        "{all:?}"
    );
    assert!(
        all.iter()
            .all(|l| l.contains(": unverified: .github/workflows/broken.yml: ")),
        "{all:?}"
    );
    // A readable workflow that satisfies a repository rule settles it.
    let dir = with_workflows(&["broken.yml", "managed-gate.yml"], &[("Cargo.lock", "")]);
    let all = findings(dir.path());
    assert!(
        rule_lines(&all, "security.secrets-gate").is_empty(),
        "{all:?}"
    );
    assert!(rule_lines(&all, "security.deps-gate").is_empty(), "{all:?}");
}

// --- doctor -------------------------------------------------------------------

/// A git checkout of the expired fixture, driven through the binary.
fn cli_repo() -> TempDir {
    let dir = with_workflows(&["managed-gate.yml"], &[]);
    copy_tree(&Path::new(AUDIT).join("one-expired"), dir.path());
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .arg(dir.path())
            .status()
            .unwrap()
            .success()
    );
    // A personal origin, so the scope check admits the checkout.
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(dir.path())
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
    dir
}

fn doctor(dir: &TempDir, extra: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_brakes"))
        .arg("doctor")
        .arg(dir.path())
        .args(["--now", TODAY])
        .args(extra)
        .output()
        .unwrap()
}

#[test]
fn doctor_prints_the_rules_as_warnings_and_they_never_decide_readiness() {
    let dir = cli_repo();
    let out = doctor(&dir, &[]);
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        text.lines().any(|l| l
            == "WARNING: security.bypass-expired: Exception osv-outage-2026-10 expired on 2026-10-20"),
        "{text}"
    );
    assert!(!text.contains("NOT READY: WARNING"), "{text}");
    assert!(!text.contains("NOT READY: security."), "{text}");
    // The same checkout without the expired entry exits with the same code.
    let code = out.status.code();
    fs::remove_file(dir.path().join(".agent-setup/security-exceptions.json")).unwrap();
    assert_eq!(doctor(&dir, &[]).status.code(), code);
}

#[test]
fn doctor_json_carries_the_rules_in_findings_and_matches_the_golden_file() {
    let dir = cli_repo();
    let out = doctor(&dir, &["--json"]);
    let document: Value = serde_json::from_slice(&out.stdout).unwrap();
    let security: Vec<Value> = document["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f.as_str().unwrap().contains("security."))
        .cloned()
        .collect();
    let level = &document["level"];
    // The reached level is at most Bronze: `security.bypass-expired` is Silver
    // since the owner's allocation (#873), and offline the host rules wait.
    assert!(
        matches!(level["reached"].as_str(), None | Some("Basic" | "Bronze")),
        "{level}"
    );
    let actual = serde_json::to_string_pretty(&json!({
        "findings": security,
        "level": {"reached": level["reached"]},
    }))
    .unwrap()
        + "\n";
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/golden/security/doctor.json"
    );
    if std::env::var_os("UPDATE_GOLDENS").is_some() {
        fs::write(path, &actual).unwrap();
    }
    let expected = fs::read_to_string(path).unwrap();
    assert_eq!(actual, expected, "{path} drifted; actual:\n{actual}");
}

#[test]
fn a_script_piped_to_a_shell_is_unpinned_even_beside_a_checksum() {
    let text = "on: [push]\njobs:\n  scan:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: |\n          sha256sum --check SHA256SUMS\n          curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin\n";
    let dir = repo(&[(".github/workflows/scan.yml", text)]);
    assert_eq!(
        rule_lines(&findings(dir.path()), "security.scanner-unpinned"),
        [
            "WARNING: security.scanner-unpinned: Scanner trivy in .github/workflows/scan.yml is not pinned by SHA or checksum"
        ]
    );
}

// --- binary artifacts (#973; SPEC-security.md, "`security.binary-artifacts`") ---

const BINARY: &str = "security.binary-artifacts";
const INVENTORY_VALID: &str = "security.bypass-inventory-valid";

/// A validated gradle wrapper: the static half of Scorecard's exclusion.
const WRAPPER_VALIDATION: &str = "on: [push]\njobs:\n  wrapper:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2\n      - uses: gradle/actions/wrapper-validation@94baf225fe0a508e581a564467443d0e2379123b # v4.3.0\n";

/// The first bytes of each format the spec lists, padded past the header.
fn magic(head: &[u8]) -> Vec<u8> {
    let mut bytes = head.to_vec();
    bytes.resize(64, 0);
    bytes
}

fn elf() -> Vec<u8> {
    magic(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0])
}

/// A zip local header, as a `.jar` or `.whl` starts.
fn zip() -> Vec<u8> {
    magic(&[0x50, 0x4b, 0x03, 0x04, 0x14, 0, 0, 0])
}

fn binary_lines(root: &Path) -> Vec<String> {
    let all = findings(root);
    assert_channel(&all);
    rule_lines(&all, BINARY)
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn finding(path: &str, kind: &str) -> String {
    format!(
        "WARNING: {BINARY}: Binary artifact {path} ({kind}) is tracked; build it in CI or register it in security-exceptions.json"
    )
}

#[test]
fn tracked_executables_and_packages_are_findings_naming_path_and_type_sorted_by_path() {
    let class = magic(&[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0x34]);
    let pyc = magic(&[0x6f, 0x0d, 0x0d, 0x0a, 0, 0, 0, 0]);
    let wasm = magic(&[0x00, b'a', b's', b'm', 1, 0, 0, 0]);
    let dir = checkout(&[
        ("lib/__pycache__/x.cpython-313.pyc", &pyc),
        ("dist/tool", &elf()),
        ("dist/x.whl", &zip()),
        ("build/App.class", &class),
        ("web/app.wasm", &wasm),
        ("README.md", b"# x\n"),
    ]);
    assert_eq!(
        binary_lines(dir.path()),
        [
            finding("build/App.class", "Java class or universal binary"),
            finding("dist/tool", "ELF"),
            finding("dist/x.whl", ".whl"),
            finding("lib/__pycache__/x.cpython-313.pyc", ".pyc"),
            finding("web/app.wasm", "WebAssembly"),
        ]
    );
}

#[test]
fn each_magic_of_the_spec_is_detected_without_an_extension() {
    for (head, kind) in [
        (vec![0xfe, 0xed, 0xfa, 0xce, 0, 0, 0, 0x12], "Mach-O"),
        (vec![0xfe, 0xed, 0xfa, 0xcf, 0, 0, 0, 0x12], "Mach-O"),
        (vec![0xce, 0xfa, 0xed, 0xfe, 0x07, 0, 0, 0], "Mach-O"),
        (vec![0xcf, 0xfa, 0xed, 0xfe, 0x07, 0, 0, 1], "Mach-O"),
        (vec![b'M', b'Z', 0x90, 0, 3, 0, 0, 0], "PE"),
        (b"!<arch>\n\x1f\x8b".to_vec(), "ar archive"),
        (vec![0xed, 0xab, 0xee, 0xdb, 3, 0, 0, 0], "RPM"),
        (b"dex\n035\0".to_vec(), "DEX"),
    ] {
        let bytes = magic(&head);
        let dir = checkout(&[("bin/x", &bytes)]);
        assert_eq!(binary_lines(dir.path()), [finding("bin/x", kind)], "{kind}");
    }
}

#[test]
fn images_archives_empty_and_text_files_are_not_findings_whatever_their_name() {
    let png = magic(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]);
    let dir = checkout(&[
        ("docs/logo.png", &png),
        ("fixtures/bundle.zip", &zip()),
        ("fixtures/empty.so", b""),
        ("fixtures/x.so", b"not a shared object\n"),
        ("fixtures/notes.exe.txt", &elf()[..0]),
    ]);
    assert_eq!(binary_lines(dir.path()), Vec::<String>::new());
}

#[test]
fn only_tracked_regular_files_are_read_never_a_symlink_or_an_untracked_file() {
    let dir = checkout(&[("README.md", b"# x\n")]);
    let outside = TempDir::new().unwrap();
    fs::write(outside.path().join("tool"), elf()).unwrap();
    fs::write(dir.path().join("untracked"), elf()).unwrap();
    std::os::unix::fs::symlink(outside.path().join("tool"), dir.path().join("link.so")).unwrap();
    git(dir.path(), &["add", "link.so"]);
    assert_eq!(binary_lines(dir.path()), Vec::<String>::new());
}

#[test]
fn a_gradle_wrapper_passes_only_when_a_workflow_validates_it() {
    let validated = checkout(&[
        ("gradle/wrapper/gradle-wrapper.jar", &zip()),
        (
            ".github/workflows/wrapper.yml",
            WRAPPER_VALIDATION.as_bytes(),
        ),
    ]);
    assert_eq!(binary_lines(validated.path()), Vec::<String>::new());
    let old_action = WRAPPER_VALIDATION.replace(
        "gradle/actions/wrapper-validation@",
        "gradle/wrapper-validation-action@",
    );
    let validated = checkout(&[
        ("gradle/wrapper/gradle-wrapper.jar", &zip()),
        (".github/workflows/wrapper.yml", old_action.as_bytes()),
    ]);
    assert_eq!(binary_lines(validated.path()), Vec::<String>::new());
    let unvalidated = checkout(&[
        ("gradle/wrapper/gradle-wrapper.jar", &zip()),
        ("other.jar", &zip()),
        (
            ".github/workflows/wrapper.yml",
            b"on: [push]\njobs:\n  x:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo\n",
        ),
    ]);
    assert_eq!(
        binary_lines(unvalidated.path()),
        [
            finding("gradle/wrapper/gradle-wrapper.jar", ".jar"),
            finding("other.jar", ".jar"),
        ]
    );
}

#[test]
fn a_registered_binary_passes_and_an_entry_for_an_untracked_path_is_stale() {
    let inventory = json!({"schema": 1, "exceptions": [
        {"id": "tool", "kind": "allowlist", "target": "binary-artifacts#dist/tool",
         "reason": "test fixture", "issue": "#1", "owner": "o", "created": "2026-11-01", "expires": "2027-10-01"},
        {"id": "gone", "kind": "allowlist", "target": "binary-artifacts#dist/gone",
         "reason": "removed", "issue": "#1", "owner": "o", "created": "2026-11-01", "expires": "2027-10-01"},
    ]})
    .to_string();
    let dir = checkout(&[
        ("dist/tool", &elf()),
        (
            ".agent-setup/security-exceptions.json",
            inventory.as_bytes(),
        ),
    ]);
    let all = findings(dir.path());
    assert_channel(&all);
    assert_eq!(rule_lines(&all, BINARY), Vec::<&str>::new(), "{all:?}");
    assert_eq!(
        rule_lines(&all, INVENTORY_VALID),
        [format!(
            "WARNING: {INVENTORY_VALID}: Exception gone registers binary-artifacts#dist/gone, which is not a tracked file"
        )]
    );
    assert!(rule_lines(&all, "security.bypass-unregistered").is_empty());
    assert!(rule_lines(&all, "security.bypass-expired").is_empty());
}

#[test]
fn an_expired_registration_is_bypass_expired_and_still_registers_the_binary() {
    let inventory = json!({"schema": 1, "exceptions": [
        {"id": "tool", "kind": "allowlist", "target": "binary-artifacts#dist/tool",
         "reason": "r", "issue": "#1", "owner": "o", "created": "2025-11-01", "expires": "2026-10-01"},
    ]})
    .to_string();
    let dir = checkout(&[
        ("dist/tool", &elf()),
        (
            ".agent-setup/security-exceptions.json",
            inventory.as_bytes(),
        ),
    ]);
    let all = findings(dir.path());
    assert_eq!(
        all,
        [
            "WARNING: security.secrets-gate: No secrets gate: no gitleaks job and secret scanning off",
            "WARNING: security.bypass-expired: Exception tool expired on 2026-10-01",
            "WARNING: security.sast-gate: No static analysis job in CI",
        ]
    );
}

#[test]
fn a_directory_that_is_not_a_checkout_is_unverified() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("tool"), elf()).unwrap();
    let all = binary_lines(dir.path());
    assert_eq!(all.len(), 1, "{all:?}");
    assert!(
        all[0].starts_with(&format!("WARNING: {BINARY}: unverified: git ls-files: ")),
        "{all:?}"
    );
}

#[test]
fn doctor_warns_about_a_tracked_binary_and_keeps_its_exit_code() {
    let dir = cli_repo();
    let without = doctor(&dir, &[]);
    fs::create_dir_all(dir.path().join("dist")).unwrap();
    fs::write(dir.path().join("dist/tool"), elf()).unwrap();
    git(dir.path(), &["add", "dist/tool"]);
    let with = doctor(&dir, &[]);
    let text = String::from_utf8(with.stdout).unwrap();
    assert!(
        text.lines().any(|l| l == finding("dist/tool", "ELF")),
        "{text}"
    );
    assert!(!text.contains("NOT READY: security."), "{text}");
    assert_eq!(with.status.code(), without.status.code());
}

#[test]
fn an_index_entry_absent_from_the_working_tree_is_skipped() {
    let dir = checkout(&[("dist/tool", &elf()), ("README.md", b"# x\n")]);
    fs::remove_file(dir.path().join("dist/tool")).unwrap();
    assert_eq!(binary_lines(dir.path()), Vec::<String>::new());
}

// --- T13 (#801): the remote security.* rules over recorded API replies -------------------

mod remote {
    use super::{repo as checkout, workflow};
    use brakes::{
        auditor::{
            Audit, Cx, Dimensions, LocalFiles, Today,
            catalogue::security_remote::{
                SECURITY_ATTESTATION_VERIFIED, SECURITY_BYPASS_UNREGISTERED,
                SECURITY_PRIVATE_VULNERABILITY_REPORTING, SECURITY_SBOM_SCANNED,
                SECURITY_SCANNER_STALE, SECURITY_SECRET_SCANNING, SECURITY_SECRETS_FULL_HISTORY,
            },
            evaluate,
            rules::{Milestone, Outcome, Profile, Rule, Status},
        },
        host::{CallBudget, RepoId, github::GitHub},
        modules::security::{audit, exceptions::DEFAULT_BYPASS_MAX_DAYS},
        remote::{Api, HttpError},
    };
    use chrono::NaiveDate;
    use serde_json::{Value, json};
    use std::{cell::RefCell, collections::BTreeMap, path::Path};

    const BASE: &str = "repos/example-owner/example";
    const RUNS: &str = "repos/example-owner/example/actions/runs?branch=main&event=push&status=completed&per_page=100&page=1";

    /// Recorded replies by path: `Ok(body)` or `Err((status, message))`.
    #[derive(Default)]
    struct Replay {
        replies: BTreeMap<String, Result<Value, (u16, &'static str)>>,
        gets: RefCell<Vec<String>>,
    }
    impl Replay {
        fn ok(mut self, path: impl Into<String>, body: Value) -> Self {
            self.replies.insert(path.into(), Ok(body));
            self
        }
        fn http(mut self, path: impl Into<String>, status: u16, message: &'static str) -> Self {
            self.replies.insert(path.into(), Err((status, message)));
            self
        }
    }
    impl Api for Replay {
        fn get(&self, path: &str) -> brakes::Result<Value> {
            self.gets.borrow_mut().push(path.to_owned());
            match self.replies.get(path) {
                Some(Ok(body)) => Ok(body.clone()),
                Some(Err((status, message))) => Err(HttpError {
                    status: *status,
                    message: (*message).to_owned(),
                }
                .into()),
                None => Err(format!("unrecorded GET {path}").into()),
            }
        }
    }

    fn repository(visibility: &str, security: Value) -> Value {
        json!({"id": 1, "default_branch": "main", "visibility": visibility,
               "private": visibility != "public", "archived": false, "fork": false,
               "security_and_analysis": security})
    }
    fn enabled(scanning: &str, push: &str) -> Value {
        json!({"secret_scanning": {"status": scanning},
               "secret_scanning_push_protection": {"status": push}})
    }

    /// Evaluates `rule` over a checkout of `root` with today's `doctor` findings
    /// of the security module, as `doctor --remote` passes them.
    fn audit(root: &Path, replay: &Replay, rule: Rule) -> (Outcome, Vec<String>) {
        let today_date = NaiveDate::from_ymd_opt(2026, 11, 10).unwrap();
        let findings = audit::findings(root, today_date, DEFAULT_BYPASS_MAX_DAYS);
        let today = Today {
            findings: &findings,
            steps: &[],
            remote: true,
        };
        let host = GitHub::new(replay, CallBudget::new(60));
        let files = LocalFiles::new(root);
        let repo = RepoId::parse("example-owner/example").unwrap();
        let cx = Cx {
            host: &host,
            files: &files,
            repo: &repo,
            default_branch: "main",
            now: today_date,
            budget: host.budget(),
            profile: Profile::P1,
            today: Some(&today),
        };
        let dims = Dimensions {
            profile: Profile::P1,
            cadence: None,
            services: None,
            criticality: None,
        };
        let rules: &'static [Rule] = Box::leak(Box::new([rule]));
        let Audit {
            rules: evaluated, ..
        } = evaluate(&cx, &dims, rules);
        let outcome = evaluated.into_iter().next().unwrap().outcome;
        (outcome, replay.gets.borrow().clone())
    }

    // --- security.secret-scanning ---------------------------------------------------

    #[test]
    fn secret_scanning_passes_enabled_fails_public_off_and_records_the_plan_risk() {
        let dir = checkout(&[]);
        let on = Replay::default().ok(BASE, repository("public", enabled("enabled", "enabled")));
        let (o, gets) = audit(dir.path(), &on, SECURITY_SECRET_SCANNING);
        assert_eq!(o.status, Status::Passed);
        assert_eq!(
            o.evidence,
            ["secret scanning enabled, push protection enabled"]
        );
        assert_eq!(gets, [BASE]);

        let off = Replay::default().ok(BASE, repository("public", enabled("enabled", "disabled")));
        let (o, _) = audit(dir.path(), &off, SECURITY_SECRET_SCANNING);
        assert_eq!(o.status, Status::Failed);
        assert_eq!(
            o.evidence,
            [
                "Secret scanning available on this plan and not enabled",
                "secret scanning enabled, push protection disabled"
            ]
        );

        // A Free private repository: security_and_analysis carries no secret scanning.
        let plan = Replay::default().ok(
            BASE,
            repository(
                "private",
                json!({"dependabot_security_updates": {"status": "enabled"}}),
            ),
        );
        let (o, _) = audit(dir.path(), &plan, SECURITY_SECRET_SCANNING);
        assert_eq!(o.status, Status::Passed);
        assert_eq!(
            o.evidence,
            [
                "secret scanning not reported, push protection not reported",
                "risk secret-scanning-unavailable-on-plan: a private repository needs Secret Protection (Team or Enterprise), which the installer never assumes; security-gate is the gate"
            ]
        );

        let missing = Replay::default().http(BASE, 404, "Not Found");
        let (o, _) = audit(dir.path(), &missing, SECURITY_SECRET_SCANNING);
        assert_eq!(o.status, Status::Unavailable);
        assert_eq!(
            o.reason.as_deref(),
            Some("repository example-owner/example was not found (404: Not Found)")
        );
    }

    // --- security.private-vulnerability-reporting ------------------------------------

    #[test]
    fn private_vulnerability_reporting_in_each_state() {
        let dir = checkout(&[]);
        let pvr = format!("{BASE}/private-vulnerability-reporting");
        let private = Replay::default().ok(BASE, repository("private", json!({})));
        let (o, gets) = audit(
            dir.path(),
            &private,
            SECURITY_PRIVATE_VULNERABILITY_REPORTING,
        );
        assert_eq!(o.status, Status::NotRequired);
        assert_eq!(
            o.reason.as_deref(),
            Some(
                "a private repository: private vulnerability reporting is required on public repositories only"
            )
        );
        assert_eq!(gets, [BASE], "a private repository costs no toggle read");

        let on = Replay::default()
            .ok(BASE, repository("public", json!({})))
            .ok(&pvr, json!({"enabled": true}));
        let (o, _) = audit(dir.path(), &on, SECURITY_PRIVATE_VULNERABILITY_REPORTING);
        assert_eq!(o.status, Status::Passed);

        let off = Replay::default()
            .ok(BASE, repository("public", json!({})))
            .ok(&pvr, json!({"enabled": false}));
        let (o, _) = audit(dir.path(), &off, SECURITY_PRIVATE_VULNERABILITY_REPORTING);
        assert_eq!(o.status, Status::Failed);
        assert_eq!(
            o.evidence,
            ["Private vulnerability reporting off on a public repository"]
        );

        let absent = Replay::default()
            .ok(BASE, repository("public", json!({})))
            .http(&pvr, 404, "Not Found");
        let (o, _) = audit(
            dir.path(),
            &absent,
            SECURITY_PRIVATE_VULNERABILITY_REPORTING,
        );
        assert_eq!(o.status, Status::NotRequired);
    }

    // --- security.bypass-unregistered: the SECURITY_BYPASS ids ------------------------

    fn inventory(ids: &[&str]) -> String {
        let entries: Vec<String> = ids
            .iter()
            .map(|id| format!(r##"{{"id": "{id}", "kind": "job-bypass", "target": "deps-scan", "reason": "r", "issue": "#1", "owner": "o", "created": "2026-11-01", "expires": "2026-11-20"}}"##))
            .collect();
        format!(
            "{{\"schema\": 1, \"exceptions\": [{}]}}\n",
            entries.join(", ")
        )
    }

    #[test]
    fn bypass_variable_ids_must_be_registered() {
        let var = format!("{BASE}/actions/variables/SECURITY_BYPASS");
        let text = inventory(&["osv-outage"]);
        let dir = checkout(&[(".agent-setup/security-exceptions.json", &text)]);

        let unset = Replay::default().http(&var, 404, "Not Found");
        let (o, _) = audit(dir.path(), &unset, SECURITY_BYPASS_UNREGISTERED);
        assert_eq!(o.status, Status::Passed);
        assert_eq!(o.evidence.last().unwrap(), "SECURITY_BYPASS is unset");

        let registered = Replay::default().ok(
            &var,
            json!({"name": "SECURITY_BYPASS", "value": "[\"osv-outage\"]"}),
        );
        let (o, _) = audit(dir.path(), &registered, SECURITY_BYPASS_UNREGISTERED);
        assert_eq!(o.status, Status::Passed);
        assert_eq!(
            o.evidence.last().unwrap(),
            "SECURITY_BYPASS names 1 registered id(s)"
        );

        let ghost = Replay::default().ok(
            &var,
            json!({"name": "SECURITY_BYPASS", "value": "[\"osv-outage\", \"ghost\"]"}),
        );
        let (o, _) = audit(dir.path(), &ghost, SECURITY_BYPASS_UNREGISTERED);
        assert_eq!(o.status, Status::Failed);
        assert_eq!(
            o.evidence,
            ["Bypass ghost is not registered in security-exceptions.json"]
        );

        let broken = Replay::default().ok(
            &var,
            json!({"name": "SECURITY_BYPASS", "value": "HOTFIX=true"}),
        );
        let (o, _) = audit(dir.path(), &broken, SECURITY_BYPASS_UNREGISTERED);
        assert_eq!(o.status, Status::Failed);
        assert_eq!(
            o.evidence,
            ["SECURITY_BYPASS is not a JSON array of exception ids"]
        );

        // Unreadable remotely: the static half stands, and says what was not read.
        let refused = Replay::default().http(&var, 403, "Resource not accessible by integration");
        let (o, _) = audit(dir.path(), &refused, SECURITY_BYPASS_UNREGISTERED);
        assert_eq!(o.status, Status::Passed);
        assert!(
            o.evidence
                .last()
                .unwrap()
                .starts_with("remote half not read: "),
            "{o:?}"
        );
    }

    #[test]
    fn a_static_bypass_finding_and_an_unregistered_variable_id_are_both_evidence() {
        let var = format!("{BASE}/actions/variables/SECURITY_BYPASS");
        let dir = super::with_workflows(&["continue-on-error.yml"], &[]);
        let ghost = Replay::default().ok(
            &var,
            json!({"name": "SECURITY_BYPASS", "value": "[\"ghost\"]"}),
        );
        let (o, _) = audit(dir.path(), &ghost, SECURITY_BYPASS_UNREGISTERED);
        assert_eq!(o.status, Status::Failed);
        assert_eq!(
            o.evidence.last().unwrap(),
            "Bypass ghost is not registered in security-exceptions.json"
        );
        assert!(
            o.evidence.len() > 1,
            "the static findings come first: {o:?}"
        );
    }

    // --- security.secrets-full-history: the run log -----------------------------------

    fn runs(ids: &[u64]) -> Value {
        let runs: Vec<Value> = ids
            .iter()
            .map(|id| {
                json!({"id": id, "name": "CI", "head_sha": "abc", "head_branch": "main",
                              "event": "push", "status": "completed", "conclusion": "success"})
            })
            .collect();
        json!({"total_count": ids.len(), "workflow_runs": runs})
    }
    fn jobs(job: (u64, &str)) -> Value {
        json!({"total_count": 1, "jobs": [{"id": job.0, "name": job.1, "status": "completed", "conclusion": "success"}]})
    }

    #[test]
    fn the_managed_shape_passes_without_a_read() {
        let dir = super::with_workflows(&["managed-gate.yml"], &[]);
        let (o, gets) = audit(
            dir.path(),
            &Replay::default(),
            SECURITY_SECRETS_FULL_HISTORY,
        );
        assert_eq!(o.status, Status::Passed);
        assert!(gets.is_empty(), "{gets:?}");
    }

    #[test]
    fn an_unmanaged_secrets_job_is_judged_by_its_latest_default_branch_log() {
        // continue-on-error.yml runs gitleaks-action in the job `gitleaks`.
        let dir = super::with_workflows(&["continue-on-error.yml"], &[]);
        let log = |text: &str| Value::String(text.to_owned());
        let base = Replay::default()
            .ok(RUNS, runs(&[30, 20]))
            .ok(
                format!("{BASE}/actions/runs/30/jobs?per_page=100&page=1"),
                jobs((300, "lint")),
            )
            .ok(
                format!("{BASE}/actions/runs/20/jobs?per_page=100&page=1"),
                jobs((200, "gitleaks")),
            );
        let path = format!("{BASE}/actions/jobs/200/logs");

        let full = base_with(
            &base,
            &path,
            log(
                "2026-11-09T10:00:00.1Z ##[group]Run echo \"history: full\"\n2026-11-09T10:00:01.2Z history: full\n",
            ),
        );
        let (o, gets) = audit(dir.path(), &full, SECURITY_SECRETS_FULL_HISTORY);
        assert_eq!(o.status, Status::Passed, "{o:?}");
        assert_eq!(o.evidence, ["job gitleaks of run 20 claims history: full"]);
        assert_eq!(gets.len(), 4, "runs, two job listings, one log: {gets:?}");

        let range = base_with(
            &base,
            &path,
            log("2026-11-09T10:00:01.2Z history: aaa..bbb\n"),
        );
        let (o, _) = audit(dir.path(), &range, SECURITY_SECRETS_FULL_HISTORY);
        assert_eq!(o.status, Status::Failed);
        assert_eq!(o.evidence[0], "Secrets scan covers pull-request diffs only");

        // Since #1253 a push scans its own range: the pushed claim covers the default branch.
        let pushed = base_with(
            &base,
            &path,
            log("2026-11-09T10:00:01.2Z history: pushed aaa..bbb\n"),
        );
        let (o, _) = audit(dir.path(), &pushed, SECURITY_SECRETS_FULL_HISTORY);
        assert_eq!(o.status, Status::Passed, "{o:?}");
        assert_eq!(
            o.evidence,
            ["job gitleaks of run 20 claims history: pushed aaa..bbb"]
        );

        // Only the echoed script mentions it: no claim, the rule stays unverified.
        let silent = base_with(
            &base,
            &path,
            log("2026-11-09T10:00:00.1Z echo \"history: full\"\n"),
        );
        let (o, _) = audit(dir.path(), &silent, SECURITY_SECRETS_FULL_HISTORY);
        assert_eq!(o.status, Status::Unavailable);
        assert!(
            o.reason
                .as_deref()
                .unwrap()
                .ends_with("the log of job gitleaks of run 20 carries no history claim"),
            "{o:?}"
        );
    }

    fn base_with(base: &Replay, path: &str, body: Value) -> Replay {
        let mut replies = base.replies.clone();
        replies.insert(path.to_owned(), Ok(body));
        Replay {
            replies,
            gets: RefCell::default(),
        }
    }

    // --- security.scanner-stale ---------------------------------------------------------

    fn pinned_workflow(tool: &str, version: &str) -> String {
        format!(
            "name: CI\non: [push]\npermissions:\n  contents: read\njobs:\n  scan:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 10\n    steps:\n      - name: Install\n        env:\n          TOOL_NAME: {tool}\n          TOOL_VERSION: \"{version}\"\n        run: echo install\n      - name: Semgrep\n        env:\n          SEMGREP_IMAGE: \"docker.io/semgrep/semgrep:1.182.0@sha256:4a34048c04fef049f71665047f074cffb00cc3d89482f965a5cd151d589237af\"\n        run: docker run --rm \"$SEMGREP_IMAGE\" semgrep --version\n"
        )
    }

    #[test]
    fn scanner_stale_compares_each_pin_with_its_upstreams_latest_release() {
        let dir = checkout(&[(
            ".github/workflows/ci.yml",
            &pinned_workflow("gitleaks", "8.30.1"),
        )]);
        let latest = |tag: &str, date: &str| json!({"tag_name": tag, "published_at": date});
        // gitleaks 8.30.1 was released on 2026-03-21 (pins.rs); semgrep's pin is the latest.
        let stale = Replay::default()
            .ok(
                "repos/gitleaks/gitleaks/releases/latest",
                latest("v8.40.0", "2026-08-01T00:00:00Z"),
            )
            .ok(
                "repos/semgrep/semgrep/releases/latest",
                latest("v1.182.0", "2026-10-20T20:27:41Z"),
            );
        let (o, gets) = audit(dir.path(), &stale, SECURITY_SCANNER_STALE);
        assert_eq!(o.status, Status::Failed, "{o:?}");
        assert_eq!(
            o.evidence,
            ["gitleaks pin 8.30.1 is 133 days behind 8.40.0"]
        );
        assert_eq!(gets.len(), 2, "the pin's date comes from pins.rs: {gets:?}");

        let fresh = Replay::default()
            .ok(
                "repos/gitleaks/gitleaks/releases/latest",
                latest("v8.31.0", "2026-05-01T00:00:00Z"),
            )
            .ok(
                "repos/semgrep/semgrep/releases/latest",
                latest("v1.182.0", "2026-10-20T20:27:41Z"),
            );
        let (o, _) = audit(dir.path(), &fresh, SECURITY_SCANNER_STALE);
        assert_eq!(o.status, Status::Passed);
        assert_eq!(
            o.evidence,
            [
                "gitleaks pin 8.30.1 is 41 days behind 8.31.0",
                "semgrep 1.182.0 is the latest release of semgrep/semgrep"
            ]
        );

        // A version pins.rs does not know: its release date is read by tag.
        let dir = checkout(&[(
            ".github/workflows/ci.yml",
            &pinned_workflow("trivy", "0.70.0"),
        )]);
        let by_tag = Replay::default()
            .ok(
                "repos/aquasecurity/trivy/releases/latest",
                latest("v0.76.1", "2026-10-21T11:18:34Z"),
            )
            .ok(
                "repos/aquasecurity/trivy/releases/tags/v0.70.0",
                latest("v0.70.0", "2026-05-02T09:00:00Z"),
            )
            .ok(
                "repos/semgrep/semgrep/releases/latest",
                latest("v1.182.0", "2026-10-20T20:27:41Z"),
            );
        let (o, _) = audit(dir.path(), &by_tag, SECURITY_SCANNER_STALE);
        assert_eq!(o.status, Status::Failed);
        assert_eq!(o.evidence, ["trivy pin 0.70.0 is 172 days behind 0.76.1"]);

        let none = checkout(&[(".github/workflows/ci.yml", &workflow("trivy-action.yml"))]);
        let (o, gets) = audit(none.path(), &Replay::default(), SECURITY_SCANNER_STALE);
        assert_eq!(o.status, Status::NotRequired);
        assert!(gets.is_empty());
    }

    // --- post-delivery rules wait for delivery ------------------------------------------

    #[test]
    fn attestation_and_sbom_rules_wait_for_delivery() {
        for rule in [SECURITY_ATTESTATION_VERIFIED, SECURITY_SBOM_SCANNED] {
            assert_eq!(
                rule.feasible_by,
                Milestone::WaitsFor("delivery"),
                "{}",
                rule.id
            );
            let dir = checkout(&[]);
            let (o, gets) = audit(dir.path(), &Replay::default(), rule);
            assert_eq!(o.status, Status::Unavailable);
            assert_eq!(o.reason.as_deref(), Some("waits for module delivery"));
            assert!(gets.is_empty());
        }
    }
}

// --- #799: security.coverage-ratchet, static half, only when answered ---------------

const COVERAGE_JOB_WORKFLOW: &str = "name: CI\non: pull_request\npermissions:\n  contents: read\njobs:\n  coverage-ratchet:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 20\n    steps:\n      - run: echo\n";

fn coverage_answers(on: bool) -> String {
    json!({"module": "security", "version": "1.0.0", "answers": {"coverage_ratchet": on}})
        .to_string()
}

#[test]
fn coverage_ratchet_answered_reports_a_missing_record_and_job() {
    let answers = coverage_answers(true);
    let dir = repo(&[(".agent-setup/modules/security.json", &answers)]);
    let all = audit::diagnose(dir.path(), today());
    assert_eq!(
        rule_lines(&all, "security.coverage-ratchet"),
        [
            "WARNING: security.coverage-ratchet: Coverage record absent or job red on main: .agent-setup/coverage.json is absent",
            "WARNING: security.coverage-ratchet: Coverage record absent or job red on main: no coverage-ratchet job in .github/workflows",
        ]
    );
}

#[test]
fn coverage_ratchet_with_record_and_job_or_unanswered_reports_nothing() {
    let answers = coverage_answers(true);
    let dir = repo(&[
        (".agent-setup/modules/security.json", &answers),
        (
            ".agent-setup/coverage.json",
            "{\"schema\": 1, \"apps\": {\"root\": 0}}\n",
        ),
        (".github/workflows/ci.yml", COVERAGE_JOB_WORKFLOW),
    ]);
    assert!(
        rule_lines(
            &audit::diagnose(dir.path(), today()),
            "security.coverage-ratchet"
        )
        .is_empty()
    );
    let off = coverage_answers(false);
    let dir = repo(&[(".agent-setup/modules/security.json", &off)]);
    assert!(
        rule_lines(
            &audit::diagnose(dir.path(), today()),
            "security.coverage-ratchet"
        )
        .is_empty()
    );
    let dir = repo(&[]);
    assert!(
        rule_lines(
            &audit::diagnose(dir.path(), today()),
            "security.coverage-ratchet"
        )
        .is_empty()
    );
}

#[test]
fn the_auditor_judges_coverage_ratchet_only_where_it_is_answered_or_wired() {
    let status = |dir: &TempDir| -> (String, Value) {
        let out = doctor(dir, &["--json"]);
        let report: Value = serde_json::from_slice(&out.stdout).unwrap();
        let rule = report["rules"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == "security.coverage-ratchet")
            .cloned()
            .expect("the rule is in the registry");
        (rule["status"].as_str().unwrap().to_owned(), rule)
    };
    // A personal git checkout, so the scope check admits it.
    let checkout = |files: &[(&str, &str)]| {
        let dir = repo(files);
        for args in [
            &["init", "-q"][..],
            &[
                "remote",
                "add",
                "origin",
                "https://github.com/example-owner/example.git",
            ],
        ] {
            assert!(
                Command::new("git")
                    .arg("-C")
                    .arg(dir.path())
                    .args(args)
                    .status()
                    .unwrap()
                    .success()
            );
        }
        dir
    };
    let dir = checkout(&[]);
    assert_eq!(status(&dir).0, "not-required");
    let answers = coverage_answers(true);
    let dir = checkout(&[(".agent-setup/modules/security.json", &answers)]);
    let (state, rule) = status(&dir);
    assert_eq!(state, "failed", "{rule}");
    assert_eq!(rule["level"], "Gold", "{rule}");
    let dir = checkout(&[
        (".agent-setup/modules/security.json", &answers),
        (
            ".agent-setup/coverage.json",
            "{\"schema\": 1, \"apps\": {\"root\": 0}}\n",
        ),
        (".github/workflows/ci.yml", COVERAGE_JOB_WORKFLOW),
    ]);
    assert_eq!(status(&dir).0, "passed");
}

// --- mutation gate (#979; SPEC-security.md, `security.mutation-gate`) ---------

const MUTATION: &str = "security.mutation-gate";
const GOLDENS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../templates/security/goldens"
);

/// A rendered golden, whole: the reader's 256 KiB cap holds every one with
/// room to spare (`every_security_golden_fits_the_workflow_reader_with_margin`).
fn golden_workflow(name: &str) -> String {
    fs::read_to_string(Path::new(GOLDENS).join(name)).expect(name)
}

fn security_answers(answers: &str) -> String {
    format!("{{\"module\": \"security\", \"version\": \"1.0.0\", \"answers\": {answers}}}\n")
}

fn mutation_lines(workflow: &str, answers: Option<&str>) -> Vec<String> {
    let recorded = answers.map(security_answers);
    let mut files = vec![(".github/workflows/ci.yml", workflow)];
    if let Some(text) = &recorded {
        files.push((".agent-setup/modules/security.json", text.as_str()));
    }
    let dir = repo(&files);
    let all = findings(dir.path());
    assert_channel(&all);
    rule_lines(&all, MUTATION)
        .into_iter()
        .map(str::to_owned)
        .collect()
}

#[test]
fn the_mutation_gate_passes_with_the_rendered_job_in_the_aggregate() {
    for golden in ["mutation-rust.yml", "mutation-python.yml"] {
        let text = golden_workflow(golden);
        assert!(
            mutation_lines(&text, Some(r#"{"mutation_diff": true}"#)).is_empty(),
            "{golden}"
        );
    }
}

#[test]
fn the_mutation_gate_fails_when_mutation_diff_is_true_and_no_job_is_in_the_aggregate() {
    let expected = [
        "WARNING: security.mutation-gate: mutation_diff is true and no mutation-diff job is in the aggregate",
    ];
    let minimal = golden_workflow("minimal.yml");
    assert_eq!(
        mutation_lines(&minimal, Some(r#"{"mutation_diff": true}"#)),
        expected
    );
    // The job exists but no `if: always()` job needs it.
    let unwired = golden_workflow("mutation-rust.yml").replace(", mutation-diff]", "]");
    assert_ne!(unwired, golden_workflow("mutation-rust.yml"));
    assert_eq!(
        mutation_lines(&unwired, Some(r#"{"mutation_diff": true}"#)),
        expected
    );
    // The job is wired but runs neither tool.
    let toolless = golden_workflow("mutation-rust.yml").replace(
        "cargo mutants --no-shuffle --in-diff git.diff",
        "echo skipped",
    );
    assert_eq!(
        mutation_lines(&toolless, Some(r#"{"mutation_diff": true}"#)),
        expected
    );
    // The embedded shell names both tools in comments and messages; only the
    // command counts.
    let python = golden_workflow("mutation-python.yml");
    let toolless = python.replace(r#"mutmut run \"$MUTATION_MODULE*\""#, "true");
    assert_ne!(toolless, python);
    assert_eq!(
        mutation_lines(&toolless, Some(r#"{"mutation_diff": true}"#)),
        expected
    );
}

#[test]
fn the_mutation_gate_is_silent_unless_mutation_diff_is_true() {
    let minimal = golden_workflow("minimal.yml");
    for answers in [None, Some("{}"), Some(r#"{"mutation_diff": false}"#)] {
        assert!(mutation_lines(&minimal, answers).is_empty(), "{answers:?}");
    }
}

// --- #978: security.diff-coverage, static, only where a root app has a per-file report ---

const DIFF_RULE: &str = "security.diff-coverage";
const DIFF_FINDING: &str = "WARNING: security.diff-coverage: No changed-line coverage gate: a pull request can ship code no test executes";

fn stack_answers(stack: &str) -> String {
    json!({"module": "stack-packs", "version": "1.0.0",
           "answers": {"apps.root.path": ".", "apps.root.stack": stack}})
    .to_string()
}

/// A workflow whose `diff-coverage` job the aggregate needs, with `run:` texts
/// `changed` and `characterization` for its two judging steps.
fn diff_workflow(changed: &str, characterization: &str) -> String {
    format!(
        "name: CI\non: pull_request\npermissions:\n  contents: read\njobs:\n  diff-coverage:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 20\n    steps:\n      - run: {changed}\n      - run: {characterization}\n  required:\n    if: always()\n    needs: [diff-coverage]\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    steps:\n      - run: echo\n"
    )
}

const GOOD_CHANGED: &str = "\"uvx diff-cover==10.6.0 lcov.info --fail-under=80\"";
const GOOD_CHARACTERIZATION: &str = "\"echo Characterization first\"";

#[test]
fn diff_coverage_is_reported_for_a_rust_or_python_root_without_the_gate() {
    for stack in ["rust", "python-uv"] {
        let packs = stack_answers(stack);
        let dir = repo(&[(".agent-setup/modules/stack-packs.json", &packs)]);
        assert_eq!(
            rule_lines(&audit::diagnose(dir.path(), today()), DIFF_RULE),
            [DIFF_FINDING],
            "{stack}"
        );
    }
}

#[test]
fn diff_coverage_passes_with_the_gate_and_is_silent_where_it_does_not_apply() {
    let packs = stack_answers("rust");
    let good = diff_workflow(GOOD_CHANGED, GOOD_CHARACTERIZATION);
    let dir = repo(&[
        (".agent-setup/modules/stack-packs.json", &packs),
        (".github/workflows/ci.yml", &good),
    ]);
    assert!(rule_lines(&audit::diagnose(dir.path(), today()), DIFF_RULE).is_empty());
    // node and go have no per-file report; no recorded pack, nothing to judge.
    for stack in ["node", "go"] {
        let packs = stack_answers(stack);
        let dir = repo(&[(".agent-setup/modules/stack-packs.json", &packs)]);
        assert!(rule_lines(&audit::diagnose(dir.path(), today()), DIFF_RULE).is_empty());
    }
    assert!(rule_lines(&audit::diagnose(repo(&[]).path(), today()), DIFF_RULE).is_empty());
    // Answered off: not judged.
    let off = json!({"module": "security", "version": "1.0.0",
                     "answers": {"coverage_changed_lines": false}})
    .to_string();
    let dir = repo(&[
        (".agent-setup/modules/stack-packs.json", &packs),
        (".agent-setup/modules/security.json", &off),
    ]);
    assert!(rule_lines(&audit::diagnose(dir.path(), today()), DIFF_RULE).is_empty());
}

/// #1349: the reusable workflow judges; the project's CI calls it and its aggregate needs it.
fn reusable_coverage() -> String {
    format!(
        "name: agentic-coverage\non:\n  workflow_call:\npermissions:\n  contents: read\njobs:\n  diff-coverage:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 15\n    steps:\n      - run: {GOOD_CHANGED}\n      - run: {GOOD_CHARACTERIZATION}\n"
    )
}

fn calling_ci(needed: bool) -> String {
    let needs = if needed {
        "[tests, diff-coverage]"
    } else {
        "[tests]"
    };
    format!(
        "name: CI\non: pull_request\npermissions:\n  contents: read\njobs:\n  tests:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 20\n    steps:\n      - run: echo test\n  diff-coverage:\n    needs: [tests]\n    uses: ./.github/workflows/agentic-coverage.yml\n  all-checks-passed:\n    if: always()\n    needs: {needs}\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    steps:\n      - run: echo\n"
    )
}

#[test]
fn a_project_ci_gate_passes_when_the_caller_aggregate_needs_the_reusable_job() {
    let packs = stack_answers("python-uv");
    let reusable = reusable_coverage();
    for (needed, findings) in [(true, 0), (false, 1)] {
        let ci = calling_ci(needed);
        let dir = repo(&[
            (".agent-setup/modules/stack-packs.json", &packs),
            (".github/workflows/agentic-coverage.yml", &reusable),
            (".github/workflows/ci.yml", &ci),
        ]);
        assert_eq!(
            rule_lines(&audit::diagnose(dir.path(), today()), DIFF_RULE).len(),
            findings,
            "needed {needed}"
        );
    }
    // The reusable workflow alone, never called, gates nothing.
    let dir = repo(&[
        (".agent-setup/modules/stack-packs.json", &packs),
        (".github/workflows/agentic-coverage.yml", &reusable),
    ]);
    assert_eq!(
        rule_lines(&audit::diagnose(dir.path(), today()), DIFF_RULE),
        [DIFF_FINDING]
    );
}

#[test]
fn a_gate_without_the_threshold_the_characterization_or_the_aggregate_fails() {
    let packs = stack_answers("rust");
    let not_needed = diff_workflow(GOOD_CHANGED, GOOD_CHARACTERIZATION)
        .replace("needs: [diff-coverage]", "needs: []");
    for workflow in [
        diff_workflow(
            "\"uvx diff-cover==10.6.0 lcov.info\"",
            GOOD_CHARACTERIZATION,
        ),
        diff_workflow(GOOD_CHANGED, "\"echo characterize\""),
        not_needed,
    ] {
        let dir = repo(&[
            (".agent-setup/modules/stack-packs.json", &packs),
            (".github/workflows/ci.yml", &workflow),
        ]);
        assert_eq!(
            rule_lines(&audit::diagnose(dir.path(), today()), DIFF_RULE),
            [DIFF_FINDING],
            "{workflow}"
        );
    }
}

#[test]
fn the_auditor_judges_diff_coverage_where_reported_or_wired_at_silver() {
    let status = |dir: &TempDir| -> (String, Value) {
        let out = doctor(dir, &["--json"]);
        let report: Value = serde_json::from_slice(&out.stdout).unwrap();
        let rule = report["rules"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == DIFF_RULE)
            .cloned()
            .expect("the rule is in the registry");
        (rule["status"].as_str().unwrap().to_owned(), rule)
    };
    let checkout = |files: &[(&str, &str)]| {
        let dir = repo(files);
        for args in [
            &["init", "-q"][..],
            &[
                "remote",
                "add",
                "origin",
                "https://github.com/example-owner/example.git",
            ],
        ] {
            assert!(
                Command::new("git")
                    .arg("-C")
                    .arg(dir.path())
                    .args(args)
                    .status()
                    .unwrap()
                    .success()
            );
        }
        dir
    };
    assert_eq!(status(&checkout(&[])).0, "not-required");
    let packs = stack_answers("rust");
    let (state, rule) = status(&checkout(&[(
        ".agent-setup/modules/stack-packs.json",
        &packs,
    )]));
    assert_eq!(state, "failed", "{rule}");
    assert_eq!(rule["level"], "Silver", "{rule}");
    let good = diff_workflow(GOOD_CHANGED, GOOD_CHARACTERIZATION);
    assert_eq!(
        status(&checkout(&[(".github/workflows/ci.yml", &good)])).0,
        "passed"
    );
}

#[test]
fn the_rendered_diff_coverage_goldens_pass_the_rule() {
    for name in ["diff-coverage-rust.yml", "diff-coverage-python.yml"] {
        let text = fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../templates/security/goldens")
                .join(name),
        )
        .unwrap();
        // #22: the golden is the reusable workflow; the project's CI calls it
        // and its aggregate needs the caller job.
        let caller = "name: CI\non: pull_request\npermissions:\n  contents: read\njobs:\n  diff-coverage:\n    uses: ./.github/workflows/agentic-coverage.yml\n  required:\n    if: always()\n    needs: [diff-coverage]\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo ok\n";
        let dir = repo(&[
            (".github/workflows/agentic-coverage.yml", &text),
            (".github/workflows/ci.yml", caller),
        ]);
        assert_eq!(
            audit::diff_coverage(dir.path()),
            Vec::<String>::new(),
            "{name}"
        );
        // Without the caller nothing judges the pull request.
        let alone = repo(&[(".github/workflows/agentic-coverage.yml", &text)]);
        assert_eq!(audit::diff_coverage(alone.path()).len(), 1, "{name}");
    }
}

#[test]
fn diff_coverage_applies_to_an_app_in_a_subdirectory() {
    let packs = json!({"module": "stack-packs", "version": "1.0.0",
        "answers": {"apps.api.path": "apps/api", "apps.api.stack": "rust",
                    "apps.web.path": "apps/web", "apps.web.stack": "node"}})
    .to_string();
    let dir = repo(&[(".agent-setup/modules/stack-packs.json", &packs)]);
    assert_eq!(
        rule_lines(&audit::diagnose(dir.path(), today()), DIFF_RULE),
        [DIFF_FINDING]
    );
}
