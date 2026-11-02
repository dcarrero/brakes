//! qa T10 (#1008; SPEC-qa.md, "Auditor rules this module enables" and "How
//! `doctor` reports the static rules"): the static Bronze `qa.*` rules over
//! every workflow, the `.hurl` files, `package.json` and the Playwright configs,
//! reported as `doctor` warnings, never as readiness; the registry block `qa`
//! with all nine ids at the spec's levels; `doctor --json` pinned by a golden.
use brakes::auditor::rules::{Block, Level, REGISTRY};
use brakes::modules::qa::audit;
use serde_json::{Value, json};
use std::{fs, path::Path, process::Command};
use tempfile::TempDir;

const AGGREGATE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/qa/audit/aggregate"
);
const CI: &str = ".github/workflows/ci.yml";
const TODAY: &str = "2026-11-03";

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

/// A git checkout with a personal origin holding `files`.
fn repo(files: &[(&str, &str)]) -> TempDir {
    let dir = TempDir::new().unwrap();
    git(dir.path(), &["init", "-q"]);
    git(
        dir.path(),
        &[
            "remote",
            "add",
            "origin",
            "https://github.com/example-owner/example.git",
        ],
    );
    write(&dir, files);
    dir
}

fn write(dir: &TempDir, files: &[(&str, &str)]) {
    for (path, text) in files {
        let path = dir.path().join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
}

/// The aggregate fixture (Hurl and Playwright in the aggregate), then `files`.
fn aggregate(files: &[(&str, &str)]) -> TempDir {
    let dir = repo(&[]);
    copy_tree(Path::new(AGGREGATE), dir.path());
    write(&dir, files);
    dir
}

fn read(dir: &TempDir, path: &str) -> String {
    fs::read_to_string(dir.path().join(path)).unwrap()
}

/// The `qa.*` findings `doctor` prints for `dir`.
fn qa(dir: &TempDir) -> Vec<String> {
    audit::diagnose(dir.path())
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

/// `doctor --json`'s rules of block `qa`: id → (status, evidence or reason).
fn qa_rules(dir: &TempDir) -> Vec<(String, String, String)> {
    let out = doctor(dir, &["--json"]);
    let document: Value = serde_json::from_slice(&out.stdout).unwrap();
    document["rules"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["id"].as_str().unwrap().starts_with("qa."))
        .map(|r| {
            let said = r["reason"]
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| r["evidence"].to_string());
            (
                r["id"].as_str().unwrap().to_owned(),
                r["status"].as_str().unwrap().to_owned(),
                said,
            )
        })
        .collect()
}

fn status_of(rules: &[(String, String, String)], id: &str) -> String {
    rules
        .iter()
        .find(|(rule, _, _)| rule == id)
        .unwrap_or_else(|| panic!("{id} not reported"))
        .1
        .clone()
}

const BRONZE: [&str; 4] = [
    "qa.hurl-no-literal-host",
    "qa.tools-pinned",
    "qa.no-snapshot-update-in-ci",
    "qa.report-artifact",
];

// --- the registry ------------------------------------------------------------------

#[test]
fn the_registry_lists_the_eleven_qa_ids_with_the_spec_levels_after_agents() {
    let qa: Vec<(&str, Level)> = REGISTRY
        .iter()
        .filter(|r| r.block == Block::Qa)
        .map(|r| (r.id, r.level))
        .collect();
    assert_eq!(
        qa,
        [
            ("qa.api-smoke-present", Level::Silver),
            ("qa.web-smoke-present", Level::Silver),
            ("qa.screenshot-baseline-present", Level::Silver),
            ("qa.snapshots-protected", Level::Silver),
            ("qa.hurl-no-literal-host", Level::Bronze),
            ("qa.tools-pinned", Level::Bronze),
            ("qa.no-snapshot-update-in-ci", Level::Bronze),
            ("qa.report-artifact", Level::Bronze),
            ("qa.main-green", Level::Silver),
            ("qa.contract-lint", Level::Silver),
            ("qa.contract-compatible", Level::Silver),
        ]
    );
    assert_eq!(Block::Qa.id(), "qa");
    let first_qa = REGISTRY.iter().position(|r| r.block == Block::Qa).unwrap();
    assert!(REGISTRY[first_qa..].iter().all(|r| r.block == Block::Qa));
    assert_eq!(REGISTRY[first_qa - 1].block, Block::Agents);
}

// --- the four Bronze rules ---------------------------------------------------------

#[test]
fn hurl_and_playwright_in_the_aggregate_pass_all_four() {
    let dir = aggregate(&[]);
    assert_eq!(qa(&dir), Vec::<String>::new());
    let rules = qa_rules(&dir);
    for id in BRONZE {
        assert_eq!(status_of(&rules, id), "passed", "{id}: {rules:?}");
    }
}

#[test]
fn a_caret_playwright_version_is_not_pinned() {
    let dir = aggregate(&[
        (
            "package.json",
            r#"{"devDependencies": {"@playwright/test": "^1.64.0"}}"#,
        ),
        ("playwright.config.ts", "export default {};\n"),
        // The root config's journey, so the web app it declares has one.
        ("e2e/home.spec.ts", "// journey\n"),
    ]);
    assert_eq!(
        qa(&dir),
        [
            "WARNING: qa.tools-pinned: QA tool @playwright/test in package.json is not pinned by checksum or exact version"
        ]
    );
    assert_eq!(status_of(&qa_rules(&dir), "qa.tools-pinned"), "failed");
    for range in ["~1.64.0", "latest", "1.64", "*", ">=1.64.0"] {
        let dir = aggregate(&[(
            "qa/web/package.json",
            &format!(r#"{{"dependencies": {{"@playwright/test": "{range}"}}}}"#),
        )]);
        assert_eq!(qa(&dir).len(), 1, "{range}");
    }
}

#[test]
fn hurl_installed_without_a_checksum_by_a_pipe_or_an_action_is_not_pinned() {
    let finding = "WARNING: qa.tools-pinned: QA tool hurl in .github/workflows/ci.yml is not pinned by checksum or exact version";
    let swap = |from: &str, to: &str| {
        let dir = aggregate(&[]);
        let text = read(&dir, CI);
        assert!(text.contains(from), "{from}");
        write(&dir, &[(CI, &text.replace(from, to))]);
        dir
    };
    // No checksum.
    let dir = swap(
        "          echo \"0000000000000000000000000000000000000000000000000000000000000000  hurl.tar.gz\" | sha256sum --check --strict\n",
        "",
    );
    assert_eq!(qa(&dir), [finding]);
    // Piped to a shell, even beside a checksum.
    let dir = swap(
        "          tar -xzf hurl.tar.gz\n",
        "          curl -fsSL https://example.invalid/install-hurl.sh | sh\n",
    );
    assert_eq!(qa(&dir), [finding]);
    // A marketplace action.
    let dir = swap(
        "      - name: Install hurl\n",
        "      - uses: gacts/install-hurl@v1\n      - name: Install hurl\n",
    );
    assert_eq!(qa(&dir), [finding]);
}

#[test]
fn playwright_install_with_another_version_is_not_pinned() {
    let dir = aggregate(&[]);
    let text = read(&dir, CI).replace(
        "npx playwright install --with-deps chromium",
        "npx playwright@1.50.0 install --with-deps chromium",
    );
    write(&dir, &[(CI, &text)]);
    assert_eq!(
        qa(&dir),
        [
            "WARNING: qa.tools-pinned: QA tool playwright in .github/workflows/ci.yml is not pinned by checksum or exact version"
        ]
    );
    // The package's own version is not another one.
    let text = text.replace("playwright@1.50.0", "playwright@1.64.1");
    write(&dir, &[(CI, &text)]);
    assert_eq!(qa(&dir), Vec::<String>::new());
}

#[test]
fn update_snapshots_in_a_workflow_or_a_config_is_reported() {
    let text =
        "CI updates screenshot baselines: a broken screen can pass by rewriting its evidence";
    assert_eq!(audit::SNAPSHOT_UPDATE_TEXT, text);
    let dir = aggregate(&[]);
    let ci = read(&dir, CI).replace(
        "npx playwright test",
        "npx playwright test --update-snapshots",
    );
    write(&dir, &[(CI, &ci)]);
    assert_eq!(
        qa(&dir),
        [format!(
            "WARNING: qa.no-snapshot-update-in-ci: {text} ({CI})"
        )]
    );
    assert_eq!(
        status_of(&qa_rules(&dir), "qa.no-snapshot-update-in-ci"),
        "failed"
    );
    // UPDATE_SNAPSHOTS in a step's env.
    let dir = aggregate(&[]);
    let ci = read(&dir, CI).replace(
        "      - run: npx playwright test\n",
        "      - run: npx playwright test\n        env:\n          UPDATE_SNAPSHOTS: all\n",
    );
    write(&dir, &[(CI, &ci)]);
    assert_eq!(qa(&dir).len(), 1, "{:?}", qa(&dir));
    // A config that updates them; `'missing'` and `'none'` do not.
    let config = "qa/web/playwright.config.ts";
    for (value, reported) in [
        ("'all'", true),
        ("\"changed\"", true),
        ("'none'", false),
        ("'missing'", false),
    ] {
        let dir = aggregate(&[]);
        let edited = read(&dir, config).replace("'missing'", value);
        write(&dir, &[(config, &edited)]);
        let expected: Vec<String> = if reported {
            vec![format!(
                "WARNING: qa.no-snapshot-update-in-ci: {text} ({config})"
            )]
        } else {
            Vec::new()
        };
        assert_eq!(qa(&dir), expected, "{value}");
    }
}

#[test]
fn a_hurl_file_with_a_literal_host_names_its_line() {
    let dir = aggregate(&[(
        "qa/api/10-orders.hurl",
        "# Orders\nGET https://api.example.com/orders\nHTTP 200\n",
    )]);
    assert_eq!(
        qa(&dir),
        [
            "WARNING: qa.hurl-no-literal-host: qa/api/10-orders.hurl:2 names a host; use {{base_url}} so the file serves test, smoke and uptime"
        ]
    );
    assert_eq!(
        status_of(&qa_rules(&dir), "qa.hurl-no-literal-host"),
        "failed"
    );
    // Also without any QA job: the rule applies where a .hurl file exists.
    let dir = repo(&[("smoke/a.hurl", "POST http://localhost:8080/x\n")]);
    assert_eq!(
        qa(&dir),
        [
            "WARNING: qa.hurl-no-literal-host: smoke/a.hurl:1 names a host; use {{base_url}} so the file serves test, smoke and uptime"
        ]
    );
    assert_eq!(
        status_of(&qa_rules(&dir), "qa.hurl-no-literal-host"),
        "failed"
    );
}

#[test]
fn a_qa_job_without_an_upload_keeps_no_report() {
    let dir = aggregate(&[]);
    let ci = read(&dir, CI).replace("            qa/web/playwright-report/\n", "");
    write(&dir, &[(CI, &ci)]);
    assert_eq!(
        qa(&dir),
        [
            "WARNING: qa.report-artifact: QA job qa-web keeps no report: failures cannot be inspected"
        ]
    );
    assert_eq!(status_of(&qa_rules(&dir), "qa.report-artifact"), "failed");
}

#[test]
fn node_modules_is_never_read() {
    let dir = aggregate(&[
        (
            "node_modules/x/package.json",
            r#"{"dependencies": {"@playwright/test": "^1.0.0"}}"#,
        ),
        ("node_modules/x/a.hurl", "GET https://example.com\n"),
    ]);
    assert_eq!(qa(&dir), Vec::<String>::new());
}

#[test]
fn without_a_qa_job_the_four_are_not_required() {
    let dir = repo(&[
        ("README.md", "# x\n"),
        (
            CI,
            "on: [push]\njobs:\n  test:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: cargo test\n",
        ),
        (
            "package.json",
            r#"{"devDependencies": {"@playwright/test": "^1.64.0"}}"#,
        ),
    ]);
    assert_eq!(qa(&dir), Vec::<String>::new());
    let rules = qa_rules(&dir);
    for id in BRONZE {
        assert_eq!(status_of(&rules, id), "not-required", "{id}: {rules:?}");
    }
    assert_eq!(status_of(&rules, "qa.main-green"), "not-required");
}

#[test]
fn a_broken_workflow_or_package_is_unverified_naming_the_file() {
    let dir = aggregate(&[(".github/workflows/broken.yml", "jobs: [unclosed\n")]);
    let found = qa(&dir);
    for rule in [
        "qa.tools-pinned",
        "qa.no-snapshot-update-in-ci",
        "qa.report-artifact",
    ] {
        let prefix = format!("WARNING: {rule}: unverified: .github/workflows/broken.yml: ");
        assert!(
            found.iter().any(|f| f.starts_with(&prefix)),
            "{rule}: {found:?}"
        );
    }
    let rules = qa_rules(&dir);
    assert_eq!(status_of(&rules, "qa.tools-pinned"), "unavailable");
    // Without any readable QA job, a broken workflow may hold one.
    let dir = repo(&[(".github/workflows/broken.yml", "jobs: [unclosed\n")]);
    assert_eq!(qa(&dir).len(), 3, "{:?}", qa(&dir));
    // A package.json that does not parse.
    let dir = aggregate(&[("qa/web/package.json", "{ not json")]);
    let found = qa(&dir);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
        found[0].starts_with("WARNING: qa.tools-pinned: unverified: qa/web/package.json: "),
        "{found:?}"
    );
}

// --- the Silver rules (T11, #1009) ---------------------------------------------------

const SILVER: [&str; 4] = [
    "qa.api-smoke-present",
    "qa.web-smoke-present",
    "qa.screenshot-baseline-present",
    "qa.snapshots-protected",
];
const API_TEXT: &str =
    "WARNING: qa.api-smoke-present: No API smoke test: no .hurl file runs in the aggregate";
const WEB_TEXT: &str =
    "WARNING: qa.web-smoke-present: No web journey: no Playwright test runs in the aggregate";
const BASELINE_TEXT: &str = "WARNING: qa.screenshot-baseline-present: Screenshot comparison without a committed baseline: the first run only writes images";
const PROTECTED_TEXT: &str = "WARNING: qa.snapshots-protected: Screenshot baselines are not a protected path: an agent can regenerate them to pass";
const SCREENSHOT_SPEC: &str = "import { test, expect } from '@playwright/test';\ntest('home', async ({ page }) => {\n  await page.goto('/');\n  await expect(page).toHaveScreenshot('home.png');\n});\n";
const PNG: &str = "\u{89}PNG\r\n";
/// The ci-baseline gate in its smallest shape: the relabel triggers and an
/// `if: always()` job whose step reads the labels and the protected paths.
const GATE: &str = ".github/workflows/gate.yml";
const GATE_YML: &str = "on:\n  pull_request:\n    types: [opened, synchronize, reopened, labeled, unlabeled]\npermissions:\n  contents: read\njobs:\n  required:\n    if: always()\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    steps:\n      - env:\n          PR_LABELS: x\n          PROTECTED: x\n        run: echo gate\n";

/// The findings of rule `id` in `findings`.
fn of<'a>(findings: &'a [String], id: &str) -> Vec<&'a str> {
    let prefix = format!("WARNING: {id}: ");
    findings
        .iter()
        .filter(|f| f.starts_with(&prefix))
        .map(String::as_str)
        .collect()
}

#[test]
fn an_api_repository_with_no_hurl_file_has_no_api_smoke() {
    let dir = repo(&[("Cargo.toml", "[dependencies]\naxum = \"0.8\"\n")]);
    assert_eq!(of(&qa(&dir), "qa.api-smoke-present"), [API_TEXT]);
    assert_eq!(status_of(&qa_rules(&dir), "qa.api-smoke-present"), "failed");
}

#[test]
fn a_hurl_job_outside_every_aggregate_is_no_api_smoke() {
    let dir = aggregate(&[("Cargo.toml", "[dependencies]\naxum = \"0.8\"\n")]);
    assert_eq!(of(&qa(&dir), "qa.api-smoke-present"), Vec::<&str>::new());
    let ci = read(&dir, CI).replace("needs: [qa-api, qa-web]", "needs: [qa-web]");
    write(&dir, &[(CI, &ci)]);
    assert_eq!(of(&qa(&dir), "qa.api-smoke-present"), [API_TEXT]);
}

#[test]
fn a_web_repository_whose_playwright_job_is_in_no_aggregate_has_no_web_journey() {
    let dir = aggregate(&[
        ("package.json", r#"{"dependencies": {"react": "19.1.0"}}"#),
        ("qa/web/smoke.spec.ts", "// journey\n"),
    ]);
    assert_eq!(of(&qa(&dir), "qa.web-smoke-present"), Vec::<&str>::new());
    let ci = read(&dir, CI).replace("needs: [qa-api, qa-web]", "needs: [qa-api]");
    write(&dir, &[(CI, &ci)]);
    assert_eq!(of(&qa(&dir), "qa.web-smoke-present"), [WEB_TEXT]);
    assert_eq!(status_of(&qa_rules(&dir), "qa.web-smoke-present"), "failed");
}

#[test]
fn a_spec_outside_the_config_test_dir_is_no_web_journey() {
    let dir = aggregate(&[
        ("package.json", r#"{"dependencies": {"react": "19.1.0"}}"#),
        (
            "qa/web/playwright.config.ts",
            "export default { testDir: './journeys' };\n",
        ),
        ("qa/web/smoke.spec.ts", "// outside testDir\n"),
    ]);
    assert_eq!(of(&qa(&dir), "qa.web-smoke-present"), [WEB_TEXT]);
    write(&dir, &[("qa/web/journeys/home.spec.ts", "// inside\n")]);
    assert_eq!(of(&qa(&dir), "qa.web-smoke-present"), Vec::<&str>::new());
}

#[test]
fn to_have_screenshot_without_a_png_has_no_baseline() {
    let dir = aggregate(&[("qa/web/smoke.spec.ts", SCREENSHOT_SPEC)]);
    assert_eq!(
        of(&qa(&dir), "qa.screenshot-baseline-present"),
        [format!("{BASELINE_TEXT} (qa/web/smoke.spec.ts)")]
    );
    assert_eq!(
        status_of(&qa_rules(&dir), "qa.screenshot-baseline-present"),
        "failed"
    );
    write(
        &dir,
        &[(
            "qa/web/smoke.spec.ts-snapshots/home-chromium-linux.png",
            PNG,
        )],
    );
    assert_eq!(
        of(&qa(&dir), "qa.screenshot-baseline-present"),
        Vec::<&str>::new()
    );
}

/// #1171: a template spec a declared `screenshot-baseline-present#<spec>`
/// entry registers is not judged; doctor prints the exclusion, and an entry for
/// a spec that does not compare screenshots is stale.
#[test]
fn a_registered_spec_is_a_declared_exclusion_of_screenshot_baseline() {
    let inventory = json!({"schema": 1, "exceptions": [
        {"id": "qa-seed", "kind": "allowlist", "target": "screenshot-baseline-present#templates/qa/seeds/web/smoke.spec.ts",
         "reason": "the qa seed, rendered into targets and never run here", "issue": "#1171", "owner": "o",
         "created": "2026-11-01", "expires": "2027-10-01"},
        {"id": "plain", "kind": "allowlist", "target": "screenshot-baseline-present#qa/web/plain.spec.ts",
         "reason": "r", "issue": "#1171", "owner": "o", "created": "2026-11-01", "expires": "2027-10-01"},
    ]})
    .to_string();
    let dir = aggregate(&[
        ("templates/qa/seeds/web/smoke.spec.ts", SCREENSHOT_SPEC),
        ("qa/web/plain.spec.ts", "// no screenshot\n"),
        (".agent-setup/security-exceptions.json", &inventory),
    ]);
    assert_eq!(
        of(&qa(&dir), "qa.screenshot-baseline-present"),
        Vec::<&str>::new()
    );
    let line = "EXCLUDED [qa.screenshot-baseline-present] templates/qa/seeds/web/smoke.spec.ts — qa-seed (#1171, until 2027-10-01): the qa seed, rendered into targets and never run here";
    assert_eq!(audit::excluded(dir.path()), [line]);
    let out = doctor(&dir, &[]);
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.lines().any(|l| l == line), "{text}");
    assert!(
        text.lines().any(|l| l == "WARNING: security.bypass-inventory-valid: Exception plain registers screenshot-baseline-present#qa/web/plain.spec.ts, which the rule does not find"),
        "{text}"
    );
    assert_eq!(
        status_of(&qa_rules(&dir), "qa.screenshot-baseline-present"),
        "passed"
    );
    // Without the registration the seed is judged again.
    fs::remove_file(dir.path().join(".agent-setup/security-exceptions.json")).unwrap();
    assert_eq!(
        of(&qa(&dir), "qa.screenshot-baseline-present"),
        [format!(
            "{BASELINE_TEXT} (templates/qa/seeds/web/smoke.spec.ts)"
        )]
    );
    assert!(audit::excluded(dir.path()).is_empty());
}

/// #16: a spec at or under a path the profile declares in `excluded_paths` is
/// not the project's; a spec of the project beside it is still judged.
#[test]
fn a_spec_under_the_profiles_excluded_paths_has_no_baseline_finding() {
    let profile = json!({
        "purpose": "p",
        "commands": {"verify": "v"},
        "excluded_paths": ["templates/qa"],
    })
    .to_string();
    let dir = aggregate(&[
        (".agent-setup/project.json", &profile),
        ("templates/qa/seeds/web/smoke.spec.ts", SCREENSHOT_SPEC),
    ]);
    assert_eq!(
        of(&qa(&dir), "qa.screenshot-baseline-present"),
        Vec::<&str>::new()
    );
    assert_eq!(
        status_of(&qa_rules(&dir), "qa.screenshot-baseline-present"),
        "passed"
    );
    write(&dir, &[("qa/web/smoke.spec.ts", SCREENSHOT_SPEC)]);
    assert_eq!(
        of(&qa(&dir), "qa.screenshot-baseline-present"),
        [format!("{BASELINE_TEXT} (qa/web/smoke.spec.ts)")]
    );
}

#[test]
fn a_snapshots_directory_outside_protected_paths_is_unprotected() {
    let dir = aggregate(&[
        ("qa/web/smoke.spec.ts", SCREENSHOT_SPEC),
        (
            "qa/web/smoke.spec.ts-snapshots/home-chromium-linux.png",
            PNG,
        ),
    ]);
    // No ci-baseline record and no gate: nothing protects it.
    assert_eq!(
        of(&qa(&dir), "qa.snapshots-protected"),
        [format!("{PROTECTED_TEXT} (qa/web/smoke.spec.ts-snapshots)")]
    );
    assert_eq!(
        status_of(&qa_rules(&dir), "qa.snapshots-protected"),
        "failed"
    );
    // An answered protected_paths that names it, but no gate: still unprotected.
    write(
        &dir,
        &[(
            ".agent-setup/modules/ci-baseline.json",
            r#"{"module": "ci-baseline", "version": "1.0.0", "answers": {"protected_paths": ["qa/web/*-snapshots/**"]}}"#,
        )],
    );
    assert_eq!(of(&qa(&dir), "qa.snapshots-protected").len(), 1);
    write(&dir, &[(GATE, GATE_YML)]);
    assert_eq!(of(&qa(&dir), "qa.snapshots-protected"), Vec::<&str>::new());
    // An answered list that does not name it is never extended.
    write(
        &dir,
        &[(
            ".agent-setup/modules/ci-baseline.json",
            r#"{"module": "ci-baseline", "version": "1.0.0", "answers": {"protected_paths": [".github/workflows/**"]}}"#,
        )],
    );
    assert_eq!(of(&qa(&dir), "qa.snapshots-protected").len(), 1);
}

#[test]
fn the_derived_protected_paths_come_from_qa_web_dirs() {
    let dir = aggregate(&[
        ("Cargo.toml", ""),
        ("Cargo.lock", ""),
        (
            ".agent-setup/modules/stack-packs.json",
            r#"{"module": "stack-packs", "version": "1.0.0", "answers": {"apps.root.path": ".", "apps.root.stack": "rust", "apps.root.container": false}}"#,
        ),
        (
            ".agent-setup/modules/ci-baseline.json",
            r#"{"module": "ci-baseline", "version": "1.0.0", "answers": {}}"#,
        ),
        (
            ".agent-setup/modules/qa.json",
            r#"{"module": "qa", "version": "1.0.0", "answers": {"web": "seeded", "web_start": "npm run dev"}}"#,
        ),
        ("qa/web/smoke.spec.ts", SCREENSHOT_SPEC),
        (
            "qa/web/smoke.spec.ts-snapshots/home-chromium-linux.png",
            PNG,
        ),
        (GATE, GATE_YML),
    ]);
    assert_eq!(of(&qa(&dir), "qa.snapshots-protected"), Vec::<&str>::new());
    // Another web_dir: the derived glob moves with it and no longer names this one.
    write(
        &dir,
        &[(
            ".agent-setup/modules/qa.json",
            r#"{"module": "qa", "version": "1.0.0", "answers": {"web": "seeded", "web_start": "npm run dev", "web_dir": "ui"}}"#,
        )],
    );
    assert_eq!(of(&qa(&dir), "qa.snapshots-protected").len(), 1);
}

#[test]
fn a_library_repository_has_the_four_not_required() {
    let dir = repo(&[
        ("Cargo.toml", "[dependencies]\nserde = \"1\"\n"),
        (
            CI,
            "on: [push]\njobs:\n  test:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: cargo test\n",
        ),
    ]);
    assert_eq!(qa(&dir), Vec::<String>::new());
    let rules = qa_rules(&dir);
    for id in SILVER {
        assert_eq!(status_of(&rules, id), "not-required", "{id}: {rules:?}");
    }
}

/// The highest level whose `qa.*` rules all passed or are not required;
/// `unavailable` rules (`qa.main-green` without `--remote`) are unverified, not gaps.
fn qa_level(rules: &[(String, String, String)]) -> Option<Level> {
    let level_of = |id: &str| REGISTRY.iter().find(|r| r.id == id).unwrap().level;
    [Level::Bronze, Level::Silver]
        .into_iter()
        .take_while(|level| {
            rules.iter().all(|(id, status, _)| {
                level_of(id) > *level
                    || ["passed", "not-required", "unavailable"].contains(&status.as_str())
            })
        })
        .last()
}

/// A rust repository installed with qa (`api` and a seeded `web`) by the
/// binary, its baseline committed: what T6–T8 render.
fn installed() -> TempDir {
    let dir = repo(&[]);
    let cli = |args: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_brakes"))
            .args(args)
            .output()
            .unwrap();
        assert!(out.status.success(), "{args:?}: {out:?}");
    };
    let root = dir.path().to_str().unwrap();
    cli(&["install", root, "--new-personal", "--apply"]);
    let profile_path = ".agent-setup/project.json";
    let mut profile: Value = serde_json::from_str(&read(&dir, profile_path)).unwrap();
    profile["commands"]["test"] = "cargo test --locked".into();
    write(
        &dir,
        &[
            (
                profile_path,
                &(serde_json::to_string_pretty(&profile).unwrap() + "\n"),
            ),
            ("Cargo.toml", ""),
            ("Cargo.lock", ""),
            (
                ".agent-setup/modules/stack-packs.json",
                r#"{"module": "stack-packs", "version": "1.0.0", "answers": {"apps.root.path": ".", "apps.root.stack": "rust", "apps.root.container": false}}"#,
            ),
            (
                ".agent-setup/modules/qa.json",
                r#"{"module": "qa", "version": "1.0.0", "answers": {"api": true, "api_start": "cargo run", "web": "seeded", "web_start": "npm run dev"}}"#,
            ),
        ],
    );
    cli(&[
        "install",
        root,
        "--module",
        "stack-packs",
        "--module",
        "ci-baseline",
        "--module",
        "qa",
        "--apply",
    ]);
    write(
        &dir,
        &[(
            "qa/web/smoke.spec.ts-snapshots/home-chromium-linux.png",
            PNG,
        )],
    );
    dir
}

#[test]
fn a_repository_installed_by_t6_to_t8_passes_the_four_and_reaches_silver() {
    let dir = installed();
    assert_eq!(qa(&dir), Vec::<String>::new());
    let rules = qa_rules(&dir);
    for id in SILVER.iter().chain(BRONZE.iter()) {
        assert_eq!(status_of(&rules, id), "passed", "{id}: {rules:?}");
    }
    assert_eq!(qa_level(&rules), Some(Level::Silver), "{rules:?}");
}

#[test]
fn a_caret_playwright_keeps_the_module_below_silver() {
    let dir = installed();
    write(
        &dir,
        &[(
            "qa/web/package.json",
            r#"{"private": true, "devDependencies": {"@playwright/test": "^1.64.0"}}"#,
        )],
    );
    let rules = qa_rules(&dir);
    assert_eq!(status_of(&rules, "qa.tools-pinned"), "failed");
    assert!(qa_level(&rules) < Some(Level::Silver), "{rules:?}");
    assert!(qa_level(&rules) <= Some(Level::Bronze), "{rules:?}");
}

/// T19 (#1018): `qa.main-green` reads the host; `doctor` without `--remote` reports
/// it unavailable with the reason the other remote rules give.
#[test]
fn main_green_needs_doctor_remote() {
    let dir = aggregate(&[]);
    let rules = qa_rules(&dir);
    let (_, status, reason) = rules.iter().find(|(r, _, _)| r == "qa.main-green").unwrap();
    assert_eq!(
        (status.as_str(), reason.as_str()),
        (
            "unavailable",
            "remote findings run only with doctor --remote"
        )
    );
}

// --- doctor --------------------------------------------------------------------------

#[test]
fn doctor_prints_warnings_never_not_ready_and_keeps_its_exit_code() {
    let clean = aggregate(&[]);
    let dirty = aggregate(&[
        ("qa/api/10-x.hurl", "GET https://example.com/x\n"),
        (
            "package.json",
            r#"{"devDependencies": {"@playwright/test": "^1.64.0"}}"#,
        ),
    ]);
    let before = doctor(&clean, &[]);
    let after = doctor(&dirty, &[]);
    let text = String::from_utf8(after.stdout).unwrap();
    assert!(
        text.lines()
            .any(|l| l.starts_with("WARNING: qa.hurl-no-literal-host: qa/api/10-x.hurl:1 ")),
        "{text}"
    );
    assert!(!text.contains("NOT READY: qa."), "{text}");
    assert!(!text.contains("NOT READY: WARNING: qa."), "{text}");
    assert_eq!(after.status.code(), before.status.code());
}

#[test]
fn doctor_json_carries_the_rules_in_findings_and_matches_the_golden_file() {
    let dir = aggregate(&[
        ("qa/api/10-x.hurl", "# x\nGET https://example.com/x\n"),
        (
            "package.json",
            r#"{"devDependencies": {"@playwright/test": "^1.64.0"}}"#,
        ),
    ]);
    let ci = read(&dir, CI).replace(
        "npx playwright test",
        "npx playwright test --update-snapshots",
    );
    write(&dir, &[(CI, &ci)]);
    let out = doctor(&dir, &["--json"]);
    let document: Value = serde_json::from_slice(&out.stdout).unwrap();
    let findings: Vec<Value> = document["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f.as_str().unwrap().contains(" qa."))
        .cloned()
        .collect();
    let rules: Vec<Value> = qa_rules(&dir)
        .into_iter()
        .map(|(id, status, said)| json!({"id": id, "status": status, "said": said}))
        .collect();
    let actual = serde_json::to_string_pretty(&json!({"findings": findings, "rules": rules}))
        .unwrap()
        + "\n";
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/qa/doctor.json");
    if std::env::var_os("UPDATE_GOLDENS").is_some() {
        fs::create_dir_all(Path::new(path).parent().unwrap()).unwrap();
        fs::write(path, &actual).unwrap();
    }
    let expected = fs::read_to_string(path).unwrap();
    assert_eq!(actual, expected, "{path} drifted; actual:\n{actual}");
}

#[test]
fn the_protected_path_matcher_reads_globs_as_the_scope_job_does() {
    use audit::case_match;
    assert!(case_match(
        "**/*-snapshots/**",
        "smoke.spec.ts-snapshots/home.png"
    ));
    assert!(case_match(
        "**/*-snapshots/**",
        "apps/web/e2e/a.spec.ts-snapshots/x.png"
    ));
    assert!(case_match(
        "qa/web/*-snapshots/**",
        "qa/web/smoke.spec.ts-snapshots/x.png"
    ));
    // `*` crosses `/` as in a shell `case`.
    assert!(case_match(
        "qa/web/*-snapshots/**",
        "qa/web/deep/a.spec.ts-snapshots/x.png"
    ));
    assert!(!case_match(
        "qa/web/*-snapshots/**",
        "ui/smoke.spec.ts-snapshots/x.png"
    ));
    assert!(!case_match(
        ".github/workflows/**",
        "qa/web/smoke.spec.ts-snapshots/x.png"
    ));
}

// --- contracts (T17, #1016) --------------------------------------------------------

const OPENAPI: &str = "openapi: 3.1.0\ninfo:\n  title: Shop\n  version: 1.0.0\npaths: {}\n";
const CONTRACTS_GOLDEN: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../templates/qa/goldens/contracts-openapi.yml"
);
const LINT_TEXT: &str =
    "WARNING: qa.contract-lint: Contract docs/openapi.yaml is not linted in the aggregate";
const COMPATIBLE_TEXT: &str = "WARNING: qa.contract-compatible: Contract docs/openapi.yaml has no backwards-compatibility check against the base branch";

fn rule_lines(found: &[String], rule: &str) -> Vec<String> {
    found
        .iter()
        .filter(|f| f.starts_with(&format!("WARNING: {rule}: ")))
        .cloned()
        .collect()
}

/// A workflow whose aggregate needs `job`, a job running `run` with `env`.
fn workflow_with(job: &str, run: &str, env: &str) -> String {
    format!(
        "name: CI\non: [pull_request]\npermissions:\n  contents: read\njobs:\n  {job}:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 10\n    steps:\n      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02\n        with:\n          path: junit.xml\n      - run: {run}\n{env}  required:\n    if: always()\n    needs: [{job}]\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    steps:\n      - run: echo done\n"
    )
}

#[test]
fn our_qa_contracts_job_passes_both_contract_rules_and_the_bronze_ones() {
    let golden = std::fs::read_to_string(CONTRACTS_GOLDEN).unwrap();
    let dir = repo(&[("docs/openapi.yaml", OPENAPI), (CI, &golden)]);
    assert_eq!(qa(&dir), Vec::<String>::new());
    let rules = qa_rules(&dir);
    for id in [
        "qa.contract-lint",
        "qa.contract-compatible",
        "qa.tools-pinned",
        "qa.report-artifact",
        "qa.no-snapshot-update-in-ci",
    ] {
        assert_eq!(status_of(&rules, id), "passed", "{id}: {rules:?}");
    }
}

#[test]
fn spectral_and_oasdiff_run_by_hand_in_the_aggregate_pass() {
    let ci = workflow_with(
        "contracts",
        "spectral lint docs/openapi.yaml && oasdiff breaking --fail-on ERR base.yaml \"$SPEC\"",
        "        env:\n          SPEC: docs/openapi.yaml\n",
    );
    let dir = repo(&[("docs/openapi.yaml", OPENAPI), (CI, &ci)]);
    let found = qa(&dir);
    assert_eq!(
        rule_lines(&found, "qa.contract-lint"),
        Vec::<String>::new(),
        "{found:?}"
    );
    assert_eq!(
        rule_lines(&found, "qa.contract-compatible"),
        Vec::<String>::new(),
        "{found:?}"
    );
}

#[test]
fn a_contract_with_no_job_fails_both_rules() {
    let dir = aggregate(&[("docs/openapi.yaml", OPENAPI)]);
    assert_eq!(qa(&dir), [LINT_TEXT, COMPATIBLE_TEXT]);
    let rules = qa_rules(&dir);
    assert_eq!(status_of(&rules, "qa.contract-lint"), "failed");
    assert_eq!(status_of(&rules, "qa.contract-compatible"), "failed");
    // A linter outside the aggregate, or one that names another file, does not count.
    let ci = workflow_with(
        "contracts",
        "vacuum lint other.yaml && oasdiff breaking base.yaml other.yaml",
        "",
    );
    let dir = repo(&[("docs/openapi.yaml", OPENAPI), (CI, &ci)]);
    assert_eq!(qa(&dir), [LINT_TEXT, COMPATIBLE_TEXT]);
    // oasdiff without --fail-on never fails a run.
    let ci = workflow_with(
        "contracts",
        "vacuum lint docs/openapi.yaml && oasdiff breaking base.yaml docs/openapi.yaml",
        "",
    );
    let dir = repo(&[("docs/openapi.yaml", OPENAPI), (CI, &ci)]);
    assert_eq!(qa(&dir), [COMPATIBLE_TEXT]);
}

#[test]
fn without_a_contract_both_rules_are_not_required() {
    let dir = aggregate(&[("docs/guide.yaml", "title: not a contract\n")]);
    assert_eq!(
        rule_lines(&qa(&dir), "qa.contract-lint"),
        Vec::<String>::new()
    );
    let rules = qa_rules(&dir);
    assert_eq!(status_of(&rules, "qa.contract-lint"), "not-required");
    assert_eq!(status_of(&rules, "qa.contract-compatible"), "not-required");
}

#[test]
fn contract_tools_unpinned_are_reported() {
    let finding = |name: &str| {
        format!(
            "WARNING: qa.tools-pinned: QA tool {name} in {CI} is not pinned by checksum or exact version"
        )
    };
    for (run, name) in [
        (
            "npx @asyncapi/cli validate docs/asyncapi.yaml",
            "@asyncapi/cli",
        ),
        (
            "npm install -g @asyncapi/cli@latest && asyncapi validate docs/asyncapi.yaml",
            "@asyncapi/cli",
        ),
        (
            "curl -fsSL https://example.invalid/vacuum.sh | sh && vacuum lint docs/openapi.yaml",
            "vacuum",
        ),
        (
            "curl -fsSLO https://example.invalid/oasdiff.tar.gz && oasdiff breaking --fail-on ERR a.yaml docs/openapi.yaml",
            "oasdiff",
        ),
    ] {
        let dir = repo(&[
            ("docs/openapi.yaml", OPENAPI),
            (CI, &workflow_with("contracts", run, "")),
        ]);
        assert_eq!(
            rule_lines(&qa(&dir), "qa.tools-pinned"),
            [finding(name)],
            "{run}"
        );
    }
    // An exact version, inline or through the step's env, is pinned.
    for (run, env) in [
        (
            "npm install --ignore-scripts @asyncapi/cli@6.2.1 && asyncapi validate docs/asyncapi.yaml",
            "",
        ),
        (
            "npm install --ignore-scripts \"@asyncapi/cli@$CLI\" && asyncapi validate docs/asyncapi.yaml",
            "        env:\n          CLI: 6.2.1\n",
        ),
    ] {
        let dir = repo(&[
            ("docs/openapi.yaml", OPENAPI),
            (CI, &workflow_with("contracts", run, env)),
        ]);
        assert_eq!(
            rule_lines(&qa(&dir), "qa.tools-pinned"),
            Vec::<String>::new(),
            "{run}"
        );
    }
}

#[test]
fn a_contracts_job_without_an_upload_keeps_no_report() {
    let golden = std::fs::read_to_string(CONTRACTS_GOLDEN).unwrap();
    let start = golden
        .find("      - name: Upload the contracts report")
        .unwrap();
    let end = golden[start..].find("  required:").unwrap() + start;
    let ci = format!("{}{}", &golden[..start], &golden[end..]);
    let dir = repo(&[("docs/openapi.yaml", OPENAPI), (CI, &ci)]);
    assert_eq!(
        rule_lines(&qa(&dir), "qa.report-artifact"),
        [
            "WARNING: qa.report-artifact: QA job qa-contracts keeps no report: failures cannot be inspected"
        ]
    );
}

// --- per-app contracts (#1115) ------------------------------------------------------

const MONOREPO_GOLDEN: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../templates/qa/goldens/contracts-monorepo.yml"
);
const ASYNCAPI: &str = "asyncapi: 3.0.0\ninfo:\n  title: Events\n  version: 1.0.0\n";

#[test]
fn app_jobs_running_from_the_app_satisfy_both_contract_rules() {
    let golden = std::fs::read_to_string(MONOREPO_GOLDEN).unwrap();
    let dir = repo(&[
        ("apps/shop/docs/openapi.yaml", OPENAPI),
        ("apps/events/asyncapi.yaml", ASYNCAPI),
        (CI, &golden),
    ]);
    let found = qa(&dir);
    assert_eq!(
        rule_lines(&found, "qa.contract-lint"),
        Vec::<String>::new(),
        "{found:?}"
    );
    assert_eq!(
        rule_lines(&found, "qa.contract-compatible"),
        Vec::<String>::new(),
        "{found:?}"
    );
}

#[test]
fn a_job_from_another_app_does_not_cover_a_contract() {
    // shop's job names `docs/openapi.yaml` from apps/shop; a contract at the
    // same relative path in another app is not covered by it.
    let golden = std::fs::read_to_string(MONOREPO_GOLDEN).unwrap();
    let dir = repo(&[
        ("apps/shop/docs/openapi.yaml", OPENAPI),
        ("apps/other/docs/openapi.yaml", OPENAPI),
        (CI, &golden),
    ]);
    let found = qa(&dir);
    assert_eq!(
        rule_lines(&found, "qa.contract-lint"),
        [
            "WARNING: qa.contract-lint: Contract apps/other/docs/openapi.yaml is not linted in the aggregate"
        ],
        "{found:?}"
    );
}

// --- several contracts per target (#1182) ----------------------------------------------

const LIVE_A: &str = "contratos/ventas/openapi.json";
const LIVE_B: &str = "contratos/precios/openapi.json";
const PUBLISHED_A: &str = "contratos/ventas/publicado/v1.openapi.json";
const PUBLISHED_B: &str = "contratos/precios/publicado/v1.openapi.json";
const OPENAPI_JSON: &str =
    "{\"openapi\": \"3.1.0\", \"info\": {\"title\": \"x\", \"version\": \"1\"}, \"paths\": {}}\n";

/// A Rust root app with two live contracts and their published copies, qa
/// answering `qa_answers`, ci-baseline running `verify`, and `ci` as the workflow.
fn several(qa_answers: &str, ci: &str) -> TempDir {
    let qa_file = format!(r#"{{"module": "qa", "version": "1.0.0", "answers": {qa_answers}}}"#);
    repo(&[
        ("Cargo.toml", "[package]\nname = \"x\"\n"),
        ("Cargo.lock", ""),
        (
            ".agent-setup/project.json",
            r#"{"purpose": "x", "generated_paths": [], "environment_notes": [], "conventions": [], "commands": {"verify": "bash scripts/verify.sh", "test": null, "lint": null, "build": null}}"#,
        ),
        (
            ".agent-setup/modules/stack-packs.json",
            r#"{"module": "stack-packs", "version": "1.0.0", "answers": {"apps.root.path": ".", "apps.root.stack": "rust", "apps.root.container": false}}"#,
        ),
        (
            ".agent-setup/modules/ci-baseline.json",
            r#"{"module": "ci-baseline", "version": "1.0.0", "answers": {"commands": ["verify"], "workflow": "generate"}}"#,
        ),
        (".agent-setup/modules/qa.json", &qa_file),
        (LIVE_A, OPENAPI_JSON),
        (LIVE_B, OPENAPI_JSON),
        (PUBLISHED_A, OPENAPI_JSON),
        (PUBLISHED_B, OPENAPI_JSON),
        (CI, ci),
    ])
}

/// A contracts job of the aggregate running `contracts-check.sh` with `QA_OPENAPI: <list>`.
fn check_job(list: &str) -> String {
    workflow_with(
        "contracts",
        "bash contracts-check.sh",
        &format!("        env:\n          QA_OPENAPI: \"{list}\"\n"),
    )
}

fn lint_of(path: &str) -> String {
    format!("WARNING: qa.contract-lint: Contract {path} is not linted in the aggregate")
}

fn compatible_of(path: &str) -> String {
    format!(
        "WARNING: qa.contract-compatible: Contract {path} has no backwards-compatibility check against the base branch"
    )
}

#[test]
fn answering_one_contract_never_hides_another_live_one() {
    let dir = several(&format!(r#"{{"openapi": "{LIVE_A}"}}"#), &check_job(LIVE_A));
    let found = qa(&dir);
    for unchecked in [LIVE_B, PUBLISHED_A, PUBLISHED_B] {
        assert!(
            found.contains(&lint_of(unchecked)),
            "{unchecked}: {found:?}"
        );
        assert!(
            found.contains(&compatible_of(unchecked)),
            "{unchecked}: {found:?}"
        );
    }
    assert!(!found.contains(&lint_of(LIVE_A)), "{found:?}");
}

#[test]
fn answering_none_keeps_every_document_a_finding() {
    let dir = several(r#"{"openapi": "none"}"#, &workflow_with("x", "true", ""));
    let found = qa(&dir);
    for path in [LIVE_A, LIVE_B, PUBLISHED_A, PUBLISHED_B] {
        assert!(found.contains(&lint_of(path)), "{path}: {found:?}");
    }
}

#[test]
fn a_list_in_the_env_and_declared_published_copies_clear_both_rules() {
    let answers = format!(
        r#"{{"openapi": "{LIVE_A},{LIVE_B}", "contract_published": "{LIVE_A}={PUBLISHED_A},{LIVE_B}={PUBLISHED_B}"}}"#
    );
    let dir = several(&answers, &check_job(&format!("{LIVE_A},{LIVE_B}")));
    let found = qa(&dir);
    assert_eq!(
        rule_lines(&found, "qa.contract-lint"),
        Vec::<String>::new(),
        "{found:?}"
    );
    assert_eq!(
        rule_lines(&found, "qa.contract-compatible"),
        Vec::<String>::new(),
        "{found:?}"
    );
    // Without the declaration the published copies are documents nothing checks.
    let dir = several(
        &format!(r#"{{"openapi": "{LIVE_A},{LIVE_B}"}}"#),
        &check_job(&format!("{LIVE_A},{LIVE_B}")),
    );
    let found = qa(&dir);
    assert_eq!(
        rule_lines(&found, "qa.contract-lint"),
        [lint_of(PUBLISHED_B), lint_of(PUBLISHED_A)],
        "{found:?}"
    );
}

#[test]
fn a_declared_compatibility_command_is_the_only_way_a_project_check_counts() {
    let lint_only = workflow_with(
        "contracts",
        &format!("vacuum lint {LIVE_A} && vacuum lint {LIVE_B}"),
        "",
    );
    let published = format!("{LIVE_A}={PUBLISHED_A},{LIVE_B}={PUBLISHED_B}");
    // Undeclared, `verify` running in required is not guessed to compare contracts.
    let dir = several(
        &format!(r#"{{"openapi": "{LIVE_A},{LIVE_B}", "contract_published": "{published}"}}"#),
        &lint_only,
    );
    assert_eq!(
        rule_lines(&qa(&dir), "qa.contract-compatible"),
        [compatible_of(LIVE_B), compatible_of(LIVE_A)]
    );
    // Declared, it counts for the listed contracts.
    let dir = several(
        &format!(
            r#"{{"openapi": "{LIVE_A},{LIVE_B}", "contract_published": "{published}", "contract_compat_by": "verify"}}"#
        ),
        &lint_only,
    );
    let found = qa(&dir);
    assert_eq!(found, Vec::<String>::new(), "{found:?}");
    // A declaration that does not load (verify not run by required) counts for nothing.
    write(
        &dir,
        &[(
            ".agent-setup/modules/ci-baseline.json",
            r#"{"module": "ci-baseline", "version": "1.0.0", "answers": {"commands": ["lint"], "workflow": "generate"}}"#,
        )],
    );
    let found = qa(&dir);
    assert!(
        found.contains(&compatible_of(LIVE_A)) && found.contains(&lint_of(PUBLISHED_A)),
        "{found:?}"
    );
}
