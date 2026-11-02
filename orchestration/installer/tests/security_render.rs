//! security T4 (#790): the `Module` impl — answers, seeds and the managed guide.
//! #891: the module in `modules::all()` and `install --module security` through the
//! binary, with the real `ci-baseline` and `stack-packs`.
//!
//! The seed and guide fixture plans through the engine with an explicit list:
//! `setup-core`, `stack-packs`, a stand-in `ci-baseline` that renders nothing, and
//! `security`, so its plans hold the module's own paths and no `ci.yml`.
mod common;
mod configured;
mod support;

use brakes::engine::answers::{self, Answers, AnswersFile};
use brakes::engine::{self, CiJob, CiTier, Context, Module, Note, Ownership, Planned, Rendered};
use brakes::modules::ci_baseline::CiBaseline;
use brakes::modules::security::exceptions::{
    self, GITLEAKS_CONFIG, INVENTORY, NativeEntry, OSV_CONFIG, SEMGREP_IGNORE, Shape, TRIVY_IGNORE,
};
use brakes::modules::security::jobs::{
    self, CONTAINER_SCAN, COVERAGE_RATCHET, ContainerScan, DELIVERY, DEPS_SCAN, GITLEAKS_SCAN,
    MUTATION_DIFF, SAST, SECURITY_GATE, Sast,
};
use brakes::modules::security::pii::{self, DSAR_PATH, PII_PATH};
use brakes::modules::security::pins::{
    ACTIONLINT_HOOK, GITLEAKS, GITLEAKS_HOOK_REV, OSV_SCANNER, PRE_COMMIT_HOOKS, SEMGREP, TRIVY,
};
use brakes::modules::security::{
    GUIDE, GUIDE_PATH, LEFTHOOK_PATH, PII_SEED, PRE_COMMIT_PATH, SECURITY, Security, deps_scan,
};
use brakes::modules::stack_packs::PinTable;
use brakes::modules::stack_packs::StackId;
use brakes::modules::{self, StackPacks};
use brakes::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use support::SetupCore;
use tempfile::TempDir;

struct CiBaselineStandIn;
impl Module for CiBaselineStandIn {
    fn id(&self) -> &'static str {
        "ci-baseline"
    }
    fn version(&self) -> &'static str {
        "0.0.0"
    }
    fn render(&self, _cx: &Context<'_>) -> brakes::Result<Vec<Rendered>> {
        Ok(Vec::new())
    }
}

const SEEDS: [&str; 5] = [
    INVENTORY,
    GITLEAKS_CONFIG,
    OSV_CONFIG,
    TRIVY_IGNORE,
    SEMGREP_IGNORE,
];

struct Repo {
    _temp: TempDir,
    root: PathBuf,
}

impl Repo {
    /// A git repository with a sample client hook, so `.git/hooks` is not empty.
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("project");
        fs::create_dir(&root).unwrap();
        let status = Command::new("git")
            .args(["init", "-q"])
            .arg(&root)
            .status()
            .unwrap();
        assert!(status.success());
        fs::write(
            root.join(".git/hooks/pre-commit"),
            "#!/bin/sh\necho owner hook\n",
        )
        .unwrap();
        Self { _temp: temp, root }
    }
    fn write(&self, path: &str, text: &str) {
        let full = self.root.join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, text).unwrap();
    }
    fn read(&self, path: &str) -> String {
        fs::read_to_string(self.root.join(path)).unwrap()
    }
    fn exists(&self, path: &str) -> bool {
        self.root.join(path).exists()
    }
    fn answer(&self, module: &str, raw: Value) {
        let file = AnswersFile {
            module: module.to_owned(),
            version: "1.0.0".to_owned(),
            profile: None,
            answers: serde_json::from_value(raw).unwrap(),
        };
        self.write(&answers::path(module), &file.to_json_string().unwrap());
    }
    fn modules(&self) -> [&'static dyn Module; 4] {
        [&SetupCore, &StackPacks, &CiBaselineStandIn, &Security]
    }
    fn plan(&self) -> Result<Planned> {
        let profile = profile_for(&self.root)?;
        engine::plan(
            &self.root,
            &Source::embedded(),
            &profile,
            &self.modules(),
            &|_| true,
        )
    }
    fn install(&self) -> Planned {
        let planned = self.plan().unwrap();
        apply(&self.root, &planned.changes).unwrap();
        planned
    }
    fn configure(&self, sets: &[&str]) -> Result<Planned> {
        let profile = profile_for(&self.root)?;
        let schema = Security.questions();
        let mut patch = Answers::new();
        for set in sets {
            let (key, value) = answers::parse_set(&schema, set)?;
            patch.insert(key, value);
        }
        let planned = engine::configure(
            &self.root,
            &Source::embedded(),
            &profile,
            &self.modules(),
            &|_| true,
            SECURITY,
            &patch,
        )?;
        apply(&self.root, &planned.changes)?;
        Ok(planned)
    }
    fn remove(&self) -> Planned {
        let planned = engine::remove(&self.root, &self.modules(), &|_| true, SECURITY).unwrap();
        apply(&self.root, &planned.changes).unwrap();
        planned
    }
    /// One digest over every file under `.git/hooks` and `.git/config`, path and bytes.
    fn git_hooks_digest(&self) -> String {
        let mut files = Vec::new();
        collect(&self.root.join(".git/hooks"), &mut files);
        files.push(self.root.join(".git/config"));
        files.sort();
        let mut hasher = Sha256::new();
        for file in files {
            hasher.update(
                file.strip_prefix(&self.root)
                    .unwrap()
                    .to_string_lossy()
                    .as_bytes(),
            );
            hasher.update(fs::read(&file).unwrap());
        }
        format!("{:x}", hasher.finalize())
    }
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect(&path, out);
        } else {
            out.push(path);
        }
    }
}

/// The line `main.rs` prints for a noted path after `--apply`: the engine puts
/// class and module after the path (tasks/plan.md, engine decisions), the spec's
/// `SKIP [seed:security] <path>` with the same information.
fn note_lines(planned: &Planned) -> Vec<String> {
    planned
        .notes
        .iter()
        .map(|(path, note)| {
            let (class, module) = &planned.tags[path];
            format!("{note} {path} [{class}:{module}]")
        })
        .collect()
}

fn security_paths(planned: &Planned) -> Vec<(String, Ownership)> {
    planned
        .tags
        .iter()
        .filter(|(_, (_, module))| module == SECURITY)
        .map(|(path, (class, _))| (path.clone(), *class))
        .collect()
}

// ---- the module -------------------------------------------------------------------

#[test]
fn module_is_registered_after_agent_guardrails_and_before_ci_baseline() {
    assert_eq!(Security.id(), "security");
    assert_eq!(Security.version(), "1.0.0");
    assert_eq!(Security.requires(), ["ci-baseline", "stack-packs"]);
    assert_eq!(
        modules::find("security").map(|m| m.version()),
        Some("1.0.0")
    );
    let ids: Vec<&str> = modules::all().iter().map(|m| m.id()).collect();
    assert_eq!(
        ids,
        crate::support::with_core(&[
            "stack-packs",
            "merge-guard",
            "repo-baseline",
            "agent-guardrails",
            "security",
            "qa",
            "ci-baseline"
        ])
    );
}

#[test]
fn questions_are_the_slice_one_answers_with_their_defaults() {
    let schema = Security.questions();
    schema.check(SECURITY).unwrap();
    let ids: Vec<&str> = schema.questions.iter().map(|q| q.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "secrets_scanner",
            "deps",
            "hooks",
            "bypass_max_days",
            "sast",
            "container_scan",
            "severity",
            "pii",
            "coverage_ratchet",
            "coverage_tolerance",
            "coverage_changed_lines",
            "coverage_changed_lines_min",
            "coverage_source",
            "coverage_runner",
            "coverage_test_args.*",
            "mutation_diff",
            "mutation_min_score"
        ]
    );
    let validated = schema
        .validate(SECURITY, &Answers::new(), answers::DEFAULT_TIER)
        .unwrap();
    assert_eq!(validated["secrets_scanner"], json!("gitleaks"));
    assert_eq!(validated["deps"], json!(true));
    assert_eq!(validated["hooks"], json!("pre-commit-config"));
    assert_eq!(validated["bypass_max_days"], json!(30));
    for (key, value) in [
        ("hooks", json!("husky")),
        ("secrets_scanner", json!("trufflehog")),
        ("bypass_max_days", json!(0)),
        ("bypass_max_days", json!(31)),
    ] {
        let raw = Answers::from([(key.to_owned(), value.clone())]);
        assert!(
            schema
                .validate(SECURITY, &raw, answers::DEFAULT_TIER)
                .is_err(),
            "{key}={value} accepted"
        );
    }
}

#[test]
fn betterleaks_refuses_at_plan_time_with_the_spec_message() {
    let repo = Repo::new();
    repo.answer(SECURITY, json!({"secrets_scanner": "betterleaks"}));
    let error = repo.plan().unwrap_err().to_string();
    assert_eq!(
        error,
        "Module security: secrets_scanner betterleaks refuses until SPEC-security.md Open question 1 is resolved and its pin exists; use gitleaks"
    );
    let configured = Repo::new();
    configured.install();
    let error = configured
        .configure(&["secrets_scanner=betterleaks"])
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("secrets_scanner betterleaks refuses"),
        "{error}"
    );
}

// ---- deps and packs(cx) -----------------------------------------------------------

fn deps_for(repo: &Repo, security: Value) -> bool {
    let raw: Answers = serde_json::from_value(security).unwrap();
    let validated = Security
        .questions()
        .validate(SECURITY, &raw, answers::DEFAULT_TIER)
        .unwrap();
    let profile = profile_for(&repo.root).unwrap();
    let source = Source::embedded();
    let previous = engine::installed_lock(&repo.root, "0.0.0", &|_| true)
        .unwrap()
        .unwrap_or(engine::Lock {
            schema: 2,
            version: "test".to_owned(),
            source_commit: None,
            source_dirty: false,
            personal_owner: brakes::config::current_owner(),
            modules: Default::default(),
            files: Default::default(),
        });
    // stack-packs' recorded answers, validated, as the engine resolves them.
    let packs_raw = answers::recorded(&repo.root, "stack-packs")
        .unwrap()
        .map(|file| file.answers)
        .unwrap_or_default();
    let resolved = std::collections::BTreeMap::from([(
        "stack-packs".to_owned(),
        StackPacks
            .questions()
            .validate("stack-packs", &packs_raw, answers::DEFAULT_TIER)
            .unwrap(),
    )]);
    let cx = Context::new(
        &repo.root, &profile, &source, &previous, &validated, &Security, &resolved,
    );
    deps_scan(&cx).unwrap()
}

#[test]
fn deps_applies_only_when_a_recorded_pack_declares_a_lockfile() {
    let repo = Repo::new();
    assert!(
        !deps_for(&repo, json!({})),
        "no stack-packs answers, no lockfile"
    );
    repo.write("ios/Package.swift", "");
    repo.answer(
        "stack-packs",
        json!({"apps.ios.path": "ios", "apps.ios.stack": "swift-ios"}),
    );
    assert!(
        !deps_for(&repo, json!({})),
        "swift-ios declares no lockfile"
    );
    repo.write("Cargo.toml", "");
    repo.write("Cargo.lock", "");
    repo.answer(
        "stack-packs",
        json!({"apps.ios.path": "ios", "apps.ios.stack": "swift-ios",
               "apps.root.path": ".", "apps.root.stack": "rust"}),
    );
    assert!(deps_for(&repo, json!({})));
    assert!(!deps_for(&repo, json!({"deps": false})));
}

// ---- seeds and the guide ----------------------------------------------------------

#[test]
fn first_install_writes_the_seeds_the_hook_config_and_the_managed_guide() {
    let repo = Repo::new();
    let planned = repo.install();
    let mut expected: Vec<(String, Ownership)> = SEEDS
        .iter()
        .chain([&PRE_COMMIT_PATH])
        .map(|p| ((*p).to_owned(), Ownership::Seed))
        .collect();
    expected.push((GUIDE_PATH.to_owned(), Ownership::Managed));
    // #854: the remote items, recorded in the lock and never written.
    for item in [
        "github:secret-scanning",
        "github:private-vulnerability-reporting",
    ] {
        expected.push((item.to_owned(), Ownership::Remote));
    }
    expected.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(security_paths(&planned), expected);
    assert!(!repo.exists(LEFTHOOK_PATH));
    let inventory: Value = serde_json::from_str(&repo.read(INVENTORY)).unwrap();
    assert_eq!(inventory, json!({"schema": 1, "exceptions": []}));
    assert!(
        repo.read(GITLEAKS_CONFIG)
            .contains("[extend]\nuseDefault = true\n")
    );
    assert!(repo.read(TRIVY_IGNORE).contains("\nvulnerabilities: []\n"));
    // The seeds are the generated shape: the exceptions check passes with nothing active.
    let report = exceptions::check(&repo.root, today(), 30).unwrap();
    assert!(report.passed(), "{:?}", report.findings);
    assert_eq!(
        report.claim(),
        "exceptions: 0 active, 0 expired, 0 unregistered"
    );
    // Idempotent: a second plan changes nothing.
    assert!(repo.plan().unwrap().changes.is_empty());
}

/// #1194: a root `.semgrepignore` replaces Semgrep CE's built-in list, so the
/// seed restates the pinned release's defaults verbatim and says so.
#[test]
fn the_semgrepignore_seed_restates_the_pinned_semgrep_defaults() {
    let repo = Repo::new();
    repo.install();
    let seed = repo.read(SEMGREP_IGNORE);
    assert!(
        seed.contains(&format!("Semgrep CE {}", SEMGREP.version)),
        "{seed}"
    );
    assert!(seed.contains("replaces"), "{seed}");
    let entries: Vec<&str> = seed
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    assert_eq!(entries, exceptions::SEMGREP_DEFAULTS);
}

#[test]
fn only_sast_semgrep_seeds_a_semgrepignore() {
    for sast in ["none", "codeql"] {
        let repo = Repo::new();
        repo.answer(SECURITY, json!({ "sast": sast }));
        if sast == "codeql" {
            repo.write("Cargo.toml", "");
            repo.write("Cargo.lock", "");
            repo.answer(
                "stack-packs",
                json!({"apps.root.path": ".", "apps.root.stack": "rust"}),
            );
        }
        repo.install();
        assert!(!repo.exists(SEMGREP_IGNORE), "sast {sast}");
    }
}

/// #1195: the example quotes `statement`; uncommented, it keeps its issue.
#[test]
fn the_trivyignore_example_keeps_its_issue_once_uncommented() {
    let repo = Repo::new();
    repo.install();
    let seed = repo.read(TRIVY_IGNORE);
    let example: String = seed
        .lines()
        .skip_while(|l| *l != "# vulnerabilities:")
        .take_while(|l| l.starts_with('#'))
        .map(|l| format!("{}\n", l.strip_prefix("# ").unwrap()))
        .collect();
    assert!(example.contains("statement: \""), "{example}");
    let Shape::Generated(entries) = exceptions::trivy_ignore(&example) else {
        panic!("the example is in the generated shape: {example}");
    };
    assert_eq!(
        entries,
        [NativeEntry {
            file: TRIVY_IGNORE,
            id: "CVE-2026-1234".to_owned(),
            expiry: Some("2026-12-01".to_owned()),
            issue: true,
        }]
    );
}

#[test]
fn the_guide_says_semgrepignore_replaces_the_defaults_and_statement_is_quoted() {
    for expected in [
        "replaces Semgrep's built-in default ignore list",
        "`statement` is always quoted",
        "never a recursive search",
    ] {
        assert!(GUIDE.contains(expected), "the guide lacks {expected}");
    }
}

#[test]
fn the_guide_carries_last_verified_and_the_four_topics() {
    let repo = Repo::new();
    repo.install();
    let guide = repo.read(GUIDE_PATH);
    assert!(last_verified(&guide).is_some(), "no Last verified line");
    for topic in [
        "## How the gates work",
        "## Adding an exception",
        "## Emergency bypass",
        "## Renewal is a new entry",
        "SECURITY_BYPASS",
        INVENTORY,
    ] {
        assert!(guide.contains(topic), "guide lacks {topic}");
    }
}

#[test]
fn existing_seeds_are_skipped_and_reported_and_stay_intact() {
    let repo = Repo::new();
    let mine = "# the project's own\n";
    for path in [PRE_COMMIT_PATH, GITLEAKS_CONFIG, INVENTORY] {
        repo.write(path, mine);
    }
    let planned = repo.install();
    let lines = note_lines(&planned);
    for path in [PRE_COMMIT_PATH, GITLEAKS_CONFIG, INVENTORY] {
        assert!(
            lines.contains(&format!("SKIP {path} [seed:security]")),
            "{lines:?}"
        );
        assert_eq!(repo.read(path), mine);
        assert!(!planned.changes.contains_key(path));
    }
}

#[test]
fn an_existing_seed_is_a_skip_note_of_class_seed() {
    let repo = Repo::new();
    repo.write(PRE_COMMIT_PATH, "repos: []\n");
    let planned = repo.plan().unwrap();
    assert_eq!(planned.notes[PRE_COMMIT_PATH], Note::Skip);
    assert_eq!(
        planned.tags[PRE_COMMIT_PATH],
        (Ownership::Seed, SECURITY.to_owned())
    );
}

#[test]
fn the_guide_refuses_when_edited() {
    let repo = Repo::new();
    repo.install();
    repo.write(GUIDE_PATH, &(repo.read(GUIDE_PATH) + "local edit\n"));
    let error = repo.plan().unwrap_err().to_string();
    assert_eq!(
        error,
        format!("Locally changed or missing managed content: {GUIDE_PATH}")
    );
}

#[test]
fn hooks_none_renders_no_hook_file() {
    let repo = Repo::new();
    repo.answer(SECURITY, json!({"hooks": "none"}));
    let planned = repo.install();
    let paths: Vec<String> = security_paths(&planned)
        .into_iter()
        .map(|(p, _)| p)
        .collect();
    assert!(!paths.contains(&PRE_COMMIT_PATH.to_owned()));
    assert!(!paths.contains(&LEFTHOOK_PATH.to_owned()));
    assert!(!repo.exists(PRE_COMMIT_PATH));
    assert!(!repo.exists(LEFTHOOK_PATH));
}

// ---- the hook seed ----------------------------------------------------------------

#[test]
fn pre_commit_seed_pins_gitleaks_to_the_release_commit_ci_installs() {
    let repo = Repo::new();
    repo.install();
    let seed = repo.read(PRE_COMMIT_PATH);
    assert!(
        seed.contains(&format!(
            "  - repo: https://github.com/gitleaks/gitleaks\n    rev: {GITLEAKS_HOOK_REV}  # frozen: v{}\n    hooks:\n      - id: gitleaks\n",
            GITLEAKS.version
        )),
        "{seed}"
    );
    assert!(seed.contains(&format!(
        "rev: {}  # frozen: v{}",
        PRE_COMMIT_HOOKS.rev, PRE_COMMIT_HOOKS.version
    )));
    for hook in [
        "detect-private-key",
        "check-added-large-files",
        "check-merge-conflict",
    ] {
        assert!(seed.contains(&format!("      - id: {hook}\n")), "{hook}");
    }
    assert!(!seed.contains("actionlint"), "no workflows, no actionlint");
}

#[test]
fn actionlint_joins_the_hook_seed_when_workflows_exist() {
    let repo = Repo::new();
    repo.write(".github/workflows/ci.yml", "on: push\n");
    repo.install();
    let seed = repo.read(PRE_COMMIT_PATH);
    assert!(seed.contains(&format!(
        "  - repo: https://github.com/rhysd/actionlint\n    rev: {}  # frozen: v{}\n    hooks:\n      - id: actionlint\n",
        ACTIONLINT_HOOK.rev, ACTIONLINT_HOOK.version
    )));
}

#[test]
fn lefthook_renders_lefthook_yml_naming_the_pinned_gitleaks() {
    let repo = Repo::new();
    repo.write(".github/workflows/ci.yml", "on: push\n");
    repo.answer(SECURITY, json!({"hooks": "lefthook"}));
    repo.install();
    assert!(!repo.exists(PRE_COMMIT_PATH));
    let seed = repo.read(LEFTHOOK_PATH);
    assert!(seed.contains(&format!(
        "gitleaks {} (commit {GITLEAKS_HOOK_REV})",
        GITLEAKS.version
    )));
    for command in [
        "gitleaks git --pre-commit --redact --staged --verbose",
        "detect-private-key {staged_files}",
        "check-added-large-files {staged_files}",
        "check-merge-conflict {staged_files}",
        "actionlint {staged_files}",
    ] {
        assert!(seed.contains(&format!("run: {command}\n")), "{command}");
    }
}

#[test]
fn hook_revs_are_full_commit_shas() {
    for rev in [GITLEAKS_HOOK_REV, PRE_COMMIT_HOOKS.rev, ACTIONLINT_HOOK.rev] {
        assert_eq!(rev.len(), 40, "{rev}");
        assert!(
            rev.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
    }
}

#[test]
fn renders_are_byte_identical() {
    let (a, b) = (Repo::new(), Repo::new());
    let (pa, pb) = (a.plan().unwrap(), b.plan().unwrap());
    for path in SEEDS.iter().chain([&PRE_COMMIT_PATH, &GUIDE_PATH]) {
        assert_eq!(pa.changes[*path], pb.changes[*path], "{path}");
    }
}

// ---- .git is never written --------------------------------------------------------

#[test]
fn git_hooks_are_byte_identical_across_install_configure_and_remove() {
    let repo = Repo::new();
    let before = repo.git_hooks_digest();
    repo.install();
    assert_eq!(repo.git_hooks_digest(), before, "install --apply");
    let configured = repo.configure(&["hooks=lefthook"]).unwrap();
    assert!(repo.exists(LEFTHOOK_PATH));
    // The retired hook seed is the project's now: kept and reported, never deleted.
    assert!(note_lines(&configured).contains(&format!("KEEP {PRE_COMMIT_PATH} [seed:security]")));
    assert!(repo.exists(PRE_COMMIT_PATH));
    assert_eq!(repo.git_hooks_digest(), before, "configure");
    let removed = repo.remove();
    assert_eq!(repo.git_hooks_digest(), before, "remove");
    // remove deletes the unchanged guide and lists the seeds.
    assert!(!repo.exists(GUIDE_PATH));
    let kept = note_lines(&removed);
    for path in SEEDS.iter().chain([&LEFTHOOK_PATH]) {
        assert!(
            kept.contains(&format!("KEEP {path} [seed:security]")),
            "{path}: {kept:?}"
        );
        assert!(repo.exists(path));
    }
}

// ---- T12 (#800): the PII pack --------------------------------------------------------

/// A seed-fixture repository whose profile declares `criticality`.
fn with_criticality(criticality: Option<&str>) -> Repo {
    let repo = Repo::new();
    repo.install();
    let path = ".agent-setup/project.json";
    let mut profile: Value = serde_json::from_str(&repo.read(path)).unwrap();
    match criticality {
        Some(c) => profile["criticality"] = json!(c),
        None => {
            profile.as_object_mut().unwrap().remove("criticality");
        }
    }
    repo.write(
        path,
        &(serde_json::to_string_pretty(&profile).unwrap() + "\n"),
    );
    repo
}

#[test]
fn pii_is_derived_from_the_criticality_and_false_refuses_under_personal_data() {
    let repo = with_criticality(None);
    assert!(!repo.exists(PII_PATH) && !repo.exists(DSAR_PATH));
    let planned = repo.plan().unwrap();
    assert!(
        !planned.changes.contains_key(PII_PATH),
        "undeclared: no pack"
    );

    let repo = with_criticality(Some("customers"));
    assert!(!repo.plan().unwrap().changes.contains_key(PII_PATH));
    repo.configure(&["pii=true"]).unwrap();
    assert!(
        repo.exists(PII_PATH) && repo.exists(DSAR_PATH),
        "opt-in anywhere"
    );
    assert_eq!(repo.read(PII_PATH), PII_SEED);

    let repo = with_criticality(Some("personal-data-or-payments"));
    let planned = repo.plan().unwrap();
    for path in [PII_PATH, DSAR_PATH] {
        assert_eq!(planned.tags[path], (Ownership::Seed, SECURITY.to_owned()));
    }
    apply(&repo.root, &planned.changes).unwrap();
    assert!(repo.exists(PII_PATH) && repo.exists(DSAR_PATH));
    let error = repo.configure(&["pii=false"]).unwrap_err().to_string();
    assert_eq!(
        error,
        "Module security: pii false refuses under criticality personal-data-or-payments; the PII declaration is required there"
    );
    // The schema question has no default: absent means derived.
    let question = Security
        .questions()
        .questions
        .into_iter()
        .find(|q| q.id == "pii")
        .unwrap();
    assert!(question.default.is_none());
}

#[test]
fn the_dsar_runbook_matches_its_golden_and_is_rendered_from_the_declaration() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/security/pii/valid/.agent-setup/pii.yaml");
    let declaration = match pii::parse(&fs::read_to_string(fixture).unwrap()) {
        exceptions::Shape::Generated(d) => d,
        exceptions::Shape::Unverified { line } => panic!("line {line}"),
    };
    let text = pii::runbook(&declaration);
    golden("dsar.md", &text);
    for expected in [
        "| `users.email` | users | contact | account lifetime + 30 days |",
        "| `users.password_hash` | users | credentials | account lifetime |",
        "| `invoices.vat_id` | invoices | financial | 6 years after the invoice |",
        "| `events.ip` | events | location | 90 days |",
        "controller: `Example Ltd`",
        "`privacy@example.test`",
        "`30` days from receipt",
    ] {
        assert!(text.contains(expected), "runbook lacks {expected}\n{text}");
    }
    assert!(!text.contains("{{"), "{text}");
    // A seeded repository renders the runbook from the seed: no field yet.
    let repo = with_criticality(Some("personal-data-or-payments"));
    repo.install();
    let seeded = repo.read(DSAR_PATH);
    assert_eq!(seeded.matches("| _none declared_ | | | |").count(), 3);
    assert!(seeded.contains("controller: `<legal entity>`"));
    // The runbook is a seed: the project's once written, so a later declaration
    // does not rewrite it; a fresh checkout with a declaration renders from it.
    repo.write(
        PII_PATH,
        &fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/security/pii/valid/.agent-setup/pii.yaml"),
        )
        .unwrap(),
    );
    fs::remove_file(repo.root.join(DSAR_PATH)).unwrap();
    repo.install();
    assert_eq!(repo.read(DSAR_PATH), text);
}

#[test]
fn the_pii_check_step_joins_security_gate_only_with_the_pack() {
    let composed = Composed::new();
    let text = composed.workflow();
    assert!(!text.contains("Check the PII declaration"), "{text}");
    composed.repo.answer(
        SECURITY,
        json!({"pii": true, "sast": "none", "container_scan": false}),
    );
    let text = composed.workflow();
    golden("pii.yml", &text);
    let blocks = job_blocks(&text);
    let gate = job(&blocks, SECURITY_GATE).join("\n");
    let at = gate
        .find("Check the PII declaration")
        .expect("the pii step");
    assert!(gate[..at].contains("Check the bypass inventory"));
    assert!(gate[at..].contains("Upload the gitleaks report"));
    // The shell is embedded without its comment-only lines (#1088).
    assert!(gate[at..].contains(&run_body(jobs::PII_CHECK)));
    assert!(!gate.contains("# pii-check.sh"));
    assert!(
        gate.contains(
            "    if: ${{ !cancelled() }}\n        run: |\n          #!/usr/bin/env bash\n"
        )
    );
    assert_eq!(text, composed.workflow(), "two renders differ");
}

// ---- T5 (#791): security-gate and deps-scan through ci_jobs ------------------------

const WORKFLOW: &str = ".github/workflows/ci.yml";
const GOLDENS: &str = "../../templates/security/goldens";

/// A contributor whose single job takes an id `security` already uses.
struct Squatter;
impl Module for Squatter {
    fn id(&self) -> &'static str {
        "fixture"
    }
    fn version(&self) -> &'static str {
        "1.0.0"
    }
    fn render(&self, _: &Context<'_>) -> Result<Vec<Rendered>> {
        Ok(Vec::new())
    }
    fn ci_jobs(&self, _: &Context<'_>) -> Vec<CiJob> {
        vec![CiJob {
            id: DEPS_SCAN.to_owned(),
            yaml: "name: deps-scan\nneeds: scope\nruns-on: ubuntu-24.04\ntimeout-minutes: 5\nsteps:\n  - name: Echo\n    run: echo\n".to_owned(),
            skippable_under: Vec::new(),
            app: None,
        }]
    }
}

/// A personal rust repository at `.` with setup-core installed, lint, test and
/// build declared and a lockfile, planned with the real `ci-baseline`.
struct Composed {
    repo: Repo,
}

impl Composed {
    fn new() -> Self {
        let repo = Repo::new();
        let out = Command::new(env!("CARGO_BIN_EXE_brakes"))
            .args([
                "install",
                &repo.root.to_string_lossy(),
                "--new-personal",
                "--apply",
            ])
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        let path = ".agent-setup/project.json";
        let mut profile: Value = serde_json::from_str(&repo.read(path)).unwrap();
        profile["commands"]["lint"] =
            "cargo clippy --workspace --all-targets --locked -- -D warnings".into();
        profile["commands"]["test"] = "cargo test --locked".into();
        profile["commands"]["build"] = "cargo build --locked".into();
        repo.write(
            path,
            &(serde_json::to_string_pretty(&profile).unwrap() + "\n"),
        );
        repo.write("Cargo.toml", "");
        repo.write("Cargo.lock", "");
        repo.answer(
            "stack-packs",
            json!({"apps.root.path": ".", "apps.root.stack": "rust"}),
        );
        // The slice-1 set: `sast` defaults to `semgrep` and `container_scan` applies
        // to a container app (T10), so both are answered off here.
        repo.answer(SECURITY, json!({"sast": "none", "container_scan": false}));
        Self { repo }
    }
    /// `Composed` with `security` answered `answers` and a root `Dockerfile`
    /// when `dockerfile`, the slice-2 shapes.
    fn with(answers: Value, dockerfile: bool) -> Self {
        let composed = Self::new();
        composed.repo.answer(SECURITY, answers);
        if dockerfile {
            composed.repo.write("Dockerfile", "FROM scratch\n");
        }
        composed
    }
    fn plan_with(&self, extra: &[&dyn Module]) -> Result<Planned> {
        let profile = profile_for(&self.repo.root)?;
        let modules: Vec<&dyn Module> = [&SetupCore as &dyn Module, &StackPacks, &Security]
            .into_iter()
            .chain(extra.iter().copied())
            .chain([&CiBaseline as &dyn Module])
            .collect();
        engine::plan(
            &self.repo.root,
            &Source::embedded(),
            &profile,
            &modules,
            &|_| true,
        )
    }
    fn workflow(&self) -> String {
        self.plan_with(&[]).unwrap().changes[WORKFLOW]
            .clone()
            .expect("ci.yml is written")
    }
    /// `reusable()` with `coverage_ratchet` answered and nothing else changed.
    fn reusable_with_ratchet(&self) -> String {
        self.repo
            .answer(SECURITY, json!({"coverage_ratchet": true}));
        self.reusable()
    }
    /// `agentic-coverage.yml`, where diff-coverage and coverage-ratchet live (#22).
    fn reusable(&self) -> String {
        self.plan_with(&[]).unwrap().changes[REUSABLE]
            .clone()
            .expect("agentic-coverage.yml is written")
    }
}

/// Compares `text` with the golden byte for byte; `UPDATE_GOLDENS=1` rewrites it.
fn golden(name: &str, text: &str) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(GOLDENS)
        .join(name);
    if std::env::var_os("UPDATE_GOLDENS").is_some() {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, text).unwrap();
    }
    let expected = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}; run with UPDATE_GOLDENS=1", path.display()));
    assert!(text == expected, "{name} differs from the golden:\n{text}");
}

fn minimal_golden() -> String {
    fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(GOLDENS)
            .join("minimal.yml"),
    )
    .unwrap()
}

/// The job blocks of a workflow: id -> its lines.
fn job_blocks(text: &str) -> Vec<(String, Vec<String>)> {
    let body = text.split_once("\njobs:\n").unwrap().1;
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    for line in body.lines() {
        if let Some(id) = line.strip_prefix("  ").filter(|l| !l.starts_with(' ')) {
            out.push((id.trim_end_matches(':').to_owned(), Vec::new()));
        } else {
            out.last_mut().unwrap().1.push(line.to_owned());
        }
    }
    out
}

fn job<'a>(blocks: &'a [(String, Vec<String>)], id: &str) -> &'a [String] {
    &blocks
        .iter()
        .find(|(j, _)| j == id)
        .unwrap_or_else(|| panic!("no job {id}"))
        .1
}

#[test]
fn the_composed_workflow_matches_the_minimal_golden() {
    let composed = Composed::new();
    let text = composed.workflow();
    golden("minimal.yml", &text);
    assert_eq!(text, composed.workflow(), "two renders differ");
}

#[test]
fn both_jobs_reach_required_through_ci_jobs() {
    let text = minimal_golden();
    let blocks = job_blocks(&text);
    let ids: Vec<&str> = blocks.iter().map(|(id, _)| id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "scope",
            "checks",
            "heldout",
            "workflow-lint",
            SECURITY_GATE,
            DEPS_SCAN,
            "required"
        ]
    );
    assert!(job(&blocks, "required").contains(
        &"    needs: [scope, checks, heldout, workflow-lint, security-gate, deps-scan]".to_owned()
    ));
    // DOCS_SKIPPABLE lists deps-scan and never security-gate.
    let scope = job(&blocks, "scope").join("\n");
    let docs = scope.split_once("DOCS_SKIPPABLE: |-\n").unwrap().1;
    let docs: Vec<&str> = docs
        .lines()
        .take_while(|l| l.starts_with("            "))
        .map(str::trim)
        .collect();
    assert_eq!(docs, ["checks", "heldout", DEPS_SCAN]);
    assert!(!scope.contains("security-gate"), "{scope}");
    let gate = job(&blocks, SECURITY_GATE);
    assert!(gate.contains(&"    needs: scope".to_owned()));
    assert!(!gate.iter().any(|l| l.starts_with("    if:")), "{gate:?}");
    assert!(gate.contains(&"    timeout-minutes: 10".to_owned()));
    let deps = job(&blocks, DEPS_SCAN);
    assert!(deps.contains(&"    needs: scope".to_owned()));
    assert!(deps.contains(&"    if: needs.scope.outputs.tier != 'docs'".to_owned()));
    assert!(deps.contains(&"    timeout-minutes: 10".to_owned()));
}

#[test]
fn ci_jobs_declares_the_skippable_tiers() {
    let composed = Composed::new();
    let planned = composed.plan_with(&[]).unwrap();
    let plan_notes: Vec<String> = planned
        .plan_notes
        .iter()
        .map(|n| format!("{} {}", n.module, n.text))
        .collect();
    for id in [SECURITY_GATE, DEPS_SCAN] {
        assert!(
            plan_notes.contains(&format!("ci-baseline JOB [security] {id} → {WORKFLOW}")),
            "{plan_notes:?}"
        );
    }
    let jobs = with_cx(&composed.repo, json!({}), |cx| {
        jobs::contributed(cx).unwrap()
    });
    let tiers: Vec<(&str, &[CiTier])> = jobs
        .iter()
        .map(|j| (j.id.as_str(), j.skippable_under.as_slice()))
        .collect();
    // The defaults of a rust app: every job but the secrets gate skips under `docs`.
    assert_eq!(
        tiers,
        [
            (SECURITY_GATE, &[][..]),
            (DEPS_SCAN, &[CiTier::Docs][..]),
            (SAST, &[CiTier::Docs][..]),
            (CONTAINER_SCAN, &[CiTier::Docs][..])
        ]
    );
    let only_gate = with_cx(
        &composed.repo,
        json!({"deps": false, "sast": "none", "container_scan": false,
               "coverage_changed_lines": false}),
        |cx| jobs::contributed(cx).unwrap(),
    );
    let ids: Vec<&str> = only_gate.iter().map(|j| j.id.as_str()).collect();
    assert_eq!(ids, [SECURITY_GATE]);
}

/// Runs `f` with a context for `security`: its validated answers, stack-packs'
/// recorded answers and ci-baseline's defaults.
fn with_cx<R>(repo: &Repo, security: Value, f: impl FnOnce(&Context<'_>) -> R) -> R {
    let raw: Answers = serde_json::from_value(security).unwrap();
    let validated = Security
        .questions()
        .validate(SECURITY, &raw, answers::DEFAULT_TIER)
        .unwrap();
    let packs_raw = answers::recorded(&repo.root, "stack-packs")
        .unwrap()
        .map(|file| file.answers)
        .unwrap_or_default();
    let resolved = std::collections::BTreeMap::from([
        (
            "stack-packs".to_owned(),
            StackPacks
                .questions()
                .validate("stack-packs", &packs_raw, answers::DEFAULT_TIER)
                .unwrap(),
        ),
        ("ci-baseline".to_owned(), Answers::new()),
    ]);
    let profile = profile_for(&repo.root).unwrap();
    let source = Source::embedded();
    let previous = engine::Lock {
        schema: 2,
        version: "test".to_owned(),
        source_commit: None,
        source_dirty: false,
        personal_owner: brakes::config::current_owner(),
        modules: Default::default(),
        files: Default::default(),
    };
    let cx = Context::new(
        &repo.root, &profile, &source, &previous, &validated, &Security, &resolved,
    );
    f(&cx)
}

/// #1178: deps-scan scans the lockfile each recorded app declares, never a
/// recursive search, so a test fixture's lockfile is not scanned.
#[test]
fn deps_scan_scans_the_declared_lockfiles_of_the_apps_and_no_fixture() {
    let repo = Repo::new();
    repo.write("Cargo.toml", "");
    repo.write("Cargo.lock", "");
    repo.write("web/package.json", "{}");
    repo.write("web/pnpm-lock.yaml", "");
    repo.write("my svc/pyproject.toml", "");
    repo.write("my svc/uv.lock", "");
    repo.write("ios/Package.swift", "");
    repo.write("tests/fixtures/django-lock/uv.lock", "");
    repo.answer(
        "stack-packs",
        json!({"apps.root.path": ".", "apps.root.stack": "rust",
               "apps.web.path": "web", "apps.web.stack": "node",
               "apps.svc.path": "my svc", "apps.svc.stack": "python-uv",
               "apps.ios.path": "ios", "apps.ios.stack": "swift-ios"}),
    );
    let security = json!({"sast": "none", "container_scan": false});
    let lockfiles = with_cx(&repo, security.clone(), |cx| {
        jobs::deps_lockfiles(cx).unwrap()
    });
    assert_eq!(
        lockfiles,
        ["Cargo.lock", "my svc/uv.lock", "web/pnpm-lock.yaml"]
    );
    let deps = with_cx(&repo, security, |cx| {
        jobs::contributed(cx)
            .unwrap()
            .into_iter()
            .find(|j| j.id == DEPS_SCAN)
            .unwrap()
            .yaml
    });
    assert!(
        deps.contains("osv-scanner scan source --config osv-scanner.toml --lockfile Cargo.lock --lockfile 'my svc/uv.lock' --lockfile web/pnpm-lock.yaml\n"),
        "{deps}"
    );
    assert!(!deps.contains("--recursive"), "{deps}");
    assert!(!deps.contains("tests/fixtures"), "{deps}");
}

#[test]
fn a_contributor_taking_deps_scan_collides_with_security() {
    let composed = Composed::new();
    let error = composed.plan_with(&[&Squatter]).unwrap_err().to_string();
    assert_eq!(
        error,
        "Module fixture contributes CI job deps-scan, which collides with module security"
    );
}

#[test]
fn the_golden_carries_no_forbidden_construct_and_pins_every_action() {
    let text = minimal_golden();
    let keys: Vec<&str> = text.lines().map(str::trim_start).collect();
    assert!(
        !keys.iter().any(|l| l.starts_with("continue-on-error:")),
        "minimal.yml sets continue-on-error"
    );
    for forbidden in [
        "|| true",
        "--ignore-unfixed",
        "trivy-action",
        "setup-trivy",
        "gitleaks-action",
        "pull_request_target",
        "self-hosted",
    ] {
        assert!(
            !text.contains(forbidden),
            "minimal.yml contains {forbidden}"
        );
    }
    // `vars.*` is read only in the env of the bypass step, never in an `if:`.
    let blocks = job_blocks(&text);
    for (id, lines) in &blocks {
        for line in lines {
            assert!(
                !(line.trim_start().starts_with("if:") && line.contains("vars.")),
                "{id}: {line}"
            );
            if line.contains("${{ vars.") {
                assert_eq!(
                    line.trim(),
                    "SECURITY_BYPASS: \"${{ vars.SECURITY_BYPASS }}\"",
                    "{id}: {line}"
                );
            }
        }
    }
    assert!(!job(&blocks, SECURITY_GATE).join("\n").contains("vars."));
    assert!(
        job(&blocks, DEPS_SCAN)
            .join("\n")
            .contains("vars.SECURITY_BYPASS")
    );
    let pins = PinTable::embedded().unwrap();
    for id in [SECURITY_GATE, DEPS_SCAN] {
        for line in job(&blocks, id).iter().filter(|l| l.contains("uses:")) {
            let uses = line.split("uses: ").nth(1).unwrap();
            let repo = uses.split('@').next().unwrap();
            assert_eq!(uses, pins.action(repo).unwrap().uses(), "{id}: {line}");
        }
    }
}

#[test]
fn security_gate_scans_with_gitleaks_and_checks_the_inventory() {
    let text = minimal_golden();
    let blocks = job_blocks(&text);
    let gate = job(&blocks, SECURITY_GATE).join("\n");
    for expected in [
        "fetch-depth: \"0\"",
        "persist-credentials: \"false\"",
        &format!("TOOL_URL_AMD64: \"{}\"", GITLEAKS.amd64.0),
        &format!("TOOL_SHA256_ARM64: \"{}\"", GITLEAKS.arm64.1),
        "gitleaks git --redact --exit-code 1 --report-format sarif --report-path gitleaks.sarif",
        "--log-opts \"$range\" .",
        "echo \"history: full\"",
        "[\"exceptions: \\($inventory_report.active + $t.active + $o.active) active, ",
        "SECURITY_BYPASS_MAX_DAYS: \"30\"",
        "retention-days: \"1\"",
        "path: gitleaks.sarif",
        "BASE_SHA: \"${{ github.event.pull_request.base.sha }}\"",
        "PUSH_BEFORE: \"${{ github.event.before }}\"",
        "PUSH_AFTER: \"${{ github.event.after }}\"",
        "baseline=.gitleaks-baseline.json",
        "scan+=(--baseline-path \"$baseline\")",
    ] {
        assert!(gate.contains(expected), "security-gate lacks {expected}");
    }
    assert!(
        !gate.contains("bypass-variable.sh"),
        "security-gate admits no bypass"
    );
    let deps = job(&blocks, DEPS_SCAN).join("\n");
    for expected in [
        "set -- deps-scan",
        "(if ($verdicts | length) == 0 then [\"bypass: none\"] else [] end)",
        &format!("TOOL_URL_ARM64: \"{}\"", OSV_SCANNER.arm64.0),
        &format!("TOOL_SHA256_AMD64: \"{}\"", OSV_SCANNER.amd64.1),
        "if: steps.bypass.outputs.id == ''",
        "osv-scanner --version\n          osv-scanner scan source --config osv-scanner.toml --lockfile Cargo.lock",
    ] {
        assert!(deps.contains(expected), "deps-scan lacks {expected}");
    }
}

#[test]
fn bypass_max_days_reaches_both_checks() {
    let composed = Composed::new();
    composed.repo.answer(
        SECURITY,
        json!({"bypass_max_days": 7, "sast": "none", "container_scan": false,
               "coverage_changed_lines": false}),
    );
    let text = composed.workflow();
    assert_eq!(
        text.matches("SECURITY_BYPASS_MAX_DAYS: \"7\"").count(),
        2,
        "{text}"
    );
}

// ---- T10 (#798): sast and container-scan ---------------------------------------------

/// `delivery` as SPEC-security.md's "Interface with delivery" describes it: a
/// module whose answers record the pull-request image job and whose job
/// exposes the reference as an output.
struct FakeDelivery;
impl Module for FakeDelivery {
    fn id(&self) -> &'static str {
        DELIVERY
    }
    fn version(&self) -> &'static str {
        "0.0.0"
    }
    fn questions(&self) -> brakes::engine::answers::Schema {
        brakes::engine::answers::Schema::parse(&json!([
            {"id": "image_job", "type": "string", "default": "build-image",
             "description": "The job that builds the pull-request image."},
            {"id": "image_ref", "type": "string", "default": "image_ref",
             "description": "Its output holding <registry>/<repo>@sha256:…"},
        ]))
        .unwrap()
    }
    fn render(&self, _: &Context<'_>) -> Result<Vec<Rendered>> {
        Ok(Vec::new())
    }
    fn ci_jobs(&self, _: &Context<'_>) -> Vec<CiJob> {
        vec![CiJob {
            id: "build-image".to_owned(),
            yaml: format!(
                "name: build-image\nneeds: scope\nif: needs.scope.outputs.tier != 'docs'\nruns-on: {}\ntimeout-minutes: 5\noutputs:\n  image_ref: \"${{{{ steps.build.outputs.ref }}}}\"\nsteps:\n  - id: build\n    name: Build the image (fixture)\n    run: echo \"ref=ghcr.io/o/r@sha256:0000000000000000000000000000000000000000000000000000000000000000\" >> \"$GITHUB_OUTPUT\"\n",
                configured::linux_runner().label
            ),
            skippable_under: vec![CiTier::Docs],
            app: None,
        }]
    }
}

#[test]
fn the_slice_2_answers_carry_the_spec_defaults() {
    let schema = Security.questions();
    let defaults = schema
        .validate(SECURITY, &Answers::new(), answers::DEFAULT_TIER)
        .unwrap();
    assert_eq!(defaults["sast"], json!("semgrep"), "{defaults:?}");
    assert_eq!(defaults["container_scan"], json!(true));
    assert_eq!(defaults["severity"], json!("high-and-critical"));
    let raw: Answers = serde_json::from_value(json!({"container_scan": false})).unwrap();
    let off = schema
        .validate(SECURITY, &raw, answers::DEFAULT_TIER)
        .unwrap();
    assert!(
        !off.contains_key("severity"),
        "severity is gated on container_scan: {off:?}"
    );
    for bad in [json!({"sast": "sonar"}), json!({"severity": "low"})] {
        let raw: Answers = serde_json::from_value(bad).unwrap();
        schema
            .validate(SECURITY, &raw, answers::DEFAULT_TIER)
            .expect_err("enum refused");
    }
}

#[test]
fn sast_is_semgrep_with_the_stacks_packs_codeql_with_their_languages_or_none() {
    let composed = Composed::new();
    assert_eq!(
        with_cx(&composed.repo, json!({}), |cx| jobs::sast(cx).unwrap()),
        Some(Sast::Semgrep {
            configs: vec!["p/default", "p/rust"]
        })
    );
    assert_eq!(
        with_cx(&composed.repo, json!({"sast": "codeql"}), |cx| jobs::sast(
            cx
        )
        .unwrap()),
        Some(Sast::CodeQl {
            languages: vec!["rust"]
        })
    );
    assert_eq!(
        with_cx(&composed.repo, json!({"sast": "none"}), |cx| jobs::sast(cx)
            .unwrap()),
        None
    );
    // Every stack maps: the spec's packs, `p/rust` for Rust, nothing for sql-dbt.
    assert_eq!(jobs::semgrep_rulesets(StackId::PythonUv), ["p/python"]);
    assert_eq!(
        jobs::semgrep_rulesets(StackId::Node),
        ["p/javascript", "p/typescript"]
    );
    assert_eq!(jobs::semgrep_rulesets(StackId::Go), ["p/golang"]);
    assert!(jobs::semgrep_rulesets(StackId::SqlDbt).is_empty());
    assert_eq!(
        jobs::codeql_language(StackId::Node),
        Some("javascript-typescript")
    );
    assert_eq!(
        jobs::codeql_language(StackId::KotlinAndroid),
        Some("java-kotlin")
    );
    assert_eq!(jobs::codeql_language(StackId::SqlDbt), None);
}

#[test]
fn container_scan_applies_with_a_dockerfile_a_container_app_or_delivery() {
    let composed = Composed::new();
    let scan = |answers: Value| {
        with_cx(&composed.repo, answers, |cx| {
            jobs::container_scan(cx).unwrap()
        })
    };
    // A rust app builds a container unless answered off: its Dockerfile is scanned.
    assert!(
        scan(json!({})).is_some(),
        "a container app has a Dockerfile to scan"
    );
    let no_container =
        json!({"apps.root.path": ".", "apps.root.stack": "rust", "apps.root.container": false});
    composed.repo.answer("stack-packs", no_container.clone());
    assert_eq!(scan(json!({})), None, "nothing to scan");
    composed.repo.write("Dockerfile", "FROM scratch\n");
    assert_eq!(
        scan(json!({})),
        Some(ContainerScan {
            severity: "HIGH,CRITICAL",
            image: None
        })
    );
    assert_eq!(
        scan(json!({"severity": "critical"})).unwrap().severity,
        "CRITICAL"
    );
    assert_eq!(scan(json!({"container_scan": false})), None);
    fs::remove_file(composed.repo.root.join("Dockerfile")).unwrap();
    assert_eq!(scan(json!({})), None);
    composed
        .repo
        .answer(DELIVERY, json!({"image_job": "build-image"}));
    assert_eq!(
        scan(json!({})).unwrap().image,
        Some(("build-image".to_owned(), "image_ref".to_owned()))
    );
    composed
        .repo
        .answer(DELIVERY, json!({"image_job": "Build Image"}));
    let err = with_cx(&composed.repo, json!({}), |cx| {
        jobs::container_scan(cx).unwrap_err().to_string()
    });
    assert_eq!(
        err,
        "Module security: delivery records image_job \"Build Image\", which is not a kebab-case job id"
    );
    composed.repo.answer(
        DELIVERY,
        json!({"image_job": "build-image", "image_ref": "ref }} ${{ secrets.X"}),
    );
    let err = with_cx(&composed.repo, json!({}), |cx| {
        jobs::container_scan(cx).unwrap_err().to_string()
    });
    assert_eq!(
        err,
        "Module security: delivery records image_ref \"ref }} ${{ secrets.X\", which is not a job output name"
    );
}

#[test]
fn the_full_workflow_matches_the_full_golden() {
    let composed = Composed::with(json!({}), true);
    let text = composed.workflow();
    golden("full.yml", &text);
    assert_eq!(text, composed.workflow(), "two renders differ");
    let blocks = job_blocks(&text);
    let ids: Vec<&str> = blocks.iter().map(|(id, _)| id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "scope",
            "checks",
            "heldout",
            "workflow-lint",
            SECURITY_GATE,
            DEPS_SCAN,
            SAST,
            CONTAINER_SCAN,
            "required"
        ]
    );
    assert!(job(&blocks, "required").contains(
        &"    needs: [scope, checks, heldout, workflow-lint, security-gate, deps-scan, sast, container-scan]".to_owned()
    ));
    let scope = job(&blocks, "scope").join("\n");
    let docs = scope.split_once("DOCS_SKIPPABLE: |-\n").unwrap().1;
    let docs: Vec<&str> = docs
        .lines()
        .take_while(|l| l.starts_with("            "))
        .map(str::trim)
        .collect();
    assert_eq!(docs, ["checks", "heldout", DEPS_SCAN, SAST, CONTAINER_SCAN]);
    let sast = job(&blocks, SAST).join("\n");
    for expected in [
        "    if: needs.scope.outputs.tier != 'docs'",
        "    timeout-minutes: 15",
        "set -- sast",
        &format!("SEMGREP_IMAGE: \"{}\"", SEMGREP.pinned()),
        &format!("Scan with Semgrep CE {}", SEMGREP.version),
        "docker run --rm -v \"$PWD:/src\" \"$SEMGREP_IMAGE\" semgrep scan --metrics=off --error --quiet --json --output semgrep.json --severity ERROR --config p/default --config p/rust || status=$?",
        "set -- semgrep semgrep.json \"$status\"",
    ] {
        assert!(sast.contains(expected), "sast lacks {expected}\n{sast}");
    }
    assert!(!sast.contains("pip install"), "Semgrep runs from its image");
    let container = job(&blocks, CONTAINER_SCAN).join("\n");
    for expected in [
        "    needs: scope",
        "    if: needs.scope.outputs.tier != 'docs'",
        "    timeout-minutes: 15",
        "set -- container-scan",
        &format!("TOOL_URL_AMD64: \"{}\"", TRIVY.amd64.0),
        &format!("TOOL_SHA256_ARM64: \"{}\"", TRIVY.arm64.1),
        "SEVERITY: \"HIGH,CRITICAL\"",
        "trivy fs --scanners vuln,misconfig --exit-code 1 --severity \"$SEVERITY\" --ignorefile .trivyignore.yaml .",
        "trivy fs --scanners secret --exit-code 1 --severity \"$SEVERITY\" --ignorefile .trivyignore.yaml --format json --output trivy-secrets.json . || status=$?",
        "trivy config --exit-code 1 --severity \"$SEVERITY\" --ignorefile .trivyignore.yaml .",
    ] {
        assert!(
            container.contains(expected),
            "container-scan lacks {expected}\n{container}"
        );
    }
    assert!(!container.contains("trivy image"));
    assert_no_forbidden_construct(&text, &[SECURITY_GATE, DEPS_SCAN, SAST, CONTAINER_SCAN]);
}

#[test]
fn with_delivery_the_container_scan_needs_the_image_job_and_scans_its_reference() {
    let composed = Composed::with(json!({}), false);
    composed.repo.answer(
        DELIVERY,
        json!({"image_job": "build-image", "image_ref": "image_ref"}),
    );
    let text = composed.plan_with(&[&FakeDelivery]).unwrap().changes[WORKFLOW]
        .clone()
        .unwrap();
    golden("with-delivery.yml", &text);
    let blocks = job_blocks(&text);
    let ids: Vec<&str> = blocks.iter().map(|(id, _)| id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "scope",
            "checks",
            "heldout",
            "workflow-lint",
            SECURITY_GATE,
            DEPS_SCAN,
            SAST,
            CONTAINER_SCAN,
            "build-image",
            "required"
        ]
    );
    let container = job(&blocks, CONTAINER_SCAN).join("\n");
    for expected in [
        "    needs: [scope, build-image]",
        "IMAGE_REF: \"${{ needs.build-image.outputs.image_ref }}\"",
        "trivy image --scanners vuln --exit-code 1 --severity \"$SEVERITY\" --ignorefile .trivyignore.yaml \"$IMAGE_REF\"",
        "trivy image --scanners secret --exit-code 1 --severity \"$SEVERITY\" --ignorefile .trivyignore.yaml --format json --output trivy-secrets.json \"$IMAGE_REF\" || status=$?",
    ] {
        assert!(
            container.contains(expected),
            "container-scan lacks {expected}\n{container}"
        );
    }
    assert!(!container.contains("trivy fs"));
    assert_no_forbidden_construct(&text, &[SECURITY_GATE, DEPS_SCAN, SAST, CONTAINER_SCAN]);
}

#[test]
fn the_codeql_answer_renders_the_pinned_action_with_the_stacks_languages() {
    let composed = Composed::with(json!({"sast": "codeql", "container_scan": false}), true);
    let text = composed.workflow();
    golden("codeql.yml", &text);
    let blocks = job_blocks(&text);
    let ids: Vec<&str> = blocks.iter().map(|(id, _)| id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "scope",
            "checks",
            "heldout",
            "workflow-lint",
            SECURITY_GATE,
            DEPS_SCAN,
            SAST,
            "required"
        ]
    );
    let pins = PinTable::embedded().unwrap();
    let sast = job(&blocks, SAST).join("\n");
    for expected in [
        "    permissions:\n      contents: read\n      security-events: write",
        "set -- sast",
        &format!(
            "uses: {}",
            pins.action("github/codeql-action/init").unwrap().uses()
        ),
        &format!(
            "uses: {}",
            pins.action("github/codeql-action/analyze").unwrap().uses()
        ),
        "languages: rust",
    ] {
        assert!(sast.contains(expected), "sast lacks {expected}\n{sast}");
    }
    assert!(!sast.contains("semgrep"));
    assert_no_forbidden_construct(&text, &[SECURITY_GATE, DEPS_SCAN, SAST]);
}

/// The golden's forbidden-construct and pin checks, for every contributed job.
fn assert_no_forbidden_construct(text: &str, ids: &[&str]) {
    let keys: Vec<&str> = text.lines().map(str::trim_start).collect();
    assert!(
        !keys.iter().any(|l| l.starts_with("continue-on-error:")),
        "sets continue-on-error"
    );
    for forbidden in [
        "|| true",
        "--ignore-unfixed",
        "trivy-action",
        "setup-trivy",
        "gitleaks-action",
        "semgrep-action",
        "pull_request_target",
        "self-hosted",
    ] {
        assert!(!text.contains(forbidden), "contains {forbidden}");
    }
    let blocks = job_blocks(text);
    for (id, lines) in &blocks {
        for line in lines {
            assert!(
                !(line.trim_start().starts_with("if:") && line.contains("vars.")),
                "{id}: {line}"
            );
            if line.contains("${{ vars.") {
                assert_eq!(
                    line.trim(),
                    "SECURITY_BYPASS: \"${{ vars.SECURITY_BYPASS }}\"",
                    "{id}: {line}"
                );
            }
        }
    }
    let pins = PinTable::embedded().unwrap();
    for id in ids {
        for line in job(&blocks, id).iter().filter(|l| l.contains("uses:")) {
            let uses = line.split("uses: ").nth(1).unwrap();
            let repo = uses.split('@').next().unwrap();
            assert_eq!(uses, pins.action(repo).unwrap().uses(), "{id}: {line}");
        }
    }
}

// ---- gitleaks-scan.sh: the history it scans ----------------------------------------

/// Runs the scan fragment in a git repository with a fake `gitleaks` that
/// records its arguments; returns (stdout, recorded arguments).
fn scan(event: &str, base: &str, head: &str) -> (String, String) {
    let run = scan_with(event, &[("BASE_SHA", base), ("HEAD_SHA", head)], None);
    assert!(run.success, "{}", run.stderr);
    (run.stdout, run.args)
}

/// One run of the scan fragment: what it printed and what gitleaks received.
struct ScanRun {
    success: bool,
    stdout: String,
    stderr: String,
    args: String,
}

/// Runs the scan fragment with `env` (`<base>` and `<head>` stand for two real
/// commits) and, when given, `.gitleaks-baseline.json` committed with that content.
fn scan_with(event: &str, env: &[(&str, &str)], baseline: Option<&str>) -> ScanRun {
    scan_with_fake(
        event,
        env,
        baseline,
        &format!("cat > gitleaks.sarif <<'SARIF'\n{EMPTY_SARIF}\nSARIF"),
    )
}

/// The report of a scan that found nothing.
const EMPTY_SARIF: &str = r#"{"runs":[{"tool":{"driver":{"name":"gitleaks"}},"results":[]}]}"#;

/// [`scan_with`] whose fake `gitleaks` runs `tail` (shell) after recording its
/// arguments, in the repository root.
fn scan_with_fake(
    event: &str,
    env: &[(&str, &str)],
    baseline: Option<&str>,
    tail: &str,
) -> ScanRun {
    let repo = Repo::new();
    let git = |args: &[&str]| {
        let out = Command::new("git")
            .args([
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .current_dir(&repo.root)
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    };
    git(&["commit", "-q", "--allow-empty", "-m", "base"]);
    let base_sha = git(&["rev-parse", "HEAD"]);
    if let Some(content) = baseline {
        fs::write(repo.root.join(".gitleaks-baseline.json"), content).unwrap();
        git(&["add", ".gitleaks-baseline.json"]);
    }
    git(&["commit", "-q", "--allow-empty", "-m", "head"]);
    let head_sha = git(&["rev-parse", "HEAD"]);
    let bin = repo.root.join(".fake-bin");
    fs::create_dir(&bin).unwrap();
    let args = repo.root.join(".fake-args");
    let fake = bin.join("gitleaks");
    common::write_executable(
        &fake,
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\n{tail}\n",
            args.display()
        ),
    );
    let pick = |v: &str| match v {
        "<base>" => base_sha.clone(),
        "<head>" => head_sha.clone(),
        other => other.to_owned(),
    };
    let mut command = Command::new("bash");
    command
        .arg("-c")
        .arg(GITLEAKS_SCAN)
        .current_dir(&repo.root)
        .env(
            "PATH",
            format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
        )
        .env("EVENT", event)
        .env("GIT_TERMINAL_PROMPT", "0");
    for name in ["BASE_SHA", "HEAD_SHA", "PUSH_BEFORE", "PUSH_AFTER"] {
        command.env_remove(name);
    }
    for (name, value) in env {
        command.env(name, pick(value));
    }
    let out = command.output().unwrap();
    let anonymise = |text: String| {
        text.replace(&base_sha, "<base>")
            .replace(&head_sha, "<head>")
    };
    ScanRun {
        success: out.status.success(),
        stdout: anonymise(String::from_utf8(out.stdout).unwrap()),
        stderr: anonymise(String::from_utf8(out.stderr).unwrap()),
        args: anonymise(fs::read_to_string(&args).unwrap_or_default()),
    }
}

const FULL_ARGS: &str =
    "git\n--redact\n--exit-code\n1\n--report-format\nsarif\n--report-path\ngitleaks.sarif\n.\n";

#[test]
fn a_pull_request_scans_its_range() {
    let (stdout, args) = scan("pull_request", "<base>", "<head>");
    assert_eq!(stdout, "history: <base>..<head>\ngitleaks: no findings\n");
    assert_eq!(
        args,
        "git\n--redact\n--exit-code\n1\n--report-format\nsarif\n--report-path\ngitleaks.sarif\n--log-opts\n<base>..<head>\n.\n"
    );
}

#[test]
fn a_push_without_its_range_scans_the_full_history() {
    let (stdout, args) = scan("push", "", "");
    assert_eq!(stdout, "history: full\ngitleaks: no findings\n");
    assert_eq!(args, FULL_ARGS);
}

const RANGE_ARGS: &str = "git\n--redact\n--exit-code\n1\n--report-format\nsarif\n--report-path\ngitleaks.sarif\n--log-opts\n<base>..<head>\n.\n";

const BASELINE_ARGS: &str = "git\n--redact\n--exit-code\n1\n--report-format\nsarif\n--report-path\ngitleaks.sarif\n--baseline-path\n.gitleaks-baseline.json\n.\n";

/// A redacted gitleaks JSON report with one historical finding.
const BASELINE: &str = r#"[{"RuleID":"generic-api-key","File":"example.env","StartLine":3,"Commit":"0123456789abcdef0123456789abcdef01234567","Secret":"REDACTED","Match":"KEY=REDACTED"}]"#;

#[test]
fn a_push_scans_the_commits_it_adds() {
    let run = scan_with(
        "push",
        &[("PUSH_BEFORE", "<base>"), ("PUSH_AFTER", "<head>")],
        None,
    );
    assert!(run.success, "{}", run.stderr);
    assert_eq!(
        run.stdout,
        "history: pushed <base>..<head>\ngitleaks: no findings\n"
    );
    assert_eq!(run.args, RANGE_ARGS);
}

#[test]
fn a_push_that_creates_the_branch_or_names_no_commit_scans_the_full_history() {
    let zeros = "0000000000000000000000000000000000000000";
    let missing = "0123456789abcdef0123456789abcdef01234567";
    for (before, after) in [
        (zeros, "<head>"),
        (missing, "<head>"),
        ("--output=x", "<head>"),
        ("<base>", ""),
    ] {
        let run = scan_with(
            "push",
            &[("PUSH_BEFORE", before), ("PUSH_AFTER", after)],
            None,
        );
        assert!(run.success, "{before}: {}", run.stderr);
        assert!(
            run.stdout
                .ends_with("history: full\ngitleaks: no findings\n"),
            "{before}: {}",
            run.stdout
        );
        assert_eq!(run.args, FULL_ARGS, "{before}");
    }
}

#[test]
fn a_full_scan_outside_pull_requests_skips_the_reviewed_baseline() {
    let zeros = "0000000000000000000000000000000000000000";
    for (event, env) in [
        ("workflow_dispatch", vec![]),
        ("schedule", vec![]),
        (
            "push",
            vec![("PUSH_BEFORE", zeros), ("PUSH_AFTER", "<head>")],
        ),
    ] {
        let run = scan_with(event, &env, Some(BASELINE));
        assert!(run.success, "{event}: {}", run.stderr);
        assert_eq!(
            run.stdout, "history: full\nbaseline: .gitleaks-baseline.json\ngitleaks: no findings\n",
            "{event}"
        );
        assert_eq!(run.args, BASELINE_ARGS, "{event}");
    }
}

#[test]
fn a_range_a_pull_request_or_a_merge_group_never_reads_the_baseline() {
    for (event, env) in [
        (
            "pull_request",
            vec![("BASE_SHA", "<base>"), ("HEAD_SHA", "<head>")],
        ),
        (
            "push",
            vec![("PUSH_BEFORE", "<base>"), ("PUSH_AFTER", "<head>")],
        ),
    ] {
        let run = scan_with(event, &env, Some(BASELINE));
        assert!(run.success, "{event}: {}", run.stderr);
        assert_eq!(run.args, RANGE_ARGS, "{event}");
        assert!(!run.stdout.contains("baseline"), "{event}: {}", run.stdout);
    }
    // A full-history fallback of a pull request must not trust a baseline the
    // change itself may have edited; nor may a merge group.
    for (event, env) in [
        (
            "pull_request",
            vec![("BASE_SHA", ""), ("HEAD_SHA", "<head>")],
        ),
        ("merge_group", vec![]),
    ] {
        let run = scan_with(event, &env, Some(BASELINE));
        assert!(run.success, "{event}: {}", run.stderr);
        assert_eq!(run.args, FULL_ARGS, "{event}");
        assert!(!run.stdout.contains("baseline"), "{event}: {}", run.stdout);
    }
}

#[test]
fn a_baseline_that_is_not_a_redacted_report_fails_on_every_event() {
    for content in [
        r#"[{"RuleID":"generic-api-key","Secret":"hunter2-not-redacted"}]"#,
        r#"[{"RuleID":"generic-api-key"}]"#,
        r#"{"RuleID":"generic-api-key","Secret":"REDACTED"}"#,
        "not json",
    ] {
        for (event, env) in [
            (
                "pull_request",
                vec![("BASE_SHA", "<base>"), ("HEAD_SHA", "<head>")],
            ),
            ("workflow_dispatch", vec![]),
        ] {
            let run = scan_with(event, &env, Some(content));
            assert!(!run.success, "{event} {content}: passed");
            assert!(
                run.stdout.contains(
                    "::error::.gitleaks-baseline.json is not a redacted gitleaks JSON report; regenerate it with --redact"
                ),
                "{event} {content}: {}",
                run.stdout
            );
            assert!(
                !run.stdout.contains("hunter2"),
                "{event}: the value is printed"
            );
            assert_eq!(run.args, "", "{event} {content}: gitleaks ran");
        }
    }
}

#[test]
fn an_unknown_range_means_full_history() {
    let missing = "0123456789abcdef0123456789abcdef01234567";
    for (event, base, head) in [
        ("pull_request", "", "<head>"),
        ("pull_request", missing, "<head>"),
        ("pull_request", "--output=x", "<head>"),
        ("workflow_dispatch", "<base>", "<head>"),
        ("merge_group", "<base>", "<head>"),
    ] {
        let (stdout, args) = scan(event, base, head);
        assert!(
            stdout.ends_with("history: full\ngitleaks: no findings\n"),
            "{event} {base}: {stdout}"
        );
        assert_eq!(args, FULL_ARGS, "{event} {base}");
    }
}

// ---- gitleaks-scan.sh: what it prints of a finding (#1317) ---------------------------

/// A synthetic AWS access key id, assembled at run time so this file holds no token.
fn synthetic_token() -> String {
    ["AKIA", "QZ7XK2M4WR6T3VPB"].concat()
}

/// A gitleaks SARIF report with one finding per `(rule, path, line)`, whose message
/// and snippet carry `secret` as an unredacted report would.
fn sarif(findings: &[(&str, &str, u32)], secret: &str) -> String {
    let results: Vec<serde_json::Value> = findings
        .iter()
        .map(|(rule, path, line)| {
            serde_json::json!({
                "ruleId": rule,
                "message": {"text": format!("{rule} has detected secret {secret} for file {path}")},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": path},
                    "region": {"startLine": line, "snippet": {"text": secret}}
                }}]
            })
        })
        .collect();
    serde_json::json!({"runs": [{"tool": {"driver": {"name": "gitleaks"}}, "results": results}]})
        .to_string()
}

/// Runs the scan with a fake gitleaks that writes `report` (when given) to
/// `gitleaks.sarif` and exits `status`.
fn scan_reporting(report: Option<&str>, status: i32) -> ScanRun {
    let write = match report {
        Some(text) => format!("cat > gitleaks.sarif <<'SARIF'\n{text}\nSARIF\n"),
        None => String::new(),
    };
    scan_with_fake(
        "pull_request",
        &[("BASE_SHA", "<base>"), ("HEAD_SHA", "<head>")],
        None,
        &format!("{write}exit {status}"),
    )
}

#[test]
fn a_finding_is_named_by_rule_file_and_line_and_its_value_never_printed() {
    let token = synthetic_token();
    let report = sarif(
        &[
            ("aws-access-token", "docs/x.md", 7),
            ("generic-api-key", "src/config.env", 12),
        ],
        &token,
    );
    let run = scan_reporting(Some(&report), 1);
    assert!(!run.success, "a finding passed the gate");
    assert_eq!(
        run.stdout,
        "history: <base>..<head>\n\
         ::error file=docs/x.md,line=7::aws-access-token\n\
         ::error file=src/config.env,line=12::generic-api-key\n\
         ::error::2 gitleaks finding(s); values withheld from the log, rotate any real credential\n"
    );
    assert!(!run.stdout.contains(&token) && !run.stderr.contains(&token));
}

#[test]
fn a_finding_cannot_inject_a_workflow_command_through_its_path_or_rule() {
    let report = sarif(
        &[("rule%x\n::warning::y", "a,b:c%d\r\n::error::z.md", 3)],
        "REDACTED",
    );
    let run = scan_reporting(Some(&report), 1);
    assert!(!run.success);
    assert_eq!(
        run.stdout,
        "history: <base>..<head>\n\
         ::error file=a%2Cb%3Ac%25d%0D%0A%3A%3Aerror%3A%3Az.md,line=3::rule%25x%0A::warning::y\n\
         ::error::1 gitleaks finding(s); values withheld from the log, rotate any real credential\n"
    );
}

#[test]
fn a_clean_scan_prints_no_finding_and_passes() {
    let run = scan_reporting(Some(EMPTY_SARIF), 0);
    assert!(run.success, "{}", run.stderr);
    assert_eq!(
        run.stdout,
        "history: <base>..<head>\ngitleaks: no findings\n"
    );
}

#[test]
fn a_failing_scan_without_a_readable_report_fails_naming_its_exit() {
    for (report, status) in [(None, 1), (Some("not json"), 1), (None, 126), (None, 0)] {
        let run = scan_reporting(report, status);
        assert!(!run.success, "{report:?} {status}");
        assert_eq!(
            run.stdout,
            format!(
                "history: <base>..<head>\n::error::gitleaks wrote no readable report (exit {status})\n"
            ),
            "{report:?}"
        );
    }
}

#[test]
fn findings_with_a_zero_exit_still_fail_the_gate() {
    let run = scan_reporting(
        Some(&sarif(&[("aws-access-token", "a.md", 1)], "REDACTED")),
        0,
    );
    assert!(!run.success, "findings passed with exit 0");
    assert!(
        run.stdout
            .contains("::error file=a.md,line=1::aws-access-token\n")
    );
}

/// The real gitleaks, when installed, against a committed synthetic token: the
/// log names rule, file and line, and neither the log nor the report holds the
/// value (`--redact`).
#[test]
fn the_installed_gitleaks_names_a_synthetic_token_without_printing_it() {
    if Command::new("gitleaks").arg("version").output().is_err() {
        eprintln!("gitleaks not installed; the fake-report tests cover the log");
        return;
    }
    let repo = Repo::new();
    let git = |args: &[&str]| {
        let out = Command::new("git")
            .args([
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .current_dir(&repo.root)
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
    };
    let token = synthetic_token();
    fs::create_dir_all(repo.root.join("docs")).unwrap();
    fs::write(
        repo.root.join("docs/x.md"),
        format!("# x\n\n\n\n\n\naws_access_key_id = {token}\n"),
    )
    .unwrap();
    git(&["add", "docs/x.md"]);
    git(&["commit", "-q", "-m", "synthetic"]);
    let out = Command::new("bash")
        .arg("-c")
        .arg(GITLEAKS_SCAN)
        .current_dir(&repo.root)
        .env("EVENT", "workflow_dispatch")
        .output()
        .unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(!out.status.success(), "{stdout}{stderr}");
    assert!(
        stdout.contains("::error file=docs/x.md,line=7::aws-access-token\n"),
        "{stdout}"
    );
    let report = fs::read_to_string(repo.root.join("gitleaks.sarif")).unwrap();
    for text in [&stdout, &stderr, &report] {
        assert!(!text.contains(&token), "the synthetic token was published");
        assert!(
            !text.contains(&token[4..]),
            "part of the token was published"
        );
    }
}

// ---- registration and the CLI path (#891) -------------------------------------------

impl Composed {
    /// The binary on this repository, `<repo>` replaced by its path.
    fn cli(&self, args: &[&str]) -> std::process::Output {
        let root = self.repo.root.to_string_lossy().into_owned();
        Command::new(env!("CARGO_BIN_EXE_brakes"))
            .args(
                args.iter()
                    .map(|a| if *a == "<repo>" { root.as_str() } else { a }),
            )
            .output()
            .unwrap()
    }
    /// `install --module` for `ids`, plus `extra`; stdout, asserting success.
    fn install(&self, ids: &[&str], extra: &[&str]) -> String {
        let mut args = vec!["install", "<repo>"];
        for id in ids {
            args.extend(["--module", id]);
        }
        args.extend(extra);
        let out = self.cli(&args);
        assert!(out.status.success(), "{args:?}: {out:?}");
        String::from_utf8(out.stdout).unwrap()
    }
}

const WITH_REQUIREMENTS: [&str; 3] = ["stack-packs", "ci-baseline", SECURITY];

#[test]
fn cli_install_module_security_alone_refuses_naming_its_requirement() {
    let composed = Composed::new();
    let out = composed.cli(&["install", "<repo>", "--module", SECURITY]);
    assert!(!out.status.success(), "{out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stderr).trim(),
        "REFUSED: Module security requires module ci-baseline, which is not installed; add it with --module ci-baseline"
    );
    let out = composed.cli(&[
        "install",
        "<repo>",
        "--module",
        "ci-baseline",
        "--module",
        SECURITY,
    ]);
    assert_eq!(
        String::from_utf8_lossy(&out.stderr).trim(),
        "REFUSED: Module security requires module stack-packs, which is not installed; add it with --module stack-packs"
    );
    assert!(!composed.repo.exists(INVENTORY));
}

#[test]
fn cli_install_module_security_plans_seeds_guide_and_both_jobs_in_required() {
    let composed = Composed::new();
    let hooks = composed.repo.git_hooks_digest();
    let plan = composed.install(&WITH_REQUIREMENTS, &[]);
    let lines: Vec<&str> = plan.lines().collect();
    // `Composed` answers `sast: none`, so no `.semgrepignore` is seeded.
    for path in SEEDS.iter().filter(|p| **p != SEMGREP_IGNORE) {
        let line = format!("PLAN {path} [seed:security]");
        assert!(lines.contains(&line.as_str()), "{line}\n{plan}");
    }
    assert!(!plan.contains(SEMGREP_IGNORE), "{plan}");
    let line = format!("PLAN {PRE_COMMIT_PATH} [seed:security]");
    assert!(lines.contains(&line.as_str()), "{line}\n{plan}");
    for line in [
        format!("PLAN {GUIDE_PATH} [managed:security]"),
        format!("PLAN {WORKFLOW} [managed:ci-baseline]"),
        format!("NOTE [ci-baseline] JOB [security] {SECURITY_GATE} → {WORKFLOW}"),
        format!("NOTE [ci-baseline] JOB [security] {DEPS_SCAN} → {WORKFLOW}"),
    ] {
        assert!(lines.contains(&line.as_str()), "{line}\n{plan}");
    }
    assert!(!composed.repo.exists(INVENTORY), "plan only");
    composed.install(&WITH_REQUIREMENTS, &["--apply"]);
    let required = job(&job_blocks(&composed.repo.read(WORKFLOW)), "required").to_vec();
    assert!(
        required.contains(
            &"    needs: [scope, checks, heldout, workflow-lint, security-gate, deps-scan]"
                .to_owned()
        ),
        "{required:#?}"
    );
    for path in SEEDS
        .iter()
        .filter(|p| **p != SEMGREP_IGNORE)
        .chain([&PRE_COMMIT_PATH, &GUIDE_PATH])
    {
        assert!(composed.repo.exists(path), "{path}");
    }
    assert!(!composed.repo.exists(SEMGREP_IGNORE), "sast: none");
    let lock: Value = serde_json::from_str(&composed.repo.read(".agent-setup/lock.json")).unwrap();
    assert_eq!(lock["modules"][SECURITY]["version"], "1.0.0", "{lock:#}");
    let again = composed.install(&[], &[]);
    assert!(again.lines().any(|l| l == "No changes."), "{again}");
    assert_eq!(composed.repo.git_hooks_digest(), hooks);
}

#[test]
fn cli_doctor_lists_the_security_findings_and_steps_and_leaves_git_hooks_alone() {
    let composed = Composed::new();
    composed.install(&WITH_REQUIREMENTS, &["--apply"]);
    // An expired exception: the gate's own check and `doctor` agree on it.
    let mut inventory: Value = serde_json::from_str(&composed.repo.read(INVENTORY)).unwrap();
    inventory["exceptions"] = json!([{
        "id": "osv-outage-2026-01", "kind": "job-bypass", "target": "deps-scan",
        "reason": "OSV outage", "issue": "#1", "owner": "owner",
        "created": "2026-01-01", "expires": "2026-01-05"
    }]);
    composed.repo.write(
        INVENTORY,
        &(serde_json::to_string_pretty(&inventory).unwrap() + "\n"),
    );
    let hooks = composed.repo.git_hooks_digest();
    let out = composed.cli(&["doctor", "<repo>"]);
    let text = String::from_utf8(out.stdout).unwrap();
    let ours: Vec<&str> = text.lines().filter(|l| l.contains("security")).collect();
    assert!(
        ours.iter()
            .any(|l| l.starts_with("WARNING: security.bypass-expired: ")),
        "{text}"
    );
    for id in [
        "secret-scanning",
        "private-vulnerability-reporting",
        "hooks-installed",
    ] {
        assert!(
            ours.iter()
                .any(|l| l.starts_with("STEP [") && l.contains(&format!(":security] {id} "))),
            "{id}\n{text}"
        );
    }
    assert_eq!(composed.repo.git_hooks_digest(), hooks);
}

#[test]
fn a_repository_without_security_in_its_lock_sees_no_security_line_on_install() {
    let composed = Composed::new();
    let first = composed.install(&["stack-packs", "ci-baseline"], &["--apply"]);
    let again = composed.install(&[], &[]);
    for text in [&first, &again] {
        assert!(!text.contains("security"), "{text}");
    }
    assert!(again.lines().any(|l| l == "No changes."), "{again}");
    assert!(!composed.repo.exists(INVENTORY));
}

// ---- contributed jobs under `workflow: existing` (#895) ------------------------------

const SEPARATE: &str = ".github/workflows/agentic-security.yml";
/// This repository's shape: its own CI with its own aggregate `Rust (linux)`.
const OWN: &str = ".github/workflows/orchestration.yml";
const OWN_YML: &str = "name: Orchestration
on:
  pull_request:
permissions:
  contents: read
jobs:
  rust:
    name: Rust (linux)
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    steps:
      - name: Verify
        run: echo verify
";

impl Composed {
    /// `Composed` with its own workflow and `workflow: existing` recorded.
    fn existing(check: &str) -> Self {
        let composed = Self::new();
        composed.repo.write(OWN, OWN_YML);
        composed.repo.answer(
            "ci-baseline",
            json!({"workflow": "existing", "aggregate_check": check}),
        );
        composed
    }
    fn refusal(&self) -> String {
        let out = self.cli(&[
            "install",
            "<repo>",
            "--module",
            "stack-packs",
            "--module",
            "ci-baseline",
            "--module",
            SECURITY,
        ]);
        assert!(!out.status.success(), "{out:?}");
        String::from_utf8_lossy(&out.stderr).trim().to_owned()
    }
}

#[test]
fn existing_with_security_writes_the_separate_workflow_and_leaves_the_own_one() {
    let composed = Composed::existing("Rust (linux)");
    let plan = composed.install(&WITH_REQUIREMENTS, &[]);
    let lines: Vec<&str> = plan.lines().collect();
    for line in [
        format!("PLAN {SEPARATE} [managed:ci-baseline]"),
        format!("NOTE [ci-baseline] JOB [security] {SECURITY_GATE} → {SEPARATE}"),
        format!("NOTE [ci-baseline] JOB [security] {DEPS_SCAN} → {SEPARATE}"),
        "STEP [unavailable:ci-baseline] agentic-required-reported — CI reports agentic-required on main".to_owned(),
        "STEP [blocked:ci-baseline] add-agentic-required-check — Remote item: the default branch also requires the agentic-required check".to_owned(),
    ] {
        assert!(lines.contains(&line.as_str()), "{line}\n{plan}");
    }
    assert!(!plan.contains(".github/workflows/ci.yml"), "{plan}");
    assert!(!plan.contains(".github/workflows/agentic-ci.yml"), "{plan}");
    assert!(!plan.contains(&format!("PLAN {OWN}")), "{plan}");

    composed.install(&WITH_REQUIREMENTS, &["--apply"]);
    let text = composed.repo.read(SEPARATE);
    golden("existing.yml", &text);
    let blocks = job_blocks(&text);
    let ids: Vec<&str> = blocks.iter().map(|(id, _)| id.as_str()).collect();
    assert_eq!(ids, ["scope", SECURITY_GATE, DEPS_SCAN, "agentic-required"]);
    let aggregate = job(&blocks, "agentic-required");
    for line in [
        "    name: agentic-required",
        "    needs: [scope, security-gate, deps-scan]",
        "    if: always()",
    ] {
        assert!(aggregate.contains(&line.to_owned()), "{line}\n{text}");
    }

    assert_eq!(composed.repo.read(OWN), OWN_YML);
    let lock: Value = serde_json::from_str(&composed.repo.read(".agent-setup/lock.json")).unwrap();
    assert_eq!(
        lock["files"][OWN],
        json!({"module": "ci-baseline", "class": "never-touch"})
    );
    assert_eq!(
        lock["files"]["github:add-agentic-required-check"],
        json!({"module": "ci-baseline", "class": "remote"})
    );
    let again = composed.install(&[], &[]);
    assert!(again.lines().any(|l| l == "No changes."), "{again}");

    let doctor = composed.cli(&["doctor", "<repo>"]);
    let report = String::from_utf8(doctor.stdout).unwrap();
    assert!(
        report
            .lines()
            .any(|l| l.starts_with("STEP [")
                && l.contains(":ci-baseline] add-agentic-required-check ")),
        "{report}"
    );
}

// ---- #1349: changed-line coverage from the project's own test run --------------------

const REUSABLE: &str = ".github/workflows/agentic-coverage.yml";

#[test]
fn diff_coverage_lives_only_in_the_reusable_workflow_the_project_calls() {
    // #22: under every workflow mode; the plan says what the project's CI must do.
    let composed = Composed::existing("Rust (linux)");
    let plan = composed.install(&WITH_REQUIREMENTS, &[]);
    let lines: Vec<&str> = plan.lines().collect();
    let planned = format!("PLAN {REUSABLE} [managed:security]");
    assert!(lines.contains(&planned.as_str()), "{plan}");
    assert!(
        lines.contains(
            &"NOTE [security] diff-coverage: upload agentic-coverage-root-<job> from every test job of root with its LCOV report (*.info) (docs/agent-setup/security-gates.md), call .github/workflows/agentic-coverage.yml from a job named diff-coverage that needs them, and make your aggregate need it"
        ),
        "{plan}"
    );
    composed.install(&WITH_REQUIREMENTS, &["--apply"]);
    let separate = composed.repo.read(SEPARATE);
    assert!(!has_diff_job(&separate), "{separate}");
    assert!(
        !job(&job_blocks(&separate), "agentic-required")
            .join("\n")
            .contains(DIFF_COVERAGE),
        "{separate}"
    );
    let text = composed.repo.read(REUSABLE);
    golden("diff-coverage-project-ci.yml", &text);
    assert!(text.contains("\non:\n  workflow_call:\n"), "{text}");
    let job = diff_job(&text);
    for needle in [
        "pattern: \"agentic-coverage-root-*\"",
        "name: Combine the coverage of root",
        "- name: Check the changed lines of root",
        "- name: Characterization first of root",
        "- name: Save the per-file coverage reports",
    ] {
        assert!(job.contains(needle), "{needle}\n{job}");
    }
    assert!(!job.contains("needs: scope"), "{job}");
    assert!(!job.contains("cargo llvm-cov"), "no test runs here\n{job}");
    assert!(!job.contains("DIFF_COMMAND: "), "{job}");
    let again = composed.install(&[], &[]);
    assert!(again.lines().any(|l| l == "No changes."), "{again}");
}

#[test]
fn missing_coverage_data_fails_naming_the_artifact_and_the_recipe() {
    let composed = Composed::new();
    let combine = step_named(
        &diff_job(&composed.reusable()),
        "Combine the coverage of root",
    );
    assert!(
        combine.contains(
            "::error::No coverage data: this run uploaded no agentic-coverage-root-* artifact; upload its LCOV report (*.info) from every test job of root as docs/agent-setup/security-gates.md shows for rust. brakes never runs the tests to measure them"
        ),
        "{combine}"
    );
}

#[test]
fn project_ci_coverage_skips_an_app_whose_tests_did_not_run_and_carries_its_base_report() {
    // A CI that filters by path runs no test job for an app the change leaves alone.
    let composed = Composed::existing("Rust (linux)");
    composed
        .repo
        .answer(SECURITY, json!({"coverage_source": "project-ci"}));
    composed.install(&WITH_REQUIREMENTS, &["--apply"]);
    let job = diff_job(&composed.repo.read(REUSABLE));
    for needle in [
        "MERGE_BASE: \"${{ steps.merge-base.outputs.sha }}\"",
        "APP_PATH: \".\"",
        "echo \"skip=true\" >> \"$GITHUB_OUTPUT\"",
        "changes nothing under",
        "steps.measure-root.outputs.skip != 'true'",
        "- name: Restore the previous base report",
        "key: \"coverage-report-${{ github.event.before }}\"",
        "if [ -f lcov.info ]; then",
    ] {
        assert!(job.contains(needle), "{needle}\n{job}");
    }
}

#[test]
fn project_ci_coverage_for_a_python_root_matches_its_golden() {
    let composed = Composed::existing("Rust (linux)");
    composed
        .repo
        .write("pyproject.toml", "[project]\nname = \"sample\"\n");
    composed.repo.write("uv.lock", "");
    composed.repo.answer(
        "stack-packs",
        json!({"apps.root.path": ".", "apps.root.stack": "python-uv", "apps.root.toolchain_version": "3.13"}),
    );
    composed
        .repo
        .answer(SECURITY, json!({"coverage_source": "project-ci"}));
    composed.install(&WITH_REQUIREMENTS, &["--apply"]);
    let text = composed.repo.read(REUSABLE);
    golden("diff-coverage-project-ci-python.yml", &text);
    let job = diff_job(&text);
    assert!(job.contains("-print0 | sort -z"), "{job}");
    assert!(job.contains("| xargs -0 uv run --frozen --all-extras --with coverage==7.17.0 coverage combine --keep"), "{job}");
    assert!(!job.contains("pytest"), "no test runs here\n{job}");
}

#[test]
fn coverage_source_is_retired_ignored_and_noted() {
    // #22: both values are accepted for one version; neither the generated
    // workflow nor the ratchet refuses any more, and nothing measures.
    for value in ["job", "project-ci"] {
        let composed = Composed::new();
        composed.repo.answer(
            SECURITY,
            json!({"coverage_source": value, "coverage_ratchet": true}),
        );
        let plan = composed.install(&WITH_REQUIREMENTS, &[]);
        let note = format!(
            "NOTE [security] coverage_source {value} is retired and ignored: diff-coverage only reads the coverage data your CI uploads; remove the answer"
        );
        assert!(plan.lines().any(|l| l == note), "{plan}");
        assert_eq!(composed.reusable(), Composed::new().reusable_with_ratchet());
    }
}

#[test]
fn no_workflow_of_brakes_runs_diff_coverage_under_existing() {
    let composed = Composed::existing("Rust (linux)");
    composed.install(&WITH_REQUIREMENTS, &["--apply"]);
    assert!(!has_diff_job(&composed.repo.read(SEPARATE)));
    assert!(composed.repo.exists(REUSABLE), "the reusable workflow");
}

/// The contexts `.github/rulesets/main.json` requires.
fn ruleset_contexts(composed: &Composed) -> Vec<String> {
    let ruleset: Value =
        serde_json::from_str(&composed.repo.read(".github/rulesets/main.json")).unwrap();
    ruleset["rules"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["type"] == "required_status_checks")
        .flat_map(|r| {
            r["parameters"]["required_status_checks"]
                .as_array()
                .unwrap()
        })
        .map(|c| c["context"].as_str().unwrap().to_owned())
        .collect()
}

/// #1159: under `workflow: existing` with contributed jobs the ruleset requires
/// the project's own aggregate and `agentic-required`, never a `required` no
/// workflow reports; `check-reported` waits on those, and `doctor` agrees.
#[test]
fn existing_with_contributed_jobs_requires_the_own_aggregate_and_agentic_required() {
    let composed = Composed::existing("all-checks-passed");
    let modules = ["stack-packs", "ci-baseline", SECURITY, "repo-baseline"];
    let plan = composed.install(&modules, &["--apply"]);
    assert!(
        !plan.contains("the standard is one aggregate check"),
        "{plan}"
    );
    assert_eq!(
        ruleset_contexts(&composed),
        ["all-checks-passed", "agentic-required"]
    );
    let text = String::from_utf8(composed.cli(&["doctor", "<repo>"]).stdout).unwrap();
    assert!(!text.contains("ci.project-ci-stale"), "{text}");

    // A product's declared workaround, verbatim, is neither stale nor needed.
    let path = ".agent-setup/project.json";
    let mut profile: Value = serde_json::from_str(&composed.repo.read(path)).unwrap();
    profile["ci"]["required_checks"] = json!(["all-checks-passed", "agentic-required"]);
    composed.repo.write(
        path,
        &(serde_json::to_string_pretty(&profile).unwrap() + "\n"),
    );
    let text = String::from_utf8(composed.cli(&["doctor", "<repo>"]).stdout).unwrap();
    assert!(!text.contains("ci.project-ci-stale"), "{text}");
    let again = composed.install(&[], &[]);
    assert!(again.lines().any(|l| l == "No changes."), "{again}");
    // Only the aggregate would lose agentic-required once classic protection retires.
    profile["ci"]["required_checks"] = json!(["all-checks-passed"]);
    composed.repo.write(
        path,
        &(serde_json::to_string_pretty(&profile).unwrap() + "\n"),
    );
    let text = String::from_utf8(composed.cli(&["doctor", "<repo>"]).stdout).unwrap();
    assert!(
        text.contains("ci.project-ci-stale: .agent-setup/project.json ci.required_checks disagree"),
        "{text}"
    );
}

/// #1159: without contributed jobs nothing reports `agentic-required`; the
/// ruleset requires the project's own aggregate alone.
#[test]
fn existing_without_contributed_jobs_requires_the_own_aggregate() {
    let composed = Composed::existing("all-checks-passed");
    composed.install(
        &["stack-packs", "ci-baseline", "repo-baseline"],
        &["--apply"],
    );
    assert_eq!(ruleset_contexts(&composed), ["all-checks-passed"]);
    let text = String::from_utf8(composed.cli(&["doctor", "<repo>"]).stdout).unwrap();
    assert!(!text.contains("ci.project-ci-stale"), "{text}");
}

impl Composed {
    /// Declares `checks` as the profile's `ci.required_checks`.
    fn declare_required_checks(&self, checks: &[&str]) {
        let path = ".agent-setup/project.json";
        let mut profile: Value = serde_json::from_str(&self.repo.read(path)).unwrap();
        profile["ci"]["required_checks"] = json!(checks);
        self.repo.write(
            path,
            &(serde_json::to_string_pretty(&profile).unwrap() + "\n"),
        );
    }
}

/// The five contexts this repository declares in `ci.required_checks`.
const DECLARED: [&str; 5] = [
    "Rust (linux)",
    "Rust (macos)",
    "test / verify",
    "build",
    "promote",
];

/// #1297: a profile that declares `ci.required_checks` keeps them verbatim, and
/// the ruleset also lists `agentic-required`, which
/// `github:add-agentic-required-check` adds to the live ruleset; otherwise
/// `ruleset-main` could never verify after that item is written.
#[test]
fn existing_with_contributed_jobs_and_declared_checks_also_requires_agentic_required() {
    let composed = Composed::existing("Rust (linux)");
    composed.declare_required_checks(&DECLARED);
    composed.install(
        &["stack-packs", "ci-baseline", SECURITY, "repo-baseline"],
        &["--apply"],
    );
    let mut expected: Vec<&str> = DECLARED.to_vec();
    expected.push("agentic-required");
    assert_eq!(ruleset_contexts(&composed), expected);
    let again = composed.install(&[], &[]);
    assert!(again.lines().any(|l| l == "No changes."), "{again}");
}

/// #1297: declared checks that already list `agentic-required` render it once.
#[test]
fn declared_checks_listing_agentic_required_render_it_once() {
    let composed = Composed::existing("Rust (linux)");
    composed.declare_required_checks(&["agentic-required", "Rust (linux)"]);
    composed.install(
        &["stack-packs", "ci-baseline", SECURITY, "repo-baseline"],
        &["--apply"],
    );
    assert_eq!(
        ruleset_contexts(&composed),
        ["agentic-required", "Rust (linux)"]
    );
}

/// #1297: without contributed jobs nothing adds `agentic-required`; the
/// declared checks render verbatim.
#[test]
fn existing_without_contributed_jobs_renders_declared_checks_verbatim() {
    let composed = Composed::existing("Rust (linux)");
    composed.declare_required_checks(&DECLARED);
    composed.install(
        &["stack-packs", "ci-baseline", "repo-baseline"],
        &["--apply"],
    );
    assert_eq!(ruleset_contexts(&composed), DECLARED);
}

#[test]
fn existing_without_contributed_jobs_still_renders_nothing() {
    let composed = Composed::existing("Rust (linux)");
    let out = composed.install(&["stack-packs", "ci-baseline"], &["--apply"]);
    assert!(!out.contains("agentic-security"), "{out}");
    assert!(!out.contains("[managed:ci-baseline]"), "{out}");
    assert!(!composed.repo.exists(SEPARATE));
}

#[test]
fn existing_refuses_an_aggregate_check_named_like_the_separate_aggregate() {
    let composed = Composed::existing("agentic-required");
    assert_eq!(
        composed.refusal(),
        "REFUSED: ci-baseline: aggregate_check agentic-required is the check of .github/workflows/agentic-security.yml; answer the project's own required check"
    );
    assert!(!composed.repo.exists(SEPARATE));
}

#[test]
fn existing_refuses_a_foreign_job_named_agentic_required() {
    let composed = Composed::existing("Rust (linux)");
    composed.repo.write(
        ".github/workflows/gate.yml",
        "on: push\njobs:\n  gate:\n    name: agentic-required\n    runs-on: x\n",
    );
    assert_eq!(
        composed.refusal(),
        "REFUSED: ci-baseline: .github/workflows/gate.yml already has a job named agentic-required; the required check would be ambiguous; rename that job"
    );
}

#[test]
fn removing_security_deletes_the_separate_workflow_and_keeps_its_remote_item() {
    let composed = Composed::existing("Rust (linux)");
    composed.install(&WITH_REQUIREMENTS, &["--apply"]);
    let out = composed.cli(&["remove", "<repo>", SECURITY, "--apply"]);
    assert!(out.status.success(), "{out:?}");
    // `remove` touches only the removed module's files; the next install
    // re-renders ci-baseline without contributed jobs.
    let text = composed.install(&[], &["--apply"]);
    for line in [
        format!("DELETE {SEPARATE} [managed:ci-baseline]"),
        format!("KEEP {OWN} [never-touch:ci-baseline]"),
        "KEEP github:add-agentic-required-check [remote:ci-baseline]".to_owned(),
    ] {
        assert!(text.lines().any(|l| l == line), "{line}\n{text}");
    }
    assert!(!composed.repo.exists(SEPARATE));
    assert_eq!(composed.repo.read(OWN), OWN_YML);
}

// ---- #799: coverage-ratchet, its answers, its record seed ----------------------------

const COVERAGE_RECORD: &str = ".agent-setup/coverage.json";

#[test]
fn coverage_questions_are_off_by_default_and_tolerance_is_a_decimal_string() {
    let schema = Security.questions();
    let ids: Vec<&str> = schema.questions.iter().map(|q| q.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "secrets_scanner",
            "deps",
            "hooks",
            "bypass_max_days",
            "sast",
            "container_scan",
            "severity",
            "pii",
            "coverage_ratchet",
            "coverage_tolerance",
            "coverage_changed_lines",
            "coverage_changed_lines_min",
            "coverage_source",
            "coverage_runner",
            "coverage_test_args.*",
            "mutation_diff",
            "mutation_min_score"
        ]
    );
    let validated = schema
        .validate(SECURITY, &Answers::new(), answers::DEFAULT_TIER)
        .unwrap();
    assert_eq!(validated["coverage_ratchet"], json!(false));
    assert!(
        !validated.contains_key("coverage_tolerance"),
        "{validated:?}"
    );
    let on = Answers::from([("coverage_ratchet".to_owned(), json!(true))]);
    let validated = schema
        .validate(SECURITY, &on, answers::DEFAULT_TIER)
        .unwrap();
    assert_eq!(validated["coverage_tolerance"], json!("0.5"));
}

#[test]
fn coverage_off_renders_no_job_and_no_record() {
    let composed = Composed::new();
    let planned = composed.plan_with(&[]).unwrap();
    assert!(!planned.changes.contains_key(COVERAGE_RECORD));
    let text = planned.changes[WORKFLOW].clone().unwrap();
    assert!(!text.contains(COVERAGE_RATCHET), "{text}");
}

#[test]
fn coverage_on_matches_the_coverage_golden_and_seeds_a_zero_record() {
    let composed = Composed::new();
    composed
        .repo
        .answer(SECURITY, json!({"coverage_ratchet": true}));
    let planned = composed.plan_with(&[]).unwrap();
    assert_eq!(
        planned.changes[COVERAGE_RECORD].as_deref(),
        Some("{\n  \"schema\": 1,\n  \"apps\": {\n    \"root\": 0\n  }\n}\n")
    );
    // #22: the generated workflow neither runs the ratchet nor lists it.
    let workflow = planned.changes[WORKFLOW].clone().unwrap();
    assert!(!workflow.contains(COVERAGE_RATCHET), "{workflow}");
    let text = planned.changes[REUSABLE].clone().unwrap();
    golden("coverage.yml", &text);
    assert_eq!(text, composed.reusable(), "two renders differ");
    let blocks = job_blocks(&text);
    let ids: Vec<&str> = blocks.iter().map(|(id, _)| id.as_str()).collect();
    assert_eq!(ids, [DIFF_COVERAGE, COVERAGE_RATCHET]);
    let ratchet = job(&blocks, COVERAGE_RATCHET);
    for line in [
        "    timeout-minutes: 15",
        "          fetch-depth: \"0\"",
        "          set -- coverage-ratchet",
        "      - name: Download the coverage of root",
        "      - id: combine-root",
        "      - name: Write the coverage report of root",
        "      - name: Compare the coverage of root with the record",
        "          COVERAGE_TOLERANCE: \"0.5\"",
    ] {
        assert!(
            ratchet.contains(&line.to_owned()),
            "{line}\n{}",
            ratchet.join("\n")
        );
    }
    let body = ratchet.join("\n");
    for needle in [
        "needs:",
        "cargo llvm-cov",
        "cargo test",
        "tool: cargo-llvm-cov",
    ] {
        assert!(!body.contains(needle), "{needle}\n{body}");
    }
    assert!(
        body.contains("COVERAGE_APPS: \"[{\\\"app\\\":\\\"root\\\",\\\"metric\\\":\\\".data[0].totals.lines.percent\\\",\\\"report\\\":\\\"coverage.json\\\"}]\""),
        "{body}"
    );
    // Every step after the bypass step runs only without a grant.
    let steps: Vec<String> = body
        .split("\n      - ")
        .skip(1)
        .map(str::to_owned)
        .collect();
    assert!(steps[1].starts_with("id: bypass"), "{}", steps[1]);
    for step in &steps[2..] {
        assert!(
            step.contains("\n        if: steps.bypass.outputs.id == ''"),
            "{step}"
        );
    }
    let pins = PinTable::embedded().unwrap();
    for line in ratchet.iter().filter(|l| l.contains("uses:")) {
        let uses = line.split("uses: ").nth(1).unwrap();
        let repo = uses.split('@').next().unwrap();
        assert_eq!(uses, pins.action(repo).unwrap().uses(), "{line}");
    }
}

#[test]
fn coverage_on_without_a_covered_app_refuses() {
    let composed = Composed::new();
    composed.repo.write("package.json", "{}");
    composed.repo.write("package-lock.json", "{}");
    composed.repo.answer(
        "stack-packs",
        json!({"apps.root.path": ".", "apps.root.stack": "node", "apps.root.toolchain_version": "24"}),
    );
    composed
        .repo
        .answer(SECURITY, json!({"coverage_ratchet": true}));
    assert_eq!(
        composed.plan_with(&[]).unwrap_err().to_string(),
        "Module security: coverage_ratchet needs an app whose stack pack declares coverage (python-uv, rust)"
    );
}

#[test]
fn coverage_tolerance_must_be_a_percentage() {
    for bad in ["-1", "abc", "1e2", "100.5", ".5", "0.5 ", "00.5", "1."] {
        let composed = Composed::new();
        composed.repo.answer(
            SECURITY,
            json!({"coverage_ratchet": true, "coverage_tolerance": bad}),
        );
        assert_eq!(
            composed.plan_with(&[]).unwrap_err().to_string(),
            format!(
                "Module security: coverage_tolerance {bad} is not a percentage between 0 and 100"
            ),
            "{bad}"
        );
    }
    let composed = Composed::new();
    composed.repo.answer(
        SECURITY,
        json!({"coverage_ratchet": true, "coverage_tolerance": "0"}),
    );
    let text = composed.reusable();
    assert!(text.contains("COVERAGE_TOLERANCE: \"0\""), "{text}");
}

#[test]
fn ci_jobs_never_contributes_coverage_ratchet() {
    // #22: it is a job of agentic-coverage.yml, which the project's CI calls.
    let composed = Composed::new();
    let jobs = with_cx(&composed.repo, json!({"coverage_ratchet": true}), |cx| {
        jobs::contributed(cx).unwrap()
    });
    let tiers: Vec<(&str, &[CiTier])> = jobs
        .iter()
        .map(|j| (j.id.as_str(), j.skippable_under.as_slice()))
        .collect();
    assert_eq!(
        tiers,
        [
            (SECURITY_GATE, &[][..]),
            (DEPS_SCAN, &[CiTier::Docs][..]),
            (SAST, &[CiTier::Docs][..]),
            (CONTAINER_SCAN, &[CiTier::Docs][..])
        ]
    );
}

#[test]
fn coverage_ratchet_reads_each_covered_app_in_its_directory_and_seeds_each() {
    let composed = Composed::new();
    composed
        .repo
        .write("web/pyproject.toml", "[project]\nname = \"web\"\n");
    composed.repo.write("web/uv.lock", "");
    // Each app declares its own commands (ci-baseline Decision 8).
    composed.repo.write(
        "web/.agent-setup/project.json",
        r#"{"commands": {"test": "uv run pytest"}}"#,
    );
    composed.repo.answer(
        "stack-packs",
        json!({"apps.root.path": ".", "apps.root.stack": "rust",
               "apps.web.path": "web", "apps.web.stack": "python-uv", "apps.web.toolchain_version": "3.13"}),
    );
    composed
        .repo
        .answer(SECURITY, json!({"coverage_ratchet": true}));
    let planned = composed.plan_with(&[]).unwrap();
    assert_eq!(
        planned.changes[COVERAGE_RECORD].as_deref(),
        Some("{\n  \"schema\": 1,\n  \"apps\": {\n    \"root\": 0,\n    \"web\": 0\n  }\n}\n")
    );
    let text = planned.changes[REUSABLE].clone().unwrap();
    let blocks = job_blocks(&text);
    let ratchet = job(&blocks, COVERAGE_RATCHET).join("\n");
    for expected in [
        "      - name: Write the coverage report of web\n        if: steps.bypass.outputs.id == '' && (steps.combine-web.outputs.skip != 'true')\n        working-directory: web\n        run: |\n          uv run --frozen --all-extras --with coverage==7.17.0 coverage json -q -i -o coverage.json",
        "\\\"report\\\":\\\"web/coverage.json\\\"",
        "\\\"report\\\":\\\"coverage.json\\\"",
    ] {
        assert!(ratchet.contains(expected), "{expected}\n{ratchet}");
    }
}

// ---- #979: mutation-diff (opt-in) ---------------------------------------------------

impl Composed {
    /// `Composed` with a python-uv app at `.` in place of the rust one.
    fn python() -> Self {
        let composed = Self::new();
        let repo = &composed.repo;
        fs::remove_file(repo.root.join("Cargo.toml")).unwrap();
        fs::remove_file(repo.root.join("Cargo.lock")).unwrap();
        let path = ".agent-setup/project.json";
        let mut profile: Value = serde_json::from_str(&repo.read(path)).unwrap();
        profile["commands"]["lint"] = "uv run --frozen ruff check".into();
        profile["commands"]["test"] = "uv run --frozen pytest -q".into();
        profile["commands"]["build"] = "uv build".into();
        repo.write(
            path,
            &(serde_json::to_string_pretty(&profile).unwrap() + "\n"),
        );
        repo.write("pyproject.toml", "[project]\nname = \"sample\"\n");
        repo.write("uv.lock", "");
        repo.answer(
            "stack-packs",
            json!({"apps.root.path": ".", "apps.root.stack": "python-uv", "apps.root.toolchain_version": "3.13"}),
        );
        composed
    }
    fn mutation(self, security: Value) -> Self {
        self.repo.answer(SECURITY, security);
        self
    }
}

#[test]
fn mutation_answers_are_opt_in_with_a_minimum_score_of_80() {
    let schema = Security.questions();
    let ids: Vec<&str> = schema.questions.iter().map(|q| q.id.as_str()).collect();
    assert_eq!(
        ids[ids.len() - 2..],
        ["mutation_diff", "mutation_min_score"]
    );
    let validated = schema
        .validate(SECURITY, &Answers::new(), answers::DEFAULT_TIER)
        .unwrap();
    assert_eq!(validated["mutation_diff"], json!(false));
    assert!(
        !validated.contains_key("mutation_min_score"),
        "{validated:?}"
    );
    let on = Answers::from([("mutation_diff".to_owned(), json!(true))]);
    let validated = schema
        .validate(SECURITY, &on, answers::DEFAULT_TIER)
        .unwrap();
    assert_eq!(validated["mutation_min_score"], json!(80));
    for score in [json!(-1), json!(101), json!("80")] {
        let mut raw = on.clone();
        raw.insert("mutation_min_score".to_owned(), score.clone());
        assert!(
            schema
                .validate(SECURITY, &raw, answers::DEFAULT_TIER)
                .is_err(),
            "mutation_min_score={score} accepted"
        );
    }
}

#[test]
fn mutation_diff_is_absent_by_default() {
    let composed = Composed::new();
    let jobs = with_cx(&composed.repo, json!({}), |cx| {
        jobs::contributed(cx).unwrap()
    });
    assert!(!jobs.iter().any(|j| j.id == MUTATION_DIFF));
    assert!(!minimal_golden().contains("mutation"));
}

#[test]
fn mutation_diff_for_rust_matches_its_golden_and_reaches_required() {
    let composed = Composed::new().mutation(json!({"mutation_diff": true}));
    let text = composed.workflow();
    golden("mutation-rust.yml", &text);
    assert_eq!(text, composed.workflow(), "two renders differ");
    let blocks = job_blocks(&text);
    let required = job(&blocks, "required").join("\n");
    assert!(
        required.contains(
            "needs: [scope, checks, heldout, workflow-lint, security-gate, deps-scan, sast, container-scan, mutation-diff]"
        ),
        "{required}"
    );
    let scope = job(&blocks, "scope").join("\n");
    let docs = scope.split_once("DOCS_SKIPPABLE: |-\n").unwrap().1;
    assert!(docs.lines().any(|l| l.trim() == MUTATION_DIFF), "{docs}");
    let jobs = with_cx(&composed.repo, json!({"mutation_diff": true}), |cx| {
        jobs::contributed(cx).unwrap()
    });
    let mutation = jobs.iter().find(|j| j.id == MUTATION_DIFF).unwrap();
    assert_eq!(mutation.skippable_under, [CiTier::Docs]);
}

#[test]
fn mutation_diff_for_python_matches_its_golden() {
    let composed =
        Composed::python().mutation(json!({"mutation_diff": true, "mutation_min_score": 70}));
    let text = composed.workflow();
    golden("mutation-python.yml", &text);
    assert_eq!(text, composed.workflow(), "two renders differ");
}

/// The `timeout-minutes` of `mutation-diff` and of the two jobs of
/// `agentic-coverage.yml` when the profile declares `ci.cycle_budget_minutes`
/// as `budget` (`None`: not declared).
fn coverage_timeouts(budget: Option<Value>) -> Vec<(String, String)> {
    let composed = Composed::new();
    let path = ".agent-setup/project.json";
    let mut profile: Value = serde_json::from_str(&composed.repo.read(path)).unwrap();
    profile["ci"]["cycle_budget_minutes"] = budget.unwrap_or(Value::Null);
    composed.repo.write(
        path,
        &(serde_json::to_string_pretty(&profile).unwrap() + "\n"),
    );
    composed.repo.answer(
        SECURITY,
        json!({"sast": "none", "container_scan": false, "coverage_ratchet": true, "mutation_diff": true}),
    );
    let reusable = composed.reusable();
    let workflow = composed.workflow();
    [
        (COVERAGE_RATCHET, &reusable),
        (DIFF_COVERAGE, &reusable),
        (MUTATION_DIFF, &workflow),
    ]
    .into_iter()
    .map(|(id, text)| {
        let timeout = job(&job_blocks(text), id)
            .iter()
            .find_map(|l| l.strip_prefix("    timeout-minutes: "))
            .unwrap_or_else(|| panic!("{id} has a timeout\n{text}"))
            .to_owned();
        (id.to_owned(), timeout)
    })
    .collect()
}

/// #1213: one measurement is `ceil(budget * 1.5)`, the checks jobs' timeout;
/// mutation-diff adds one to its mutants' 30 minutes; a budget never lowers a
/// default. The coverage jobs only combine and judge (#22): 15 minutes.
#[test]
fn coverage_timeouts_follow_the_declared_cycle_budget() {
    let pairs = |r, d, m| -> Vec<(String, String)> {
        [
            (COVERAGE_RATCHET, r),
            (DIFF_COVERAGE, d),
            (MUTATION_DIFF, m),
        ]
        .into_iter()
        .map(|(id, t): (&str, &str)| (id.to_owned(), t.to_owned()))
        .collect()
    };
    // Undeclared, or not a finite positive number: the fixed defaults.
    // #22: the coverage jobs run no test, so the budget never reaches them.
    assert_eq!(coverage_timeouts(None), pairs("15", "15", "30"));
    assert_eq!(coverage_timeouts(Some(json!(0))), pairs("15", "15", "30"));
    assert_eq!(
        coverage_timeouts(Some(json!("15"))),
        pairs("15", "15", "30")
    );
    assert_eq!(coverage_timeouts(Some(json!(18))), pairs("15", "15", "57"));
    // #1228: capped at GitHub's 360-minute job maximum.
    assert_eq!(
        coverage_timeouts(Some(json!(300))),
        pairs("15", "15", "360")
    );
    assert_eq!(coverage_timeouts(Some(json!(5))), pairs("15", "15", "38"));
}

/// #1228: the plan notes the coverage jobs whose budget-derived timeout was
/// capped, with the uncapped value; none below the maximum.
#[test]
fn coverage_timeouts_above_the_job_maximum_are_noted() {
    let notes = |budget: Value| -> Vec<String> {
        let composed = Composed::new();
        let path = ".agent-setup/project.json";
        let mut profile: Value = serde_json::from_str(&composed.repo.read(path)).unwrap();
        profile["ci"]["cycle_budget_minutes"] = budget;
        composed.repo.write(
            path,
            &(serde_json::to_string_pretty(&profile).unwrap() + "\n"),
        );
        let security = json!({
            "sast": "none", "container_scan": false,
            "coverage_ratchet": true, "mutation_diff": true,
        });
        with_cx(&composed.repo, security, |cx| Security.notes(cx).unwrap())
            .into_iter()
            .filter(|n| n.starts_with("ci.cycle_budget_minutes"))
            .collect()
    };
    assert_eq!(notes(json!(150)), Vec::<String>::new());
    assert_eq!(
        notes(json!(300)),
        [
            "ci.cycle_budget_minutes 300 derives timeouts above GitHub's 360-minute job maximum (mutation-diff 480); those jobs render timeout-minutes: 360"
        ]
    );
}

/// The job's lines, from the golden.
fn mutation_job(name: &str) -> Vec<String> {
    let text = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(GOLDENS)
            .join(name),
    )
    .unwrap();
    job(&job_blocks(&text), MUTATION_DIFF).to_vec()
}

#[test]
fn mutation_diff_runs_on_pull_requests_only_through_step_conditions() {
    for name in ["mutation-rust.yml", "mutation-python.yml"] {
        let lines = mutation_job(name);
        let text = lines.join("\n");
        // The job condition carries the tier only; every step the event.
        assert!(
            lines.contains(&"    if: needs.scope.outputs.tier != 'docs'".to_owned()),
            "{name}"
        );
        assert_eq!(
            lines.iter().filter(|l| l.starts_with("    if:")).count(),
            1,
            "{name}"
        );
        let steps = lines.iter().filter(|l| l.starts_with("      - ")).count();
        let conditioned = lines
            .iter()
            .filter(|l| {
                l.trim_start().starts_with("if:")
                    && l.contains("github.event_name == 'pull_request'")
            })
            .count();
        assert_eq!(
            steps, conditioned,
            "{name}: every step is pull-request only\n{text}"
        );
        for expected in [
            "    timeout-minutes: 30",
            "    permissions:",
            "      contents: read",
            "          fetch-depth: \"0\"",
            "          persist-credentials: \"false\"",
            "          retention-days: \"7\"",
            "      - id: bypass",
        ] {
            assert!(
                lines.contains(&expected.to_owned()),
                "{name}: {expected}\n{text}"
            );
        }
        assert!(
            text.contains("if: ${{ always() && github.event_name == 'pull_request' }}"),
            "{name}"
        );
        assert!(text.contains("set -- mutation-diff\n"), "{name}");
        assert!(
            text.contains("BASE_SHA: \"${{ github.event.pull_request.base.sha }}\""),
            "{name}"
        );
        assert!(
            !lines
                .iter()
                .any(|l| l.trim_start().starts_with("continue-on-error:")),
            "{name}"
        );
        assert!(!text.contains("|| true"), "{name}");
    }
}

#[test]
fn mutation_diff_runs_the_pinned_recipe_of_each_pack() {
    let rust = mutation_job("mutation-rust.yml").join("\n");
    for expected in [
        "set -- cargo-mutants 80",
        "MUTATION_COMMAND: cargo mutants --no-shuffle --in-diff git.diff",
        "tool: cargo-mutants@27.1.0",
        "path: mutants.out",
    ] {
        assert!(rust.contains(expected), "rust: {expected}\n{rust}");
    }
    let python = mutation_job("mutation-python.yml").join("\n");
    for expected in [
        "set -- mutmut 70",
        r#"MUTATION_COMMAND: "uv run --frozen --all-extras --with mutmut==3.8.1 mutmut run \"$MUTATION_MODULE*\"""#,
        "MUTATION_STATS: \"uv run --frozen --all-extras --with mutmut==3.8.1 mutmut export-cicd-stats\"",
        "path: mutants/mutmut-cicd-stats.json",
        "uv sync --frozen",
    ] {
        assert!(python.contains(expected), "python: {expected}\n{python}");
    }
    // The cache save of the pack's setup runs on the default branch only, which
    // a pull-request-only job never is: it is not rendered.
    assert!(!python.contains("Save uv cache"), "{python}");
    let pins = PinTable::embedded().unwrap();
    for (name, text) in [("rust", &rust), ("python", &python)] {
        for line in text.lines().filter(|l| l.contains("uses:")) {
            let uses = line.split("uses: ").nth(1).unwrap();
            let repo = uses.split('@').next().unwrap();
            assert_eq!(uses, pins.action(repo).unwrap().uses(), "{name}: {line}");
        }
        let script = jobs::MUTATION_DIFF_SH
            .lines()
            .find(|l| l.starts_with("run_mutmut() {"))
            .unwrap();
        assert!(
            text.contains(script),
            "{name}: the shell is embedded verbatim"
        );
    }
}

#[test]
fn mutation_diff_refuses_where_no_installed_pack_declares_mutation() {
    let composed = Composed::new().mutation(json!({"mutation_diff": true}));
    composed.repo.answer(
        "stack-packs",
        json!({"apps.root.path": ".", "apps.root.stack": "go"}),
    );
    composed.repo.write("go.mod", "module sample\n");
    composed.repo.write("go.sum", "");
    let error = composed.plan_with(&[]).unwrap_err().to_string();
    assert_eq!(
        error,
        "Module security: mutation_diff needs a stack pack that declares mutation (rust, python-uv); no app of this repository has one"
    );
}

#[test]
fn the_guide_states_the_mutation_gaps_and_the_mutmut_configuration() {
    for text in [
        "## Mutation testing on the diff (opt-in)",
        "mutates every **changed file**, not\n  only the changed lines",
        "mutate_only_covered_lines = true",
        "a full mutation run\nis the project's own scheduled job",
        "measure the run time on one real\npull request",
    ] {
        assert!(GUIDE.contains(text), "guide lacks {text:?}");
    }
}

// ---- #1088: shells are embedded without comment-only lines ---------------------------

/// `shell` as a step's `run:` body: comment-only lines dropped, every other
/// non-empty line indented ten spaces, empty lines kept empty.
fn run_body(shell: &str) -> String {
    brakes::modules::security::embed::without_comment_lines(shell)
        .lines()
        .map(|l| {
            if l.is_empty() {
                String::new()
            } else {
                format!("          {l}")
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn every_embedded_shell_is_its_fragment_without_comment_only_lines() {
    let full = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(GOLDENS)
            .join("full.yml"),
    )
    .unwrap();
    // Only the security jobs: ci-baseline's own jobs embed their shells themselves.
    let blocks = job_blocks(&full);
    let full: String = [SECURITY_GATE, DEPS_SCAN, SAST, CONTAINER_SCAN]
        .iter()
        .map(|id| job(&blocks, id).join("\n"))
        .collect::<Vec<_>>()
        .join("\n");
    for (name, shell) in [
        ("install-tool.sh", brakes::modules::security::INSTALL_TOOL),
        ("gitleaks-scan.sh", GITLEAKS_SCAN),
        (
            "exceptions-check.sh",
            include_str!("../../../templates/security/fragments/exceptions-check.sh"),
        ),
        (
            "bypass-variable.sh",
            include_str!("../../../templates/security/fragments/bypass-variable.sh"),
        ),
    ] {
        assert!(
            full.contains(&run_body(shell)),
            "{name} is not embedded as its stripped fragment"
        );
        let first_comment = shell
            .lines()
            .find(|l| l.trim_start().starts_with("# "))
            .unwrap();
        assert!(
            !full.contains(first_comment.trim()),
            "{name}: {first_comment:?} was embedded"
        );
    }
}

// ---- #978: diff-coverage, changed lines and characterization first ------------------

use brakes::modules::security::diff_coverage::{self as diff_coverage, DIFF_COVERAGE};

/// The `diff-coverage` job of a composed workflow, as one text.
fn diff_job(text: &str) -> String {
    job(&job_blocks(text), DIFF_COVERAGE).join("\n")
}

fn has_diff_job(text: &str) -> bool {
    job_blocks(text).iter().any(|(id, _)| id == DIFF_COVERAGE)
}

/// The steps of a job body (`      - ` items), as texts.
fn steps_of(job: &str) -> Vec<String> {
    job.split("\n      - ").skip(1).map(str::to_owned).collect()
}

#[test]
fn diff_coverage_is_derived_on_for_a_rust_root_and_matches_its_golden() {
    let composed = Composed::new();
    // #22: the reusable workflow the project's CI calls; no workflow of brakes runs it.
    let text = composed.reusable();
    let job = diff_job(&text);
    golden("diff-coverage-rust.yml", &text);
    for line in [
        "    timeout-minutes: 15",
        "          fetch-depth: \"0\"",
        "          persist-credentials: \"false\"",
        "          set -- diff-coverage",
        "          pattern: \"agentic-coverage-root-*\"",
        "          DIFF_COVER: \"uvx diff-cover==10.6.0\"",
        "          MIN: \"80\"",
        "          DIFF_FORMAT: lcov",
        "          ABSENT: fail",
        "          SOURCE_EXT: rs",
        "          APP_ID: root",
        "          APP_PATH: \".\"",
        "          BASE_REPORT: \".coverage-base/root/lcov.info\"",
        "          key: \"coverage-report-${{ steps.merge-base.outputs.sha }}\"",
        "          path: \".coverage-base\"",
        "          PR_NUMBER: \"${{ github.event.pull_request.number }}\"",
    ] {
        assert!(job.lines().any(|l| l == line), "{line}\n{job}");
    }
    assert!(job.contains("uses: astral-sh/setup-uv@"), "{job}");
    // No job condition on the event; every step carries its own.
    assert!(
        !job.lines()
            .any(|l| l.starts_with("    if:") && l.contains("event_name"))
    );
    for step in steps_of(&job) {
        assert!(step.contains("\n        if: "), "{step}");
    }
    let names = step_names(&job);
    for name in [
        "Combine the coverage of root",
        "Keep the per-file coverage reports",
        "Save the per-file coverage reports",
        "Write diff-coverage.sh",
        "Check the changed lines of root",
        "Characterization first of root",
    ] {
        assert!(names.contains(&name.to_owned()), "{name}: {names:?}");
    }
    // The shell is written once, byte for byte, and every judging step runs it.
    let write = steps_of(&job)
        .into_iter()
        .find(|s| s.contains("name: Write diff-coverage.sh"))
        .unwrap();
    let body: String = write
        .split_once("<<'DIFF_COVERAGE_SH'\n")
        .unwrap()
        .1
        .lines()
        .take_while(|l| l.trim() != "DIFF_COVERAGE_SH")
        .map(|l| format!("{}\n", l.strip_prefix("          ").unwrap_or(l)))
        .collect();
    assert_eq!(
        body,
        brakes::modules::security::embed::without_comment_lines(diff_coverage::DIFF_COVERAGE_SH)
    );
    // #1169: the writer runs whenever its consumers run, so a failed
    // measurement never surfaces as a missing script (exit 127).
    let judging = step_named(&job, "Check the changed lines of root");
    let condition = |step: &str| {
        step.lines()
            .find(|l| l.starts_with("        if: "))
            .map(str::to_owned)
    };
    // #1170: a judging step also needs its own app's measurement, so the
    // writer's condition is the judging one without that conjunct.
    assert_eq!(
        condition(&write)
            .map(|c| c.replace(
                " }}",
                " && steps.measure-root.outcome == 'success' && steps.measure-root.outputs.skip != 'true' }}",
            )),
        condition(&judging),
        "{write}\n{judging}"
    );
    assert!(write.contains("!cancelled()"), "{write}");
    assert_eq!(
        job.matches("bash \"$RUNNER_TEMP/diff-coverage.sh\"")
            .count(),
        2
    );
    // No test runs: no coverage tool, no declared command, and the generated
    // workflow neither runs diff-coverage nor needs it.
    for needle in [
        "cargo llvm-cov",
        "cargo test",
        "cargo-llvm-cov",
        "DIFF_COMMAND",
    ] {
        assert!(!job.contains(needle), "{needle}\n{job}");
    }
    let workflow = composed.workflow();
    assert!(!has_diff_job(&workflow), "{workflow}");
    let blocks = job_blocks(&workflow);
    assert!(
        !blocks
            .iter()
            .find(|(id, _)| id == "required")
            .unwrap()
            .1
            .join("\n")
            .contains(DIFF_COVERAGE),
        "{workflow}"
    );
}

/// The `name:` of every step of a job body, in order.
fn step_names(job: &str) -> Vec<String> {
    steps_of(job)
        .iter()
        .filter_map(|s| s.lines().find_map(|l| l.trim().strip_prefix("name: ")))
        .map(str::to_owned)
        .collect()
}

/// The step of `job` named `name`.
fn step_named(job: &str, name: &str) -> String {
    steps_of(job)
        .into_iter()
        .find(|s| s.lines().any(|l| l.trim() == format!("name: {name}")))
        .unwrap_or_else(|| panic!("no step {name}"))
}

#[test]
fn diff_coverage_saves_the_base_report_on_default_branch_pushes() {
    let composed = Composed::new();
    let job = diff_job(&composed.reusable());
    let push_only = format!(
        "        if: github.event_name == 'push' && {}",
        brakes::modules::stack_packs::DEFAULT_BRANCH_CONDITION
    );
    let keep = step_named(&job, "Keep the per-file coverage reports");
    assert!(keep.lines().any(|l| l == push_only), "{keep}");
    assert!(keep.contains("          if [ -f lcov.info ]; then\n            mkdir -p .coverage-base/root\n            cp lcov.info .coverage-base/root/lcov.info\n          fi"), "{keep}");
    let save = step_named(&job, "Save the per-file coverage reports");
    assert!(save.lines().any(|l| l == push_only), "{save}");
    assert!(save.contains("uses: actions/cache/save@"));
    assert!(save.contains("          key: \"coverage-report-${{ github.sha }}\""));
    // Checkout, setup and combine run on both; the judging steps on pull requests only.
    let both = format!(
        "(github.event_name == 'pull_request' || (github.event_name == 'push' && {}))",
        brakes::modules::stack_packs::DEFAULT_BRANCH_CONDITION
    );
    assert!(step_named(&job, "Check out").contains(&format!("        if: {both}")));
    assert!(
        step_named(&job, "Combine the coverage of root").contains(&format!(
            "        if: {both} && steps.bypass.outputs.id == ''"
        ))
    );
    for name in [
        "Find the merge base",
        "Restore the base coverage report",
        "Write diff-coverage.sh",
        "Check the changed lines of root",
    ] {
        let step = step_named(&job, name);
        assert!(
            step.contains("github.event_name == 'pull_request' && steps.bypass.outputs.id == ''"),
            "{step}"
        );
        assert!(!step.contains("'push'"), "{step}");
    }
}

#[test]
fn with_the_ratchet_on_both_coverage_jobs_read_uploads_and_only_diff_coverage_saves() {
    // #22: coverage-ratchet is the reusable workflow's second job; it reads the
    // uploaded data, writes the report its metric reads, and runs no test.
    let composed = Composed::new();
    composed
        .repo
        .answer(SECURITY, json!({"coverage_ratchet": true}));
    let workflow = composed.workflow();
    assert!(
        !job_blocks(&workflow)
            .iter()
            .any(|(id, _)| id == COVERAGE_RATCHET),
        "{workflow}"
    );
    let text = composed.reusable();
    assert!(diff_job(&text).contains("actions/cache/save@"));
    let ratchet = job(&job_blocks(&text), COVERAGE_RATCHET).join("\n");
    for name in [
        "Download the coverage of root",
        "Combine the coverage of root",
        "Compare the coverage of root with the record",
    ] {
        step_named(&ratchet, name);
    }
    let report = step_named(&ratchet, "Write the coverage report of root");
    assert!(report.contains("lcov.info > coverage.json"), "{report}");
    assert!(
        report.contains(
            "        if: steps.bypass.outputs.id == '' && (steps.combine-root.outputs.skip != 'true')"
        ),
        "{report}"
    );
    for needle in [
        "cargo llvm-cov",
        "cargo test",
        "pytest",
        "actions/cache/save@",
    ] {
        assert!(!ratchet.contains(needle), "{needle}\n{ratchet}");
    }
    assert_eq!(
        text.matches("uses: actions/cache/save@").count(),
        1,
        "exactly one job saves the key"
    );
    assert_eq!(
        diff_coverage::cache_key("github.sha"),
        "coverage-report-${{ github.sha }}"
    );
}

/// A monorepo: a rust app in `apps/api` and a python-uv app in `apps/web`, each
/// with its own profile, and optionally a rust app at the root.
fn monorepo(root_app: bool) -> Composed {
    let composed = Composed::new();
    let repo = &composed.repo;
    if !root_app {
        fs::remove_file(repo.root.join("Cargo.toml")).unwrap();
        fs::remove_file(repo.root.join("Cargo.lock")).unwrap();
        // Without a root app the root profile declares nothing: a root command
        // would run in ci-baseline's root `checks` job (#1165).
        let path = ".agent-setup/project.json";
        let mut profile: Value = serde_json::from_str(&repo.read(path)).unwrap();
        for name in ["lint", "test", "build"] {
            profile["commands"][name] = Value::Null;
        }
        repo.write(
            path,
            &(serde_json::to_string_pretty(&profile).unwrap() + "\n"),
        );
    }
    repo.write("apps/api/Cargo.toml", "");
    repo.write("apps/api/Cargo.lock", "");
    repo.write(
        "apps/api/.agent-setup/project.json",
        r#"{"commands": {"test": "cargo test --locked"}}"#,
    );
    repo.write("apps/web/pyproject.toml", "[project]\nname = \"web\"\n");
    repo.write("apps/web/uv.lock", "");
    repo.write(
        "apps/web/.agent-setup/project.json",
        r#"{"commands": {"test": "uv run --frozen pytest -q"}}"#,
    );
    let mut apps = json!({"apps.api.path": "apps/api", "apps.api.stack": "rust",
                          "apps.web.path": "apps/web", "apps.web.stack": "python-uv", "apps.web.toolchain_version": "3.13"});
    if root_app {
        apps["apps.root.path"] = json!(".");
        apps["apps.root.stack"] = json!("rust");
    }
    repo.answer("stack-packs", apps);
    composed
}

/// #1169: the question says what the derivation does since #1130: unanswered,
/// on wherever any recorded app (not only one at the root) has a per-file report.
#[test]
fn coverage_changed_lines_describes_its_derived_default_over_every_app() {
    let schema = Security.questions();
    let question = schema
        .questions
        .iter()
        .find(|q| q.id == "coverage_changed_lines")
        .unwrap();
    assert!(
        !question.description.contains("root app"),
        "{}",
        question.description
    );
    assert!(
        question
            .description
            .contains("unanswered, on where any app's stack pack has a per-file coverage report"),
        "{}",
        question.description
    );
}

#[test]
fn a_monorepo_combines_and_judges_every_covered_app_in_its_directory() {
    let composed = monorepo(false);
    let text = composed.reusable();
    golden("diff-coverage-monorepo.yml", &text);
    let job = diff_job(&text);
    for (name, lines) in [
        (
            "Combine the coverage of api",
            &["        working-directory: apps/api"][..],
        ),
        (
            "Combine the coverage of web",
            &["        working-directory: apps/web"][..],
        ),
        (
            "Check the changed lines of api",
            &[
                "          APP_ID: api",
                "          DIFF_REPORT: apps/api/lcov.info",
                "          DIFF_FORMAT: lcov",
            ][..],
        ),
        (
            "Check the changed lines of web",
            &[
                "          APP_ID: web",
                "          DIFF_REPORT: apps/web/coverage.xml",
                "          DIFF_FORMAT: cobertura",
            ][..],
        ),
        (
            "Characterization first of api",
            &[
                "          APP_PATH: apps/api",
                "          BASE_REPORT: \".coverage-base/api/lcov.info\"",
                "          ABSENT: fail",
            ][..],
        ),
        (
            "Characterization first of web",
            &[
                "          APP_PATH: apps/web",
                "          BASE_REPORT: \".coverage-base/web/coverage.xml\"",
                "          ABSENT: warn",
            ][..],
        ),
    ] {
        let step = step_named(&job, name);
        for line in lines {
            assert!(step.lines().any(|l| l == *line), "{name}: {line}\n{step}");
        }
    }
    assert!(
        !job.lines()
            .any(|l| l.trim_start().starts_with("EXCLUDE_PATHS:")),
        "no app at the root, nothing to exclude"
    );
    for step in steps_of(&job) {
        assert!(step.contains("\n        if: "), "{step}");
    }
    let keep = step_named(&job, "Keep the per-file coverage reports");
    assert!(keep.contains("mkdir -p .coverage-base/api\n            cp apps/api/lcov.info .coverage-base/api/lcov.info"), "{keep}");
    assert!(keep.contains("mkdir -p .coverage-base/web\n            cp apps/web/coverage.xml .coverage-base/web/coverage.xml"), "{keep}");
    assert_eq!(
        step_names(&job)
            .iter()
            .filter(|n| *n == "Restore the base coverage report")
            .count(),
        1,
        "one entry per commit"
    );
    assert_eq!(job.matches("uses: astral-sh/setup-uv@").count(), 1, "{job}");
}

#[test]
fn the_root_app_of_a_monorepo_excludes_the_other_apps() {
    let job = diff_job(&monorepo(true).reusable());
    let root = step_named(&job, "Characterization first of root");
    assert!(
        root.contains("          EXCLUDE_PATHS: |-\n            apps/api\n            apps/web"),
        "{root}"
    );
    assert!(!step_named(&job, "Characterization first of api").contains("EXCLUDE_PATHS"));
}

#[test]
fn diff_coverage_for_a_python_root_matches_its_golden() {
    let composed = Composed::new();
    composed
        .repo
        .write("pyproject.toml", "[project]\nname = \"sample\"\n");
    composed.repo.write("uv.lock", "");
    composed.repo.answer(
        "stack-packs",
        json!({"apps.root.path": ".", "apps.root.stack": "python-uv", "apps.root.toolchain_version": "3.13"}),
    );
    let text = composed.reusable();
    golden("diff-coverage-python.yml", &text);
    let job = diff_job(&text);
    for line in [
        "          DIFF_FORMAT: cobertura",
        "          ABSENT: warn",
        "          SOURCE_EXT: py",
        "          DIFF_REPORT: coverage.xml",
        "          key: \"coverage-report-${{ steps.merge-base.outputs.sha }}\"",
        "          BASE_REPORT: \".coverage-base/root/coverage.xml\"",
    ] {
        assert!(job.lines().any(|l| l == line), "{line}\n{job}");
    }
    assert_eq!(job.matches("uses: astral-sh/setup-uv@").count(), 1, "{job}");
}

#[test]
fn node_and_go_roots_render_no_diff_coverage_job_and_true_refuses() {
    for (stack, files) in [
        (
            "node",
            &[("package.json", "{}"), ("package-lock.json", "{}")][..],
        ),
        (
            "go",
            &[("go.mod", "module x\n\ngo 1.24\n"), ("go.sum", "")][..],
        ),
    ] {
        let composed = Composed::new();
        for (path, text) in files {
            composed.repo.write(path, text);
        }
        composed.repo.answer(
            "stack-packs",
            json!({"apps.root.path": ".", "apps.root.stack": stack, "apps.root.toolchain": false}),
        );
        let text = composed.workflow();
        assert!(!has_diff_job(&text), "{stack}");
        composed
            .repo
            .answer(SECURITY, json!({"coverage_changed_lines": true}));
        assert_eq!(
            composed.plan_with(&[]).unwrap_err().to_string(),
            "Module security: coverage_changed_lines needs an app whose stack pack declares a per-file coverage report (python-uv, rust)",
            "{stack}"
        );
    }
}

#[test]
fn coverage_changed_lines_false_removes_the_job_and_the_minimum_reaches_the_step() {
    let composed = Composed::new();
    composed
        .repo
        .answer(SECURITY, json!({"coverage_changed_lines": false}));
    assert!(
        !composed
            .plan_with(&[])
            .unwrap()
            .changes
            .contains_key(REUSABLE)
    );
    composed
        .repo
        .answer(SECURITY, json!({"coverage_changed_lines_min": 90}));
    assert!(diff_job(&composed.reusable()).contains("          MIN: \"90\""));
    for bad in [json!(101), json!(-1)] {
        composed
            .repo
            .answer(SECURITY, json!({"coverage_changed_lines_min": bad}));
        assert!(composed.plan_with(&[]).is_err(), "{bad}");
    }
}

// ---- #1344: the coverage jobs may run on the configured large Linux runner -----------

#[test]
fn coverage_runner_defaults_to_the_standard_runner() {
    let composed = Composed::new();
    let text = composed.reusable();
    assert!(
        diff_job(&text).contains("\n    runs-on: example-cloud-2\n"),
        "{text}"
    );
}

#[test]
fn coverage_runner_large_moves_only_the_coverage_jobs_and_tells_actionlint() {
    let composed = Composed::new();
    composed.repo.answer(
        SECURITY,
        json!({"coverage_runner": "large", "coverage_ratchet": true}),
    );
    let planned = composed.plan_with(&[]).unwrap();
    let text = planned.changes[REUSABLE].clone().unwrap();
    assert!(
        diff_job(&text).contains("\n    runs-on: example-cloud-8\n"),
        "{text}"
    );
    let ratchet = job(&job_blocks(&text), COVERAGE_RATCHET).join("\n");
    assert!(
        ratchet.contains("\n    runs-on: example-cloud-8\n"),
        "{ratchet}"
    );
    let large = text.matches("runs-on: example-cloud-8").count();
    assert_eq!(large, 2, "only the two coverage jobs move\n{text}");
    let workflow = planned.changes[WORKFLOW].clone().unwrap();
    assert!(workflow.contains("runs-on: example-cloud-2"), "{workflow}");
    assert!(!workflow.contains("example-cloud-8"), "{workflow}");
    let lint = planned.changes[".github/actionlint.yaml"].clone().unwrap();
    assert!(lint.contains("    - example-cloud-8\n"), "{lint}");
}

#[test]
fn coverage_runner_refuses_an_unknown_value() {
    let composed = Composed::new();
    composed
        .repo
        .answer(SECURITY, json!({"coverage_runner": "huge"}));
    assert!(composed.plan_with(&[]).is_err());
}

// ---- #1177: coverage measures the tests the project declares --------------------------

#[test]
fn coverage_test_args_only_narrow_what_an_absent_rust_file_means() {
    // #22: nothing here measures, so the selection reaches no command; it still
    // tells characterization that a rust file outside it was not measured.
    let composed = Composed::new();
    composed.repo.answer(
        SECURITY,
        json!({"coverage_ratchet": true, "coverage_test_args.root": "-p brakes"}),
    );
    let text = composed.reusable();
    let diff = diff_job(&text);
    assert!(
        diff.lines().any(|l| l == "          ABSENT: warn"),
        "{diff}"
    );
    assert!(
        diff.lines().any(|l| l
            == "          ABSENT_HINT: \"it is outside coverage_test_args.root, so it is not judged\""),
        "{diff}"
    );
    for needle in ["-p brakes", "DIFF_COMMAND", "cargo llvm-cov --locked"] {
        assert!(!text.contains(needle), "{needle}\n{text}");
    }
}

#[test]
fn coverage_test_args_leave_python_its_own_absent_rule() {
    let composed = Composed::new();
    composed
        .repo
        .write("pyproject.toml", "[project]\nname = \"sample\"\n");
    composed.repo.write("uv.lock", "");
    composed.repo.answer(
        "stack-packs",
        json!({"apps.root.path": ".", "apps.root.stack": "python-uv", "apps.root.toolchain_version": "3.13"}),
    );
    composed.repo.answer(
        SECURITY,
        json!({"coverage_test_args.root": "-m 'not services'"}),
    );
    let diff = diff_job(&composed.reusable());
    assert!(!diff.contains("pytest"), "no test runs here\n{diff}");
    // python keeps its own absent rule and hint.
    assert!(
        diff.lines().any(|l| l == "          ABSENT: warn"),
        "{diff}"
    );
    assert!(
        !diff
            .lines()
            .any(|l| l.starts_with("          ABSENT_HINT:")),
        "{diff}"
    );
}

#[test]
fn unanswered_coverage_test_args_judge_an_absent_rust_file_as_unexecuted() {
    let diff = diff_job(&Composed::new().reusable());
    assert!(
        diff.lines().any(|l| l == "          ABSENT: fail"),
        "{diff}"
    );
    assert!(
        !diff
            .lines()
            .any(|l| l.starts_with("          ABSENT_HINT:")),
        "{diff}"
    );
}

#[test]
fn coverage_test_args_refuse_an_unknown_app_a_second_line_and_an_expression() {
    let composed = Composed::new();
    for (answer, message) in [
        (
            json!({"coverage_test_args.web": "-p web"}),
            "Module security: coverage_test_args.web names no app whose stack pack declares coverage (python-uv, rust)",
        ),
        (
            json!({"coverage_test_args.root": "-p a\ncurl evil"}),
            "Module security: coverage_test_args.root must be one line",
        ),
        (
            json!({"coverage_test_args.root": "-p ${{ github.head_ref }}"}),
            "Module security: coverage_test_args.root must not contain ${{; it is baked into the workflow",
        ),
    ] {
        composed.repo.answer(SECURITY, answer.clone());
        assert_eq!(
            composed.plan_with(&[]).unwrap_err().to_string(),
            message,
            "{answer}"
        );
    }
}

// ---- #1173: a scanner job never prints a matched secret value ------------------------

/// A JWT-shaped credential the fake scanners report; no part of it may reach the log.
const TOKEN: &str = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJyZWFsLXVzZXItMTE3MyJ9.Zm9yLWEtdGVzdC1vbmx5LXNpZ25hdHVyZS0xMTcz";

/// The `run:` text and `env:` of the step of job `job` whose name starts with `name`.
fn step_of(workflow: &str, job: &str, name: &str) -> (String, Vec<(String, String)>) {
    let docs = yaml_rust2::YamlLoader::load_from_str(workflow).unwrap();
    let steps = docs[0]["jobs"][job]["steps"].as_vec().unwrap();
    let step = steps
        .iter()
        .find(|s| s["name"].as_str().is_some_and(|n| n.starts_with(name)))
        .unwrap_or_else(|| panic!("{job} has no step {name}"));
    let env = step["env"]
        .as_hash()
        .map(|h| {
            h.iter()
                .map(|(k, v)| {
                    (
                        k.as_str().unwrap().to_owned(),
                        v.as_str().unwrap().to_owned(),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    (step["run"].as_str().unwrap().to_owned(), env)
}

/// Runs `run` as GitHub's default shell does, in a fresh directory whose PATH
/// starts with `fakes` (name, body); returns (exit code, stdout + stderr).
fn run_step(run: &str, env: &[(String, String)], fakes: &[(&str, &str)]) -> (i32, String) {
    let dir = TempDir::new().unwrap();
    let bin = dir.path().join(".fake-bin");
    fs::create_dir(&bin).unwrap();
    for (name, body) in fakes {
        common::write_executable(&bin.join(name), body);
    }
    let out = Command::new("bash")
        .args(["--noprofile", "--norc", "-eo", "pipefail", "-c", run])
        .current_dir(dir.path())
        .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .env(
            "PATH",
            format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
        )
        .output()
        .unwrap();
    let mut log = String::from_utf8(out.stdout).unwrap();
    log.push_str(&String::from_utf8(out.stderr).unwrap());
    (out.status.code().unwrap_or(-1), log)
}

/// No fragment of the token long enough to be useful is in `log`.
fn assert_withheld(log: &str) {
    for part in TOKEN.split('.') {
        assert!(
            !log.contains(&part[..12]),
            "the log carries the token:\n{log}"
        );
    }
}

/// A fake that answers `--version` and otherwise, when its arguments carry
/// `marker`, writes `report` to the path after `--output` and exits `status`.
fn fake_scanner(marker: &str, report: &str, status: i32) -> String {
    format!(
        "#!/usr/bin/env bash\nfor a in \"$@\"; do [ \"$a\" = --version ] && {{ echo 'fake 1.0'; exit 0; }}; done\n\
         case \" $* \" in *'{marker}'*) ;; *) exit 0 ;; esac\n\
         out=''; prev=''; for a in \"$@\"; do [ \"$prev\" = --output ] && out=\"$a\"; prev=\"$a\"; done\n\
         [ -n \"$out\" ] && cat > \"$out\" <<'REPORT'\n{report}\nREPORT\n\
         echo 'scanner progress without values' >&2\nexit {status}\n"
    )
}

fn semgrep_report() -> String {
    json!({
        "results": [{
            "check_id": "generic.secrets.security.detected-jwt-token",
            "path": "config/settings.py",
            "start": {"line": 12, "col": 9},
            "end": {"line": 12, "col": 120},
            "extra": {
                "message": format!("JWT token detected: {TOKEN}"),
                "lines": format!("    API_TOKEN = \"{TOKEN}\""),
                "metavars": {"$X": {"abstract_content": TOKEN}},
                "severity": "ERROR"
            }
        }],
        "errors": [{
            "type": "Syntax error",
            "level": "warn",
            "message": format!("could not parse `{TOKEN}`"),
            "path": "config/broken.py"
        }]
    })
    .to_string()
}

#[test]
fn the_sast_step_reports_semgrep_findings_by_location_only() {
    let composed = Composed::with(json!({"container_scan": false}), false);
    let (run, env) = step_of(&composed.workflow(), SAST, "Scan with Semgrep");
    let fake = fake_scanner("semgrep scan", &semgrep_report(), 1);
    let (code, log) = run_step(&run, &env, &[("docker", &fake)]);
    assert_eq!(code, 1, "{log}");
    assert!(
        log.contains(
            "semgrep finding: generic.secrets.security.detected-jwt-token at config/settings.py:12"
        ),
        "{log}"
    );
    assert!(
        log.contains("semgrep error: Syntax error at config/broken.py"),
        "{log}"
    );
    assert!(
        log.contains(
            "::error::1 semgrep finding(s); values withheld from the log, rotate any real credential"
        ),
        "{log}"
    );
    assert_withheld(&log);
}

#[test]
fn the_sast_step_fails_when_semgrep_writes_no_report_and_passes_without_findings() {
    let composed = Composed::with(json!({"container_scan": false}), false);
    let (run, env) = step_of(&composed.workflow(), SAST, "Scan with Semgrep");
    let crash =
        "#!/usr/bin/env bash\nfor a in \"$@\"; do [ \"$a\" = --version ] && exit 0; done\nexit 2\n";
    let (code, log) = run_step(&run, &env, &[("docker", crash)]);
    assert_eq!(code, 2, "{log}");
    assert!(
        log.contains("::error::semgrep wrote no readable report (exit 2)"),
        "{log}"
    );
    let clean = fake_scanner("semgrep scan", r#"{"results": [], "errors": []}"#, 0);
    let (code, log) = run_step(&run, &env, &[("docker", &clean)]);
    assert_eq!(code, 0, "{log}");
    assert!(log.contains("semgrep: no findings"), "{log}");
}

fn trivy_report() -> String {
    json!({
        "Results": [
            {"Target": "Cargo.lock", "Class": "lang-pkgs"},
            {"Target": "deploy/.env", "Class": "secret", "Secrets": [{
                "RuleID": "jwt-token",
                "Category": "JWT",
                "Severity": "HIGH",
                "Title": "JWT token",
                "StartLine": 3,
                "EndLine": 3,
                "Match": format!("TOKEN={}", &TOKEN[..20]),
                "Code": {"Lines": [{"Number": 3, "Content": format!("TOKEN={TOKEN}")}]}
            }]}
        ]
    })
    .to_string()
}

#[test]
fn the_container_scan_reports_trivy_secrets_by_location_only_in_both_shapes() {
    let fs_shape = Composed::with(json!({}), true).workflow();
    let composed = Composed::with(json!({}), false);
    composed.repo.answer(
        DELIVERY,
        json!({"image_job": "build-image", "image_ref": "image_ref"}),
    );
    let image_shape = composed.plan_with(&[&FakeDelivery]).unwrap().changes[WORKFLOW]
        .clone()
        .unwrap();
    for workflow in [fs_shape, image_shape] {
        let blocks = job_blocks(&workflow);
        let container = job(&blocks, CONTAINER_SCAN).join("\n");
        assert!(
            !container.contains("vuln,misconfig,secret")
                && !container.contains("trivy image --exit-code"),
            "the table scan must not include the secret scanner\n{container}"
        );
        let (run, env) = step_of(&workflow, CONTAINER_SCAN, "Scan for secrets with trivy");
        let fake = fake_scanner("--scanners secret", &trivy_report(), 1);
        let mut env = env;
        env.push(("IMAGE_REF".to_owned(), "ghcr.io/o/r@sha256:00".to_owned()));
        let (code, log) = run_step(&run, &env, &[("trivy", &fake)]);
        assert_eq!(code, 1, "{log}");
        assert!(
            log.contains("trivy finding: jwt-token at deploy/.env:3"),
            "{log}"
        );
        assert!(log.contains("::error::1 trivy finding(s)"), "{log}");
        assert_withheld(&log);
    }
}

// ---- #1170: the services a measured app declares, and one failure ---------------------

const PG: &str =
    "postgres:17-alpine@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// `monorepo(false)` whose python-uv app `web` declares a Postgres service.
fn monorepo_with_a_database() -> Composed {
    let composed = monorepo(false);
    composed.repo.write(
        "apps/web/.agent-setup/project.json",
        &json!({
            "commands": {"test": "uv run --frozen pytest -q"},
            "ci": {
                "services": {"postgres": {"image": PG, "env": {"POSTGRES_PASSWORD": "test"},
                                          "ports": ["5432:5432"], "health_cmd": "pg_isready"}},
                "env": {"TEST_DATABASE_URL": "postgresql://postgres:test@localhost:5432/postgres"}
            }
        })
        .to_string(),
    );
    composed
}

#[test]
fn only_the_job_that_runs_tests_gets_the_services_an_app_declares() {
    // #22: the coverage jobs read uploaded data and start no service; mutation
    // testing still runs the suite.
    let composed = monorepo_with_a_database();
    composed.repo.answer(
        SECURITY,
        json!({"sast": "none", "container_scan": false, "coverage_ratchet": true, "mutation_diff": true}),
    );
    let text = composed.workflow();
    let docs = yaml_rust2::YamlLoader::load_from_str(&text).unwrap();
    let mutation = &docs[0]["jobs"][MUTATION_DIFF];
    assert_eq!(
        mutation["services"]["postgres"]["image"].as_str(),
        Some(PG),
        "{mutation:?}"
    );
    assert!(docs[0]["jobs"][SECURITY_GATE]["services"].is_badvalue());
    let reusable = composed.reusable();
    let docs = yaml_rust2::YamlLoader::load_from_str(&reusable).unwrap();
    for id in [DIFF_COVERAGE, COVERAGE_RATCHET] {
        let job = &docs[0]["jobs"][id];
        assert!(!job.is_badvalue(), "{id}\n{reusable}");
        assert!(job["services"].is_badvalue(), "{id}: {job:?}");
    }
}

#[test]
fn a_failed_combine_is_reported_once_and_skips_its_judging_steps() {
    let composed = monorepo(false);
    let job = diff_job(&composed.reusable());
    let write = step_named(&job, "Write diff-coverage.sh");
    assert!(
        write.contains("if: ${{ !cancelled() && github.event_name == 'pull_request' && steps.bypass.outputs.id == '' }}"),
        "{write}"
    );
    for app in ["api", "web"] {
        let combine = step_named(&job, &format!("Combine the coverage of {app}"));
        assert!(
            combine.starts_with(&format!("id: measure-{app}\n")),
            "{combine}"
        );
        for name in [
            format!("Check the changed lines of {app}"),
            format!("Characterization first of {app}"),
        ] {
            let step = step_named(&job, &name);
            assert!(
                step.contains(&format!(
                    "if: ${{{{ !cancelled() && github.event_name == 'pull_request' && steps.bypass.outputs.id == '' && steps.measure-{app}.outcome == 'success' && steps.measure-{app}.outputs.skip != 'true' }}}}"
                )),
                "{step}"
            );
        }
    }
}

/// #1299: under `workflow: generate` beside a project's own workflow,
/// ci-baseline's `github:switch-required-check` leaves `required` the only
/// required check, so the rendered ruleset lists `required` alone even when the
/// profile declares `ci.required_checks`; otherwise `ruleset-main` could never
/// verify after the switch is written.
#[test]
fn the_brownfield_switch_replaces_declared_checks_in_the_ruleset() {
    let composed = Composed::new();
    composed.repo.write(OWN, OWN_YML);
    let path = ".agent-setup/project.json";
    let mut profile: Value = serde_json::from_str(&composed.repo.read(path)).unwrap();
    profile["ci"]["required_checks"] = json!(["Orchestration / verify", "build"]);
    composed.repo.write(
        path,
        &(serde_json::to_string_pretty(&profile).unwrap() + "\n"),
    );
    let modules = ["stack-packs", "ci-baseline", "repo-baseline"];
    composed.install(&modules, &["--apply"]);
    let lock: Value = serde_json::from_str(&composed.repo.read(".agent-setup/lock.json")).unwrap();
    assert_eq!(
        lock["files"]["github:switch-required-check"],
        json!({"module": "ci-baseline", "class": "remote"})
    );
    assert_eq!(ruleset_contexts(&composed), ["required"]);
    let again = composed.install(&[], &[]);
    assert!(again.lines().any(|l| l == "No changes."), "{again}");
}

/// #1373: a declared `ci.required_checks` that names the aggregate is the
/// post-switch state, so the switch does not replace it: the ruleset renders
/// it verbatim.
#[test]
fn the_brownfield_switch_keeps_a_declared_list_naming_the_aggregate() {
    let composed = Composed::new();
    composed.repo.write(OWN, OWN_YML);
    let path = ".agent-setup/project.json";
    let mut profile: Value = serde_json::from_str(&composed.repo.read(path)).unwrap();
    profile["ci"]["required_checks"] = json!(["required", "neutrality"]);
    composed.repo.write(
        path,
        &(serde_json::to_string_pretty(&profile).unwrap() + "\n"),
    );
    composed.install(
        &["stack-packs", "ci-baseline", "repo-baseline"],
        &["--apply"],
    );
    let lock: Value = serde_json::from_str(&composed.repo.read(".agent-setup/lock.json")).unwrap();
    assert_eq!(
        lock["files"]["github:switch-required-check"],
        json!({"module": "ci-baseline", "class": "remote"})
    );
    assert_eq!(ruleset_contexts(&composed), ["required", "neutrality"]);
}

/// #1299: without a project workflow there is no switch; declared checks
/// render verbatim, as before.
#[test]
fn without_the_switch_declared_checks_render_verbatim() {
    let composed = Composed::new();
    let path = ".agent-setup/project.json";
    let mut profile: Value = serde_json::from_str(&composed.repo.read(path)).unwrap();
    profile["ci"]["required_checks"] = json!(["Orchestration / verify", "build"]);
    composed.repo.write(
        path,
        &(serde_json::to_string_pretty(&profile).unwrap() + "\n"),
    );
    composed.install(
        &["stack-packs", "ci-baseline", "repo-baseline"],
        &["--apply"],
    );
    assert_eq!(
        ruleset_contexts(&composed),
        ["Orchestration / verify", "build"]
    );
}
