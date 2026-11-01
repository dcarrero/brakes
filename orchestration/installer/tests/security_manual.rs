//! security T6 (#792): the manual steps `secret-scanning`,
//! `private-vulnerability-reporting` and `hooks-installed` with their probes
//! (SPEC-security.md, Manual steps with probes).
//!
//! The two remote probes have no runner in the CLI until host-adapter registers
//! them (#683), so `doctor` reports them `unavailable`; a fake `RemoteRunner`
//! drives the other states here, as `tests/engine_manual.rs` does. Nothing in
//! this file runs a step, a hook manager or `gh`, or writes under `.git/` except
//! the fixture's own hook file. The fixture installs an explicit list
//! with a stand-in `ci-baseline` that renders nothing, so the steps are read
//! without a workflow; `tests/security_render.rs` covers the registered module
//! through the binary (#891).
mod support;
use brakes::engine::answers::{self, AnswersFile};
use brakes::engine::manual::{
    ManualStep, NoRunner, Owner, Probe, ProbeResult, RemoteRunner, StepReport, StepState,
};
use brakes::engine::{self, Context, Lock, Module, Rendered};
use brakes::modules::StackPacks;
use brakes::modules::security::{CODE_SECURITY_STEP, SECURITY, Security};
use brakes::*;
use serde_json::{Value, json};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use support::SetupCore;
use tempfile::TempDir;

const SECRET_SCANNING: &str = "gh api -X PATCH repos/{owner}/{repo} --input - <<'EOF'\n\
{\"security_and_analysis\":{\"secret_scanning\":{\"status\":\"enabled\"},\"secret_scanning_push_protection\":{\"status\":\"enabled\"}}}\n\
EOF";
const PVR: &str = "gh api -X PUT repos/{owner}/{repo}/private-vulnerability-reporting";
const HOOK: &str = ".git/hooks/pre-commit";
/// A plan refusal as a host adapter would pass it on; fixture text, not GitHub's.
const PLAN_REFUSAL: &str =
    "HTTP 422: Secret scanning is not available for this repository on its current plan";

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

/// Answers each remote probe id with a fixed result and records every call.
#[derive(Default)]
struct FakeHost {
    answers: BTreeMap<&'static str, ProbeResult>,
    calls: RefCell<Vec<(String, BTreeMap<String, Value>)>>,
}
impl FakeHost {
    fn with(answers: &[(&'static str, ProbeResult)]) -> Self {
        Self {
            answers: answers.iter().cloned().collect(),
            calls: RefCell::default(),
        }
    }
}
impl RemoteRunner for FakeHost {
    fn run(&self, id: &str, args: &BTreeMap<String, Value>) -> ProbeResult {
        self.calls.borrow_mut().push((id.to_owned(), args.clone()));
        self.answers
            .get(id)
            .cloned()
            .unwrap_or_else(|| ProbeResult::Failed(format!("unexpected probe {id}")))
    }
}

struct Repo {
    _temp: TempDir,
    root: PathBuf,
}
impl Repo {
    /// A git repository with no client hook installed.
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
        let _ = fs::remove_file(root.join(HOOK));
        Self { _temp: temp, root }
    }
    fn modules(&self) -> [&'static dyn Module; 4] {
        [&SetupCore, &StackPacks, &CiBaselineStandIn, &Security]
    }
    fn answer(&self, raw: Value) {
        let file = AnswersFile {
            module: SECURITY.to_owned(),
            version: "1.0.0".to_owned(),
            profile: None,
            answers: serde_json::from_value(raw).unwrap(),
        };
        let path = self.root.join(answers::path(SECURITY));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, file.to_json_string().unwrap()).unwrap();
    }
    fn install(&self) {
        let profile = profile_for(&self.root).unwrap();
        let planned = engine::plan(
            &self.root,
            &Source::embedded(),
            &profile,
            &self.modules(),
            &|_| true,
        )
        .unwrap();
        apply(&self.root, &planned.changes).unwrap();
    }
    /// What the owner's `pre-commit install` would leave; the test writes it.
    fn install_hook(&self) {
        fs::write(self.root.join(HOOK), "#!/bin/sh\nexec pre-commit\n").unwrap();
    }
    fn declared(&self) -> Vec<ManualStep> {
        let profile = profile_for(&self.root).unwrap();
        let recorded = answers::recorded(&self.root, SECURITY).unwrap();
        let answers = Security
            .questions()
            .validate(
                SECURITY,
                &recorded.map(|f| f.answers).unwrap_or_default(),
                answers::DEFAULT_TIER,
            )
            .unwrap();
        let source = Source::embedded();
        let previous = Lock {
            schema: 2,
            version: "test".to_owned(),
            source_commit: None,
            source_dirty: false,
            personal_owner: brakes::config::current_owner(),
            modules: Default::default(),
            files: Default::default(),
        };
        let resolved = Default::default();
        let cx = Context::new(
            &self.root, &profile, &source, &previous, &answers, &Security, &resolved,
        );
        Security.manual_steps(&cx)
    }
    fn diagnose(&self, runner: &dyn RemoteRunner) -> Diagnosis {
        diagnose_with(
            &self.root,
            today(),
            &Source::embedded(),
            &self.modules(),
            runner,
        )
        .unwrap()
    }
    fn steps(&self, runner: &dyn RemoteRunner) -> BTreeMap<String, StepReport> {
        self.diagnose(runner)
            .steps
            .into_iter()
            .filter(|s| s.module == SECURITY)
            .map(|s| (s.id.clone(), s))
            .collect()
    }
}

/// Every file under `dir`, `.git/` included, with its bytes, sorted by path.
fn tree(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut out = BTreeMap::new();
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            out.extend(tree(&path));
        } else {
            out.insert(path.clone(), fs::read(&path).unwrap());
        }
    }
    out
}

fn remote(id: &str) -> Probe {
    Probe::Remote {
        id: id.to_owned(),
        args: BTreeMap::new(),
    }
}

fn lines(steps: &BTreeMap<String, StepReport>) -> Vec<String> {
    steps.values().map(StepReport::doctor_line).collect()
}

// ---- declaration ------------------------------------------------------------------

#[test]
fn the_default_answers_declare_the_three_steps_with_exact_instructions_and_probes() {
    let repo = Repo::new();
    let steps = repo.declared();
    let declared: Vec<(&str, Owner, &str, &Probe, Option<&str>)> = steps
        .iter()
        .map(|s| {
            (
                s.id.as_str(),
                s.owner,
                s.instructions.as_str(),
                &s.probe,
                s.after.as_deref(),
            )
        })
        .collect();
    let hook = Probe::FileExists {
        path: HOOK.to_owned(),
    };
    assert_eq!(
        declared,
        vec![
            (
                "secret-scanning",
                Owner::Owner,
                SECRET_SCANNING,
                &remote("secret-scanning"),
                None
            ),
            (
                "private-vulnerability-reporting",
                Owner::Owner,
                PVR,
                &remote("private-vulnerability-reporting"),
                None
            ),
            (
                "hooks-installed",
                Owner::Owner,
                "pre-commit install (or prek install)",
                &hook,
                None
            ),
        ]
    );
    let titles: Vec<&str> = steps.iter().map(|s| s.title.as_str()).collect();
    assert_eq!(
        titles,
        [
            "Enable secret scanning and push protection",
            "Enable private vulnerability reporting",
            "Install the pre-commit hook in this clone",
        ]
    );
    engine::manual::check(SECURITY, &steps).unwrap();
}

/// T10 (#798): `code-security` exists only with `sast == codeql`, between the
/// remote items and the hook step, informational and probed.
#[test]
fn code_security_is_declared_only_with_the_codeql_answer() {
    let repo = Repo::new();
    let ids =
        |repo: &Repo| -> Vec<String> { repo.declared().iter().map(|s| s.id.clone()).collect() };
    assert_eq!(
        ids(&repo),
        [
            "secret-scanning",
            "private-vulnerability-reporting",
            "hooks-installed"
        ]
    );
    repo.answer(json!({"sast": "semgrep"}));
    assert!(!ids(&repo).contains(&"code-security".to_owned()));
    repo.answer(json!({"sast": "codeql"}));
    let steps = repo.declared();
    assert_eq!(
        ids(&repo),
        [
            "secret-scanning",
            "private-vulnerability-reporting",
            "code-security",
            "hooks-installed"
        ]
    );
    let step = steps.iter().find(|s| s.id == "code-security").unwrap();
    assert_eq!(step.owner, Owner::Owner);
    assert_eq!(step.title, "Enable GitHub Code Security for CodeQL");
    assert_eq!(step.instructions, CODE_SECURITY_STEP);
    assert_eq!(step.probe, remote("code-scanning-default-setup"));
    engine::manual::check(SECURITY, &steps).unwrap();
    // `doctor` reports the step once the module is installed; the plan needs a
    // stack CodeQL analyses, so the repository is a rust app.
    fs::write(repo.root.join("Cargo.toml"), "").unwrap();
    fs::write(repo.root.join("Cargo.lock"), "").unwrap();
    let packs = AnswersFile {
        module: "stack-packs".to_owned(),
        version: "1.0.0".to_owned(),
        profile: None,
        answers: serde_json::from_value(json!({"apps.root.path": ".", "apps.root.stack": "rust"}))
            .unwrap(),
    };
    fs::write(
        repo.root.join(answers::path("stack-packs")),
        packs.to_json_string().unwrap(),
    )
    .unwrap();
    repo.install();
    let line = lines(&repo.steps(&NoRunner));
    assert!(
        line.contains(&"STEP [unavailable:security] code-security — remote probe `code-scanning-default-setup` runs only with doctor --remote".to_owned()),
        "{line:?}"
    );
    let refused = FakeHost::with(&[(
        "code-scanning-default-setup",
        ProbeResult::Failed("Code Security must be enabled for this repository.".to_owned()),
    )]);
    assert_eq!(
        repo.steps(&refused)["code-security"].doctor_line(),
        "STEP [failed:security] code-security — Code Security must be enabled for this repository."
    );
}

#[test]
fn hooks_instructions_follow_the_hooks_answer_and_none_declares_no_hook_step() {
    let repo = Repo::new();
    let hooks_step = |repo: &Repo| {
        repo.declared()
            .into_iter()
            .find(|s| s.id == "hooks-installed")
    };
    repo.answer(json!({"hooks": "lefthook"}));
    let step = hooks_step(&repo).unwrap();
    assert_eq!(step.instructions, "lefthook install");
    assert_eq!(
        step.probe,
        Probe::FileExists {
            path: HOOK.to_owned()
        }
    );
    repo.answer(json!({"hooks": "none"}));
    assert!(hooks_step(&repo).is_none());
    let ids: Vec<String> = repo.declared().into_iter().map(|s| s.id).collect();
    assert_eq!(ids, ["secret-scanning", "private-vulnerability-reporting"]);
}

#[test]
fn no_step_changes_a_setting_or_writes_anything() {
    let repo = Repo::new();
    repo.install();
    let before = tree(&repo.root);
    let host = FakeHost::with(&[
        (
            "secret-scanning",
            ProbeResult::Pending("disabled".to_owned()),
        ),
        (
            "private-vulnerability-reporting",
            ProbeResult::Pending("disabled".to_owned()),
        ),
    ]);
    repo.diagnose(&host);
    assert!(!repo.root.join(HOOK).exists());
    assert_eq!(tree(&repo.root), before);
    // The remote probes are reads with no arguments; the instructions are never run.
    assert_eq!(
        *host.calls.borrow(),
        vec![
            ("secret-scanning".to_owned(), BTreeMap::new()),
            (
                "private-vulnerability-reporting".to_owned(),
                BTreeMap::new()
            ),
        ]
    );
}

// ---- doctor without host-adapter --------------------------------------------------

#[test]
fn without_host_adapter_remote_probes_are_unavailable_and_never_fail_readiness() {
    let repo = Repo::new();
    repo.install();
    let diagnosis = repo.diagnose(&NoRunner);
    let steps: BTreeMap<_, _> = diagnosis
        .steps
        .iter()
        .filter(|s| s.module == SECURITY)
        .map(|s| (s.id.as_str(), s.state))
        .collect();
    assert_eq!(
        steps,
        BTreeMap::from([
            ("hooks-installed", StepState::Pending),
            ("private-vulnerability-reporting", StepState::Unavailable),
            ("secret-scanning", StepState::Unavailable),
        ])
    );
    // Readiness is the findings alone: a failed remote probe changes none of them.
    let failing = FakeHost::with(&[
        (
            "secret-scanning",
            ProbeResult::Failed(PLAN_REFUSAL.to_owned()),
        ),
        (
            "private-vulnerability-reporting",
            ProbeResult::Failed("HTTP 500".to_owned()),
        ),
    ]);
    let failed = repo.diagnose(&failing);
    assert_eq!(failed.findings, diagnosis.findings);
    assert_eq!(failed.ready(), diagnosis.ready());
    assert!(
        diagnosis
            .findings
            .iter()
            .all(|f| !f.contains("secret-scanning") && !f.contains("hooks-installed"))
    );
}

// ---- each step in each state ------------------------------------------------------

#[test]
fn hooks_installed_is_verified_with_the_hook_file_and_pending_without_it() {
    let repo = Repo::new();
    repo.install();
    assert_eq!(
        repo.steps(&NoRunner)["hooks-installed"].doctor_line(),
        "STEP [pending:security] hooks-installed — .git/hooks/pre-commit is absent"
    );
    repo.install_hook();
    assert_eq!(
        repo.steps(&NoRunner)["hooks-installed"].doctor_line(),
        "STEP [verified:security] hooks-installed — .git/hooks/pre-commit exists"
    );
    fs::remove_file(repo.root.join(HOOK)).unwrap();
    fs::create_dir(repo.root.join(HOOK)).unwrap();
    let line = repo.steps(&NoRunner)["hooks-installed"].doctor_line();
    assert!(
        line.starts_with("STEP [failed:security] hooks-installed — Expected a file: "),
        "{line}"
    );
}

#[test]
fn remote_steps_carry_every_state_their_probe_answers() {
    let repo = Repo::new();
    repo.install();
    let unavailable = lines(&repo.steps(&NoRunner));
    assert_eq!(
        unavailable[1..],
        [
            "STEP [unavailable:security] private-vulnerability-reporting — remote probe `private-vulnerability-reporting` runs only with doctor --remote",
            "STEP [unavailable:security] secret-scanning — remote probe `secret-scanning` runs only with doctor --remote",
        ]
    );
    let off = FakeHost::with(&[
        (
            "secret-scanning",
            ProbeResult::Pending(
                "secret_scanning enabled, secret_scanning_push_protection disabled".to_owned(),
            ),
        ),
        (
            "private-vulnerability-reporting",
            ProbeResult::Pending("enabled: false".to_owned()),
        ),
    ]);
    assert_eq!(
        lines(&repo.steps(&off))[1..],
        [
            "STEP [pending:security] private-vulnerability-reporting — enabled: false",
            "STEP [pending:security] secret-scanning — secret_scanning enabled, secret_scanning_push_protection disabled",
        ]
    );
    let on = FakeHost::with(&[
        (
            "secret-scanning",
            ProbeResult::Verified(
                "secret_scanning enabled, secret_scanning_push_protection enabled".to_owned(),
            ),
        ),
        (
            "private-vulnerability-reporting",
            ProbeResult::Verified("enabled: true".to_owned()),
        ),
    ]);
    assert_eq!(
        lines(&repo.steps(&on))[1..],
        [
            "STEP [verified:security] private-vulnerability-reporting — enabled: true",
            "STEP [verified:security] secret-scanning — secret_scanning enabled, secret_scanning_push_protection enabled",
        ]
    );
    // A plan refusal is `failed` with the host's message as the evidence.
    let refused = FakeHost::with(&[
        (
            "secret-scanning",
            ProbeResult::Failed(PLAN_REFUSAL.to_owned()),
        ),
        (
            "private-vulnerability-reporting",
            ProbeResult::Failed("HTTP 502: Bad Gateway".to_owned()),
        ),
    ]);
    let steps = repo.steps(&refused);
    assert_eq!(
        steps["secret-scanning"].doctor_line(),
        format!("STEP [failed:security] secret-scanning — {PLAN_REFUSAL}")
    );
    assert_eq!(
        steps["secret-scanning"].error.as_deref(),
        Some(PLAN_REFUSAL)
    );
    assert_eq!(
        steps["private-vulnerability-reporting"].doctor_line(),
        "STEP [failed:security] private-vulnerability-reporting — HTTP 502: Bad Gateway"
    );
}

// ---- doctor --json ----------------------------------------------------------------

/// The `steps` and `modules` of `doctor --json` for one scenario. Findings and
/// readiness belong to setup-core and are pinned by `tests/engine_manual.rs`, so
/// the document carries none and `ready: true`.
fn json(repo: &Repo, runner: &dyn RemoteRunner) -> String {
    let diagnosis = repo.diagnose(runner);
    let steps: Vec<StepReport> = diagnosis
        .steps
        .into_iter()
        .filter(|s| s.module == SECURITY)
        .collect();
    let dir = repo.root.join(HOOK).display().to_string();
    doctor_json(true, &[], &steps, &diagnosis.modules)
        .unwrap()
        .replace(&dir, "<repo>/.git/hooks/pre-commit")
}

fn golden(name: &str, actual: &str) {
    let path = format!(
        "{}/tests/golden/security/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let expected = fs::read_to_string(&path).unwrap();
    assert_eq!(actual, expected, "{path} drifted; actual:\n{actual}");
}

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "asserts setup-core's own content or id; product-boundary T7b"
)]
#[test]
fn doctor_json_matches_the_golden_files() {
    let repo = Repo::new();
    repo.install();
    golden("doctor-no-host-adapter.json", &json(&repo, &NoRunner));
    repo.install_hook();
    let host = FakeHost::with(&[
        (
            "secret-scanning",
            ProbeResult::Failed(PLAN_REFUSAL.to_owned()),
        ),
        (
            "private-vulnerability-reporting",
            ProbeResult::Verified("enabled: true".to_owned()),
        ),
    ]);
    golden("doctor-host.json", &json(&repo, &host));
    let host = FakeHost::with(&[
        (
            "secret-scanning",
            ProbeResult::Verified(
                "secret_scanning enabled, secret_scanning_push_protection enabled".to_owned(),
            ),
        ),
        (
            "private-vulnerability-reporting",
            ProbeResult::Pending("enabled: false".to_owned()),
        ),
    ]);
    fs::remove_file(repo.root.join(HOOK)).unwrap();
    fs::create_dir(repo.root.join(HOOK)).unwrap();
    golden("doctor-host-pending.json", &json(&repo, &host));
}
