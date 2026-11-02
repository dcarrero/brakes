//! qa T9 (#1007): the manual steps `qa-web-lockfile`, `qa-web-baseline` and
//! `qa-api-reported` with their probes (SPEC-qa.md, Manual steps with probes).
//!
//! Declarations are read from `Qa::manual_steps` over a real `Context`; states
//! come from `diagnose_with` over a repository installed by the binary, with a
//! fake host for the remote probe. Nothing here runs `npm`, `docker`,
//! Playwright or `gh`; the PNG and the lockfile are fixture bytes.
use brakes::engine::answers::{self, Answers, AnswersFile};
use brakes::engine::manual::{
    ManualStep, NoRunner, Owner, Probe, ProbeResult, RemoteRunner, StepReport, StepState,
};
use brakes::engine::{Context, Module, lock::Lock};
use brakes::modules::{self, qa::QA, qa::Qa, stack_packs::PinTable};
use brakes::{Source, diagnose_with, doctor_json, profile_for};
use serde_json::{Value, json};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::{fs, path::PathBuf, process::Command};
use tempfile::TempDir;

const WEB_DIR: &str = "qa/web";
const LOCKFILE: &str = "qa/web/package-lock.json";
const BASELINE: &str = "qa/web/smoke.spec.ts-snapshots/home-chromium-linux.png";
const WEB_START: &str = "npm run dev -- --port 3000";
const WEB_URL: &str = "http://127.0.0.1:3000";

fn today() -> chrono::NaiveDate {
    chrono::NaiveDate::from_ymd_opt(2026, 10, 30).unwrap()
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
    /// A personal rust repository: one root app in `stack-packs`.
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
        let repo = Self { _temp: temp, root };
        repo.cli(&["install", "<repo>", "--new-personal", "--apply"]);
        let path = ".agent-setup/project.json";
        let mut profile: Value = serde_json::from_str(&repo.read(path)).unwrap();
        profile["commands"]["test"] = "cargo test --locked".into();
        repo.write(
            path,
            &(serde_json::to_string_pretty(&profile).unwrap() + "\n"),
        );
        repo.write("Cargo.toml", "");
        repo.write("Cargo.lock", "");
        repo.answer(
            "stack-packs",
            json!({"apps.root.path": ".", "apps.root.stack": "rust", "apps.root.container": false}),
        );
        // The deprecated generated `ci.yml` these tests read (#21), pinned until #25.
        repo.answer("ci-baseline", json!({"workflow": "generate"}));
        repo
    }
    fn write(&self, path: &str, text: &str) {
        let full = self.root.join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, text).unwrap();
    }
    fn read(&self, path: &str) -> String {
        fs::read_to_string(self.root.join(path)).unwrap()
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
    fn cli(&self, args: &[&str]) -> String {
        let root = self.root.to_string_lossy().into_owned();
        let out = Command::new(env!("CARGO_BIN_EXE_brakes"))
            .args(
                args.iter()
                    .map(|a| if *a == "<repo>" { root.as_str() } else { a }),
            )
            .output()
            .unwrap();
        assert!(out.status.success(), "{args:?}: {out:?}");
        String::from_utf8(out.stdout).unwrap()
    }
    /// `install` of stack-packs, ci-baseline and qa with these qa answers.
    fn install(&self, qa: Value, apply: bool) -> String {
        self.answer(QA, qa);
        let mut args = vec!["install", "<repo>"];
        for id in ["stack-packs", "ci-baseline", QA] {
            args.extend(["--module", id]);
        }
        if apply {
            args.push("--apply");
        }
        self.cli(&args)
    }
    /// `Qa::manual_steps` over the recorded qa answers, as the engine calls it.
    fn declared(&self) -> Vec<ManualStep> {
        let profile = profile_for(&self.root).unwrap();
        let source = Source::embedded();
        let lock = Lock {
            schema: brakes::engine::lock::SCHEMA,
            version: "test".to_owned(),
            source_commit: None,
            source_dirty: false,
            personal_owner: brakes::config::current_owner(),
            modules: BTreeMap::new(),
            files: BTreeMap::new(),
        };
        let recorded = answers::recorded(&self.root, QA)
            .unwrap()
            .map(|f| f.answers)
            .unwrap_or_default();
        let answers = Qa.questions().validate(QA, &recorded, "P1").unwrap();
        let mut resolved = BTreeMap::new();
        resolved.insert(
            "stack-packs".to_owned(),
            serde_json::from_value::<Answers>(
                json!({"apps.root.path": ".", "apps.root.stack": "rust", "apps.root.container": false}),
            )
            .unwrap(),
        );
        resolved.insert(
            "ci-baseline".to_owned(),
            serde_json::from_value::<Answers>(json!({"workflow": "generate"})).unwrap(),
        );
        let cx = Context::new(
            &self.root, &profile, &source, &lock, &answers, &Qa, &resolved,
        );
        Qa.manual_steps(&cx)
    }
    fn steps(&self, runner: &dyn RemoteRunner) -> BTreeMap<String, StepReport> {
        diagnose_with(
            &self.root,
            today(),
            &Source::embedded(),
            &modules::all(),
            runner,
        )
        .unwrap()
        .steps
        .into_iter()
        .filter(|s| s.module == QA)
        .map(|s| (s.id.clone(), s))
        .collect()
    }
}

fn seeded() -> Value {
    json!({"api": true, "api_start": "cargo run --locked", "web": "seeded",
           "web_start": WEB_START, "web_url": WEB_URL})
}

fn pinned_image() -> String {
    PinTable::embedded()
        .unwrap()
        .image("playwright")
        .unwrap()
        .pinned()
}

fn remote(id: &str, args: Value) -> Probe {
    Probe::Remote {
        id: id.to_owned(),
        args: serde_json::from_value(args).unwrap(),
    }
}

// ---- declaration ------------------------------------------------------------------

#[test]
fn a_seeded_web_with_an_api_declares_the_three_steps_with_exact_instructions_and_probes() {
    let repo = Repo::new();
    repo.answer(QA, seeded());

    let steps = repo.declared();

    let image = pinned_image();
    assert_eq!(
        image,
        "mcr.microsoft.com/playwright:v1.64.1-noble@sha256:47b510dd9230bf0b9bfc9b20102241e577ea7a99334ab4c3ca19f19770e9b8ea"
    );
    let baseline = format!(
        "docker run --rm -v \"$PWD\":/work -w /work/{WEB_DIR} -e QA_WEB_START='{WEB_START}' -e QA_WEB_URL='{WEB_URL}' {image} npx playwright test --update-snapshots\n\
         git add {WEB_DIR}/*-snapshots/ && git commit -m 'qa: screenshot baseline'\n\
         # Generate the baseline on Linux, in the pinned image, so it matches the runner; review every image before committing."
    );
    let expected = vec![
        ManualStep {
            id: "qa-web-lockfile".to_owned(),
            title: "Commit the web lockfile".to_owned(),
            owner: Owner::Project,
            instructions: format!("cd {WEB_DIR} && npm install && git add package-lock.json"),
            probe: Probe::FileExists {
                path: LOCKFILE.to_owned(),
            },
            after: None,
        },
        ManualStep {
            id: "qa-web-baseline".to_owned(),
            title: "Generate the screenshot baseline on Linux".to_owned(),
            owner: Owner::Project,
            instructions: baseline,
            probe: Probe::FileExists {
                path: BASELINE.to_owned(),
            },
            after: Some("qa-web-lockfile".to_owned()),
        },
        ManualStep {
            id: "qa-api-reported".to_owned(),
            title: "CI reports qa-api on main".to_owned(),
            owner: Owner::Platform,
            instructions: "Nothing to run: wait until qa-api has reported green once on main; until then required is red on purpose.".to_owned(),
            probe: remote(
                "check-run-reported",
                json!({"contexts": ["qa-api"], "branch": "main"}),
            ),
            after: None,
        },
    ];
    assert_eq!(steps, expected);
    brakes::engine::manual::check(QA, &steps).unwrap();
}

#[test]
fn a_project_web_emits_only_the_api_step_and_no_api_emits_none_of_it() {
    let repo = Repo::new();
    repo.write("playwright.config.ts", "export default {};\n");
    repo.answer(
        QA,
        json!({"api": true, "api_start": "cargo run --locked", "web": "project",
               "web_start": WEB_START}),
    );
    let ids: Vec<String> = repo.declared().into_iter().map(|s| s.id).collect();
    assert_eq!(ids, ["qa-api-reported"]);

    repo.answer(
        QA,
        json!({"api": false, "web": "seeded", "web_start": WEB_START}),
    );
    let ids: Vec<String> = repo.declared().into_iter().map(|s| s.id).collect();
    assert_eq!(ids, ["qa-web-lockfile", "qa-web-baseline"]);

    repo.answer(QA, json!({"api": false, "web": "none"}));
    assert!(repo.declared().is_empty());
}

#[test]
fn a_start_command_with_a_single_quote_stays_one_shell_word() {
    let repo = Repo::new();
    repo.answer(
        QA,
        json!({"api": false, "web": "seeded", "web_start": "sh -c 'npm start'"}),
    );
    let steps = repo.declared();
    let baseline = &steps[1].instructions;
    assert!(
        baseline.contains(r#"-e QA_WEB_START='sh -c '\''npm start'\''' "#),
        "{baseline}"
    );
}

#[test]
fn no_step_touches_secrets_billing_or_settings() {
    let repo = Repo::new();
    repo.answer(QA, seeded());
    for step in repo.declared() {
        let text = step.instructions.to_lowercase();
        for word in ["secret", "billing", "settings", "gh api", "token"] {
            assert!(!text.contains(word), "{}: {word}", step.id);
        }
    }
}

// ---- states -----------------------------------------------------------------------

#[test]
fn the_baseline_is_blocked_until_the_lockfile_then_pending_then_verified() {
    let repo = Repo::new();
    let plan = repo.install(seeded(), false);
    assert!(
        plan.contains("STEP [pending:qa] qa-web-lockfile — Commit the web lockfile\n"),
        "{plan}"
    );
    assert!(
        plan.contains(
            "STEP [blocked:qa] qa-web-baseline — Generate the screenshot baseline on Linux\n"
        ),
        "{plan}"
    );
    repo.install(seeded(), true);

    let steps = repo.steps(&NoRunner);
    assert_eq!(steps["qa-web-lockfile"].state, StepState::Pending);
    assert_eq!(steps["qa-web-baseline"].state, StepState::Blocked);

    repo.write(LOCKFILE, "{}\n");
    let steps = repo.steps(&NoRunner);
    assert_eq!(steps["qa-web-lockfile"].state, StepState::Verified);
    assert_eq!(steps["qa-web-baseline"].state, StepState::Pending);
    let plan = repo.install(seeded(), false);
    assert!(
        plan.contains(
            "STEP [pending:qa] qa-web-baseline — Generate the screenshot baseline on Linux\n"
        ),
        "{plan}"
    );

    repo.write(BASELINE, "\u{89}PNG fixture");
    let steps = repo.steps(&NoRunner);
    assert_eq!(steps["qa-web-baseline"].state, StepState::Verified);
}

#[test]
fn the_remote_probe_is_unavailable_without_a_host_and_verified_with_one() {
    let repo = Repo::new();
    repo.install(seeded(), true);

    let steps = repo.steps(&NoRunner);
    assert_eq!(steps["qa-api-reported"].state, StepState::Unavailable);

    let host = FakeHost::with(&[(
        "check-run-reported",
        ProbeResult::Verified("reported on the last 10 commits of main: qa-api".to_owned()),
    )]);
    let steps = repo.steps(&host);
    assert_eq!(steps["qa-api-reported"].state, StepState::Verified);
    let calls = host.calls.borrow();
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert_eq!(calls[0].0, "check-run-reported");
    assert_eq!(
        serde_json::to_value(&calls[0].1).unwrap(),
        json!({"contexts": ["qa-api"], "branch": "main"})
    );
}

// ---- doctor --json ----------------------------------------------------------------

/// The qa `steps` and the qa entry of `modules` of `doctor --json`; findings,
/// readiness and the other modules' versions belong elsewhere, so the document
/// carries none of them.
fn doctor(repo: &Repo, runner: &dyn RemoteRunner) -> String {
    let diagnosis = diagnose_with(
        &repo.root,
        today(),
        &Source::embedded(),
        &modules::all(),
        runner,
    )
    .unwrap();
    let steps: Vec<StepReport> = diagnosis
        .steps
        .into_iter()
        .filter(|s| s.module == QA)
        .collect();
    let modules: Vec<(String, String)> = diagnosis
        .modules
        .into_iter()
        .filter(|(id, _)| id == QA)
        .collect();
    doctor_json(true, &[], &steps, &modules).unwrap()
}

/// Compares with `tests/golden/qa/<name>`; `UPDATE_GOLDENS=1` rewrites it.
fn golden(name: &str, actual: &str) {
    let path = format!("{}/tests/golden/qa/{name}", env!("CARGO_MANIFEST_DIR"));
    if std::env::var_os("UPDATE_GOLDENS").is_some() {
        fs::create_dir_all(PathBuf::from(&path).parent().unwrap()).unwrap();
        fs::write(&path, actual).unwrap();
    }
    let expected = fs::read_to_string(&path).unwrap();
    assert_eq!(actual, expected, "{path} drifted; actual:\n{actual}");
}

#[test]
fn doctor_json_carries_the_steps() {
    let repo = Repo::new();
    repo.install(seeded(), true);
    golden("doctor-no-host.json", &doctor(&repo, &NoRunner));

    repo.write(LOCKFILE, "{}\n");
    repo.write(BASELINE, "\u{89}PNG fixture");
    let host = FakeHost::with(&[(
        "check-run-reported",
        ProbeResult::Verified("reported on the last 10 commits of main: qa-api".to_owned()),
    )]);
    golden("doctor-host-verified.json", &doctor(&repo, &host));
}
