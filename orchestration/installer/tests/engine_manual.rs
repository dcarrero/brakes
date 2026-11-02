//! Manual steps and probes (SPEC-engine.md, #655): a fixture module that lives only
//! here declares one step per probe kind plus an `after` dependency; every probe is
//! driven through each state, `doctor` prints one line per step, and `doctor --json`
//! is pinned by a golden file.
mod support;
use brakes::Diagnosis;
use brakes::engine::manual::{
    ManualStep, NoRunner, Owner, Probe, ProbeResult, RemoteRunner, StepReport, StepState,
};
use brakes::engine::{self, Context, Module, Planned, Rendered};
use brakes::*;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::{fs, path::PathBuf, process::Command};
use support::SetupCore;
use tempfile::TempDir;

const PRESENT: &str = "fixture/present.md";
const SETTINGS: &str = "fixture/settings.json";

/// One step per probe kind, plus `after-remote`, which waits for the remote step.
struct Steps;
impl Module for Steps {
    fn id(&self) -> &'static str {
        "steps"
    }
    fn version(&self) -> &'static str {
        "0.2.0"
    }
    fn render(&self, _: &Context<'_>) -> Result<Vec<Rendered>> {
        Ok(Vec::new())
    }
    fn manual_steps(&self, _: &Context<'_>) -> Vec<ManualStep> {
        vec![
            step(
                "file",
                Probe::FileExists {
                    path: PRESENT.to_owned(),
                },
                None,
            ),
            step(
                "pointer",
                Probe::JsonPointer {
                    path: SETTINGS.to_owned(),
                    pointer: "/permissions/deny/0".to_owned(),
                    equals: json!("Read(./**/.env)"),
                },
                None,
            ),
            step(
                "remote",
                Probe::Remote {
                    id: "required-check".to_owned(),
                    args: BTreeMap::from([
                        ("branch".to_owned(), json!("main")),
                        ("check".to_owned(), json!("verify")),
                    ]),
                },
                None,
            ),
            step(
                "after-remote",
                Probe::FileExists {
                    path: PRESENT.to_owned(),
                },
                Some("remote"),
            ),
        ]
    }
}

fn step(id: &str, probe: Probe, after: Option<&str>) -> ManualStep {
    ManualStep {
        id: id.to_owned(),
        title: format!("Do {id}"),
        owner: if id == "remote" {
            Owner::Platform
        } else {
            Owner::Owner
        },
        instructions: format!("how to {id}"),
        probe,
        after: after.map(str::to_owned),
    }
}

/// A module whose steps are given by the test, to drive the load-time refusals.
struct Declared(Vec<ManualStep>);
impl Module for Declared {
    fn id(&self) -> &'static str {
        "declared"
    }
    fn version(&self) -> &'static str {
        "0.1.0"
    }
    fn render(&self, _: &Context<'_>) -> Result<Vec<Rendered>> {
        Ok(Vec::new())
    }
    fn manual_steps(&self, _: &Context<'_>) -> Vec<ManualStep> {
        self.0
            .iter()
            .map(|s| ManualStep {
                id: s.id.clone(),
                title: s.title.clone(),
                owner: s.owner,
                instructions: s.instructions.clone(),
                probe: s.probe.clone(),
                after: s.after.clone(),
            })
            .collect()
    }
}

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
    fn source() -> Source {
        Source {
            documents: BTreeMap::new(),
            version: "0.1.0".to_owned(),
            revision: None,
            dirty: false,
        }
    }
    fn plan(&self, modules: &[&dyn Module]) -> Result<Planned> {
        let profile = profile_for(&self.root)?;
        engine::plan(&self.root, &Self::source(), &profile, modules, &|_| true)
    }
    fn steps(&self) -> BTreeMap<String, StepReport> {
        self.plan(&[&SetupCore, &Steps])
            .unwrap()
            .steps
            .into_iter()
            .map(|s| (s.id.clone(), s))
            .collect()
    }
    fn refusal(&self, steps: Vec<ManualStep>) -> String {
        self.plan(&[&Declared(steps)]).unwrap_err().to_string()
    }
    fn write(&self, name: &str, text: &str) {
        let path = self.root.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
    /// Installs `modules` so the lock records them.
    fn install(&self, modules: &[&dyn Module]) {
        let planned = self.plan(modules).unwrap();
        apply(&self.root, &planned.changes).unwrap();
    }
    fn diagnose(&self, modules: &[&dyn Module]) -> Diagnosis {
        diagnose_with(&self.root, today(), &Repo::source(), modules, &NoRunner).unwrap()
    }
    fn cli(&self, args: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_brakes"))
            .args(args)
            .arg(&self.root)
            .output()
            .unwrap()
    }
}

fn state(report: &StepReport) -> (StepState, Option<&str>, Option<&str>) {
    (
        report.state,
        report.evidence.as_deref(),
        report.error.as_deref(),
    )
}

// ---- file-exists ------------------------------------------------------------------

#[test]
fn file_exists_is_pending_when_absent_and_verified_when_present() {
    let repo = Repo::new();
    let steps = repo.steps();
    assert_eq!(
        state(&steps["file"]),
        (
            StepState::Pending,
            Some("fixture/present.md is absent"),
            None
        )
    );
    assert_eq!(steps["file"].module, "steps");
    assert_eq!(steps["file"].title, "Do file");
    assert_eq!(steps["file"].owner, Owner::Owner);
    repo.write(PRESENT, "x\n");
    assert_eq!(
        state(&repo.steps()["file"]),
        (StepState::Verified, Some("fixture/present.md exists"), None)
    );
}

#[test]
fn file_exists_fails_when_the_path_is_a_directory() {
    let repo = Repo::new();
    fs::create_dir_all(repo.root.join(PRESENT)).unwrap();
    let steps = repo.steps();
    assert_eq!(steps["file"].state, StepState::Failed);
    assert!(
        steps["file"]
            .error
            .as_deref()
            .is_some_and(|e| e.starts_with("Expected a file: ")),
        "{:?}",
        steps["file"]
    );
    assert_eq!(steps["file"].evidence, None);
}

// ---- json-pointer -----------------------------------------------------------------

#[test]
fn json_pointer_is_pending_without_the_file_the_pointer_or_the_value() {
    let repo = Repo::new();
    assert_eq!(
        state(&repo.steps()["pointer"]),
        (
            StepState::Pending,
            Some("fixture/settings.json is absent"),
            None
        )
    );
    repo.write(SETTINGS, "{\"permissions\": {}}\n");
    assert_eq!(
        state(&repo.steps()["pointer"]),
        (
            StepState::Pending,
            Some("fixture/settings.json: /permissions/deny/0 is absent"),
            None
        )
    );
    repo.write(SETTINGS, "{\"permissions\": {\"deny\": [\"Edit(x)\"]}}\n");
    assert_eq!(
        state(&repo.steps()["pointer"]),
        (
            StepState::Pending,
            Some(
                "fixture/settings.json: /permissions/deny/0 is \"Edit(x)\", expected \"Read(./**/.env)\""
            ),
            None
        )
    );
}

#[test]
fn json_pointer_is_verified_when_equal_and_failed_on_invalid_json() {
    let repo = Repo::new();
    repo.write(
        SETTINGS,
        "{\"permissions\": {\"deny\": [\"Read(./**/.env)\"]}}\n",
    );
    assert_eq!(
        state(&repo.steps()["pointer"]),
        (
            StepState::Verified,
            Some("fixture/settings.json: /permissions/deny/0 is \"Read(./**/.env)\""),
            None
        )
    );
    repo.write(SETTINGS, "{not json\n");
    let steps = repo.steps();
    assert_eq!(steps["pointer"].state, StepState::Failed);
    assert!(
        steps["pointer"]
            .error
            .as_deref()
            .is_some_and(|e| e.starts_with("fixture/settings.json: ")),
        "{:?}",
        steps["pointer"]
    );
}

#[test]
fn json_pointer_resolves_escapes_the_whole_document_and_array_indexes() {
    let repo = Repo::new();
    repo.write(SETTINGS, "{\"a/b\": {\"c~d\": [10, 20]}}\n");
    let probe = |pointer: &str, equals: Value| {
        repo.plan(&[&Declared(vec![step(
            "p",
            Probe::JsonPointer {
                path: SETTINGS.to_owned(),
                pointer: pointer.to_owned(),
                equals,
            },
            None,
        )])])
        .unwrap()
        .steps
        .remove(0)
        .state
    };
    assert_eq!(probe("/a~1b/c~0d/1", json!(20)), StepState::Verified);
    assert_eq!(probe("/a~1b/c~0d/01", json!(20)), StepState::Pending);
    assert_eq!(probe("/a~1b/c~0d/2", json!(20)), StepState::Pending);
    assert_eq!(probe("/a~1b/c~0d/-", json!(20)), StepState::Pending);
    assert_eq!(probe("/a~1b/c~0d/x", json!(20)), StepState::Pending);
    assert_eq!(
        probe("", json!({"a/b": {"c~d": [10, 20]}})),
        StepState::Verified
    );
}

// ---- json-pointer: contains_all and under/contains (agent-guardrails T5, #744) ------

/// The state and evidence of one probe declared alone, against `SETTINGS`.
fn probed(repo: &Repo, probe: Probe) -> (StepState, Option<String>, Option<String>) {
    let report = repo
        .plan(&[&Declared(vec![step("p", probe, None)])])
        .unwrap()
        .steps
        .remove(0);
    (report.state, report.evidence, report.error)
}

fn deny_all() -> Probe {
    Probe::JsonPointerContainsAll {
        path: SETTINGS.to_owned(),
        pointer: "/permissions/deny".to_owned(),
        contains_all: vec![json!("Read(./**/.env)"), json!("Read(./secrets/**)")],
    }
}

fn stop_names_hook() -> Probe {
    Probe::JsonPointerContains {
        path: SETTINGS.to_owned(),
        under: "/hooks/Stop".to_owned(),
        contains: "stop_verify.sh".to_owned(),
    }
}

fn pending(evidence: &str) -> (StepState, Option<String>, Option<String>) {
    (StepState::Pending, Some(evidence.to_owned()), None)
}

#[test]
fn contains_all_is_pending_until_every_member_is_present() {
    let repo = Repo::new();
    assert_eq!(
        probed(&repo, deny_all()),
        pending("fixture/settings.json is absent")
    );
    repo.write(SETTINGS, "{\"permissions\": {}}\n");
    assert_eq!(
        probed(&repo, deny_all()),
        pending("fixture/settings.json: /permissions/deny is absent")
    );
    repo.write(
        SETTINGS,
        "{\"permissions\": {\"deny\": \"Read(./**/.env)\"}}\n",
    );
    assert_eq!(
        probed(&repo, deny_all()),
        pending(
            "fixture/settings.json: /permissions/deny is \"Read(./**/.env)\", expected an array"
        )
    );
    repo.write(
        SETTINGS,
        "{\"permissions\": {\"deny\": [\"Read(./**/.env)\"]}}\n",
    );
    assert_eq!(
        probed(&repo, deny_all()),
        pending("fixture/settings.json: /permissions/deny lacks \"Read(./secrets/**)\"")
    );
}

#[test]
fn contains_all_is_a_union_other_members_still_verify() {
    let repo = Repo::new();
    repo.write(
        SETTINGS,
        "{\"permissions\": {\"deny\": [\"Bash(rm:*)\", \"Read(./secrets/**)\", \"Read(./**/.env)\"]}}\n",
    );
    assert_eq!(
        probed(&repo, deny_all()),
        (
            StepState::Verified,
            Some(
                "fixture/settings.json: /permissions/deny contains \"Read(./**/.env)\", \"Read(./secrets/**)\""
                    .to_owned()
            ),
            None
        )
    );
    repo.write(SETTINGS, "{not json\n");
    assert_eq!(probed(&repo, deny_all()).0, StepState::Failed);
}

#[test]
fn under_contains_finds_the_text_in_any_string_beneath_the_pointer() {
    let repo = Repo::new();
    assert_eq!(
        probed(&repo, stop_names_hook()),
        pending("fixture/settings.json is absent")
    );
    repo.write(SETTINGS, "{\"hooks\": {\"PreToolUse\": []}}\n");
    assert_eq!(
        probed(&repo, stop_names_hook()),
        pending("fixture/settings.json: /hooks/Stop is absent")
    );
    repo.write(
        SETTINGS,
        "{\"hooks\": {\"Stop\": [{\"hooks\": [{\"type\": \"command\", \"command\": \"other.sh\"}]}], \"PreToolUse\": [{\"command\": \"stop_verify.sh\"}]}}\n",
    );
    assert_eq!(
        probed(&repo, stop_names_hook()),
        pending("fixture/settings.json: /hooks/Stop does not name stop_verify.sh")
    );
    repo.write(
        SETTINGS,
        "{\"hooks\": {\"Stop\": [{\"hooks\": [{\"type\": \"command\", \"command\": \"other.sh\"}]}, {\"hooks\": [{\"type\": \"command\", \"command\": \"sh \\\"$CLAUDE_PROJECT_DIR/.claude/hooks/stop_verify.sh\\\"\"}]}]}}\n",
    );
    assert_eq!(
        probed(&repo, stop_names_hook()),
        (
            StepState::Verified,
            Some("fixture/settings.json: /hooks/Stop names stop_verify.sh".to_owned()),
            None
        )
    );
}

#[test]
fn the_new_json_pointer_forms_check_path_and_pointer_at_load() {
    let repo = Repo::new();
    let escape = Probe::JsonPointerContainsAll {
        path: "../settings.json".to_owned(),
        pointer: "/a".to_owned(),
        contains_all: vec![json!(1)],
    };
    assert_eq!(
        repo.refusal(vec![step("p", escape, None)]),
        "Module declared: step `p` probes a path outside the repository: ../settings.json"
    );
    let invalid = Probe::JsonPointerContains {
        path: SETTINGS.to_owned(),
        under: "hooks".to_owned(),
        contains: "x".to_owned(),
    };
    assert_eq!(
        repo.refusal(vec![step("p", invalid, None)]),
        "Module declared: step `p` has an invalid JSON pointer: hooks"
    );
}

#[test]
fn a_project_owned_step_reports_owner_project() {
    assert_eq!(Owner::Project.to_string(), "project");
    assert_eq!(
        serde_json::to_value(Owner::Project).unwrap(),
        json!("project")
    );
}

// ---- remote and after -------------------------------------------------------------

#[test]
fn remote_is_unavailable_without_a_runner_and_blocks_the_step_after_it() {
    let repo = Repo::new();
    repo.write(PRESENT, "x\n");
    let steps = repo.steps();
    assert_eq!(
        state(&steps["remote"]),
        (
            StepState::Unavailable,
            Some("remote probe `required-check` runs only with doctor --remote"),
            None
        )
    );
    assert_eq!(steps["remote"].owner, Owner::Platform);
    assert_eq!(
        state(&steps["after-remote"]),
        (
            StepState::Blocked,
            Some("waits for step `remote` (unavailable)"),
            None
        )
    );
}

/// A runner answering `verified` for one id, as host-adapter will.
struct Stub;
impl RemoteRunner for Stub {
    fn run(&self, id: &str, args: &BTreeMap<String, Value>) -> ProbeResult {
        if id == "required-check" && args["branch"] == json!("main") {
            ProbeResult::Verified("ruleset 42".to_owned())
        } else {
            ProbeResult::Failed(format!("unknown probe {id}"))
        }
    }
}

#[test]
fn a_registered_runner_answers_remote_probes_and_unblocks_the_step_after() {
    let repo = Repo::new();
    repo.write(PRESENT, "x\n");
    let profile = profile_for(&repo.root).unwrap();
    let previous =
        engine::Lock::parse("{\"schema\": 1, \"files\": {}}", "1.0.0", &|_| true).unwrap();
    let evaluate = |runner: &dyn RemoteRunner| {
        engine::steps(
            &repo.root,
            &Repo::source(),
            &profile,
            &[&Steps],
            &previous,
            runner,
        )
        .unwrap()
        .into_iter()
        .map(|s| (s.id.clone(), (s.state, s.evidence)))
        .collect::<BTreeMap<_, _>>()
    };
    let steps = evaluate(&Stub);
    assert_eq!(
        steps["remote"],
        (StepState::Verified, Some("ruleset 42".to_owned()))
    );
    assert_eq!(
        steps["after-remote"],
        (
            StepState::Verified,
            Some("fixture/present.md exists".to_owned())
        )
    );
    assert_eq!(evaluate(&NoRunner)["after-remote"].0, StepState::Blocked);
}

/// A runner whose host says the remote step does not exist for this repository (#846).
struct NotApplicable;
impl RemoteRunner for NotApplicable {
    fn run(&self, _id: &str, _args: &BTreeMap<String, Value>) -> ProbeResult {
        ProbeResult::NotApplicable("not found (404: Not Found)".to_owned())
    }
}

#[test]
fn a_not_applicable_step_prints_its_state_blocks_the_step_after_and_never_changes_readiness() {
    let repo = Repo::new();
    repo.install(&[&SetupCore, &Steps]);
    repo.write(PRESENT, "x\n");
    let diagnose = |runner: &dyn RemoteRunner| {
        diagnose_with(
            &repo.root,
            today(),
            &Repo::source(),
            &[&SetupCore, &Steps],
            runner,
        )
        .unwrap()
    };
    let diagnosis = diagnose(&NotApplicable);
    let steps: BTreeMap<_, _> = diagnosis.steps.iter().map(|s| (s.id.as_str(), s)).collect();
    assert_eq!(
        state(steps["remote"]),
        (
            StepState::NotApplicable,
            Some("not found (404: Not Found)"),
            None
        )
    );
    assert_eq!(
        steps["remote"].doctor_line(),
        "STEP [not-applicable:steps] remote — not found (404: Not Found)"
    );
    assert_eq!(
        steps["remote"].plan_line(),
        "STEP [not-applicable:steps] remote — Do remote"
    );
    assert_eq!(
        state(steps["after-remote"]),
        (
            StepState::Blocked,
            Some("waits for step `remote` (not-applicable)"),
            None
        )
    );
    let json = doctor_json(
        diagnosis.ready(),
        &diagnosis.printed_findings(),
        &diagnosis.steps,
        &diagnosis.modules,
    )
    .unwrap();
    let value: Value = serde_json::from_str(&json).unwrap();
    let remote = value["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == json!("remote"))
        .unwrap();
    assert_eq!(remote["state"], json!("not-applicable"));
    assert_eq!(remote["evidence"], json!("not found (404: Not Found)"));
    assert!(remote["error"].is_null());
    // Readiness and findings are those of the same repository with every remote
    // probe verified or unavailable: the state never changes them.
    for other in [&Stub as &dyn RemoteRunner, &NoRunner] {
        let baseline = diagnose(other);
        assert_eq!(diagnosis.ready(), baseline.ready());
        assert_eq!(diagnosis.findings, baseline.findings);
    }
}

#[test]
fn a_blocked_chain_names_the_first_unverified_step_and_runs_no_probe() {
    let repo = Repo::new();
    let steps = repo
        .plan(&[&Declared(vec![
            step(
                "c",
                Probe::FileExists {
                    path: PRESENT.to_owned(),
                },
                Some("b"),
            ),
            step(
                "b",
                Probe::FileExists {
                    path: PRESENT.to_owned(),
                },
                Some("a"),
            ),
            step(
                "a",
                Probe::FileExists {
                    path: PRESENT.to_owned(),
                },
                None,
            ),
        ])])
        .unwrap()
        .steps;
    assert_eq!(
        steps
            .iter()
            .map(|s| (s.id.as_str(), s.state, s.evidence.as_deref()))
            .collect::<Vec<_>>(),
        vec![
            (
                "a",
                StepState::Pending,
                Some("fixture/present.md is absent")
            ),
            (
                "b",
                StepState::Blocked,
                Some("waits for step `a` (pending)")
            ),
            (
                "c",
                StepState::Blocked,
                Some("waits for step `b` (blocked)")
            ),
        ]
    );
}

// ---- load-time refusals -----------------------------------------------------------

#[test]
fn a_probe_path_outside_the_repository_refuses_at_load() {
    let repo = Repo::new();
    for path in ["../outside.md", "/etc/passwd", "a/../../b"] {
        let message = repo.refusal(vec![step(
            "escape",
            Probe::FileExists {
                path: path.to_owned(),
            },
            None,
        )]);
        assert_eq!(
            message,
            format!("Module declared: step `escape` probes a path outside the repository: {path}")
        );
        let message = repo.refusal(vec![step(
            "escape",
            Probe::JsonPointer {
                path: path.to_owned(),
                pointer: "/a".to_owned(),
                equals: json!(1),
            },
            None,
        )]);
        assert_eq!(
            message,
            format!("Module declared: step `escape` probes a path outside the repository: {path}")
        );
    }
}

#[test]
fn a_remote_probe_the_registry_cannot_run_refuses_at_load() {
    let repo = Repo::new();
    let remote = |id: &str, args: Value| {
        step(
            "r",
            Probe::Remote {
                id: id.to_owned(),
                args: serde_json::from_value(args).unwrap(),
            },
            None,
        )
    };
    assert_eq!(
        repo.refusal(vec![remote("ruleset-presnt", json!({}))]),
        "Module declared: step `r`: remote probe `ruleset-presnt` is not in the host-adapter registry"
    );
    assert_eq!(
        repo.refusal(vec![remote("required-check", json!({"branch": "main"}))]),
        "Module declared: step `r`: remote probe `required-check` needs argument `check`"
    );
}

#[test]
fn an_invalid_json_pointer_refuses_at_load() {
    let repo = Repo::new();
    for pointer in ["a", "/a~2", "/a~", "a/b"] {
        let message = repo.refusal(vec![step(
            "p",
            Probe::JsonPointer {
                path: SETTINGS.to_owned(),
                pointer: pointer.to_owned(),
                equals: json!(1),
            },
            None,
        )]);
        assert_eq!(
            message,
            format!("Module declared: step `p` has an invalid JSON pointer: {pointer}")
        );
    }
}

#[test]
fn a_duplicate_step_id_an_unknown_after_and_an_after_cycle_refuse_at_load() {
    let repo = Repo::new();
    let file = |id: &str, after: Option<&str>| {
        step(
            id,
            Probe::FileExists {
                path: PRESENT.to_owned(),
            },
            after,
        )
    };
    assert_eq!(
        repo.refusal(vec![file("twice", None), file("twice", None)]),
        "Module declared: step `twice` is declared twice"
    );
    assert_eq!(
        repo.refusal(vec![file("late", Some("missing"))]),
        "Module declared: step `late` waits for unknown step `missing`"
    );
    assert_eq!(
        repo.refusal(vec![file("a", Some("b")), file("b", Some("a"))]),
        "Module declared: step `a` waits for itself through `after`"
    );
    assert_eq!(
        repo.refusal(vec![file("self", Some("self"))]),
        "Module declared: step `self` waits for itself through `after`"
    );
}

#[test]
fn an_after_in_another_module_is_unknown() {
    let repo = Repo::new();
    let message = repo
        .plan(&[
            &Steps,
            &Declared(vec![step(
                "cross",
                Probe::FileExists {
                    path: PRESENT.to_owned(),
                },
                Some("remote"),
            )]),
        ])
        .unwrap_err()
        .to_string();
    assert_eq!(
        message,
        "Module declared: step `cross` waits for unknown step `remote`"
    );
}

// ---- plan -------------------------------------------------------------------------

#[test]
fn plan_records_steps_sorted_by_module_and_id_and_writes_nothing_for_them() {
    let repo = Repo::new();
    let planned = repo
        .plan(&[
            &Steps,
            &SetupCore,
            &Declared(vec![step(
                "z",
                Probe::FileExists {
                    path: PRESENT.to_owned(),
                },
                None,
            )]),
        ])
        .unwrap();
    assert_eq!(
        planned
            .steps
            .iter()
            .map(|s| format!("{}:{}", s.module, s.id))
            .collect::<Vec<_>>(),
        vec![
            "declared:z",
            "steps:after-remote",
            "steps:file",
            "steps:pointer",
            "steps:remote"
        ]
    );
    assert!(planned.changes.keys().all(|p| !p.starts_with("fixture/")));
    apply(&repo.root, &planned.changes).unwrap();
    assert!(!repo.root.join("fixture").exists());
    let lock: Value =
        serde_json::from_str(&fs::read_to_string(repo.root.join(LOCK)).unwrap()).unwrap();
    assert_eq!(lock["modules"]["steps"]["version"], json!("0.2.0"));
    assert_eq!(
        lock["files"]
            .as_object()
            .unwrap()
            .keys()
            .filter(|k| k.starts_with("fixture/"))
            .count(),
        0
    );
}

#[test]
fn a_module_without_steps_has_none() {
    let repo = Repo::new();
    assert!(repo.plan(&[&SetupCore]).unwrap().steps.is_empty());
}

// ---- lines ------------------------------------------------------------------------

#[test]
fn plan_and_doctor_lines_carry_state_module_and_id() {
    let repo = Repo::new();
    repo.write(PRESENT, "x\n");
    let steps = repo.steps();
    assert_eq!(
        steps["file"].plan_line(),
        "STEP [verified:steps] file — Do file"
    );
    assert_eq!(
        steps["file"].doctor_line(),
        "STEP [verified:steps] file — fixture/present.md exists"
    );
    assert_eq!(
        steps["after-remote"].doctor_line(),
        "STEP [blocked:steps] after-remote — waits for step `remote` (unavailable)"
    );
    fs::remove_file(repo.root.join(PRESENT)).unwrap();
    fs::create_dir_all(repo.root.join(PRESENT)).unwrap();
    let line = repo.steps()["file"].doctor_line();
    assert!(
        line.starts_with("STEP [failed:steps] file — Expected a file: "),
        "{line}"
    );
}

// ---- doctor -----------------------------------------------------------------------

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "asserts setup-core's own content or id; product-boundary T7b"
)]
#[test]
fn doctor_evaluates_the_steps_of_the_installed_modules_only() {
    let repo = Repo::new();
    repo.install(&[&SetupCore]);
    // `steps` is compiled in but not in the lock: nothing of it is evaluated.
    let diagnosis = repo.diagnose(&[&SetupCore, &Steps]);
    assert!(diagnosis.steps.is_empty(), "{:?}", diagnosis.steps);
    assert_eq!(
        diagnosis.modules,
        vec![("setup-core".to_owned(), "1.3.0".to_owned())]
    );
    repo.install(&[&SetupCore, &Steps]);
    repo.write(PRESENT, "x\n");
    let diagnosis = repo.diagnose(&[&SetupCore, &Steps]);
    assert_eq!(
        diagnosis
            .steps
            .iter()
            .map(|s| (s.id.as_str(), s.state))
            .collect::<Vec<_>>(),
        vec![
            ("after-remote", StepState::Blocked),
            ("file", StepState::Verified),
            ("pointer", StepState::Pending),
            ("remote", StepState::Unavailable),
        ]
    );
    assert_eq!(
        diagnosis.modules,
        vec![
            ("setup-core".to_owned(), "1.3.0".to_owned()),
            ("steps".to_owned(), "0.2.0".to_owned())
        ]
    );
    // Steps are the owner's work: they never change readiness, which is about
    // managed content and the profile.
    assert!(diagnosis.findings.iter().all(|f| !f.contains("STEP")));
    assert_eq!(diagnosis.findings, doctor_at(&repo.root, today()).unwrap());
}

#[test]
fn doctor_without_a_lock_has_no_steps_and_no_modules() {
    let repo = Repo::new();
    let diagnosis = repo.diagnose(&[&SetupCore, &Steps]);
    assert!(diagnosis.steps.is_empty());
    assert!(diagnosis.modules.is_empty());
    assert!(
        diagnosis
            .findings
            .contains(&"Setup lock missing".to_owned())
    );
}

#[test]
fn printed_findings_keep_the_not_ready_and_warning_prefixes() {
    let diagnosis = Diagnosis {
        findings: vec![
            "WARNING: Decisions index stale: x".to_owned(),
            "Verification command missing".to_owned(),
        ],
        steps: Vec::new(),
        modules: Vec::new(),
        excluded: Vec::new(),
    };
    assert_eq!(
        diagnosis.printed_findings(),
        vec![
            "WARNING: Decisions index stale: x".to_owned(),
            "NOT READY: Verification command missing".to_owned()
        ]
    );
    assert!(!diagnosis.ready());
    assert!(
        Diagnosis {
            findings: vec!["WARNING: x".to_owned()],
            steps: Vec::new(),
            modules: Vec::new(),
            excluded: Vec::new(),
        }
        .ready()
    );
}

// ---- doctor --json ----------------------------------------------------------------

/// A step whose probe errors, for the golden file.
struct Broken;
impl Module for Broken {
    fn id(&self) -> &'static str {
        "broken"
    }
    fn version(&self) -> &'static str {
        "0.0.1"
    }
    fn render(&self, _: &Context<'_>) -> Result<Vec<Rendered>> {
        Ok(Vec::new())
    }
    fn manual_steps(&self, _: &Context<'_>) -> Vec<ManualStep> {
        vec![step(
            "dir",
            Probe::FileExists {
                path: "fixture/dir".to_owned(),
            },
            None,
        )]
    }
}

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "asserts setup-core's own content or id; product-boundary T7b"
)]
#[test]
fn doctor_json_matches_the_golden_file() {
    let repo = Repo::new();
    repo.install(&[&SetupCore, &Steps, &Broken]);
    repo.write(PRESENT, "x\n");
    repo.write(SETTINGS, "{\"permissions\": {\"deny\": [\"Edit(x)\"]}}\n");
    fs::create_dir_all(repo.root.join("fixture/dir")).unwrap();
    let diagnosis = repo.diagnose(&[&SetupCore, &Steps, &Broken]);
    let dir = repo.root.join("fixture/dir").display().to_string();
    let findings = vec![
        "NOT READY: Verification command missing".to_owned(),
        "WARNING: Decisions index stale: docs/agent-setup/decisions-index.md; regenerate with the setup installer".to_owned(),
    ];
    let json = doctor_json(false, &findings, &diagnosis.steps, &diagnosis.modules)
        .unwrap()
        .replace(&dir, "<repo>/fixture/dir");
    let golden = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/doctor.json");
    let expected = fs::read_to_string(golden).unwrap();
    assert_eq!(
        json, expected,
        "doctor --json drifted from {golden}; actual:\n{json}"
    );
    let value: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(value["schema"], json!(1));
    assert_eq!(value["ready"], json!(false));
    assert_eq!(value["steps"].as_array().unwrap().len(), 5);
    assert_eq!(
        value["steps"][0]["error"].as_str().unwrap(),
        "Expected a file: <repo>/fixture/dir"
    );
    assert!(value["steps"][0]["evidence"].is_null());
    assert!(value["steps"][2]["error"].is_null());
}

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "asserts setup-core's own content or id; product-boundary T7b"
)]
#[test]
fn cli_doctor_json_emits_the_document_instead_of_text_with_the_same_exit_code() {
    let repo = Repo::new();
    assert!(
        repo.cli(&["install", "--new-personal", "--apply"])
            .status
            .success()
    );
    let text = repo.cli(&["doctor"]);
    assert_eq!(text.status.code(), Some(1));
    let result = repo.cli(&["doctor", "--json"]);
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    let out = String::from_utf8_lossy(&result.stdout);
    assert!(out.starts_with("{\n"), "{out}");
    assert!(
        out.lines()
            .all(|l| !l.starts_with("NOT READY:") && !l.starts_with("WARNING:")),
        "{out}"
    );
    let value: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(value["schema"], json!(1));
    assert_eq!(value["ready"], json!(false));
    // A fresh install carries merge-guard and its registration step (#696).
    assert_eq!(
        value["steps"],
        json!([{"id": "hook-registered", "module": "merge-guard",
            "title": "Register the merge guard hook", "owner": "project", "state": "pending",
            "evidence": ".claude/settings.json is absent", "error": null}])
    );
    assert_eq!(
        value["modules"],
        json!([{"id": "merge-guard", "version": "1.0.0"}, {"id": "setup-core", "version": "1.3.0"}])
    );
    let findings: Vec<&str> = value["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f.as_str().unwrap())
        .collect();
    assert!(
        findings.contains(&"NOT READY: Verification command missing"),
        "{findings:?}"
    );
    let text_lines: Vec<&str> = String::from_utf8_lossy(&text.stdout)
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>()
        .leak()
        .iter()
        .map(String::as_str)
        .collect();
    for finding in &findings {
        assert!(
            text_lines.contains(finding),
            "{finding} not in {text_lines:?}"
        );
    }
    // Key order is part of the stable shape (a parsed Value sorts its keys).
    let positions: Vec<usize> = [
        "\"schema\"",
        "\"ready\"",
        "\"findings\"",
        "\"steps\"",
        "\"modules\"",
    ]
    .iter()
    .map(|key| out.find(key).unwrap())
    .collect();
    assert!(positions.windows(2).all(|w| w[0] < w[1]), "{out}");
}

#[test]
fn cli_json_is_only_available_with_doctor() {
    let repo = Repo::new();
    let result = repo.cli(&["install", "--new-personal", "--json"]);
    assert_eq!(result.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&result.stderr).trim(),
        "REFUSED: --json is only available with doctor"
    );
    assert!(!repo.root.join("AGENTS.md").exists());
}

// ---- doctor --remote through the host adapter (#683) --------------------------------

/// Serves canned GitHub replies by path; any other path answers `fallback`.
struct GitHubFake {
    replies: BTreeMap<String, Value>,
    fallback: (u16, &'static str),
}
impl brakes::remote::Api for GitHubFake {
    fn get(&self, path: &str) -> Result<Value> {
        match self.replies.get(path) {
            Some(value) => Ok(value.clone()),
            None => Err(brakes::remote::HttpError {
                status: self.fallback.0,
                message: self.fallback.1.to_owned(),
            }
            .into()),
        }
    }
}

/// `doctor` over the `Steps` fixture with `HostRunner` on GitHub over `fake`.
fn remote_step(repo: &Repo, fake: &GitHubFake) -> (StepState, Option<String>, Option<String>) {
    use brakes::host::{CallBudget, RepoId, github::GitHub, probes::HostRunner};
    let host = GitHub::new(fake, CallBudget::default());
    let runner = HostRunner::new(&host, RepoId::parse("example-owner/example").unwrap());
    let diagnosis = diagnose_with(
        &repo.root,
        today(),
        &Repo::source(),
        &[&SetupCore, &Steps],
        &runner,
    )
    .unwrap();
    let step = diagnosis
        .steps
        .into_iter()
        .find(|s| s.id == "remote")
        .unwrap();
    (step.state, step.evidence, step.error)
}

fn ruleset_fake(checks: &[&str]) -> GitHubFake {
    let contexts: Vec<Value> = checks.iter().map(|c| json!({ "context": c })).collect();
    let base = "repos/example-owner/example";
    GitHubFake {
        replies: BTreeMap::from([
            (
                format!("{base}/rulesets?per_page=100&page=1"),
                json!([{"id": 42}]),
            ),
            (
                format!("{base}/rulesets/42"),
                json!({"id": 42, "name": "main", "target": "branch", "enforcement": "active",
                    "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
                    "bypass_actors": [],
                    "rules": [{"type": "required_status_checks",
                        "parameters": {"required_status_checks": contexts}}]}),
            ),
        ]),
        fallback: (404, "Branch not protected"),
    }
}

#[test]
fn doctor_dispatches_a_remote_probe_to_the_registry_through_the_host() {
    let repo = Repo::new();
    repo.install(&[&SetupCore, &Steps]);
    assert_eq!(
        remote_step(&repo, &ruleset_fake(&["verify"])),
        (
            StepState::Verified,
            Some("ruleset 42 \"main\" requires \"verify\"".to_owned()),
            None
        )
    );
    assert_eq!(
        remote_step(&repo, &ruleset_fake(&["build"])),
        (
            StepState::Pending,
            Some("no ruleset or classic protection requires \"verify\" on main".to_owned()),
            None
        )
    );
    let unauthenticated = GitHubFake {
        replies: BTreeMap::new(),
        fallback: (401, "Bad credentials"),
    };
    assert_eq!(
        remote_step(&repo, &unauthenticated),
        (
            StepState::Unavailable,
            Some("gh not authenticated: GitHub CLI is not authenticated, so rulesets of example-owner/example could not be read (401: Bad credentials)".to_owned()),
            None
        )
    );
}

// ---- the auditor's rules for manual steps (#730) ---------------------------------

/// Audits the baseline step rules of `diagnosis`: no registry rule, only the
/// manual steps of the installed modules, judged from the engine's probes.
fn step_rules(
    root: &std::path::Path,
    diagnosis: &Diagnosis,
) -> BTreeMap<String, auditor::Evaluated> {
    use brakes::auditor::{Cx, Dimensions, LocalFiles, Today, evaluate, rules::Profile};
    use brakes::host::{CallBudget, RepoId};
    let host = auditor::offline_host();
    let files = LocalFiles::new(root);
    let repo = RepoId::parse("example-owner/example").unwrap();
    let budget = CallBudget::new(60);
    let diagnosed = Today {
        findings: &diagnosis.findings,
        steps: &diagnosis.steps,
        remote: false,
    };
    let cx = Cx {
        host: &host,
        files: &files,
        repo: &repo,
        default_branch: "main",
        now: today(),
        budget: &budget,
        profile: Profile::P1,
        today: Some(&diagnosed),
    };
    let dims = Dimensions {
        profile: Profile::P1,
        cadence: None,
        services: None,
        criticality: None,
        humans: None,
    };
    evaluate(&cx, &dims, &[])
        .rules
        .into_iter()
        .map(|e| (e.rule.id.to_owned(), e))
        .collect()
}

#[test]
fn each_manual_step_is_a_rule_whose_status_is_its_probe_result_with_the_evidence() {
    use brakes::auditor::rules::{Level, Probe as RuleProbe, Remediation, Status};
    let repo = Repo::new();
    repo.install(&[&SetupCore, &Steps]);
    repo.write(PRESENT, "x\n");
    let rules = step_rules(&repo.root, &repo.diagnose(&[&SetupCore, &Steps]));
    let status = |id: &str| {
        let o = &rules[id].outcome;
        (o.status, o.evidence.clone(), o.reason.clone())
    };
    // verified → passed, pending → failed, unavailable (and blocked behind it) → unavailable.
    assert_eq!(
        status("baseline.steps.file"),
        (
            Status::Passed,
            vec!["fixture/present.md exists".to_owned()],
            None
        )
    );
    assert_eq!(
        status("baseline.steps.pointer"),
        (
            Status::Failed,
            vec!["fixture/settings.json is absent".to_owned()],
            None
        )
    );
    assert_eq!(
        status("baseline.steps.remote"),
        (
            Status::Unavailable,
            vec![],
            Some("remote probe `required-check` runs only with doctor --remote".to_owned())
        )
    );
    assert_eq!(
        status("baseline.steps.after-remote"),
        (
            Status::Unavailable,
            vec![],
            Some("waits for step `remote` (unavailable)".to_owned())
        )
    );
    // The rule carries the module's step: level, probe and remediation.
    let rule = rules["baseline.steps.pointer"].rule;
    assert_eq!(rule.level, Level::Bronze);
    assert!(rules["baseline.steps.pointer"].required);
    assert_eq!(rule.title, "Do pointer");
    assert_eq!(
        rule.how,
        RuleProbe::ManualStep {
            module: "steps",
            step: "pointer"
        }
    );
    assert_eq!(
        rule.remediation,
        Remediation::Manual {
            step: "pointer",
            instructions: "Do pointer"
        }
    );
    // The same step is the same rule in a second audit.
    let again = step_rules(&repo.root, &repo.diagnose(&[&SetupCore, &Steps]));
    assert!(std::ptr::eq(rule, again["baseline.steps.pointer"].rule));
}

#[test]
fn a_probe_that_fails_is_unavailable_and_a_not_applicable_step_is_not_required() {
    use brakes::auditor::rules::Status;
    let repo = Repo::new();
    repo.install(&[&SetupCore, &Steps]);
    repo.write(SETTINGS, "{not json");
    let diagnosis = diagnose_with(
        &repo.root,
        today(),
        &Repo::source(),
        &[&SetupCore, &Steps],
        &NotApplicable,
    )
    .unwrap();
    let error = diagnosis
        .steps
        .iter()
        .find(|s| s.id == "pointer")
        .unwrap()
        .error
        .clone()
        .unwrap();
    let rules = step_rules(&repo.root, &diagnosis);
    let pointer = &rules["baseline.steps.pointer"].outcome;
    assert_eq!(pointer.status, Status::Unavailable);
    assert_eq!(pointer.reason.as_deref(), Some(error.as_str()));
    let remote = &rules["baseline.steps.remote"].outcome;
    assert_eq!(remote.status, Status::NotRequired);
    assert_eq!(remote.reason.as_deref(), Some("not found (404: Not Found)"));
}
