//! `apply <repo>` without `--remote` (#901, slice 1 of #900; decision #848 point 2):
//! the read-only REMOTE diff of the remote items the lock records for the
//! installed modules, evaluated through a fake probe runner. Nothing is written
//! and no test reaches a real host. #902: each pending item is named `create`,
//! `update` or `remove` from the desired state its module declares.
mod support;
use brakes::apply_remote::{
    Applied, RemoteLine, RemoteReader, RemoteVerb, RemoteWriter, apply_remote, closing, remote_plan,
};
use brakes::engine::{self, Module, ProbeResult, RemoteRunner};
use brakes::host::desired::{Change, Desired, RemoteWrite, Supersession, ruleset_from_file};
use brakes::host::types::WriteReport;
use brakes::modules::ci_baseline::CiBaseline;
use brakes::modules::repo_baseline::RepoBaseline;
use brakes::modules::repo_baseline::{REVIEW_RULESET_PATH, RULESET_PATH, steps::LABELS};
use brakes::*;
use serde_json::Value;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use support::SetupCore;
use tempfile::TempDir;

/// Answers each remote probe id with a fixed result and records every call;
/// classifies a ruleset as `create` (or fails it with `ruleset_read`), a
/// retirement as `remove` and every other desired state as `update`.
#[derive(Default)]
struct FakeRunner {
    answers: BTreeMap<&'static str, ProbeResult>,
    calls: RefCell<Vec<String>>,
    ruleset_read: Option<String>,
}
impl FakeRunner {
    fn with(answers: &[(&'static str, ProbeResult)]) -> Self {
        Self {
            answers: answers.iter().cloned().collect(),
            ..Self::default()
        }
    }
}
impl RemoteReader for FakeRunner {
    fn change(&self, desired: &Desired) -> std::result::Result<Change, String> {
        self.calls.borrow_mut().push("change".to_owned());
        match desired {
            Desired::Ruleset(_) => self.ruleset_read.clone().map_or(Ok(Change::Create), Err),
            Desired::RetireProtection { .. } => Ok(Change::Remove),
            _ => Ok(Change::Update),
        }
    }
}
impl RemoteRunner for FakeRunner {
    fn run(&self, id: &str, _args: &BTreeMap<String, Value>) -> ProbeResult {
        self.calls.borrow_mut().push(id.to_owned());
        self.answers
            .get(id)
            .cloned()
            .unwrap_or_else(|| ProbeResult::Failed(format!("unexpected probe {id}")))
    }
}

fn verified(id: &'static str) -> (&'static str, ProbeResult) {
    (id, ProbeResult::Verified(format!("{id} ok")))
}

/// A repository with setup-core and repo-baseline installed, as `install --apply` leaves it.
fn installed() -> (TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("project");
    fs::create_dir(&root).unwrap();
    let profile = profile_for(&root).unwrap();
    let modules: [&dyn Module; 2] = [&SetupCore, &RepoBaseline];
    let planned = engine::plan(&root, &Source::embedded(), &profile, &modules, &|_| true).unwrap();
    apply(&root, &planned.changes).unwrap();
    (temp, root)
}

fn plan(root: &Path, runner: &dyn RemoteReader) -> Result<Vec<RemoteLine>> {
    let modules: [&dyn Module; 2] = [&SetupCore, &RepoBaseline];
    remote_plan(root, &Source::embedded(), &modules, runner)
}

fn lines(diff: &[RemoteLine]) -> Vec<String> {
    diff.iter().map(RemoteLine::line).collect()
}

/// Every file under `root` with its bytes, to prove nothing was written.
fn tree(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut files = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else {
                files.insert(path.clone(), fs::read(&path).unwrap());
            }
        }
    }
    files
}

#[test]
fn one_line_per_remote_item_in_module_and_id_order_with_each_state() {
    let (_temp, root) = installed();
    let runner = FakeRunner::with(&[
        verified("check-run-reported"),
        (
            "ruleset-present",
            ProbeResult::Pending("no ruleset named \"main\"".to_owned()),
        ),
        (
            "classic-protection-absent",
            ProbeResult::Verified("no classic protection on main".to_owned()),
        ),
        verified("labels-present"),
        (
            "repo-settings",
            ProbeResult::Failed("repository read failed (502: Bad Gateway)".to_owned()),
        ),
        (
            "dependabot-alerts",
            ProbeResult::Unavailable("gh not authenticated: run gh auth login".to_owned()),
        ),
        (
            "automated-security-fixes",
            ProbeResult::Pending("disabled".to_owned()),
        ),
    ]);
    let diff = plan(&root, &runner).unwrap();
    assert_eq!(
        lines(&diff),
        [
            "REMOTE github:classic-protection-retire [repo-baseline] blocked — waits for step `ruleset-main` (pending)",
            "REMOTE github:dependabot-alerts [repo-baseline] unavailable — gh not authenticated: run gh auth login",
            "REMOTE github:dependabot-security-updates [repo-baseline] update — disabled",
            "REMOTE github:labels [repo-baseline] unchanged — labels-present ok",
            "REMOTE github:repo-settings [repo-baseline] failed — repository read failed (502: Bad Gateway)",
            "REMOTE github:ruleset-main [repo-baseline] create — no ruleset named \"main\"",
        ]
    );
    assert_eq!(closing(&diff), "Remote plan only; no writes.");
    // `check-reported` is a manual step, not a remote item: it gates, it is not listed.
    assert!(
        diff.iter().all(|l| l.item != "github:check-reported"),
        "{diff:?}"
    );
    // A blocked item's probe does not run.
    assert!(
        !runner
            .calls
            .borrow()
            .contains(&"classic-protection-absent".to_owned())
    );
}

#[test]
fn a_not_applicable_item_is_listed_never_written_and_counts_as_no_change() {
    let (_temp, root) = installed();
    let not_applicable = ProbeResult::NotApplicable("not found (404: Not Found)".to_owned());
    let runner = FakeRunner::with(&[
        verified("check-run-reported"),
        verified("ruleset-present"),
        verified("classic-protection-absent"),
        verified("labels-present"),
        verified("repo-settings"),
        ("dependabot-alerts", not_applicable.clone()),
        verified("automated-security-fixes"),
    ]);
    let diff = plan(&root, &runner).unwrap();
    assert!(
        lines(&diff).contains(
            &"REMOTE github:dependabot-alerts [repo-baseline] not-applicable — not found (404: Not Found)"
                .to_owned()
        ),
        "{diff:?}"
    );
    assert_eq!(closing(&diff), "No remote changes.");
    // Not pending, so the desired state is never classified.
    assert!(!runner.calls.borrow().contains(&"change".to_owned()));
    // `apply --remote` writes nothing for it.
    let host = StatefulHost {
        not_applicable: vec!["dependabot-alerts"],
        ..StatefulHost::default()
    };
    let applied = run_remote(&root, &host);
    assert!(host.written.borrow().is_empty());
    assert!(
        applied.lines.contains(
            &"REMOTE github:dependabot-alerts [repo-baseline] not-applicable — dependabot-alerts does not apply"
                .to_owned()
        ),
        "{:#?}",
        applied.lines
    );
    assert_eq!(applied.closing, "No remote changes.");
    assert!(applied.verified);
}

#[test]
fn all_verified_is_no_remote_changes() {
    let (_temp, root) = installed();
    let runner = FakeRunner::with(&[
        verified("check-run-reported"),
        verified("ruleset-present"),
        verified("classic-protection-absent"),
        verified("labels-present"),
        verified("repo-settings"),
        verified("dependabot-alerts"),
        verified("automated-security-fixes"),
    ]);
    let diff = plan(&root, &runner).unwrap();
    assert_eq!(diff.len(), 6);
    assert!(
        diff.iter().all(|l| l.verb == RemoteVerb::Unchanged),
        "{diff:?}"
    );
    assert_eq!(closing(&diff), "No remote changes.");
    // Only a pending item is classified.
    assert!(!runner.calls.borrow().contains(&"change".to_owned()));
}

#[test]
fn a_pending_retirement_is_a_removal_and_a_failed_classification_is_failed() {
    let (_temp, root) = installed();
    let mut runner = FakeRunner::with(&[
        verified("check-run-reported"),
        (
            "ruleset-present",
            ProbeResult::Pending("no ruleset named \"main\"".to_owned()),
        ),
        verified("labels-present"),
        verified("repo-settings"),
        verified("dependabot-alerts"),
        verified("automated-security-fixes"),
    ]);
    runner.ruleset_read =
        Some("rulesets of example-owner/example failed (502: Bad Gateway)".to_owned());
    let diff = plan(&root, &runner).unwrap();
    assert!(
        lines(&diff).contains(
            &"REMOTE github:ruleset-main [repo-baseline] failed — rulesets of example-owner/example failed (502: Bad Gateway)".to_owned()
        ),
        "{diff:?}"
    );
    assert_eq!(closing(&diff), "No remote changes.");
    let runner = FakeRunner::with(&[
        verified("check-run-reported"),
        verified("ruleset-present"),
        (
            "classic-protection-absent",
            ProbeResult::Pending(
                "classic protection of main is in force (requires: verify)".to_owned(),
            ),
        ),
        verified("labels-present"),
        verified("repo-settings"),
        verified("dependabot-alerts"),
        verified("automated-security-fixes"),
    ]);
    let diff = plan(&root, &runner).unwrap();
    assert!(
        lines(&diff).contains(
            &"REMOTE github:classic-protection-retire [repo-baseline] remove — classic protection of main is in force (requires: verify)".to_owned()
        ),
        "{diff:?}"
    );
    assert_eq!(closing(&diff), "Remote plan only; no writes.");
}

fn desired_of(module: &dyn Module, root: &Path) -> BTreeMap<String, Desired> {
    let profile = profile_for(root).unwrap();
    let lock = engine::Lock::parse(
        &fs::read_to_string(root.join(LOCK)).unwrap(),
        modules::core_version(),
        &|_| true,
    )
    .unwrap();
    engine::remote_writes(root, &Source::embedded(), &profile, &[module], &lock)
        .unwrap()
        .into_iter()
        .map(|(_, write)| (write.id, write.desired))
        .collect()
}

/// A repository whose repo-baseline declares an organization-admin bypass
/// (#1218), registered in the inventory, installed at P2.
fn installed_with_bypass() -> (TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("project");
    fs::create_dir_all(root.join(".agent-setup/modules")).unwrap();
    fs::write(
        root.join(".agent-setup/modules/repo-baseline.json"),
        r#"{"module": "repo-baseline", "version": "1.0.0", "profile": "P2", "answers": {"bypass_actors": ["OrganizationAdmin:1:pull_request"]}}"#,
    )
    .unwrap();
    fs::write(
        root.join(".agent-setup/security-exceptions.json"),
        r##"{"schema": 1, "exceptions": [{"id": "owners", "kind": "ruleset-bypass-actor", "target": "OrganizationAdmin:1:pull_request", "reason": "organization owners merge their own pull requests", "issue": "#1218", "owner": "example-owner", "created": "2026-10-31", "expires": "2027-10-31"}]}"##,
    )
    .unwrap();
    let profile = profile_for(&root).unwrap();
    let modules: [&dyn Module; 2] = [&SetupCore, &RepoBaseline];
    let planned = engine::plan(&root, &Source::embedded(), &profile, &modules, &|_| true).unwrap();
    apply(&root, &planned.changes).unwrap();
    (temp, root)
}

#[test]
fn a_declared_bypass_writes_two_rulesets_and_only_the_review_one_is_bypassed() {
    let (_temp, root) = installed_with_bypass();
    let desired = desired_of(&RepoBaseline, &root);
    assert!(
        desired.contains_key("ruleset-review"),
        "{:?}",
        desired.keys()
    );
    let Desired::Ruleset(checks) = &desired["ruleset-main"] else {
        panic!("{:?}", desired["ruleset-main"]);
    };
    assert!(
        checks.bypass_actors.is_empty(),
        "the checks are never bypassed"
    );
    assert_eq!(checks.required_status_checks, ["required"]);
    assert!(!checks.rules.iter().any(|r| r == "pull_request"));
    let review = fs::read_to_string(root.join(REVIEW_RULESET_PATH)).unwrap();
    assert_eq!(
        desired["ruleset-review"],
        Desired::Ruleset(ruleset_from_file(&review, REVIEW_RULESET_PATH).unwrap())
    );
    let Desired::Ruleset(review) = &desired["ruleset-review"] else {
        unreachable!()
    };
    assert_eq!(review.bypass_actors, ["OrganizationAdmin:1:pull_request"]);
    assert!(review.required_status_checks.is_empty());
    assert_eq!(review.rules, ["pull_request"]);
}

#[test]
fn repo_baseline_declares_the_desired_state_of_each_remote_item() {
    let (_temp, root) = installed();
    let desired = desired_of(&RepoBaseline, &root);
    assert_eq!(
        desired.keys().map(String::as_str).collect::<Vec<_>>(),
        [
            "classic-protection-retire",
            "dependabot-alerts",
            "dependabot-security-updates",
            "labels",
            "repo-settings",
            "ruleset-main",
        ]
    );
    // The ruleset is the rendered file, read back.
    let file = fs::read_to_string(root.join(RULESET_PATH)).unwrap();
    assert_eq!(
        desired["ruleset-main"],
        Desired::Ruleset(ruleset_from_file(&file, RULESET_PATH).unwrap())
    );
    let Desired::Labels(labels) = &desired["labels"] else {
        panic!("{:?}", desired["labels"]);
    };
    let declared: Vec<Value> = serde_json::from_str(LABELS).unwrap();
    assert_eq!(labels.len(), declared.len());
    for (label, value) in labels.iter().zip(&declared) {
        assert_eq!(label.name, value["name"].as_str().unwrap());
        assert_eq!(label.color, value["color"].as_str().unwrap());
        assert_eq!(label.description.as_deref(), value["description"].as_str());
    }
    let Desired::Settings(settings) = &desired["repo-settings"] else {
        panic!("{:?}", desired["repo-settings"]);
    };
    assert_eq!(settings.allow_squash_merge, Some(true));
    assert_eq!(settings.allow_merge_commit, Some(false));
    assert_eq!(settings.allow_rebase_merge, Some(false));
    assert_eq!(settings.delete_branch_on_merge, Some(true));
    assert_eq!(settings.allow_auto_merge, Some(true));
    assert_eq!(settings.allow_update_branch, Some(true));
    assert_eq!(settings.vulnerability_alerts, None);
    let Desired::Settings(alerts) = &desired["dependabot-alerts"] else {
        panic!("{:?}", desired["dependabot-alerts"]);
    };
    assert_eq!(alerts.vulnerability_alerts, Some(true));
    assert_eq!(alerts.allow_squash_merge, None);
    let Desired::Settings(fixes) = &desired["dependabot-security-updates"] else {
        panic!("{:?}", desired["dependabot-security-updates"]);
    };
    assert_eq!(fixes.automated_security_fixes, Some(true));
    assert_eq!(fixes.vulnerability_alerts, None);
    assert_eq!(
        desired["classic-protection-retire"],
        Desired::RetireProtection {
            branch: "main".to_owned(),
            superseded_by: Supersession::None,
        }
    );
}

#[test]
fn ci_baseline_declares_the_required_check_switch_and_addition() {
    let (_temp, root) = installed();
    let desired = desired_of(&CiBaseline, &root);
    assert_eq!(
        desired["switch-required-check"],
        Desired::RequiredChecks {
            branch: "main".to_owned(),
            checks: vec!["required".to_owned()],
            keep_others: false,
        }
    );
    assert_eq!(
        desired["add-agentic-required-check"],
        Desired::RequiredChecks {
            branch: "main".to_owned(),
            checks: vec!["agentic-required".to_owned()],
            keep_others: true,
        }
    );
}

#[test]
fn the_diff_writes_nothing() {
    let (_temp, root) = installed();
    let before = tree(&root);
    let runner = FakeRunner::default();
    plan(&root, &runner).unwrap();
    assert_eq!(tree(&root), before);
}

#[test]
fn a_repository_with_only_setup_core_has_no_remote_items() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("project");
    fs::create_dir(&root).unwrap();
    let profile = profile_for(&root).unwrap();
    let planned = engine::plan(&root, &Source::embedded(), &profile, &[&SetupCore], &|_| {
        true
    })
    .unwrap();
    apply(&root, &planned.changes).unwrap();
    let runner = FakeRunner::default();
    let diff = plan(&root, &runner).unwrap();
    assert!(diff.is_empty());
    assert_eq!(closing(&diff), "No remote changes.");
    assert!(runner.calls.borrow().is_empty());
}

#[test]
fn without_a_lock_it_refuses() {
    let temp = tempfile::tempdir().unwrap();
    let error = plan(temp.path(), &FakeRunner::default()).unwrap_err();
    assert_eq!(
        error.to_string(),
        "Setup lock missing: .agent-setup/lock.json; run install first"
    );
}

/// A remote item whose module declares no step of its id cannot be probed.
struct Unprobed;
impl Module for Unprobed {
    fn id(&self) -> &'static str {
        "unprobed"
    }
    fn version(&self) -> &'static str {
        "1.0.0"
    }
    fn requires(&self) -> &'static [&'static str] {
        &["setup-core"]
    }
    fn render(&self, _cx: &engine::Context<'_>) -> Result<Vec<engine::Rendered>> {
        Ok(vec![engine::Rendered {
            path: "github:orphan".to_owned(),
            class: engine::Ownership::Remote,
            content: None,
            scaffold: None,
        }])
    }
    fn remote_writes(&self, _cx: &engine::Context<'_>) -> Result<Vec<RemoteWrite>> {
        Ok(vec![RemoteWrite {
            id: "orphan".to_owned(),
            desired: Desired::RetireProtection {
                branch: "main".to_owned(),
                superseded_by: Supersession::None,
            },
        }])
    }
}

/// Remote items with no desired state, or with two for one id.
struct Undeclared {
    writes: usize,
}
impl Module for Undeclared {
    fn id(&self) -> &'static str {
        "undeclared"
    }
    fn version(&self) -> &'static str {
        "1.0.0"
    }
    fn requires(&self) -> &'static [&'static str] {
        &["setup-core"]
    }
    fn render(&self, _cx: &engine::Context<'_>) -> Result<Vec<engine::Rendered>> {
        Ok(vec![engine::Rendered {
            path: "github:item".to_owned(),
            class: engine::Ownership::Remote,
            content: None,
            scaffold: None,
        }])
    }
    fn remote_writes(&self, _cx: &engine::Context<'_>) -> Result<Vec<RemoteWrite>> {
        let write = RemoteWrite {
            id: "item".to_owned(),
            desired: Desired::RetireProtection {
                branch: "main".to_owned(),
                superseded_by: Supersession::None,
            },
        };
        Ok(vec![write; self.writes])
    }
}

#[test]
fn a_remote_item_without_or_with_two_desired_states_refuses_before_any_probe() {
    for (writes, message) in [
        (
            0,
            "Module undeclared: remote item github:item declares no desired state",
        ),
        (
            2,
            "Module undeclared: remote item github:item declares two desired states",
        ),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("project");
        fs::create_dir(&root).unwrap();
        let profile = profile_for(&root).unwrap();
        let module = Undeclared { writes };
        let modules: [&dyn Module; 2] = [&SetupCore, &module];
        let planned =
            engine::plan(&root, &Source::embedded(), &profile, &modules, &|_| true).unwrap();
        apply(&root, &planned.changes).unwrap();
        let runner = FakeRunner::default();
        let error = remote_plan(&root, &Source::embedded(), &modules, &runner).unwrap_err();
        assert_eq!(error.to_string(), message);
        assert!(runner.calls.borrow().is_empty(), "{:?}", runner.calls);
    }
}

#[test]
fn a_remote_item_without_a_step_is_reported_failed() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("project");
    fs::create_dir(&root).unwrap();
    let profile = profile_for(&root).unwrap();
    let modules: [&dyn Module; 2] = [&SetupCore, &Unprobed];
    let planned = engine::plan(&root, &Source::embedded(), &profile, &modules, &|_| true).unwrap();
    apply(&root, &planned.changes).unwrap();
    let diff = remote_plan(&root, &Source::embedded(), &modules, &FakeRunner::default()).unwrap();
    assert_eq!(
        lines(&diff),
        [
            "REMOTE github:orphan [unprobed] failed — module unprobed declares no probe for github:orphan"
        ]
    );
}

// --- `apply <repo> --remote` (#903) ------------------------------------------------------

/// A fake host with state: each probe answers pending until the item it checks
/// was written, then verified (unless `stuck`); writes are recorded in order and
/// fail for the ids in `failing`. Probes of `check-run-reported` verify.
#[derive(Default)]
struct StatefulHost {
    pending: Vec<&'static str>,
    stuck: Vec<&'static str>,
    failing: Vec<&'static str>,
    /// Items the host says do not exist for this repository (#846).
    not_applicable: Vec<&'static str>,
    written: RefCell<Vec<String>>,
}
/// The probe id that checks each repo-baseline item.
const PROBE_OF: [(&str, &str); 6] = [
    ("ruleset-main", "ruleset-present"),
    ("classic-protection-retire", "classic-protection-absent"),
    ("labels", "labels-present"),
    ("repo-settings", "repo-settings"),
    ("dependabot-alerts", "dependabot-alerts"),
    ("dependabot-security-updates", "automated-security-fixes"),
];
impl RemoteRunner for StatefulHost {
    fn run(&self, id: &str, _args: &BTreeMap<String, Value>) -> ProbeResult {
        let item = PROBE_OF.iter().find(|(_, p)| *p == id).map(|(i, _)| *i);
        let Some(item) = item else {
            return ProbeResult::Verified(format!("{id} ok"));
        };
        if self.not_applicable.contains(&item) {
            return ProbeResult::NotApplicable(format!("{item} does not apply"));
        }
        let written = self.written.borrow().iter().any(|w| w == item);
        if self.pending.contains(&item) && (!written || self.stuck.contains(&item)) {
            ProbeResult::Pending(format!("{item} differs"))
        } else {
            ProbeResult::Verified(format!("{item} ok"))
        }
    }
}
impl RemoteReader for StatefulHost {
    fn change(&self, desired: &Desired) -> std::result::Result<Change, String> {
        Ok(match desired {
            Desired::RetireProtection { .. } => Change::Remove,
            Desired::Ruleset(_) => Change::Create,
            _ => Change::Update,
        })
    }
}
impl RemoteWriter for StatefulHost {
    fn write(&self, write: &RemoteWrite) -> std::result::Result<WriteReport, String> {
        if self.failing.contains(&write.id.as_str()) {
            return Err(format!("{} failed (422: Validation Failed)", write.id));
        }
        self.written.borrow_mut().push(write.id.clone());
        Ok(WriteReport {
            updated: vec![write.id.clone()],
            ..WriteReport::default()
        })
    }
}

fn run_remote(root: &Path, host: &StatefulHost) -> Applied {
    let modules: [&dyn Module; 2] = [&SetupCore, &RepoBaseline];
    apply_remote(root, &Source::embedded(), &modules, host, host).unwrap()
}

#[test]
fn remote_writes_exactly_the_diffed_items_in_declaration_order_and_verifies_them() {
    let (_temp, root) = installed();
    let host = StatefulHost {
        pending: vec!["repo-settings", "ruleset-main", "labels"],
        ..StatefulHost::default()
    };
    let applied = run_remote(&root, &host);
    // repo-baseline declares ruleset-main, the retirement, labels, settings, …
    assert_eq!(
        *host.written.borrow(),
        ["ruleset-main", "labels", "repo-settings"]
    );
    assert_eq!(
        applied.lines,
        [
            "REMOTE github:classic-protection-retire [repo-baseline] blocked — waits for step `ruleset-main` (pending)",
            "REMOTE github:dependabot-alerts [repo-baseline] unchanged — dependabot-alerts ok",
            "REMOTE github:dependabot-security-updates [repo-baseline] unchanged — dependabot-security-updates ok",
            "REMOTE github:labels [repo-baseline] update — labels differs",
            "REMOTE github:repo-settings [repo-baseline] update — repo-settings differs",
            "REMOTE github:ruleset-main [repo-baseline] create — ruleset-main differs",
            "WRITE github:ruleset-main [repo-baseline] create — updated: ruleset-main",
            "WRITE github:labels [repo-baseline] update — updated: labels",
            "WRITE github:repo-settings [repo-baseline] update — updated: repo-settings",
            "VERIFY github:ruleset-main [repo-baseline] verified — ruleset-main ok",
            "VERIFY github:labels [repo-baseline] verified — labels ok",
            "VERIFY github:repo-settings [repo-baseline] verified — repo-settings ok",
        ]
    );
    assert_eq!(
        applied.closing,
        "Remote writes applied; every written item verified."
    );
    assert!(applied.verified);
    // The retirement was blocked in the diff, so this run did not write it.
    assert!(
        !host
            .written
            .borrow()
            .contains(&"classic-protection-retire".to_owned())
    );
}

#[test]
fn a_second_run_after_a_verified_one_sends_nothing() {
    let (_temp, root) = installed();
    let host = StatefulHost {
        pending: vec!["repo-settings", "dependabot-alerts"],
        ..StatefulHost::default()
    };
    assert!(run_remote(&root, &host).verified);
    let first = host.written.borrow().len();
    let again = run_remote(&root, &host);
    assert_eq!(host.written.borrow().len(), first);
    assert!(
        again
            .lines
            .iter()
            .all(|l| l.starts_with("REMOTE ") && l.contains("] unchanged — ")
                || l.contains("] blocked — ")),
        "{:?}",
        again.lines
    );
    assert_eq!(again.closing, "No remote changes.");
    assert!(again.verified);
}

#[test]
fn a_write_that_does_not_verify_or_fails_is_reported_and_never_retried() {
    let (_temp, root) = installed();
    let host = StatefulHost {
        pending: vec!["labels", "repo-settings", "dependabot-alerts"],
        stuck: vec!["labels"],
        failing: vec!["repo-settings"],
        ..StatefulHost::default()
    };
    let applied = run_remote(&root, &host);
    assert_eq!(*host.written.borrow(), ["labels", "dependabot-alerts"]);
    for line in [
        "WRITE github:repo-settings [repo-baseline] failed — repo-settings failed (422: Validation Failed)",
        "VERIFY github:labels [repo-baseline] pending — labels differs",
        "VERIFY github:repo-settings [repo-baseline] pending — repo-settings differs",
        "VERIFY github:dependabot-alerts [repo-baseline] verified — dependabot-alerts ok",
    ] {
        assert!(
            applied.lines.contains(&line.to_owned()),
            "{line}\n{:#?}",
            applied.lines
        );
    }
    assert_eq!(
        applied.closing,
        "Remote writes applied; 2 of 3 items not verified."
    );
    assert!(!applied.verified);
}

#[test]
fn nothing_pending_writes_nothing_and_says_so() {
    let (_temp, root) = installed();
    let host = StatefulHost::default();
    let applied = run_remote(&root, &host);
    assert!(host.written.borrow().is_empty());
    assert!(applied.lines.iter().all(|l| l.starts_with("REMOTE ")));
    assert_eq!(applied.closing, "No remote changes.");
    assert!(applied.verified);
}

#[test]
fn an_item_blocked_on_a_step_written_and_verified_in_this_run_is_written_in_the_same_run() {
    // #1148: the pilot created `ruleset-main` and left the retirement for a third run.
    let (_temp, root) = installed();
    let host = StatefulHost {
        pending: vec!["ruleset-main", "classic-protection-retire"],
        ..StatefulHost::default()
    };
    let applied = run_remote(&root, &host);
    assert_eq!(
        *host.written.borrow(),
        ["ruleset-main", "classic-protection-retire"]
    );
    assert_eq!(
        applied.lines,
        [
            "REMOTE github:classic-protection-retire [repo-baseline] blocked — waits for step `ruleset-main` (pending)",
            "REMOTE github:dependabot-alerts [repo-baseline] unchanged — dependabot-alerts ok",
            "REMOTE github:dependabot-security-updates [repo-baseline] unchanged — dependabot-security-updates ok",
            "REMOTE github:labels [repo-baseline] unchanged — labels ok",
            "REMOTE github:repo-settings [repo-baseline] unchanged — repo-settings ok",
            "REMOTE github:ruleset-main [repo-baseline] create — ruleset-main differs",
            "WRITE github:ruleset-main [repo-baseline] create — updated: ruleset-main",
            "REMOTE github:classic-protection-retire [repo-baseline] remove — classic-protection-retire differs",
            "WRITE github:classic-protection-retire [repo-baseline] remove — updated: classic-protection-retire",
            "VERIFY github:ruleset-main [repo-baseline] verified — ruleset-main ok",
            "VERIFY github:classic-protection-retire [repo-baseline] verified — classic-protection-retire ok",
        ]
    );
    assert_eq!(
        applied.closing,
        "Remote writes applied; every written item verified."
    );
    assert!(applied.verified);
}

#[test]
fn an_item_stays_blocked_when_its_step_does_not_verify_in_this_run() {
    let (_temp, root) = installed();
    let host = StatefulHost {
        pending: vec!["ruleset-main", "classic-protection-retire"],
        stuck: vec!["ruleset-main"],
        ..StatefulHost::default()
    };
    let applied = run_remote(&root, &host);
    assert_eq!(*host.written.borrow(), ["ruleset-main"]);
    assert!(
        applied
            .lines
            .iter()
            .all(|l| !l.contains("github:classic-protection-retire") || l.contains("] blocked — ")),
        "{:#?}",
        applied.lines
    );
    assert!(
        applied.lines.contains(
            &"VERIFY github:ruleset-main [repo-baseline] pending — ruleset-main differs".to_owned()
        ),
        "{:#?}",
        applied.lines
    );
    assert_eq!(
        applied.closing,
        "Remote writes applied; 1 of 1 items not verified."
    );
    assert!(!applied.verified);
}
