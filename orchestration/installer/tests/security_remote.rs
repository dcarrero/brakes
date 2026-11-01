//! security #854 (decision 2026-10-28, #848 point 5): `secret-scanning` and
//! `private-vulnerability-reporting` are `remote` items `apply <repo> --remote`
//! writes and verifies with the same probes (SPEC-security.md, Manual steps
//! with probes). The host is `GitHub` over a stateful fake transport: a write
//! changes what the next read answers, so the re-probe proves the write. No
//! `gh` process runs and nothing is sent to GitHub.
mod support;
use brakes::apply_remote::{Applied, HostWriter, apply_remote, remote_plan};
use brakes::engine::manual::{StepReport, StepState};
use brakes::engine::{self, Context, Lock, Module, Ownership, Rendered};
use brakes::host::{
    CallBudget, RepoId, authorize,
    desired::{Desired, RemoteWrite},
    github::GitHub,
    probes::HostRunner,
    types::RepositorySettingsPatch,
};
use brakes::modules::StackPacks;
use brakes::modules::security::{SECURITY, Security};
use brakes::remote::{Api, HttpError};
use brakes::*;
use serde_json::{Value, json};
use std::cell::RefCell;
use std::{fs, path::PathBuf, process::Command};
use support::SetupCore;
use tempfile::TempDir;

const BASE: &str = "repos/example-owner/example";
const PVR: &str = "repos/example-owner/example/private-vulnerability-reporting";

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

fn modules() -> [&'static dyn Module; 4] {
    [&SetupCore, &StackPacks, &CiBaselineStandIn, &Security]
}

/// A git repository with security installed (default answers).
fn installed() -> (TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("project");
    fs::create_dir(&root).unwrap();
    let status = Command::new("git")
        .args(["init", "-q"])
        .arg(&root)
        .status()
        .unwrap();
    assert!(status.success());
    let profile = profile_for(&root).unwrap();
    let planned =
        engine::plan(&root, &Source::embedded(), &profile, &modules(), &|_| true).unwrap();
    apply(&root, &planned.changes).unwrap();
    (temp, root)
}

/// GitHub's side of the two settings: reads answer the current state, the two
/// writes change it; `pvr: None` answers 404, as on a private repository.
struct Remote {
    visibility: &'static str,
    secret_scanning: RefCell<&'static str>,
    push_protection: RefCell<&'static str>,
    pvr: RefCell<Option<bool>>,
    writes: RefCell<Vec<(String, Option<Value>)>>,
}
impl Remote {
    fn new(scanning: &'static str, push: &'static str, pvr: Option<bool>) -> Self {
        Self {
            visibility: "public",
            secret_scanning: RefCell::new(scanning),
            push_protection: RefCell::new(push),
            pvr: RefCell::new(pvr),
            writes: RefCell::default(),
        }
    }
    fn repository(&self) -> Value {
        json!({
            "id": 7, "default_branch": "main", "visibility": self.visibility, "private": self.visibility != "public",
            "archived": false, "fork": false,
            "security_and_analysis": {
                "secret_scanning": {"status": *self.secret_scanning.borrow()},
                "secret_scanning_push_protection": {"status": *self.push_protection.borrow()},
            },
        })
    }
}
fn not_found() -> Box<dyn std::error::Error> {
    HttpError {
        status: 404,
        message: "Not Found".to_owned(),
    }
    .into()
}
impl Api for Remote {
    fn get(&self, path: &str) -> Result<Value> {
        match path {
            BASE => Ok(self.repository()),
            PVR => match *self.pvr.borrow() {
                Some(enabled) => Ok(json!({ "enabled": enabled })),
                None => Err(not_found()),
            },
            _ => Err(format!("unexpected GET {path}").into()),
        }
    }
    fn send(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value> {
        self.writes
            .borrow_mut()
            .push((format!("{method} {path}"), body.cloned()));
        match (method, path) {
            ("PATCH", BASE) => {
                let security = &body.unwrap()["security_and_analysis"];
                if security["secret_scanning"]["status"] == "enabled" {
                    *self.secret_scanning.borrow_mut() = "enabled";
                }
                if security["secret_scanning_push_protection"]["status"] == "enabled" {
                    *self.push_protection.borrow_mut() = "enabled";
                }
                Ok(self.repository())
            }
            ("PUT", PVR) => {
                *self.pvr.borrow_mut() = Some(true);
                Ok(Value::Null)
            }
            _ => Err(format!("unexpected {method} {path}").into()),
        }
    }
}

fn run(root: &std::path::Path, remote: &Remote) -> Applied {
    let github = GitHub::new(remote, CallBudget::new(100));
    let repo = RepoId::parse("example-owner/example").unwrap();
    let reader = HostRunner::new(&github, repo.clone());
    let writer = HostWriter::new(&github, authorize::write(&repo, true).unwrap());
    apply_remote(root, &Source::embedded(), &modules(), &reader, &writer).unwrap()
}

fn security_lines(applied: &Applied) -> Vec<&str> {
    applied
        .lines
        .iter()
        .map(String::as_str)
        .filter(|l| l.contains("[security]"))
        .collect()
}

#[test]
fn both_items_are_recorded_remote_in_the_lock_and_never_written() {
    let (_temp, root) = installed();
    let lock = Lock::parse(
        &fs::read_to_string(root.join(LOCK)).unwrap(),
        modules::core_version(),
        &|_| true,
    )
    .unwrap();
    for item in [
        "github:secret-scanning",
        "github:private-vulnerability-reporting",
    ] {
        let entry = &lock.files[item];
        assert_eq!(entry.class, Ownership::Remote, "{item}");
        assert_eq!(entry.module, SECURITY, "{item}");
        assert!(!root.join(item).exists(), "{item}");
    }
    assert!(
        !lock
            .files
            .keys()
            .any(|path| path == "github:hooks-installed")
    );
}

#[test]
fn each_item_declares_the_settings_of_its_instructions() {
    let (_temp, root) = installed();
    let profile = profile_for(&root).unwrap();
    let lock = Lock::parse(
        &fs::read_to_string(root.join(LOCK)).unwrap(),
        modules::core_version(),
        &|_| true,
    )
    .unwrap();
    let writes: Vec<RemoteWrite> =
        engine::remote_writes(&root, &Source::embedded(), &profile, &modules(), &lock)
            .unwrap()
            .into_iter()
            .filter(|(module, _)| module == SECURITY)
            .map(|(_, write)| write)
            .collect();
    assert_eq!(
        writes,
        [
            RemoteWrite {
                id: "secret-scanning".to_owned(),
                desired: Desired::Settings(RepositorySettingsPatch {
                    secret_scanning: Some("enabled".to_owned()),
                    secret_scanning_push_protection: Some("enabled".to_owned()),
                    ..RepositorySettingsPatch::default()
                }),
            },
            RemoteWrite {
                id: "private-vulnerability-reporting".to_owned(),
                desired: Desired::Settings(RepositorySettingsPatch {
                    private_vulnerability_reporting: Some(true),
                    ..RepositorySettingsPatch::default()
                }),
            },
        ]
    );
}

#[test]
fn apply_without_remote_prints_the_diff_and_writes_nothing() {
    let (_temp, root) = installed();
    let remote = Remote::new("disabled", "disabled", Some(false));
    let github = GitHub::new(&remote, CallBudget::new(100));
    let reader = HostRunner::new(&github, RepoId::parse("example-owner/example").unwrap());
    let diff = remote_plan(&root, &Source::embedded(), &modules(), &reader).unwrap();
    let lines: Vec<String> = diff.iter().map(|l| l.line()).collect();
    assert_eq!(
        lines,
        [
            "REMOTE github:private-vulnerability-reporting [security] update — disabled",
            "REMOTE github:secret-scanning [security] update — secret scanning disabled, push protection disabled",
        ]
    );
    assert!(remote.writes.borrow().is_empty());
}

#[test]
fn apply_remote_sends_exactly_the_instructions_writes_and_both_verify() {
    let (_temp, root) = installed();
    let remote = Remote::new("disabled", "disabled", Some(false));
    let applied = run(&root, &remote);
    assert_eq!(
        *remote.writes.borrow(),
        [
            (
                format!("PATCH {BASE}"),
                Some(json!({"security_and_analysis": {
                    "secret_scanning": {"status": "enabled"},
                    "secret_scanning_push_protection": {"status": "enabled"},
                }})),
            ),
            (format!("PUT {PVR}"), None),
        ]
    );
    assert_eq!(
        security_lines(&applied),
        [
            "REMOTE github:private-vulnerability-reporting [security] update — disabled",
            "REMOTE github:secret-scanning [security] update — secret scanning disabled, push protection disabled",
            "WRITE github:secret-scanning [security] update — updated: secret_scanning, secret_scanning_push_protection",
            "WRITE github:private-vulnerability-reporting [security] update — updated: private_vulnerability_reporting",
            "VERIFY github:secret-scanning [security] verified — secret scanning enabled, push protection enabled",
            "VERIFY github:private-vulnerability-reporting [security] verified — enabled",
        ]
    );
    assert!(applied.verified, "{applied:?}");

    // A second run finds both verified and sends nothing.
    let again = run(&root, &remote);
    assert_eq!(remote.writes.borrow().len(), 2);
    assert_eq!(again.closing, "No remote changes.");
}

#[test]
fn only_the_differing_status_is_patched() {
    let (_temp, root) = installed();
    let remote = Remote::new("enabled", "disabled", Some(true));
    let applied = run(&root, &remote);
    assert_eq!(
        *remote.writes.borrow(),
        [(
            format!("PATCH {BASE}"),
            Some(json!({"security_and_analysis": {
                "secret_scanning_push_protection": {"status": "enabled"},
            }})),
        )]
    );
    assert!(applied.verified, "{applied:?}");
}

#[test]
fn private_vulnerability_reporting_not_applicable_on_a_private_repository_is_not_attempted() {
    let (_temp, root) = installed();
    let remote = Remote::new("enabled", "enabled", None);
    let applied = run(&root, &remote);
    assert!(remote.writes.borrow().is_empty(), "{:?}", remote.writes);
    let pvr: Vec<&str> = security_lines(&applied)
        .into_iter()
        .filter(|l| l.contains("private-vulnerability-reporting"))
        .collect();
    assert_eq!(pvr.len(), 1, "{pvr:?}");
    assert!(
        pvr[0].starts_with(
            "REMOTE github:private-vulnerability-reporting [security] not-applicable — "
        ),
        "{pvr:?}"
    );
    assert_eq!(applied.closing, "No remote changes.");
}

/// #1136 (the owner's first `apply --remote` on a private repository): GitHub
/// answered the PATCH with 422 "Secret scanning is not available for this
/// repository." Now neither secret scanning nor private vulnerability
/// reporting is attempted there; both are `not-applicable` and nothing stays
/// pending.
#[test]
fn on_a_private_repository_secret_scanning_is_not_applicable_and_never_written() {
    let (_temp, root) = installed();
    let remote = Remote {
        visibility: "private",
        ..Remote::new("disabled", "disabled", None)
    };
    let applied = run(&root, &remote);
    assert!(remote.writes.borrow().is_empty(), "{:?}", remote.writes);
    assert_eq!(
        security_lines(&applied),
        [
            "REMOTE github:private-vulnerability-reporting [security] not-applicable — private vulnerability reporting of example-owner/example was not found (404: Not Found)",
            "REMOTE github:secret-scanning [security] not-applicable — secret scanning disabled, push protection disabled; a private repository needs Secret Protection (Team or Enterprise), which the installer never assumes (risk secret-scanning-unavailable-on-plan)",
        ]
    );
    assert_eq!(applied.closing, "No remote changes.");
    assert!(applied.verified, "{applied:?}");
}

#[test]
fn hooks_installed_stays_a_local_manual_step() {
    let (_temp, root) = installed();
    let remote = Remote::new("enabled", "enabled", Some(true));
    let github = GitHub::new(&remote, CallBudget::new(100));
    let reader = HostRunner::new(&github, RepoId::parse("example-owner/example").unwrap());
    let profile = profile_for(&root).unwrap();
    let lock = Lock::parse(
        &fs::read_to_string(root.join(LOCK)).unwrap(),
        modules::core_version(),
        &|_| true,
    )
    .unwrap();
    let steps: Vec<StepReport> = engine::steps(
        &root,
        &Source::embedded(),
        &profile,
        &modules(),
        &lock,
        &reader,
    )
    .unwrap();
    let hooks = steps
        .iter()
        .find(|s| s.module == SECURITY && s.id == "hooks-installed")
        .unwrap();
    // Read from the clone (no hook file): pending; its declaration is pinned by
    // tests/security_manual.rs.
    assert_eq!(hooks.state, StepState::Pending, "{hooks:?}");
    let diff = remote_plan(&root, &Source::embedded(), &modules(), &reader).unwrap();
    assert!(!diff.iter().any(|l| l.item.contains("hooks-installed")));
}
