//! The merge-guard doctor rule (SPEC-merge-guard.md, #693): the registration
//! warning, and with `--remote` the mode line with the server's evidence, read
//! through a fake `Api` shaped as the five rows of the 2026-10-28 evidence table.
use brakes::guard::Mode;
use brakes::guard::doctor::{UNREGISTERED, mode_line, registration};
use brakes::guard::protection::{Kind, Protection, mode_for};
use brakes::remote::{Api, HttpError};
use brakes::{Result, diagnose};
use serde_json::{Value, json};
use std::{cell::RefCell, collections::BTreeMap, fs, path::Path};
use tempfile::TempDir;

const REPO: &str = "example-owner/example";
const BASE: &str = "repos/example-owner/example";
const PLAN: &str = "Upgrade to GitHub Pro or make this repository public to enable this feature.";

/// Answers each GET from a table; `{"status": "403", "message": …}` is an HTTP error.
struct Fake {
    responses: BTreeMap<String, Value>,
    calls: RefCell<Vec<String>>,
}
impl Api for Fake {
    fn get(&self, path: &str) -> Result<Value> {
        self.calls.borrow_mut().push(path.to_owned());
        let value = self
            .responses
            .get(path)
            .cloned()
            .ok_or_else(|| format!("unexpected GET {path}"))?;
        if let Some(status) = value["status"].as_str() {
            return Err(HttpError {
                status: status.parse().unwrap(),
                message: value["message"].as_str().unwrap().to_owned(),
            }
            .into());
        }
        Ok(value)
    }
}

fn fake(rules: Value, protection: Value, extra: &[(&str, Value)]) -> Fake {
    let mut responses = BTreeMap::from([
        (BASE.to_owned(), json!({"default_branch": "main"})),
        (format!("{BASE}/rules/branches/main"), rules),
        (format!("{BASE}/branches/main/protection"), protection),
    ]);
    for (path, value) in extra {
        responses.insert(format!("{BASE}/{path}"), value.clone());
    }
    Fake {
        responses,
        calls: RefCell::new(Vec::new()),
    }
}

fn classic(contexts: &[&str], admins: bool) -> Value {
    json!({"required_status_checks": {"contexts": contexts, "checks": []},
        "enforce_admins": {"enabled": admins}})
}

fn ruleset_rule(id: u64, context: &str) -> Value {
    json!([{"type": "required_status_checks", "ruleset_id": id,
        "ruleset_source_type": "Repository", "ruleset_source": REPO,
        "parameters": {"required_status_checks": [{"context": context}],
            "strict_required_status_checks_policy": false}}])
}

fn ruleset(bypass: Value) -> Value {
    json!({"id": 7, "enforcement": "active", "bypass_actors": bypass})
}

fn line(mode_and_evidence: &str) -> String {
    format!("Merge guard for {REPO}: {mode_and_evidence}")
}

#[test]
fn doctor_reports_hook_registration_and_mode() {
    let not_protected = json!({"status": "404", "message": "Branch not protected"});
    let forbidden = json!({"status": "403", "message": PLAN});
    let rows = [
        // Classic protection, admins enforced.
        (
            fake(json!([]), classic(&["all-checks-passed"], true), &[]),
            "light — classic protection, required: all-checks-passed, admins enforced",
        ),
        // Classic protection, admins not enforced.
        (
            fake(json!([]), classic(&["verify"], false), &[]),
            "full — required: verify, admins not enforced (an admin can merge on red; ask the owner to enforce)",
        ),
        // A Free organization's private repository.
        (
            fake(forbidden.clone(), forbidden, &[]),
            "full — no server-side protection (HTTP 403: plan does not allow it on a private repository); the hook is the only barrier",
        ),
        // repo-baseline's target: an active ruleset without bypass actors.
        (
            fake(
                ruleset_rule(7, "all-checks-passed"),
                not_protected.clone(),
                &[("rulesets/7", ruleset(json!([])))],
            ),
            "light — ruleset protection, required: all-checks-passed, no bypass actors",
        ),
        // The same ruleset with bypass actors: listed for the owner.
        (
            fake(
                ruleset_rule(7, "all-checks-passed"),
                not_protected,
                &[(
                    "rulesets/7",
                    ruleset(json!([
                        {"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"},
                        {"actor_id": null, "actor_type": "OrganizationAdmin", "bypass_mode": "pull_request"}
                    ])),
                )],
            ),
            "full — ruleset protection, required: all-checks-passed, bypass actors: RepositoryRole 5, OrganizationAdmin (they can merge on red; ask the owner to remove them)",
        ),
    ];
    for (api, expected) in rows {
        assert_eq!(mode_line(&api, REPO), line(expected));
        assert!(api.calls.borrow().iter().all(|c| c.starts_with(BASE)));
    }
}

#[test]
fn an_unprotected_branch_or_an_unreadable_server_is_full() {
    let not_protected = json!({"status": "404", "message": "Branch not protected"});
    let api = fake(json!([]), not_protected, &[]);
    assert_eq!(
        mode_line(&api, REPO),
        line(
            "full — no server-side protection (the default branch is not protected); the hook is the only barrier"
        )
    );
    // A 403 that does not name the plan is a token that cannot read, not evidence.
    let denied = json!({"status": "403", "message": "Resource not accessible by integration"});
    let api = fake(json!([]), denied, &[]);
    assert_eq!(
        mode_line(&api, REPO),
        line(
            "full — the server protection could not be read (GitHub read failed (HTTP 403)); treat the hook as the only barrier"
        )
    );
    // A ruleset whose bypass actors are not readable cannot be called protected.
    let api = fake(
        ruleset_rule(7, "verify"),
        classic(&[], true),
        &[("rulesets/7", json!({"id": 7, "enforcement": "active"}))],
    );
    assert!(mode_line(&api, REPO).contains(": full — the server protection could not be read"));
    // An outside repository is refused before any read.
    let api = fake(json!([]), classic(&["verify"], true), &[]);
    assert!(mode_line(&api, "example-corp/app").contains("could not be read"));
    assert!(api.calls.borrow().is_empty());
}

#[test]
fn mode_for_is_pure_over_the_protection() {
    let protection = |kind, required: &[&str], admins, bypass: &[&str]| Protection {
        kind,
        required: required.iter().map(|s| s.to_string()).collect(),
        admins_enforced: admins,
        bypass_actors: bypass.iter().map(|s| s.to_string()).collect(),
        plan_forbids: false,
    };
    assert_eq!(
        mode_for(&protection(Kind::Classic, &["verify"], true, &[])),
        Mode::Light
    );
    assert_eq!(
        mode_for(&protection(Kind::Classic, &["verify"], false, &[])),
        Mode::Full
    );
    assert_eq!(
        mode_for(&protection(Kind::Classic, &[], true, &[])),
        Mode::Full
    );
    assert_eq!(
        mode_for(&protection(Kind::Ruleset, &["verify"], false, &[])),
        Mode::Light
    );
    assert_eq!(
        mode_for(&protection(Kind::Ruleset, &["verify"], false, &["Team 1"])),
        Mode::Full
    );
    assert_eq!(
        mode_for(&protection(Kind::Ruleset, &[], false, &[])),
        Mode::Full
    );
    assert_eq!(
        mode_for(&protection(Kind::None, &["verify"], true, &[])),
        Mode::Full
    );
}

fn write(root: &Path, name: &str, text: &str) {
    let path = root.join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

#[test]
fn registration_warning_follows_the_pre_tool_use_entry() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    // Without the hook there is nothing to register.
    assert_eq!(registration(root).unwrap(), None);
    write(root, ".claude/hooks/merge_guard.sh", "#!/bin/sh\n");
    assert_eq!(registration(root).unwrap().as_deref(), Some(UNREGISTERED));
    // Registered for another event, or unparseable: still not registered.
    let elsewhere = json!({"hooks": {"Stop": [{"hooks": [{"type": "command",
        "command": "sh .claude/hooks/merge_guard.sh"}]}]}});
    write(root, ".claude/settings.json", &elsewhere.to_string());
    assert_eq!(registration(root).unwrap().as_deref(), Some(UNREGISTERED));
    write(root, ".claude/settings.json", "{not json");
    assert_eq!(registration(root).unwrap().as_deref(), Some(UNREGISTERED));
    let registered = json!({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{
        "type": "command", "command": "sh \"$CLAUDE_PROJECT_DIR/.claude/hooks/merge_guard.sh\"",
        "timeout": 60, "onFailure": "block"}]}]}});
    write(root, ".claude/settings.json", &registered.to_string());
    assert_eq!(registration(root).unwrap(), None);
}

#[test]
fn the_registration_warning_never_makes_doctor_not_ready() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    write(root, ".claude/hooks/merge_guard.sh", "#!/bin/sh\n");
    let diagnosis = diagnose(root).unwrap();
    assert!(diagnosis.findings.iter().any(|f| f == UNREGISTERED));
    assert!(
        diagnosis
            .printed_findings()
            .iter()
            .any(|f| f == UNREGISTERED),
        "printed as a WARNING, not behind NOT READY"
    );
    let others = brakes::Diagnosis {
        findings: vec![UNREGISTERED.to_owned()],
        steps: Vec::new(),
        modules: Vec::new(),
        excluded: Vec::new(),
    };
    assert!(others.ready());
}

// The module (#696): the hook is `managed` content of merge-guard, moved out of
// setup-core with a lock-only ownership transfer; registration is a probed
// manual step; `doctor --json` carries the rule object.

const HOOK: &str = ".claude/hooks/merge_guard.sh";
const MERGE_GUARD: &str = "merge-guard";

struct Repo {
    _temp: TempDir,
    root: std::path::PathBuf,
}
impl Repo {
    /// A personal checkout installed from the embedded source.
    fn new() -> Self {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("project");
        fs::create_dir(&root).unwrap();
        assert!(
            std::process::Command::new("git")
                .args(["init", "-q"])
                .arg(&root)
                .status()
                .unwrap()
                .success()
        );
        let repo = Self { _temp: temp, root };
        repo.ok(&["install", "<repo>", "--new-personal", "--apply"]);
        repo
    }
    fn cli(&self, args: &[&str]) -> std::process::Output {
        let root = self.root.to_string_lossy().into_owned();
        std::process::Command::new(env!("CARGO_BIN_EXE_brakes"))
            .args(
                args.iter()
                    .map(|a| if *a == "<repo>" { root.as_str() } else { a }),
            )
            .output()
            .unwrap()
    }
    fn ok(&self, args: &[&str]) -> String {
        let out = self.cli(args);
        assert!(out.status.success(), "{args:?}: {out:?}");
        String::from_utf8(out.stdout).unwrap()
    }
    fn lock(&self) -> Value {
        serde_json::from_str(&fs::read_to_string(self.root.join(".agent-setup/lock.json")).unwrap())
            .unwrap()
    }
    fn write_lock(&self, lock: &Value) {
        write(
            &self.root,
            ".agent-setup/lock.json",
            &(serde_json::to_string_pretty(lock).unwrap() + "\n"),
        );
    }
    /// The lock as the installer wrote it before #696: the hook under setup-core
    /// 1.1.0, no merge-guard entry.
    fn lock_before_the_module(&self) -> Value {
        let mut lock = self.lock();
        lock["files"][HOOK]["module"] = json!("setup-core");
        lock["modules"]["setup-core"]["version"] = json!("1.1.0");
        lock["modules"].as_object_mut().unwrap().remove(MERGE_GUARD);
        lock
    }
    fn lines(&self, args: &[&str]) -> Vec<String> {
        self.ok(args).lines().map(str::to_owned).collect()
    }
    /// `doctor`'s lines, whatever its exit code (an unconfigured profile is not ready).
    fn doctor(&self) -> Vec<String> {
        String::from_utf8(self.cli(&["doctor", "<repo>"]).stdout)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

/// The plan's change lines (writes and deletes), without steps and notes.
fn changes(lines: &[String]) -> Vec<&str> {
    lines
        .iter()
        .filter(|l| l.starts_with("PLAN ") || l.starts_with("WRITE ") || l.starts_with("DELETE "))
        .map(String::as_str)
        .collect()
}

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "lists setup-core or its guides; product-boundary T7a"
)]
#[test]
fn a_fresh_install_records_the_hook_under_merge_guard() {
    let repo = Repo::new();
    let lock = repo.lock();
    assert_eq!(lock["files"][HOOK]["module"], json!(MERGE_GUARD));
    assert_eq!(lock["files"][HOOK]["class"], json!("managed"));
    assert!(lock["modules"][MERGE_GUARD]["version"].is_string());
    let versioned = include_str!("../../../.claude/hooks/merge_guard.sh");
    assert_eq!(fs::read_to_string(repo.root.join(HOOK)).unwrap(), versioned);
    // Registration stays the project's: nothing writes .claude/settings.json.
    assert!(!repo.root.join(".claude/settings.json").exists());
    assert_eq!(
        repo.lines(&["install", "<repo>"]).last().unwrap(),
        "No changes."
    );
}

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "lists setup-core or its guides; product-boundary T7a"
)]
#[test]
fn a_schema_2_lock_with_the_hook_under_setup_core_transfers_only_the_lock() {
    let repo = Repo::new();
    let after = fs::read_to_string(repo.root.join(".agent-setup/lock.json")).unwrap();
    repo.write_lock(&repo.lock_before_the_module());
    let hook = fs::read_to_string(repo.root.join(HOOK)).unwrap();
    let plan = repo.lines(&["install", "<repo>"]);
    assert_eq!(changes(&plan), ["PLAN .agent-setup/lock.json"], "{plan:?}");
    let applied = repo.lines(&["install", "<repo>", "--apply"]);
    assert_eq!(changes(&applied), ["WRITE .agent-setup/lock.json"]);
    assert_eq!(fs::read_to_string(repo.root.join(HOOK)).unwrap(), hook);
    assert_eq!(
        fs::read_to_string(repo.root.join(".agent-setup/lock.json")).unwrap(),
        after,
        "the transferred lock is the one a fresh install writes"
    );
    let again = repo.lines(&["install", "<repo>"]);
    assert!(changes(&again).is_empty(), "{again:?}");
    assert_eq!(again.last().unwrap(), "No changes.");
}

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "lists setup-core or its guides; product-boundary T7a"
)]
#[test]
fn a_schema_1_lock_with_the_hook_transfers_only_the_lock() {
    let repo = Repo::new();
    let lock = repo.lock_before_the_module();
    let files: serde_json::Map<String, Value> = lock["files"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(path, entry)| (path.clone(), entry["digest"].clone()))
        .collect();
    let v1 = json!({"schema": 1, "version": lock["version"], "source_commit": lock["source_commit"],
        "source_dirty": lock["source_dirty"], "personal_owner": lock["personal_owner"], "files": files});
    repo.write_lock(&v1);
    let plan = repo.lines(&["install", "<repo>", "--apply"]);
    assert_eq!(changes(&plan), ["WRITE .agent-setup/lock.json"], "{plan:?}");
    assert_eq!(repo.lock()["files"][HOOK]["module"], json!(MERGE_GUARD));
    assert_eq!(
        repo.lines(&["install", "<repo>"]).last().unwrap(),
        "No changes."
    );
}

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "lists setup-core or its guides; product-boundary T7a"
)]
#[test]
fn a_locally_changed_hook_still_refuses_across_the_transfer() {
    let repo = Repo::new();
    repo.write_lock(&repo.lock_before_the_module());
    write(&repo.root, HOOK, "#!/bin/sh\nexit 0\n");
    let out = repo.cli(&["install", "<repo>"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("Locally changed or missing managed content: .claude/hooks/merge_guard.sh"),
        "{out:?}"
    );
}

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "lists setup-core or its guides; product-boundary T7a"
)]
#[test]
fn a_removed_merge_guard_stays_removed() {
    let repo = Repo::new();
    repo.ok(&["remove", "<repo>", MERGE_GUARD, "--apply"]);
    assert!(!repo.root.join(HOOK).exists());
    let again = repo.lines(&["install", "<repo>"]);
    assert_eq!(again.last().unwrap(), "No changes.", "{again:?}");
    let doctor = repo.doctor().join("\n");
    assert!(!doctor.contains(HOOK), "{doctor}");
    assert!(!doctor.contains(":merge-guard]"), "{doctor}");
    // Asked for again, it comes back.
    repo.ok(&["install", "<repo>", "--module", MERGE_GUARD, "--apply"]);
    assert!(repo.root.join(HOOK).is_file());
}

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "lists setup-core or its guides; product-boundary T7a"
)]
#[test]
fn doctor_lists_the_registration_step_pending_then_verified() {
    let repo = Repo::new();
    let doctor = repo.doctor();
    assert!(
        doctor.contains(
            &"STEP [pending:merge-guard] hook-registered — .claude/settings.json is absent"
                .to_owned()
        ),
        "{doctor:?}"
    );
    // T5's line is unchanged.
    assert!(doctor.contains(&UNREGISTERED.to_owned()), "{doctor:?}");
    let registered = json!({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{
        "type": "command", "command": "sh \"$CLAUDE_PROJECT_DIR/.claude/hooks/merge_guard.sh\"",
        "timeout": 60, "onFailure": "block"}]}]}});
    write(&repo.root, ".claude/settings.json", &registered.to_string());
    let doctor = repo.doctor();
    assert!(
        doctor.contains(&"STEP [verified:merge-guard] hook-registered — .claude/settings.json: /hooks/PreToolUse names merge_guard.sh".to_owned()),
        "{doctor:?}"
    );
    assert!(!doctor.contains(&UNREGISTERED.to_owned()), "{doctor:?}");
    // The plan lists the step too, and it never becomes a change.
    let plan = repo.lines(&["install", "<repo>"]);
    assert!(
        plan.iter()
            .any(|l| l.starts_with("STEP [verified:merge-guard] hook-registered")),
        "{plan:?}"
    );
    assert_eq!(plan.last().unwrap(), "No changes.");
}

fn golden(name: &str, actual: &str) {
    let path = format!(
        "{}/tests/golden/merge-guard/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    if std::env::var_os("UPDATE_GOLDENS").is_some() {
        fs::create_dir_all(Path::new(&path).parent().unwrap()).unwrap();
        fs::write(&path, actual).unwrap();
    }
    let expected = fs::read_to_string(&path).unwrap();
    assert_eq!(actual, expected, "{path} drifted; actual:\n{actual}");
}

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "lists setup-core or its guides; product-boundary T7a"
)]
#[test]
fn doctor_json_carries_the_local_rule_object() {
    let repo = Repo::new();
    let out = repo.cli(&["doctor", "<repo>", "--json", "--now", "2026-10-29"]);
    let document: Value = serde_json::from_slice(&out.stdout).unwrap();
    let rule = serde_json::to_string_pretty(&document["merge_guard"]).unwrap() + "\n";
    golden("doctor-local.json", &rule);
    let steps: Vec<&Value> = document["steps"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|s| s["module"] == MERGE_GUARD)
        .collect();
    assert_eq!(steps.len(), 1);
    assert_eq!(steps[0]["id"], json!("hook-registered"));
    assert_eq!(steps[0]["owner"], json!("project"));
    // A changed hook is reported as such.
    write(&repo.root, HOOK, "#!/bin/sh\n");
    let out = repo.cli(&["doctor", "<repo>", "--json", "--now", "2026-10-29"]);
    let document: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        document["merge_guard"]["hook"],
        json!({"present": true, "unchanged": false, "registered": false})
    );
}

#[test]
fn the_remote_rule_object_matches_the_golden() {
    use brakes::guard::doctor::{probe, rule};
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    write(root, HOOK, "#!/bin/sh\n");
    let lock = json!({"files": {HOOK: {"module": MERGE_GUARD, "class": "managed",
        "digest": brakes::digest("#!/bin/sh\n")}}});
    write(root, ".agent-setup/lock.json", &lock.to_string());
    let probed_at = "2026-10-28T10:12:00Z";
    let rows = [
        fake(json!([]), classic(&["all-checks-passed"], true), &[]),
        fake(
            json!({"status": "403", "message": PLAN}),
            json!({"status": "403", "message": PLAN}),
            &[],
        ),
        fake(
            ruleset_rule(7, "all-checks-passed"),
            json!({"status": "404", "message": "Branch not protected"}),
            &[(
                "rulesets/7",
                ruleset(
                    json!([{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}]),
                ),
            )],
        ),
        fake(
            json!([]),
            json!({"status": "403", "message": "Resource not accessible by integration"}),
            &[],
        ),
    ];
    let objects: Vec<Value> = rows
        .iter()
        .map(|api| rule(root, Some(REPO), Some((&probe(api, REPO), probed_at))).unwrap())
        .collect();
    golden(
        "doctor-remote.json",
        &(serde_json::to_string_pretty(&objects).unwrap() + "\n"),
    );
}
