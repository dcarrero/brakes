//! Behavioral port of tests/test_setup.py; real Git and filesystem boundaries.
// Names setup-core (its module, guides or version): runs with the feature only (product-boundary T7a).
#![cfg(feature = "setup-core")]
use brakes::*;
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::TempDir;

mod configured;
use configured::{capitalised, denied};

struct Fixture {
    _temp: TempDir,
    root: PathBuf,
    source_root: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("project");
        let source_root = temp.path().join("source");
        fs::create_dir(&root).unwrap();
        assert!(
            Command::new("git")
                .args(["init", "-q"])
                .arg(&root)
                .status()
                .unwrap()
                .success()
        );
        fs::create_dir_all(source_root.join("templates")).unwrap();
        fs::write(source_root.join("VERSION"), "0.1.0\n").unwrap();
        for (name, _) in DOCUMENTS {
            let today = today().format("%Y-%m-%d");
            fs::write(
                source_root.join("templates").join(name),
                format!("# Guide\n\nLast verified: {today}\n\ncommon\n"),
            )
            .unwrap();
        }
        for (name, _) in HOOKS {
            let path = source_root.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, "#!/bin/sh\n").unwrap();
        }
        Self {
            _temp: temp,
            root,
            source_root,
        }
    }
    fn source(&self) -> Source {
        Source::checkout(&self.source_root).unwrap()
    }
    fn apply(&self) {
        apply(&self.root, &plan(&self.root, &self.source()).unwrap()).unwrap();
    }
    fn write(&self, name: &str, text: &str) {
        let path = self.root.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
    fn read(&self, name: &str) -> String {
        fs::read_to_string(self.root.join(name)).unwrap()
    }
    fn value(&self, name: &str) -> Value {
        serde_json::from_str(&self.read(name)).unwrap()
    }
    fn write_value(&self, name: &str, value: &Value) {
        self.write(name, &serde_json::to_string(value).unwrap());
    }
    fn git(&self, args: &[&str]) {
        scope::git(&self.root, args).unwrap();
    }
    fn remote(&self, url: &str) {
        self.git(&["remote", "add", "origin", url]);
    }
    fn refused(&self) {
        assert!(personal_scope(&self.root, true).is_err());
        assert!(!self.root.join(PROFILE).exists());
    }
}

#[test]
fn new_repo_requires_explicit_personal_declaration() {
    let f = Fixture::new();
    assert!(personal_scope(&f.root, false).is_err());
    assert_eq!(
        personal_scope(&f.root, true).unwrap(),
        f.root.canonicalize().unwrap()
    );
    f.apply();
    assert!(personal_scope(&f.root, false).is_ok());
}

#[test]
fn personal_https_and_ssh_remotes() {
    for url in [
        "https://github.com/example-owner/example.git",
        "git@github.com:example-owner/example.git",
        "ssh://git@github.com/example-owner/example.git",
    ] {
        let f = Fixture::new();
        f.remote(url);
        assert_eq!(
            personal_scope(&f.root, false).unwrap(),
            f.root.canonicalize().unwrap()
        );
    }
}
#[test]
fn authorized_personal_organization_repositories() {
    for repo in ["example-org/example-app", "example-org/other-app"] {
        let f = Fixture::new();
        f.remote(&format!("git@github.com:{repo}.git"));
        assert!(personal_scope(&f.root, false).is_ok());
    }
}
#[test]
fn corporate_scope_and_unapproved_organizations_refused_even_with_declaration() {
    let word = denied();
    for repo in [
        format!("{word}/example"),
        format!("example-owner/{word}-user-story-toolkit"),
        "outside-org/other".to_owned(),
        "outside-team/other".to_owned(),
    ] {
        let f = Fixture::new();
        f.remote(&format!("https://github.com/{repo}.git"));
        f.refused();
    }
}
#[test]
fn personal_origin_does_not_allow_corporate_upstream() {
    let f = Fixture::new();
    f.remote("https://github.com/example-owner/example.git");
    f.git(&[
        "remote",
        "add",
        "upstream",
        &format!("https://github.com/{}/example.git", denied()),
    ]);
    f.refused();
}
#[test]
fn corporate_and_unapproved_push_urls_refused() {
    for url in [
        format!("https://github.com/{}/example.git", denied()),
        "https://github.com/outside-org/other.git".to_owned(),
    ] {
        let f = Fixture::new();
        f.remote("https://github.com/example-org/example-app.git");
        f.git(&["remote", "set-url", "--push", "origin", &url]);
        f.refused();
    }
}
#[test]
fn personal_owner_does_not_make_corporate_workspace_personal() {
    let f = Fixture::new();
    let corporate = f
        .root
        .parent()
        .unwrap()
        .join(format!("Claude-{}-Tech-Strategy", capitalised(&denied())));
    fs::rename(&f.root, &corporate).unwrap();
    assert!(personal_scope(&corporate, true).is_err());
}
#[test]
fn nested_repository_refused() {
    let f = Fixture::new();
    let child = f.root.join("child");
    fs::create_dir(&child).unwrap();
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .arg(&child)
            .status()
            .unwrap()
            .success()
    );
    assert!(personal_scope(&child, true).is_err());
}
#[test]
fn host_spoofing_and_local_remotes_refused() {
    for url in [
        "https://github.com.evil/example-owner/example.git",
        "/tmp/example-owner/example.git",
        "file://github.com/example-owner/example.git",
    ] {
        let f = Fixture::new();
        f.remote(url);
        f.refused();
    }
}
#[test]
fn dry_plan_writes_nothing() {
    let f = Fixture::new();
    assert!(!plan(&f.root, &f.source()).unwrap().is_empty());
    assert_eq!(fs::read_dir(&f.root).unwrap().count(), 1);
}
#[test]
fn existing_instructions_and_profile_preserved() {
    let f = Fixture::new();
    f.write("AGENTS.md", "Project-specific policy\n");
    f.write("CLAUDE.md", "Existing Claude notes\n");
    f.apply();
    assert!(f.read("AGENTS.md").starts_with("Project-specific policy"));
    assert!(f.read("CLAUDE.md").starts_with("Existing Claude notes"));
    let raw = f.read(PROFILE);
    f.apply();
    assert_eq!(f.read(PROFILE), raw);
}
#[test]
fn idempotent_installation() {
    let f = Fixture::new();
    f.apply();
    assert!(plan(&f.root, &f.source()).unwrap().is_empty());
}
/// The fixture's source at `revision`, clean or dirty (#1322).
fn source_at(f: &Fixture, revision: Option<&str>, dirty: bool) -> Source {
    Source {
        revision: revision.map(str::to_owned),
        dirty,
        ..f.source()
    }
}
fn apply_from(f: &Fixture, source: &Source) {
    apply(&f.root, &plan(&f.root, source).unwrap()).unwrap();
}
#[test]
fn a_clean_record_stays_when_only_the_source_commit_moves() {
    let f = Fixture::new();
    apply_from(&f, &source_at(&f, Some("aaa"), false));
    let installed = f.read(LOCK);
    for later in [
        source_at(&f, Some("bbb"), false),
        source_at(&f, Some("bbb"), true),
        source_at(&f, None, false),
    ] {
        assert!(plan(&f.root, &later).unwrap().is_empty());
    }
    assert_eq!(f.read(LOCK), installed);
    assert_eq!(f.value(LOCK)["source_commit"], "aaa");
}
#[test]
fn a_dirty_or_commitless_record_is_replaced_by_a_clean_run() {
    for (revision, dirty) in [(Some("aaa"), true), (None, false)] {
        let f = Fixture::new();
        apply_from(&f, &source_at(&f, revision, dirty));
        let clean = source_at(&f, Some("bbb"), false);
        let changes = plan(&f.root, &clean).unwrap();
        assert_eq!(changes.keys().collect::<Vec<_>>(), [LOCK]);
        apply_from(&f, &clean);
        let lock = f.value(LOCK);
        assert_eq!(lock["source_commit"], "bbb");
        assert_eq!(lock["source_dirty"], false);
    }
}
#[test]
fn provenance_moves_with_the_recorded_content() {
    let f = Fixture::new();
    apply_from(&f, &source_at(&f, Some("aaa"), false));
    let (name, _) = DOCUMENTS[0];
    let today = today().format("%Y-%m-%d");
    fs::write(
        f.source_root.join("templates").join(name),
        format!("# Guide\n\nLast verified: {today}\n\nchanged\n"),
    )
    .unwrap();
    apply_from(&f, &source_at(&f, Some("bbb"), true));
    let lock = f.value(LOCK);
    assert_eq!(lock["source_commit"], "bbb");
    assert_eq!(lock["source_dirty"], true);
}
#[test]
fn profile_accepts_deploy_verification_keys_and_declared_lint() {
    let f = Fixture::new();
    let mut profile = default_profile();
    assert!(profile["commands"].get("verify_deploy").is_some());
    assert!(profile["commands"].get("deploy_status").is_some());
    assert_eq!(profile["deploy_environments"], json!([]));
    assert_eq!(profile["environment_manifests"], json!({}));
    profile["commands"]["verify_deploy"] = json!("./scripts/verify-deploy");
    profile["commands"]["deploy_status"] = json!("./scripts/deploy-status");
    profile["commands"]["lint"] = json!(
        "git diff --check && cargo fmt --all --manifest-path orchestration/Cargo.toml -- --check && cargo clippy --manifest-path orchestration/Cargo.toml --locked --all-targets -- -D warnings"
    );
    profile["deploy_environments"] = json!(["production"]);
    profile["environment_manifests"] = json!({"production": ".env.production.manifest"});
    f.write_value(PROFILE, &profile);
    assert_eq!(profile_for(&f.root).unwrap().value, profile);
}

#[test]
fn planning_has_no_profile_field_and_a_leftover_one_is_reported_not_rewritten() {
    let f = Fixture::new();
    assert!(default_profile().get("planning").is_none());
    f.apply();
    let agents = f.read("AGENTS.md");
    assert!(agents.contains(
        "A handoff that spans sessions is a comment on the task in the project's tracker"
    ));
    assert!(!agents.contains("Plans live in"));
    assert!(!agents.contains("Agent Skills") && !agents.contains("GitHub Issues"));
    assert!(
        doctor(&f.root)
            .unwrap()
            .iter()
            .all(|s| !s.contains("planning"))
    );
    for planning in [
        json!({"plans_dir": "tasks", "max_active_milestones": 2}),
        json!("anything"),
    ] {
        let mut profile = default_profile();
        profile["planning"] = planning.clone();
        f.write_value(PROFILE, &profile);
        let raw = f.read(PROFILE);
        assert!(plan(&f.root, &f.source()).unwrap().is_empty(), "{planning}");
        assert_eq!(f.read(PROFILE), raw);
        assert!(
            doctor(&f.root)
                .unwrap()
                .iter()
                .any(|s| s.starts_with("Obsolete profile field: planning")),
            "{planning}"
        );
    }
}

#[test]
fn invalid_profiles_refused() {
    let f = Fixture::new();
    for (pointer, invalid) in [
        (
            "/commands/verify_deploy",
            json!("./scripts/verify-deploy\nextra"),
        ),
        ("/commands/lint", json!("  ")),
        ("/commands", json!([])),
        ("/purpose", json!(12)),
        ("/conventions", json!([12])),
        ("/deploy_environments", json!("production")),
        ("/deploy_environments", json!(["production", "production"])),
        ("/deploy_environments", json!(["prod\nuction"])),
        (
            "/environment_manifests",
            json!({"staging": ".env.staging.manifest"}),
        ),
        ("/acceptance", json!([])),
        ("/acceptance/scenarios_dir", json!(" ")),
    ] {
        let mut profile = default_profile();
        *profile.pointer_mut(pointer).unwrap() = invalid;
        f.write_value(PROFILE, &profile);
        assert!(profile_for(&f.root).is_err(), "{pointer}");
    }
}
#[test]
fn update_preserves_local_text_and_refreshes_common_documents() {
    let f = Fixture::new();
    f.apply();
    f.write("AGENTS.md", &(f.read("AGENTS.md") + "\nLocal addition\n"));
    fs::write(f.source_root.join("templates/principles.md"), "updated\n").unwrap();
    fs::write(f.source_root.join("VERSION"), "0.2.0\n").unwrap();
    f.apply();
    assert!(f.read("AGENTS.md").contains("Local addition"));
    assert_eq!(f.read("docs/agent-setup/principles.md"), "updated\n");
}
#[test]
fn managed_edit_and_deletion_refuse_entire_update() {
    for delete in [false, true] {
        let f = Fixture::new();
        f.apply();
        let original_lock = f.read(LOCK);
        if delete {
            fs::remove_file(f.root.join("CLAUDE.md")).unwrap();
        } else {
            f.write("docs/agent-setup/principles.md", "local change\n");
        }
        assert!(plan(&f.root, &f.source()).is_err());
        assert_eq!(f.read(LOCK), original_lock);
        if !delete {
            assert_eq!(f.read("docs/agent-setup/principles.md"), "local change\n");
        }
    }
}
#[cfg(unix)]
#[test]
fn symlink_refused_before_writes() {
    use std::os::unix::fs::symlink;
    let f = Fixture::new();
    let outside = f.root.parent().unwrap().join("outside");
    fs::create_dir(&outside).unwrap();
    symlink(&outside, f.root.join("docs")).unwrap();
    assert!(plan(&f.root, &f.source()).is_err());
    assert_eq!(fs::read_dir(outside).unwrap().count(), 0);
    let root_link = f.root.parent().unwrap().join("linked");
    symlink(&f.root, &root_link).unwrap();
    assert!(personal_scope(&root_link, true).is_err());
}
#[test]
fn unsafe_references_refused() {
    let f = Fixture::new();
    f.apply();
    let mut profile = f.value(PROFILE);
    profile["conventions"] = json!(["../outside.md"]);
    f.write_value(PROFILE, &profile);
    assert!(plan(&f.root, &f.source()).is_err());
    profile["conventions"] = json!([]);
    profile["deploy_environments"] = json!(["production"]);
    profile["environment_manifests"] = json!({"production": "../outside"});
    f.write_value(PROFILE, &profile);
    assert!(profile_for(&f.root).is_err());
}
#[test]
fn incomplete_configuration_is_not_ready() {
    let f = Fixture::new();
    f.apply();
    let issues = doctor(&f.root).unwrap();
    assert!(issues.contains(&"Verification command missing".to_owned()));
    assert!(issues.contains(&"Project purpose missing".to_owned()));
}
#[test]
fn profile_change_refreshes_entrypoint_without_running_command() {
    let f = Fixture::new();
    f.apply();
    let mut profile = f.value(PROFILE);
    profile["purpose"] = json!("Example");
    profile["commands"]["verify"] = json!("never-execute-this-command");
    f.write_value(PROFILE, &profile);
    assert!(
        doctor(&f.root)
            .unwrap()
            .iter()
            .any(|s| s.contains("Entrypoint"))
    );
    f.apply();
    assert!(f.read("AGENTS.md").contains("never-execute-this-command"));
}
#[test]
fn replacing_retired_commands_regenerates_only_the_managed_instructions() {
    let f = Fixture::new();
    let mut profile = default_profile();
    profile["purpose"] = json!("Command refresh regression");
    profile["commands"]["verify"] = json!("python3 -I scripts/retired-check.py");
    profile["commands"]["test"] = json!("python3 -I scripts/retired-check.py");
    f.write_value(PROFILE, &profile);
    f.apply();
    let before = format!("Local policy\n{}\nLocal notes\n", f.read("AGENTS.md"));
    f.write("AGENTS.md", &before);
    profile["commands"]["verify"] = json!("bash scripts/check.sh");
    profile["commands"]["test"] = json!("bash scripts/check.sh");
    f.write_value(PROFILE, &profile);
    let raw_profile = f.read(PROFILE);
    assert!(
        doctor(&f.root)
            .unwrap()
            .contains(&"Entrypoint does not reflect project profile: AGENTS.md".to_owned())
    );
    let changes = plan(&f.root, &f.source()).unwrap();
    assert_eq!(f.read("AGENTS.md"), before, "planning must not write");
    apply(&f.root, &changes).unwrap();
    let agents = f.read("AGENTS.md");
    assert!(agents.starts_with("Local policy\n"));
    assert!(agents.ends_with("\nLocal notes\n"));
    assert!(agents.contains("- verify: `bash scripts/check.sh`"));
    assert!(agents.contains("- test: `bash scripts/check.sh`"));
    assert!(!agents.contains("retired-check.py"));
    assert_eq!(f.read(PROFILE), raw_profile);
    assert!(plan(&f.root, &f.source()).unwrap().is_empty());
    assert!(
        doctor(&f.root)
            .unwrap()
            .iter()
            .all(|s| !s.contains("Entrypoint"))
    );
}

#[test]
fn command_order_matches_python_rendering_and_legacy_defaults_do_not_rewrite_profile() {
    let f = Fixture::new();
    f.write(PROFILE, "{\"purpose\":\"Example\",\"commands\":{\"verify\":\"check\",\"test\":\"test\",\"lint\":\"lint\"},\"conventions\":[],\"generated_paths\":[],\"environment_notes\":[]}");
    let raw = f.read(PROFILE);
    f.apply();
    assert_eq!(f.read(PROFILE), raw);
    assert!(
        f.read("AGENTS.md")
            .contains("- verify: `check`\n- test: `test`\n- lint: `lint`")
    );
    assert!(plan(&f.root, &f.source()).unwrap().is_empty());
}
#[test]
fn new_install_routes_official_workflow_and_preserves_neutral_profile() {
    let f = Fixture::new();
    f.apply();
    assert!(f.value(PROFILE).get("framework").is_none());
    assert_eq!(
        f.value(PROFILE)["ci"],
        json!({"required_checks": null, "shards": null, "tiers": null, "cycle_budget_minutes": null})
    );
    let instructions = f.read("AGENTS.md");
    assert!(instructions.contains("Choose and record the project's development workflow"));
    assert!(instructions.contains("docs/agent-setup/workflow.md"));
    assert!(!instructions.contains("Agent Skills") && !instructions.contains("GitHub Issues"));
    assert!(!instructions.contains("Superpowers") && !instructions.contains("Product Factory"));
    for (name, _) in DOCUMENTS {
        assert!(f.root.join("docs/agent-setup").join(name).is_file());
    }
}
#[test]
fn merge_guard_hook_is_distributed_pinned_and_not_registered() {
    let f = Fixture::new();
    // A project upgrading from a lock without the hook gets it on the next install.
    f.apply();
    let mut lock = f.value(LOCK);
    let name = ".claude/hooks/merge_guard.sh";
    lock["files"].as_object_mut().unwrap().remove(name);
    fs::remove_file(f.root.join(name)).unwrap();
    f.write_value(LOCK, &lock);
    assert!(doctor(&f.root).unwrap().iter().any(|i| i.ends_with(name)));
    f.apply();
    assert_eq!(f.read(name), "#!/bin/sh\n");
    assert_eq!(
        f.value(LOCK)["files"][name]["digest"],
        json!(digest("#!/bin/sh\n"))
    );
    // The registration in .claude/settings.json is the project's.
    assert!(!f.root.join(".claude/settings.json").exists());
    // The embedded copy is the one versioned in this repository.
    let versioned = include_str!("../../../.claude/hooks/merge_guard.sh");
    assert_eq!(Source::embedded().documents[name], versioned);
    assert!(versioned.starts_with("#!/bin/sh\n"));
}
#[test]
fn legacy_upgrade_preserves_project_choice_and_removes_managed_preference() {
    let f = Fixture::new();
    f.apply();
    let mut lock = f.value(LOCK);
    let files = lock["files"].as_object_mut().unwrap();
    let remove: Vec<_> = files
        .keys()
        .filter(|n| {
            n.starts_with("docs/agent-setup/")
                && !n.ends_with("principles.md")
                && !n.ends_with("task.md")
        })
        .cloned()
        .collect();
    for name in remove {
        fs::remove_file(f.root.join(&name)).unwrap();
        files.remove(&name);
    }
    lock["version"] = json!("0.1.0");
    let old = format!("{BEGIN}\nSuperpowers is the selected everyday framework.\n{END}");
    f.write("AGENTS.md", &format!("Local convention\n{old}\n"));
    lock["files"]["AGENTS.md"] =
        json!({"module": "setup-core", "class": "managed-block", "digest": digest(&old)});
    f.write_value(LOCK, &lock);
    let mut profile = f.value(PROFILE);
    profile["framework"] = json!({"name": "my-project-choice", "host_versions": {"host": "1"}});
    f.write_value(PROFILE, &profile);
    let raw_profile = f.read(PROFILE);
    assert!(
        doctor(&f.root)
            .unwrap()
            .iter()
            .any(|s| s.contains("Engineering guide not installed"))
    );
    f.apply();
    assert_eq!(f.read(PROFILE), raw_profile);
    assert!(f.read("AGENTS.md").contains("Local convention"));
    assert!(!f.read("AGENTS.md").contains("Superpowers"));
    assert!(
        !doctor(&f.root)
            .unwrap()
            .iter()
            .any(|s| s.contains("Engineering guide not installed"))
    );
    assert!(plan(&f.root, &f.source()).unwrap().is_empty());
}
#[test]
fn workflow_upgrade_preserves_controls_and_refuses_guide_drift() {
    let f = Fixture::new();
    f.apply();
    let name = "docs/agent-setup/workflow.md";
    let mut lock = f.value(LOCK);
    lock["files"].as_object_mut().unwrap().remove(name);
    fs::remove_file(f.root.join(name)).unwrap();
    f.write_value(LOCK, &lock);
    f.write(
        "AGENTS.md",
        &("Local workflow exception: manual release approval\n".to_owned() + &f.read("AGENTS.md")),
    );
    assert!(doctor(&f.root).unwrap().iter().any(|s| s.contains(name)));
    f.apply();
    assert!(
        f.read("AGENTS.md")
            .contains("Local workflow exception: manual release approval")
    );
    assert!(f.root.join(name).is_file());
    assert!(plan(&f.root, &f.source()).unwrap().is_empty());
    f.write(name, "Project-owned workflow edits\n");
    assert!(plan(&f.root, &f.source()).is_err());
    assert_eq!(f.read(name), "Project-owned workflow edits\n");
}

#[test]
fn retired_templates_are_deleted_when_unchanged_and_refused_when_edited() {
    let f = Fixture::new();
    f.apply();
    let legacy = "# Plan template\n\nLast verified: 2026-10-27\n";
    let install_legacy = |names: &[&str]| {
        let mut lock = f.value(LOCK);
        for name in names {
            f.write(name, legacy);
            lock["files"][*name] =
                json!({"module": "setup-core", "class": "managed", "digest": digest(legacy)});
        }
        f.write_value(LOCK, &lock);
    };
    install_legacy(RETIRED);
    let findings = doctor(&f.root).unwrap();
    for name in RETIRED {
        assert!(findings.contains(&format!(
            "Retired guide still installed; update setup: {name}"
        )));
    }
    let changes = plan(&f.root, &f.source()).unwrap();
    for name in RETIRED {
        assert_eq!(changes.get(*name), Some(&None));
    }
    f.apply();
    for name in RETIRED {
        assert!(!f.root.join(name).exists());
        assert!(f.value(LOCK)["files"].get(*name).is_none());
    }
    assert!(plan(&f.root, &f.source()).unwrap().is_empty());

    let name = RETIRED[0];
    install_legacy(&[name]);
    f.write(name, "Locally edited plan template\n");
    assert!(plan(&f.root, &f.source()).is_err());
    assert_eq!(f.read(name), "Locally edited plan template\n");

    fs::remove_file(f.root.join(name)).unwrap();
    f.apply();
    assert!(f.value(LOCK)["files"].get(name).is_none());

    // A file at a retired path that the lock never recorded is project-owned.
    f.write(name, "Project-owned template\n");
    assert!(plan(&f.root, &f.source()).unwrap().is_empty());
    f.apply();
    assert_eq!(f.read(name), "Project-owned template\n");
    assert!(doctor(&f.root).unwrap().iter().all(|s| !s.contains(name)));
}

#[test]
fn new_guide_collision_refuses_entire_legacy_upgrade() {
    let f = Fixture::new();
    f.apply();
    let name = "docs/agent-setup/architecture.md";
    let mut lock = f.value(LOCK);
    lock["files"].as_object_mut().unwrap().remove(name);
    f.write_value(LOCK, &lock);
    f.write(name, "Project-owned architecture\n");
    assert!(plan(&f.root, &f.source()).is_err());
    assert_eq!(f.read(name), "Project-owned architecture\n");
}
#[test]
fn unknown_managed_paths_and_bad_lock_schemas_refused() {
    for patch in [
        json!({"schema": 2,"files":{}}),
        json!({"schema":1,"files":{"../../outside":"bad"}}),
        json!({"schema":1,"files":[]}),
    ] {
        let f = Fixture::new();
        f.apply();
        f.write_value(LOCK, &patch);
        assert!(plan(&f.root, &f.source()).is_err());
        assert!(doctor(&f.root).is_err());
    }
}
#[test]
fn doctor_distinguishes_placeholders_from_discussion() {
    for (text, expected) in [
        (
            "When deferring work, explain the TODO at the call site.\nUse functional placeholder copy only when approved.\n",
            false,
        ),
        ("TBD\n- Levantar:\n", true),
    ] {
        let f = Fixture::new();
        f.write("CLAUDE.md", text);
        f.apply();
        assert_eq!(
            doctor(&f.root)
                .unwrap()
                .iter()
                .any(|s| s.contains("placeholder guidance")),
            expected
        );
    }
}
#[test]
fn doctor_reports_missing_configuration_and_conventions() {
    let f = Fixture::new();
    assert!(
        doctor(&f.root)
            .unwrap()
            .iter()
            .any(|s| s.contains("project profile missing"))
    );
    f.apply();
    let mut profile = f.value(PROFILE);
    profile["conventions"] = json!(["missing.md"]);
    f.write_value(PROFILE, &profile);
    assert!(
        doctor(&f.root)
            .unwrap()
            .contains(&"Convention reference missing: missing.md".to_owned())
    );
}
#[test]
fn malformed_blocks_refused() {
    for text in [
        BEGIN.to_owned(),
        END.to_owned(),
        format!("{BEGIN}{BEGIN}{END}"),
        format!("{END}{BEGIN}"),
    ] {
        assert!(block_content(&text).is_err());
        let f = Fixture::new();
        f.write("AGENTS.md", &text);
        assert!(plan(&f.root, &f.source()).is_err());
    }
}
#[test]
fn new_install_writes_incident_runbook_postmortem_guides() {
    let f = Fixture::new();
    f.apply();
    for name in [
        "docs/agent-setup/incidents.md",
        "docs/agent-setup/runbook-template.md",
        "docs/agent-setup/postmortem-template.md",
    ] {
        assert!(f.root.join(name).is_file(), "{name}");
    }
}

#[test]
fn update_from_v030_lock_adds_incident_runbook_postmortem_guides() {
    let f = Fixture::new();
    f.apply();
    let new_names = [
        "docs/agent-setup/incidents.md",
        "docs/agent-setup/runbook-template.md",
        "docs/agent-setup/postmortem-template.md",
    ];
    let mut lock = f.value(LOCK);
    let files = lock["files"].as_object_mut().unwrap();
    for name in &new_names {
        fs::remove_file(f.root.join(name)).unwrap();
        files.remove(*name);
    }
    lock["version"] = json!("0.3.0");
    f.write_value(LOCK, &lock);
    assert!(
        doctor(&f.root)
            .unwrap()
            .iter()
            .any(|s| new_names.iter().any(|n| s.contains(n)))
    );
    f.apply();
    for name in &new_names {
        assert!(f.root.join(name).is_file(), "{name}");
    }
    assert!(plan(&f.root, &f.source()).unwrap().is_empty());
}

const DECISIONS: &str = "# Decisions\n\n## Use rust — accepted, 2026-10-01\n\nbody\n\n## Old way — Superseded, 2026-09-01\n\n## Bad idea — Rejected, 2026-09-02\n\n## Plain note\n";

fn with_conventions(f: &Fixture, conventions: Value) {
    f.apply();
    let mut profile = f.value(PROFILE);
    profile["purpose"] = json!("p");
    profile["conventions"] = conventions;
    f.write_value(PROFILE, &profile);
    f.write("docs/decisions.md", DECISIONS);
    f.write("docs/design.md", "design\n");
}
fn entrypoint(f: &Fixture) -> String {
    let plan = plan(&f.root, &f.source()).unwrap();
    plan.get("AGENTS.md")
        .cloned()
        .flatten()
        .unwrap_or_else(|| f.read("AGENTS.md"))
}

#[test]
fn plain_string_conventions_render_unchanged() {
    let f = Fixture::new();
    f.apply();
    let before = f.read("AGENTS.md");
    assert_eq!(before, include_str!("fixtures/plain-string-agents.md"));
    let mut profile = f.value(PROFILE);
    profile["conventions"] = json!(["docs/design.md"]);
    f.write_value(PROFILE, &profile);
    f.write("docs/design.md", "design\n");
    assert_eq!(entrypoint(&f), before);
    assert!(
        !plan(&f.root, &f.source())
            .unwrap()
            .contains_key("docs/agent-setup/decisions-index.md")
    );
}

#[test]
fn object_conventions_render_hierarchy_table_and_decisions() {
    let f = Fixture::new();
    with_conventions(
        &f,
        json!([
            "docs/design.md",
            {"path": "docs/design.md", "when": ["src/**", "lib/*.rs"], "adr": "docs/decisions.md#use-rust--accepted-2026-10-01"}
        ]),
    );
    let text = entrypoint(&f);
    assert!(text.contains("### Truth hierarchy"));
    assert!(text.contains("| `src/**`, `lib/*.rs` | `docs/design.md` |"));
    assert!(text.ends_with("\nDecisions: `docs/agent-setup/decisions-index.md` (generated from `docs/decisions.md`)\n<!-- brakes:end -->\n"));
    assert!(!text.contains("Use rust"));
    f.apply();
    let index = f.read("docs/agent-setup/decisions-index.md");
    assert_eq!(
        index,
        "# Decisions index\n\nGenerated from `docs/decisions.md`. Regenerate with the setup installer.\n\n- [Use rust](../../docs/decisions.md#use-rust--accepted-2026-10-01) — accepted, 2026-10-01\n- [Old way](../../docs/decisions.md#old-way--superseded-2026-09-01) — Superseded, 2026-09-01 — SUPERSEDED (not binding)\n- [Bad idea](../../docs/decisions.md#bad-idea--rejected-2026-09-02) — Rejected, 2026-09-02 — REJECTED (not binding)\n"
    );
    assert_eq!(
        f.value(LOCK)["files"]["docs/agent-setup/decisions-index.md"]["digest"],
        digest(&index)
    );
    assert!(
        doctor(&f.root)
            .unwrap()
            .iter()
            .all(|s| !s.contains("decision"))
    );
}

#[test]
fn decision_changes_warn_without_entrypoint_drift_and_regenerate_idempotently() {
    let f = Fixture::new();
    with_conventions(
        &f,
        json!([{"path": "docs/design.md", "adr": "docs/decisions.md#use-rust--accepted-2026-10-01"}]),
    );
    f.apply();
    let before = f.read("AGENTS.md");
    f.write(
        "docs/decisions.md",
        &format!("{DECISIONS}\n## New choice — accepted, 2026-10-23\n"),
    );
    let issues = doctor(&f.root).unwrap();
    assert!(issues.contains(&"WARNING: Decisions index stale: docs/agent-setup/decisions-index.md; regenerate with the setup installer".to_owned()), "{issues:?}");
    assert!(
        !issues
            .iter()
            .any(|s| s.contains("drift") || s.contains("Entrypoint") || s.starts_with("Guide ")),
        "{issues:?}"
    );
    let changes = plan(&f.root, &f.source()).unwrap();
    assert_eq!(
        changes.keys().map(String::as_str).collect::<Vec<_>>(),
        vec![LOCK, "docs/agent-setup/decisions-index.md"]
    );
    f.apply();
    assert_eq!(f.read("AGENTS.md"), before);
    assert!(
        f.read("docs/agent-setup/decisions-index.md")
            .contains("[New choice](../../docs/decisions.md#new-choice--accepted-2026-10-23)")
    );
    // Regeneration clears the stale-index warning; the warnings left are the
    // merge-guard registration (#693), since the fixture registers no hook, and
    // the static secrets gate (#793), since it has no workflow.
    // A fresh pin table (#763): the age warning depends on the real clock.
    let fresh = brakes::modules::stack_packs::PinTable::embedded()
        .unwrap()
        .last_verified;
    let warnings: Vec<String> = brakes::doctor_at(&f.root, fresh)
        .unwrap()
        .into_iter()
        .filter(|s| s.starts_with("WARNING:"))
        .collect();
    assert_eq!(
        warnings,
        vec![
            brakes::guard::doctor::UNREGISTERED.to_owned(),
            "WARNING: security.secrets-gate: No secrets gate: no gitleaks job and secret scanning off"
                .to_owned(),
            "WARNING: security.sast-gate: No static analysis job in CI".to_owned(),
        ]
    );
    assert!(plan(&f.root, &f.source()).unwrap().is_empty());
}

#[test]
fn decisions_index_keeps_managed_file_preservation_guards() {
    for replacement in [Some("Local edits\n"), None] {
        let f = Fixture::new();
        with_conventions(
            &f,
            json!([{"path": "docs/design.md", "adr": "docs/decisions.md#use-rust--accepted-2026-10-01"}]),
        );
        f.apply();
        let name = "docs/agent-setup/decisions-index.md";
        if let Some(text) = replacement {
            f.write(name, text);
        } else {
            fs::remove_file(f.root.join(name)).unwrap();
        }
        assert!(
            doctor(&f.root)
                .unwrap()
                .iter()
                .any(|s| s.starts_with("WARNING: Decisions index"))
        );
        assert!(
            plan(&f.root, &f.source())
                .unwrap_err()
                .to_string()
                .contains("Locally changed or missing managed content")
        );
    }
}

#[test]
fn decisions_index_deduplicates_sources_and_retains_ownership_after_profile_changes() {
    let f = Fixture::new();
    with_conventions(
        &f,
        json!([
            {"path": "docs/design.md", "adr": "docs/decisions.md#use-rust--accepted-2026-10-01"},
            {"path": "docs/design.md", "adr": "docs/other.md#other--accepted-2026-10-23"},
            {"path": "docs/design.md", "adr": "docs/decisions.md#use-rust--accepted-2026-10-01"}
        ]),
    );
    f.write("docs/other.md", "## Other — accepted, 2026-10-23\n");
    let name = "docs/agent-setup/decisions-index.md";
    f.write(name, "Existing project-owned document\n");
    assert!(
        plan(&f.root, &f.source())
            .unwrap_err()
            .to_string()
            .contains("Unowned managed destination")
    );
    fs::remove_file(f.root.join(name)).unwrap();
    f.apply();
    let index = f.read(name);
    assert_eq!(index.matches("- [Use rust]").count(), 1);
    assert!(index.contains("[Other](../../docs/other.md#other--accepted-2026-10-23)"));
    assert!(
        f.read("AGENTS.md")
            .contains("(generated from `docs/decisions.md`, `docs/other.md`)")
    );
    let mut profile = f.value(PROFILE);
    profile["conventions"] = json!(["docs/design.md"]);
    f.write_value(PROFILE, &profile);
    f.apply();
    assert!(f.value(LOCK)["files"].get(name).is_some());
    assert!(!f.read(name).contains("[Use rust]"));
    assert!(!f.read("AGENTS.md").contains("Decisions:"));
    assert!(plan(&f.root, &f.source()).unwrap().is_empty());
}

#[test]
fn doctor_flags_conventions_without_a_valid_decision() {
    let f = Fixture::new();
    with_conventions(
        &f,
        json!([
            {"path": "docs/design.md"},
            {"path": "docs/design.md", "adr": "docs/decisions.md#nope"},
            {"path": "docs/design.md", "adr": "docs/missing.md#x"},
            {"path": "docs/design.md", "adr": "docs/decisions.md#old-way--superseded-2026-09-01"},
            {"path": "docs/design.md", "adr": "docs/decisions.md#bad-idea--rejected-2026-09-02"}
        ]),
    );
    let issues = doctor(&f.root).unwrap();
    for expected in [
        "Convention without a decision: docs/design.md",
        "Convention decision does not resolve: docs/design.md -> docs/decisions.md#nope",
        "Convention decision does not resolve: docs/design.md -> docs/missing.md#x",
        "Convention points at a superseded decision: docs/design.md -> docs/decisions.md#old-way--superseded-2026-09-01",
        "Convention points at a rejected decision: docs/design.md -> docs/decisions.md#bad-idea--rejected-2026-09-02",
    ] {
        assert!(
            issues.contains(&expected.to_owned()),
            "{expected}: {issues:?}"
        );
    }
}

#[test]
fn malformed_convention_objects_refused() {
    for bad in [
        json!([{"when": ["a"]}]),
        json!([{"path": "a", "extra": 1}]),
        json!([{"path": "a", "when": "a"}]),
        json!([{"path": "a", "adr": 3}]),
        json!([{"path": "../a"}]),
        json!([3]),
    ] {
        let f = Fixture::new();
        f.apply();
        let mut profile = f.value(PROFILE);
        profile["conventions"] = bad;
        f.write_value(PROFILE, &profile);
        assert!(profile_for(&f.root).is_err());
    }
}

fn day(text: &str) -> chrono::NaiveDate {
    chrono::NaiveDate::parse_from_str(text, "%Y-%m-%d").unwrap()
}
fn guide_issues(f: &Fixture, today: &str) -> Vec<String> {
    doctor_at(&f.root, day(today))
        .unwrap()
        .into_iter()
        .filter(|s| s.starts_with("Guide "))
        .collect()
}
#[test]
fn doctor_flags_stale_missing_and_unparsable_guide_dates() {
    let f = Fixture::new();
    f.apply();
    let name = "docs/agent-setup/index.md";
    let text = f.read(name);
    let date = last_verified(&text).unwrap();
    let fresh = date.format("%Y-%m-%d").to_string();
    assert!(guide_issues(&f, &fresh).is_empty());
    let old = (date + chrono::Days::new(200))
        .format("%Y-%m-%d")
        .to_string();
    let issues = guide_issues(&f, &old);
    // Every installed guide under docs/agent-setup/ is dated: 24 at PL11, plus
    // observability, incidents, runbook and postmortem (RM5, RM7), less the plan,
    // change and PRD templates withdrawn on 2026-10-27.
    assert_eq!(issues.len(), DOCUMENTS.len(), "{issues:?}");
    assert_eq!(issues.len(), 27, "{issues:?}");
    assert!(issues.contains(&"Guide not verified for 200 days: index.md".to_owned()));
    let edge = (date + chrono::Days::new(180))
        .format("%Y-%m-%d")
        .to_string();
    assert!(guide_issues(&f, &edge).is_empty());
    for bad in ["common\n", "# Guide\n\nLast verified: soon\n"] {
        f.write(name, bad);
        assert!(
            guide_issues(&f, &fresh)
                .contains(&"Guide verification date missing: index.md".to_owned())
        );
    }
}
#[test]
fn guide_verification_bound_comes_from_profile() {
    let f = Fixture::new();
    f.apply();
    let date = last_verified(&f.read("docs/agent-setup/index.md")).unwrap();
    let later = (date + chrono::Days::new(60))
        .format("%Y-%m-%d")
        .to_string();
    assert!(guide_issues(&f, &later).is_empty());
    let mut profile = f.value(PROFILE);
    profile["guide_verification_days"] = json!(30);
    f.write_value(PROFILE, &profile);
    assert!(
        guide_issues(&f, &later).contains(&"Guide not verified for 60 days: index.md".to_owned())
    );
    for bad in [json!(0), json!("30"), json!(-1)] {
        profile["guide_verification_days"] = bad;
        f.write_value(PROFILE, &profile);
        assert!(doctor(&f.root).is_err());
    }
}

const RULE: &str = "groups:\n  - name: api\n    rules:\n      - alert: HighErrorRatio\n        expr: job:errors:ratio > 0.05\n        for: 5m\n        labels:\n          severity: page\n          owner: team-api\n        annotations:\n          summary: \"Errors # high\"\n          runbook_url: docs/runbooks/errors.md\n";

fn alert_findings(f: &Fixture) -> Vec<String> {
    doctor(&f.root)
        .unwrap()
        .into_iter()
        .filter(|s| s.contains("lert") || s.contains("unbook"))
        .collect()
}
fn alert_fixture() -> Fixture {
    let f = Fixture::new();
    f.apply();
    let mut profile = f.value(PROFILE);
    profile["observability"] = json!({"alerts_dir": "ops/alerts", "runbooks_dir": null});
    f.write_value(PROFILE, &profile);
    f.write("docs/runbooks/errors.md", "Runbook\n");
    f
}
#[test]
fn alerts_undeclared_dir_gives_no_finding() {
    let f = Fixture::new();
    f.apply();
    f.write("ops/alerts/bad.yml", "not: prometheus\n");
    assert!(alert_findings(&f).is_empty());
}
#[test]
fn alerts_complete_rule_gives_no_finding() {
    let f = alert_fixture();
    f.write("ops/alerts/api.yml", RULE);
    assert_eq!(alert_findings(&f), Vec::<String>::new());
}
#[test]
fn alerts_missing_owner_is_reported() {
    let f = alert_fixture();
    f.write(
        "ops/alerts/api.yaml",
        &RULE.replace("          owner: team-api\n", ""),
    );
    let found = alert_findings(&f);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("HighErrorRatio") && found[0].contains("labels.owner"));
}
#[test]
fn alerts_absent_runbook_path_is_reported() {
    let f = alert_fixture();
    f.write("ops/alerts/api.yml", &RULE.replace("errors.md", "gone.md"));
    let found = alert_findings(&f);
    assert!(
        found.iter().any(|s| s.contains("runbook not found")),
        "{found:?}"
    );
    f.write(
        "ops/alerts/api.yml",
        &RULE.replace("docs/runbooks/errors.md", "https://wiki.example/errors"),
    );
    assert!(alert_findings(&f).is_empty());
}
#[test]
fn alerts_unrecognised_file_is_reported() {
    let f = alert_fixture();
    f.write(
        "ops/alerts/other.yml",
        "apiVersion: v1\nkind: AlertmanagerConfig\n",
    );
    f.write("ops/alerts/notes.txt", "ignored\n");
    let found = alert_findings(&f);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("Unrecognised alert file") && found[0].contains("other.yml"));
}
#[test]
fn alerts_dir_must_stay_inside_repository() {
    let f = Fixture::new();
    f.apply();
    let mut profile = f.value(PROFILE);
    profile["observability"] = json!({"alerts_dir": "../outside"});
    f.write_value(PROFILE, &profile);
    assert!(doctor(&f.root).is_err());
}

#[test]
fn schema_1_lock_migrates_with_a_lock_only_plan_and_then_no_changes() {
    let f = Fixture::new();
    f.apply();
    // Rewrite the lock in the shape 0.3.0 wrote: schema 1, a flat map of digests.
    let v2 = f.value(LOCK);
    let files: serde_json::Map<String, Value> = v2["files"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v["digest"].clone()))
        .collect();
    f.write_value(
        LOCK,
        &json!({"schema": 1, "version": v2["version"], "source_commit": v2["source_commit"],
            "source_dirty": false, "personal_owner": brakes::config::current_owner(), "files": files}),
    );
    let changes = plan(&f.root, &f.source()).unwrap();
    assert_eq!(changes.keys().collect::<Vec<_>>(), vec![LOCK]);
    f.apply();
    let migrated = f.value(LOCK);
    assert_eq!(migrated["schema"], 2);
    assert_eq!(migrated["modules"]["setup-core"]["version"], "1.3.0");
    // The hook moves to merge-guard with the same digest (#696).
    assert_eq!(
        migrated["files"][".claude/hooks/merge_guard.sh"]["module"],
        "merge-guard"
    );
    assert_eq!(migrated["files"]["AGENTS.md"]["class"], "managed-block");
    assert_eq!(migrated["files"]["AGENTS.md"]["module"], "setup-core");
    assert!(plan(&f.root, &f.source()).unwrap().is_empty());
}

/// "The installer distributes no workflow framework" (2026-10-29, #986): nothing
/// under `templates/` names a workflow framework, a skill pack or one of its skill
/// identifiers, nor `tasks/todo.md`. "GitHub Issues" is a host feature: allowed only
/// under `templates/repo-baseline/`, the host adapter's seeds.
#[test]
fn distributed_templates_name_no_workflow_framework() {
    const FORBIDDEN: &[&str] = &[
        "agent skills",
        "agent-skills",
        "addy osmani",
        "addyosmani",
        "using-agent-skills",
        "interview-me",
        "spec-driven-development",
        "planning-and-task-breakdown",
        "incremental-implementation",
        "test-driven-development",
        "code-review-and-quality",
        "documentation-and-adrs",
        "shipping-and-launch",
        "spec kit",
        "spec-kit",
        "speckit",
        "openspec",
        "superpowers",
        "product factory",
        "bmad",
        "tasks/todo.md",
    ];
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
    let templates = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../templates");
    let mut files = Vec::new();
    collect(&templates, &mut files);
    files.sort();
    assert!(files.iter().any(|f| f.ends_with("workflow.md")));
    let mut offences = Vec::new();
    for file in &files {
        let relative = file.strip_prefix(&templates).unwrap().to_string_lossy();
        let text = fs::read_to_string(file).unwrap().to_lowercase();
        for name in FORBIDDEN {
            if text.contains(name) {
                offences.push(format!("{relative}: `{name}`"));
            }
        }
        if text.contains("github issues") && !relative.starts_with("repo-baseline/") {
            offences.push(format!(
                "{relative}: `GitHub Issues` outside the host seeds"
            ));
        }
    }
    assert_eq!(offences, Vec::<String>::new());
}
