//! product-boundary T7a (#1056; SPEC-product-boundary.md, plan T7): `setup-core`
//! is a cargo feature, on by default here. Without it the module, its guides,
//! conventions and decisions index are not compiled in, and `agent-guardrails`
//! renders the `technical-debt.md` line of `AGENTS.md` itself (Decided 6).
use brakes::modules;

fn ids() -> Vec<&'static str> {
    modules::all().iter().map(|m| m.id()).collect()
}

#[cfg(feature = "setup-core")]
#[test]
fn with_the_feature_setup_core_is_the_first_module() {
    assert_eq!(ids()[0], "setup-core");
    assert!(!brakes::DOCUMENTS.is_empty());
}

#[cfg(not(feature = "setup-core"))]
#[test]
fn without_the_feature_no_setup_core_module_is_compiled_in() {
    assert!(!ids().contains(&"setup-core"), "{:?}", ids());
    assert_eq!(ids()[0], "stack-packs");
}

#[cfg(not(feature = "setup-core"))]
#[test]
fn without_the_feature_agent_guardrails_renders_the_technical_debt_line() {
    use std::{fs, process::Command};
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
    let cli = |args: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_brakes"))
            .arg("install")
            .arg(&root)
            .args(args)
            .output()
            .unwrap();
        assert!(out.status.success(), "{args:?}: {out:?}");
    };
    cli(&["--new-personal", "--apply"]);
    let profile = root.join(".agent-setup/project.json");
    let mut value: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&profile).unwrap()).unwrap();
    value["commands"]["test"] = "cargo test".into();
    fs::write(
        &profile,
        serde_json::to_string_pretty(&value).unwrap() + "\n",
    )
    .unwrap();
    fs::write(root.join("Cargo.toml"), "").unwrap();
    fs::write(root.join("Cargo.lock"), "").unwrap();
    fs::create_dir_all(root.join(".agent-setup/modules")).unwrap();
    fs::write(
        root.join(".agent-setup/modules/stack-packs.json"),
        r#"{"module": "stack-packs", "version": "1.0.0", "answers": {"apps.root.path": ".", "apps.root.stack": "rust", "apps.root.container": false}}"#,
    )
    .unwrap();
    // A managed `ci.yml` is the deprecated generated workflow (#21), pinned here.
    fs::write(
        root.join(".agent-setup/modules/ci-baseline.json"),
        r#"{"module": "ci-baseline", "version": "1.0.0", "answers": {"workflow": "generate"}}"#,
    )
    .unwrap();
    cli(&[
        "--module",
        "stack-packs",
        "--module",
        "repo-baseline",
        "--module",
        "ci-baseline",
        "--module",
        "agent-guardrails",
        "--apply",
    ]);
    let agents = fs::read_to_string(root.join("AGENTS.md")).unwrap();
    assert!(
        agents.contains("Before imitating neighbouring code, read `docs/agent-setup/technical-debt.md`: it lists the patterns not to copy."),
        "{agents}"
    );
    assert!(!agents.contains("principles.md"), "{agents}");
    assert!(root.join("docs/agent-setup/technical-debt.md").exists());
    assert!(!root.join("docs/agent-setup/principles.md").exists());
}

// ---- the auditor rules that audit setup-core (T7b, #1057) ----------------------------

/// The `baseline.*` rules over setup-core's content: they exist with the feature only.
/// `baseline.managed-content-intact` is not one of them: it audits every module's
/// managed files (SPEC-product-boundary.md, Decided (coordinator) 9).
const SETUP_CORE_RULES: [&str; 7] = [
    "baseline.setup-installed",
    "baseline.guides-installed",
    "baseline.guides-verified",
    "baseline.conventions-resolved",
    "baseline.decisions-index-current",
    "baseline.entrypoints-current",
    "baseline.placeholder-guidance-reviewed",
];

fn registry_ids() -> Vec<&'static str> {
    brakes::auditor::rules::REGISTRY
        .iter()
        .map(|r| r.id)
        .collect()
}

#[cfg(feature = "setup-core")]
#[test]
fn with_the_feature_the_catalogue_audits_setup_core() {
    let ids = registry_ids();
    for id in SETUP_CORE_RULES {
        assert!(ids.contains(&id), "{id}");
    }
    assert!(ids.contains(&"agents.technical-debt"));
}

#[cfg(not(feature = "setup-core"))]
#[test]
fn without_the_feature_the_catalogue_is_shorter_by_exactly_those_rules() {
    let ids = registry_ids();
    for id in SETUP_CORE_RULES {
        assert!(!ids.contains(&id), "{id}");
    }
    assert!(ids.contains(&"agents.technical-debt"));
    assert!(ids.contains(&"baseline.purpose-declared"));
    assert!(ids.contains(&"baseline.managed-content-intact"));
}

/// A repository installed with stack-packs and ci-baseline (and setup-core when the
/// build has it), whose `ci.yml` is a managed file of ci-baseline.
fn installed_without_setup_core() -> tempfile::TempDir {
    use std::{fs, process::Command};
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .arg(root)
            .status()
            .unwrap()
            .success()
    );
    let cli = |args: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_brakes"))
            .args(args)
            .output()
            .unwrap();
        assert!(out.status.success(), "{args:?}: {out:?}");
        String::from_utf8(out.stdout).unwrap()
    };
    let path = root.to_str().unwrap();
    cli(&["install", path, "--new-personal", "--apply"]);
    let profile = root.join(".agent-setup/project.json");
    let mut value: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&profile).unwrap()).unwrap();
    value["commands"]["test"] = "cargo test".into();
    fs::write(
        &profile,
        serde_json::to_string_pretty(&value).unwrap() + "\n",
    )
    .unwrap();
    fs::write(root.join("Cargo.toml"), "").unwrap();
    fs::write(root.join("Cargo.lock"), "").unwrap();
    fs::create_dir_all(root.join(".agent-setup/modules")).unwrap();
    fs::write(
        root.join(".agent-setup/modules/stack-packs.json"),
        r#"{"module": "stack-packs", "version": "1.0.0", "answers": {"apps.root.path": ".", "apps.root.stack": "rust", "apps.root.container": false}}"#,
    )
    .unwrap();
    // A managed `ci.yml` is the deprecated generated workflow (#21), pinned here.
    fs::write(
        root.join(".agent-setup/modules/ci-baseline.json"),
        r#"{"module": "ci-baseline", "version": "1.0.0", "answers": {"workflow": "generate"}}"#,
    )
    .unwrap();
    cli(&[
        "install",
        path,
        "--module",
        "stack-packs",
        "--module",
        "ci-baseline",
        "--apply",
    ]);
    temp
}

#[cfg(not(feature = "setup-core"))]
#[test]
fn without_the_feature_a_hand_edited_managed_file_of_another_module_is_reported() {
    use std::{fs, process::Command};
    let temp = installed_without_setup_core();
    let root = temp.path();
    let doctor = |json: bool| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_brakes"));
        command.arg("doctor").arg(root);
        if json {
            command.arg("--json");
        }
        String::from_utf8(command.output().unwrap().stdout).unwrap()
    };
    let rule = |text: &str| -> serde_json::Value {
        let document: serde_json::Value = serde_json::from_str(text).unwrap();
        document["rules"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == "baseline.managed-content-intact")
            .cloned()
            .expect("baseline.managed-content-intact is evaluated")
    };
    assert_eq!(rule(&doctor(true))["status"], "passed");
    let ci = root.join(".github/workflows/ci.yml");
    let edited = fs::read_to_string(&ci).unwrap() + "# a hand edit\n";
    fs::write(&ci, edited).unwrap();
    let text = doctor(false);
    assert!(
        text.lines()
            .any(|l| l
                .ends_with("Managed content drift: .github/workflows/ci.yml (module ci-baseline)")),
        "{text}"
    );
    let failed = rule(&doctor(true));
    assert_eq!(failed["status"], "failed", "{failed}");
    assert!(
        failed["evidence"]
            .to_string()
            .contains("Managed content drift: .github/workflows/ci.yml (module ci-baseline)"),
        "{failed}"
    );
}

/// `doctor`'s plain text and its `--json` rule for a managed-content drift.
fn drift_report(root: &std::path::Path) -> (String, serde_json::Value) {
    use std::process::Command;
    let doctor = |json: bool| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_brakes"));
        command.arg("doctor").arg(root);
        if json {
            command.arg("--json");
        }
        String::from_utf8(command.output().unwrap().stdout).unwrap()
    };
    let document: serde_json::Value = serde_json::from_str(&doctor(true)).unwrap();
    let rule = document["rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "baseline.managed-content-intact")
        .cloned()
        .expect("baseline.managed-content-intact is evaluated");
    (doctor(false), rule)
}

/// #1254: a hand edit of a file the lock assigns to ci-baseline names ci-baseline,
/// in the finding and in the remediation, never setup-core.
#[test]
fn a_drifted_managed_file_names_the_module_the_lock_records() {
    use std::fs;
    let temp = installed_without_setup_core();
    let root = temp.path();
    let ci = root.join(".github/workflows/ci.yml");
    fs::write(&ci, fs::read_to_string(&ci).unwrap() + "# a hand edit\n").unwrap();
    let (text, rule) = drift_report(root);
    assert!(
        text.lines()
            .any(|l| l
                .ends_with("Managed content drift: .github/workflows/ci.yml (module ci-baseline)")),
        "{text}"
    );
    let fail = text
        .lines()
        .find(|l| l.contains("[basic:baseline.managed-content-intact]"))
        .unwrap_or_else(|| panic!("no FAIL line: {text}"));
    assert!(
        fail.ends_with("Managed content drift: .github/workflows/ci.yml (module ci-baseline) → module ci-baseline"),
        "{fail}"
    );
    assert_eq!(rule["status"], "failed", "{rule}");
    assert_eq!(rule["remediation"], "module ci-baseline", "{rule}");
}

/// A module the build does not compile (setup-core without the feature) is never
/// named as the fix: the file is restored or install re-run.
#[cfg(not(feature = "setup-core"))]
#[test]
fn without_the_feature_a_drift_owned_by_setup_core_is_restored_by_hand() {
    use std::fs;
    let temp = installed_without_setup_core();
    let root = temp.path();
    let lock_path = root.join(".agent-setup/lock.json");
    let mut lock: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&lock_path).unwrap()).unwrap();
    lock["files"][".github/workflows/ci.yml"]["module"] = "setup-core".into();
    fs::write(
        &lock_path,
        serde_json::to_string_pretty(&lock).unwrap() + "\n",
    )
    .unwrap();
    let ci = root.join(".github/workflows/ci.yml");
    fs::write(&ci, fs::read_to_string(&ci).unwrap() + "# a hand edit\n").unwrap();
    let (text, rule) = drift_report(root);
    let fail = text
        .lines()
        .find(|l| l.contains("[basic:baseline.managed-content-intact]"))
        .unwrap_or_else(|| panic!("no FAIL line: {text}"));
    assert!(
        fail.contains("(module setup-core) → manual step restore-managed-content: "),
        "{fail}"
    );
    assert!(
        rule["remediation"]
            .as_str()
            .unwrap()
            .starts_with("manual step restore-managed-content: "),
        "{rule}"
    );
}

/// Without the feature, no rule's remediation sends the user to setup-core (#1260);
/// a planned module is printed as such (`auditor_report`).
#[cfg(not(feature = "setup-core"))]
#[test]
fn without_the_feature_no_remediation_names_a_module_the_build_lacks() {
    use brakes::auditor::rules::{REGISTRY, Remediation};
    let missing: Vec<(&str, &str)> = REGISTRY
        .iter()
        .filter_map(|rule| match rule.remediation {
            Remediation::Module { id } if id == "setup-core" => Some((rule.id, id)),
            _ => None,
        })
        .collect();
    assert!(missing.is_empty(), "{missing:?}");
}

/// Without the feature, nothing doctor prints, as text or JSON, names setup-core
/// (#1260): neither a remediation nor a reason.
#[cfg(not(feature = "setup-core"))]
#[test]
fn without_the_feature_doctor_never_names_setup_core() {
    use std::{fs, process::Command};
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("project");
    fs::create_dir(&root).unwrap();
    let git = |args: &[&str]| {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(&root)
                .args(args)
                .status()
                .unwrap()
                .success()
        )
    };
    git(&["init", "-q"]);
    git(&[
        "remote",
        "add",
        "origin",
        "https://github.com/example-owner/toy.git",
    ]);
    let run = |args: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_brakes"))
            .args(args)
            .arg(&root)
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr)
    };
    let installed = run(&["install", "--module", "repo-baseline", "--apply"]);
    assert!(!installed.contains("REFUSED"), "{installed}");
    for args in [&["doctor"][..], &["doctor", "--json"], &["adopt"]] {
        let out = run(args);
        assert!(!out.contains("REFUSED"), "{args:?}: {out}");
        assert!(!out.contains("setup-core"), "{args:?}: {out}");
    }
}
