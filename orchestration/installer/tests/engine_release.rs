//! #48: a module the lock records but this build does not ship is released, not
//! refused. Its entries leave the lock; its files stay as the project's own
//! content, a managed block losing only its markers; the plan lists each released
//! path once under `RELEASED [<module>]`; nothing is deleted; a second plan after
//! `--apply` prints `No changes.`
use serde_json::{Value, json};
use std::{fs, path::PathBuf, process::Command};
use tempfile::TempDir;

/// A module id no build of this repository compiles in (`setup-core` is behind a
/// feature this repository never builds).
const GONE: &str = "setup-core";
const GUIDE: &str = "docs/agent-setup/legacy-guide.md";
const GUIDE_TEXT: &str = "# A guide an earlier build managed\n\nKeep it.\n";
const AGENTS_BEFORE: &str = "# Project\n\nIntro the project wrote.\n\n<!-- brakes:begin -->\nRules an earlier build managed.\n<!-- brakes:end -->\n\nOutro the project wrote.\n";
const AGENTS_RELEASED: &str = "# Project\n\nIntro the project wrote.\n\nRules an earlier build managed.\n\nOutro the project wrote.\n";

struct Repo {
    _temp: TempDir,
    root: PathBuf,
}

impl Repo {
    /// A personal repository installed with nothing but its profile, whose lock
    /// also records `GONE` with a managed guide, the managed block of AGENTS.md,
    /// a seed and a remote item, as an earlier, larger build left it.
    fn with_released_module() -> Self {
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
        let repo = Self { _temp: temp, root };
        let out = repo.cli(&["install", "<repo>", "--new-personal", "--apply"]);
        assert!(out.status.success(), "{out:?}");
        repo.write(GUIDE, GUIDE_TEXT);
        repo.write("AGENTS.md", AGENTS_BEFORE);
        repo.write("docs/agent-setup/seeded.md", "a seed the project kept\n");
        let mut lock = repo.lock();
        lock["modules"][GONE] = json!({"version": "1.0.0", "answers_digest": null});
        lock["files"][GUIDE] =
            json!({"module": GONE, "class": "managed", "digest": brakes::digest(GUIDE_TEXT)});
        lock["files"]["AGENTS.md"] = json!({"module": GONE, "class": "managed-block",
            "digest": brakes::digest("Rules an earlier build managed.\n")});
        lock["files"]["docs/agent-setup/seeded.md"] = json!({"module": GONE, "class": "seed"});
        lock["files"]["github:legacy-setting"] = json!({"module": GONE, "class": "remote"});
        repo.write(
            ".agent-setup/lock.json",
            &(serde_json::to_string_pretty(&lock).unwrap() + "\n"),
        );
        repo
    }

    fn write(&self, path: &str, text: &str) {
        let full = self.root.join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, text).unwrap();
    }

    fn read(&self, path: &str) -> Option<String> {
        fs::read_to_string(self.root.join(path)).ok()
    }

    fn lock(&self) -> Value {
        serde_json::from_str(&self.read(".agent-setup/lock.json").unwrap()).unwrap()
    }

    fn cli(&self, args: &[&str]) -> std::process::Output {
        let root = self.root.to_string_lossy().into_owned();
        Command::new(env!("CARGO_BIN_EXE_brakes"))
            .args(
                args.iter()
                    .map(|a| if *a == "<repo>" { root.as_str() } else { a }),
            )
            .output()
            .unwrap()
    }

    /// `install` with `args`; the standard output, after asserting success.
    fn install(&self, args: &[&str]) -> String {
        let mut all = vec!["install", "<repo>"];
        all.extend(args);
        let out = self.cli(&all);
        assert!(out.status.success(), "{args:?}: {out:?}");
        String::from_utf8_lossy(&out.stdout).into_owned()
    }
}

#[test]
fn a_plan_lists_each_released_path_once_and_writes_nothing() {
    let repo = Repo::with_released_module();
    let lock_before = repo.read(".agent-setup/lock.json").unwrap();
    let plan = repo.install(&[]);
    let released: Vec<&str> = plan
        .lines()
        .filter(|l| l.starts_with("RELEASED "))
        .collect();
    assert_eq!(
        released,
        [
            "RELEASED [setup-core] AGENTS.md — the managed block loses its markers and keeps its text",
            "RELEASED [setup-core] docs/agent-setup/legacy-guide.md — kept as the project's own file",
            "RELEASED [setup-core] docs/agent-setup/seeded.md — kept as the project's own file",
            "RELEASED [setup-core] github:legacy-setting — a host setting, left as it is",
        ],
        "{plan}"
    );
    assert!(!plan.contains("REFUSED"), "{plan}");
    assert_eq!(repo.read(".agent-setup/lock.json").unwrap(), lock_before);
    assert_eq!(repo.read("AGENTS.md").unwrap(), AGENTS_BEFORE);
}

#[test]
fn apply_keeps_every_file_drops_the_markers_and_forgets_the_module() {
    let repo = Repo::with_released_module();
    repo.install(&["--apply"]);
    assert_eq!(repo.read(GUIDE).unwrap(), GUIDE_TEXT);
    assert_eq!(repo.read("AGENTS.md").unwrap(), AGENTS_RELEASED);
    assert_eq!(
        repo.read("docs/agent-setup/seeded.md").unwrap(),
        "a seed the project kept\n"
    );
    let lock = repo.lock();
    assert!(lock["modules"].get(GONE).is_none(), "{lock}");
    let files = lock["files"].as_object().unwrap();
    assert!(
        files.values().all(|entry| entry["module"] != GONE),
        "{lock}"
    );
    assert_eq!(
        repo.install(&[]).trim_end().lines().last(),
        Some("No changes.")
    );
}

#[test]
fn an_active_module_takes_a_released_path_as_the_projects_file() {
    // AGENTS.md held the released module's block; agent-guardrails renders its own
    // block there: the earlier text stays, unmarked, and the new block is added.
    let repo = Repo::with_released_module();
    let mut profile: Value =
        serde_json::from_str(&repo.read(".agent-setup/project.json").unwrap()).unwrap();
    profile["commands"]["verify"] = json!("make check");
    repo.write(
        ".agent-setup/project.json",
        &(serde_json::to_string_pretty(&profile).unwrap() + "\n"),
    );
    let modules = [
        "--module",
        "stack-packs",
        "--module",
        "repo-baseline",
        "--module",
        "ci-baseline",
        "--module",
        "agent-guardrails",
    ];
    let plan = repo.install(&modules);
    assert!(!plan.contains("REFUSED"), "{plan}");
    assert!(plan.contains("RELEASED [setup-core] AGENTS.md"), "{plan}");
    repo.install(&[&modules[..], &["--apply"]].concat());
    let agents = repo.read("AGENTS.md").unwrap();
    assert!(agents.starts_with(AGENTS_RELEASED), "{agents}");
    assert_eq!(
        agents.matches("<!-- brakes:begin -->").count(),
        1,
        "{agents}"
    );
    let lock = repo.lock();
    assert_eq!(
        lock["files"]["AGENTS.md"]["module"], "agent-guardrails",
        "{lock}"
    );
    assert_eq!(
        repo.install(&[]).trim_end().lines().last(),
        Some("No changes.")
    );
}

#[test]
fn a_module_this_build_ships_is_never_released() {
    let repo = Repo::with_released_module();
    repo.install(&["--module", "repo-baseline", "--apply"]);
    let plan = repo.install(&[]);
    assert!(
        !plan
            .lines()
            .any(|l| l.starts_with("RELEASED [repo-baseline]")),
        "{plan}"
    );
    let lock = repo.lock();
    assert!(lock["modules"].get("repo-baseline").is_some(), "{lock}");
}

#[test]
fn a_lock_written_by_a_newer_installer_is_refused_not_released() {
    // An older binary must not drop what a newer build owns.
    let repo = Repo::with_released_module();
    let mut lock = repo.lock();
    lock["version"] = json!("99.0.0");
    repo.write(
        ".agent-setup/lock.json",
        &(serde_json::to_string_pretty(&lock).unwrap() + "\n"),
    );
    let out = repo.cli(&["install", "<repo>"]);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        text.contains("REFUSED: The lock was written by brakes 99.0.0, newer than this build"),
        "{text}"
    );
    assert!(!text.contains("RELEASED"), "{text}");
}

#[test]
fn a_released_never_touch_path_still_refuses_a_render_in_the_releasing_plan() {
    // The released module protected ci.yml; ci-baseline would seed it: refused, so
    // the owner sees the conflict instead of a write to a path nobody owned.
    let repo = Repo::with_released_module();
    let mut lock = repo.lock();
    lock["files"][".github/workflows/ci.yml"] = json!({"module": GONE, "class": "never-touch"});
    repo.write(
        ".agent-setup/lock.json",
        &(serde_json::to_string_pretty(&lock).unwrap() + "\n"),
    );
    let mut profile: Value =
        serde_json::from_str(&repo.read(".agent-setup/project.json").unwrap()).unwrap();
    profile["commands"]["verify"] = json!("make check");
    repo.write(
        ".agent-setup/project.json",
        &(serde_json::to_string_pretty(&profile).unwrap() + "\n"),
    );
    let out = repo.cli(&[
        "install",
        "<repo>",
        "--module",
        "stack-packs",
        "--module",
        "ci-baseline",
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("path declared never-touch is rendered: .github/workflows/ci.yml"),
        "{out:?}"
    );
}

#[test]
fn unmarking_keeps_everything_but_the_two_marker_lines() {
    assert_eq!(
        brakes::unmark_block(AGENTS_BEFORE).unwrap().as_deref(),
        Some(AGENTS_RELEASED)
    );
    assert_eq!(
        brakes::unmark_block("<!-- brakes:begin -->\nonly\n<!-- brakes:end -->")
            .unwrap()
            .as_deref(),
        Some("only\n")
    );
    assert_eq!(brakes::unmark_block("no block\n").unwrap(), None);
}

#[test]
fn unmarking_refuses_a_marker_sharing_its_line_or_an_incomplete_block() {
    for text in [
        "intro <!-- brakes:begin -->\nrules\n<!-- brakes:end -->\n",
        "<!-- brakes:begin -->\nrules\n<!-- brakes:end --> outro\n",
        "<!-- brakes:begin -->\nrules\n",
        "<!-- brakes:begin -->\na\n<!-- brakes:end -->\n<!-- brakes:begin -->\nb\n<!-- brakes:end -->\n",
    ] {
        assert!(brakes::unmark_block(text).is_err(), "{text:?}");
    }
}

#[test]
fn a_newer_version_compares_part_by_part() {
    assert!(brakes::version_newer("0.10.0", "0.9.9"));
    assert!(brakes::version_newer("v1.0", "0.99.0"));
    assert!(!brakes::version_newer("0.5.1", "0.5.3"));
    assert!(!brakes::version_newer("0.5.3", "0.5.3"));
}
