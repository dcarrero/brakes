//! The ownership matrix (SPEC-engine.md, #653): a fixture module that lives only
//! here renders one path per class under `fixture/`; every class is driven through
//! absent, present unchanged, present edited and present unowned, plus retirement.
mod support;
use brakes::engine::{self, Context, Module, Note, Ownership, Planned, Rendered};
use brakes::*;
use serde_json::{Value, json};
use std::{fs, path::PathBuf, process::Command};
use support::SetupCore;
use tempfile::TempDir;

const MANAGED: &str = "fixture/managed.md";
const BLOCK: &str = "fixture/block.md";
const SEED: &str = "fixture/seed.md";
const NEVER_TOUCH: &str = "fixture/never-touch.md";
const REMOTE: &str = "fixture/remote-setting";

struct FixtureModule;
impl Module for FixtureModule {
    fn id(&self) -> &'static str {
        "fixture"
    }
    fn version(&self) -> &'static str {
        "0.1.0"
    }
    fn render(&self, _cx: &Context<'_>) -> Result<Vec<Rendered>> {
        Ok(vec![
            rendered(MANAGED, Ownership::Managed, Some("managed\n")),
            rendered(BLOCK, Ownership::ManagedBlock, Some(&block("block"))),
            rendered(SEED, Ownership::Seed, Some("seed\n")),
            rendered(NEVER_TOUCH, Ownership::NeverTouch, None),
            rendered(REMOTE, Ownership::Remote, None),
        ])
    }
}

fn rendered(path: &str, class: Ownership, content: Option<&str>) -> Rendered {
    Rendered {
        path: path.to_owned(),
        class,
        content: content.map(str::to_owned),
        scaffold: None,
    }
}
fn block(body: &str) -> String {
    format!("{BEGIN}\n{body}\n{END}")
}

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
        for (name, _) in support::guides() {
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
    fn plan_with(&self, modules: &[&dyn Module]) -> Result<Planned> {
        let source = Source::checkout(&self.source_root)?;
        let profile = profile_for(&self.root)?;
        engine::plan(&self.root, &source, &profile, modules, &|_| true)
    }
    fn plan(&self) -> Planned {
        self.plan_with(&[&SetupCore, &FixtureModule]).unwrap()
    }
    fn refusal(&self, modules: &[&dyn Module]) -> String {
        self.plan_with(modules).unwrap_err().to_string()
    }
    fn apply(&self) -> Planned {
        let planned = self.plan();
        apply(&self.root, &planned.changes).unwrap();
        planned
    }
    fn write(&self, name: &str, text: &str) {
        let path = self.root.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
    fn read(&self, name: &str) -> String {
        fs::read_to_string(self.root.join(name)).unwrap()
    }
    fn exists(&self, name: &str) -> bool {
        self.root.join(name).exists()
    }
    fn lock(&self) -> Value {
        serde_json::from_str(&self.read(LOCK)).unwrap()
    }
    fn remove(&self, modules: &[&dyn Module], id: &str) -> Result<Planned> {
        engine::remove(&self.root, modules, &|_| true, id)
    }
    fn remove_refusal(&self, modules: &[&dyn Module], id: &str) -> String {
        self.remove(modules, id).unwrap_err().to_string()
    }
}

/// The plan has no write or delete for the fixture paths.
fn fixture_changes(planned: &Planned) -> Vec<(&String, &Option<String>)> {
    planned
        .changes
        .iter()
        .filter(|(path, _)| path.starts_with("fixture/"))
        .collect()
}

// ---- seed ---------------------------------------------------------------------

#[test]
fn seed_absent_is_written_and_recorded_without_digest() {
    let f = Fixture::new();
    let planned = f.plan();
    assert_eq!(planned.changes[SEED], Some("seed\n".to_owned()));
    assert_eq!(planned.tags[SEED], (Ownership::Seed, "fixture".to_owned()));
    assert!(planned.notes.is_empty());
    apply(&f.root, &planned.changes).unwrap();
    assert_eq!(f.read(SEED), "seed\n");
    assert_eq!(
        f.lock()["files"][SEED],
        json!({"module": "fixture", "class": "seed"})
    );
}

#[test]
fn seed_present_unchanged_is_skipped_not_rewritten() {
    let f = Fixture::new();
    f.apply();
    let planned = f.plan();
    assert!(planned.changes.is_empty(), "{:?}", planned.changes.keys());
    assert_eq!(planned.notes[SEED], Note::Skip);
    assert_eq!(planned.tags[SEED], (Ownership::Seed, "fixture".to_owned()));
}

#[test]
fn seed_present_edited_is_skipped_and_kept() {
    let f = Fixture::new();
    f.apply();
    f.write(SEED, "my own compose\n");
    let planned = f.apply();
    assert!(planned.changes.is_empty(), "{:?}", planned.changes.keys());
    assert_eq!(planned.notes[SEED], Note::Skip);
    assert_eq!(f.read(SEED), "my own compose\n");
}

#[test]
fn seed_present_unowned_is_skipped_recorded_and_left_alone() {
    let f = Fixture::new();
    f.write(SEED, "project-owned\n");
    let planned = f.apply();
    assert!(!planned.changes.contains_key(SEED));
    assert_eq!(planned.notes[SEED], Note::Skip);
    assert_eq!(f.read(SEED), "project-owned\n");
    assert_eq!(
        f.lock()["files"][SEED],
        json!({"module": "fixture", "class": "seed"})
    );
}

#[test]
fn seed_without_content_is_refused() {
    struct Empty;
    impl Module for Empty {
        fn id(&self) -> &'static str {
            "empty-seed"
        }
        fn version(&self) -> &'static str {
            "0.1.0"
        }
        fn render(&self, _cx: &Context<'_>) -> Result<Vec<Rendered>> {
            Ok(vec![rendered("fixture/empty", Ownership::Seed, None)])
        }
    }
    let f = Fixture::new();
    assert_eq!(
        f.refusal(&[&Empty]),
        "Module empty-seed: ownership class seed requires content: fixture/empty"
    );
}

// ---- idempotence and determinism ---------------------------------------------

#[test]
fn plan_apply_plan_is_empty_for_the_fixture_module() {
    let f = Fixture::new();
    f.apply();
    let planned = f.plan();
    assert!(planned.changes.is_empty(), "{:?}", planned.changes.keys());
    assert!(fixture_changes(&planned).is_empty());
}

#[test]
fn two_renders_of_the_same_inputs_are_byte_identical() {
    let f = Fixture::new();
    let first = f.plan();
    let second = f.plan();
    assert_eq!(first.changes, second.changes);
    assert_eq!(first.changes[LOCK], second.changes[LOCK]);
    f.apply();
    let before = f.read(LOCK);
    f.apply();
    assert_eq!(f.read(LOCK), before);
}

// ---- never-touch ---------------------------------------------------------------

/// Renders managed content at the path the fixture module declares never-touch.
struct Intruder;
impl Module for Intruder {
    fn id(&self) -> &'static str {
        "intruder"
    }
    fn version(&self) -> &'static str {
        "0.1.0"
    }
    fn render(&self, _cx: &Context<'_>) -> Result<Vec<Rendered>> {
        Ok(vec![rendered(
            NEVER_TOUCH,
            Ownership::Managed,
            Some("overwritten\n"),
        )])
    }
}

#[test]
fn never_touch_absent_is_recorded_without_digest_and_never_written() {
    let f = Fixture::new();
    let planned = f.apply();
    assert!(!planned.changes.contains_key(NEVER_TOUCH));
    assert!(!planned.notes.contains_key(NEVER_TOUCH));
    assert_eq!(
        planned.tags[NEVER_TOUCH],
        (Ownership::NeverTouch, "fixture".to_owned())
    );
    assert!(!f.exists(NEVER_TOUCH));
    assert_eq!(
        f.lock()["files"][NEVER_TOUCH],
        json!({"module": "fixture", "class": "never-touch"})
    );
}

#[test]
fn never_touch_present_in_any_state_is_left_alone() {
    // Unowned before the first install, then unchanged, then edited: never a line, never a write.
    let f = Fixture::new();
    f.write(NEVER_TOUCH, "project secrets\n");
    let planned = f.apply();
    assert!(!planned.changes.contains_key(NEVER_TOUCH));
    assert!(!planned.notes.contains_key(NEVER_TOUCH));
    assert_eq!(f.read(NEVER_TOUCH), "project secrets\n");
    let planned = f.apply();
    assert!(!planned.changes.contains_key(NEVER_TOUCH));
    f.write(NEVER_TOUCH, "edited secrets\n");
    let planned = f.apply();
    assert!(planned.changes.is_empty(), "{:?}", planned.changes.keys());
    assert_eq!(f.read(NEVER_TOUCH), "edited secrets\n");
    assert_eq!(
        f.lock()["files"][NEVER_TOUCH],
        json!({"module": "fixture", "class": "never-touch"})
    );
}

#[test]
fn never_touch_rendered_by_another_module_is_refused_in_either_order() {
    let f = Fixture::new();
    let expected = "Module intruder: path declared never-touch is rendered: fixture/never-touch.md";
    assert_eq!(f.refusal(&[&FixtureModule, &Intruder]), expected);
    assert_eq!(f.refusal(&[&Intruder, &FixtureModule]), expected);
    assert!(!f.exists(NEVER_TOUCH));
}

#[test]
fn never_touch_declared_with_content_is_refused() {
    struct Leaky;
    impl Module for Leaky {
        fn id(&self) -> &'static str {
            "leaky"
        }
        fn version(&self) -> &'static str {
            "0.1.0"
        }
        fn render(&self, _cx: &Context<'_>) -> Result<Vec<Rendered>> {
            Ok(vec![rendered(
                "fixture/protected",
                Ownership::NeverTouch,
                Some("content\n"),
            )])
        }
    }
    let f = Fixture::new();
    assert_eq!(
        f.refusal(&[&Leaky]),
        "Module leaky: path declared never-touch is rendered: fixture/protected"
    );
}

// ---- remote ----------------------------------------------------------------------

#[test]
fn remote_is_recorded_without_digest_and_prints_nothing() {
    let f = Fixture::new();
    let planned = f.apply();
    assert!(!planned.changes.contains_key(REMOTE));
    assert!(!planned.notes.contains_key(REMOTE));
    assert_eq!(
        planned.tags[REMOTE],
        (Ownership::Remote, "fixture".to_owned())
    );
    assert!(!f.exists(REMOTE));
    assert_eq!(
        f.lock()["files"][REMOTE],
        json!({"module": "fixture", "class": "remote"})
    );
    // A local file at the remote path is not the engine's business.
    f.write(REMOTE, "local note\n");
    let planned = f.apply();
    assert!(planned.changes.is_empty(), "{:?}", planned.changes.keys());
    assert_eq!(f.read(REMOTE), "local note\n");
}

#[test]
fn remote_declared_with_content_is_refused() {
    struct Pushy;
    impl Module for Pushy {
        fn id(&self) -> &'static str {
            "pushy"
        }
        fn version(&self) -> &'static str {
            "0.1.0"
        }
        fn render(&self, _cx: &Context<'_>) -> Result<Vec<Rendered>> {
            Ok(vec![rendered(
                "rulesets/main",
                Ownership::Remote,
                Some("{}\n"),
            )])
        }
    }
    let f = Fixture::new();
    assert_eq!(
        f.refusal(&[&Pushy]),
        "Module pushy: ownership class remote carries no content: rulesets/main"
    );
}

// ---- retire ------------------------------------------------------------------------

/// The fixture module, a version later, keeps only its managed block: the other four
/// paths are retired.
struct Shrunk;
impl Module for Shrunk {
    fn id(&self) -> &'static str {
        "fixture"
    }
    fn version(&self) -> &'static str {
        "0.2.0"
    }
    fn render(&self, _cx: &Context<'_>) -> Result<Vec<Rendered>> {
        Ok(vec![rendered(
            BLOCK,
            Ownership::ManagedBlock,
            Some(&block("block")),
        )])
    }
}

#[test]
fn retiring_deletes_unchanged_managed_keeps_seed_and_remote_and_drops_lock_entries() {
    let f = Fixture::new();
    f.apply();
    let planned = f.plan_with(&[&SetupCore, &Shrunk]).unwrap();
    assert_eq!(planned.changes[MANAGED], None);
    assert_eq!(planned.notes[SEED], Note::Keep);
    assert_eq!(planned.notes[REMOTE], Note::Keep);
    assert!(
        !planned.notes.contains_key(NEVER_TOUCH),
        "absent: nothing to keep"
    );
    assert!(!planned.changes.contains_key(SEED));
    assert_eq!(planned.tags[SEED], (Ownership::Seed, "fixture".to_owned()));
    assert_eq!(
        planned.tags[REMOTE],
        (Ownership::Remote, "fixture".to_owned())
    );
    apply(&f.root, &planned.changes).unwrap();
    assert!(!f.exists(MANAGED));
    assert_eq!(f.read(SEED), "seed\n");
    let files = f.lock()["files"].clone();
    for path in [MANAGED, SEED, NEVER_TOUCH, REMOTE] {
        assert!(files.get(path).is_none(), "{path}");
    }
    assert_eq!(files[BLOCK]["class"], "managed-block");
    assert_eq!(f.lock()["modules"]["fixture"]["version"], "0.2.0");
    let again = f.plan_with(&[&SetupCore, &Shrunk]).unwrap();
    assert!(again.changes.is_empty(), "{:?}", again.changes.keys());
    assert!(again.notes.is_empty());
}

#[test]
fn retired_never_touch_present_is_kept() {
    let f = Fixture::new();
    f.write(NEVER_TOUCH, "project secrets\n");
    f.apply();
    let planned = f.plan_with(&[&SetupCore, &Shrunk]).unwrap();
    assert_eq!(planned.notes[NEVER_TOUCH], Note::Keep);
    assert!(!planned.changes.contains_key(NEVER_TOUCH));
    apply(&f.root, &planned.changes).unwrap();
    assert_eq!(f.read(NEVER_TOUCH), "project secrets\n");
    assert!(f.lock()["files"].get(NEVER_TOUCH).is_none());
}

#[test]
fn retired_seed_absent_is_forgotten_silently() {
    let f = Fixture::new();
    f.apply();
    fs::remove_file(f.root.join(SEED)).unwrap();
    let planned = f.plan_with(&[&SetupCore, &Shrunk]).unwrap();
    assert!(!planned.notes.contains_key(SEED));
    assert!(!planned.changes.contains_key(SEED));
    apply(&f.root, &planned.changes).unwrap();
    assert!(f.lock()["files"].get(SEED).is_none());
}

#[test]
fn retired_edited_managed_is_still_refused() {
    let f = Fixture::new();
    f.apply();
    f.write(MANAGED, "edited\n");
    assert_eq!(
        f.refusal(&[&SetupCore, &Shrunk]),
        "Locally changed retired managed content: fixture/managed.md; restore it or move it out of docs/agent-setup/"
    );
}

// ---- remove (#658) -----------------------------------------------------------------------

const ANSWERS: &str = ".agent-setup/modules/fixture.json";

/// The fixture module installed with an answers file; `setup-core` beside it.
fn installed_with_answers() -> Fixture {
    let f = Fixture::new();
    f.write(
        ANSWERS,
        "{\n  \"module\": \"fixture\",\n  \"version\": \"0.1.0\",\n  \"answers\": {}\n}\n",
    );
    f.apply();
    assert_eq!(
        f.lock()["modules"]["fixture"]["answers_digest"],
        json!(digest(&f.read(ANSWERS)))
    );
    f
}

#[test]
fn remove_plans_deletions_keeps_seed_and_remote_and_drops_lock_entries_and_answers() {
    let f = installed_with_answers();
    let lock_before = f.read(LOCK);
    let planned = f.remove(&[&SetupCore, &FixtureModule], "fixture").unwrap();
    assert_eq!(planned.changes[MANAGED], None);
    // The block was the whole file: nothing else to keep, the file goes.
    assert_eq!(planned.changes[BLOCK], None);
    assert_eq!(planned.changes[ANSWERS], None);
    assert_eq!(planned.answers[ANSWERS], "fixture");
    assert!(planned.changes.contains_key(LOCK));
    assert_eq!(planned.notes[SEED], Note::Keep);
    assert_eq!(planned.notes[REMOTE], Note::Keep);
    assert!(
        !planned.notes.contains_key(NEVER_TOUCH),
        "absent: nothing to keep"
    );
    assert!(!planned.changes.contains_key(SEED));
    for (path, class) in [
        (MANAGED, Ownership::Managed),
        (BLOCK, Ownership::ManagedBlock),
        (SEED, Ownership::Seed),
        (REMOTE, Ownership::Remote),
    ] {
        assert_eq!(planned.tags[path], (class, "fixture".to_owned()), "{path}");
    }
    assert!(planned.steps.is_empty());
    // Plan only: nothing was written.
    assert_eq!(f.read(MANAGED), "managed\n");
    assert_eq!(f.read(LOCK), lock_before);
    assert!(f.exists(ANSWERS));

    apply(&f.root, &planned.changes).unwrap();
    assert!(!f.exists(MANAGED));
    assert!(!f.exists(BLOCK));
    assert!(!f.exists(ANSWERS));
    assert_eq!(f.read(SEED), "seed\n");
    let lock = f.lock();
    assert!(lock["modules"].get("fixture").is_none());
    assert!(lock["modules"].get("setup-core").is_some());
    for path in [MANAGED, BLOCK, SEED, NEVER_TOUCH, REMOTE] {
        assert!(lock["files"].get(path).is_none(), "{path}");
    }
    assert!(
        lock["files"]
            .as_object()
            .unwrap()
            .values()
            .all(|entry| entry["module"] == "setup-core")
    );
    assert_eq!(lock["schema"], 2);
    // The repository is as if the module had never been installed: a re-install
    // plans the module afresh and refuses nothing.
    let again = f.plan();
    assert_eq!(again.changes[MANAGED], Some("managed\n".to_owned()));
    assert_eq!(again.notes[SEED], Note::Skip);
}

#[test]
fn remove_strips_the_block_and_keeps_the_rest_of_a_foreign_file() {
    let f = Fixture::new();
    f.write(BLOCK, "# Mine\n\nkept paragraph\n");
    f.apply();
    assert_eq!(
        f.read(BLOCK),
        format!("# Mine\n\nkept paragraph\n\n{}\n", block("block"))
    );
    let planned = f.remove(&[&SetupCore, &FixtureModule], "fixture").unwrap();
    assert_eq!(
        planned.changes[BLOCK],
        Some("# Mine\n\nkept paragraph\n".to_owned())
    );
    assert_eq!(
        planned.tags[BLOCK],
        (Ownership::ManagedBlock, "fixture".to_owned())
    );
    apply(&f.root, &planned.changes).unwrap();
    assert_eq!(f.read(BLOCK), "# Mine\n\nkept paragraph\n");
    assert!(f.lock()["files"].get(BLOCK).is_none());
}

#[test]
fn remove_refuses_an_edited_managed_file_before_any_write() {
    for (path, edited) in [
        (MANAGED, "edited\n".to_owned()),
        (BLOCK, format!("# Mine\n\n{}\n", block("edited"))),
    ] {
        let f = installed_with_answers();
        let lock_before = f.read(LOCK);
        f.write(path, &edited);
        assert_eq!(
            f.remove_refusal(&[&SetupCore, &FixtureModule], "fixture"),
            format!(
                "Locally changed managed content of module fixture: {path}; restore it before removing the module"
            )
        );
        assert_eq!(f.read(path), edited);
        assert!(f.exists(MANAGED));
        assert!(f.exists(BLOCK));
        assert!(f.exists(ANSWERS));
        assert_eq!(f.read(LOCK), lock_before);
    }
}

#[test]
fn remove_forgets_absent_managed_and_seed_paths_silently() {
    let f = Fixture::new();
    f.apply();
    fs::remove_file(f.root.join(MANAGED)).unwrap();
    fs::remove_file(f.root.join(SEED)).unwrap();
    let planned = f.remove(&[&SetupCore, &FixtureModule], "fixture").unwrap();
    assert!(!planned.changes.contains_key(MANAGED));
    assert!(!planned.notes.contains_key(MANAGED));
    assert!(!planned.notes.contains_key(SEED));
    assert!(
        !planned.changes.contains_key(ANSWERS),
        "no answers file: nothing to delete"
    );
    assert!(planned.answers.is_empty());
    apply(&f.root, &planned.changes).unwrap();
    assert!(f.lock()["files"].get(MANAGED).is_none());
    assert!(f.lock()["files"].get(SEED).is_none());
}

#[test]
fn remove_keeps_a_present_never_touch_path() {
    let f = Fixture::new();
    f.write(NEVER_TOUCH, "project secrets\n");
    f.apply();
    let planned = f.remove(&[&SetupCore, &FixtureModule], "fixture").unwrap();
    assert_eq!(planned.notes[NEVER_TOUCH], Note::Keep);
    assert!(!planned.changes.contains_key(NEVER_TOUCH));
    apply(&f.root, &planned.changes).unwrap();
    assert_eq!(f.read(NEVER_TOUCH), "project secrets\n");
    assert!(f.lock()["files"].get(NEVER_TOUCH).is_none());
}

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "asserts setup-core's own content or id; product-boundary T7b"
)]
#[test]
fn remove_setup_core_is_refused() {
    let f = Fixture::new();
    f.apply();
    let lock_before = f.read(LOCK);
    assert_eq!(
        f.remove_refusal(&[&SetupCore, &FixtureModule], "setup-core"),
        "Cannot remove setup-core: it is the installer's own content"
    );
    assert_eq!(f.read(LOCK), lock_before);
    assert!(f.exists("AGENTS.md"));
}

#[test]
fn remove_unknown_id_is_refused_naming_it() {
    let f = Fixture::new();
    f.apply();
    assert_eq!(
        f.remove_refusal(&[&SetupCore, &FixtureModule], "nope"),
        "Unknown module id: nope"
    );
    // Without a lock the id is still checked first.
    let fresh = Fixture::new();
    assert_eq!(
        fresh.remove_refusal(&[&SetupCore, &FixtureModule], "nope"),
        "Unknown module id: nope"
    );
}

#[test]
fn remove_twice_refuses_as_not_installed() {
    let f = Fixture::new();
    f.apply();
    let planned = f.remove(&[&SetupCore, &FixtureModule], "fixture").unwrap();
    apply(&f.root, &planned.changes).unwrap();
    assert_eq!(
        f.remove_refusal(&[&SetupCore, &FixtureModule], "fixture"),
        "Module fixture is not installed; nothing to remove"
    );
    // A compiled module never installed, and a repository without a lock, say the same.
    let fresh = Fixture::new();
    assert_eq!(
        fresh.remove_refusal(&[&SetupCore, &FixtureModule], "fixture"),
        "Module fixture is not installed; nothing to remove"
    );
    assert!(!fresh.exists(LOCK));
}

#[test]
fn remove_works_for_a_module_recorded_in_the_lock_but_no_longer_compiled() {
    // The undo must not depend on the module still being in the registry.
    let f = installed_with_answers();
    let planned = f.remove(&[&SetupCore], "fixture").unwrap();
    assert_eq!(planned.changes[MANAGED], None);
    assert_eq!(planned.changes[ANSWERS], None);
    assert_eq!(planned.notes[SEED], Note::Keep);
    apply(&f.root, &planned.changes).unwrap();
    assert!(f.lock()["modules"].get("fixture").is_none());
    assert!(!f.exists(ANSWERS));
}

// ---- ownership conflicts -------------------------------------------------------------

#[test]
fn a_path_recorded_for_another_module_is_refused_for_every_class() {
    // The other owner is a module this build ships, not active in this plan. A module
    // this build does not ship is released instead (#48, tests/engine_release.rs).
    for path in [MANAGED, BLOCK, SEED, NEVER_TOUCH, REMOTE] {
        let f = Fixture::new();
        f.apply();
        let mut lock = f.lock();
        lock["files"][path]["module"] = json!("qa");
        f.write(LOCK, &serde_json::to_string(&lock).unwrap());
        assert_eq!(
            f.refusal(&[&SetupCore, &FixtureModule]),
            format!("Managed destination owned by module qa: {path}")
        );
    }
}

// ---- managed and managed-block (the rows T2 already honours) -----------------------

#[test]
fn managed_absent_is_written_with_digest() {
    let f = Fixture::new();
    let planned = f.apply();
    assert_eq!(planned.changes[MANAGED], Some("managed\n".to_owned()));
    assert_eq!(
        planned.tags[MANAGED],
        (Ownership::Managed, "fixture".to_owned())
    );
    assert_eq!(
        f.lock()["files"][MANAGED],
        json!({"module": "fixture", "class": "managed", "digest": digest("managed\n")})
    );
}

#[test]
fn managed_present_unchanged_plans_nothing() {
    let f = Fixture::new();
    f.apply();
    let planned = f.plan();
    assert!(!planned.changes.contains_key(MANAGED));
    assert!(!planned.notes.contains_key(MANAGED));
}

#[test]
fn managed_present_edited_is_refused() {
    let f = Fixture::new();
    f.apply();
    f.write(MANAGED, "edited\n");
    assert_eq!(
        f.refusal(&[&SetupCore, &FixtureModule]),
        "Locally changed or missing managed content: fixture/managed.md"
    );
    assert_eq!(f.read(MANAGED), "edited\n");
}

#[test]
fn managed_present_unowned_is_refused() {
    let f = Fixture::new();
    f.write(MANAGED, "project-owned\n");
    assert_eq!(
        f.refusal(&[&SetupCore, &FixtureModule]),
        "Unowned managed destination: fixture/managed.md"
    );
}

#[test]
fn managed_block_absent_creates_the_file_with_the_block() {
    let f = Fixture::new();
    let planned = f.apply();
    assert_eq!(
        planned.changes[BLOCK],
        Some(format!("{}\n", block("block")))
    );
    assert_eq!(
        f.lock()["files"][BLOCK],
        json!({"module": "fixture", "class": "managed-block", "digest": digest(&block("block"))})
    );
}

#[test]
fn managed_block_present_unchanged_plans_nothing() {
    let f = Fixture::new();
    f.apply();
    let planned = f.plan();
    assert!(!planned.changes.contains_key(BLOCK));
    assert!(!planned.notes.contains_key(BLOCK));
}

#[test]
fn managed_block_present_edited_is_refused() {
    let f = Fixture::new();
    f.apply();
    f.write(BLOCK, &format!("# Mine\n\n{}\n", block("edited")));
    assert_eq!(
        f.refusal(&[&SetupCore, &FixtureModule]),
        "Locally changed or missing managed content: fixture/block.md"
    );
}

#[test]
fn managed_block_present_unowned_block_is_refused_and_foreign_file_gets_the_block() {
    let f = Fixture::new();
    f.write(BLOCK, &format!("# Mine\n\n{}\n", block("foreign")));
    assert_eq!(
        f.refusal(&[&SetupCore, &FixtureModule]),
        "Unowned managed destination: fixture/block.md"
    );
    f.write(BLOCK, "# Mine\n");
    let planned = f.apply();
    assert_eq!(
        planned.changes[BLOCK],
        Some(format!("# Mine\n\n{}\n", block("block")))
    );
    assert!(f.plan().changes.is_empty());
}

// ---- managed-block scaffold (#703) ------------------------------------------------------

const SCAFFOLDED: &str = "fixture/scaffolded.md";

/// Renders one managed block with the skeleton the engine writes around it when
/// the file is absent; `class` and `scaffold` vary to reach the refusals.
struct ScaffoldModule {
    class: Ownership,
    scaffold: String,
}
impl ScaffoldModule {
    fn around_the_block() -> Self {
        Self {
            class: Ownership::ManagedBlock,
            scaffold: format!("Summary:\n\n{}\n\nNotes.\n", block("block")),
        }
    }
}
impl Module for ScaffoldModule {
    fn id(&self) -> &'static str {
        "scaffold"
    }
    fn version(&self) -> &'static str {
        "0.1.0"
    }
    fn render(&self, _cx: &Context<'_>) -> Result<Vec<Rendered>> {
        Ok(vec![Rendered {
            scaffold: Some(self.scaffold.clone()),
            ..rendered(SCAFFOLDED, self.class, Some(&block("block")))
        }])
    }
}

#[test]
fn scaffold_is_written_when_the_managed_block_file_is_absent() {
    let f = Fixture::new();
    let module = ScaffoldModule::around_the_block();
    let planned = f.plan_with(&[&SetupCore, &module]).unwrap();
    assert_eq!(
        planned.changes[SCAFFOLDED],
        Some(format!("Summary:\n\n{}\n\nNotes.\n", block("block")))
    );
    apply(&f.root, &planned.changes).unwrap();
    // The lock pins the block, not the skeleton: the skeleton is the project's.
    assert_eq!(
        f.lock()["files"][SCAFFOLDED],
        json!({"module": "scaffold", "class": "managed-block", "digest": digest(&block("block"))})
    );
    assert!(
        f.plan_with(&[&SetupCore, &module])
            .unwrap()
            .changes
            .is_empty()
    );
    f.write(
        SCAFFOLDED,
        &format!("Summary: mine\n\n{}\n\nNotes: mine.\n", block("block")),
    );
    assert!(
        f.plan_with(&[&SetupCore, &module])
            .unwrap()
            .changes
            .is_empty()
    );
}

#[test]
fn scaffold_is_ignored_when_the_file_is_present() {
    let f = Fixture::new();
    f.write(SCAFFOLDED, "# Mine\n");
    let module = ScaffoldModule::around_the_block();
    let planned = f.plan_with(&[&SetupCore, &module]).unwrap();
    assert_eq!(
        planned.changes[SCAFFOLDED],
        Some(format!("# Mine\n\n{}\n", block("block")))
    );
}

#[test]
fn scaffold_without_its_block_is_refused() {
    let f = Fixture::new();
    for scaffold in [
        "Summary:\n".to_owned(),
        format!("{}\n", block("other")),
        format!("{}\n{}\n", block("block"), block("block")),
    ] {
        let module = ScaffoldModule {
            scaffold,
            ..ScaffoldModule::around_the_block()
        };
        assert_eq!(
            f.refusal(&[&SetupCore, &module]),
            "Module scaffold: the scaffold must contain its managed block once: fixture/scaffolded.md"
        );
    }
    assert!(!f.exists(SCAFFOLDED));
}

#[test]
fn scaffold_on_a_class_other_than_managed_block_is_refused() {
    let f = Fixture::new();
    for class in [Ownership::Managed, Ownership::Seed] {
        let module = ScaffoldModule {
            class,
            ..ScaffoldModule::around_the_block()
        };
        assert_eq!(
            f.refusal(&[&SetupCore, &module]),
            format!(
                "Module scaffold: ownership class {class} takes no scaffold: fixture/scaffolded.md"
            )
        );
    }
}

// ---- doctor ---------------------------------------------------------------------------

#[test]
fn doctor_reports_drift_for_managed_only_never_for_a_seed_without_digest() {
    let f = Fixture::new();
    f.apply();
    f.write(SEED, "my own compose\n");
    f.write(NEVER_TOUCH, "project secrets\n");
    let today = today();
    let findings = doctor_at(&f.root, today).unwrap();
    for path in [SEED, NEVER_TOUCH, REMOTE] {
        assert!(findings.iter().all(|s| !s.contains(path)), "{findings:?}");
    }
    assert!(
        !findings
            .iter()
            .any(|f| f.starts_with(&format!("Managed content drift: {MANAGED}")))
    );
    f.write(MANAGED, "edited\n");
    let findings = doctor_at(&f.root, today).unwrap();
    assert!(findings.contains(&format!(
        "Managed content drift: {MANAGED} (module fixture)"
    )));
    assert!(findings.iter().all(|s| !s.contains(SEED)), "{findings:?}");
}

// ---- plan lines -----------------------------------------------------------------------

#[test]
fn notes_print_as_the_skip_and_keep_verbs() {
    assert_eq!(Note::Skip.to_string(), "SKIP");
    assert_eq!(Note::Keep.to_string(), "KEEP");
}

// ---- managed-entries (#747) -----------------------------------------------------------

const SETTINGS: &str = ".claude/settings.json";
/// A project's own settings file with no installer entries in it: hooks the installer
/// must never touch. A frozen copy of this repository's file from before it installed
/// `agent-guardrails`, whose managed entries would collide with `fragment()` (#1158).
const REPO_SETTINGS: &str = include_str!("fixtures/engine/project-settings.json");
const STOP_COMMAND: &str = "sh \"$CLAUDE_PROJECT_DIR/fixture/stop.sh\"";

fn stop_entry(timeout: u64) -> Value {
    json!({ "hooks": [ { "type": "command", "command": STOP_COMMAND, "timeout": timeout } ] })
}
fn fragment() -> Value {
    json!({
        "permissions": { "deny": ["Read(./**/.env)", "Edit(./fixture/lock.json)"] },
        "hooks": { "Stop": [ stop_entry(630) ] }
    })
}
fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap() + "\n"
}
fn repo_settings() -> Value {
    serde_json::from_str(REPO_SETTINGS).unwrap()
}

/// Renders `fragment()` as the managed entries of `.claude/settings.json`.
struct Entries;
impl Module for Entries {
    fn id(&self) -> &'static str {
        "entries"
    }
    fn version(&self) -> &'static str {
        "0.1.0"
    }
    fn render(&self, _cx: &Context<'_>) -> Result<Vec<Rendered>> {
        Ok(vec![rendered(
            SETTINGS,
            Ownership::ManagedEntries,
            Some(&pretty(&fragment())),
        )])
    }
}
/// 0.2.0 keeps one deny rule and drops the hook and the other rule.
struct FewerEntries;
impl Module for FewerEntries {
    fn id(&self) -> &'static str {
        "entries"
    }
    fn version(&self) -> &'static str {
        "0.2.0"
    }
    fn render(&self, _cx: &Context<'_>) -> Result<Vec<Rendered>> {
        Ok(vec![rendered(
            SETTINGS,
            Ownership::ManagedEntries,
            Some(&pretty(
                &json!({"permissions": {"deny": ["Read(./**/.env)"]}}),
            )),
        )])
    }
}
/// 0.3.0 renders nothing: the path is retired.
struct NoEntries;
impl Module for NoEntries {
    fn id(&self) -> &'static str {
        "entries"
    }
    fn version(&self) -> &'static str {
        "0.3.0"
    }
    fn render(&self, _cx: &Context<'_>) -> Result<Vec<Rendered>> {
        Ok(Vec::new())
    }
}
/// A module whose fragment is the given text, for the shape refusals.
struct Fragment(&'static str);
impl Module for Fragment {
    fn id(&self) -> &'static str {
        "bad"
    }
    fn version(&self) -> &'static str {
        "0.1.0"
    }
    fn render(&self, _cx: &Context<'_>) -> Result<Vec<Rendered>> {
        Ok(vec![rendered(
            "fixture/x.json",
            Ownership::ManagedEntries,
            Some(self.0),
        )])
    }
}

impl Fixture {
    fn entries_plan(&self) -> Planned {
        self.plan_with(&[&SetupCore, &Entries]).unwrap()
    }
    fn entries_apply(&self) -> Planned {
        let planned = self.entries_plan();
        apply(&self.root, &planned.changes).unwrap();
        planned
    }
    fn settings(&self) -> Value {
        serde_json::from_str(&self.read(SETTINGS)).unwrap()
    }
    fn write_settings(&self, value: &Value) {
        self.write(SETTINGS, &pretty(value));
    }
}

#[test]
fn entries_file_absent_is_created_with_the_entries_alone() {
    let f = Fixture::new();
    let planned = f.entries_plan();
    assert_eq!(planned.changes[SETTINGS], Some(pretty(&fragment())));
    assert_eq!(
        planned.tags[SETTINGS],
        (Ownership::ManagedEntries, "entries".to_owned())
    );
    apply(&f.root, &planned.changes).unwrap();
    assert_eq!(f.settings(), fragment());
    assert_eq!(
        f.lock()["files"][SETTINGS],
        json!({
            "module": "entries",
            "class": "managed-entries",
            "digest": digest(&pretty(&fragment())),
            "entries": fragment()
        })
    );
}

#[test]
fn entries_file_without_them_gains_them_after_the_projects_own() {
    let f = Fixture::new();
    f.write(SETTINGS, REPO_SETTINGS);
    let before = repo_settings();
    let planned = f.entries_apply();
    assert!(planned.changes.contains_key(SETTINGS));
    let after = f.settings();
    assert_eq!(
        after["hooks"]["SessionStart"],
        before["hooks"]["SessionStart"]
    );
    assert_eq!(after["hooks"]["PreToolUse"], before["hooks"]["PreToolUse"]);
    assert_eq!(after["hooks"]["Stop"][0], before["hooks"]["Stop"][0]);
    assert_eq!(after["hooks"]["Stop"][1], stop_entry(630));
    assert_eq!(after["hooks"]["Stop"].as_array().unwrap().len(), 2);
    // The repository's own `ask` entry (#1146) stays; the owned deny rules join it.
    assert_eq!(
        after["permissions"]["deny"],
        fragment()["permissions"]["deny"]
    );
    assert_eq!(after["permissions"]["ask"], before["permissions"]["ask"]);
    assert_eq!(after["permissions"].as_object().unwrap().len(), 2);
    let again = f.entries_plan();
    assert!(again.changes.is_empty(), "{:?}", again.changes.keys());
}

#[test]
fn entries_present_unchanged_plan_nothing_and_never_rewrite_the_file() {
    let f = Fixture::new();
    // Merged by hand (#744): other key order and indentation, beside the project's own rule.
    let by_hand = r#"{
    "permissions": {"deny": ["Bash(rm:*)", "Edit(./fixture/lock.json)", "Read(./**/.env)"]},
    "hooks": {"Stop": [{"hooks": [{"timeout": 630, "type": "command", "command": "sh \"$CLAUDE_PROJECT_DIR/fixture/stop.sh\""}]}]}
}
"#;
    f.write(SETTINGS, by_hand);
    let planned = f.entries_plan();
    assert!(
        !planned.changes.contains_key(SETTINGS),
        "{:?}",
        planned.changes.keys()
    );
    assert_eq!(
        planned.tags[SETTINGS],
        (Ownership::ManagedEntries, "entries".to_owned())
    );
    apply(&f.root, &planned.changes).unwrap();
    assert_eq!(f.read(SETTINGS), by_hand);
    assert_eq!(f.lock()["files"][SETTINGS]["class"], "managed-entries");
    let again = f.entries_plan();
    assert!(again.changes.is_empty(), "{:?}", again.changes.keys());
}

#[test]
fn entries_owned_hook_entry_edited_is_refused_by_its_command() {
    let f = Fixture::new();
    f.write(SETTINGS, REPO_SETTINGS);
    f.entries_apply();
    let mut settings = f.settings();
    settings["hooks"]["Stop"][1] = stop_entry(600);
    f.write_settings(&settings);
    assert_eq!(
        f.refusal(&[&SetupCore, &Entries]),
        format!("Locally changed managed entry: {SETTINGS} at /hooks/Stop ({STOP_COMMAND})")
    );
}

#[test]
fn entries_edited_rule_reads_as_deleted_and_is_re_added_beside_the_foreign_one() {
    let f = Fixture::new();
    f.entries_apply();
    let mut settings = f.settings();
    settings["permissions"]["deny"][0] = json!("Read(./**/.env.local)");
    f.write_settings(&settings);
    let planned = f.entries_apply();
    assert!(planned.changes.contains_key(SETTINGS));
    assert_eq!(
        f.settings()["permissions"]["deny"],
        json!([
            "Read(./**/.env.local)",
            "Edit(./fixture/lock.json)",
            "Read(./**/.env)"
        ])
    );
}

#[test]
fn entries_foreign_entries_are_kept_and_the_owned_ones_added_after_them() {
    let f = Fixture::new();
    f.write_settings(&json!({
        "permissions": {"deny": ["Bash(rm:*)"], "allow": ["Bash(git:*)"]},
        "hooks": {"Stop": [{"hooks": [{"type": "command", "command": "echo bye"}]}]},
        "model": "opus"
    }));
    f.entries_apply();
    let after = f.settings();
    assert_eq!(after["model"], "opus");
    assert_eq!(after["permissions"]["allow"], json!(["Bash(git:*)"]));
    assert_eq!(
        after["permissions"]["deny"],
        json!(["Bash(rm:*)", "Read(./**/.env)", "Edit(./fixture/lock.json)"])
    );
    assert_eq!(after["hooks"]["Stop"][0]["hooks"][0]["command"], "echo bye");
    assert_eq!(after["hooks"]["Stop"][1], stop_entry(630));
    let again = f.entries_plan();
    assert!(again.changes.is_empty(), "{:?}", again.changes.keys());
}

#[test]
fn entries_deleted_owned_entry_is_re_added_in_the_next_plan() {
    let f = Fixture::new();
    f.write(SETTINGS, REPO_SETTINGS);
    f.entries_apply();
    let mut settings = f.settings();
    settings["permissions"]["deny"]
        .as_array_mut()
        .unwrap()
        .remove(0);
    settings["hooks"]["Stop"].as_array_mut().unwrap().remove(1);
    f.write_settings(&settings);
    let planned = f.entries_apply();
    assert!(planned.changes.contains_key(SETTINGS));
    let after = f.settings();
    assert_eq!(
        after["permissions"]["deny"],
        json!(["Edit(./fixture/lock.json)", "Read(./**/.env)"])
    );
    assert_eq!(after["hooks"]["Stop"][1], stop_entry(630));
    assert_eq!(
        after["hooks"]["PreToolUse"],
        repo_settings()["hooks"]["PreToolUse"]
    );
}

#[test]
fn entries_plan_apply_plan_is_empty_and_two_renders_are_byte_identical() {
    let a = Fixture::new();
    let b = Fixture::new();
    a.write(SETTINGS, REPO_SETTINGS);
    b.write(SETTINGS, REPO_SETTINGS);
    let first = a.entries_apply();
    let second = b.entries_apply();
    assert_eq!(first.changes[SETTINGS], second.changes[SETTINGS]);
    assert_eq!(a.read(SETTINGS), b.read(SETTINGS));
    let again = a.entries_plan();
    assert!(again.changes.is_empty(), "{:?}", again.changes.keys());
    assert!(again.notes.is_empty());
}

#[test]
fn entries_no_longer_rendered_are_removed_with_their_emptied_containers() {
    let f = Fixture::new();
    f.entries_apply();
    let fewer = json!({"permissions": {"deny": ["Read(./**/.env)"]}});
    let planned = f.plan_with(&[&SetupCore, &FewerEntries]).unwrap();
    assert_eq!(planned.changes[SETTINGS], Some(pretty(&fewer)));
    apply(&f.root, &planned.changes).unwrap();
    assert_eq!(f.lock()["files"][SETTINGS]["entries"], fewer);
    let again = f.plan_with(&[&SetupCore, &FewerEntries]).unwrap();
    assert!(again.changes.is_empty(), "{:?}", again.changes.keys());
}

#[test]
fn entries_no_longer_rendered_but_edited_are_refused() {
    let f = Fixture::new();
    f.entries_apply();
    let mut settings = f.settings();
    settings["hooks"]["Stop"][0] = stop_entry(600);
    f.write_settings(&settings);
    assert_eq!(
        f.refusal(&[&SetupCore, &FewerEntries]),
        format!(
            "Locally changed retired managed entry: {SETTINGS} at /hooks/Stop ({STOP_COMMAND})"
        )
    );
}

#[test]
fn retiring_the_entries_path_removes_only_the_owned_entries() {
    let f = Fixture::new();
    f.write(SETTINGS, REPO_SETTINGS);
    f.entries_apply();
    let planned = f.plan_with(&[&SetupCore, &NoEntries]).unwrap();
    assert!(matches!(planned.changes.get(SETTINGS), Some(Some(_))));
    assert_eq!(
        planned.tags[SETTINGS],
        (Ownership::ManagedEntries, "entries".to_owned())
    );
    apply(&f.root, &planned.changes).unwrap();
    assert_eq!(f.settings(), repo_settings());
    assert!(f.lock()["files"].get(SETTINGS).is_none());
}

#[test]
fn retiring_the_entries_path_deletes_a_file_the_entries_alone_filled() {
    let f = Fixture::new();
    f.entries_apply();
    let planned = f.plan_with(&[&SetupCore, &NoEntries]).unwrap();
    assert_eq!(planned.changes[SETTINGS], None);
    apply(&f.root, &planned.changes).unwrap();
    assert!(!f.exists(SETTINGS));
}

#[test]
fn retired_entries_path_absent_is_forgotten_silently() {
    let f = Fixture::new();
    f.entries_apply();
    fs::remove_file(f.root.join(SETTINGS)).unwrap();
    let planned = f.plan_with(&[&SetupCore, &NoEntries]).unwrap();
    assert!(!planned.changes.contains_key(SETTINGS));
    assert!(!planned.notes.contains_key(SETTINGS));
    apply(&f.root, &planned.changes).unwrap();
    assert!(f.lock()["files"].get(SETTINGS).is_none());
}

#[test]
fn remove_deletes_only_the_owned_entries_and_leaves_the_projects_file() {
    let f = Fixture::new();
    f.write(SETTINGS, REPO_SETTINGS);
    f.entries_apply();
    let planned = f.remove(&[&SetupCore, &Entries], "entries").unwrap();
    assert!(matches!(planned.changes.get(SETTINGS), Some(Some(_))));
    apply(&f.root, &planned.changes).unwrap();
    assert_eq!(f.settings(), repo_settings());
    assert!(f.lock()["files"].get(SETTINGS).is_none());
    assert!(f.lock()["modules"].get("entries").is_none());
}

#[test]
fn remove_refuses_an_edited_owned_entry_before_any_write() {
    let f = Fixture::new();
    f.entries_apply();
    let mut settings = f.settings();
    settings["hooks"]["Stop"][0] = stop_entry(600);
    f.write_settings(&settings);
    assert_eq!(
        f.remove_refusal(&[&SetupCore, &Entries], "entries"),
        format!(
            "Locally changed managed entry of module entries: {SETTINGS} at /hooks/Stop ({STOP_COMMAND}); restore it before removing the module"
        )
    );
}

#[test]
fn remove_deletes_the_entries_file_without_the_module_compiled_in() {
    let f = Fixture::new();
    f.entries_apply();
    let planned = f.remove(&[&SetupCore], "entries").unwrap();
    assert_eq!(planned.changes[SETTINGS], None);
}

#[test]
fn entries_fragment_that_is_not_an_object_is_refused() {
    let f = Fixture::new();
    assert_eq!(
        f.refusal(&[&SetupCore, &Fragment("[1]\n")]),
        "Module bad: managed entries must be a JSON object: fixture/x.json"
    );
}

#[test]
fn entries_fragment_with_a_scalar_leaf_is_refused_naming_the_pointer() {
    let f = Fixture::new();
    assert_eq!(
        f.refusal(&[&SetupCore, &Fragment(r#"{"a": {"b/c": 1}}"#)]),
        "Module bad: managed entries must be arrays: fixture/x.json at /a/b~1c"
    );
}

#[test]
fn entries_destination_that_is_not_an_object_is_refused() {
    let f = Fixture::new();
    f.write(SETTINGS, "[]\n");
    assert_eq!(
        f.refusal(&[&SetupCore, &Entries]),
        format!("Managed entries destination is not a JSON object: {SETTINGS}")
    );
}

#[test]
fn entries_destination_without_an_array_at_the_pointer_is_refused() {
    let f = Fixture::new();
    f.write_settings(&json!({"permissions": {"deny": "none"}}));
    assert_eq!(
        f.refusal(&[&SetupCore, &Entries]),
        format!("Managed entries destination has no array at /permissions/deny: {SETTINGS}")
    );
    f.write_settings(&json!({"permissions": "none"}));
    assert_eq!(
        f.refusal(&[&SetupCore, &Entries]),
        format!("Managed entries destination has no array at /permissions/deny: {SETTINGS}")
    );
}

#[test]
fn doctor_reports_managed_entries_drift_for_a_missing_or_edited_entry() {
    let f = Fixture::new();
    f.write(SETTINGS, REPO_SETTINGS);
    f.entries_apply();
    let today = today();
    let findings = doctor_at(&f.root, today).unwrap();
    assert!(
        findings.iter().all(|s| !s.contains(SETTINGS)),
        "{findings:?}"
    );
    let mut settings = f.settings();
    settings["permissions"]["deny"]
        .as_array_mut()
        .unwrap()
        .remove(0);
    f.write_settings(&settings);
    let findings = doctor_at(&f.root, today).unwrap();
    assert!(
        findings.contains(&format!(
            "Managed entries drift: {SETTINGS} (module entries)"
        )),
        "{findings:?}"
    );
    assert!(
        !findings
            .iter()
            .any(|f| f.starts_with(&format!("Managed content drift: {SETTINGS}")))
    );
}

// ---- managed-entries: object members (#751) -------------------------------------------

const OPENCODE: &str = "fixture/opencode.json";

/// Owns two string leaves of `permission.read`: object members named by key.
struct Keys(&'static str);
impl Module for Keys {
    fn id(&self) -> &'static str {
        "keys"
    }
    fn version(&self) -> &'static str {
        "0.1.0"
    }
    fn render(&self, _cx: &Context<'_>) -> Result<Vec<Rendered>> {
        Ok(vec![rendered(
            OPENCODE,
            Ownership::ManagedEntries,
            Some(self.0),
        )])
    }
}
const TWO_KEYS: Keys = Keys(r#"{"permission": {"read": {".env": "deny", "secrets/*": "deny"}}}"#);
const THREE_KEYS: Keys = Keys(
    r#"{"permission": {"read": {".env": "deny", "secrets/*": "deny"}, "edit": {".env": "deny"}}}"#,
);
const ONE_KEY: Keys = Keys(r#"{"permission": {"read": {".env": "deny"}}}"#);

#[test]
fn object_members_are_added_beside_the_projects_keys_and_a_second_plan_is_empty() {
    let f = Fixture::new();
    f.write(
        OPENCODE,
        &pretty(
            &json!({"$schema": "https://opencode.ai/config.json", "model": "x/y",
            "permission": {"read": {"*.md": "allow"}, "bash": "ask"}}),
        ),
    );
    let planned = f.plan_with(&[&SetupCore, &TWO_KEYS]).unwrap();
    apply(&f.root, &planned.changes).unwrap();
    let after: Value = serde_json::from_str(&f.read(OPENCODE)).unwrap();
    assert_eq!(
        after,
        json!({"$schema": "https://opencode.ai/config.json", "model": "x/y",
            "permission": {"read": {"*.md": "allow", ".env": "deny", "secrets/*": "deny"}, "bash": "ask"}})
    );
    let again = f.plan_with(&[&SetupCore, &TWO_KEYS]).unwrap();
    assert!(again.changes.is_empty(), "{:?}", again.changes.keys());
}

#[test]
fn object_members_present_unchanged_never_rewrite_the_file() {
    let f = Fixture::new();
    let by_hand = "{\"permission\":{\"read\":{\"secrets/*\":\"deny\",\".env\":\"deny\"}}}\n";
    f.write(OPENCODE, by_hand);
    let planned = f.plan_with(&[&SetupCore, &TWO_KEYS]).unwrap();
    assert!(!planned.changes.contains_key(OPENCODE));
    apply(&f.root, &planned.changes).unwrap();
    assert_eq!(f.read(OPENCODE), by_hand);
}

#[test]
fn an_object_member_edited_refuses_by_key_and_a_deleted_one_is_re_added() {
    let f = Fixture::new();
    apply(
        &f.root,
        &f.plan_with(&[&SetupCore, &TWO_KEYS]).unwrap().changes,
    )
    .unwrap();
    f.write(
        OPENCODE,
        &pretty(&json!({"permission": {"read": {".env": "allow", "secrets/*": "deny"}}})),
    );
    assert_eq!(
        f.refusal(&[&SetupCore, &TWO_KEYS]),
        format!("Locally changed managed entry: {OPENCODE} at /permission/read/.env (.env)")
    );
    f.write(
        OPENCODE,
        &pretty(&json!({"permission": {"read": {"secrets/*": "deny"}}})),
    );
    apply(
        &f.root,
        &f.plan_with(&[&SetupCore, &TWO_KEYS]).unwrap().changes,
    )
    .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&f.read(OPENCODE)).unwrap(),
        json!({"permission": {"read": {".env": "deny", "secrets/*": "deny"}}})
    );
}

#[test]
fn object_members_grow_with_the_fragment_and_retire_with_it() {
    let f = Fixture::new();
    f.write(OPENCODE, &pretty(&json!({"model": "x/y"})));
    apply(
        &f.root,
        &f.plan_with(&[&SetupCore, &TWO_KEYS]).unwrap().changes,
    )
    .unwrap();
    apply(
        &f.root,
        &f.plan_with(&[&SetupCore, &THREE_KEYS]).unwrap().changes,
    )
    .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&f.read(OPENCODE)).unwrap(),
        json!({"model": "x/y", "permission": {"read": {".env": "deny", "secrets/*": "deny"}, "edit": {".env": "deny"}}})
    );
    apply(
        &f.root,
        &f.plan_with(&[&SetupCore, &ONE_KEY]).unwrap().changes,
    )
    .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&f.read(OPENCODE)).unwrap(),
        json!({"model": "x/y", "permission": {"read": {".env": "deny"}}})
    );
    let planned = f.remove(&[&SetupCore, &ONE_KEY], "keys").unwrap();
    apply(&f.root, &planned.changes).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&f.read(OPENCODE)).unwrap(),
        json!({"model": "x/y"})
    );
}

#[test]
fn an_object_member_under_a_non_object_refuses_naming_the_pointer() {
    let f = Fixture::new();
    f.write(OPENCODE, &pretty(&json!({"permission": "allow"})));
    assert_eq!(
        f.refusal(&[&SetupCore, &TWO_KEYS]),
        format!("Managed entries destination has no object at /permission/read: {OPENCODE}")
    );
}

#[test]
fn doctor_reports_drift_for_a_missing_object_member() {
    let f = Fixture::new();
    apply(
        &f.root,
        &f.plan_with(&[&SetupCore, &TWO_KEYS]).unwrap().changes,
    )
    .unwrap();
    assert!(
        doctor_at(&f.root, today())
            .unwrap()
            .iter()
            .all(|s| !s.contains(OPENCODE))
    );
    f.write(
        OPENCODE,
        &pretty(&json!({"permission": {"read": {".env": "deny"}}})),
    );
    assert!(
        doctor_at(&f.root, today())
            .unwrap()
            .contains(&format!("Managed entries drift: {OPENCODE} (module keys)"))
    );
}
