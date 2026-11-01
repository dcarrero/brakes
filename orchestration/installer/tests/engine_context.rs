//! Context additions (#863; SPEC-engine.md, Context additions): the repository
//! identity derived from `origin`, the optional read of an active module's
//! answers and the notes a module adds after the plan.
use brakes::engine::answers::{Answers, Schema};
use brakes::engine::{self, Context, Module, Ownership, PlanNote, Planned, Rendered};
use brakes::{Result, Source, apply, profile_for};
use serde_json::json;
use std::{collections::BTreeMap, fs, path::PathBuf, process::Command};
use tempfile::TempDir;

/// A module with one question, so a reader can see its answers.
struct Provider;
impl Module for Provider {
    fn id(&self) -> &'static str {
        "provider"
    }
    fn version(&self) -> &'static str {
        "1.0.0"
    }
    fn questions(&self) -> Schema {
        Schema::parse(&json!([{"id": "flavour", "type": "string", "default": "vanilla"}])).unwrap()
    }
    fn render(&self, _: &Context<'_>) -> Result<Vec<Rendered>> {
        Ok(Vec::new())
    }
}

/// Reports what its context sees as notes, and renders one managed file.
struct Reader;
impl Module for Reader {
    fn id(&self) -> &'static str {
        "reader"
    }
    fn version(&self) -> &'static str {
        "1.0.0"
    }
    fn render(&self, _: &Context<'_>) -> Result<Vec<Rendered>> {
        Ok(vec![Rendered {
            path: "docs/agent-setup/reader.md".to_owned(),
            class: Ownership::Managed,
            content: Some("reader\n".to_owned()),
            scaffold: None,
        }])
    }
    fn notes(&self, cx: &Context<'_>) -> Result<Vec<String>> {
        let flavour = cx
            .answers_if_active("provider")
            .map_or("inactive".to_owned(), |a| a["flavour"].to_string());
        Ok(vec![
            format!("repository {}", cx.repository().unwrap_or("<none>")),
            format!("provider {flavour}"),
        ])
    }
}

/// `Reader` without notes: the same id, the same render.
struct QuietReader;
impl Module for QuietReader {
    fn id(&self) -> &'static str {
        "reader"
    }
    fn version(&self) -> &'static str {
        "1.0.0"
    }
    fn render(&self, cx: &Context<'_>) -> Result<Vec<Rendered>> {
        Reader.render(cx)
    }
}

/// A second noting module, listed before `Reader` in the plan.
struct Early;
impl Module for Early {
    fn id(&self) -> &'static str {
        "early"
    }
    fn version(&self) -> &'static str {
        "1.0.0"
    }
    fn render(&self, _: &Context<'_>) -> Result<Vec<Rendered>> {
        Ok(Vec::new())
    }
    fn notes(&self, _: &Context<'_>) -> Result<Vec<String>> {
        Ok(vec!["first".to_owned()])
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
        let repo = Self { _temp: temp, root };
        repo.git(&["init", "-q"]);
        repo
    }
    fn git(&self, args: &[&str]) {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(&self.root)
                .args(args)
                .status()
                .unwrap()
                .success()
        );
    }
    fn source() -> Source {
        Source {
            documents: BTreeMap::new(),
            version: "0.1.0".to_owned(),
            revision: None,
            dirty: false,
        }
    }
    fn plan(&self, modules: &[&dyn Module]) -> Planned {
        let profile = profile_for(&self.root).unwrap();
        engine::plan(&self.root, &Self::source(), &profile, modules, &|_| true).unwrap()
    }
    fn lines(&self, modules: &[&dyn Module]) -> Vec<String> {
        notes(&self.plan(modules))
    }
}

fn notes(planned: &Planned) -> Vec<String> {
    planned.plan_notes.iter().map(PlanNote::to_string).collect()
}

#[test]
fn repository_is_none_without_an_origin() {
    let repo = Repo::new();
    assert_eq!(repo.lines(&[&Reader])[0], "NOTE [reader] repository <none>");
}

#[test]
fn repository_is_the_origin_owner_and_name_as_written() {
    let repo = Repo::new();
    repo.git(&[
        "remote",
        "add",
        "origin",
        "git@github.com:example-owner/Demo-App.git",
    ]);
    assert_eq!(
        repo.lines(&[&Reader])[0],
        "NOTE [reader] repository example-owner/Demo-App"
    );
}

#[test]
fn repository_is_none_when_origin_names_two_repositories_or_a_refused_one() {
    let repo = Repo::new();
    repo.git(&[
        "remote",
        "add",
        "origin",
        "https://github.com/example-owner/one",
    ]);
    repo.git(&[
        "remote",
        "set-url",
        "--add",
        "origin",
        "https://github.com/example-owner/two",
    ]);
    assert_eq!(repo.lines(&[&Reader])[0], "NOTE [reader] repository <none>");
    let refused = Repo::new();
    refused.git(&[
        "remote",
        "add",
        "origin",
        "https://github.com/someone-else/demo",
    ]);
    assert_eq!(
        refused.lines(&[&Reader])[0],
        "NOTE [reader] repository <none>"
    );
}

#[test]
fn repository_ignores_other_remotes_when_origin_is_absent() {
    let repo = Repo::new();
    repo.git(&[
        "remote",
        "add",
        "upstream",
        "https://github.com/example-owner/demo",
    ]);
    assert_eq!(repo.lines(&[&Reader])[0], "NOTE [reader] repository <none>");
}

#[test]
fn answers_if_active_is_none_for_an_inactive_module() {
    let repo = Repo::new();
    assert_eq!(repo.lines(&[&Reader])[1], "NOTE [reader] provider inactive");
}

#[test]
fn answers_if_active_reads_an_active_module_without_requiring_it() {
    let repo = Repo::new();
    assert_eq!(Reader.requires(), [] as [&str; 0]);
    assert_eq!(
        repo.lines(&[&Provider, &Reader])[1],
        "NOTE [reader] provider \"vanilla\""
    );
}

#[test]
fn answers_if_active_sees_the_answers_configure_is_recording() {
    let repo = Repo::new();
    let planned = repo.plan(&[&Provider, &Reader]);
    apply(&repo.root, &planned.changes).unwrap();
    let profile = profile_for(&repo.root).unwrap();
    let patch: Answers = serde_json::from_value(json!({"flavour": "mint"})).unwrap();
    let configured = engine::configure(
        &repo.root,
        &Repo::source(),
        &profile,
        &[&Provider, &Reader],
        &|_| true,
        "provider",
        &patch,
    )
    .unwrap();
    assert_eq!(notes(&configured)[1], "NOTE [reader] provider \"mint\"");
}

#[test]
fn answers_if_active_and_new_build_a_context_outside_the_engine() {
    let repo = Repo::new();
    let profile = profile_for(&repo.root).unwrap();
    let source = Repo::source();
    let lock = engine::Lock {
        schema: 2,
        version: "test".to_owned(),
        source_commit: None,
        source_dirty: false,
        personal_owner: "example-owner".to_owned(),
        modules: Default::default(),
        files: Default::default(),
    };
    let own = Answers::new();
    let resolved = BTreeMap::from([("provider".to_owned(), own.clone())]);
    let cx = Context::new(
        &repo.root, &profile, &source, &lock, &own, &Reader, &resolved,
    );
    assert_eq!(cx.repository(), None);
    assert_eq!(cx.answers_if_active("provider"), Some(&own));
    assert_eq!(cx.answers_if_active("other"), None);
    let cx = cx.with_repository(Some("example-owner/demo"));
    assert_eq!(cx.repository(), Some("example-owner/demo"));
}

#[test]
fn notes_follow_module_order_and_change_nothing_else() {
    let repo = Repo::new();
    let noted = repo.plan(&[&Early, &Reader]);
    assert_eq!(
        notes(&noted),
        [
            "NOTE [early] first",
            "NOTE [reader] repository <none>",
            "NOTE [reader] provider inactive",
        ]
    );
    let quiet = repo.plan(&[&Early, &QuietReader]);
    assert_eq!(notes(&quiet), ["NOTE [early] first"]);
    assert_eq!(noted.changes, quiet.changes);
    assert_eq!(noted.steps.len(), quiet.steps.len());
    apply(&repo.root, &noted.changes).unwrap();
    // After apply the plan is empty, the notes stay: a note is never a change.
    let again = repo.plan(&[&Early, &Reader]);
    assert!(again.changes.is_empty());
    assert_eq!(notes(&again).len(), 3);
}

#[test]
fn a_plan_without_notes_carries_none_and_remove_prints_none() {
    let repo = Repo::new();
    let planned = repo.plan(&[&QuietReader]);
    assert!(planned.plan_notes.is_empty());
    apply(&repo.root, &planned.changes).unwrap();
    let removed = engine::remove(&repo.root, &[&Reader], &|_| true, "reader").unwrap();
    assert!(removed.plan_notes.is_empty());
}
