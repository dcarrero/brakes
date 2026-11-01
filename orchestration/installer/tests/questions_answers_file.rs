//! The answers-file driver (SPEC-questions.md, #708): both file shapes, the merge
//! order recorded < default < preset < file < set, the provenance line and the
//! guarantee that every driver ends in `engine::configure`.
use brakes::engine::answers::Answers;
use brakes::questions::{self, AnswerSource, Layer};
use serde_json::{Value, json};
use std::path::PathBuf;

fn answers(value: Value) -> Answers {
    serde_json::from_value(value).unwrap()
}

fn layer(source: AnswerSource, value: Value) -> Layer {
    Layer {
        source,
        answers: answers(value),
    }
}

fn file(name: &str) -> AnswerSource {
    AnswerSource::File(PathBuf::from(name))
}

#[test]
fn resolve_lets_the_highest_source_win_per_key_whatever_the_order_given() {
    let resolution = questions::resolve(vec![
        layer(AnswerSource::Set, json!({"a": "set"})),
        layer(
            file("f.json"),
            json!({"a": "file", "b": "file", "c": "file"}),
        ),
        layer(
            AnswerSource::Preset("personal-vps".to_owned()),
            json!({"a": "preset", "b": "preset", "c": "preset", "d": "preset"}),
        ),
        layer(
            AnswerSource::Recorded,
            json!({"a": "rec", "b": "rec", "c": "rec", "d": "rec", "e": "rec"}),
        ),
    ]);
    assert_eq!(
        serde_json::to_value(&resolution.patch).unwrap(),
        json!({"a": "set", "b": "file", "c": "file", "d": "preset"}),
        "the recorded layer is the engine's; the patch carries only what overrides it"
    );
    assert_eq!(resolution.origins["a"], AnswerSource::Set);
    assert_eq!(resolution.origins["b"], file("f.json"));
    assert_eq!(resolution.origins["c"], file("f.json"));
    assert_eq!(
        resolution.origins["d"],
        AnswerSource::Preset("personal-vps".to_owned())
    );
    assert_eq!(resolution.origins["e"], AnswerSource::Recorded);
}

#[test]
fn resolve_applies_several_files_in_the_order_given() {
    let resolution = questions::resolve(vec![
        layer(file("first.json"), json!({"a": 1, "b": 1})),
        layer(file("second.json"), json!({"a": 2})),
    ]);
    assert_eq!(
        serde_json::to_value(&resolution.patch).unwrap(),
        json!({"a": 2, "b": 1})
    );
    assert_eq!(resolution.origins["a"], file("second.json"));
    assert_eq!(resolution.origins["b"], file("first.json"));
}

#[test]
fn provenance_names_the_source_of_every_recorded_key_in_merge_order() {
    let resolution = questions::resolve(vec![
        layer(AnswerSource::Set, json!({"reason": "why"})),
        layer(
            file("/tmp/a.json"),
            json!({"flavour": "chocolate", "count": 9}),
        ),
        layer(AnswerSource::Recorded, json!({"count": 7, "name": "demo"})),
    ]);
    // What the engine recorded: defaults filled the rest, `--set` beat the file on
    // nothing here, the file beat the recorded `count`.
    let recorded = answers(json!({
        "name": "demo", "enabled": false, "count": 9, "flavour": "chocolate",
        "reason": "why", "toppings": [], "paths": ["docs/**"]
    }));
    assert_eq!(
        resolution.provenance(&recorded),
        "ANSWERS recorded name + default enabled, paths, toppings + file /tmp/a.json count, flavour + --set reason"
    );
    let none = questions::resolve(Vec::new());
    assert_eq!(none.provenance(&Answers::new()), "ANSWERS none");
}

#[test]
fn provenance_omits_a_source_whose_keys_were_all_overridden_or_dropped() {
    let resolution = questions::resolve(vec![
        layer(AnswerSource::Set, json!({"count": 3, "detail": "z"})),
        layer(file("a.json"), json!({"count": 1})),
    ]);
    // `detail` was gated out by the engine: it is not in the recorded answers.
    let recorded = answers(json!({"count": 3}));
    assert_eq!(resolution.provenance(&recorded), "ANSWERS --set count");
}

/// A temporary answers file with `text`; returns its path and the display form
/// refusals name.
fn temp_file(dir: &tempfile::TempDir, name: &str, text: &str) -> (PathBuf, String) {
    let path = dir.path().join(name);
    std::fs::write(&path, text).unwrap();
    let display = path.display().to_string();
    (path, display)
}

#[test]
fn an_answers_file_accepts_the_recorded_shape_the_multi_module_shape_and_a_bare_object() {
    let dir = tempfile::tempdir().unwrap();
    let (recorded, _) = temp_file(
        &dir,
        "recorded.json",
        &json!({"module": "survey", "version": "0.9.0", "answers": {"count": 3}}).to_string(),
    );
    assert_eq!(
        questions::answers_file::load(&recorded, "survey").unwrap(),
        answers(json!({"count": 3}))
    );
    let (multi, _) = temp_file(
        &dir,
        "multi.json",
        &json!({"preset": "personal-vps", "description": "One VPS",
                "modules": {"survey": {"count": 4, "flavour": "chocolate"},
                            "repo-baseline": {"approvals": "checks-only"}}})
        .to_string(),
    );
    assert_eq!(
        questions::answers_file::load(&multi, "survey").unwrap(),
        answers(json!({"count": 4, "flavour": "chocolate"}))
    );
    let (bare, _) = temp_file(&dir, "bare.json", &json!({"count": 5}).to_string());
    assert_eq!(
        questions::answers_file::load(&bare, "survey").unwrap(),
        answers(json!({"count": 5}))
    );
}

#[test]
fn an_answers_file_refuses_naming_the_path_and_the_module_or_key() {
    let dir = tempfile::tempdir().unwrap();
    let cases = [
        (
            json!({"module": "other", "answers": {}}).to_string(),
            "Answers file names module `other`, not `survey`: {path}",
        ),
        (
            json!({"modules": {"repo-baseline": {}}}).to_string(),
            "Answers file has no section for module `survey`: {path}",
        ),
        (
            json!({"modules": {"survey": []}}).to_string(),
            "Answers file section for module `survey` must be an object: {path}",
        ),
        (
            json!({"module": "survey", "answers": 7}).to_string(),
            "Answers file key `answers` must be an object: {path}",
        ),
        (
            json!({"modules": "survey"}).to_string(),
            "Answers file key `modules` must be an object: {path}",
        ),
        (
            "[]".to_owned(),
            "Answers file must be a JSON object: {path}",
        ),
        ("{".to_owned(), "Answers file is not valid JSON: {path}"),
    ];
    for (index, (text, message)) in cases.iter().enumerate() {
        let (path, display) = temp_file(&dir, &format!("case{index}.json"), text);
        assert_eq!(
            questions::answers_file::load(&path, "survey")
                .unwrap_err()
                .to_string(),
            message.replace("{path}", &display),
            "{text}"
        );
    }
    let missing = dir.path().join("missing.json");
    assert_eq!(
        questions::answers_file::load(&missing, "survey")
            .unwrap_err()
            .to_string(),
        format!("Answers file cannot be read: {}", missing.display())
    );
}

// ---- Through the engine: the Survey fixture of engine_answers.rs, on a real repository.

use brakes::engine::answers::{self, Schema};
use brakes::engine::{Context, Module, Ownership, Planned, Rendered};
use brakes::questions::Inputs;
use brakes::{LOCK, Source, apply, digest, profile_for};
use std::{collections::BTreeMap, fs, process::Command};

/// A per-profile default, a gated question and a required question behind a gate.
struct Survey;
impl Module for Survey {
    fn id(&self) -> &'static str {
        "survey"
    }
    fn version(&self) -> &'static str {
        "1.0.0"
    }
    fn questions(&self) -> Schema {
        Schema::parse(&json!([
            {"id": "name", "type": "string", "default": "demo", "minLength": 1, "maxLength": 8},
            {"id": "enabled", "type": "boolean", "default": {"P1": false, "P2": true}},
            {"id": "count", "type": "integer", "default": 2, "minimum": 1, "maximum": 10},
            {"id": "flavour", "type": "string", "enum": ["vanilla", "chocolate"], "default": "vanilla"},
            {"id": "toppings", "type": "array", "items": {"type": "string", "enum": ["nuts", "cream"]},
             "default": [], "maxItems": 2},
            {"id": "paths", "type": "array", "items": {"type": "string"}, "default": ["docs/**"],
             "minItems": 1},
            {"id": "detail", "type": "string", "default": "x", "when": "enabled"},
            {"id": "reason", "type": "string", "required": true, "when": "flavour == chocolate"},
        ]))
        .unwrap()
    }
    fn render(&self, cx: &Context<'_>) -> brakes::Result<Vec<Rendered>> {
        Ok(vec![Rendered {
            path: "docs/agent-setup/survey.json".to_owned(),
            class: Ownership::Managed,
            content: Some(serde_json::to_string(cx.answers)? + "\n"),
            scaffold: None,
        }])
    }
}

struct Repo {
    temp: tempfile::TempDir,
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
        Self { temp, root }
    }
    fn source() -> Source {
        Source {
            documents: BTreeMap::new(),
            version: "0.1.0".to_owned(),
            revision: None,
            dirty: false,
        }
    }
    /// An answers file outside the repository, as `--answers` would name it.
    fn file(&self, name: &str, value: Value) -> PathBuf {
        let path = self.temp.path().join(name);
        fs::write(&path, value.to_string()).unwrap();
        path
    }
    fn configure(&self, inputs: Inputs) -> brakes::Result<questions::Configured> {
        let profile = profile_for(&self.root).unwrap();
        questions::configure(
            &self.root,
            &Self::source(),
            &profile,
            &[&Survey],
            &|_| true,
            "survey",
            &inputs,
        )
    }
    fn configure_and_apply(&self, inputs: Inputs) -> questions::Configured {
        let configured = self.configure(inputs).unwrap();
        apply(&self.root, &configured.planned.changes).unwrap();
        configured
    }
    fn recorded(&self) -> String {
        fs::read_to_string(self.root.join(answers::path("survey"))).unwrap()
    }
    fn recorded_answers(&self) -> Value {
        serde_json::from_str::<Value>(&self.recorded()).unwrap()["answers"].clone()
    }
    fn sets(pairs: &[&str]) -> Inputs {
        Inputs {
            files: Vec::new(),
            sets: pairs.iter().map(|s| (*s).to_owned()).collect(),
            ..Inputs::default()
        }
    }
}

#[test]
fn configure_merges_recorded_default_files_and_set_in_order_on_the_recorded_file() {
    let repo = Repo::new();
    repo.configure_and_apply(Repo::sets(&["count=7", "name=kept", "flavour=vanilla"]));
    let first = repo.file(
        "first.json",
        json!({"module": "survey", "version": "0.9.0",
               "answers": {"count": 8, "flavour": "chocolate", "reason": "first", "toppings": ["nuts"]}}),
    );
    let second = repo.file(
        "second.json",
        json!({"modules": {"survey": {"count": 9, "reason": "second"}}}),
    );
    let configured = repo.configure_and_apply(Inputs {
        files: vec![first.clone(), second.clone()],
        sets: vec!["reason=set".to_owned()],
        ..Inputs::default()
    });
    assert_eq!(
        repo.recorded_answers(),
        json!({
            "name": "kept",                 // recorded, nobody overrode it
            "enabled": false,               // recorded: the engine wrote the P1 default on the first run
            "paths": ["docs/**"],           // recorded, likewise
            "toppings": ["nuts"],           // first file
            "flavour": "chocolate",         // first file over recorded
            "count": 9,                     // second file over first over recorded
            "reason": "set"                 // --set over both files
        })
    );
    assert_eq!(
        configured.provenance,
        format!(
            "ANSWERS recorded enabled, name, paths + file {} flavour, toppings + file {} count + --set reason",
            first.display(),
            second.display()
        )
    );
    let file: Value = serde_json::from_str(&repo.recorded()).unwrap();
    assert_eq!(
        file["version"],
        json!("1.0.0"),
        "the compiled version, not the file's 0.9.0"
    );
}

#[test]
fn the_recorded_file_is_byte_identical_whether_answered_by_set_or_by_answers() {
    let by_set = Repo::new();
    by_set.configure_and_apply(Repo::sets(&[
        "flavour=chocolate",
        "reason=why",
        "count=5",
        "toppings=nuts,cream",
    ]));
    let by_file = Repo::new();
    let file = by_file.file(
        "a.json",
        json!({"flavour": "chocolate", "reason": "why", "count": 5, "toppings": ["nuts", "cream"]}),
    );
    by_file.configure_and_apply(Inputs {
        files: vec![file],
        sets: Vec::new(),
        ..Inputs::default()
    });
    assert_eq!(by_set.recorded(), by_file.recorded());
    let lock = |repo: &Repo| -> Value {
        serde_json::from_str(&fs::read_to_string(repo.root.join(LOCK)).unwrap()).unwrap()
    };
    assert_eq!(
        lock(&by_set)["modules"]["survey"]["answers_digest"],
        lock(&by_file)["modules"]["survey"]["answers_digest"]
    );
    assert_eq!(
        lock(&by_set)["modules"]["survey"]["answers_digest"],
        json!(digest(&by_set.recorded()))
    );
}

#[test]
fn an_unknown_key_in_an_answers_file_is_refused_by_the_engine_with_the_question_id() {
    let repo = Repo::new();
    let file = repo.file("a.json", json!({"colour": "red"}));
    assert_eq!(
        repo.configure(Inputs {
            files: vec![file],
            sets: Vec::new(),
            ..Inputs::default()
        })
        .unwrap_err()
        .to_string(),
        "Module survey: answer `colour` is not a question of this module"
    );
    assert_eq!(
        repo.configure(Repo::sets(&["flavour=mint"]))
            .unwrap_err()
            .to_string(),
        "Module survey: answer `flavour` must be one of: vanilla, chocolate"
    );
    assert!(!repo.root.join(answers::path("survey")).exists());
    assert!(!repo.root.join(LOCK).exists());
}

#[test]
fn the_provenance_line_is_returned_and_written_nowhere() {
    let repo = Repo::new();
    let file = repo.file("a.json", json!({"count": 3}));
    let configured = repo.configure_and_apply(Inputs {
        files: vec![file.clone()],
        sets: vec!["name=x".to_owned()],
        ..Inputs::default()
    });
    assert_eq!(
        configured.provenance,
        format!(
            "ANSWERS default enabled, flavour, paths, toppings + file {} count + --set name",
            file.display()
        )
    );
    let mut pending = vec![repo.root.clone()];
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.file_name().is_some_and(|n| n == ".git") {
                continue;
            }
            if path.is_dir() {
                pending.push(path);
            } else {
                let text = fs::read_to_string(&path).unwrap_or_default();
                assert!(!text.contains("ANSWERS"), "{}", path.display());
            }
        }
    }
    let planned: &Planned = &configured.planned;
    assert!(
        planned
            .changes
            .values()
            .flatten()
            .all(|text| !text.contains("ANSWERS"))
    );
}

// ---- The binary: `configure` goes through the driver.

impl Repo {
    /// Runs the binary; `<repo>` in `args` stands for the repository path.
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
}

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "lists setup-core or its guides; product-boundary T7a"
)]
#[test]
fn cli_configure_prints_the_provenance_line_before_the_plan_and_accepts_the_multi_module_shape() {
    let repo = Repo::new();
    assert!(
        repo.cli(&["install", "<repo>", "--new-personal", "--apply"])
            .status
            .success()
    );
    let multi = repo.file(
        "multi.json",
        json!({"preset": "personal-vps", "modules": {"setup-core": {}, "repo-baseline": {"approvals": "checks-only"}}}),
    );
    let single = repo.file(
        "single.json",
        json!({"module": "setup-core", "version": "0.1.0", "answers": {}}),
    );
    let result = repo.cli(&[
        "configure",
        "<repo>",
        "setup-core",
        "--answers",
        multi.to_str().unwrap(),
        "--answers",
        single.to_str().unwrap(),
    ]);
    assert!(result.status.success(), "{result:?}");
    let out = String::from_utf8_lossy(&result.stdout);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[0], "ANSWERS none", "{out}");
    assert!(
        lines[1].starts_with("PLAN ")
            && lines.contains(
                &format!("PLAN {} [answers:setup-core]", answers::path("setup-core")).as_str()
            ),
        "{out}"
    );
    assert!(result.stderr.is_empty(), "{result:?}");

    let bad = repo.file("bad.json", json!({"modules": {"repo-baseline": {}}}));
    let result = repo.cli(&[
        "configure",
        "<repo>",
        "setup-core",
        "--answers",
        bad.to_str().unwrap(),
    ]);
    assert_eq!(result.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&result.stderr).trim(),
        format!(
            "REFUSED: Answers file has no section for module `setup-core`: {}",
            bad.display()
        )
    );
    let unknown = repo.file("unknown.json", json!({"x": 1}));
    let result = repo.cli(&[
        "configure",
        "<repo>",
        "setup-core",
        "--answers",
        unknown.to_str().unwrap(),
    ]);
    assert_eq!(result.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&result.stderr).trim(),
        "REFUSED: Module setup-core: answer `x` is not a question of this module"
    );
    assert!(!repo.root.join(answers::path("setup-core")).exists());
}

// ---- `install --preset` and `install --answers` (#731): sugar over `configure`.

impl Repo {
    /// A checkout whose `templates/presets/` holds the fixture preset `demo`; the
    /// real catalogue ships with empty sections until each module's slice fills them.
    fn demo_catalogue(&self) -> PathBuf {
        let dir = self.temp.path().join("checkout/templates/presets");
        fs::create_dir_all(&dir).unwrap();
        let demo = json!({"preset": "demo", "description": "A fixture preset",
                          "modules": {"survey": {"flavour": "chocolate", "reason": "preset", "count": 4},
                                      "elsewhere": {"x": 1}}});
        fs::write(dir.join("demo.json"), demo.to_string()).unwrap();
        self.temp.path().join("checkout")
    }
    fn install(&self, requested: &[&str], inputs: Inputs) -> brakes::Result<questions::Installed> {
        let profile = profile_for(&self.root).unwrap();
        questions::install(
            &self.root,
            &Self::source(),
            &profile,
            &[&Survey],
            &|_| true,
            requested,
            None,
            &inputs,
        )
    }
    /// Every file of the repository but `.git`, by relative path.
    fn tree(&self) -> BTreeMap<String, String> {
        let mut files = BTreeMap::new();
        let mut pending = vec![self.root.clone()];
        while let Some(dir) = pending.pop() {
            for entry in fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.file_name().is_some_and(|n| n == ".git") {
                    continue;
                }
                if path.is_dir() {
                    pending.push(path);
                } else {
                    let name = path.strip_prefix(&self.root).unwrap();
                    files.insert(
                        name.to_string_lossy().into_owned(),
                        fs::read_to_string(&path).unwrap(),
                    );
                }
            }
        }
        files
    }
}

#[test]
fn install_with_a_preset_leaves_what_configure_with_it_then_install_leaves() {
    let by_steps = Repo::new();
    let catalogue = by_steps.demo_catalogue();
    let preset = |catalogue: PathBuf| Inputs {
        preset: Some("demo".to_owned()),
        catalogue: Some(catalogue),
        ..Inputs::default()
    };
    by_steps.configure_and_apply(preset(catalogue));
    let installed = by_steps.install(&["survey"], Inputs::default()).unwrap();
    apply(&by_steps.root, &installed.planned.changes).unwrap();

    let by_sugar = Repo::new();
    let catalogue = by_sugar.demo_catalogue();
    let installed = by_sugar.install(&["survey"], preset(catalogue)).unwrap();
    apply(&by_sugar.root, &installed.planned.changes).unwrap();
    assert_eq!(
        installed.provenance,
        ["survey: ANSWERS default enabled, name, paths, toppings + preset demo count, flavour, reason".to_owned()]
    );
    assert!(installed.notes.is_empty(), "{:?}", installed.notes);

    let tree = by_sugar.tree();
    assert!(tree.contains_key(LOCK) && tree.contains_key(&answers::path("survey")));
    assert_eq!(by_steps.tree(), tree);
}

#[test]
fn install_without_a_preset_or_answers_files_is_the_plain_install() {
    let repo = Repo::new();
    let installed = repo.install(&["survey"], Inputs::default()).unwrap();
    assert!(installed.provenance.is_empty() && installed.notes.is_empty());
    let profile = profile_for(&repo.root).unwrap();
    let plain = brakes::engine::install(
        &repo.root,
        &Repo::source(),
        &profile,
        &[&Survey],
        &|_| true,
        &["survey"],
        None,
        &BTreeMap::new(),
    )
    .unwrap();
    assert_eq!(installed.planned.changes, plain.changes);
}

#[test]
fn install_answers_takes_each_installed_modules_section_over_the_preset() {
    let repo = Repo::new();
    let catalogue = repo.demo_catalogue();
    let file = repo.file(
        "multi.json",
        json!({"modules": {"survey": {"count": 9}, "elsewhere": {"y": 2}}}),
    );
    let installed = repo
        .install(
            &["survey"],
            Inputs {
                files: vec![file.clone()],
                preset: Some("demo".to_owned()),
                catalogue: Some(catalogue),
                ..Inputs::default()
            },
        )
        .unwrap();
    apply(&repo.root, &installed.planned.changes).unwrap();
    assert_eq!(
        repo.recorded_answers(),
        json!({"name": "demo", "enabled": false, "paths": ["docs/**"], "toppings": [],
               "flavour": "chocolate", "reason": "preset", "count": 9})
    );
    assert_eq!(
        installed.provenance,
        [format!(
            "survey: ANSWERS default enabled, name, paths, toppings + preset demo flavour, reason + file {} count",
            file.display()
        )]
    );
}

#[test]
fn install_with_a_preset_that_leaves_a_required_question_open_refuses_by_id() {
    let repo = Repo::new();
    let file = repo.file(
        "multi.json",
        json!({"modules": {"survey": {"flavour": "chocolate"}}}),
    );
    let error = repo
        .install(
            &["survey"],
            Inputs {
                files: vec![file],
                ..Inputs::default()
            },
        )
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "Module survey: question reason has no answer; pass --set reason=<value>, --answers <file> or --preset <name>"
    );
}

#[test]
fn install_answers_refuses_the_single_module_shape_and_a_bare_object_naming_shape_and_file() {
    let repo = Repo::new();
    for (name, value) in [
        (
            "single.json",
            json!({"module": "survey", "version": "1.0.0", "answers": {"count": 3}}),
        ),
        ("bare.json", json!({"count": 3})),
    ] {
        let file = repo.file(name, value);
        let error = repo
            .install(
                &["survey"],
                Inputs {
                    files: vec![file.clone()],
                    ..Inputs::default()
                },
            )
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            format!(
                "install --answers takes the multi-module shape {{\"modules\": {{\"<module-id>\": {{...}}}}}}: {}",
                file.display()
            )
        );
    }
    assert!(!repo.root.join(LOCK).exists());
}

#[test]
fn cli_install_takes_preset_answers_and_no_input_and_refuses_the_single_module_shape() {
    let repo = Repo::new();
    let result = repo.cli(&[
        "install",
        "<repo>",
        "--new-personal",
        "--module",
        "repo-baseline",
        "--preset",
        "personal-vps",
        "--no-input",
    ]);
    assert!(result.status.success(), "{result:?}");
    let out = String::from_utf8_lossy(&result.stdout);
    // The catalogue answers who merges for repo-baseline (#1181).
    assert!(
        out.lines().any(|line| line
            == "repo-baseline: ANSWERS default bypass_actors, dependency_updates + preset personal-vps approvals, codeowners"),
        "{out}"
    );
    assert!(!repo.root.join(LOCK).exists());

    let multi = repo.file(
        "multi.json",
        json!({"modules": {"repo-baseline": {"approvals": "checks-only"}}}),
    );
    let result = repo.cli(&[
        "install",
        "<repo>",
        "--new-personal",
        "--module",
        "repo-baseline",
        "--answers",
        multi.to_str().unwrap(),
        "--apply",
    ]);
    assert!(result.status.success(), "{result:?}");
    let out = String::from_utf8_lossy(&result.stdout);
    assert!(
        out.lines()
            .any(|line| line.starts_with("repo-baseline: ANSWERS ")
                && line.contains(&format!("file {} approvals", multi.display()))),
        "{out}"
    );
    let recorded: Value = serde_json::from_str(
        &fs::read_to_string(repo.root.join(answers::path("repo-baseline"))).unwrap(),
    )
    .unwrap();
    assert_eq!(recorded["answers"]["approvals"], json!("checks-only"));

    let single = repo.file(
        "single.json",
        json!({"module": "repo-baseline", "version": "1.0.0", "answers": {}}),
    );
    let result = repo.cli(&["install", "<repo>", "--answers", single.to_str().unwrap()]);
    assert_eq!(result.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&result.stderr).trim(),
        format!(
            "REFUSED: install --answers takes the multi-module shape {{\"modules\": {{\"<module-id>\": {{...}}}}}}: {}",
            single.display()
        )
    );
    for (args, message) in [
        (
            vec!["install", "<repo>", "--set", "a=b"],
            "REFUSED: --set is only available with configure",
        ),
        (
            vec!["install", "<repo>", "--interactive"],
            "REFUSED: --interactive is only available with configure",
        ),
        (
            vec!["doctor", "<repo>", "--preset", "personal-vps"],
            "REFUSED: --preset and --answers are only available with configure and install",
        ),
        (
            vec!["doctor", "<repo>", "--no-input"],
            "REFUSED: --no-input is only available with configure and install",
        ),
    ] {
        let result = repo.cli(&args);
        assert_eq!(result.status.code(), Some(2), "{args:?}");
        assert_eq!(String::from_utf8_lossy(&result.stderr).trim(), message);
    }
}
