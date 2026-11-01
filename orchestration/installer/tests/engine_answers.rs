//! Recorded answers (SPEC-engine.md, #654): the question schema subset, its
//! validator, `when`, the refusal of secret questions and `configure`.
mod support;
use brakes::engine::answers::{self, Answers, DEFAULT_TIER, Schema};
use brakes::engine::{self, Context, Module, Ownership, Rendered};
use brakes::{LOCK, Source, apply, digest, profile_for};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, path::PathBuf, process::Command};
use support::SetupCore;
use tempfile::TempDir;

/// Every kind of the subset, a per-profile default, a gated question and a
/// required question that only applies behind a gate.
fn survey_schema() -> Schema {
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

fn answers(value: Value) -> Answers {
    serde_json::from_value(value).unwrap()
}

#[test]
fn validate_fills_defaults_and_resolves_the_per_profile_default_to_a_scalar() {
    let schema = survey_schema();
    let validated = schema
        .validate("survey", &Answers::new(), DEFAULT_TIER)
        .unwrap();
    assert_eq!(
        serde_json::to_value(&validated).unwrap(),
        json!({"name": "demo", "enabled": false, "count": 2, "flavour": "vanilla",
               "toppings": [], "paths": ["docs/**"]})
    );
    let p2 = schema.validate("survey", &Answers::new(), "P2").unwrap();
    assert_eq!(p2["enabled"], json!(true));
    assert_eq!(p2["detail"], json!("x"));
}

#[test]
fn validate_refuses_an_invalid_value_naming_the_question_and_the_rule() {
    let schema = survey_schema();
    for (patch, rule) in [
        (json!({"name": 5}), "must be a string"),
        (json!({"name": ""}), "must have at least 1 character"),
        (
            json!({"name": "abcdefghi"}),
            "must have at most 8 characters",
        ),
        (json!({"enabled": "yes"}), "must be a boolean"),
        (json!({"count": "x"}), "must be an integer"),
        (json!({"count": 2.5}), "must be an integer"),
        (json!({"count": 0}), "must be at least 1"),
        (json!({"count": 11}), "must be at most 10"),
        (
            json!({"flavour": "mint"}),
            "must be one of: vanilla, chocolate",
        ),
        (json!({"toppings": "nuts"}), "must be an array"),
        (json!({"toppings": ["nuts", 1]}), "item 2 must be a string"),
        (
            json!({"toppings": ["jam"]}),
            "item 1 must be one of: nuts, cream",
        ),
        (
            json!({"toppings": ["nuts", "cream", "nuts"]}),
            "must have at most 2 items",
        ),
        (json!({"paths": []}), "must have at least 1 item"),
    ] {
        let question = patch.as_object().unwrap().keys().next().unwrap().clone();
        let error = schema
            .validate("survey", &answers(patch), DEFAULT_TIER)
            .unwrap_err()
            .to_string();
        assert_eq!(error, format!("Module survey: answer `{question}` {rule}"));
    }
}

#[test]
fn validate_refuses_an_unknown_key() {
    let error = survey_schema()
        .validate("survey", &answers(json!({"colour": "red"})), DEFAULT_TIER)
        .unwrap_err()
        .to_string();
    assert_eq!(
        error,
        "Module survey: answer `colour` is not a question of this module"
    );
}

#[test]
fn validate_refuses_a_missing_required_key_only_when_its_gate_holds() {
    let schema = survey_schema();
    let error = schema
        .validate(
            "survey",
            &answers(json!({"flavour": "chocolate"})),
            DEFAULT_TIER,
        )
        .unwrap_err()
        .to_string();
    assert_eq!(
        error,
        "Module survey: answer `reason` is required and has no value"
    );
    let ok = schema
        .validate(
            "survey",
            &answers(json!({"flavour": "chocolate", "reason": "why"})),
            DEFAULT_TIER,
        )
        .unwrap();
    assert_eq!(ok["reason"], json!("why"));
}

#[test]
fn validate_drops_a_key_whose_when_is_false_and_keeps_it_when_true() {
    let schema = survey_schema();
    let dropped = schema
        .validate(
            "survey",
            &answers(json!({"enabled": false, "detail": "z"})),
            DEFAULT_TIER,
        )
        .unwrap();
    assert!(!dropped.contains_key("detail"));
    let kept = schema
        .validate(
            "survey",
            &answers(json!({"enabled": true, "detail": "z"})),
            DEFAULT_TIER,
        )
        .unwrap();
    assert_eq!(kept["detail"], json!("z"));
    // A gated-out answer is not validated: the gate decides before the rule.
    let ignored = schema
        .validate(
            "survey",
            &answers(json!({"enabled": false, "detail": 7})),
            DEFAULT_TIER,
        )
        .unwrap();
    assert!(!ignored.contains_key("detail"));
}

#[test]
fn when_supports_negation_and_inequality_over_earlier_answers() {
    let schema = Schema::parse(&json!([
        {"id": "mode", "type": "string", "enum": ["a", "b"], "default": "a"},
        {"id": "on", "type": "boolean", "default": true},
        {"id": "not_a", "type": "string", "default": "x", "when": "mode != a"},
        {"id": "off", "type": "string", "default": "x", "when": "!on"},
        {"id": "is_b", "type": "string", "default": "x", "when": "mode == b"},
    ]))
    .unwrap();
    let validated = schema
        .validate(
            "m",
            &answers(json!({"mode": "b", "on": false})),
            DEFAULT_TIER,
        )
        .unwrap();
    assert_eq!(validated["not_a"], json!("x"));
    assert_eq!(validated["off"], json!("x"));
    assert_eq!(validated["is_b"], json!("x"));
    let validated = schema.validate("m", &Answers::new(), DEFAULT_TIER).unwrap();
    assert!(!validated.contains_key("not_a"));
    assert!(!validated.contains_key("off"));
    assert!(!validated.contains_key("is_b"));
}

#[test]
fn check_refuses_a_secret_question_a_dangling_when_and_a_duplicate_id() {
    let secret =
        Schema::parse(&json!([{"id": "token", "type": "string", "secret": true}])).unwrap();
    assert_eq!(
        secret.check("leaky").unwrap_err().to_string(),
        "Module leaky: question `token` is marked secret; secrets are probed by name, never recorded"
    );
    let later = Schema::parse(&json!([
        {"id": "detail", "type": "string", "when": "enabled"},
        {"id": "enabled", "type": "boolean"},
    ]))
    .unwrap();
    assert_eq!(
        later.check("m").unwrap_err().to_string(),
        "Module m: question `detail` has a `when` on `enabled`, which is not an earlier question"
    );
    let twice = Schema::parse(&json!([
        {"id": "a", "type": "string"},
        {"id": "a", "type": "boolean"},
    ]))
    .unwrap();
    assert_eq!(
        twice.check("m").unwrap_err().to_string(),
        "Module m: question `a` is declared twice"
    );
    assert!(survey_schema().check("survey").is_ok());
}

#[test]
fn parse_refuses_shapes_outside_the_subset() {
    for (value, message) in [
        (
            json!({"a": {"type": "string"}}),
            "Question schema must be an array of questions",
        ),
        (
            json!([{"type": "string"}]),
            "Question schema: every question needs a string `id`",
        ),
        (
            json!([{"id": "n", "type": "number"}]),
            "Question schema: `n` has unsupported type `number`",
        ),
        (
            json!([{"id": "n", "type": "array", "items": {"type": "integer"}}]),
            "Question schema: `n` has unsupported array items; only strings and enums",
        ),
        (
            json!([{"id": "n", "type": "string", "when": "a b c"}]),
            "Question schema: `n` has an invalid `when`: a b c",
        ),
        (
            json!([{"id": "n", "type": "string", "pattern": "^x"}]),
            "Question schema: `n` uses unsupported validator `pattern`",
        ),
    ] {
        assert_eq!(
            Schema::parse(&value).unwrap_err().to_string(),
            message,
            "{value}"
        );
    }
}

#[test]
fn parse_keeps_the_x_extensions_for_the_drivers_and_ignores_them_itself() {
    let schema = Schema::parse(&json!([
        {"id": "approvals", "type": "string", "enum": ["checks-only", "other"],
         "x-ui": {"label": "Merge policy", "order": 10},
         "x-configure-new": {"contract": "m.approvals"}},
        {"id": "plain", "type": "boolean"},
    ]))
    .unwrap();
    let approvals = schema.question("approvals").unwrap();
    assert_eq!(
        approvals.extensions.keys().collect::<Vec<_>>(),
        ["x-configure-new", "x-ui"]
    );
    assert_eq!(approvals.extensions["x-ui"]["label"], json!("Merge policy"));
    assert!(schema.question("plain").unwrap().extensions.is_empty());
    // The engine neither validates nor records them.
    assert!(schema.check("m").is_ok());
    let validated = schema
        .validate("m", &answers(json!({"approvals": "other"})), DEFAULT_TIER)
        .unwrap();
    assert_eq!(
        serde_json::to_value(&validated).unwrap(),
        json!({"approvals": "other"})
    );
}

/// A module that renders its validated answers, so a test reads what `render` saw.
struct Survey;
impl Module for Survey {
    fn id(&self) -> &'static str {
        "survey"
    }
    fn version(&self) -> &'static str {
        "1.0.0"
    }
    fn questions(&self) -> Schema {
        survey_schema()
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

/// A module whose schema asks for a secret: it must never load.
struct Leaky;
impl Module for Leaky {
    fn id(&self) -> &'static str {
        "leaky"
    }
    fn version(&self) -> &'static str {
        "1.0.0"
    }
    fn questions(&self) -> Schema {
        Schema::parse(&json!([{"id": "token", "type": "string", "secret": true}])).unwrap()
    }
    fn render(&self, _: &Context<'_>) -> brakes::Result<Vec<Rendered>> {
        Ok(Vec::new())
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
    fn plan(&self, modules: &[&dyn Module]) -> brakes::Result<engine::Planned> {
        let profile = profile_for(&self.root).unwrap();
        engine::plan(&self.root, &Self::source(), &profile, modules, &|_| true)
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
    fn lock(&self) -> engine::Lock {
        engine::Lock::parse(&self.read(LOCK), "0.0.0", &|_| true).unwrap()
    }
    fn answers_file(&self, answers: Value) -> String {
        let text = serde_json::to_string_pretty(
            &json!({"module": "survey", "version": "1.0.0", "answers": answers}),
        )
        .unwrap()
            + "\n";
        self.write(&answers::path("survey"), &text);
        text
    }
}

#[test]
fn plan_applies_defaults_without_an_answers_file_and_records_no_digest() {
    let repo = Repo::new();
    let planned = repo.plan(&[&Survey]).unwrap();
    apply(&repo.root, &planned.changes).unwrap();
    assert_eq!(
        repo.value("docs/agent-setup/survey.json"),
        json!({"name": "demo", "enabled": false, "count": 2, "flavour": "vanilla",
               "toppings": [], "paths": ["docs/**"]})
    );
    assert_eq!(
        repo.value(LOCK)["modules"]["survey"],
        json!({"version": "1.0.0", "answers_digest": null})
    );
    assert!(!repo.root.join(answers::path("survey")).exists());
}

#[test]
fn plan_renders_recorded_answers_and_records_their_digest() {
    let repo = Repo::new();
    let text = repo.answers_file(json!({"flavour": "chocolate", "reason": "why", "count": 7}));
    let planned = repo.plan(&[&Survey]).unwrap();
    apply(&repo.root, &planned.changes).unwrap();
    let rendered = repo.value("docs/agent-setup/survey.json");
    assert_eq!(rendered["flavour"], json!("chocolate"));
    assert_eq!(rendered["reason"], json!("why"));
    assert_eq!(rendered["count"], json!(7));
    assert_eq!(rendered["name"], json!("demo"));
    assert_eq!(
        repo.value(LOCK)["modules"]["survey"]["answers_digest"],
        json!(digest(&text))
    );
    assert!(repo.plan(&[&Survey]).unwrap().changes.is_empty());
}

#[test]
fn plan_refuses_an_invalid_recorded_answer_and_a_file_of_another_module() {
    let repo = Repo::new();
    repo.answers_file(json!({"flavour": "mint"}));
    assert_eq!(
        repo.plan(&[&Survey]).unwrap_err().to_string(),
        "Module survey: answer `flavour` must be one of: vanilla, chocolate"
    );
    repo.write(
        &answers::path("survey"),
        &json!({"module": "other", "version": "1.0.0", "answers": {}}).to_string(),
    );
    assert_eq!(
        repo.plan(&[&Survey]).unwrap_err().to_string(),
        "Module survey: answers file names module `other`: .agent-setup/modules/survey.json"
    );
    repo.write(&answers::path("survey"), "{");
    assert_eq!(
        repo.plan(&[&Survey]).unwrap_err().to_string(),
        "Module survey: invalid answers file: .agent-setup/modules/survey.json"
    );
}

#[test]
fn plan_refuses_a_module_with_a_secret_question_at_load() {
    let repo = Repo::new();
    assert_eq!(
        repo.plan(&[&Survey, &Leaky]).unwrap_err().to_string(),
        "Module leaky: question `token` is marked secret; secrets are probed by name, never recorded"
    );
    assert!(!repo.root.join(LOCK).exists());
}

impl Repo {
    fn configure(
        &self,
        modules: &[&dyn Module],
        module: &str,
        patch: Value,
    ) -> brakes::Result<engine::Planned> {
        let profile = profile_for(&self.root).unwrap();
        engine::configure(
            &self.root,
            &Self::source(),
            &profile,
            modules,
            &|_| true,
            module,
            &answers(patch),
        )
    }
}

#[test]
fn configure_set_round_trips_through_the_answers_file() {
    let repo = Repo::new();
    let planned = repo
        .configure(
            &[&Survey],
            "survey",
            json!({"flavour": "chocolate", "reason": "why"}),
        )
        .unwrap();
    let path = answers::path("survey");
    assert_eq!(
        planned.answers.get(&path).map(String::as_str),
        Some("survey")
    );
    let text = planned.changes[&path].clone().unwrap();
    assert!(!repo.root.join(&path).exists(), "plan only");
    apply(&repo.root, &planned.changes).unwrap();
    assert_eq!(repo.read(&path), text);
    let recorded = answers::recorded(&repo.root, "survey").unwrap().unwrap();
    assert_eq!(recorded.module, "survey");
    assert_eq!(recorded.version, "1.0.0");
    assert_eq!(
        serde_json::to_value(&recorded.answers).unwrap(),
        json!({"name": "demo", "enabled": false, "count": 2, "flavour": "chocolate",
               "reason": "why", "toppings": [], "paths": ["docs/**"]})
    );
    assert_eq!(
        repo.value("docs/agent-setup/survey.json")["reason"],
        json!("why")
    );
    assert_eq!(
        repo.value(LOCK)["modules"]["survey"]["answers_digest"],
        json!(digest(&text))
    );
    assert!(repo.plan(&[&Survey]).unwrap().changes.is_empty());
    let again = repo.configure(&[&Survey], "survey", json!({})).unwrap();
    assert!(again.changes.is_empty(), "{again:?}");
}

#[test]
fn configure_merges_the_patch_over_recorded_answers_and_drops_gated_out_keys() {
    let repo = Repo::new();
    let first = repo
        .configure(
            &[&Survey],
            "survey",
            json!({"count": 5, "enabled": true, "detail": "z"}),
        )
        .unwrap();
    apply(&repo.root, &first.changes).unwrap();
    let second = repo
        .configure(&[&Survey], "survey", json!({"enabled": false}))
        .unwrap();
    apply(&repo.root, &second.changes).unwrap();
    let recorded = answers::recorded(&repo.root, "survey").unwrap().unwrap();
    assert_eq!(recorded.answers["count"], json!(5));
    assert_eq!(recorded.answers["enabled"], json!(false));
    assert!(!recorded.answers.contains_key("detail"));
}

#[test]
fn configure_refuses_an_invalid_patch_and_an_unknown_module_without_writing() {
    let repo = Repo::new();
    assert_eq!(
        repo.configure(&[&Survey], "survey", json!({"flavour": "mint"}))
            .unwrap_err()
            .to_string(),
        "Module survey: answer `flavour` must be one of: vanilla, chocolate"
    );
    assert_eq!(
        repo.configure(&[&Survey], "nope", json!({}))
            .unwrap_err()
            .to_string(),
        "Unknown module id: nope"
    );
    assert!(!repo.root.join(answers::path("survey")).exists());
    assert!(!repo.root.join(LOCK).exists());
}

/// A `*` segment stands for one identifier: `apps.*.port` answers
/// `apps.web.port`. The engine checks the type; the module owns the rest.
fn pattern_schema() -> Schema {
    Schema::parse(&json!([
        {"id": "family", "type": "string", "enum": ["a", "b"], "default": "a"},
        {"id": "apps.*.path", "type": "string", "minLength": 1},
        {"id": "apps.*.port", "type": "integer", "minimum": 1},
        {"id": "apps.*.container", "type": "boolean"},
    ]))
    .unwrap()
}

#[test]
fn pattern_questions_accept_every_instance_and_type_it() {
    let schema = pattern_schema();
    schema.check("m").unwrap();
    let validated = schema
        .validate(
            "m",
            &answers(json!({"apps.web.path": "web", "apps.api-2.port": 80})),
            DEFAULT_TIER,
        )
        .unwrap();
    assert_eq!(
        serde_json::to_value(&validated).unwrap(),
        json!({"family": "a", "apps.web.path": "web", "apps.api-2.port": 80})
    );
    assert_eq!(
        answers::parse_set(&schema, "apps.web.port=8000").unwrap(),
        ("apps.web.port".to_owned(), json!(8000))
    );
    assert_eq!(
        answers::parse_set(&schema, "apps.web.container=true").unwrap(),
        ("apps.web.container".to_owned(), json!(true))
    );
}

#[test]
fn pattern_questions_refuse_by_the_concrete_key() {
    let schema = pattern_schema();
    for (patch, message) in [
        (
            json!({"apps.web.port": 0}),
            "Module m: answer `apps.web.port` must be at least 1",
        ),
        (
            json!({"apps.web.colour": "red"}),
            "Module m: answer `apps.web.colour` is not a question of this module",
        ),
        (
            json!({"apps.a.b.path": "x"}),
            "Module m: answer `apps.a.b.path` is not a question of this module",
        ),
        (
            json!({"apps..path": "x"}),
            "Module m: answer `apps..path` is not a question of this module",
        ),
    ] {
        assert_eq!(
            schema
                .validate("m", &answers(patch), DEFAULT_TIER)
                .unwrap_err()
                .to_string(),
            message
        );
    }
    for extra in [
        json!({"id": "apps.*.bin", "type": "string", "default": "x"}),
        json!({"id": "apps.*.bin", "type": "string", "required": true}),
        json!({"id": "apps.*.bin", "type": "string", "when": "family == a"}),
    ] {
        let schema = Schema::parse(&json!([{"id": "family", "type": "string"}, extra])).unwrap();
        assert_eq!(
            schema.check("m").unwrap_err().to_string(),
            "Module m: question `apps.*.bin` is a pattern; its default, required and when belong to the module"
        );
    }
}

#[test]
fn set_pairs_are_parsed_by_the_question_type() {
    let schema = survey_schema();
    for (arg, expected) in [
        ("name=x", json!("x")),
        ("enabled=true", json!(true)),
        ("count=5", json!(5)),
        ("count=abc", json!("abc")),
        ("flavour=vanilla", json!("vanilla")),
        ("toppings=nuts, cream", json!(["nuts", "cream"])),
        ("toppings=", json!([])),
        ("colour=red", json!("red")),
    ] {
        let (key, value) = answers::parse_set(&schema, arg).unwrap();
        assert_eq!(key, arg.split('=').next().unwrap());
        assert_eq!(value, expected, "{arg}");
    }
    assert_eq!(
        answers::parse_set(&schema, "nope").unwrap_err().to_string(),
        "--set needs key=value: nope"
    );
}

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
    ignore = "asserts setup-core's own content or id; product-boundary T7b"
)]
#[test]
fn cli_configure_plans_by_default_and_writes_the_answers_file_with_apply() {
    let repo = Repo::new();
    assert!(
        repo.cli(&["install", "<repo>", "--new-personal", "--apply"])
            .status
            .success()
    );
    let path = answers::path("setup-core");
    let result = repo.cli(&["configure", "<repo>", "setup-core"]);
    assert!(result.status.success(), "{result:?}");
    let out = String::from_utf8_lossy(&result.stdout);
    assert!(
        out.contains(&format!("PLAN {path} [answers:setup-core]")),
        "{out}"
    );
    assert!(out.contains("Plan only; no writes."), "{out}");
    assert!(!repo.root.join(&path).exists());

    let result = repo.cli(&["configure", "<repo>", "setup-core", "--apply"]);
    assert!(result.status.success(), "{result:?}");
    let out = String::from_utf8_lossy(&result.stdout);
    assert!(
        out.contains(&format!("WRITE {path} [answers:setup-core]")),
        "{out}"
    );
    assert_eq!(
        repo.value(&path),
        json!({"module": "setup-core", "version": "1.3.0", "answers": {}})
    );
    assert_eq!(
        repo.value(LOCK)["modules"]["setup-core"]["answers_digest"],
        json!(digest(&repo.read(&path)))
    );
    let result = repo.cli(&["install", "<repo>"]);
    assert!(String::from_utf8_lossy(&result.stdout).contains("No changes."));

    let file = repo.root.join("../patch.json");
    fs::write(
        &file,
        json!({"module": "setup-core", "answers": {}}).to_string(),
    )
    .unwrap();
    let result = repo.cli(&[
        "configure",
        "<repo>",
        "setup-core",
        "--answers",
        file.to_str().unwrap(),
    ]);
    assert!(result.status.success(), "{result:?}");
    assert!(String::from_utf8_lossy(&result.stdout).contains("No changes."));
}

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "asserts setup-core's own content or id; product-boundary T7b"
)]
#[test]
fn cli_configure_refuses_an_unknown_module_an_unknown_key_and_a_missing_module_id() {
    let repo = Repo::new();
    assert!(
        repo.cli(&["install", "<repo>", "--new-personal", "--apply"])
            .status
            .success()
    );
    let result = repo.cli(&["configure", "<repo>", "nope", "--apply"]);
    assert_eq!(result.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&result.stderr).trim(),
        "REFUSED: Unknown module id: nope"
    );
    let result = repo.cli(&[
        "configure",
        "<repo>",
        "setup-core",
        "--set",
        "x=1",
        "--apply",
    ]);
    assert_eq!(result.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&result.stderr).trim(),
        "REFUSED: Module setup-core: answer `x` is not a question of this module"
    );
    let result = repo.cli(&["configure", "<repo>"]);
    assert_eq!(result.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&result.stderr).contains("Usage:"));
    assert!(!repo.root.join(answers::path("setup-core")).exists());
    assert!(!repo.root.join(answers::path("nope")).exists());
}

// ---- #657: `install --module`, `requires` resolution and the migrate hook ----

/// A module with nothing to ask and one managed file; what `Dependent` requires.
struct Base;
impl Module for Base {
    fn id(&self) -> &'static str {
        "base"
    }
    fn version(&self) -> &'static str {
        "1.0.0"
    }
    fn render(&self, _: &Context<'_>) -> brakes::Result<Vec<Rendered>> {
        Ok(vec![Rendered {
            path: "docs/agent-setup/base.md".to_owned(),
            class: Ownership::Managed,
            content: Some("base\n".to_owned()),
            scaffold: None,
        }])
    }
}

/// A module that only installs on top of `base`.
struct Dependent;
impl Module for Dependent {
    fn id(&self) -> &'static str {
        "dependent"
    }
    fn version(&self) -> &'static str {
        "1.0.0"
    }
    fn requires(&self) -> &'static [&'static str] {
        &["base"]
    }
    fn render(&self, _: &Context<'_>) -> brakes::Result<Vec<Rendered>> {
        Ok(vec![Rendered {
            path: "docs/agent-setup/dependent.md".to_owned(),
            class: Ownership::Managed,
            content: Some("dependent\n".to_owned()),
            scaffold: None,
        }])
    }
}

fn ids(modules: &[&dyn Module]) -> Vec<&'static str> {
    modules.iter().map(|m| m.id()).collect()
}

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "asserts setup-core's own content or id; product-boundary T7b"
)]
#[test]
fn registry_finds_a_compiled_module_by_id() {
    assert_eq!(
        brakes::modules::find("setup-core").map(|m| m.version()),
        Some(brakes::modules::core_version())
    );
    assert!(brakes::modules::find("nope").is_none());
}

#[test]
fn select_activates_setup_core_the_recorded_modules_and_the_requested_ones_in_registry_order() {
    let repo = Repo::new();
    let registry: Vec<&dyn Module> = vec![&SetupCore, &Base, &Dependent, &Survey];
    assert_eq!(
        ids(&engine::select(&registry, None, &[]).unwrap()),
        vec!["setup-core"]
    );
    let planned = repo.plan(&[&SetupCore, &Survey]).unwrap();
    apply(&repo.root, &planned.changes).unwrap();
    let lock = repo.lock();
    assert_eq!(
        ids(&engine::select(&registry, Some(&lock), &[]).unwrap()),
        vec!["setup-core", "survey"]
    );
    assert_eq!(
        ids(&engine::select(&registry, Some(&lock), &["dependent", "base", "survey"]).unwrap()),
        vec!["setup-core", "base", "dependent", "survey"]
    );
}

#[test]
fn select_refuses_an_unknown_module_id_naming_it() {
    let registry: Vec<&dyn Module> = vec![&SetupCore, &Base];
    let error = engine::select(&registry, None, &["base", "nope"])
        .map(|selected| ids(&selected))
        .unwrap_err();
    assert_eq!(error.to_string(), "Unknown module id: nope");
}

#[test]
fn plan_refuses_a_module_whose_requirement_is_not_active_naming_the_dependency() {
    let repo = Repo::new();
    assert_eq!(
        repo.plan(&[&Dependent]).unwrap_err().to_string(),
        "Module dependent requires module base, which is not installed; add it with --module base"
    );
    assert!(!repo.root.join(LOCK).exists());
    let planned = repo.plan(&[&Base, &Dependent]).unwrap();
    apply(&repo.root, &planned.changes).unwrap();
    assert_eq!(repo.read("docs/agent-setup/dependent.md"), "dependent\n");
    assert_eq!(
        repo.value(LOCK)["modules"]["dependent"]["version"],
        json!("1.0.0")
    );
}

thread_local! {
    /// Migrations run on this test's thread (tests run in parallel, one thread each).
    static MIGRATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
fn migrations() -> usize {
    MIGRATIONS.with(std::cell::Cell::get)
}

/// `survey` one version later: the same questions, and a migration that marks
/// the recorded answers so a test sees what `render` and the file received.
struct SurveyV2;
impl Module for SurveyV2 {
    fn id(&self) -> &'static str {
        "survey"
    }
    fn version(&self) -> &'static str {
        "1.1.0"
    }
    fn questions(&self) -> Schema {
        survey_schema()
    }
    fn render(&self, cx: &Context<'_>) -> brakes::Result<Vec<Rendered>> {
        Survey.render(cx)
    }
    fn migrate(&self, from: &str, answers: &mut Answers) -> brakes::Result<()> {
        assert_eq!(from, "1.0.0");
        MIGRATIONS.with(|n| n.set(n.get() + 1));
        answers.insert("name".to_owned(), json!("migrated"));
        Ok(())
    }
}

/// `base` one version later, with the default (empty) migration.
struct BaseV2;
impl Module for BaseV2 {
    fn id(&self) -> &'static str {
        "base"
    }
    fn version(&self) -> &'static str {
        "2.0.0"
    }
    fn render(&self, cx: &Context<'_>) -> brakes::Result<Vec<Rendered>> {
        Base.render(cx)
    }
}

#[test]
fn a_version_bump_runs_migrate_once_before_render_and_records_the_new_version_in_lock_and_file() {
    let repo = Repo::new();
    repo.answers_file(json!({"count": 7}));
    let planned = repo.plan(&[&Survey]).unwrap();
    apply(&repo.root, &planned.changes).unwrap();
    assert_eq!(
        repo.value(LOCK)["modules"]["survey"]["version"],
        json!("1.0.0")
    );

    let path = answers::path("survey");
    assert_eq!(migrations(), 0);
    let planned = repo.plan(&[&SurveyV2]).unwrap();
    assert_eq!(migrations(), 1);
    assert_eq!(
        planned.answers.get(&path).map(String::as_str),
        Some("survey")
    );
    let text = planned.changes[&path].clone().unwrap();
    let file: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(file["version"], json!("1.1.0"));
    assert_eq!(file["answers"]["name"], json!("migrated"));
    assert_eq!(file["answers"]["count"], json!(7));
    let rendered: Value = serde_json::from_str(
        planned.changes["docs/agent-setup/survey.json"]
            .as_deref()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        rendered["name"],
        json!("migrated"),
        "render saw the migrated answers"
    );
    assert_eq!(repo.value(&path)["version"], json!("1.0.0"), "plan only");

    apply(&repo.root, &planned.changes).unwrap();
    assert_eq!(repo.read(&path), text);
    assert_eq!(
        repo.value(LOCK)["modules"]["survey"],
        json!({"version": "1.1.0", "answers_digest": digest(&text)})
    );
    let again = repo.plan(&[&SurveyV2]).unwrap();
    assert!(again.changes.is_empty(), "{again:?}");
    assert_eq!(migrations(), 1, "migrate runs exactly once");
}

#[test]
fn a_version_bump_without_recorded_answers_records_the_version_and_writes_a_file_only_when_migrate_answers()
 {
    let repo = Repo::new();
    let planned = repo.plan(&[&Base, &Survey]).unwrap();
    apply(&repo.root, &planned.changes).unwrap();
    assert!(!repo.root.join(answers::path("base")).exists());
    assert!(!repo.root.join(answers::path("survey")).exists());

    let planned = repo.plan(&[&BaseV2, &SurveyV2]).unwrap();
    apply(&repo.root, &planned.changes).unwrap();
    assert_eq!(
        repo.value(LOCK)["modules"]["base"],
        json!({"version": "2.0.0", "answers_digest": null})
    );
    assert!(!repo.root.join(answers::path("base")).exists());
    let recorded = answers::recorded(&repo.root, "survey").unwrap().unwrap();
    assert_eq!(recorded.version, "1.1.0");
    assert_eq!(recorded.answers["name"], json!("migrated"));
    assert_eq!(
        repo.value(LOCK)["modules"]["survey"]["answers_digest"],
        json!(digest(&repo.read(&answers::path("survey"))))
    );
    assert!(repo.plan(&[&BaseV2, &SurveyV2]).unwrap().changes.is_empty());
}

#[test]
fn a_recorded_version_newer_than_the_compiled_one_is_refused() {
    let repo = Repo::new();
    let planned = repo.plan(&[&BaseV2]).unwrap();
    apply(&repo.root, &planned.changes).unwrap();
    assert_eq!(
        repo.plan(&[&Base]).unwrap_err().to_string(),
        "Module base is installed at version 2.0.0, newer than this installer's 1.0.0; update the installer"
    );
}

#[test]
fn configure_on_a_bumped_module_migrates_the_merged_answers_and_records_the_new_version() {
    let repo = Repo::new();
    let first = repo
        .configure(&[&Survey], "survey", json!({"count": 4}))
        .unwrap();
    apply(&repo.root, &first.changes).unwrap();
    let second = repo
        .configure(&[&SurveyV2], "survey", json!({"count": 6}))
        .unwrap();
    apply(&repo.root, &second.changes).unwrap();
    let recorded = answers::recorded(&repo.root, "survey").unwrap().unwrap();
    assert_eq!(recorded.version, "1.1.0");
    assert_eq!(recorded.answers["count"], json!(6));
    assert_eq!(recorded.answers["name"], json!("migrated"));
    assert_eq!(
        repo.value(LOCK)["modules"]["survey"],
        json!({"version": "1.1.0", "answers_digest": digest(&repo.read(&answers::path("survey")))})
    );
    assert!(repo.plan(&[&SurveyV2]).unwrap().changes.is_empty());
}

#[test]
fn install_module_records_it_and_a_later_install_without_module_reconciles_it() {
    let repo = Repo::new();
    let registry: Vec<&dyn Module> = vec![&SetupCore, &Base, &Survey];
    let profile = profile_for(&repo.root).unwrap();
    let selected = engine::select(&registry, None, &["survey"]).unwrap();
    let planned =
        engine::plan(&repo.root, &Repo::source(), &profile, &selected, &|_| true).unwrap();
    apply(&repo.root, &planned.changes).unwrap();
    assert_eq!(
        repo.value(LOCK)["modules"]["survey"]["version"],
        json!("1.0.0")
    );
    assert!(repo.value(LOCK)["modules"].get("base").is_none());

    // Plain `install`: setup-core and survey, nothing else; the recorded module
    // is reconciled, so its edited answers reach the rendered file.
    repo.answers_file(json!({"count": 9}));
    let selected = engine::select(&registry, Some(&repo.lock()), &[]).unwrap();
    assert_eq!(ids(&selected), vec!["setup-core", "survey"]);
    let planned =
        engine::plan(&repo.root, &Repo::source(), &profile, &selected, &|_| true).unwrap();
    assert!(planned.changes.contains_key("docs/agent-setup/survey.json"));
    apply(&repo.root, &planned.changes).unwrap();
    assert_eq!(
        repo.value("docs/agent-setup/survey.json")["count"],
        json!(9)
    );
}

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "asserts setup-core's own content or id; product-boundary T7b"
)]
#[test]
fn cli_install_module_refuses_an_unknown_id_and_reconciles_a_known_one() {
    let repo = Repo::new();
    let result = repo.cli(&["install", "<repo>", "--new-personal", "--module", "nope"]);
    assert_eq!(result.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&result.stderr).trim(),
        "REFUSED: Unknown module id: nope"
    );
    assert!(!repo.root.join(LOCK).exists());

    assert!(
        repo.cli(&["install", "<repo>", "--new-personal", "--apply"])
            .status
            .success()
    );
    let result = repo.cli(&["install", "<repo>", "--module", "setup-core"]);
    assert!(result.status.success(), "{result:?}");
    assert!(String::from_utf8_lossy(&result.stdout).contains("No changes."));

    let result = repo.cli(&["doctor", "<repo>", "--module", "setup-core"]);
    assert_eq!(result.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&result.stderr).trim(),
        "REFUSED: --module is only available with install"
    );
    let result = repo.cli(&["install", "<repo>", "--module"]);
    assert_eq!(result.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&result.stderr).trim(),
        "REFUSED: --module needs a module id"
    );
}

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "asserts setup-core's own content or id; product-boundary T7b"
)]
#[test]
fn plan_install_activates_the_requested_module_through_the_library() {
    let repo = Repo::new();
    assert!(
        repo.cli(&["install", "<repo>", "--new-personal", "--apply"])
            .status
            .success()
    );
    let planned =
        brakes::plan_install(&repo.root, &Source::embedded(), &["setup-core"], None).unwrap();
    assert!(planned.changes.is_empty(), "{planned:?}");
    assert_eq!(
        brakes::plan_install(&repo.root, &Source::embedded(), &["nope"], None)
            .map(|p| p.changes)
            .unwrap_err()
            .to_string(),
        "Unknown module id: nope"
    );
}

// ---- #831: `configure` plans the installed modules and the configured one ----

#[test]
fn configure_plans_the_installed_modules_and_the_configured_one_not_every_registered_one() {
    let repo = Repo::new();
    let planned = repo.plan(&[&SetupCore]).unwrap();
    apply(&repo.root, &planned.changes).unwrap();
    // `dependent` is registered but not installed, and its `base` is absent: it
    // neither renders nor makes the plan refuse on its requirement.
    let registry: Vec<&dyn Module> = vec![&SetupCore, &Dependent, &Survey];
    let planned = repo.configure(&registry, "setup-core", json!({})).unwrap();
    assert!(
        !planned
            .changes
            .contains_key("docs/agent-setup/dependent.md")
    );
    assert!(!planned.changes.contains_key("docs/agent-setup/survey.json"));

    // Configuring `survey` adds it, and only it, to the installed set.
    let planned = repo.configure(&registry, "survey", json!({})).unwrap();
    assert!(planned.changes.contains_key("docs/agent-setup/survey.json"));
    assert!(
        !planned
            .changes
            .contains_key("docs/agent-setup/dependent.md")
    );
    apply(&repo.root, &planned.changes).unwrap();
    assert_eq!(
        repo.lock()
            .modules
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec!["setup-core", "survey"]
    );

    // A later `configure setup-core` keeps reconciling the installed `survey`.
    repo.answers_file(json!({"count": 7}));
    let planned = repo.configure(&registry, "setup-core", json!({})).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(
            planned.changes["docs/agent-setup/survey.json"]
                .as_deref()
                .unwrap()
        )
        .unwrap()["count"],
        json!(7)
    );
    assert!(
        !planned
            .changes
            .contains_key("docs/agent-setup/dependent.md")
    );
}

#[test]
fn remove_reads_the_lock_and_ignores_registered_modules_that_are_not_installed() {
    let repo = Repo::new();
    let planned = repo.plan(&[&SetupCore, &Survey]).unwrap();
    apply(&repo.root, &planned.changes).unwrap();
    let registry: Vec<&dyn Module> = vec![&SetupCore, &Base, &Dependent, &Survey];
    let planned = engine::remove(&repo.root, &registry, &|_| true, "survey").unwrap();
    assert_eq!(
        planned
            .changes
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec![LOCK, "docs/agent-setup/survey.json"]
    );
    assert_eq!(planned.changes["docs/agent-setup/survey.json"], None);
    assert_eq!(
        engine::remove(&repo.root, &registry, &|_| true, "dependent")
            .unwrap_err()
            .to_string(),
        "Module dependent is not installed; nothing to remove"
    );
}

/// repo-baseline T7 (#710): the profile recorded with the answers survives a
/// migration, and a file without one parses as before and is written without one.
#[test]
fn a_version_bump_keeps_the_recorded_profile() {
    let repo = Repo::new();
    let text = serde_json::to_string_pretty(
        &json!({"module": "survey", "version": "1.0.0", "profile": "P3", "answers": {"count": 7}}),
    )
    .unwrap()
        + "\n";
    repo.write(&answers::path("survey"), &text);
    let planned = repo.plan(&[&Survey]).unwrap();
    apply(&repo.root, &planned.changes).unwrap();
    let planned = repo.plan(&[&SurveyV2]).unwrap();
    let file: Value = serde_json::from_str(
        planned.changes[&answers::path("survey")]
            .as_deref()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(file["profile"], json!("P3"));
    assert_eq!(file["version"], json!("1.1.0"));

    let plain = Repo::new();
    plain.answers_file(json!({"count": 7}));
    let planned = plain.plan(&[&Survey]).unwrap();
    apply(&plain.root, &planned.changes).unwrap();
    let planned = plain.plan(&[&SurveyV2]).unwrap();
    let file: Value = serde_json::from_str(
        planned.changes[&answers::path("survey")]
            .as_deref()
            .unwrap(),
    )
    .unwrap();
    assert!(file.get("profile").is_none(), "{file}");
}
