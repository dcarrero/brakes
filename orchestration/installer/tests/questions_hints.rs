//! Question hints (SPEC-questions.md, schema extensions; #714): the typed
//! `x-ui`, `x-plan-dependency` and `x-configure-new` hints, the rendering order
//! the TUI and the MCP server share, and the load-time lint every compiled
//! module must pass.
use brakes::engine::answers::Schema;
use brakes::modules;
use brakes::questions::hints::{self, Hints, lint, ordered};
use serde_json::{Value, json};

fn schema(questions: Value) -> Schema {
    Schema::parse(&questions).unwrap()
}

/// The findings of `lint` as printed, so a test compares exact wording.
fn findings(module: &str, questions: Value) -> Vec<String> {
    lint(module, &schema(questions))
        .iter()
        .map(ToString::to_string)
        .collect()
}

/// The spec's example question, with every hint.
fn approvals() -> Value {
    json!({
        "id": "approvals", "type": "string",
        "enum": ["checks-only", "one-approval", "other"], "default": "checks-only",
        "description": "Who can merge",
        "x-ui": {"label": "Merge policy", "help": "Longer text shown on `?`", "group": "Policy", "order": 10},
        "x-plan-dependency": {"feature": "rulesets-private-repo", "values": ["one-approval"]},
        "x-configure-new": {"contract": "repo-baseline.approvals"}
    })
}

#[test]
fn hints_parse_the_three_extensions_of_the_spec_example() {
    let schema = schema(json!([approvals()]));
    let hints = Hints::of(schema.question("approvals").unwrap());
    assert_eq!(hints.ui.label.as_deref(), Some("Merge policy"));
    assert_eq!(hints.ui.help.as_deref(), Some("Longer text shown on `?`"));
    assert_eq!(hints.ui.group.as_deref(), Some("Policy"));
    assert_eq!(hints.ui.order, Some(10));
    let dependency = hints.plan_dependency.as_ref().unwrap();
    assert_eq!(dependency.feature, "rulesets-private-repo");
    assert_eq!(dependency.values, ["one-approval"]);
    assert_eq!(
        hints.configure_new.as_ref().unwrap().contract,
        "repo-baseline.approvals"
    );
    assert!(hints.unknown.is_empty());
    assert!(hints.malformed.is_empty());
}

#[test]
fn hints_of_a_question_without_extensions_are_empty() {
    let schema = schema(json!([{"id": "plain", "type": "boolean", "description": "A flag"}]));
    let hints = Hints::of(schema.question("plain").unwrap());
    assert_eq!(hints, Hints::default());
}

#[test]
fn a_bare_string_plan_dependency_applies_to_every_value() {
    let schema = schema(json!([{
        "id": "runner", "type": "string", "enum": ["github", "self-hosted"], "description": "Runner",
        "x-plan-dependency": "actions-larger-runners"
    }]));
    let hints = Hints::of(schema.question("runner").unwrap());
    let dependency = hints.plan_dependency.as_ref().unwrap();
    assert_eq!(dependency.feature, "actions-larger-runners");
    assert!(dependency.values.is_empty());
    assert!(dependency.applies_to("github"));
    assert!(dependency.applies_to("self-hosted"));
}

#[test]
fn unknown_and_malformed_extensions_are_kept_for_the_lint_not_refused() {
    let schema = schema(json!([{
        "id": "q", "type": "string", "description": "Q",
        "x-ui": {"label": 7, "order": "first"},
        "x-plan-dependency": 3,
        "x-configure-new": true,
        "x-colour": "red"
    }]));
    let hints = Hints::of(schema.question("q").unwrap());
    assert_eq!(hints.unknown, ["x-colour"]);
    assert_eq!(
        hints.malformed,
        [
            "`x-configure-new` must be an object with a string `contract`",
            "`x-plan-dependency` must be a string or an object with a string `feature`",
            "`x-ui.label` must be a non-empty string",
            "`x-ui.order` must be an integer",
        ]
    );
    assert_eq!(hints.ui.label, None);
    assert_eq!(hints.ui.order, None);
    assert!(hints.plan_dependency.is_none());
    assert!(hints.configure_new.is_none());
}

#[test]
fn ordered_sorts_by_order_with_ties_and_unordered_questions_in_schema_order() {
    let schema = schema(json!([
        {"id": "d", "type": "string", "description": "D"},
        {"id": "b", "type": "string", "description": "B", "x-ui": {"order": 20}},
        {"id": "a", "type": "string", "description": "A", "x-ui": {"order": 10}},
        {"id": "e", "type": "string", "description": "E"},
        {"id": "c", "type": "string", "description": "C", "x-ui": {"order": 20}},
    ]));
    let ids: Vec<&str> = ordered(&schema)
        .iter()
        .map(|entry| entry.question.id.as_str())
        .collect();
    assert_eq!(ids, ["a", "b", "c", "d", "e"]);
    // Deterministic: the same schema always yields the same order.
    let again: Vec<&str> = ordered(&schema)
        .iter()
        .map(|entry| entry.question.id.as_str())
        .collect();
    assert_eq!(ids, again);
}

#[test]
fn ordered_produces_a_group_header_once_and_the_label_replaces_the_id() {
    let schema = schema(json!([
        {"id": "codeowners", "type": "boolean", "description": "Require CODEOWNERS",
         "x-ui": {"group": "Policy", "order": 20}},
        approvals(),
        {"id": "name", "type": "string", "description": "Repository name"},
        {"id": "dependency_updates", "type": "boolean", "description": "Dependabot",
         "x-ui": {"label": "Dependency updates", "group": "Policy", "order": 30}},
    ]));
    let entries = ordered(&schema);
    let rendered: Vec<(Option<&str>, &str, &str)> = entries
        .iter()
        .map(|entry| (entry.header.as_deref(), entry.label(), entry.help()))
        .collect();
    assert_eq!(
        rendered,
        [
            (Some("Policy"), "Merge policy", "Longer text shown on `?`"),
            (None, "codeowners", "Require CODEOWNERS"),
            (None, "Dependency updates", "Dependabot"),
            (None, "name", "Repository name"),
        ]
    );
}

#[test]
fn the_plan_dependency_note_marks_only_the_values_that_need_the_feature() {
    let schema = schema(json!([approvals()]));
    let entries = ordered(&schema);
    let lines: Vec<String> = ["checks-only", "one-approval", "other"]
        .iter()
        .map(|value| entries[0].option_line(value))
        .collect();
    assert_eq!(
        lines,
        [
            "checks-only",
            "one-approval  (needs GitHub feature rulesets-private-repo: not checked)",
            "other — configure new (seed skeleton + manual steps)",
        ]
    );
    assert_eq!(
        hints::plan_dependency_note("rulesets-private-repo"),
        "(needs GitHub feature rulesets-private-repo: not checked)"
    );
}

#[test]
fn lint_passes_the_spec_example_and_a_schema_without_hints() {
    assert!(findings("m", json!([approvals()])).is_empty());
    assert!(
        findings(
            "m",
            json!([
                {"id": "name", "type": "string", "description": "Name"},
                {"id": "flavour", "type": "string", "enum": ["vanilla", "chocolate"],
                 "description": "Flavour"},
            ])
        )
        .is_empty()
    );
    assert!(findings("m", json!([])).is_empty());
}

#[test]
fn lint_reports_a_question_with_neither_label_nor_description() {
    assert_eq!(
        findings(
            "m",
            json!([
                {"id": "silent", "type": "string"},
                {"id": "blank", "type": "string", "description": "  "},
                {"id": "labelled", "type": "string", "x-ui": {"label": "Fine"}},
            ])
        ),
        [
            "Module m: question `silent` has neither `x-ui.label` nor a `description`",
            "Module m: question `blank` has neither `x-ui.label` nor a `description`",
        ]
    );
}

#[test]
fn lint_reports_an_order_collision_inside_a_group() {
    assert_eq!(
        findings(
            "m",
            json!([
                {"id": "a", "type": "string", "description": "A", "x-ui": {"group": "Policy", "order": 10}},
                {"id": "b", "type": "string", "description": "B", "x-ui": {"group": "Policy", "order": 10}},
                {"id": "c", "type": "string", "description": "C", "x-ui": {"group": "Other", "order": 10}},
                {"id": "d", "type": "string", "description": "D", "x-ui": {"order": 5}},
                {"id": "e", "type": "string", "description": "E", "x-ui": {"order": 5}},
            ])
        ),
        // Findings come in asking order: order 5 is asked before order 10.
        [
            "Module m: question `e` has `x-ui.order` 5, already used by `d` outside any group",
            "Module m: question `b` has `x-ui.order` 10, already used by `a` in group `Policy`",
        ]
    );
}

#[test]
fn lint_reports_configure_new_on_a_non_enum_and_on_an_enum_without_other() {
    assert_eq!(
        findings(
            "m",
            json!([
                {"id": "free", "type": "string", "description": "Free",
                 "x-configure-new": {"contract": "m.free"}},
                {"id": "flag", "type": "boolean", "description": "Flag",
                 "x-configure-new": {"contract": "m.flag"}},
                {"id": "closed", "type": "string", "enum": ["a", "b"], "description": "Closed",
                 "x-configure-new": {"contract": "m.closed"}},
            ])
        ),
        [
            "Module m: question `free` has `x-configure-new` but is not an enum",
            "Module m: question `flag` has `x-configure-new` but is not an enum",
            "Module m: question `closed` has `x-configure-new` but its enum does not list `other`",
        ]
    );
}

#[test]
fn lint_reports_other_without_configure_new_on_enums_and_arrays_of_enum() {
    assert_eq!(
        findings(
            "m",
            json!([
                {"id": "target", "type": "string", "enum": ["vps", "other"], "description": "Target"},
                {"id": "channels", "type": "array", "items": {"type": "string", "enum": ["slack", "other"]},
                 "description": "Channels"},
                {"id": "declared", "type": "string", "enum": ["vps", "other"], "description": "Declared",
                 "x-configure-new": {"contract": "m.declared"}},
            ])
        ),
        [
            "Module m: question `target` lists `other` without `x-configure-new`",
            "Module m: question `channels` lists `other` without `x-configure-new`",
        ]
    );
}

#[test]
fn lint_reports_a_plan_dependency_on_a_non_enum_or_naming_a_missing_value() {
    assert_eq!(
        findings(
            "m",
            json!([
                {"id": "flag", "type": "boolean", "description": "Flag",
                 "x-plan-dependency": "rulesets-private-repo"},
                {"id": "approvals", "type": "string", "enum": ["checks-only", "one-approval"],
                 "description": "Approvals",
                 "x-plan-dependency": {"feature": "rulesets-private-repo", "values": ["two-approvals"]}},
            ])
        ),
        [
            "Module m: question `flag` has `x-plan-dependency` but is not an enum",
            "Module m: question `approvals` has `x-plan-dependency` on `two-approvals`, which is not a value of its enum",
        ]
    );
}

#[test]
fn lint_reports_a_when_that_reads_a_question_asked_later_once_sorted() {
    // In schema order `enabled` precedes `detail`, so the engine accepts it; the
    // hints move `detail` first and the TUI could not evaluate its `when`.
    let questions = json!([
        {"id": "enabled", "type": "boolean", "description": "Enabled"},
        {"id": "detail", "type": "string", "description": "Detail", "when": "enabled",
         "x-ui": {"order": 1}},
    ]);
    assert!(schema(questions.clone()).check("m").is_ok());
    assert_eq!(
        findings("m", questions),
        [
            "Module m: question `detail` has a `when` on `enabled`, which is asked later once sorted by `x-ui.order`"
        ]
    );
}

#[test]
fn lint_reports_unknown_and_malformed_extensions() {
    assert_eq!(
        findings(
            "m",
            json!([{
                "id": "q", "type": "string", "description": "Q",
                "x-ui": "Merge policy",
                "x-colour": "red"
            }])
        ),
        [
            "Module m: question `q` uses unknown extension `x-colour`; known: `x-configure-new`, `x-plan-dependency`, `x-ui`",
            "Module m: question `q` has a malformed hint: `x-ui` must be an object",
        ]
    );
}

#[test]
fn check_refuses_at_load_with_the_first_finding() {
    let schema = schema(json!([
        {"id": "target", "type": "string", "enum": ["vps", "other"], "description": "Target"},
        {"id": "silent", "type": "string"},
    ]));
    assert_eq!(
        hints::check("delivery", &schema).unwrap_err().to_string(),
        "Module delivery: question `target` lists `other` without `x-configure-new`"
    );
    assert!(hints::check("m", &Schema::default()).is_ok());
}

/// A module with bad hints cannot compile in silently: this test names the
/// module and the question when one does.
#[test]
fn every_compiled_module_passes_the_hints_lint() {
    let modules = modules::all();
    assert!(!modules.is_empty());
    let findings: Vec<String> = modules
        .iter()
        .flat_map(|module| lint(module.id(), &module.questions()))
        .map(|finding| finding.to_string())
        .collect();
    assert!(findings.is_empty(), "{}", findings.join("\n"));
}

// ---- #725: the "configure new" contract ----------------------------------------------

use brakes::engine::answers;
use brakes::engine::{
    Context, EnvVar, IntegrationContract, ManualStep, Module, NoRunner, Ownership, Probe, Rendered,
    StepState,
};
use brakes::questions::{Inputs, configure_new};
use brakes::{Source, apply, profile_for};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const SKELETON: &str = "deploy/target.sh";
const GUIDE: &str = "docs/agent-setup/integrations/deploy.target.md";

/// How the fixture's contract is (mis)shaped, so one module covers every refusal.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Shape {
    Good,
    None,
    WrongId,
    NoMarker,
    Managed,
    GuideElsewhere,
    FileProbe,
    UnknownEnv,
}

/// A module whose enum lists `other` and declares `x-configure-new`; its
/// contract is shaped by `Shape`. No compiled module declares `other` yet.
struct Deploy(Shape);
impl Module for Deploy {
    fn id(&self) -> &'static str {
        "deploy"
    }
    fn version(&self) -> &'static str {
        "1.0.0"
    }
    fn questions(&self) -> Schema {
        schema(json!([{
            "id": "target", "type": "string", "enum": ["none", "other"], "default": "none",
            "description": "Where the application is delivered.",
            "x-configure-new": {"contract": "deploy.target"}
        }]))
    }
    fn render(&self, _: &Context<'_>) -> brakes::Result<Vec<Rendered>> {
        Ok(Vec::new())
    }
    fn configure_new(&self, question: &str, _: &Context<'_>) -> Option<IntegrationContract> {
        if question != "target" || self.0 == Shape::None {
            return None;
        }
        let seed = |path: &str, class: Ownership, text: &str| Rendered {
            path: path.to_owned(),
            class,
            content: Some(text.to_owned()),
            scaffold: None,
        };
        let skeleton = match self.0 {
            Shape::NoMarker => "#!/bin/sh\nexit 1\n",
            _ => {
                "#!/bin/sh\n# TODO(configure-new): deliver the build to the target named by DEPLOY_URL.\nexit 1\n"
            }
        };
        let mut steps = vec![
            configure_new::endpoint_answers(if self.0 == Shape::UnknownEnv {
                "MISSING_URL"
            } else {
                "DEPLOY_URL"
            }),
            configure_new::secret_exists("DEPLOY_TOKEN", "production"),
        ];
        if self.0 == Shape::FileProbe {
            steps.push(ManualStep {
                id: "file".to_owned(),
                title: "A file".to_owned(),
                owner: brakes::engine::manual::Owner::Owner,
                instructions: "Write it.".to_owned(),
                probe: Probe::FileExists {
                    path: "x".to_owned(),
                },
                after: None,
            });
        }
        Some(IntegrationContract {
            id: if self.0 == Shape::WrongId {
                "deploy.other"
            } else {
                "deploy.target"
            },
            env: vec![EnvVar {
                name: "DEPLOY_URL".to_owned(),
                purpose: "The URL the delivered application answers on.".to_owned(),
                example: "https://app.example.org".to_owned(),
                required: true,
            }],
            seed: vec![seed(
                SKELETON,
                if self.0 == Shape::Managed {
                    Ownership::Managed
                } else {
                    Ownership::Seed
                },
                skeleton,
            )],
            steps,
            guide: seed(
                if self.0 == Shape::GuideElsewhere {
                    "docs/deploy.md"
                } else {
                    GUIDE
                },
                Ownership::Seed,
                "# Deliver to a new target\n\nTODO(configure-new): name the provider and finish the skeleton in one PR.\n",
            ),
        })
    }
}

struct Checkout {
    _temp: tempfile::TempDir,
    root: PathBuf,
}
impl Checkout {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("project");
        std::fs::create_dir(&root).unwrap();
        assert!(
            std::process::Command::new("git")
                .args(["init", "-q"])
                .arg(&root)
                .status()
                .unwrap()
                .success()
        );
        Self { _temp: temp, root }
    }
    fn configure(&self, module: &Deploy, target: &str) -> brakes::Result<questions::Configured> {
        let profile = profile_for(&self.root).unwrap();
        questions::configure(
            &self.root,
            &source(),
            &profile,
            &[module],
            &|_| true,
            "deploy",
            &Inputs {
                sets: vec![format!("target={target}")],
                ..Inputs::default()
            },
        )
    }
    fn refusal(&self, shape: Shape) -> String {
        self.configure(&Deploy(shape), "other")
            .unwrap_err()
            .to_string()
    }
}

use brakes::questions;

fn source() -> Source {
    Source {
        documents: BTreeMap::new(),
        version: "0.1.0".to_owned(),
        revision: None,
        dirty: false,
    }
}

#[test]
fn picking_other_plans_the_skeleton_and_guide_as_seeds_and_the_two_probes_unavailable() {
    let checkout = Checkout::new();
    let planned = checkout
        .configure(&Deploy(Shape::Good), "other")
        .unwrap()
        .planned;
    for path in [SKELETON, GUIDE] {
        assert_eq!(
            planned.tags[path],
            (Ownership::Seed, "deploy".to_owned()),
            "{path}"
        );
        assert!(
            planned.changes[path]
                .as_deref()
                .unwrap()
                .contains("TODO(configure-new):"),
            "{path}"
        );
    }
    let lines: Vec<String> = planned.steps.iter().map(|s| s.plan_line()).collect();
    assert_eq!(
        lines,
        [
            "STEP [unavailable:deploy] endpoint-answers-deploy-url — The endpoint named by DEPLOY_URL answers",
            "STEP [unavailable:deploy] secret-exists-deploy-token — Secret DEPLOY_TOKEN exists in environment production",
        ]
    );
    assert!(
        planned
            .steps
            .iter()
            .all(|s| s.state == StepState::Unavailable)
    );
    let recorded = answers::AnswersFile::parse(
        "deploy",
        planned.changes[&answers::path("deploy")]
            .as_deref()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(&recorded.answers).unwrap(),
        json!({"target": "other"})
    );
}

#[test]
fn the_guide_carries_the_env_contract_and_never_a_secret_value() {
    let checkout = Checkout::new();
    let planned = checkout
        .configure(&Deploy(Shape::Good), "other")
        .unwrap()
        .planned;
    let guide = planned.changes[GUIDE].as_deref().unwrap();
    assert!(guide.contains("## Environment contract\n"), "{guide}");
    assert!(
        guide.contains("| `DEPLOY_URL` | yes | The URL the delivered application answers on. | `https://app.example.org` |\n"),
        "{guide}"
    );
    assert!(guide.ends_with('\n'));
    // The secret is probed by name and environment only; the registry takes no value.
    let step = configure_new::secret_exists("DEPLOY_TOKEN", "production");
    let Probe::Remote { id, args } = &step.probe else {
        panic!("secret-exists is a remote probe");
    };
    assert_eq!(id, "secret-exists");
    assert_eq!(
        args.keys().map(String::as_str).collect::<Vec<_>>(),
        ["environment", "name"]
    );
    let mut with_value = args.clone();
    with_value.insert("value".to_owned(), json!("s3cr3t"));
    assert_eq!(
        brakes::host::probes::check("secret-exists", &with_value),
        Err("remote probe `secret-exists` has no argument `value`".to_owned())
    );
}

#[test]
fn an_answer_other_than_other_plans_no_contract() {
    let checkout = Checkout::new();
    let planned = checkout
        .configure(&Deploy(Shape::Good), "none")
        .unwrap()
        .planned;
    assert!(!planned.tags.contains_key(SKELETON));
    assert!(!planned.tags.contains_key(GUIDE));
    assert!(planned.steps.is_empty());
}

#[test]
fn a_seed_being_filled_is_never_overwritten() {
    let checkout = Checkout::new();
    let planned = checkout
        .configure(&Deploy(Shape::Good), "other")
        .unwrap()
        .planned;
    apply(&checkout.root, &planned.changes).unwrap();
    let filled = "#!/bin/sh\nrsync build/ host:/srv/app\n";
    std::fs::write(checkout.root.join(SKELETON), filled).unwrap();
    let again = checkout
        .configure(&Deploy(Shape::Good), "other")
        .unwrap()
        .planned;
    assert!(!again.changes.contains_key(SKELETON));
    assert!(!again.changes.contains_key(GUIDE));
    assert_eq!(again.notes.get(SKELETON), Some(&brakes::engine::Note::Skip));
    apply(&checkout.root, &again.changes).unwrap();
    assert_eq!(
        std::fs::read_to_string(checkout.root.join(SKELETON)).unwrap(),
        filled
    );
}

#[test]
fn a_contract_that_breaks_the_rules_is_refused_naming_module_and_contract() {
    let checkout = Checkout::new();
    for (shape, message) in [
        (
            Shape::None,
            "Module deploy: question `target` is answered `other` but `configure_new` returns no contract",
        ),
        (
            Shape::WrongId,
            "Module deploy: question `target` declares contract `deploy.target` but `configure_new` returns `deploy.other`",
        ),
        (
            Shape::NoMarker,
            "Module deploy: contract `deploy.target` file deploy/target.sh carries no `TODO(configure-new):` marker",
        ),
        (
            Shape::Managed,
            "Module deploy: contract `deploy.target` renders deploy/target.sh as managed; a contract renders seeds only",
        ),
        (
            Shape::GuideElsewhere,
            "Module deploy: contract `deploy.target` guide must be docs/agent-setup/integrations/deploy.target.md, not docs/deploy.md",
        ),
        (
            Shape::FileProbe,
            "Module deploy: contract `deploy.target` step `file` uses a probe other than the generic remote `endpoint-answers` and `secret-exists`",
        ),
        (
            Shape::UnknownEnv,
            "Module deploy: contract `deploy.target` step `endpoint-answers-missing-url` probes `MISSING_URL`, which is not in its env contract",
        ),
    ] {
        assert_eq!(checkout.refusal(shape), message);
    }
}

#[test]
fn doctor_reports_the_two_generic_probes_unavailable_without_a_runner() {
    let checkout = Checkout::new();
    let planned = checkout
        .configure(&Deploy(Shape::Good), "other")
        .unwrap()
        .planned;
    apply(&checkout.root, &planned.changes).unwrap();
    let previous = brakes::engine::installed_lock(&checkout.root, "0.0.0", &|_| true)
        .unwrap()
        .unwrap();
    let profile = profile_for(&checkout.root).unwrap();
    let steps = brakes::engine::steps(
        &checkout.root,
        &source(),
        &profile,
        &[&Deploy(Shape::Good)],
        &previous,
        &NoRunner,
    )
    .unwrap();
    assert_eq!(steps.len(), 2);
    assert!(steps.iter().all(|s| s.state == StepState::Unavailable));
}

/// A context with no lock and no answers, as the CI test reads every module.
fn bare_context<'a>(
    root: &'a Path,
    profile: &'a brakes::profile::Profile,
    source: &'a Source,
    lock: &'a brakes::engine::Lock,
    answers: &'a answers::Answers,
    module: &'a dyn Module,
    resolved: &'a BTreeMap<String, answers::Answers>,
) -> Context<'a> {
    Context::new(root, profile, source, lock, answers, module, resolved)
}

fn empty_lock() -> brakes::engine::Lock {
    brakes::engine::Lock {
        schema: brakes::engine::lock::SCHEMA,
        version: "0.1.0".to_owned(),
        source_commit: None,
        source_dirty: false,
        personal_owner: brakes::config::current_owner(),
        modules: BTreeMap::new(),
        files: BTreeMap::new(),
    }
}

/// Every `x-configure-new` question of `module` gets a contract, or the
/// refusal naming module and question.
fn declared(module: &dyn Module) -> brakes::Result<()> {
    let checkout = Checkout::new();
    let profile = profile_for(&checkout.root).unwrap();
    let source = source();
    let lock = empty_lock();
    let answers = answers::Answers::new();
    let resolved = BTreeMap::new();
    let cx = bare_context(
        &checkout.root,
        &profile,
        &source,
        &lock,
        &answers,
        module,
        &resolved,
    );
    configure_new::check_declared(module, &cx)
}

#[test]
fn a_module_declaring_configure_new_without_a_contract_fails_naming_module_and_question() {
    assert!(declared(&Deploy(Shape::Good)).is_ok());
    assert_eq!(
        declared(&Deploy(Shape::None)).unwrap_err().to_string(),
        "Module deploy: question `target` declares `x-configure-new` but `configure_new` returns None"
    );
}

/// The CI gate of decision 3: a compiled module that declares `x-configure-new`
/// returns a contract for that question.
#[test]
fn every_compiled_module_returns_a_contract_for_each_declared_question() {
    let failures: Vec<String> = modules::all()
        .into_iter()
        .filter_map(|module| declared(module).err().map(|e| e.to_string()))
        .collect();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn the_summary_names_what_the_real_contract_generates() {
    let checkout = Checkout::new();
    let profile = profile_for(&checkout.root).unwrap();
    let source = source();
    let lock = empty_lock();
    let answers = answers::Answers::new();
    let resolved = BTreeMap::new();
    let module = Deploy(Shape::Good);
    let cx = bare_context(
        &checkout.root,
        &profile,
        &source,
        &lock,
        &answers,
        &module,
        &resolved,
    );
    let contract = module.configure_new("target", &cx).unwrap();
    assert_eq!(
        configure_new::summary(&contract),
        "other: contract deploy.target; the plan generates an env contract (DEPLOY_URL), a seed skeleton (deploy/target.sh), a seed guide (docs/agent-setup/integrations/deploy.target.md) and 2 manual steps (endpoint-answers-deploy-url, secret-exists-deploy-token)."
    );
}
