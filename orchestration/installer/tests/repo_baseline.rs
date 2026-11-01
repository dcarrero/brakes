//! repo-baseline T1 (#700): the ruleset as a value by profile and answers, its
//! refusals, the five-contexts finding, and the two managed files rendered through
//! `engine::plan` with an explicit module list (the module is not registered yet).
//! T2 (#701): the three questions on the engine's answers, their per-profile
//! defaults, and `configure` routing them into the ruleset and the seed selection.
//! T3 (#702): the issue forms and `config.yml` as managed files, pinned by goldens.
//! T4 (#703): the PR template's managed block and the skeleton written around it
//! when the file is absent.
//! T6 (#707): the remote items and the `check-reported` step with their probes
//! (decision #848), the label set and the RFC template.
//! T5 (#705): the seeds (service card, SECURITY.md, CODEOWNERS, dependabot.yml or
//! renovate.json), skipped when present, and the four goldens.
//! T8 (#942): the `human-approved` label and the CODEOWNERS lines for the
//! protected paths (workflows and the held-out directory `ci-baseline` answers).
mod support;
use brakes::engine::answers::{self as engine_answers, DEFAULT_TIER, Kind};
use brakes::engine::{self, Module, Ownership, Planned};
use brakes::modules::repo_baseline::{
    Choices, DependencyUpdates, ISSUE_FORM_PATHS, PR_TEMPLATE_PATH, REVIEW_RULESET_PATH,
    RULESET_PATH, RepoBaseline, SERVICE_SCHEMA_PATH, questions_schema,
    ruleset::{Answers, Approvals, Tier, default_checks, required_checks, ruleset},
    service_schema,
};
use brakes::profile::Profile;
use brakes::questions::{self, Inputs};
use brakes::*;
use serde_json::{Value, json};
use std::fs;
use tempfile::TempDir;

fn project(value: Value) -> Profile {
    Profile {
        value,
        raw: None,
        command_names: Vec::new(),
    }
}
fn plain_project() -> Profile {
    project(default_profile())
}
fn five_contexts_project() -> Profile {
    let mut value = default_profile();
    value["ci"]["required_checks"] = json!([
        "Rust (linux)",
        "Rust (macos)",
        "test / verify",
        "build",
        "promote"
    ]);
    project(value)
}
fn rule<'a>(value: &'a Value, kind: &str) -> &'a Value {
    value["rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["type"] == kind)
        .unwrap_or_else(|| panic!("rule {kind} missing in {value}"))
}
fn contexts(value: &Value) -> Vec<&Value> {
    rule(value, "required_status_checks")["parameters"]["required_status_checks"]
        .as_array()
        .unwrap()
        .iter()
        .collect()
}
fn value_of(tier: Tier, answers: &Answers, project: &Profile) -> Value {
    ruleset(tier, answers, project, &default_checks())
        .unwrap()
        .value
}

// ---- the value ----------------------------------------------------------------

#[test]
fn p1_defaults_render_the_spec_ruleset_byte_for_byte() {
    let out = ruleset(
        Tier::P1,
        &Answers::defaults(Tier::P1),
        &plain_project(),
        &default_checks(),
    )
    .unwrap();
    assert_eq!(
        out.value,
        json!({
            "name": "brakes: default branch baseline",
            "target": "branch",
            "enforcement": "active",
            "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
            "bypass_actors": [],
            "rules": [
                { "type": "deletion" },
                { "type": "non_fast_forward" },
                { "type": "required_linear_history" },
                { "type": "pull_request", "parameters": {
                    "required_approving_review_count": 0,
                    "dismiss_stale_reviews_on_push": true,
                    "require_code_owner_review": false,
                    "require_last_push_approval": false,
                    "required_review_thread_resolution": true,
                    "allowed_merge_methods": ["squash"] } },
                { "type": "required_status_checks", "parameters": {
                    "strict_required_status_checks_policy": true,
                    "do_not_enforce_on_create": false,
                    "required_status_checks": [ { "context": "required", "integration_id": 15368 } ] } }
            ]
        })
    );
    assert!(out.findings.is_empty(), "{:?}", out.findings);
}

#[test]
fn exactly_one_context_with_integration_id_by_default_in_every_tier() {
    for tier in [Tier::P1, Tier::P2, Tier::P3] {
        let value = value_of(tier, &Answers::defaults(tier), &plain_project());
        let checks = contexts(&value);
        assert_eq!(checks.len(), 1, "{tier:?}");
        assert_eq!(checks[0]["context"], "required", "{tier:?}");
        assert_eq!(checks[0]["integration_id"], 15368, "{tier:?}");
        assert_eq!(
            rule(&value, "required_status_checks")["parameters"]["strict_required_status_checks_policy"],
            true
        );
    }
}

#[test]
fn bypass_actors_are_empty_except_for_owner_bypass_in_p1() {
    for tier in [Tier::P1, Tier::P2, Tier::P3] {
        let value = value_of(tier, &Answers::defaults(tier), &plain_project());
        assert_eq!(value["bypass_actors"], json!([]), "{tier:?}");
    }
    let answers = Answers {
        approvals: Approvals::ChecksOnlyOwnerBypass,
        codeowners: false,
        bypass_actors: Vec::new(),
    };
    let value = value_of(Tier::P1, &answers, &plain_project());
    assert_eq!(
        value["bypass_actors"],
        json!([{ "actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always" }])
    );
    assert_eq!(
        rule(&value, "pull_request")["parameters"]["required_approving_review_count"],
        0
    );
}

#[test]
fn one_approval_sets_the_three_review_parameters() {
    for tier in [Tier::P2, Tier::P3] {
        let value = value_of(tier, &Answers::defaults(tier), &plain_project());
        let parameters = &rule(&value, "pull_request")["parameters"];
        assert_eq!(parameters["required_approving_review_count"], 1, "{tier:?}");
        assert_eq!(parameters["require_last_push_approval"], true, "{tier:?}");
        assert_eq!(parameters["require_code_owner_review"], true, "{tier:?}");
        assert_eq!(
            parameters["dismiss_stale_reviews_on_push"], true,
            "{tier:?}"
        );
        assert_eq!(value["bypass_actors"], json!([]), "{tier:?}");
    }
    let without_codeowners = Answers {
        approvals: Approvals::OneApproval,
        codeowners: false,
        bypass_actors: Vec::new(),
    };
    let value = value_of(Tier::P2, &without_codeowners, &plain_project());
    assert_eq!(
        rule(&value, "pull_request")["parameters"]["require_code_owner_review"],
        false
    );
}

#[test]
fn defaults_follow_the_owner_policy_by_tier() {
    assert_eq!(
        Answers::defaults(Tier::P1),
        Answers {
            approvals: Approvals::ChecksOnly,
            codeowners: false,
            bypass_actors: Vec::new(),
        }
    );
    for tier in [Tier::P2, Tier::P3] {
        assert_eq!(
            Answers::defaults(tier),
            Answers {
                approvals: Approvals::OneApproval,
                codeowners: true,
                bypass_actors: Vec::new(),
            }
        );
    }
    assert_eq!(Tier::default(), Tier::P1);
    assert_eq!(Tier::parse(engine::answers::DEFAULT_TIER), Some(Tier::P1));
    assert_eq!(Tier::parse("P4"), None);
    for approvals in Approvals::ALL {
        assert_eq!(Approvals::parse(approvals.as_str()), Some(*approvals));
    }
    assert_eq!(Approvals::parse("two-approvals"), None);
}

// ---- refusals -----------------------------------------------------------------

#[test]
fn owner_bypass_is_refused_outside_p1_with_the_exact_message() {
    let answers = Answers {
        approvals: Approvals::ChecksOnlyOwnerBypass,
        codeowners: false,
        bypass_actors: Vec::new(),
    };
    for tier in [Tier::P2, Tier::P3] {
        let error = ruleset(tier, &answers, &plain_project(), &default_checks()).unwrap_err();
        assert_eq!(
            error.to_string(),
            "Module repo-baseline: approvals `checks-only-owner-bypass` is P1-only; use `checks-only` or `one-approval`",
            "{tier:?}"
        );
    }
}

#[test]
fn review_app_is_refused_in_every_tier_with_the_exact_message() {
    let answers = Answers {
        approvals: Approvals::ReviewApp,
        codeowners: true,
        bypass_actors: Vec::new(),
    };
    for tier in [Tier::P1, Tier::P2, Tier::P3] {
        let error = ruleset(tier, &answers, &plain_project(), &default_checks()).unwrap_err();
        assert_eq!(
            error.to_string(),
            "Module repo-baseline: review-app needs the agent App (org-level slice)",
            "{tier:?}"
        );
    }
}

// ---- declared required checks ------------------------------------------------

#[test]
fn declared_required_checks_render_verbatim_with_the_finding() {
    let out = ruleset(
        Tier::P1,
        &Answers::defaults(Tier::P1),
        &five_contexts_project(),
        &default_checks(),
    )
    .unwrap();
    let checks = contexts(&out.value);
    assert_eq!(
        checks
            .iter()
            .map(|c| c["context"].clone())
            .collect::<Vec<_>>(),
        json!([
            "Rust (linux)",
            "Rust (macos)",
            "test / verify",
            "build",
            "promote"
        ])
        .as_array()
        .unwrap()
        .clone()
    );
    assert!(checks.iter().all(|c| c["integration_id"] == 15368));
    assert_eq!(
        out.findings,
        vec!["Required checks: 5 contexts, the standard is one aggregate check".to_owned()]
    );
}

#[test]
fn required_checks_default_to_the_cross_module_name() {
    assert_eq!(
        required_checks(&plain_project(), &default_checks()),
        vec!["required".to_owned()]
    );
    let mut empty = default_profile();
    empty["ci"]["required_checks"] = json!([]);
    assert_eq!(
        required_checks(&project(empty), &default_checks()),
        vec!["required".to_owned()]
    );
    let mut declared = default_profile();
    declared["ci"]["required_checks"] = json!(["required"]);
    let out = ruleset(
        Tier::P1,
        &Answers::defaults(Tier::P1),
        &project(declared),
        &default_checks(),
    )
    .unwrap();
    assert!(out.findings.is_empty(), "{:?}", out.findings);
    let mut other = default_profile();
    other["ci"]["required_checks"] = json!(["all-checks-passed"]);
    let out = ruleset(
        Tier::P1,
        &Answers::defaults(Tier::P1),
        &project(other),
        &default_checks(),
    )
    .unwrap();
    assert_eq!(contexts(&out.value)[0]["context"], "all-checks-passed");
    assert_eq!(
        out.findings,
        vec!["Required checks: 1 context, the standard is one aggregate check".to_owned()]
    );
}

// ---- the module through the engine ------------------------------------------

struct Fixture {
    _temp: TempDir,
    root: std::path::PathBuf,
}
/// The synthetic configuration every test of this binary runs under, so the
/// rendered seeds and goldens name `example-owner` and the product's own schema
/// base, never a real account (product-boundary T6e, #1055). Installed before
/// anything reads the configuration; idempotent.
fn synthetic_config() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        brakes::config::install(brakes::config::Config::for_test(
            "example-owner",
            &["example-owner/*"],
            &["example-corp"],
        ))
        .unwrap();
    });
}

impl Fixture {
    fn new() -> Self {
        synthetic_config();
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("project");
        fs::create_dir(&root).unwrap();
        Self { _temp: temp, root }
    }
    /// A repository whose answers file records `tier`, as `install --profile` does.
    fn profiled(tier: Tier) -> Self {
        let f = Self::new();
        let path = f.root.join(engine_answers::path("repo-baseline"));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let file = json!({ "module": "repo-baseline", "version": "1.0.0", "profile": tier.as_str(), "answers": {} });
        fs::write(path, serde_json::to_string_pretty(&file).unwrap() + "\n").unwrap();
        f
    }
    fn plan(&self, module: &RepoBaseline) -> Result<Planned> {
        let source = Source::embedded();
        let profile = profile_for(&self.root)?;
        // `repo-baseline` requires `setup-core`, which must be active in the same plan.
        let core = support::SetupCore;
        engine::plan(&self.root, &source, &profile, &[&core, module], &|_| true)
    }
    fn apply(&self, module: &RepoBaseline) -> Planned {
        let planned = self.plan(module).unwrap();
        apply(&self.root, &planned.changes).unwrap();
        planned
    }
    fn read(&self, name: &str) -> String {
        fs::read_to_string(self.root.join(name)).unwrap()
    }
    /// `configure <repo> repo-baseline --set ...` through the questions driver,
    /// with an explicit module list.
    fn configure(&self, module: &RepoBaseline, sets: &[&str]) -> Result<Planned> {
        let source = Source::embedded();
        let profile = profile_for(&self.root)?;
        let core = support::SetupCore;
        let inputs = Inputs {
            files: Vec::new(),
            sets: sets.iter().map(|s| (*s).to_owned()).collect(),
            ..Inputs::default()
        };
        let configured = questions::configure(
            &self.root,
            &source,
            &profile,
            &[&core, module],
            &|_| true,
            "repo-baseline",
            &inputs,
        )?;
        Ok(configured.planned)
    }
    fn ruleset(&self) -> Value {
        serde_json::from_str(&self.read(RULESET_PATH)).unwrap()
    }
}

#[test]
fn plan_writes_the_two_managed_files_and_records_the_module() {
    let f = Fixture::new();
    let module = RepoBaseline;
    let planned = f.apply(&module);
    for path in [RULESET_PATH, SERVICE_SCHEMA_PATH] {
        assert_eq!(
            planned.tags[path],
            (Ownership::Managed, "repo-baseline".to_owned()),
            "{path}"
        );
        assert!(f.root.join(path).is_file(), "{path}");
    }
    let written: Value = serde_json::from_str(&f.read(RULESET_PATH)).unwrap();
    let expected = value_of(Tier::P1, &Answers::defaults(Tier::P1), &plain_project());
    assert_eq!(written, expected);
    assert!(f.read(RULESET_PATH).ends_with("}\n"));
    let lock: Value = serde_json::from_str(&f.read(LOCK)).unwrap();
    assert_eq!(lock["modules"]["repo-baseline"]["version"], "1.0.0");
    assert_eq!(lock["files"][RULESET_PATH]["class"], "managed");
    assert_eq!(
        lock["files"][SERVICE_SCHEMA_PATH]["module"],
        "repo-baseline"
    );
}

#[test]
fn two_renders_are_byte_identical_and_the_second_plan_is_empty() {
    let f = Fixture::new();
    let module = RepoBaseline;
    let first = f.plan(&module).unwrap();
    let second = f.plan(&module).unwrap();
    for path in [RULESET_PATH, SERVICE_SCHEMA_PATH] {
        assert_eq!(first.changes[path], second.changes[path], "{path}");
    }
    apply(&f.root, &first.changes).unwrap();
    let after = f.plan(&module).unwrap();
    assert!(after.changes.is_empty(), "{:?}", after.changes.keys());
}

#[test]
fn edited_ruleset_file_refuses() {
    let f = Fixture::new();
    let module = RepoBaseline;
    f.apply(&module);
    let edited = f.read(RULESET_PATH).replace("\"active\"", "\"disabled\"");
    fs::write(f.root.join(RULESET_PATH), edited).unwrap();
    let error = f.plan(&module).unwrap_err().to_string();
    assert_eq!(
        error,
        format!("Locally changed or missing managed content: {RULESET_PATH}")
    );
}

#[test]
fn p2_module_renders_one_approval_through_the_engine() {
    let f = Fixture::profiled(Tier::P2);
    let module = RepoBaseline;
    f.apply(&module);
    let written: Value = serde_json::from_str(&f.read(RULESET_PATH)).unwrap();
    assert_eq!(
        rule(&written, "pull_request")["parameters"]["required_approving_review_count"],
        1
    );
    assert_eq!(written["bypass_actors"], json!([]));
}

#[test]
fn module_findings_carry_the_declared_checks_finding() {
    let module = RepoBaseline;
    let answers = engine_answers::Answers::new();
    assert!(
        module
            .findings(Tier::P1, &plain_project(), &answers)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        module
            .findings(Tier::P1, &five_contexts_project(), &answers)
            .unwrap(),
        vec!["Required checks: 5 contexts, the standard is one aggregate check".to_owned()]
    );
}

// ---- the service card schema ---------------------------------------------------

#[test]
fn service_schema_is_json_schema_with_the_spec_rules() {
    let f = Fixture::new();
    f.apply(&RepoBaseline);
    let schema: Value = serde_json::from_str(&f.read(SERVICE_SCHEMA_PATH)).unwrap();
    assert_eq!(
        schema["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    assert_eq!(schema["type"], "object");
    let required = schema["required"].as_array().unwrap();
    for field in ["name", "owner", "tier", "criticality"] {
        assert!(required.contains(&json!(field)), "{field}");
    }
    let owner = &schema["properties"]["owner"];
    assert_eq!(owner["type"], "string");
    assert_eq!(owner["minLength"], 1);
    assert_eq!(owner["not"]["enum"], json!(["unknown"]));
    assert_eq!(
        schema["properties"]["criticality"]["enum"],
        json!(["internal", "customers", "personal-data-or-payments"])
    );
    let tier = &schema["properties"]["tier"];
    assert_eq!(tier["type"], "integer");
    assert_eq!(tier["minimum"], 1);
    assert_eq!(tier["maximum"], 3);
    for field in [
        "runbook",
        "dashboard",
        "alerts",
        "slo",
        "on_call",
        "security_contact",
    ] {
        let property = &schema["properties"][field];
        assert_eq!(property["type"], json!(["string", "null"]), "{field}");
    }
}

// ---- answers (T2, #701) ---------------------------------------------------------

#[test]
fn answers_schema_declares_the_four_spec_questions() {
    let schema = questions_schema();
    let ids: Vec<&str> = schema.questions.iter().map(|q| q.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "approvals",
            "dependency_updates",
            "codeowners",
            "bypass_actors"
        ]
    );
    let approvals = schema.question("approvals").unwrap();
    assert_eq!(
        approvals.kind,
        Kind::Enum(
            [
                "checks-only",
                "checks-only-owner-bypass",
                "one-approval",
                "review-app"
            ]
            .map(str::to_owned)
            .to_vec()
        )
    );
    assert_eq!(
        approvals.default,
        Some(json!({ "P1": "checks-only", "P2": "one-approval", "P3": "one-approval" }))
    );
    let updates = schema.question("dependency_updates").unwrap();
    assert_eq!(
        updates.kind,
        Kind::Enum(["dependabot", "renovate"].map(str::to_owned).to_vec())
    );
    assert_eq!(updates.default, Some(json!("dependabot")));
    let codeowners = schema.question("codeowners").unwrap();
    assert_eq!(codeowners.kind, Kind::Boolean);
    assert_eq!(
        codeowners.default,
        Some(json!({ "P1": false, "P2": true, "P3": true }))
    );
    for question in &schema.questions {
        assert!(!question.description.is_empty(), "{}", question.id);
    }
    schema.check("repo-baseline").unwrap();
}

#[test]
fn answers_module_has_no_when_and_no_secret_question() {
    for schema in [questions_schema(), RepoBaseline.questions()] {
        assert_eq!(schema.questions.len(), 4);
        for question in &schema.questions {
            assert!(question.when.is_none(), "{} has a when", question.id);
            assert!(!question.secret, "{} is secret", question.id);
        }
    }
}

#[test]
fn answers_defaults_follow_the_profile() {
    for (tier, approvals, codeowners) in [
        (Tier::P1, "checks-only", false),
        (Tier::P2, "one-approval", true),
        (Tier::P3, "one-approval", true),
    ] {
        let resolved = RepoBaseline
            .questions()
            .validate(
                "repo-baseline",
                &engine_answers::Answers::new(),
                tier.as_str(),
            )
            .unwrap();
        assert_eq!(
            serde_json::to_value(&resolved).unwrap(),
            json!({ "approvals": approvals, "bypass_actors": [], "codeowners": codeowners, "dependency_updates": "dependabot" }),
            "{tier:?}"
        );
        let choices = Choices::from_answers(&resolved).unwrap();
        assert_eq!(choices.ruleset, Answers::defaults(tier), "{tier:?}");
        assert_eq!(choices.dependency_updates, DependencyUpdates::Dependabot);
    }
}

#[test]
fn answers_codeowners_default_reaches_the_ruleset_by_profile() {
    for (tier, expected) in [(Tier::P2, true), (Tier::P3, true)] {
        let f = Fixture::profiled(tier);
        f.apply(&RepoBaseline);
        assert_eq!(
            rule(&f.ruleset(), "pull_request")["parameters"]["require_code_owner_review"],
            expected,
            "{tier:?}"
        );
    }
    let f = Fixture::profiled(Tier::P2);
    let planned = f.configure(&RepoBaseline, &["codeowners=false"]).unwrap();
    apply(&f.root, &planned.changes).unwrap();
    assert_eq!(
        rule(&f.ruleset(), "pull_request")["parameters"]["require_code_owner_review"],
        false
    );
}

#[test]
fn answers_invalid_enum_is_refused_with_the_question_id() {
    let f = Fixture::new();
    let module = RepoBaseline;
    assert_eq!(
        f.configure(&module, &["approvals=two-approvals"])
            .unwrap_err()
            .to_string(),
        "Module repo-baseline: answer `approvals` must be one of: checks-only, checks-only-owner-bypass, one-approval, review-app"
    );
    assert_eq!(
        f.configure(&module, &["dependency_updates=greenkeeper"])
            .unwrap_err()
            .to_string(),
        "Module repo-baseline: answer `dependency_updates` must be one of: dependabot, renovate"
    );
    assert_eq!(
        f.configure(&module, &["codeowners=maybe"])
            .unwrap_err()
            .to_string(),
        "Module repo-baseline: answer `codeowners` must be a boolean"
    );
    assert!(!f.root.join(LOCK).exists(), "nothing written");
}

#[test]
fn answers_configure_set_one_approval_round_trip_changes_the_ruleset() {
    let f = Fixture::new();
    let module = RepoBaseline;
    f.apply(&module);
    let before = f.ruleset();
    assert_eq!(
        rule(&before, "pull_request")["parameters"]["required_approving_review_count"],
        0
    );
    let planned = f.configure(&module, &["approvals=one-approval"]).unwrap();
    let path = engine_answers::path("repo-baseline");
    assert_eq!(path, ".agent-setup/modules/repo-baseline.json");
    assert!(
        planned.changes.contains_key(RULESET_PATH),
        "ruleset replanned"
    );
    assert!(!f.root.join(&path).exists(), "plan only");
    apply(&f.root, &planned.changes).unwrap();
    let recorded: Value = serde_json::from_str(&f.read(&path)).unwrap();
    assert_eq!(
        recorded,
        json!({
            "module": "repo-baseline",
            "version": "1.0.0",
            "answers": { "approvals": "one-approval", "bypass_actors": [], "codeowners": false, "dependency_updates": "dependabot" }
        })
    );
    let after = f.ruleset();
    let parameters = &rule(&after, "pull_request")["parameters"];
    assert_eq!(parameters["required_approving_review_count"], 1);
    assert_eq!(parameters["require_last_push_approval"], true);
    assert_eq!(parameters["require_code_owner_review"], false);
    assert_eq!(after["bypass_actors"], json!([]));
    assert!(f.plan(&module).unwrap().changes.is_empty());
    let back = f.configure(&module, &["approvals=checks-only"]).unwrap();
    apply(&f.root, &back.changes).unwrap();
    assert_eq!(f.ruleset(), before);
}

#[test]
fn answers_owner_bypass_is_refused_at_configure_outside_p1() {
    for tier in [Tier::P2, Tier::P3] {
        let f = Fixture::profiled(tier);
        let error = f
            .configure(&RepoBaseline, &["approvals=checks-only-owner-bypass"])
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "Module repo-baseline: approvals `checks-only-owner-bypass` is P1-only; use `checks-only` or `one-approval`",
            "{tier:?}"
        );
        assert!(!f.root.join(LOCK).exists(), "{tier:?}: nothing written");
    }
    let f = Fixture::new();
    let planned = f
        .configure(&RepoBaseline, &["approvals=checks-only-owner-bypass"])
        .unwrap();
    apply(&f.root, &planned.changes).unwrap();
    assert_eq!(
        f.ruleset()["bypass_actors"],
        json!([{ "actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always" }])
    );
}

#[test]
fn answers_review_app_is_refused_at_configure_in_every_profile() {
    for tier in [Tier::P1, Tier::P2, Tier::P3] {
        let f = Fixture::profiled(tier);
        let error = f
            .configure(&RepoBaseline, &["approvals=review-app"])
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "Module repo-baseline: review-app needs the agent App (org-level slice)",
            "{tier:?}"
        );
    }
}

#[test]
fn answers_dependency_updates_selects_one_seed() {
    assert_eq!(
        DependencyUpdates::Dependabot.seed_path(),
        ".github/dependabot.yml"
    );
    assert_eq!(DependencyUpdates::Renovate.seed_path(), "renovate.json");
    let mut raw = engine_answers::Answers::new();
    raw.insert("dependency_updates".to_owned(), json!("renovate"));
    let resolved = RepoBaseline
        .questions()
        .validate("repo-baseline", &raw, DEFAULT_TIER)
        .unwrap();
    assert_eq!(
        Choices::from_answers(&resolved).unwrap().dependency_updates,
        DependencyUpdates::Renovate
    );
    for choice in DependencyUpdates::ALL {
        assert_eq!(DependencyUpdates::parse(choice.as_str()), Some(*choice));
    }
}

// ---- issue forms (T3, #702) ----------------------------------------------------

const FORMS_DIR: &str = ".github/ISSUE_TEMPLATE";

/// Every file the module writes (managed, managed-block and seed), as (path,
/// content) read back from disk; remote items have no file.
fn rendered_tree(f: &Fixture, planned: &Planned) -> Vec<(String, String)> {
    planned
        .tags
        .iter()
        .filter(|(_, (class, module))| {
            matches!(
                class,
                Ownership::Managed | Ownership::ManagedBlock | Ownership::Seed
            ) && module == "repo-baseline"
        })
        .map(|(path, _)| (path.clone(), f.read(path)))
        .collect()
}

/// Compares the rendered tree with `tests/golden/repo-baseline/<name>`, the
/// product's rendering; a build with `setup-core` keeps the guide references the
/// product omits (#1247) and compares with `tests/golden/repo-baseline-setup-core/<name>`.
/// `UPDATE_GOLDENS=1` rewrites the directory first.
fn assert_golden(name: &str, tree: &[(String, String)]) {
    let family = if cfg!(feature = "setup-core") {
        "repo-baseline-setup-core"
    } else {
        "repo-baseline"
    };
    let dir = format!(
        "{}/tests/golden/{family}/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    if std::env::var_os("UPDATE_GOLDENS").is_some() {
        let _ = fs::remove_dir_all(&dir);
        for (path, content) in tree {
            let file = std::path::Path::new(&dir).join(path);
            fs::create_dir_all(file.parent().unwrap()).unwrap();
            fs::write(file, content).unwrap();
        }
    }
    let mut golden = Vec::new();
    let mut pending = vec![std::path::PathBuf::from(&dir)];
    while let Some(next) = pending.pop() {
        for entry in fs::read_dir(&next).unwrap_or_else(|e| panic!("{dir}: {e}")) {
            let entry = entry.unwrap().path();
            if entry.is_dir() {
                pending.push(entry);
            } else {
                let relative = entry.strip_prefix(&dir).unwrap();
                let relative = relative.to_string_lossy().replace('\\', "/");
                golden.push((relative, fs::read_to_string(&entry).unwrap()));
            }
        }
    }
    golden.sort();
    assert_eq!(
        tree,
        golden.as_slice(),
        "the rendered tree drifted from {dir}"
    );
}

#[test]
fn forms_are_the_managed_files_of_the_issue_template_directory() {
    assert_eq!(
        ISSUE_FORM_PATHS,
        [
            ".github/ISSUE_TEMPLATE/task.yml",
            ".github/ISSUE_TEMPLATE/checkpoint.yml",
            ".github/ISSUE_TEMPLATE/incident.yml",
            ".github/ISSUE_TEMPLATE/post-mortem-action.yml",
            ".github/ISSUE_TEMPLATE/config.yml",
        ]
    );
    let f = Fixture::new();
    let planned = f.apply(&RepoBaseline);
    for path in ISSUE_FORM_PATHS {
        assert_eq!(
            planned.tags[path],
            (Ownership::Managed, "repo-baseline".to_owned()),
            "{path}"
        );
        assert!(f.root.join(path).is_file(), "{path}");
    }
    let lock: Value = serde_json::from_str(&f.read(LOCK)).unwrap();
    assert_eq!(lock["files"][ISSUE_FORM_PATHS[0]]["class"], "managed");
}

#[test]
fn forms_golden_p1_defaults_pins_the_rendered_tree() {
    let f = Fixture::new();
    let planned = f.apply(&RepoBaseline);
    let tree = rendered_tree(&f, &planned);
    assert_golden("p1-defaults", &tree);
    for path in ISSUE_FORM_PATHS.iter().chain([&PR_TEMPLATE_PATH]) {
        assert!(tree.iter().any(|(p, _)| p == path), "{path} in the golden");
    }
}

#[test]
fn forms_task_carries_the_ready_and_done_groups_and_its_labels() {
    let f = Fixture::new();
    f.apply(&RepoBaseline);
    let task = f.read(&format!("{FORMS_DIR}/task.yml"));
    assert!(task.starts_with("name: Task\n"), "{task}");
    assert!(task.contains("title: \"[Task] \"\n"));
    assert!(task.contains("labels:\n  - type:task\n  - status:backlog\n"));
    for id in [
        "outcome",
        "scope",
        "sources",
        "decisions",
        "verification",
        "dependencies",
        "definition-of-ready",
        "definition-of-done",
    ] {
        assert!(task.contains(&format!("    id: {id}\n")), "id {id}");
    }
    for label in [
        "Outcome and acceptance criteria",
        "Scope and exclusions",
        "Sources and relevant conventions",
        "Decisions, provenance and open questions",
        "Verification",
        "Dependencies",
        "Definition of ready",
        "Definition of done",
    ] {
        assert!(
            task.contains(&format!("      label: {label}\n")),
            "label {label}"
        );
    }
    // Fields that only exist after work starts stay in the handoff comment.
    for later in [
        "Changes completed",
        "Checks executed",
        "Lessons",
        "Branch or worktree",
    ] {
        assert!(!task.contains(&format!("label: {later}")), "{later}");
    }
}

#[test]
fn forms_checkpoint_incident_and_post_mortem_carry_the_spec_fields() {
    let f = Fixture::new();
    f.apply(&RepoBaseline);
    let read = |name: &str| f.read(&format!("{FORMS_DIR}/{name}"));
    let checkpoint = read("checkpoint.yml");
    assert!(checkpoint.contains("labels:\n  - type:checkpoint\nbody:"));
    for id in ["outcome", "slices", "evidence", "decision", "if-no-go"] {
        assert!(
            checkpoint.contains(&format!("    id: {id}\n")),
            "checkpoint {id}"
        );
    }
    let incident = read("incident.yml");
    assert!(incident.contains("labels:\n  - incident\nbody:"));
    for id in [
        "severity",
        "impact",
        "start-time",
        "commander",
        "mitigation",
        "next-update",
    ] {
        assert!(
            incident.contains(&format!("    id: {id}\n")),
            "incident {id}"
        );
    }
    // The severities as docs/agent-setup/incidents.md defines them, in order.
    let severities: Vec<&str> = incident
        .lines()
        .filter_map(|l| l.trim().strip_prefix("- \"SEV-"))
        .collect();
    assert_eq!(severities.len(), 4, "{incident}");
    for (n, line) in severities.iter().enumerate() {
        assert!(line.starts_with(&format!("{}: ", n + 1)), "{line}");
    }
    let action = read("post-mortem-action.yml");
    assert!(action.contains("labels:\n  - type:post-mortem-action\nbody:"));
    for id in [
        "post-mortem",
        "action",
        "owner",
        "due-date",
        "converted-into",
    ] {
        assert!(
            action.contains(&format!("    id: {id}\n")),
            "post-mortem {id}"
        );
    }
    for option in ["alert", "SLO", "runbook", "standard", "test"] {
        assert!(
            action.contains(&format!("        - {option}\n")),
            "{option}"
        );
    }
}

#[test]
fn forms_config_only_hides_blank_issues() {
    // Owner decision 2026-10-28 (#702): no contact link; GitHub already lists the
    // security policy in the chooser when SECURITY.md exists.
    let f = Fixture::new();
    f.apply(&RepoBaseline);
    assert_eq!(
        f.read(&format!("{FORMS_DIR}/config.yml")),
        "blank_issues_enabled: false\n"
    );
}

#[test]
fn forms_have_no_last_verified_line_and_render_byte_identically() {
    let f = Fixture::new();
    let module = RepoBaseline;
    let first = f.plan(&module).unwrap();
    let second = f.plan(&module).unwrap();
    for path in ISSUE_FORM_PATHS {
        assert_eq!(first.changes[path], second.changes[path], "{path}");
    }
    apply(&f.root, &first.changes).unwrap();
    for path in ISSUE_FORM_PATHS {
        let text = f.read(path);
        assert!(!text.contains("Last verified"), "{path}");
        assert!(text.ends_with('\n') && !text.ends_with("\n\n"), "{path}");
    }
}

#[test]
fn forms_project_owned_forms_stay_and_an_edited_task_form_refuses() {
    let f = Fixture::new();
    let story = format!("{FORMS_DIR}/user-story.md");
    fs::create_dir_all(f.root.join(FORMS_DIR)).unwrap();
    let body = "---\nname: User story\n---\nAs a ...\n";
    fs::write(f.root.join(&story), body).unwrap();
    let module = RepoBaseline;
    let planned = f.apply(&module);
    assert!(!planned.changes.contains_key(&story));
    assert_eq!(f.read(&story), body);
    for path in ISSUE_FORM_PATHS {
        assert!(f.root.join(path).is_file(), "{path}");
    }
    let task = format!("{FORMS_DIR}/task.yml");
    let edited = f.read(&task).replace("status:backlog", "status:ready");
    fs::write(f.root.join(&task), edited).unwrap();
    assert_eq!(
        f.plan(&module).unwrap_err().to_string(),
        format!("Locally changed or missing managed content: {task}")
    );
    assert_eq!(f.read(&story), body);
}

// ---- PR template (T4, #703) -----------------------------------------------------

/// The spec's five Definition-of-done lines (SPEC-repo-baseline.md, Data model:
/// PR template block), byte for byte, between the engine's markers.
fn spec_block() -> String {
    format!(
        "{BEGIN}\n\
- [ ] Verification output is in this PR (the command and its result, not \"CI green\")\n\
- [ ] Migration is backwards-compatible (expand/contract) or there is no migration\n\
- [ ] Every flag this PR touches was tested in both states\n\
- [ ] The flag is removed, or its removal issue is linked with a date (a story does not close with a live flag)\n\
- [ ] The slice is ≤ 400 changed lines, or the PR says why it cannot be split\n\
{END}"
    )
}

#[test]
fn pr_template_block_is_the_spec_five_lines_byte_for_byte() {
    let f = Fixture::new();
    let planned = f.apply(&RepoBaseline);
    assert_eq!(
        planned.tags[PR_TEMPLATE_PATH],
        (Ownership::ManagedBlock, "repo-baseline".to_owned())
    );
    let text = f.read(PR_TEMPLATE_PATH);
    assert_eq!(block_content(&text).unwrap(), Some(spec_block().as_str()));
    let lock: Value = serde_json::from_str(&f.read(LOCK)).unwrap();
    assert_eq!(
        lock["files"][PR_TEMPLATE_PATH],
        json!({"module": "repo-baseline", "class": "managed-block", "digest": digest(&spec_block())})
    );
}

#[test]
fn pr_template_absent_file_gets_the_skeleton_around_the_block() {
    let f = Fixture::new();
    let module = RepoBaseline;
    f.apply(&module);
    assert_eq!(
        f.read(PR_TEMPLATE_PATH),
        format!(
            "Summary (one line):\n\n{}\n\nNotes for review: only what the diff does not say (why, risk, rollback).\n",
            spec_block()
        )
    );
    assert!(f.plan(&module).unwrap().changes.is_empty());
}

/// #1106: `doctor` digests a `managed-block` file's block, as the engine does,
/// whatever the file's name; the template right after install is intact.
#[test]
fn doctor_reports_the_pr_template_block_intact_after_install() {
    let f = Fixture::new();
    let body = "## Description\n\nWhat changes and why.\n";
    fs::create_dir_all(f.root.join(".github")).unwrap();
    fs::write(f.root.join(PR_TEMPLATE_PATH), body).unwrap();
    f.apply(&RepoBaseline);
    let findings = |f: &Fixture| {
        diagnose_with(
            &f.root,
            today(),
            &Source::embedded(),
            &[&support::SetupCore, &RepoBaseline],
            &NoRunner,
        )
        .unwrap()
        .findings
    };

    let clean = findings(&f);
    assert!(
        !clean.iter().any(|l| l.contains(PR_TEMPLATE_PATH)),
        "{clean:?}"
    );

    let own = format!("{}- [ ] Screenshots attached\n", f.read(PR_TEMPLATE_PATH));
    fs::write(f.root.join(PR_TEMPLATE_PATH), &own).unwrap();
    let outside = findings(&f);
    assert!(
        !outside.iter().any(|l| l.contains(PR_TEMPLATE_PATH)),
        "an edit outside the block is the project's: {outside:?}"
    );

    let edited = own.replace("≤ 400 changed lines", "≤ 800 changed lines");
    fs::write(f.root.join(PR_TEMPLATE_PATH), edited).unwrap();
    let inside = findings(&f);
    assert!(
        inside
            .iter()
            .any(|l| l
                == &format!("Managed content drift: {PR_TEMPLATE_PATH} (module repo-baseline)")),
        "an edit inside the block is drift: {inside:?}"
    );
}

#[test]
fn pr_template_present_foreign_body_is_kept_and_gains_the_block() {
    let f = Fixture::new();
    let body = "## Descripción\n\nQué cambia y por qué.\n\n## Cómo probarlo\n\n- [ ] Pasos\n";
    fs::create_dir_all(f.root.join(".github")).unwrap();
    fs::write(f.root.join(PR_TEMPLATE_PATH), body).unwrap();
    let module = RepoBaseline;
    f.apply(&module);
    assert_eq!(
        f.read(PR_TEMPLATE_PATH),
        format!("{body}\n{}\n", spec_block())
    );
    assert!(f.plan(&module).unwrap().changes.is_empty());
}

#[test]
fn pr_template_project_items_outside_the_block_stay_and_an_edited_block_refuses() {
    let f = Fixture::new();
    let module = RepoBaseline;
    f.apply(&module);
    let own = format!("{}- [ ] Screenshots attached\n", f.read(PR_TEMPLATE_PATH));
    fs::write(f.root.join(PR_TEMPLATE_PATH), &own).unwrap();
    assert!(f.plan(&module).unwrap().changes.is_empty());
    let edited = own.replace("≤ 400 changed lines", "≤ 800 changed lines");
    fs::write(f.root.join(PR_TEMPLATE_PATH), edited).unwrap();
    assert_eq!(
        f.plan(&module).unwrap_err().to_string(),
        format!("Locally changed or missing managed content: {PR_TEMPLATE_PATH}")
    );
}

#[test]
fn pr_template_has_no_last_verified_line_and_renders_byte_identically() {
    let f = Fixture::new();
    let module = RepoBaseline;
    let first = f.plan(&module).unwrap();
    let second = f.plan(&module).unwrap();
    assert_eq!(
        first.changes[PR_TEMPLATE_PATH],
        second.changes[PR_TEMPLATE_PATH]
    );
    let text = first.changes[PR_TEMPLATE_PATH].clone().unwrap();
    assert!(!text.contains("Last verified"), "{text}");
}

// ---- remote items and the manual step (T6, #707) ---------------------------------
// Decision #848: the GitHub-side changes are `remote` items written by
// `apply --remote` and verified by their probes; `check-reported` stays a manual
// step. The CLI has no remote runner until #683, so the probes answer
// `unavailable`; a fake runner drives every other state.

use brakes::engine::manual::Owner;
use brakes::engine::{NoRunner, Probe, ProbeResult, RemoteRunner, StepReport};
use brakes::modules::repo_baseline::{
    RFC_TEMPLATE_PATH,
    steps::{self as baseline_steps, LABELS, REMOTE_ITEMS},
};
use std::cell::RefCell;
use std::collections::BTreeMap;

const PLAN_REFUSAL: &str =
    "HTTP 403: Upgrade to GitHub Pro or make this repository public to enable this feature.";

/// Answers each remote probe id with a fixed result and records every call.
#[derive(Default)]
struct FakeHost {
    answers: BTreeMap<&'static str, ProbeResult>,
    calls: RefCell<Vec<(String, BTreeMap<String, Value>)>>,
}
impl FakeHost {
    fn with(answers: &[(&'static str, ProbeResult)]) -> Self {
        Self {
            answers: answers.iter().cloned().collect(),
            calls: RefCell::default(),
        }
    }
    /// Every probe id of the module answered `verified` with `<id> ok`.
    fn all_verified() -> Self {
        Self::with(&PROBE_IDS.map(|id| (id, ProbeResult::Verified(format!("{id} ok")))))
    }
}
impl RemoteRunner for FakeHost {
    fn run(&self, id: &str, args: &BTreeMap<String, Value>) -> ProbeResult {
        self.calls.borrow_mut().push((id.to_owned(), args.clone()));
        self.answers
            .get(id)
            .cloned()
            .unwrap_or_else(|| ProbeResult::Failed(format!("unexpected probe {id}")))
    }
}

const PROBE_IDS: [&str; 7] = [
    "check-run-reported",
    "ruleset-present",
    "classic-protection-absent",
    "labels-present",
    "repo-settings",
    "dependabot-alerts",
    "automated-security-fixes",
];

impl Fixture {
    fn reports(&self, module: &RepoBaseline, runner: &dyn RemoteRunner) -> Vec<StepReport> {
        let core = support::SetupCore;
        diagnose_with(
            &self.root,
            today(),
            &Source::embedded(),
            &[&core, module],
            runner,
        )
        .unwrap()
        .steps
        .into_iter()
        .filter(|s| s.module == "repo-baseline")
        .collect()
    }
    fn doctor_lines(&self, runner: &dyn RemoteRunner) -> Vec<String> {
        self.reports(&RepoBaseline, runner)
            .iter()
            .map(StepReport::doctor_line)
            .collect()
    }
    fn state(&self, runner: &dyn RemoteRunner, id: &str) -> StepReport {
        self.reports(&RepoBaseline, runner)
            .into_iter()
            .find(|s| s.id == id)
            .unwrap_or_else(|| panic!("no step {id}"))
    }
}

fn installed() -> Fixture {
    let f = Fixture::new();
    f.apply(&RepoBaseline);
    f
}

#[test]
fn steps_declares_six_remote_items_and_one_manual_step() {
    assert_eq!(
        REMOTE_ITEMS,
        [
            "ruleset-main",
            "classic-protection-retire",
            "labels",
            "repo-settings",
            "dependabot-alerts",
            "dependabot-security-updates",
        ]
    );
    let declared = baseline_steps::steps(&Fixture::new().root, &["required".to_owned()], false);
    let ids: Vec<&str> = declared.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "check-reported",
            "ruleset-main",
            "classic-protection-retire",
            "labels",
            "repo-settings",
            "dependabot-alerts",
            "dependabot-security-updates",
        ]
    );
    let check = &declared[0];
    assert_eq!(check.owner, Owner::Platform);
    assert!(declared[1..].iter().all(|s| s.owner == Owner::Owner));
    let after: Vec<(&str, Option<&str>)> = declared
        .iter()
        .map(|s| (s.id.as_str(), s.after.as_deref()))
        .filter(|(_, a)| a.is_some())
        .collect();
    assert_eq!(
        after,
        [
            ("ruleset-main", Some("check-reported")),
            ("classic-protection-retire", Some("ruleset-main")),
        ]
    );
}

#[test]
fn steps_remote_items_are_recorded_in_the_lock_and_never_written() {
    let f = Fixture::new();
    let planned = f.apply(&RepoBaseline);
    let lock: Value = serde_json::from_str(&f.read(LOCK)).unwrap();
    for id in REMOTE_ITEMS {
        let path = format!("github:{id}");
        assert_eq!(
            planned.tags[&path],
            (Ownership::Remote, "repo-baseline".to_owned()),
            "{path}"
        );
        assert!(!planned.changes.contains_key(&path), "{path}");
        assert!(!f.root.join(&path).exists(), "{path}");
        assert_eq!(
            lock["files"][&path],
            json!({"module": "repo-baseline", "class": "remote"})
        );
    }
    assert!(lock["files"].get("github:check-reported").is_none());
    let again = f.plan(&RepoBaseline).unwrap();
    assert!(again.changes.is_empty(), "{:?}", again.changes.keys());
}

#[test]
fn steps_without_a_runner_are_unavailable_and_the_ordered_items_blocked() {
    let f = installed();
    assert_eq!(
        f.doctor_lines(&NoRunner),
        [
            "STEP [unavailable:repo-baseline] check-reported — remote probe `check-run-reported` runs only with doctor --remote",
            "STEP [blocked:repo-baseline] classic-protection-retire — waits for step `ruleset-main` (blocked)",
            "STEP [unavailable:repo-baseline] dependabot-alerts — remote probe `dependabot-alerts` runs only with doctor --remote",
            "STEP [unavailable:repo-baseline] dependabot-security-updates — remote probe `automated-security-fixes` runs only with doctor --remote",
            "STEP [unavailable:repo-baseline] labels — remote probe `labels-present` runs only with doctor --remote",
            "STEP [unavailable:repo-baseline] repo-settings — remote probe `repo-settings` runs only with doctor --remote",
            "STEP [blocked:repo-baseline] ruleset-main — waits for step `check-reported` (unavailable)",
        ]
    );
}

#[test]
fn steps_every_id_reaches_verified_with_the_probe_evidence() {
    let f = installed();
    assert_eq!(
        f.doctor_lines(&FakeHost::all_verified()),
        [
            "STEP [verified:repo-baseline] check-reported — check-run-reported ok",
            "STEP [verified:repo-baseline] classic-protection-retire — classic-protection-absent ok",
            "STEP [verified:repo-baseline] dependabot-alerts — dependabot-alerts ok",
            "STEP [verified:repo-baseline] dependabot-security-updates — automated-security-fixes ok",
            "STEP [verified:repo-baseline] labels — labels-present ok",
            "STEP [verified:repo-baseline] repo-settings — repo-settings ok",
            "STEP [verified:repo-baseline] ruleset-main — ruleset-present ok",
        ]
    );
}

#[test]
fn steps_every_id_reports_pending_failed_and_unavailable() {
    let f = installed();
    for (make, state) in [
        (ProbeResult::Pending as fn(String) -> ProbeResult, "pending"),
        (ProbeResult::Failed, "failed"),
        (ProbeResult::Unavailable, "unavailable"),
    ] {
        // The two ordered items reach their probe only behind verified predecessors.
        for (id, probe) in [
            ("check-reported", "check-run-reported"),
            ("labels", "labels-present"),
            ("repo-settings", "repo-settings"),
            ("dependabot-alerts", "dependabot-alerts"),
            ("dependabot-security-updates", "automated-security-fixes"),
            ("ruleset-main", "ruleset-present"),
            ("classic-protection-retire", "classic-protection-absent"),
        ] {
            let mut host = FakeHost::all_verified();
            host.answers.insert(probe, make(format!("{probe} said so")));
            assert_eq!(
                f.state(&host, id).doctor_line(),
                format!("STEP [{state}:repo-baseline] {id} — {probe} said so")
            );
        }
    }
}

#[test]
fn steps_ruleset_main_is_blocked_until_check_reported_is_verified() {
    let f = installed();
    let host = FakeHost::with(&[(
        "check-run-reported",
        ProbeResult::Pending("no check run named required on main".to_owned()),
    )]);
    assert_eq!(
        f.state(&host, "ruleset-main").doctor_line(),
        "STEP [blocked:repo-baseline] ruleset-main — waits for step `check-reported` (pending)"
    );
    assert_eq!(
        f.state(&host, "classic-protection-retire").doctor_line(),
        "STEP [blocked:repo-baseline] classic-protection-retire — waits for step `ruleset-main` (blocked)"
    );
    let probed: Vec<String> = host
        .calls
        .borrow()
        .iter()
        .map(|(id, _)| id.clone())
        .collect();
    assert!(
        !probed.iter().any(|id| id == "ruleset-present"),
        "{probed:?}"
    );
    assert!(
        !probed.iter().any(|id| id == "classic-protection-absent"),
        "{probed:?}"
    );
}

#[test]
fn steps_plan_refusal_is_failed_with_github_message_and_protection_stays_blocked() {
    let f = installed();
    let mut host = FakeHost::all_verified();
    host.answers.insert(
        "ruleset-present",
        ProbeResult::Failed(PLAN_REFUSAL.to_owned()),
    );
    let ruleset = f.state(&host, "ruleset-main");
    assert_eq!(
        ruleset.doctor_line(),
        format!("STEP [failed:repo-baseline] ruleset-main — {PLAN_REFUSAL}")
    );
    assert_eq!(ruleset.error.as_deref(), Some(PLAN_REFUSAL));
    assert_eq!(ruleset.evidence, None);
    assert_eq!(
        f.state(&host, "classic-protection-retire").doctor_line(),
        "STEP [blocked:repo-baseline] classic-protection-retire — waits for step `ruleset-main` (failed)"
    );
}

#[test]
fn steps_classic_protection_retire_is_verified_where_none_exists() {
    let f = installed();
    let mut host = FakeHost::all_verified();
    host.answers.insert(
        "classic-protection-absent",
        ProbeResult::Verified("no classic protection on main".to_owned()),
    );
    assert_eq!(
        f.state(&host, "classic-protection-retire").doctor_line(),
        "STEP [verified:repo-baseline] classic-protection-retire — no classic protection on main"
    );
}

#[test]
fn steps_probe_ids_and_args_are_the_declared_ones() {
    let f = installed();
    let host = FakeHost::all_verified();
    f.reports(&RepoBaseline, &host);
    let calls: BTreeMap<String, Value> = host
        .calls
        .borrow()
        .iter()
        .map(|(id, args)| (id.clone(), json!(args)))
        .collect();
    let labels: Value = serde_json::from_str(LABELS).unwrap();
    assert_eq!(
        calls,
        BTreeMap::from([
            (
                "check-run-reported".to_owned(),
                json!({"branch": "main", "contexts": ["required"]})
            ),
            (
                "ruleset-present".to_owned(),
                json!({"branch": "main", "name": "brakes: default branch baseline", "path": RULESET_PATH})
            ),
            (
                "classic-protection-absent".to_owned(),
                json!({"branch": "main"})
            ),
            ("labels-present".to_owned(), json!({"labels": labels})),
            (
                "repo-settings".to_owned(),
                json!({"fields": {
                    "allow_squash_merge": true,
                    "allow_merge_commit": false,
                    "allow_rebase_merge": false,
                    "delete_branch_on_merge": true,
                    "allow_auto_merge": true,
                    "allow_update_branch": true,
                }})
            ),
            ("dependabot-alerts".to_owned(), json!({})),
            ("automated-security-fixes".to_owned(), json!({})),
        ])
    );
    // #942: the probe checks the label the merge guard and the aggregate rely on.
    assert!(
        calls["labels-present"]["labels"]
            .as_array()
            .unwrap()
            .iter()
            .any(|l| l["name"] == "human-approved"),
        "{}",
        calls["labels-present"]
    );
    for (_, probe) in baseline_steps::steps(&f.root, &["required".to_owned()], false)
        .iter()
        .map(|s| (s.id.clone(), s.probe.clone()))
    {
        assert!(matches!(probe, Probe::Remote { .. }), "{probe:?}");
    }
}

#[test]
fn steps_declared_checks_are_the_contexts_check_reported_waits_for() {
    let contexts: Vec<String> = ["test / verify", "build"].map(str::to_owned).to_vec();
    let declared = baseline_steps::steps(&Fixture::new().root, &contexts, false);
    let Probe::Remote { args, .. } = &declared[0].probe else {
        panic!("remote probe");
    };
    assert_eq!(args["contexts"], json!(["test / verify", "build"]));
}

/// The instructions of `id`, declared for a repository whose default branch is `branch`.
fn instructions(id: &str, branch: Option<&str>) -> String {
    let f = Fixture::new();
    if let Some(branch) = branch {
        let refs = f.root.join(".git/refs/remotes/origin");
        fs::create_dir_all(&refs).unwrap();
        fs::write(
            refs.join("HEAD"),
            format!("ref: refs/remotes/origin/{branch}\n"),
        )
        .unwrap();
    }
    baseline_steps::steps(&f.root, &["required".to_owned()], false)
        .into_iter()
        .find(|s| s.id == id)
        .unwrap()
        .instructions
}

#[test]
fn steps_instructions_are_the_exact_gh_commands_with_the_branch_substituted() {
    assert_eq!(
        instructions("ruleset-main", None),
        "gh api -X POST repos/{owner}/{repo}/rulesets --input .github/rulesets/main.json\n\
         # when doctor reports a ruleset of that name with different rules (id <id>):\n\
         gh api -X PUT repos/{owner}/{repo}/rulesets/<id> --input .github/rulesets/main.json"
    );
    assert_eq!(
        instructions("classic-protection-retire", Some("trunk")),
        "gh api -X DELETE repos/{owner}/{repo}/branches/trunk/protection"
    );
    assert_eq!(
        instructions("classic-protection-retire", None),
        "gh api -X DELETE repos/{owner}/{repo}/branches/main/protection"
    );
    assert_eq!(
        instructions("repo-settings", None),
        "gh api -X PATCH repos/{owner}/{repo} -F allow_squash_merge=true -F allow_merge_commit=false -F allow_rebase_merge=false -F delete_branch_on_merge=true -F allow_auto_merge=true -F allow_update_branch=true"
    );
    assert_eq!(
        instructions("dependabot-alerts", None),
        "gh api -X PUT repos/{owner}/{repo}/vulnerability-alerts"
    );
    assert_eq!(
        instructions("dependabot-security-updates", None),
        "gh api -X PUT repos/{owner}/{repo}/automated-security-fixes"
    );
    assert_eq!(
        instructions("check-reported", Some("trunk")),
        "Nothing to run: wait until ci-baseline has reported the required checks on trunk."
    );
}

#[test]
fn steps_default_branch_follows_origin_head_through_a_worktree_gitdir() {
    let f = Fixture::new();
    let common = f.root.join("common");
    fs::create_dir_all(common.join("refs/remotes/origin")).unwrap();
    fs::write(
        common.join("refs/remotes/origin/HEAD"),
        "ref: refs/remotes/origin/develop\n",
    )
    .unwrap();
    let worktree = common.join("worktrees/x");
    fs::create_dir_all(&worktree).unwrap();
    fs::write(worktree.join("commondir"), "../..\n").unwrap();
    fs::write(
        f.root.join(".git"),
        format!("gitdir: {}\n", worktree.display()),
    )
    .unwrap();
    assert_eq!(baseline_steps::default_branch(&f.root), "develop");
    assert_eq!(baseline_steps::default_branch(&Fixture::new().root), "main");
}

#[test]
fn steps_labels_are_the_fifteen_standard_labels_one_command_each() {
    let labels: Vec<Value> = serde_json::from_str(LABELS).unwrap();
    let names: Vec<&str> = labels.iter().map(|l| l["name"].as_str().unwrap()).collect();
    assert_eq!(
        names,
        [
            "status:backlog",
            "status:ready",
            "status:in-progress",
            "status:in-review",
            "status:blocked",
            "priority:high",
            "priority:normal",
            "priority:low",
            "type:task",
            "type:checkpoint",
            "type:bug",
            "type:rfc",
            "type:post-mortem-action",
            "incident",
            "human-approved",
        ]
    );
    // #942: the label a person sets and an agent may not (SPEC-repo-baseline.md, Labels).
    assert_eq!(
        labels[14]["description"],
        "A person approved this protected-path change. Never set by an agent; the merge guard enforces it."
    );
    for label in &labels {
        // GitHub refuses a longer one with 422 (REST "Create a label": "Must be 100
        // characters or fewer", https://docs.github.com/en/rest/issues/labels; #1136).
        let description = label["description"].as_str().unwrap();
        assert!(
            description.chars().count() <= 100,
            "{}: {} characters",
            label["name"],
            description.chars().count()
        );
        let color = label["color"].as_str().unwrap();
        assert!(
            color.len() == 6 && color.chars().all(|c| c.is_ascii_hexdigit()),
            "{label}"
        );
        assert!(
            !label["description"].as_str().unwrap().is_empty(),
            "{label}"
        );
        assert_eq!(label.as_object().unwrap().len(), 3, "{label}");
    }
    let text = instructions("labels", None);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 15);
    for (line, label) in lines.iter().zip(&labels) {
        assert_eq!(
            *line,
            format!(
                "gh label create \"{}\" --color {} --description \"{}\" --force",
                label["name"].as_str().unwrap(),
                label["color"].as_str().unwrap(),
                label["description"].as_str().unwrap()
            )
        );
    }
    assert!(!text.contains("delete") && !text.contains("edit"));
}

#[test]
fn steps_issue_form_labels_are_in_the_label_set() {
    let labels: Vec<Value> = serde_json::from_str(LABELS).unwrap();
    let f = installed();
    let mut seen = 0;
    for path in ISSUE_FORM_PATHS {
        let form = f.read(path);
        // The forms list their labels as a top-level YAML sequence under `labels:`.
        let names = form
            .lines()
            .skip_while(|l| *l != "labels:")
            .skip(1)
            .map_while(|l| l.strip_prefix("  - "));
        for name in names {
            seen += 1;
            assert!(
                labels.iter().any(|l| l["name"] == name),
                "{path}: label {name} not in labels.json"
            );
        }
    }
    assert_eq!(
        seen, 5,
        "type:task, status:backlog, type:checkpoint, incident, type:post-mortem-action"
    );
}

#[test]
fn steps_doctor_json_matches_the_golden_file() {
    let f = installed();
    let steps = f.reports(&RepoBaseline, &NoRunner);
    let actual = doctor_json(
        true,
        &[],
        &steps,
        &[("repo-baseline".to_owned(), "1.0.0".to_owned())],
    )
    .unwrap();
    let path = format!(
        "{}/tests/golden/repo-baseline/doctor-no-host-adapter.json",
        env!("CARGO_MANIFEST_DIR")
    );
    if std::env::var_os("UPDATE_GOLDENS").is_some() {
        fs::write(&path, &actual).unwrap();
    }
    let expected = fs::read_to_string(&path).unwrap();
    assert_eq!(actual, expected, "{path} drifted; actual:\n{actual}");
}

// ---- RFC template (T6, #707) ------------------------------------------------------

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "asserts setup-core's own content or id; product-boundary T7b"
)]
#[test]
fn rfc_template_is_managed_with_last_verified_status_line_and_location() {
    let f = Fixture::new();
    let planned = f.apply(&RepoBaseline);
    assert_eq!(RFC_TEMPLATE_PATH, "docs/agent-setup/rfc-template.md");
    assert_eq!(
        planned.tags[RFC_TEMPLATE_PATH],
        (Ownership::Managed, "repo-baseline".to_owned())
    );
    let text = f.read(RFC_TEMPLATE_PATH);
    assert!(last_verified(&text).is_some(), "{text}");
    assert!(text.contains(
        "Draft → Discussion (5 days) → Decision (30-minute meeting or written decision) → Accepted | Rejected | Withdrawn"
    ));
    assert!(text.contains("docs/rfc/<date>-<slug>.md"));
    assert!(text.contains("`type:rfc`"));
    assert!(text.contains("adr-template.md"));
    for section in [
        "## Problem and classification",
        "## Options",
        "## Recommendation",
        "## Timebox",
        "## Decision",
    ] {
        assert!(text.contains(section), "{section}");
    }
    // The ADR template stays setup-core's, unchanged.
    assert_ne!(
        planned.tags["docs/agent-setup/adr-template.md"].1,
        "repo-baseline"
    );
    let doctor = diagnose_with(
        &f.root,
        today(),
        &Source::embedded(),
        &[&support::SetupCore, &RepoBaseline],
        &NoRunner,
    )
    .unwrap();
    assert!(
        !doctor
            .findings
            .iter()
            .any(|l| l.contains("rfc-template.md")),
        "{:?}",
        doctor.findings
    );
}

// ---- seeds (T5, #705) ----------------------------------------------------------

const SERVICE_CARD: &str = ".agent-setup/service.yaml";
const SECURITY: &str = ".github/SECURITY.md";
const CODEOWNERS: &str = ".github/CODEOWNERS";
const DEPENDABOT: &str = ".github/dependabot.yml";
const RENOVATE: &str = "renovate.json";

fn seeds_of(planned: &Planned) -> Vec<&str> {
    planned
        .tags
        .iter()
        .filter(|(_, tag)| **tag == (Ownership::Seed, "repo-baseline".to_owned()))
        .map(|(path, _)| path.as_str())
        .collect()
}

/// `package-ecosystem` values of `dependabot.yml`, in file order, with the
/// directory and interval of each entry.
fn dependabot_entries(text: &str) -> Vec<(String, String, String)> {
    let value = |line: &str, key: &str| {
        line.trim()
            .trim_start_matches("- ")
            .strip_prefix(key)
            .map(|v| v.trim().trim_matches('"').to_owned())
    };
    let mut entries = Vec::new();
    for line in text.lines() {
        if let Some(ecosystem) = value(line, "package-ecosystem:") {
            entries.push((ecosystem, String::new(), String::new()));
        } else if let (Some(entry), Some(dir)) = (entries.last_mut(), value(line, "directory:")) {
            entry.1 = dir;
        } else if let (Some(entry), Some(interval)) = (entries.last_mut(), value(line, "interval:"))
        {
            entry.2 = interval;
        }
    }
    entries
}

#[test]
fn seeds_p1_defaults_are_card_security_and_dependabot_without_codeowners() {
    let f = Fixture::new();
    let planned = f.apply(&RepoBaseline);
    assert_eq!(seeds_of(&planned), vec![SERVICE_CARD, SECURITY, DEPENDABOT]);
    assert!(!f.root.join(CODEOWNERS).exists());
    assert!(!f.root.join(RENOVATE).exists());
    let lock: Value = serde_json::from_str(&f.read(LOCK)).unwrap();
    for path in [SERVICE_CARD, SECURITY, DEPENDABOT] {
        assert_eq!(lock["files"][path]["class"], "seed", "{path}");
        assert!(
            lock["files"][path].get("digest").is_none(),
            "{path} is never digested"
        );
    }
}

#[test]
fn seeds_service_card_prefills_the_owner_and_the_spec_fields() {
    let f = Fixture::new();
    f.apply(&RepoBaseline);
    let card = f.read(SERVICE_CARD);
    for line in [
        "name: <owner>/<name>",
        "owner: example-owner",
        "tier: 3",
        "criticality: internal",
        "runbook: null",
        "dashboard: null",
        "alerts: null",
        "slo: null",
        "on_call: null",
        "security_contact: null",
    ] {
        assert!(
            card.lines()
                .any(|l| l.split(" #").next().unwrap().trim_end() == line),
            "{line} in\n{card}"
        );
    }
    assert!(!card.contains("{{"), "{card}");
}

#[test]
fn seeds_service_card_names_the_origin_repository() {
    let f = Fixture::new();
    let git = |args: &[&str]| {
        assert!(
            std::process::Command::new("git")
                .arg("-C")
                .arg(&f.root)
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
        "git@github.com:example-owner/demo-app.git",
    ]);
    f.apply(&RepoBaseline);
    assert!(
        f.read(SERVICE_CARD)
            .lines()
            .any(|l| l.starts_with("name: example-owner/demo-app")),
        "{}",
        f.read(SERVICE_CARD)
    );
}

#[test]
fn seeds_security_policy_points_to_the_card_and_promises_five_working_days() {
    let f = Fixture::new();
    f.apply(&RepoBaseline);
    let policy = f.read(SECURITY);
    for needle in [
        "default branch",
        "`security_contact`",
        ".agent-setup/service.yaml",
        "5 working days",
        "No secret is ever committed",
    ] {
        assert!(policy.contains(needle), "{needle} in\n{policy}");
    }
}

#[test]
fn seeds_dependabot_without_stack_packs_is_github_actions_monthly_only() {
    let f = Fixture::new();
    f.apply(&RepoBaseline);
    let text = f.read(DEPENDABOT);
    assert!(text.lines().any(|l| l == "version: 2"), "{text}");
    assert_eq!(
        dependabot_entries(&text),
        vec![("github-actions".into(), "/".into(), "monthly".into())]
    );
    assert_eq!(text.matches("default-days: 7").count(), 1, "{text}");
    assert_eq!(text.matches("compatible-updates:").count(), 1, "{text}");
    assert_eq!(
        text.matches("update-types: [\"minor\", \"patch\"]").count(),
        1,
        "{text}"
    );
    assert_eq!(
        text.matches("open-pull-requests-limit: 2").count(),
        1,
        "{text}"
    );
    assert!(!text.contains("reviewers"), "{text}");
}

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "asserts setup-core's own content or id; product-boundary T7b"
)]
#[test]
fn seeds_dependabot_adds_a_weekly_entry_per_active_stack_pack() {
    let f = Fixture::new();
    fs::write(f.root.join("Cargo.toml"), "[package]\nname = \"demo\"\n").unwrap();
    fs::write(f.root.join("Cargo.lock"), "").unwrap();
    fs::create_dir_all(f.root.join(".agent-setup/modules")).unwrap();
    fs::write(
        f.root.join(".agent-setup/modules/stack-packs.json"),
        serde_json::to_string_pretty(&json!({
            "module": "stack-packs",
            "version": "1.0.0",
            "answers": {
                "apps.root.path": ".", "apps.root.stack": "rust",
                "apps.root.container": false, "apps.root.toolchain": false,
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let source = Source::embedded();
    let profile = profile_for(&f.root).unwrap();
    let core = support::SetupCore;
    let packs = brakes::modules::StackPacks;
    let module = RepoBaseline;
    // A soft read: `repo-baseline` does not require `stack-packs`.
    assert_eq!(module.requires(), &["setup-core"]);
    let planned = engine::plan(
        &f.root,
        &source,
        &profile,
        &[&core, &packs, &module],
        &|_| true,
    )
    .unwrap();
    let text = planned.changes[DEPENDABOT].clone().unwrap();
    assert_eq!(
        dependabot_entries(&text),
        vec![
            ("github-actions".into(), "/".into(), "monthly".into()),
            ("cargo".into(), "/".into(), "weekly".into()),
        ]
    );
    assert_eq!(text.matches("default-days: 7").count(), 2, "{text}");
    assert_eq!(text.matches("compatible-updates:").count(), 2, "{text}");
    assert_eq!(
        text.matches("open-pull-requests-limit: 2").count(),
        2,
        "{text}"
    );
}

#[test]
fn seeds_renovate_and_codeowners_follow_the_answers() {
    let f = Fixture::new();
    let module = RepoBaseline;
    let planned = f
        .configure(
            &module,
            &[
                "approvals=checks-only-owner-bypass",
                "dependency_updates=renovate",
                "codeowners=true",
            ],
        )
        .unwrap();
    apply(&f.root, &planned.changes).unwrap();
    assert_eq!(
        seeds_of(&planned),
        vec![SERVICE_CARD, CODEOWNERS, SECURITY, RENOVATE]
    );
    assert!(!f.root.join(DEPENDABOT).exists());
    // #942: the owner line, then the protected paths; `ci-baseline` is not
    // active, so the held-out directory is the default.
    assert_eq!(
        f.read(CODEOWNERS)
            .lines()
            .filter(|l| !l.starts_with('#'))
            .collect::<Vec<_>>(),
        [
            "* @example-owner",
            "/.github/workflows/ @example-owner",
            "/tests/heldout/ @example-owner",
        ]
    );
    let renovate: Value = serde_json::from_str(&f.read(RENOVATE)).unwrap();
    assert_eq!(renovate["extends"], json!(["config:recommended"]));
    assert_eq!(renovate["minimumReleaseAge"], "7 days");
    assert_eq!(renovate["github-actions"]["enabled"], true);
    assert_eq!(
        renovate["packageRules"][0]["matchUpdateTypes"],
        json!(["minor", "patch"])
    );
    assert_golden(
        "p1-owner-bypass-renovate-codeowners",
        &rendered_tree(&f, &planned),
    );
}

#[test]
fn seeds_golden_p2_and_p3_defaults_carry_codeowners() {
    for (tier, name) in [(Tier::P2, "p2-defaults"), (Tier::P3, "p3-defaults")] {
        let f = Fixture::profiled(tier);
        let planned = f.apply(&RepoBaseline);
        assert!(seeds_of(&planned).contains(&CODEOWNERS), "{name}");
        assert!(seeds_of(&planned).contains(&DEPENDABOT), "{name}");
        assert_golden(name, &rendered_tree(&f, &planned));
    }
}

/// The CODEOWNERS seed `RepoBaseline` renders at P2 when the plan resolves
/// `ci_baseline` as `ci-baseline`'s answers (`None`: the module is not active).
fn codeowners_with(ci_baseline: Option<Value>) -> String {
    let resolved: Vec<(&str, Value)> = ci_baseline
        .map(|value| ("ci-baseline", value))
        .into_iter()
        .collect();
    codeowners_resolved(json!({}), &resolved).expect("P2 renders CODEOWNERS")
}

/// The CODEOWNERS seed at P2 with `files` written at the root first.
fn codeowners_with_files(files: &[(&str, &str)], resolved: &[(&str, Value)]) -> String {
    codeowners_in(json!({}), resolved, files).expect("P2 renders CODEOWNERS")
}

fn codeowners_resolved(answers: Value, resolved: &[(&str, Value)]) -> Option<String> {
    codeowners_in(answers, resolved, &[])
}

/// The CODEOWNERS seed `RepoBaseline` renders at P2 with its own `answers`
/// and `resolved` as the other active modules' answers; `None` when not rendered.
fn codeowners_in(
    answers: Value,
    resolved: &[(&str, Value)],
    files: &[(&str, &str)],
) -> Option<String> {
    let f = Fixture::new();
    for (path, text) in files {
        fs::write(f.root.join(path), text).unwrap();
    }
    // Each stack-packs app directory exists, with a node manifest.
    for (_, value) in resolved.iter().filter(|(id, _)| *id == "stack-packs") {
        for (key, path) in value.as_object().unwrap() {
            if key.ends_with(".path") {
                let dir = f.root.join(path.as_str().unwrap());
                fs::create_dir_all(&dir).unwrap();
                for manifest in ["package.json", "package-lock.json"] {
                    if !dir.join(manifest).exists() {
                        fs::write(dir.join(manifest), "{}").unwrap();
                    }
                }
            }
        }
    }
    let profile = profile_for(&f.root).unwrap();
    let source = Source::embedded();
    let previous = engine::Lock {
        schema: 2,
        version: "test".to_owned(),
        source_commit: None,
        source_dirty: false,
        personal_owner: "example-owner".to_owned(),
        modules: Default::default(),
        files: Default::default(),
    };
    let answers = RepoBaseline
        .questions()
        .validate(
            "repo-baseline",
            &serde_json::from_value(answers).unwrap(),
            "P2",
        )
        .unwrap();
    let resolved: std::collections::BTreeMap<String, engine_answers::Answers> = resolved
        .iter()
        .map(|(id, value)| {
            (
                (*id).to_owned(),
                serde_json::from_value(value.clone()).unwrap(),
            )
        })
        .collect();
    let cx = engine::Context::new(
        &f.root,
        &profile,
        &source,
        &previous,
        &answers,
        &RepoBaseline,
        &resolved,
    )
    .with_tier("P2");
    RepoBaseline
        .render(&cx)
        .unwrap()
        .into_iter()
        .find(|r| r.path == CODEOWNERS)
        .and_then(|r| r.content)
}

#[test]
fn seeds_codeowners_names_the_held_out_directory_ci_baseline_answers() {
    let protected = |text: &str| {
        text.lines()
            .filter(|l| l.starts_with('/'))
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        protected(&codeowners_with(Some(
            json!({ "heldout_dir": "qa/heldout" })
        ))),
        [
            "/.github/workflows/ @example-owner",
            "/qa/heldout/ @example-owner",
        ]
    );
    // The answer as a user may write it: a leading `./`, a trailing slash.
    assert_eq!(
        protected(&codeowners_with(Some(
            json!({ "heldout_dir": "./qa/heldout/" })
        )))[1],
        "/qa/heldout/ @example-owner"
    );
    // `ci-baseline` active without the answer, or not active: the spec's default.
    for answers in [Some(json!({})), None] {
        assert_eq!(
            protected(&codeowners_with(answers.clone()))[1],
            "/tests/heldout/ @example-owner",
            "{answers:?}"
        );
    }
}

/// qa T8 (#1005): the screenshot baselines' CODEOWNERS line, from the same
/// derivation as `ci-baseline`'s protected glob.
#[test]
fn seeds_codeowners_names_qa_web_directories_when_qa_has_a_web() {
    let protected = |text: &str| {
        text.lines()
            .filter(|l| !l.starts_with('#') && !l.starts_with("* "))
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    // qa requires stack-packs: one node app at the root, whose seeded
    // Dockerfile derives an API, so every case answers `api: false`.
    let root = json!({"apps.root.path": ".", "apps.root.stack": "node"});
    let seeded = json!({"api": false, "web": "seeded", "web_start": "npm start"});
    assert_eq!(
        protected(
            &codeowners_resolved(
                json!({}),
                &[("qa", seeded.clone()), ("stack-packs", root.clone())]
            )
            .unwrap()
        ),
        [
            "/.github/workflows/ @example-owner",
            "/tests/heldout/ @example-owner",
            "/qa/web/ @example-owner",
        ]
    );
    // A project web lives at the root: every snapshots directory, not `/./`.
    let project = json!({"api": false, "web": "project", "web_start": "npm run dev"});
    assert_eq!(
        protected(&codeowners_with_files(
            &[("playwright.config.ts", "")],
            &[("qa", project), ("stack-packs", root.clone())],
        ))[2..],
        ["**/*-snapshots/ @example-owner"]
    );
    // Monorepo: each app's web directory under its stack-packs path.
    let apps = json!({"apps": ["web"], "apps.web.api": false, "apps.web.web": "seeded", "apps.web.web_start": "npm start",
                      "apps.web.web_dir": "e2e"});
    let packs = json!({"apps.web.path": "apps/web", "apps.web.stack": "node"});
    assert_eq!(
        protected(
            &codeowners_resolved(json!({}), &[("qa", apps), ("stack-packs", packs)]).unwrap()
        )[2..],
        ["/apps/web/e2e/ @example-owner"]
    );
    // No web, answers qa refuses, or qa not active: only the two lines of #942.
    for resolved in [
        vec![
            ("qa", json!({"api": false, "web": "none"})),
            ("stack-packs", root.clone()),
        ],
        vec![
            ("qa", json!({"api": false, "web": "seeded"})),
            ("stack-packs", root.clone()),
        ],
        vec![],
    ] {
        assert_eq!(
            protected(&codeowners_resolved(json!({}), &resolved).unwrap()).len(),
            2,
            "{resolved:?}"
        );
    }
    // T4 (#1001): no `web` answer, but the root app's files derive one.
    let derived = codeowners_with_files(
        &[
            (
                "package.json",
                r#"{"devDependencies": {"@playwright/test": "1.56.1"}}"#,
            ),
            ("package-lock.json", "{}"),
            ("playwright.config.ts", ""),
        ],
        &[
            ("qa", json!({"api": false, "web_start": "npm run dev"})),
            ("stack-packs", root.clone()),
        ],
    );
    assert_eq!(protected(&derived)[2..], ["**/*-snapshots/ @example-owner"]);
    // codeowners = false: no CODEOWNERS at all.
    assert_eq!(
        codeowners_resolved(
            json!({"codeowners": false}),
            &[("qa", seeded), ("stack-packs", root)]
        ),
        None
    );
}

#[test]
fn seeds_existing_files_are_skipped_never_rewritten_and_listed_by_remove() {
    let f = Fixture::profiled(Tier::P2);
    let module = RepoBaseline;
    let owned = [
        (SERVICE_CARD, "name: theirs\nowner: someone\n"),
        (SECURITY, "# Their policy\n"),
        (CODEOWNERS, "/ios/ @someone\n"),
        (DEPENDABOT, "version: 2\nupdates: []\n"),
    ];
    for (path, text) in owned {
        let file = f.root.join(path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, text).unwrap();
    }
    let planned = f.apply(&module);
    for (path, text) in owned {
        assert_eq!(
            planned.tags[path],
            (Ownership::Seed, "repo-baseline".to_owned()),
            "{path}"
        );
        assert_eq!(planned.notes.get(path), Some(&engine::Note::Skip), "{path}");
        assert!(!planned.changes.contains_key(path), "{path}");
        assert_eq!(f.read(path), text, "{path}");
    }
    let core = support::SetupCore;
    let removed = engine::remove(&f.root, &[&core, &module], &|_| true, "repo-baseline").unwrap();
    for (path, _) in owned {
        assert_eq!(removed.notes.get(path), Some(&engine::Note::Keep), "{path}");
        assert!(!removed.changes.contains_key(path), "{path}");
    }
}

// ---- T7 (#710): activation through the registry -------------------------------

/// `install <repo> [--module <id>] [--profile <P>]` through the library, as the CLI runs it.
fn install(f: &Fixture, requested: &[&str], profile: Option<&str>) -> Result<Planned> {
    brakes::plan_install(&f.root, &Source::embedded(), requested, profile)
}
fn install_applied(f: &Fixture, requested: &[&str], profile: Option<&str>) -> Planned {
    let planned = install(f, requested, profile).unwrap();
    apply(&f.root, &planned.changes).unwrap();
    planned
}
fn recorded_answers(f: &Fixture) -> Value {
    serde_json::from_str(&f.read(&engine_answers::path("repo-baseline"))).unwrap()
}

#[test]
fn lifecycle_module_is_registered_after_stack_packs_and_before_ci_baseline() {
    let ids: Vec<&str> = modules::all().iter().map(|m| m.id()).collect();
    assert_eq!(
        ids,
        crate::support::with_core(&[
            "stack-packs",
            "merge-guard",
            "repo-baseline",
            "agent-guardrails",
            "security",
            "qa",
            "ci-baseline"
        ])
    );
    assert_eq!(
        modules::find("repo-baseline").map(|m| m.version()),
        Some("1.0.0")
    );
}

#[test]
fn lifecycle_fresh_p1_install_writes_the_baseline_and_a_second_run_is_empty() {
    let f = Fixture::new();
    let planned = install_applied(&f, &["repo-baseline"], None);
    let mut expected = vec![
        RULESET_PATH,
        PR_TEMPLATE_PATH,
        SERVICE_CARD,
        SERVICE_SCHEMA_PATH,
        DEPENDABOT,
        SECURITY,
        "docs/agent-setup/rfc-template.md",
    ];
    expected.extend(ISSUE_FORM_PATHS);
    for path in expected {
        assert_eq!(
            planned.tags.get(path).map(|(_, m)| m.as_str()),
            Some("repo-baseline"),
            "{path}"
        );
        assert!(f.root.join(path).is_file(), "{path}");
    }
    assert!(!f.root.join(CODEOWNERS).exists(), "P1 has no CODEOWNERS");
    let mut ids: Vec<&str> = planned
        .steps
        .iter()
        .filter(|s| s.module == "repo-baseline")
        .map(|s| s.id.as_str())
        .collect();
    ids.sort_unstable();
    assert_eq!(
        ids,
        [
            "check-reported",
            "classic-protection-retire",
            "dependabot-alerts",
            "dependabot-security-updates",
            "labels",
            "repo-settings",
            "ruleset-main"
        ]
    );
    assert!(
        !f.root.join(engine_answers::path("repo-baseline")).exists(),
        "the default profile records no answers file"
    );
    // The lock records the module, so a plain `install` reconciles it: nothing to do.
    assert!(install(&f, &[], None).unwrap().changes.is_empty());
    assert!(
        install(&f, &["repo-baseline"], None)
            .unwrap()
            .changes
            .is_empty()
    );
}

#[test]
fn lifecycle_install_without_the_module_in_the_lock_has_no_repo_baseline_line() {
    let f = Fixture::new();
    let planned = install_applied(&f, &[], None);
    assert!(
        planned.tags.values().all(|(_, m)| m != "repo-baseline"),
        "{:?}",
        planned.tags
    );
    assert!(planned.steps.iter().all(|s| s.module != "repo-baseline"));
    assert!(
        planned
            .plan_notes
            .iter()
            .all(|n| n.module != "repo-baseline")
    );
    assert!(!f.root.join(RULESET_PATH).exists());
    let lock: Value = serde_json::from_str(&f.read(LOCK)).unwrap();
    assert!(lock["modules"].get("repo-baseline").is_none());
}

#[test]
fn lifecycle_profile_is_recorded_with_the_answers_and_drives_the_defaults() {
    let f = Fixture::new();
    let planned = install_applied(&f, &["repo-baseline"], Some("P2"));
    let path = engine_answers::path("repo-baseline");
    assert_eq!(
        planned.answers.get(&path).map(String::as_str),
        Some("repo-baseline")
    );
    assert_eq!(
        recorded_answers(&f),
        json!({ "module": "repo-baseline", "version": "1.0.0", "profile": "P2", "answers": {} })
    );
    let ruleset = f.ruleset();
    let parameters = &rule(&ruleset, "pull_request")["parameters"];
    assert_eq!(parameters["required_approving_review_count"], 1);
    assert_eq!(parameters["require_code_owner_review"], true);
    assert!(f.root.join(CODEOWNERS).is_file(), "P2 seeds CODEOWNERS");
    // The recorded profile holds without the flag; repeating it changes nothing.
    assert!(install(&f, &[], None).unwrap().changes.is_empty());
    assert!(
        install(&f, &["repo-baseline"], Some("P2"))
            .unwrap()
            .changes
            .is_empty()
    );
    // Back to P1: the file records it and the ruleset follows.
    install_applied(&f, &["repo-baseline"], Some("P1"));
    assert_eq!(recorded_answers(&f)["profile"], "P1");
    assert_eq!(
        rule(&f.ruleset(), "pull_request")["parameters"]["required_approving_review_count"],
        0
    );
}

#[test]
fn lifecycle_unknown_profile_is_refused_before_anything_is_planned() {
    let f = Fixture::new();
    assert_eq!(
        install(&f, &["repo-baseline"], Some("P4"))
            .unwrap_err()
            .to_string(),
        "Unknown profile: P4; use P1, P2 or P3"
    );
    let path = engine_answers::path("repo-baseline");
    fs::create_dir_all(f.root.join(".agent-setup/modules")).unwrap();
    fs::write(
        f.root.join(&path),
        r#"{"module":"repo-baseline","version":"1.0.0","profile":"P9","answers":{}}"#,
    )
    .unwrap();
    assert_eq!(
        install(&f, &["repo-baseline"], None)
            .unwrap_err()
            .to_string(),
        format!("Module repo-baseline: answers file records unknown profile `P9`: {path}")
    );
}

#[test]
fn lifecycle_configure_keeps_the_recorded_profile() {
    let f = Fixture::new();
    install_applied(&f, &["repo-baseline"], Some("P3"));
    let configured = brakes::configure(
        &f.root,
        &Source::embedded(),
        "repo-baseline",
        &Inputs {
            sets: vec!["dependency_updates=renovate".to_owned()],
            ..Inputs::default()
        },
    )
    .unwrap();
    apply(&f.root, &configured.planned.changes).unwrap();
    let recorded = recorded_answers(&f);
    assert_eq!(recorded["profile"], "P3");
    assert_eq!(recorded["answers"]["dependency_updates"], "renovate");
    assert_eq!(recorded["answers"]["approvals"], "one-approval");
    assert!(f.root.join(RENOVATE).is_file());
}

#[test]
fn lifecycle_plan_notes_carry_the_declared_checks_finding() {
    let f = Fixture::new();
    install_applied(&f, &[], None);
    let mut value: Value = serde_json::from_str(&f.read(PROFILE)).unwrap();
    value["ci"]["required_checks"] = five_contexts_project().value["ci"]["required_checks"].clone();
    fs::write(
        f.root.join(PROFILE),
        serde_json::to_string_pretty(&value).unwrap(),
    )
    .unwrap();
    let planned = install(&f, &["repo-baseline"], None).unwrap();
    let notes: Vec<String> = planned.plan_notes.iter().map(ToString::to_string).collect();
    assert_eq!(
        notes,
        ["NOTE [repo-baseline] Required checks: 5 contexts, the standard is one aggregate check"]
    );
    let plain = Fixture::new();
    assert!(
        install(&plain, &["repo-baseline"], None)
            .unwrap()
            .plan_notes
            .is_empty()
    );
}

#[test]
fn lifecycle_remove_deletes_unchanged_refuses_edited_and_reports_seeds() {
    let f = Fixture::new();
    install_applied(&f, &["repo-baseline"], Some("P2"));
    let edited = f.read(RULESET_PATH).replace("\"active\"", "\"disabled\"");
    let original = f.read(RULESET_PATH);
    fs::write(f.root.join(RULESET_PATH), &edited).unwrap();
    assert_eq!(
        brakes::remove(&f.root, "repo-baseline")
            .unwrap_err()
            .to_string(),
        format!(
            "Locally changed managed content of module repo-baseline: {RULESET_PATH}; restore it before removing the module"
        )
    );
    fs::write(f.root.join(RULESET_PATH), original).unwrap();
    let removed = brakes::remove(&f.root, "repo-baseline").unwrap();
    apply(&f.root, &removed.changes).unwrap();
    for path in [
        RULESET_PATH,
        SERVICE_SCHEMA_PATH,
        "docs/agent-setup/rfc-template.md",
    ]
    .into_iter()
    .chain(ISSUE_FORM_PATHS)
    {
        assert!(!f.root.join(path).exists(), "{path} deleted");
    }
    // The PR template loses its managed block; the skeleton around it is the project's.
    let template = fs::read_to_string(f.root.join(PR_TEMPLATE_PATH)).unwrap_or_default();
    assert_eq!(block_content(&template).unwrap(), None);
    for seed in [SERVICE_CARD, SECURITY, CODEOWNERS, DEPENDABOT] {
        assert_eq!(removed.notes.get(seed), Some(&engine::Note::Keep), "{seed}");
        assert!(f.root.join(seed).is_file(), "{seed} kept");
    }
    assert!(!f.root.join(engine_answers::path("repo-baseline")).exists());
    let lock: Value = serde_json::from_str(&f.read(LOCK)).unwrap();
    assert!(lock["modules"].get("repo-baseline").is_none());
    assert!(install(&f, &[], None).unwrap().changes.is_empty());
}

// ---- the service schema's $id (product-boundary T6e, #1055) ----------------------

#[test]
fn the_service_schema_id_is_the_configured_base_or_the_products_own() {
    let id = |text: &str| -> String {
        serde_json::from_str::<Value>(text).unwrap()["$id"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    assert_eq!(
        id(&service_schema(None)),
        "https://github.com/gemba-app/brakes/blob/main/templates/repo-baseline/service.schema.json"
    );
    assert_eq!(
        id(&service_schema(Some("https://example.invalid/t/"))),
        "https://example.invalid/t/repo-baseline/service.schema.json"
    );
}

// ---- declared bypass actors (decision 2026-10-31, #1218) -------------------------

fn with_actors(approvals: Approvals, actors: &[&str]) -> Answers {
    Answers {
        approvals,
        codeowners: false,
        bypass_actors: actors.iter().map(|a| (*a).to_owned()).collect(),
    }
}

#[test]
fn bypass_actors_default_to_empty_in_every_profile() {
    for tier in [Tier::P1, Tier::P2, Tier::P3] {
        assert!(Answers::defaults(tier).bypass_actors.is_empty(), "{tier:?}");
    }
    let question = questions_schema();
    let question = question.question("bypass_actors").unwrap();
    assert_eq!(question.kind, Kind::ArrayOfString);
    assert_eq!(question.default, Some(json!([])));
}

#[test]
fn one_approval_with_an_org_admin_bypass_renders_a_checks_ruleset_without_bypass_and_a_review_ruleset_with_it()
 {
    let answers = with_actors(
        Approvals::OneApproval,
        &["OrganizationAdmin:1:pull_request"],
    );
    let out = ruleset(Tier::P2, &answers, &plain_project(), &default_checks()).unwrap();
    // The checks ruleset: every rule but the review, and nobody bypasses it.
    let checks = &out.value;
    assert_eq!(checks["name"], "brakes: default branch baseline");
    assert_eq!(checks["bypass_actors"], json!([]));
    let kinds: Vec<&str> = checks["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["type"].as_str().unwrap())
        .collect();
    assert_eq!(
        kinds,
        [
            "deletion",
            "non_fast_forward",
            "required_linear_history",
            "required_status_checks"
        ]
    );
    assert_eq!(contexts(checks)[0]["context"], "required");
    // The review ruleset: the approval rule alone, with the declared bypass.
    let review = out
        .review
        .expect("a review ruleset when a bypass is declared");
    assert_eq!(
        review,
        json!({
            "name": "brakes: default branch review",
            "target": "branch",
            "enforcement": "active",
            "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
            "bypass_actors": [
                { "actor_id": 1, "actor_type": "OrganizationAdmin", "bypass_mode": "pull_request" }
            ],
            "rules": [
                { "type": "pull_request", "parameters": {
                    "required_approving_review_count": 1,
                    "dismiss_stale_reviews_on_push": true,
                    "require_code_owner_review": false,
                    "require_last_push_approval": true,
                    "required_review_thread_resolution": true,
                    "allowed_merge_methods": ["squash"] } }
            ]
        })
    );
}

#[test]
fn without_a_declared_bypass_there_is_one_ruleset_as_before() {
    for tier in [Tier::P1, Tier::P2, Tier::P3] {
        let out = ruleset(
            tier,
            &Answers::defaults(tier),
            &plain_project(),
            &default_checks(),
        )
        .unwrap();
        assert_eq!(out.review, None, "{tier:?}");
    }
    let owner = Answers {
        approvals: Approvals::ChecksOnlyOwnerBypass,
        codeowners: false,
        bypass_actors: Vec::new(),
    };
    assert_eq!(
        ruleset(Tier::P1, &owner, &plain_project(), &default_checks())
            .unwrap()
            .review,
        None
    );
}

#[test]
fn the_owner_bypass_answer_cannot_be_combined_with_declared_actors() {
    let answers = with_actors(Approvals::ChecksOnlyOwnerBypass, &["Team:42:pull_request"]);
    let error = ruleset(Tier::P1, &answers, &plain_project(), &default_checks()).unwrap_err();
    assert_eq!(
        error.to_string(),
        "Module repo-baseline: approvals `checks-only-owner-bypass` bypasses the required checks too, so it cannot be combined with bypass_actors; use `checks-only` or `one-approval`"
    );
}

#[test]
fn bypass_actors_outside_the_policy_are_refused_with_the_exact_message() {
    let cases = [
        (
            "Integration:15368:always",
            "Module repo-baseline: bypass actor `Integration:15368:always` refused: type Integration is not allowed; bypass actors are OrganizationAdmin, RepositoryRole or Team, never an agent identity or App",
        ),
        (
            "User:7:pull_request",
            "Module repo-baseline: bypass actor `User:7:pull_request` refused: type User is not allowed; bypass actors are OrganizationAdmin, RepositoryRole or Team, never an agent identity or App",
        ),
        (
            "DeployKey:3:always",
            "Module repo-baseline: bypass actor `DeployKey:3:always` refused: type DeployKey is not allowed; bypass actors are OrganizationAdmin, RepositoryRole or Team, never an agent identity or App",
        ),
        (
            "Team:12:exempt",
            "Module repo-baseline: bypass actor `Team:12:exempt` refused: mode exempt is not allowed; use pull_request or always",
        ),
        (
            "OrganizationAdmin:2:pull_request",
            "Module repo-baseline: bypass actor `OrganizationAdmin:2:pull_request` refused: OrganizationAdmin is written with the id 1, which GitHub ignores",
        ),
        (
            "Team:abc:always",
            "Module repo-baseline: bypass actor `Team:abc:always` refused: not actor_type:actor_id:bypass_mode with a numeric actor_id",
        ),
        (
            "Team:12",
            "Module repo-baseline: bypass actor `Team:12` refused: not actor_type:actor_id:bypass_mode with a numeric actor_id",
        ),
    ];
    for (actor, message) in cases {
        let answers = with_actors(Approvals::OneApproval, &[actor]);
        let error = ruleset(Tier::P2, &answers, &plain_project(), &default_checks()).unwrap_err();
        assert_eq!(error.to_string(), message, "{actor}");
    }
}

#[test]
fn a_repeated_bypass_actor_is_refused() {
    let answers = with_actors(
        Approvals::OneApproval,
        &["Team:12:always", "Team:12:always"],
    );
    let error = ruleset(Tier::P2, &answers, &plain_project(), &default_checks()).unwrap_err();
    assert_eq!(
        error.to_string(),
        "Module repo-baseline: bypass actor `Team:12:always` is declared twice"
    );
}

const ORG_ADMIN: &str = "OrganizationAdmin:1:pull_request";

fn inventory(f: &Fixture, entries: Value) {
    let path = f.root.join(".agent-setup/security-exceptions.json");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let text = json!({ "schema": 1, "exceptions": entries });
    fs::write(path, serde_json::to_string_pretty(&text).unwrap() + "\n").unwrap();
}

fn bypass_entry(target: &str) -> Value {
    json!({
        "id": "org-owners-merge", "kind": "ruleset-bypass-actor", "target": target,
        "reason": "organization owners merge their own pull requests", "issue": "#392",
        "owner": "example-owner", "created": "2026-10-31", "expires": "2027-10-31"
    })
}

#[test]
fn a_declared_actor_without_an_inventory_entry_is_refused_at_configure() {
    let f = Fixture::profiled(Tier::P2);
    let error = f
        .configure(&RepoBaseline, &[&format!("bypass_actors={ORG_ADMIN}")])
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "Module repo-baseline: bypass actor `OrganizationAdmin:1:pull_request` has no ruleset-bypass-actor entry in .agent-setup/security-exceptions.json; add one with an issue and an expiry"
    );
    assert!(!f.root.join(LOCK).exists(), "nothing written");
    // An entry of another kind for the same target does not register it.
    let mut entry = bypass_entry(ORG_ADMIN);
    entry["kind"] = json!("allowlist");
    inventory(&f, json!([entry]));
    assert!(
        f.configure(&RepoBaseline, &[&format!("bypass_actors={ORG_ADMIN}")])
            .is_err()
    );
}

#[test]
fn a_declared_actor_with_an_invalid_entry_is_refused_naming_the_defect() {
    let f = Fixture::profiled(Tier::P2);
    let mut entry = bypass_entry(ORG_ADMIN);
    entry.as_object_mut().unwrap().remove("issue");
    inventory(&f, json!([entry]));
    let error = f
        .configure(&RepoBaseline, &[&format!("bypass_actors={ORG_ADMIN}")])
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "Module repo-baseline: bypass actor `OrganizationAdmin:1:pull_request` is registered by an invalid entry: Exception org-owners-merge is missing issue"
    );
    let mut entry = bypass_entry(ORG_ADMIN);
    entry["expires"] = json!("2028-01-01");
    inventory(&f, json!([entry]));
    let error = f
        .configure(&RepoBaseline, &[&format!("bypass_actors={ORG_ADMIN}")])
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "Module repo-baseline: bypass actor `OrganizationAdmin:1:pull_request` is registered by an invalid entry: Exception org-owners-merge lasts 427 days; ruleset-bypass-actor allows at most 365"
    );
}

#[test]
fn a_registered_actor_renders_through_the_engine_by_full_form_or_prefix() {
    for target in [ORG_ADMIN, "OrganizationAdmin:1"] {
        let f = Fixture::profiled(Tier::P2);
        inventory(&f, json!([bypass_entry(target)]));
        let planned = f
            .configure(&RepoBaseline, &[&format!("bypass_actors={ORG_ADMIN}")])
            .unwrap();
        assert_eq!(
            planned.tags[REVIEW_RULESET_PATH],
            (Ownership::Managed, "repo-baseline".to_owned()),
            "{target}"
        );
        apply(&f.root, &planned.changes).unwrap();
        let checks = f.ruleset();
        assert_eq!(checks["bypass_actors"], json!([]), "{target}");
        assert_eq!(contexts(&checks)[0]["context"], "required");
        let review: Value = serde_json::from_str(&f.read(REVIEW_RULESET_PATH)).unwrap();
        assert_eq!(
            review["bypass_actors"],
            json!([{ "actor_id": 1, "actor_type": "OrganizationAdmin", "bypass_mode": "pull_request" }]),
            "{target}"
        );
        assert_eq!(
            rule(&review, "pull_request")["parameters"]["required_approving_review_count"],
            1
        );
        assert!(
            f.plan(&RepoBaseline).unwrap().changes.is_empty(),
            "{target}"
        );
        // `apply --remote` reads both files back: the bypass is on the review only.
        let desired = brakes::host::desired::ruleset_from_file(
            &f.read(REVIEW_RULESET_PATH),
            REVIEW_RULESET_PATH,
        )
        .unwrap();
        assert_eq!(desired.bypass_actors, [ORG_ADMIN], "{target}");
        let lock: Value = serde_json::from_str(&f.read(LOCK)).unwrap();
        assert_eq!(lock["files"]["github:ruleset-review"]["class"], "remote");
    }
}

#[test]
fn removing_the_bypass_returns_to_one_ruleset_and_drops_the_review_file() {
    let f = Fixture::profiled(Tier::P2);
    let before = {
        let planned = f
            .configure(&RepoBaseline, &["approvals=one-approval"])
            .unwrap();
        apply(&f.root, &planned.changes).unwrap();
        f.read(RULESET_PATH)
    };
    inventory(&f, json!([bypass_entry(ORG_ADMIN)]));
    let planned = f
        .configure(&RepoBaseline, &[&format!("bypass_actors={ORG_ADMIN}")])
        .unwrap();
    apply(&f.root, &planned.changes).unwrap();
    assert!(f.root.join(REVIEW_RULESET_PATH).is_file());
    let planned = f.configure(&RepoBaseline, &["bypass_actors="]).unwrap();
    apply(&f.root, &planned.changes).unwrap();
    assert!(!f.root.join(REVIEW_RULESET_PATH).exists());
    assert_eq!(
        f.read(RULESET_PATH),
        before,
        "byte-identical to the single ruleset"
    );
    let lock: Value = serde_json::from_str(&f.read(LOCK)).unwrap();
    assert!(lock["files"].get("github:ruleset-review").is_none());
}

#[test]
fn a_declared_bypass_adds_the_review_ruleset_step_after_ruleset_main() {
    let root = Fixture::new().root;
    let ids = |split: bool| -> Vec<String> {
        baseline_steps::steps(&root, &["required".to_owned()], split)
            .into_iter()
            .map(|s| s.id)
            .collect()
    };
    assert!(!ids(false).iter().any(|id| id == "ruleset-review"));
    let split = baseline_steps::steps(&root, &["required".to_owned()], true);
    let review = split.iter().find(|s| s.id == "ruleset-review").unwrap();
    assert_eq!(review.after.as_deref(), Some("ruleset-main"));
    assert_eq!(
        ids(true)[..3],
        ["check-reported", "ruleset-main", "ruleset-review"]
    );
    let brakes::engine::manual::Probe::Remote { id, args } = &review.probe else {
        panic!("{:?}", review.probe);
    };
    assert_eq!(id, "ruleset-present");
    assert_eq!(args["name"], "brakes: default branch review");
    assert_eq!(args["path"], ".github/rulesets/main-review.json");
}

// --- #1236: the card's criticality follows the project profile ---------------------

/// A minimal profile declaring `criticality` (absent when `None`).
fn write_profile(f: &Fixture, criticality: Option<&str>) {
    let mut profile = default_profile();
    profile["purpose"] = json!("fixture");
    profile["criticality"] = criticality.map_or(Value::Null, |c| json!(c));
    let path = f.root.join(".agent-setup/project.json");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, serde_json::to_string_pretty(&profile).unwrap() + "\n").unwrap();
}

fn card_criticality(card: &str) -> String {
    card.lines()
        .find_map(|l| l.strip_prefix("criticality:"))
        .map(|v| v.split(" #").next().unwrap().trim().to_owned())
        .unwrap()
}

#[test]
fn seeds_service_card_criticality_from_the_project_profile() {
    for criticality in ["internal", "customers", "personal-data-or-payments"] {
        let f = Fixture::new();
        write_profile(&f, Some(criticality));
        f.apply(&RepoBaseline);
        assert_eq!(
            card_criticality(&f.read(SERVICE_CARD)),
            criticality,
            "{criticality}"
        );
    }
}

#[test]
fn seeds_service_card_internal_only_when_the_profile_declares_none() {
    let f = Fixture::new();
    write_profile(&f, None);
    f.apply(&RepoBaseline);
    assert_eq!(card_criticality(&f.read(SERVICE_CARD)), "internal");
}

#[test]
fn a_deleted_service_card_is_re_seeded_with_the_declared_criticality() {
    let f = Fixture::new();
    write_profile(&f, None);
    f.apply(&RepoBaseline);
    assert_eq!(card_criticality(&f.read(SERVICE_CARD)), "internal");
    write_profile(&f, Some("personal-data-or-payments"));
    fs::remove_file(f.root.join(SERVICE_CARD)).unwrap();
    f.apply(&RepoBaseline);
    assert_eq!(
        card_criticality(&f.read(SERVICE_CARD)),
        "personal-data-or-payments"
    );
}

/// `doctor`'s lines about the card for a profile declaring `profile` and a card
/// saying `card` (no card when `None`).
fn card_findings(profile: Option<&str>, card: Option<&str>) -> Vec<String> {
    let f = Fixture::new();
    write_profile(&f, profile);
    if let Some(card) = card {
        fs::write(
            f.root.join(SERVICE_CARD),
            format!(
                "name: a/b\nowner: example-owner\ntier: 3\ncriticality: {card}   # a comment\n"
            ),
        )
        .unwrap();
    }
    doctor(&f.root)
        .unwrap()
        .into_iter()
        .filter(|l| l.contains("Service card criticality"))
        .collect()
}

#[test]
fn doctor_reports_a_card_criticality_that_differs_from_the_profile() {
    assert_eq!(
        card_findings(Some("personal-data-or-payments"), Some("internal")),
        [
            "WARNING: Service card criticality differs from the project profile: .agent-setup/service.yaml says internal, .agent-setup/project.json says personal-data-or-payments; project.json decides the required level, align the card"
        ]
    );
    assert_eq!(
        card_findings(None, Some("customers")),
        [
            "WARNING: Service card criticality differs from the project profile: .agent-setup/service.yaml says customers, .agent-setup/project.json says undeclared, audited as internal; project.json decides the required level, align the card"
        ]
    );
}

#[test]
fn doctor_is_silent_on_a_matching_card_an_undeclared_internal_one_or_no_card() {
    assert!(card_findings(Some("customers"), Some("customers")).is_empty());
    assert!(card_findings(None, Some("internal")).is_empty());
    assert!(card_findings(Some("customers"), None).is_empty());
}
