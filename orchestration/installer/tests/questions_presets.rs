//! The preset catalogue (SPEC-questions.md, Preset; #711): the four embedded
//! presets, `--preset` on `configure`, the `presets` listing and the CI gate that
//! validates every preset against every compiled module with a section.
use brakes::engine::answers::{self, Schema};
use brakes::engine::{Context, Module, Ownership, Rendered};
use brakes::questions::{self, Inputs, answers_file};
use brakes::{LOCK, Source, apply, modules, profile_for};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, path::PathBuf, process::Command};

const NAMES: [&str; 4] = [
    "enterprise-k8s",
    "personal-paas",
    "personal-vps",
    "team-cloud",
];

// ---- The CI gate: every embedded preset × every compiled module with a section.

#[test]
fn every_embedded_preset_validates_against_every_compiled_module_it_names() {
    let catalogue = answers_file::catalogue(None).unwrap();
    let names: Vec<&str> = catalogue.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, NAMES);
    for preset in &catalogue {
        assert!(!preset.description.is_empty(), "{}", preset.name);
        answers_file::check(preset, &modules::all()).unwrap();
    }
}

#[test]
fn the_embedded_catalogue_is_exactly_the_files_under_templates_presets() {
    let checkout = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let from_checkout = answers_file::catalogue(Some(&checkout)).unwrap();
    assert_eq!(from_checkout, answers_file::catalogue(None).unwrap());
}

// ---- What the catalogue answers (#1181).

/// The compiled modules that ask anything.
fn modules_with_questions() -> Vec<&'static dyn Module> {
    modules::all()
        .into_iter()
        .filter(|m| !m.questions().questions.is_empty())
        .collect()
}

#[test]
fn every_embedded_preset_answers_or_explains_every_compiled_module_with_questions() {
    let modules = modules_with_questions();
    assert!(modules.len() >= 6, "{}", modules.len());
    for preset in answers_file::catalogue(None).unwrap() {
        for module in &modules {
            let id = module.id();
            let section = preset.modules.get(id);
            let reason = preset.no_answers.get(id);
            assert!(
                section.is_some_and(|s| !s.is_empty()) ^ reason.is_some(),
                "preset {}: module {id} needs exactly one of a non-empty section or a no_answers reason",
                preset.name
            );
            if let Some(reason) = reason {
                assert!(
                    reason.len() >= 40,
                    "preset {}: {id}: reason too short",
                    preset.name
                );
            }
        }
        for id in preset.no_answers.keys() {
            assert!(
                modules.iter().any(|m| m.id() == id),
                "preset {}: no_answers names `{id}`, which asks nothing or is not compiled",
                preset.name
            );
        }
    }
}

#[test]
fn every_embedded_preset_answers_what_its_description_implies() {
    // (preset, approvals, codeowners, merge_queue): who merges, from the description;
    // the merge queue only where several teams merge on Enterprise Cloud.
    let expected = [
        ("enterprise-k8s", "one-approval", true, true),
        ("personal-paas", "checks-only", false, false),
        ("personal-vps", "checks-only", false, false),
        ("team-cloud", "one-approval", true, false),
    ];
    let catalogue = answers_file::catalogue(None).unwrap();
    for (preset, (name, approvals, codeowners, merge_queue)) in catalogue.iter().zip(expected) {
        assert_eq!(preset.name, name);
        let only_owner = preset
            .description
            .contains("the owner is the only human with merge rights");
        let one_approval = preset.description.contains("merges need one approval");
        assert!(only_owner ^ one_approval, "{name}: {}", preset.description);
        assert_eq!(approvals == "checks-only", only_owner, "{name}");
        let repo = &preset.modules["repo-baseline"];
        assert_eq!(repo["approvals"], json!(approvals), "{name}");
        assert_eq!(repo["codeowners"], json!(codeowners), "{name}");
        assert_eq!(
            preset.modules["ci-baseline"]["merge_queue"],
            json!(merge_queue),
            "{name}"
        );
    }
}

#[test]
fn no_embedded_preset_holds_a_value_that_depends_on_the_repository_or_the_account() {
    // Stack, apps, commands, held-out commands, pins and names the repository or
    // the organisation owns; the review model's key, the runner provider and the
    // minutes budget belong to the account.
    let forbidden = [
        "commands",
        "workflow",
        "aggregate_check",
        "heldout",
        "heldout_command",
        "heldout_properties_command",
        "reusable_sha",
        "macos",
        "runner",
        "minutes_budget",
        "pii",
        "review_family",
        "mcp_servers",
        "spec_dir",
        "agent_app_slug",
        "unattended_prompt",
        "api_start",
        "web_start",
        "openapi",
        "asyncapi",
        "apps",
    ];
    for preset in answers_file::catalogue(None).unwrap() {
        for (id, section) in &preset.modules {
            for key in section.keys() {
                assert!(
                    !key.contains('.') && !forbidden.contains(&key.as_str()),
                    "preset {}: module {id}: `{key}` depends on the repository or the account",
                    preset.name
                );
            }
        }
    }
}

#[test]
fn a_module_both_answered_and_explained_or_a_bad_reason_is_refused() {
    let both = answers_file::Preset::parse(
        "p",
        &json!({"preset": "p", "description": "x", "modules": {"gate": {"target": "vps"}},
                "no_answers": {"gate": "because"}})
        .to_string(),
    )
    .unwrap();
    assert_eq!(
        answers_file::check(&both, &[&Gate])
            .unwrap_err()
            .to_string(),
        "Preset p: module gate has both a section and a `no_answers` reason"
    );
    for bad in [json!({"gate": ""}), json!({"gate": 1}), json!(["gate"])] {
        let error = answers_file::Preset::parse(
            "p",
            &json!({"preset": "p", "description": "x", "modules": {}, "no_answers": bad})
                .to_string(),
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "Preset p: `no_answers` must be an object of non-empty strings (module id: reason)"
        );
    }
}

#[test]
fn a_reason_is_printed_where_the_preset_contributes_nothing() {
    let explained = json!({"preset": "explained", "description": "x", "modules": {},
                           "no_answers": {"survey": "every answer is the repository's"}});
    let repo = Repo::new();
    let checkout = repo.checkout(&[explained]);
    let configured = repo
        .configure(Inputs {
            preset: Some("explained".to_owned()),
            catalogue: Some(checkout.clone()),
            ..Inputs::default()
        })
        .unwrap();
    assert_eq!(
        configured.notes,
        ["PRESET explained: no answers for survey: every answer is the repository's".to_owned()]
    );
    let listed = Command::new(env!("CARGO_BIN_EXE_brakes"))
        .args(["presets", "survey", "--source"])
        .arg(&checkout)
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&listed.stdout),
        "PRESET explained: no answers for survey: every answer is the repository's\n"
    );
}

/// A module whose schema exercises the three failures the gate names.
struct Gate;
impl Module for Gate {
    fn id(&self) -> &'static str {
        "gate"
    }
    fn version(&self) -> &'static str {
        "1.0.0"
    }
    fn questions(&self) -> Schema {
        Schema::parse(&json!([
            {"id": "target", "type": "string", "enum": ["vps", "paas", "other"], "default": "vps"},
            {"id": "proxy", "type": "boolean", "default": true, "when": "target == vps"},
            {"id": "extras", "type": "array", "items": {"type": "string", "enum": ["a", "other"]},
             "default": []},
        ]))
        .unwrap()
    }
    fn render(&self, _: &Context<'_>) -> brakes::Result<Vec<Rendered>> {
        Ok(Vec::new())
    }
}

fn preset_with(section: Value) -> answers_file::Preset {
    answers_file::Preset::parse(
        "bad",
        &json!({"preset": "bad", "description": "deliberately bad", "modules": {"gate": section}})
            .to_string(),
    )
    .unwrap()
}

#[test]
fn the_gate_accepts_a_good_section_and_ignores_modules_not_compiled() {
    let preset = answers_file::Preset::parse(
        "good",
        &json!({"preset": "good", "description": "fine",
                "modules": {"gate": {"target": "vps", "proxy": false, "extras": ["a"]},
                            "not-compiled-yet": {"anything": 1}}})
        .to_string(),
    )
    .unwrap();
    answers_file::check(&preset, &[&Gate]).unwrap();
}

#[test]
fn the_gate_names_preset_module_and_key_for_a_key_that_is_not_a_question() {
    let error = answers_file::check(&preset_with(json!({"colour": "red"})), &[&Gate]).unwrap_err();
    assert_eq!(
        error.to_string(),
        "Preset bad: module gate: key `colour` is not a question of this module"
    );
}

#[test]
fn the_gate_names_preset_module_and_key_for_a_key_whose_when_is_false() {
    let error = answers_file::check(
        &preset_with(json!({"target": "paas", "proxy": true})),
        &[&Gate],
    )
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "Preset bad: module gate: key `proxy` is never asked: its `when` is false under the preset's own answers"
    );
}

#[test]
fn the_gate_names_preset_module_and_key_for_an_other_value_scalar_or_in_an_array() {
    for (section, key) in [
        (json!({"target": "other"}), "target"),
        (json!({"extras": ["a", "other"]}), "extras"),
    ] {
        let error = answers_file::check(&preset_with(section), &[&Gate]).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!(
                "Preset bad: module gate: key `{key}` is `other`; a preset is a known configuration, not a contract"
            )
        );
    }
}

#[test]
fn the_gate_names_preset_and_module_for_a_value_the_engine_refuses() {
    let error =
        answers_file::check(&preset_with(json!({"target": "cloud"})), &[&Gate]).unwrap_err();
    assert_eq!(
        error.to_string(),
        "Preset bad: Module gate: answer `target` must be one of: vps, paas, other"
    );
}

#[test]
fn a_preset_file_whose_name_or_shape_is_wrong_is_refused() {
    let wrong_name = answers_file::Preset::parse(
        "personal-vps",
        &json!({"preset": "other-name", "description": "x", "modules": {}}).to_string(),
    )
    .unwrap_err();
    assert_eq!(
        wrong_name.to_string(),
        "Preset personal-vps: `preset` must be `personal-vps`"
    );
    let no_description =
        answers_file::Preset::parse("p", &json!({"preset": "p", "modules": {}}).to_string())
            .unwrap_err();
    assert_eq!(
        no_description.to_string(),
        "Preset p: needs a string `preset`, a string `description` and an object `modules` of objects"
    );
}

// ---- `--preset` through the driver, on a real repository.

/// The Survey-like fixture: a default, a gated question and an enum.
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
            {"id": "name", "type": "string", "default": "demo"},
            {"id": "flavour", "type": "string", "enum": ["vanilla", "chocolate"], "default": "vanilla"},
            {"id": "reason", "type": "string", "required": true, "when": "flavour == chocolate"},
            {"id": "count", "type": "integer", "default": 2},
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
    /// A checkout whose `templates/presets/` holds `presets`, outside the repository.
    fn checkout(&self, presets: &[Value]) -> PathBuf {
        let checkout = self.temp.path().join("checkout");
        let dir = checkout.join("templates/presets");
        fs::create_dir_all(&dir).unwrap();
        for preset in presets {
            let name = preset["preset"].as_str().unwrap();
            fs::write(dir.join(format!("{name}.json")), preset.to_string()).unwrap();
        }
        checkout
    }
    fn configure(&self, inputs: Inputs) -> brakes::Result<questions::Configured> {
        let profile = profile_for(&self.root).unwrap();
        let source = Source {
            documents: BTreeMap::new(),
            version: "0.1.0".to_owned(),
            revision: None,
            dirty: false,
        };
        questions::configure(
            &self.root,
            &source,
            &profile,
            &[&Survey],
            &|_| true,
            "survey",
            &inputs,
        )
    }
    fn recorded(&self) -> String {
        fs::read_to_string(self.root.join(answers::path("survey"))).unwrap()
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
}

fn demo() -> Value {
    json!({"preset": "demo", "description": "A demo preset",
           "modules": {"survey": {"flavour": "chocolate", "reason": "preset", "count": 4},
                       "elsewhere": {"x": 1}}})
}

#[test]
fn configure_with_a_preset_records_the_same_file_as_answers_with_that_section() {
    let by_preset = Repo::new();
    let checkout = by_preset.checkout(&[demo()]);
    let configured = by_preset
        .configure(Inputs {
            preset: Some("demo".to_owned()),
            catalogue: Some(checkout),
            ..Inputs::default()
        })
        .unwrap();
    apply(&by_preset.root, &configured.planned.changes).unwrap();
    assert_eq!(
        configured.provenance,
        "ANSWERS default name + preset demo count, flavour, reason"
    );
    assert!(configured.notes.is_empty());

    let by_file = Repo::new();
    let file = by_file.temp.path().join("section.json");
    fs::write(&file, demo()["modules"]["survey"].to_string()).unwrap();
    let configured = by_file
        .configure(Inputs {
            files: vec![file],
            ..Inputs::default()
        })
        .unwrap();
    apply(&by_file.root, &configured.planned.changes).unwrap();
    assert_eq!(by_preset.recorded(), by_file.recorded());
    let digest = |repo: &Repo| -> Value {
        let lock: Value =
            serde_json::from_str(&fs::read_to_string(repo.root.join(LOCK)).unwrap()).unwrap();
        lock["modules"]["survey"]["answers_digest"].clone()
    };
    assert_eq!(digest(&by_preset), digest(&by_file));
}

#[test]
fn a_preset_sits_below_answers_files_and_set() {
    let repo = Repo::new();
    let checkout = repo.checkout(&[demo()]);
    let file = repo.temp.path().join("a.json");
    fs::write(&file, json!({"count": 9}).to_string()).unwrap();
    let configured = repo
        .configure(Inputs {
            files: vec![file.clone()],
            sets: vec!["reason=set".to_owned()],
            preset: Some("demo".to_owned()),
            catalogue: Some(checkout),
            ..Inputs::default()
        })
        .unwrap();
    apply(&repo.root, &configured.planned.changes).unwrap();
    let recorded: Value = serde_json::from_str(&repo.recorded()).unwrap();
    assert_eq!(
        recorded["answers"],
        json!({"name": "demo", "flavour": "chocolate", "reason": "set", "count": 9})
    );
    assert_eq!(
        configured.provenance,
        format!(
            "ANSWERS default name + preset demo flavour + file {} count + --set reason",
            file.display()
        )
    );
}

#[test]
fn a_preset_without_a_section_for_the_module_contributes_nothing_and_says_so() {
    let repo = Repo::new();
    let checkout =
        repo.checkout(&[json!({"preset": "empty", "description": "none", "modules": {}})]);
    let configured = repo
        .configure(Inputs {
            preset: Some("empty".to_owned()),
            catalogue: Some(checkout),
            ..Inputs::default()
        })
        .unwrap();
    assert_eq!(
        configured.provenance,
        "ANSWERS default count, flavour, name"
    );
    assert_eq!(
        configured.notes,
        ["PRESET empty: no answers for survey".to_owned()]
    );
}

#[test]
fn an_unknown_preset_is_refused_listing_the_available_names() {
    let repo = Repo::new();
    let error = repo
        .configure(Inputs {
            preset: Some("personal-vsp".to_owned()),
            ..Inputs::default()
        })
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "Unknown preset `personal-vsp`; available: enterprise-k8s, personal-paas, personal-vps, team-cloud"
    );
    assert!(!repo.root.join(answers::path("survey")).exists());
}

// ---- The binary: `configure --preset` and `presets`.

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "lists setup-core or its guides; product-boundary T7a"
)]
#[test]
fn cli_configure_with_a_preset_plans_without_asking_and_prints_the_preset_line() {
    let repo = Repo::new();
    assert!(
        repo.cli(&["install", "<repo>", "--new-personal", "--apply"])
            .status
            .success()
    );
    let result = repo.cli(&[
        "configure",
        "<repo>",
        "setup-core",
        "--preset",
        "personal-vps",
    ]);
    assert!(result.status.success(), "{result:?}");
    let out = String::from_utf8_lossy(&result.stdout);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[0], "ANSWERS none", "{out}");
    assert_eq!(
        lines[1], "PRESET personal-vps: no answers for setup-core",
        "{out}"
    );
    assert!(
        lines.contains(
            &format!("PLAN {} [answers:setup-core]", answers::path("setup-core")).as_str()
        ),
        "{out}"
    );
    assert_eq!(
        lines.last(),
        Some(&"Plan only; no writes. Review before using --apply.")
    );
    assert!(!repo.root.join(answers::path("setup-core")).exists());

    let unknown = repo.cli(&["configure", "<repo>", "setup-core", "--preset", "nope"]);
    assert_eq!(unknown.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&unknown.stderr).trim(),
        "REFUSED: Unknown preset `nope`; available: enterprise-k8s, personal-paas, personal-vps, team-cloud"
    );
    let doctor = repo.cli(&["doctor", "<repo>", "--preset", "personal-vps"]);
    assert_eq!(doctor.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&doctor.stderr).trim(),
        "REFUSED: --preset and --answers are only available with configure and install"
    );
}

#[test]
fn cli_presets_lists_the_four_names_with_their_descriptions() {
    let result = Command::new(env!("CARGO_BIN_EXE_brakes"))
        .arg("presets")
        .output()
        .unwrap();
    assert!(result.status.success(), "{result:?}");
    let out = String::from_utf8_lossy(&result.stdout);
    let catalogue = answers_file::catalogue(None).unwrap();
    let expected: Vec<String> = catalogue
        .iter()
        .map(|p| format!("{}: {}", p.name, p.description))
        .collect();
    assert_eq!(out.lines().collect::<Vec<_>>(), expected);
    assert_eq!(expected.len(), 4);
}

#[test]
fn cli_presets_for_a_module_prints_each_section_or_no_answers() {
    let repo = Repo::new();
    let checkout = repo.checkout(&[
        demo(),
        json!({"preset": "empty", "description": "none", "modules": {}}),
    ]);
    let result = Command::new(env!("CARGO_BIN_EXE_brakes"))
        .args(["presets", "survey", "--source"])
        .arg(&checkout)
        .output()
        .unwrap();
    assert!(result.status.success(), "{result:?}");
    assert_eq!(
        String::from_utf8_lossy(&result.stdout),
        "PRESET demo: {\"count\":4,\"flavour\":\"chocolate\",\"reason\":\"preset\"}\n\
         PRESET empty: no answers for survey\n"
    );
    let embedded = Command::new(env!("CARGO_BIN_EXE_brakes"))
        .args(["presets", "setup-core"])
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&embedded.stdout),
        NAMES
            .iter()
            .map(|n| format!("PRESET {n}: no answers for setup-core\n"))
            .collect::<String>()
    );
    let extra = Command::new(env!("CARGO_BIN_EXE_brakes"))
        .args(["presets", "a", "b"])
        .output()
        .unwrap();
    assert_eq!(extra.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&extra.stderr).starts_with("REFUSED: Usage: brakes presets"),
        "{extra:?}"
    );
}
