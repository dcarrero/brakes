//! The `--answers <file.json>` formats (SPEC-questions.md, Data model). Two
//! shapes, detected by key: the engine's recorded shape `{module, version,
//! answers}` (a recorded file of one repository is an answers file for another)
//! and the multi-module shape `{preset?, description?, modules: {<id>: {…}}}`,
//! of which the module's section is taken and the rest ignored. A bare object of
//! answers, the form engine T4 accepted, stays accepted. Nothing here validates
//! an answer: the engine refuses an unknown key or a bad value by question id.
//!
//! A preset is a multi-module answers file with a name, shipped in the binary from
//! `templates/presets/<name>.json` or read from a checkout's catalogue under
//! `--source` (owner, 2026-10-28). There is no preset code path beyond loading it:
//! the engine validates its section like any other answers. `check` is the CI
//! gate every catalogue preset passes against every compiled module it names.
use crate::{
    Result,
    engine::{Answers, Module, answers::DEFAULT_TIER},
    refuse,
};
use serde_json::{Map, Value};
use std::{collections::BTreeMap, path::Path};

/// The embedded catalogue, by name; `presets` lists it and `--preset` reads it.
pub const PRESETS: &[(&str, &str)] = &[
    (
        "enterprise-k8s",
        include_str!("../../../../templates/presets/enterprise-k8s.json"),
    ),
    (
        "personal-paas",
        include_str!("../../../../templates/presets/personal-paas.json"),
    ),
    (
        "personal-vps",
        include_str!("../../../../templates/presets/personal-vps.json"),
    ),
    (
        "team-cloud",
        include_str!("../../../../templates/presets/team-cloud.json"),
    ),
];

/// One preset: `{preset, description, modules: {<id>: {…}}, no_answers?: {<id>:
/// "<reason>"}}`, named like its file. `no_answers` records why the preset leaves
/// a module to its defaults and the repository (#1181).
#[derive(Clone, Debug, PartialEq)]
pub struct Preset {
    pub name: String,
    pub description: String,
    pub modules: BTreeMap<String, Answers>,
    pub no_answers: BTreeMap<String, String>,
}

impl Preset {
    /// Parses the file of the preset called `name`; `preset` must repeat the name.
    pub fn parse(name: &str, text: &str) -> Result<Preset> {
        let value: Value = serde_json::from_str(text).unwrap_or(Value::Null);
        let modules = value["modules"].as_object().and_then(|modules| {
            modules
                .iter()
                .map(|(id, section)| {
                    let answers = section.as_object()?;
                    Some((id.clone(), answers.clone().into_iter().collect()))
                })
                .collect::<Option<BTreeMap<String, Answers>>>()
        });
        let (Some(named), Some(description), Some(modules)) = (
            value["preset"].as_str(),
            value["description"].as_str(),
            modules,
        ) else {
            return refuse(format!(
                "Preset {name}: needs a string `preset`, a string `description` and an object `modules` of objects"
            ));
        };
        if named != name {
            return refuse(format!("Preset {name}: `preset` must be `{name}`"));
        }
        let no_answers = match &value["no_answers"] {
            Value::Null => Some(BTreeMap::new()),
            Value::Object(reasons) => reasons
                .iter()
                .map(|(id, reason)| {
                    let reason = reason.as_str().filter(|r| !r.is_empty())?;
                    Some((id.clone(), reason.to_owned()))
                })
                .collect(),
            _ => None,
        };
        let Some(no_answers) = no_answers else {
            return refuse(format!(
                "Preset {name}: `no_answers` must be an object of non-empty strings (module id: reason)"
            ));
        };
        Ok(Preset {
            name: name.to_owned(),
            description: description.to_owned(),
            modules,
            no_answers,
        })
    }

    /// The note printed where the preset has no section for `module`, with its
    /// recorded reason when there is one.
    pub fn absence(&self, module: &str) -> String {
        match self.no_answers.get(module) {
            Some(reason) => format!("PRESET {}: no answers for {module}: {reason}", self.name),
            None => format!("PRESET {}: no answers for {module}", self.name),
        }
    }
}

/// The catalogue sorted by name: the embedded one, or every
/// `<checkout>/templates/presets/*.json` when a checkout is given.
pub fn catalogue(checkout: Option<&Path>) -> Result<Vec<Preset>> {
    let Some(checkout) = checkout else {
        return PRESETS
            .iter()
            .map(|(name, text)| Preset::parse(name, text))
            .collect();
    };
    let dir = checkout.join("templates/presets");
    let mut presets = Vec::new();
    if dir.is_dir() {
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.extension().is_some_and(|e| e == "json")
                && let Some(name) = path.file_stem().and_then(|s| s.to_str())
            {
                presets.push(Preset::parse(name, &std::fs::read_to_string(&path)?)?);
            }
        }
    }
    presets.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(presets)
}

/// The preset called `name`, refused with the available names when unknown.
pub fn preset(name: &str, checkout: Option<&Path>) -> Result<Preset> {
    let presets = catalogue(checkout)?;
    let names: Vec<&str> = presets.iter().map(|p| p.name.as_str()).collect();
    let available = if names.is_empty() {
        "none".to_owned()
    } else {
        names.join(", ")
    };
    match presets.iter().find(|p| p.name == name) {
        Some(preset) => Ok(preset.clone()),
        None => refuse(format!("Unknown preset `{name}`; available: {available}")),
    }
}

/// The CI gate (SPEC-questions.md, Testing Strategy): for every module of
/// `modules` the preset has a section for, every key is a question, no value is
/// `other`, the engine accepts the section, no key is gated out by a `when`
/// under the preset's own answers and the module has no `no_answers` reason too. Sections for modules not compiled yet are not
/// checked; each module's slice adds its section and the gate grows with it.
pub fn check(preset: &Preset, modules: &[&dyn Module]) -> Result<()> {
    let name = &preset.name;
    for module in modules {
        let id = module.id();
        let Some(section) = preset.modules.get(id) else {
            continue;
        };
        if preset.no_answers.contains_key(id) {
            return refuse(format!(
                "Preset {name}: module {id} has both a section and a `no_answers` reason"
            ));
        }
        let schema = module.questions();
        for (key, value) in section {
            if schema.question(key).is_none() {
                return refuse(format!(
                    "Preset {name}: module {id}: key `{key}` is not a question of this module"
                ));
            }
            let is_other = |v: &Value| v.as_str() == Some("other");
            if is_other(value) || value.as_array().is_some_and(|a| a.iter().any(is_other)) {
                return refuse(format!(
                    "Preset {name}: module {id}: key `{key}` is `other`; a preset is a known configuration, not a contract"
                ));
            }
        }
        let resolved = schema
            .validate(id, section, DEFAULT_TIER)
            .or_else(|error| refuse(format!("Preset {name}: {error}")))?;
        if let Some(key) = section.keys().find(|key| !resolved.contains_key(*key)) {
            return refuse(format!(
                "Preset {name}: module {id}: key `{key}` is never asked: its `when` is false under the preset's own answers"
            ));
        }
    }
    Ok(())
}

/// The JSON object `file` holds, refused naming the file otherwise.
fn read_object(file: &Path) -> Result<Map<String, Value>> {
    let path = file.display();
    let Ok(text) = std::fs::read_to_string(file) else {
        return refuse(format!("Answers file cannot be read: {path}"));
    };
    let Ok(value) = serde_json::from_str::<Value>(&text) else {
        return refuse(format!("Answers file is not valid JSON: {path}"));
    };
    match value {
        Value::Object(object) => Ok(object),
        _ => refuse(format!("Answers file must be a JSON object: {path}")),
    }
}

/// Every section of the multi-module answers `file`, by module id: what
/// `install --answers` takes. The single-module shape and a bare object name one
/// module at most, so `install` refuses them naming the shape it expects.
pub fn sections(file: &Path) -> Result<BTreeMap<String, Answers>> {
    let object = read_object(file)?;
    let (None, Some(modules)) = (object.get("answers"), object.get("modules")) else {
        return refuse(format!(
            "install --answers takes the multi-module shape {{\"modules\": {{\"<module-id>\": {{...}}}}}}: {}",
            file.display()
        ));
    };
    object_under(modules, "modules", file)?
        .iter()
        .map(|(id, section)| match section.as_object() {
            Some(section) => Ok((id.clone(), section.clone().into_iter().collect())),
            None => refuse(format!(
                "Answers file section for module `{id}` must be an object: {}",
                file.display()
            )),
        })
        .collect()
}

/// The answers `file` holds for `module`, as a patch for `engine::configure`.
pub fn load(file: &Path, module: &str) -> Result<Answers> {
    let path = file.display();
    let object = &read_object(file)?;
    let section = match (object.get("answers"), object.get("modules")) {
        (Some(answers), _) => {
            if let Some(named) = object.get("module").and_then(Value::as_str)
                && named != module
            {
                return refuse(format!(
                    "Answers file names module `{named}`, not `{module}`: {path}"
                ));
            }
            object_under(answers, "answers", file)?
        }
        (None, Some(modules)) => {
            let Some(section) = object_under(modules, "modules", file)?.get(module) else {
                return refuse(format!(
                    "Answers file has no section for module `{module}`: {path}"
                ));
            };
            let Some(section) = section.as_object() else {
                return refuse(format!(
                    "Answers file section for module `{module}` must be an object: {path}"
                ));
            };
            section
        }
        (None, None) => object,
    };
    Ok(section
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect())
}

fn object_under<'a>(value: &'a Value, key: &str, file: &Path) -> Result<&'a Map<String, Value>> {
    value.as_object().map_or_else(
        || {
            refuse(format!(
                "Answers file key `{key}` must be an object: {}",
                file.display()
            ))
        },
        Ok,
    )
}
