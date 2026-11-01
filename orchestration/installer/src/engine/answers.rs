//! Question schema subset, its validator, `when` and the recorded answers file
//! `.agent-setup/modules/<id>.json` (SPEC-engine.md, recorded answers).
//!
//! The subset is hand-written (tasks/plan.md): questions typed `string`,
//! `boolean`, `integer`, enum (`string` + `enum`), array of enum and array of
//! string, with `default` (a scalar or a per-profile map resolved here to one
//! scalar), `description`, `required`, `when` (a predicate on an earlier
//! answer), `secret` (refused at load) and the validators `minLength`,
//! `maxLength`, `minimum`, `maximum`, `minItems`, `maxItems`. Keys prefixed
//! `x-` are extensions the drivers read (`questions::hints`); this module keeps
//! them on the question untouched and ignores them otherwise. A question id with
//! a `*` segment is a pattern (`apps.*.port`): it answers every key whose
//! segment there is an identifier, typed and validated here; its defaults,
//! `required` and `when` belong to the module that reads it (SPEC-stack-packs.md,
//! the flat `apps.<id>.<field>` namespace).
use crate::{Result, read, refuse};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, path::Path, str::FromStr};

/// Validated answers of one module, by question id.
pub type Answers = BTreeMap<String, Value>;
pub const ANSWERS_DIR: &str = ".agent-setup/modules";
/// The maturity profile per-profile defaults are resolved with until the
/// auditor derives one: personal repositories are P1 (SPEC-repo-baseline.md).
pub const DEFAULT_TIER: &str = "P1";
/// The maturity profiles a module may be installed for (`install --profile`).
pub const TIERS: [&str; 3] = ["P1", "P2", "P3"];

/// Refuses a maturity profile that is not one of `TIERS`.
pub fn check_tier(tier: &str) -> Result<()> {
    if TIERS.contains(&tier) {
        Ok(())
    } else {
        refuse(format!("Unknown profile: {tier}; use P1, P2 or P3"))
    }
}

/// The recorded answers file of a module, relative to the repository root.
pub fn path(module: &str) -> String {
    format!("{ANSWERS_DIR}/{module}.json")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    String,
    Boolean,
    Integer,
    Enum(Vec<String>),
    ArrayOfEnum(Vec<String>),
    ArrayOfString,
}

/// A predicate on one earlier answer: `id`, `!id`, `id == literal`, `id != literal`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum When {
    Truthy(String),
    Falsy(String),
    Eq(String, String),
    Ne(String, String),
}

impl When {
    /// The question this predicate reads.
    pub fn reference(&self) -> &str {
        match self {
            When::Truthy(id) | When::Falsy(id) | When::Eq(id, _) | When::Ne(id, _) => id,
        }
    }

    /// True when the predicate holds over `answers`; an unanswered reference never holds.
    pub fn holds(&self, answers: &Answers) -> bool {
        let Some(value) = answers.get(self.reference()) else {
            return false;
        };
        match self {
            When::Truthy(_) => value == &Value::Bool(true),
            When::Falsy(_) => value == &Value::Bool(false),
            When::Eq(_, literal) => literal_matches(value, literal),
            When::Ne(_, literal) => !literal_matches(value, literal),
        }
    }
}

fn literal_matches(value: &Value, literal: &str) -> bool {
    match value {
        Value::String(s) => s == literal,
        Value::Bool(b) => b.to_string() == literal,
        Value::Number(n) => n.to_string() == literal,
        _ => false,
    }
}

fn identifier(text: &str) -> Option<String> {
    let text = text.trim();
    let valid = !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    valid.then(|| text.to_owned())
}

impl FromStr for When {
    type Err = String;
    fn from_str(text: &str) -> std::result::Result<Self, Self::Err> {
        let invalid = || text.to_owned();
        if let Some((id, literal)) = text.split_once("==") {
            let id = identifier(id).ok_or_else(invalid)?;
            return Ok(When::Eq(id, literal.trim().to_owned()));
        }
        if let Some((id, literal)) = text.split_once("!=") {
            let id = identifier(id).ok_or_else(invalid)?;
            return Ok(When::Ne(id, literal.trim().to_owned()));
        }
        if let Some(id) = text.trim().strip_prefix('!') {
            return Ok(When::Falsy(identifier(id).ok_or_else(invalid)?));
        }
        Ok(When::Truthy(identifier(text).ok_or_else(invalid)?))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Question {
    pub id: String,
    pub kind: Kind,
    pub description: String,
    /// A scalar (or array) default, or a per-profile map `{"P1": …, "P2": …}`.
    pub default: Option<Value>,
    pub required: bool,
    pub when: Option<When>,
    pub secret: bool,
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
    pub minimum: Option<i64>,
    pub maximum: Option<i64>,
    pub min_items: Option<usize>,
    pub max_items: Option<usize>,
    /// The `x-*` keys as written, by key; the drivers read them, the engine does not.
    pub extensions: BTreeMap<String, Value>,
}

impl Question {
    pub fn new(id: &str, kind: Kind) -> Self {
        Self {
            id: id.to_owned(),
            kind,
            description: String::new(),
            default: None,
            required: false,
            when: None,
            secret: false,
            min_length: None,
            max_length: None,
            minimum: None,
            maximum: None,
            min_items: None,
            max_items: None,
            extensions: BTreeMap::new(),
        }
    }

    /// True when the id has a `*` segment and so answers a family of keys.
    pub fn is_pattern(&self) -> bool {
        self.id.split('.').any(|segment| segment == "*")
    }

    /// True when `key` is this question's id or, for a pattern, an instance of it.
    pub fn answers(&self, key: &str) -> bool {
        if !self.is_pattern() {
            return self.id == key;
        }
        let pattern: Vec<&str> = self.id.split('.').collect();
        let segments: Vec<&str> = key.split('.').collect();
        pattern.len() == segments.len()
            && pattern.iter().zip(&segments).all(|(p, s)| {
                if *p == "*" {
                    identifier(s).as_deref() == Some(*s)
                } else {
                    p == s
                }
            })
    }

    /// The default for one maturity profile: a per-profile map yields its entry, a
    /// scalar is the default for every profile.
    pub fn default_for(&self, tier: &str) -> Option<Value> {
        match &self.default {
            Some(Value::Object(by_tier)) => by_tier.get(tier).cloned(),
            other => other.clone(),
        }
    }

    /// Validates one value against this question's kind and validators.
    fn accept(&self, value: &Value) -> std::result::Result<(), String> {
        match &self.kind {
            Kind::String => {
                let text = value.as_str().ok_or("must be a string")?;
                self.accept_length(text)
            }
            Kind::Enum(options) => {
                let text = value.as_str().ok_or("must be a string")?;
                accept_option(text, options)
            }
            Kind::Boolean => value
                .as_bool()
                .map(|_| ())
                .ok_or("must be a boolean".into()),
            Kind::Integer => {
                let number = value.as_i64().ok_or("must be an integer")?;
                if let Some(min) = self.minimum
                    && number < min
                {
                    return Err(format!("must be at least {min}"));
                }
                if let Some(max) = self.maximum
                    && number > max
                {
                    return Err(format!("must be at most {max}"));
                }
                Ok(())
            }
            Kind::ArrayOfEnum(_) | Kind::ArrayOfString => {
                let items = value.as_array().ok_or("must be an array")?;
                bounded(items.len(), self.min_items, self.max_items, "item")?;
                for (index, item) in items.iter().enumerate() {
                    let text = item
                        .as_str()
                        .ok_or_else(|| format!("item {} must be a string", index + 1))?;
                    let result = match &self.kind {
                        Kind::ArrayOfEnum(options) => accept_option(text, options),
                        _ => self.accept_length(text),
                    };
                    result.map_err(|rule| format!("item {} {rule}", index + 1))?;
                }
                Ok(())
            }
        }
    }

    fn accept_length(&self, text: &str) -> std::result::Result<(), String> {
        bounded(
            text.chars().count(),
            self.min_length,
            self.max_length,
            "character",
        )
    }
}

fn accept_option(text: &str, options: &[String]) -> std::result::Result<(), String> {
    if options.iter().any(|option| option == text) {
        Ok(())
    } else {
        Err(format!("must be one of: {}", options.join(", ")))
    }
}

/// `minLength`/`maxLength` and `minItems`/`maxItems` share one rule wording.
fn bounded(
    count: usize,
    min: Option<usize>,
    max: Option<usize>,
    unit: &str,
) -> std::result::Result<(), String> {
    let plural = |n: usize| format!("{n} {unit}{}", if n == 1 { "" } else { "s" });
    if let Some(min) = min
        && count < min
    {
        return Err(format!("must have at least {}", plural(min)));
    }
    if let Some(max) = max
        && count > max
    {
        return Err(format!("must have at most {}", plural(max)));
    }
    Ok(())
}

/// A module's questions, in the order they are asked; `when` reads earlier ones.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Schema {
    pub questions: Vec<Question>,
}

const QUESTION_KEYS: &[&str] = &[
    "id",
    "type",
    "enum",
    "items",
    "description",
    "default",
    "required",
    "when",
    "secret",
    "minLength",
    "maxLength",
    "minimum",
    "maximum",
    "minItems",
    "maxItems",
];

impl Schema {
    /// Parses the JSON array form the module specs write, one object per question.
    pub fn parse(value: &Value) -> Result<Schema> {
        let Some(items) = value.as_array() else {
            return refuse("Question schema must be an array of questions");
        };
        let questions = items.iter().map(parse_question).collect::<Result<_>>()?;
        Ok(Schema { questions })
    }

    /// The schema errors a module refuses with at load time: a secret question, a
    /// `when` that does not read an earlier question, a duplicated id.
    pub fn check(&self, module: &str) -> Result<()> {
        let mut seen: Vec<&str> = Vec::new();
        for question in &self.questions {
            let id = question.id.as_str();
            if seen.contains(&id) {
                return refuse(format!(
                    "Module {module}: question `{id}` is declared twice"
                ));
            }
            if question.secret {
                return refuse(format!(
                    "Module {module}: question `{id}` is marked secret; secrets are probed by name, never recorded"
                ));
            }
            if question.is_pattern()
                && (question.default.is_some() || question.required || question.when.is_some())
            {
                return refuse(format!(
                    "Module {module}: question `{id}` is a pattern; its default, required and when belong to the module"
                ));
            }
            if let Some(reference) = question.when.as_ref().map(When::reference)
                && !seen.contains(&reference)
            {
                return refuse(format!(
                    "Module {module}: question `{id}` has a `when` on `{reference}`, which is not an earlier question"
                ));
            }
            seen.push(id);
        }
        Ok(())
    }

    /// The question that answers `key`: its own id first, then a pattern.
    pub fn question(&self, key: &str) -> Option<&Question> {
        self.questions
            .iter()
            .find(|q| q.id == key)
            .or_else(|| self.questions.iter().find(|q| q.answers(key)))
    }

    /// True when `question` applies given the answers resolved so far.
    pub fn when_holds(&self, question: &Question, answers: &Answers) -> bool {
        question
            .when
            .as_ref()
            .is_none_or(|when| when.holds(answers))
    }

    /// Resolves `raw` into the module's answers: unknown keys refuse, gated-out
    /// questions are dropped, defaults fill the rest (per-profile ones by `tier`),
    /// a required question without a value refuses, every value is validated.
    pub fn validate(&self, module: &str, raw: &Answers, tier: &str) -> Result<Answers> {
        for key in raw.keys() {
            if self.question(key).is_none() {
                return refuse(format!(
                    "Module {module}: answer `{key}` is not a question of this module"
                ));
            }
        }
        let mut resolved = Answers::new();
        for question in &self.questions {
            if question.is_pattern() {
                // A key goes to the question `question()` names for it: an exact id wins.
                let owned = |key: &&String| self.question(key).is_some_and(|q| q.id == question.id);
                for (key, value) in raw.iter().filter(|(key, _)| owned(key)) {
                    if let Err(rule) = question.accept(value) {
                        return refuse(format!("Module {module}: answer `{key}` {rule}"));
                    }
                    resolved.insert(key.clone(), value.clone());
                }
                continue;
            }
            if !self.when_holds(question, &resolved) {
                continue;
            }
            let value = raw
                .get(&question.id)
                .cloned()
                .or_else(|| question.default_for(tier));
            let Some(value) = value else {
                if question.required {
                    return refuse(format!(
                        "Module {module}: answer `{}` is required and has no value",
                        question.id
                    ));
                }
                continue;
            };
            if let Err(rule) = question.accept(&value) {
                return refuse(format!("Module {module}: answer `{}` {rule}", question.id));
            }
            resolved.insert(question.id.clone(), value);
        }
        Ok(resolved)
    }
}

fn parse_question(value: &Value) -> Result<Question> {
    let Some(object) = value.as_object() else {
        return refuse("Question schema: every question needs a string `id`");
    };
    let Some(id) = object.get("id").and_then(Value::as_str) else {
        return refuse("Question schema: every question needs a string `id`");
    };
    for key in object.keys() {
        if !QUESTION_KEYS.contains(&key.as_str()) && !key.starts_with("x-") {
            return refuse(format!(
                "Question schema: `{id}` uses unsupported validator `{key}`"
            ));
        }
    }
    let options = |node: &Value| -> Option<Vec<String>> {
        node.get("enum")?.as_array().map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
    };
    let type_name = value["type"].as_str().unwrap_or("");
    let kind = match type_name {
        "string" => options(value).map_or(Kind::String, Kind::Enum),
        "boolean" => Kind::Boolean,
        "integer" => Kind::Integer,
        "array" if value["items"]["type"].as_str() == Some("string") => {
            options(&value["items"]).map_or(Kind::ArrayOfString, Kind::ArrayOfEnum)
        }
        "array" => {
            return refuse(format!(
                "Question schema: `{id}` has unsupported array items; only strings and enums"
            ));
        }
        other => {
            return refuse(format!(
                "Question schema: `{id}` has unsupported type `{other}`"
            ));
        }
    };
    let when = match value.get("when") {
        None => None,
        Some(node) => {
            let text = node.as_str().unwrap_or("");
            Some(text.parse::<When>().or_else(|_| {
                refuse(format!(
                    "Question schema: `{id}` has an invalid `when`: {text}"
                ))
            })?)
        }
    };
    let size = |key: &str| value[key].as_u64().map(|n| n as usize);
    Ok(Question {
        id: id.to_owned(),
        kind,
        description: value["description"].as_str().unwrap_or("").to_owned(),
        default: value.get("default").cloned(),
        required: value["required"].as_bool().unwrap_or(false),
        when,
        secret: value["secret"].as_bool().unwrap_or(false),
        min_length: size("minLength"),
        max_length: size("maxLength"),
        minimum: value["minimum"].as_i64(),
        maximum: value["maximum"].as_i64(),
        min_items: size("minItems"),
        max_items: size("maxItems"),
        extensions: object
            .iter()
            .filter(|(key, _)| key.starts_with("x-"))
            .map(|(key, node)| (key.clone(), node.clone()))
            .collect(),
    })
}

/// `.agent-setup/modules/<id>.json`: the answers a module was configured with.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AnswersFile {
    pub module: String,
    pub version: String,
    /// The maturity profile the module is installed for (`install --profile`);
    /// absent means `DEFAULT_TIER`, so files written before it parse unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    pub answers: Answers,
}

impl AnswersFile {
    /// Parses a recorded file, refusing one that names another module.
    pub fn parse(module: &str, raw: &str) -> Result<AnswersFile> {
        let file: AnswersFile = match serde_json::from_str(raw) {
            Ok(file) => file,
            Err(_) => {
                return refuse(format!(
                    "Module {module}: invalid answers file: {}",
                    path(module)
                ));
            }
        };
        if file.module != module {
            return refuse(format!(
                "Module {module}: answers file names module `{}`: {}",
                file.module,
                path(module)
            ));
        }
        if let Some(profile) = file.profile.as_deref().filter(|p| !TIERS.contains(p)) {
            return refuse(format!(
                "Module {module}: answers file records unknown profile `{profile}`: {}",
                path(module)
            ));
        }
        Ok(file)
    }

    /// The maturity profile per-profile defaults resolve with.
    pub fn tier(&self) -> &str {
        self.profile.as_deref().unwrap_or(DEFAULT_TIER)
    }

    /// Deterministic text: struct field order, sorted answers, trailing newline.
    pub fn to_json_string(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)? + "\n")
    }
}

/// The recorded answers file of `module`, parsed; `None` when the module has none.
pub fn recorded(root: &Path, module: &str) -> Result<Option<AnswersFile>> {
    read(root, &path(module))?
        .map(|raw| AnswersFile::parse(module, &raw))
        .transpose()
}

/// One `--set key=value`, the value parsed by the question's type: `true`/`false`
/// for booleans, a number for integers, a comma-separated list for arrays. A
/// value that does not parse, or a key with no question, stays a string so the
/// validator names the rule it breaks.
pub fn parse_set(schema: &Schema, arg: &str) -> Result<(String, Value)> {
    let Some((key, raw)) = arg.split_once('=') else {
        return refuse(format!("--set needs key=value: {arg}"));
    };
    let text = Value::String(raw.to_owned());
    let value = match schema.question(key).map(|q| &q.kind) {
        Some(Kind::Boolean) => match raw {
            "true" => Value::Bool(true),
            "false" => Value::Bool(false),
            _ => text,
        },
        Some(Kind::Integer) => raw.parse::<i64>().map_or(text, Value::from),
        Some(Kind::ArrayOfEnum(_) | Kind::ArrayOfString) => Value::Array(
            raw.split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(|item| Value::String(item.to_owned()))
                .collect(),
        ),
        _ => text,
    };
    Ok((key.to_owned(), value))
}
