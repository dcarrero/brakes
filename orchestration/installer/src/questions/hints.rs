//! The question hints: the `x-*` extensions the engine keeps on a question and
//! ignores (SPEC-questions.md, schema extensions). This is the one rendering
//! model the TUI and the MCP server share: `ordered` gives the questions in the
//! order they are asked, with group headers, labels, help and the
//! `x-plan-dependency` note; `lint` returns what a module got wrong, and `check`
//! refuses it at load naming the module and the question.
//!
//! Known extensions:
//! - `x-ui`: `{label, help, group, order}`; `label` replaces the id as the
//!   question line, `help` prints on `?` (the description otherwise), `group`
//!   prints a header once when its first question is reached, `order` sorts
//!   within the module (ties and unordered questions keep schema order,
//!   unordered ones after the ordered ones).
//! - `x-plan-dependency`: `{feature, values}` or the bare feature name; says
//!   which enum values need a host plan feature. Rendered as a note, never
//!   checked here.
//! - `x-configure-new`: `{contract}`; allowed only on an enum that lists the
//!   literal `other`, and required when one does.
use crate::engine::answers::{Kind, Question, Schema, When};
use crate::{Result, refuse};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;

/// The reserved enum value that opens the "configure new" contract.
pub const OTHER: &str = "other";
/// The extensions this module reads, sorted; any other `x-` key is a finding.
pub const KNOWN: &[&str] = &["x-configure-new", "x-plan-dependency", "x-ui"];

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ui {
    pub label: Option<String>,
    pub help: Option<String>,
    pub group: Option<String>,
    pub order: Option<i64>,
}

/// Which enum values need a host plan feature; empty `values` means every value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanDependency {
    pub feature: String,
    pub values: Vec<String>,
}

impl PlanDependency {
    /// True when choosing `value` needs the feature.
    pub fn applies_to(&self, value: &str) -> bool {
        self.values.is_empty() || self.values.iter().any(|v| v == value)
    }
}

/// Marks the enum value `other` as the entry of the "configure new" contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigureNew {
    pub contract: String,
}

/// The typed hints of one question. Parsing never fails: an unknown key lands in
/// `unknown`, a wrong shape in `malformed` (with the hint dropped), and the lint
/// reports both.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Hints {
    pub ui: Ui,
    pub plan_dependency: Option<PlanDependency>,
    pub configure_new: Option<ConfigureNew>,
    pub unknown: Vec<String>,
    pub malformed: Vec<String>,
}

impl Hints {
    pub fn of(question: &Question) -> Hints {
        let mut hints = Hints::default();
        for (key, node) in &question.extensions {
            match key.as_str() {
                "x-ui" => hints.ui = parse_ui(node, &mut hints.malformed),
                "x-plan-dependency" => {
                    hints.plan_dependency = parse_plan_dependency(node, &mut hints.malformed);
                }
                "x-configure-new" => {
                    hints.configure_new = parse_configure_new(node, &mut hints.malformed);
                }
                _ => hints.unknown.push(key.clone()),
            }
        }
        hints
    }
}

fn parse_ui(node: &Value, malformed: &mut Vec<String>) -> Ui {
    let Some(object) = node.as_object() else {
        malformed.push("`x-ui` must be an object".to_owned());
        return Ui::default();
    };
    let mut text = |key: &str| -> Option<String> {
        match object.get(key) {
            None => None,
            Some(Value::String(s)) if !s.trim().is_empty() => Some(s.clone()),
            Some(_) => {
                malformed.push(format!("`x-ui.{key}` must be a non-empty string"));
                None
            }
        }
    };
    let label = text("label");
    let help = text("help");
    let group = text("group");
    let order = match object.get("order") {
        None => None,
        Some(Value::Number(n)) if n.as_i64().is_some() => n.as_i64(),
        Some(_) => {
            malformed.push("`x-ui.order` must be an integer".to_owned());
            None
        }
    };
    Ui {
        label,
        help,
        group,
        order,
    }
}

fn parse_plan_dependency(node: &Value, malformed: &mut Vec<String>) -> Option<PlanDependency> {
    const SHAPE: &str = "`x-plan-dependency` must be a string or an object with a string `feature`";
    match node {
        Value::String(feature) if !feature.trim().is_empty() => Some(PlanDependency {
            feature: feature.clone(),
            values: Vec::new(),
        }),
        Value::Object(object) => {
            let Some(feature) = object
                .get("feature")
                .and_then(Value::as_str)
                .filter(|f| !f.trim().is_empty())
            else {
                malformed.push(SHAPE.to_owned());
                return None;
            };
            let values = match object.get("values") {
                None => Some(Vec::new()),
                Some(Value::Array(items)) => items
                    .iter()
                    .map(|item| item.as_str().map(str::to_owned))
                    .collect::<Option<Vec<_>>>(),
                Some(_) => None,
            };
            let Some(values) = values else {
                malformed.push("`x-plan-dependency.values` must be an array of strings".to_owned());
                return None;
            };
            Some(PlanDependency {
                feature: feature.to_owned(),
                values,
            })
        }
        _ => {
            malformed.push(SHAPE.to_owned());
            None
        }
    }
}

fn parse_configure_new(node: &Value, malformed: &mut Vec<String>) -> Option<ConfigureNew> {
    match node
        .as_object()
        .and_then(|o| o.get("contract"))
        .and_then(Value::as_str)
        .filter(|c| !c.trim().is_empty())
    {
        Some(contract) => Some(ConfigureNew {
            contract: contract.to_owned(),
        }),
        None => {
            malformed
                .push("`x-configure-new` must be an object with a string `contract`".to_owned());
            None
        }
    }
}

/// What follows `other` in an enum listing that declares `x-configure-new`.
pub const CONFIGURE_NEW_OPTION: &str = "— configure new (seed skeleton + manual steps)";

/// The note the drivers append to an enum value that needs a host plan feature.
pub fn plan_dependency_note(feature: &str) -> String {
    format!("(needs GitHub feature {feature}: not checked)")
}

/// One question as the drivers ask it: in its sorted place, with the header of
/// its group when it is the group's first question.
#[derive(Clone, Debug, PartialEq)]
pub struct Entry<'a> {
    pub question: &'a Question,
    pub hints: Hints,
    /// The `x-ui.group` name, on the first question of the group only.
    pub header: Option<String>,
}

impl Entry<'_> {
    /// The question line: `x-ui.label`, or the id.
    pub fn label(&self) -> &str {
        self.hints.ui.label.as_deref().unwrap_or(&self.question.id)
    }
    /// What `?` prints: `x-ui.help`, or the description.
    pub fn help(&self) -> &str {
        self.hints
            .ui
            .help
            .as_deref()
            .unwrap_or(&self.question.description)
    }
    /// An enum value as listed: `other` as the "configure new" entry when the
    /// question declares it, then the plan-dependency note when it applies.
    pub fn option_line(&self, value: &str) -> String {
        let mut line = match &self.hints.configure_new {
            Some(_) if value == OTHER => format!("{OTHER} {CONFIGURE_NEW_OPTION}"),
            _ => value.to_owned(),
        };
        if let Some(dependency) = &self.hints.plan_dependency
            && dependency.applies_to(value)
        {
            line = format!("{line}  {}", plan_dependency_note(&dependency.feature));
        }
        line
    }
    /// The one line shown once `other` is picked: the contract and what the plan
    /// generates for it. `None` when the question declares no contract.
    pub fn configure_new_summary(&self) -> Option<String> {
        self.hints.configure_new.as_ref().map(|new| {
            format!(
                "{OTHER}: contract {}; the plan generates an env contract, a seed skeleton, a seed guide and manual steps.",
                new.contract
            )
        })
    }
}

/// The questions in the order they are asked: by `x-ui.order`, ties by schema
/// order, unordered questions last in schema order. Stable and deterministic.
pub fn ordered(schema: &Schema) -> Vec<Entry<'_>> {
    let mut entries: Vec<Entry<'_>> = schema
        .questions
        .iter()
        .map(|question| Entry {
            question,
            hints: Hints::of(question),
            header: None,
        })
        .collect();
    entries.sort_by_key(|entry| entry.hints.ui.order.unwrap_or(i64::MAX));
    let mut seen_groups: Vec<&str> = Vec::new();
    for entry in &mut entries {
        if let Some(group) = entry.hints.ui.group.as_deref()
            && !seen_groups.contains(&group)
        {
            seen_groups.push(group);
            entry.header = Some(group.to_owned());
        }
    }
    entries
}

/// One thing a module's hints got wrong, named by module and question.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub module: String,
    pub question: String,
    pub message: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Module {}: question `{}` {}",
            self.module, self.question, self.message
        )
    }
}

fn enum_values(kind: &Kind) -> Option<&[String]> {
    match kind {
        Kind::Enum(values) | Kind::ArrayOfEnum(values) => Some(values),
        _ => None,
    }
}

/// Every finding over `schema`, in asking order: unknown or malformed
/// extensions, a question with neither label nor description, an `order`
/// collision inside a group, `x-configure-new` off an enum listing `other` or
/// `other` without it, a plan dependency off an enum or on a missing value,
/// and a `when` that reads a question asked later once sorted.
pub fn lint(module: &str, schema: &Schema) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut orders: BTreeMap<(Option<String>, i64), String> = BTreeMap::new();
    let mut asked: Vec<&str> = Vec::new();
    for entry in ordered(schema) {
        let question = entry.question;
        let hints = &entry.hints;
        let mut report = |message: String| {
            findings.push(Finding {
                module: module.to_owned(),
                question: question.id.clone(),
                message,
            });
        };
        for key in &hints.unknown {
            report(format!(
                "uses unknown extension `{key}`; known: {}",
                KNOWN
                    .iter()
                    .map(|k| format!("`{k}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        for shape in &hints.malformed {
            report(format!("has a malformed hint: {shape}"));
        }
        if hints.ui.label.is_none() && question.description.trim().is_empty() {
            report("has neither `x-ui.label` nor a `description`".to_owned());
        }
        if let Some(order) = hints.ui.order {
            let slot = (hints.ui.group.clone(), order);
            match orders.get(&slot) {
                Some(first) => report(format!(
                    "has `x-ui.order` {order}, already used by `{first}` {}",
                    match &hints.ui.group {
                        Some(group) => format!("in group `{group}`"),
                        None => "outside any group".to_owned(),
                    }
                )),
                None => {
                    orders.insert(slot, question.id.clone());
                }
            }
        }
        let values = enum_values(&question.kind);
        let lists_other = values.is_some_and(|v| v.iter().any(|value| value == OTHER));
        match (&hints.configure_new, values) {
            (Some(_), None) => report("has `x-configure-new` but is not an enum".to_owned()),
            (Some(_), Some(_)) if !lists_other => {
                report("has `x-configure-new` but its enum does not list `other`".to_owned());
            }
            (None, Some(_)) if lists_other => {
                report("lists `other` without `x-configure-new`".to_owned());
            }
            _ => {}
        }
        if let Some(dependency) = &hints.plan_dependency {
            match values {
                None => report("has `x-plan-dependency` but is not an enum".to_owned()),
                Some(values) => {
                    for value in dependency
                        .values
                        .iter()
                        .filter(|value| !values.contains(value))
                    {
                        report(format!(
                            "has `x-plan-dependency` on `{value}`, which is not a value of its enum"
                        ));
                    }
                }
            }
        }
        if let Some(reference) = question.when.as_ref().map(When::reference)
            && !asked.contains(&reference)
        {
            report(format!(
                "has a `when` on `{reference}`, which is asked later once sorted by `x-ui.order`"
            ));
        }
        asked.push(question.id.as_str());
    }
    findings
}

/// The load-time refusal: the first finding of `lint`, as an error.
pub fn check(module: &str, schema: &Schema) -> Result<()> {
    match lint(module, schema).into_iter().next() {
        Some(finding) => refuse(finding.to_string()),
        None => Ok(()),
    }
}
