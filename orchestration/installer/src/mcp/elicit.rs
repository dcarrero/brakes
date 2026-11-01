//! `elicitation/create` for `brakes mcp` (SPEC-questions.md, MCP server
//! and Elicitation during plan; decision 2026-10-28, point 9): the questions
//! `plan` still needs, asked in the client's own form one `x-ui.group` at a time,
//! and the one boolean `confirm` that `apply` needs before it writes.
//!
//! Sources (MCP specification):
//! - capability and form mode: <https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation#capabilities>
//!   (an empty `elicitation` object means form mode; "Servers MUST NOT send
//!   elicitation requests with modes that are not supported by the client").
//! - request shape: <https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation#form-mode-elicitation-requests>
//!   (`mode: "form"`, `message`, a flat `requestedSchema`); revision 2025-06-18
//!   has no `mode`: <https://modelcontextprotocol.io/specification/2025-06-18/client/elicitation#protocol-messages>.
//! - property subset: `schema.ts` of each revision. 2025-06-18 allows string
//!   (`minLength`, `maxLength`, `format`), number/integer (`minimum`,
//!   `maximum`), boolean and an enum with `enumNames`; 2025-11-25 adds the
//!   multi-select `type: array` with `items.enum`, `minItems` and `maxItems`, and
//!   keeps `enumNames` as `LegacyTitledEnumSchema`. The questions asked here are
//!   the ones with no value, so no `default` is sent for them.
//! - response actions: <https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation#response-actions>
//!   (`accept` with `content`, `decline`, `cancel`).
use super::{Client, Peer};
use crate::{
    Result,
    engine::{
        Answers,
        answers::{Kind, Schema},
    },
    questions::hints::{self, Entry},
    refuse,
};
use serde_json::{Map, Value, json};

/// What `cancel` returns, from `plan` and from `apply` (the exact SPEC text).
pub const CANCELLED: &str = "Cancelled by the user; nothing recorded.";
/// What `decline`, or an `accept` without `confirm: true`, returns from `apply`.
pub const DECLINED: &str = "Declined by the user; nothing recorded.";
/// How many requests one group gets before the engine's message is the error.
pub const ROUNDS: usize = 3;

/// The human stopped the call: a tool result with `isError` and this text, with
/// no `REFUSED:` prefix, because nothing was refused.
#[derive(Debug)]
pub struct Stopped(pub &'static str);

impl std::fmt::Display for Stopped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for Stopped {}

/// The client's answer to one `elicitation/create`.
#[derive(Debug, PartialEq)]
pub enum Reply {
    Accept(Map<String, Value>),
    Decline,
    Cancel,
    /// A JSON-RPC error, a malformed result or a client that went away.
    Failed(String),
}

/// True when `capabilities` (the client's, from `initialize`) declares form-mode
/// elicitation: an `elicitation` object that is empty or names `form`. Under
/// 2025-06-18 there are no modes, so any `elicitation` object is form mode.
pub fn supports_form(capabilities: &Value, version: &str) -> bool {
    match capabilities.get("elicitation") {
        Some(Value::Object(modes)) => {
            version == "2025-06-18" || modes.is_empty() || modes.contains_key("form")
        }
        _ => false,
    }
}

/// Sends one form request and reads the client's answer.
/// Every property is required, listed in asking order (`properties`, a JSON
/// object, is sorted by key).
fn ask(
    client: &mut dyn Client,
    peer: &Peer,
    message: &str,
    properties: Map<String, Value>,
    required: &[&str],
) -> Reply {
    let mut params = json!({
        "message": message,
        "requestedSchema": {"type": "object", "properties": properties, "required": required},
    });
    if peer.version != "2025-06-18" {
        params["mode"] = json!("form");
    }
    match client.request("elicitation/create", params) {
        None => Reply::Failed("the client closed the connection".to_owned()),
        Some(Err(error)) => Reply::Failed(
            error["message"]
                .as_str()
                .map_or_else(|| error.to_string(), str::to_owned),
        ),
        Some(Ok(result)) => match result["action"].as_str() {
            Some("accept") => {
                Reply::Accept(result["content"].as_object().cloned().unwrap_or_default())
            }
            Some("decline") => Reply::Decline,
            Some("cancel") => Reply::Cancel,
            _ => Reply::Failed(format!("unknown elicitation result {result}")),
        },
    }
}

/// `apply`'s gate: the plan summary and one boolean `confirm`. `Ok` only on an
/// `accept` with `confirm: true`; everything else stops the call untouched.
pub fn confirm(client: &mut dyn Client, peer: &Peer, message: &str) -> Result<()> {
    let mut properties = Map::new();
    properties.insert(
        "confirm".to_owned(),
        json!({"type": "boolean", "title": "Apply this plan",
               "description": "Writes the files listed above to the repository; nothing remote.",
               "default": false}),
    );
    match ask(client, peer, message, properties, &["confirm"]) {
        Reply::Accept(content) if content.get("confirm") == Some(&Value::Bool(true)) => Ok(()),
        Reply::Accept(_) | Reply::Decline => Err(Stopped(DECLINED).into()),
        Reply::Cancel => Err(Stopped(CANCELLED).into()),
        Reply::Failed(why) => refuse(format!(
            "the client did not answer the confirmation ({why}); nothing recorded"
        )),
    }
}

/// One question as an elicitation property, or why it cannot be one: an array
/// of enum needs 2025-11-25, an array of free strings is never elicited.
fn property(entry: &Entry<'_>, peer: &Peer, module: &str) -> Result<Value> {
    let q = entry.question;
    let mut out = Map::new();
    let mut put = |key: &str, value: Value| {
        out.insert(key.to_owned(), value);
    };
    match &q.kind {
        Kind::String => put("type", json!("string")),
        Kind::Integer => put("type", json!("integer")),
        Kind::Boolean => put("type", json!("boolean")),
        Kind::Enum(options) => {
            put("type", json!("string"));
            put("enum", json!(options));
            let names: Vec<String> = options.iter().map(|o| entry.option_line(o)).collect();
            put("enumNames", json!(names));
        }
        Kind::ArrayOfEnum(options) if peer.version != "2025-06-18" => {
            put("type", json!("array"));
            put("items", json!({"type": "string", "enum": options}));
        }
        Kind::ArrayOfEnum(_) => {
            return refuse(format!(
                "Module {module}: question {} needs a 2025-11-25 client or an explicit answer",
                q.id
            ));
        }
        Kind::ArrayOfString => {
            return refuse(format!(
                "Module {module}: question {} needs an explicit answer",
                q.id
            ));
        }
    }
    put("title", json!(entry.label()));
    put("description", json!(entry.help()));
    let bounds = [
        ("minLength", q.min_length.map(|n| json!(n))),
        ("maxLength", q.max_length.map(|n| json!(n))),
        ("minimum", q.minimum.map(|n| json!(n))),
        ("maximum", q.maximum.map(|n| json!(n))),
        ("minItems", q.min_items.map(|n| json!(n))),
        ("maxItems", q.max_items.map(|n| json!(n))),
    ];
    for (key, value) in bounds {
        if let Some(value) = value {
            put(key, value);
        }
    }
    Ok(Value::Object(out))
}

/// The refusal that lists the questions still open.
fn missing<T>(module: &str, open: &[String]) -> Result<T> {
    refuse(format!(
        "Module {module}: no answer for {}; pass them in `answers`",
        open.join(", ")
    ))
}

/// `patch` with every open required question answered in the client, one
/// `x-ui.group` at a time in asking order (the ungrouped ones form one more), so
/// a `when` resolves on what the previous group answered. `open` lists the
/// questions still open over a patch. A client without form elicitation gets
/// the open ids; `decline` (or a failed request) returns them too; `cancel`
/// stops with `CANCELLED`; an invalid answer is asked again with the engine's
/// message in the property's description, `ROUNDS` times at most.
pub fn complete(
    client: &mut dyn Client,
    peer: &Peer,
    module: &str,
    schema: &Schema,
    tier: &str,
    patch: &Answers,
    open: &dyn Fn(&Answers) -> Result<Vec<String>>,
) -> Result<Answers> {
    let entries = hints::ordered(schema);
    let mut patch = patch.clone();
    loop {
        let still_open = open(&patch)?;
        if still_open.is_empty() {
            return Ok(patch);
        }
        if !peer.elicitation {
            return missing(module, &still_open);
        }
        let is_open = |entry: &&Entry<'_>| still_open.contains(&entry.question.id);
        let group = entries
            .iter()
            .find(is_open)
            .expect("an open question is a question of the schema")
            .hints
            .ui
            .group
            .clone();
        let asked: Vec<&Entry<'_>> = entries
            .iter()
            .filter(is_open)
            .filter(|e| e.hints.ui.group == group)
            .collect();
        let required: Vec<&str> = asked.iter().map(|e| e.question.id.as_str()).collect();
        let mut properties = Map::new();
        for entry in &asked {
            properties.insert(entry.question.id.clone(), property(entry, peer, module)?);
        }
        let message = match &group {
            Some(group) => format!("brakes: {module} needs answers ({group})."),
            None => format!("brakes: {module} needs answers."),
        };
        let mut round = 1;
        loop {
            let content = match ask(client, peer, &message, properties.clone(), &required) {
                Reply::Accept(content) => content,
                Reply::Cancel => return Err(Stopped(CANCELLED).into()),
                Reply::Decline | Reply::Failed(_) => return missing(module, &still_open),
            };
            let mut first_error = None;
            for entry in &asked {
                let help = entry.help();
                properties[&entry.question.id]["description"] =
                    match validate(module, tier, entry, &content) {
                        Ok(()) => json!(help),
                        Err(error) => {
                            let described = json!(format!("{error}. {help}"));
                            first_error.get_or_insert(error);
                            described
                        }
                    };
            }
            match first_error {
                None => {
                    for entry in &asked {
                        let id = &entry.question.id;
                        patch.insert(id.clone(), content[id].clone());
                    }
                    break;
                }
                Some(error) if round == ROUNDS => return Err(error),
                Some(_) => round += 1,
            }
        }
    }
}

/// The engine's verdict on the one answer `content` gives `entry`'s question:
/// the question alone, ungated, through `Schema::validate`, so the message is
/// the engine's own.
fn validate(
    module: &str,
    tier: &str,
    entry: &Entry<'_>,
    content: &Map<String, Value>,
) -> Result<()> {
    let id = &entry.question.id;
    let mut question = entry.question.clone();
    question.when = None;
    let alone = Schema {
        questions: vec![question],
    };
    let answer: Answers = content
        .get(id)
        .map(|value| (id.clone(), value.clone()))
        .into_iter()
        .collect();
    alone.validate(module, &answer, tier).map(|_| ())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn form_mode_is_an_empty_elicitation_object_or_one_naming_form() {
        let latest = "2025-11-25";
        assert!(supports_form(&json!({"elicitation": {}}), latest));
        assert!(supports_form(&json!({"elicitation": {"form": {}}}), latest));
        assert!(supports_form(
            &json!({"elicitation": {"form": {}, "url": {}}}),
            latest
        ));
        assert!(!supports_form(&json!({"elicitation": {"url": {}}}), latest));
        assert!(!supports_form(&json!({}), latest));
        assert!(!supports_form(&json!({"elicitation": true}), latest));
        assert!(supports_form(&json!({"elicitation": {}}), "2025-06-18"));
    }
}
