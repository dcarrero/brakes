//! The minimal TUI (SPEC-questions.md, TUI transcript and rendering rules):
//! line prompts over any `BufRead` and `Write`, so the terminal in production and
//! a scripted pair in tests. No terminal library, cursor control or colour; it
//! never reads `std::io::stdin()` itself.
//!
//! Enums are numbered with the default marked and take the number or the value;
//! arrays of enum are numbered the same way, take comma-separated numbers or
//! values and show their `minItems`/`maxItems`; booleans show `[y/N]`/`[Y/n]`;
//! integers, strings and arrays of strings (comma-separated) show the default in
//! brackets. A bad answer re-prompts with the engine's message verbatim; `?`
//! prints `x-ui.help` or the description; Enter keeps the proposed value; EOF or
//! `q` cancels.
//!
//! `when` is re-evaluated before every question over the answers so far: a gated
//! question is skipped silently, and `N` in `[n/N]` is recounted before each
//! prompt, so it follows an answer that opens or closes a gated question (the
//! header counts the questions live under the proposed values). A group header
//! is printed once, before the first question of the group that is asked. Picking
//! `other` on a question that declares `x-configure-new` prints the contract's
//! one-line summary and asks nothing more. Pattern questions (`apps.*.port`) are
//! not asked: which instances exist belongs to the module (decision #757).
use super::hints::{self, Entry};
use crate::{
    Result,
    engine::answers::{self, Answers, Kind, Question, Schema},
    refuse,
};
use serde_json::Value;
use std::io::{BufRead, Write};

/// The refusal of a cancelled run; nothing has been recorded when it is raised.
pub const CANCELLED: &str = "Cancelled; nothing recorded.";

/// What the header names besides the module: `recorded` is the number of
/// recorded answers, `preset` the `--preset` given.
pub struct Header<'a> {
    pub module: &'a str,
    pub version: &'a str,
    pub tier: &'a str,
    pub recorded: usize,
    pub preset: Option<&'a str>,
}

/// The values the questions start from: `merged` (recorded answers and the
/// drivers' layers) with each question's default for `tier` filling the gaps.
fn proposed(schema: &Schema, merged: &Answers, tier: &str) -> Answers {
    let mut proposed = merged.clone();
    for question in schema.questions.iter().filter(|q| !q.is_pattern()) {
        if !proposed.contains_key(&question.id)
            && let Some(default) = question.default_for(tier)
        {
            proposed.insert(question.id.clone(), default);
        }
    }
    proposed
}

/// The questions that will be asked, in asking order: no pattern, `when` holding
/// over the proposed values.
fn live<'a>(schema: &'a Schema, proposed: &Answers) -> Vec<Entry<'a>> {
    hints::ordered(schema)
        .into_iter()
        .filter(|entry| !entry.question.is_pattern())
        .filter(|entry| schema.when_holds(entry.question, proposed))
        .collect()
}

/// Asks every live question once and returns the patch; writes nothing to the
/// repository. The header line goes first, then one block per question.
/// `contract` gives the one-line summary of the module's contract for a question
/// answered `other`, over the answers so far; the hint's line stands in when it
/// gives none.
pub fn ask(
    header: &Header<'_>,
    schema: &Schema,
    merged: &Answers,
    contract: &dyn Fn(&str, &Answers) -> Option<String>,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<Answers> {
    let mut current = proposed(schema, merged, header.tier);
    let total = live(schema, &current).len();
    writeln!(
        output,
        "{} {} — {total} question{} (profile {}; recorded answers: {}; preset: {})",
        header.module,
        header.version,
        if total == 1 { "" } else { "s" },
        header.tier,
        match header.recorded {
            0 => "none".to_owned(),
            n => n.to_string(),
        },
        header.preset.unwrap_or("none"),
    )?;
    writeln!(output)?;
    let mut patch = Answers::new();
    let mut asked = 0;
    let mut groups: Vec<String> = Vec::new();
    for entry in hints::ordered(schema) {
        let question = entry.question;
        if question.is_pattern() || !schema.when_holds(question, &current) {
            continue;
        }
        asked += 1;
        if let Some(group) = &entry.hints.ui.group
            && !groups.contains(group)
        {
            writeln!(output, "{group}")?;
            groups.push(group.clone());
        }
        let total = live(schema, &current).len();
        let proposal = current.get(&question.id).cloned();
        prompt(output, &entry, asked, total, proposal.as_ref())?;
        let answer = loop {
            write!(output, "> ")?;
            output.flush()?;
            let mut line = String::new();
            if input.read_line(&mut line)? == 0 {
                return refuse(CANCELLED);
            }
            let text = line.trim();
            let candidate = match text {
                "q" => return refuse(CANCELLED),
                "?" => {
                    writeln!(output, "  {}", entry.help())?;
                    continue;
                }
                "" => proposal.clone(),
                _ => match parse(question, text) {
                    Ok(value) => Some(value),
                    Err(message) => {
                        writeln!(output, "  {message}")?;
                        continue;
                    }
                },
            };
            match check(header, question, candidate.as_ref()) {
                Ok(()) => break candidate,
                Err(message) => writeln!(output, "  {message}")?,
            }
        };
        if let Some(value) = answer {
            current.insert(question.id.clone(), value.clone());
            patch.insert(question.id.clone(), value);
        }
        if let Some(fallback) = entry.configure_new_summary()
            && current
                .get(&question.id)
                .is_some_and(super::configure_new::picks_other)
        {
            let summary = contract(&question.id, &current).unwrap_or(fallback);
            writeln!(output, "  {summary}")?;
        }
    }
    Ok(patch)
}

/// The question block: `[n/N] label`, then for an enum or an array of enum its
/// description and the numbered values (an array adds its bounds); other kinds
/// carry their default on the same line.
fn prompt(
    output: &mut impl Write,
    entry: &Entry<'_>,
    index: usize,
    total: usize,
    proposal: Option<&Value>,
) -> Result<()> {
    let line = format!("[{index}/{total}] {}", entry.label());
    match &entry.question.kind {
        Kind::Enum(values) | Kind::ArrayOfEnum(values) => {
            writeln!(output, "{line}")?;
            if !entry.question.description.is_empty() {
                writeln!(output, "  {}", entry.question.description)?;
            }
            for (number, value) in values.iter().enumerate() {
                let proposed = |item: &Value| item.as_str() == Some(value.as_str());
                let default = match proposal {
                    Some(Value::Array(items)) => items.iter().any(proposed),
                    Some(single) => proposed(single),
                    None => false,
                };
                writeln!(
                    output,
                    "  {}) {}{}",
                    number + 1,
                    entry.option_line(value),
                    if default { "  (default)" } else { "" }
                )?;
            }
            if matches!(entry.question.kind, Kind::ArrayOfEnum(_)) {
                writeln!(output, "  {}", array_bounds(entry.question))?;
            }
        }
        Kind::Boolean => writeln!(
            output,
            "{line}  {}",
            match proposal.and_then(Value::as_bool) {
                Some(true) => "[Y/n]",
                Some(false) => "[y/N]",
                None => "[y/n]",
            }
        )?,
        _ => match proposal {
            Some(value) => writeln!(output, "{line}  [{}]", display(value))?,
            None => writeln!(output, "{line}")?,
        },
    }
    Ok(())
}

/// How an array of enum is answered, with its `minItems`/`maxItems`.
fn array_bounds(question: &Question) -> String {
    let bounds: Vec<String> = [
        question.min_items.map(|n| format!("at least {n}")),
        question.max_items.map(|n| format!("at most {n}")),
    ]
    .into_iter()
    .flatten()
    .collect();
    if bounds.is_empty() {
        "Numbers separated by commas (1,3).".to_owned()
    } else {
        format!("Numbers separated by commas (1,3); {}.", bounds.join(", "))
    }
}

/// An enum value by its number, or the text as typed for the engine to judge;
/// only an out-of-range number is refused here.
fn choice(values: &[String], text: &str) -> std::result::Result<Value, String> {
    match text.parse::<usize>() {
        Ok(number) if (1..=values.len()).contains(&number) => {
            Ok(Value::String(values[number - 1].clone()))
        }
        Ok(_) => Err(format!(
            "Not a choice: {text}. Pick 1–{}, Enter for the default, ? for help.",
            values.len()
        )),
        Err(_) => Ok(Value::String(text.to_owned())),
    }
}

/// A value as typed back: strings bare, arrays comma-separated.
fn display(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Array(items) => items.iter().map(display).collect::<Vec<_>>().join(", "),
        other => other.to_string(),
    }
}

/// The typed value of `text`: an enum by number, an array of enum by
/// comma-separated numbers or values, a boolean by y/yes/n/no, any other answer
/// as `--set` parses it. Only an out-of-range number is refused here;
/// everything else is the engine's to judge.
fn parse(question: &Question, text: &str) -> std::result::Result<Value, String> {
    let as_set = |raw: &str| {
        let schema = Schema {
            questions: vec![question.clone()],
        };
        answers::parse_set(&schema, &format!("{}={raw}", question.id))
            .map(|(_, value)| value)
            .map_err(|error| error.to_string())
    };
    match &question.kind {
        Kind::Enum(values) => choice(values, text),
        Kind::ArrayOfEnum(values) => text
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(|item| choice(values, item))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map(Value::Array),
        Kind::Boolean => match text.to_ascii_lowercase().as_str() {
            "y" | "yes" => Ok(Value::Bool(true)),
            "n" | "no" => Ok(Value::Bool(false)),
            _ => as_set(text),
        },
        _ => as_set(text),
    }
}

/// The engine's verdict on one answer, by its own validator and wording: the
/// question alone, its `when` dropped (it already holds).
fn check(
    header: &Header<'_>,
    question: &Question,
    value: Option<&Value>,
) -> std::result::Result<(), String> {
    let schema = Schema {
        questions: vec![Question {
            when: None,
            ..question.clone()
        }],
    };
    let raw: Answers = value
        .map(|value| (question.id.clone(), value.clone()))
        .into_iter()
        .collect();
    schema
        .validate(header.module, &raw, header.tier)
        .map(|_| ())
        .map_err(|error| error.to_string())
}
