//! The PII declaration (SPEC-security.md, "PII pack"; T12, #800):
//! `.agent-setup/pii.yaml`, the owner's statement of which fields hold personal
//! data, read line-wise in the shape the installer seeds (no YAML crate, as
//! `exceptions.rs` reads the native files), validated by the rules the spec
//! states and rendered into the DSAR runbook. The shell twin,
//! `templates/security/fragments/pii-check.sh`, runs inside `security-gate` as
//! the `pii-check` step; `tests/security_gate_shell.rs` proves both print the
//! same findings over the same fixtures. The installer never reads production
//! data: the declaration is audited for shape and presence, not completeness.
use super::exceptions::Shape;
use crate::auditor::rules::Criticality;
use std::{fs, path::Path};

pub const PII_PATH: &str = ".agent-setup/pii.yaml";
pub const DSAR_PATH: &str = "docs/runbooks/dsar.md";
pub const SCHEMA: &str = "1";
/// The seven keys of every field, in the order the check names them.
pub const FIELD_KEYS: [&str; 7] = [
    "path",
    "category",
    "purpose",
    "lawful_basis",
    "retention",
    "exclude_from",
    "erasure",
];
pub const CATEGORIES: [&str; 8] = [
    "identifier",
    "contact",
    "financial",
    "health",
    "location",
    "biometric",
    "behavioural",
    "credentials",
];
/// GDPR Article 6 bases, kebab-case.
pub const LAWFUL_BASES: [&str; 6] = [
    "consent",
    "contract",
    "legal-obligation",
    "vital-interests",
    "public-task",
    "legitimate-interests",
];
pub const ERASURES: [&str; 3] = ["delete", "anonymise", "retain-legal"];
/// The consumers `exclude_from` may name: `logs` and `traces` are
/// `observability`'s, `analytics` and `cdc` the data modules'.
pub const CONSUMERS: [&str; 4] = ["logs", "traces", "analytics", "cdc"];
/// A `retain-legal` purpose names its obligation when it mentions one of these.
pub const OBLIGATION_WORDS: [&str; 3] = ["obligation", "legal", "law"];

/// One declared field; every value as written, `None` when the key is absent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Field {
    pub path: Option<String>,
    pub category: Option<String>,
    pub purpose: Option<String>,
    pub lawful_basis: Option<String>,
    pub retention: Option<String>,
    /// The inline list as written (`[logs, traces]`).
    pub exclude_from: Option<String>,
    pub erasure: Option<String>,
}

impl Field {
    fn get(&self, key: &str) -> Option<&str> {
        match key {
            "path" => self.path.as_deref(),
            "category" => self.category.as_deref(),
            "purpose" => self.purpose.as_deref(),
            "lawful_basis" => self.lawful_basis.as_deref(),
            "retention" => self.retention.as_deref(),
            "exclude_from" => self.exclude_from.as_deref(),
            "erasure" => self.erasure.as_deref(),
            _ => None,
        }
    }
    fn set(&mut self, key: &str, value: String) {
        let slot = match key {
            "path" => &mut self.path,
            "category" => &mut self.category,
            "purpose" => &mut self.purpose,
            "lawful_basis" => &mut self.lawful_basis,
            "retention" => &mut self.retention,
            "exclude_from" => &mut self.exclude_from,
            "erasure" => &mut self.erasure,
            _ => return,
        };
        *slot = Some(value);
    }
    /// What the findings call the field: its path, or its index.
    pub fn label(&self, index: usize) -> String {
        match self.path.as_deref() {
            Some(path) if !path.is_empty() => path.to_owned(),
            _ => format!("fields[{index}]"),
        }
    }
    /// `exclude_from` as a list: `None` when it is not an inline `[a, b]`.
    pub fn excluded(&self) -> Option<Vec<String>> {
        inline_list(self.exclude_from.as_deref().unwrap_or(""))
    }
    /// The storage the field lives in: the part before the first dot.
    pub fn storage(&self) -> &str {
        self.path
            .as_deref()
            .and_then(|p| p.split_once('.').map(|(s, _)| s))
            .unwrap_or("")
    }
}

/// The declaration as written; the top-level values stay text.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Declaration {
    pub schema: Option<String>,
    pub controller: Option<String>,
    pub dsar_contact: Option<String>,
    pub sla_days: Option<String>,
    pub fields: Vec<Field>,
}

fn unquote(s: &str) -> &str {
    let b = s.as_bytes();
    if b.len() >= 2
        && ((b[0] == b'"' && b[b.len() - 1] == b'"') || (b[0] == b'\'' && b[b.len() - 1] == b'\''))
    {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

/// `#` starts a comment outside quotes.
fn strip_comment(s: &str) -> &str {
    let mut quote: Option<char> = None;
    for (at, c) in s.char_indices() {
        match quote {
            None if c == '"' || c == '\'' => quote = Some(c),
            None if c == '#' => return &s[..at],
            Some(q) if c == q => quote = None,
            _ => {}
        }
    }
    s
}

fn split_key(rest: &str, lowercase_only: bool) -> Option<(&str, &str)> {
    let end = rest.find(':')?;
    let key = &rest[..end];
    let ok = !key.is_empty()
        && key.bytes().all(|b| {
            b == b'_' || b.is_ascii_lowercase() || (!lowercase_only && b.is_ascii_uppercase())
        });
    if !ok {
        return None;
    }
    let value = rest[end + 1..].trim_start_matches([' ', '\t']);
    Some((key, unquote(value)))
}

/// `[a, b]` as a list; `[]` and the empty text are empty; anything else `None`.
pub fn inline_list(text: &str) -> Option<Vec<String>> {
    if text.is_empty() || text == "[]" {
        return Some(Vec::new());
    }
    let inner = text.strip_prefix('[')?.strip_suffix(']')?;
    Some(
        inner
            .split(',')
            .map(|s| s.trim_matches([' ', '\t']).to_owned())
            .filter(|s| !s.is_empty())
            .collect(),
    )
}

/// Reads the seeded shape line by line, as `pii-check.sh` does; the first line
/// outside it is `Unverified`.
pub fn parse(text: &str) -> Shape<Declaration> {
    let mut out = Declaration::default();
    let mut in_fields = false;
    for (n, raw) in text.lines().enumerate() {
        let line_no = n + 1;
        let line = strip_comment(raw.trim_end_matches('\r')).trim_end_matches([' ', '\t']);
        let trimmed = line.trim_start_matches([' ', '\t']);
        if trimmed.is_empty() || line == "---" {
            continue;
        }
        if !line.starts_with([' ', '\t'])
            && let Some((key, value)) = split_key(line, false)
        {
            if key == "fields" {
                if !value.is_empty() && value != "[]" {
                    return Shape::Unverified { line: line_no };
                }
                in_fields = true;
                continue;
            }
            in_fields = false;
            let value = Some(value.to_owned());
            match key {
                "schema" => out.schema = value,
                "controller" => out.controller = value,
                "dsar_contact" => out.dsar_contact = value,
                "sla_days" => out.sla_days = value,
                _ => {}
            }
            continue;
        }
        if !in_fields {
            return Shape::Unverified { line: line_no };
        }
        if let Some(rest) = line.strip_prefix("  - ") {
            let Some((key, value)) = split_key(rest, true) else {
                return Shape::Unverified { line: line_no };
            };
            let mut field = Field::default();
            field.set(key, value.to_owned());
            out.fields.push(field);
            continue;
        }
        if let Some(rest) = line.strip_prefix("    ")
            && !rest.starts_with(' ')
            && let Some(field) = out.fields.last_mut()
        {
            let Some((key, value)) = split_key(rest, true) else {
                return Shape::Unverified { line: line_no };
            };
            field.set(key, value.to_owned());
            continue;
        }
        return Shape::Unverified { line: line_no };
    }
    Shape::Generated(out)
}

fn undeclared(value: Option<&str>) -> bool {
    let value = value.unwrap_or("");
    value.is_empty() || (value.starts_with('<') && value.ends_with('>'))
}

/// The findings of a parsed declaration, in the order `pii-check.sh` prints them.
pub fn validate(declaration: &Declaration, required: bool) -> Vec<String> {
    let mut out = Vec::new();
    if declaration.schema.as_deref() != Some(SCHEMA) {
        out.push(format!(
            "{PII_PATH} has an unsupported schema {}",
            declaration.schema.as_deref().unwrap_or("none")
        ));
    }
    if required && undeclared(declaration.controller.as_deref()) {
        out.push(format!("{PII_PATH} controller is not declared"));
    }
    if required && undeclared(declaration.dsar_contact.as_deref()) {
        out.push(format!("{PII_PATH} dsar_contact is not declared"));
    }
    let sla = declaration.sla_days.as_deref().unwrap_or("");
    let positive = !sla.is_empty()
        && sla.bytes().all(|b| b.is_ascii_digit())
        && sla.parse::<u64>().is_ok_and(|n| n >= 1);
    if !positive {
        out.push(format!("{PII_PATH} sla_days must be a positive integer"));
    }
    if required && declaration.fields.is_empty() {
        out.push(format!(
            "{PII_PATH} declares no fields; criticality personal-data-or-payments needs at least one"
        ));
    }
    for (i, field) in declaration.fields.iter().enumerate() {
        let label = field.label(i);
        for key in FIELD_KEYS {
            if field.get(key).unwrap_or("").is_empty() {
                out.push(format!("Field {label} is missing {key}"));
            }
        }
        fn unknown<'a>(value: Option<&'a str>, allowed: &[&str]) -> Option<&'a str> {
            value.filter(|v| !v.is_empty() && !allowed.contains(v))
        }
        if let Some(v) = unknown(field.category.as_deref(), &CATEGORIES) {
            out.push(format!("Field {label} has an unknown category {v}"));
        }
        if let Some(v) = unknown(field.lawful_basis.as_deref(), &LAWFUL_BASES) {
            out.push(format!("Field {label} has an unknown lawful_basis {v}"));
        }
        if let Some(v) = unknown(field.erasure.as_deref(), &ERASURES) {
            out.push(format!("Field {label} has an unknown erasure {v}"));
        }
        let excluded = field.excluded();
        match &excluded {
            None => out.push(format!("Field {label} exclude_from is not an inline list")),
            Some(list) => {
                for consumer in list.iter().filter(|c| !CONSUMERS.contains(&c.as_str())) {
                    out.push(format!(
                        "Field {label} excludes from an unknown consumer {consumer}"
                    ));
                }
            }
        }
        if field.erasure.as_deref() == Some("retain-legal") {
            let purpose = field.purpose.as_deref().unwrap_or("").to_ascii_lowercase();
            if !OBLIGATION_WORDS.iter().any(|w| purpose.contains(w)) {
                out.push(format!(
                    "Field {label} is retain-legal and its purpose names no obligation"
                ));
            }
        }
        if field.category.as_deref() == Some("credentials")
            && let Some(list) = &excluded
            && !(list.iter().any(|c| c == "logs") && list.iter().any(|c| c == "traces"))
        {
            out.push(format!(
                "Field {label} is credentials and must exclude logs and traces"
            ));
        }
    }
    out
}

/// What the `pii-check` step prints: the findings, then the claim line.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub findings: Vec<String>,
    pub required: bool,
    /// `None` when the file is absent.
    pub fields: Option<usize>,
}

impl Report {
    pub fn claim(&self) -> String {
        let required = if self.required {
            "required"
        } else {
            "not required"
        };
        match self.fields {
            None => format!("pii: {required}, absent"),
            Some(n) => format!("pii: {required}, {n} fields"),
        }
    }
    pub fn passed(&self) -> bool {
        self.findings.is_empty()
    }
    /// The lines in print order.
    pub fn lines(&self) -> Vec<String> {
        self.findings
            .iter()
            .map(|f| format!("::error::{f}"))
            .chain(std::iter::once(self.claim()))
            .collect()
    }
}

/// Whether the pack is required: the criticality is `personal-data-or-payments`.
pub fn required(criticality: Option<Criticality>) -> bool {
    criticality == Some(Criticality::PersonalDataOrPayments)
}

/// The whole check over a repository root for `criticality`, as `pii-check.sh`
/// runs it from the recorded profile.
pub fn check(root: &Path, criticality: Option<Criticality>) -> crate::Result<Report> {
    let required = required(criticality);
    let text = match fs::read_to_string(root.join(PII_PATH)) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let findings = if required {
                vec![format!(
                    "{PII_PATH} is missing: criticality personal-data-or-payments needs a PII declaration"
                )]
            } else {
                Vec::new()
            };
            return Ok(Report {
                findings,
                required,
                fields: None,
            });
        }
        Err(e) => return Err(e.into()),
    };
    Ok(match parse(&text) {
        Shape::Unverified { line } => Report {
            findings: vec![format!(
                "{PII_PATH} is unverified: line {line} is outside the seeded shape"
            )],
            required,
            fields: Some(0),
        },
        Shape::Generated(declaration) => Report {
            findings: validate(&declaration, required),
            required,
            fields: Some(declaration.fields.len()),
        },
    })
}

const RUNBOOK: &str = include_str!("../../../../../templates/security/seeds/dsar.md");

/// The DSAR runbook (runbook-template shape) for a declaration: the fields
/// grouped by `erasure` with the storage each lives in; pure.
pub fn runbook(declaration: &Declaration) -> String {
    let rows = |erasure: &str| -> String {
        let rows: Vec<String> = declaration
            .fields
            .iter()
            .filter(|f| f.erasure.as_deref() == Some(erasure))
            .map(|f| {
                format!(
                    "| `{}` | {} | {} | {} |",
                    f.path.as_deref().unwrap_or(""),
                    f.storage(),
                    f.category.as_deref().unwrap_or(""),
                    f.retention.as_deref().unwrap_or("")
                )
            })
            .collect();
        if rows.is_empty() {
            "| _none declared_ | | | |".to_owned()
        } else {
            rows.join("\n")
        }
    };
    let text = |value: Option<&str>| value.unwrap_or("<not declared>").to_owned();
    [
        ("controller", text(declaration.controller.as_deref())),
        ("dsar_contact", text(declaration.dsar_contact.as_deref())),
        ("sla_days", text(declaration.sla_days.as_deref())),
        ("delete_rows", rows("delete")),
        ("anonymise_rows", rows("anonymise")),
        ("retain_rows", rows("retain-legal")),
    ]
    .iter()
    .fold(RUNBOOK.to_owned(), |text, (key, value)| {
        text.replace(&format!("{{{{{key}}}}}"), value)
    })
}
