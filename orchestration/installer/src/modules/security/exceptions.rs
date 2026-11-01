//! The bypass inventory and the native exception files (SPEC-security.md,
//! "The bypass inventory"; owner decision 2026-10-28, point 11). Every way of
//! switching a gate off carries eight fields, an issue and an expiry; an
//! expired one turns the gate red; renewal is a new entry, never an edited
//! date, which only the file's git log can show. The readers are line-wise
//! over the shape the installer seeds, without a YAML or TOML crate: a file
//! outside that shape is `unverified` and named. `exceptions-check.sh` is the
//! shell twin of this file (jq and awk); `tests/security_gate_shell.rs` proves
//! both agree on every fixture, so every text here is a contract.
use chrono::NaiveDate;
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use std::{fs, path::Path};

pub const INVENTORY: &str = ".agent-setup/security-exceptions.json";
pub const SCHEMA: f64 = 1.0;
/// `bypass_max_days`: job skips, hotfix variables, `continue-on-error` and coverage resets.
pub const DEFAULT_BYPASS_MAX_DAYS: u32 = 30;
/// Allowlists, ruleset bypass actors and accepted risks.
pub const LONG_BOUND_DAYS: u32 = 365;
pub const FIELDS: [&str; 8] = [
    "id", "kind", "target", "reason", "issue", "owner", "created", "expires",
];
pub const TRIVY_IGNORE: &str = ".trivyignore.yaml";
pub const TRIVY_PLAIN: &str = ".trivyignore";
pub const OSV_CONFIG: &str = "osv-scanner.toml";
pub const GITLEAKS_IGNORE: &str = ".gitleaksignore";
pub const SEMGREP_IGNORE: &str = ".semgrepignore";
pub const GITLEAKS_CONFIG: &str = ".gitleaks.toml";
/// Semgrep CE's built-in ignore list for the pinned release (`pins::SEMGREP`,
/// 1.182.0): `src/targeting/default.semgrepignore` at tag `v1.182.0` of
/// semgrep/semgrep. A root `.semgrepignore` replaces this list rather than
/// extending it (`Semgrepignore.ml`: the defaults apply only when no root file
/// exists), so the seed restates it (#1194). An entry equal to one of these
/// ignores nothing Semgrep would scan without the file and needs no inventory
/// entry. `exceptions-check.sh` carries the same list; a test holds them equal.
pub const SEMGREP_DEFAULTS: [&str; 22] = [
    ".git",
    ".svn",
    ".hg",
    "_darcs",
    "CVS",
    "build/",
    "vendor/",
    "dist/",
    "*.min.js",
    ".env/",
    ".tox/",
    "node_modules/",
    ".npm/",
    ".yarn/",
    ".venv/",
    "_opam/",
    "_build/",
    "_cargo/",
    "test/",
    "tests/",
    "testsuite/",
    "*_test.go",
];
const TRIVY_SECTIONS: [&str; 4] = [
    "vulnerabilities",
    "misconfigurations",
    "secrets",
    "licenses",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    JobBypass,
    RulesetBypassActor,
    RepoVariable,
    ContinueOnError,
    Allowlist,
    CoverageReset,
    /// An owner-accepted risk against named auditor rules (#1217): `target`
    /// is one rule id or several separated by commas; no gate consumes it.
    AcceptedRisk,
}

impl Kind {
    pub const ALL: [Kind; 7] = [
        Kind::JobBypass,
        Kind::RulesetBypassActor,
        Kind::RepoVariable,
        Kind::ContinueOnError,
        Kind::Allowlist,
        Kind::CoverageReset,
        Kind::AcceptedRisk,
    ];
    pub fn parse(text: &str) -> Option<Kind> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == text)
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::JobBypass => "job-bypass",
            Kind::RulesetBypassActor => "ruleset-bypass-actor",
            Kind::RepoVariable => "repo-variable",
            Kind::ContinueOnError => "continue-on-error",
            Kind::Allowlist => "allowlist",
            Kind::CoverageReset => "coverage-reset",
            Kind::AcceptedRisk => "accepted-risk",
        }
    }
    /// The longest an exception of this kind may last, in days.
    pub fn max_days(self, bypass_max_days: u32) -> u32 {
        match self {
            Kind::Allowlist | Kind::RulesetBypassActor | Kind::AcceptedRisk => LONG_BOUND_DAYS,
            _ => bypass_max_days,
        }
    }
}

/// One inventory entry; a field that is absent, empty or not a string is `None`
/// and reported as missing (the shell twin applies the same rule with `jq`).
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct Entry {
    #[serde(default, deserialize_with = "text")]
    pub id: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub kind: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub target: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub reason: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub issue: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub owner: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub created: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub expires: Option<String>,
    /// Position in `exceptions`, the label of an entry without an id.
    #[serde(skip)]
    pub index: usize,
}

fn text<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Ok(match Value::deserialize(d)? {
        Value::String(s) if !s.is_empty() => Some(s),
        _ => None,
    })
}

impl Entry {
    pub fn label(&self) -> String {
        self.id
            .clone()
            .unwrap_or_else(|| format!("exceptions[{}]", self.index))
    }
    fn field(&self, name: &str) -> Option<&str> {
        match name {
            "id" => self.id.as_deref(),
            "kind" => self.kind.as_deref(),
            "target" => self.target.as_deref(),
            "reason" => self.reason.as_deref(),
            "issue" => self.issue.as_deref(),
            "owner" => self.owner.as_deref(),
            "created" => self.created.as_deref(),
            "expires" => self.expires.as_deref(),
            _ => None,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct Inventory {
    pub schema: serde_json::Number,
    pub exceptions: Vec<Entry>,
}

impl Inventory {
    /// `None` when the text is not the inventory shape: an object with a
    /// numeric `schema` and an `exceptions` array of objects.
    pub fn parse(text: &str) -> Option<Inventory> {
        let mut inventory: Inventory = serde_json::from_str(text).ok()?;
        for (index, entry) in inventory.exceptions.iter_mut().enumerate() {
            entry.index = index;
        }
        Some(inventory)
    }
    /// Targets every `allowlist` entry registers, whatever its state.
    pub fn allowlist_targets(&self) -> Vec<&str> {
        self.exceptions
            .iter()
            .filter(|e| e.kind.as_deref() == Some(Kind::Allowlist.as_str()))
            .filter_map(|e| e.target.as_deref())
            .collect()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Active,
    Expired,
    Invalid,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    pub state: State,
    pub findings: Vec<String>,
}

impl Verdict {
    fn invalid(findings: Vec<String>) -> Verdict {
        Verdict {
            state: State::Invalid,
            findings,
        }
    }
}

/// `YYYY-MM-DD` and a real calendar day; nothing looser.
pub fn parse_date(text: &str) -> Option<NaiveDate> {
    let bytes = text.as_bytes();
    let shaped = bytes.len() == 10
        && bytes.iter().enumerate().all(|(i, b)| {
            if i == 4 || i == 7 {
                *b == b'-'
            } else {
                b.is_ascii_digit()
            }
        });
    shaped
        .then(|| NaiveDate::parse_from_str(text, "%Y-%m-%d").ok())
        .flatten()
}

/// `#<n>` or an issue URL.
pub fn issue_reference(text: &str) -> bool {
    if let Some(number) = text.strip_prefix('#') {
        return !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit());
    }
    text.strip_prefix("https://")
        .or_else(|| text.strip_prefix("http://"))
        .is_some_and(|rest| !rest.is_empty())
}

/// Free text that names an issue: `#<n>` anywhere, or a URL.
pub fn mentions_issue(text: &str) -> bool {
    text.contains("https://")
        || text.contains("http://")
        || text
            .as_bytes()
            .windows(2)
            .any(|w| w[0] == b'#' && w[1].is_ascii_digit())
}

/// The state of an inventory entry on `today`, with one finding per defect in
/// a fixed order: missing fields, unknown kind, invalid dates, invalid issue;
/// then the bound; then the expiry. `expires` is the last active day.
pub fn state(entry: &Entry, today: NaiveDate, bypass_max_days: u32) -> Verdict {
    let label = entry.label();
    let mut findings: Vec<String> = FIELDS
        .iter()
        .filter(|field| entry.field(field).is_none())
        .map(|field| format!("Exception {label} is missing {field}"))
        .collect();
    let kind = entry.kind.as_deref().and_then(|k| {
        let kind = Kind::parse(k);
        if kind.is_none() {
            findings.push(format!("Exception {label} has an unknown kind {k}"));
        }
        kind
    });
    let mut date = |name: &str, value: Option<&str>| {
        value.and_then(|v| {
            let date = parse_date(v);
            if date.is_none() {
                findings.push(format!("Exception {label} has an invalid {name} date {v}"));
            }
            date
        })
    };
    let created = date("created", entry.created.as_deref());
    let expires = date("expires", entry.expires.as_deref());
    if let Some(issue) = &entry.issue
        && !issue_reference(issue)
    {
        findings.push(format!(
            "Exception {label} has an invalid issue reference {issue}"
        ));
    }
    if !findings.is_empty() {
        return Verdict::invalid(findings);
    }
    let (Some(kind), Some(created), Some(expires)) = (kind, created, expires) else {
        unreachable!("every field was present and valid");
    };
    let days = (expires - created).num_days();
    let bound = i64::from(kind.max_days(bypass_max_days));
    if days < 0 {
        return Verdict::invalid(vec![format!(
            "Exception {label} expires on {expires}, before it was created on {created}"
        )]);
    }
    if days > bound {
        return Verdict::invalid(vec![format!(
            "Exception {label} lasts {days} days; {} allows at most {bound}",
            kind.as_str()
        )]);
    }
    if expires < today {
        return Verdict {
            state: State::Expired,
            findings: vec![format!("Exception {label} expired on {expires}")],
        };
    }
    Verdict {
        state: State::Active,
        findings: Vec::new(),
    }
}

/// The defects `state` finds in `entry` without a clock: every check but the
/// expiry, for readers that have no `today` (rendering is pure; #1218).
pub fn defects(entry: &Entry) -> Vec<String> {
    let verdict = state(entry, NaiveDate::MIN, DEFAULT_BYPASS_MAX_DAYS);
    match verdict.state {
        State::Invalid => verdict.findings,
        State::Active | State::Expired => Vec::new(),
    }
}

/// What a line-wise reader returns: the entries of a file in the generated
/// shape, or the first line that leaves it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Shape<T> {
    Generated(T),
    Unverified { line: usize },
}

/// An entry of `.trivyignore.yaml` or `osv-scanner.toml`: id, native expiry
/// field and whether its free text names an issue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeEntry {
    pub file: &'static str,
    pub id: String,
    pub expiry: Option<String>,
    pub issue: bool,
}

impl NativeEntry {
    fn fields(&self) -> (&'static str, &'static str) {
        if self.file == TRIVY_IGNORE {
            ("expired_at", "statement")
        } else {
            ("ignoreUntil", "reason")
        }
    }
}

/// The state of a native entry: no expiry or a bad one, then no issue; then expired.
pub fn native_state(entry: &NativeEntry, today: NaiveDate) -> Verdict {
    let (expiry_field, issue_field) = entry.fields();
    let (id, file) = (&entry.id, entry.file);
    let mut findings = Vec::new();
    let expires = match entry.expiry.as_deref() {
        None => {
            findings.push(format!("Exception {id} in {file} has no {expiry_field}"));
            None
        }
        Some(value) => {
            let date = parse_date(value);
            if date.is_none() {
                findings.push(format!(
                    "Exception {id} in {file} has an invalid {expiry_field} date {value}"
                ));
            }
            date
        }
    };
    if !entry.issue {
        findings.push(format!(
            "Exception {id} in {file} has no issue in {issue_field}"
        ));
    }
    if !findings.is_empty() {
        return Verdict::invalid(findings);
    }
    let expires = expires.expect("validated above");
    if expires < today {
        return Verdict {
            state: State::Expired,
            findings: vec![format!("Exception {id} in {file} expired on {expires}")],
        };
    }
    Verdict {
        state: State::Active,
        findings: Vec::new(),
    }
}

fn unquote(value: &str) -> &str {
    let bytes = value.as_bytes();
    if bytes.len() >= 2
        && ((bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\''))
    {
        &value[1..value.len() - 1]
    } else {
        value
    }
}

/// A `.trivyignore.yaml` value as YAML reads it: a plain (unquoted) scalar
/// ends where a `#` at its start or after a blank starts a comment (#1195);
/// a quoted one is unquoted.
fn yaml_scalar(value: &str) -> &str {
    let value = value.trim();
    if value.starts_with(['"', '\'']) {
        return unquote(value);
    }
    let end = value
        .char_indices()
        .find(|&(i, c)| c == '#' && (i == 0 || value[..i].ends_with([' ', '\t'])))
        .map_or(value.len(), |(i, _)| i);
    value[..end].trim_end()
}

fn double_quoted(value: &str) -> Option<&str> {
    (value.len() >= 2 && value.starts_with('"') && value.ends_with('"'))
        .then(|| &value[1..value.len() - 1])
}

fn skip(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.is_empty() || trimmed.starts_with('#')
}

/// Lines of a file, numbered from 1, without trailing whitespace.
fn lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.lines()
        .enumerate()
        .map(|(i, line)| (i + 1, line.trim_end()))
}

/// `.trivyignore.yaml` in the generated shape: top-level sections
/// (`vulnerabilities:` and the other three, `[]` or a list), entries
/// `  - id: <id>` with `    statement:`, `    expired_at:` and the lists
/// `    paths:` / `    purls:` of `      - <item>` lines.
pub fn trivy_ignore(text: &str) -> Shape<Vec<NativeEntry>> {
    let mut entries = Vec::new();
    let mut current: Option<NativeEntry> = None;
    let (mut section, mut inline_empty, mut list) = (false, false, false);
    for (number, line) in lines(text) {
        if skip(line) || line == "---" {
            continue;
        }
        let unverified = Shape::Unverified { line: number };
        if let Some((key, tail)) = line.split_once(':')
            && TRIVY_SECTIONS.contains(&key)
            && matches!(tail.trim(), "" | "[]")
        {
            entries.extend(current.take());
            section = true;
            inline_empty = tail.trim() == "[]";
            list = false;
            continue;
        }
        if let Some(rest) = line.strip_prefix("  - id:") {
            let id = yaml_scalar(rest);
            if !section || inline_empty || id.is_empty() {
                return unverified;
            }
            entries.extend(current.take());
            current = Some(NativeEntry {
                file: TRIVY_IGNORE,
                id: id.to_string(),
                expiry: None,
                issue: false,
            });
            list = false;
            continue;
        }
        let Some(entry) = current.as_mut() else {
            return unverified;
        };
        if let Some(field) = line.strip_prefix("    ").filter(|f| !f.starts_with(' ')) {
            let Some((key, value)) = field.split_once(':') else {
                return unverified;
            };
            let value = yaml_scalar(value);
            match key {
                "statement" => {
                    entry.issue = mentions_issue(value);
                    list = false;
                }
                "expired_at" => {
                    entry.expiry = (!value.is_empty()).then(|| value.to_string());
                    list = false;
                }
                "paths" | "purls" if value.is_empty() => list = true,
                _ => return unverified,
            }
            continue;
        }
        if list
            && line
                .strip_prefix("      - ")
                .is_some_and(|item| !item.is_empty())
        {
            continue;
        }
        return unverified;
    }
    entries.extend(current);
    Shape::Generated(entries)
}

/// `osv-scanner.toml` in the generated shape: `[[IgnoredVulns]]` tables with
/// `id = "<id>"`, `ignoreUntil = <date>` (bare or quoted) and `reason = "<text>"`.
/// Any other table, `[[PackageOverrides]]` included, is outside the shape.
pub fn osv_config(text: &str) -> Shape<Vec<NativeEntry>> {
    let mut entries = Vec::new();
    let mut current: Option<(usize, NativeEntry)> = None;
    let flush =
        |current: &mut Option<(usize, NativeEntry)>, entries: &mut Vec<NativeEntry>| match current
            .take()
        {
            Some((header, entry)) if entry.id.is_empty() => {
                Some(Shape::Unverified { line: header })
            }
            Some((_, entry)) => {
                entries.push(entry);
                None
            }
            None => None,
        };
    for (number, line) in lines(text) {
        if skip(line) {
            continue;
        }
        if line == "[[IgnoredVulns]]" {
            if let Some(unverified) = flush(&mut current, &mut entries) {
                return unverified;
            }
            current = Some((
                number,
                NativeEntry {
                    file: OSV_CONFIG,
                    id: String::new(),
                    expiry: None,
                    issue: false,
                },
            ));
            continue;
        }
        let unverified = Shape::Unverified { line: number };
        let Some((_, entry)) = current.as_mut() else {
            return unverified;
        };
        let Some((key, value)) = line.split_once('=') else {
            return unverified;
        };
        let value = value.trim();
        match (key.trim(), double_quoted(value)) {
            ("id", Some(id)) => entry.id = id.to_string(),
            ("ignoreUntil", _) if !value.is_empty() => {
                entry.expiry = Some(unquote(value).to_string())
            }
            ("reason", Some(reason)) => entry.issue = mentions_issue(reason),
            _ => return unverified,
        }
    }
    if let Some(unverified) = flush(&mut current, &mut entries) {
        return unverified;
    }
    Shape::Generated(entries)
}

/// `.gitleaksignore` or `.semgrepignore`: one entry per non-blank, non-comment
/// line, as the inventory target `<file>#<entry>`.
pub fn ignore_lines(file: &str, text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| format!("{file}#{line}"))
        .collect()
}

fn toml_string(value: &str) -> Option<&str> {
    let value = value.strip_suffix(',').unwrap_or(value).trim_end();
    if value.len() >= 6 && value.starts_with("'''") && value.ends_with("'''") {
        return Some(&value[3..value.len() - 3]);
    }
    let bytes = value.as_bytes();
    (bytes.len() >= 2
        && ((bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\'')))
        .then(|| &value[1..value.len() - 1])
}

/// The `[allowlist]` table of `.gitleaks.toml` in the seeded shape: `description`
/// and `regexTarget` scalars, and arrays (`paths`, `regexes`, `commits`, …)
/// written `[]` or one quoted entry per line. Entries become the inventory
/// target `.gitleaks.toml#<key>:<value>`; other tables are not read.
pub fn gitleaks_allowlist(text: &str) -> Shape<Vec<String>> {
    let mut entries = Vec::new();
    let mut inside = false;
    let mut array: Option<&str> = None;
    for (number, raw) in lines(text) {
        let line = raw.trim_start();
        if skip(line) {
            continue;
        }
        let unverified = Shape::Unverified { line: number };
        if line.starts_with('[') {
            if array.is_some() {
                return unverified;
            }
            inside = line == "[allowlist]";
            continue;
        }
        if !inside {
            continue;
        }
        if let Some(key) = array {
            if line == "]" {
                array = None;
            } else if let Some(value) = toml_string(line) {
                entries.push(format!("{GITLEAKS_CONFIG}#{key}:{value}"));
            } else {
                return unverified;
            }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return unverified;
        };
        match (key.trim(), value.trim()) {
            ("description" | "regexTarget", _) | (_, "[]") => {}
            (key, "[") => array = Some(key),
            _ => return unverified,
        }
    }
    if array.is_some() {
        return Shape::Unverified {
            line: text.lines().count(),
        };
    }
    Shape::Generated(entries)
}

/// What the gate prints: one finding per line, then the claim line.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub findings: Vec<String>,
    pub active: usize,
    pub expired: usize,
    pub unregistered: usize,
}

impl Report {
    pub fn claim(&self) -> String {
        format!(
            "exceptions: {} active, {} expired, {} unregistered",
            self.active, self.expired, self.unregistered
        )
    }
    pub fn passed(&self) -> bool {
        self.findings.is_empty()
    }
    fn tally(&mut self, verdict: Verdict) {
        match verdict.state {
            State::Active => self.active += 1,
            State::Expired => self.expired += 1,
            State::Invalid => {}
        }
        self.findings.extend(verdict.findings);
    }
    fn native(&mut self, file: &str, shape: Shape<Vec<NativeEntry>>, today: NaiveDate) {
        match shape {
            Shape::Generated(entries) => {
                for entry in &entries {
                    self.tally(native_state(entry, today));
                }
            }
            Shape::Unverified { line } => self.findings.push(unverified(file, line)),
        }
    }
}

fn unverified(file: &str, line: usize) -> String {
    format!("{file} is unverified: line {line} is outside the generated shape")
}

fn read(root: &Path, name: &str) -> crate::Result<Option<String>> {
    match fs::read_to_string(root.join(name)) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// The whole exceptions check over a repository root without a pull-request
/// base: what `doctor` runs, so it never compares the coverage record.
pub fn check(root: &Path, today: NaiveDate, bypass_max_days: u32) -> crate::Result<Report> {
    check_against(root, None, today, bypass_max_days)
}

/// The coverage record: one line percentage per app (SPEC-security.md,
/// "Coverage ratchet as built").
pub const COVERAGE_RECORD: &str = ".agent-setup/coverage.json";

/// The apps of a record in the shape `{"schema": 1, "apps": {<id>: <number>}}`,
/// or `None` when the text is anything else.
pub fn coverage_record(text: &str) -> Option<Vec<(String, f64)>> {
    let doc: Value = serde_json::from_str(text).ok()?;
    if doc.get("schema").and_then(Value::as_f64) != Some(SCHEMA) {
        return None;
    }
    doc.get("apps")?
        .as_object()?
        .iter()
        .map(|(app, value)| value.as_f64().map(|v| (app.clone(), v)))
        .collect()
}

/// The decreases of the record from `base` to the working tree, one finding
/// per app unless an active `coverage-reset` targets the record.
fn coverage_decreases(
    root: &Path,
    base: &str,
    inventory: Option<&Inventory>,
    today: NaiveDate,
    bypass_max_days: u32,
) -> crate::Result<Vec<String>> {
    let Some(base) = coverage_record(base) else {
        return Ok(Vec::new());
    };
    let head = match read(root, COVERAGE_RECORD)? {
        None => Vec::new(),
        Some(text) => match coverage_record(&text) {
            Some(head) => head,
            None => return Ok(vec![format!("{COVERAGE_RECORD} does not parse")]),
        },
    };
    let reset = inventory.is_some_and(|inv| {
        inv.exceptions.iter().any(|e| {
            e.kind.as_deref() == Some(Kind::CoverageReset.as_str())
                && e.target.as_deref() == Some(COVERAGE_RECORD)
                && state(e, today, bypass_max_days).state == State::Active
        })
    });
    if reset {
        return Ok(Vec::new());
    }
    Ok(base
        .iter()
        .filter_map(|(app, old)| {
            let new = head.iter().find(|(a, _)| a == app).map(|(_, v)| *v);
            match new {
                Some(new) if new >= *old => None,
                Some(new) => Some(new.to_string()),
                None => Some("absent".to_owned()),
            }
            .map(|new| {
                format!(
                    "{COVERAGE_RECORD} lowers {app} from {old} to {new} without an active coverage-reset"
                )
            })
        })
        .collect())
}

/// The target prefix of a `coverage-reset` that lets one pull request through
/// `diff-coverage` (SPEC-security.md, "Changed-line coverage"; #978).
pub const DIFF_COVERAGE_TARGET: &str = "diff-coverage#";

/// What a pull request adds to the check: the base revision's coverage record
/// and inventory (`None` when absent there) and the pull request's number
/// (`None` on any other event). `exceptions-check.sh` reads the base with
/// `git show "$BASE_SHA:<path>"` and the number from `PR_NUMBER`.
#[derive(Clone, Copy, Debug, Default)]
pub struct PullRequest<'a> {
    pub coverage: Option<&'a str>,
    pub inventory: Option<&'a str>,
    pub number: Option<u64>,
}

/// The `coverage-reset` entries this pull request adds (ids absent from the
/// base inventory) whose target is `diff-coverage#<x>` with `<x>` not its number.
fn foreign_diff_coverage_resets(
    inventory: Option<&Inventory>,
    base: Option<&str>,
    number: u64,
) -> Vec<String> {
    let base_ids: Vec<String> = base
        .and_then(Inventory::parse)
        .map(|inv| inv.exceptions.into_iter().filter_map(|e| e.id).collect())
        .unwrap_or_default();
    let own = format!("{DIFF_COVERAGE_TARGET}{number}");
    inventory
        .map(|inv| inv.exceptions.as_slice())
        .unwrap_or_default()
        .iter()
        .filter(|e| e.id.as_ref().is_none_or(|id| !base_ids.contains(id)))
        .filter(|e| e.kind.as_deref() == Some(Kind::CoverageReset.as_str()))
        .filter_map(|e| e.target.as_deref().map(|t| (e, t)))
        .filter(|(_, target)| target.starts_with(DIFF_COVERAGE_TARGET) && *target != own)
        .map(|(e, target)| {
            format!(
                "Exception {} targets {target}; a coverage-reset added in pull request #{number} must target {own}",
                e.label()
            )
        })
        .collect()
}

/// The whole exceptions check over a repository root: inventory, native
/// files, the plain `.trivyignore`, allowlist registration, then, on a pull
/// request, the decreases of the coverage record against its base and the
/// `diff-coverage#<n>` resets it adds for another pull request; in the order
/// `exceptions-check.sh` prints them.
pub fn check_against(
    root: &Path,
    pull_request: Option<&PullRequest<'_>>,
    today: NaiveDate,
    bypass_max_days: u32,
) -> crate::Result<Report> {
    let mut report = Report::default();
    let mut registered: Vec<String> = Vec::new();
    let mut parsed: Option<Inventory> = None;
    if let Some(text) = read(root, INVENTORY)? {
        match Inventory::parse(&text) {
            None => report.findings.push(format!("{INVENTORY} does not parse")),
            Some(inventory) if inventory.schema.as_f64() != Some(SCHEMA) => report.findings.push(
                format!("{INVENTORY} has an unsupported schema {}", inventory.schema),
            ),
            Some(inventory) => {
                for entry in &inventory.exceptions {
                    report.tally(state(entry, today, bypass_max_days));
                }
                registered = inventory
                    .allowlist_targets()
                    .into_iter()
                    .map(str::to_string)
                    .collect();
                parsed = Some(inventory);
            }
        }
    }
    if let Some(text) = read(root, TRIVY_IGNORE)? {
        report.native(TRIVY_IGNORE, trivy_ignore(&text), today);
    }
    if let Some(text) = read(root, OSV_CONFIG)? {
        report.native(OSV_CONFIG, osv_config(&text), today);
    }
    if root.join(TRIVY_PLAIN).exists() {
        report.findings.push(format!(
            "{TRIVY_PLAIN} cannot carry an expiry; use {TRIVY_IGNORE}"
        ));
    }
    let unregistered = |report: &mut Report, file: &str, noun: &str, targets: Vec<String>| {
        for target in targets {
            if !registered.contains(&target) {
                let entry = &target[file.len() + 1..];
                report.unregistered += 1;
                report.findings.push(format!(
                    "{file} {noun} {entry} is not registered in {INVENTORY}"
                ));
            }
        }
    };
    if let Some(text) = read(root, GITLEAKS_IGNORE)? {
        let targets = ignore_lines(GITLEAKS_IGNORE, &text);
        unregistered(&mut report, GITLEAKS_IGNORE, "entry", targets);
    }
    if let Some(text) = read(root, SEMGREP_IGNORE)? {
        let targets = ignore_lines(SEMGREP_IGNORE, &text)
            .into_iter()
            .filter(|t| !SEMGREP_DEFAULTS.contains(&&t[SEMGREP_IGNORE.len() + 1..]))
            .collect();
        unregistered(&mut report, SEMGREP_IGNORE, "entry", targets);
    }
    if let Some(text) = read(root, GITLEAKS_CONFIG)? {
        match gitleaks_allowlist(&text) {
            Shape::Generated(targets) => {
                unregistered(&mut report, GITLEAKS_CONFIG, "allowlist entry", targets)
            }
            Shape::Unverified { line } => report.findings.push(unverified(GITLEAKS_CONFIG, line)),
        }
    }
    let Some(pull_request) = pull_request else {
        return Ok(report);
    };
    if let Some(base) = pull_request.coverage {
        let decreases = coverage_decreases(root, base, parsed.as_ref(), today, bypass_max_days)?;
        report.findings.extend(decreases);
    }
    if let Some(number) = pull_request.number {
        let foreign = foreign_diff_coverage_resets(parsed.as_ref(), pull_request.inventory, number);
        report.unregistered += foreign.len();
        report.findings.extend(foreign);
    }
    Ok(report)
}

/// The job that admits no variable bypass: a false positive of the secrets
/// scan is a registered `.gitleaksignore` fingerprint.
pub const SECRETS_GATE: &str = "security-gate";
pub const BYPASS_VARIABLE: &str = "SECURITY_BYPASS";

/// An active `job-bypass` granted to a job by `SECURITY_BYPASS`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    pub id: String,
    pub expires: String,
    pub issue: String,
}

/// What `bypass-variable.sh` prints: one `::error::` per finding, a warning
/// and a `bypass:` line per grant, `bypass: none` when the variable is empty.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BypassReport {
    pub findings: Vec<String>,
    pub granted: Vec<Grant>,
}

impl BypassReport {
    pub fn passed(&self) -> bool {
        self.findings.is_empty()
    }
    pub fn lines(&self) -> Vec<String> {
        let mut lines: Vec<String> = self
            .findings
            .iter()
            .map(|f| format!("::error::{f}"))
            .collect();
        for grant in &self.granted {
            lines.push(format!(
                "::warning::bypass {} until {} ({})",
                grant.id, grant.expires, grant.issue
            ));
            lines.push(format!("bypass: {}", grant.id));
        }
        if self.findings.is_empty() && self.granted.is_empty() {
            lines.push("bypass: none".to_string());
        }
        lines
    }
}

/// The ids of `SECURITY_BYPASS`: empty means none; anything but a JSON array
/// of non-empty strings is refused.
fn bypass_ids(variable: &str) -> Option<Vec<String>> {
    if variable.trim().is_empty() {
        return Some(Vec::new());
    }
    let Ok(Value::Array(items)) = serde_json::from_str::<Value>(variable) else {
        return None;
    };
    items
        .into_iter()
        .map(|item| match item {
            Value::String(s) if !s.is_empty() => Some(s),
            _ => None,
        })
        .collect()
}

/// The verdict of `SECURITY_BYPASS` for one job (SPEC-security.md, "Bypass
/// variable"): every named id must be a registered, valid, active `job-bypass`
/// whose target is this job; `security-gate` never runs it.
pub fn bypass(
    root: &Path,
    job: &str,
    variable: &str,
    today: NaiveDate,
    bypass_max_days: u32,
) -> crate::Result<BypassReport> {
    let mut report = BypassReport::default();
    if job == SECRETS_GATE {
        report
            .findings
            .push(format!("{SECRETS_GATE} admits no bypass variable"));
        return Ok(report);
    }
    let Some(ids) = bypass_ids(variable) else {
        report.findings.push(format!(
            "{BYPASS_VARIABLE} is not a JSON array of exception ids"
        ));
        return Ok(report);
    };
    if ids.is_empty() {
        return Ok(report);
    }
    let text = read(root, INVENTORY)?;
    let inventory = match text.as_deref().map(Inventory::parse) {
        None => None,
        Some(None) => {
            report.findings.push(format!("{INVENTORY} does not parse"));
            return Ok(report);
        }
        Some(Some(inventory)) if inventory.schema.as_f64() != Some(SCHEMA) => {
            report.findings.push(format!(
                "{INVENTORY} has an unsupported schema {}",
                inventory.schema
            ));
            return Ok(report);
        }
        Some(Some(inventory)) => Some(inventory),
    };
    for id in ids {
        let entry = inventory
            .as_ref()
            .and_then(|inv| inv.exceptions.iter().find(|e| e.id.as_deref() == Some(&id)));
        let Some(entry) = entry else {
            report
                .findings
                .push(format!("Bypass {id} is not registered in {INVENTORY}"));
            continue;
        };
        let verdict = state(entry, today, bypass_max_days);
        let finding = if verdict.state == State::Invalid {
            format!("Bypass {id} is not a valid exception; see {SECRETS_GATE}")
        } else if entry.kind.as_deref() != Some(Kind::JobBypass.as_str()) {
            format!(
                "Bypass {id} is a {} exception, not a job-bypass",
                entry.kind.as_deref().unwrap_or_default()
            )
        } else if entry.target.as_deref() != Some(job) {
            format!(
                "Bypass {id} targets {}, not {job}",
                entry.target.as_deref().unwrap_or_default()
            )
        } else if verdict.state == State::Expired {
            format!(
                "Bypass {id} expired on {}; remove the variable or renew the exception",
                entry.expires.as_deref().unwrap_or_default()
            )
        } else {
            report.granted.push(Grant {
                id,
                expires: entry.expires.clone().unwrap_or_default(),
                issue: entry.issue.clone().unwrap_or_default(),
            });
            continue;
        };
        report.findings.push(finding);
    }
    Ok(report)
}
