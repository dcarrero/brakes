#[cfg(feature = "setup-core")]
use crate::conventions;
use crate::{
    PROFILE, Result,
    auditor::rules::{Criticality, Level},
    destination, read, refuse,
};
use serde::{
    Deserialize, Deserializer,
    de::{MapAccess, Visitor},
};
use serde_json::Value;
use std::{fmt, path::Path};

// Keep the original command order: changing it would drift existing managed blocks.
const DEFAULT: &str = r#"{
  "purpose": "",
  "commands": {
    "verify": null,
    "test": null,
    "lint": null,
    "build": null,
    "preprod_up": null,
    "preprod_seed": null,
    "preprod_url": null,
    "preprod_down": null,
    "verify_deploy": null,
    "deploy_status": null
  },
  "conventions": [],
  "generated_paths": [],
  "environment_notes": [],
  "acceptance": {
    "scenarios_dir": null,
    "synthetic_profiles": null,
    "unsure_routes_to": null
  },
  "observability": {
    "alerts_dir": null,
    "runbooks_dir": null
  },
  "deploy_environments": [],
  "environment_manifests": {},
  "ci": {
    "required_checks": null,
    "shards": null,
    "tiers": null,
    "cycle_budget_minutes": null
  }
}
"#;

pub fn default_profile() -> Value {
    serde_json::from_str(DEFAULT).expect("default profile")
}
pub fn default_json() -> &'static str {
    DEFAULT
}

#[derive(Deserialize)]
struct Ordered {
    #[serde(deserialize_with = "command_names")]
    commands: Vec<String>,
}
fn command_names<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Vec<String>, D::Error> {
    struct Names;
    impl<'de> Visitor<'de> for Names {
        type Value = Vec<String>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("commands object")
        }
        fn visit_map<M: MapAccess<'de>>(
            self,
            mut map: M,
        ) -> std::result::Result<Self::Value, M::Error> {
            let mut names = Vec::new();
            while let Some((name, _)) = map.next_entry::<String, Value>()? {
                names.push(name);
            }
            Ok(names)
        }
    }
    d.deserialize_map(Names)
}

pub struct Profile {
    pub value: Value,
    pub raw: Option<String>,
    pub command_names: Vec<String>,
}

pub fn profile_for(root: &Path) -> Result<Profile> {
    profile_from(root, read(root, PROFILE)?)
}

/// The profile `raw` declares for `root`, validated as `profile_for` validates the
/// file; `None` is the default profile. `ci init` plans with the profile it is
/// about to write (#24).
pub fn profile_from(root: &Path, raw: Option<String>) -> Result<Profile> {
    let text = raw.as_deref().unwrap_or(DEFAULT);
    let mut value: Value = serde_json::from_str(text)?;
    if !value.is_object() || !value["commands"].is_object() {
        return refuse("Project profile must declare a commands object");
    }
    let mut names = serde_json::from_str::<Ordered>(text)?.commands;
    for name in ["verify_deploy", "deploy_status"] {
        if value["commands"].get(name).is_none() {
            value["commands"][name] = Value::Null;
            names.push(name.to_owned());
        }
    }
    // Optional fields a minimal profile leaves out (#1258): absent means empty;
    // a field that is present keeps its own type check below.
    let object = value.as_object_mut().expect("validated object");
    for key in [
        "conventions",
        "generated_paths",
        "environment_notes",
        "deploy_environments",
    ] {
        object.entry(key).or_insert(serde_json::json!([]));
    }
    object
        .entry("environment_manifests")
        .or_insert(serde_json::json!({}));
    if !value["purpose"].is_string() {
        return refuse("Project purpose must be a string");
    }
    for command in value["commands"].as_object().expect("commands").values() {
        if !command.is_null() && !command.as_str().is_some_and(single_line) {
            return refuse("Commands must be nonempty single-line strings or null");
        }
    }
    for key in [
        "generated_paths",
        "environment_notes",
        "deploy_environments",
    ] {
        if !value[key]
            .as_array()
            .is_some_and(|items| items.iter().all(Value::is_string))
        {
            return refuse(format!("Project {key} must be a list of strings"));
        }
    }
    let environments = strings(&value["deploy_environments"]);
    let unique: std::collections::BTreeSet<_> = environments.iter().collect();
    if environments.iter().any(|s| !single_line(s)) || unique.len() != environments.len() {
        return refuse("Deploy environments must be unique nonempty single-line strings");
    }
    let Some(manifests) = value["environment_manifests"].as_object() else {
        return refuse("Environment manifests must map declared environments to paths");
    };
    for (environment, path) in manifests {
        if !environments.contains(&environment.as_str()) || !path.as_str().is_some_and(single_line)
        {
            return refuse("Environment manifests must map declared environments to paths");
        }
        destination(root, path.as_str().expect("manifest path"))?;
    }
    #[cfg(feature = "setup-core")]
    conventions::validate(root, &value["conventions"])?;
    let acceptance = &value["acceptance"];
    if !acceptance.is_null() {
        if !acceptance.is_object() {
            return refuse("Project acceptance block must be an object");
        }
        for key in ["scenarios_dir", "synthetic_profiles", "unsure_routes_to"] {
            let v = &acceptance[key];
            if !v.is_null() && !v.as_str().is_some_and(|s| !s.trim().is_empty()) {
                return refuse(format!(
                    "Project acceptance.{key} must be a non-empty string or null"
                ));
            }
        }
    }
    let excluded = &value["excluded_paths"];
    if !excluded.is_null() {
        if !excluded
            .as_array()
            .is_some_and(|items| items.iter().all(Value::is_string))
        {
            return refuse("Project excluded_paths must be a list of strings");
        }
        for path in strings(excluded) {
            if !single_line(path)
                || normal(path).is_empty()
                || crate::scope::location(root, path).is_err()
            {
                return refuse(format!(
                    "Project excluded_paths must name paths inside the repository other than its root (got {path:?})"
                ));
            }
        }
    }
    let days = &value["guide_verification_days"];
    if !days.is_null() && !days.as_u64().is_some_and(|d| d > 0) {
        return refuse("Project guide_verification_days must be a positive integer");
    }
    let observability = &value["observability"];
    if !observability.is_null() {
        if !observability.is_object() {
            return refuse("Project observability block must be an object");
        }
        for key in ["alerts_dir", "runbooks_dir"] {
            let v = &observability[key];
            if !v.is_null() && !v.as_str().is_some_and(single_line) {
                return refuse(format!(
                    "Project observability.{key} must be a non-empty single-line string or null"
                ));
            }
            if let Some(path) = v.as_str() {
                crate::directory(root, path)?;
            }
        }
    }
    audit_fields(&value)?;
    Ok(Profile {
        value,
        raw,
        command_names: names,
    })
}

/// The paths `excluded_paths` declares as not the project's files (#16),
/// normalized (`./templates/` is `templates`); empty when absent.
pub fn excluded_paths(value: &Value) -> Vec<String> {
    strings(&value["excluded_paths"])
        .into_iter()
        .map(normal)
        .collect()
}

/// The declared excluded paths of the profile at `root`; empty when the
/// profile does not load, so an invalid declaration excludes nothing.
pub fn excluded_paths_at(root: &Path) -> Vec<String> {
    profile_for(root)
        .map(|profile| excluded_paths(&profile.value))
        .unwrap_or_default()
}

/// Whether the repository path `path` is at or under one of `declared`.
pub fn is_excluded(declared: &[String], path: &str) -> bool {
    declared.iter().any(|excluded| {
        path.strip_prefix(excluded.as_str())
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
    })
}

/// `doctor`'s line for each declared excluded path: information, never a finding.
pub fn exclusion_lines(value: &Value) -> Vec<String> {
    excluded_paths(value)
        .into_iter()
        .map(|path| {
            format!(
                "EXCLUDED [project.excluded_paths] {path} — not the project's files ({PROFILE})"
            )
        })
        .collect()
}

/// `path` without `.` components or trailing slashes: `.` and `./` are empty.
fn normal(path: &str) -> String {
    Path::new(path)
        .components()
        .filter(|c| *c != std::path::Component::CurDir)
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

/// An owner-recorded interim level that governs the exit code until `expires`
/// (decision "Auditor standard v1", point 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptedLevel {
    pub level: Level,
    pub expires: chrono::NaiveDate,
}

/// The optional profile fields the auditor reads: `criticality`,
/// `audit.agent_accounts` and `audit.accepted_level`. An absent or null
/// `criticality` is `None` (undeclared).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditFields {
    pub criticality: Option<Criticality>,
    pub agent_accounts: Vec<String>,
    pub accepted_level: Option<AcceptedLevel>,
}

/// Validates and reads the auditor's fields; unknown values are refused naming
/// what is allowed.
pub fn audit_fields(value: &Value) -> Result<AuditFields> {
    let criticality = match &value["criticality"] {
        Value::Null => None,
        other => match other.as_str().and_then(Criticality::parse) {
            Some(c) => Some(c),
            None => {
                return refuse(format!(
                    "Project criticality must be one of {} (got {other})",
                    Criticality::NAMES.join(", ")
                ));
            }
        },
    };
    let audit = &value["audit"];
    if audit.is_null() {
        return Ok(AuditFields {
            criticality,
            ..AuditFields::default()
        });
    }
    if !audit.is_object() {
        return refuse("Project audit block must be an object");
    }
    let accounts = &audit["agent_accounts"];
    if !accounts.is_null()
        && !accounts
            .as_array()
            .is_some_and(|items| items.iter().all(|a| a.as_str().is_some_and(login)))
    {
        return refuse("Project audit.agent_accounts must be a list of logins");
    }
    let accepted = &audit["accepted_level"];
    let accepted_level = if accepted.is_null() {
        None
    } else {
        if !accepted.is_object() {
            return refuse("Project audit.accepted_level must be an object with level and expires");
        }
        let Some(level) = accepted["level"].as_str().and_then(Level::parse) else {
            return refuse(format!(
                "Project audit.accepted_level.level must be one of {}",
                Level::ALL.map(|l| l.to_string()).join(", ")
            ));
        };
        let Some(expires) = accepted["expires"]
            .as_str()
            .and_then(|d| chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d").ok())
        else {
            return refuse("Project audit.accepted_level.expires must be a YYYY-MM-DD date");
        };
        Some(AcceptedLevel { level, expires })
    };
    Ok(AuditFields {
        criticality,
        agent_accounts: strings(accounts).into_iter().map(str::to_owned).collect(),
        accepted_level,
    })
}

fn login(s: &str) -> bool {
    !s.is_empty() && !s.chars().any(char::is_whitespace)
}

/// Days after which an installed guide's last-verified date is stale.
pub const DEFAULT_GUIDE_VERIFICATION_DAYS: u64 = 180;

pub fn guide_verification_days(value: &Value) -> u64 {
    value["guide_verification_days"]
        .as_u64()
        .unwrap_or(DEFAULT_GUIDE_VERIFICATION_DAYS)
}

pub fn single_line(s: &str) -> bool {
    !s.trim().is_empty() && !s.contains('\n')
}
pub fn strings(value: &Value) -> Vec<&str> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect()
}

/// `text` with each `commands.<name>` value that is the literal `null` replaced
/// by its command as a JSON string; every other byte is kept (decision
/// 2026-10-28, point 8: only `null` fields are written, never a declared one).
/// A field that is absent or not `null` refuses naming it and `path`.
pub fn fill_null_commands(text: &str, path: &str, fills: &[(&str, &str)]) -> Result<String> {
    let commands = members(text, 0)
        .and_then(|top| top.get("commands").copied())
        .and_then(|(start, _)| members(text, start));
    let Some(commands) = commands else {
        return refuse(format!(
            "stack-packs: {path} must be a JSON object with a commands object"
        ));
    };
    let mut spans = Vec::new();
    for (name, command) in fills {
        match commands.get(*name) {
            None => {
                return refuse(format!(
                    "stack-packs: commands.{name} is absent from {path}; declare it as null to accept its proposal"
                ));
            }
            Some(&(start, end)) if &text[start..end] != "null" => {
                return refuse(format!(
                    "stack-packs: commands.{name} in {path} is declared ({}); --accept-commands fills only null fields",
                    &text[start..end]
                ));
            }
            Some(&span) => spans.push((span, serde_json::to_string(command)?)),
        }
    }
    spans.sort();
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    for ((start, end), value) in spans {
        out.push_str(&text[at..start]);
        out.push_str(&value);
        at = end;
    }
    out.push_str(&text[at..]);
    Ok(out)
}

/// The byte span of each member value of the JSON object starting at `start`
/// (the last one wins on a repeated key, as `serde_json` reads it); `None` when
/// the text there is not an object.
fn members(text: &str, start: usize) -> Option<std::collections::BTreeMap<String, (usize, usize)>> {
    let bytes = text.as_bytes();
    let skip = |mut i: usize| {
        while bytes.get(i).is_some_and(u8::is_ascii_whitespace) {
            i += 1;
        }
        i
    };
    let mut i = skip(start);
    if bytes.get(i) != Some(&b'{') {
        return None;
    }
    let mut found = std::collections::BTreeMap::new();
    i = skip(i + 1);
    if bytes.get(i) == Some(&b'}') {
        return Some(found);
    }
    loop {
        let key_end = value_end(bytes, i)?;
        let key: String = serde_json::from_str(&text[i..key_end]).ok()?;
        i = skip(key_end);
        if bytes.get(i) != Some(&b':') {
            return None;
        }
        let value = skip(i + 1);
        let end = value_end(bytes, value)?;
        found.insert(key, (value, end));
        i = skip(end);
        match bytes.get(i) {
            Some(b',') => i = skip(i + 1),
            Some(b'}') => return Some(found),
            _ => return None,
        }
    }
}

/// The end of the JSON value starting at `i`: a string, an object or array
/// (strings inside skipped), or a scalar up to the next delimiter.
fn value_end(bytes: &[u8], i: usize) -> Option<usize> {
    let string_end = |mut j: usize| {
        j += 1;
        while let Some(&b) = bytes.get(j) {
            match b {
                b'\\' => j += 2,
                b'"' => return Some(j + 1),
                _ => j += 1,
            }
        }
        None
    };
    match *bytes.get(i)? {
        b'"' => string_end(i),
        b'{' | b'[' => {
            let (mut depth, mut j) = (0usize, i);
            while let Some(&b) = bytes.get(j) {
                match b {
                    b'"' => {
                        j = string_end(j)?;
                        continue;
                    }
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth -= 1;
                        if depth == 0 {
                            return Some(j + 1);
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
            None
        }
        _ => Some(
            i + bytes[i..]
                .iter()
                .position(|b| b.is_ascii_whitespace() || matches!(b, b',' | b'}' | b']'))
                .unwrap_or(bytes.len() - i),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile_of(text: &str) -> Result<Profile> {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".agent-setup")).unwrap();
        std::fs::write(dir.path().join(PROFILE), text).unwrap();
        profile_for(dir.path())
    }

    /// A new user's profile names its purpose and its verify command; every other
    /// field is optional and reads as empty (#1258).
    #[test]
    fn a_minimal_profile_reads_with_empty_optional_fields() {
        let profile =
            profile_of(r#"{"purpose": "A toy library.", "commands": {"verify": "make check"}}"#)
                .unwrap();
        for key in [
            "conventions",
            "generated_paths",
            "environment_notes",
            "deploy_environments",
        ] {
            assert_eq!(profile.value[key], serde_json::json!([]), "{key}");
        }
        assert_eq!(profile.value["commands"]["verify"], "make check");
        assert_eq!(audit_fields(&profile.value).unwrap().criticality, None);
    }

    /// Optional is not unchecked: a field that is present keeps its type rule.
    #[test]
    fn a_present_optional_field_of_the_wrong_type_is_still_refused() {
        for (key, value) in [
            ("generated_paths", "\"dist\""),
            ("environment_notes", "[1]"),
            ("deploy_environments", "{}"),
        ] {
            let text =
                format!(r#"{{"purpose": "p", "commands": {{"verify": "v"}}, "{key}": {value}}}"#);
            let error = profile_of(&text).err().expect(key).to_string();
            assert!(error.contains(key), "{key}: {error}");
        }
    }

    /// #16: `excluded_paths` lists repository paths that are not the root.
    #[test]
    fn excluded_paths_are_repository_paths_other_than_the_root() {
        let of = |value: &str| {
            profile_of(&format!(
                r#"{{"purpose": "p", "commands": {{"verify": "v"}}, "excluded_paths": {value}}}"#
            ))
        };
        let profile = of(r#"["templates", "tests/fixtures/"]"#).unwrap();
        assert_eq!(
            excluded_paths(&profile.value),
            ["templates", "tests/fixtures"]
        );
        for value in [
            r#""templates""#,
            "[1]",
            r#"[""]"#,
            r#"["."]"#,
            r#"["./"]"#,
            r#"["/etc"]"#,
            r#"["../other"]"#,
            r#"["a\nb"]"#,
        ] {
            let error = of(value).err().expect(value).to_string();
            assert!(error.contains("excluded_paths"), "{value}: {error}");
        }
    }

    #[test]
    fn a_path_is_excluded_at_or_under_a_declared_one_only() {
        let declared = ["templates".to_owned(), "tests/fixtures".to_owned()];
        for (path, expected) in [
            ("templates", true),
            ("templates/go/Dockerfile", true),
            ("tests/fixtures/svc/Dockerfile", true),
            ("templates.d/Dockerfile", false),
            ("tests/Dockerfile", false),
            ("Dockerfile", false),
        ] {
            assert_eq!(is_excluded(&declared, path), expected, "{path}");
        }
    }
}
