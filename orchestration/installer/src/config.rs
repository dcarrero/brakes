//! The user's configuration (`SPEC-product-boundary.md`, "Configuration contract";
//! plan T2, #1046): everything personal the installer used to hard-code becomes a
//! value the user supplies. The product ships no value for any of them: the empty
//! configuration refuses every write (empty allowlist) and denies nothing (empty
//! denylist).
//!
//! Lookup, first found wins: (1) the file embedded at build time, only when the build
//! sets `BRAKES_EMBEDDED_CONFIG` (`build.rs`); (2) `--config <path>`;
//! (3) `$XDG_CONFIG_HOME/brakes/config.json` (`$HOME/.config` when unset). Never the
//! target repository, never a run-time environment variable carrying values. No file
//! at all is the empty configuration. Every level refuses unknown keys.
//!
//! Read through [`current`]: the scope sites (T3) use it; the host, auditor and runner
//! sites follow (T4, T5).

use crate::{Result, refuse};
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// The file `build.rs` embedded, if any (empty string when none).
const EMBEDDED: &str = include_str!(concat!(env!("OUT_DIR"), "/embedded-config.json"));

/// The refusal a binary without any configuration gives for every write.
pub const NO_CONFIGURATION: &str = "No configuration: writes refused. Declare owner and write_allowlist in a configuration file (--config <path> or $XDG_CONFIG_HOME/brakes/config.json), or build with BRAKES_EMBEDDED_CONFIG";

pub const SCHEMA: u64 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Host {
    pub kind: String,
    pub hostname: String,
}

impl Default for Host {
    fn default() -> Self {
        Self {
            kind: "github".into(),
            hostname: "github.com".into(),
        }
    }
}

/// A runner the user names for `ci-baseline`'s answers: the answer value and the
/// `runs-on` label it renders. GitHub-hosted runners need no entry.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedRunner {
    pub name: String,
    pub label: String,
}

/// The user's own runners: when present each is the default of its answer and the
/// label actionlint is told about; when absent only GitHub-hosted runners exist.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Runners {
    #[serde(default)]
    pub linux: Option<NamedRunner>,
    #[serde(default)]
    pub macos: Option<NamedRunner>,
    /// A larger Linux runner `security`'s `coverage_runner: large` moves the
    /// coverage jobs to (#1344); absent, they stay on `linux`.
    #[serde(default)]
    pub linux_large: Option<NamedRunner>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema: u64,
    #[serde(default)]
    pub host: Host,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub write_allowlist: Vec<String>,
    #[serde(default)]
    pub identity_denylist: Vec<String>,
    #[serde(default)]
    pub runners: Runners,
    #[serde(default)]
    pub presets_dir: Option<PathBuf>,
    #[serde(default)]
    pub schema_base_url: Option<String>,
    /// `owner/name` of the repository hosting the reusable verify workflow that
    /// `ci-baseline`'s `reusable: true` calls; none means nothing is called (#1201).
    #[serde(default)]
    pub reusable_callee: Option<String>,
}

/// Where the configuration in effect came from, for `doctor` and error messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    Embedded,
    Explicit(PathBuf),
    User(PathBuf),
    None,
}

impl Config {
    /// No owner, nothing writable, nothing denied, GitHub.
    pub fn empty() -> Self {
        Self {
            schema: SCHEMA,
            ..Self::default()
        }
    }

    /// A configuration for tests: the literals live in the test, not in the code.
    pub fn for_test(owner: &str, write_allowlist: &[&str], identity_denylist: &[&str]) -> Self {
        Self {
            owner: Some(owner.to_owned()),
            write_allowlist: write_allowlist.iter().map(|s| (*s).to_owned()).collect(),
            identity_denylist: identity_denylist.iter().map(|s| s.to_lowercase()).collect(),
            ..Self::empty()
        }
    }

    /// Parse and validate one configuration file's text.
    pub fn parse(text: &str) -> Result<Self> {
        let mut config: Config =
            serde_json::from_str(text).map_err(|e| format!("Configuration refused: {e}"))?;
        if config.schema != SCHEMA {
            return refuse(format!(
                "Configuration refused: schema {} is not supported (expected {SCHEMA})",
                config.schema
            ));
        }
        if config.host.kind != "github" {
            return refuse(format!(
                "Configuration refused: host kind {} is not supported",
                config.host.kind
            ));
        }
        for entry in &config.write_allowlist {
            let Some((owner, name)) = entry.split_once('/') else {
                return refuse(format!(
                    "Configuration refused: write_allowlist entry {entry} is not owner/name or owner/*"
                ));
            };
            if owner.is_empty() || owner == "*" || name.is_empty() || name.contains('/') {
                return refuse(format!(
                    "Configuration refused: write_allowlist entry {entry} is not owner/name or owner/*"
                ));
            }
        }
        for runner in [&config.runners.linux, &config.runners.macos]
            .into_iter()
            .flatten()
        {
            let reserved = ["github", "github-hosted"].contains(&runner.name.as_str());
            if runner.name.trim().is_empty()
                || runner.label.trim().is_empty()
                || reserved
                || runner.label.contains("self-hosted")
            {
                return refuse(format!(
                    "Configuration refused: runner {} needs a name other than github or github-hosted and a label without self-hosted",
                    runner.name
                ));
            }
        }
        if let Some(callee) = &config.reusable_callee {
            let valid = callee.split_once('/').is_some_and(|(owner, name)| {
                [owner, name]
                    .iter()
                    .all(|s| !s.is_empty() && !s.contains(['/', '*']))
            });
            if !valid {
                return refuse(format!(
                    "Configuration refused: reusable_callee {callee} is not owner/name"
                ));
            }
        }
        if config.identity_denylist.iter().any(|w| w.trim().is_empty()) {
            return refuse("Configuration refused: identity_denylist has an empty entry");
        }
        config.identity_denylist = config
            .identity_denylist
            .iter()
            .map(|w| w.trim().to_lowercase())
            .collect();
        Ok(config)
    }

    /// The lookup with every input explicit, so each step is testable.
    pub fn resolve(
        embedded: &str,
        explicit: Option<&Path>,
        user_dir: Option<&Path>,
    ) -> Result<(Self, Origin)> {
        if !embedded.trim().is_empty() {
            return Ok((Self::parse(embedded)?, Origin::Embedded));
        }
        if let Some(path) = explicit {
            let text = std::fs::read_to_string(path)
                .map_err(|e| format!("Configuration refused: {}: {e}", path.display()))?;
            return Ok((Self::parse(&text)?, Origin::Explicit(path.to_owned())));
        }
        if let Some(dir) = user_dir {
            let path = dir.join("brakes/config.json");
            if path.is_file() {
                let text = std::fs::read_to_string(&path)?;
                return Ok((Self::parse(&text)?, Origin::User(path)));
            }
        }
        Ok((Self::empty(), Origin::None))
    }

    /// The configuration in effect for this process.
    pub fn load(explicit: Option<&Path>) -> Result<(Self, Origin)> {
        let user_dir = std::env::var_os("XDG_CONFIG_HOME")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")));
        Self::resolve(EMBEDDED, explicit, user_dir.as_deref())
    }

    /// The configured owner, or "" when none is configured.
    pub fn owner(&self) -> &str {
        self.owner.as_deref().unwrap_or_default()
    }

    /// Whether a lowercased `owner/name` identity is in the write allowlist; the
    /// comparison ignores case and never matches a wildcard against a nested path.
    pub fn write_allowed(&self, identity: &str) -> bool {
        let identity = identity.to_lowercase();
        let Some((owner, name)) = identity.split_once('/') else {
            return false;
        };
        if name.is_empty() || name.contains('/') {
            return false;
        }
        self.write_allowlist.iter().any(|entry| {
            let entry = entry.to_lowercase();
            entry
                .strip_suffix("/*")
                .map_or(entry == identity, |allowed_owner| allowed_owner == owner)
        })
    }

    /// The denylist entry `text` contains (case-insensitive), capitalised for the
    /// refusal message, or `None`.
    pub fn refused_word(&self, text: &str) -> Option<String> {
        let lower = text.to_lowercase();
        self.identity_denylist
            .iter()
            .find(|word| lower.contains(word.as_str()))
            .map(|word| {
                let mut chars = word.chars();
                chars
                    .next()
                    .map(|c| c.to_uppercase().chain(chars).collect())
                    .unwrap_or_default()
            })
    }

    /// Whether this binary carries an embedded configuration.
    pub fn embedded() -> bool {
        !EMBEDDED.trim().is_empty()
    }
}

static CURRENT: std::sync::OnceLock<std::result::Result<Config, String>> =
    std::sync::OnceLock::new();

/// The configuration in effect for this process, loaded once (`Config::load(None)`)
/// unless [`install`] or [`install_from`] set it first.
pub fn current() -> Result<&'static Config> {
    match CURRENT.get_or_init(|| {
        Config::load(None)
            .map(|(c, _)| c)
            .map_err(|e| e.to_string())
    }) {
        Ok(config) => Ok(config),
        Err(e) => refuse(e.clone()),
    }
}

/// Sets the configuration in effect, once, before anything reads it: for tests and
/// for `--config`. Refused when a different configuration is already in effect; an
/// embedded configuration still wins, as in the lookup order.
pub fn install(config: Config) -> Result<()> {
    let config = if Config::embedded() {
        Config::parse(EMBEDDED)?
    } else {
        config
    };
    match CURRENT.set(Ok(config.clone())) {
        Ok(()) => Ok(()),
        Err(_) if CURRENT.get().is_some_and(|c| c.as_ref() == Ok(&config)) => Ok(()),
        Err(_) => refuse("Configuration refused: another configuration is already in effect"),
    }
}

/// `--config <path>`: the lookup with the explicit step, installed for the process.
pub fn install_from(path: &Path) -> Result<()> {
    let (config, _) = Config::load(Some(path))?;
    install(config)
}

/// The denylist word `text` names under the configuration in effect (capitalised),
/// or `None`; a configuration that cannot load is an error, never "nothing denied".
pub fn denied_word(text: &str) -> Result<Option<String>> {
    Ok(current()?.refused_word(text))
}

/// Refuses a repository identity or remote URL that names a denylist word, with the
/// message the gates have always used: "<Word> repository refused, regardless of
/// remote owner".
pub fn refuse_denied_repository(text: &str) -> Result<()> {
    match denied_word(text)? {
        Some(word) => refuse(format!(
            "{word} repository refused, regardless of remote owner"
        )),
        None => Ok(()),
    }
}

/// The configured Linux runner in effect, if any (none when the configuration
/// cannot load: only GitHub-hosted runners are then offered).
pub fn linux_runner() -> Option<&'static NamedRunner> {
    current().ok().and_then(|c| c.runners.linux.as_ref())
}

/// The configured large Linux runner in effect, if any (#1344).
pub fn linux_large_runner() -> Option<&'static NamedRunner> {
    current().ok().and_then(|c| c.runners.linux_large.as_ref())
}

/// The configured macOS runner in effect, if any.
pub fn macos_runner() -> Option<&'static NamedRunner> {
    current().ok().and_then(|c| c.runners.macos.as_ref())
}

/// The base of a rendered JSON schema's `$id` when `schema_base_url` is unset: the
/// product's own templates (SPEC-product-boundary.md, Configuration contract).
pub const PRODUCT_SCHEMA_BASE_URL: &str =
    "https://github.com/gemba-app/brakes/blob/main/templates/";

/// The configured `schema_base_url` in effect, if any (none when the configuration
/// cannot load: the product's own base is then rendered).
pub fn schema_base_url() -> Option<&'static str> {
    current().ok().and_then(|c| c.schema_base_url.as_deref())
}

/// The configured callee of the reusable verify workflow, if any (none when the
/// configuration cannot load: nothing is then called).
pub fn reusable_callee() -> Option<&'static str> {
    current().ok().and_then(|c| c.reusable_callee.as_deref())
}

/// The configured owner in effect, or "" when none is configured or it cannot load.
pub fn current_owner() -> String {
    current().map(|c| c.owner().to_owned()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const MINIMAL: &str = r#"{"schema": 1}"#;

    #[test]
    fn the_empty_configuration_has_no_owner_no_writes_and_no_denials() {
        let config = Config::empty();
        assert_eq!(config.owner, None);
        assert!(config.write_allowlist.is_empty());
        assert!(config.identity_denylist.is_empty());
        assert_eq!(config.reusable_callee, None);
        assert_eq!(config.host, Host::default());
        assert_eq!(Config::parse(MINIMAL).unwrap(), config);
    }

    #[test]
    fn a_full_file_parses_and_lowercases_the_denylist() {
        let config = Config::parse(
            r#"{"schema": 1, "host": {"kind": "github", "hostname": "github.com"},
                "owner": "example-owner",
                "write_allowlist": ["example-owner/*", "example-org/example-app"],
                "identity_denylist": [" Example-Corp "],
                "runners": {"linux": {"name": "custom", "label": "custom-2"}, "macos": {"name": "macfarm", "label": "mac-1"}},
                "presets_dir": "presets", "schema_base_url": "https://example.invalid/t/",
                "reusable_callee": "example-owner/workflows"}"#,
        )
        .unwrap();
        assert_eq!(config.owner.as_deref(), Some("example-owner"));
        assert_eq!(
            config.reusable_callee.as_deref(),
            Some("example-owner/workflows")
        );
        assert_eq!(config.identity_denylist, vec!["example-corp"]);
        assert_eq!(config.runners.linux.as_ref().unwrap().label, "custom-2");
        assert_eq!(config.runners.macos.as_ref().unwrap().name, "macfarm");
    }

    #[test]
    fn unknown_keys_are_refused_at_every_level() {
        for text in [
            r#"{"schema": 1, "ownr": "x"}"#,
            r#"{"schema": 1, "host": {"kind": "github", "hostname": "github.com", "token": "x"}}"#,
            r#"{"schema": 1, "runners": {"linux": {"name": "a", "label": "b", "arch": "x"}}}"#,
        ] {
            let err = Config::parse(text).unwrap_err().to_string();
            assert!(err.contains("unknown field"), "{text}: {err}");
        }
    }

    #[test]
    fn schema_host_allowlist_and_denylist_shapes_are_validated() {
        for text in [
            r#"{}"#,
            r#"{"schema": 2}"#,
            r#"{"schema": 1, "host": {"kind": "gitlab", "hostname": "x"}}"#,
            r#"{"schema": 1, "write_allowlist": ["*/*"]}"#,
            r#"{"schema": 1, "write_allowlist": ["owner"]}"#,
            r#"{"schema": 1, "write_allowlist": ["owner/a/b"]}"#,
            r#"{"schema": 1, "identity_denylist": [" "]}"#,
            r#"{"schema": 1, "runners": {"linux": {"name": "github", "label": "x"}}}"#,
            r#"{"schema": 1, "runners": {"macos": {"name": "m", "label": "self-hosted"}}}"#,
            r#"{"schema": 1, "runners": {"linux": {"name": "a", "label": " "}}}"#,
            r#"{"schema": 1, "reusable_callee": "owner"}"#,
            r#"{"schema": 1, "reusable_callee": "owner/*"}"#,
            r#"{"schema": 1, "reusable_callee": "owner/a/b"}"#,
            r#"{"schema": 1, "reusable_callee": "/name"}"#,
        ] {
            assert!(Config::parse(text).is_err(), "accepted {text}");
        }
    }

    #[test]
    fn embedded_wins_over_explicit_and_user() {
        let dir = tempfile::tempdir().unwrap();
        let explicit = dir.path().join("explicit.json");
        fs::write(&explicit, r#"{"schema": 1, "owner": "explicit"}"#).unwrap();
        let (config, origin) = Config::resolve(
            r#"{"schema": 1, "owner": "embedded"}"#,
            Some(&explicit),
            Some(dir.path()),
        )
        .unwrap();
        assert_eq!(
            (config.owner.as_deref(), origin),
            (Some("embedded"), Origin::Embedded)
        );
    }

    #[test]
    fn explicit_wins_over_user_and_a_missing_explicit_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("brakes")).unwrap();
        fs::write(
            dir.path().join("brakes/config.json"),
            r#"{"schema": 1, "owner": "user"}"#,
        )
        .unwrap();
        let explicit = dir.path().join("explicit.json");
        fs::write(&explicit, r#"{"schema": 1, "owner": "explicit"}"#).unwrap();
        let (config, origin) = Config::resolve("", Some(&explicit), Some(dir.path())).unwrap();
        assert_eq!(config.owner.as_deref(), Some("explicit"));
        assert_eq!(origin, Origin::Explicit(explicit));
        assert!(Config::resolve("", Some(&dir.path().join("absent.json")), None).is_err());
    }

    #[test]
    fn the_user_file_is_read_and_its_absence_is_the_empty_configuration() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            Config::resolve("", None, Some(dir.path())).unwrap(),
            (Config::empty(), Origin::None)
        );
        fs::create_dir_all(dir.path().join("brakes")).unwrap();
        fs::write(
            dir.path().join("brakes/config.json"),
            r#"{"schema": 1, "owner": "user"}"#,
        )
        .unwrap();
        let (config, origin) = Config::resolve("", None, Some(dir.path())).unwrap();
        assert_eq!(config.owner.as_deref(), Some("user"));
        assert_eq!(origin, Origin::User(dir.path().join("brakes/config.json")));
    }

    #[test]
    fn the_embedded_configuration_if_any_is_valid() {
        let (config, origin) = Config::resolve(EMBEDDED, None, None).unwrap();
        assert_eq!(origin == Origin::Embedded, Config::embedded());
        assert_eq!(config.schema, SCHEMA);
    }

    #[test]
    fn install_is_set_once_and_keeps_an_equal_configuration() {
        // `current()` may already hold the test configuration; installing it again is
        // accepted, a different one is refused.
        let in_effect = current().unwrap().clone();
        assert!(install(in_effect.clone()).is_ok());
        if !Config::embedded() {
            let other = Config::for_test("someone-else", &[], &[]);
            assert!(
                install(other)
                    .unwrap_err()
                    .to_string()
                    .contains("already in effect")
            );
        }
    }

    #[test]
    fn the_empty_configuration_allows_no_write_and_refuses_no_word() {
        let empty = Config::empty();
        for identity in ["example-owner/app", "a/b", "x/*"] {
            assert!(!empty.write_allowed(identity), "{identity}");
        }
        assert_eq!(empty.refused_word("anything/at-all"), None);
        assert_eq!(empty.owner(), "");
    }

    #[test]
    fn write_allowed_matches_wildcards_and_exact_entries_only() {
        let config = Config::for_test(
            "example-owner",
            &["Example-Owner/*", "example-org/app"],
            &[],
        );
        for yes in ["example-owner/x", "EXAMPLE-OWNER/Y", "example-org/app"] {
            assert!(config.write_allowed(yes), "{yes}");
        }
        for no in [
            "example-org/other",
            "example-owner/a/b",
            "example-owner/",
            "example-owner",
            "other/x",
        ] {
            assert!(!config.write_allowed(no), "{no}");
        }
    }

    #[test]
    fn refused_word_finds_a_denylisted_substring_and_capitalises_it() {
        let config = Config::for_test("o", &[], &["example-corp"]);
        assert_eq!(
            config
                .refused_word("https://github.com/Example-Corp-Labs/x")
                .as_deref(),
            Some("Example-corp")
        );
        assert_eq!(config.refused_word("example/corp"), None);
    }

    #[test]
    fn an_invalid_embedded_file_is_refused_not_ignored() {
        assert!(Config::resolve(r#"{"schema": 1, "x": 1}"#, None, None).is_err());
    }
}
