//! The shared pin table: `templates/stack-packs/pins.json`, embedded at build
//! time and readable from a checkout under `--source`. Every action SHA, image
//! digest and tool version any pack renders comes from here; a key the table
//! lacks refuses with the key named. Two native files Dependabot understands
//! carry the same pins (this repository's workflows and `pins/Dockerfile`), and
//! the pins test holds the three in step.
use crate::{Result, refuse};
use chrono::NaiveDate;
use serde::Deserialize;
use std::{collections::BTreeMap, fs, path::Path};

use super::pack::ActionRef;

/// Where the table lives in this repository.
pub const PINS_PATH: &str = "templates/stack-packs/pins.json";
/// The never-built Dockerfile whose `FROM` lines Dependabot's `docker` ecosystem bumps.
pub const PINS_DOCKERFILE_PATH: &str = "templates/stack-packs/pins/Dockerfile";
/// Days after `last_verified` before `doctor` reports `stack.pin-table-stale`.
pub const PIN_VERIFICATION_DAYS: u32 = 30;

const EMBEDDED: &str = include_str!("../../../../../templates/stack-packs/pins.json");

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionPin {
    pub sha: String,
    pub version: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImagePin {
    /// `registry/repository:tag`, the human-readable half of a `FROM`.
    #[serde(rename = "ref")]
    pub reference: String,
    /// `sha256:<64 hex>`, the pin.
    pub digest: String,
}

impl ImagePin {
    /// The `FROM` value: `<ref>@<digest>`.
    pub fn pinned(&self) -> String {
        format!("{}@{}", self.reference, self.digest)
    }
}

/// A tool pinned by version, and optionally as a binary downloaded by URL and
/// verified by SHA-256 through `security`'s `install-tool.sh` (Hurl, #997).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolPin {
    pub version: String,
    pub binary: Option<BinaryPin>,
}

/// How the downloaded asset holds the binary: the values `install-tool.sh` reads as `TOOL_FORMAT`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BinaryFormat {
    /// A gzipped tarball holding `bin` at its root, or at `bin_path`.
    Tgz,
    /// The executable itself.
    Bin,
}

impl BinaryFormat {
    pub fn token(self) -> &'static str {
        match self {
            BinaryFormat::Tgz => "tgz",
            BinaryFormat::Bin => "bin",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub url: String,
    /// 64 lowercase hex, copied from the upstream checksum file.
    pub sha256: String,
}

/// The binary half of a tool pin; both architectures are required (GitHub
/// amd64 and self-hosted arm64 run the same job).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryPin {
    /// Upstream release date, `YYYY-MM-DD`.
    pub released: String,
    /// The executable's name once installed.
    pub bin: String,
    pub format: BinaryFormat,
    /// The binary's path inside a tarball when it is not at the root (`*` allowed).
    pub bin_path: Option<String>,
    /// Where the digests were copied from: a checksum file, or the release
    /// whose per-archive `.sha256` files were read.
    pub checksums: String,
    pub amd64: Artifact,
    pub arm64: Artifact,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTool {
    version: String,
    released: Option<String>,
    bin: Option<String>,
    format: Option<BinaryFormat>,
    bin_path: Option<String>,
    checksums: Option<String>,
    amd64: Option<Artifact>,
    arm64: Option<Artifact>,
}

impl RawTool {
    fn into_pin(self, key: &str) -> Result<ToolPin> {
        let RawTool {
            version,
            released,
            bin,
            format,
            bin_path,
            checksums,
            amd64,
            arm64,
        } = self;
        let any = released.is_some()
            || bin.is_some()
            || format.is_some()
            || bin_path.is_some()
            || checksums.is_some()
            || amd64.is_some()
            || arm64.is_some();
        if !any {
            return Ok(ToolPin {
                version,
                binary: None,
            });
        }
        let missing = |field: &str| -> Result<ToolPin> {
            refuse(format!(
                "stack-packs: tool `{key}` in {PINS_PATH} has a binary pin without `{field}`"
            ))
        };
        let Some(released) = released else {
            return missing("released");
        };
        let Some(bin) = bin else {
            return missing("bin");
        };
        let Some(format) = format else {
            return missing("format");
        };
        let Some(checksums) = checksums else {
            return missing("checksums");
        };
        let Some(amd64) = amd64 else {
            return missing("amd64");
        };
        let Some(arm64) = arm64 else {
            return missing("arm64");
        };
        for (arch, artifact) in [("amd64", &amd64), ("arm64", &arm64)] {
            if !lowercase_hex(&artifact.sha256, 64) {
                return refuse(format!(
                    "stack-packs: tool `{key}` in {PINS_PATH} has sha256 `{}` for {arch}; a checksum is 64 lowercase hex",
                    artifact.sha256
                ));
            }
            if !artifact.url.starts_with("https://") || !artifact.url.contains(&version) {
                return refuse(format!(
                    "stack-packs: tool `{key}` in {PINS_PATH} has {arch} URL `{}`; a binary URL is https and names version {version}",
                    artifact.url
                ));
            }
        }
        if let Some(path) = &bin_path {
            if path.starts_with('/') || path.split('/').any(|part| part == "..") {
                return refuse(format!(
                    "stack-packs: tool `{key}` in {PINS_PATH} has bin_path `{path}`; it is relative to the archive root without .."
                ));
            }
            if format != BinaryFormat::Tgz {
                return refuse(format!(
                    "stack-packs: tool `{key}` in {PINS_PATH} has bin_path `{path}` with format {}; bin_path needs tgz",
                    format.token()
                ));
            }
        }
        Ok(ToolPin {
            version,
            binary: Some(BinaryPin {
                released,
                bin,
                format,
                bin_path,
                checksums,
                amd64,
                arm64,
            }),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinTable {
    pub last_verified: NaiveDate,
    pub actions: BTreeMap<String, ActionPin>,
    pub images: BTreeMap<String, ImagePin>,
    pub tools: BTreeMap<String, ToolPin>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTable {
    last_verified: String,
    actions: BTreeMap<String, ActionPin>,
    images: BTreeMap<String, ImagePin>,
    tools: BTreeMap<String, RawTool>,
}

fn lowercase_hex(text: &str, len: usize) -> bool {
    text.len() == len
        && text
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

impl PinTable {
    /// The table compiled into the binary.
    pub fn embedded() -> Result<Self> {
        Self::parse(EMBEDDED)
    }

    /// The table of a checkout of this repository (`--source`).
    pub fn from_checkout(root: &Path) -> Result<Self> {
        Self::parse(&fs::read_to_string(root.join(PINS_PATH))?)
    }

    /// Parses and validates: every SHA 40 lowercase hex, every digest
    /// `sha256:` plus 64, every ref tagged and digest-free, no empty version.
    pub fn parse(text: &str) -> Result<Self> {
        let raw: RawTable = serde_json::from_str(text)?;
        let Ok(last_verified) = NaiveDate::parse_from_str(&raw.last_verified, "%Y-%m-%d") else {
            return refuse(format!(
                "stack-packs: last_verified `{}` in {PINS_PATH} is not a YYYY-MM-DD date",
                raw.last_verified
            ));
        };
        for (key, pin) in &raw.actions {
            if !lowercase_hex(&pin.sha, 40) {
                return refuse(format!(
                    "stack-packs: action `{key}` in {PINS_PATH} has sha `{}`; a pin is 40 lowercase hex",
                    pin.sha
                ));
            }
        }
        for (key, pin) in &raw.images {
            let hex = pin.digest.strip_prefix("sha256:").unwrap_or("");
            if !lowercase_hex(hex, 64) {
                return refuse(format!(
                    "stack-packs: image `{key}` in {PINS_PATH} has digest `{}`; a pin is sha256: plus 64 lowercase hex",
                    pin.digest
                ));
            }
            let tag = pin
                .reference
                .rsplit('/')
                .next()
                .and_then(|name| name.split_once(':'))
                .map(|(_, tag)| tag);
            if pin.reference.contains('@') || tag.is_none_or(|t| t.is_empty() || t == "latest") {
                return refuse(format!(
                    "stack-packs: image `{key}` in {PINS_PATH} has ref `{}`; a ref carries a tag other than latest and no digest",
                    pin.reference
                ));
            }
        }
        let mut tools = BTreeMap::new();
        for (key, pin) in raw.tools {
            if pin.version.trim().is_empty() {
                return refuse(format!(
                    "stack-packs: tool `{key}` in {PINS_PATH} has an empty version"
                ));
            }
            let pin = pin.into_pin(&key)?;
            tools.insert(key, pin);
        }
        Ok(Self {
            last_verified,
            actions: raw.actions,
            images: raw.images,
            tools,
        })
    }

    /// The pinned action for a `uses:` path (`actions/cache/restore` is its own key).
    pub fn action(&self, repo: &str) -> Result<ActionRef> {
        match self.actions.get(repo) {
            Some(pin) => Ok(ActionRef {
                repo: repo.to_owned(),
                sha: pin.sha.clone(),
                version: pin.version.clone(),
            }),
            None => refuse(format!(
                "stack-packs: action `{repo}` is not in {PINS_PATH}; add it with its sha before rendering"
            )),
        }
    }

    pub fn image(&self, key: &str) -> Result<&ImagePin> {
        match self.images.get(key) {
            Some(pin) => Ok(pin),
            None => refuse(format!(
                "stack-packs: image `{key}` is not in {PINS_PATH}; add it with its digest before rendering"
            )),
        }
    }

    pub fn tool(&self, key: &str) -> Result<&ToolPin> {
        match self.tools.get(key) {
            Some(pin) => Ok(pin),
            None => refuse(format!(
                "stack-packs: tool `{key}` is not in {PINS_PATH}; add it with its version before rendering"
            )),
        }
    }

    /// The environment `install-tool.sh` reads for the binary pin `key`, in the
    /// order `security::pins::ToolPin::env` uses, plus `TOOL_BIN_PATH` when the
    /// binary is below the archive root. A tool pinned by version only refuses.
    pub fn tool_binary(&self, key: &str) -> Result<Vec<(&'static str, String)>> {
        let pin = self.tool(key)?;
        let Some(binary) = &pin.binary else {
            return refuse(format!(
                "stack-packs: tools.{key} has no binary pin in {PINS_PATH}; it is pinned by version only"
            ));
        };
        let mut env = vec![
            ("TOOL_NAME", key.to_owned()),
            ("TOOL_VERSION", pin.version.clone()),
            ("TOOL_BIN", binary.bin.clone()),
            ("TOOL_FORMAT", binary.format.token().to_owned()),
            ("TOOL_URL_AMD64", binary.amd64.url.clone()),
            ("TOOL_SHA256_AMD64", binary.amd64.sha256.clone()),
            ("TOOL_URL_ARM64", binary.arm64.url.clone()),
            ("TOOL_SHA256_ARM64", binary.arm64.sha256.clone()),
        ];
        if let Some(path) = &binary.bin_path {
            env.push(("TOOL_BIN_PATH", path.clone()));
        }
        Ok(env)
    }

    /// Days since `last_verified` on `today`; negative before it.
    pub fn age_days(&self, today: NaiveDate) -> i64 {
        (today - self.last_verified).num_days()
    }

    /// The `stack.pin-table-stale` finding when the table is older than `limit_days`.
    pub fn stale_finding(&self, today: NaiveDate, limit_days: u32) -> Option<String> {
        let age = self.age_days(today);
        (age > i64::from(limit_days)).then(|| {
            format!(
                "stack.pin-table-stale: pin table last verified {}, {age} days ago (limit {limit_days})",
                self.last_verified
            )
        })
    }
}
