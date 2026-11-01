//! Lock schema 2: which module owns each installed path, under which ownership
//! class, and which module versions are recorded. A schema-1 lock (one flat
//! `files` map written by the installer until 0.3.0) is read and migrated to
//! schema 2; it is never written again.
use crate::{Result, refuse};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const SCHEMA: u64 = 2;
/// The module that owns today's content: guides, hook, managed blocks, decisions index.
pub const SETUP_CORE: &str = "setup-core";

/// How the engine treats a path it rendered (SPEC-engine.md, ownership classes).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Ownership {
    Managed,
    ManagedBlock,
    Seed,
    NeverTouch,
    Remote,
    /// The members of the arrays of a JSON fragment inside a project-owned JSON
    /// file (#747); the rest of the file is the project's.
    ManagedEntries,
}

impl std::fmt::Display for Ownership {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Ownership::Managed => "managed",
            Ownership::ManagedBlock => "managed-block",
            Ownership::Seed => "seed",
            Ownership::NeverTouch => "never-touch",
            Ownership::Remote => "remote",
            Ownership::ManagedEntries => "managed-entries",
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    pub module: String,
    pub class: Ownership,
    /// Present for `managed` and `managed-block`; absent for the classes without content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    /// `managed-entries` only: the fragment whose arrays hold the owned entries,
    /// what `remove` and a retirement take out of the file without rendering.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entries: Option<Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleEntry {
    pub version: String,
    pub answers_digest: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lock {
    pub schema: u64,
    pub version: String,
    pub source_commit: Option<String>,
    pub source_dirty: bool,
    pub personal_owner: String,
    pub modules: BTreeMap<String, ModuleEntry>,
    pub files: BTreeMap<String, FileEntry>,
}

impl Lock {
    /// Parses an installed lock of schema 1 (migrated) or 2. `core_version` is the
    /// compiled `setup-core` version recorded for a migrated lock; `known` says
    /// whether a schema-1 path belongs to today's content.
    pub fn parse(raw: &str, core_version: &str, known: &dyn Fn(&str) -> bool) -> Result<Lock> {
        let value: Value = serde_json::from_str(raw)?;
        match value["schema"].as_u64() {
            Some(1) => Self::from_v1(&value, core_version, known),
            Some(SCHEMA) => Ok(serde_json::from_value(value)?),
            _ => refuse("Unsupported lock schema; migration required"),
        }
    }

    /// The pure migration: every schema-1 file becomes `setup-core`, `managed`,
    /// except the two entrypoints, which hold a managed block.
    pub fn from_v1(
        value: &Value,
        core_version: &str,
        known: &dyn Fn(&str) -> bool,
    ) -> Result<Lock> {
        let Some(files) = value["files"].as_object() else {
            return refuse("Invalid installed lock");
        };
        if files.keys().any(|path| !known(path)) {
            return refuse("Unknown managed paths in lock; migration required");
        }
        let mut migrated = BTreeMap::new();
        for (path, digest) in files {
            let Some(digest) = digest.as_str() else {
                return refuse("Invalid installed lock");
            };
            let class = if path == "AGENTS.md" || path == "CLAUDE.md" {
                Ownership::ManagedBlock
            } else {
                Ownership::Managed
            };
            migrated.insert(
                path.clone(),
                FileEntry {
                    module: SETUP_CORE.to_owned(),
                    class,
                    digest: Some(digest.to_owned()),
                    entries: None,
                },
            );
        }
        let mut modules = BTreeMap::new();
        modules.insert(
            SETUP_CORE.to_owned(),
            ModuleEntry {
                version: core_version.to_owned(),
                answers_digest: None,
            },
        );
        Ok(Lock {
            schema: SCHEMA,
            version: value["version"].as_str().unwrap_or_default().to_owned(),
            source_commit: value["source_commit"].as_str().map(str::to_owned),
            source_dirty: value["source_dirty"].as_bool().unwrap_or(true),
            personal_owner: value["personal_owner"]
                .as_str()
                .map_or_else(crate::config::current_owner, str::to_owned),
            modules,
            files: migrated,
        })
    }

    /// Records a module version and the digest of its answers file.
    pub fn record(&mut self, module: &str, version: &str, answers_digest: Option<&str>) {
        self.modules.insert(
            module.to_owned(),
            ModuleEntry {
                version: version.to_owned(),
                answers_digest: answers_digest.map(str::to_owned),
            },
        );
    }

    pub fn insert_file(
        &mut self,
        path: &str,
        module: &str,
        class: Ownership,
        digest: Option<&str>,
    ) {
        self.files.insert(
            path.to_owned(),
            FileEntry {
                module: module.to_owned(),
                class,
                digest: digest.map(str::to_owned),
                entries: None,
            },
        );
    }

    /// Records a `managed-entries` path: the digest of the fragment text and the
    /// fragment itself.
    pub fn insert_entries(&mut self, path: &str, module: &str, digest: &str, entries: Value) {
        self.files.insert(
            path.to_owned(),
            FileEntry {
                module: module.to_owned(),
                class: Ownership::ManagedEntries,
                digest: Some(digest.to_owned()),
                entries: Some(entries),
            },
        );
    }

    /// Deterministic text: struct field order, sorted maps, trailing newline.
    pub fn to_json_string(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)? + "\n")
    }
}
