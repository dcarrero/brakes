//! Lock schema 2 and the migration from the schema-1 lock written today (SPEC-engine.md, #650).
mod support;
use brakes::engine::lock::{Lock, Ownership, SCHEMA};
use brakes::{HOOKS, config::current_owner};
use serde_json::{Value, json};
use std::{fs, path::PathBuf};

fn known(path: &str) -> bool {
    path == "AGENTS.md"
        || path == "CLAUDE.md"
        || path == "docs/agent-setup/decisions-index.md"
        || support::guides()
            .iter()
            .any(|(n, _)| format!("docs/agent-setup/{n}") == path)
        || HOOKS.iter().any(|(n, _)| *n == path)
}

fn v1(files: Value) -> Value {
    json!({
        "schema": 1, "version": "0.3.0", "source_commit": "abc", "source_dirty": false,
        "personal_owner": current_owner(), "files": files
    })
}

fn fixtures() -> Vec<(String, String)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/locks");
    let mut out: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .map(|p| {
            (
                p.file_name().unwrap().to_string_lossy().into_owned(),
                fs::read_to_string(&p).unwrap(),
            )
        })
        .collect();
    out.push((
        "agentic-project-setup".to_owned(),
        fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.agent-setup/lock.json"),
        )
        .unwrap(),
    ));
    out.sort();
    out
}

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "asserts setup-core's own content or id; product-boundary T7b"
)]
#[test]
fn from_v1_maps_every_file_to_setup_core_with_block_classes() {
    let lock = Lock::from_v1(
        &v1(json!({
            "AGENTS.md": "d1", "CLAUDE.md": "d2",
            "docs/agent-setup/testing.md": "d3", ".claude/hooks/merge_guard.sh": "d4"
        })),
        "1.0.0",
        &known,
    )
    .unwrap();
    assert_eq!(lock.schema, SCHEMA);
    assert_eq!(lock.version, "0.3.0");
    assert_eq!(lock.source_commit.as_deref(), Some("abc"));
    assert_eq!(lock.personal_owner, current_owner());
    assert_eq!(lock.modules["setup-core"].version, "1.0.0");
    assert_eq!(lock.modules["setup-core"].answers_digest, None);
    let agents = &lock.files["AGENTS.md"];
    assert_eq!(agents.module, "setup-core");
    assert_eq!(agents.class, Ownership::ManagedBlock);
    assert_eq!(agents.digest.as_deref(), Some("d1"));
    assert_eq!(lock.files["CLAUDE.md"].class, Ownership::ManagedBlock);
    assert_eq!(
        lock.files["docs/agent-setup/testing.md"].class,
        Ownership::Managed
    );
    assert_eq!(
        lock.files[".claude/hooks/merge_guard.sh"].class,
        Ownership::Managed
    );
}

#[test]
fn from_v1_refuses_unknown_paths_with_migration_required() {
    let error = Lock::from_v1(&v1(json!({"docs/other.md": "x"})), "1.0.0", &known)
        .unwrap_err()
        .to_string();
    assert_eq!(error, "Unknown managed paths in lock; migration required");
}

#[test]
fn from_v1_refuses_a_lock_without_a_files_object() {
    let error = Lock::from_v1(&json!({"schema": 1, "files": []}), "1.0.0", &known)
        .unwrap_err()
        .to_string();
    assert_eq!(error, "Invalid installed lock");
}

#[test]
fn parse_migrates_schema_1_and_accepts_schema_2() {
    let migrated =
        Lock::parse(&v1(json!({"AGENTS.md": "d1"})).to_string(), "1.0.0", &known).unwrap();
    let serialized = migrated.to_json_string().unwrap();
    let reparsed = Lock::parse(&serialized, "1.0.0", &known).unwrap();
    assert_eq!(reparsed, migrated);
    assert_eq!(reparsed.to_json_string().unwrap(), serialized);
    assert!(serialized.ends_with('\n'));
}

#[test]
fn parse_refuses_unsupported_schemas() {
    for raw in [
        json!({"schema": 3, "files": {}}).to_string(),
        json!({"files": {}}).to_string(),
    ] {
        let error = Lock::parse(&raw, "1.0.0", &known).unwrap_err().to_string();
        assert_eq!(
            error, "Unsupported lock schema; migration required",
            "{raw}"
        );
    }
}

#[test]
fn seed_and_remote_entries_serialize_without_a_digest_and_keys_are_sorted() {
    let mut lock = Lock::from_v1(&v1(json!({"AGENTS.md": "d1"})), "1.0.0", &known).unwrap();
    lock.record("delivery", "1.2.0", Some("a9"));
    lock.insert_file("compose.yaml", "delivery", Ownership::Seed, None);
    lock.insert_file("rulesets/main", "repo-baseline", Ownership::Remote, None);
    lock.insert_file("a.md", "delivery", Ownership::Managed, Some("zz"));
    let text = lock.to_json_string().unwrap();
    let value: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        value["files"]["compose.yaml"],
        json!({"module": "delivery", "class": "seed"})
    );
    assert_eq!(
        value["files"]["rulesets/main"],
        json!({"module": "repo-baseline", "class": "remote"})
    );
    assert_eq!(value["files"]["a.md"]["digest"], "zz");
    assert_eq!(
        value["modules"]["delivery"],
        json!({"version": "1.2.0", "answers_digest": "a9"})
    );
    let keys: Vec<_> = value["files"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted);
    assert!(text.find("\"modules\"").unwrap() < text.find("\"files\"").unwrap());
}

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "asserts setup-core's own content or id; product-boundary T7b"
)]
#[test]
fn every_real_lock_parses_and_a_schema_1_one_migrates_to_setup_core_only() {
    for (name, raw) in fixtures() {
        let value: Value = serde_json::from_str(&raw).unwrap();
        let lock = Lock::parse(&raw, "1.0.0", &known).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(lock.schema, SCHEMA, "{name}");
        assert_eq!(lock.version, value["version"], "{name}");
        if value["schema"] == 2 {
            // Already migrated (this repository since 2026-10-28): it round-trips byte for byte.
            assert_eq!(lock.to_json_string().unwrap(), raw, "{name}");
            continue;
        }
        assert_eq!(
            lock.files.len(),
            value["files"].as_object().unwrap().len(),
            "{name}"
        );
        assert!(
            lock.files.values().all(|f| f.module == "setup-core"),
            "{name}"
        );
        assert_eq!(lock.modules.len(), 1, "{name}");
        for (path, entry) in &lock.files {
            let expected = if path == "AGENTS.md" || path == "CLAUDE.md" {
                Ownership::ManagedBlock
            } else {
                Ownership::Managed
            };
            assert_eq!(entry.class, expected, "{name}: {path}");
            assert_eq!(
                entry.digest.as_deref(),
                value["files"][path].as_str(),
                "{name}: {path}"
            );
        }
        // The migrated lock, written and read again, is the same lock (the schema-2 path).
        let text = lock.to_json_string().unwrap();
        assert_eq!(Lock::parse(&text, "1.0.0", &known).unwrap(), lock, "{name}");
    }
}
