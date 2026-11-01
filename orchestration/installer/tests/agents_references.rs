//! product-boundary T8 (#1058; SPEC-product-boundary.md, "No Python in the new
//! repository: the one Python test that travels is ported"): every file
//! `AGENTS.md` names in backticks exists. The port of
//! `tests/test_agents_references.py`, which stays here while the declared
//! verify runs it. Also: the installer's manifest stays a crate of its own, so
//! the export builds it as the root crate with its own `Cargo.lock`.
use std::path::{Path, PathBuf};

/// The repository root: two levels above this crate.
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The names the Python test's `` `([^`*\s]+\.(?:md|json))` `` finds, in text
/// order: a backtick, a run of characters that are not a backtick, `*` or
/// whitespace and ends in `.md` or `.json` with something before the dot,
/// then a backtick. Scanning resumes after a match's closing backtick, or one
/// character after an opening backtick that did not match.
fn named(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut found = Vec::new();
    let mut at = 0;
    while at < chars.len() {
        if chars[at] != '`' {
            at += 1;
            continue;
        }
        let start = at + 1;
        let mut end = start;
        while end < chars.len() && !matches!(chars[end], '`' | '*') && !chars[end].is_whitespace() {
            end += 1;
        }
        let run: String = chars[start..end].iter().collect();
        let suffix = [".md", ".json"]
            .into_iter()
            .find(|s| run.ends_with(s) && run.len() > s.len());
        if end < chars.len() && chars[end] == '`' && suffix.is_some() {
            found.push(run);
            at = end + 1;
        } else {
            at += 1;
        }
    }
    found
}

#[test]
fn the_extractor_matches_the_python_pattern() {
    let text = "Read `docs/a.md` and `x.json`; not `two words.md`, `*.md`, `a.txt`, `.md` \
                or ``` fences; `b.md`` `c.md` and `d.md";
    assert_eq!(named(text), ["docs/a.md", "x.json", "b.md", "c.md"]);
}

#[test]
fn every_file_agents_md_names_exists() {
    let text = std::fs::read_to_string(root().join("AGENTS.md")).unwrap();
    let named: std::collections::BTreeSet<String> = named(&text).into_iter().collect();
    assert!(!named.is_empty());
    // This repository's entrypoint names the technical-debt seed; the import's
    // (`export/AGENTS.md`, laid over it by the export, which never carries
    // `export/`) names it once the new repository installs itself.
    if root().join("export").is_dir() {
        assert!(
            named
                .iter()
                .any(|n| n == "docs/agent-setup/technical-debt.md"),
            "{named:?}"
        );
    }
    let missing: Vec<&String> = named.iter().filter(|n| !root().join(n).is_file()).collect();
    assert_eq!(missing, Vec::<&String>::new());
}

/// The export builds this crate alone, at the root of a new repository, with a
/// lock of its own (plan T8, T10): its manifest inherits nothing from a
/// workspace and depends on no crate by path.
#[test]
fn the_installer_manifest_stands_alone() {
    let manifest =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).unwrap();
    for line in manifest.lines().map(str::trim) {
        assert!(!line.contains("workspace = true"), "{line}");
        assert!(!line.contains(".workspace"), "{line}");
        assert!(!line.starts_with("[workspace"), "{line}");
        assert!(!line.contains("path ="), "{line}");
    }
}
