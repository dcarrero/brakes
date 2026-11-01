//! N4 (`SPEC-product-boundary.md`): no recorded fixture names a real account.
//! Every GitHub identity a fixture or golden carries belongs to the synthetic
//! set. The groups grow as the T6 pull requests make them synthetic; the whole
//! of `tests/fixtures/**` and `tests/golden/**` is the target. Still outside:
//! `golden/stack_packs` (the public action publishers its setup steps pin).

use std::fs;
use std::path::{Path, PathBuf};

/// The trees and files already synthetic, by T6 group.
const GROUPS: &[&str] = &[
    // T6a: auditor
    "tests/fixtures/auditor",
    "tests/golden/auditor",
    // T6b: GitHub responses
    "tests/fixtures/github",
    "tests/golden/host_features.json",
    "tests/golden/host_org.json",
    "tests/golden/host_probe.json",
    "tests/golden/host_repos.json",
    // T6c: workflows
    "tests/fixtures/ci-baseline",
    "tests/fixtures/security/audit/ours",
    // T6d: locks, exceptions, MCP, entrypoints
    "tests/fixtures/locks",
    "tests/fixtures/security/exceptions",
    "tests/fixtures/mcp",
    "tests/fixtures/plain-string-agents.md",
    // T6e: module goldens
    "tests/golden/repo-baseline",
    "tests/golden/repo-baseline-setup-core",
    "tests/golden/tui",
    "tests/golden/agent-guardrails",
    "tests/golden/security",
    "tests/golden/merge-guard",
    // T6g: QA
    "tests/fixtures/qa",
    "tests/golden/qa",
    // T6i: the test configuration
    "tests/fixtures/config",
];

/// The product's own home (spec N1): rendered schema `$id`s point at it.
const HOME: &str = "gemba-app/brakes";

/// The synthetic accounts: the owner, the organisation, numbered
/// collaborators and GitHub's own bots; plus the upstream publishers whose
/// public releases a fixture downloads (Hurl's), which are no recording.
fn synthetic(account: &str) -> bool {
    matches!(
        account,
        "example-owner"
            | "example-org"
            | "dependabot[bot]"
            | "github-actions[bot]"
            | "Orange-OpenSource"
    ) || account
        .strip_prefix("collaborator-")
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// The account segment that starts at `rest`: up to the next `/`, quote,
/// whitespace or other character no account name holds.
fn account(rest: &str) -> &str {
    let end = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || "-_.[]".contains(c)))
        .unwrap_or(rest.len());
    &rest[..end]
}

/// The accounts `text` names: REST paths (`repos/`, `orgs/`, `users/`), web
/// and SSH remotes (`github.com/`, `github.com:`, `www.` included, never another
/// subdomain such as `docs.github.com/en`) and the JSON fields that carry an account or an
/// `owner/name`. The product's home is not an account a fixture records.
fn accounts(text: &str) -> Vec<String> {
    const MARKERS: &[&str] = &[
        "repos/",
        "orgs/",
        "users/",
        "github.com/",
        "github.com:",
        "\"login\": \"",
        "\"full_name\": \"",
        "\"repo\": \"",
    ];
    let mut found = Vec::new();
    for marker in MARKERS {
        for (at, _) in text.match_indices(marker) {
            let rest = &text[at + marker.len()..];
            let before = &text[..at];
            if marker.starts_with("github.com")
                && before.ends_with('.')
                && !before.ends_with("www.")
            {
                continue;
            }
            if rest.starts_with(HOME) {
                continue;
            }
            let name = account(rest);
            // `api.github.com/repos/…`: the REST marker reads the account.
            if name.is_empty() || matches!(name, "repos" | "orgs" | "users") {
                continue;
            }
            found.push(name.to_owned());
        }
    }
    found
}

fn files(path: &Path, out: &mut Vec<PathBuf>) {
    if path.is_dir() {
        let mut entries: Vec<_> = fs::read_dir(path)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        entries.sort();
        for entry in entries {
            files(&entry, out);
        }
    } else {
        out.push(path.to_owned());
    }
}

#[test]
fn the_tokeniser_reads_paths_remotes_and_account_fields() {
    let text = r#"{"repos/acme/app/pulls": 1, "url": "https://api.github.com/repos/acme/app",
        "login": "someone", "full_name": "org/x", "remote": "git@github.com:other/y.git",
        "repo": "third/z", "orgs/fourth": 1, "users/fifth": 1,
        "docs": "https://docs.github.com/en/actions", "probe": "https://api.github.com/zen",
        "$id": "https://github.com/gemba-app/brakes/blob/main/x.json",
        "web": "https://www.github.com/sixth/w"}"#;
    assert_eq!(
        accounts(text),
        [
            "acme", "acme", "fourth", "fifth", "sixth", "other", "someone", "org", "third"
        ]
    );
    assert!(synthetic("collaborator-12") && !synthetic("collaborator-"));
    assert!(!synthetic("someone"));
}

#[test]
fn every_account_in_the_synthetic_groups_is_synthetic() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut paths = Vec::new();
    for group in GROUPS {
        files(&root.join(group), &mut paths);
    }
    let mut read = 0;
    let mut real = Vec::new();
    for path in &paths {
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        for name in accounts(&text) {
            read += 1;
            if !synthetic(&name) {
                real.push(format!(
                    "{}: {name}",
                    path.strip_prefix(root).unwrap().display()
                ));
            }
        }
    }
    assert!(read > 0, "no account read under {GROUPS:?}");
    real.sort();
    real.dedup();
    assert!(
        real.is_empty(),
        "accounts outside the synthetic set:\n{real:#?}"
    );
}
