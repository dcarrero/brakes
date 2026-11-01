//! #1161, #1168 (SPEC-stack-packs.md, "Version of the toolchain seed"): a
//! toolchain seed takes its version from the repository's own files and never
//! contradicts them; disagreeing or absent evidence refuses naming the answers
//! that settle it, and the owner's `toolchain_version` wins over the evidence.
use brakes::modules::stack_packs::{App, PackageManager, PinTable, StackId, seeds, versions};
use std::{collections::BTreeMap, fs, path::Path};
use tempfile::TempDir;

fn repo(files: &[(&str, &str)]) -> TempDir {
    let dir = TempDir::new().unwrap();
    for (path, text) in files {
        let path = dir.path().join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
    dir
}

fn app(stack: StackId, path: &str) -> App {
    App {
        id: "web".to_owned(),
        path: path.to_owned(),
        stack,
        container: false,
        toolchain: true,
        package_manager: (stack == StackId::Node).then_some(PackageManager::Npm),
        declared: BTreeMap::new(),
    }
}

/// The seed's content, or the refusal.
fn seed(root: &Path, app: &App, answer: Option<&str>) -> Result<String, String> {
    let pins = PinTable::embedded().unwrap();
    match seeds::toolchain(root, app, answer, &pins) {
        Ok(rendered) => Ok(rendered[0].content.clone().unwrap()),
        Err(error) => Err(error.to_string()),
    }
}

const SETUP_NODE_22: &str = "\
on: push
jobs:
  web:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@v4
        with:
          node-version: '22'
";

#[test]
fn a_single_node_app_seeds_the_repositorys_node_22_never_the_pin() {
    let dir = repo(&[
        ("web/package.json", "{}"),
        ("web/package-lock.json", "{}"),
        ("web/Dockerfile", "FROM node:22-slim\n"),
        (
            "web/Dockerfile.prod",
            "FROM node:22-alpine AS deps\nFROM node:22-alpine AS runner\n",
        ),
        (".github/workflows/ci.yml", SETUP_NODE_22),
    ]);
    assert_eq!(
        seed(dir.path(), &app(StackId::Node, "web"), None),
        Ok("22\n".to_owned())
    );
}

#[test]
fn conflicting_evidence_refuses_naming_each_version_and_the_answers() {
    let dir = repo(&[
        ("web/package.json", r#"{"engines": {"node": "^24.1.0"}}"#),
        ("web/Dockerfile", "FROM node:22-slim\n"),
        (".github/workflows/ci.yml", SETUP_NODE_22),
    ]);
    assert_eq!(
        seed(dir.path(), &app(StackId::Node, "web"), None),
        Err("stack-packs: app `web` (node): the repository names different Node versions for `web/.nvmrc`: 22 (.github/workflows/ci.yml, web/Dockerfile), 24.1.0 (web/package.json); set apps.web.toolchain_version=<version> (the pin table has 24) or apps.web.toolchain=false".to_owned())
    );
    // The owner's answer settles it.
    assert_eq!(
        seed(dir.path(), &app(StackId::Node, "web"), Some("22")),
        Ok("22\n".to_owned())
    );
}

#[test]
fn absent_evidence_asks_instead_of_seeding_the_pin_table() {
    let dir = repo(&[("web/package.json", "{}")]);
    assert_eq!(
        seed(dir.path(), &app(StackId::Node, "web"), None),
        Err("stack-packs: app `web` (node): no Node version found in the repository to seed `web/.nvmrc` from; set apps.web.toolchain_version=<version> (the pin table has 24) or apps.web.toolchain=false".to_owned())
    );
}

#[test]
fn agreeing_versions_seed_the_most_specific() {
    let dir = repo(&[
        (".tool-versions", "nodejs 22.11.0\n"),
        (
            "web/Dockerfile",
            "FROM docker.io/library/node:22@sha256:abc\n",
        ),
    ]);
    assert_eq!(
        seed(dir.path(), &app(StackId::Node, "web"), None),
        Ok("22.11.0\n".to_owned())
    );
}

#[test]
fn ranges_words_expressions_and_lists_are_not_versions() {
    for text in [
        ">=20",
        "~=3.12",
        "20 || 22",
        "stable",
        "lts",
        "${{ matrix.node }}",
        "",
        "v",
    ] {
        assert_eq!(versions::single_version(text), None, "{text}");
    }
    for (text, version) in [
        ("22", "22"),
        ("'22.x'", "22"),
        ("==3.12.*", "3.12"),
        ("^22.1", "22.1"),
        ("~22.1.0", "22.1.0"),
        ("v22", "22"),
        ("1.99.0", "1.99.0"),
    ] {
        assert_eq!(
            versions::single_version(text).as_deref(),
            Some(version),
            "{text}"
        );
    }
}

#[test]
fn a_monorepo_python_app_seeds_3_12_from_setup_python_and_from() {
    let dir = repo(&[
        (
            "apps/backend/pyproject.toml",
            "[project]\nrequires-python = \">=3.12\"\n",
        ),
        (
            "apps/backend/Dockerfile",
            "FROM python:3.12-slim AS base\nFROM base AS prod\n",
        ),
        (
            ".github/workflows/ci.yml",
            "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/setup-python@v5\n        with:\n          python-version: 3.12\n",
        ),
    ]);
    let mut backend = app(StackId::PythonUv, "apps/backend");
    backend.id = "backend".to_owned();
    assert_eq!(seed(dir.path(), &backend, None), Ok("3.12\n".to_owned()));
}

#[test]
fn rust_seeds_the_exact_toolchain_the_ci_installs() {
    let dir = repo(&[(
        ".github/workflows/ci.yml",
        "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: dtolnay/rust-toolchain@d124f86f28ff42855784ff3319f48ac182c248f8\n        with:\n          toolchain: 1.99.0\n",
    )]);
    let content = seed(dir.path(), &app(StackId::Rust, "."), None).unwrap();
    assert!(content.contains("channel = \"1.99.0\"\n"), "{content}");
}

#[test]
fn java_and_xcode_come_from_their_setup_steps() {
    let dir = repo(&[(
        ".github/workflows/ci.yml",
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/setup-java@v4\n        with:\n          distribution: temurin\n          java-version: '25'\n  i:\n    runs-on: macos-15\n    steps:\n      - run: sudo xcode-select -s /Applications/Xcode_16.4.app\n",
    )]);
    assert_eq!(
        seed(dir.path(), &app(StackId::KotlinAndroid, "android"), None),
        Ok("25\n".to_owned())
    );
    assert_eq!(
        seed(dir.path(), &app(StackId::SwiftIos, "ios"), None),
        Ok("16.4\n".to_owned())
    );
}

#[test]
fn an_existing_seed_is_not_re_read() {
    // The engine skips a present seed; a conflict elsewhere does not refuse it.
    let dir = repo(&[
        ("web/.nvmrc", "20\n"),
        ("web/package.json", r#"{"engines": {"node": "24"}}"#),
        ("web/Dockerfile", "FROM node:22\n"),
    ]);
    assert!(seed(dir.path(), &app(StackId::Node, "web"), None).is_ok());
}
