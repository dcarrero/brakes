//! The shared pin table (SPEC-stack-packs.md, "Pin table"): one JSON file,
//! embedded and read from the checkout, tied by test to the two native files
//! Dependabot bumps: this repository's workflows and `pins/Dockerfile`.
use brakes::modules::stack_packs::{
    ActionRef, BinaryFormat, DEFAULT_BRANCH_CONDITION, PIN_VERIFICATION_DAYS, PINS_DOCKERFILE_PATH,
    PINS_PATH, PinTable, StackId, Step,
};
use chrono::NaiveDate;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn table() -> PinTable {
    PinTable::embedded().unwrap()
}

fn is_hex(text: &str, len: usize) -> bool {
    text.len() == len
        && text
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// `uses: <action>@<sha>` across every workflow of this repository: action -> SHAs.
fn workflow_uses() -> BTreeMap<String, BTreeSet<String>> {
    let dir = repo_root().join(".github/workflows");
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for entry in fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "yml") {
            continue;
        }
        for line in fs::read_to_string(&path).unwrap().lines() {
            let item = line.trim().trim_start_matches("- ").trim();
            let Some(rest) = item.strip_prefix("uses:") else {
                continue;
            };
            let spec = rest.split('#').next().unwrap().trim();
            let Some((action, sha)) = spec.split_once('@') else {
                continue;
            };
            out.entry(action.to_owned())
                .or_default()
                .insert(sha.to_owned());
        }
    }
    out
}

/// `FROM <ref>@<digest>` lines of `templates/stack-packs/pins/Dockerfile`: ref -> digest.
fn dockerfile_froms() -> BTreeMap<String, String> {
    let text = fs::read_to_string(repo_root().join(PINS_DOCKERFILE_PATH)).unwrap();
    text.lines()
        .filter_map(|line| line.strip_prefix("FROM "))
        .map(|rest| {
            let image = rest.split_whitespace().next().unwrap();
            let (reference, digest) = image.split_once('@').expect("FROM carries a digest");
            (reference.to_owned(), digest.to_owned())
        })
        .collect()
}

#[test]
fn embedded_table_matches_the_checkout() {
    let embedded = table();
    let checkout = PinTable::from_checkout(&repo_root()).unwrap();
    assert_eq!(embedded, checkout);
    assert_eq!(PINS_PATH, "templates/stack-packs/pins.json");
}

/// Every pinned action is used at its pinned SHA. Here every pin is used by some
/// workflow; the import's workflows (the export never carries `export/`) use
/// fewer actions until the new repository renders its own.
#[test]
fn every_action_sha_is_the_one_this_repository_uses() {
    let pins = table();
    let uses = workflow_uses();
    let here = repo_root().join("export").is_dir();
    assert!(!pins.actions.is_empty());
    assert!(
        pins.actions.keys().any(|a| uses.contains_key(a)),
        "no workflow uses a pinned action"
    );
    for (action, pin) in &pins.actions {
        assert!(
            is_hex(&pin.sha, 40),
            "{action}: sha `{}` is not 40 hex",
            pin.sha
        );
        let Some(used) = uses.get(action) else {
            assert!(
                !here,
                "{action} is pinned in pins.json but no workflow uses it"
            );
            continue;
        };
        assert_eq!(
            used,
            &BTreeSet::from([pin.sha.clone()]),
            "{action}: pins.json says {} but the workflows use {used:?}",
            pin.sha
        );
    }
}

#[test]
fn every_image_digest_is_the_dockerfile_line() {
    let pins = table();
    let froms = dockerfile_froms();
    assert!(!pins.images.is_empty());
    let mut seen = BTreeSet::new();
    for (key, pin) in &pins.images {
        let (prefix, hex) = pin.digest.split_once(':').unwrap_or(("", ""));
        assert!(
            prefix == "sha256" && is_hex(hex, 64),
            "{key}: digest `{}` is not sha256: plus 64 hex",
            pin.digest
        );
        assert_eq!(
            froms.get(&pin.reference),
            Some(&pin.digest),
            "{key}: pins.json and {PINS_DOCKERFILE_PATH} disagree on {}",
            pin.reference
        );
        seen.insert(pin.reference.clone());
    }
    let extra: Vec<_> = froms.keys().filter(|r| !seen.contains(*r)).collect();
    assert!(
        extra.is_empty(),
        "{PINS_DOCKERFILE_PATH} has images pins.json lacks: {extra:?}"
    );
}

#[test]
fn the_table_carries_the_owner_defaults() {
    let pins = table();
    for key in [
        "distroless.static",
        "distroless.cc",
        "distroless.python",
        "distroless.node",
    ] {
        assert!(pins.images.contains_key(key), "{key} missing");
    }
    for key in ["rust.build", "python-uv.build", "node.build", "go.build"] {
        assert!(pins.images.contains_key(key), "{key} missing");
    }
    assert!(
        pins.images.keys().all(|k| !k.starts_with("dhi.")),
        "dhi.* stays absent until its pull authentication is confirmed"
    );
    for action in [
        "actions/checkout",
        "dtolnay/rust-toolchain",
        "Swatinem/rust-cache",
        "taiki-e/install-action",
        "actions/setup-python",
        "astral-sh/setup-uv",
        "actions/setup-node",
        "pnpm/action-setup",
        "actions/setup-go",
        "actions/cache/restore",
        "actions/cache/save",
        "actions/setup-java",
        "gradle/actions/setup-gradle",
    ] {
        assert!(pins.actions.contains_key(action), "{action} missing");
    }
    for tool in [
        "rust",
        "python",
        "node",
        "go",
        "uv",
        "nextest",
        "coverage-py",
        "pytest-cov",
        "cargo-llvm-cov",
        "java",
        "xcode",
        "dbt-core",
        "sqlfluff",
        "diff-cover",
        "cargo-mutants",
        "mutmut",
    ] {
        let version = &pins.tool(tool).unwrap().version;
        assert!(
            !version.is_empty() && version.chars().all(|c| c.is_ascii_digit() || c == '.'),
            "{tool}: version `{version}`"
        );
    }
    assert_eq!(
        pins.actions["actions/cache/restore"].sha,
        pins.actions["actions/cache/save"].sha
    );
}

#[test]
fn lookups_by_name() {
    let pins = table();
    let node = pins.action("actions/setup-node").unwrap();
    assert_eq!(node.repo, "actions/setup-node");
    assert_eq!(node.sha, pins.actions["actions/setup-node"].sha);
    assert_eq!(node.version, pins.actions["actions/setup-node"].version);
    assert_eq!(
        node.uses(),
        format!("{}@{} # {}", node.repo, node.sha, node.version)
    );

    let image = pins.image("distroless.static").unwrap();
    assert_eq!(image.reference, "gcr.io/distroless/static-debian12:nonroot");
    assert_eq!(
        image.pinned(),
        format!("{}@{}", image.reference, image.digest)
    );

    assert_eq!(pins.tool("rust").unwrap().version, "1.99");
}

#[test]
fn a_missing_key_refuses_naming_it() {
    let pins = table();
    assert_eq!(
        pins.action("actions/missing").unwrap_err().to_string(),
        "stack-packs: action `actions/missing` is not in templates/stack-packs/pins.json; add it with its sha before rendering"
    );
    assert_eq!(
        pins.image("dhi.static").unwrap_err().to_string(),
        "stack-packs: image `dhi.static` is not in templates/stack-packs/pins.json; add it with its digest before rendering"
    );
    assert_eq!(
        pins.tool("bun").unwrap_err().to_string(),
        "stack-packs: tool `bun` is not in templates/stack-packs/pins.json; add it with its version before rendering"
    );
}

#[test]
fn last_verified_parses_and_staleness_uses_the_given_clock() {
    let pins = table();
    assert_eq!(PIN_VERIFICATION_DAYS, 30);
    let verified = pins.last_verified;
    assert!(verified >= NaiveDate::from_ymd_opt(2026, 10, 28).unwrap());
    let limit = verified + chrono::Days::new(30);
    assert_eq!(pins.age_days(limit), 30);
    assert_eq!(pins.stale_finding(limit, 30), None);
    let day_after = limit + chrono::Days::new(1);
    assert_eq!(
        pins.stale_finding(day_after, 30),
        Some(format!(
            "stack.pin-table-stale: pin table last verified {verified}, 31 days ago (limit 30)"
        ))
    );
    assert_eq!(pins.age_days(verified - chrono::Days::new(5)), -5);
}

const VALID: &str = r#"{
  "last_verified": "2026-10-28",
  "actions": { "a/b": { "sha": "0123456789abcdef0123456789abcdef01234567", "version": "v1.2.3" } },
  "images": { "x.build": { "ref": "docker.io/library/x:1-slim", "digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" } },
  "tools": { "x": { "version": "1.0.0" } }
}"#;

#[test]
fn parse_refuses_a_malformed_table() {
    assert!(PinTable::parse(VALID).is_ok());
    let cases = [
        (
            VALID.replace("2026-10-28", "28/10/2026"),
            "stack-packs: last_verified `28/10/2026` in templates/stack-packs/pins.json is not a YYYY-MM-DD date",
        ),
        (
            VALID.replace("0123456789abcdef0123456789abcdef01234567", "v1.2.3"),
            "stack-packs: action `a/b` in templates/stack-packs/pins.json has sha `v1.2.3`; a pin is 40 lowercase hex",
        ),
        (
            VALID.replace("sha256:0123456789abcdef", "sha256:0123456789ABCDEF"),
            "stack-packs: image `x.build` in templates/stack-packs/pins.json has digest `sha256:0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef`; a pin is sha256: plus 64 lowercase hex",
        ),
        (
            VALID.replace("x:1-slim", "x:latest"),
            "stack-packs: image `x.build` in templates/stack-packs/pins.json has ref `docker.io/library/x:latest`; a ref carries a tag other than latest and no digest",
        ),
        (
            VALID.replace("x:1-slim", "x"),
            "stack-packs: image `x.build` in templates/stack-packs/pins.json has ref `docker.io/library/x`; a ref carries a tag other than latest and no digest",
        ),
        (
            VALID.replace("x:1-slim", "x:1-slim@sha256:abc"),
            "stack-packs: image `x.build` in templates/stack-packs/pins.json has ref `docker.io/library/x:1-slim@sha256:abc`; a ref carries a tag other than latest and no digest",
        ),
        (
            VALID.replace("\"1.0.0\"", "\"\""),
            "stack-packs: tool `x` in templates/stack-packs/pins.json has an empty version",
        ),
    ];
    for (text, message) in cases {
        assert_eq!(PinTable::parse(&text).unwrap_err().to_string(), message);
    }
    let unknown = PinTable::parse(&VALID.replace("\"tools\"", "\"tool\""));
    assert!(
        unknown.is_err(),
        "an unknown top-level key is a typo, not data"
    );
}

#[test]
fn step_and_action_ref_serialize_as_ci_baseline_embeds_them() {
    let pins = table();
    let step = Step::new("Set up node")
        .uses(pins.action("actions/setup-node").unwrap())
        .with("node-version-file", ".nvmrc")
        .with("package-manager-cache", "false");
    let json = serde_json::to_value(&step).unwrap();
    assert_eq!(json["name"], "Set up node");
    assert_eq!(json["uses"]["repo"], "actions/setup-node");
    assert_eq!(json["with"]["package-manager-cache"], "false");
    assert!(json.get("run").is_none() && json.get("env").is_none());
    assert!(json.get("if").is_none() && json.get("working-directory").is_none());

    let save = Step::new("Save cache")
        .run("echo")
        .working_directory("apps/web")
        .env("GOFLAGS", "-mod=readonly")
        .only_on_default_branch();
    assert_eq!(save.condition.as_deref(), Some(DEFAULT_BRANCH_CONDITION));
    assert_eq!(
        DEFAULT_BRANCH_CONDITION,
        "github.ref == format('refs/heads/{0}', github.event.repository.default_branch)"
    );
    let json = serde_json::to_value(&save).unwrap();
    assert_eq!(json["if"], DEFAULT_BRANCH_CONDITION);
    assert_eq!(json["working-directory"], "apps/web");
    assert_eq!(json["env"]["GOFLAGS"], "-mod=readonly");
    assert!(json.get("uses").is_none() && json.get("with").is_none());

    let action = ActionRef {
        repo: "a/b".into(),
        sha: "0".repeat(40),
        version: "v1".into(),
    };
    assert_eq!(action.uses(), format!("a/b@{} # v1", "0".repeat(40)));
}

#[test]
fn stack_ids_are_kebab_case_and_ordered() {
    let ids: Vec<String> = StackId::ALL
        .iter()
        .map(|id| serde_json::to_string(id).unwrap())
        .collect();
    assert_eq!(
        ids,
        [
            "\"rust\"",
            "\"python-uv\"",
            "\"node\"",
            "\"go\"",
            "\"kotlin-android\"",
            "\"swift-ios\"",
            "\"sql-dbt\""
        ]
    );
    assert_eq!(
        serde_json::from_str::<StackId>("\"python-uv\"").unwrap(),
        StackId::PythonUv
    );
    assert_eq!(StackId::PythonUv.as_str(), "python-uv");
    assert_eq!(StackId::PythonUv.to_string(), "python-uv");
    assert_eq!("go".parse::<StackId>().unwrap(), StackId::Go);
    assert_eq!(
        "ruby".parse::<StackId>().unwrap_err().to_string(),
        "stack-packs: `ruby` is not a stack; one of rust, python-uv, node, go, kotlin-android, swift-ios, sql-dbt"
    );
}

// ---- binary pins: tools installed by URL and SHA-256 (qa T1, #997) -------

const HURL_RELEASE: &str = "https://github.com/Orange-OpenSource/hurl/releases/download/8.1.0/";

#[test]
fn hurl_is_pinned_by_checksum_for_both_architectures() {
    let pins = table();
    let hurl = pins.tool("hurl").unwrap();
    assert_eq!(hurl.version, "8.1.0");
    let binary = hurl.binary.as_ref().expect("hurl is a binary pin");
    assert_eq!(binary.released, "2026-10-28");
    assert_eq!(binary.bin, "hurl");
    assert_eq!(binary.format, BinaryFormat::Tgz);
    assert_eq!(binary.bin_path.as_deref(), Some("hurl-*/bin/hurl"));
    assert_eq!(
        binary.checksums,
        "https://github.com/Orange-OpenSource/hurl/releases/tag/8.1.0"
    );
    for (artifact, triple) in [
        (&binary.amd64, "x86_64-unknown-linux-gnu"),
        (&binary.arm64, "aarch64-unknown-linux-gnu"),
    ] {
        assert_eq!(
            artifact.url,
            format!("{HURL_RELEASE}hurl-8.1.0-{triple}.tar.gz")
        );
        assert!(
            is_hex(&artifact.sha256, 64),
            "{triple}: {}",
            artifact.sha256
        );
    }
    assert_ne!(binary.amd64.sha256, binary.arm64.sha256);
}

// ---- contract tools (qa T17, #1016; SPEC-qa.md, Contracts) ------------------

/// vacuum and oasdiff by checksum per architecture, the binary at the archive's
/// root; the SHA-256 values are upstream's `checksums.txt` lines (2026-10-30).
#[test]
fn vacuum_and_oasdiff_are_pinned_by_checksum_for_both_architectures() {
    let pins = table();
    for (key, version, release, released, amd64, arm64) in [
        (
            "vacuum",
            "0.35.0",
            "https://github.com/daveshanley/vacuum/releases/download/v0.35.0/",
            "2026-10-22",
            (
                "vacuum_0.35.0_linux_x86_64.tar.gz",
                "1732561b38f065b16b60a89bdc248e690c643a1fbfd34a4fbcbf423b27177d4e",
            ),
            (
                "vacuum_0.35.0_linux_arm64.tar.gz",
                "76417f0fd6f5bfd69cbd8fd1d8367aaff5c2122416a5eaeda82b469965942b8a",
            ),
        ),
        (
            "oasdiff",
            "1.34.1",
            "https://github.com/oasdiff/oasdiff/releases/download/v1.34.1/",
            "2026-10-21",
            (
                "oasdiff_1.34.1_linux_amd64.tar.gz",
                "75775f65b0adebd26a8e013af51a799342dfdc6262d89efa9e3b7bdf89657d90",
            ),
            (
                "oasdiff_1.34.1_linux_arm64.tar.gz",
                "e8f99bbf102a4b7f235104da72d0b9d67702e78622d1d4d37169e698ee90a249",
            ),
        ),
    ] {
        let pin = pins.tool(key).unwrap();
        assert_eq!(pin.version, version, "{key}");
        let binary = pin.binary.as_ref().expect("a binary pin");
        assert_eq!(binary.bin, key);
        assert_eq!(binary.format, BinaryFormat::Tgz);
        assert_eq!(
            binary.bin_path, None,
            "{key}: the binary is at the archive's root"
        );
        assert_eq!(binary.released, released);
        assert_eq!(binary.checksums, format!("{release}checksums.txt"));
        for (artifact, (name, sha)) in [(&binary.amd64, amd64), (&binary.arm64, arm64)] {
            assert_eq!(artifact.url, format!("{release}{name}"));
            assert!(is_hex(&artifact.sha256, 64));
            assert_eq!(artifact.sha256, sha);
        }
    }
}

#[test]
fn the_asyncapi_cli_is_an_exact_npm_version() {
    let pins = table();
    let pin = pins.tool("asyncapi-cli").unwrap();
    assert_eq!(pin.version, "6.2.1");
    assert!(pin.binary.is_none());
    // `@asyncapi/cli` 6.2.1 requires Node >= 24.
    let node: u32 = pins
        .tool("node")
        .unwrap()
        .version
        .split('.')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert!(node >= 24, "{node}");
}

#[test]
fn playwright_tool_and_image_are_the_same_release() {
    let pins = table();
    let version = &pins.tool("playwright").unwrap().version;
    assert_eq!(version, "1.64.1");
    let image = pins.image("playwright").unwrap();
    assert_eq!(
        image.reference,
        format!("mcr.microsoft.com/playwright:v{version}-noble")
    );
    assert_eq!(
        dockerfile_froms().get(&image.reference),
        Some(&image.digest),
        "images.playwright has its FROM line in {PINS_DOCKERFILE_PATH}"
    );
    assert!(pins.tool("playwright").unwrap().binary.is_none());
}

#[test]
fn tool_binary_yields_the_install_fragment_env() {
    let pins = table();
    let env = pins.tool_binary("hurl").unwrap();
    let names: Vec<&str> = env.iter().map(|(k, _)| *k).collect();
    assert_eq!(
        names,
        [
            "TOOL_NAME",
            "TOOL_VERSION",
            "TOOL_BIN",
            "TOOL_FORMAT",
            "TOOL_URL_AMD64",
            "TOOL_SHA256_AMD64",
            "TOOL_URL_ARM64",
            "TOOL_SHA256_ARM64",
            "TOOL_BIN_PATH",
        ]
    );
    let value = |k: &str| env.iter().find(|(n, _)| *n == k).unwrap().1.clone();
    assert_eq!(value("TOOL_NAME"), "hurl");
    assert_eq!(value("TOOL_VERSION"), "8.1.0");
    assert_eq!(value("TOOL_FORMAT"), "tgz");
    assert_eq!(value("TOOL_BIN_PATH"), "hurl-*/bin/hurl");
}

#[test]
fn tool_binary_refuses_a_tool_pinned_by_version_only() {
    let pins = table();
    let err = pins.tool_binary("rust").unwrap_err().to_string();
    assert!(err.contains("tools.rust has no binary pin"), "{err}");
    let err = pins.tool_binary("absent").unwrap_err().to_string();
    assert!(err.contains("tool `absent` is not in"), "{err}");
}

const BINARY: &str = r#"{
  "last_verified": "2026-10-28",
  "actions": {},
  "images": {},
  "tools": {
    "x": { "version": "1.0.0" },
    "y": { "version": "2.0.0", "released": "2026-10-01", "bin": "y", "format": "tgz",
           "bin_path": "y-*/bin/y",
           "checksums": "https://github.com/o/y/releases/download/2.0.0/SHA256SUMS",
           "amd64": { "url": "https://github.com/o/y/releases/download/2.0.0/y-x86_64.tar.gz",
                      "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" },
           "arm64": { "url": "https://github.com/o/y/releases/download/2.0.0/y-aarch64.tar.gz",
                      "sha256": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210" } }
  }
}"#;

#[test]
fn a_binary_pin_parses_beside_a_version_only_one() {
    let pins = PinTable::parse(BINARY).unwrap();
    assert!(pins.tool("x").unwrap().binary.is_none());
    assert!(pins.tool("y").unwrap().binary.is_some());
    assert_eq!(pins.tool_binary("y").unwrap().len(), 9);
    let without_path =
        PinTable::parse(&BINARY.replace("\"bin_path\": \"y-*/bin/y\",", "")).unwrap();
    let env = without_path.tool_binary("y").unwrap();
    assert_eq!(
        env.len(),
        8,
        "no TOOL_BIN_PATH when the binary is at the root"
    );
}

#[test]
fn a_malformed_binary_pin_refuses_naming_the_key() {
    let arm64 = r#",
           "arm64": { "url": "https://github.com/o/y/releases/download/2.0.0/y-aarch64.tar.gz",
                      "sha256": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210" }"#;
    let cases = [
        (
            BINARY.replace(
                "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
                "FEDCBA9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
            ),
            "stack-packs: tool `y` in templates/stack-packs/pins.json has sha256 `FEDCBA9876543210fedcba9876543210fedcba9876543210fedcba9876543210` for arm64; a checksum is 64 lowercase hex",
        ),
        (
            BINARY.replace(arm64, ""),
            "stack-packs: tool `y` in templates/stack-packs/pins.json has a binary pin without `arm64`",
        ),
        (
            BINARY.replace("\"released\": \"2026-10-01\", ", ""),
            "stack-packs: tool `y` in templates/stack-packs/pins.json has a binary pin without `released`",
        ),
        (
            BINARY.replace("download/2.0.0/y-x86_64", "download/1.9.0/y-x86_64"),
            "stack-packs: tool `y` in templates/stack-packs/pins.json has amd64 URL `https://github.com/o/y/releases/download/1.9.0/y-x86_64.tar.gz`; a binary URL is https and names version 2.0.0",
        ),
        (
            BINARY.replace("y-*/bin/y", "../y"),
            "stack-packs: tool `y` in templates/stack-packs/pins.json has bin_path `../y`; it is relative to the archive root without ..",
        ),
        (
            BINARY.replace("\"format\": \"tgz\"", "\"format\": \"bin\""),
            "stack-packs: tool `y` in templates/stack-packs/pins.json has bin_path `y-*/bin/y` with format bin; bin_path needs tgz",
        ),
    ];
    for (text, message) in cases {
        assert_eq!(PinTable::parse(&text).unwrap_err().to_string(), message);
    }
    for bad in [
        BINARY.replace("\"format\": \"tgz\"", "\"format\": \"zip\""),
        BINARY.replace("\"bin\": \"y\",", "\"bin\": \"y\", \"extra\": 1,"),
    ] {
        assert!(PinTable::parse(&bad).is_err(), "unknown format or field");
    }
}

/// #29: an action bump here is a pin-table bump (the table, every workflow that uses
/// the action and the goldens move together), which Dependabot alone cannot make.
/// Its `github-actions` updates, majors included, therefore arrive as one grouped
/// pull request: the task a maintainer completes on that branch (design.md, "One
/// shared pin table"), never one pull request per action that can never pass.
#[test]
fn dependabot_groups_every_action_bump_into_one_pull_request() {
    use yaml_rust2::{Yaml, YamlLoader};
    let text = fs::read_to_string(repo_root().join(".github/dependabot.yml")).unwrap();
    let doc = &YamlLoader::load_from_str(&text).unwrap()[0];
    let actions: Vec<&Yaml> = doc["updates"]
        .as_vec()
        .unwrap()
        .iter()
        .filter(|u| u["package-ecosystem"].as_str() == Some("github-actions"))
        .collect();
    assert_eq!(actions.len(), 1, "one github-actions entry");
    let groups = actions[0]["groups"]
        .as_hash()
        .expect("github-actions has groups");
    assert_eq!(groups.len(), 1, "one group: {groups:?}");
    let group = groups.values().next().unwrap();
    assert_eq!(
        group["patterns"],
        Yaml::Array(vec![Yaml::String("*".into())]),
        "the group takes every action"
    );
    assert!(
        group["update-types"].is_badvalue(),
        "the group takes every update type, majors included: {group:?}"
    );
}
