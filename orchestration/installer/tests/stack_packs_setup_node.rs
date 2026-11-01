//! #1166: every rendered `actions/setup-node` step passes only inputs the
//! pinned action declares, and `cache` (when present) names a package manager.
//! A product rollout (#1157) failed at `Set up Node` with
//! `Caching for 'false' is not supported`: in setup-node `cache` is a package
//! manager name, and `package-manager-cache: false` is the input that turns
//! its automatic caching off (SPEC-stack-packs.md, CI setup as data).
use brakes::modules::stack_packs::{App, PackageManager, PinTable, StackId, packs};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

/// The inputs of `actions/setup-node` at the pinned v7.1.0
/// (949feb2413d6458794dcd2491c4babbbce0c15c1), read from its `action.yml` with
/// `gh api repos/actions/setup-node/contents/action.yml?ref=<sha>` on 2026-10-30.
const SETUP_NODE_INPUTS: [&str; 12] = [
    "node-version",
    "node-version-file",
    "architecture",
    "check-latest",
    "registry-url",
    "scope",
    "token",
    "cache",
    "package-manager-cache",
    "cache-dependency-path",
    "mirror",
    "mirror-token",
];
const PINNED_SHA: &str = "949feb2413d6458794dcd2491c4babbbce0c15c1";
/// `cache`: "Supported values: npm, yarn, pnpm."
const CACHE_VALUES: [&str; 3] = ["npm", "yarn", "pnpm"];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The problems of one setup-node step's `with:` map, `at` naming it.
fn check(at: &str, with: &BTreeMap<String, String>) -> Vec<String> {
    let mut out = Vec::new();
    for (key, value) in with {
        if !SETUP_NODE_INPUTS.contains(&key.as_str()) {
            out.push(format!("{at}: `{key}` is not an input of setup-node"));
        }
        if key == "cache" && !CACHE_VALUES.contains(&value.as_str()) {
            out.push(format!("{at}: cache `{value}` is not a package manager"));
        }
    }
    out
}

fn node_app(path: &str, pm: PackageManager, toolchain: bool) -> App {
    App {
        id: "web".to_owned(),
        path: path.to_owned(),
        stack: StackId::Node,
        container: false,
        toolchain,
        package_manager: Some(pm),
        declared: BTreeMap::new(),
    }
}

#[test]
fn the_node_pack_turns_setup_nodes_own_cache_off_with_an_input_it_declares() {
    let pins = PinTable::embedded().unwrap();
    let app = node_app("web", PackageManager::Npm, true);
    let steps = (packs::pack(StackId::Node).ci_setup)(&app, &pins).unwrap();
    let json = serde_json::to_value(&steps).unwrap();
    let node = json
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == "Set up Node")
        .unwrap();
    assert_eq!(node["uses"]["sha"], PINNED_SHA);
    assert_eq!(
        node["with"],
        serde_json::json!({"package-manager-cache": "false", "node-version-file": "web/.nvmrc"})
    );
    // The explicit pair stays: restore before the install, save after it.
    let names: Vec<&str> = json
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "Set up Node",
            "Restore npm store",
            "Install dependencies",
            "Save npm store"
        ]
    );
}

#[test]
fn every_node_package_manager_renders_valid_setup_node_inputs() {
    let pins = PinTable::embedded().unwrap();
    let mut problems = Vec::new();
    for pm in PackageManager::ALL {
        for toolchain in [true, false] {
            let app = node_app(".", pm, toolchain);
            let steps = (packs::pack(StackId::Node).ci_setup)(&app, &pins).unwrap();
            for step in serde_json::to_value(&steps).unwrap().as_array().unwrap() {
                if step["uses"]["repo"] == "actions/setup-node" {
                    problems.extend(check(&format!("{pm} toolchain={toolchain}"), &with(step)));
                }
            }
        }
    }
    assert_eq!(problems, Vec::<String>::new());
}

fn with(step: &Value) -> BTreeMap<String, String> {
    step["with"]
        .as_object()
        .map(|m| {
            m.iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_owned()))
                .collect()
        })
        .unwrap_or_default()
}

/// Every `.yml`/`.yaml` under `dir`, recursively.
fn yaml_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            yaml_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "yml" || e == "yaml") {
            out.push(path);
        }
    }
}

/// The `with:` maps of every `uses: actions/setup-node@` step in a workflow's
/// text: the keys indented under the step's `with:` line.
fn setup_node_steps(text: &str) -> Vec<(usize, BTreeMap<String, String>)> {
    let lines: Vec<&str> = text.lines().collect();
    let indent = |line: &str| line.len() - line.trim_start().len();
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start().trim_start_matches("- ");
        if !trimmed.starts_with("uses: actions/setup-node@") {
            continue;
        }
        let step_indent = indent(line);
        let mut with = BTreeMap::new();
        let mut j = i + 1;
        while j < lines.len() && (lines[j].trim().is_empty() || indent(lines[j]) >= step_indent) {
            if lines[j].trim_start().starts_with("- ") && indent(lines[j]) < step_indent + 1 {
                break;
            }
            if lines[j].trim() == "with:" {
                let with_indent = indent(lines[j]);
                j += 1;
                while j < lines.len() && indent(lines[j]) > with_indent {
                    if let Some((k, v)) = lines[j].trim().split_once(':') {
                        with.insert(k.trim().to_owned(), v.trim().trim_matches('"').to_owned());
                    }
                    j += 1;
                }
                break;
            }
            j += 1;
        }
        out.push((i + 1, with));
    }
    out
}

#[test]
fn the_parser_reads_the_with_block_of_a_setup_node_step() {
    let text = "steps:\n  - name: Set up Node\n    uses: actions/setup-node@abc # v7\n    with:\n      cache: \"false\"\n      node-version: \"24\"\n  - name: Next\n    run: echo\n";
    let steps = setup_node_steps(text);
    assert_eq!(steps.len(), 1);
    assert_eq!(steps[0].1["cache"], "false");
    assert_eq!(steps[0].1["node-version"], "24");
    assert_eq!(
        check("x", &steps[0].1),
        ["x: cache `false` is not a package manager"]
    );
}

/// The goldens and this repository's own workflows are renders of the packs
/// and the qa jobs; none may carry a setup-node input the pin rejects.
#[test]
fn no_rendered_workflow_passes_setup_node_an_input_it_rejects() {
    let root = repo_root();
    let mut files = Vec::new();
    for dir in [
        "templates",
        ".github/workflows",
        "orchestration/installer/tests/golden",
    ] {
        yaml_files(&root.join(dir), &mut files);
    }
    let mut seen = 0;
    let mut problems = Vec::new();
    for file in files {
        let text = fs::read_to_string(&file).unwrap();
        for (line, with) in setup_node_steps(&text) {
            seen += 1;
            let at = format!(
                "{}:{line}",
                file.strip_prefix(&root).unwrap_or(&file).display()
            );
            problems.extend(check(&at, &with));
        }
    }
    assert!(seen > 0, "no setup-node step found; the scan reads nothing");
    assert_eq!(problems, Vec::<String>::new());
}
