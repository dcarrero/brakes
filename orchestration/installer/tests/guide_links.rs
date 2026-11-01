//! product-boundary T10b (#1247): what the installer renders names only documents
//! the same build installs. Without `setup-core` (the product), no form, guide or
//! datum points at an engineering guide that only `setup-core` installs.
use brakes::modules::stack_packs::packs;
use std::{collections::BTreeSet, fs, path::Path, process::Command};

/// Every module this build compiles in, installed into a fresh repository with the
/// widest profile, as the CLI does.
fn rendered() -> tempfile::TempDir {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .arg(root)
            .status()
            .unwrap()
            .success()
    );
    fs::write(root.join("Cargo.toml"), "").unwrap();
    fs::write(root.join("Cargo.lock"), "").unwrap();
    fs::create_dir_all(root.join(".agent-setup/modules")).unwrap();
    fs::write(
        root.join(".agent-setup/modules/stack-packs.json"),
        r#"{"module": "stack-packs", "version": "1.0.0", "answers": {"apps.root.path": ".", "apps.root.stack": "rust", "apps.root.container": false}}"#,
    )
    .unwrap();
    let cli = |args: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_brakes"))
            .arg("install")
            .arg(root)
            .args(args)
            .output()
            .unwrap();
        assert!(out.status.success(), "{args:?}: {out:?}");
    };
    cli(&["--new-personal", "--apply"]);
    let profile = root.join(".agent-setup/project.json");
    let mut value: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&profile).unwrap()).unwrap();
    value["commands"]["test"] = "cargo test".into();
    fs::write(
        &profile,
        serde_json::to_string_pretty(&value).unwrap() + "\n",
    )
    .unwrap();
    let mut args = vec!["--profile", "P3", "--no-input", "--apply"];
    for module in brakes::modules::all() {
        args.extend(["--module", module.id()]);
    }
    cli(&args);
    temp
}

fn files(dir: &Path, base: &Path, acc: &mut Vec<String>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.file_name().is_some_and(|n| n == ".git") {
            continue;
        }
        if path.is_dir() {
            files(&path, base, acc);
        } else {
            acc.push(
                path.strip_prefix(base)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
            );
        }
    }
}

/// `docs/agent-setup/<name>.md|json` named anywhere in `text`, placeholders aside.
fn guide_paths(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    let prefix = "docs/agent-setup/";
    let mut rest = text;
    while let Some(i) = rest.find(prefix) {
        let tail = &rest[i..];
        let end = tail
            .find(|c: char| !(c.is_ascii_alphanumeric() || "/._-".contains(c)))
            .unwrap_or(tail.len());
        let path = tail[..end].trim_end_matches('.');
        let placeholder = tail[end..].starts_with(['<', '{']);
        if !placeholder && (path.ends_with(".md") || path.ends_with(".json")) {
            found.push(path.to_owned());
        }
        rest = &tail[end.max(1)..];
    }
    found
}

/// The agent host's instruction files: a guide names them as concepts, not as guides.
const ENTRYPOINTS: [&str; 2] = ["AGENTS.md", "CLAUDE.md"];

/// Bare `` `<name>.md` `` siblings a rendered guide names, entrypoints aside.
fn sibling_names(text: &str) -> Vec<String> {
    text.split('`')
        .skip(1)
        .step_by(2)
        .filter(|s| s.ends_with(".md") && s.len() > 3 && !s.contains(['/', ' ', '<', '{', '*']))
        .filter(|s| !ENTRYPOINTS.contains(s))
        .map(str::to_owned)
        .collect()
}

#[test]
fn every_document_the_rendered_repository_names_exists() {
    let repo = rendered();
    let root = repo.path();
    let mut all = Vec::new();
    files(root, root, &mut all);
    let present: BTreeSet<&str> = all.iter().map(String::as_str).collect();
    assert!(present.contains("AGENTS.md"), "{present:?}");
    let mut dangling = Vec::new();
    for path in &all {
        let Ok(text) = fs::read_to_string(root.join(path)) else {
            continue;
        };
        for named in guide_paths(&text) {
            if !present.contains(named.as_str()) {
                dangling.push(format!("{path}: {named}"));
            }
        }
        if path.starts_with("docs/agent-setup/") && path.ends_with(".md") {
            for name in sibling_names(&text) {
                let sibling = format!("docs/agent-setup/{name}");
                if !present.contains(sibling.as_str()) && !present.contains(name.as_str()) {
                    dangling.push(format!("{path}: {name}"));
                }
            }
        }
    }
    assert_eq!(dangling, Vec::<String>::new());
}

#[test]
fn the_extractors_skip_placeholders_and_paths() {
    assert_eq!(
        guide_paths(
            "see docs/agent-setup/a.md. and `docs/agent-setup/integrations/<id>.md`, docs/agent-setup/{n}"
        ),
        ["docs/agent-setup/a.md"]
    );
    assert_eq!(
        sibling_names("`a.md`, `docs/b.md`, `two words.md`, `*.md`, `c.json`, `CLAUDE.md`"),
        ["a.md"]
    );
}

#[cfg(not(feature = "setup-core"))]
#[test]
fn without_setup_core_no_pack_names_a_guide() {
    for pack in packs::ALL {
        if let Some(otel) = pack.otel {
            assert_eq!(otel.guide, None, "{}", pack.id);
        }
    }
}

#[cfg(feature = "setup-core")]
#[test]
fn with_setup_core_every_pack_guide_is_a_document_it_installs() {
    let installed: BTreeSet<String> = brakes::DOCUMENTS
        .iter()
        .map(|(name, _)| format!("docs/agent-setup/{name}"))
        .collect();
    let mut named = 0;
    for pack in packs::ALL {
        if let Some(guide) = pack.otel.and_then(|o| o.guide) {
            let path = guide.split_once('#').map_or(guide, |(p, _)| p);
            assert!(installed.contains(path), "{}: {guide}", pack.id);
            named += 1;
        }
    }
    assert!(named > 0);
}

#[test]
fn the_obsolete_planning_finding_names_the_workflow_guide_only_with_setup_core() {
    let repo = rendered();
    let profile = repo.path().join(".agent-setup/project.json");
    let mut value: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&profile).unwrap()).unwrap();
    value["planning"] = "anything".into();
    fs::write(
        &profile,
        serde_json::to_string_pretty(&value).unwrap() + "\n",
    )
    .unwrap();
    let guide = if cfg!(feature = "setup-core") {
        " (docs/agent-setup/workflow.md)"
    } else {
        ""
    };
    let expected = format!(
        "Obsolete profile field: planning; the workflow is a project convention{guide}, remove the field"
    );
    let findings = brakes::doctor(repo.path()).unwrap();
    assert!(findings.contains(&expected), "{findings:#?}");
}

#[test]
fn setup_core_text_keeps_marked_text_only_with_setup_core() {
    let template = "done[[setup-core: (see `task.md`)]].\nnext[[setup-core:\n- `e2e.md`\n]]end\n";
    let expected = if cfg!(feature = "setup-core") {
        "done (see `task.md`).\nnext\n- `e2e.md`\nend\n"
    } else {
        "done.\nnextend\n"
    };
    assert_eq!(brakes::setup_core_text(template).unwrap(), expected);
    assert!(brakes::setup_core_text("a[[setup-core: open").is_err());
}
