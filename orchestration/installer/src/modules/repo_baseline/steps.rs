//! The GitHub-side changes of repo-baseline (SPEC-repo-baseline.md, Remote items
//! and the manual step; T6, #707). Decision #848: each change is a `remote` item
//! (`github:<id>`, recorded in the lock, never written by the engine) that
//! `apply --remote` writes through host-adapter and verifies with the probe of the
//! step of the same id. `check-reported` stays a manual step: CI reports it.
//! The module declares only; it never calls GitHub. Every instruction is the
//! exact `gh` command equivalent to the write; `{owner}/{repo}` are `gh api`
//! placeholders resolved by `gh` from the checkout it runs in.
use crate::Result;
use crate::engine::{
    Rendered,
    lock::Ownership,
    manual::{ManualStep, Owner, Probe},
};
use crate::host::{
    desired::{Desired, RemoteWrite, Supersession, ruleset_from_file},
    types::{Label, RepositorySettingsPatch},
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::Path;

use super::ruleset::{REVIEW_RULESET_NAME, RULESET_NAME};
use super::{REVIEW_RULESET_PATH, RULESET_PATH};

/// The standard label set: data for the `labels` item and the auditor.
pub const LABELS: &str = include_str!("../../../../../templates/repo-baseline/labels.json");

/// The remote item of the review ruleset, declared only with a bypass (#1218).
pub const REVIEW_ITEM: &str = "ruleset-review";

/// The ids of the remote items, in declaration order.
pub const REMOTE_ITEMS: [&str; 6] = [
    "ruleset-main",
    "classic-protection-retire",
    "labels",
    "repo-settings",
    "dependabot-alerts",
    "dependabot-security-updates",
];

/// The repository settings the `repo-settings` item writes, in the spec's order.
const SETTINGS: [(&str, bool); 6] = [
    ("allow_squash_merge", true),
    ("allow_merge_commit", false),
    ("allow_rebase_merge", false),
    ("delete_branch_on_merge", true),
    ("allow_auto_merge", true),
    ("allow_update_branch", true),
];

/// The lock entries of the remote items: class `remote`, no content; the
/// review ruleset's after `ruleset-main` when `split`.
pub fn remote_items(split: bool) -> Vec<Rendered> {
    let mut ids: Vec<&str> = REMOTE_ITEMS.to_vec();
    if split {
        ids.insert(1, REVIEW_ITEM);
    }
    ids.into_iter()
        .map(|id| Rendered {
            path: format!("github:{id}"),
            class: Ownership::Remote,
            content: None,
            scaffold: None,
        })
        .collect()
}

/// The labels of `labels.json`; empty only if the embedded file were malformed,
/// which `render` refuses and a test pins.
pub fn labels() -> Vec<Value> {
    serde_json::from_str(LABELS).unwrap_or_default()
}

/// The default branch from `refs/remotes/origin/HEAD`, else `main`. Read as a
/// file (a symbolic ref is never packed), following a worktree's `gitdir:` and
/// `commondir`; no command runs.
pub fn default_branch(root: &Path) -> String {
    let dot_git = root.join(".git");
    let git_dir = match std::fs::read_to_string(&dot_git) {
        Ok(text) => match text.trim().strip_prefix("gitdir:") {
            Some(dir) => root.join(dir.trim()),
            None => dot_git,
        },
        Err(_) => dot_git,
    };
    let common = match std::fs::read_to_string(git_dir.join("commondir")) {
        Ok(dir) => git_dir.join(dir.trim()),
        Err(_) => git_dir,
    };
    std::fs::read_to_string(common.join("refs/remotes/origin/HEAD"))
        .ok()
        .and_then(|head| {
            head.trim()
                .strip_prefix("ref: refs/remotes/origin/")
                .map(str::to_owned)
        })
        .filter(|branch| !branch.is_empty())
        .unwrap_or_else(|| "main".to_owned())
}

/// The manual step and the probes of the remote items, for a repository at
/// `root` whose ruleset requires `contexts`. `ruleset-main` waits for
/// `check-reported`, and `classic-protection-retire` for `ruleset-main`, so no
/// control is removed before its replacement is in force.
pub fn steps(root: &Path, contexts: &[String], split: bool) -> Vec<ManualStep> {
    let branch = default_branch(root);
    let step = |id: &str,
                owner: Owner,
                title: String,
                instructions: String,
                probe: &str,
                args: Value,
                after: Option<&str>| ManualStep {
        id: id.to_owned(),
        title,
        owner,
        instructions,
        probe: Probe::Remote {
            id: probe.to_owned(),
            args: serde_json::from_value::<BTreeMap<String, Value>>(args).unwrap_or_default(),
        },
        after: after.map(str::to_owned),
    };
    let labels = labels();
    let label_commands = labels
        .iter()
        .map(|label| {
            let text = |key: &str| label[key].as_str().unwrap_or_default();
            format!(
                "gh label create \"{}\" --color {} --description \"{}\" --force",
                text("name"),
                text("color"),
                text("description")
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let settings_flags = SETTINGS
        .iter()
        .map(|(key, value)| format!(" -F {key}={value}"))
        .collect::<String>();
    let fields: serde_json::Map<String, Value> = SETTINGS
        .iter()
        .map(|(key, value)| ((*key).to_owned(), json!(value)))
        .collect();
    let review = step(
        REVIEW_ITEM,
        Owner::Owner,
        "Remote item: the review ruleset is active and equals .github/rulesets/main-review.json"
            .to_owned(),
        format!(
            "gh api -X POST repos/{{owner}}/{{repo}}/rulesets --input {REVIEW_RULESET_PATH}\n\
             # when doctor reports a ruleset of that name with different rules (id <id>):\n\
             gh api -X PUT repos/{{owner}}/{{repo}}/rulesets/<id> --input {REVIEW_RULESET_PATH}"
        ),
        "ruleset-present",
        json!({ "name": REVIEW_RULESET_NAME, "branch": branch, "path": REVIEW_RULESET_PATH }),
        Some("ruleset-main"),
    );
    let mut steps = vec![
        step(
            "check-reported",
            Owner::Platform,
            format!("CI reports the required checks on {branch}"),
            format!(
                "Nothing to run: wait until ci-baseline has reported the required checks on {branch}."
            ),
            "check-run-reported",
            json!({ "contexts": contexts, "branch": branch }),
            None,
        ),
        step(
            "ruleset-main",
            Owner::Owner,
            "Remote item: the default-branch ruleset is active and equals .github/rulesets/main.json"
                .to_owned(),
            format!(
                "gh api -X POST repos/{{owner}}/{{repo}}/rulesets --input {RULESET_PATH}\n\
                 # when doctor reports a ruleset of that name with different rules (id <id>):\n\
                 gh api -X PUT repos/{{owner}}/{{repo}}/rulesets/<id> --input {RULESET_PATH}"
            ),
            "ruleset-present",
            json!({ "name": RULESET_NAME, "branch": branch, "path": RULESET_PATH }),
            Some("check-reported"),
        ),
        step(
            "classic-protection-retire",
            Owner::Owner,
            format!("Remote item: no classic branch protection on {branch}"),
            format!("gh api -X DELETE repos/{{owner}}/{{repo}}/branches/{branch}/protection"),
            "classic-protection-absent",
            json!({ "branch": branch }),
            Some("ruleset-main"),
        ),
        step(
            "labels",
            Owner::Owner,
            "Remote item: the standard labels exist with their colors".to_owned(),
            label_commands,
            "labels-present",
            json!({ "labels": labels }),
            None,
        ),
        step(
            "repo-settings",
            Owner::Owner,
            "Remote item: squash-only merges, branch cleanup, auto-merge and update branch"
                .to_owned(),
            format!("gh api -X PATCH repos/{{owner}}/{{repo}}{settings_flags}"),
            "repo-settings",
            json!({ "fields": fields }),
            None,
        ),
        step(
            "dependabot-alerts",
            Owner::Owner,
            "Remote item: Dependabot alerts enabled".to_owned(),
            "gh api -X PUT repos/{owner}/{repo}/vulnerability-alerts".to_owned(),
            "dependabot-alerts",
            json!({}),
            None,
        ),
        step(
            "dependabot-security-updates",
            Owner::Owner,
            "Remote item: Dependabot security updates enabled".to_owned(),
            "gh api -X PUT repos/{owner}/{repo}/automated-security-fixes".to_owned(),
            "automated-security-fixes",
            json!({}),
            None,
        ),
    ];
    if split {
        steps.insert(2, review);
    }
    steps
}

/// The desired state of each remote item (#902; SPEC-repo-baseline.md, Remote
/// items): the ruleset read from `ruleset_file`, the text `render` writes to
/// `.github/rulesets/main.json`; the labels of `labels.json`; the settings; the
/// retirement of classic protection on the default branch of `root`.
pub fn remote_writes(
    root: &Path,
    ruleset_file: &str,
    review_file: Option<&str>,
    superseded_by: Supersession,
) -> Result<Vec<RemoteWrite>> {
    let labels = labels()
        .iter()
        .map(|label| Label {
            name: label["name"].as_str().unwrap_or_default().to_owned(),
            color: label["color"].as_str().unwrap_or_default().to_owned(),
            description: label["description"].as_str().map(str::to_owned),
        })
        .collect();
    // The patch refuses an unknown key, so SETTINGS cannot drift from it.
    let settings: RepositorySettingsPatch = serde_json::from_value(Value::Object(
        SETTINGS
            .iter()
            .map(|(key, value)| ((*key).to_owned(), json!(value)))
            .collect(),
    ))?;
    let write = |id: &str, desired: Desired| RemoteWrite {
        id: id.to_owned(),
        desired,
    };
    let mut writes = vec![
        write(
            "ruleset-main",
            Desired::Ruleset(ruleset_from_file(ruleset_file, RULESET_PATH)?),
        ),
        write(
            "classic-protection-retire",
            Desired::RetireProtection {
                branch: default_branch(root),
                superseded_by,
            },
        ),
        write("labels", Desired::Labels(labels)),
        write("repo-settings", Desired::Settings(settings)),
        write(
            "dependabot-alerts",
            Desired::Settings(RepositorySettingsPatch {
                vulnerability_alerts: Some(true),
                ..RepositorySettingsPatch::default()
            }),
        ),
        write(
            "dependabot-security-updates",
            Desired::Settings(RepositorySettingsPatch {
                automated_security_fixes: Some(true),
                ..RepositorySettingsPatch::default()
            }),
        ),
    ];
    if let Some(review) = review_file {
        writes.insert(
            1,
            write(
                REVIEW_ITEM,
                Desired::Ruleset(ruleset_from_file(review, REVIEW_RULESET_PATH)?),
            ),
        );
    }
    Ok(writes)
}
