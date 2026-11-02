//! Brownfield migration (SPEC-ci-baseline.md, Brownfield migration; T5, #775).
//! A workflow is foreign when the installed lock does not record it, or records
//! it `never-touch`. With a foreign workflow the generated one goes to
//! `agentic-ci.yml`, every foreign workflow (and a project-owned actionlint
//! configuration) is listed `never-touch`, and the switch of the required check
//! is the `remote` item `github:switch-required-check` (decision #848) with its
//! probe, after `check-reported`. The module declares only; nothing is deleted.
//!
//! Under `workflow: existing` with contributed jobs (#895) the jobs go to the
//! separate `agentic-security.yml`, whose aggregate `agentic-required` joins the
//! required checks through the `remote` item `github:add-agentic-required-check`.
use super::{AGGREGATE_CHECK, CI_BASELINE, CONTRIBUTED_AGGREGATE_CHECK, render::WORKFLOW_PATH};
use crate::{
    Result,
    engine::{
        Context, Ownership, Rendered,
        manual::{ManualStep, Owner, Probe},
    },
    host::desired::{Desired, RemoteWrite},
    modules::repo_baseline::steps::default_branch,
    refuse,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::Path;

/// The generated workflow next to a project's own.
pub const BROWNFIELD_PATH: &str = ".github/workflows/agentic-ci.yml";
/// Its `name:`, so the Actions tab tells the two apart.
pub const BROWNFIELD_NAME: &str = "CI (brakes)";
/// actionlint reads either file; a project-owned one is never rendered over.
pub const ACTIONLINT_CONFIGS: [&str; 2] = [".github/actionlint.yaml", ".github/actionlint.yml"];
/// The remote item and the step that gates it.
pub const SWITCH: &str = "switch-required-check";
pub const CHECK_REPORTED: &str = "check-reported";
/// The separate workflow of the contributed jobs under `workflow: existing`.
pub const SEPARATE_PATH: &str = ".github/workflows/agentic-security.yml";
pub const SEPARATE_NAME: &str = "Security (brakes)";
/// Its remote item and the step that gates it.
pub const ADD_CHECK: &str = "add-agentic-required-check";
pub const SEPARATE_REPORTED: &str = "agentic-required-reported";

const WORKFLOWS_DIR: &str = ".github/workflows";

/// True when the installed lock records `path` under a class other than `never-touch`.
fn owned(cx: &Context<'_>, path: &str) -> bool {
    cx.previous
        .files
        .get(path)
        .is_some_and(|entry| entry.class != Ownership::NeverTouch)
}

/// The foreign `*.yml` / `*.yaml` files directly under `.github/workflows/`, sorted.
pub fn foreign_workflows(cx: &Context<'_>) -> Result<Vec<String>> {
    let entries = match std::fs::read_dir(cx.root.join(WORKFLOWS_DIR)) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return refuse(format!("ci-baseline: cannot list {WORKFLOWS_DIR}: {error}")),
    };
    let mut foreign = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = format!("{WORKFLOWS_DIR}/{name}");
        let workflow = name.ends_with(".yml") || name.ends_with(".yaml");
        if workflow && entry.file_type()?.is_file() && !owned(cx, &path) {
            foreign.push(path);
        }
    }
    foreign.sort();
    Ok(foreign)
}

/// The project-owned actionlint configurations that exist.
pub fn foreign_actionlint(cx: &Context<'_>) -> Vec<String> {
    ACTIONLINT_CONFIGS
        .iter()
        .filter(|path| cx.root.join(path).is_file() && !owned(cx, path))
        .map(|path| (*path).to_owned())
        .collect()
}

/// The labels actionlint 1.7.12 knows and never reports as unknown, compared
/// case-insensitively as actionlint does: its own self-hosted labels
/// (`selfHostedRunnerPreset*Labels`) and the GitHub-hosted ones
/// (`allGitHubHostedRunnerLabels`), both from `rule_runner_label.go` of the
/// release `security/pins.rs` pins
/// (https://github.com/rhysd/actionlint/blob/v1.7.12/rule_runner_label.go).
/// The list moves with the actionlint pin; a test holds the two together.
pub const ACTIONLINT_KNOWN_RELEASE: &str = "1.7.12";

/// The labels of [`ACTIONLINT_KNOWN_RELEASE`], as above.
const ACTIONLINT_KNOWN: [&str; 36] = [
    "self-hosted",
    "linux",
    "macos",
    "windows",
    "x64",
    "arm",
    "arm64",
    "windows-latest",
    "windows-latest-8-cores",
    "windows-2025",
    "windows-2025-vs2026",
    "windows-2022",
    "windows-11-arm",
    "ubuntu-slim",
    "ubuntu-latest",
    "ubuntu-latest-4-cores",
    "ubuntu-latest-8-cores",
    "ubuntu-latest-16-cores",
    "ubuntu-24.04",
    "ubuntu-24.04-arm",
    "ubuntu-22.04",
    "ubuntu-22.04-arm",
    "macos-latest",
    "macos-latest-xlarge",
    "macos-latest-large",
    "macos-26-intel",
    "macos-26-xlarge",
    "macos-26-large",
    "macos-26",
    "macos-15-intel",
    "macos-15-xlarge",
    "macos-15-large",
    "macos-15",
    "macos-14-xlarge",
    "macos-14-large",
    "macos-14",
];

/// The custom labels the foreign workflows' jobs already run on, sorted and
/// once each, for `.github/actionlint.yaml` (#1167, #1215): every label of a
/// job's `runs-on`, scalar, list or `{group, labels}`, that actionlint does not
/// already know, but expressions and text with control characters. Read, never
/// invented; a workflow that does not read or parse adds none (actionlint
/// reports it itself).
pub fn custom_labels(root: &Path, foreign: &[String]) -> Vec<String> {
    let known = |label: &str| {
        ACTIONLINT_KNOWN
            .iter()
            .any(|k| k.eq_ignore_ascii_case(label))
    };
    let mut labels = std::collections::BTreeSet::new();
    for path in foreign {
        let Some(workflow) = std::fs::read_to_string(root.join(path))
            .ok()
            .and_then(|text| crate::auditor::workflows::parse(&text).ok())
        else {
            continue;
        };
        for job in workflow.jobs {
            labels.extend(
                job.runs_on
                    .into_iter()
                    .filter(|l| !known(l) && !l.contains("${{") && !l.trim().is_empty())
                    // A label is one line; anything else could break the YAML it is written into.
                    .filter(|l| !l.chars().any(char::is_control)),
            );
        }
    }
    labels.into_iter().collect()
}

/// Where the workflow goes: the filename the lock already records for this
/// module (sticky), else `agentic-ci.yml` when a foreign workflow exists.
pub fn workflow_path(cx: &Context<'_>, foreign: &[String]) -> &'static str {
    let recorded = [WORKFLOW_PATH, BROWNFIELD_PATH].into_iter().find(|path| {
        cx.previous
            .files
            .get(*path)
            .is_some_and(|e| e.module == CI_BASELINE && e.class == Ownership::Managed)
    });
    match recorded {
        Some(path) => path,
        None if foreign.is_empty() => WORKFLOW_PATH,
        None => BROWNFIELD_PATH,
    }
}

/// `key: value` of a YAML line, the key unquoted, the value without a trailing
/// comment or quotes.
fn key_value(content: &str) -> Option<(&str, &str)> {
    let (key, value) = content.split_once(':')?;
    let value = value.split(" #").next().unwrap_or("").trim();
    Some((
        key.trim().trim_matches(['"', '\'']),
        value.trim_matches(['"', '\'']),
    ))
}

/// True when the workflow text has a job whose id or job-level `name:` is
/// `AGGREGATE_CHECK`.
pub fn has_required_job(text: &str) -> bool {
    has_job_named(text, AGGREGATE_CHECK)
}

/// True when the workflow text has a job whose id or job-level `name:` is
/// `check`. A line scanner over `jobs:`: job ids sit at the first indentation
/// below it, job keys at the first indentation below a job id.
pub fn has_job_named(text: &str, check: &str) -> bool {
    let mut in_jobs = false;
    let mut job_indent = None;
    let mut key_indent = None;
    for line in text.lines() {
        let content = line.trim_start();
        if content.is_empty() || content.starts_with('#') {
            continue;
        }
        let indent = line.len() - content.len();
        if indent == 0 {
            in_jobs =
                key_value(content).is_some_and(|(key, value)| key == "jobs" && value.is_empty());
            job_indent = None;
            continue;
        }
        if !in_jobs {
            continue;
        }
        let jobs = *job_indent.get_or_insert(indent);
        if indent <= jobs {
            key_indent = None;
            if key_value(content).is_some_and(|(key, _)| key == check) {
                return true;
            }
            continue;
        }
        if indent == *key_indent.get_or_insert(indent)
            && key_value(content).is_some_and(|(key, value)| key == "name" && value == check)
        {
            return true;
        }
    }
    false
}

/// Refuses when a foreign workflow already has a `required` job: the check
/// name the ruleset requires would be ambiguous.
pub fn refuse_required_job(root: &Path, foreign: &[String]) -> Result<()> {
    refuse_job_named(
        root,
        foreign,
        AGGREGATE_CHECK,
        &format!(
            "rename that job, or answer workflow=existing with aggregate_check={AGGREGATE_CHECK}"
        ),
    )
}

/// Refuses when a foreign workflow already has an `agentic-required` job: the
/// separate workflow's aggregate would be ambiguous.
pub fn refuse_contributed_job(root: &Path, foreign: &[String]) -> Result<()> {
    refuse_job_named(
        root,
        foreign,
        CONTRIBUTED_AGGREGATE_CHECK,
        "rename that job",
    )
}

fn refuse_job_named(root: &Path, foreign: &[String], check: &str, remedy: &str) -> Result<()> {
    for path in foreign {
        let text = std::fs::read_to_string(root.join(path))
            .or_else(|error| refuse(format!("ci-baseline: cannot read {path}: {error}")))?;
        if has_job_named(&text, check) {
            return refuse(format!(
                "ci-baseline: {path} already has a job named {check}; the required check would be ambiguous; {remedy}"
            ));
        }
    }
    Ok(())
}

/// The `never-touch` declarations of `paths`.
pub fn never_touch(paths: &[String]) -> Vec<Rendered> {
    paths
        .iter()
        .map(|path| declared(path, Ownership::NeverTouch))
        .collect()
}

/// The answer that retires the generated workflow after a switch to `existing` (#1354).
pub const RETIRE_ANSWER: &str = "retire_generated";
/// The step that waits for the ruleset to require the new checks, and the retirement.
pub const EXISTING_REQUIRED: &str = "existing-checks-required";
pub const RETIRE: &str = "retire-generated-workflow";

/// True while a switch from `generate` to `existing` keeps the generated
/// workflow (#1354): the lock records `agentic-ci.yml` as ci-baseline's and
/// `retire_generated` is not `true`.
pub fn keeps_generated(cx: &Context<'_>) -> bool {
    let recorded = cx
        .previous
        .files
        .get(BROWNFIELD_PATH)
        .is_some_and(|e| e.module == CI_BASELINE && e.class == Ownership::Managed);
    recorded && cx.answers.get(RETIRE_ANSWER).and_then(Value::as_bool) != Some(true)
}

/// Step 1 of the switch to `existing` (#1354): the generated workflow as it is
/// on disk, still `managed`, so its `required` keeps reporting on the default
/// branch beside the project's aggregate and `agentic-required` until the
/// ruleset requires those; `None` when nothing is kept.
pub fn kept_generated(cx: &Context<'_>) -> Result<Option<Rendered>> {
    if !keeps_generated(cx) {
        return Ok(None);
    }
    match std::fs::read_to_string(cx.root.join(BROWNFIELD_PATH)) {
        Ok(text) => Ok(Some(Rendered {
            path: BROWNFIELD_PATH.to_owned(),
            class: Ownership::Managed,
            content: Some(text),
            scaffold: None,
        })),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => refuse(format!(
            "ci-baseline: cannot read {BROWNFIELD_PATH}: {error}"
        )),
    }
}

/// The two steps of the switch's second half (#1354): the ruleset requires
/// exactly `checks` on the default branch, then `retire_generated` is answered.
pub fn retire_steps(root: &Path, checks: &[String]) -> Vec<ManualStep> {
    let branch = default_branch(root);
    let listed = checks.join(" and ");
    vec![
        ManualStep {
            id: EXISTING_REQUIRED.to_owned(),
            title: format!("The default branch requires {listed}"),
            owner: Owner::Owner,
            instructions: format!(
                "Apply the ruleset once CI has reported {listed} on {branch} (repo-baseline's check-reported, then ruleset-main): brakes apply <repo> --remote"
            ),
            probe: remote(
                "ruleset-required-checks",
                json!({ "branch": branch, "checks": checks }),
            ),
            after: None,
        },
        ManualStep {
            id: RETIRE.to_owned(),
            title: format!("Retire {BROWNFIELD_PATH}: answer {RETIRE_ANSWER} true"),
            owner: Owner::Owner,
            instructions: format!(
                "In a pull request: brakes configure <repo> ci-baseline --set {RETIRE_ANSWER}=true --apply\n\
                 # it deletes {BROWNFIELD_PATH}, whose required check the ruleset no longer needs"
            ),
            probe: Probe::JsonPointer {
                path: ".agent-setup/modules/ci-baseline.json".to_owned(),
                pointer: format!("/answers/{RETIRE_ANSWER}"),
                equals: Value::Bool(true),
            },
            after: Some(EXISTING_REQUIRED.to_owned()),
        },
    ]
}

/// The lock entry of the switch: class `remote`, no content.
pub fn remote_items() -> Vec<Rendered> {
    vec![declared(&format!("github:{SWITCH}"), Ownership::Remote)]
}

/// The lock entry that requires `agentic-required`: class `remote`, no content.
pub fn separate_remote_items() -> Vec<Rendered> {
    vec![declared(&format!("github:{ADD_CHECK}"), Ownership::Remote)]
}

fn declared(path: &str, class: Ownership) -> Rendered {
    Rendered {
        path: path.to_owned(),
        class,
        content: None,
        scaffold: None,
    }
}

pub(crate) fn remote(id: &str, args: Value) -> Probe {
    Probe::Remote {
        id: id.to_owned(),
        args: serde_json::from_value::<BTreeMap<String, Value>>(args).unwrap_or_default(),
    }
}

/// The step of a migration from `generate` to `seed` (#25).
pub const GENERATE_TO_SEED: &str = "generate-to-seed";

/// The generated workflow the lock records as ci-baseline's `managed` file, if any.
pub fn recorded_generated(cx: &Context<'_>) -> Option<&'static str> {
    [WORKFLOW_PATH, BROWNFIELD_PATH].into_iter().find(|path| {
        cx.previous
            .files
            .get(*path)
            .is_some_and(|e| e.module == CI_BASELINE && e.class == Ownership::Managed)
    })
}

/// Whether `workflow: seed` writes `ci.yml` (#21, #25): where the project has no
/// workflow of its own, or where it migrates from a generated workflow, which was
/// its CI, and no `ci.yml` of its own is in the way.
pub fn seed_allowed(cx: &Context<'_>, foreign: &[String]) -> bool {
    foreign.is_empty()
        || (recorded_generated(cx).is_some() && !foreign.iter().any(|f| f == WORKFLOW_PATH))
}

/// The commands that add `check` to the default branch's required checks.
fn add_check_commands(branch: &str, check: &str) -> String {
    let rules = format!(
        "{{name, target, enforcement, conditions, bypass_actors, rules: (.rules | map(if .type == \"required_status_checks\" then .parameters.required_status_checks |= (. + [{{\"context\": \"{check}\"}}] | unique_by(.context)) else . end))}}"
    );
    format!(
        "gh api repos/{{owner}}/{{repo}}/rulesets/<id> | jq '{rules}' | gh api -X PUT repos/{{owner}}/{{repo}}/rulesets/<id> --input -\n\
         # with classic branch protection instead of a ruleset:\n\
         gh api -X POST repos/{{owner}}/{{repo}}/branches/{branch}/protection/required_status_checks/contexts -f 'contexts[]={check}'"
    )
}

/// Expand before contract (#25): while a migration from `generate` is planned, the
/// default branch must require `agentic-required` before the migrating pull request
/// merges. That pull request's own run reports both checks: the seed's `required`
/// and the judges' `agentic-required`. The generated workflow stops running on it,
/// so two checks named `required` never report together, and `required`
/// never stops being reported.
pub fn migration_step(root: &Path) -> ManualStep {
    let branch = default_branch(root);
    let check = CONTRIBUTED_AGGREGATE_CHECK;
    ManualStep {
        id: GENERATE_TO_SEED.to_owned(),
        title: format!(
            "Before the pull request that moves to seed merges, the default branch requires {check}"
        ),
        owner: Owner::Owner,
        instructions: format!(
            "The migrating pull request reports {AGGREGATE_CHECK} (the seed) and {check} (the judges); require {check} first, so protected paths and the scanners stay gated, then merge:\n{}",
            add_check_commands(&branch, check)
        ),
        probe: remote(
            "required-check",
            json!({ "branch": branch, "check": check }),
        ),
        after: None,
    }
}

/// `agentic-required-reported` and the remote item that adds `agentic-required`
/// to the required checks, for a repository at `root`; the project's own check
/// stays required. The item waits for the check to have reported.
pub fn separate_steps(root: &Path) -> Vec<ManualStep> {
    let branch = default_branch(root);
    let check = CONTRIBUTED_AGGREGATE_CHECK;
    vec![
        ManualStep {
            id: SEPARATE_REPORTED.to_owned(),
            title: format!("CI reports {check} on {branch}"),
            owner: Owner::Platform,
            instructions: format!(
                "Nothing to run: wait until {check} has reported on {branch} ({SEPARATE_PATH})."
            ),
            probe: remote(
                "check-run-reported",
                json!({ "contexts": [check], "branch": branch }),
            ),
            after: None,
        },
        ManualStep {
            id: ADD_CHECK.to_owned(),
            title: format!("Remote item: the default branch also requires the {check} check"),
            owner: Owner::Owner,
            instructions: add_check_commands(&branch, check),
            probe: remote(
                "required-check",
                json!({ "branch": branch, "check": check }),
            ),
            after: Some(SEPARATE_REPORTED.to_owned()),
        },
    ]
}

/// The checks the switch leaves required on the default branch (#1373): a
/// declared `ci.required_checks` that names `required` is the post-switch
/// state, kept verbatim; otherwise `required` alone supersedes it (#1299).
pub fn switch_checks(profile: &Value) -> Vec<String> {
    let declared = crate::profile::strings(&profile["ci"]["required_checks"]);
    if declared.contains(&AGGREGATE_CHECK) {
        declared.into_iter().map(str::to_owned).collect()
    } else {
        vec![AGGREGATE_CHECK.to_owned()]
    }
}

/// `check-reported` and the switch, for a repository at `root`; the switch
/// leaves `checks` ([`switch_checks`]) the required ones. The switch waits for
/// `required` to have reported on the default branch, so it never requires a
/// check nobody reports.
pub fn steps(root: &Path, checks: &[String]) -> Vec<ManualStep> {
    let branch = default_branch(root);
    let contexts = checks
        .iter()
        .map(|c| format!("{{\"context\": \"{c}\"}}"))
        .collect::<Vec<_>>()
        .join(", ");
    let rules = format!(
        "{{name, target, enforcement, conditions, bypass_actors, rules: (.rules | map(if .type == \"required_status_checks\" then .parameters.required_status_checks = [{contexts}] else . end))}}"
    );
    let fields = checks
        .iter()
        .map(|c| format!("-f 'contexts[]={c}'"))
        .collect::<Vec<_>>()
        .join(" ");
    let named = checks.join(", ");
    let plural = if checks.len() == 1 { "" } else { "s" };
    vec![
        ManualStep {
            id: CHECK_REPORTED.to_owned(),
            title: format!("CI reports {AGGREGATE_CHECK} on {branch}"),
            owner: Owner::Platform,
            instructions: format!(
                "Nothing to run: wait until {AGGREGATE_CHECK} has reported on {branch} ({BROWNFIELD_PATH})."
            ),
            probe: remote(
                "check-run-reported",
                json!({ "contexts": [AGGREGATE_CHECK], "branch": branch }),
            ),
            after: None,
        },
        ManualStep {
            id: SWITCH.to_owned(),
            title: format!(
                "Remote item: the default branch requires only the {named} check{plural}"
            ),
            owner: Owner::Owner,
            instructions: format!(
                "gh api repos/{{owner}}/{{repo}}/rulesets/<id> | jq '{rules}' | gh api -X PUT repos/{{owner}}/{{repo}}/rulesets/<id> --input -\n\
                 # with classic branch protection instead of a ruleset:\n\
                 gh api -X PATCH repos/{{owner}}/{{repo}}/branches/{branch}/protection/required_status_checks {fields}"
            ),
            probe: remote(
                "ruleset-required-checks",
                json!({ "branch": branch, "checks": checks }),
            ),
            after: Some(CHECK_REPORTED.to_owned()),
        },
    ]
}

/// The desired state of both remote items (#902; SPEC-ci-baseline.md): the
/// switch leaves `switched` ([`switch_checks`]) the only required checks of the
/// default branch of `root`; the addition adds `agentic-required` to the
/// others. Only the items the lock records are classified, so declaring both
/// is safe.
pub fn remote_writes(root: &Path, switched: &[String]) -> Vec<RemoteWrite> {
    let branch = default_branch(root);
    let checks = |id: &str, checks: Vec<String>, keep_others: bool| RemoteWrite {
        id: id.to_owned(),
        desired: Desired::RequiredChecks {
            branch: branch.clone(),
            checks,
            keep_others,
        },
    };
    vec![
        checks(SWITCH, switched.to_vec(), false),
        checks(
            ADD_CHECK,
            vec![CONTRIBUTED_AGGREGATE_CHECK.to_owned()],
            true,
        ),
    ]
}
