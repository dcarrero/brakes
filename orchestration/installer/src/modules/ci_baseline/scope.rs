//! The scope job's shell: tiers, inert paths, the skippable list and the
//! per-app change flags. The logic lives once, in the embedded fragment; the
//! renderer embeds it verbatim and this module only names its contract.

/// The scope job's script, embedded verbatim in the generated workflow.
pub const FRAGMENT: &str = include_str!("../../../../../templates/ci-baseline/fragments/scope.sh");

/// The line of [`FRAGMENT`] that turns the collected ids into the output;
/// [`APP_JOBS_STEP`] goes right before it.
const SKIPPABLE_LINE: &str = "skippable=\"$(printf '%s' \"$ids\" | jq -R . | jq -cs .)\"\n";

/// The lines that list a contributed job with an `app` (#1097) when that app
/// is unchanged: `APP_JOBS` holds `<job id>=<app id>` per line, the per-app
/// flags are those just computed.
pub const APP_JOBS_STEP: &str = r#"# Contributed jobs of one app are skippable with it (APP_JOBS: <job>=<app>).
while IFS= read -r pair; do
  [ -n "$pair" ] || continue
  job=${pair%%=*}
  app=${pair#*=}
  case $'\n'"$flags" in
    *$'\n'"$app=false"$'\n'*) add "$job" ;;
  esac
done <<< "${APP_JOBS:-}"
"#;

/// The scope job's script: [`FRAGMENT`], with [`APP_JOBS_STEP`] when some
/// contributed job names an app, so a workflow without one is unchanged.
pub fn script(app_jobs: bool) -> String {
    if app_jobs {
        FRAGMENT.replacen(
            SKIPPABLE_LINE,
            &format!("{APP_JOBS_STEP}{SKIPPABLE_LINE}"),
            1,
        )
    } else {
        FRAGMENT.to_owned()
    }
}

/// The tier of a run that verifies everything; also the answer to any doubt.
pub const TIER_FULL: &str = "full";
/// The tier of a pull request whose every changed file matches an inert path.
pub const TIER_DOCS: &str = "docs";

/// The default `inert_paths` answer: the only paths whose exclusive change
/// means tier `docs`. `.github/workflows/**` is never inert, whatever the answer.
pub const DEFAULT_INERT_PATHS: &[&str] = &["docs/**", "tasks/**", "**/*.md"];

/// The default `heldout_dir` answer: the tests an agent may not edit.
pub const DEFAULT_HELDOUT_DIR: &str = "tests/heldout";

/// The default `protected_paths` answer with the default `heldout_dir`: paths
/// whose change in a pull request needs the `human-approved` label before the
/// aggregate passes. The last entry is `<heldout_dir>/**`; [`default_protected_paths`]
/// writes it for an answered directory. A protected path is never inert, so a
/// protected change is never tier `docs`. When `qa` is active with a web app,
/// `model.rs` appends its screenshot baselines to the unanswered default
/// (`<web_dir>/*-snapshots/**`, `**/*-snapshots/**` at the root, one per app;
/// `qa::protected`, #1005).
pub const DEFAULT_PROTECTED_PATHS: &[&str] = &[
    ".github/workflows/**",
    ".github/rulesets/**",
    ".github/CODEOWNERS",
    ".agent-setup/lock.json",
    "tests/heldout/**",
];

/// True when the `protected_paths` entry `path` still carries a `<name>`
/// placeholder: the scope job and the deny rules would match it literally, so it
/// names no path and protects nothing (#1229).
pub fn unresolved_placeholder(path: &str) -> bool {
    path.find('<')
        .is_some_and(|open| path[open + 1..].find('>').is_some_and(|len| len > 0))
}

/// The default `protected_paths` for the held-out directory `heldout_dir`.
pub fn default_protected_paths(heldout_dir: &str) -> Vec<String> {
    let fixed = &DEFAULT_PROTECTED_PATHS[..DEFAULT_PROTECTED_PATHS.len() - 1];
    fixed
        .iter()
        .map(|p| (*p).to_owned())
        .chain([format!("{heldout_dir}/**")])
        .collect()
}

/// The environment the script reads; the renderer writes exactly these names
/// in the step's `env:` block, lists one entry per line.
pub const INPUTS: &[(&str, &str)] = &[
    ("EVENT", "github.event_name"),
    ("BASE_SHA", "github.event.pull_request.base.sha"),
    ("HEAD_SHA", "github.event.pull_request.head.sha"),
    (
        "INERT_PATHS",
        "the inert_paths answer, one prefix glob per line",
    ),
    (
        "DOCS_SKIPPABLE",
        "job ids skippable under tier docs, one per line",
    ),
    ("APPS", "<id>=<path> per app in monorepo mode, one per line"),
    (
        "PROTECTED_PATHS",
        "the protected_paths answer, one prefix glob per line",
    ),
];

/// Why the scope job may list a job id as skippable in a run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SkipWhen {
    /// The tier is `docs`: verification jobs handed in `DOCS_SKIPPABLE`.
    TierDocs,
    /// A pull request whose listed files include no `.github/**` path.
    NoWorkflowChange,
    /// The event is not a push (the macOS job runs on pushes only).
    NotPush,
    /// A pull request whose listed files include none under the app's path.
    AppUnchanged,
}

/// The built-in job ids the scope job may list as skippable and when. The
/// shards are one matrix job `shard` (a job id cannot carry `i/n`; the display
/// name `shard i/n` does); app ids are a pattern the renderer instantiates.
pub const SKIPPABLE: &[(&str, SkipWhen)] = &[
    ("checks", SkipWhen::TierDocs),
    ("lint", SkipWhen::TierDocs),
    ("shard", SkipWhen::TierDocs),
    ("heldout", SkipWhen::TierDocs),
    ("heldout-properties", SkipWhen::TierDocs),
    ("workflow-lint", SkipWhen::NoWorkflowChange),
    ("macos", SkipWhen::NotPush),
    ("<id>-checks", SkipWhen::AppUnchanged),
];

/// The built-in ids the renderer hands the script as `DOCS_SKIPPABLE`: one
/// `checks` job without shards, `lint` plus the matrix job `shard` with `n > 1`
/// shards. Contributed jobs that opt in are appended by the renderer.
pub fn docs_skippable(shards: u32) -> Vec<String> {
    let ids: &[&str] = if shards <= 1 {
        &["checks"]
    } else {
        &["lint", "shard"]
    };
    ids.iter().map(|id| (*id).to_owned()).collect()
}
