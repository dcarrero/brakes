//! The protected screenshot baseline (`SPEC-qa.md`, Protected baseline; T8,
//! #1005): the one derivation of where Playwright's `*-snapshots/` directories
//! live, read by `ci-baseline` for its derived `protected_paths`, by
//! `repo-baseline` for its CODEOWNERS seed and by the rule
//! `qa.snapshots-protected` (T11).
//!
//! A soft read: `qa` is not required by its readers. Its recorded answers are
//! resolved by `QaAnswers::load` itself, so an unanswered `web` takes the value
//! T4 (#1001) derives from the app's files exactly as `qa`'s jobs will; answers
//! `qa` would refuse add nothing here, because the plan refuses on `qa`'s own
//! render before anything is written.
use super::{QA, Qa, QaAnswers, Web, seeds::join};
use crate::engine::Context;

/// The repository-relative directory of every target whose `web` is not
/// `none`: the root target, then each app `apps` lists, in app id order, each
/// once; `.` is the repository root. An app's `web_dir` is relative to its
/// `stack-packs` path and may leave it (#1211).
pub fn web_dirs(qa: &QaAnswers) -> Vec<String> {
    dirs_where(qa, |web| web != Web::None)
}

/// The directories of [`web_dirs`] whose target is `web: seeded`: the
/// Playwright projects `qa` itself writes, which `stack-packs` detection does
/// not take for apps (#1238).
pub fn seeded_web_dirs(qa: &QaAnswers) -> Vec<String> {
    dirs_where(qa, |web| web == Web::Seeded)
}

fn dirs_where(qa: &QaAnswers, keep: impl Fn(Web) -> bool) -> Vec<String> {
    let root = keep(qa.web).then(|| qa.web_dir.clone());
    let apps = qa
        .apps
        .values()
        .filter(|app| keep(app.web))
        .map(|app| join(&app.path, &app.web_dir));
    let mut dirs: Vec<String> = Vec::new();
    for dir in root.into_iter().chain(apps) {
        if !dirs.contains(&dir) {
            dirs.push(dir);
        }
    }
    dirs
}

/// The `protected_paths` entry for the web directory `dir`, written for the
/// `scope` job's matcher (a shell `case` pattern: `*` crosses `/`, a leading
/// `**/` is optional), so it matches a `*-snapshots/` directory at any depth.
pub fn protected_glob(dir: &str) -> String {
    match dir {
        "." => "**/*-snapshots/**".to_owned(),
        dir => format!("{dir}/*-snapshots/**"),
    }
}

/// The CODEOWNERS line for the web directory `dir`: the directory itself, or
/// every `*-snapshots/` directory when it is the root, which `* @owner`
/// already covers and `/./` would not name.
pub fn codeowners_line(dir: &str, owner: &str) -> String {
    match dir {
        "." => format!("**/*-snapshots/ @{owner}"),
        dir => format!("/{dir}/ @{owner}"),
    }
}

/// The web directories of `qa` when it is active in this plan and its answers
/// load, else none. `cx` is the reader's context; `qa`'s answers are loaded as
/// `qa` itself sees them.
fn active_web_dirs(cx: &Context<'_>) -> Vec<String> {
    let Some(answers) = cx.answers_if_active(QA) else {
        return Vec::new();
    };
    let qa = Context {
        answers,
        module: &Qa,
        ..*cx
    };
    QaAnswers::load(&qa)
        .map(|loaded| web_dirs(&loaded))
        .unwrap_or_default()
}

/// What `ci-baseline` adds to its derived `protected_paths`.
pub fn snapshot_globs(cx: &Context<'_>) -> Vec<String> {
    active_web_dirs(cx)
        .iter()
        .map(|d| protected_glob(d))
        .collect()
}

/// What `repo-baseline` adds to its CODEOWNERS seed.
pub fn codeowners_lines(cx: &Context<'_>, owner: &str) -> Vec<String> {
    active_web_dirs(cx)
        .iter()
        .map(|d| codeowners_line(d, owner))
        .collect()
}
