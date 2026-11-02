//! The audit of the project's own CI (#23, decision of 2026-11-02): what the
//! brakes need from the workflows the project owns, each finding with the patch
//! it proposes. Nothing here writes: `doctor --propose` prints every patch as a
//! unified diff, and a patch reaches the default branch only through a pull
//! request labelled `human-approved`, because workflows are a protected path.
//!
//! The project's workflows are those under `.github/workflows/` the lock does not
//! record as `managed`: what `brakes` renders it fixes by rendering again. Patches
//! are line edits on the file as written (an inserted key, a block before `jobs:`,
//! an appended job, a replaced step), so the project's comments and layout stay.
//! The checks that existing rules already make keep their ids
//! (`ci.job-timeouts`, `ci.permissions-least`, `posture.actions-pinned`,
//! `ci.command-missing`); the others are proposals only and hold no level.
use crate::{
    LOCK, PROFILE,
    auditor::workflows::{self, Workflow},
    modules::stack_packs::{self, App, Measure, PinTable, Step, packs::pack, steps_yaml},
};
use serde_json::Value;
use std::{collections::BTreeMap, fmt::Write as _, path::Path};

/// What a project's CI job gets when it has none.
pub const TIMEOUT_MINUTES: u32 = 15;
/// The label a proposed job runs on: GitHub-hosted, never a configured runner.
const RUNNER: &str = "ubuntu-24.04";
const WORKFLOWS_DIR: &str = ".github/workflows";
/// Text a workflow must not interpolate into `run:`: values a pull request's
/// author, or a commenter, chooses.
const UNTRUSTED: [&str; 18] = [
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.pull_request.head.repo.default_branch",
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.head_commit.message",
    "github.event.head_commit.author",
    "github.event.commits",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.event.pages",
    "github.event.workflow_run.head_branch",
    "github.head_ref",
];

/// A patch: the file as it would be, and the unified diff to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Patch {
    pub after: String,
    pub diff: String,
}

/// One finding on the project's CI and, when a line edit can settle it, its patch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    pub rule: &'static str,
    pub file: String,
    pub text: String,
    pub patch: Option<Patch>,
}

struct File {
    path: String,
    text: String,
    wf: Workflow,
}

/// Every finding on the project's CI at `root`, by file in path order and rule,
/// then the repository-wide ones. Unreadable or unparsable files are skipped:
/// the `ci.*` rules of `doctor` already report them as unverified.
pub fn proposals(root: &Path) -> Vec<Proposal> {
    let files = project_workflows(root);
    let profile = read_json(root, PROFILE);
    let pins = PinTable::embedded().ok();
    let mut out = Vec::new();
    for file in &files {
        permissions(file, &mut out);
        concurrency(file, &mut out);
        timeouts(file, &mut out);
        pinned(file, pins.as_ref(), &mut out);
        target_head(file, &mut out);
        untrusted(file, &mut out);
    }
    if files.is_empty() {
        // No CI: `ci-health.workflow-exists` fails and the guided setup writes one.
        return out;
    }
    pull_request_trigger(&files, &mut out);
    let apps = apps(root);
    command_missing(&files, &profile, &apps, pins.as_ref(), &mut out);
    // Only `security`'s diff-coverage judges the upload; without it the seed has none.
    if read_json(root, LOCK)["modules"]["security"].is_object() {
        coverage_upload(root, &files, &profile, &apps, pins.as_ref(), &mut out);
    }
    out
}

/// The workflows the lock does not record as `managed`, parsed, in path order.
fn project_workflows(root: &Path) -> Vec<File> {
    let lock = read_json(root, LOCK);
    let managed = |path: &str| lock["files"][path]["class"] == "managed";
    let Ok(entries) = std::fs::read_dir(root.join(WORKFLOWS_DIR)) else {
        return Vec::new();
    };
    let mut paths: Vec<String> = entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.ends_with(".yml") || n.ends_with(".yaml"))
        .map(|n| format!("{WORKFLOWS_DIR}/{n}"))
        .filter(|p| !managed(p))
        .collect();
    paths.sort();
    paths
        .into_iter()
        .filter_map(|path| {
            let text = crate::read(root, &path).ok().flatten()?;
            let wf = workflows::parse(&text).ok()?;
            Some(File { path, text, wf })
        })
        .collect()
}

fn read_json(root: &Path, path: &str) -> Value {
    crate::read(root, path)
        .ok()
        .flatten()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or(Value::Null)
}

fn on_pull_requests(wf: &Workflow) -> bool {
    wf.triggers
        .iter()
        .any(|t| t == "pull_request" || t == "pull_request_target")
}

fn proposal(rule: &'static str, file: &File, text: String, after: Option<String>) -> Proposal {
    Proposal {
        rule,
        file: file.path.clone(),
        text,
        patch: after.map(|after| Patch {
            diff: unified(&file.path, &file.text, &after),
            after,
        }),
    }
}

// ---- per-file checks ------------------------------------------------------

fn permissions(file: &File, out: &mut Vec<Proposal>) {
    if file.wf.permissions.is_some() {
        return;
    }
    let after = insert_before_jobs(&file.text, &["permissions:", "  contents: read"]);
    out.push(proposal(
        "ci.permissions-least",
        file,
        "no top-level permissions: every job's token gets the repository default".to_owned(),
        after,
    ));
}

fn concurrency(file: &File, out: &mut Vec<Proposal>) {
    if !on_pull_requests(&file.wf) || file.wf.concurrency.is_some() {
        return;
    }
    let after = insert_before_jobs(
        &file.text,
        &[
            "concurrency:",
            "  group: ${{ github.workflow }}-${{ github.ref }}",
            "  cancel-in-progress: ${{ github.event_name == 'pull_request' }}",
        ],
    );
    out.push(proposal(
        "ci.concurrency",
        file,
        "no concurrency group: a superseded pull-request run keeps running".to_owned(),
        after,
    ));
}

fn timeouts(file: &File, out: &mut Vec<Proposal>) {
    for job in file
        .wf
        .jobs
        .iter()
        .filter(|j| j.uses.is_none() && j.timeout_minutes.is_none())
    {
        let after = insert_timeout(&file.text, &job.id);
        out.push(proposal(
            "ci.job-timeouts",
            file,
            format!("Job {} has no timeout-minutes", job.id),
            after,
        ));
    }
}

fn pinned(file: &File, pins: Option<&PinTable>, out: &mut Vec<Proposal>) {
    let mut seen = Vec::new();
    for uses in file.wf.unpinned_uses() {
        if seen.contains(&uses) {
            continue;
        }
        seen.push(uses);
        let repo = uses.split_once('@').map_or(uses, |(r, _)| r);
        let pin = pins.and_then(|p| p.action(repo).ok());
        let after = pin.map(|pin| {
            edit_lines(&file.text, |line| {
                let (head, rest) = line.split_once("uses:")?;
                let value = rest.split(" #").next()?.trim().trim_matches(['"', '\'']);
                (value == uses).then(|| format!("{head}uses: {}", pin.uses()))
            })
        });
        let text = if after.is_some() {
            format!("{uses} is not pinned by SHA")
        } else {
            format!(
                "{uses} is not pinned by SHA; the pin table does not know it, so pin it by hand"
            )
        };
        out.push(proposal("posture.actions-pinned", file, text, after));
    }
}

fn target_head(file: &File, out: &mut Vec<Proposal>) {
    if !file.wf.triggers.iter().any(|t| t == "pull_request_target") {
        return;
    }
    for job in &file.wf.jobs {
        let head = job.steps.iter().any(|s| {
            s.uses
                .as_deref()
                .is_some_and(|u| u.starts_with("actions/checkout"))
                && s.with.get("ref").is_some_and(|r| head_ref(r))
        });
        if !head {
            continue;
        }
        let after = job_block(&file.text, &job.id).map(|(start, end)| {
            let lines: Vec<&str> = file.text.lines().collect();
            let kept: Vec<&str> = lines
                .iter()
                .enumerate()
                .filter(|(i, line)| {
                    !(*i > start && *i < end && {
                        let t = line.trim_start();
                        t.starts_with("ref:") && head_ref(t)
                    })
                })
                .map(|(_, l)| *l)
                .collect();
            joined(&kept)
        });
        out.push(proposal(
            "ci.pull-request-target-head",
            file,
            format!(
                "job {} checks out the pull request's head under pull_request_target, with the base's token and secrets",
                job.id
            ),
            after,
        ));
    }
}

fn head_ref(text: &str) -> bool {
    text.contains("pull_request.head") || text.contains("head_ref")
}

fn untrusted(file: &File, out: &mut Vec<Proposal>) {
    for job in &file.wf.jobs {
        for (index, step) in job.steps.iter().enumerate() {
            let Some(run) = &step.run else { continue };
            for (written, expr) in expressions(run) {
                if !UNTRUSTED.iter().any(|u| expr.starts_with(u)) {
                    continue;
                }
                let after = move_to_env(&file.text, &job.id, index, &written, &expr);
                out.push(proposal(
                    "ci.untrusted-interpolation",
                    file,
                    format!("job {} interpolates {expr} into run:", job.id),
                    after,
                ));
            }
        }
    }
}

/// Every `${{ … }}` of `text`, as written and as its trimmed expression, once each.
fn expressions(text: &str) -> Vec<(String, String)> {
    let mut found: Vec<(String, String)> = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("${{") {
        let Some(len) = rest[start..].find("}}") else {
            break;
        };
        let written = &rest[start..start + len + 2];
        let expr = written[3..written.len() - 2].trim().to_owned();
        if !found.iter().any(|(w, _)| w == written) {
            found.push((written.to_owned(), expr));
        }
        rest = &rest[start + len + 2..];
    }
    found
}

/// The variable a moved expression becomes: `github.event.pull_request.title`
/// is `PULL_REQUEST_TITLE`.
fn env_name(expr: &str) -> String {
    let tail = expr
        .strip_prefix("github.event.")
        .or_else(|| expr.strip_prefix("github."))
        .unwrap_or(expr);
    tail.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

/// The step's `${{ expr }}` replaced in its lines by `${NAME}`, with `NAME`
/// added to its `env:` (created when absent).
fn move_to_env(text: &str, job: &str, index: usize, written: &str, expr: &str) -> Option<String> {
    let (start, end) = step_block(text, job, index)?;
    let lines: Vec<&str> = text.lines().collect();
    let dash = indent(lines[start]);
    let prop = dash + 2;
    let name = env_name(expr);
    let mut out: Vec<String> = Vec::new();
    let mut env_at = None;
    for (i, line) in lines.iter().enumerate() {
        if i >= start && i < end {
            let body = if i == start {
                &line[dash + 2..]
            } else {
                line.trim_start()
            };
            if body.starts_with("env:") && (i == start || indent(line) == prop) {
                env_at = Some(out.len());
            }
            out.push(line.replace(written, &format!("${{{name}}}")));
        } else {
            out.push((*line).to_owned());
        }
    }
    let entry = format!("{}{name}: {written}", " ".repeat(prop + 2));
    match env_at {
        Some(at) => out.insert(at + 1, entry),
        None => {
            out.insert(start + 1, entry);
            out.insert(start + 1, format!("{}env:", " ".repeat(prop)));
        }
    }
    Some(joined(&out))
}

// ---- repository-wide checks -----------------------------------------------

fn pull_request_trigger(files: &[File], out: &mut Vec<Proposal>) {
    if files.iter().any(|f| on_pull_requests(&f.wf)) {
        return;
    }
    let file = files
        .iter()
        .find(|f| f.wf.triggers.iter().any(|t| t == "push"))
        .unwrap_or(&files[0]);
    out.push(proposal(
        "ci.pull-request-trigger",
        file,
        "no workflow of the project runs on pull_request: the brakes have nothing to judge"
            .to_owned(),
        add_pull_request(&file.text),
    ));
}

/// The file a proposed job goes to: the first that runs on pull requests.
fn ci_file(files: &[File]) -> &File {
    files
        .iter()
        .find(|f| on_pull_requests(&f.wf))
        .unwrap_or(&files[0])
}

/// A step runs `commands.<name>` when its `run:` holds the command as declared,
/// names `commands.<name>`, or reads `.commands[…]` from the profile at run time
/// with `name` as a value of its `env:` (the seed's and the generated jobs'
/// form). `measured` are the runs a pack takes in place of the declared test
/// (`Measure::Instead`): they run `test`.
fn runs(files: &[File], name: &str, command: &str, measured: &[String]) -> bool {
    let reads = format!("commands.{name}");
    files.iter().any(|f| {
        f.wf.jobs.iter().any(|j| {
            j.steps.iter().any(|s| {
                s.run.as_deref().is_some_and(|r| {
                    r.contains(command.trim())
                        || r.contains(&reads)
                        || (r.contains(".commands[") && s.env.values().any(|v| v == name))
                        || (name == "test" && measured.iter().any(|m| r.contains(m.as_str())))
                })
            })
        })
    })
}

/// The runs that take the declared test's place for `apps` (`Measure::Instead`),
/// as `upload_steps` renders them.
fn measured_runs(apps: &[App], pins: Option<&PinTable>) -> Vec<String> {
    let Some(pins) = pins else {
        return Vec::new();
    };
    apps.iter()
        .filter_map(|app| {
            let recipe = pack(app.stack).coverage?;
            matches!(recipe.upload.measure, Measure::Instead(_)).then_some(())?;
            let steps = recipe.upload_steps(app, "test", "", pins, None).ok()?;
            steps.into_iter().find_map(|s| s.run)
        })
        .collect()
}

/// The commands a project's CI must run, as ci-baseline selects them: `lint`;
/// `test`, or `verify` when `test` is not declared; `build`. Each with its text.
fn selected(profile: &Value) -> Vec<(&'static str, String)> {
    let declared = |name: &str| profile["commands"][name].as_str().map(str::to_owned);
    let check = declared("test")
        .map(|t| ("test", t))
        .or_else(|| declared("verify").map(|v| ("verify", v)));
    [
        declared("lint").map(|c| ("lint", c)),
        check,
        declared("build").map(|c| ("build", c)),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// The recorded apps as `App`s, without macOS targets (no Linux job runs them).
fn apps(root: &Path) -> Vec<App> {
    stack_packs::audit::recorded_apps(root)
        .unwrap_or_default()
        .into_iter()
        .filter(|a| !pack(a.stack).macos_target)
        .map(|a| {
            let prefix = if a.path == "." {
                String::new()
            } else {
                format!("{}/", a.path)
            };
            let toolchain = pack(a.stack)
                .toolchain_seed
                .is_some_and(|s| root.join(format!("{prefix}{}", s.path)).exists());
            App {
                id: a.id,
                path: a.path,
                stack: a.stack,
                container: false,
                toolchain,
                package_manager: None,
                declared: BTreeMap::new(),
            }
        })
        .collect()
}

fn command_missing(
    files: &[File],
    profile: &Value,
    apps: &[App],
    pins: Option<&PinTable>,
    out: &mut Vec<Proposal>,
) {
    let measured = measured_runs(apps, pins);
    for (name, command) in selected(profile) {
        if runs(files, name, &command, &measured) {
            continue;
        }
        let file = ci_file(files);
        let app = (apps.len() == 1).then(|| &apps[0]);
        let after = pins.and_then(|pins| {
            let job = job_yaml(name, &command, app, pins)?;
            append_job(&file.text, &job)
        });
        out.push(proposal(
            "ci.command-missing",
            file,
            format!("commands.{name} is declared and no job of the project's CI runs it"),
            after,
        ));
    }
}

/// A job running `command`: checkout, the app's pack setup, and the run (the
/// test command measured and uploaded when the app's pack has coverage).
fn job_yaml(name: &str, command: &str, app: Option<&App>, pins: &PinTable) -> Option<String> {
    let checkout = Step::new("Check out")
        .uses(pins.action("actions/checkout").ok()?)
        .with("persist-credentials", "false");
    let mut steps = vec![checkout];
    if let Some(app) = app {
        steps.extend((pack(app.stack).ci_setup)(app, pins).ok()?);
    }
    let recipe = app.and_then(|a| pack(a.stack).coverage.map(|r| (a, r)));
    match recipe.filter(|_| name == "test") {
        Some((app, recipe)) => {
            steps.extend(recipe.upload_steps(app, name, command, pins, None).ok()?);
        }
        None => {
            let mut run = Step::new(format!("Run commands.{name}")).run(command);
            run.working_directory = app.and_then(App::working_directory);
            steps.push(run);
        }
    }
    let mut out = format!(
        "  {name}:\n    runs-on: {RUNNER}\n    timeout-minutes: {TIMEOUT_MINUTES}\n    steps:\n"
    );
    out.push_str(&steps_yaml(&steps));
    Some(out)
}

fn coverage_upload(
    root: &Path,
    files: &[File],
    profile: &Value,
    apps: &[App],
    pins: Option<&PinTable>,
    out: &mut Vec<Proposal>,
) {
    for app in apps {
        let stack = pack(app.stack);
        let Some(recipe) = stack.coverage else {
            if let Some(reason) = stack.no_coverage {
                out.push(proposal(
                    "ci.coverage-upload",
                    ci_file(files),
                    format!("app {} ({}) is not judged: {reason}", app.id, app.stack),
                    None,
                ));
            }
            continue;
        };
        let prefix = format!("agentic-coverage-{}-", app.id);
        let uploaded = files.iter().any(|f| {
            f.wf.jobs.iter().any(|j| {
                j.steps.iter().any(|s| {
                    s.uses
                        .as_deref()
                        .is_some_and(|u| u.starts_with("actions/upload-artifact"))
                        && s.with.get("name").is_some_and(|n| n.starts_with(&prefix))
                })
            })
        });
        if uploaded {
            continue;
        }
        let test = app_command(root, profile, app, "test");
        // The step that runs the app's declared test command, replaced by the measured run.
        let found = test.as_deref().and_then(|test| {
            files.iter().find_map(|f| {
                f.wf.jobs.iter().find_map(|j| {
                    j.steps.iter().enumerate().find_map(|(i, s)| {
                        let run = s.run.as_deref()?;
                        run.contains(test.trim())
                            .then(|| (f, j, i, run.trim_end().to_owned()))
                    })
                })
            })
        });
        let (file, after) = match (found, pins) {
            (Some((file, job, index, run)), Some(pins)) => {
                let after = recipe
                    .upload_steps(app, &job.id, &run, pins, None)
                    .ok()
                    .and_then(|steps| replace_step(&file.text, &job.id, index, &steps));
                (file, after)
            }
            (Some((file, ..)), None) => (file, None),
            (None, _) => (ci_file(files), None),
        };
        out.push(proposal(
            "ci.coverage-upload",
            file,
            format!(
                "app {} ({}): no job uploads {}<job>, so diff-coverage has nothing to judge",
                app.id, app.stack, prefix
            ),
            after,
        ));
    }
}

/// `commands.<name>` from the app's own profile, else the root's.
fn app_command(root: &Path, profile: &Value, app: &App, name: &str) -> Option<String> {
    let own = (app.path != ".")
        .then(|| read_json(root, &format!("{}/{PROFILE}", app.path)))
        .and_then(|p| p["commands"][name].as_str().map(str::to_owned));
    own.or_else(|| profile["commands"][name].as_str().map(str::to_owned))
}

// ---- line edits -----------------------------------------------------------

fn indent(line: &str) -> usize {
    line.len() - line.trim_start_matches(' ').len()
}

fn content(line: &str) -> bool {
    let t = line.trim();
    !t.is_empty() && !t.starts_with('#')
}

fn joined<S: AsRef<str>>(lines: &[S]) -> String {
    let mut out = String::new();
    for line in lines {
        out.push_str(line.as_ref());
        out.push('\n');
    }
    out
}

/// Each line `edit` returns `Some` for, replaced; `None` when nothing changed.
fn edit_lines(text: &str, edit: impl Fn(&str) -> Option<String>) -> String {
    let lines: Vec<String> = text
        .lines()
        .map(|l| edit(l).unwrap_or_else(|| l.to_owned()))
        .collect();
    joined(&lines)
}

/// The index of the top-level `key:` line.
fn top_key(lines: &[&str], keys: &[&str]) -> Option<usize> {
    lines.iter().position(|line| {
        indent(line) == 0
            && keys.iter().any(|k| {
                line.strip_prefix(k)
                    .and_then(|rest| rest.strip_prefix(':'))
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with([' ', '#']))
            })
    })
}

fn insert_before_jobs(text: &str, block: &[&str]) -> Option<String> {
    let mut lines: Vec<&str> = text.lines().collect();
    let at = top_key(&lines, &["jobs"])?;
    for (i, line) in block.iter().enumerate() {
        lines.insert(at + i, line);
    }
    Some(joined(&lines))
}

/// The jobs' indentation and each job's id with its line range `[start, end)`,
/// `end` past its last content line.
/// A job's id and its line range `[start, end)`.
type JobSpan = (String, usize, usize);

fn jobs(text: &str) -> Option<(usize, Vec<JobSpan>)> {
    let lines: Vec<&str> = text.lines().collect();
    let at = top_key(&lines, &["jobs"])?;
    let child = lines[at + 1..]
        .iter()
        .find(|l| content(l))
        .map(|l| indent(l))
        .filter(|i| *i > 0)?;
    let mut out: Vec<JobSpan> = Vec::new();
    for (i, line) in lines.iter().enumerate().skip(at + 1) {
        if !content(line) {
            continue;
        }
        let depth = indent(line);
        if depth == 0 {
            break;
        }
        if depth == child {
            let key = line.trim().split(':').next().unwrap_or_default();
            let id = key.trim().trim_matches(['"', '\'']);
            out.push((id.to_owned(), i, i + 1));
        } else if let Some(last) = out.last_mut() {
            last.2 = i + 1;
        }
    }
    Some((child, out))
}

fn job_block(text: &str, id: &str) -> Option<(usize, usize)> {
    jobs(text)?
        .1
        .into_iter()
        .find(|(j, ..)| j == id)
        .map(|(_, s, e)| (s, e))
}

fn insert_timeout(text: &str, id: &str) -> Option<String> {
    let (start, end) = job_block(text, id)?;
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    let prop = lines[start + 1..end]
        .iter()
        .find(|l| content(l))
        .map(|l| indent(l))?;
    let runs_on = (start + 1..end).find(|&i| {
        indent(&lines[i]) == prop
            && lines[i]
                .trim()
                .strip_prefix("runs-on:")
                .is_some_and(|v| !v.trim().is_empty())
    });
    let at = runs_on.map_or(start + 1, |i| i + 1);
    lines.insert(
        at,
        format!("{}timeout-minutes: {TIMEOUT_MINUTES}", " ".repeat(prop)),
    );
    Some(joined(&lines))
}

/// The `[start, end)` lines of step `index` of job `id`: from its `- ` line to
/// the next step's, or the job's last content line.
fn step_block(text: &str, id: &str, index: usize) -> Option<(usize, usize)> {
    let (start, end) = job_block(text, id)?;
    let lines: Vec<&str> = text.lines().collect();
    let steps_at = (start + 1..end).find(|&i| lines[i].trim() == "steps:")?;
    let dash = lines[steps_at + 1..end]
        .iter()
        .find(|l| content(l))
        .map(|l| indent(l))?;
    let starts: Vec<usize> = (steps_at + 1..end)
        .filter(|&i| indent(lines[i]) == dash && lines[i].trim_start().starts_with("- "))
        .collect();
    let from = *starts.get(index)?;
    let to = starts.get(index + 1).copied().unwrap_or_else(|| {
        (from + 1..end)
            .take_while(|&i| !content(lines[i]) || indent(lines[i]) > dash)
            .last()
            .map_or(from + 1, |i| i + 1)
    });
    Some((from, to))
}

/// `yaml` (rendered at a job indentation of 2) re-indented to `child`.
fn reindent(yaml: &str, from: usize, to: usize) -> Vec<String> {
    yaml.lines()
        .map(|l| {
            if l.is_empty() {
                String::new()
            } else if to >= from {
                format!("{}{l}", " ".repeat(to - from))
            } else {
                l.get(from - to..).unwrap_or(l).to_owned()
            }
        })
        .collect()
}

fn replace_step(text: &str, id: &str, index: usize, steps: &[Step]) -> Option<String> {
    let (from, to) = step_block(text, id, index)?;
    let lines: Vec<&str> = text.lines().collect();
    let rendered = reindent(&steps_yaml(steps), 6, indent(lines[from]));
    let mut out: Vec<String> = lines[..from].iter().map(|l| (*l).to_owned()).collect();
    out.extend(rendered);
    out.extend(lines[to..].iter().map(|l| (*l).to_owned()));
    Some(joined(&out))
}

fn append_job(text: &str, job: &str) -> Option<String> {
    let (child, all) = jobs(text)?;
    let lines: Vec<&str> = text.lines().collect();
    let at = all.last().map(|(.., end)| *end)?;
    let mut out: Vec<String> = lines[..at].iter().map(|l| (*l).to_owned()).collect();
    out.extend(reindent(job, 2, child));
    out.extend(lines[at..].iter().map(|l| (*l).to_owned()));
    Some(joined(&out))
}

/// `on:` with `pull_request` added: a key under the mapping form, an item of
/// the list form, a list from the scalar form.
fn add_pull_request(text: &str) -> Option<String> {
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    let borrowed: Vec<&str> = text.lines().collect();
    let at = top_key(&borrowed, &["on", "\"on\"", "'on'"])?;
    let (key, value) = lines[at].split_once(':')?;
    let value = value.split(" #").next().unwrap_or("").trim().to_owned();
    if value.is_empty() {
        let child = borrowed[at + 1..]
            .iter()
            .find(|l| content(l))
            .map_or(2, |l| indent(l).max(1));
        lines.insert(at + 1, format!("{}pull_request:", " ".repeat(child)));
    } else if let Some(items) = value.strip_prefix('[').and_then(|v| v.strip_suffix(']')) {
        lines[at] = format!("{key}: [{}, pull_request]", items.trim());
    } else {
        lines[at] = format!("{key}: [{value}, pull_request]");
    }
    Some(joined(&lines))
}

// ---- unified diff ---------------------------------------------------------

/// The unified diff from `before` to `after` of `path`, three lines of context.
pub fn unified(path: &str, before: &str, after: &str) -> String {
    let a: Vec<&str> = before.lines().collect();
    let b: Vec<&str> = after.lines().collect();
    let ops = edit_script(&a, &b);
    let mut out = format!("--- a/{path}\n+++ b/{path}\n");
    let changed: Vec<usize> = ops
        .iter()
        .enumerate()
        .filter(|(_, (op, _))| *op != ' ')
        .map(|(i, _)| i)
        .collect();
    let mut i = 0;
    while i < changed.len() {
        let first = changed[i];
        let mut last = first;
        while i + 1 < changed.len() && changed[i + 1] <= last + 7 {
            i += 1;
            last = changed[i];
        }
        i += 1;
        let from = first.saturating_sub(3);
        let to = (last + 4).min(ops.len());
        let old_before = ops[..from].iter().filter(|(op, _)| *op != '+').count();
        let new_before = ops[..from].iter().filter(|(op, _)| *op != '-').count();
        let hunk = &ops[from..to];
        let old_len = hunk.iter().filter(|(op, _)| *op != '+').count();
        let new_len = hunk.iter().filter(|(op, _)| *op != '-').count();
        let start = |before: usize, len: usize| if len == 0 { before } else { before + 1 };
        let _ = writeln!(
            out,
            "@@ -{},{old_len} +{},{new_len} @@",
            start(old_before, old_len),
            start(new_before, new_len)
        );
        for (op, line) in hunk {
            let _ = writeln!(out, "{op}{line}");
        }
    }
    out
}

/// A shortest edit script: ' ', '-' or '+' per line. The common head and tail
/// are kept as they are, so the longest-common-subsequence table spans only the
/// edited middle (a patch is a local edit; the file may be 256 KiB).
fn edit_script<'a>(a: &[&'a str], b: &[&'a str]) -> Vec<(char, &'a str)> {
    let head = a.iter().zip(b).take_while(|(x, y)| x == y).count();
    let tail = a[head..]
        .iter()
        .rev()
        .zip(b[head..].iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    let mut ops: Vec<(char, &'a str)> = a[..head].iter().map(|l| (' ', *l)).collect();
    ops.extend(middle_script(
        &a[head..a.len() - tail],
        &b[head..b.len() - tail],
    ));
    ops.extend(a[a.len() - tail..].iter().map(|l| (' ', *l)));
    ops
}

/// The edit script of `a` to `b` by longest common subsequence.
fn middle_script<'a>(a: &[&'a str], b: &[&'a str]) -> Vec<(char, &'a str)> {
    let (n, m) = (a.len(), b.len());
    let mut lcs = vec![vec![0u32; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let (mut i, mut j) = (0, 0);
    let mut ops = Vec::with_capacity(n + m);
    while i < n || j < m {
        if i < n && j < m && a[i] == b[j] {
            ops.push((' ', a[i]));
            i += 1;
            j += 1;
        } else if i < n && (j == m || lcs[i + 1][j] >= lcs[i][j + 1]) {
            ops.push(('-', a[i]));
            i += 1;
        } else {
            ops.push(('+', b[j]));
            j += 1;
        }
    }
    ops
}
