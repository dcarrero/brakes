//! The static `ci.*` rules (SPEC-ci-baseline.md, "Auditor rules this module
//! enables" and "How `doctor` reports the static rules"): evaluated locally over
//! every workflow under `.github/workflows/`, owned or not, through the walker
//! of `auditor/workflows.rs`. A failed rule is a `WARNING: ci.<rule-id>: <text>`
//! finding, an unreadable file `WARNING: ci.<rule-id>: unverified: <file>:
//! <reason>`, a passed rule nothing; the auditor's registry judges its rules
//! from these findings at the levels the owner allocated (#873,
//! `auditor::catalogue::modules`). Pinned actions report under the one id kept,
//! `posture.actions-pinned`.
//!
//! The remote rules of slice 2 (#783) are at the end: `ci.required-is-aggregate`,
//! `ci.main-red`, `ci.minutes-month` and the remote half of `ci.workflow-lint`
//! read the host through the auditor's context, sharing its read cache and
//! call budget, and are registered as rules of the `ci` block.
use super::{
    AGGREGATE_CHECK, CI_BASELINE, CONTRIBUTED_AGGREGATE_CHECK, DEFAULT_HELDOUT_DIR, WorkflowMode,
    render::{HELDOUT_JOB, HELDOUT_PROPERTIES_JOB},
};
use crate::{
    PROFILE,
    auditor::{
        Cx, Files, LocalFiles, WORKFLOWS,
        catalogue::{
            ci_health::{self, RECENT_RUNS},
            posture::{Guard, budget_stopped, unread},
        },
        rules::Outcome,
        workflows::{
            self, Job, Permissions, Workflow, file_rule, read_all, repository_rule, unverified,
            warn,
        },
    },
    engine::answers::{self, Answers, AnswersFile},
    host::types::{Job as RunJob, RunFilter, WorkflowRun},
    modules::stack_packs::{self, packs::pack},
};
use chrono::{DateTime, Days};
use serde_json::Value;
use std::{collections::BTreeSet, path::Path};

const DEPENDABOT: &str = ".github/dependabot.yml";

/// `doctor`'s `ci.*` findings for the checkout at `root`, with the recorded
/// answers of `ci-baseline` when it has them.
pub fn diagnose(root: &Path, profile: &Value) -> Vec<String> {
    let recorded = answers::recorded(root, CI_BASELINE).ok().flatten();
    findings(root, profile, recorded.as_ref().map(|f| &f.answers))
}

/// The `ci.*` findings, in the spec's rule order then file order.
pub fn findings(root: &Path, profile: &Value, answers: Option<&Answers>) -> Vec<String> {
    let files = LocalFiles::new(root);
    let answers = answers.map(Recorded::from);
    let mut out = Vec::new();
    if let Some(a) = &answers {
        command_missing(root, profile, a, &mut out);
    }
    let read = read_all(&files);
    if !read.is_empty() {
        let required_checks = strings(&profile["ci"]["required_checks"]);
        let aggregate = answers.as_ref().map(|a| a.aggregate.as_str());
        repository_rule(
            "ci.aggregate-present",
            "No aggregate job: required checks can hang or skip",
            &read,
            |wf| aggregate_present(wf, aggregate, &required_checks),
            &mut out,
        );
        file_rule("ci.job-timeouts", &read, job_timeouts, &mut out);
        file_rule("ci.permissions-least", &read, permissions_least, &mut out);
        // One id for pinned actions: the auditor's (#873).
        file_rule("posture.actions-pinned", &read, actions_pinned, &mut out);
        repository_rule(
            "ci.workflow-lint",
            "Workflow lint absent",
            &read,
            |wf| wf.job("workflow-lint").is_some(),
            &mut out,
        );
        file_rule("ci.no-self-hosted-label", &read, no_self_hosted, &mut out);
        file_rule("ci.hosted-macos", &read, hosted_macos, &mut out);
        dependabot_actions(&files, &mut out);
        let heldout_dir = answers
            .as_ref()
            .map_or(DEFAULT_HELDOUT_DIR, |a| a.heldout_dir.as_str());
        let has_tests = has_file(&root.join(heldout_dir));
        repository_rule(
            "ci.heldout-present",
            "No held-out test job: the agent can edit every test it is measured against",
            &read,
            |wf| has_tests && heldout_wired(wf),
            &mut out,
        );
        repository_rule(
            "ci.protected-paths-gate",
            "Protected paths are not gated: a workflow or held-out change can merge without a human",
            &read,
            protected_paths_gated,
            &mut out,
        );
        // #1255: a gate that reads the label but not who added it counts an App's.
        let gated = read
            .iter()
            .any(|(_, wf)| wf.as_ref().is_ok_and(protected_paths_gated));
        let checked = read
            .iter()
            .any(|(_, wf)| wf.as_ref().is_ok_and(label_actor_checked));
        if gated && !checked {
            out.push(warn(
                "ci.protected-paths-gate",
                "The protected-paths gate reads the label but not who added it: a human-approved an App or bot added would count",
            ));
        }
        if let Some(a) = &answers {
            placeholder_paths(&a.protected_paths, &mut out);
        }
        heldout_properties(
            &read,
            answers.as_ref().is_some_and(|a| a.heldout_properties),
            &mut out,
        );
    }
    // The answer is the flag (#784), workflows or none: a generated push-only
    // job never bills on pull requests, but hosted macOS still bills at a
    // premium multiple.
    if answers.as_ref().is_some_and(|a| a.hosted_macos) {
        out.push(warn(
            "ci.hosted-macos",
            hosted_macos_message(crate::config::macos_runner()),
        ));
    }
    if let Some(a) = &answers {
        let lock = crate::read(root, crate::LOCK).ok().flatten();
        project_ci_stale(profile, &required_checks(a, lock.as_deref()), a, &mut out);
    }
    out
}

/// The checks the default branch requires for these answers (#1159): the
/// aggregate, followed under `workflow: existing` by `agentic-required` when
/// the installed `lock` records ci-baseline's `github:add-agentic-required-check`,
/// as `model::required_checks` gives them to the ruleset at plan time.
fn required_checks(a: &Recorded, lock: Option<&str>) -> Vec<String> {
    let mut checks = vec![a.aggregate.clone()];
    let item = format!("github:{}", super::brownfield::ADD_CHECK);
    let added = lock
        .and_then(|text| serde_json::from_str::<Value>(text).ok())
        .is_some_and(|lock| lock["files"][item.as_str()]["module"] == CI_BASELINE);
    if a.workflow == WorkflowMode::Existing && added {
        checks.push(CONTRIBUTED_AGGREGATE_CHECK.to_owned());
    }
    checks
}

/// The answers the rules read, with the module's defaults.
struct Recorded {
    workflow: WorkflowMode,
    /// The check the aggregate is named by.
    aggregate: String,
    commands: Vec<String>,
    runner: String,
    tiers: bool,
    /// The answered held-out directory without a leading `./` or trailing `/`.
    heldout_dir: String,
    /// The answered `protected_paths`, empty when unanswered (the derived
    /// default carries no placeholder).
    protected_paths: Vec<String>,
    /// The monthly billed-minute threshold `ci.minutes-month` compares against.
    minutes_budget: u64,
    /// `macos` true with `macos_runner: github-hosted`.
    hosted_macos: bool,
    /// `heldout_properties` answered true and `heldout` not answered false:
    /// the loader reads it only under `heldout` (#980).
    heldout_properties: bool,
}
impl Default for Recorded {
    /// The defaults of the question table: what an unmanaged repository is
    /// held to (`required`, the default budget).
    fn default() -> Self {
        Self::from(&Answers::default())
    }
}
impl From<&Answers> for Recorded {
    fn from(a: &Answers) -> Self {
        let text = |id: &str| a.get(id).and_then(Value::as_str);
        let workflow = match text("workflow") {
            Some("existing") => WorkflowMode::Existing,
            Some("seed") => WorkflowMode::Seed,
            _ => WorkflowMode::Generate,
        };
        let aggregate = match workflow {
            WorkflowMode::Existing => text("aggregate_check").unwrap_or(AGGREGATE_CHECK),
            WorkflowMode::Generate | WorkflowMode::Seed => AGGREGATE_CHECK,
        };
        Self {
            workflow,
            aggregate: aggregate.to_owned(),
            commands: a.get("commands").map(strings).unwrap_or_default(),
            runner: text("runner")
                .unwrap_or_else(|| super::Runner::default_choice().as_str())
                .to_owned(),
            tiers: a.get("tiers").and_then(Value::as_bool).unwrap_or(true),
            heldout_dir: text("heldout_dir")
                .map(|d| d.trim_start_matches("./").trim_end_matches('/'))
                .filter(|d| !d.is_empty())
                .unwrap_or(DEFAULT_HELDOUT_DIR)
                .to_owned(),
            protected_paths: a.get("protected_paths").map(strings).unwrap_or_default(),
            minutes_budget: a
                .get("minutes_budget")
                .and_then(Value::as_u64)
                .unwrap_or(DEFAULT_MINUTES_BUDGET),
            hosted_macos: a.get("macos").and_then(Value::as_bool) == Some(true)
                && text("macos_runner") == Some("github-hosted"),
            heldout_properties: a.get("heldout_properties").and_then(Value::as_bool) == Some(true)
                && a.get("heldout").and_then(Value::as_bool) != Some(false),
        }
    }
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn command_missing(root: &Path, profile: &Value, a: &Recorded, out: &mut Vec<String>) {
    if a.workflow != WorkflowMode::Generate {
        return;
    }
    // Monorepo mode (#784): each app's job reads its own profile, so this rule
    // reads the apps' (#1037), and the root's when no app is at `.`, since the
    // root `checks` job runs what it declares (#1165).
    let recorded = stack_packs::audit::recorded_apps(root).unwrap_or_default();
    let root_job = !recorded.iter().any(|app| app.path == ".");
    let apps: Vec<_> = recorded
        .into_iter()
        .filter(|app| !pack(app.stack).macos_target)
        .collect();
    if apps.len() > 1 || apps.iter().any(|app| app.path != ".") {
        return command_missing_in_apps(root, &apps, root_job.then_some(profile), a, out);
    }
    for name in &a.commands {
        if !profile["commands"][name.as_str()].is_string() {
            out.push(warn(
                "ci.command-missing",
                format!("Verification command missing: commands.{name}"),
            ));
        }
    }
}

/// In a monorepo an app runs only the answered commands its own profile
/// declares (#784), so what the per-app jobs would miss is an answered command
/// no app (nor the root profile, when its job runs) declares, and an app
/// without a profile or declaring none of them.
fn command_missing_in_apps(
    root: &Path,
    apps: &[stack_packs::audit::RecordedApp],
    root_profile: Option<&Value>,
    a: &Recorded,
    out: &mut Vec<String>,
) {
    const RULE: &str = "ci.command-missing";
    let mut profiles = Vec::new();
    for app in apps {
        let file = format!("{}/{PROFILE}", app.path);
        match crate::read(root, &file) {
            Ok(Some(text)) => match serde_json::from_str::<Value>(&text) {
                Ok(profile) => profiles.push((app, file, Some(profile))),
                Err(e) => out.push(unverified(RULE, &file, &e.to_string())),
            },
            Ok(None) => profiles.push((app, file, None)),
            Err(e) => out.push(unverified(RULE, &file, &e.to_string())),
        }
    }
    let declares = |profile: &Value, name: &str| profile["commands"][name].is_string();
    for name in &a.commands {
        let declared = root_profile.is_some_and(|p| declares(p, name))
            || profiles
                .iter()
                .any(|(_, _, p)| p.as_ref().is_some_and(|p| declares(p, name)));
        if !declared {
            out.push(warn(
                RULE,
                format!("Verification command missing: commands.{name} is declared by no app"),
            ));
        }
    }
    for (app, file, profile) in &profiles {
        match profile {
            None => out.push(warn(
                RULE,
                format!("Verification command missing: app {} has no {file}", app.id),
            )),
            Some(p) if !a.commands.iter().any(|name| declares(p, name)) => {
                let names: Vec<String> =
                    a.commands.iter().map(|n| format!("commands.{n}")).collect();
                out.push(warn(
                    RULE,
                    format!(
                        "Verification command missing: app {} declares none of {} in {file}",
                        app.id,
                        names.join(", ")
                    ),
                ));
            }
            Some(_) => {}
        }
    }
}

fn display_name(job: &Job) -> &str {
    job.name.as_deref().unwrap_or(&job.id)
}

/// Runs only on pushes: a job-level `if:` with no top-level `||` and a
/// top-level conjunct `github.event_name == 'push'`; a `||` nested inside
/// another conjunct leaves it push-only (#1160).
fn push_only(job: &Job) -> bool {
    job.condition.as_deref().is_some_and(|c| {
        let c: String = c.chars().filter(|ch| !ch.is_whitespace()).collect();
        let c = c
            .strip_prefix("${{")
            .and_then(|c| c.strip_suffix("}}"))
            .unwrap_or(&c);
        top_level(c, "||").len() == 1
            && top_level(c, "&&").iter().any(|conjunct| {
                let conjunct = conjunct.trim_start_matches('(').trim_end_matches(')');
                conjunct == "github.event_name=='push'" || conjunct == "github.event_name==\"push\""
            })
    })
}

/// `expression` split on `operator` outside parentheses and quoted strings.
fn top_level<'a>(expression: &'a str, operator: &str) -> Vec<&'a str> {
    let mut parts = Vec::new();
    let (mut depth, mut quote, mut start) = (0usize, None, 0);
    let mut chars = expression.char_indices();
    while let Some((i, ch)) = chars.next() {
        match (quote, ch) {
            (Some(q), _) if ch == q => quote = None,
            (Some(_), _) => {}
            (None, '\'' | '"') => quote = Some(ch),
            (None, '(') => depth += 1,
            (None, ')') => depth = depth.saturating_sub(1),
            (None, _) if depth == 0 && expression[i..].starts_with(operator) => {
                parts.push(&expression[start..i]);
                start = i + operator.len();
                chars.nth(operator.len() - 2);
            }
            _ => {}
        }
    }
    parts.push(&expression[start..]);
    parts
}

/// A job with `if: always()` (the answered aggregate when there is one) that
/// covers every other job: in its transitive `needs`, push-only, itself
/// another check listed in `ci.required_checks`, or downstream of it.
fn aggregate_present(wf: &Workflow, aggregate: Option<&str>, required_checks: &[String]) -> bool {
    wf.jobs.iter().any(|gate| {
        let always = always(gate);
        let named = aggregate.is_none_or(|name| display_name(gate) == name);
        always && named && {
            let mut needed = BTreeSet::new();
            let mut stack: Vec<&str> = gate.needs.iter().map(String::as_str).collect();
            while let Some(id) = stack.pop() {
                if needed.insert(id)
                    && let Some(job) = wf.job(id)
                {
                    stack.extend(job.needs.iter().map(String::as_str));
                }
            }
            wf.jobs.iter().filter(|j| j.id != gate.id).all(|job| {
                needed.contains(job.id.as_str())
                    || push_only(job)
                    || required_checks.iter().any(|c| c == display_name(job))
                    || downstream(wf, job, &gate.id)
            })
        }
    })
}

/// True when `gate` is in the transitive `needs` of `job`: the job runs after
/// the aggregate has judged, so it cannot gate a pull request (#1160).
fn downstream(wf: &Workflow, job: &Job, gate: &str) -> bool {
    let mut seen = BTreeSet::new();
    let mut stack: Vec<&str> = job.needs.iter().map(String::as_str).collect();
    while let Some(id) = stack.pop() {
        if id == gate {
            return true;
        }
        if seen.insert(id)
            && let Some(job) = wf.job(id)
        {
            stack.extend(job.needs.iter().map(String::as_str));
        }
    }
    false
}

/// True when `dir` holds a regular file at any depth; symbolic links are not
/// followed and an unreadable directory holds none.
fn has_file(dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    entries.flatten().any(|entry| match entry.file_type() {
        Ok(kind) if kind.is_file() => true,
        Ok(kind) if kind.is_dir() => has_file(&entry.path()),
        _ => false,
    })
}

fn always(job: &Job) -> bool {
    job.condition
        .as_deref()
        .is_some_and(|c| c.contains("always()"))
}

/// A `heldout` job that an `if: always()` job of the same workflow needs.
fn heldout_wired(wf: &Workflow) -> bool {
    wf.job(HELDOUT_JOB).is_some()
        && wf
            .jobs
            .iter()
            .any(|gate| always(gate) && gate.needs.iter().any(|n| n == HELDOUT_JOB))
}

/// `ci.heldout-properties` (#980), opt-in: judged where `heldout_properties`
/// is answered true or a workflow has a `heldout-properties` job, silent
/// elsewhere. It passes when such a job is in the `needs` of an `if: always()`
/// job of its workflow and has a step whose `env:` names `HELDOUT_SEED` and
/// `HELDOUT_EXAMPLES`; an unread file leaves it unverified unless another
/// file already settles it.
fn heldout_properties(read: &workflows::Parsed, answered: bool, out: &mut Vec<String>) {
    const RULE: &str = "ci.heldout-properties";
    let parsed: Vec<&Workflow> = read.iter().filter_map(|(_, wf)| wf.as_ref().ok()).collect();
    let present = parsed
        .iter()
        .any(|wf| wf.job(HELDOUT_PROPERTIES_JOB).is_some());
    if !answered && !present {
        return;
    }
    let wired = |wf: &Workflow| {
        wf.jobs
            .iter()
            .any(|gate| always(gate) && gate.needs.iter().any(|n| n == HELDOUT_PROPERTIES_JOB))
    };
    let seeded = |wf: &Workflow| {
        wf.job(HELDOUT_PROPERTIES_JOB).is_some_and(|job| {
            job.steps.iter().any(|step| {
                step.env.contains_key("HELDOUT_SEED") && step.env.contains_key("HELDOUT_EXAMPLES")
            })
        })
    };
    let in_aggregate: Vec<&&Workflow> = parsed
        .iter()
        .filter(|wf| wf.job(HELDOUT_PROPERTIES_JOB).is_some() && wired(wf))
        .collect();
    if in_aggregate.iter().any(|wf| seeded(wf)) {
        return;
    }
    let broken: Vec<String> = read
        .iter()
        .filter_map(|(path, wf)| wf.as_ref().err().map(|e| unverified(RULE, path, e)))
        .collect();
    if !broken.is_empty() {
        out.extend(broken);
    } else if !in_aggregate.is_empty() {
        out.push(warn(
            RULE,
            "Held-out properties job present but no seed is exported: the run is deterministic and memorisable",
        ));
    } else if answered {
        out.push(warn(
            RULE,
            "heldout_properties is true and no heldout-properties job is in the aggregate",
        ));
    } else {
        out.push(warn(
            RULE,
            "Held-out properties job is not in the aggregate: a red run does not block the merge",
        ));
    }
}

/// `ci.protected-paths-gate` (#1229): one finding per answered `protected_paths`
/// entry still carrying a `<name>` placeholder, which the scope job matches
/// literally.
fn placeholder_paths(protected_paths: &[String], out: &mut Vec<String>) {
    for path in protected_paths
        .iter()
        .filter(|p| super::scope::unresolved_placeholder(p))
    {
        out.push(warn(
            "ci.protected-paths-gate",
            format!(
                "protected_paths entry {path} carries an unresolved placeholder; the scope job matches it literally"
            ),
        ));
    }
}

/// `on.pull_request.types` lists `labeled` and `unlabeled`, and an `if:
/// always()` job has a step whose `env:` names `PR_LABELS` and `PROTECTED`
/// (`ci.protected-paths-gate`; also read by `qa.snapshots-protected`).
pub fn protected_paths_gated(wf: &Workflow) -> bool {
    let types = wf.trigger_types.get("pull_request");
    let relabelled = types.is_some_and(|t| {
        ["labeled", "unlabeled"]
            .iter()
            .all(|want| t.iter().any(|have| have == want))
    });
    relabelled
        && wf.jobs.iter().any(|gate| {
            always(gate)
                && gate.steps.iter().any(|step| {
                    step.env.contains_key("PR_LABELS") && step.env.contains_key("PROTECTED")
                })
        })
}

/// A gate of [`protected_paths_gated`] that also reads who added the label
/// (#1255): its step's `run:` reads the pull request's issue events (`/events`) and
/// the job's token may (`issues` or `pull-requests`, read or write, from the job's
/// `permissions:` or else the workflow's). A static reading of the script, not a
/// proof of its logic.
pub fn label_actor_checked(wf: &Workflow) -> bool {
    let grants = |permissions: Option<&Permissions>| match permissions {
        Some(Permissions::Scopes(scopes)) => ["issues", "pull-requests"].iter().any(|scope| {
            scopes
                .get(*scope)
                .is_some_and(|a| a == "read" || a == "write")
        }),
        Some(Permissions::Scalar(all)) => all == "read-all" || all == "write-all",
        None => false,
    };
    protected_paths_gated(wf)
        && wf.jobs.iter().any(|gate| {
            always(gate)
                && grants(gate.permissions.as_ref().or(wf.permissions.as_ref()))
                && gate.steps.iter().any(|step| {
                    step.env.contains_key("PR_LABELS")
                        && step.env.contains_key("PROTECTED")
                        && step.run.as_deref().is_some_and(|r| r.contains("/events"))
                })
        })
}

fn job_timeouts(_: &str, wf: &Workflow) -> Vec<String> {
    wf.jobs
        .iter()
        .filter(|j| j.uses.is_none() && j.timeout_minutes.is_none())
        .map(|j| format!("Job {} has no timeout-minutes", j.id))
        .collect()
}

fn permissions_least(path: &str, wf: &Workflow) -> Vec<String> {
    let least = match &wf.permissions {
        Some(Permissions::Scopes(scopes)) => scopes
            .iter()
            .all(|(scope, access)| access == "none" || (scope == "contents" && access == "read")),
        _ => false,
    };
    let top =
        (!least).then(|| format!("Workflow {path} grants more than contents: read at top level"));
    let checkouts =
        wf.jobs
            .iter()
            .filter(|j| {
                j.steps.iter().any(|s| {
                    s.uses.as_deref().is_some_and(|u| {
                        u.starts_with("actions/checkout@") || u == "actions/checkout"
                    }) && s.with.get("persist-credentials").map(String::as_str) != Some("false")
                })
            })
            .map(|j| format!("Checkout in job {} of {path} persists credentials", j.id));
    top.into_iter().chain(checkouts).collect()
}

fn actions_pinned(path: &str, wf: &Workflow) -> Vec<String> {
    wf.unpinned_uses()
        .into_iter()
        .map(|u| format!("Unpinned action {u} in {path}"))
        .collect()
}

fn no_self_hosted(_: &str, wf: &Workflow) -> Vec<String> {
    wf.jobs
        .iter()
        .filter(|j| j.runs_on.iter().any(|l| l.contains("self-hosted")))
        .map(|j| format!("Job {} runs on a self-hosted label", j.id))
        .collect()
}

fn hosted_macos(_: &str, wf: &Workflow) -> Vec<String> {
    let on_pull_requests = wf
        .triggers
        .iter()
        .any(|t| t == "pull_request" || t == "pull_request_target");
    let macos = wf
        .jobs
        .iter()
        .any(|j| !push_only(j) && j.runs_on.iter().any(|l| l.contains("macos-")));
    (on_pull_requests && macos)
        .then(|| "Hosted macOS on pull requests bills at a premium multiple".to_owned())
        .into_iter()
        .collect()
}

fn dependabot_actions(files: &dyn Files, out: &mut Vec<String>) {
    const RULE: &str = "ci.dependabot-actions";
    let text = match files.read(DEPENDABOT) {
        Ok(text) => text,
        Err(e) => return out.push(unverified(RULE, DEPENDABOT, &e.to_string())),
    };
    let ecosystems = match text.as_deref().map(workflows::dependabot_ecosystems) {
        None => Vec::new(),
        Some(Ok(ecosystems)) => ecosystems,
        Some(Err(e)) => return out.push(unverified(RULE, DEPENDABOT, &e)),
    };
    if !ecosystems.iter().any(|e| e == "github-actions") {
        out.push(warn(
            RULE,
            "Dependabot does not update the github-actions ecosystem",
        ));
    }
}

/// The `ci.hosted-macos` warning: it names the configured macOS runner as the
/// default, or asks for one when none is configured.
fn hosted_macos_message(configured: Option<&crate::config::NamedRunner>) -> String {
    let head = "Hosted macOS answered (macos_runner github-hosted) bills at a premium multiple on every push to main";
    match configured {
        Some(r) => format!("{head}; {} is the default", r.name),
        None => format!("{head}; configure a macOS runner to avoid it"),
    }
}

/// Decision 4: `ci.runners`, `ci.required_checks` and `ci.tiers` of the
/// profile are superseded by the answers; one warning names those that disagree.
fn project_ci_stale(profile: &Value, required: &[String], a: &Recorded, out: &mut Vec<String>) {
    let ci = &profile["ci"];
    let runners = &ci["runners"];
    let values: Vec<&str> = match runners {
        Value::Object(map) => map.values().filter_map(Value::as_str).collect(),
        other => other.as_str().into_iter().collect(),
    };
    let linux = runners["linux"].as_str().or_else(|| runners.as_str());
    let provider: &[&str] = if a.runner == "github" {
        &["github", "ubuntu"]
    } else {
        &[crate::config::linux_runner().map_or("github", |r| r.name.as_str())]
    };
    let runners_stale = values.iter().any(|v| v.contains("self-hosted"))
        || linux.is_some_and(|l| !provider.iter().any(|p| l.contains(p)));
    let checks = &ci["required_checks"];
    let checks_stale = !checks.is_null() && strings(checks) != required;
    let tiers = &ci["tiers"];
    let tiers_stale = !tiers.is_null() && (tiers != &Value::Bool(false)) != a.tiers;
    let stale: Vec<&str> = [
        (runners_stale, "ci.runners"),
        (checks_stale, "ci.required_checks"),
        (tiers_stale, "ci.tiers"),
    ]
    .into_iter()
    .filter_map(|(stale, field)| stale.then_some(field))
    .collect();
    if !stale.is_empty() {
        out.push(warn(
            "ci.project-ci-stale",
            format!(
                "{PROFILE} {} disagree with the ci-baseline answers; the answers govern (Decision 4)",
                stale.join(", ")
            ),
        ));
    }
}

// ---- the remote rules (SPEC-ci-baseline.md, slice 2; #783) --------------------------

/// The window `ci.minutes-month` bills over, in days to `--now`.
pub const MONTH_DAYS: u64 = 30;
/// Runs whose jobs the month's minutes are read from, newest first, one call
/// each; the rest of the listing is extrapolated from them.
pub const MONTH_SAMPLE_RUNS: usize = 10;
/// The fewest runs the minutes are judged over when the call budget cuts the
/// sample (SPEC-auditor.md, "Block allowances").
pub const MONTH_MIN_RUNS: usize = 5;
/// The default of the `minutes_budget` answer.
pub const DEFAULT_MINUTES_BUDGET: u64 = 2000;
/// The job the remote half of `ci.workflow-lint` reads.
pub const WORKFLOW_LINT_JOB: &str = "workflow-lint";

/// The recorded answers through the auditor's files (the contents API under
/// `--fleet`): the defaults without the file, so an unmanaged repository is
/// held to `required` and the default budget.
fn recorded_answers(files: &dyn Files) -> Result<Recorded, Outcome> {
    let path = answers::path(CI_BASELINE);
    match files.read(&path) {
        Ok(None) => Ok(Recorded::default()),
        Ok(Some(text)) => AnswersFile::parse(CI_BASELINE, &text)
            .map(|file| Recorded::from(&file.answers))
            .map_err(|_| Outcome::unavailable(format!("{path} does not parse"))),
        Err(e) => Err(Outcome::unavailable(format!("{path} unreadable: {e}"))),
    }
}

fn joined(items: &BTreeSet<String>) -> String {
    if items.is_empty() {
        "none".to_owned()
    } else {
        items.iter().cloned().collect::<Vec<_>>().join(", ")
    }
}

/// `ci.required-is-aggregate`: the status checks the default branch requires,
/// through rulesets and classic protection together, are exactly the
/// aggregate (`required`, or the recorded `aggregate_check` under
/// `workflow: existing`, followed by `agentic-required` when the lock records
/// its remote item; #1159).
pub fn required_is_aggregate(cx: &Cx<'_>) -> Outcome {
    let answers = match recorded_answers(cx.files) {
        Ok(answers) => answers,
        Err(outcome) => return outcome,
    };
    let guard = Guard::read(cx);
    if let Some(e) = guard.unreadable() {
        return unread(e);
    }
    let mut required: BTreeSet<String> = guard
        .protection()
        .map(|p| p.required_status_checks.iter().cloned().collect())
        .unwrap_or_default();
    required.extend(
        guard
            .active()
            .iter()
            .flat_map(|r| r.required_status_checks.iter().cloned()),
    );
    let lock = match cx.files.read(crate::LOCK) {
        Ok(text) => text,
        Err(e) => return Outcome::unavailable(format!("{} unreadable: {e}", crate::LOCK)),
    };
    let expected: BTreeSet<String> = required_checks(&answers, lock.as_deref())
        .into_iter()
        .collect();
    let names = joined(&expected);
    if required == expected {
        Outcome::passed([format!("{} requires only {names}", guard.branch)])
    } else {
        guard.settle(vec![format!(
            "Required checks are {}; expected only {names}",
            joined(&required)
        )])
    }
}

/// The names of the workflows under `.github/workflows` with a job whose
/// display name is `job`, sorted; `None` with the reason when there is none.
fn workflows_with_job(cx: &Cx<'_>, job: &str) -> Result<Vec<String>, Outcome> {
    let mut names: Vec<String> = read_all(cx.files)
        .into_iter()
        .filter_map(|(path, parsed)| {
            let wf = parsed.ok()?;
            wf.jobs
                .iter()
                .any(|j| display_name(j) == job)
                .then(|| wf.name.unwrap_or(path))
        })
        .collect();
    names.sort();
    names.dedup();
    if names.is_empty() {
        return Err(Outcome::unavailable(format!(
            "no workflow under {WORKFLOWS} declares a job named {job}"
        )));
    }
    Ok(names)
}

/// The latest conclusive completed push run on the default branch of one of
/// `names`, from the listing ci-health reads (one call per audit).
fn latest_cycle(cx: &Cx<'_>, names: &[String]) -> Result<WorkflowRun, Outcome> {
    let runs = ci_health::latest(cx, true, RECENT_RUNS)?;
    runs.into_iter()
        .find(|r| names.contains(&r.name) && ci_health::conclusive(r))
        .ok_or_else(|| {
            Outcome::unavailable(format!(
                "no completed push run of {} on {} among the latest {RECENT_RUNS} that was neither cancelled nor skipped",
                names.join(", "),
                cx.default_branch
            ))
        })
}

/// `ci.main-red`: the latest conclusive push run on the default branch of the
/// workflow that declares the aggregate job concluded `success`.
pub fn main_red(cx: &Cx<'_>) -> Outcome {
    let answers = match recorded_answers(cx.files) {
        Ok(answers) => answers,
        Err(outcome) => return outcome,
    };
    let names = match workflows_with_job(cx, &answers.aggregate) {
        Ok(names) => names,
        Err(outcome) => return outcome,
    };
    let run = match latest_cycle(cx, &names) {
        Ok(run) => run,
        Err(outcome) => return outcome,
    };
    let main = cx.default_branch;
    match run.conclusion.as_deref() {
        Some("success") => Outcome::passed([format!(
            "the latest conclusive push run of {} on {main}, run {}, succeeded",
            run.name, run.id
        )]),
        other => Outcome::failed([format!(
            "Latest main cycle is red: run {} of {} on {main} concluded {}",
            run.id,
            run.name,
            other.unwrap_or("without a conclusion")
        )]),
    }
}

/// The remote half of `ci.workflow-lint` (`doctor --remote`): the
/// `workflow-lint` job of the latest conclusive push run on the default branch
/// of the workflow that declares it concluded `success`.
pub fn workflow_lint_green(cx: &Cx<'_>) -> Outcome {
    let names = match workflows_with_job(cx, WORKFLOW_LINT_JOB) {
        Ok(names) => names,
        Err(outcome) => return outcome,
    };
    let run = match latest_cycle(cx, &names) {
        Ok(run) => run,
        Err(outcome) => return outcome,
    };
    let jobs = match cx.host.jobs(cx.repo, run.id) {
        Ok(jobs) => jobs,
        Err(e) => return unread(&e),
    };
    let main = cx.default_branch;
    let Some(job) = jobs.iter().find(|j| j.name == WORKFLOW_LINT_JOB) else {
        return Outcome::unavailable(format!(
            "run {} of {} on {main} has no job {WORKFLOW_LINT_JOB}",
            run.id, run.name
        ));
    };
    match job.conclusion.as_deref() {
        Some("success") => Outcome::passed([format!(
            "{WORKFLOW_LINT_JOB} succeeded in run {} of {} on {main}",
            run.id, run.name
        )]),
        other => Outcome::failed([format!(
            "Workflow lint red on main: job {WORKFLOW_LINT_JOB} of run {} of {} concluded {}",
            run.id,
            run.name,
            other.unwrap_or("without a conclusion")
        )]),
    }
}

fn seconds(time: &str) -> Option<i64> {
    DateTime::parse_from_rfc3339(time)
        .ok()
        .map(|t| t.timestamp())
}

/// The minutes GitHub bills a job: its wall-clock time rounded up to the next
/// minute, at least one; a skipped job or one without both timestamps bills
/// nothing.
fn billed_minutes(job: &RunJob) -> u64 {
    if job.conclusion.as_deref() == Some("skipped") {
        return 0;
    }
    let (Some(start), Some(end)) = (
        job.started_at.as_deref().and_then(seconds),
        job.completed_at.as_deref().and_then(seconds),
    ) else {
        return 0;
    };
    if end < start {
        return 0;
    }
    u64::try_from(end - start).map_or(0, |s| s.div_ceil(60).max(1))
}

/// `ci.minutes-month`: the sum over the last [`MONTH_DAYS`] days of each
/// job's minutes rounded up, hosted and third-party alike, read from the jobs
/// of the newest [`MONTH_SAMPLE_RUNS`] completed runs of the window and
/// extrapolated to the runs listed, against the recorded `minutes_budget`.
pub fn minutes_month(cx: &Cx<'_>) -> Outcome {
    let answers = match recorded_answers(cx.files) {
        Ok(answers) => answers,
        Err(outcome) => return outcome,
    };
    let budget = answers.minutes_budget;
    let since = cx
        .now
        .checked_sub_days(Days::new(MONTH_DAYS))
        .unwrap_or(cx.now)
        .format("%Y-%m-%d")
        .to_string();
    let filter = RunFilter {
        status: Some("completed".to_owned()),
        created_since: Some(since.clone()),
        limit: Some(RECENT_RUNS),
        ..RunFilter::default()
    };
    let runs = match cx.host.workflow_runs(cx.repo, &filter) {
        Ok(runs) => runs,
        Err(e) => return unread(&e),
    };
    let verdict = |minutes: u64, how: String| {
        let evidence = [
            format!("Billed about {minutes} minutes in 30 days; budget {budget}"),
            how,
        ];
        if minutes <= budget {
            Outcome::passed(evidence)
        } else {
            Outcome::failed(evidence)
        }
    };
    if runs.is_empty() {
        return verdict(0, format!("no completed run since {since}"));
    }
    let mut sum = 0;
    let mut sampled = 0;
    let mut stopped = None;
    for (read, run) in runs.iter().take(MONTH_SAMPLE_RUNS).enumerate() {
        match cx.host.jobs(cx.repo, run.id) {
            Ok(jobs) => {
                sum += jobs.iter().map(billed_minutes).sum::<u64>();
                sampled += 1;
            }
            Err(e) => match unread(&e) {
                outcome if budget_stopped(&outcome) && sampled >= MONTH_MIN_RUNS => {
                    stopped = Some(read);
                    break;
                }
                outcome => return outcome,
            },
        }
    }
    let listed = runs.len();
    let minutes = if sampled == listed {
        sum
    } else {
        (sum * listed as u64).div_ceil(sampled as u64)
    };
    // The listing holds at most RECENT_RUNS: a full page may hide earlier
    // runs of the window, so the figure is then a floor, and says so.
    let extrapolated = if sampled == listed {
        String::new()
    } else if listed == RECENT_RUNS as usize {
        format!(", extrapolated to the {listed} listed; earlier runs of the window are not counted")
    } else {
        format!(", extrapolated to the {listed}")
    };
    let cut = stopped.map_or_else(String::new, |read| {
        format!(" (the call budget stopped it at {read} of {MONTH_SAMPLE_RUNS} runs)")
    });
    verdict(
        minutes,
        format!(
            "the jobs of {sampled} of {listed} completed runs since {since}, each rounded up to the minute{extrapolated}{cut}"
        ),
    )
}

#[cfg(test)]
mod runner_message_tests {
    use super::*;
    use crate::config::NamedRunner;

    #[test]
    fn the_hosted_macos_warning_names_the_configured_runner_or_asks_for_one() {
        let mac = NamedRunner {
            name: "macfarm".into(),
            label: "mac-1".into(),
        };
        assert!(hosted_macos_message(Some(&mac)).ends_with("; macfarm is the default"));
        assert!(hosted_macos_message(None).ends_with("; configure a macOS runner to avoid it"));
    }
}
