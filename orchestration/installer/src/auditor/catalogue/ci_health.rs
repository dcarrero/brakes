//! CI health rules (SPEC-auditor.md, "CI health reads and the budget", #724):
//! a workflow exists and its latest default-branch run succeeded, re-runs and
//! cancellations within their thresholds, and the median cycle to the first
//! declared required check within `ci.cycle_budget_minutes`, with a labelled
//! sample of this month's CI minutes. Host reads go through the adapter only;
//! every read is bounded so the block fits the 60-call budget of a repository.
use super::posture::{budget_stopped, unread};
use crate::{
    PROFILE,
    auditor::{
        Cx, WORKFLOWS,
        rules::{
            Block, Cadence, Condition, Level, Milestone, Outcome, Probe, Profile, Remediation,
            Required, Rule,
        },
        workflows,
    },
    host::types::{RunFilter, WorkflowRun},
};
use chrono::{DateTime, Datelike};
use serde_json::Value;

const ALL: Required = Required {
    profiles: &[Profile::P1, Profile::P2, Profile::P3],
    when: &[],
};
/// Cadence rules: required whatever the profile once the agents merge enough.
const CADENCE_MID: Required = Required {
    profiles: &[],
    when: &[Condition::CadenceAtLeast(Cadence::Mid)],
};
/// The events that run CI; scheduled and chained workflows (uptime probes,
/// bots) would drown the rates and say nothing about the CI.
pub const CI_EVENTS: &[&str] = &["push", "pull_request", "merge_group"];
/// The runs the rates and the minutes sample are read from (one call).
pub const RECENT_RUNS: u32 = 100;
/// Default-branch push runs the latest-run verdict looks through: the first of
/// the [`RECENT_RUNS`] listing `minutes-budget` reads, so one audit lists them
/// once (#917).
pub const LATEST_RUNS: usize = 20;
/// Runs whose jobs the median cycle reads, one call each.
pub const CYCLE_RUNS: usize = 20;
/// The fewest runs the median cycle is judged over when the call budget cuts
/// its sample (SPEC-auditor.md, "Block allowances", #920).
pub const CYCLE_MIN_RUNS: usize = 5;
/// More re-run runs than this percentage fails.
pub const RERUN_MAX_PERCENT: f64 = 10.0;
/// More cancelled runs than this percentage fails.
pub const CANCELLED_MAX_PERCENT: f64 = 20.0;

pub const WORKFLOW_EXISTS: Rule = Rule {
    id: "ci-health.workflow-exists",
    title: "CI workflow exists and is green",
    block: Block::CiHealth,
    checks: "A workflow exists and the latest conclusive push run on the default branch succeeded.",
    how: Probe::Remote {
        id: "workflows+workflow-runs",
    },
    level: Level::Basic,
    required: ALL,
    remediation: Remediation::Module { id: "ci-baseline" },
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: workflow_exists,
};

pub const RERUN_RATE: Rule = Rule {
    id: "ci-health.rerun-rate",
    title: "Few re-runs",
    block: Block::CiHealth,
    checks: "At most 10 % of the CI runs (push, pull_request, merge_group) among the latest 100 workflow runs needed a re-run.",
    how: Probe::Remote {
        id: "workflow-runs",
    },
    level: Level::Silver,
    required: CADENCE_MID,
    remediation: Remediation::Manual {
        step: "fix-flaky-jobs",
        instructions: "Find the jobs that needed a re-run, then fix or quarantine the flaky tests and steps behind them.",
    },
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: rerun_rate,
};

pub const CANCELLATION_RATE: Rule = Rule {
    id: "ci-health.cancellation-rate",
    title: "Few cancellations",
    block: Block::CiHealth,
    checks: "At most 20 % of the completed CI runs (push, pull_request, merge_group) among the latest 100 workflow runs were cancelled.",
    how: Probe::Remote {
        id: "workflow-runs",
    },
    level: Level::Silver,
    required: ALL,
    remediation: Remediation::Manual {
        step: "reduce-cancellations",
        instructions: "Find the workflows whose runs are cancelled, then fix their timeouts or narrow their concurrency groups and triggers.",
    },
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: cancellation_rate,
};

/// Last in the block: the most expensive reads, so a budget it exhausts
/// leaves the cheaper rules evaluated.
pub const MINUTES_BUDGET: Rule = Rule {
    id: "ci-health.minutes-budget",
    title: "CI cycle within budget",
    block: Block::CiHealth,
    checks: "`ci.cycle_budget_minutes` is declared and the median cycle to the first of `ci.required_checks` over default-branch push runs is within it.",
    how: Probe::Remote {
        id: "workflow-runs+jobs+run-timing",
    },
    level: Level::Bronze,
    required: CADENCE_MID,
    remediation: Remediation::Manual {
        step: "meet-ci-cycle-budget",
        instructions: "Declare ci.required_checks and ci.cycle_budget_minutes in .agent-setup/project.json, then shard, cache or split jobs until the median cycle fits.",
    },
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: minutes_budget,
};

// --- shared readings --------------------------------------------------------------

/// The latest `limit` runs: all of them, or only the completed pushes to the
/// default branch. ci-baseline's remote rules (#783) read the same listing,
/// so one audit lists it once.
pub(crate) fn latest(cx: &Cx<'_>, pushes: bool, limit: u32) -> Result<Vec<WorkflowRun>, Outcome> {
    let filter = RunFilter {
        branch: pushes.then(|| cx.default_branch.to_owned()),
        event: pushes.then(|| "push".to_owned()),
        status: pushes.then(|| "completed".to_owned()),
        limit: Some(limit),
        ..RunFilter::default()
    };
    cx.host
        .workflow_runs(cx.repo, &filter)
        .map_err(|e| unread(&e))
}

/// The CI runs among the latest [`RECENT_RUNS`].
fn ci_runs(cx: &Cx<'_>) -> Result<Vec<WorkflowRun>, Outcome> {
    let mut runs = latest(cx, false, RECENT_RUNS)?;
    runs.retain(|r| CI_EVENTS.contains(&r.event.as_str()));
    Ok(runs)
}

/// `part of whole` as a percentage with one decimal, and whether it is within `max`.
fn rate(part: usize, whole: usize, max: f64) -> (String, bool) {
    let percent = part as f64 * 100.0 / whole as f64;
    let within = percent <= max;
    let sign = if within { "≤" } else { ">" };
    (format!("({percent:.1} %) {sign} {max} %"), within)
}

/// Superseded or skipped runs say nothing about the health of the CI.
pub(crate) fn conclusive(run: &WorkflowRun) -> bool {
    !matches!(run.conclusion.as_deref(), Some("cancelled" | "skipped"))
}

/// Passed when within the threshold, failed otherwise, with the same evidence.
fn judged(within: bool, evidence: [String; 1]) -> Outcome {
    if within {
        Outcome::passed(evidence)
    } else {
        Outcome::failed(evidence)
    }
}

fn seconds(time: &str) -> Option<i64> {
    DateTime::parse_from_rfc3339(time)
        .ok()
        .map(|t| t.timestamp())
}

// --- rules ------------------------------------------------------------------------

fn workflow_exists(cx: &Cx<'_>) -> Outcome {
    let read = workflows::read_all(cx.files);
    match read.as_slice() {
        [] => return Outcome::failed([format!("no workflow under {WORKFLOWS}")]),
        [(path, Err(reason))] if path == WORKFLOWS => return Outcome::unavailable(reason.clone()),
        _ => {}
    }
    let main = cx.default_branch;
    let runs = match latest(cx, true, RECENT_RUNS) {
        Ok(runs) => runs,
        Err(outcome) => return outcome,
    };
    let n = read.len();
    let workflows = if n == 1 { "workflow" } else { "workflows" };
    match runs.iter().take(LATEST_RUNS).find(|r| conclusive(r)) {
        None => Outcome::unavailable(format!(
            "no completed push run on {main} among the latest {LATEST_RUNS} that was neither cancelled nor skipped"
        )),
        Some(r) => {
            let run = format!(
                "{n} {workflows}; the latest conclusive push run on {main}, run {} of {}",
                r.id, r.name
            );
            match r.conclusion.as_deref() {
                Some("success") => Outcome::passed([format!("{run}, succeeded")]),
                other => Outcome::failed([format!(
                    "{run}, concluded {}",
                    other.unwrap_or("without a conclusion")
                )]),
            }
        }
    }
}

fn rerun_rate(cx: &Cx<'_>) -> Outcome {
    let runs = match ci_runs(cx) {
        Ok(runs) => runs,
        Err(outcome) => return outcome,
    };
    if runs.is_empty() {
        return Outcome::not_required(format!(
            "no CI run among the latest {RECENT_RUNS} workflow runs"
        ));
    }
    let rerun = runs
        .iter()
        .filter(|r| r.run_attempt.is_some_and(|a| a > 1))
        .count();
    let (rate, within) = rate(rerun, runs.len(), RERUN_MAX_PERCENT);
    let evidence = [format!("{rerun} of {} CI runs re-run {rate}", runs.len())];
    judged(within, evidence)
}

fn cancellation_rate(cx: &Cx<'_>) -> Outcome {
    let runs = match ci_runs(cx) {
        Ok(runs) => runs,
        Err(outcome) => return outcome,
    };
    let completed: Vec<&WorkflowRun> = runs.iter().filter(|r| r.status == "completed").collect();
    if completed.is_empty() {
        return Outcome::not_required(format!(
            "no completed CI run among the latest {RECENT_RUNS} workflow runs"
        ));
    }
    let cancelled = completed
        .iter()
        .filter(|r| r.conclusion.as_deref() == Some("cancelled"))
        .count();
    let (rate, within) = rate(cancelled, completed.len(), CANCELLED_MAX_PERCENT);
    let evidence = [format!(
        "{cancelled} of {} completed CI runs cancelled {rate}",
        completed.len()
    )];
    judged(within, evidence)
}

/// The declared budget and check, or the evidence naming what is missing.
fn declared(cx: &Cx<'_>) -> Result<Result<(f64, String), Vec<String>>, Outcome> {
    let project = match cx.files.read(PROFILE) {
        Ok(None) => Value::Null,
        Ok(Some(text)) => serde_json::from_str(&text)
            .map_err(|e| Outcome::unavailable(format!("{PROFILE} does not parse: {e}")))?,
        Err(e) => return Err(Outcome::unavailable(format!("{PROFILE} unreadable: {e}"))),
    };
    let ci = &project["ci"];
    let check = ci["required_checks"][0].as_str().filter(|c| !c.is_empty());
    let budget = ci["cycle_budget_minutes"]
        .as_f64()
        .filter(|b| b.is_finite() && *b > 0.0);
    match (check, budget) {
        (Some(check), Some(budget)) => Ok(Ok((budget, check.to_owned()))),
        _ => Ok(Err([
            check.is_none().then_some("ci.required_checks"),
            budget.is_none().then_some("ci.cycle_budget_minutes"),
        ]
        .into_iter()
        .flatten()
        .map(|field| format!("{field} undeclared in {PROFILE}"))
        .collect())),
    }
}

/// The median minutes from run creation to `check` completing, over the
/// latest first-attempt default-branch push runs of the workflows declaring it.
fn median_cycle(cx: &Cx<'_>, budget: f64, check: &str) -> Outcome {
    let mut names: Vec<String> = workflows::read_all(cx.files)
        .into_iter()
        .filter_map(|(path, parsed)| {
            let wf = parsed.ok()?;
            wf.jobs
                .iter()
                .any(|j| j.name.as_deref().unwrap_or(&j.id) == check)
                .then(|| wf.name.unwrap_or(path))
        })
        .collect();
    if names.is_empty() {
        return Outcome::unavailable(format!(
            "no workflow under {WORKFLOWS} declares a job named {check}"
        ));
    }
    names.sort();
    names.dedup();
    let main = cx.default_branch;
    let runs = match latest(cx, true, RECENT_RUNS) {
        Ok(runs) => runs,
        Err(outcome) => return outcome,
    };
    let candidates = runs
        .iter()
        .filter(|r| names.contains(&r.name) && r.run_attempt.unwrap_or(1) == 1 && conclusive(r));
    let mut minutes = Vec::new();
    let mut stopped = None;
    for (read, run) in candidates.take(CYCLE_RUNS).enumerate() {
        let jobs = match cx.host.jobs(cx.repo, run.id) {
            Ok(jobs) => jobs,
            Err(e) => match unread(&e) {
                outcome if budget_stopped(&outcome) && minutes.len() >= CYCLE_MIN_RUNS => {
                    stopped = Some(read);
                    break;
                }
                outcome => return outcome,
            },
        };
        let cycle = jobs
            .iter()
            .filter(|j| j.name == check && j.status == "completed")
            .filter(|j| !matches!(j.conclusion.as_deref(), Some("cancelled" | "skipped")))
            .find_map(|j| {
                let end = seconds(j.completed_at.as_deref()?)?;
                let start = seconds(run.created_at.as_deref()?)?;
                (end >= start).then(|| (end - start) as f64 / 60.0)
            });
        minutes.extend(cycle);
    }
    let workflows = names.join(", ");
    if minutes.is_empty() {
        return Outcome::unavailable(format!(
            "none of the latest {RECENT_RUNS} completed push runs on {main} is a first-attempt run of {workflows} whose job {check} completed"
        ));
    }
    minutes.sort_by(f64::total_cmp);
    let n = minutes.len();
    let median = if n % 2 == 1 {
        minutes[n / 2]
    } else {
        (minutes[n / 2 - 1] + minutes[n / 2]) / 2.0
    };
    let within = median <= budget;
    let sign = if within { "≤" } else { ">" };
    let sample = stopped.map_or_else(String::new, |read| {
        format!(" (a sample: the call budget stopped it at {read} of {CYCLE_RUNS} runs)")
    });
    let evidence = [format!(
        "median {median:.1} min from run creation to job {check} over {n} first-attempt push runs of {workflows} on {main}{sample} {sign} the cycle budget of {budget} min"
    )];
    judged(within, evidence)
}

/// CI minutes this month as a labelled sample, read from the listing of the
/// latest runs the rates already hold: each completed run created this month,
/// from its start (its creation when GitHub gives none) to its last update. No
/// call per run (#1318): `actions/runs/{id}/timing` of the same runs whose
/// jobs `ci.minutes-month` reads cost up to 10 calls a repository. Organisation
/// billing is not read.
fn minutes_sample(cx: &Cx<'_>) -> String {
    const LABEL: &str = "CI minutes this month (a sample, not billing)";
    let runs = match latest(cx, false, RECENT_RUNS) {
        Ok(runs) => runs,
        Err(outcome) => {
            let reason = outcome.reason.unwrap_or_default();
            return format!("{LABEL}: unavailable: {reason}");
        }
    };
    let month = format!("{:04}-{:02}", cx.now.year(), cx.now.month());
    let this_month: Vec<&WorkflowRun> = runs
        .iter()
        .filter(|r| r.status == "completed")
        .filter(|r| {
            r.created_at
                .as_deref()
                .is_some_and(|t| t.starts_with(&month))
        })
        .collect();
    if this_month.is_empty() {
        return format!("{LABEL}: no completed run this month among the latest {RECENT_RUNS}");
    }
    let durations: Vec<i64> = this_month
        .iter()
        .filter_map(|run| {
            let start = seconds(
                run.run_started_at
                    .as_deref()
                    .or(run.created_at.as_deref())?,
            )?;
            let end = seconds(run.updated_at.as_deref()?)?;
            (end >= start).then_some(end - start)
        })
        .collect();
    format!(
        "{LABEL}: {:.1} min, the wall-clock of {} of {} completed runs created this month among the latest {RECENT_RUNS} listed, from run start to last update",
        durations.iter().sum::<i64>() as f64 / 60.0,
        durations.len(),
        this_month.len()
    )
}

fn minutes_budget(cx: &Cx<'_>) -> Outcome {
    let mut verdict = match declared(cx) {
        Err(outcome) => return outcome,
        Ok(Err(missing)) => Outcome::failed(missing),
        Ok(Ok((budget, check))) => median_cycle(cx, budget, &check),
    };
    // An unavailable verdict has a reason, not evidence, to attach a sample to.
    if verdict.reason.is_none() {
        verdict.evidence.push(minutes_sample(cx));
    }
    verdict
}
