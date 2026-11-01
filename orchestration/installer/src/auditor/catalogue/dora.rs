//! DORA rules (SPEC-auditor.md, "DORA reads and the budget", #726): the
//! Deployments API in use for `production`, deployment frequency, lead time,
//! change failure rate and time to restore, from GitHub APIs only. Every read
//! goes through the host adapter and is bounded: one listing of the newest
//! production deployments, then the statuses and pull requests of a labelled
//! sample of them, so the block fits what CI health and posture leave of the
//! 60 calls of a repository.
use super::posture::{budget_stopped, unread};
use crate::{
    auditor::{
        Cx,
        rules::{Block, Level, Milestone, Outcome, Probe, Profile, Remediation, Required, Rule},
    },
    host::types::{Deployment, IssueFilter},
};
use chrono::{DateTime, Days, NaiveDate, Utc};

const ALL: Required = Required {
    profiles: &[Profile::P1, Profile::P2, Profile::P3],
    when: &[],
};
const DELIVERY: Remediation = Remediation::Module { id: "delivery" };

/// The environment whose deployments are measured.
pub const PRODUCTION: &str = "production";
/// The window every DORA measure is read over, in days, `--now` included: a
/// deployment exactly this many days old is in, one day older is out.
pub const WINDOW_DAYS: i64 = 28;
/// Successful production deployments the window needs: one per week.
pub const FREQUENCY_MIN: usize = (WINDOW_DAYS / 7) as usize;
/// Final statuses `deployment-frequency` and `change-failure-rate` read, one
/// call each, from the newest deployment in the window.
pub const STATUS_SAMPLE: usize = 8;
/// Deployments `lead-time` reads, newest first: a status and, when it
/// succeeded, its pull requests (two calls each).
pub const LEAD_SAMPLE: usize = 3;
/// A median lead time above this many days fails.
pub const LEAD_MAX_DAYS: f64 = 7.0;
/// More failed or rolled-back deployments than this percentage fails.
pub const FAILURE_MAX_PERCENT: f64 = 15.0;
/// A deployment of a sha that succeeded within this many hours before it is a
/// rollback.
pub const ROLLBACK_HOURS: i64 = 24;
/// A median time to restore above this many hours fails.
pub const RESTORE_MAX_HOURS: f64 = 24.0;
/// The label an incident issue carries. The convention is finalised by the
/// `incidents` module; revisit this constant when it lands.
pub const INCIDENT_LABEL: &str = "incident";

pub const DEPLOYMENTS_API_IN_USE: Rule = Rule {
    id: "dora.deployments-api-in-use",
    title: "Deployments API in use",
    block: Block::Dora,
    checks: "Production deployments are recorded through the GitHub Deployments API.",
    how: Probe::Remote { id: "deployments" },
    level: Level::Silver,
    required: ALL,
    remediation: DELIVERY,
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: deployments_api_in_use,
};

pub const TIME_TO_RESTORE: Rule = Rule {
    id: "dora.time-to-restore",
    title: "Service restored within a day",
    block: Block::Dora,
    checks: "The median time from opening to closing the issues labelled `incident` closed in the last 28 days is at most 24 hours.",
    how: Probe::Remote { id: "issues" },
    level: Level::Gold,
    required: ALL,
    remediation: Remediation::Manual {
        step: "restore-within-a-day",
        instructions: "Label each incident issue `incident` and close it once service is restored; give the slowest ones a runbook or a rollback path.",
    },
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: time_to_restore,
};

pub const DEPLOYMENT_FREQUENCY: Rule = Rule {
    id: "dora.deployment-frequency",
    title: "Deploys at least weekly",
    block: Block::Dora,
    checks: "At least 4 production deployments (one per week) in the last 28 days succeeded.",
    how: Probe::Remote {
        id: "deployments+deployment-statuses",
    },
    level: Level::Silver,
    required: ALL,
    remediation: DELIVERY,
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: deployment_frequency,
};

pub const LEAD_TIME: Rule = Rule {
    id: "dora.lead-time",
    title: "Short lead time",
    block: Block::Dora,
    checks: "The median time from merging a pull request to its successful production deployment, over the newest deployments of the last 28 days, is at most 7 days.",
    how: Probe::Remote {
        id: "deployments+deployment-statuses+commit-pulls",
    },
    level: Level::Silver,
    required: ALL,
    remediation: Remediation::Manual {
        step: "shorten-lead-time",
        instructions: "Merge smaller pull requests and deploy each merge to production through the Deployments API soon after it lands.",
    },
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: lead_time,
};

/// Last in the block: the most status reads, so a budget it exhausts leaves
/// the cheaper rules evaluated.
pub const CHANGE_FAILURE_RATE: Rule = Rule {
    id: "dora.change-failure-rate",
    title: "Few failed changes",
    block: Block::Dora,
    checks: "At most 15 % of the newest production deployments of the last 28 days failed or were rollbacks.",
    how: Probe::Remote {
        id: "deployments+deployment-statuses",
    },
    level: Level::Silver,
    required: ALL,
    remediation: Remediation::Manual {
        step: "reduce-change-failures",
        instructions: "Find the failed and rolled-back deployments, then add the check or the post-deploy smoke test that would have stopped each.",
    },
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: change_failure_rate,
};

// --- shared readings --------------------------------------------------------------

fn instant(time: Option<&str>) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(time?)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

fn hours(from: DateTime<Utc>, to: DateTime<Utc>) -> f64 {
    (to - from).num_seconds() as f64 / 3600.0
}

/// Whether `date` is within the window ending at `now`, both ends included.
fn in_window(now: NaiveDate, date: NaiveDate) -> bool {
    (0..=WINDOW_DAYS).contains(&(now - date).num_days())
}

/// The middle value, or the mean of the two middle values of an even count.
fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(f64::total_cmp);
    let n = values.len();
    if n % 2 == 1 {
        values[n / 2]
    } else {
        (values[n / 2 - 1] + values[n / 2]) / 2.0
    }
}

/// The newest production deployments, one call.
fn listed(cx: &Cx<'_>) -> Result<Vec<Deployment>, Outcome> {
    cx.host
        .latest_deployments(cx.repo, PRODUCTION)
        .map_err(|e| unread(&e))
}

/// The listed deployments created in the window, newest first, each with its
/// creation instant; `unavailable` when none was listed or a date is unreadable.
fn window(cx: &Cx<'_>) -> Result<Vec<(Deployment, DateTime<Utc>)>, Outcome> {
    let listed = listed(cx)?;
    if listed.is_empty() {
        return Err(Outcome::unavailable("no deployments recorded"));
    }
    let mut window = Vec::new();
    for d in listed {
        let Some(created) = instant(d.created_at.as_deref()) else {
            return Err(Outcome::unavailable(format!(
                "deployment {} has no readable created_at",
                d.id
            )));
        };
        if in_window(cx.now, created.date_naive()) {
            window.push((d, created));
        }
    }
    Ok(window)
}

/// `the 28 days to <now>`, as every evidence line names the window.
fn days(cx: &Cx<'_>) -> String {
    format!("the {WINDOW_DAYS} days to {}", cx.now)
}

/// The final status of a deployment (GitHub lists them newest first) and when
/// it was set; `None` when it has none yet.
fn final_status(cx: &Cx<'_>, id: u64) -> Result<Option<(String, Option<String>)>, Outcome> {
    let statuses = cx
        .host
        .deployment_statuses(cx.repo, id)
        .map_err(|e| unread(&e))?;
    Ok(statuses.into_iter().next().map(|s| (s.state, s.created_at)))
}

fn judged(within: bool, evidence: Vec<String>) -> Outcome {
    if within {
        Outcome::passed(evidence)
    } else {
        Outcome::failed(evidence)
    }
}

// --- rules ------------------------------------------------------------------------

fn deployments_api_in_use(cx: &Cx<'_>) -> Outcome {
    match listed(cx) {
        Err(outcome) => outcome,
        Ok(listed) => match listed.first() {
            None => Outcome::failed([format!(
                "no {PRODUCTION} deployment recorded through the Deployments API"
            )]),
            Some(newest) => Outcome::passed([format!(
                "{PRODUCTION} deployments recorded; the newest, {}, created {}",
                newest.id,
                newest.created_at.as_deref().unwrap_or("at an unknown time")
            )]),
        },
    }
}

/// Reads final statuses newest first and stops once the verdict is decided:
/// passed at [`FREQUENCY_MIN`] successes, failed once the successes plus the
/// deployments not yet read cannot reach it, `unavailable` when
/// [`STATUS_SAMPLE`] reads leave it undecided.
fn deployment_frequency(cx: &Cx<'_>) -> Outcome {
    let window = match window(cx) {
        Ok(window) => window,
        Err(outcome) => return outcome,
    };
    let n = window.len();
    let needs = format!("needs {FREQUENCY_MIN} successful, 1 per week");
    if n == 0 {
        return Outcome::failed([format!(
            "0 {PRODUCTION} deployments in {} ({needs})",
            days(cx)
        )]);
    }
    let mut succeeded = 0;
    for (read, (d, _)) in window.iter().enumerate() {
        if succeeded + (n - read) < FREQUENCY_MIN {
            return Outcome::failed([format!(
                "at most {} of {n} {PRODUCTION} deployments in {} succeeded, {read} final statuses read ({needs})",
                succeeded + (n - read),
                days(cx)
            )]);
        }
        if read == STATUS_SAMPLE {
            return Outcome::unavailable(format!(
                "{succeeded} of the newest {STATUS_SAMPLE} of {n} {PRODUCTION} deployments in {} succeeded, undecided at the cap of {STATUS_SAMPLE} status reads ({needs})",
                days(cx)
            ));
        }
        match final_status(cx, d.id) {
            Err(outcome) if budget_stopped(&outcome) && read >= FREQUENCY_MIN => {
                return Outcome::unavailable(format!(
                    "{succeeded} of the newest {read} of {n} {PRODUCTION} deployments in {} succeeded, undecided: the call budget stopped the status reads at {read} ({needs})",
                    days(cx)
                ));
            }
            Err(outcome) => return outcome,
            Ok(status) => {
                if status.is_some_and(|(state, _)| state == "success") {
                    succeeded += 1;
                }
            }
        }
        if succeeded == FREQUENCY_MIN {
            return Outcome::passed([format!(
                "at least {FREQUENCY_MIN} of {n} {PRODUCTION} deployments in {} succeeded: {succeeded} of the newest {} ({needs})",
                days(cx),
                read + 1
            )]);
        }
    }
    Outcome::failed([format!(
        "{succeeded} of {n} {PRODUCTION} deployments in {} succeeded ({needs})",
        days(cx)
    )])
}

/// Over the newest [`LEAD_SAMPLE`] deployments of the window: for each that
/// succeeded, the time from the earliest merge of a pull request containing
/// its sha to its success status.
fn lead_time(cx: &Cx<'_>) -> Outcome {
    let window = match window(cx) {
        Ok(window) => window,
        Err(outcome) => return outcome,
    };
    let n = window.len();
    if n == 0 {
        return Outcome::unavailable(format!("no {PRODUCTION} deployment in {}", days(cx)));
    }
    let sample = n.min(LEAD_SAMPLE);
    let mut lead = Vec::new();
    let mut stopped = None;
    for (read, (d, _)) in window.iter().take(LEAD_SAMPLE).enumerate() {
        let succeeded = match final_status(cx, d.id) {
            Err(outcome) if budget_stopped(&outcome) && !lead.is_empty() => {
                stopped = Some(read);
                break;
            }
            Err(outcome) => return outcome,
            Ok(Some((state, at))) if state == "success" => instant(at.as_deref()),
            Ok(_) => None,
        };
        let Some(succeeded) = succeeded else { continue };
        let pulls = match cx.host.pulls_for_commit(cx.repo, &d.sha) {
            Ok(pulls) => pulls,
            Err(e) => match unread(&e) {
                outcome if budget_stopped(&outcome) && !lead.is_empty() => {
                    stopped = Some(read);
                    break;
                }
                outcome => return outcome,
            },
        };
        let merged = pulls
            .iter()
            .filter_map(|p| instant(p.merged_at.as_deref()))
            .min();
        if let Some(merged) = merged.filter(|m| *m <= succeeded) {
            lead.push(hours(merged, succeeded));
        }
    }
    let of = format!(
        "the newest {sample} of {n} {PRODUCTION} deployments in {}",
        days(cx)
    );
    if lead.is_empty() {
        return Outcome::unavailable(format!(
            "none of {of} succeeded with a merged pull request containing its sha"
        ));
    }
    let k = lead.len();
    let cut = stopped.map_or_else(String::new, |read| {
        format!(": the call budget stopped it at {read} of {sample} deployments")
    });
    let median = median(lead);
    let within = median <= LEAD_MAX_DAYS * 24.0;
    let sign = if within { "≤" } else { ">" };
    judged(
        within,
        vec![format!(
            "median {median:.1} h from merge to successful deployment over {k} of {of} (a sample{cut}) {sign} {LEAD_MAX_DAYS} days"
        )],
    )
}

/// Over the newest [`STATUS_SAMPLE`] deployments of the window: those whose
/// final status is `failure` or `error`, and rollbacks, deployments of a sha
/// that a sampled deployment deployed successfully within [`ROLLBACK_HOURS`]
/// before. A redeploy after a failure is not a rollback: the failure counted.
fn change_failure_rate(cx: &Cx<'_>) -> Outcome {
    let window = match window(cx) {
        Ok(window) => window,
        Err(outcome) => return outcome,
    };
    let n = window.len();
    if n == 0 {
        return Outcome::unavailable(format!("no {PRODUCTION} deployment in {}", days(cx)));
    }
    let mut sample = &window[..n.min(STATUS_SAMPLE)];
    let mut states = Vec::new();
    let mut cut = String::new();
    for (d, _) in sample {
        match final_status(cx, d.id) {
            Err(outcome) if budget_stopped(&outcome) && states.len() >= FREQUENCY_MIN => {
                cut = format!(
                    " (a sample: the call budget stopped it at {} of {STATUS_SAMPLE})",
                    states.len()
                );
                break;
            }
            Err(outcome) => return outcome,
            Ok(status) => states.push(status.map(|(state, _)| state)),
        }
    }
    sample = &sample[..states.len()];
    let mut failures = Vec::new();
    for (i, (d, created)) in sample.iter().enumerate() {
        if let Some(state @ ("failure" | "error")) = states[i].as_deref() {
            failures.push(format!("{} {state}", d.id));
            continue;
        }
        // Older deployments come later in the newest-first sample.
        let rolled_back_to = sample.iter().enumerate().skip(i + 1).find(|(j, (e, at))| {
            e.sha == d.sha
                && states[*j].as_deref() == Some("success")
                && at <= created
                && *created - *at <= chrono::Duration::hours(ROLLBACK_HOURS)
        });
        if let Some((_, (earlier, _))) = rolled_back_to {
            failures.push(format!("{} rollback to {}", d.id, earlier.id));
        }
    }
    let k = sample.len();
    let percent = failures.len() as f64 * 100.0 / k as f64;
    let within = percent <= FAILURE_MAX_PERCENT;
    let sign = if within { "≤" } else { ">" };
    let mut evidence = vec![format!(
        "{} of the newest {k} of {n} {PRODUCTION} deployments in {} failed or rolled back ({percent:.1} %) {sign} {FAILURE_MAX_PERCENT} %{cut}",
        failures.len(),
        days(cx)
    )];
    if !failures.is_empty() {
        evidence.push(format!("failed: {}", failures.join(", ")));
    }
    judged(within, evidence)
}

/// The median hours from opening to closing the incident issues closed in
/// the window (one call, at most 100 issues).
fn time_to_restore(cx: &Cx<'_>) -> Outcome {
    let start = cx
        .now
        .checked_sub_days(Days::new(WINDOW_DAYS as u64))
        .unwrap_or(cx.now);
    let filter = IssueFilter {
        state: Some("closed".to_owned()),
        labels: vec![INCIDENT_LABEL.to_owned()],
        since: Some(format!("{start}T00:00:00Z")),
        limit: Some(100),
    };
    let issues = match cx.host.issues(cx.repo, &filter) {
        Ok(issues) => issues,
        Err(e) => return unread(&e),
    };
    let mut restore = Vec::new();
    for issue in &issues {
        let (Some(opened), Some(closed)) = (
            instant(issue.created_at.as_deref()),
            instant(issue.closed_at.as_deref()),
        ) else {
            return Outcome::unavailable(format!(
                "issue #{} labelled {INCIDENT_LABEL} has no readable created_at or closed_at",
                issue.number
            ));
        };
        if in_window(cx.now, closed.date_naive()) && opened <= closed {
            restore.push(hours(opened, closed));
        }
    }
    if restore.is_empty() {
        return Outcome::not_required(format!(
            "no issue labelled {INCIDENT_LABEL} closed in {}",
            days(cx)
        ));
    }
    let k = restore.len();
    let median = median(restore);
    let within = median <= RESTORE_MAX_HOURS;
    let sign = if within { "≤" } else { ">" };
    judged(
        within,
        vec![format!(
            "median {median:.1} h from opening to closing over {k} issues labelled {INCIDENT_LABEL} closed in {} {sign} {RESTORE_MAX_HOURS} h",
            days(cx)
        )],
    )
}
