//! The two counters (SPEC-auditor.md, "Counters"; decision "Testing brakes
//! moved into the 7 November scope", point 6): `post_merge_corrections` and
//! `cost_per_change`, read under `--remote` after the rules from the listings
//! the measures and `ci-health.rerun-rate` already hold in the read cache. A
//! counter has no threshold, no level and no remediation: it never changes the
//! reached level or the exit code, and its value is a trend for the owner.
use super::{Cx, catalogue::ci_health::RECENT_RUNS, measures};
use crate::host::{
    HostError, HostErrorKind,
    types::{PullMeta, RunFilter, WorkflowRun},
};
use chrono::{DateTime, Days, NaiveDate, TimeDelta, Utc};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

/// Days a merged pull request has to be corrected.
pub const CORRECTION_DAYS: u64 = 30;
/// Judged pull requests read, newest first.
pub const CORRECTIONS_SAMPLE: usize = 10;
/// Judged pull requests the counter settles on.
pub const CORRECTIONS_MIN: usize = 3;
/// Calls held back for the counters while the measures and rules read
/// (SPEC-auditor.md, "Block allowances"): the files of [`CORRECTIONS_MIN`]
/// judged pull requests and three followers; `cost_per_change` costs none.
pub const ALLOWANCE: u32 = 6;
/// Authors whose pull requests are neither judged nor followers.
pub const BOTS: [&str; 2] = ["dependabot[bot]", "renovate[bot]"];

const NOT_REMOTE: &str = "not read without --remote";
const CEILING: &str = "a ceiling, not a level: a later pull request touching the same file is a correction or a planned second slice; read the trend";
const NOT_READ: &str = "wall-clock of the pull_request runs among the latest 100 (a floor of runner minutes when jobs run in parallel); not read: billable minutes (actions/runs/{id}/timing is closing down), the model's spend, human time, runs older than the latest 100";

/// One counter as reported: `value` is `None` when it is unavailable, and
/// `reason` then says why.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Counter {
    pub value: Option<f64>,
    pub unit: &'static str,
    pub evidence: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}
impl Counter {
    fn value(value: f64, unit: &'static str, evidence: Vec<String>) -> Self {
        Self {
            value: Some((value * 10.0).round() / 10.0),
            unit,
            evidence,
            reason: None,
        }
    }
    fn unavailable(unit: &'static str, reason: impl Into<String>, evidence: Vec<String>) -> Self {
        Self {
            value: None,
            unit,
            evidence,
            reason: Some(reason.into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Counters {
    pub post_merge_corrections: Counter,
    pub cost_per_change: Counter,
}
impl Counters {
    /// Both unavailable for `reason`.
    pub fn unread(reason: &str) -> Self {
        Self {
            post_merge_corrections: Counter::unavailable("percent", reason, Vec::new()),
            cost_per_change: Counter::unavailable("minutes", reason, Vec::new()),
        }
    }

    /// The `COUNTER` lines printed after the `AUDIT` line.
    pub fn lines(&self) -> Vec<String> {
        self.named()
            .map(|(name, counter, suffix)| match counter.value {
                Some(value) => format!(
                    "COUNTER {name}: {value:.1} {suffix} ({})",
                    counter.evidence.join("; ")
                ),
                None => format!(
                    "COUNTER {name}: unavailable: {}",
                    counter.reason.as_deref().unwrap_or_default()
                ),
            })
            .to_vec()
    }

    /// The two cells of the fleet table.
    pub fn cells(&self) -> [String; 2] {
        self.named().map(|(_, counter, _)| match counter.value {
            Some(value) => format!("{value:.1} {}", short(counter.unit)),
            None => "unavailable".to_owned(),
        })
    }

    /// The `counters` object of the JSON output.
    pub fn to_json(&self) -> Value {
        json!(self)
    }

    fn named(&self) -> [(&'static str, &Counter, &'static str); 2] {
        [
            ("post-merge-corrections", &self.post_merge_corrections, "%"),
            ("cost-per-change", &self.cost_per_change, "min median"),
        ]
    }
}

fn short(unit: &str) -> &'static str {
    if unit == "percent" { "%" } else { "min" }
}

/// Counts both over `cx`, whose host is the audit's read cache. Without
/// `remote` nothing is read. The allowance held back for them is released.
pub fn count(cx: &Cx<'_>, remote: bool) -> Counters {
    if !remote {
        return Counters::unread(NOT_REMOTE);
    }
    cx.budget.hold(0);
    let merged = match cx.host.pulls(cx.repo, &measures::pulls_filter(cx.now)) {
        Ok(pulls) => pulls,
        Err(e) => return Counters::unread(&unread(&e)),
    };
    let merged: Vec<Merged> = merged
        .into_iter()
        .filter(|p| p.base == cx.default_branch)
        .filter_map(|pull| {
            let at = pull.merged_at.as_deref()?.parse::<DateTime<Utc>>().ok()?;
            Some(Merged { pull, at })
        })
        .collect();
    // The cost first: it reads one cached listing, while the corrections
    // read files until the budget stops them.
    let cost_per_change = cost(cx, &merged);
    Counters {
        post_merge_corrections: corrections(cx, &merged),
        cost_per_change,
    }
}

struct Merged {
    pull: PullMeta,
    at: DateTime<Utc>,
}
impl Merged {
    fn day(&self) -> NaiveDate {
        self.at.date_naive()
    }
    fn bot(&self) -> bool {
        self.pull
            .author
            .as_deref()
            .is_some_and(|a| BOTS.contains(&a))
    }
}

/// `budget exhausted: …` when the call budget refused the read, otherwise its
/// own sentence.
fn unread(e: &HostError) -> String {
    if stopped(e) {
        format!("budget exhausted: {e}")
    } else {
        e.message.clone()
    }
}
fn stopped(e: &HostError) -> bool {
    matches!(e.kind, HostErrorKind::RateLimited { .. }) && e.message.starts_with("call budget")
}

/// A file list as names, both names of a rename; `None` when it was truncated.
type Names = Option<BTreeSet<String>>;

fn corrections(cx: &Cx<'_>, merged: &[Merged]) -> Counter {
    let unit = "percent";
    let to = cx.now - Days::new(CORRECTION_DAYS);
    let from = cx.now - Days::new(measures::LISTING_DAYS);
    let window = TimeDelta::days(CORRECTION_DAYS as i64);
    let people: Vec<&Merged> = merged.iter().filter(|m| !m.bot()).collect();
    let mut candidates: Vec<&Merged> = people
        .iter()
        .copied()
        .filter(|m| (from..=to).contains(&m.day()))
        .collect();
    candidates.sort_by_key(|m| std::cmp::Reverse(m.at));
    if candidates.is_empty() {
        return Counter::unavailable(
            unit,
            format!("no pull request merged {from}..{to} to judge"),
            Vec::new(),
        );
    }
    let mut files: BTreeMap<u64, Names> = BTreeMap::new();
    let mut budget: Option<String> = None;
    let read = |m: &Merged, files: &mut BTreeMap<u64, Names>| -> Result<(), String> {
        if files.contains_key(&m.pull.number) {
            return Ok(());
        }
        match cx.host.pull_files(cx.repo, m.pull.number) {
            Ok(list) => {
                let names = list
                    .into_iter()
                    .flat_map(|f| std::iter::once(f.filename).chain(f.previous_filename))
                    .collect();
                files.insert(m.pull.number, Some(names));
                Ok(())
            }
            Err(e) if e.kind == HostErrorKind::Truncated => {
                files.insert(m.pull.number, None);
                Ok(())
            }
            Err(e) => Err(unread(&e)),
        }
    };
    // The judged, newest first; then the followers in merge order.
    let sample: Vec<&Merged> = candidates
        .iter()
        .copied()
        .take(CORRECTIONS_SAMPLE)
        .collect();
    for judged in &sample {
        if let Err(reason) = read(judged, &mut files) {
            if reason.starts_with("budget exhausted") {
                budget = Some(reason);
                break;
            }
            return Counter::unavailable(unit, reason, Vec::new());
        }
    }
    let judged: Vec<&Merged> = sample
        .iter()
        .copied()
        .filter(|j| matches!(files.get(&j.pull.number), Some(Some(_))))
        .collect();
    let inside = |j: &Merged, f: &Merged| j.at < f.at && f.at <= j.at + window;
    let mut followers: Vec<&Merged> = people
        .iter()
        .copied()
        .filter(|f| judged.iter().any(|j| inside(j, f)))
        .collect();
    followers.sort_by_key(|f| f.at);
    // The first follower that touched one of a judged pull request's files.
    let hit = |j: &Merged, files: &BTreeMap<u64, Names>| -> Option<(u64, String)> {
        let own = files.get(&j.pull.number)?.as_ref()?;
        followers.iter().filter(|f| inside(j, f)).find_map(|f| {
            let theirs = files.get(&f.pull.number)?.as_ref()?;
            own.intersection(theirs)
                .next()
                .map(|name| (f.pull.number, name.clone()))
        })
    };
    let decided = |j: &Merged, files: &BTreeMap<u64, Names>| {
        hit(j, files).is_some()
            || followers
                .iter()
                .filter(|f| inside(j, f))
                .all(|f| matches!(files.get(&f.pull.number), Some(Some(_))))
    };
    if budget.is_none() {
        for follower in &followers {
            let open = judged
                .iter()
                .any(|j| inside(j, follower) && !decided(j, &files));
            if !open {
                continue;
            }
            if let Err(reason) = read(follower, &mut files) {
                if reason.starts_with("budget exhausted") {
                    budget = Some(reason);
                    break;
                }
                return Counter::unavailable(unit, reason, Vec::new());
            }
        }
    }
    let settled: Vec<&Merged> = judged
        .iter()
        .copied()
        .filter(|j| decided(j, &files))
        .collect();
    let mut corrected: Vec<(u64, u64, String)> = settled
        .iter()
        .filter_map(|j| hit(j, &files).map(|(by, name)| (j.pull.number, by, name)))
        .collect();
    corrected.sort();
    let read_followers = followers
        .iter()
        .filter(|f| matches!(files.get(&f.pull.number), Some(Some(_))))
        .count();
    let mut sample_line = format!(
        "judged {} of {} merged {from}..{to}; files read for {read_followers} of {} followers",
        settled.len(),
        candidates.len(),
        followers.len(),
    );
    let unjudged: Vec<String> = sample
        .iter()
        .filter(|j| matches!(files.get(&j.pull.number), Some(None)))
        .map(|j| format!("#{} ({} or more files)", j.pull.number, 100))
        .collect();
    if !unjudged.is_empty() {
        sample_line.push_str(&format!("; unjudged: {}", unjudged.join(", ")));
    }
    if settled.len() < CORRECTIONS_MIN {
        let reason = match &budget {
            Some(stop) => format!(
                "budget exhausted: {sample_line} ({})",
                stop.trim_start_matches("budget exhausted: ")
            ),
            None => format!("fewer than {CORRECTIONS_MIN} judged: {sample_line}"),
        };
        return Counter::unavailable(unit, reason, vec![sample_line]);
    }
    let listed = if corrected.is_empty() {
        "none".to_owned()
    } else {
        corrected
            .iter()
            .map(|(judged, by, name)| format!("#{judged} by #{by} ({name})"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut evidence = vec![sample_line, format!("corrected: {listed}")];
    if let Some(stop) = &budget {
        evidence.push(format!(
            "the call budget stopped the file reads: {}",
            stop.trim_start_matches("budget exhausted: ")
        ));
    }
    evidence.push(CEILING.to_owned());
    let percent = corrected.len() as f64 * 100.0 / settled.len() as f64;
    Counter::value(percent, unit, evidence)
}

fn cost(cx: &Cx<'_>, merged: &[Merged]) -> Counter {
    let unit = "minutes";
    let from = cx.now - Days::new(measures::WINDOW_DAYS);
    let in_window: Vec<&Merged> = merged
        .iter()
        .filter(|m| (from..=cx.now).contains(&m.day()))
        .collect();
    let days = format!("{from}..{}", cx.now);
    if in_window.is_empty() {
        return Counter::unavailable(unit, format!("no pull request merged {days}"), Vec::new());
    }
    // The listing `ci-health.rerun-rate` reads, so the cache answers it.
    let filter = RunFilter {
        limit: Some(RECENT_RUNS),
        ..RunFilter::default()
    };
    let runs = match cx.host.workflow_runs(cx.repo, &filter) {
        Ok(runs) => runs,
        Err(e) => return Counter::unavailable(unit, unread(&e), Vec::new()),
    };
    let (mut minutes, mut counted, mut attempts) = (Vec::new(), 0, 0);
    for m in &in_window {
        let own: Vec<(&WorkflowRun, f64)> = runs
            .iter()
            .filter(|r| r.event == "pull_request" && runs_for(r, &m.pull))
            .filter_map(|r| wall_clock(r).map(|t| (r, t)))
            .collect();
        if own.is_empty() {
            continue;
        }
        counted += own.len();
        attempts += own
            .iter()
            .map(|(r, _)| r.run_attempt.unwrap_or(1).saturating_sub(1))
            .sum::<u32>();
        minutes.push(own.iter().map(|(_, t)| t).sum::<f64>());
    }
    let measured = format!(
        "measured {} of {} merged {days}",
        minutes.len(),
        in_window.len()
    );
    if minutes.is_empty() {
        return Counter::unavailable(
            unit,
            format!(
                "{measured}: none has a pull_request run among the latest {RECENT_RUNS} workflow runs"
            ),
            Vec::new(),
        );
    }
    minutes.sort_by(f64::total_cmp);
    let median = median(&minutes);
    let p90 = minutes[(minutes.len() * 9).div_ceil(10) - 1];
    Counter::value(
        median,
        unit,
        vec![
            format!(
                "{measured}; runs {counted}, attempts {attempts}; median {median:.1} min, p90 {p90:.1} min"
            ),
            NOT_READ.to_owned(),
        ],
    )
}

/// Whether `run` ran for `pull`: its `pull_requests` names it, or, since
/// GitHub empties that list once a merged pull request's branch is deleted,
/// its head sha is the pull request's head sha (runs of earlier heads are
/// then missed, so the figure is a floor).
fn runs_for(run: &WorkflowRun, pull: &PullMeta) -> bool {
    run.pull_requests.contains(&pull.number) || run.head_sha == pull.head_sha
}

/// `updated_at − run_started_at` in minutes, `created_at` when the start is
/// absent; `None` when the times are missing or out of order.
fn wall_clock(run: &WorkflowRun) -> Option<f64> {
    let time = |t: &Option<String>| t.as_deref()?.parse::<DateTime<Utc>>().ok();
    let start = time(&run.run_started_at).or_else(|| time(&run.created_at))?;
    let seconds = (time(&run.updated_at)? - start).num_seconds();
    (seconds >= 0).then(|| seconds as f64 / 60.0)
}

/// The median of sorted `values`, which are not empty.
fn median(values: &[f64]) -> f64 {
    let n = values.len();
    if n % 2 == 1 {
        values[n / 2]
    } else {
        (values[n / 2 - 1] + values[n / 2]) / 2.0
    }
}
