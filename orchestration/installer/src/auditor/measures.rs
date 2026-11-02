//! The four measures and the profile they derive (SPEC-auditor.md, "Profiles
//! and measures"; decision "Full-lifecycle installer", point 3). Every measure
//! carries its value, tier and evidence so a wrong derivation is visible and
//! correctable by declaration. Host-backed measures without `--remote`, or
//! whose read failed, are `unavailable`; the profile is then P1 `unverified`
//! and the required level is still stated.
use super::{
    Audit, Cx, Dimensions,
    rules::{Cadence, Criticality, Level, Profile, Services},
    workflows,
};
use crate::{
    PROFILE, Result,
    host::types::PullFilter,
    profile::{AcceptedLevel, AuditFields, audit_fields},
};
use chrono::{Days, NaiveDate};
use serde::Serialize;
use serde_json::{Value, json};

/// The window merge cadence is measured over, in days (decision point 3).
pub const WINDOW_DAYS: u64 = 28;

/// Days the merged pull request listing reaches back: the cadence window plus
/// the 30 days `post_merge_corrections` gives a pull request to be corrected
/// (SPEC-auditor.md, "Counters"). The cadence filters its window in memory.
pub const LISTING_DAYS: u64 = WINDOW_DAYS + super::counters::CORRECTION_DAYS;

/// The one pull request listing the cadence measure and the counters share
/// through the read cache: closed pull requests updated in the last
/// [`LISTING_DAYS`] days.
pub fn pulls_filter(now: NaiveDate) -> PullFilter {
    PullFilter {
        state: Some("closed".to_owned()),
        base: None,
        since: Some(format!("{}T00:00:00Z", now - Days::new(LISTING_DAYS))),
        limit: None,
    }
}

/// Permissions that can merge: GitHub reports `write` for `push`.
const MERGE_PERMISSIONS: &[&str] = &["admin", "maintain", "write", "push"];

/// One measure as reported: an unavailable one has a null value, the tier
/// `unavailable` and the reason as evidence.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Measure {
    pub value: Value,
    pub tier: String,
    pub evidence: Vec<String>,
}
impl Measure {
    fn new(value: impl Into<Value>, tier: impl Into<String>, evidence: Vec<String>) -> Self {
        Self {
            value: value.into(),
            tier: tier.into(),
            evidence,
        }
    }
    fn unavailable(reason: impl Into<String>) -> Self {
        Self::new(Value::Null, "unavailable", vec![reason.into()])
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Measures {
    pub humans: Measure,
    pub cadence: Measure,
    pub services: Measure,
    pub criticality: Measure,
}

/// What the measures derive for one repository.
#[derive(Debug, Clone, PartialEq)]
pub struct Measured {
    pub profile: Profile,
    /// The humans measure was unavailable, so the profile defaulted to P1.
    pub unverified: bool,
    pub measures: Measures,
    /// What [`super::audit`] decides `required` from.
    pub dimensions: Dimensions,
    /// The level the standard requires for this profile and criticality.
    pub required: Level,
    /// An unexpired `audit.accepted_level`.
    pub accepted: Option<AcceptedLevel>,
    /// Findings about the declarations themselves, such as an expired acceptance.
    pub findings: Vec<String>,
}
impl Measured {
    /// [`Audit::exit_code`] against the required level. An unexpired
    /// `audit.accepted_level` lowers the level gap (codes 3 and 4) to 0 and
    /// nothing else (decision "Auditor standard v1", point 2): it covers the
    /// level, not readiness, so `NOT READY` stays 1, and the printed required
    /// level and gap do not change.
    pub fn exit_code(&self, audit: &Audit, ready: bool) -> i32 {
        match audit.exit_code(ready, self.required) {
            3 | 4 if self.accepted.is_some() => 0,
            code => code,
        }
    }

    /// The `profile` object of the JSON output.
    pub fn to_json(&self) -> Value {
        let m = &self.measures;
        json!({
            "id": format!("{:?}", self.profile),
            "unverified": self.unverified,
            "measures": {
                "humans_with_merge": m.humans,
                "merge_cadence_per_week": m.cadence,
                "deployable_services": m.services,
                "criticality": m.criticality,
            },
        })
    }
}

/// 1 → P1, 2–5 → P2, > 5 → P3 (none counts as one person).
pub fn humans_tier(humans: usize) -> Profile {
    match humans {
        0 | 1 => Profile::P1,
        2..=5 => Profile::P2,
        _ => Profile::P3,
    }
}

/// < 10 low, 10–40 mid, > 40 high merged PRs per week.
pub fn cadence_tier(per_week: f64) -> Cadence {
    if per_week < 10.0 {
        Cadence::Low
    } else if per_week <= 40.0 {
        Cadence::Mid
    } else {
        Cadence::High
    }
}

/// 1 single, 2–5 few, > 5 many (none counts as single).
pub fn services_tier(services: usize) -> Services {
    match services {
        0 | 1 => Services::Single,
        2..=5 => Services::Few,
        _ => Services::Many,
    }
}

/// P1 Bronze, P2 Silver, P3 Gold; `customers` at least Silver;
/// `personal-data-or-payments` one level up, capped at Gold. Undeclared is
/// audited as internal.
pub fn required_level(profile: Profile, criticality: Option<Criticality>) -> Level {
    let base = match profile {
        Profile::P1 => Level::Bronze,
        Profile::P2 => Level::Silver,
        Profile::P3 => Level::Gold,
    };
    match criticality.unwrap_or(Criticality::Internal) {
        Criticality::Internal => base,
        Criticality::Customers => base.max(Level::Silver),
        Criticality::PersonalDataOrPayments => base.raised(),
    }
}

/// Measures the repository of `cx`. Host reads happen only when `remote`; the
/// profile's fields are read through `cx.files` and refused when malformed.
pub fn measure(cx: &Cx<'_>, remote: bool) -> Result<Measured> {
    let fields = match cx.files.read(PROFILE)? {
        Some(text) => audit_fields(&serde_json::from_str(&text)?)?,
        None => AuditFields::default(),
    };
    let ((humans, count), (cadence, per_week), (services, deployable)) = if remote {
        (
            humans(cx, &fields.agent_accounts),
            cadence(cx),
            services(cx),
        )
    } else {
        let none = || Measure::unavailable("unavailable without --remote");
        ((none(), None), (none(), None), (none(), None))
    };
    let profile = count.map_or(Profile::P1, humans_tier);
    let criticality = fields.criticality;
    let mut findings = Vec::new();
    let accepted = fields.accepted_level.filter(|a| {
        let live = cx.now <= a.expires;
        if !live {
            findings.push(format!("audit.accepted_level expired on {}", a.expires));
        }
        live
    });
    Ok(Measured {
        profile,
        unverified: count.is_none(),
        measures: Measures {
            humans,
            cadence,
            services,
            criticality: criticality_measure(criticality),
        },
        dimensions: Dimensions {
            profile,
            cadence: per_week.map(cadence_tier),
            services: deployable.map(services_tier),
            criticality,
            humans: count,
        },
        required: required_level(profile, criticality),
        accepted,
        findings,
    })
}

fn humans(cx: &Cx<'_>, agents: &[String]) -> (Measure, Option<usize>) {
    let collaborators = match cx.host.collaborators(cx.repo) {
        Ok(c) => c,
        Err(e) => return (Measure::unavailable(e.message), None),
    };
    let mut sorted = collaborators;
    sorted.sort_by(|a, b| a.login.cmp(&b.login));
    let (mut counted, mut agents_excluded, mut non_users) = (Vec::new(), Vec::new(), Vec::new());
    for c in sorted
        .iter()
        .filter(|c| MERGE_PERMISSIONS.contains(&c.permission.as_str()))
    {
        let kind = c.kind.as_deref().unwrap_or("unknown");
        if kind != "User" {
            non_users.push(format!("excluded non-user account: {} ({kind})", c.login));
        } else if agents.iter().any(|a| a.eq_ignore_ascii_case(&c.login)) {
            agents_excluded.push(format!("excluded agent account: {}", c.login));
        } else {
            counted.push(format!("{} ({})", c.login, c.permission));
        }
    }
    let n = counted.len();
    let listed = if counted.is_empty() {
        "none with merge rights".to_owned()
    } else {
        counted.join(", ")
    };
    let mut evidence = vec![format!("collaborators: {listed}")];
    evidence.extend(agents_excluded);
    evidence.extend(non_users);
    let tier = format!("{:?}", humans_tier(n));
    (Measure::new(n, tier, evidence), Some(n))
}

fn cadence(cx: &Cx<'_>) -> (Measure, Option<f64>) {
    let start = cx.now - Days::new(WINDOW_DAYS);
    let pulls = match cx.host.pulls(cx.repo, &pulls_filter(cx.now)) {
        Ok(p) => p,
        Err(e) => return (Measure::unavailable(e.message), None),
    };
    let in_window = |merged_at: &str| {
        merged_at
            .get(..10)
            .and_then(|d| NaiveDate::parse_from_str(d, "%Y-%m-%d").ok())
            .is_some_and(|d| start <= d && d <= cx.now)
    };
    let merged = pulls
        .iter()
        .filter(|p| p.merged_at.as_deref().is_some_and(in_window))
        .count();
    let per_week = merged as f64 / (WINDOW_DAYS / 7) as f64;
    let tier = match cadence_tier(per_week) {
        Cadence::Low => "low",
        Cadence::Mid => "mid",
        Cadence::High => "high",
    };
    let evidence = vec![format!("{merged} merged PRs {start}..{}", cx.now)];
    (Measure::new(per_week, tier, evidence), Some(per_week))
}

/// The max of deploy workflows (a job with an `environment:` key), Dockerfiles
/// and the host's environments. Workflows are read with the walker of
/// [`workflows`]; one it cannot read leaves the measure unavailable.
fn services(cx: &Cx<'_>) -> (Measure, Option<usize>) {
    let mut evidence = Vec::new();
    let workflows = match deploy_workflows(cx) {
        Ok(w) => w,
        Err(reason) => return (Measure::unavailable(reason), None),
    };
    if !workflows.is_empty() {
        evidence.push(format!(
            "workflows with environment: {}",
            workflows.join(", ")
        ));
    }
    let dockerfiles = match cx.files.read("Dockerfile") {
        Ok(found) => usize::from(found.is_some()),
        Err(e) => {
            return (
                Measure::unavailable(format!("Dockerfile unreadable: {e}")),
                None,
            );
        }
    };
    if dockerfiles > 0 {
        evidence.push("Dockerfile".to_owned());
    }
    let environments = match cx.host.environments(cx.repo) {
        Ok(e) => e,
        Err(e) => return (Measure::unavailable(e.message), None),
    };
    if !environments.is_empty() {
        let names: Vec<&str> = environments.iter().map(|e| e.name.as_str()).collect();
        evidence.push(format!("environments: {}", names.join(", ")));
    }
    if evidence.is_empty() {
        evidence.push("no deploy workflow, Dockerfile or environment".to_owned());
    }
    let n = workflows.len().max(dockerfiles).max(environments.len());
    let tier = match services_tier(n) {
        Services::Single => "single",
        Services::Few => "few",
        Services::Many => "many",
    };
    (Measure::new(n, tier, evidence), Some(n))
}

fn deploy_workflows(cx: &Cx<'_>) -> std::result::Result<Vec<String>, String> {
    let mut found = Vec::new();
    for (path, parsed) in workflows::read_all(cx.files) {
        let workflow = parsed.map_err(|e| format!("{path} unreadable: {e}"))?;
        if workflow.jobs.iter().any(|j| j.environment.is_some()) {
            found.push(path);
        }
    }
    Ok(found)
}

fn criticality_measure(criticality: Option<Criticality>) -> Measure {
    match criticality {
        Some(c) => Measure::new(
            c.name(),
            c.name(),
            vec!["project.json#criticality".to_owned()],
        ),
        None => Measure::new(
            "undeclared",
            "internal",
            vec!["project.json#criticality undeclared (audited as internal)".to_owned()],
        ),
    }
}
