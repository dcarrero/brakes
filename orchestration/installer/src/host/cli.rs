//! `brakes host <subcommand>` (SPEC-host-adapter.md, "CLI"): read-only
//! views of a code host. Exit codes: 0 complete, 1 refused, 2 truncated or
//! rate-limited. Each subcommand parses its own arguments, so later slices add
//! a match arm here and nothing else.
use super::{
    CallBudget, Features, Host, HostError, HostErrorKind, OwnerId, OwnerKind, RepoId, Visibility,
    github::GitHub,
    probes::{self, ArgKind},
    types::{OrgSettings, RepoSummary, Ruleset},
};
use crate::engine::manual::{ProbeResult, StepState};
use crate::remote::Gh;
use serde::Serialize;
use serde_json::Value;
use std::{collections::BTreeMap, ffi::OsString, process::ExitCode};

pub const USAGE: &str = "Usage: brakes host features <owner/repo> [--json]\n       brakes host repos <owner> [--json] [--call-budget <n>]\n       brakes host org <org> [--json]\n       brakes host probe <owner/repo> <probe-id> [--arg key=value]... [--json]";

pub fn cli(args: &[OsString]) -> ExitCode {
    let Some(args) = args.iter().map(|a| a.to_str()).collect::<Option<Vec<_>>>() else {
        return refused(USAGE);
    };
    // `--json` is every subcommand's flag and may stand anywhere.
    let json = args.contains(&"--json");
    let mut rest: Vec<&str> = args.into_iter().filter(|a| *a != "--json").collect();
    // `--call-budget <n>` is `repos`' flag and may stand anywhere after it.
    let budget = match rest.iter().position(|a| *a == "--call-budget") {
        None => None,
        Some(at) => match rest.get(at + 1).and_then(|n| n.parse::<u32>().ok()) {
            Some(n) if n > 0 => {
                rest.drain(at..=at + 1);
                Some(n)
            }
            _ => return refused("--call-budget needs a whole number of calls above 0"),
        },
    };
    // `--arg key=value` is `probe`'s flag and may repeat.
    let mut probe_args = Vec::new();
    while let Some(at) = rest.iter().position(|a| *a == "--arg") {
        let Some(pair) = rest.get(at + 1).copied() else {
            return refused("--arg needs key=value");
        };
        let Some((key, value)) = pair.split_once('=').filter(|(k, _)| !k.is_empty()) else {
            return refused(&format!("--arg needs key=value, got `{pair}`"));
        };
        probe_args.push((key, value));
        rest.drain(at..=at + 1);
    }
    let operand = |a: &&str| !a.starts_with('-');
    if !probe_args.is_empty() && rest.first() != Some(&"probe") {
        return refused("--arg is only available with host probe");
    }
    match (rest.as_slice(), budget) {
        (["--help" | "-h"], None) => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        (["features", identity], None) if operand(identity) => features(identity, json),
        (["repos", owner], budget) if operand(owner) => repos(
            owner,
            json,
            budget.map_or_else(CallBudget::default, CallBudget::new),
        ),
        (["org", org], None) if operand(org) => org_report(org, json),
        (["probe", identity, id], None) if operand(identity) && operand(id) => {
            probe(identity, id, &probe_args, json)
        }
        _ => refused(USAGE),
    }
}

/// The `--json` form of `host features`, fields in declaration order.
#[derive(Serialize)]
struct FeaturesReport<'a> {
    repository: String,
    features: &'a Features,
}

/// `host features <owner/repo> [--json]`.
fn features(identity: &str, json: bool) -> ExitCode {
    let repo = match RepoId::parse(identity) {
        Ok(repo) => repo,
        Err(error) => return refused(&error.to_string()),
    };
    let gh = Gh::default();
    let features = match GitHub::new(&gh, CallBudget::default()).features(&repo) {
        Ok(features) => features,
        Err(error) => return stopped(&error),
    };
    if json {
        let report = FeaturesReport {
            repository: repo.to_string(),
            features: &features,
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&report).expect("features serialise")
        );
    } else {
        println!("repository: {repo}");
        for line in features.lines() {
            println!("{line}");
        }
    }
    ExitCode::SUCCESS
}

/// The `--json` form of `host repos`: the owner, the repositories read, why the
/// listing stopped and what it did not read.
#[derive(Serialize)]
struct ReposReport<'a> {
    owner: &'a OwnerId,
    repositories: &'a [RepoSummary],
    stopped: &'a Option<HostError>,
    unread: &'a [String],
}

/// `host repos <owner> [--json] [--call-budget <n>]`: exit 2 when the listing
/// was stopped, after printing what it read and the count it did not.
fn repos(name: &str, json: bool, budget: CallBudget) -> ExitCode {
    let gh = Gh::default();
    let github = GitHub::new(&gh, budget);
    let (owner, listing) = match github
        .owner(name)
        .and_then(|owner| github.list_repositories(&owner).map(|l| (owner, l)))
    {
        Ok(read) => read,
        Err(error) => return stopped(&error),
    };
    if json {
        let report = ReposReport {
            owner: &owner,
            repositories: &listing.items,
            stopped: &listing.stopped,
            unread: &listing.unread,
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&report).expect("repositories serialise")
        );
    } else {
        let kind = match owner.kind {
            OwnerKind::User => "user",
            OwnerKind::Organization => "organization",
            OwnerKind::Unknown => "unknown",
        };
        println!("owner: {owner} ({kind})");
        for repo in &listing.items {
            let visibility = match repo.visibility {
                Visibility::Public => "public",
                Visibility::Private => "private",
                Visibility::Internal => "internal",
            };
            let mut line = format!("{} {visibility} {}", repo.id, repo.default_branch);
            for (set, flag) in [(repo.archived, " archived"), (repo.fork, " fork")] {
                if set {
                    line.push_str(flag);
                }
            }
            println!("{line}");
        }
        println!("{} repositories", listing.items.len());
    }
    if let Some(error) = &listing.stopped {
        eprintln!("INCOMPLETE: {error}");
    }
    for unread in &listing.unread {
        eprintln!("NOT READ: {unread}");
    }
    if listing.stopped.is_some() {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
}

/// The `--json` form of `host org`: settings with `null` for unseen fields,
/// and either the rulesets or why they are unavailable.
#[derive(Serialize)]
struct OrgReport<'a> {
    organization: &'a str,
    settings: &'a OrgSettings,
    rulesets: Option<&'a [Ruleset]>,
    rulesets_unavailable: Option<&'a str>,
}

/// `host org <org> [--json]`: read-only settings and rulesets of an organization.
fn org_report(org: &str, json: bool) -> ExitCode {
    let gh = Gh::default();
    let github = GitHub::new(&gh, CallBudget::default());
    let settings = match github.org_settings(org) {
        Ok(settings) => settings,
        Err(error) => return stopped(&error),
    };
    let (rulesets, unavailable) = match github.org_rulesets(org) {
        Ok(rulesets) => (Some(rulesets), None),
        Err(error) if error.kind == HostErrorKind::Forbidden => (None, Some(error.message)),
        Err(error) => return stopped(&error),
    };
    if json {
        let report = OrgReport {
            organization: org,
            settings: &settings,
            rulesets: rulesets.as_deref(),
            rulesets_unavailable: unavailable.as_deref(),
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&report).expect("organization serialises")
        );
        return ExitCode::SUCCESS;
    }
    let seen = |value: Option<String>| {
        value.unwrap_or_else(|| "unknown (not visible to this token)".to_owned())
    };
    let flag = |value: Option<bool>| seen(value.map(|b| b.to_string()));
    println!("organization: {org}");
    println!(
        "two_factor_requirement_enabled: {}",
        flag(settings.two_factor_requirement_enabled)
    );
    println!(
        "default_repository_permission: {}",
        seen(settings.default_repository_permission.clone())
    );
    println!(
        "members_can_create_public_repositories: {}",
        flag(settings.members_can_create_public_repositories)
    );
    println!(
        "web_commit_signoff_required: {}",
        flag(settings.web_commit_signoff_required)
    );
    match &settings.plan_hint {
        Some(plan) => println!("plan_hint: {plan} (never decides)"),
        None => println!("plan_hint: none"),
    }
    match (&rulesets, &unavailable) {
        (Some(rulesets), _) => {
            println!("rulesets: {}", rulesets.len());
            for r in rulesets {
                println!("ruleset {}: {}, {}", r.name, r.target, r.enforcement);
            }
        }
        (None, reason) => println!(
            "rulesets: unavailable ({})",
            reason.as_deref().unwrap_or("")
        ),
    }
    ExitCode::SUCCESS
}

/// The `--json` form of `host probe`: the step-report fields of the engine.
#[derive(Serialize)]
struct ProbeReport<'a> {
    repository: String,
    probe: &'a str,
    args: &'a BTreeMap<String, Value>,
    state: StepState,
    evidence: Option<&'a str>,
    error: Option<&'a str>,
}

/// Each `--arg` value as the probe's schema expects it: a list argument takes
/// a JSON array or comma-separated texts, an object one JSON, any other text.
fn probe_arguments(id: &str, pairs: &[(&str, &str)]) -> Result<BTreeMap<String, Value>, String> {
    let kind = |key: &str| {
        probes::schema(id)
            .and_then(|s| s.args.iter().find(|a| a.name == key))
            .map(|a| a.kind)
    };
    let json = |key: &str, value: &str| {
        serde_json::from_str::<Value>(value).map_err(|e| format!("--arg {key} is not JSON: {e}"))
    };
    pairs
        .iter()
        .map(|(key, value)| {
            let parsed = match kind(key) {
                Some(ArgKind::TextList) if value.starts_with('[') => json(key, value)?,
                Some(ArgKind::TextList) => Value::from(
                    value
                        .split(',')
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                        .collect::<Vec<_>>(),
                ),
                Some(ArgKind::Object | ArgKind::ObjectList) => json(key, value)?,
                _ => Value::from(*value),
            };
            Ok(((*key).to_owned(), parsed))
        })
        .collect()
}

/// `host probe <owner/repo> <probe-id> [--arg key=value]... [--json]`: one
/// registry probe. Exit 0 for `verified`, `pending` and `not-applicable`, 2 when the read was
/// cut short, 1 for a refusal or any other `failed` or `unavailable` answer.
fn probe(identity: &str, id: &str, pairs: &[(&str, &str)], json: bool) -> ExitCode {
    let repo = match RepoId::parse(identity) {
        Ok(repo) => repo,
        Err(error) => return refused(&error.to_string()),
    };
    let args = match probe_arguments(id, pairs) {
        Ok(args) => args,
        Err(reason) => return refused(&reason),
    };
    if let Err(reason) = probes::check(id, &args) {
        return refused(&reason);
    }
    let gh = Gh::default();
    let host = GitHub::new(&gh, CallBudget::default());
    let (result, kind) = probes::run_detailed(&host, &repo, id, &args);
    let (state, text) = match &result {
        ProbeResult::Verified(t) => (StepState::Verified, t),
        ProbeResult::Pending(t) => (StepState::Pending, t),
        ProbeResult::Failed(t) => (StepState::Failed, t),
        ProbeResult::Unavailable(t) => (StepState::Unavailable, t),
        ProbeResult::NotApplicable(t) => (StepState::NotApplicable, t),
    };
    if json {
        let failed = state == StepState::Failed;
        let report = ProbeReport {
            repository: repo.to_string(),
            probe: id,
            args: &args,
            state,
            evidence: (!failed).then_some(text.as_str()),
            error: failed.then_some(text.as_str()),
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&report).expect("probe report serialises")
        );
    } else {
        println!("REMOTE [{state}:host-adapter] {id} — {text}");
    }
    match (state, kind) {
        (_, Some(HostErrorKind::RateLimited { .. } | HostErrorKind::Truncated)) => {
            ExitCode::from(2)
        }
        (StepState::Verified | StepState::Pending | StepState::NotApplicable, _) => {
            ExitCode::SUCCESS
        }
        _ => ExitCode::from(1),
    }
}

fn refused(reason: &str) -> ExitCode {
    eprintln!("REFUSED: {reason}");
    ExitCode::from(1)
}
/// A host error: 2 when the read was cut short (rate limit, budget, page cap),
/// 1 for every other refusal.
fn stopped(error: &HostError) -> ExitCode {
    if matches!(
        error.kind,
        HostErrorKind::RateLimited { .. } | HostErrorKind::Truncated
    ) {
        eprintln!("INCOMPLETE: {error}");
        ExitCode::from(2)
    } else {
        refused(&error.message)
    }
}
