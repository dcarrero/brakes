//! Governance rules (SPEC-auditor.md, "Blocks and feasibility"). The Bronze
//! rules read local files only, so they spend no host call: the dependency
//! update cooldown, the service card owner, CODEOWNERS, the pull request
//! template and issue forms that `repo-baseline` seeds. Flags expiry, cost
//! tags and persistent oversizing read conventions of `flags`, `iac` and
//! `k8s`; until those modules land they are `feasible_by: WaitsFor(<module>)`
//! and report `unavailable: waits for module <id>`, never `failed`.
use super::{posture::unread, waiting};
use crate::{
    PROFILE,
    auditor::{
        Cx, ISSUE_TEMPLATES,
        rules::{
            Block, Condition, Level, Milestone, Outcome, Probe, Profile, Remediation, Required,
            Rule,
        },
    },
    host::types::IssueFilter,
    modules::security::exceptions::{INVENTORY, Inventory, parse_date},
};
use serde_json::Value;
use yaml_rust2::{Yaml, YamlLoader};

const ALL: Required = Required {
    profiles: &[Profile::P1, Profile::P2, Profile::P3],
    when: &[],
};
/// Formal ownership adds nothing with one human (decision "Auditor standard
/// v1", point 1; SPEC-auditor.md, "Profiles and measures").
const P2_P3: Required = Required {
    profiles: &[Profile::P2, Profile::P3],
    when: &[],
};
const REPO_BASELINE: Remediation = Remediation::Module {
    id: "repo-baseline",
};

const DEPENDABOT: [&str; 2] = [".github/dependabot.yml", ".github/dependabot.yaml"];
const RENOVATE: &str = "renovate.json";
/// Where the service card may live: the seed of `repo-baseline` first.
const SERVICE_CARDS: [&str; 3] = [
    ".agent-setup/service.yaml",
    "service.yaml",
    "catalog-info.yaml",
];
/// The locations GitHub reads CODEOWNERS from, in its order of precedence.
const CODEOWNERS: [&str; 3] = [".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"];
/// The locations GitHub reads a pull request template from.
const PR_TEMPLATES: [&str; 3] = [
    ".github/pull_request_template.md",
    "pull_request_template.md",
    "docs/pull_request_template.md",
];

pub const DEPENDENCY_UPDATES_WITH_COOLDOWN: Rule = Rule {
    id: "governance.dependency-updates-with-cooldown",
    title: "Dependency updates with cooldown",
    block: Block::Governance,
    checks: "Dependabot gives every update entry a cooldown, or Renovate declares `minimumReleaseAge`.",
    how: Probe::LocalFile {
        path: ".github/dependabot.yml",
    },
    level: Level::Bronze,
    required: ALL,
    remediation: REPO_BASELINE,
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: dependency_updates_with_cooldown,
};

pub const SERVICE_CARD_OWNER: Rule = Rule {
    id: "governance.service-card-owner",
    title: "Service card with owner",
    block: Block::Governance,
    checks: "A service card (`.agent-setup/service.yaml`, `service.yaml` or `catalog-info.yaml`) names an owner other than unknown.",
    how: Probe::LocalFile {
        path: ".agent-setup/service.yaml",
    },
    level: Level::Bronze,
    required: ALL,
    remediation: REPO_BASELINE,
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: service_card_owner,
};

pub const CODEOWNERS_PRESENT: Rule = Rule {
    id: "governance.codeowners-present",
    title: "CODEOWNERS present",
    block: Block::Governance,
    checks: "The CODEOWNERS file GitHub reads has at least one ownership rule.",
    how: Probe::LocalFile {
        path: ".github/CODEOWNERS",
    },
    level: Level::Bronze,
    required: P2_P3,
    remediation: REPO_BASELINE,
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: codeowners_present,
};

pub const PR_TEMPLATE_AND_ISSUE_FORMS: Rule = Rule {
    id: "governance.pr-template-and-issue-forms",
    title: "PR template and issue forms",
    block: Block::Governance,
    checks: "A pull request template exists and `.github/ISSUE_TEMPLATE` holds at least one issue form.",
    how: Probe::LocalFile {
        path: ".github/pull_request_template.md",
    },
    level: Level::Bronze,
    required: ALL,
    remediation: REPO_BASELINE,
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: pr_template_and_issue_forms,
};

/// A rule of this block that waits for `module`, whose probe it declares.
const fn waits(
    id: &'static str,
    title: &'static str,
    checks: &'static str,
    required: Required,
    module: &'static str,
    step: &'static str,
) -> Rule {
    Rule {
        id,
        title,
        block: Block::Governance,
        checks,
        how: Probe::ManualStep { module, step },
        level: Level::Gold,
        required,
        remediation: Remediation::Module { id: module },
        plan: None,
        feasible_by: Milestone::WaitsFor(module),
        evaluate: waiting,
    }
}

pub const NO_EXPIRED_BYPASS: Rule = Rule {
    id: "governance.no-expired-bypass",
    title: "No expired bypass",
    block: Block::Governance,
    checks: "Every entry of `.agent-setup/security-exceptions.json` has an `expires` date that has not passed.",
    how: Probe::LocalFile { path: INVENTORY },
    level: Level::Silver,
    required: ALL,
    remediation: Remediation::Manual {
        step: "renew-or-remove-bypass",
        instructions: "Remove the expired exception and what it bypasses, or register a new entry with a new created date and a comment on its issue; never edit the date.",
    },
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: no_expired_bypass,
};

pub const POSTMORTEM_ACTIONS_CLOSED: Rule = Rule {
    id: "governance.postmortem-actions-closed",
    title: "Post-mortem actions closed by their due date",
    block: Block::Governance,
    checks: "No open issue labelled `type:post-mortem-action` is past the due date its form records.",
    how: Probe::Remote {
        id: "post-mortem-actions",
    },
    level: Level::Gold,
    required: ALL,
    remediation: Remediation::Manual {
        step: "close-post-mortem-actions",
        instructions: "Close each overdue post-mortem action, or record a new due date on it with the reason; every action carries a Due date.",
    },
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: postmortem_actions_closed,
};

pub const ADR_STATE_KNOWN: Rule = Rule {
    id: "governance.adr-state-known",
    title: "Every decision heading has a known state",
    block: Block::Governance,
    checks: "Every `##` heading of the decision files the conventions declare ends in ` — <state>`, the state one of proposed, accepted, rejected, deprecated or superseded.",
    how: Probe::LocalFile { path: PROFILE },
    level: Level::Gold,
    required: ALL,
    remediation: Remediation::Manual {
        step: "state-every-decision",
        instructions: "End every decision heading with ` — <state>, <date>`, the state one of proposed, accepted, rejected, deprecated or superseded.",
    },
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: adr_state_known,
};

pub const NO_EXPIRED_FLAGS: Rule = waits(
    "governance.no-expired-flags",
    "No expired flag",
    "No flag of the flags registry is past its expiry.",
    ALL,
    "flags",
    "flag-registry",
);

pub const COST_TAGS: Rule = waits(
    "governance.cost-tags",
    "Cost tags",
    "Every IaC resource carries the cost attribution tags.",
    ALL,
    "iac",
    "cost-tags",
);

pub const NO_PERSISTENT_OVERSIZING: Rule = waits(
    "governance.no-persistent-oversizing",
    "No persistent oversizing",
    "No workload requests persistently more than it uses (platform ladder L4).",
    Required {
        profiles: &[],
        when: &[Condition::PlatformLadderL4],
    },
    "k8s",
    "rightsizing",
);

/// The text of `path`, `None` when absent, or the `Unavailable` outcome of a
/// read that failed.
fn read(cx: &Cx<'_>, path: &str) -> Result<Option<String>, Outcome> {
    cx.files
        .read(path)
        .map_err(|e| Outcome::unavailable(format!("{path} unreadable: {e}")))
}

/// The first of `paths` that exists, with its text, in the order given.
fn first<'p>(cx: &Cx<'_>, paths: &[&'p str]) -> Result<Option<(&'p str, String)>, Outcome> {
    for path in paths {
        if let Some(text) = read(cx, path)? {
            return Ok(Some((path, text)));
        }
    }
    Ok(None)
}

/// Every YAML document of `text`, or `None` when it does not parse.
fn yaml(text: &str) -> Option<Vec<Yaml>> {
    YamlLoader::load_from_str(text).ok()
}

/// A cooldown that delays at least one kind of update by a day or more.
fn cools_down(cooldown: &Yaml) -> bool {
    cooldown.as_hash().is_some_and(|keys| {
        keys.iter().any(|(key, days)| {
            key.as_str().is_some_and(|k| k.ends_with("-days"))
                && days.as_i64().is_some_and(|d| d > 0)
        })
    })
}

/// Passed or the failures of a Dependabot configuration.
fn dependabot(path: &str, text: &str) -> Result<String, Vec<String>> {
    let docs = yaml(text).ok_or_else(|| vec![format!("{path} is not valid YAML")])?;
    let updates = docs
        .first()
        .and_then(|d| d["updates"].as_vec())
        .cloned()
        .unwrap_or_default();
    if updates.is_empty() {
        return Err(vec![format!("{path} declares no update")]);
    }
    let name = |u: &Yaml| {
        format!(
            "{} {}",
            u["package-ecosystem"].as_str().unwrap_or("?"),
            u["directory"].as_str().unwrap_or("?")
        )
    };
    let missing: Vec<String> = updates
        .iter()
        .filter(|u| !cools_down(&u["cooldown"]))
        .map(|u| format!("{path}: update {} has no cooldown", name(u)))
        .collect();
    if !missing.is_empty() {
        return Err(missing);
    }
    let names: Vec<String> = updates.iter().map(name).collect();
    Ok(format!(
        "{path}: cooldown on every update ({})",
        names.join(", ")
    ))
}

/// Passed or the failure of a Renovate configuration.
fn renovate(text: &str) -> Result<String, Vec<String>> {
    let config: Value =
        serde_json::from_str(text).map_err(|_| vec![format!("{RENOVATE} is not valid JSON")])?;
    match config["minimumReleaseAge"].as_str().map(str::trim) {
        Some(age) if !age.is_empty() && !age.starts_with('0') => {
            Ok(format!("{RENOVATE}: minimumReleaseAge {age}"))
        }
        _ => Err(vec![format!("{RENOVATE} declares no minimumReleaseAge")]),
    }
}

fn dependency_updates_with_cooldown(cx: &Cx<'_>) -> Outcome {
    let mut verdicts = Vec::new();
    match first(cx, &DEPENDABOT) {
        Ok(Some((path, text))) => verdicts.push(dependabot(path, &text)),
        Ok(None) => {}
        Err(outcome) => return outcome,
    }
    match read(cx, RENOVATE) {
        Ok(Some(text)) => verdicts.push(renovate(&text)),
        Ok(None) => {}
        Err(outcome) => return outcome,
    }
    if verdicts.is_empty() {
        return Outcome::failed([format!(
            "neither {} nor {RENOVATE} configures dependency updates",
            DEPENDABOT[0]
        )]);
    }
    if let Some(Ok(evidence)) = verdicts.iter().find(|v| v.is_ok()) {
        return Outcome::passed([evidence.clone()]);
    }
    Outcome::failed(verdicts.into_iter().filter_map(Result::err).flatten())
}

/// The owner a card names: `owner`, or Backstage's `spec.owner`.
fn card_owner(docs: &[Yaml]) -> Option<String> {
    docs.iter().find_map(|d| {
        d["owner"]
            .as_str()
            .or_else(|| d["spec"]["owner"].as_str())
            .map(str::to_owned)
    })
}

fn service_card_owner(cx: &Cx<'_>) -> Outcome {
    let mut failures = Vec::new();
    for path in SERVICE_CARDS {
        let text = match read(cx, path) {
            Ok(Some(text)) => text,
            Ok(None) => continue,
            Err(outcome) => return outcome,
        };
        let Some(docs) = yaml(&text) else {
            failures.push(format!("{path} is not valid YAML"));
            continue;
        };
        match card_owner(&docs).as_deref().map(str::trim) {
            None => failures.push(format!("{path}: no owner")),
            Some("") => failures.push(format!("{path}: owner is empty")),
            Some(owner) if owner.eq_ignore_ascii_case("unknown") => {
                failures.push(format!("{path}: owner is unknown"));
            }
            Some(owner) => return Outcome::passed([format!("owner {owner} in {path}")]),
        }
    }
    if failures.is_empty() {
        failures.push(format!(
            "no service card: {}, {} or {}",
            SERVICE_CARDS[0], SERVICE_CARDS[1], SERVICE_CARDS[2]
        ));
    }
    Outcome::failed(failures)
}

fn codeowners_present(cx: &Cx<'_>) -> Outcome {
    // GitHub reads the first file it finds; the others are ignored.
    let (path, text) = match first(cx, &CODEOWNERS) {
        Ok(Some(found)) => found,
        Ok(None) => return Outcome::failed(["no CODEOWNERS in .github/, the root or docs/"]),
        Err(outcome) => return outcome,
    };
    let rules = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .count();
    match rules {
        0 => Outcome::failed([format!("{path} has no ownership rule")]),
        1 => Outcome::passed([format!("{path}: 1 ownership rule")]),
        n => Outcome::passed([format!("{path}: {n} ownership rules")]),
    }
}

fn pr_template_and_issue_forms(cx: &Cx<'_>) -> Outcome {
    let template = match first(cx, &PR_TEMPLATES) {
        Ok(found) => found.map(|(path, _)| path),
        Err(outcome) => return outcome,
    };
    let forms: Vec<String> = match cx.files.list(ISSUE_TEMPLATES) {
        Ok(paths) => paths
            .into_iter()
            .filter(|p| {
                let name = p.rsplit('/').next().unwrap_or_default();
                (name.ends_with(".yml") || name.ends_with(".yaml"))
                    && !matches!(name, "config.yml" | "config.yaml")
            })
            .collect(),
        Err(e) => return Outcome::unavailable(format!("{ISSUE_TEMPLATES} unreadable: {e}")),
    };
    if let (Some(path), false) = (template, forms.is_empty()) {
        return Outcome::passed([
            format!("pull request template {path}"),
            format!("issue forms: {}", forms.join(", ")),
        ]);
    }
    let mut failures = Vec::new();
    if template.is_none() {
        failures.push("no pull request template in .github/, the root or docs/".to_owned());
    }
    if forms.is_empty() {
        failures.push(format!("no issue form (.yml) under {ISSUE_TEMPLATES}"));
    }
    Outcome::failed(failures)
}

fn no_expired_bypass(cx: &Cx<'_>) -> Outcome {
    let text = match read(cx, INVENTORY) {
        Ok(Some(text)) => text,
        Ok(None) => {
            return Outcome::not_required(format!("no bypass registered: {INVENTORY} absent"));
        }
        Err(outcome) => return outcome,
    };
    let Some(inventory) = Inventory::parse(&text) else {
        return Outcome::failed([format!(
            "{INVENTORY} does not parse as the bypass inventory"
        )]);
    };
    let mut active = Vec::new();
    let mut failures = Vec::new();
    for entry in &inventory.exceptions {
        let label = entry.label();
        match entry.expires.as_deref() {
            None => failures.push(format!("exception {label} has no expires")),
            Some(text) => match parse_date(text) {
                None => failures.push(format!(
                    "exception {label} has an invalid expires date {text}"
                )),
                // `expires` is the last active day.
                Some(day) if day < cx.now => {
                    failures.push(format!("exception {label} expired on {day}"));
                }
                Some(day) => active.push(format!("exception {label} active until {day}")),
            },
        }
    }
    if !failures.is_empty() {
        return Outcome::failed(failures);
    }
    if active.is_empty() {
        return Outcome::passed([format!("{INVENTORY} registers no exception")]);
    }
    Outcome::passed(active)
}

/// The issue label `repo-baseline` gives post-mortem actions
/// (SPEC-repo-baseline.md, "Labels").
const POSTMORTEM_LABEL: &str = "type:post-mortem-action";
/// Open actions read in one call; more is `Unavailable` unless one already fails.
const POSTMORTEM_CAP: u32 = 100;

/// The due date of an action: the value under the form's `### Due date`
/// heading, or a `due: YYYY-MM-DD` line.
fn due_date(body: &str) -> Option<chrono::NaiveDate> {
    let mut lines = body.lines().map(str::trim);
    while let Some(line) = lines.next() {
        if let Some(rest) = line.to_ascii_lowercase().strip_prefix("due:") {
            return parse_date(rest.trim());
        }
        if line
            .trim_start_matches('#')
            .trim()
            .eq_ignore_ascii_case("due date")
            && line.starts_with('#')
        {
            return lines.find(|l| !l.is_empty()).and_then(parse_date);
        }
    }
    None
}

fn postmortem_actions_closed(cx: &Cx<'_>) -> Outcome {
    let filter = IssueFilter {
        state: Some("open".to_owned()),
        labels: vec![POSTMORTEM_LABEL.to_owned()],
        since: None,
        limit: Some(POSTMORTEM_CAP),
    };
    let actions = match cx.host.issues(cx.repo, &filter) {
        Ok(actions) => actions,
        Err(e) => return unread(&e),
    };
    let failures: Vec<String> = actions
        .iter()
        .filter_map(|a| {
            let title = format!("#{} \"{}\"", a.number, a.title);
            match a.body.as_deref().and_then(due_date) {
                None => Some(format!("{title} has no due date")),
                Some(due) if due < cx.now => Some(format!("{title} was due on {due}")),
                Some(_) => None,
            }
        })
        .collect();
    if !failures.is_empty() {
        return Outcome::failed(failures);
    }
    match actions.len() {
        0 => Outcome::passed([format!("no open {POSTMORTEM_LABEL} issue")]),
        n if n >= POSTMORTEM_CAP as usize => Outcome::unavailable(format!(
            "{n} open post-mortem actions or more; the first {POSTMORTEM_CAP} are not past their due date"
        )),
        1 => Outcome::passed(["1 open post-mortem action, not past its due date"]),
        n => Outcome::passed([format!(
            "{n} open post-mortem actions, none past its due date"
        )]),
    }
}

/// The lifecycle states of an ADR (`templates/decisions.md`; Nygard's and
/// MADR's status values).
#[cfg(feature = "setup-core")]
const ADR_STATES: [&str; 5] = [
    "proposed",
    "accepted",
    "rejected",
    "deprecated",
    "superseded",
];
/// Unknown headings named one by one before the rest are counted.
#[cfg(feature = "setup-core")]
const ADR_SHOWN: usize = 10;

/// Whether a heading's status starts with a known state word.
#[cfg(feature = "setup-core")]
fn known_state(status: &str) -> bool {
    let word: String = status
        .chars()
        .take_while(|c| c.is_alphabetic())
        .collect::<String>()
        .to_lowercase();
    ADR_STATES.contains(&word.as_str())
}

/// Conventions are `setup-core`'s: without the feature nothing declares a
/// decision file (product-boundary T7a; the rule leaves the catalogue in T7b).
#[cfg(not(feature = "setup-core"))]
fn adr_state_known(_: &Cx<'_>) -> Outcome {
    Outcome::not_required("no decision convention: this build reads none")
}

#[cfg(feature = "setup-core")]
fn adr_state_known(cx: &Cx<'_>) -> Outcome {
    let profile: Value = match read(cx, PROFILE) {
        Ok(text) => text
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or(Value::Null),
        Err(outcome) => return outcome,
    };
    use crate::conventions;
    let declared = conventions::parse(&profile["conventions"]);
    let files = conventions::decision_files(&declared);
    if files.is_empty() {
        return Outcome::not_required(format!(
            "no decision file declared in {PROFILE} conventions"
        ));
    }
    let mut unknown = Vec::new();
    let mut known = Vec::new();
    for file in files {
        let text = match read(cx, file) {
            Ok(Some(text)) => text,
            Ok(None) => {
                unknown.push(format!(
                    "{file}, declared in {PROFILE} conventions, does not exist"
                ));
                continue;
            }
            Err(outcome) => return outcome,
        };
        let headings: Vec<_> = conventions::headings(&text)
            .into_iter()
            .filter(|h| h.level == 2)
            .collect();
        for h in &headings {
            match h.status.as_deref() {
                Some(status) if known_state(status) => {}
                Some(status) => unknown.push(format!(
                    "{file}: \"{}\" has the unknown state \"{status}\"",
                    h.title
                )),
                None => unknown.push(format!("{file}: \"{}\" has no state", h.title)),
            }
        }
        known.push(format!(
            "{file}: {} decision headings, each with a known state",
            headings.len()
        ));
    }
    if unknown.is_empty() {
        return Outcome::passed(known);
    }
    let more = unknown.len().saturating_sub(ADR_SHOWN);
    unknown.truncate(ADR_SHOWN);
    if more > 0 {
        unknown.push(format!(
            "and {more} more decision headings without a known state"
        ));
    }
    Outcome::failed(unknown)
}
