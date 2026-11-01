//! What `doctor <repo>` shows of an audit (SPEC-auditor.md, "Outputs"): the
//! text lines appended after today's lines, the `--json` schema-1 additions and
//! the Markdown of one repository that `--report` writes, and the Markdown and
//! JSON of `--fleet`. Rendering is a pure function of the audit, so the same
//! inputs and `--now` give the same bytes.
use super::{
    Audit, Evaluated,
    counters::Counters,
    fleet::Fleet,
    measures::{Measure, Measured, WINDOW_DAYS},
    rules::{Block, Milestone, Remediation, Status},
};
use chrono::NaiveDate;
use serde_json::{Map, Value, json};

/// The standard the levels are stated against: the accepted decision
/// "Auditor standard v1" (docs/decisions.md, #706).
pub const STANDARD: &str = "accepted";

/// Every block, in the order the JSON reports them.
const BLOCKS: [Block; 11] = [
    Block::Baseline,
    Block::Posture,
    Block::CiHealth,
    Block::Dora,
    Block::Operations,
    Block::Governance,
    Block::Ci,
    Block::Security,
    Block::Stack,
    Block::Agents,
    Block::Qa,
];

/// The host calls one audit spent against its budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    pub api_calls: u32,
    pub limit: u32,
    pub exhausted: bool,
}

/// The audit of one repository, with what the report needs around it.
#[derive(Debug, Clone, PartialEq)]
pub struct Audited {
    /// `owner/name`, as printed.
    pub repo: String,
    pub now: NaiveDate,
    pub measured: Measured,
    pub audit: Audit,
    /// Reported beside the audit; they never change its level or exit code.
    pub counters: Counters,
    pub budget: Budget,
}

impl Audited {
    /// The exit code of the CI contract (SPEC-auditor.md, "Exit codes").
    pub fn exit_code(&self, ready: bool) -> i32 {
        self.measured.exit_code(&self.audit, ready)
    }

    /// The lines appended after today's `doctor` lines: `AUDIT`, the two
    /// `COUNTER` lines, any `FINDING`
    /// about the declarations, `FAIL` and `UNAVAILABLE` for each required rule
    /// in registry order, and `NEXT` while a level remains.
    pub fn lines(&self) -> Vec<String> {
        let m = &self.measured;
        let mut audit_line = format!(
            "AUDIT {}: profile {} ({}); required {}; reached {}",
            self.repo,
            self.profile_name(),
            dimensions(
                &m.measures.humans,
                &m.measures.cadence,
                &m.measures.services,
                &m.measures.criticality
            ),
            m.required,
            self.reached(),
        );
        if let Some(accepted) = &m.accepted {
            audit_line.push_str(&format!(
                "; accepted {} until {}",
                accepted.level, accepted.expires
            ));
        }
        let mut lines = vec![audit_line];
        lines.extend(self.counters.lines());
        lines.extend(m.findings.iter().map(|f| format!("FINDING {f}")));
        lines.extend(
            self.audit
                .risk_findings
                .iter()
                .map(|f| format!("FINDING {f}")),
        );
        for e in self.audit.rules.iter().filter(|e| e.required) {
            let tag = format!(
                "[{}:{}]",
                e.rule.level.to_string().to_lowercase(),
                e.rule.id
            );
            let accepted = self
                .audit
                .accepted_risks
                .iter()
                .find(|a| a.rule == e.rule.id);
            match (e.outcome.status, accepted) {
                // An accepted risk is shown, never hidden, and stays in the gap (#1217).
                (Status::Failed, Some(a)) => lines.push(format!(
                    "{:<11} {tag} {} → accepted risk {}: {} ({}, owner {}, until {})",
                    "ACCEPTED",
                    e.outcome.evidence.join("; "),
                    a.id,
                    a.reason,
                    a.issue,
                    a.owner,
                    a.expires
                )),
                (Status::Failed, None) => lines.push(format!(
                    "{:<11} {tag} {} → {}",
                    "FAIL",
                    e.outcome.evidence.join("; "),
                    remediations(e)
                )),
                (Status::Unavailable, _) => lines.push(format!(
                    "UNAVAILABLE {tag} {}",
                    e.outcome.reason.as_deref().unwrap_or_default()
                )),
                (Status::Passed | Status::NotRequired, _) => {}
            }
        }
        if let Some(next) = &self.audit.next {
            let n = next.gap.len();
            lines.push(format!(
                "NEXT {}: {n} rule{} ({})",
                next.level,
                if n == 1 { "" } else { "s" },
                next.gap.join(", ")
            ));
        }
        lines
    }

    /// The schema-1 additions of `doctor --json`, merged beside today's keys.
    pub fn json(&self) -> Map<String, Value> {
        let m = &self.measured;
        let level = |l: Option<super::rules::Level>| l.map(|l| l.to_string());
        let mut out = Map::new();
        out.insert("repo".into(), json!(self.repo));
        out.insert("audited_at".into(), json!(self.now.to_string()));
        out.insert("window_days".into(), json!(WINDOW_DAYS));
        out.insert("profile".into(), m.to_json());
        out.insert(
            "level".into(),
            json!({
                "required": m.required.to_string(),
                "reached": level(self.audit.reached),
                "unverified_from": level(self.audit.unverified_from),
                "standard": STANDARD,
                "accepted": m.accepted.map(|a| json!({
                    "level": a.level.to_string(),
                    "expires": a.expires.to_string(),
                })),
                "findings": m.findings.iter().chain(&self.audit.risk_findings).collect::<Vec<_>>(),
            }),
        );
        out.insert(
            "rules".into(),
            Value::Array(
                self.audit
                    .rules
                    .iter()
                    .map(|e| {
                        let mut rule = rule_json(e);
                        if let Some(a) = self
                            .audit
                            .accepted_risks
                            .iter()
                            .find(|a| a.rule == e.rule.id)
                        {
                            rule["accepted_risk"] = json!({
                                "id": a.id,
                                "reason": a.reason,
                                "issue": a.issue,
                                "owner": a.owner,
                                "expires": a.expires,
                            });
                        }
                        rule
                    })
                    .collect(),
            ),
        );
        out.insert(
            "next_level".into(),
            self.audit.next.as_ref().map_or(
                Value::Null,
                |n| json!({ "level": n.level.to_string(), "gap": n.gap }),
            ),
        );
        out.insert(
            "blocks".into(),
            Value::Object(
                BLOCKS
                    .iter()
                    .map(|&b| (b.id().replace('-', "_"), json!(self.block_state(b))))
                    .collect(),
            ),
        );
        out.insert("counters".into(), self.counters.to_json());
        out.insert(
            "budget".into(),
            json!({
                "api_calls": self.budget.api_calls,
                "limit": self.budget.limit,
                "exhausted": self.budget.exhausted,
            }),
        );
        out
    }

    /// The Markdown of one repository: a header, the summary row the fleet
    /// report also uses, and the audit lines with their remediations.
    pub fn markdown(&self) -> String {
        let gap = self.gap();
        let (unavailable, waiting) = self.unavailable();
        let mut out = format!(
            "# Audit {repo}\n\nAudited at {now} over a {WINDOW_DAYS}-day window against the {STANDARD} standard.\n\n\
             | Repository | Profile | Required | Reached | Gap | Unavailable | Waiting |\n\
             |---|---|---|---|---|---|---|\n\
             | {repo} | {profile} | {required} | {reached} | {gap} | {unavailable} | {waiting} |\n\n## {repo}\n\n",
            repo = self.repo,
            now = self.now,
            profile = self.profile_name(),
            required = self.measured.required,
            reached = self.reached(),
        );
        out.push_str("```text\n");
        for line in self.lines() {
            out.push_str(&line);
            out.push('\n');
        }
        out.push_str("```\n");
        out
    }

    fn gap(&self) -> usize {
        self.audit.next.as_ref().map_or(0, |n| n.gap.len())
    }

    /// The rules `Unavailable` for want of evidence, and those waiting for a
    /// module, counted apart.
    fn unavailable(&self) -> (usize, usize) {
        let (waiting, unavailable) = self
            .audit
            .rules
            .iter()
            .filter(|e| e.outcome.status == Status::Unavailable)
            .partition::<Vec<_>, _>(|e| waits(e));
        (unavailable.len(), waiting.len())
    }

    fn rule(&self, id: &str) -> Option<&Evaluated> {
        self.audit.rules.iter().find(|e| e.rule.id == id)
    }

    /// The fleet table's cells for one repository (SPEC-auditor.md, "Outputs").
    fn fleet_row(&self) -> String {
        let (unavailable, waiting) = self.unavailable();
        let posture = self
            .audit
            .rules
            .iter()
            .filter(|e| e.rule.block == Block::Posture && e.blocks_any(Status::Failed))
            .count();
        let state = |id: &str| self.rule(id).map_or("absent", state);
        let minutes = self
            .rule("ci-health.minutes-budget")
            .and_then(|e| {
                e.outcome
                    .evidence
                    .iter()
                    .find_map(|line| line.strip_prefix(MINUTES_LABEL))
            })
            .and_then(|rest| rest.split_once(" min,").map(|(m, _)| format!("{m} min")))
            .unwrap_or_else(|| state("ci-health.minutes-budget").to_owned());
        let lead = self
            .rule("dora.lead-time")
            .and_then(|e| e.outcome.evidence.first())
            .and_then(|line| line.strip_prefix("median "))
            .and_then(|rest| rest.split_once(" h ").map(|(h, _)| format!("{h} h")))
            .unwrap_or_else(|| state("dora.lead-time").to_owned());
        let [corrections, cost] = self.counters.cells();
        format!(
            "| {} | {} | {} | {} | {} | {posture} | {minutes} | {} | {lead} | {} | {corrections} | {cost} | {unavailable} | {waiting} |",
            self.repo,
            self.profile_name(),
            self.measured.required,
            self.reached(),
            self.gap(),
            state("dora.deployment-frequency"),
            state("operations.incidents-bounded"),
        )
    }

    fn profile_name(&self) -> String {
        let m = &self.measured;
        if m.unverified {
            format!("{:?} unverified", m.profile)
        } else {
            format!("{:?}", m.profile)
        }
    }

    fn reached(&self) -> String {
        self.audit
            .reached
            .map_or_else(|| "none".to_owned(), |l| l.to_string())
    }

    /// `empty` without rules yet; `partial` while a rule waits for its module
    /// (the catalogue is complete, the evidence is not); otherwise `complete`
    /// when every rule produced evidence, `unavailable` when none did,
    /// `partial` in between.
    fn block_state(&self, block: Block) -> &'static str {
        let rules: Vec<&Evaluated> = self
            .audit
            .rules
            .iter()
            .filter(|e| e.rule.block == block)
            .collect();
        let unavailable = rules
            .iter()
            .filter(|e| e.outcome.status == Status::Unavailable)
            .count();
        match (rules.len(), unavailable) {
            (0, _) => "empty",
            _ if rules.iter().any(|e| waits(e)) => "partial",
            (_, 0) => "complete",
            (n, u) if n == u => "unavailable",
            _ => "partial",
        }
    }
}

/// `1 human, cadence mid, services few, customers`; an unavailable measure
/// says so instead of a value.
fn dimensions(
    humans: &Measure,
    cadence: &Measure,
    services: &Measure,
    criticality: &Measure,
) -> String {
    let humans = match humans.value.as_u64() {
        Some(1) => "1 human".to_owned(),
        Some(n) => format!("{n} humans"),
        None => format!("humans {}", humans.tier),
    };
    let criticality = match criticality.value.as_str() {
        Some("undeclared") => "criticality undeclared".to_owned(),
        Some(name) => name.to_owned(),
        None => format!("criticality {}", criticality.tier),
    };
    format!(
        "{humans}, cadence {}, services {}, {criticality}",
        cadence.tier, services.tier
    )
}

/// The label `ci-health.minutes-budget` puts before its minutes sample.
const MINUTES_LABEL: &str = "CI minutes this month (a sample, not billing): ";

/// A rule's state as one word of the fleet table.
fn state(e: &Evaluated) -> &'static str {
    match e.outcome.status {
        _ if waits(e) => "waiting",
        Status::Passed => "passed",
        Status::Failed => "failed",
        Status::Unavailable => "unavailable",
        Status::NotRequired => "not required",
    }
}

impl Fleet {
    /// The Markdown fleet report: a header with the owner, the date, the window
    /// and the token's login; one table sorted by repository; one section per
    /// repository with its audit lines and remediations; "Not audited".
    pub fn markdown(&self) -> String {
        let mut out = format!(
            "# Fleet audit {owner}\n\nAudited at {now} over a {WINDOW_DAYS}-day window against the {STANDARD} standard, read as {identity}. Exit code {code}.\n\n",
            owner = self.owner.name,
            now = self.now,
            identity = self.identity,
            code = self.exit_code(),
        );
        if self.audited.is_empty() {
            out.push_str("No repository was audited.\n");
        } else {
            out.push_str(
                "| Repository | Profile | Required | Reached | Gap | Posture failures | CI minutes (sample) | Deployment frequency | Lead time | Open incidents | Post-merge corrections | Cost per change | Unavailable | Waiting |\n\
                 |---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n",
            );
            for audited in &self.audited {
                out.push_str(&audited.fleet_row());
                out.push('\n');
            }
        }
        for audited in &self.audited {
            let b = &audited.budget;
            out.push_str(&format!(
                "\n## {}\n\nExit code {}; {} of {} calls{}.\n\n```text\n",
                audited.repo,
                audited.exit_code(true),
                b.api_calls,
                b.limit,
                if b.exhausted {
                    ", budget exhausted"
                } else {
                    ""
                },
            ));
            for line in audited.lines() {
                out.push_str(&line);
                out.push('\n');
            }
            out.push_str("```\n");
        }
        out.push_str("\n## Not audited\n\n");
        if self.not_audited.is_empty() && self.unread.is_empty() {
            out.push_str("Every listed repository was audited.\n");
        }
        for n in &self.not_audited {
            out.push_str(&format!("- {}: {}\n", n.repo, n.reason));
        }
        for line in &self.unread {
            out.push_str(&format!("- {line}\n"));
        }
        out
    }

    /// `doctor --fleet --json`: schema 1, each repository as `doctor --json`
    /// reports its audit, with its exit code.
    pub fn json(&self) -> Value {
        let repositories: Vec<Value> = self
            .audited
            .iter()
            .map(|a| {
                let mut audit = a.json();
                audit.insert("exit_code".into(), json!(a.exit_code(true)));
                Value::Object(audit)
            })
            .collect();
        let not_audited: Vec<Value> = self
            .not_audited
            .iter()
            .map(|n| json!({ "repo": n.repo, "reason": n.reason, "error": n.error }))
            .collect();
        json!({
            "schema": 1,
            "fleet": self.owner.name,
            "audited_at": self.now.to_string(),
            "window_days": WINDOW_DAYS,
            "identity": self.identity,
            "include_archived": self.include_archived,
            "repositories": repositories,
            "not_audited": not_audited,
            "unread": self.unread,
            "exit_code": self.exit_code(),
        })
    }
}

/// A rule that waits for a module: unavailable by construction, counted apart.
fn waits(e: &Evaluated) -> bool {
    matches!(e.rule.feasible_by, Milestone::WaitsFor(_))
}

/// The remediation as doctor prints it. A module this build does not compile in
/// (a planned one) is named as such, so the user is never sent to a module that
/// `install --module` would refuse (#1260).
fn remediation(remediation: &Remediation) -> String {
    match remediation {
        Remediation::Module { id } if !crate::modules::all().iter().any(|m| m.id() == *id) => {
            format!("module {id} (planned; not in this build)")
        }
        Remediation::Module { id } => format!("module {id}"),
        Remediation::Command { text } => format!("run `{text}`"),
        Remediation::Manual { step, instructions } => format!("manual step {step}: {instructions}"),
    }
}

/// Every remediation of a failed rule, joined in order.
fn remediations(e: &Evaluated) -> String {
    e.remediations()
        .iter()
        .map(remediation)
        .collect::<Vec<_>>()
        .join("; ")
}

fn rule_json(e: &Evaluated) -> Value {
    let status = match e.outcome.status {
        Status::Passed => "passed",
        Status::Failed => "failed",
        Status::Unavailable => "unavailable",
        Status::NotRequired => "not-required",
    };
    json!({
        "id": e.rule.id,
        "block": e.rule.block.id(),
        "level": e.rule.level.to_string(),
        "required": e.required,
        "status": status,
        "evidence": e.outcome.evidence,
        "reason": e.outcome.reason,
        "remediation": (e.outcome.status == Status::Failed).then(|| remediations(e)),
    })
}

#[cfg(test)]
mod remediation_tests {
    use super::*;

    /// A remediation naming a module this build lacks says so (#1260); a compiled
    /// module is named plainly.
    #[test]
    fn a_module_the_build_lacks_is_printed_as_planned() {
        assert_eq!(
            remediation(&Remediation::Module { id: "delivery" }),
            "module delivery (planned; not in this build)"
        );
        assert_eq!(
            remediation(&Remediation::Module { id: "ci-baseline" }),
            "module ci-baseline"
        );
    }
}
