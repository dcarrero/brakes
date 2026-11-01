//! Operations rules (SPEC-auditor.md, "Blocks and feasibility"): each reads a
//! convention another module defines (the delivery smoke run and rollback, the
//! observability uptime footprint, the incidents labels, SLO and runbooks, the
//! continuity backup status and restore drill). Until that module lands every
//! one is `feasible_by: WaitsFor(<module>)`, so the catalogue is complete and
//! `evaluate` reports `unavailable: waits for module <id>`, never `failed`.
use super::waiting;
use crate::auditor::rules::{Block, Level, Milestone, Probe, Profile, Remediation, Required, Rule};

const ALL: Required = Required {
    profiles: &[Profile::P1, Profile::P2, Profile::P3],
    when: &[],
};

/// A rule of this block that waits for `module`, whose probe it declares.
const fn waits(
    id: &'static str,
    title: &'static str,
    checks: &'static str,
    level: Level,
    module: &'static str,
    step: &'static str,
) -> Rule {
    Rule {
        id,
        title,
        block: Block::Operations,
        checks,
        how: Probe::ManualStep { module, step },
        level,
        required: ALL,
        remediation: Remediation::Module { id: module },
        plan: None,
        feasible_by: Milestone::WaitsFor(module),
        evaluate: waiting,
    }
}

pub const POST_DEPLOY_SMOKE: Rule = waits(
    "operations.post-deploy-smoke",
    "Post-deploy smoke",
    "A smoke workflow runs after every production deployment and its latest run succeeded.",
    Level::Silver,
    "delivery",
    "post-deploy-smoke",
);

pub const ROLLBACK_EVIDENCE: Rule = waits(
    "operations.rollback-evidence",
    "Rollback evidence",
    "A rollback deployment or rollback workflow exists and has run.",
    Level::Silver,
    "delivery",
    "rollback",
);

pub const UPTIME_FOOTPRINT: Rule = waits(
    "operations.uptime-footprint",
    "Uptime footprint fresh",
    "The latest run of the uptime workflow, or the uptime commit status, is at most 15 minutes old.",
    Level::Silver,
    "observability",
    "uptime-footprint",
);

pub const INCIDENTS_BOUNDED: Rule = waits(
    "operations.incidents-bounded",
    "Incidents labelled and bounded",
    "Incidents are issues labelled `incident` and at most 2 are open.",
    Level::Silver,
    "incidents",
    "incident-label",
);

pub const RUNBOOK_PER_ALERT: Rule = waits(
    "operations.runbook-per-alert",
    "Runbook per alert",
    "Every alert references a runbook that exists.",
    Level::Silver,
    "incidents",
    "linked-runbooks",
);

pub const SLO_BURN_RATE_VALIDATED: Rule = waits(
    "operations.slo-burn-rate-validated",
    "SLO burn-rate alerts validated",
    "The SLO spec and its burn-rate alerts are validated in CI.",
    Level::Gold,
    "incidents",
    "slo-spec",
);

pub const BACKUP_AGE_WITHIN_RPO: Rule = waits(
    "operations.backup-age-within-rpo",
    "Backup age within RPO",
    "The newest backup the continuity status publishes is younger than the declared RPO.",
    Level::Gold,
    "continuity",
    "backup-age",
);

pub const RESTORE_DRILL_FRESH: Rule = waits(
    "operations.restore-drill-fresh",
    "Restore drill fresh",
    "The latest issue labelled `restore-drill` was closed at most 90 days ago.",
    Level::Gold,
    "continuity",
    "restore-drill",
);
