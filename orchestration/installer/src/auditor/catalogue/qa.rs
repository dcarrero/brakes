//! The `qa.*` rules (SPEC-qa.md, "Auditor rules this module enables"; T10,
//! #1008; T11, #1009), block `qa` after `agents`, at the levels the spec
//! proposes (#873's rule). The four Bronze and the four Silver rules take
//! today's `doctor` findings through [`relabelled`] as `catalogue::modules`
//! does: a reported rule fails; an unreported one is `not-required` where
//! neither a finding nor the job it is about exists (the auditor may not
//! list the checkout), and passes otherwise. `qa.main-green` reads the host
//! under `doctor --remote` (T19, #1018).
use super::baseline::{NO_CHECKOUT, Origin, relabel, relabelled};
use crate::{
    auditor::{
        Cx, WORKFLOWS,
        rules::{Block, Level, Milestone, Outcome, Probe, Profile, Remediation, Required, Rule},
        workflows,
    },
    modules::qa::audit as qa_audit,
};

const ALL: &[Profile] = &[Profile::P1, Profile::P2, Profile::P3];
const QA: &str = "qa";

/// Whether a readable workflow has a QA job (`hurl --test` or `playwright test`).
fn qa_job(cx: &Cx<'_>) -> bool {
    qa_audit::has_qa_job(&workflows::read_all(cx.files))
}

/// Whether today's `doctor` reported the rule `id`.
fn reported(cx: &Cx<'_>, id: &str) -> bool {
    cx.today.is_some_and(|today| {
        today
            .findings
            .iter()
            .any(|f| relabel(f).as_deref() == Some(id))
    })
}

/// Whether a readable workflow has a job calling `hurl --test`.
fn hurl_job(cx: &Cx<'_>) -> bool {
    qa_audit::has_hurl_job(&workflows::read_all(cx.files))
}

/// Whether a readable workflow has a job linting or comparing a contract.
fn contract_job(cx: &Cx<'_>) -> bool {
    qa_audit::has_contract_job(&workflows::read_all(cx.files))
}

/// Whether a readable workflow has a job calling `playwright test`.
fn playwright_job(cx: &Cx<'_>) -> bool {
    qa_audit::has_playwright_job(&workflows::read_all(cx.files))
}

macro_rules! qa_rule {
    ($name:ident, $id:path, $title:literal, $checks:literal, $applies:expr, $why:literal) => {
        qa_rule!($name, $id, Bronze, $title, $checks, $applies, $why);
    };
    ($name:ident, $id:path, $level:ident, $title:literal, $checks:literal, $applies:expr, $why:literal) => {
        pub const $name: Rule = Rule {
            id: $id,
            title: $title,
            block: Block::Qa,
            checks: $checks,
            how: Probe::LocalFile { path: WORKFLOWS },
            level: Level::$level,
            required: Required {
                profiles: ALL,
                when: &[],
            },
            remediation: Remediation::Module { id: QA },
            plan: None,
            feasible_by: Milestone::Nov7,
            evaluate: |cx| {
                let applies: fn(&Cx<'_>) -> bool = $applies;
                if cx.today.is_some() && !reported(cx, $id) && !applies(cx) {
                    return Outcome::not_required($why);
                }
                relabelled(cx, $id, Origin::Checkout)
            },
        };
    };
}

// The Silver rules (T11): `doctor` reports each where it is required (a
// declared service or web app, a spec calling `toHaveScreenshot`, a
// `*-snapshots/` directory) and fails; without a finding they pass where the
// job they are about exists.
qa_rule!(
    API_SMOKE_PRESENT,
    qa_audit::API_SMOKE_PRESENT,
    Silver,
    "API smoke in the aggregate",
    "Where a service is declared, a `.hurl` file runs under `hurl --test` in a job the aggregate needs.",
    hurl_job,
    "no service declared and no job calls hurl --test"
);
qa_rule!(
    WEB_SMOKE_PRESENT,
    qa_audit::WEB_SMOKE_PRESENT,
    Silver,
    "Web journey in the aggregate",
    "Where a web app is declared, a Playwright spec runs under `playwright test` in a job the aggregate needs.",
    playwright_job,
    "no web app declared and no job calls playwright test"
);
qa_rule!(
    SCREENSHOT_BASELINE_PRESENT,
    qa_audit::SCREENSHOT_BASELINE_PRESENT,
    Silver,
    "Screenshot baseline committed",
    "Every spec that calls `toHaveScreenshot` has a `.png` under its `*-snapshots/` directory.",
    playwright_job,
    "no spec calls toHaveScreenshot without a baseline and no job calls playwright test"
);
qa_rule!(
    SNAPSHOTS_PROTECTED,
    qa_audit::SNAPSHOTS_PROTECTED,
    Silver,
    "Screenshot baselines protected",
    "Every `*-snapshots/` directory matches ci-baseline's `protected_paths` and the protected-paths gate passes.",
    playwright_job,
    "no unprotected *-snapshots directory and no job calls playwright test"
);

// `qa.hurl-no-literal-host` applies where a `.hurl` file exists; the auditor
// may not list the checkout, so a clean `.hurl` file outside a repository with
// a QA job reads as `not-required`, never as a pass it did not see.
qa_rule!(
    HURL_NO_LITERAL_HOST,
    qa_audit::HURL_NO_LITERAL_HOST,
    "Hurl files name no host",
    "No request line of a `.hurl` file names `http://` or `https://`; each starts with `{{base_url}}` or another variable.",
    qa_job,
    "no QA job and no .hurl file names a host"
);
qa_rule!(
    TOOLS_PINNED,
    qa_audit::TOOLS_PINNED,
    "QA tools pinned",
    "Hurl is installed by a checksum-verified `run:`, `@playwright/test` is an exact version and `playwright install` names no other.",
    qa_job,
    "no QA job (hurl --test or playwright test) in .github/workflows"
);
qa_rule!(
    NO_SNAPSHOT_UPDATE_IN_CI,
    qa_audit::NO_SNAPSHOT_UPDATE_IN_CI,
    "CI never updates snapshots",
    "No workflow passes `--update-snapshots` or sets `UPDATE_SNAPSHOTS`, and no Playwright config sets `updateSnapshots` but to `missing` or `none`.",
    qa_job,
    "no QA job (hurl --test or playwright test) in .github/workflows"
);
qa_rule!(
    REPORT_ARTIFACT,
    qa_audit::REPORT_ARTIFACT,
    "QA reports kept",
    "Every QA job uploads `playwright-report/` or a JUnit file with `actions/upload-artifact`.",
    qa_job,
    "no QA job (hurl --test or playwright test) in .github/workflows"
);

/// `qa.main-green` (Silver, remote; T19 #1018): with `doctor --remote`, each QA
/// job's latest default-branch run concluded success (`qa::audit::main_green`, on
/// the run listing `ci.main-red` reads); `unavailable` without `--remote`;
/// `not-required` without a QA job, and under `--fleet` like the other module rules.
pub const MAIN_GREEN: Rule = Rule {
    id: "qa.main-green",
    title: "QA jobs green on main",
    block: Block::Qa,
    checks: "The latest default-branch run of each QA job concluded success.",
    how: Probe::Remote {
        id: "workflow-runs",
    },
    level: Level::Silver,
    required: Required {
        profiles: ALL,
        when: &[],
    },
    remediation: Remediation::Module { id: QA },
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: |cx| {
        if cx.today.is_none() {
            return Outcome::not_required(NO_CHECKOUT);
        }
        if !qa_job(cx) {
            return Outcome::not_required(
                "no QA job (hurl --test or playwright test) in .github/workflows",
            );
        }
        if !cx.today.is_some_and(|today| today.remote) {
            return Outcome::unavailable("remote findings run only with doctor --remote");
        }
        qa_audit::main_green(cx)
    },
};

// The contract rules (T17, #1016; SPEC-qa.md, Contracts): `doctor` reports
// each contract no aggregated job lints or compares; without a finding they
// pass where such a job exists and are `not-required` elsewhere.
qa_rule!(
    CONTRACT_LINT,
    qa_audit::CONTRACT_LINT,
    Silver,
    "Contracts linted in the aggregate",
    "A job the aggregate needs lints each OpenAPI 3 or AsyncAPI contract (vacuum, Spectral, Redocly, `asyncapi validate` or `contracts-check.sh`) and names it.",
    contract_job,
    "no contract unlinted and no job lints a contract"
);
qa_rule!(
    CONTRACT_COMPATIBLE,
    qa_audit::CONTRACT_COMPATIBLE,
    Silver,
    "Contracts compared with the base",
    "A job the aggregate needs compares each contract with the base branch (`oasdiff breaking --fail-on`, `asyncapi diff` or `contracts-check.sh`) and names it.",
    contract_job,
    "no contract uncompared and no job compares a contract"
);
