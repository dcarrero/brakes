//! The static rules the modules declare (`ci.*`, `security.*`, `stack.*`,
//! `agents.*`), at the levels the owner allocated (docs/decisions.md, "Auditor
//! standard v1, amended", #873). Each module's `doctor` check already reports
//! them as `WARNING: <id>: <text>` findings; a rule here takes those findings
//! through [`relabelled`], never evaluating its check a second time, and is
//! `not-required` where `doctor` does not evaluate it ([`Origin`]). The static
//! rules read no host and have no call allowance; ci-baseline's remote rules
//! (slice 2, #783) read it through `ci_baseline::audit` and are listed last
//! in their block with the allowances `rules::ALLOWANCES` records.
use super::baseline::{Origin, relabel, relabelled};
use crate::{
    PROFILE,
    auditor::{
        Cx, WORKFLOWS,
        rules::{
            Block, Condition, Criticality, Level, Milestone, Outcome, Probe, Profile, Remediation,
            Required, Rule, Status,
        },
        workflows,
    },
    modules::{
        agent_guardrails::{audit::heldout_enabled, injection, unattended},
        ci_baseline::audit as ci_audit,
        security::{
            diff_coverage::DIFF_COVERAGE as DIFF_COVERAGE_JOB, exceptions::INVENTORY,
            jobs::COVERAGE_RATCHET as COVERAGE_RATCHET_JOB, pii::PII_PATH,
        },
    },
};

const ALL: &[Profile] = &[Profile::P1, Profile::P2, Profile::P3];
const TEAMS: &[Profile] = &[Profile::P2, Profile::P3];
const P3: &[Profile] = &[Profile::P3];

const CI: &str = "ci-baseline";
const SECURITY: &str = "security";
const STACK: &str = "stack-packs";
const AGENTS: &str = "agent-guardrails";

macro_rules! module_rule {
    ($name:ident, $id:literal, $block:ident, $level:ident, $profiles:expr, $module:expr,
     $origin:expr, $path:expr, $title:literal, $checks:literal) => {
        module_rule!(
            $name,
            $id,
            $block,
            $level,
            $profiles,
            &[],
            $module,
            $origin,
            $path,
            $title,
            $checks
        );
    };
    ($name:ident, $id:literal, $block:ident, $level:ident, $profiles:expr, $when:expr, $module:expr,
     $origin:expr, $path:expr, $title:literal, $checks:literal) => {
        pub const $name: Rule = Rule {
            id: $id,
            title: $title,
            block: Block::$block,
            checks: $checks,
            how: Probe::LocalFile { path: $path },
            level: Level::$level,
            required: Required {
                profiles: $profiles,
                when: $when,
            },
            remediation: Remediation::Module { id: $module },
            plan: None,
            feasible_by: Milestone::Nov7,
            evaluate: |cx| relabelled(cx, $id, $origin),
        };
    };
}

// --- ci (SPEC-ci-baseline.md, "Auditor rules this module enables") ---------------------

module_rule!(
    CI_COMMAND_MISSING,
    "ci.command-missing",
    Ci,
    Basic,
    ALL,
    CI,
    Origin::Installed(CI),
    PROFILE,
    "Answered commands declared",
    "Every command the ci-baseline answers list is declared in `.agent-setup/project.json`."
);
module_rule!(
    CI_AGGREGATE_PRESENT,
    "ci.aggregate-present",
    Ci,
    Basic,
    ALL,
    CI,
    Origin::Workflows,
    WORKFLOWS,
    "Aggregate job present",
    "A job with `if: always()` needs every other job of its workflow."
);
module_rule!(
    CI_JOB_TIMEOUTS,
    "ci.job-timeouts",
    Ci,
    Basic,
    ALL,
    CI,
    Origin::Workflows,
    WORKFLOWS,
    "Jobs time out",
    "Every job declares `timeout-minutes` (callers of reusable workflows excepted)."
);
module_rule!(
    CI_PERMISSIONS_LEAST,
    "ci.permissions-least",
    Ci,
    Bronze,
    ALL,
    CI,
    Origin::Workflows,
    WORKFLOWS,
    "Least workflow permissions",
    "Every workflow grants at most `contents: read` at top level and no checkout persists credentials."
);
/// `ci.workflow-lint`: its static half (a `workflow-lint` job exists) from
/// today's `doctor`; under `doctor --remote` also its remote half (#783): the
/// job succeeded in the latest push run on the default branch. Offline the
/// static verdict stands, so Bronze stays reachable without the host.
pub const CI_WORKFLOW_LINT: Rule = Rule {
    id: "ci.workflow-lint",
    title: "Workflow lint job",
    block: Block::Ci,
    checks: "A `workflow-lint` job exists and, with --remote, succeeded in the latest push run on the default branch.",
    how: Probe::Remote {
        id: "workflows+workflow-runs+jobs",
    },
    level: Level::Bronze,
    required: Required {
        profiles: ALL,
        when: &[],
    },
    remediation: Remediation::Module { id: CI },
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: workflow_lint,
};

fn workflow_lint(cx: &Cx<'_>) -> Outcome {
    let local = relabelled(cx, CI_WORKFLOW_LINT.id, Origin::Workflows);
    let remote = cx.today.is_some_and(|today| today.remote);
    if local.status != Status::Passed || !remote {
        return local;
    }
    ci_audit::workflow_lint_green(cx)
}
module_rule!(
    CI_NO_SELF_HOSTED_LABEL,
    "ci.no-self-hosted-label",
    Ci,
    Bronze,
    ALL,
    CI,
    Origin::Workflows,
    WORKFLOWS,
    "No self-hosted runners",
    "No `runs-on` names a `self-hosted` label."
);
module_rule!(
    CI_HOSTED_MACOS,
    "ci.hosted-macos",
    Ci,
    Bronze,
    ALL,
    CI,
    Origin::Workflows,
    WORKFLOWS,
    "No hosted macOS on pull requests",
    "No job that runs on pull requests uses a hosted `macos-*` runner."
);
module_rule!(
    CI_DEPENDABOT_ACTIONS,
    "ci.dependabot-actions",
    Ci,
    Bronze,
    ALL,
    CI,
    Origin::Workflows,
    ".github/dependabot.yml",
    "Dependabot updates actions",
    "`.github/dependabot.yml` updates the `github-actions` ecosystem."
);
module_rule!(
    CI_HELDOUT_PRESENT,
    "ci.heldout-present",
    Ci,
    Silver,
    ALL,
    CI,
    Origin::Workflows,
    WORKFLOWS,
    "Held-out tests in the required check",
    "`heldout_dir` holds a file and a `heldout` job is in the `needs` of an `if: always()` job."
);
module_rule!(
    CI_PROTECTED_PATHS_GATE,
    "ci.protected-paths-gate",
    Ci,
    Silver,
    ALL,
    CI,
    Origin::Workflows,
    WORKFLOWS,
    "Protected paths gated",
    "A workflow re-runs on `labeled` and `unlabeled` pull requests and its `if: always()` job reads `PR_LABELS` and `PROTECTED`, and who added the label from the issue events with `issues` or `pull-requests` read (#1255)."
);
/// `ci.heldout-properties` (#980), opt-in: `not-required` where
/// `heldout_properties` is not answered true and no workflow has a
/// `heldout-properties` job. The answer arrives as today's `doctor` finding
/// (the answers file is outside the auditor's allowlist, as for
/// `agents.unattended-gated`).
pub const CI_HELDOUT_PROPERTIES: Rule = Rule {
    id: "ci.heldout-properties",
    title: "Held-out properties with a fresh seed",
    block: Block::Ci,
    checks: "A `heldout-properties` job is in the `needs` of an `if: always()` job and a step's `env:` names `HELDOUT_SEED` and `HELDOUT_EXAMPLES`.",
    how: Probe::LocalFile { path: WORKFLOWS },
    level: Level::Silver,
    required: Required {
        profiles: ALL,
        when: &[],
    },
    remediation: Remediation::Module { id: CI },
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: heldout_properties,
};

fn heldout_properties(cx: &Cx<'_>) -> Outcome {
    let id = CI_HELDOUT_PROPERTIES.id;
    let reported = cx.today.is_some_and(|today| {
        today
            .findings
            .iter()
            .any(|f| relabel(f).as_deref() == Some(id))
    });
    let present = || {
        workflows::read_all(cx.files)
            .into_iter()
            .any(|(_, parsed)| {
                parsed.is_ok_and(|wf| {
                    wf.job(crate::modules::ci_baseline::render::HELDOUT_PROPERTIES_JOB)
                        .is_some()
                })
            })
    };
    if cx.today.is_some() && !reported && !present() {
        return Outcome::not_required(
            "heldout_properties is not true and no workflow has a heldout-properties job",
        );
    }
    relabelled(cx, id, Origin::Workflows)
}
module_rule!(
    CI_PROJECT_CI_STALE,
    "ci.project-ci-stale",
    Ci,
    Bronze,
    ALL,
    CI,
    Origin::Installed(CI),
    PROFILE,
    "Profile CI fields match the answers",
    "`ci.runners`, `ci.required_checks` and `ci.tiers` of `.agent-setup/project.json` agree with the ci-baseline answers."
);

// The remote rules of ci-baseline (SPEC-ci-baseline.md, slice 2; #783), last in
// the block: they read the host, the cheapest first.

pub const CI_REQUIRED_IS_AGGREGATE: Rule = Rule {
    id: "ci.required-is-aggregate",
    title: "Required checks are the aggregate",
    block: Block::Ci,
    checks: "The status checks the default branch requires, through rulesets and classic protection together, are exactly the aggregate check (`required`, or the recorded `aggregate_check`).",
    how: Probe::Remote {
        id: "branch-protection+rulesets",
    },
    level: Level::Silver,
    required: Required {
        profiles: ALL,
        when: &[],
    },
    remediation: Remediation::Module { id: CI },
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: ci_audit::required_is_aggregate,
};

pub const CI_MAIN_RED: Rule = Rule {
    id: "ci.main-red",
    title: "Default branch green",
    block: Block::Ci,
    checks: "The latest conclusive push run on the default branch of the workflow that declares the aggregate job succeeded.",
    how: Probe::Remote {
        id: "workflow-runs",
    },
    level: Level::Silver,
    required: Required {
        profiles: ALL,
        when: &[],
    },
    remediation: Remediation::Manual {
        step: "fix-main",
        instructions: "Fix or revert the change that turned the default branch red; a red default branch blocks every merge behind it.",
    },
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: ci_audit::main_red,
};

pub const CI_MINUTES_MONTH: Rule = Rule {
    id: "ci.minutes-month",
    title: "CI minutes within the monthly budget",
    block: Block::Ci,
    checks: "The minutes billed in the last 30 days, each job rounded up to the minute and read from a sample of the completed runs, are within the recorded `minutes_budget`.",
    how: Probe::Remote {
        id: "workflow-runs+jobs",
    },
    level: Level::Gold,
    required: Required {
        profiles: ALL,
        when: &[],
    },
    remediation: Remediation::Manual {
        step: "cut-ci-minutes",
        instructions: "Merge short jobs into one (each job bills a whole minute), skip the verification jobs on docs-only pull requests, and retire hosted macOS or scheduled workflows that bill without verifying a change; or raise minutes_budget with a reason.",
    },
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: ci_audit::minutes_month,
};

// --- security (SPEC-security.md, "Auditor rules this module enables") -----------------

// The two rules with a remote half live with the remote rules (#801).
pub use super::security_remote::{SECURITY_BYPASS_UNREGISTERED, SECURITY_SECRETS_FULL_HISTORY};

module_rule!(
    SECURITY_SECRETS_GATE,
    "security.secrets-gate",
    Security,
    Basic,
    ALL,
    SECURITY,
    Origin::Checkout,
    WORKFLOWS,
    "Secrets gate",
    "A workflow job runs gitleaks or betterleaks."
);
module_rule!(
    SECURITY_DEPS_GATE,
    "security.deps-gate",
    Security,
    Bronze,
    ALL,
    SECURITY,
    Origin::Checkout,
    WORKFLOWS,
    "Lockfile vulnerability scan",
    "When a lockfile exists, a job scans lockfiles with OSV-Scanner, Trivy or Grype."
);
module_rule!(
    SECURITY_SCANNER_UNPINNED,
    "security.scanner-unpinned",
    Security,
    Bronze,
    ALL,
    SECURITY,
    Origin::Checkout,
    WORKFLOWS,
    "Scanners pinned",
    "Every scanner a workflow uses is pinned by SHA or checksum."
);
module_rule!(
    SECURITY_TRIVY_COMPROMISED_VERSION,
    "security.trivy-compromised-version",
    Security,
    Bronze,
    ALL,
    SECURITY,
    Origin::Checkout,
    WORKFLOWS,
    "No compromised Trivy",
    "No Trivy pin or `trivy-action` ref falls in the March 2026 compromise window."
);
module_rule!(
    SECURITY_BYPASS_INVENTORY_VALID,
    "security.bypass-inventory-valid",
    Security,
    Bronze,
    ALL,
    SECURITY,
    Origin::Checkout,
    INVENTORY,
    "Bypass inventory valid",
    "`.agent-setup/security-exceptions.json`, when present, parses with every entry complete."
);
module_rule!(
    SECURITY_BYPASS_EXPIRED,
    "security.bypass-expired",
    Security,
    Silver,
    ALL,
    SECURITY,
    Origin::Checkout,
    INVENTORY,
    "No expired bypass",
    "No exception in the inventory, `.trivyignore.yaml` or `osv-scanner.toml` is past its expiry or its duration bound."
);
module_rule!(
    SECURITY_BINARY_ARTIFACTS,
    "security.binary-artifacts",
    Security,
    Bronze,
    ALL,
    SECURITY,
    Origin::Checkout,
    INVENTORY,
    "No tracked binary artifact",
    "No tracked file is a compiled executable or package unless a workflow validates it (`gradle-wrapper.jar`) or an `allowlist` entry registers `binary-artifacts#<path>`."
);
// T10 (#798): the levels #873 point 5 reserves for the slice.
module_rule!(
    SECURITY_SAST_GATE,
    "security.sast-gate",
    Security,
    Silver,
    &[],
    &[Condition::CriticalityAtLeast(Criticality::Customers)],
    SECURITY,
    Origin::Checkout,
    WORKFLOWS,
    "Static analysis job",
    "A workflow job runs Semgrep or CodeQL; required from criticality `customers`."
);
module_rule!(
    SECURITY_CONTAINER_GATE,
    "security.container-gate",
    Security,
    Silver,
    ALL,
    SECURITY,
    Origin::Checkout,
    WORKFLOWS,
    "Container scan",
    "Where a Dockerfile exists, a job scans with Trivy or Grype (image, filesystem or config)."
);
// T12 (#800): the level #873 point 5 reserves for the slice.
module_rule!(
    SECURITY_PII_DECLARED,
    "security.pii-declared",
    Security,
    Silver,
    &[],
    &[Condition::CriticalityAtLeast(
        Criticality::PersonalDataOrPayments
    )],
    SECURITY,
    Origin::Checkout,
    PII_PATH,
    "PII declared",
    "Under criticality `personal-data-or-payments`, `.agent-setup/pii.yaml` is present, valid and non-empty and `docs/runbooks/dsar.md` exists."
);

/// `security.coverage-ratchet` (#799): Gold and opt-in. `doctor` reports its
/// static half only where `coverage_ratchet` is answered `true` (the answers
/// file is outside the auditor's allowlist, #966), so the rule is judged where
/// that finding exists or a workflow has a `coverage-ratchet` job, and
/// `not-required` elsewhere.
pub const SECURITY_COVERAGE_RATCHET: Rule = Rule {
    id: "security.coverage-ratchet",
    title: "Coverage ratchet",
    block: Block::Security,
    checks: "Where the ratchet is answered, `.agent-setup/coverage.json` and a `coverage-ratchet` job exist.",
    how: Probe::LocalFile { path: WORKFLOWS },
    level: Level::Gold,
    required: Required {
        profiles: ALL,
        when: &[],
    },
    remediation: Remediation::Module { id: SECURITY },
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: coverage_ratchet,
};

fn coverage_ratchet(cx: &Cx<'_>) -> Outcome {
    let id = SECURITY_COVERAGE_RATCHET.id;
    let reported = cx.today.is_some_and(|today| {
        today
            .findings
            .iter()
            .any(|f| relabel(f).as_deref() == Some(id))
    });
    let job = || {
        workflows::read_all(cx.files)
            .into_iter()
            .filter_map(|(_, parsed)| parsed.ok())
            .any(|wf| wf.jobs.iter().any(|j| j.id == COVERAGE_RATCHET_JOB))
    };
    if cx.today.is_some() && !reported && !job() {
        return Outcome::not_required(
            "coverage_ratchet is not answered true and no coverage-ratchet job exists",
        );
    }
    relabelled(cx, id, Origin::Checkout)
}

/// Gold and opt-in (#979): `not-required` unless the recorded `security` answers
/// turn `mutation_diff` on; then `doctor`'s finding decides it.
pub const SECURITY_MUTATION_GATE: Rule = Rule {
    id: "security.mutation-gate",
    title: "Mutation testing on the diff",
    block: Block::Security,
    checks: "When `mutation_diff` is true, a `mutation-diff` job that runs `cargo mutants --in-diff` or `mutmut run` is in the `needs` of an `if: always()` job.",
    how: Probe::LocalFile { path: WORKFLOWS },
    level: Level::Gold,
    required: Required {
        profiles: ALL,
        when: &[],
    },
    remediation: Remediation::Module { id: SECURITY },
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: mutation_gate,
};

fn mutation_gate(cx: &Cx<'_>) -> Outcome {
    if cx.today.is_some() && !mutation_diff_on(cx) {
        return Outcome::not_required("security's mutation_diff is not true");
    }
    relabelled(cx, SECURITY_MUTATION_GATE.id, Origin::Installed(SECURITY))
}

/// The recorded `security` answers turn `mutation_diff` on.
fn mutation_diff_on(cx: &Cx<'_>) -> bool {
    cx.files
        .read(".agent-setup/modules/security.json")
        .ok()
        .flatten()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .and_then(|v| v["answers"]["mutation_diff"].as_bool())
        == Some(true)
}

/// `security.diff-coverage` (#978): Silver, static. `doctor` reports it only
/// where stack-packs records an app whose pack has a per-file coverage
/// report and `coverage_changed_lines` is not `false` (answers the auditor's
/// allowlist does not admit, #966), so the rule is judged where that finding
/// exists or a workflow has a `diff-coverage` job, and `not-required` elsewhere.
pub const SECURITY_DIFF_COVERAGE: Rule = Rule {
    id: "security.diff-coverage",
    title: "Changed-line coverage",
    block: Block::Security,
    checks: "A `diff-coverage` job in the `needs` of an `if: always()` job runs `diff-cover --fail-under` and the characterization-first check.",
    how: Probe::LocalFile { path: WORKFLOWS },
    level: Level::Silver,
    required: Required {
        profiles: ALL,
        when: &[],
    },
    remediation: Remediation::Module { id: SECURITY },
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: diff_coverage_rule,
};

fn diff_coverage_rule(cx: &Cx<'_>) -> Outcome {
    let id = SECURITY_DIFF_COVERAGE.id;
    let reported = cx.today.is_some_and(|today| {
        today
            .findings
            .iter()
            .any(|f| relabel(f).as_deref() == Some(id))
    });
    let job = || {
        workflows::read_all(cx.files)
            .into_iter()
            .filter_map(|(_, parsed)| parsed.ok())
            .any(|wf| wf.job(DIFF_COVERAGE_JOB).is_some())
    };
    if cx.today.is_some() && !reported && !job() {
        return Outcome::not_required(
            "no app with a per-file coverage report and no diff-coverage job",
        );
    }
    relabelled(cx, id, Origin::Checkout)
}

// --- stack (SPEC-stack-packs.md, "Auditor rules declared by this module") -------------

/// The answers that name the apps the app and image rules read.
const STACK_ANSWERS: &str = ".agent-setup/modules/stack-packs.json";

module_rule!(
    STACK_UNCONFIGURED,
    "stack.unconfigured",
    Stack,
    Basic,
    ALL,
    STACK,
    Origin::Checkout,
    STACK_ANSWERS,
    "Detected stacks configured",
    "Every stack detected in the checkout is recorded by the stack-packs answers."
);
module_rule!(
    STACK_LOCKFILE_PRESENT,
    "stack.lockfile-present",
    Stack,
    Basic,
    ALL,
    STACK,
    Origin::Installed(STACK),
    STACK_ANSWERS,
    "Lockfile present",
    "Every app the answers name has its lockfile."
);
module_rule!(
    STACK_LOCKFILE_NOT_ENFORCED,
    "stack.lockfile-not-enforced",
    Stack,
    Basic,
    ALL,
    STACK,
    Origin::Installed(STACK),
    STACK_ANSWERS,
    "Lockfile enforced",
    "Every declared `test` and `verify` that names the pack's tool passes its strict lockfile flag."
);
module_rule!(
    STACK_TOOLCHAIN_PINNED,
    "stack.toolchain-pinned",
    Stack,
    Silver,
    ALL,
    STACK,
    Origin::Installed(STACK),
    STACK_ANSWERS,
    "Toolchain pinned",
    "Every app the answers name pins its toolchain."
);
module_rule!(
    STACK_IMAGE_BY_DIGEST,
    "stack.image-by-digest",
    Stack,
    Silver,
    ALL,
    STACK,
    Origin::Installed(STACK),
    "Dockerfile",
    "Images by digest",
    "Every `FROM` of an image in a Dockerfile under an app path names a digest and not `latest`."
);
module_rule!(
    STACK_IMAGE_NONROOT,
    "stack.image-nonroot",
    Stack,
    Silver,
    ALL,
    STACK,
    Origin::Installed(STACK),
    "Dockerfile",
    "Images run as non-root",
    "The final stage of every Dockerfile under an app path sets a `USER` other than root."
);
module_rule!(
    STACK_IMAGE_ARBITRARY_UID,
    "stack.image-arbitrary-uid",
    Stack,
    Gold,
    P3,
    STACK,
    Origin::Installed(STACK),
    "Dockerfile",
    "Images run under an arbitrary uid",
    "The final stage sets a numeric `USER` and every `COPY` and `ADD` is owned by group 0."
);

// --- agents (SPEC-agent-guardrails.md, "Doctor and auditor rules") -------------------

const SETTINGS: &str = ".claude/settings.json";

module_rule!(
    AGENTS_DENY_SECRETS,
    "agents.deny-secrets",
    Agents,
    Basic,
    ALL,
    AGENTS,
    Origin::Installed(AGENTS),
    SETTINGS,
    "Secret reads denied",
    "`.claude/settings.json` registers the deny rules for secrets."
);
module_rule!(
    AGENTS_STOP_VERIFY,
    "agents.stop-verify",
    Agents,
    Bronze,
    ALL,
    AGENTS,
    Origin::Installed(AGENTS),
    SETTINGS,
    "Stop hook runs verify",
    "The Stop verify hook is registered and runs the `verify` `.agent-setup/project.json` declares."
);
module_rule!(
    AGENTS_PROTECTED_PATHS,
    "agents.protected-paths",
    Agents,
    Bronze,
    TEAMS,
    AGENTS,
    Origin::Installed(AGENTS),
    SETTINGS,
    "Protected paths denied",
    "`.claude/settings.json` denies edits to the lock and to `.github/workflows`."
);
module_rule!(
    AGENTS_MCP_ALLOWLIST,
    "agents.mcp-allowlist",
    Agents,
    Bronze,
    ALL,
    AGENTS,
    Origin::Checkout,
    ".mcp.json",
    "MCP servers allowlisted",
    "Every server in `.mcp.json` matches an entry of `.agent-setup/mcp-allowlist.json`."
);
module_rule!(
    AGENTS_TECHNICAL_DEBT,
    "agents.technical-debt",
    Agents,
    Bronze,
    ALL,
    AGENTS,
    Origin::Installed(AGENTS),
    "docs/agent-setup/technical-debt.md",
    "Technical debt listed",
    "`docs/agent-setup/technical-debt.md` exists with a `Last verified` date within `guide_verification_days`."
);
module_rule!(
    AGENTS_READABLE_SECRETS,
    "agents.readable-secrets",
    Agents,
    Basic,
    ALL,
    AGENTS,
    Origin::Checkout,
    ".worktreeinclude",
    "No readable secrets",
    "No tracked path is a secret file and `.worktreeinclude` lists none."
);
module_rule!(
    AGENTS_CROSS_REVIEW,
    "agents.cross-review",
    Agents,
    Silver,
    ALL,
    AGENTS,
    Origin::Installed(AGENTS),
    WORKFLOWS,
    "Cross-family review required",
    "A reviewer of the other model family is answered and its `cross-review-model` and `cross-review` jobs are in the aggregate's `needs`."
);

module_rule!(
    AGENTS_WORKFLOW_CAPS,
    "agents.workflow-caps",
    Agents,
    Silver,
    ALL,
    AGENTS,
    Origin::Checkout,
    WORKFLOWS,
    "Agent workflows capped",
    "Every job that runs an agent has `timeout-minutes`, a `concurrency` group and, for Claude, `--max-turns`."
);
module_rule!(
    AGENTS_IDENTITY,
    "agents.identity",
    Agents,
    Silver,
    TEAMS,
    AGENTS,
    Origin::Checkout,
    WORKFLOWS,
    "Agents act through the App",
    "No agent job references a secret named like a personal access token (a heuristic); the step `agent-app` is its own rule."
);

/// `agents.unattended-gated` (#946): judged in any checkout, managed or not, but
/// `not-required` where `unattended` is not answered true and no workflow starts an
/// agent from an issue label (the spec's table).
pub const AGENTS_UNATTENDED_GATED: Rule = Rule {
    id: "agents.unattended-gated",
    title: "Unattended agent gated",
    block: Block::Agents,
    checks: "A workflow that starts an agent from an issue label is gated by the label, capped and triggered by nothing else.",
    how: Probe::LocalFile { path: WORKFLOWS },
    level: Level::Silver,
    required: Required {
        profiles: ALL,
        when: &[],
    },
    remediation: Remediation::Module { id: AGENTS },
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: unattended_gated,
};

fn unattended_gated(cx: &Cx<'_>) -> Outcome {
    if cx.today.is_some() && !unattended_applies(cx) {
        return Outcome::not_required(
            "unattended is not true and no workflow starts an agent from an issue label",
        );
    }
    relabelled(cx, AGENTS_UNATTENDED_GATED.id, Origin::Checkout)
}

/// A workflow is in the rule's scope, or today's `doctor` reported the rule: it
/// reads the module's answers itself, so `unattended: true` arrives as its
/// missing-workflow finding; the answers file is outside the auditor's
/// allowlist and never read here (spec, "as built"; #966).
fn unattended_applies(cx: &Cx<'_>) -> bool {
    let reported = cx.today.is_some_and(|today| {
        today
            .findings
            .iter()
            .any(|f| relabel(f).as_deref() == Some(AGENTS_UNATTENDED_GATED.id))
    });
    reported
        || workflows::read_all(cx.files)
            .into_iter()
            .any(|(_, parsed)| parsed.is_ok_and(|wf| unattended::in_scope(&wf)))
}

/// `agents.heldout-denied` (#945; both entries since #982): judged where agent-guardrails is installed and
/// ci-baseline's `heldout` is true, which its `heldout` job stands for; `not-required`
/// elsewhere (the spec's table).
pub const AGENTS_HELDOUT_DENIED: Rule = Rule {
    id: "agents.heldout-denied",
    title: "Held-out tests denied to agents",
    block: Block::Agents,
    checks: "`.claude/settings.json` denies edits and reads of ci-baseline's held-out directory.",
    how: Probe::LocalFile { path: SETTINGS },
    level: Level::Silver,
    required: Required {
        profiles: ALL,
        when: &[],
    },
    remediation: Remediation::Module { id: AGENTS },
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: heldout_denied,
};

fn heldout_denied(cx: &Cx<'_>) -> Outcome {
    if cx.today.is_some() && !heldout_enabled(cx.files) {
        return Outcome::not_required("ci-baseline's heldout is not true (no heldout job)");
    }
    relabelled(cx, AGENTS_HELDOUT_DENIED.id, Origin::Installed(AGENTS))
}

/// `agents.workflow-injection` (#972; "CI hardening for agent workflows", point 6):
/// judged in any checkout, managed or not; `not-required` where no workflow job runs
/// an agent, whether or not agent-guardrails is in the lock (the spec's table).
pub const AGENTS_WORKFLOW_INJECTION: Rule = Rule {
    id: "agents.workflow-injection",
    title: "Agent workflows hardened",
    block: Block::Agents,
    checks: "Every workflow job that runs an agent has no untrusted trigger or interpolation, no write scope, no wildcard trigger allowance, no foreign token, no permission bypass, no cache and no persisted credential.",
    how: Probe::LocalFile { path: WORKFLOWS },
    level: Level::Bronze,
    required: Required {
        profiles: ALL,
        when: &[],
    },
    remediation: Remediation::Module { id: AGENTS },
    plan: None,
    feasible_by: Milestone::Nov7,
    evaluate: workflow_injection,
};

fn workflow_injection(cx: &Cx<'_>) -> Outcome {
    let applies = || {
        workflows::read_all(cx.files)
            .into_iter()
            .any(|(_, parsed)| parsed.is_ok_and(|wf| injection::in_scope(&wf)))
    };
    if cx.today.is_some() && !applies() {
        return Outcome::not_required("no workflow job runs an agent");
    }
    relabelled(cx, AGENTS_WORKFLOW_INJECTION.id, Origin::Checkout)
}
