//! The aggregate `required` job (SPEC-ci-baseline.md, "Aggregate job: exact logic"):
//! the one required status check and the shell that decides it. The logic lives in
//! the fragment alone; the renderer embeds it verbatim and never restates it in Rust.
//!
//! The job runs `if: always()` and needs `scope` and every verification job, because
//! GitHub counts a skipped job as a passing required check while a path-filtered
//! workflow leaves it pending. Its inputs reach the shell through `env:` only:
//! `SCOPE` (`needs.scope.result`), `TIER` (`needs.scope.outputs.tier`), `SKIPPABLE`
//! (`needs.scope.outputs.skippable`, a JSON array of job ids), `NEEDS`
//! (`toJSON(needs)`) and, for rule 3 (the protected-paths gate, #943), `EVENT`
//! (`github.event_name`), `PROTECTED` (`needs.scope.outputs.protected`) and
//! `PR_LABELS` (`toJSON(github.event.pull_request.labels.*.name)`). The label counts
//! only when a person added it (#1255): the script reads the pull request's issue
//! events with `gh api` and the job's token (`PR_NUMBER`, `REPOSITORY`, `GH_TOKEN`),
//! and checks the sender of a run the label triggered (`EVENT_ACTION`, `EVENT_LABEL`,
//! `SENDER_LOGIN`, `SENDER_TYPE`); the job alone gets [`AGGREGATE_PERMISSIONS`].

/// The aggregate job's `permissions:`: both scopes GitHub lists for reading a pull
/// request's issue events, and nothing else (the job checks nothing out).
pub const AGGREGATE_PERMISSIONS: &[(&str, &str)] = &[("issues", "read"), ("pull-requests", "read")];

/// The one required check. repo-baseline renders its ruleset from this constant.
pub const AGGREGATE_CHECK: &str = "required";

/// The aggregate of `agentic-security.yml`, the separate workflow that hosts the
/// contributed jobs under `workflow: existing` (#895): distinct from `required`
/// and from the project's own required check, so the two never collide.
pub const CONTRIBUTED_AGGREGATE_CHECK: &str = "agentic-required";

/// The label a human sets on a pull request that changes a protected path
/// (seeded by repo-baseline, denied to agent sessions by merge-guard).
pub const HUMAN_APPROVED: &str = "human-approved";

/// The single entry of the scope job's `protected` output when the changed files
/// of a pull request could not be listed: the gate fails closed on it.
pub const UNKNOWN_PROTECTED: &str = "<unknown>";

/// The shell of the `required` job, verbatim from
/// `templates/ci-baseline/fragments/required.sh`.
pub const REQUIRED_SH: &str =
    include_str!("../../../../../templates/ci-baseline/fragments/required.sh");
