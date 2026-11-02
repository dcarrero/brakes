# Technical debt

Last verified: 2026-11-02

Read this before imitating neighbouring code. It lists what an agent or a new
contributor must not copy even though the repository contains it, the commands that
work inside the development container, and the shortcuts that expire. The installer
seeds this file once; afterwards it belongs to the project and is edited by hand.

Keep every entry short and dated. When an entry is retired, delete it in the pull
request that closes its issue. When a section is empty, say so with a date, so a
reader can tell "nothing known" from "nobody looked".

## Patterns not to imitate

One row per pattern: where it lives, why it exists, what to do instead and the issue
that retires it.

| Pattern | Where | Why it exists | Instead | Retiring issue |
|---|---|---|---|---|
| Hand-rolled argument parsing, one style per subcommand (2026-11-02) | `orchestration/installer/src/main.rs` (`run`, the early `args.first()` dispatch), and each `cli` in `guard/`, `host/cli.rs`, `auditor/fleet.rs`, `auditor/adopt.rs`, `mcp/`, `questions/mod.rs` | No dependency without a decision in `docs/decisions.md`, so there is no parser crate | Add a flag to the existing parser of its subcommand and to `USAGE` in `main.rs`; no new dispatch branch, no new parsing style | none yet |
| `workflow: generate` and `_reusable-verify.yml` (2026-11-02) | `WorkflowMode::Generate` in `modules/ci_baseline/model.rs`, the deprecation note in `modules/ci_baseline/mod.rs`, `modules/ci_baseline/reusable.rs` (called only under `generate`) | Installs from before `seed` keep their output until they migrate | `workflow: seed` or `existing`: the project's CI runs its commands (decision of 2026-11-02 in `docs/decisions.md`); never a job `brakes` owns that runs them | #25 |
| Coverage pack fields `command` and `diff_command` (2026-11-02) | `CoverageRecipe` in `modules/stack_packs/pack.rs`; `render_command` and `render_diff_command` are called only from `tests/stack_packs_interfaces.rs` | Left behind when the coverage jobs stopped running the suite (#22) | Use `upload`, `combine` and `combined_report`; do not render or extend the two fields | none yet |
| A gate check written twice, in shell and in Rust (2026-11-02) | `templates/security/fragments/exceptions-check.sh` with `modules/security/exceptions.rs`, `pii-check.sh` with `modules/security/pii.rs`, `bypass-variable.sh` with `exceptions::bypass` | `doctor` and the in-workflow gate must give the same findings; `tests/security_gate_shell.rs` proves they agree | Keep new logic in the fragment alone, as `modules/ci_baseline/aggregate.rs` does; a new twin only with an agreement test in `tests/security_gate_shell.rs` | none yet |
| `#NNNN` references with three or more digits in comments (2026-11-02) | Over 200 files under `orchestration/installer/src`, `orchestration/installer/tests` and `templates` (`grep -rlE '#[0-9]{3,5}'`) | The code was imported from earlier development (see the intro of `docs/decisions.md`); this repository's issues are two-digit (`git log`) | Cite only an issue of this repository, or the dated decision in `docs/decisions.md` | none yet |
| Golden compare-or-rewrite copied into each test file (2026-11-02) | 20 copies of `if std::env::var_os("UPDATE_GOLDENS").is_some()` across 14 files in `orchestration/installer/tests`; none in `tests/common/mod.rs` | Each module's goldens grew with their own helper | Reuse the helper of the file you are in; change the renderer behind a failing test first, then rerun with `UPDATE_GOLDENS=1` and explain the golden diff in the commit; never rewrite a golden to turn a red test green | none yet |

## Commands that work inside the container

Commands that differ from the declared ones when run in the development container or
an agent environment (missing tools, network limits, paths), with the reason.

| Command | Works instead of | Why |
|---|---|---|

None yet (2026-11-02).

## Shortcuts with an expiry

Temporary exceptions accepted on purpose: what was skipped, who accepted it and the
date after which it must be gone.

| Shortcut | Where | Accepted by | Expires | Retiring issue |
|---|---|---|---|---|

None yet (2026-10-28).
