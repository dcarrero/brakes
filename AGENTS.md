# brakes

This repository is `brakes`, a Rust tool that installs and audits the mechanical brakes of
a repository: agent-host hooks, repository controls and GitHub checks. Read
[`README.md`](README.md) for what it does, [`docs/design.md`](docs/design.md) before
changing a module, and [`docs/decisions.md`](docs/decisions.md) before changing a policy.

## Rules for every change

- Plan and verify with the declared commands before you claim a change is done:
  `cargo test --locked`, then
  `git diff --check && cargo fmt --all -- --check && cargo clippy --locked --all-targets -- -D warnings`.
  Report what you ran and what you did not.
- Write the failing test first. A refusal, a finding text or a rendered file changes only
  with a test that names it; goldens change only in the pull request that explains why.
- Never weaken a check to get green: no skipped or deleted test, no lowered threshold, no
  suppressed lint, no `continue-on-error` or `|| true` in a rendered workflow.
- Rendering is pure. A module sees its context and nothing else: no network, no project
  command, no file outside the repository it renders for.
- Every write goes through the plan, the scope guard and, for a host write, the write
  gate. Never add a second path that writes.
- Generated files are never edited by hand: rerun the tool or the test that writes them.
- The product knows nothing about where work is planned or how a team works. Do not add an
  engineering guide, a workflow framework, a planning convention or instruction prose a
  brake does not need.
- No configuration value in the tree. A user, organization, runner label or private preset
  is configuration the user supplies; tests build theirs with a synthetic configuration.
  The `neutrality` check refuses any other name.
- Add no dependency without a decision in `docs/decisions.md`.
- A decision that changes a policy is written in `docs/decisions.md` first, then the code.

## Where things are

| Path | What |
|---|---|
| `orchestration/installer/src/engine/` | the module system: plan, apply, doctor, ownership classes, the lock |
| `orchestration/installer/src/modules/` | the modules that render brakes |
| `orchestration/installer/src/auditor/` | the rule catalogue, levels, profiles and the fleet audit |
| `orchestration/installer/src/host/` | the GitHub host adapter: reads, the read gate and the write gate |
| `orchestration/installer/src/questions/` | answers files, presets and the terminal interview |
| `orchestration/installer/src/mcp/` | the MCP server: the same operations for one agent host, over stdio |
| `orchestration/installer/src/guard/` | the never-merge-on-red hook |
| `templates/` | module data: fragments, seeds, goldens, presets and the shared pin table |
| `orchestration/installer/tests/` | integration tests, synthetic fixtures and goldens |

<!-- brakes:begin -->
Before imitating neighbouring code, read `docs/agent-setup/technical-debt.md`: it lists the patterns not to copy.
<!-- brakes:end -->
