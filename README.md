# brakes

`brakes` installs and audits the mechanical brakes that make a coding agent's work pass
the same gates whether or not the agent cooperates: hooks run by the agent's environment,
repository controls, and GitHub checks. It renders them from the commands and answers a
repository declares, for any language, stack, agent host and model provider, and it
audits any repository against the same rules, whether `brakes` installed it or not.

It covers enforcement only. It does not decide where work is planned or how a team works:
it ships no engineering guide, no workflow framework and no instruction prose beyond what a
brake needs, and it never runs a project's commands.

Home: <https://github.com/gemba-app/brakes>. License: [Apache-2.0](LICENSE).

## Example

A repository whose tests run with `make test`, given the brakes for Claude Code:

```sh
cargo install --locked --git https://github.com/gemba-app/brakes

mkdir -p ~/.config/brakes
echo '{"schema": 1, "owner": "octo-dev", "write_allowlist": ["octo-dev/*"]}' \
  > ~/.config/brakes/config.json                     # who you are, what brakes may write

cd toy                                               # a clone of octo-dev/toy
mkdir -p .agent-setup
echo '{"purpose": "A toy service.", "commands": {"verify": "make test"}}' \
  > .agent-setup/project.json                        # what it is, how it is verified

brakes install . --preset personal-paas \
  --module stack-packs --module repo-baseline --module ci-baseline \
  --module merge-guard --module agent-guardrails --apply
```

The install writes files you review and commit like any change:

| Written | What it does |
|---|---|
| `.github/workflows/ci.yml` | CI on every pull request: one aggregate job, `required`, over `make test` and the other gates |
| `.github/rulesets/main.json` | the default-branch ruleset: `required` must pass, no bypass; `brakes apply . --remote` sends it to GitHub |
| `.claude/settings.json`, `.claude/hooks/` | the agent's hooks: refuse `gh pr merge` on red, run `make test` before the agent may stop, deny secrets and the lock |
| `AGENTS.md`, `docs/agent-setup/` | the rules the agent reads, inside a block `brakes` manages |
| `.github/` templates, `dependabot.yml`, `SECURITY.md` | pull request and issue templates, dependency updates with a cooldown |
| `.agent-setup/lock.json` | what was installed and the digest of every file, so a hand edit is never overwritten |

From then on, when the agent tries to end its turn with a failing test, the Stop hook
runs the declared command and sends the agent back to work:

```text
verify failed (exit 2, 1s): make test
1 failed: test_total
make: *** [test] Error 1
```

`brakes doctor .` says what is still missing, each line with its fix.
[Getting started](#getting-started) goes through the same steps one at a time.

## Requirements

- **Rust 1.99 or later** and Cargo, to build from source. There are no prebuilt binaries
  yet.
- **GitHub only.** The host adapter reads and writes GitHub (`github.com`); other hosts
  are not supported.
- **The GitHub CLI, `gh`, signed in**, for everything that reads or writes the remote
  repository: `doctor --remote`, `doctor --fleet`, `apply --remote`. Local `install` and
  `doctor` need neither `gh` nor a network.
- **Agent hosts.** Claude Code gets every local brake (the merge guard, the Stop hook,
  the deny rules). OpenCode gets the deny rules through `opencode.json`. Codex relies on
  the server-side required checks; the per-host table is in the guide `agent-guardrails`
  installs.
- **A model provider key for the cross-review** (brake 5), stored as a repository secret
  of the reviewer you choose: `OPENAI_API_KEY` for Codex (the default),
  `CLAUDE_CODE_OAUTH_TOKEN` for Claude, `DEEPINFRA_API_KEY` for DeepSeek. With
  `review_family: none` no key is needed and brake 5 is off.

## Install

```sh
cargo install --locked --git https://github.com/gemba-app/brakes
```

Without a configuration `brakes` diagnoses and plans but refuses every write; the next
section writes the smallest one.

## Getting started

On a clone of one of your GitHub repositories:

```sh
cd my-repo
brakes doctor .
```

`doctor` reads only the working tree, needs no configuration and writes nothing. On a
repository nothing has touched yet it ends like this (shortened; exit code 1 while a
`basic` rule fails):

```text
NOT READY: Setup not installed: project profile missing
...
FAIL        [basic:baseline.purpose-declared] .agent-setup/project.json missing → manual step declare-purpose: ...
FAIL        [basic:baseline.verify-declared] .agent-setup/project.json missing → manual step declare-verify: ...
FAIL        [basic:ci-health.workflow-exists] no workflow under .github/workflows → module ci-baseline
FAIL        [bronze:governance.pr-template-and-issue-forms] no pull request template in .github/, ... → module repo-baseline
UNAVAILABLE [basic:posture.default-branch-protected] ... is unavailable without --remote
...
NEXT Basic: 10 rules (...)
```

Every `FAIL` names its fix: a module of `brakes`, or a manual step. `UNAVAILABLE` rules
need the remote (`doctor --remote`, with `gh` signed in) or a module that is not built
yet.

To write, `brakes` needs a configuration that names you and the repositories it may
change. The smallest one, in `~/.config/brakes/config.json` (or
`$XDG_CONFIG_HOME/brakes/config.json`):

```json
{
  "schema": 1,
  "owner": "<your-github-login>",
  "write_allowlist": ["<your-github-login>/*"]
}
```

The repository declares what it is and how it is verified, in `.agent-setup/project.json`;
`purpose` and `commands.verify` are the only required fields:

```json
{
  "purpose": "One sentence: what this repository is for.",
  "commands": { "verify": "make test" }
}
```

Then plan an installation, read it, and apply it:

```sh
brakes install . --preset personal-paas \
  --module stack-packs --module repo-baseline --module ci-baseline \
  --module merge-guard --module agent-guardrails          # plan only: prints every file
brakes install . --preset personal-paas \
  --module stack-packs --module repo-baseline --module ci-baseline \
  --module merge-guard --module agent-guardrails --apply
brakes doctor .
```

The plan lists every file with its owner (`PLAN .github/workflows/ci.yml
[managed:ci-baseline]`), every remote step it cannot take from your machine
(`STEP [unavailable:repo-baseline] repo-settings — ...`) and ends with `Plan only; no
writes.` `--apply` writes the same list and records it in `.agent-setup/lock.json`. The
second `doctor` shows what is left, each line with its fix, for example:

```text
FAIL        [basic:baseline.criticality-declared] criticality undeclared in .agent-setup/project.json (audited as internal) → manual step declare-criticality: ...
FAIL        [basic:security.secrets-gate] No secrets gate: no gitleaks job and secret scanning off → module security
```

Commit the files, open a pull request, and add the cross-review key (Requirements). The
repository's settings and its ruleset are written by `brakes apply . --remote`, which
reads and writes GitHub through `gh` and only for a repository your `write_allowlist`
names. `brakes presets` lists the presets; `brakes doctor . --json` gives the same
diagnosis as JSON.

## Use

```sh
brakes install <repo>                         # plan only: prints every change
brakes install <repo> --module stack-packs --module ci-baseline --apply
brakes configure <repo> security --set deps=true --apply
brakes doctor <repo> [--remote] [--json]      # read-only diagnosis and audit
brakes doctor --fleet <org-or-user>           # audit every repository, read-only
brakes adopt <repo>                           # what would bring an untouched repository under the brakes
brakes apply <repo> --remote                  # write the repository's settings, rulesets and environments
brakes remove <repo> <module> [--apply]
brakes mcp                                    # the same operations for one agent host, over stdio
```

Every write is planned and printed first; `doctor` and every plan run without a
configuration, writes and remote reads need one. A repository declares its commands in
`.agent-setup/project.json` and each module's answers in `.agent-setup/modules/<id>.json`;
`brakes` records what it installed, and the digest of every managed file, in
`.agent-setup/lock.json`, and refuses to overwrite a file someone edited by hand.

## The brakes

| # | Brake | Module | Rendered as |
|---|---|---|---|
| 1 | CI required on every pull request | `ci-baseline` | a workflow whose single aggregate job, `required`, needs every verification job, rendered from the declared commands |
| 2 | Protected default branch, no bypass for administrators | `repo-baseline` | a ruleset with `enforcement: active` and no bypass actors, applied with `apply --remote` |
| 3 | Never merge on red, also locally | `merge-guard` | the `guard pre-bash` hook for the agent host, light and full mode |
| 4 | Touching CI needs approval | `repo-baseline`, `ci-baseline` | CODEOWNERS over `.github/workflows/` with code-owner review in the ruleset; protected paths that need the `human-approved` label |
| 5 | Cross-family model review as a gate | `agent-guardrails` | a review by another model family, in two jobs, inside the aggregate |
| 6 | Human review when the team has more than one person | `repo-baseline` | the review count of the ruleset, from the repository's profile |
| 7 | Held-out tests | `ci-baseline`, `agent-guardrails` | a held-out directory and job, denied to agents for reading and editing |
| 8 | Coverage over changed lines | `security` | a `diff-coverage` job over the stack pack's per-file report against the merge base |
| 9 | Characterisation tests before touching old code | `security` | the same job fails a change to a file no test executed |
| 10 | User-visible tests | `qa` | Hurl for the API, Playwright for the web with screenshot comparison; screenshot baselines are a protected path |
| 11 | Property-based tests and mutation on the diff | `stack-packs`, `ci-baseline`, `security` | property and mutation recipes per pack, held-out properties with a fresh recorded seed, an opt-in `mutation-diff` job with a minimum score |
| 12 | "Done" means verification green | `agent-guardrails` | a Stop hook that runs the declared `verify` command |
| 13 | Hard prohibitions | `agent-guardrails` | deny rules for secret paths, lockfiles and the held-out directory |
| 14 | Scanners in CI | `security` | gitleaks, OSV-Scanner, Semgrep and Trivy jobs, each tool pinned by checksum |
| 15 | Pinned actions and dependencies, with a cooldown | `security`, `repo-baseline`, `stack-packs` | SHA pins, a shared pin table, Dependabot or Renovate cooldown |
| 16 | Exceptions with an expiry | `security` | `security-exceptions.json` and the rules that read it |
| 17 | Workflows without open doors | `agent-guardrails`, `security` | `agents.workflow-injection`, `zizmor` in `workflow-lint` |
| 18 | Least privilege in CI | `ci-baseline` | `permissions: contents: read` at the top, grants per job, `ci.permissions-least` |
| 19 | Periodic audit | `auditor` | `doctor`, `doctor --fleet`, levels and profiles |
| 20 | Delivery and CI health figures | `auditor` | DORA and CI-health measures |
| 21 | Unattended work passes the same brakes | `agent-guardrails` | the unattended workflow behind the ruleset, `agents.unattended-gated` |

The modules rest on the `engine` (plan, apply, doctor, ownership classes, the lock),
`questions` (answers files, presets, a terminal interview and an MCP server) and the host
adapter (GitHub reads and gated writes).

## Relation with OpenSSF Scorecard

[OpenSSF Scorecard](https://github.com/ossf/scorecard) audits a repository's supply-chain
posture. `brakes` installs brakes and audits them: it takes ideas from Scorecard and adds
the part that concerns the agent, the gates an agent's work must pass on the developer's
machine and in CI.

- **Taken.** Binary-Artifacts detection, as Scorecard does it: a tracked file whose first
  1024 bytes are not text and that starts with an executable or package magic, or carries
  one of Scorecard's extensions, is a finding (`security.binary-artifacts`).
- **Not taken.** The Fuzzing check as evidence: it recognises OSS-Fuzz, ClusterFuzzLite,
  Go fuzzing and a short list of property-based libraries, so a Python or Rust project
  with property tests scores as if it had none. `brakes` renders property and mutation
  recipes per stack instead (brake 11). Nor does it install the Scorecard action: on a
  private repository it needs GitHub Advanced Security.
- **Covered otherwise.** Scorecard's workflow checks (Dangerous-Workflow,
  Token-Permissions) by [zizmor](https://github.com/zizmorcore/zizmor) in the rendered
  `workflow-lint` job and by `agents.workflow-injection`; its posture checks by auditor
  rules that `doctor` evaluates.

| Scorecard check | In `brakes` |
|---|---|
| Binary-Artifacts | `security.binary-artifacts`, the same detection |
| Branch-Protection | brakes 2 and 6: the ruleset `brakes` writes, audited by `posture.default-branch-protected`, `posture.required-check-enforced`, `posture.no-unlisted-bypass-actors`, `posture.human-approval-required` |
| CI-Tests | brake 1: one aggregate required check over the declared commands (`ci.aggregate-present`, `ci.required-is-aggregate`) |
| Code-Review | brake 6 for human review; brake 5 adds a review by another model family as a required check. Scorecard counts neither bot nor AI reviews, and in `brakes` the model review is added to human review, never a substitute |
| Dangerous-Workflow | brake 17: zizmor in `workflow-lint`, `agents.workflow-injection` |
| Dependency-Update-Tool | brake 15: a Dependabot or Renovate seed with a cooldown (`governance.dependency-updates-with-cooldown`, `ci.dependabot-actions`) |
| Fuzzing | not taken (above); brake 11 instead |
| Pinned-Dependencies | brake 15: `posture.actions-pinned`, `stack.lockfile-present`, `stack.lockfile-not-enforced`, `stack.image-by-digest`, `security.scanner-unpinned` |
| SAST | brake 14: a Semgrep job (`security.sast-gate`) |
| Security-Policy | a `SECURITY.md` seed (`repo-baseline`); `security.private-vulnerability-reporting` on a public repository |
| Token-Permissions | brake 18: `ci.permissions-least`, and zizmor |
| Vulnerabilities | brake 14: an OSV-Scanner job (`security.deps-gate`), `posture.no-stale-critical-alerts` |
| SBOM, Signed-Releases | for deployed images only: `security.sbom-scanned`, `security.attestation-verified` |
| CII-Best-Practices, Contributors, Maintained, License, Packaging, Webhooks | not covered: they describe a project's community, publication or badges, not a gate a change must pass |

Brakes with no Scorecard counterpart, all about the agent or the change it proposes:

| # | Brake | Why Scorecard cannot see it |
|---|---|---|
| 3 | Never merge on red, also locally | a hook in the agent's host refuses the merge command before it reaches GitHub |
| 4 | Touching CI needs approval | Scorecard asks for code-owner review of everything; `brakes` puts a person in front of the paths that change the gates themselves (partly overlapping) |
| 5 | Cross-family model review as a gate | a required check whose reviewer is a model of another family than the author |
| 7 | Held-out tests | tests the agent can neither read nor edit, run in their own job |
| 8, 9 | Coverage over changed lines; characterisation first | judged per change against the merge base, not per repository |
| 10 | User-visible tests | API and browser tests with screenshot baselines as a protected path |
| 12 | "Done" means verification green | the agent's Stop hook runs the declared `verify` command |
| 13 | Hard prohibitions | deny rules in the agent host for secrets, lockfiles and the held-out tests |
| 16 | Exceptions with an expiry | every waiver carries a reason, an issue and a date |
| 20 | Delivery and CI health figures | DORA and CI-health measures in `doctor` |
| 21 | Unattended work passes the same brakes | an agent running in CI is held to the ruleset and the required checks |

## Configuration

One file, never inside a target repository: `$XDG_CONFIG_HOME/brakes/config.json`, or
`--config <path>`, or a file embedded at build time with `BRAKES_EMBEDDED_CONFIG=<path>`.
It names the GitHub host, your login, the repositories `brakes` may write to, the
identities it must refuse, and your own runners and presets. `brakes` ships no value for
any of them. The contract is in [`docs/design.md`](docs/design.md#configuration-contract).

## Develop

```sh
cargo build --locked
cargo test --locked
git diff --check && cargo fmt --all -- --check && cargo clippy --locked --all-targets -- -D warnings
```

The design is in [`docs/design.md`](docs/design.md) and the decisions it depends on in
[`docs/decisions.md`](docs/decisions.md). Contributors and agents start at
[`AGENTS.md`](AGENTS.md).

## Neutrality

The tree carries no person, organization, project or infrastructure name other than its
own home. A required CI check, `neutrality`, enforces it with keyed hashes of a list that
is not in the repository.
