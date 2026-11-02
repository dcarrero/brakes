# brakes

`brakes` installs and audits the mechanical brakes that make a coding agent's work pass
the same gates whether or not the agent cooperates: hooks run by the agent's environment,
repository controls, and GitHub checks. It renders them from the commands and answers a
repository declares, for any language, stack, agent host and model provider, and it
audits any repository against the same rules, whether `brakes` installed it or not.

It covers enforcement only. It does not decide where work is planned or how a team works:
it ships no engineering guide, no workflow framework and no instruction prose beyond what a
brake needs. Your CI runs your commands, once; `brakes` installs and audits the gates around
it and never runs them: when a repository has no CI it guides you to one you own, when it
has one it audits it and proposes patches it never applies, and its own jobs only judge
what your CI produced.

Home: <https://github.com/gemba-app/brakes>. License: [Apache-2.0](LICENSE).

## Example

A Rust crate with no CI yet, given its CI and the brakes for Claude Code:

```sh
mkdir -p ~/.config/brakes
echo '{"schema": 1, "owner": "octo-dev", "write_allowlist": ["octo-dev/*"]}' \
  > ~/.config/brakes/config.json                     # who you are, what brakes may write

cd toy                                               # a clone of octo-dev/toy
mkdir -p .agent-setup
echo '{"purpose": "A toy service.", "commands": {"verify": "cargo test --locked"}, "criticality": "internal"}' \
  > .agent-setup/project.json                        # what it is, how it is verified

brakes doctor .                                      # FAIL ci-health.workflow-exists → run `brakes ci init .`
brakes ci init . --no-input --apply                  # your CI, written once: it is yours from now on
brakes install . --preset personal-paas \
  --module stack-packs --module repo-baseline --module ci-baseline \
  --module security --module merge-guard --module agent-guardrails --apply
```

They write files you review and commit like any change:

| Written | What it does |
|---|---|
| `.github/workflows/ci.yml` | **your** CI, a seed `brakes` writes once and never rewrites: one job per declared command (here `verify`, which also uploads its coverage data), `diff-coverage`, and the aggregate `required`, which fails unless every job succeeded |
| `.github/workflows/agentic-security.yml` | the brakes' judges, which never run your commands: the scope of the change, the secrets, dependency and static scans, and the aggregate `agentic-required`, which also refuses a change to a protected path without the `human-approved` label |
| `.github/workflows/agentic-coverage.yml` | the coverage judge your CI calls: it reads the coverage data your test job uploaded and fails a changed line no test executed; it runs no test |
| `.github/rulesets/main.json` | the default-branch ruleset: `required` and `agentic-required` must pass, no bypass; `brakes apply . --remote` sends it to GitHub |
| `.claude/settings.json`, `.claude/hooks/` | the agent's hooks: refuse `gh pr merge` on red, run `cargo test --locked` before the agent may stop, deny secrets and the lock |
| `AGENTS.md`, `docs/agent-setup/` | the rules the agent reads, inside a block `brakes` manages |
| `.github/` templates, `dependabot.yml`, `SECURITY.md` | pull request and issue templates, dependency updates with a cooldown |
| `.gitleaks.toml`, `osv-scanner.toml`, `.agent-setup/security-exceptions.json` | the scans' configuration; every exception carries an expiry |
| `.agent-setup/lock.json` | what was installed and the digest of every file `brakes` manages, so a hand edit is never overwritten |

On a pull request your tests run once, in your CI's job; `diff-coverage` judges the data
that job uploaded. From then on, when the agent tries to end its turn with a failing test,
the Stop hook runs the declared command on the agent's machine and sends it back to work:

```text
verify failed (exit 101, 4s): cargo test --locked
```

`brakes doctor .` says what is still missing, each line with its fix.
[Getting started](#getting-started) goes through the same steps one at a time.

## Requirements

- **A prebuilt binary** for Linux (x86_64, aarch64) or macOS (aarch64), checked against
  `SHA256SUMS` and its attestation (see Install), or **Rust 1.99 or later** to build from
  source.
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

Each release attaches a binary for `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`
and `aarch64-apple-darwin`, a `SHA256SUMS` file and a build-provenance attestation. With
the GitHub CLI (`gh`):

```sh
V=v0.5.2 T=aarch64-apple-darwin   # or x86_64-unknown-linux-gnu, aarch64-unknown-linux-gnu
gh release download "$V" -R gemba-app/brakes -p "brakes-$V-$T.tar.gz" -p SHA256SUMS
shasum -a 256 --ignore-missing -c SHA256SUMS   # prints "brakes-…tar.gz: OK"
gh attestation verify "brakes-$V-$T.tar.gz" -R gemba-app/brakes
tar -xzf "brakes-$V-$T.tar.gz"
install -m 0755 brakes ~/.local/bin/brakes     # any directory on your PATH
brakes --version
```

`gh attestation verify` exits 0 only when the archive was built by this repository's
release workflow; a modified archive fails. On another platform, build from source with
Rust 1.99 or later:

```sh
cargo install --locked --git https://github.com/gemba-app/brakes --tag v0.5.2
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
FAIL        [basic:ci-health.workflow-exists] no workflow under .github/workflows → run `brakes ci init .`; module ci-baseline
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
`purpose` and `commands.verify` are the only required fields, and `criticality` (`internal`,
`customers` or `personal-data-or-payments`) sets how strict the audit is:

```json
{
  "purpose": "One sentence: what this repository is for.",
  "commands": { "verify": "cargo test --locked" },
  "criticality": "internal"
}
```

**No CI yet?** `brakes ci init .` writes yours. It detects the stack (here `Cargo.toml`),
proposes the commands you left `null` and never invents one, and asks only what it cannot
detect; `--no-input` takes the proposals as they are. It prints the plan; `--apply` writes it:

```sh
brakes ci init .                     # plan only
brakes ci init . --no-input --apply
```

It writes `.github/workflows/ci.yml` once, as a seed: one job per declared command, the
coverage upload in the test job, `diff-coverage` and the aggregate `required`. From then on
the file is yours; `brakes` never rewrites it, and `brakes doctor . --propose` audits it and
prints each fix as a diff it never applies. A repository that already has a CI skips this
step: `doctor --propose` audits that CI the same way.

Then plan an installation, read it, and apply it:

```sh
brakes install . --preset personal-paas \
  --module stack-packs --module repo-baseline --module ci-baseline \
  --module security --module merge-guard --module agent-guardrails          # plan only: prints every file
brakes install . --preset personal-paas \
  --module stack-packs --module repo-baseline --module ci-baseline \
  --module security --module merge-guard --module agent-guardrails --apply
brakes doctor .
```

The plan lists every file with its owner (`PLAN .github/workflows/agentic-security.yml
[managed:ci-baseline]`, and `SKIP .github/workflows/ci.yml [seed:ci-baseline]` for your CI), every remote step it cannot take from your machine
(`STEP [unavailable:repo-baseline] repo-settings — ...`) and ends with `Plan only; no
writes.` `--apply` writes the same list and records it in `.agent-setup/lock.json`. The
second `doctor` shows what is left, each line with its fix, for example:

```text
FAIL        [silver:ci.heldout-present] No held-out tests yet: the heldout job is in the aggregate and tests/heldout holds no test → module ci-baseline
FAIL        [silver:stack.toolchain-pinned] app `root` (rust at .) has no toolchain pin (rust-toolchain.toml) → module stack-packs
FAIL        [bronze:baseline.security.hooks-installed] .git/hooks/pre-commit is absent → manual step hooks-installed: Install the pre-commit hook in this clone
```

Held-out tests are tests the agent can neither read nor edit; you write them under
`tests/heldout/` and answer `heldout_command`, and the `heldout` job runs them.

Commit the files, open a pull request, and add the cross-review key (Requirements). On
that pull request `required` (your CI) and `agentic-required` (the judges) report. The
repository's settings and its ruleset are written by `brakes apply . --remote`, which
reads and writes GitHub through `gh` and only for a repository your `write_allowlist`
names. `brakes presets` lists the presets; `brakes doctor . --json` gives the same
diagnosis as JSON.

## Use

```sh
brakes ci init <repo> [--no-input] [--apply]  # a repository without CI: write yours, once
brakes install <repo>                         # plan only: prints every change
brakes install <repo> --module stack-packs --module ci-baseline --apply
brakes configure <repo> security --set deps=true --apply
brakes doctor <repo> [--remote] [--json]      # read-only diagnosis and audit
brakes doctor <repo> --propose                # also each fix to your CI, as a diff it never applies
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
| 1 | CI required on every pull request | `ci-baseline` | your CI, seeded once by `brakes ci init` or your own, audited by `doctor --propose`; its aggregate `required` and the judges' `agentic-required` are both required |
| 2 | Protected default branch, no bypass for administrators | `repo-baseline` | a ruleset with `enforcement: active` and no bypass actors, applied with `apply --remote` |
| 3 | Never merge on red, also locally | `merge-guard` | the `guard pre-bash` hook for the agent host, light and full mode |
| 4 | Touching CI needs approval | `repo-baseline`, `ci-baseline` | CODEOWNERS over `.github/workflows/` with code-owner review in the ruleset; protected paths that need the `human-approved` label |
| 5 | Cross-family model review as a gate | `agent-guardrails` | a review by another model family, in two jobs, inside the aggregate |
| 6 | Human review when the team has more than one person | `repo-baseline` | the review count of the ruleset, from the repository's profile |
| 7 | Held-out tests | `ci-baseline`, `agent-guardrails` | a held-out directory and job, denied to agents for reading and editing |
| 8 | Coverage over changed lines | `security`, `stack-packs` | your test job uploads its coverage data with the stack pack's recipe; `agentic-coverage.yml` judges it against the merge base and runs no test |
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
