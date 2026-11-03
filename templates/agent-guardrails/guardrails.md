# Agent guardrails

Last verified: 2026-11-03

Instructions in `AGENTS.md`, `CLAUDE.md` and skills are read by agents; they are not
enforced. This guide lists the rules the agent host enforces in this repository, what
stays prose, and how a rule is lifted. The installer module `agent-guardrails` renders
the files named here as data; it never runs them. In `.claude/settings.json` it owns
only the entries it adds (the deny rules, the hook entries and, with `merge-guard`, one
ask rule); every other key and
entry belongs to the project.

## What is enforced, by host

Each cell says how the rule holds on that host: **enforced** (the host refuses the
action), **configured** (the host's own setting, which this setup does not write), or
**documented** (this guide only). Codex and OpenCode never get a `verify`-on-stop
guarantee from this setup: for them the server-side required check is the barrier.

| Rule | Claude Code | Codex | OpenCode |
|---|---|---|---|
| `verify` green before the agent stops | Enforced: Stop hook `.claude/hooks/stop_verify.sh`, registered by the installer | Documented: not claimed; the required check (`ci-baseline`, `repo-baseline`) is the barrier | Documented: not claimed; the required check is the barrier |
| No `Read` or `Edit` of `.env` files, `secrets/**` and key files | Enforced: `permissions.deny`, anchored at the filesystem root (`//**/`) so it holds in worktrees and any other directory too, in every permission mode including `bypassPermissions`; the merge-guard hook also denies a Bash command that names a secret `.env` file | Documented: no setting denies reading a path; keep secrets out of the checkout | Enforced: `opencode.json` sets the same paths to `deny` for `read` and `edit` (which covers its write tool) |
| No `Edit` of `.agent-setup/lock.json` and the protected paths | Enforced: `permissions.deny`, anchored at the filesystem root, worktrees included | Documented | Enforced: `opencode.json` `edit` |
| No `Read` or `Edit` of the held-out tests (`ci-baseline`'s `heldout_dir`, else `tests/heldout`) | Enforced: `permissions.deny`, in every profile | Documented: no equivalent rule; the protected path (a held-out change needs the `human-approved` label in CI) and the separate held-out job | Enforced: `opencode.json` `read` and `edit` |
| No writes to `.git` and the host's own configuration | Documented: no deny rule for them in this setup | Configured: in `workspace-write`, `.git`, `.agents`, `.codex` and `.aws` are read-only, recursively | Documented |
| Network | Configured by the project (Claude Code sandbox), not by this setup | Configured: `workspace-write` runs with network off unless enabled | Documented |
| Merge only on green | Enforced: server-side required check and the merge-guard hook | Enforced: server-side required check | Enforced: server-side required check |
| `human-approved` is set only by a person | Enforced over the commands it can read, a brake and not a barrier: the merge-guard hook denies the commands it can read that set the label, `gh pr edit <n> [--repo <owner>/<repo>] --add-label human-approved` included, because in a real session under `bypassPermissions` the `permissions.ask` rule showed no prompt; a command it cannot read is not stopped. `required` counts the label only when its last `labeled` event is a person's, not an App's or a bot's, so a session on your own token counts as you: run agent sessions on the agents' App token, and set the label on GitHub under your own login | Enforced in CI: `required` counts the label only when a person added it; set it on GitHub under your own login | Enforced in CI: `required` counts the label only when a person added it; `--auto` approves `ask`, so set it on GitHub under your own login |

Deny rules cover the agent's file tools (`Read`, `Grep`, `Glob`, `Edit`, `Write`,
`MultiEdit`, `NotebookEdit`) and the file commands Claude Code recognizes in Bash, such
as `cat`, `head`, `tail`, `sed`, `tee` and redirections. They do not cover a program
that opens a file itself, such as `python3 -c "open('.env')"`: for `.env` files the
merge-guard hook denies a command that names one, and anything stronger needs the
Claude Code sandbox, which stays the project's choice. Every deny rule is written
`//**/<path>`: a `./` rule holds only under the session's directory, so a session in
the main checkout could read a `.env`, or edit the lock, a workflow or a held-out
test, in a worktree beside it
(https://code.claude.com/docs/en/permissions#how-path-patterns-match, read 2026-11-01).

The held-out tests are the exam the agent is measured against, so it can neither open,
search nor edit them. Two things stay outside the rule: a program that
opens a held-out file itself without the sandbox, as for secrets; and the output of the
held-out command, which the agent may run and read (the verdict, not the questions).
Codex has no equivalent rule: it relies on the protected path and the separate held-out
job in CI. OpenCode enforces it through `opencode.json`.

Codex reads hooks from `<repo>/.codex/hooks.json` once the project's `.codex/` layer
is trusted, and a `Stop` hook may ask it to continue; this setup ships no Codex hook,
so nothing above claims one.

In `opencode.json` the installer owns only its deny patterns under `permission.read`
and `permission.edit`, as it does with its entries in `.claude/settings.json`: every
other key and pattern stays the project's, a deleted pattern is added again by the
next install, a pattern whose value was changed refuses the install, and a deny list
that grows reaches the file on the next install. A file with comments is not JSON and
refuses; such a project copies the patterns by hand. OpenCode matches a pattern against the
repository-relative path and its `*` crosses `/`, so `//**/.env` becomes `.env` and
`*/.env`, `//**/secrets/**` becomes `secrets/*` and `*/secrets/*` (observed with OpenCode 1.18.35 in a
session, 2026-10-29). The rules cover OpenCode's file tools, not shell
commands such as `cat .env`.

Sources, read 2026-10-29: Codex, https://learn.chatgpt.com/docs/agent-approvals-security
(protected paths, network), https://learn.chatgpt.com/docs/sandboxing (modes; no
per-path read restriction), https://learn.chatgpt.com/docs/hooks (hooks, trust);
OpenCode, https://opencode.ai/docs/permissions/ (permission keys, patterns, defaults)
and https://opencode.ai/docs/config/ (project `opencode.json`).

## Registration

The installer registers the rules itself: `install --apply` adds the entries of
`.agent-setup/claude-settings.json` (the `permissions.deny` rules, the `hooks.Stop`
entry and, where the merge guard is installed, its `hooks.PreToolUse` entry) to
`.claude/settings.json`, after the project's own entries, and touches nothing else in
the file. An entry already present is left as it is; an entry deleted by hand is
added again by the next install; an entry edited in place refuses the install until
it is restored. `doctor` reports a missing entry as `Managed entries drift` and as the
rule it enforces (`agents.deny-secrets`, `agents.stop-verify`, `agents.heldout-denied`).

The set grows when the setup adds a rule: the held-out entries
`Edit(//**/<heldout_dir>/**)` and `Read(//**/<heldout_dir>/**)` (2026-10-29) are two; the
next install adds them.

The hook, the fragment and the entries are re-rendered by the installer: change the
answers with `brakes configure <repo> agent-guardrails --set ...`, never by
editing the rendered files or the owned entries, which refuses the next install.

## The Stop hook

When the agent wants to stop, the hook runs the `verify` command baked in from
`.agent-setup/project.json` at install time. On failure it exits 2 with the command,
the exit code and the last 60 lines of output, and the agent continues. It never
blocks twice on an identical tree: state lives under the git directory in
`brakes/stop-verify.json`, never versioned. With no `verify` declared it runs
nothing and says so. A changed `verify` reaches the hook on the next install.

## Hosted tools: CLI or API first

Agents reach a hosted tool through its CLI or its API whenever one exists, not through
an MCP server: the merge guard sees shell commands, and every connected MCP server
costs agent context even when unused.

| Tool | How agents reach it | Credential |
|---|---|---|
| GitHub | `gh`, which the merge guard already watches | `gh`'s own login or `GH_TOKEN` in the environment |
| Sentry | Its CLI (`sentry-cli`) or its REST API | The project's token in `SENTRY_AUTH_TOKEN`, scoped read-only where the task only reads |

A token is read from the environment at agent time; no token value is ever written to
the repository, the allowlist or `.mcp.json`. An MCP server is allowed only where no
adequate CLI or API path exists, as an entry in `.agent-setup/mcp-allowlist.json`
with a written purpose and its permissions, read-only by default; the allowlist
changes through `brakes configure`, never by editing the file. The default
catalogue holds one server, `docs` (library documentation lookup, a pinned package
version). Any other server is recorded as `mcp_custom.<name>.<field>` answers
(`purpose`, `transport`, `permissions`, and `command`/`args` or `url`): the purpose is
required, a stdio server runs an exact version, an http URL carries no credential, and
a `read-write` server is reported at Silver until justified. `.mcp.json` is the
project's once seeded; a server in it that the allowlist does not list is a finding.

## Agent environments

`agent_environments` renders the files a hosted agent starts from:
`.github/workflows/copilot-setup-steps.yml` for GitHub Copilot's coding agent
(managed), `scripts/agent-env-setup.sh` to paste into the Codex cloud environment's
setup script, and `.devcontainer/` for Claude Code in a container (seeds, the
project's once written). They install the stack packs' toolchains and dependencies
and never run `verify`. The container allows outbound traffic only to `github.com`,
`api.github.com`, `api.anthropic.com`, `claude.ai` and `platform.claude.com` (claude.ai
sign-in), the stack packs' registries and the hosts of the allowlist's http MCP
servers, as resolved when it starts.

Known limitations of that list:

- `uv python install` downloads Python builds from GitHub release assets, which are
  served from hosts outside `github.com`: a python-uv project adds them to
  `.devcontainer/init-firewall.sh` or uses the image's Python.
- The `docs` MCP server runs through `npx` and calls its own API: in the container it
  needs `registry.npmjs.org` (present only with a node pack) and that API host, which
  the project adds to `.devcontainer/init-firewall.sh` when it uses the server there.

## The model's user and its egress

Every job that runs a model (`cross-review-model`, `implement`) runs it as
`agent-model`, a user without sudo and in no group but its own, on its own copy of
the checkout. The first step after the checkout creates that user and closes its
outbound traffic, IPv4 and IPv6. It keeps loopback, replies and the link's IPv6
discovery, and nothing else. It has no DNS either: no resolver, no systemd-resolved,
no `resolve1` on D-Bus.

No model process holds a credential:
- Codex runs through its action, whose proxy holds only a dummy key. That proxy
  sends Codex's requests to a small filtering proxy the runner starts on loopback,
  which holds the real key and forwards to `api.openai.com`.
- Claude's token belongs to a small proxy the runner starts on loopback. The Claude
  CLI holds a dummy token and sends its requests there, and the proxy forwards them
  to `api.anthropic.com` with the real one.

The step proves the limit as `agent-model`, and proves it again right before the
model, through the filtering proxy:
- a host outside the list is refused;
- names do not resolve;
- UDP does not leave;
- `sudo` is refused;
- the Docker socket is out of reach.

If any of that fails, the job stops before the model starts. The runner's own
traffic (logs, artifacts) is not limited.

Claude runs as the CLI rather than the action, because the action cannot run as
another user. The job keeps what the action checked: a person with write access, or
Dependabot for the review. Its subprocesses run scrubbed of secrets, inside
bubblewrap, allowed by an AppArmor profile for bubblewrap alone. It may not read
`/proc` or let git write files, and its output cannot issue workflow commands.

The Claude proxy forwards only what the pinned CLI was measured to send: `POST`
to the messages endpoints, the betas that version uses, and a body of at most 32 MB.
It refuses MCP servers, code-execution containers and the API's server tools (web
search, web fetch and the like), which would make the API reach out on the model's
behalf. Codex's calls to OpenAI go through the same filter: only `POST
/v1/responses` with the fields Codex was measured to send, and only tools Codex runs
itself. The Responses API's server tools (web search, file search, code
interpreter, computer use, image generation, remote MCP servers) and stored prompts
are refused.

What is still open:
- Services on loopback stay reachable.
- Through the proxy, the model can spend the owner's API quota on the inference
  calls the filter lets through.
- In `implement`, the model reaches no package registry, so a project whose tests
  need one cannot run them inside the agent's job.

## The reviewer's key

By default the reviewer's key (`OPENAI_API_KEY`, `CLAUDE_CODE_OAUTH_TOKEN` or
`DEEPINFRA_API_KEY`) is a repository secret. A repository with a `production`
environment fails `posture.no-repo-secrets-with-production` while any secret sits
at repository level. Answer `review_environment` (for example
`configure --set review_environment=ci-review`) and `cross-review-model`, the only
job that reads the key, declares `environment: ci-review`; the step
`review-secret-present` then looks for the key in that environment. Give the
environment no branch restriction: pull requests run the job, and a branch policy
would refuse them. Each run is recorded as a deployment to that environment, never
to `production`. Use a key of its own there, so the one that pull requests can
reach can be revoked alone. Dependabot's pull requests still read only the
Dependabot secrets. On a private repository, environments need GitHub Pro, Team or
Enterprise.

## Unattended issue to pull request

Off by default. With `unattended` answered true, `.github/workflows/agentic-implement.yml`
runs when a person with write access labels an issue `unattended_label`
(`agent:ready` by default):

1. `implement` runs the pinned Claude Code CLI with `unattended_prompt`, the project's
   own implement entry point, plus the issue. Its token only reads, so the agent can
   neither push, label, approve nor merge. It commits on `agent/<issue>`, within `--max-turns` and
   45 minutes. It reads the issue as it was when labelled; later edits and other
   people's comments never reach it. The tools it may use without a prompt are the
   file tools and `git add|commit`, plus the allow rules of `.claude/settings.json`.
   It may never write under `.git/`, and the deny rules always win.
2. `publish` runs no agent. It pushes `agent/<issue>` and opens the pull request.
3. GitHub holds that pull request's checks until a person with write access selects
   "Approve workflows to run". From then on, `required`, `cross-review` and the
   ruleset apply as to any pull request.

Why the checks wait: a pull request opened or updated with the workflow token
(`GITHUB_TOKEN`) creates its `pull_request` runs for `opened`, `synchronize` and `reopened`
in an approval-required state, and only a person with write access starts them; other
events made with that token create no run at all. Source: GitHub,
"Triggering a workflow from a workflow",
https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow
(read 2026-10-29). That approval is the intended gate, so no dispatch and no App
token are added: an App token would start the checks unattended, but it is a second
write credential in the run.

Both jobs declare `cache-mode: none`, and neither restores nor saves a cache entry:
nothing cached reaches the agent, and the agent leaves nothing for a later run.

Two owner steps come first. One creates the `CLAUDE_CODE_OAUTH_TOKEN` secret. The
other ticks "Allow GitHub Actions to create and approve pull requests" in the
repository's Actions settings. That switch also lets every workflow token approve pull
requests. An approval by `github-actions[bot]` never counts as a code owner's, so a
ruleset that counts plain approvals must also require code-owner review.
Labelling an issue means trusting its text as the agent's instructions: label only
issues you have read.

## Spend caps and identity

Every agent workflow this setup renders carries its caps: `timeout-minutes` on the job
(`cross-review` 15, `agentic-implement` 45), a `concurrency` group (the workflow's, or
one per issue) and `--max-turns` where the model has one (Claude: 30 for the review,
`unattended_max_turns` for the implementer; Codex exposes no turn or budget cap, so
its timeout is the cap). No `--max-budget-usd` is rendered until its amount is
measured. `agents.workflow-caps` (Silver) audits every workflow of the repository,
hand-written ones included: an agent job without `timeout-minutes`, without a
`concurrency` group or, for Claude, without `--max-turns` is a finding.

In P2 and P3 agents act through one GitHub App per organization, never through a
personal access token. `doctor` lists the step `agent-app` (permissions: Contents,
Pull requests and Issues read and write; Checks and Metadata read; no Workflows, no
Administration; installed on selected repositories only, never on all repositories)
and the two secrets it needs, by name only (`AGENT_APP_ID`, `AGENT_APP_PRIVATE_KEY`;
the installer never reads a value). The ruleset keeps no bypass actors, so the App is
never one. `agents.identity` (Silver, P2 and P3) reports an agent job that references
a secret named like a personal access token (`*_PAT`, `GH_TOKEN`); it is a heuristic
and says so.

## Lifting a rule

A deny rule has no exception syntax. A task that must touch a protected path, such as
`.github/workflows/**` in P2 and P3, is done by a human, or in a session whose
project settings a human changed for that branch. Agents never lift a deny rule and
never edit `.claude/settings.json` to do so.

## Definition of done

The pull request template rendered by `repo-baseline` carries the definition-of-done
checkboxes; this module does not render that template. A green Stop hook is local
evidence, not the merge decision: the required check on the pull request decides.
