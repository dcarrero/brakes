# Design — brakes

`brakes` installs and audits the mechanical brakes that make a coding agent's work pass
the same gates whether or not the agent cooperates: hooks run by the agent's environment,
repository controls, and GitHub checks, rendered from a declared set of commands and
answers, for any language, stack, agent host and model provider. It covers enforcement
only: it knows nothing about where work is planned or how a team works, and it ships no
engineering guide, workflow framework or instruction prose beyond what a brake needs.
The project's CI runs the project's commands; `brakes` installs and audits the gates around
it and never runs them (decision of 2026-11-02).

This document states what the code does, module by module. The decisions it depends on
are in `docs/decisions.md`.

## Operations

`brakes` has three base operations, `plan` (print what would change), `apply` (write it)
and `doctor` (diagnose, read-only), plus `configure` (record a module's answers),
`remove` (uninstall a module) and `adopt` (the plan, never written, that would bring an
untouched repository under the modules its audit names). `brakes mcp` serves the same
operations to one agent host at a time over stdio: its read tools list modules, return a
module's questions, propose answers from files and return the plan with a confirmation
token; its `apply` writes that plan's local files only with the token and the human's
confirmation in the client's own form, and a client without elicitation is refused.
`brakes guard pre-bash` is the never-merge-on-red hook: it reads the agent host's
PreToolUse payload on stdin, prints a deny line or nothing and exits 0.

Installation and update are one reconciliation. Every write is planned first and printed;
`--apply` writes it. Target repository commands are data: `brakes` never runs a project
command, never calls the network during a local plan, never writes outside the
repository root or follows a symbolic link out of it, and writes at most one repository
per invocation. Writes are refused unless the configuration allows the repository
(below); there is no fleet-wide write and no change to home-level settings.

## Configuration contract

Everything that names a user, an organization, a runner or a private preset is a value the
user supplies. `brakes` ships **no default value** for any of them: without a
configuration every write is refused and every local read is allowed: `doctor` and the plan
of `install`, `configure` and `remove` run, under the denylist only. What reads the remote
repository with the user's credentials (`--remote`) needs a configuration that names it.

```jsonc
// brakes configuration, one file, never inside a target repository
{
  "schema": 1,
  "host": { "kind": "github", "hostname": "github.com" },
  "owner": "<login>",                                  // `personal_owner` in locks compares with it
  "write_allowlist": ["<login>/*", "<org>/<repo>"],    // wildcard only as <owner>/*
  "identity_denylist": ["<substring>"],                // substring, case-insensitive, applied to
                                                       // canonical paths, remote URLs and host identities
  "runners": {                                         // the user's own runners; absent: GitHub-hosted only
    "linux": { "name": "<answer value>", "label": "<runs-on label>" },   // default of `runner`
    "macos": { "name": "<answer value>", "label": "<runs-on label>" }    // default of `macos_runner`
  },
  "presets_dir": null,                                 // private presets merged over the catalogue
  "schema_base_url": null,                             // `$id` base for rendered JSON schemas; unset renders
                                                       // https://github.com/gemba-app/brakes/blob/main/templates/
  "reusable_callee": null                              // `<owner>/<repo>` hosting `_reusable-verify.yml`; unset:
                                                       // `reusable: true` renders the single-repo workflow
}
```

It is read from, first wins: (1) a file embedded at build time, only when the build sets
`BRAKES_EMBEDDED_CONFIG=<path>` (read by `build.rs`; a relative path resolves against the
source checkout), for users who want their scope compiled into their own binary; (2)
`--config <path>`; (3) `$XDG_CONFIG_HOME/brakes/config.json` (`$HOME/.config` when unset).
A build without the variable embeds nothing. The configuration is never read from the
target repository nor from an environment variable at run time. No file at all is the
empty configuration, which refuses every write and every remote read with "No
configuration: writes refused", naming where a configuration is read from. The file is
validated against a schema; an unknown key is a refusal.

Tests run under a synthetic configuration through step (3): `.cargo/config.toml` sets
`XDG_CONFIG_HOME` for every process Cargo runs to `tests/fixtures/config`, so in-process
tests and the binaries they spawn read `brakes/config.json` there. `config::install` (set
once, before the first read) and `--config` serve tests that need another configuration.

What stays a repository-level answer (in `.agent-setup/project.json` and the module
answers under `.agent-setup/modules/`): the declared commands, the `ci.*` fields the
modules consume, `criticality`, `agent_accounts`, `accepted_level`, `excluded_paths`, and
every module answer (`runner` may name any label the configuration or GitHub knows).
`excluded_paths` (#16) lists repository paths, files or directories, that are not the
project's files (templates it renders for others, its test fixtures): the Dockerfile walks
of `security` and `stack-packs` and `qa`'s file walk skip anything at or under them, and
`doctor` prints one `EXCLUDED [project.excluded_paths] <path>` line for each. A path outside
the repository or the root itself refuses the profile.

## The module engine (2026-10-28)

This section states what the code does.

**Modules.** A module is compiled in (`src/modules/`) and
implements the `Module` trait of `engine/module.rs`: an id, a version, the ids it
`requires`, a question schema, `render`, manual steps and `migrate`. Rendering is pure:
it sees the root, the profile, the source, the installed lock and the module's
validated answers, never the network or a command. The registry (`modules::all`)
holds `stack-packs`, `merge-guard`, `repo-baseline`, `agent-guardrails`, `security`,
`qa` and `ci-baseline`, in that order (`ci-baseline` last, after every module whose
`ci_jobs` it collects). A registered module stays inactive until the lock records it or
`install --module` requests it. Registering the merge-guard hook in
`.claude/settings.json` is `agent-guardrails`'s `managed-entries` write where that
module is active; without it, `merge-guard` declares the `hook-registered` manual step.
`install` reconciles every module the installed lock records and every
`--module <id>`; an id no compiled module answers to is refused by name, and the lock
entries of a recorded module this build does not know are carried over untouched. A
module whose `requires` is not active in the same plan is refused with the
`--module` that adds it; nothing is installed on its behalf.
The engine resolves and validates the answers of every active module once per
plan before any module renders, the answers `configure` is changing included, and
`Context::answers_of(id)` hands a module the resolved answers of a module it
`requires`; any other id refuses naming both modules. A module never reads another
module's recorded answers file: in a plan that changes them it would render from
the file the plan replaces.
Three additive reads complete the context. `Context::repository` is the
checkout's `owner/name`, derived once per plan from the fetch URLs of `origin` with
the scope guard's parse, never the network; no origin, a refused URL or URLs naming
different repositories give `None` and the module renders a placeholder.
`Context::answers_if_active(id)` is a soft read of the resolved answers of a module
active in the plan, `None` otherwise, without requiring it. `Module::notes` returns
lines the plan prints after the plan and `STEP` lines as `NOTE [<module>] <text>`, in
module order; a note never changes the plan, the lock, readiness or the exit code,
and `doctor` prints none.

**Ownership classes**, declared per rendered path:

| Class | Written | Lock entry | Plan behaviour |
|---|---|---|---|
| `managed` | always, to the rendered content | digest | local edit or deletion refuses |
| `managed-block` | between the `BEGIN`/`END` markers of a project file; an absent file gets the module's optional scaffold (the whole file, holding the block exactly once), else the block alone; a scaffold on another class is refused | digest of the block only | local edit of the block refuses; surrounding text, scaffold included, is the project's |
| `seed` | once, only if the path is absent | no digest | an existing path prints `SKIP`; afterwards the file is the project's |
| `never-touch` | never | no digest | any module rendering content at that path refuses |
| `remote` | never (a host setting) | no digest | content on a `remote` entry refuses |
| `managed-entries` | the members of the arrays of a JSON fragment, inside a project-owned JSON file; the rest of the file stays the project's | digest of the fragment and the entries | an owned entry edited in place refuses by name; a deleted one is re-added; an entry no longer rendered is removed when unchanged |

`managed-entries` is how the
installer registers hooks and deny rules in `.claude/settings.json` without owning the
file: the module's content is a JSON object whose arrays hold the owned entries; the
plan appends each one missing from the project file after the project's own members,
leaves a present one alone, and refuses a member that carries the same name (a hook
entry's `command`, a rule's text) with different content. Entries the lock records
that the module stops rendering are removed when present exactly and refused when
edited; containers emptied that way go with them, and `remove` deletes the file only
when `{}` is all that remains. A file whose entries already match is never rewritten,
so a repository that merged the fragment by hand plans `No changes.`; one that changes
is written as `serde_json` pretty-prints it (two-space indentation, sorted keys).
`doctor` reports `Managed entries drift` for an owned entry missing or edited.
A string leaf of the fragment is an owned object member named by its key: added
when absent, left when equal, refused when its value differs; `agent-guardrails` owns
its deny patterns in `opencode.json` that way.

A path rendered by two modules, a path the lock assigns to another module and an
unowned file at a managed destination all refuse. A path an active module stops
rendering is retired: managed content is deleted when unchanged, refused when edited,
forgotten when absent; a present seed or never-touch path and every remote entry are
kept and printed `KEEP`. Plan lines keep their verb first and add class and module
after the path: `PLAN docs/agent-setup/security-gates.md [managed:security]`,
`PLAN SKIP <path> [seed:<module>]`, `PLAN <answers file> [answers:<module>]`; with
`--apply` the verbs are `WRITE`, `DELETE`, `SKIP`, `KEEP`.

**Lock schema 2.** `.agent-setup/lock.json` records the installer version, source
commit and dirtiness, the configured owner, per module its version and the digest of
its answers file, and per path its module, class and (for `managed` and
`managed-block`) digest; a `managed-entries` path records the fragment's digest and
the entries themselves, so `remove` needs no render. A schema-1 lock, written by an
earlier installer, is migrated in memory by `Lock::from_v1` for the paths a compiled
module still renders; any other path refuses with "migration required". The first plan writes schema 2; schema 1 is never written again. Every
plan validates all destinations inside the root before the first write and writes
the lock last.

**Recorded answers.** A module's questions are a hand-written subset of JSON Schema
(`engine/answers.rs`; no dependency): `string`, `boolean`, `integer`, enum, array of
enum and array of string, with `default` (a scalar or a per-profile map, resolved
with the module's maturity profile), `required`, `when` (a predicate on an
earlier answer), length, range and item-count validators, and `x-` extensions that
only the drivers read. Keys stay flat: a question id with one `*` segment
(`apps.*.port`) is a pattern that types and validates every key with an identifier
in that segment, refusing by the concrete key; a pattern has no `default`,
`required` or `when`, so its instances, defaults and cross-field rules belong to
the module. A question marked `secret` refuses at load: secrets are
probed by name, never asked or recorded. Answers live in
`.agent-setup/modules/<id>.json` (`{module, version, profile?, answers}`), committed
owner data. `profile` is the maturity profile (P1–P3) the module is installed for;
absent means P1, until the auditor derives one. `install <repo> --module <id>
--profile P1|P2|P3` records it for each requested module when it differs, keeping
the recorded answers; `--profile` without `--module` refuses, an unknown profile
refuses, `configure` and migrations keep the recorded one. The engine resolves
per-profile defaults with it and hands it to `render` as `Context::tier`; answers
already recorded (`configure` records them with their defaults filled) do not change
with the profile. Every load validates them: an unknown key, a missing required answer or a
broken rule refuses naming the question; questions whose `when` is false are dropped.
`configure <repo> <id> [--set key=value]... [--answers <file>]... [--preset <name>]
[--apply]` merges over the recorded answers (the `questions` driver orders recorded,
default, preset, file, `--set`), validates and adds the file to the plan; nothing is written without
`--apply`. When the lock records an older version of a module, `migrate(from,
answers)` runs once before validation and the plan rewrites the answers file with
the new version; a lock recording a newer version than the installer refuses.
`install --preset <name>` and `install --answers <file>` (multi-module shape only) are
sugar over `configure`: `engine::install` takes one answers patch per module, and each
module the install reconciles with a section is recorded as `configure` would record it
in the same plan, so the result equals `configure --apply` followed by `install --apply`.

**Manual steps.** A module declares work it cannot do (`engine/manual.rs`): id,
title, owner (`owner` or `platform`), instructions shown and never executed, a
read-only probe and an optional `after` naming a step of the same module. Probes are
`file-exists {path}`, `json-pointer {path, pointer, equals}` (RFC 6901) and `remote
{id, args}`, answered by a `RemoteRunner`. A remote id names an entry of the host
adapter's probe registry (`host/probes.rs`, one canonical id and argument set per
check); `doctor --remote` answers them through `GitHub` for the origin
repository, and without `--remote` every remote probe is `unavailable`. Steps are
checked at load (unique ids, paths inside the root, well-formed pointers, remote ids
and arguments the registry can run, `after` without cycles). States: `pending`, `verified` (with evidence), `failed`
(with the error), `unavailable`, `not-applicable` (a remote probe's host says the
step does not exist for this repository), and `blocked` when the `after` step
is not verified, in which case the probe does not run. `install` prints `STEP [state:module] id —
title`; `doctor` prints `STEP [state:module] id — evidence`. Steps never change
readiness. `doctor --json` emits a document of schema 1 with `ready`, the printed
`findings`, the evaluated `steps` and the installed `modules`, with the same exit code
as the text form.

**Remove.** `remove <repo> <id> [--apply]` applies the retirement rule to every path
the lock records for the module: unchanged managed files are deleted, a managed block
is cut out of its file (the file goes only when nothing else remains), edited content
refuses, absent content is forgotten, present seeds and never-touch paths and every
remote entry are kept and reported. The module's lock entries and its answers file
go. It reads the lock only, so a module no longer compiled in can still be removed.

**What the engine never does:** run a project command, call the network, write
outside the repository root, read or record a secret value, write more than one
repository per invocation, or perform a manual step.

The auditor extends `doctor` with a rule catalogue (levels Basic–Gold, profiles P1–P3
derived from humans with merge rights, merge cadence, deployable services and declared
criticality), `--fleet` read-only over an organization or user, and `adopt` for
repositories the installer never touched. `--fleet` audits each listed repository in
turn with its own 60-call budget and read cache, reads the files its rules need through
the contents API within the auditor's path allowlist (there is no checkout, so the
rules that re-label today's `doctor` are `not-required`), lists archived and unread
repositories under "Not audited" and exits with the highest code among them. `adopt <repo>` plans without writing: the offline audit names
the modules (the `module` remediation of a required rule that fails or blocks the next
level, with their requirements), the engine plans them as `install --module` would, and
the plan is re-labelled `ADD` (a managed block appended to an existing file),
`SEED` (a new file), `STEP` (a manual step not yet verified) or `PROPOSE` (an existing
file the module would change, a skipped seed that differs from its rendering, or a module
whose plan the engine refuses, which then stays out); `--apply` is refused until its
later slice. Drivers (`questions`) sit on top of the schema: answers
are given through an answers file, a preset (an answers file with a name, shipped in
`templates/presets/` and named by infrastructure shape), a line-oriented TUI on
`configure` or an MCP client, and every driver ends in the
engine's `configure`, the only writer of the recorded answers. "No stack detection
invents commands" stands for them too: proposing answers from files never proposes
a command. Each module's design is the section of this document that bears its name;
`docs/decisions.md` holds the policies (remote scope, standard, rulesets, runners,
guardrails, security).

## The host adapter (2026-10-28)

This section states what the code in
`src/host/` does. Its decisions are in `docs/decisions.md` (2026-10-28).

**The contract.** `Host` (`host/mod.rs`) is everything the engine, the auditor and
merge-guard know about a code host: typed reads of one repository (settings,
probed features, classic protection, rulesets, environments, secret names, workflow
runs and their timing, jobs, check runs, collaborators, deployments and their
statuses, issues, pull requests, file existence and contents, directory listings,
Dependabot and secret-scanning alerts, branches, labels, recent commits and the
security toggles), four organization reads (`owner`, `list_repositories`,
`org_rulesets`, `org_settings`) and the writes (labels, one issue, one comment,
repository settings, a ruleset, an environment, classic branch protection and its
retirement). A method added after the first trait carries a default that answers
`Unsupported`, so an implementation written earlier keeps compiling; the auditor's
read cache (`auditor::cached::Cached`) delegates every method. Every failure is a
`HostError`: one sentence naming the repository, organization or operation, and a
kind, one of `unsupported`, `unauthenticated`, `forbidden`, `not_found`,
`rate_limited`, `truncated`, `shape`, `transport` and `write_refused`. No method
returns or sends a secret value: secrets are listed by name and update time, a
secret-scanning alert carries the kind of secret, never the secret, and the
transport refuses any request body that carries `encrypted_value` at any depth.

**GitHub over `gh`.** `github::GitHub` implements `Host` over `remote::Api`, whose
production transport `remote::Gh` runs `gh api --include --hostname github.com`
with `GH_REPO`, `GH_HOST` and `GH_DEBUG` removed, stderr discarded, a 30-second
deadline and a 4 MiB response cap; GitHub Enterprise Server is out of scope. Every
repository call passes, in order, the host check (an Azure DevOps identity is
`unsupported`) and the read gate (an owner or organization read passes the read gate
on its name), then the rate-limit floor (it stops, never waits, once
`x-ratelimit-remaining` is under 50) and the invocation's call budget (2 000 calls by
default; exhaustion is `rate_limited` with "call budget of N exhausted"). HTTP
answers map to kinds: 401 `unauthenticated`, 429 and a 403 with no calls left
`rate_limited`, any other 403 `forbidden`, 404 `not_found`, any other status
`transport`, and an unreadable body `shape`. Lists page with `per_page=100&page=N`
up to 30 full pages; a longer list is `truncated`, never a silent partial result.

**The two gates** (`host/authorize.rs`) decide on the identity alone, before any
`gh` process starts. The read gate admits any repository or owner the token can read
and refuses every identity that matches the configured `identity_denylist` (a
substring, case-insensitive), also when the user runs the
command in person. The write gate, `authorize::write`, is the only constructor of the
`WriteToken` a write needs: it refuses without the explicit flag ("Remote write to
{repo} needs the explicit --remote flag of apply"), then applies the read gate, then
refuses a repository outside the configured `write_allowlist` ("Remote write refused:
{repo} is not in the authorized write allowlist"), the list the file-scope guard also
reads; without a configuration every write is refused. Two flags mint a token: `--remote` of `apply` and
`--publish-issue` of `doctor --fleet`. A write takes its repository from the token
only, so no call writes to more than one repository. The writes and the endpoints
they send are fixed in `src/host/`; no write is ever sent under
`/secrets`, `/merge`, `/merges`, `/collaborators` or `/orgs/`, and none re-runs a
workflow or deletes a repository. Classic protection is written only from a module's
complete declaration of it (`BranchProtectionSpec`): a change to the required checks
of a branch whose checks live in classic protection alone is `write_refused`, because
the adapter reads that protection only in part, and is left to the owner by hand.

**The probe registry** (`host/probes.rs`) holds one canonical id and argument set per
remote check: `automated-security-fixes`, `check-run-reported`,
`classic-protection-absent`, `default-branch`, `dependabot-alerts`,
`endpoint-answers`, `environment-main-only`, `feature-available`, `labels-present`,
`org-2fa-required`, `private-vulnerability-reporting`, `repo-settings`,
`repository-visibility`, `required-check`, `ruleset-present`,
`ruleset-required-checks`, `secret-exists`, `secret-present`, `secret-scanning` and
`workflow-lockfile`; the spec's table gives each one's arguments and its `verified`
and `pending` conditions. `endpoint-answers` and `secret-exists` are declared for the
"configure new" contract and have no runner yet: they always answer
`unavailable`. The engine checks every `Probe::Remote` of a module against the
registry at load, so a module cannot ship a step the registry cannot run.
`doctor --remote` and `apply` answer the probes through `GitHub` for the checkout's
origin repository; a host error maps to `failed`, except `unsupported` and
`unauthenticated` (`gh not authenticated: …`), which are `unavailable`.

**Fleet reads** (`host/github/fleet.rs`) serve `host repos`, `host org` and
`doctor --fleet`. `owner` reads `users/{name}` for the kind. A listing reads the
owner's repository count first, then pages to a cap of 100 pages (10 000
repositories); the authenticated user's own listing reads `user/repos?affiliation=owner`
so that it includes private repositories. Only the rate limit and the call budget make
a listing partial: it returns what it read, why it stopped and one sentence for what
it did not read. A denylisted identity in a listing is left out and counted as not
read, without stopping the listing.

**Azure DevOps** (`host/azure_devops.rs`) parses `https://dev.azure.com/{org}/{project}/_git/{repo}`
and `git@ssh.dev.azure.com:v3/{org}/{project}/{repo}` into a `RepoId` with a project,
and every operation answers `unsupported` with one fixed sentence. It makes no REST
call, runs no `az` and holds no credential; implementing it is a module of its own.

**The `host` command** is read-only and takes no checkout: `main` dispatches it
before the project-scope parsing, so it runs in any directory. It never mints a
`WriteToken`.

| Command | Prints | Exit |
|---|---|---|
| `host features <owner/repo> [--json]` | `repository:`, `visibility:`, `plan_hint:` (a hint that never decides) and one line per feature (`rulesets`, `environments`, `branch_protection`, `required_reviewers`, `dependabot_alerts`, `secret_scanning`, `workflow_lockfile`, `merge_queue`): `available`, `unavailable (status: message)` or `unknown (reason)` | 0, 1, 2 |
| `host repos <owner> [--json] [--call-budget <n>]` | `owner: <name> (user\|organization\|unknown)`, one line `<owner/name> <visibility> <default branch>` per repository with ` archived` and ` fork` when set, then `N repositories`; on stderr `INCOMPLETE: <reason>` when stopped and `NOT READ: <sentence>` per gap | 0 complete, also when only denylisted identities were left out; 1; 2 stopped |
| `host org <org> [--json]` | `organization:`, the settings `two_factor_requirement_enabled`, `default_repository_permission`, `members_can_create_public_repositories`, `web_commit_signoff_required` (`unknown (not visible to this token)` when unseen), `plan_hint:`, then `rulesets: N` and `ruleset <name>: <target>, <enforcement>` lines, or `rulesets: unavailable (<reason>)` on a 403 | 0, 1, 2 |
| `host probe <owner/repo> <probe-id> [--arg key=value]... [--json]` | `REMOTE [<state>:host-adapter] <probe-id> — <evidence>` | 0 `verified`, `pending` or `not-applicable`; 2 when the read was rate-limited or truncated; 1 otherwise |

Exit 1 is a refusal, printed on stderr as `REFUSED: <reason>`: the usage line, an
identity that is not `owner/name`, a denylisted identity, `--call-budget` without a
whole number above 0, `--arg` without `key=value` or outside `host probe`, a probe id
the registry does not hold, a missing, unknown or mistyped probe argument, and every
host error other than a cut-short read. Exit 2 is a read cut short by the rate limit,
the call budget or a page cap (`INCOMPLETE: <reason>` on stderr), so a fleet run can
tell partial from clean. `--json` may stand anywhere and prints one document instead
of the lines: `{repository, features}`, `{owner, repositories, stopped, unread}`,
`{organization, settings, rulesets, rulesets_unavailable}` and `{repository, probe,
args, state, evidence, error}`. A probe's `--arg` takes text, a list as a JSON array
or comma-separated texts, and an object as JSON.

## The auditor (2026-10-28)

This section states what the code in
`src/auditor/` does. The standard is the auditor standard v1 and its amendment in `docs/decisions.md`.

**Read scope.** `doctor <repo>` audits the checkout after today's diagnosis; `doctor
--fleet <org-or-user>` audits every repository the listing returns and takes no
checkout. Every host read goes through the host adapter, so the read gate refuses a
denylisted identity before any call, in both modes. Without `--remote`, `doctor <repo>`
audits over an offline host whose every read answers "`<path>` is unavailable without
--remote"; `--fleet` always reads the host. Rules read files through one bounded
interface, the same for both modes: the paths of `auditor::FILE_ALLOWLIST`
(`.agent-setup/project.json`, `lock.json`, `security-exceptions.json`,
`modules/ci-baseline.json` and `service.yaml`, `AGENTS.md`, the three
`CODEOWNERS` locations, `service.yaml`,
`catalog-info.yaml`, `.github/dependabot.yml` or `.yaml`, `renovate.json`,
`Dockerfile`), the direct files of `.github/workflows`, and any Markdown document by
extension; they may list `.github/workflows` and `.github/ISSUE_TEMPLATE` and nothing
else. Any other path refuses ("Auditor file read refused: <path> is outside the
auditor's path allowlist"). A checkout reads through the crate's path guard;
`--fleet` reads through the contents API at the default branch, one call per file or
listing, each file at most 256 KiB.

**Rules, levels and profiles are data.** The registry (`auditor/rules.rs`, rules in
`auditor/catalogue/`) holds every rule with an id `<block>.<kebab>`, a level (Basic,
Bronze, Silver, Gold), the profiles or conditions under which it is required and a
remediation that names the module, command or manual step that fixes it. The blocks
are `baseline`, `posture`, `ci-health`, `dora`, `operations`, `governance`, `ci`,
`security`, `stack` and `agents`; a registry invariant test asserts each rule's
allocation against the decision's table, so moving a rule or a threshold is a new
decision plus a PR, never a flag. Each rule evaluates to `passed`, `failed`,
`unavailable` (absence of evidence, never a pass; a rule that waits for a module
answers "waits for module <id>" without being evaluated) or `not-required`. Levels
are cumulative: the level reached is the highest whose required rules, and those of
every level below, all passed. The baseline block re-labels today's `doctor`: a
`NOT READY` finding is Basic, a `WARNING` Bronze, and a manual step of an installed
module takes that module's level; under `--fleet`, which has no checkout, those rules
are `not-required`. The profile is derived from four measures over a 28-day window,
each printed with its value, tier and evidence: humans with merge rights (1 is P1,
2–5 P2, more P3; accounts that are not users, such as GitHub Apps, are excluded, and
so are the logins listed in `audit.agent_accounts`), merged pull requests per week
(under 10 low, 10–40 mid, over 40 high), deployable services (the most of deploy
workflows, Dockerfiles and the host's environments) and the declared `criticality`.
The required level is P1 Bronze, P2 Silver, P3 Gold; `customers` raises it to at
least Silver and `personal-data-or-payments` one level, capped at Gold; an undeclared
criticality is audited as `internal` with a Basic finding. When the humans measure is
unavailable, as it always is without `--remote`, the profile is P1 flagged
`unverified` and the required level is still stated. When it counts exactly one human,
`posture.human-approval-required` and `posture.codeowners-review` are `not-required`
with the reason `single maintainer: nobody else can approve`, without being evaluated:
GitHub does not let a pull request's author approve it, so that maintainer's merge gate
is the required checks and `human-approved` on protected paths.

**The project profile fields** the auditor reads from `.agent-setup/project.json`,
all optional, refused when malformed with a sentence naming what is allowed:

| Field | Allowed values | Effect |
|---|---|---|
| `criticality` | `internal`, `customers`, `personal-data-or-payments`; absent or `null` is undeclared | lifts the required level as above |
| `audit.agent_accounts` | a list of logins | those collaborators are not counted as humans |
| `audit.accepted_level` | `{"level": "Basic" \| "Bronze" \| "Silver" \| "Gold", "expires": "YYYY-MM-DD"}` | while `now` is on or before `expires`, lowers exit code 3 or 4 to 0 and nothing else; once expired it is the finding `audit.accepted_level expired on <date>` |

**Output and exit codes.** `doctor <repo>` prints today's lines unchanged, then
`AUDIT <repo>: profile <P>[ unverified] (<measures>); required <level>; reached <level or none>` (with
`; accepted <level> until <date>` while an acceptance holds), a `FINDING` line per
declaration problem, `FAIL [<level>:<rule>] <evidence> → <remediation>` and
`UNAVAILABLE [<level>:<rule>] <reason>` for each required rule in registry order, and
`NEXT <level>: N rules (<ids>)` while a level remains. `--json` adds `repo`,
`audited_at`, `window_days`, `profile`, `level` (with `"standard": "accepted"`) and the
per-block `rules` and the `counters` beside the engine's schema-1 keys. `--report <file.md>` also writes
the Markdown of the audit to that path; `--now <YYYY-MM-DD>` fixes the clock, so the
same inputs give the same bytes. The exit codes are a CI contract: 0 ready and the
required level reached, 1 `NOT READY` (unchanged), 2 refused (unchanged), 3 ready but a
required rule at or below the required level failed, 4 ready but only `unavailable`
evidence keeps the required level out of reach, so a token without permission is
visible in CI rather than mistaken for a pass.

**Counters.** Two figures report whether the brakes work (`auditor/counters.rs`);
neither has a threshold or a level, and neither changes the reached level or the exit
code. Under `--remote` they read after the rules, from what the read cache already
holds, with an allowance of 6 calls held back while the measures and rules read (38 of
60 with the rules'); under `--fleet`, whose file allowances already hold 47, they hold
none and read what the rules leave. `post_merge_corrections` (percent) judges at
most 10 pull requests merged into the default branch 58 to 30 days ago, newest first,
bots (`dependabot[bot]`, `renovate[bot]`) excluded: one is corrected when a pull request
merged within 30 days after it touched one of its files, a rename matching on both names.
The cadence listing reaches back 58 days so both read it once (the cadence still counts
its 28 days); the files come from `Host::pull_files`, one call per pull request, and a
list of 100 or more files leaves that pull request unjudged. A judged pull request is
decided by its first correction or once every follower in its window has been read; the
counter settles with 3 decided and is `unavailable: budget exhausted …` below. It is a
ceiling (a follower may be a planned second slice), so its trend matters, not its level.
`cost_per_change` (minutes) is the median, over the pull requests merged in the 28-day
window, of the wall-clock minutes of their `pull_request` runs (named by the run's
`pull_requests` or, once GitHub has emptied that list, by its head sha; `updated_at −
run_started_at`, `created_at` when the start is absent) among the latest 100 runs that
`ci-health.rerun-rate` lists, so it costs no call; its evidence counts the unmeasured
pull requests, the runs and the re-run attempts, and names what is not read (billable
minutes, the model's spend, human time, older runs). Text prints one `COUNTER` line each
after `AUDIT`; `--json` adds `counters` (`value` null with `reason` when unavailable);
the fleet table gains two columns. Without `--remote` both are `not read without
--remote`.

**The fleet.** `doctor --fleet <org-or-user> [--json] [--report <file.md>]
[--include-archived] [--now <YYYY-MM-DD>] [--publish-issue <owner/repo>]` lists the
owner's repositories through the host adapter (one invocation, one owner) and audits
each in turn, sorted by name, with its own budget of 60 host calls and its own read
cache, dropped when that audit ends. Each rule's minimum allowance is held back while
the measures read, when the allowances fit, so no block is starved by the measures.
Archived repositories are listed under "Not audited" unless `--include-archived`; an
audit that fails is listed there as an error and counts as exit 2; denylisted
identities and what a stopped listing did not read are counted, never named. The
output is the Markdown fleet report (a header with the owner, the date, the window and
the login the token reads as; one table row per repository with profile, required and
reached level, gap, posture failures, a CI-minutes sample, deployment frequency, lead
time, open incidents, the two counters, unavailable and waiting rules; one section per repository with
its exit code, the calls it spent and its audit lines; then "Not audited"), or one
JSON document with `--json`; `--report` writes the same Markdown. The exit code is the highest among the audited repositories (each audited as
ready), 2 when the listing itself failed or the invocation was refused; `--remote` is
accepted and implied.

**The single write.** `--publish-issue <owner/repo>` is the auditor's only write. The
target passes the host adapter's write gate before the listing starts, so a target
outside `scope::WRITE_ALLOWLIST` refuses and audits nothing. After the audit the
adapter reads the target's labels and sends exactly one `POST repos/{r}/issues`, titled
`Fleet audit <owner> <date>`, whose body is the Markdown report (cut at GitHub's
65 535 characters with a closing line that names the `--report` file, when the report
is longer). The issue carries the label `fleet-audit` when the target already has it;
a missing label is a finding in the output, never a label write, and earlier issues
are never updated or closed. The text output then ends with `## Published` and the
issue URL; the JSON gains a `published` object.

**Adoption.** `adopt <repo> [--json]` is the plan, never written, that would
bring a repository the installer never touched under the modules its offline audit
names (the `module` remediation of each required rule that fails or blocks the next
level, with their requirements): the engine's `install --module` plan re-labelled with
additive verbs only, `ADD [managed-block:<module>] <path>` (a block appended to an
existing file), `SEED <path> [<class>:<module>]` (a file that does not exist),
`STEP [<state>:<module>] …` (a manual step with its probe) and `PROPOSE <path>: <what
exists> → <what the module would render>` (every collision, and a module whose plan the
engine refuses, which stays out). It closes with `Plan only; no writes. adopt --apply
lands in a later slice.`, or `No changes.` when nothing would be added, and exits 0;
`--apply` passes the write scope and is then refused with that sentence, exit 2.

## Stack packs (2026-10-28)

This section states what the module
`stack-packs` (`src/modules/stack_packs/`) does. Its defaults and
container runtimes are in `docs/decisions.md`.

**Packs are compiled data.** A pack is a `const StackPack` selected by `StackId`:
all seven are filled. The two device packs build no container, seed
`.java-version` and `.xcode-version`, carry Java and Gradle setup steps or an Xcode
selection step, and `swift-ios` is the one macOS target `ci-baseline`'s `macos`
answer requires. The data pack `sql-dbt` builds no container either, seeds
`.python-version`, installs the pinned dbt-core and sqlfluff in CI and proposes
`sqlfluff lint` only when the project's `.sqlfluff` declares the dialect. A pack carries the files that suggest it, the commands it would
propose, its lockfile flag, its toolchain seed, its Dockerfile and `.dockerignore`
seeds, its CI setup steps (`ci_setup`, data that `ci-baseline` turns into workflow
steps; `Step` and `ActionRef` live here), its test-runner profile, its
instrumentation recipe and its coverage recipe. The coverage recipe is filled
for `python-uv` (coverage.py run through `uv run --with coverage==<version>`) and
`rust` (`cargo llvm-cov`, installed by `taiki-e/install-action`), `None` for `node` and
`go`: the tool's pin-table key, how it reaches CI, the command that writes a JSON
report in the app directory, and the `jq` filter that reads the line percentage from
it. It is data for the coverage ratchet of `security`,
which no module renders yet. Each recipe also carries the project's test job upload
(`CoverageUpload`): `rust` measures the declared test command unchanged between
`eval "$(cargo llvm-cov show-env --sh)"` and `cargo llvm-cov report --lcov` (`eval`, not
the README's `source <(…)`, which shellcheck reports as SC1090); `python-uv` runs pytest
under coverage.py in place of it, because coverage.py measures only the interpreter it
starts. `CoverageRecipe::upload_steps` renders the install, the measured run and the upload
of `agentic-coverage-<app id>-<job>` (`coverage_artifact`), the artifact `diff-coverage`
downloads; the seed workflow and the CI audit use it. A pack without a recipe states why in
`no_coverage`, and its apps are not judged; nothing falls back to measuring. No pack is read from the target repository and nothing in the
module runs a command or reads the network. Other modules reach the packs a
repository records only through `stack_packs::packs(cx)`.

**Detection proposes with evidence.** `configure <repo> stack-packs` with no `--set`,
`--answers` or `--preset` prints, after the plan, a block `stack-packs: proposals
(nothing written; confirm with --set or --answers)`: per detected app its id, path
and stack, the evidence (files present and the few fields read by hand:
`rust-version`, `packageManager`, the `go` directive, the Gradle wrapper's version
and checksum, an Xcode project's shared schemes, a dbt project's name, profile and
`require-dbt-version`), each command as `declared`
(kept) or `proposed` (only for a `null` field of the app's profile) and the seeds an
apply would write. Detection reads files only and writes nothing; `doctor` reports
`stack.unconfigured` while a detected stack is not recorded. Answers are flat keys,
`base_image_family` and `apps.<id>.{path, stack, container, toolchain, port,
healthcheck, bin, force}`, validated by the engine through pattern questions and by
the module across fields. `configure <repo> stack-packs --accept-commands [<app-id>]
[--apply]` is the only path from a proposal into a profile: it prints the diff and
fills only the `null` `commands.*` fields of the root `project.json` (no app id) or of
`<path>/.agent-setup/project.json` for the named app (created from the default profile
when absent), never a declared one; several stacks at `.` without an app id refuse. It
does not regenerate entrypoints: re-run `install` for that.

**Seeds and never-touch manifests.** Per app, under its `<path>/` prefix (empty for
`.`), `render` declares the toolchain pin file as `seed` (`rust-toolchain.toml`,
`.python-version`, `.nvmrc`, `.java-version` or `.xcode-version`; for `rust` only when
`toolchain` is answered `true`), the manifests the pack reads (`Cargo.toml`,
`pyproject.toml`, `package.json`, `go.mod`, the Gradle files and the wrapper's
properties, `Package.swift`, `dbt_project.yml` and dbt's packages files) as
`never-touch`, and, for a container app, `Dockerfile` and `.dockerignore` as
`seed`. A seed is written once and afterwards is the project's (`PLAN SKIP <path>
[seed:stack-packs]`). The Dockerfile seed is OpenShift-compatible: an arbitrary
non-root UID in group 0 with a numeric `USER`, files owned by `root:0` and
group-writable, writes only under `/tmp` (`HOME=/tmp`); its header states those rules
and the runtime. `base_image_family` defaults to `distroless` and `dhi` refuses at
render while the table has no `dhi` image pins.

**One shared pin table.** Every `uses:`, `FROM` and tool version the module renders
comes from `templates/stack-packs/pins.json`, owned by `stack-packs` and read by
the modules that render pinned steps (`ci-baseline`, `security`, `agent-guardrails`): actions by 40-hex SHA with the version beside it, images by
`@sha256:` digest with the tag kept for people, tools by version. A test ties the
table to this repository's workflow `uses:` lines and to the `FROM` lines of
`templates/stack-packs/pins/Dockerfile`, the never-built file that exists so
Dependabot's `docker` ecosystem bumps the digests; a bump of either fails until the
table and its `last_verified` follow. `doctor` reports `stack.pin-table-stale` (a
warning without a level) once `last_verified` is more than 30 days old, reading the
checkout's table in this repository and the embedded one elsewhere. The other
`stack.*` rules (`lockfile-present`, `lockfile-not-enforced`, `toolchain-pinned`,
`image-by-digest`, `image-nonroot`, `image-arbitrary-uid`, `no-healthcheck`) are
`doctor` warnings over the recorded apps, their files and every Dockerfile under
them outside the profile's `excluded_paths`, which the auditor judges at the levels of decision.

## The CI baseline (2026-10-28)

This section states what the module
`ci-baseline` (`src/modules/ci_baseline/`) does. Its policies
(generated configuration is installed content, `required` is the single aggregate
check, the runner policy, remote settings and its rules' levels) are in
`docs/decisions.md`; this section repeats none of them.

**The project's CI is a seed (`workflow: seed`, the default).** The project's CI runs
the project's commands; `brakes` installs and audits the gates around it and never runs
them (decision 2026-11-02). Under `seed`, `ci-baseline` writes `.github/workflows/ci.yml`
once, as class `seed`, and never re-renders it: one job per declared command (`lint`,
`test` or `verify` when `test` is `null`, `build`; in a monorepo `<app>-<command>` in
each app's directory, from its own profile, plus the root profile's commands when no app
sits at `.`), each with its pack's `ci_setup` and the command read at run time; when
`security` is active and judges changed lines, the test job runs its pack's
`upload_steps` (`stack-packs`, `CoverageUpload`) and a `diff-coverage` job calls
`./.github/workflows/agentic-coverage.yml`; `required` (`if: always()`) passes only when
every other job succeeded (`seed-required.sh`). A pack without coverage is named in the
seed's header with its `no_coverage` reason; a macOS-target app is left to the project.
From then on the module behaves as under `existing` with `aggregate_check` `required`:
its judges (scope, `workflow-lint`, the held-out jobs and every contributed job) go to
`agentic-security.yml` with `agentic-required`, and the required checks are `required`
and `agentic-required`. With a workflow of the project's own already present no seed is
written and a plan note says to answer `existing`. Unanswered, `workflow` is `generate`
where the installed lock records a workflow this module generated, so an install from
before `seed` keeps its output; `generate` prints a deprecation note.

**The guided setup (`brakes ci init`, #24).** For a repository without CI, `ci init
<project> [--answers <file>]... [--no-input] [--apply]` (`src/ci_init.rs`) asks only what
it cannot detect, one line per step: which apps stack-packs detection found to record
(without a container), the `null` commands of each app's profile (the pack's proposal
is offered, `-` declines it, nothing is invented; an app left with no runnable command
refuses), and the runner when the configuration offers more than one. It then plans
`stack-packs`, `ci-baseline` and `security` in one engine plan, with the profile it is
about to write, so the seed is complete on its first and only write: the test job
uploads its coverage data and `diff-coverage` judges it (plan-only, the root profile is
the one planned with; an app profile under a directory is read from disk, so a monorepo
sees its seed whole only in the `--apply` plan). An answers file's stack-packs apps count
as recorded. A plan refusal writes nothing;
with `--apply` the profiles are written first and the plan is computed again from disk,
then applied as `install` applies. A workflow under `.github/workflows/` the lock does
not record refuses (the project's CI is audited, not doubled), as does one it records.
It ends with what to commit and how to see `required` and `agentic-required` green.
`ci-health.workflow-exists` without any workflow names `brakes ci init .` before the
module. Without a terminal or with `--no-input` it asks nothing and takes the
proposals.

**Migrating from `generate`.** Answering `seed` where the lock records a generated
workflow migrates it in one plan. The generated workflow was the project's CI, so the
project's other workflows do not keep the seed out. Only a `ci.yml` of the project's own
does, and then a note says so. A generated `ci.yml` becomes the seed: the engine replaces a
file it recorded as the module's `managed` content with the seed once, when it is unchanged
("Locally changed managed content cannot become a seed" otherwise), and records it as
`seed` from then on. A generated `agentic-ci.yml` is retired by the usual rule: deleted when
unchanged, refused when edited. The ordering is expand, then contract. While the
migration is planned, the manual step `generate-to-seed` asks for `agentic-required` to be
required before the migrating pull request merges (probe `required-check`). That pull
request's own run reports both the seed's `required` and `agentic-required`, and the
generated workflow no longer runs on it, so no check named `required` reports twice and
none stops reporting.

**Commands are read at run time (`workflow: generate`, deprecated).** `ci-baseline`
requires `stack-packs` and renders one `managed` workflow, `.github/workflows/ci.yml`
(`name: CI`). Which commands run is
decided at render time: the `commands` answer, or, unanswered, `lint`, then `test` (or
`verify` when `test` is `null`), then `build`, each where the profile declares it; with
no declared command at all the plan refuses. What each command is, the workflow reads
from `.agent-setup/project.json` with `jq` when it runs, and executes as
`bash -euo pipefail -c "$cmd"`: a command changed in the profile never leaves the
workflow stale, and a command deleted from it fails the job red with
`Verification command missing: commands.<name> is not declared`. An answered command
that is `null` at render time gets no step and a plan note. The installer never runs
any of them. The setup steps come from each recorded stack pack's `ci_setup`, pinned
from the shared pin table.

**One aggregate check.** The jobs are `scope`, the verification job `checks` (or, when
`ci.shards.count` asks for more than one shard, a `lint` job for the other commands and
a `shard` matrix that runs `ci.shards.command`), `workflow-lint`, the jobs other
modules contribute, and `required`. `required` (`AGGREGATE_CHECK`, the single
definition that `repo-baseline`'s ruleset also reads) runs with `if: always` and
`needs` every other job, because GitHub counts a skipped job as a passing check: it
passes only when `scope` succeeded and decided a tier, and every other job is
`success`, or `skipped` and listed by `scope` as skippable; anything else fails naming
the job and its result.

**Tiers and `skippable`.** With `tiers` on (the default), `scope` lists the changed
files of a pull request; when every one matches `inert_paths` (default `docs/**`,
`tasks/**`, `**/*.md`; `.github/workflows/**` is never inert, a negation is never
evaluated) the tier is `docs` and the verification jobs, plus the contributed jobs that
opted in, are skippable. Any other event, an unlistable or empty change set, or any
other path is tier `full`, which skips no verification job. Independently of the tier,
`workflow-lint` is skippable on a pull request whose listed files include nothing under
`.github/`, and the reserved `macos` id on every event but a push. A filter therefore
never turns the gate green over unverified work.

**Hardening.** Top-level `permissions: contents: read`; every checkout with
`persist-credentials: false`; every `uses:` pinned to a 40-hex SHA with its version in a
comment; a `timeout-minutes` on every job (5 for `scope`, `workflow-lint` and
`required`; the verification jobs `ceil(1.5 × ci.cycle_budget_minutes)` capped at 360, else
15); a
concurrency group that cancels superseded pull-request runs only; caches saved only on
the default branch; `workflow-lint` runs `actionlint`, a checksum-pinned binary, and
`zizmor`. The runner label comes from the `runner` answer, never from free text: the
Linux runner the configuration names (`runners.linux`, with a managed
`.github/actionlint.yaml` declaring its label) or `ubuntu-24.04`, GitHub-hosted and the
default without a configured runner; no `self-hosted` label can be generated. `merge_queue` adds
`on: merge_group`. The `macos` answer refuses unless a recorded stack pack declares a
macOS target; with it, the push-only `macos` job (`if: github.event_name == 'push'`,
40 minutes) runs the macOS-target apps on the macOS runner the configuration names
(`runners.macos`), or on `macos-15` when
`macos_runner: github-hosted` is answered, which is always a `ci.hosted-macos` warning
(see `docs/decisions.md`).

**Monorepo.** With more than one Linux app recorded by stack-packs, or one not at `.`,
each app gets a `<id>-checks` job in its directory that runs the answered commands its
own `<path>/.agent-setup/project.json` declares, read at run time; `scope` lists an
app's job as skippable when the pull request changed nothing under its path, and a
path outside every app runs every app.

**Reusable workflow.** This repository hosts `.github/workflows/_reusable-verify.yml`,
rendered from the stack packs and the pin table and kept equal to its render by a test.
With `reusable: true` and a pinned `reusable_sha`, a same-owner repository's `checks`
job calls it while `scope`, `workflow-lint` and `required` stay local; the callee's
repository is the configuration's `reusable_callee`. Without one, a repository of
another owner, or an app whose setup the callee does not carry, gets the single-repo
workflow and a plan note. The step `reusable-reachable` probes that the callee lets the
caller in.

**Brownfield.** A workflow is foreign when it sits directly under `.github/workflows/`
and the lock does not record it as this module's. With any foreign workflow at the
first render, the module writes `.github/workflows/agentic-ci.yml` (`name: CI
(brakes)`) instead of `ci.yml`, lists every foreign workflow (and a project-owned
`.github/actionlint.yaml` or `.yml`) as `never-touch`, refuses when a foreign workflow
already has a job named `required`, and declares the switch: the remote item
`github:switch-required-check` (the default branch then requires only `required`, or
a declared `ci.required_checks` that names `required`, kept verbatim; the remote rule
`ci.required-is-aggregate` expects the same list once the lock records the switch),
written by `apply --remote` only after the step `check-reported` verifies that
`required` has reported on the default branch. The chosen filename is kept by later
renders. Nothing is ever deleted: the old workflow stays `never-touch` and stays
required until the switch verifies.

**`workflow: existing`** is for repositories whose own workflow already embodies the
rules: no CI workflow is rendered, `aggregate_check`
records the project's required check, and the auditor reads the project's workflows.
When an active module contributes jobs (today `security` and `agent-guardrails`),
they go to a separate `managed` workflow, `.github/workflows/agentic-security.yml`
(`name: Security (brakes)`), with its own `scope` and the aggregate
`agentic-required`, made required beside the project's check by the remote item
`github:add-agentic-required-check` after the step `agentic-required-reported`.

**Composition through `ci_jobs`.** Another module adds jobs only through the additive
`Module::ci_jobs`, read by `ci-baseline` from `Context::contributed_jobs`, never by
calling the module. Each job is a kebab-case id and its YAML body, inserted verbatim in
module order before the aggregate and added to its `needs`; its `skippable_under` tiers
reach `scope`, and a job whose optional `app` names a stack-packs app is also skippable
when that app saw no change, as `ci-baseline`'s own `<app>-checks`. A contributed job's job-level `if:` is the tier condition only, because
`scope` sanctions skips by tier and nothing else: a job that must act only on some
events puts the event condition on each of its steps and passes with no step run
elsewhere. Today's contributors are `security` (`security-gate`, `deps-scan`)
and `agent-guardrails` (`cross-review-model` and `cross-review`, unless `review_family`
is `none`: the other model family's review in two jobs, the model with `contents: read`
alone emitting its verdict as a job output and the gate with `pull-requests: write`
alone running no model, both running their steps on pull requests only and the gate
deciding with its exit code, inside the one aggregate rather than as a check of its
own; see `docs/decisions.md`, CI hardening). `ci-baseline` registers last so it sees every contributor. A contributed
id equal to a built-in (`scope`, `checks`, `lint`, `shard`, `workflow-lint`, `macos`,
`required`, `agentic-required`), to another contributor's or not kebab-case refuses at
plan time naming the modules; the plan prints `NOTE [ci-baseline] JOB [<module>] <id> →
<workflow path>` per inserted job.

**Rules.** The static `ci.*` rules (`command-missing`, `aggregate-present`,
`job-timeouts`, `permissions-least`, `workflow-lint`, `no-self-hosted-label`,
`hosted-macos`, `dependabot-actions`, `project-ci-stale`, and `posture.actions-pinned`)
read every workflow under `.github/workflows/`, owned or not, with the YAML walker of
the auditor, and report as `WARNING: ci.<rule>: <text>` (or `unverified: <file>:
<reason>` for a file the walker cannot read); they never make `doctor` `NOT READY`.

**The project's CI, audited with patches (#23).** `auditor::ci_audit` reads the
workflows under `.github/workflows/` that the lock does not record as `managed` (what
`brakes` renders it fixes by rendering again) and reports what the brakes need from the
project's own CI, each finding with the patch that settles it when a line edit can:
`ci.permissions-least` (no top-level `permissions:`: `contents: read` before `jobs:`),
`ci.concurrency` (a pull-request workflow without a group: one that cancels superseded
pull-request runs), `ci.job-timeouts` (`timeout-minutes: 15` after the job's `runs-on`),
`posture.actions-pinned` (an action the shared pin table knows, pinned by SHA; any
other is named without a patch), `ci.pull-request-target-head` (a checkout of the pull
request's head under `pull_request_target`: the `ref:` goes), `ci.untrusted-interpolation`
(an author-chosen `github.event.*` value in `run:`, moved to the step's `env:`),
`ci.pull-request-trigger` (no project workflow runs on pull requests: `pull_request`
added to `on:`), `ci.command-missing` (a command of ci-baseline's selection, `lint`, `test` or else
`verify`, and `build`, that no step runs: a step runs it when its `run:` holds the
command as declared, names `commands.<name>`, reads `.commands[…]` at run time with the
name in its `env:` as the seed does, or, for `test`, runs a pack's measured run that
takes its place; a job appended with checkout, the app's pack setup and the command)
and, where `security` is installed (its `diff-coverage` is what judges the data),
`ci.coverage-upload` (a recorded app whose pack has a coverage recipe and whose
`agentic-coverage-<app id>-<job>` no step uploads: the step that runs its test command
replaced by the pack's measured run and upload; an app whose pack has none is named as
not judged, with the pack's reason, and no patch). Patches are line edits on the file
as written, so its comments and layout stay. `doctor` prints one line with the count;
`doctor --propose` prints every finding as `PROPOSE <rule> <file>: <text>` with its
unified diff (`--json --propose` adds `proposals`), then states that nothing was
written. Nothing in the module writes: a patch reaches the default branch through a
pull request labelled `human-approved`, since workflows are a protected path. The
proposals never change readiness, a level or the exit code: the ids the catalogue
already holds are judged, as before, from `doctor`'s own `WARNING` lines, and the new
ones (`ci.concurrency`, `ci.pull-request-target-head`, `ci.untrusted-interpolation`,
`ci.pull-request-trigger`, `ci.coverage-upload`) hold no level until a decision
allocates one.
`remove ci-baseline` deletes an unchanged workflow and actionlint configuration,
refuses an edited one and keeps every `never-touch` workflow and remote item.

## Security gates (2026-10-28)

This section states what the module
`security` (`src/modules/security/`) does. Its policy (the free
gate as the default, checksum pins, the bypass policy and its expiries, its two remote
items and its rules' levels) is in `docs/decisions.md`; this section repeats none of
them.

**The free gate is data.** `security` requires `ci-baseline` and `stack-packs` and runs
nothing: it contributes two jobs through `Module::ci_jobs`, which `ci-baseline` inserts
into `ci.yml` (or into `agentic-security.yml` under `workflow: existing`) and adds to
the aggregate's `needs`. `security-gate` is never skippable, because a docs-only pull
request can leak a key: gitleaks scans the pull request's commit range, and the full
history on any other event or when the range cannot be computed (it prints
`history: full` or `history: <base>..<head>`), then the exceptions check runs.
Every shell a job runs is a fragment under `templates/security/fragments/`, embedded in
its `run:` without comment-only lines: a line whose first non-blank character is
`#` outside a quoted string or a heredoc body is dropped, every other line is kept as
written. The fragments keep their comments, and the tests run the fragments themselves.
`deps-scan` runs OSV-Scanner over the lockfiles, is skippable under tier `docs`, and
exists only when the `deps` answer is not `false` and a recorded stack pack declares a
lockfile. Answers: `secrets_scanner` (`gitleaks`; `betterleaks` refuses until its pin
exists), `deps`, `hooks` (`pre-commit-config`, `lefthook` or `none`) and
`bypass_max_days` (at most 30, so an answer can only tighten the decision). The module
seeds, once, `.agent-setup/security-exceptions.json`, `.gitleaks.toml`,
`osv-scanner.toml`, `.trivyignore.yaml` and the hook-manager configuration
(`.pre-commit-config.yaml` or `lefthook.yml`, gitleaks pinned to the commit of the
release CI installs, plus actionlint when `.github/workflows/` exists); it manages
`docs/agent-setup/security-gates.md`, the guide to the gates, exceptions and bypasses;
and it declares two remote items: `github:secret-scanning` (secret scanning and
push protection `enabled`) and `github:private-vulnerability-reporting`. The engine
never writes them; `apply` lists their diff and `apply --remote` writes them through
the host adapter, enabling only (private vulnerability reporting is sent only after a
read shows it off). Each is probed by the step of the same id: `verified` when enabled,
`pending` with the statuses observed otherwise, `failed` when GitHub refuses the read
(the plan refusal where the plan lacks the feature). Private vulnerability reporting
answers 404 on private repositories, where the step is `not-applicable` with GitHub's
message rather than pending.

**Static analysis and container scans (slice 2).** Two more jobs, both skippable
under `docs` and both starting with the bypass step. `sast` follows the `sast` answer:
`semgrep` (the default for every stack; the spec's Open question 6 is closed that way)
runs Semgrep CE from its container image pinned by manifest digest (`pins::SEMGREP`,
Semgrep ships no release binary) with `--config p/default` plus the packs of the
plan's stacks (`jobs::semgrep_rulesets`: `p/rust`, `p/python`, `p/javascript` and
`p/typescript`, `p/golang`, `p/kotlin`, `p/swift`), failing on any `ERROR`-severity
finding; `codeql` renders `github/codeql-action` `init` and `analyze` by SHA from the
shared pin table with the stacks' languages (`jobs::codeql_language`) and the job-level
`security-events: write` the action documents, refuses when no stack has a language,
and adds the informational step `code-security`; `none` renders nothing.
`container-scan` exists when the `container_scan` answer is not `false` and a
`Dockerfile` at the root or an app path, a container app or `delivery`'s image job
exists: Trivy by checksum (`pins::TRIVY`, after the compromise window) runs `trivy fs
--scanners vuln,misconfig,secret` and `trivy config` over the checkout, or `trivy
image` over the reference the image job outputs once `delivery` records `image_job`
(and the output name `image_ref`) in `.agent-setup/modules/delivery.json`, with
`needs` on that job; `severity` is `HIGH,CRITICAL` by default or `CRITICAL`; the
seeded `.trivyignore.yaml` is passed with `--ignorefile` and `--ignore-unfixed` is
never generated. The rules `security.sast-gate` (Silver, required from criticality
`customers`) and `security.container-gate` (Silver, where a `Dockerfile` or
`Containerfile` exists within three directory levels, outside the profile's
`excluded_paths`) read any workflow, owned or not.

**The PII pack (slice 4).** The `pii` answer has no default: absent, it is
derived `true` when `project.json`'s `criticality` is `personal-data-or-payments` and
`false` otherwise, and an explicit `false` under that criticality refuses the plan.
With the pack the module seeds `.agent-setup/pii.yaml` (`schema`, `controller`,
`dsar_contact`, `sla_days`, `fields: []`) and `docs/runbooks/dsar.md` (runbook-template
shape, the declared fields grouped by `erasure` with the storage each lives in,
rendered from the declaration present at the first install, else from the seed; a seed,
so later edits are the project's), and `security-gate` gains the step `pii-check`
after the exceptions check. `pii.rs` (Rust, line-wise over the seeded shape) and
`pii-check.sh` (bash, `jq`, `awk`) apply the same rules and print the same findings,
proven over one fixture matrix: every field has the seven keys (`path`, `category`,
`purpose`, `lawful_basis`, `retention`, `exclude_from`, `erasure`) with known values,
`retain-legal` names its obligation in `purpose`, `credentials` excludes `logs` and
`traces`, and under the criticality the file exists with a declared controller, a
contact and at least one field. The step ends with `pii: required|not required, <n>
fields` (or `absent`). `observability` will read `exclude_from` for `logs` and
`traces`, the data modules `analytics` and `cdc`; neither exists yet. The declaration
is the owner's statement, audited for shape and presence, never for completeness, and
the installer never reads production data.

**The coverage jobs only judge (#22).** `diff-coverage` and `coverage-ratchet` are
the jobs of `.github/workflows/agentic-coverage.yml` (`managed`, `on: workflow_call`),
rendered whenever an app is judged or the ratchet is answered, under every
`ci-baseline` workflow mode; no contributed job and no workflow of `brakes` runs them.
The project's CI calls it from a job named `diff-coverage` that needs its test jobs,
which upload `agentic-coverage-<app id>-<job>` as the stack pack's `CoverageUpload`
says; its aggregate needs that job. Each job downloads and combines the parts with the
recipe's `combine` (coverage.py's needs the pack's setup), 15 minutes, no service and
no test command. An app with no part fails `No coverage data`, naming the artifact and
the guide, except on a push or on a pull request that changes nothing under its path,
where it is not judged. The base report is kept only by `diff-coverage`, on pushes to
the default branch; a missing one warns and is never recomputed. `coverage_source` is
retired: accepted, ignored and noted for one version.

**The coverage ratchet.** Opt-in: `coverage_ratchet` (default `false`) adds the
job `coverage-ratchet` to `agentic-coverage.yml`, bypassable like
`deps-scan`, and seeds `.agent-setup/coverage.json`, one line percentage per app whose
stack pack carries a coverage recipe (`python-uv`, `rust`), each at `0` because
the installer never invents a measurement. The job writes each covered app's report
from the combined data (`combined_report`: `coverage json` for coverage.py, the
executed share of the LCOV `DA` lines for rust), reads the number with the recipe's
`jq` filter and compares it with the record in `coverage-ratchet.sh`: below the
record minus `coverage_tolerance` (a decimal string, `0.5` by default) fails, more
than one point above warns to ratchet the record up. Lowering the record is the bypass: the exceptions check reads the
record at the pull request's base and requires an active `coverage-reset` entry for
every lowered or removed app, in both implementations. With the ratchet answered,
`doctor` reports `security.coverage-ratchet` (Gold) when the record or the job is
missing. Coverage of the changed lines is not judged (spec Open question 10).

**Checksum-pinned binaries.** Every scanner the security jobs run (gitleaks,
OSV-Scanner, Trivy), and `ci-baseline`'s actionlint, comes from `security/pins.rs`: a version and, per
`linux/amd64` and `linux/arm64`, a release URL and its SHA-256 from the upstream
checksum file. `install-tool.sh` downloads it, compares the digest and only then
installs the binary (from the archive root, or from the one regular file the optional
`TOOL_BIN_PATH` names, as for Hurl's `hurl-*/bin/hurl`); a mismatch is one `::error::` line and exit 1, with nothing
installed. No marketplace action installs these binaries (`trivy-action` and
`setup-trivy` were re-pointed in March 2026, CVE-2026-33634); the remaining `uses:`
lines (checkout, artifact upload, and `ci-baseline`'s zizmor action) come by SHA from
the shared pin table. `security.scanner-unpinned` and
`security.trivy-compromised-version` (Trivy 0.69.4 to 0.69.6) report a workflow that
breaks this.

**The bypass inventory and its expiry rules.** Every way of switching a gate off is an
entry of `.agent-setup/security-exceptions.json` with eight fields (`id`, `kind`,
`target`, `reason`, `issue`, `owner`, `created`, `expires`), or an entry of a native
file that carries its own expiry (`.trivyignore.yaml` `expired_at`, `osv-scanner.toml`
`ignoreUntil`, each naming an issue). Kinds are `job-bypass`, `ruleset-bypass-actor`,
`repo-variable`, `continue-on-error`, `allowlist` and `coverage-reset`; `expires -
created` is at most `bypass_max_days` (30 by default), and at most 365 days for
`allowlist` and `ruleset-bypass-actor`. Every `.gitleaksignore` fingerprint,
`.semgrepignore` path and `.gitleaks.toml` allowlist entry must be registered by an
`allowlist` entry; a plain `.trivyignore` is refused because it cannot carry an expiry.
An expired entry turns `security-gate` red; renewal is a new entry with a new `id`,
never an edited date. `SECURITY_BYPASS`, a repository variable holding a JSON array of
inventory ids, is the one sanctioned switch: it lets a job named by an active
`job-bypass` succeed with a warning and turns it red once the entry expires;
`security-gate` ignores it, so the secrets scan and the exceptions check have no
bypass.

**Two tested implementations of the check.** `exceptions.rs` (Rust, line-wise over the
seeded shapes, no YAML or TOML crate) feeds `doctor`'s `security.bypass-*` rules;
`exceptions-check.sh` (bash, `jq` and `awk`) runs inside `security-gate` and ends with
`exceptions: <active> active, <expired> expired, <unregistered> unregistered`.
`tests/security_gate_shell.rs` runs both over every fixture and requires the same
findings, so `doctor` and the gate cannot disagree; a file outside the seeded shape is
`unverified` and named by both. Only the gate has a pull-request base, so only it
compares the coverage record (`exceptions::check_against` is the Rust twin the test
hands the base text).

**What the installer never does with `.git/`.** It never writes under `.git/`, never
installs or registers a hook and never edits `.git/config`. The hook-manager file is a
seed the project owns; installing the hook (`pre-commit install`, `prek install` or
`lefthook install`) is the owner's, once per clone, and the manual step
`hooks-installed` only probes whether `.git/hooks/pre-commit` exists. The `doctor`
rules are `security.secrets-gate`, `security.deps-gate`, `security.secrets-full-history`,
`security.scanner-unpinned`, `security.trivy-compromised-version`,
`security.bypass-inventory-valid`, `security.bypass-unregistered`,
`security.bypass-expired`, `security.sast-gate`, `security.container-gate`,
`security.pii-declared` (only under `personal-data-or-payments`) and, where the ratchet
is answered, `security.coverage-ratchet`, reported as warnings at the levels of. With `doctor --remote`
and `--fleet` the auditor adds the remote rules: `security.secret-scanning` and
`security.private-vulnerability-reporting` (Bronze; a repository that is not public records
the plan risk `secret-scanning-unavailable-on-plan` instead of failing, and PVR is not
required there), the remote halves of `security.bypass-unregistered` (`vars.SECURITY_BYPASS`
ids against the inventory) and `security.secrets-full-history` (the `history:` claim in the
latest default-branch log of a secrets job that is not the managed shape),
`security.scanner-stale` (Gold, 90 days behind the upstream release), and
`security.attestation-verified` and `security.sbom-scanned`, which wait for `delivery`. They
hold no call allowance and read only what the blocks before them leave.

## Tests of what the user sees (2026-10-29)

This section states what the module `qa`
(`src/modules/qa/`) does. Its decisions are in `docs/decisions.md`; this section repeats none of them.

**What it renders.** `qa` requires `ci-baseline` and `stack-packs` and runs nothing: it
never runs Hurl, Playwright, `npm`, a browser or the application. Its answers are
`qa_dir` (`qa`), `api`, `api_start`, `api_url`, `api_ready_path`, `web`
(`none`/`seeded`/`project`), `web_start`, `web_url`, `web_command`, `web_dir` and
`apps`, each under `apps.<id>.*` per app. Unanswered, `api` and `web` are derived from
each recorded app's files (`qa/detect.rs`), and the plan prints a `NOTE` with the
evidence: `api` is true for a `Dockerfile` (also the one `stack-packs` seeds in the
same plan) or a service framework in the manifest; `web` is `project` for
`@playwright/test` plus a root `playwright.config.*`, `seeded` for a front-end framework
(`react`, `vue`, `svelte`, `@angular/core`, `solid-js`, `preact`) or an answered
`web_url`. The start commands are never invented: a derived `api` or `web` without
its start command refuses the plan. The URLs are local only (`http://127.0.0.1:<port>`
or `http://localhost:<port>`), and `qa_dir` is never, and never contains, a test
directory (`tests`, `test`, `e2e`, `spec`). With `api` the module seeds
`<qa_dir>/api/00-ready.hurl` and `<qa_dir>/api/smoke.hurl`; with `web: seeded` it
seeds `package.json` (`@playwright/test` at `tools.playwright`), `playwright.config.ts`
(`retries: 0`, `workers: 1`, `toHaveScreenshot` with `maxDiffPixels: 0`, JUnit and
HTML reporters, `webServer` from `QA_WEB_START`) and `smoke.spec.ts` under `web_dir` (`<qa_dir>/web`). Seeds are written
once and are the project's afterwards; `docs/agent-setup/qa.md` is the managed guide.
An existing root `playwright.config.*`, every existing test directory and every
`.hurl` file the module did not seed are listed `never-touch`, so no module writes
them. With `web: project` nothing is seeded under `web_dir` (`.`).

**One `.hurl` file, three uses.** A `.hurl` file never names a host: every request
starts with `{{base_url}}`, and `qa::hurl::literal_host` is the one reading of a
request line, shared by the seed check and the auditor. The pull-request job passes the
local `api_url`; `delivery`'s post-deploy smoke and `observability`'s uptime probe will
pass the deployed and production URLs to the same files. They read where the files are
through `qa::files::files(cx)`, a `QaFiles { app, dir, ready, glob }` per target with an
API (the root, then each listed app; it refuses when `qa` is not active or no target has
an API), and render the commands through `qa::files::hurl_command(&files, base_url_var)`,
which `qa-api` itself uses: `QA_DIR` in the environment, readiness with Hurl's own
`--retry` on the readiness file only, then every file once with a JUnit report, the
base URL always read from the named variable.

**The two jobs.** Both reach `ci-baseline`'s workflow through `Module::ci_jobs` (in
`ci.yml`, or `agentic-security.yml` under `workflow: existing`), join the aggregate's
`needs` and are skippable under tier `docs` (`if: needs.scope.outputs.tier != 'docs'`).
`qa-api` (15 minutes, or the readiness wait in minutes plus 5 when that is more,
capped at 360) checks out, runs the root app's `ci_setup`, installs Hurl from
the shared pin table through `security`'s `install-tool.sh` (SHA-256 per architecture,
`TOOL_BIN_PATH` for `hurl-*/bin/hurl`), starts the API with `start-app.sh` (its own
session, a PID file, the log under `$RUNNER_TEMP/qa/`), retries only `00-ready.hurl`
(`--retry <api_ready_timeout> --retry-interval 1000`: about one attempt a second for
`api_ready_timeout` seconds, default one measurement of `ci.cycle_budget_minutes` when
declared, else 600, #1243), runs every `.hurl` under `<qa_dir>/api/` once
with `hurl --test --report-junit`, stops the process group with `stop-app.sh` (the
last 50 log lines on failure) and uploads the JUnit report and the log. `qa-web`
(20 minutes) runs in the pinned `images.playwright` image as its `container:`, the
environment the baseline is generated in. It checks out, runs the root app's
`ci_setup` (plus `actions/setup-node` at `tools.node` when that app is not node),
fails with
`qa-web: <web_dir>/package-lock.json missing; run npm install locally and commit it`
when the lockfile is absent, runs `npm ci` and `npx playwright install chromium` (the
image carries the system packages), then `npx playwright test` (seeded, whose config
starts the web) or
`web_command` (project) with `QA_WEB_START` and `QA_WEB_URL` in `env:`, and uploads
`playwright-report/` and `test-results/`. Both uploads keep 7 days. No shell has a
retry loop, `|| true` or `continue-on-error`, and no job passes `--update-snapshots`.
Answers reach a job only through `env:`. Monorepo ids `<app>-qa-api` and
`<app>-qa-web`, each skipped with its unchanged app, are qa T13.

**The protected baseline.** Screenshot baselines live in Playwright's
`<spec>-snapshots/` directories and are generated only locally, on Linux, in the pinned
`images.playwright` image. When `qa` is active with a web app, `ci-baseline`'s
unanswered `protected_paths` gains `<web_dir>/*-snapshots/**` (`**/*-snapshots/**`
when `web_dir` is `.`, one entry per app), and `repo-baseline`'s CODEOWNERS seed gains
`/<web_dir>/ @<owner>` (`**/*-snapshots/ @<owner>` at the root) when `codeowners` is
true; `qa::protected` is the one derivation both read, through a soft read of `qa`'s
answers. A pull request that changes a baseline keeps `required` red until the owner
adds `human-approved`. An answered `protected_paths` is never modified, and no deny rule
is added to `agent-guardrails`.

**Contracts (slice 2).** When `openapi` or `asyncapi` is answered or derived
(the only OpenAPI 3 or AsyncAPI document within four levels; `none` turns it off, the
engine's schema having no null), `qa` contributes `qa-contracts`, never skippable by
tier because a contract under `docs/` would otherwise skip its own check. It checks out
with `fetch-depth: 2`, installs vacuum 0.35.0 and oasdiff 1.34.1 by checksum through
`install-tool.sh`, or Node and `@asyncapi/cli` 6.2.1 with `--ignore-scripts`, and runs
`templates/qa/fragments/contracts-check.sh`: a `$ref` outside the file refuses before
any tool runs; lint on every event; on pull requests only, the comparison with
`git show HEAD^1:<path>`, red on a break unless `human-approved` is present. The report
under `$RUNNER_TEMP/qa/contracts/` is kept 7 days. The contracts are `never-touch`; the
Silver rules `qa.contract-lint` and `qa.contract-compatible` read any workflow. In
monorepo mode each listed app with a contract gets `<app>-qa-contracts`: its
answers `apps.<id>.openapi`, `.asyncapi` and `.contract_ruleset` are relative to the
app, the root's walk skips listed apps, the job carries `CiJob.app` so only an
unchanged app skips it, and the script runs from the app's directory, reading the base
as `HEAD^1:./<path>`.

**Rules and manual steps.** `doctor` reports `qa.hurl-no-literal-host`,
`qa.tools-pinned`, `qa.no-snapshot-update-in-ci` and `qa.report-artifact` (Bronze) and
`qa.api-smoke-present`, `qa.web-smoke-present`, `qa.screenshot-baseline-present` and
`qa.snapshots-protected` (Silver) as `WARNING: qa.<id>: <text>` over every workflow,
`.hurl` file, `package.json` and Playwright config, owned or not; never `NOT READY`,
never an exit code. The auditor's block `qa`, after `agents`, judges them from those
findings; under `--fleet` they are `not-required`, and `qa.main-green`
(Silver, remote) is `unavailable` until qa T19. The manual steps are
`qa-web-lockfile` (`file-exists <web_dir>/package-lock.json`), `qa-web-baseline`
(seeded only, after the lockfile, `file-exists
<web_dir>/smoke.spec.ts-snapshots/home-chromium-linux.png`) and `qa-api-reported`
(the `check-run-reported` probe on the default branch).
