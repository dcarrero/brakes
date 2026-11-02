# Decisions

These are the decisions the design of `brakes` depends on. They were taken during the tool's
earlier development, imported into this repository and rewritten in neutral terms; each keeps
its original date and is marked "imported". Newer decisions are added above them, newest first.

## A module the lock records and this build does not ship is released, not refused — 2026-11-02

Decided upstream by the owner when the installer's earlier copy was retired. Context: repositories
installed by an earlier, larger build carry about 29 lock entries of `setup-core` (guides under
`docs/agent-setup/`, the managed block of `AGENTS.md` and `CLAUDE.md`). This product never ships
that module, so every plan refused them (`Managed destination owned by module setup-core:
AGENTS.md`) and no build of this repository could update them.

1. **Released.** In an `install` or `configure` plan, a module the lock records that is neither
   active nor compiled into this build leaves the lock with every entry of every class. Nothing
   on disk is deleted: its files stay as the project's own content, a managed block loses its two
   marker lines and keeps its text, `managed-entries` stay as the project's members, and its
   answers file stays.
2. **Seen before `--apply`.** The plan prints one `RELEASED [<module>] <path> — <what>` line per
   path, before the changes. A second plan after `--apply` prints `No changes.`: every module
   renders against the lock as it is once released, so both plans agree.
3. **Refusals that stay.**
   - A lock written by a newer installer is refused instead: an older build never drops what a
     newer one owns.
   - A released `never-touch` path still refuses a render in the plan that releases it.
   - A block marker that shares its line with other text, or a duplicate or incomplete block,
     refuses rather than guess which text is the project's.
   - A `managed` render over a released file still refuses, as over any unowned file.
4. **Accepted trade-offs**, named so nobody rediscovers them:
   - Switching to a build that ships the module again does not take its files back; the owner
     moves them aside or adopts them.
   - Released remote settings stay as they are on the host and are no longer tracked.
   - `remove <module>` cannot clean up after a release; the plan shows the released paths first,
     so an owner who wants the files gone removes the module before applying.
   - Released text may contradict a block an active module adds after it (`AGENTS.md`); the owner
     edits the released text, which is now theirs.
   - A kept answers file can be stale if the module is installed again later.
   - `remove` plans never release; only `install` and `configure` do.

Reviewed before implementation by a fresh-context reviewer and by a second model family.

## A project declares the paths that are not its files; `doctor`'s file scans skip them — 2026-11-02

Context (#16): `doctor` walks the checkout for Dockerfiles and Playwright specs and judges every
one it finds as the project's. A repository that ships templates or test fixtures (files it
renders for other repositories, or feeds to its own tests) is judged on them:
`security.container-gate`, `stack.image-by-digest`, `stack.image-nonroot` and
`qa.screenshot-baseline-present` fail at Silver on files the project never builds and cannot fix
without deleting them. The per-file `allowlist` exclusion (#1171) does not fit: it expires (365
days at most), only `container-gate` and `screenshot-baseline-present` read it, and a template is
not a temporary exception.

1. **A declared exclusion, not a built-in rule.** `.agent-setup/project.json` gains the optional
   field `excluded_paths`: repository-relative paths, files or directories, that are not the
   project's files. A file at or under one of them is not judged by any rule that finds files by
   walking the checkout (the Dockerfile walks of `security` and `stack-packs`, and `qa`'s file
   walk).
   Rejected: a built-in rule such as "a file with unrendered `{{...}}` placeholders is a
   template". It misses the files a project keeps without placeholders (a never-built pin file,
   a rendered seed, a golden, a fixture), and it would let any project file escape every gate by
   carrying a placeholder.
2. **Validated with the profile.** The field is a list of strings; each is inside the repository
   (no absolute path, no `..`, no symlink on the way) and is not the repository root. Absent
   means empty. An invalid field refuses the profile, as every other field does.
3. **Visible, never silent.** `doctor` prints one `EXCLUDED [project.excluded_paths] <path>`
   line per declared path, in text and in `--json`: information, never a finding. The field
   lives in the profile, so changing it is a reviewed change of the repository like any other.
4. **No new exemption from the rules themselves.** A repository whose own Dockerfile or spec is
   outside the declared paths is judged exactly as before.

## A single maintainer is not asked for an approval nobody can give — 2026-11-02

Context: GitHub does not let the author of a pull request approve it. In a repository whose
only human with merge rights is one person, `posture.human-approval-required` and
`posture.codeowners-review` judged a review nobody can give: they were already not required for
P1, but each still reported `failed` with its evidence, as if something were missing.

1. **Exactly one measured human: not required, with the reason.** When the humans measure
   counts exactly one collaborator with merge rights, both rules are `not-required` with the
   reason `single maintainer: nobody else can approve`, and they are not evaluated (no read is
   spent on them). The rule ids, levels and profiles they are required for do not change.
2. **Only a measured count of one.** An unavailable humans measure (always the case without
   `--remote`) or a count of zero proves nothing about who can approve, so both rules are
   evaluated and reported as before; with two or more humans they are evaluated and required
   exactly as before.
3. **The merge gate of a single maintainer** stays the required checks, plus the
   `human-approved` label on protected paths. The doctor names no substitute approval.
4. **CODEOWNERS is not written for anyone.** `governance.codeowners-present` keeps its
   allocation (P2, P3); naming an owner is configuration the owner adds, never a file `brakes`
   puts in the tree with a person's name.

## `brakes` never runs the project's commands in CI; the project's CI runs them once — 2026-11-02

Decided by the owner. Context: measured on a Python monorepo, with the default `diff-coverage`
the backend suite ran twice per pull request (about 8 minutes each): once in the project's CI,
once again under coverage in `diff-coverage`. With `coverage_source: project-ci` it ran once,
plus 1.6 minutes to combine and judge.

1. **The project's CI runs the declared commands** (`commands.verify`, `test`, `build`, `lint`),
   once. No job `brakes` owns runs them. A CI workflow `brakes` writes for a project is a `seed`:
   written once, owned by the project from then on, never re-rendered or overwritten.
2. **No CI: warn and guide.** `doctor` fails `ci-health.workflow-exists` and points to the
   guided setup, which writes the seed.
3. **A CI exists: audit it and propose, never apply.** `doctor` audits what the brakes need from
   the project's CI; each finding carries its patch as a diff. `brakes` never edits the
   project's `.github/workflows/` by itself: a patch reaches the default branch through a pull
   request with `human-approved`, because workflows are a protected path (brake 4).
4. **The brakes' own jobs only judge** what the project's CI produces: scope, the scanners,
   cross-review, held-out tests, `workflow-lint` and the aggregates. `diff-coverage` and
   `coverage-ratchet` read the coverage data the project's test jobs upload as
   `agentic-coverage-<app id>-<job>`, in the reusable workflow the project's CI calls; the mode
   that measures by running the suite again is removed, and `coverage_source` is retired.
5. **Each stack pack carries the recipe** for its test job's measured run and upload. A pack
   whose coverage tool cannot produce data `diff-coverage` reads says so; its apps are not
   judged, and `brakes` never falls back to measuring.
6. **No window over unverified work.** A repository moving from a generated workflow requires
   the new checks first and retires the old ones afterwards (expand, then contract).

Outside this decision, and unchanged: the local Stop hook runs `commands.verify` on the agent's
machine (that is brake 1); the opt-in `heldout`, `heldout-properties`, `mutation-diff` and `qa`
jobs run the commands the project answers for those brakes (held-out tests, mutation testing,
end-to-end tests), never the declared ones.

## Codex reaches the model API only through the filtering model proxy — imported, 2026-10-30

Context: once model jobs ran as an unprivileged user (see the entry below of the same date),
Codex's calls to the Responses API were still unfiltered. The proxy that `openai/codex-action`
starts forwards whatever Codex sends with the real key, so a compromised model could ask for the
API's server tools (web search, remote MCP servers). A measurement on GitHub-hosted runners and on
a self-hosted runner, with fake keys, showed that the action's proxy (codex-responses-api-proxy,
Codex 0.165.0) accepts a loopback `http://127.0.0.1` upstream through `responses-api-endpoint`,
that it already refuses every request but `POST /v1/responses`, and that Codex sends one shape:
no query, no `OpenAI-Beta`, the body keys `client_metadata`, `include`, `input`, `model`,
`parallel_tool_calls`, `prompt_cache_key`, `reasoning`, `store` (false), `stream`, `text` and
`tool_choice`, and no tools in the first request.

1. **The action keeps running Codex, with a dummy key.** Its upstream is `model-proxy.py` in
   OpenAI mode on loopback, running as the runner user and reading the real key from stdin. The
   real key exists in that process only.
2. **The OpenAI mode forwards only the measured shape:**
   - `POST /v1/responses` without a query, to `https://api.openai.com/v1/responses`, with the
     proxy's own bearer replacing any credential that arrives;
   - a JSON object of at most 32 MiB whose keys are the measured ones, plus `tools`;
   - tool entries only of the client-executed types `function`, `custom` and `local_shell`, and
     `tool_choice` only as a string;
   - at most four requests at once.

   Everything else is refused with 403, 411, 413 or 429: server tools (`web_search*`,
   `file_search`, `code_interpreter`, `computer_use*`, `image_generation`, `mcp`), stored prompts
   (`prompt`), `background`, `conversation`, any other key. A key or tool type Codex turns out to
   need enters only with a measurement from a run with a real key.
3. **The same proof as for Claude.** The egress limit is proved again right before the model runs
   through the proxy; the residual risk for Codex becomes the one Claude has: the inference calls
   the filter lets through.

Rejected: running the Codex CLI directly as `agent-model` (the action accepts the custom upstream
and keeps its sandbox preparation); trusting the action's own proxy (it filters paths, not server
tools).

## Security shells are embedded without comment-only lines — imported, 2026-10-30

Context: the `security` module embeds each shell fragment in the `run:` of the job that uses it,
and a test requires every security golden to stay under half the workflow reader's cap
(`MAX_BYTES`, 256 KiB). With `diff-coverage` on by default and `mutation-diff` opted in, the
mutation goldens reached 133,907 bytes against 131,072.

1. **Comment-only lines are dropped when a security shell is embedded in a rendered workflow.** A
   line is dropped when its first non-blank character is `#` and it lies outside a quoted string
   and a heredoc body; `#!` lines and every line that holds code are kept as written, in order.
   The fragments under `templates/security/fragments/` keep their comments and remain the
   reviewed source.
2. **The tests keep running the fragments.** The Rust-versus-shell agreement tests run the files
   on disk; a test asserts that each embedded body equals its fragment minus comment-only lines,
   and that the stripped text passes `bash -n`, shellcheck and the exceptions agreement matrix.
3. **The margin stays.** The cap and the half-cap test are unchanged.

Rejected: rendering the mutation goldens with `coverage_changed_lines: false` (it would hide that a
repository with both jobs renders that size); raising the margin (it lowers the bar); stripping
every `#` character or blank lines (a `#` inside a string or a `$#` is code).

## Model jobs run as an unprivileged user behind an egress limit on that user alone — imported, 2026-10-30

Context: "CI hardening for agent workflows" (point 3) closed outbound traffic for the whole runner
before the model started, and stopped the work if the runner's own traffic could not pass. A spike
measured exactly that on GitHub-hosted runners and on a self-hosted runner: under a host-wide
default-deny, `upload-artifact` fails (`EHOSTUNREACH`) and the job never completes, because the
runner's results service, its blob storage (a different storage account per run) and the hosted
VM agent all need new connections. The alternative chosen confines the model by user; a second
spike run showed the model, as `agent-model`, reaching its API and nothing else while
`upload-artifact` and the job completed.

1. **The model runs as `agent-model`, a user without sudo.** The egress step creates it (home
   0755, no sudoers entry, no supplementary group) and works on a copy of the checkout that
   `agent-model` owns: `/home/runner` is 0750 on the measured images, so the runner's workspace
   and temp directory, its event file included, stay unreadable to the model.
2. **Outbound traffic is closed for that uid only** (`iptables`/`ip6tables` matched on the uid),
   per address because the images lack `ipset`. Allowed:
   - loopback, except port 53 on it;
   - replies to the user's own connections;
   - IPv6 router and neighbour discovery, only to `fe80::/10` and `ff02::/16` with hop limit 255;
   - the job's hosts, which are none today.

   The uid has no name resolution: no packet to the resolver stub, no rule for the upstream
   resolvers, an ACL entry denying it systemd-resolved's varlink socket and a D-Bus policy denying
   it `org.freedesktop.resolve1`. Any allowed host goes to `/etc/hosts`. The runner's own traffic
   is untouched. The self-test runs as `agent-model`, once after the checkout and again right
   before the model, and fails the job when a host outside the list answers, a name resolves
   (`getent`, `resolvectl`, `dig`), a UDP datagram leaves, `sudo -n true` or `sudo -n -l`
   succeeds, the user's groups are anything but its own, it can write the Docker socket, or the
   probe URL (when the job sets one) does not answer.
3. **No model process holds a credential.**
   - **Codex** runs with `safety-strategy: unprivileged-user` and `codex-user: agent-model`; the
     key is held by a proxy running as the runner user (see the entry above).
   - **Claude** runs as the pinned Claude Code CLI as `agent-model`, not through the action, which
     cannot run as another user. The CLI is installed as an exact npm version (`tools.claude-code`
     in the pin table, also used by the dev container) and holds a dummy token.
     `ANTHROPIC_BASE_URL` points at `model-proxy.py`, a standard-library loopback proxy running as
     the runner user, which reads the real token from stdin and forwards to the fixed upstream
     `https://api.anthropic.com`. It forwards only what the pinned CLI was measured to send:
     `POST` to `/v1/messages` or `/v1/messages/count_tokens`, with or without `?beta=true`; a JSON
     object body of at most 32 MiB with no `mcp_servers`, no `container` and no `tools` entry
     carrying a `type` (the API's server tools); the measured `anthropic-beta` values, others
     dropped; at most four requests at once.
   - **Both model egress allowlists are therefore empty.** The stack packs' registries leave the
     implementing job's list while the agent's Bash is git-only.
   - **Defence in depth** in both Claude jobs: `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB` on, with
     bubblewrap allowed user namespaces by an AppArmor profile for `/usr/bin/bwrap` alone (modelled
     on AppArmor's `bwrap-userns-restrict`), whatever bwrap runs stacked against a profile that
     denies capabilities and further user namespaces, and a step proving a nested user namespace
     is refused, while `kernel.apparmor_restrict_unprivileged_userns` stays at 1;
     `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`; `GIT_CONFIG_GLOBAL=/dev/null` and
     `GIT_CONFIG_NOSYSTEM=1`; `--disallowedTools` for `Read`, `Grep` and `Glob` under
     `//proc/**` and for `Bash(git * --output*)` and `Bash(git * -o *)`; the model's output
     printed between `::stop-commands::` markers so it cannot issue workflow commands.

   The cross-review verdict is the CLI's `structured_output` (`--output-format json
   --json-schema`); Codex's review schema is a file (`output-schema-file`), because the action's
   inline schema is unreadable for `codex-user`.
4. **What the action did for Claude is done in the workflow:** the actor check (a person with
   write access, or Dependabot for the review); the commit identity of the implementing job; the
   base restore of `.mcp.json`, `.claude.json`, `.gitmodules`, `.ripgreprc`, `.husky/` and every
   `.claude/` directory at any depth, after deleting any tracked path named `.claude` (which can
   only be a file or a link). A `claude -p` run without `--bare` loads the folder's hooks and MCP
   servers, and `--bare` would not read the OAuth token.
5. **The hand-over in the implementing job reads nothing the model could redirect.** The runner
   kills `agent-model`'s processes until none remains; `agent-model` bundles its own commits; the
   runner takes the bundle only as a regular file that is not a symbolic link, read as
   `agent-model`, within a time and a size cap; the runner never runs git in the model's
   repository.

Rejected: a host-wide limit (it breaks the runner, above); allowlisting the runner's blob storage
(any storage account behind those addresses); lifting the limit after the model (the model would
keep the runner's sudo and could lift it first); giving `agent-model` the token, even through the
environment only (a security review showed the model could read it through `/proc/<pid>/environ`
of its own CLI, a git `--output` write leading to code execution, or the posted verdict); resolving
the vendor API by DNS for the model (DNS is a channel both ways). This amends point 3 of "CI
hardening for agent workflows".

## A contributed CI job may name the app it verifies — imported, 2026-10-30

Context: the `qa` module renders one `<app>-qa-api` and `<app>-qa-web` per app of a monorepo, which
should be skipped, like `ci-baseline`'s own `<app>-checks`, when a pull request did not touch that
app. The engine's `CiJob` had no link from a contributed job to an app, and the scope script listed
only `<app>-checks` for an unchanged app, so a contributor could skip by tier and nothing else.

1. **`CiJob` gains `app: Option<String>`**, additive: every existing contributor sets `None` and
   renders as before.
2. **`ci-baseline` treats a contributed job with `app` like its own app jobs.** It hands `scope`
   the pairs `<job id>=<app id>` as `APP_JOBS`; `scope` lists the job as skippable when that app's
   change flag is `false`. The variable and the script lines that read it are rendered only when
   some job carries an `app`, so every other workflow is byte-identical. `required.sh` is
   unchanged.
3. **An `app` that is not an app of the stack-packs record refuses**, naming the contributor, the
   job and the app.
4. **The contributor's job-level `if:` for such a job is
   `contains(fromJSON(needs.scope.outputs.skippable), '<id>') == false`**, which covers the tier
   skip as well.

Rejected: a naming convention (`<app>-*` ids skip with their app), which no contributor could opt
out of; skipping by tier only, which runs every app's QA on every pull request that touches any
app.

## QA slice 1: start commands, project-owned Playwright, report retention, protected baseline, probes and pins — imported, 2026-10-29

Context: the `qa` module renders tests of what the user sees: Hurl for an API, Playwright for a
web app with screenshot comparison. Its first slice needed six rules fixed before it could render.

1. **The start commands are module answers.** `api_start` and `web_start` are answers of `qa`,
   required when their job exists and never invented; `project.json`'s `commands` stay the
   repository's verification commands. Rejected: a `commands.serve` field in `project.json`, which
   would change the profile, `ci-baseline` and the engine.
2. **A project that already runs Playwright gets the job only.** With `@playwright/test` and a root
   `playwright.config.*` (`web: project`) the module contributes `qa-web` running `web_command` and
   seeds nothing; it never merges a reporter or a `webServer` into the project's config, which is
   listed `never-touch`. Rejected: a managed block in the project's config, which would edit a
   project test file.
3. **QA reports are kept 7 days.** `qa-api` uploads the JUnit report and the API log, `qa-web`
   `playwright-report/` and `test-results/` (traces, actual and diff images), each with
   `retention-days: 7`, because the report is what a person opens days later to understand a red
   run. Rejected: 1 day, uniform with `ci-baseline`'s log artifacts.
4. **The screenshot baseline is a protected path and is never updated in CI.** `ci-baseline`'s
   derived `protected_paths` gains `<web_dir>/*-snapshots/**` (`**/*-snapshots/**` when `web_dir`
   is `.`; the glob is written for the `scope` job's shell `case` matcher), `repo-baseline`'s
   CODEOWNERS seed names the web directory, `qa.no-snapshot-update-in-ci` is Bronze, and the
   baseline is generated only locally in the pinned Playwright image. Rejected: a
   `workflow_dispatch` job that regenerates the baseline and opens a pull request, because a job
   that rewrites the evidence is what the rule forbids.
5. **No new probe kind.** `qa-web-baseline` exists only for `web: seeded`, whose baseline name the
   seed fixes (`<web_dir>/smoke.spec.ts-snapshots/home-chromium-linux.png`), so the engine's
   `file-exists` probe suffices; under `web: project` the rule `qa.screenshot-baseline-present`
   covers the project's own tests. Rejected: an additive `glob-exists` probe in the engine.
6. **The pins live in the shared table.** `tools.hurl` (URL and SHA-256 per architecture,
   installed by `security`'s `install-tool.sh` with `TOOL_BIN_PATH`), `tools.playwright` and
   `images.playwright` (by digest) are entries of `templates/stack-packs/pins.json`, so one
   `last_verified` and one staleness rule cover them. Rejected: a module-local pin file.

## The product is layer 3 only and distributes no workflow framework — imported, 2026-10-29

Context: a development setup for coding agents mixes three layers: where the work lives (spec,
plan, task list), how the work is done (TDD, review, debugging, project conventions), and what
enforces it (hooks run by the agent's environment rather than by the model, and the mechanical
brakes of the repository and of GitHub, which hold whether or not the agent cooperates). Before
the extraction, the installer also rendered an instruction block, a workflow guide and a task
guide that named one workflow framework and one tracker as the mandated process; a repository
that used another workflow, another tracker or none read a mandate it had never chosen.

1. **`brakes` covers layer 3 only.** It installs and audits hooks, repository controls and GitHub
   checks, rendered from declared commands and answers. No specification, plan, task list,
   issue-tracker convention, workflow framework, engineering guide or principles file is part of
   it, and nothing it distributes names a workflow framework or a tracker as a mandated process.
2. **The former core module (`setup-core`: the managed instruction block, the guides, conventions
   and decisions index) is not part of the product.** The installer compiled it behind a cargo
   feature (`setup-core`) before the extraction; without it, `doctor` checks no guides,
   conventions or decisions index, and `agent-guardrails` renders the `AGENTS.md` line about
   `technical-debt.md` in a managed block of its own. Managed-file drift (every managed file,
   managed block and managed entry the lock records) stays audited in every build.
3. **The `technical-debt.md` seed and its `AGENTS.md` line stay, as a layer-3 repository control.**
   They are a brake against copying patterns the repository marks as debt, they name no workflow
   framework, and the auditor checks them (`agents.technical-debt`, Bronze). They travel with
   `agent-guardrails`.
4. **GitHub issue forms, labels and the issue-to-pull-request workflow stay as host features and
   optional seeds.** `repo-baseline` renders them because GitHub is the host, not because the tool
   mandates a process; a project may keep them, remove them or never install the module.
5. **An optional, framework-agnostic `spec_dir` answer** in `agent-guardrails`: when a project
   names the directory where it keeps its specifications, that directory is added to the paths
   agents may not edit, as one more `protected_paths` entry; no default names a tool or a
   directory.
6. **Neutral by construction.** The product ships no default value for anything that identifies a
   user: the write allowlist, the identity denylist, runner labels and private presets are
   configuration the user supplies, and fixtures are synthetic. The empty configuration refuses
   every write and denies nothing.

Rejected: a neutral workflow guide that still "recommends" one framework (a recommendation inside
managed content is read as a mandate by agents); removing `repo-baseline`'s issue forms and labels
(host features, optional seeds).

## Testing brakes: changed-line coverage, characterisation first, held-out properties, mutation on the diff — imported, 2026-10-29

Context: the brakes that keep an agent from gaming its own tests (held-out tests, coverage of
changed lines, characterisation before touching untested code, randomised tests, and the two
figures that show the trend) were completed together. This entry amends point 8 of "CI hardening
for agent workflows", which had left property-based and mutation testing as follow-ups. Every tool
fact below was read in its primary source on the date of the entry.

1. **Every pull request covers the lines it changes.** `security` gains `diff-coverage`, a
   pull-request-only job in `required`'s `needs`, default on wherever a stack pack has a coverage
   recipe with a per-file report (python-uv, rust), that runs the pack's `diff_command` and
   `diff-cover --fail-under=<coverage_changed_lines_min>` against the merge base, default 80 %
   (unsourced). One tool for both stacks: diff-cover reads Cobertura (coverage.py's `coverage
   xml`) and LCOV (`cargo llvm-cov --lcov`); on the rust pack it runs as `uvx
   diff-cover==<pin>` through the `setup-uv` pin already in the table. `node` and `go` are
   unsupported until their packs declare the report. The `coverage-reset` exception kind gains the
   target `diff-coverage#<pull request number>`; no new kind.
2. **Characterisation first has a mechanical form, on the base.** A pull request that modifies a
   file which, at its merge base, had no executed line in the default branch's per-file coverage
   report fails `diff-coverage` with `Characterization first: <path> …`. The base report is the
   one `coverage-ratchet` saves on default-branch pushes under a cache key by SHA (restore-only on
   pull requests; no model runs in this job), recomputed at the merge base when the cache misses.
   The base is the one thing the pull request cannot change, so a test added in the same pull
   request does not satisfy the rule. It does not prove that the earlier tests characterise the
   behaviour or that their assertions are strong (point 4). No separate auditor rule exists
   beyond `security.diff-coverage` (static: the job and its step are present).
3. **Property-based tests are held-out tests, in their own job, with a fresh recorded seed.**
   `ci-baseline` gains `heldout-properties` (opt-in, `heldout_properties`): the properties,
   strategies, settings and runner configuration live under `heldout_dir`, denied to agents and
   protected for humans; the minimum example count is an answer (`heldout_examples`, default 200,
   unsourced) fixed in protected files; the job draws a seed from `/dev/urandom`, prints it as a
   claim line and in the step summary, and exports it. The seed must be explicit because the tools
   default to determinism on CI: Hypothesis's `ci` profile (active whenever `CI` is set) has
   `derandomize=True` and `database=None`, and `--hypothesis-seed` overrides it; proptest draws a
   random seed unless `PROPTEST_RNG_SEED` is set and runs 256 cases unless `PROPTEST_CASES` or the
   test's config says otherwise; `go test` without `-fuzz` replays only the seed corpus. The job
   blocks; the procedure for a red run on a pre-existing bug (file it, commit the minimised example
   under the held-out directory, re-run) is documented, and `ci-health.rerun-rate` shows the cost.
   `go` and `node` are refused until their packs declare the recipe.
4. **Mutation testing on the diff, opt-in, with a minimum score.** `security` gains `mutation-diff`
   (`mutation_diff`, default false: cost per pull request unmeasured; `mutation_min_score` default
   80, unsourced). rust: `cargo mutants --no-shuffle --in-diff git.diff` (exit codes 2 missed, 3
   timeouts, 4 baseline failed, 5–6 bad diff; results in
   `mutants.out/{caught,missed,timeout,unviable}.txt`), score `caught / (caught + missed +
   timeout)`. python-uv: mutmut 3 has no diff mode and no score flag, so mutation runs per changed
   file (`mutmut run "<module>*"`, `mutate_only_covered_lines = true`) and the score is
   `(killed + timeout) / (total − skipped)` over `mutants/mutmut-cicd-stats.json`; the
   file-not-line gap is documented. Why mutation at all: coverage alone admits weak tests, and an
   agent that writes both the implementation and the test can repeat the same assumption in both
   (published industrial evidence: arXiv 2501.12862).
5. **The held-out directory is unreadable to agents, in every profile.** `agent-guardrails` renders
   `Read(./<heldout_dir>/**)` beside the `Edit` entry: `Read` rules cover Read, Grep and Glob, so
   the agent neither opens nor searches the exam; the output of the held-out command stays visible
   (the verdict, not the questions), and `Bash` is uncovered without the sandbox, as for secrets.
   `MAX_DENY_RULES` rises from 24 to 25 so the documented room for two `secret_paths` entries holds
   in every profile; `agents.heldout-denied` requires both entries.
6. **Two counters in the auditor, read under `--remote`, with no threshold.**
   `post_merge_corrections`: of the pull requests merged 58 to 30 days ago, the share followed
   within 30 days by a merged pull request touching one of the same files (from the `pulls` listing
   widened to 58 days and an additive host read `pull_files`, `GET repos/{r}/pulls/{n}/files`, one
   page of 100), bots excluded, a sample of at most 10 judged with allowance 6. `cost_per_change`:
   the median wall-clock minutes of each merged pull request's `pull_request` runs from the cached
   listing of the latest 100 runs, zero extra calls. What cannot be read is stated in the report:
   billable minutes, model spend, human time, runs older than the latest 100. A counter never
   changes the level or the exit code.

Rejected: a changed-line step inside `coverage-ratchet`; a percentage threshold for
characterisation first (0 % is the rule and the least arguable); per-file numbers kept in
`.agent-setup/coverage.json`; artifact plumbing for the base report (needs `actions: read` and a
run lookup); a non-blocking properties job; mutmut on changed lines (no such mode exists); the
OpenSSF Scorecard Fuzzing check as evidence (an import grep that sees neither Hypothesis nor
proptest).

## CI hardening for agent workflows — imported, 2026-10-29

Context: the two agent workflows the tool renders, `cross-review` and `agentic-implement.yml`,
were compared with the published incidents of 2025–2026: in every one, untrusted text reached a
model or a shell in a job that held a token or a secret and had a way out (a comment, the network,
the Actions cache).

1. **The model never holds a write token; the job that writes runs no model.** `cross-review`
   becomes two jobs. `cross-review-model` runs the reviewer with `permissions: { contents: read }`,
   `cache-mode: none`, the egress limit and the model as its last step, and emits the verdict as a
   job output. `cross-review` (same id, so the aggregate and `agents.cross-review` keep their
   names) runs no model, checks out nothing and holds no vendor secret: `permissions: {
   pull-requests: write }`, `cache-mode: none`; it validates the verdict's shape, refuses a verdict
   over 60 000 bytes or carrying a credential-shaped string (and then posts nothing), posts the
   comment and fails on blocking findings. GitHub redacts a job output that contains a secret and
   does not send it, so a verdict that quotes the reviewer's secret arrives empty and the gate
   fails closed.
2. **Instruction files come from the base.** Before the reviewer starts, `cross-review-model`
   restores `AGENTS.md`, `AGENTS.override.md`, `CLAUDE.md` and `CLAUDE.local.md`, at any depth,
   from the pull request's base (removing those the base lacks); the reviewer still sees their
   changes in the diff, as data. The pinned review action restores a fixed list that misses
   `AGENTS.md`, while the rendered `CLAUDE.md` imports `@AGENTS.md`.
3. **Model jobs run behind an egress limit that proves itself**, and fail when it cannot be
   established: a model never runs unconfined. (Amended the next day: the limit applies to the
   model's user only.) **`step-security/harden-runner` is not rendered**: its documentation states
   that private repositories need a paid tier and that on self-hosted runners without a
   subscription the step succeeds and monitors nothing, so it would be green and block nothing. It
   may become an answer value pinned at a SHA of 2.16.0 or later (its DNS-over-TCP and
   DNS-over-HTTPS advisories) for users who hold that tier.
4. **No cache in a model job, enforced by GitHub.** Both model jobs, `publish` and the
   `cross-review` gate declare `cache-mode: none`, which GitHub enforces with scoped cache tokens and
   which also removes the restore: a poisoned entry never reaches an agent and an agent never writes
   one. actionlint 1.7.12 reports the key as unexpected; `workflow-lint` ignores exactly that
   message until a release accepts it.
5. **No trigger workaround.** Events made with `GITHUB_TOKEN` create no run, except
   `workflow_dispatch`, `repository_dispatch` and `pull_request` `opened`, `synchronize` and
   `reopened`, whose runs wait in an approval-required state for a person with write access. The
   pull request `publish` opens therefore waits for that approval and then meets `required`,
   `cross-review` and the ruleset; no dispatch or App token is added.
6. **`agents.workflow-injection`, Bronze, static.** A rule over every workflow job that runs an
   agent: no `pull_request_target` or `workflow_run` trigger; no `${{ }}` of `github.event.*` or
   `github.head_ref` ending in a field GitHub lists as untrusted (`body`, `default_branch`,
   `email`, `head_ref`, `label`, `message`, `name`, `page_name`, `ref`, `title`) or of a whole
   `github.event`, in a `run:` or in any `with:` input of the agent step; no write scope and no
   `id-token: write`; no `allowed_non_write_users`, no `*` in `allowed_bots`, `allow-users` or
   `allow-bot-users`, no `allow-bots: true`; `github_token` only the job's own; no
   `--dangerously-skip-permissions`, `bypassPermissions` or bare `Bash` in `--allowedTools`; Codex
   `safety-strategy` only `drop-sudo` or `unprivileged-user`, and the Codex step last in its job;
   `cache-mode: none` and no `actions/cache` step or `cache:` input; `persist-credentials: false`
   on every checkout; no `show_full_output: true`; no `claude-code-base-action`.
7. **`security.binary-artifacts`, Bronze, static.** A tracked file that is a compiled executable or
   package, detected as OpenSSF Scorecard's Binary-Artifacts check does (non-text first 1024 bytes
   and an executable or package magic or one of its 27 extensions), is a finding naming the path;
   `gradle-wrapper.jar` passes when a workflow runs `gradle/actions/wrapper-validation`, and any
   other file passes when registered as an `allowlist` exception (`binary-artifacts#<path>`) in
   `.agent-setup/security-exceptions.json`.
8. **OpenSSF Scorecard is not installed.** Its action supports private repositories only with
   GitHub Advanced Security; its workflow checks are covered by zizmor in `workflow-lint`, and its
   posture checks by auditor rules already present or added here.

Rejected: harden-runner as the default limit; one job with the comment posted after the model (the
model's token is the job's); trusting the action's restore list for `AGENTS.md`; a dispatch or App
token to start the agent's pull-request checks (a second write credential in the run); installing
Scorecard.

## The installer owns the entries it adds to `.claude/settings.json`: ownership class `managed-entries` — imported, 2026-10-29

Context: `.claude/settings.json` is a project-owned file, so the Stop hook, the deny rules and the
merge-guard hook were registered by hand as probed manual steps; a manual step nobody runs protects
nobody.

1. **A sixth ownership class, `managed-entries`.** A module renders a JSON fragment for a
   project-owned JSON file (`.claude/settings.json`); the installer owns exactly the members of the
   fragment's arrays (deny rules, hook entries) and nothing else in the file. The lock records the
   fragment's digest and the entries themselves, so `remove` and a later plan know what was added
   without rendering.
2. **The rules of the class.** An absent file is created with the entries alone; a file without
   them gains them, appended after the project's own; entries already present exactly change
   nothing (`No changes.`), which is how a file merged by hand migrates; a deleted owned entry is
   re-added in the next plan; an owned entry edited in place refuses, naming the file, the pointer
   and the entry (a hook entry by its `command`, a rule by its text); entries the module no longer
   renders are removed when unchanged and refused when edited; `remove` deletes only the owned
   entries and deletes the file only when nothing else remains. A changed file is written back as
   the engine serialises JSON (two-space indentation, sorted keys); a file whose entries already
   match is never rewritten. `doctor` reports `Managed entries drift` for an owned entry missing
   or edited.
3. **Registration moves to the installer.** `agent-guardrails` and `merge-guard` register the Stop
   hook, the deny rules and the merge-guard hook through the class, retiring the manual
   registration steps.

Rejected: `.claude/settings.json` as whole-file `managed` (it would overwrite a project's own
hooks); a text-marker block (JSON has no comments).

## Auditor standard v1, amended: module rules and manual steps allocated — imported, 2026-10-29

Context: the `ci.*`, `security.*`, `stack.*` and `agents.*` rules of the modules were `doctor`
`WARNING` findings that counted toward no level. The rule applied: adopt the level each module
proposes; a rule with no proposed level is Bronze when evaluated from local files and Silver when
it needs the host; manual steps take their module's level; a rule two modules define keeps one id.
Moving a rule between levels is always a new decision.

1. **More blocks.** `ci`, `security`, `stack`, `agents` and later `qa`, reported after `governance`
   in that order; a rule's block is its id's prefix. Levels, required in every profile unless
   noted:
   - Basic: `ci.command-missing`, `ci.aggregate-present`, `ci.job-timeouts`;
     `security.secrets-gate` (static half); `stack.unconfigured`, `stack.lockfile-present`,
     `stack.lockfile-not-enforced`; `agents.deny-secrets`, `agents.readable-secrets`.
   - Bronze: `ci.permissions-least`, `ci.workflow-lint`, `ci.no-self-hosted-label`,
     `ci.hosted-macos`, `ci.dependabot-actions`, `ci.project-ci-stale`;
     `security.secrets-full-history`, `security.deps-gate`, `security.scanner-unpinned`,
     `security.trivy-compromised-version`, `security.bypass-inventory-valid`,
     `security.bypass-unregistered`, `security.binary-artifacts`, `security.secret-scanning` and
     `security.private-vulnerability-reporting` (remote; a non-public repository passes the first
     with the risk `secret-scanning-unavailable-on-plan` recorded, and the second is
     `not-required` there); `agents.stop-verify`, `agents.mcp-allowlist`,
     `agents.technical-debt`, `agents.workflow-injection`, `agents.protected-paths` (P2, P3 only);
     `qa.hurl-no-literal-host`, `qa.tools-pinned`, `qa.no-snapshot-update-in-ci`,
     `qa.report-artifact`.
   - Silver: `ci.heldout-present`, `ci.protected-paths-gate`, `ci.heldout-properties` (opt-in),
     `ci.required-is-aggregate`, `ci.main-red` (remote); `security.bypass-expired`,
     `security.sast-gate` (when criticality ≥ customers), `security.container-gate`,
     `security.pii-declared` (when criticality is personal-data-or-payments);
     `stack.toolchain-pinned`, `stack.image-by-digest`, `stack.image-nonroot`;
     `agents.cross-review`, `agents.unattended-gated`, `agents.heldout-denied`,
     `agents.workflow-caps`, `agents.identity` (P2, P3 only); `qa.api-smoke-present`,
     `qa.web-smoke-present`, `qa.screenshot-baseline-present`, `qa.snapshots-protected`,
     `qa.main-green` (remote), `qa.contract-lint`, `qa.contract-compatible`.
   - Gold: `ci.minutes-month` (remote); `security.scanner-stale` (remote),
     `security.attestation-verified`, `security.sbom-scanned`, `security.coverage-ratchet` (only
     where answered), `security.mutation-gate` (opt-in); `stack.image-arbitrary-uid` (P3 only).
2. **Evaluated from `doctor`, never twice.** Each rule takes the findings `doctor` already prints
   for its id: it fails with them as evidence and passes when there is none. A rule whose only
   findings are `unverified: <file>: <reason>` is `unavailable`. A finding that names a level
   above its rule's (`Silver: …`) does not fail the rule. Where `doctor` evaluates a rule only in
   some checkouts (the module is not in the lock, no workflow exists, an opt-in is not answered),
   the rule is `not-required` in the others. Under `--fleet`, which has no checkout, they are
   `not-required` with "no checkout under --fleet" and read nothing. Static rules have no host
   call allowance; remote rules read the host within per-block allowances.
3. **One id for one check.** `posture.actions-pinned` is kept and `ci.actions-pinned` retired; the
   registration warnings for deny rules and the Stop hook carry `agents.deny-secrets` and
   `agents.stop-verify`; the by-origin ids `baseline.agent-hooks-registered` and
   `baseline.stop-hook-current` leave the registry.
4. **Warning only.** `stack.no-healthcheck` and `stack.pin-table-stale` (it measures the tool's
   embedded pin table, not the repository, and must not turn `doctor` red by the clock alone)
   stay `doctor` warnings and enter no level; so do the `Silver: …` halves of
   `agents.mcp-allowlist` and `agents.technical-debt`.
5. **A module's level, which its manual steps take, never below Bronze.** A module's level is the
   lowest level of the rules it serves. A manual step `baseline.<module>.<step>` takes
   `max(Bronze, module level)` and is required in every profile: a pending step is often remote
   work, and Basic is about the checkout, so a step never blocks Basic. Today every step is Bronze.
6. **`doctor`'s lines.** The `WARNING` lines stay `doctor`'s finding channel and never change
   readiness (exit 1). The audit appended after them prints a failing required rule as
   `FAIL [<level>:<id>]`, which can keep the required level out of reach (exit 3).
7. **Managed-file drift stays audited in every build.** A managed file, managed block or managed
   entry whose content differs from what the lock records is a `doctor` finding whatever modules
   the build compiles; a managed-block file is digested by the lock's class, not by its name.

## Stack packs defaults and container runtimes — imported, 2026-10-28

Context: the `stack-packs` module declares toolchains, commands, container seeds and a shared pin
table per language. Its defaults and its runtime images needed fixing; one measurement found that a
pinned python build stage (Python 3.13 on Debian 12) was paired with a distroless runtime carrying
Debian 12's own Python 3.11, so a virtual environment built by 3.13 (`cp313` extensions) could not
run, and that the rust pack's `static` runtime carried no C library while `cargo build` on the
Debian build image links against glibc.

1. **`base_image_family` defaults to `distroless`** until Docker Hardened Images pull
   authentication is confirmed. `dhi` stays in the answer's enum so the schema never changes, and
   refuses at render, naming the image key, while `images.dhi.*` has no pins; `official-slim` is
   the third value.
2. **`apps.<id>.toolchain` defaults to `false` for `rust` and `true` for every other pack.** A
   seeded `rust-toolchain.toml` changes which toolchain `cargo` uses locally, so a rust app gets one
   only when answered `true`.
3. **The pin table goes stale after 30 days.** `doctor` reports `stack.pin-table-stale` (a warning,
   no level) when `last_verified` in `templates/stack-packs/pins.json` is more than 30 days old.
   The window is the constant `PIN_VERIFICATION_DAYS`, not a setting; the guides' window is too
   slow for action SHAs and image digests.
4. **python-uv is Debian 13 in both stages.** `python-uv.build` is
   `ghcr.io/astral-sh/uv:python3.13-trixie-slim` and `distroless.python` is
   `gcr.io/distroless/python3-debian13:nonroot` (Python 3.13, glibc 2.41 in both). The
   `.python-version` seed and `tools.python` stay 3.13.
5. **rust runs on `distroless.cc`** (`gcr.io/distroless/cc-debian12`, glibc, the same Debian
   release as the build image); no `crt-static` or musl build is attempted. `go` keeps `static`
   with `CGO_ENABLED=0`.
6. **Digests are resolved from upstream** by read-only registry queries for the tag's current index
   digest, recorded with source and date in the pull request, and copied into
   `templates/stack-packs/pins.json` and `templates/stack-packs/pins/Dockerfile`.
7. **Detection proposes, never applies.** Stack detection proposes commands with evidence and
   applies nothing without confirmation; `configure --accept-commands` fills only `commands.*`
   fields that are `null`, never a declared one.

Rejected: `dhi` as default before its pull path is verified (a registry credential in CI and in
every disconnected mirror); `toolchain: true` for rust; reusing the guides' verification window
for pins; keeping Debian 12 and building for 3.11; running python on `cc` with a copied
interpreter. Changing any default is a new decision.

## The "configure new" contract: data returned by an additive `Module` method — imported, 2026-10-28

Context: some questions offer a choice the catalogue does not know yet (a provider the tool has no
template for). The engine needs one shape for that answer that never turns into a free-text
provider template.

1. **`other` is the only reserved enum value.** A question that lists it declares
   `x-configure-new: {contract: <id>}`, and the reverse (refused at load). Picking it records
   `"other"` and nothing more in the answers file; no driver asks anything further.
2. **One additive `Module` method.** `configure_new(question, cx) -> Option<IntegrationContract>`,
   default `None`, is the only trait change. A module whose schema declares `x-configure-new`
   returns `Some` for that question, asserted in CI over every compiled module; a plan with the
   question answered `other` and no contract, or a contract whose id differs from the declared one,
   refuses naming the module and the question.
3. **The contract is data, never a provider template.** `IntegrationContract { id, env, seed,
   steps, guide }`: an env contract (name, purpose, example, required), a skeleton and an integration guide
   at `docs/agent-setup/integrations/<id>.md` in the target repository, both of class `seed` and carrying
   `TODO(configure-new):` markers, so a file the project has started filling is never overwritten;
   the engine appends the env contract to the guide. A module may not add a free-text "name of the
   provider" question.
4. **Manual steps use only the two generic remote probes**: `endpoint-answers {env}` and
   `secret-exists {name, environment}`, reported `unavailable` until a runner reads them; the
   contract never asks for, reads or stores a secret value.
5. **Promotion is a human act.** A contract filled in two repositories may become a catalogue
   preset by a pull request to `templates/presets/`; a preset never contains `other`.

## Agents reach hosted tools through their CLI or API; MCP only when none exists — imported, 2026-10-28

Context: the MCP allowlist policy started with read-only servers by default and a catalogue that
included read-only servers for hosted services. The merge guard sees only `Bash`, so a GitHub MCP
server could act outside it, while `gh` is already there and guarded; and every connected MCP
server's tool schemas cost agent context even when unused.

1. **CLI or API first.** An agent reaches a hosted tool through its CLI or the vendor API whenever
   one exists: GitHub through `gh`, an error tracker through its API or CLI with the project's
   token. The token is read from the environment at agent time; no token value is ever rendered,
   recorded or stored.
2. **MCP only where no adequate CLI or API path exists**, and then only as a recorded allowlist
   entry with a written purpose and its permissions: read-only by default, `read-write` a Silver
   finding until justified, and the auditor flags any server outside the allowlist.
3. **The default catalogue is `docs` alone** (a documentation lookup server at a pinned exact
   package version, lookup tools only). The `mcp_servers` answer defaults to no server.

Rejected: read-only hosted-service servers in the catalogue. The read-only switch is a header or URL
query in a file the project owns, so a later edit lifts it silently, and a GitHub server would give
agents a second path to GitHub that the merge guard does not see.

## Pattern questions in the engine answers subset — imported, 2026-10-28

Context: `stack-packs` records one entry per app of a repository. Nested objects stay outside the
engine's schema subset, so apps live in a flat `apps.<id>.<field>` namespace; but the engine
refuses any key that is not a declared question id, so those keys could not be recorded.

1. **A question id with one `*` segment is a pattern.** `apps.*.port` answers every key equal to it
   with the `*` replaced by an identifier (`[A-Za-z0-9_-]+`); other keys stay unknown and refuse as
   before.
2. **Typed and validated per key by the engine.** `--set` parses the value by the pattern's type
   and the pattern's validators apply to each key; a refusal names the concrete key ("answer
   `apps.web.port` must be at least 1"). An exact question id wins over a pattern.
3. **No `default`, `required` or `when` on a pattern** (refused at load). Which instances exist,
   their defaults and the rules across fields belong to the module that declares the pattern,
   applied when it loads its answers.

## Host adapter: `Host` contract, read gate, write gate and remote writes — imported, 2026-10-28

Context: the tool reads any repository it audits and writes to a few, so the remote scope needed to
be stated in the terms the code uses, and the manual steps the installer could perform itself
(copying a `gh` command into another terminal) needed to become mechanical work.

1. **The `Host` contract.** The tool has a host adapter: a `Host` trait with typed reads and a small
   set of gated writes, a GitHub implementation over `gh api` (hostname `github.com`; GitHub
   Enterprise Server out of scope), and an Azure DevOps interface that parses its identities and
   answers `Unsupported` from every operation until a module implements it. No type of the crate
   can hold a secret value, `Host` has no method that returns one, and nothing under `/secrets` is
   ever written.
2. **Reads.** `host::authorize::read` refuses, before any transport call, any identity matching the
   configured identity denylist (a case-insensitive substring over canonical paths, remote URLs
   and host identities), and admits every other repository the token can read. The refusal is a
   capability of the tool, not of the person running it.
3. **Writes.** One repository per invocation, through a `WriteToken` that only
   `host::authorize::write` mints, and only when a person passes the explicit `--remote` flag of
   `apply`. Without the flag the refusal is "Remote write to {repo} needs the explicit --remote flag
   of apply". There is no fleet-wide write command.
4. **The write allowlist is configuration, not a constant.** The file-scope guard and the host write
   gate read the same `write_allowlist` from the user's configuration (exact `<org>/<repo>` entries,
   or a wildcard only as `<org>/*`). A repository becomes writable by adding it there and is revoked
   by removing it; never by a flag, an environment variable at run time, a profile field or
   inherited organisation membership. The configuration is read from a file embedded at build time
   (only when the build sets `BRAKES_EMBEDDED_CONFIG`), then `--config <path>`, then
   `$XDG_CONFIG_HOME/brakes/config.json`; never from the target repository. Without configuration
   every write is refused with "No configuration: writes refused".
5. **What `brakes apply --remote` writes.** What the installed modules declare with the ownership
   class `remote`: repository settings, rulesets, environments (with their deployment branch
   policies) and branch protection, alongside labels, issues and comments. Rulesets are preferred
   where the repository's features probe reports them available; classic branch protection is
   written where a module declares it. `plan` (and `apply` without `--remote`) reads the remote
   state and prints the diff of every declared remote item; only `apply --remote` writes, and only
   what that diff showed. After writing, the tool runs the same probes the manual steps used and
   reports each item `verified` or `pending` with the evidence; a write that does not verify is
   reported, never retried in a loop. Items whose feature the probe reports `Unavailable` (for
   example branch protection in a private repository of a free organisation) are reported and not
   attempted.
6. **Still never:** secret values (names may be probed; values are never read, sent or stored);
   merges; deleting a repository; writing outside the allowlist or to several repositories in one
   invocation; any identity on the denylist, for reads or writes.
7. **Agent sessions stay denied.** The merge guard denies ruleset and protection writes through
   `gh api` from agent sessions, and denies `brakes apply --remote` run from an agent session; a
   person runs that single command by hand. A manual step remains only for what the tool may not
   do (secret values, plan purchases, organisation-level settings).

## Preset catalogue and `Last verified` — imported, 2026-10-28

Context: presets are named answer sets the `questions` module offers; and rendered configuration
files, unlike Markdown, cannot carry a dated comment line.

1. **Preset names are infrastructure shapes, not profiles.** The catalogue is `personal-vps`,
   `personal-paas`, `team-cloud` and `enterprise-k8s`: a P1 repository may run on a managed
   platform and a P3 one on a VPS, so a preset never stands for a profile.
2. **A preset is an answers file with a name.** It lives at `templates/presets/<name>.json`
   (`{preset, description, modules: {<id>: {…}}}`), is embedded in the binary and read from a
   checkout under `--source`; there is no preset-specific validation beyond the engine's schema,
   and a preset may omit any question or module. Users may add private presets from a configured
   directory, merged over the catalogue; names must not collide.
3. **Ownership is split.** The format, the embedded catalogue, `--preset`, the `presets` listing and
   the CI gate belong to `questions`; the values of a preset's section for module X are proposed
   and reviewed with module X.
4. **The CI gate.** For every catalogue preset and every compiled module it has a section for: every
   key is a question, the engine accepts the section, no key is gated out by a `when` under the
   preset's own answers, and no value is `other`. A failure names the preset, the module and the
   key.
5. **`Last verified` applies to Markdown only.** JSON and YAML files a module renders (the first was
   `repo-baseline`'s `.github/rulesets/main.json`) are data, carry no date and are outside the
   stale-guide finding, which `doctor` scopes by extension.
6. **Issue forms carry no contact link.** `repo-baseline`'s `config.yml` is the same file in every
   repository, `blank_issues_enabled: false` and nothing else: a contact link needs an absolute
   URL no render input carries, and GitHub already lists the security policy when `SECURITY.md`
   exists.

Rejected: one preset per profile (P1–P3).

## Auditor standard v1: levels, allocation and exit codes — imported, 2026-10-28

Context: the auditor states how a repository must be and reports the gap; it never decides for
the user. It needed its levels, thresholds, rule allocation and exit codes written down so its
registry invariant test could hold them.

1. **Levels.** Basic, Bronze, Silver and Gold are cumulative. Thresholds: critical alerts open ≤ 7
   days; stale branches ≤ 10 older than 90 days; ≥ 1 deployment per week; lead time ≤ 7 days;
   change failure rate ≤ 15 %; CI re-runs ≤ 10 %; cancellations ≤ 20 %; time to restore ≤ 24 h;
   restore drill ≤ 90 days old; 28-day window.
2. **Required level by profile.** P1 (one person with agents) Bronze, P2 (small team) Silver, P3
   (several teams) Gold; criticality `customers` raises to at least Silver;
   `personal-data-or-payments` raises one level, capped at Gold. A recorded `audit.accepted_level`
   with an expiry may govern the exit code while a brownfield repository climbs; the auditor still
   prints the required level and the gap, and an expired acceptance is a finding. Agent user
   accounts count as humans unless listed in `audit.agent_accounts`; GitHub Apps are excluded
   automatically.
3. **Allocation, v1.** Ids are `<block>.<kebab>`, stable once shipped. Basic:
   `baseline.purpose-declared`, `baseline.verify-declared`, `baseline.criticality-declared`,
   `baseline.setup-installed`, `posture.default-branch-protected`,
   `posture.no-open-secret-scanning-alerts`, `ci-health.workflow-exists`. Bronze:
   `posture.required-check-enforced`, `posture.no-unlisted-bypass-actors`,
   `posture.human-approval-required` and `posture.codeowners-review` (P2, P3),
   `posture.serialised-merges` (cadence ≥ mid), `posture.actions-pinned`,
   `posture.no-stale-critical-alerts`, `posture.no-repo-secrets-with-production`,
   `posture.stale-branches`, `ci-health.minutes-budget` (cadence ≥ mid),
   `governance.dependency-updates-with-cooldown`, `governance.service-card-owner`,
   `governance.codeowners-present` (P2, P3), `governance.pr-template-and-issue-forms`. Silver: the
   `dora.*` deployment rules (`deployments-api-in-use`, `deployment-frequency`, `lead-time`,
   `change-failure-rate`), `posture.production-environment-guarded`, `ci-health.rerun-rate`
   (cadence ≥ mid), `ci-health.cancellation-rate`, the `operations.*` rules (`post-deploy-smoke`,
   `rollback-evidence`, `uptime-footprint`, `incidents-bounded`, `runbook-per-alert`),
   `governance.no-expired-bypass`. Gold: `dora.time-to-restore`,
   `operations.slo-burn-rate-validated`, `operations.backup-age-within-rpo`,
   `operations.restore-drill-fresh`, `governance.postmortem-actions-closed`,
   `governance.no-expired-flags`, `governance.adr-state-known`, `governance.cost-tags`,
   `governance.no-persistent-oversizing` (platform ladder L4 only), `posture.org-2fa-required`
   (`unavailable` for user accounts). Findings not named keep their level by origin: a finding
   that makes `doctor` `NOT READY` is Basic, a `WARNING` is Bronze.
4. **Exit codes.** `doctor` keeps 0, 1 and 2 and adds 3 (ready, required level not reached because a
   required rule failed) and 4 (ready, required level not reached only because of `unavailable`
   evidence); `--fleet` exits with the highest code of its repositories, 2 if the listing failed.
   Without `--remote` the host-backed measures are `unavailable`, the profile is P1 flagged
   `unverified` and the required level is still stated. An unexpired `audit.accepted_level` lowers
   the exit code to 0 and nothing else.
5. **Fleet report target.** There is no default target: `--publish-issue <org>/<repo>` names the one
   write-scope repository each time, one issue titled `Fleet audit <name> <date>` with the label
   `fleet-audit`, which is never created (a missing label is a finding). `--fleet` takes one
   organisation or user per invocation; alerts the token cannot read (403) are `unavailable` with
   the missing permission as the reason; CI minutes are reported as a labelled sample and only the
   per-cycle budget is a rule.

## Engine, CI baseline, security gates and agent guardrails — imported, 2026-10-28

Context: the tool became one installer that audits any GitHub repository or fleet against a
technical standard and then automates setup and improvement: mechanical work generated and applied,
conversation only where a decision is required, manual steps as probed data.

1. **Generated configuration is installed content.** Modules may generate executable or
   configuration files (rulesets, issue forms, Dependabot config, workflows, Dockerfiles, pin files,
   scanner configs, hooks) as data with an ownership class (`managed`, `managed-block`, `seed`,
   `never-touch`, `remote`, and later `managed-entries`), recorded in the schema-2 lock. The tool
   still never runs project commands, checks, deployments or infrastructure applies.
2. **Recorded answers.** The repository profile (`.agent-setup/project.json`) stays the
   repository's; module answers live in `.agent-setup/modules/<id>.json`; per-app profiles of a
   monorepo live at `<app>/.agent-setup/project.json`. `project.json` carries `criticality` and
   `audit.agent_accounts`.
3. **`required` is the single aggregate status check** every repository requires, produced by
   `ci-baseline` as an `if: always()` job that `needs` every other job and passes only when each is
   `success`, or `skipped` and listed by `scope` as skippable (GitHub counts a skipped job as
   passing). With tiers on, a pull request whose changed files all match `inert_paths` (default
   `docs/**`, `tasks/**` and `**/*.md`) is tier `docs` and its verification jobs may skip;
   `.github/workflows/**` and every protected path are never inert. Other modules add jobs only
   through the additive `Module::ci_jobs`.
4. **Protected paths and held-out tests.** A change to a `protected_paths` glob (default
   `.github/workflows/**`, `.github/rulesets/**`, `.github/CODEOWNERS`, `.agent-setup/lock.json`,
   `<heldout_dir>/**`) needs the `human-approved` label before `required` passes; labels come from
   the event payload and `labeled`/`unlabeled` re-run the workflow; an unknown change set fails
   closed. The `heldout` job runs `heldout_command` over `heldout_dir` (default `tests/heldout`),
   which agents may not edit, so the suite an agent optimises against is never one it can edit.
5. **Runner policy.** The runner label comes from an enum answer, never free text: GitHub-hosted
   `ubuntu-24.04`, or a self-hosted runner label from the configuration; the bare `self-hosted`
   label is never generated. macOS runs only on push to the default branch when a stack pack
   declares a macOS target; GitHub-hosted macOS is a `ci.hosted-macos` warning.
6. **Ruleset policy by profile.** P1: pull request required, linear history, no force-push, no
   deletion, the `required` check, no bypass actors, administrators included. P2 and P3: one
   approval, no bypass actors; agent identities are never bypass actors. CODEOWNERS is not seeded
   in P1; the PR template is a managed block; the service card `.agent-setup/service.yaml` is
   seeded and its maintainer field validated.
7. **Security gates.** Paid GitHub security features are never assumed: secret scanning and push
   protection are enabled where the plan includes them and a plan refusal is recorded as a risk;
   the free gate (gitleaks, OSV-Scanner, Semgrep CE, Trivy, each pinned by checksum) is the default;
   CodeQL only where Code Security is bought. Defaults are answers, and the auditor checks that a
   pinned gate exists, not which tool.
8. **Exceptions expire.** Every exception to a control (in `.agent-setup/security-exceptions.json`)
   carries eight mandatory fields and an expiry: 30 days for job skips, hotfix variables,
   `continue-on-error` and coverage resets; 365 days for allowlists and ruleset bypass actors.
   Renewal is a new entry, never an edited date; the secrets gate admits no variable bypass; an
   expired bypass turns the gate red; the auditor reports unregistered bypasses at Bronze and
   expired ones at Silver.
9. **Agent guardrails.** A Stop hook runs the declared verify command, so "done" means verification
   green; a deny-rules fragment refuses agents secret paths, lockfiles and the held-out directory;
   `.github/workflows/**` is denied to agents in P2 and P3 (humans lift, agents never). The MCP
   allowlist is policy (see "Agents reach hosted tools through their CLI or API").
10. **Interfaces.** `brakes doctor` has `--fleet`, `--report`, `--publish-issue` and `--now`;
    `brakes adopt` handles brownfield repositories; `brakes mcp` is an entry point with the same
    scope rules, no remote writes and no secrets: `apply` over MCP only with the plan token and an
    elicitation confirmation in the client's own interface, refused for clients without
    elicitation.
11. **Approved dependencies.** A YAML crate for auditing unmanaged workflows; the additive trait
    method `Module::ci_jobs`.

## Never merge on red, also locally — imported, 2026-10-19

Context: a pull request merges only when every CI check is `pass` or `skipping`, including when a
failure is pre-existing on the default branch, caused by infrastructure or unrelated to the change.
One recorded re-run of a failed job is allowed; after that the change waits for the fix.

1. **The server-side required check is the primary mechanism.** The ruleset or branch protection
   requires `required`, administrators included, and refuses force-pushes and deletion; classic
   protection with `enforce_admins` counts as protection.
2. **The merge guard anticipates it in the agent session.** `brakes guard pre-bash`, registered as
   a hook through `managed-entries`, stops a session earlier with the reason; denies `gh pr merge
   --admin` and merges through `gh api`; denies any change to branch protection or rulesets and the
   `human-approved` label from agent sessions. It checks the pull request in the repository the
   merge targets (`-R`, `GH_REPO`, an earlier `cd`, the session directory resolved from its GitHub
   remotes) and denies when it cannot tell which. Heredoc bodies and quoted text are data, not
   commands. In a repository probed as protected, an undecidable merge is allowed with a note on
   stderr because the server decides; the probe is cached for 15 minutes. Where the plan allows no
   branch protection or rulesets, the hook is the only barrier, and `brakes doctor --remote` says
   so. It runs in a light and a full mode.
3. **A POSIX `sh` wrapper, `.claude/hooks/merge_guard.sh`,** is the one exception to Rust: it must
   work exactly when the binary is missing. It only finds the binary (an environment override, then
   `brakes` on `PATH`, each only if its `--help` lists `guard pre-bash`) and runs it; without one it
   denies what could merge (`gh pr merge`, `gh api …/merge`, matched loosely on the raw payload),
   says how to install the binary, and allows every other command. It grows no other logic. The
   rendered Stop hook shares the exception.
4. **Known limits fail closed.** The guard reads one command line and does not run the shell. When
   it cannot tell the repository it denies and asks for an explicit `-R`. Variable assignments it cannot
   follow, `gh repo set-default` earlier in the line, a `cd` inside a group, branch or loop, and
   unknown merge options leave the state unknown and deny; `bash -c`, `sh -c` and `eval` scripts
   are parsed as commands. Only plain `;`/newline sequences propagate state unconditionally; merge
   options are consumed with their values, so text passed to `--subject`, `--body` or
   `--body-file` cannot become `-R` or `--admin`.
