# Security gates

Last verified: 2026-11-01

This repository's security gates are CI jobs the installer module `security` renders
as data. The installer never runs a scanner, never installs a hook and never reads or
writes a secret. This guide says how the gates work, how to add an exception, how to
bypass a gate in an emergency and how to renew an exception.

## How the gates work

| Job | Skipped on docs-only changes | What fails it |
|---|---|---|
| `security-gate` | Never | A secret gitleaks finds in the commits the event adds (the pull request range, or the pushed range on the default branch; the whole history when the workflow is run by hand), or any finding of the exceptions check below |
| `deps-scan` | Yes | Any vulnerability OSV-Scanner reports in the lockfile of an app `stack-packs` records, unless ignored in `osv-scanner.toml` |
| `sast` | Yes | Any `ERROR`-severity finding of Semgrep CE over `p/default` plus the packs of the repository's stacks; or, with the `codeql` answer, CodeQL's analysis (needs GitHub Code Security) |
| `container-scan` | Yes | Any `HIGH` or `CRITICAL` finding of Trivy (`CRITICAL` only with the `severity: critical` answer) over the filesystem, the lockfiles, the secrets and the `Dockerfile` (`trivy fs`, `trivy config`), or over the pull-request image when `delivery` builds one (`trivy image`), unless ignored in `.trivyignore.yaml` |
| `coverage-ratchet` | Yes | Only when `coverage_ratchet` is answered `true`: an app's line coverage below its record in `.agent-setup/coverage.json` minus `coverage_tolerance` |
| `diff-coverage` | Yes | On pull requests only: changed lines covered below `coverage_changed_lines_min` (80 by default), or a modified source file no test executed at the merge base |
| `mutation-diff` (opt-in) | Yes | On a pull request, a mutation score of the changed code below `mutation_min_score`; see below |

Every scanner is downloaded by URL and verified by SHA-256 before it runs, or, for
Semgrep CE, run from its container image by digest; no marketplace action installs
one. Every job is needed by `required`, the single status check the default branch
requires. `sast` is absent with the `sast: none` answer; `container-scan` exists only
where a `Dockerfile`, a container app or `delivery`'s image job exists. `coverage-ratchet` exists only when
`coverage_ratchet` is answered `true`; `diff-coverage` exists where an app is `rust` or
`python-uv`, unless `coverage_changed_lines` is answered `false`.

A secret finding shows its location only. The run log is readable by anyone who can
read the repository, so no scanner job prints a matched value, masked or not: gitleaks
runs with `--redact`, and Semgrep and Trivy's secret scanner write their findings to a
JSON file the job never prints or uploads, then print one line per finding,
`<scanner> finding: <rule id> at <path>:<line>`. Every Semgrep finding is shown this
way, since a rule's message can quote the match; reproduce the detail locally. When a
finding is a real credential, rotate it at its issuer first: removing it from the code
does not take it out of the history, and anyone who saw it can still use it.

gitleaks scans what each event adds and prints it first: a pull request its
`<base>..<head>` (`history: <base>..<head>`), a push its `<before>..<after>`
(`history: pushed <before>..<after>`). A push that creates the branch, a range whose
commits cannot be fetched, a run started by hand (`workflow_dispatch`) and any other
event scan the whole history (`history: full`). Run the workflow by hand once after
the install, and whenever you want the whole history checked again.

A finding in an old commit that is not a live credential (a revoked key, a test
hash, a placeholder) is recorded once in `.gitleaks-baseline.json`, not as an
expiring exception: rotate any real credential first, then generate the report over
the whole history with `gitleaks git --redact --report-format json --report-path
.gitleaks-baseline.json .`, review every finding, and commit it through a pull
request. gitleaks matches each entry by its commit, so the baseline never hides a new
commit; it is read only by full-history scans of the default branch (push, run by
hand or scheduled), never by a pull request, whose own edits to it must not count. A
baseline that is not a JSON array whose every `Secret` is `REDACTED` fails the gate,
so a value is never committed or printed. It has no expiry and no inventory entry;
remove it when the history no longer needs it.

`deps-scan` passes OSV-Scanner one `--lockfile` per recorded app whose stack pack
declares one (`<app path>/Cargo.lock`, `uv.lock`, `go.sum`, a node app's package
manager's lockfile): the declared lockfiles, never a recursive search, so a lockfile
under test fixtures, templates or examples is not scanned. A new app is scanned once
`stack-packs` records it and the installer renders the workflow again.

The exceptions check inside `security-gate` reads every place a gate can be
switched off and prints one `::error::` line per problem, then the claim line
`exceptions: <active> active, <expired> expired, <unregistered> unregistered`:

- `.agent-setup/security-exceptions.json`, the bypass inventory;
- `.trivyignore.yaml` (each entry needs `expired_at` and an issue in `statement`;
  the check reads the file as YAML does, so an unquoted `statement` ends at ` #`
  and an issue written after it does not count);
- `osv-scanner.toml` (each `[[IgnoredVulns]]` needs `ignoreUntil` and an issue in `reason`);
- `.gitleaksignore`, `.semgrepignore` and the `[allowlist]` of `.gitleaks.toml`
  (each entry must be registered in the inventory);
- a plain `.trivyignore`, which is refused because it cannot carry an expiry;
- on a pull request, `.agent-setup/coverage.json` against the base branch: a lowered
  or removed app needs an active `coverage-reset` entry.

The scanner configuration files and the hook configuration were seeded once and
belong to the project; the installer never overwrites them.

## Mutation testing on the diff (opt-in)

Coverage says a line ran; mutation says whether a test would notice it changing.
`mutation-diff` is rendered only when `mutation_diff` is true in
`.agent-setup/modules/security.json`, for the apps whose stack pack declares a
mutation tool (rust, python-uv). It runs on pull requests only (on a push its steps
are skipped and it passes), mutates the code the pull request changes and fails with
`::error::Mutation score <score> % on changed code, below <min> %` when the share of
viable mutants the tests kill is below `mutation_min_score` (80 by default). The claim
line is `mutation: <score> % of <n> mutants killed`; a pull request with no mutant in
its changes passes with `mutation: no mutants in the diff`. The results are uploaded
as the artifact `mutants-<app>` for seven days.

- **rust**: `cargo mutants --no-shuffle --in-diff git.diff` over
  `git diff <merge base>...HEAD`. Only mutants that overlap the changed lines run;
  unviable mutants are excluded and timeouts count as missed. Exit code 4 (the tests
  already fail without a mutant), 5 (the diff does not match the tree) and 6 (the
  diff cannot be parsed) fail the job with the tool's message.
- **python-uv**: mutmut has no diff mode, so it mutates every **changed file**, not
  only the changed lines: a small change to a large, weakly tested file can fail the
  job. mutmut reads its settings only from its own configuration, never from flags,
  so the project adds them once (the job fails, naming the setting, until it does):

  ```toml
  [tool.mutmut]
  source_paths = ["src"]
  mutate_only_covered_lines = true
  ```

  (or the same keys under `[mutmut]` in `setup.cfg`, which mutmut reads only when
  `pyproject.toml` has no `[tool.mutmut]`). `mutate_only_covered_lines` leaves lines
  no test executes to changed-line coverage instead of counting them twice.

What it does not do: it does not protect code outside the diff (a full mutation run
is the project's own scheduled job), and an agent that reads the surviving mutants
can write assertions aimed at them; held-out tests and the cross-family review are
the checks against that. Before switching it on, measure the run time on one real
pull request: mutation runs the test suite once per mutant.

## Adding an exception

An exception is added in the same pull request that needs it. Every inventory entry
in `.agent-setup/security-exceptions.json` carries eight fields:

```json
{ "id": "osv-outage-2026-11", "kind": "job-bypass", "target": "deps-scan",
  "reason": "OSV.dev API down; dependencies unchanged in this PR", "issue": "#731",
  "owner": "<github-login>", "created": "2026-11-03", "expires": "2026-11-05" }
```

- `kind` is one of `job-bypass`, `ruleset-bypass-actor`, `repo-variable`,
  `continue-on-error`, `allowlist`, `coverage-reset`, `accepted-risk`.
- `issue` is `#<n>` or an issue URL; the issue explains why and tracks the removal.
- `expires - created` is at most `bypass_max_days` (30 by default, recorded in
  `.agent-setup/modules/security.json`); `allowlist`, `ruleset-bypass-actor`
  and `accepted-risk` entries last at most 365 days.
- An `accepted-risk` entry records an owner's decision to accept a failing
  auditor rule: its `target` is the rule id (several separated by commas).
  `doctor` prints the rule as `ACCEPTED` with the reason, issue, owner and
  expiry instead of `FAIL`; the rule still counts as not passed toward the level.
- A gitleaks false positive is a `.gitleaksignore` fingerprint plus an `allowlist`
  entry whose `target` is `.gitleaksignore#<fingerprint>`. One that is only in the
  history, before the gate existed, belongs in `.gitleaks-baseline.json` (above).
- A tracked compiled executable or package (`doctor` warns `security.binary-artifacts`:
  a test fixture, a vendored tool) is built in CI instead, or registered with an
  `allowlist` entry whose `target` is `binary-artifacts#<path>`; `gradle-wrapper.jar`
  needs no entry when a workflow runs `gradle/actions/wrapper-validation`. An entry
  for a path no longer tracked is stale and reported.
- A `Dockerfile` or `Containerfile` that is not built here (a template, an example) is
  registered with an `allowlist` entry whose `target` is `container-gate#<path>`, and a
  Playwright spec that is not run here with `screenshot-baseline-present#<path>`; the
  rule then does not judge that file and `doctor` prints an `EXCLUDED` line for it.
- A vulnerability without a fix is an entry in `osv-scanner.toml` or
  `.trivyignore.yaml` with its native expiry field; those files need no inventory entry.
  Never `--ignore-unfixed`: it is a blanket bypass and the auditor reports it.
- A Semgrep false positive is a path in `.semgrepignore` plus an `allowlist` entry
  whose `target` is `.semgrepignore#<path>`. A root `.semgrepignore`
  replaces Semgrep's built-in default ignore list; it does not extend it. The seeded
  file therefore restates the defaults of the pinned Semgrep CE release (`test/`, `tests/`, `vendor/`, `node_modules/`, `dist/`,
  `*.min.js` and the rest); keep them, or Semgrep starts scanning those paths. An
  entry equal to one of those defaults needs no inventory entry; every other one does.
  A `.semgrepignore` that existed before the installer is left alone: add the default
  block to it yourself.
- In `.trivyignore.yaml`, `statement` is always quoted
  (`statement: "not reachable from our code; tracked in #123"`): unquoted, YAML ends
  it at ` #` (and refuses a `: ` inside it), so Trivy never sees the issue.

An expired entry turns `security-gate` red. Remove it, or renew it.

## Coverage ratchet

`.agent-setup/coverage.json` records one line percentage per app,
`{"schema": 1, "apps": {"<app>": <percentage>}}`. It is seeded at `0`, so the first
runs warn `Coverage <m>; ratchet the record up`: raise each record to the measured
value in a pull request of its own; raising never needs an exception. A measurement
below `record - coverage_tolerance` fails `Coverage <m> below recorded <r>
(tolerance <t>)`. Lowering a record, or removing an app from it, is allowed only with
a `coverage-reset` entry whose `target` is `.agent-setup/coverage.json`, with the old
and new value in `reason`; it lasts at most `bypass_max_days`. Never lower the record
or raise `coverage_tolerance` to get a pull request green.

## Changed lines and characterization first

`diff-coverage` judges each pull request twice, and both judgements must pass.

1. **Changed lines.** `diff-cover` compares the head's coverage report with the merge
   base and fails when fewer than `coverage_changed_lines_min` percent of the changed
   lines a report measures were executed (`Changed lines covered <m> %, below <min> %`).
   A pull request that changes no measured line (documentation, workflows, tests only)
   passes with `changed lines: none measured`.
2. **Characterization first.** Every source file the pull request modifies must have
   had at least one line executed by a test at the merge base; otherwise it fails with
   `Characterization first: <path> had no test executing it at <sha>`. Write tests of
   the file's current behaviour, merge them in a pull request of their own, then change
   the file. Added and deleted files, and test files, are not judged.

What the second rule proves: some test executed the file before the change, and the
tests and the change arrived in separate pull requests (a test added in the same pull
request does not change the base). What it does not prove: that those tests
characterise the behaviour, which stays the reviewer's question, or that their
assertions are strong, which `mutation-diff` measures.

The base report comes from the cache saved on every push to the default branch (by
`coverage-ratchet` when it is answered, else by `diff-coverage` itself), so a pull
request normally runs its tests once; it is recomputed at the merge base when the cache
misses, so the verdict never depends on the cache. A rust file the base report does not list fails like an
unexecuted one, since cargo-llvm-cov lists every source compiled into the tests. A
python file it does not list only warns, because coverage.py lists the files no test
imported only when `[tool.coverage.run] source` is set; set it so every file can be
judged.

Coverage measures the tests the pack selects by default: `cargo llvm-cov --workspace`
for rust, `pytest -q` for python-uv. When your declared `test` command runs fewer (one
package, or a subset because the rest needs services the CI job does not start), answer
`coverage_test_args.<app id>` with the same selection, for example `-p my-crate` or
`-m "not services"`; both `coverage-ratchet` and `diff-coverage` then measure exactly
those tests. For a rust app with the answer, a modified file outside the selection is
not in the report and only warns (`it is outside coverage_test_args.<app id>, so it is
not judged`).

### Measuring once: `coverage_source: project-ci`

By default `diff-coverage` runs your tests a second time, under coverage, beside your own
CI. When your repository keeps its own workflow (`ci-baseline` `workflow: existing`),
answer `coverage_source: project-ci` and the suite runs once:

1. Every test job of an app runs its tests under coverage and uploads the data as an
   artifact named `agentic-coverage-<app id>-<job>`: the coverage.py data file
   (`COVERAGE_CORE=sysmon pytest --cov --cov-report=` writes `.coverage`; upload it with
   `include-hidden-files: true`; on Python < 3.12, or with branch coverage on 3.12 and
   3.13, coverage.py keeps its default core and warns `no-sysmon`, which a suite that turns
   warnings into errors silences with `disable_warnings = ["no-sysmon"]`) or the LCOV report (`*.info`, for example
   `cargo llvm-cov nextest --lcov --output-path lcov.info`). Shards each upload their own.
2. A job named `diff-coverage` that needs those test jobs calls
   `uses: ./.github/workflows/agentic-coverage.yml`, which brakes renders: it combines
   the parts, judges both rules and, on pushes to the default branch, keeps the base
   report. It runs no test.
3. Your aggregate check needs `diff-coverage`, so the pull request cannot merge without it.

The plan prints one note per app with the artifact name. A missing base report only
warns (`<app>: no base report for <sha>; not judged`) instead of running the tests at the merge base;
the next push to the default branch saves one. `coverage_ratchet: true` refuses with
`project-ci` for now: `coverage-ratchet` still measures by itself.

`coverage_changed_lines` is on by default where an app is `rust` or `python-uv`, and every
such app is measured and judged in its own directory: in a monorepo each app gets its
own changed-lines and characterization steps, and the app at the repository root leaves
the other apps' files to them. `node` and `go` are unsupported until their packs declare
a per-file report. For one pull request
that cannot meet either rule, add a `coverage-reset` entry whose `target` is
`diff-coverage#<pull request number>` in that same pull request; both steps then print
`::warning::coverage-reset <id> until <expires> (<issue>)` and pass. An entry for any
other number that the pull request adds is unregistered and fails `security-gate`.

## Emergency bypass

`SECURITY_BYPASS` is the one sanctioned switch: a repository variable holding a JSON
array of inventory ids, empty by default.

1. Add a `job-bypass` entry whose `target` is the job to bypass, with a short expiry.
2. Set the variable, for example `gh variable set SECURITY_BYPASS --body '["osv-outage-2026-11"]'`.
3. The bypassed job prints `::warning::bypass <id> until <expires> (<issue>)` and
   succeeds; once `expires` passes, the same variable turns the job red.
4. Clear the variable (`gh variable set SECURITY_BYPASS --body '[]'`) and remove the
   entry when the cause is fixed.

`security-gate` ignores the variable: the secrets scan and the exceptions check have
no bypass. Never add `continue-on-error`, `|| true` or an `if:` on another variable
to a gate; the auditor reports them.

## Renewal is a new entry

Never edit `created` or `expires` of an existing entry. To renew, add a new entry
with a new `id`, today's `created` and a new `expires`, comment on the issue why the
exception is still needed, and remove the old entry when it expires. The history of
renewals is the file's git log.

## PII declaration

Where `.agent-setup/project.json` declares `criticality: personal-data-or-payments`
(or the `pii` answer is `true`), `.agent-setup/pii.yaml` lists every field that holds
personal data, and `security-gate` checks it in the step `Check the PII declaration`.
Each field carries seven keys: `path`, `category`, `purpose`, `lawful_basis`,
`retention`, `exclude_from` (an inline list of `logs`, `traces`, `analytics`, `cdc`)
and `erasure` (`delete`, `anonymise` or `retain-legal`). A `retain-legal` field names
its obligation in `purpose`; a `credentials` field excludes `logs` and `traces`. Add
the field in the same pull request that adds the column, event or attribute, and keep
`docs/runbooks/dsar.md` in step: it was generated once from the declaration and is the
project's afterwards.

## Local hooks

The hook configuration (`.pre-commit-config.yaml` or `lefthook.yml`) runs gitleaks on
staged changes with the release CI pins. Installing it writes under `.git/`, which
only the owner does, once per clone: `pre-commit install`, `prek install` or
`lefthook install`.
