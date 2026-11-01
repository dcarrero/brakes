# Tests of what the user sees

Last verified: 2026-10-30

The installer module `qa` gives this repository two tests that run on every pull
request as part of the `required` check: real HTTP requests against the API with
[Hurl](https://hurl.dev), and a browser journey against the web application with
[Playwright](https://playwright.dev) that compares screenshots with a committed
baseline. The installer writes the first files once and never runs Hurl, Playwright,
`npm` or a browser; the jobs do, in CI.

The files live under the `qa_dir` answer (`qa` by default): `api/` holds the `.hurl`
files, `web/` the seeded Playwright project when the module seeds one. After the first
install every file there is yours; only this guide is managed.

## How a `.hurl` file serves three times

A `.hurl` file never names a host. Every request starts with `{{base_url}}`, and each
runner passes its own value:

| Use | Who runs it | `base_url` |
|---|---|---|
| Pull-request test | the `qa-api` job | the API the job starts from the `api_start` answer, on `api_url` (`127.0.0.1` or `localhost` only) |
| Post-deploy smoke | `delivery` | the deployed URL |
| Uptime probe | `observability`, on a schedule | the production URL |

`api/00-ready.hurl` is the readiness request: the job retries only that file, about
once a second for `api_ready_timeout` seconds (`--retry <seconds> --retry-interval
1000`), until the API answers, then runs every other file once with `hurl --test`. The
wait defaults to one measurement of `ci.cycle_budget_minutes` when the profile declares
it, else 600 seconds; a start command that builds an image on a cold runner may need
more, so answer `api_ready_timeout` rather than retrying a red run. Keep it a `GET` with no side effect. The three uses run the
same two commands, rendered by the installer from one builder; only the variable that
holds `base_url` differs.

To run the files locally against a running API:

```sh
hurl --test --variable base_url=http://127.0.0.1:8080 --glob "qa/api/**/*.hurl"
```

## Add a test

- **An endpoint:** add a file beside `api/smoke.hurl`, one per endpoint family. Start
  each request with `{{base_url}}`; a literal `http://` or `https://` host is an auditor
  finding (`qa.hurl-no-literal-host`) because the file could no longer serve as smoke or
  uptime probe. A token the API needs comes from `HURL_VARIABLE_<name>`, never from the
  file.
- **A journey:** add a `*.spec.ts` beside `web/smoke.spec.ts`. Use `toHaveScreenshot`
  only where the screen is stable; every new screenshot needs its baseline (next
  section) before the job can pass.

## The web's host

`web_url` defaults to `http://localhost:3000`. A development server may refuse its own
resources to a host it does not know, and a page whose client code never loads keeps
its first render: Next.js blocks cross-origin requests to its development resources
and allows `localhost`, its subdomains and the hostname it was started with
(`allowedDevOrigins`), so `next dev` reached on `127.0.0.1` never hydrates and every
screenshot shows its entrance state. Check the job log of the first run for such a
warning (`Blocked cross-origin request`), and answer `web_url` with a host the server
accepts, or add the host to the server's own allow-list.

## Regenerate a screenshot baseline

A baseline is evidence, not code. It is generated on Linux, in the pinned Playwright
image, the image the `qa-web` job runs in, so both see the same browser and fonts; one
generated on macOS or Windows, or on a machine with other fonts, never matches. CI
never updates a baseline, and the installer never generates one.

```sh
cd qa/web
npm install                     # once: commit package-lock.json
docker run --rm -v "$PWD":/work -w /work \
  -e QA_WEB_START='<web_start>' -e QA_WEB_URL='<web_url>' \
  {{images.playwright}} \
  npx playwright test --update-snapshots
```

`@playwright/test` is pinned to `{{tools.playwright}}` in `package.json`, the same
version as the image. Open every image and look at it before committing the
`*-snapshots/` directory: a baseline with blank sections makes blank sections the
reference.

The seeded smoke test screenshots a settled page: `reducedMotion: 'reduce'` in the
config, then in the test a quiet network, loaded fonts, one pass down the page so
content that appears on scroll is revealed, and `animations: 'disabled'`. Animations
that ignore `prefers-reduced-motion`, or start only once client code has run, can still
be caught mid-way. When the first image shows empty blocks where the page has content,
make the application honour reduced motion, or settle that part in the test (wait for
an element it shows), then regenerate. A page that never hydrates keeps its entrance
state however long the test waits: a development server may refuse the test's origin
(Next.js blocks its development resources for hosts other than `localhost` and the one
it was started with unless `allowedDevOrigins` lists them, so `next dev` reached on
`127.0.0.1` stays unhydrated). Answer `web_url` with a host the server accepts, or
serve a production build.

Keep the baselines where Playwright puts them by default, in `<spec file>-snapshots/`
beside each spec. The auditor's `qa.screenshot-baseline-present` and the protected-path
glob look only there: a custom `snapshotPathTemplate` or `snapshotDir` is not followed,
so baselines moved elsewhere read as missing and are not protected.

## What the `human-approved` label means

The `*-snapshots/` directories under the web directory are protected paths: a pull
request that changes a baseline keeps `required` red until the owner adds the
`human-approved` label. Without that gate an agent could make a broken screen pass by
regenerating its evidence. Changing a `.hurl` or `.spec.ts` file needs no label.

## Contracts

When the repository holds an OpenAPI 3 or AsyncAPI contract (the `openapi` and
`asyncapi` answers, or the only such document the installer finds), the `qa-contracts`
job lints it on every run (vacuum for OpenAPI, `asyncapi validate` for AsyncAPI) and,
on a pull request, compares it with the base: the file as it is in `HEAD^1`, the
commit the pull request merges into. A change that can break a client written
against the base (`oasdiff breaking` at `ERR`, or `asyncapi diff`'s breaking
changes) keeps `required` red until the owner adds the `human-approved` label; a
document a tool cannot load is red with or without it. The job runs on docs-only
pull requests too, so a contract under `docs/` still gets its check.

A contract must be one self-contained file. A `$ref` that points outside the file
(another file or a URL) fails the job before any tool runs, because the tools would
read other files or the network. Bundle it locally and point the answer at the
bundled file:

```sh
vacuum bundle docs/openapi.yaml docs/openapi.bundled.yaml
brakes configure . qa --set openapi=docs/openapi.bundled.yaml --apply
```

Several contracts are answered as one list, separated by commas; each one is linted
and compared. When a live contract has a frozen copy of its published version beside
it, declare the pair so the live contract is compared with what clients were given
rather than with the previous commit; the published copy is then a baseline, not a
contract, and a pull request that changes it needs `human-approved`:

```sh
brakes configure . qa \
  --set openapi=contracts/sales/openapi.json,contracts/prices/openapi.json \
  --set contract_published=contracts/sales/openapi.json=contracts/sales/published/v1.openapi.json,contracts/prices/openapi.json=contracts/prices/published/v1.openapi.json \
  --apply
```

If a declared command already fails on a breaking change of every listed contract,
`--set contract_compat_by=verify` (or `lint`, `test`, `build`) says so: `qa-contracts`
then only lints. The installer accepts it only when `required` runs that command on
every change of the contracts (ci-baseline generates the workflow, answers `commands`
with it, and no contract is an inert path); it never reads the command to guess.

In a monorepo each app answers its own contracts (`apps.<id>.openapi`, relative to the
app) and gets its own `<app>-qa-contracts` job, skipped when the pull request does not
touch the app. `--set openapi=none` (or `asyncapi=none`) turns the job off, but `doctor`
keeps reporting every OpenAPI or AsyncAPI document it finds that nothing checks: an
answer never hides a contract. A Swagger 2.0 file is never checked; convert it to
OpenAPI 3.[[setup-core:

## See also

- `e2e.md`: describing critical user journeys independently of the tool, and keeping
  the environments they run against controlled.
- `testing.md`: acceptance before implementation, test design and the evidence a test
  must be able to give.]]
