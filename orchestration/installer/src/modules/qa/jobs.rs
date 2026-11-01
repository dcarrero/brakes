//! The jobs `qa` contributes to `ci-baseline`'s workflow through
//! `Module::ci_jobs` (SPEC-qa.md, Contributed CI jobs; SPEC-ci-baseline.md,
//! Composition): `qa-api` (T6, #1003) and `qa-web` (T7, #1004), both
//! skippable under tier `docs`. Each body is the job mapping at column zero,
//! rendered from `templates/qa/fragments/{api,web}-job.yml`; the shells are
//! embedded verbatim, Hurl comes from the shared pin table through
//! `security`'s `install-tool.sh`, Playwright from the web directory's own
//! lockfile (never a version on the command line), and every `uses:` from the
//! same table. Answers reach the job only through
//! `env:`, as JSON strings (valid YAML double-quoted scalars). `ci-baseline`
//! inserts the job; nothing here writes a workflow.
use super::{
    AppQa, QaAnswers, Web, api_job_minutes,
    contracts::Contracts,
    files::{QaFiles, hurl_command},
    seeds::join,
};
use crate::{
    Result,
    engine::{CiJob, CiTier, Context},
    modules::{
        ci_baseline::{
            CI_BASELINE, Runner,
            render::{runner_label, within_job_max},
        },
        security::INSTALL_TOOL,
        stack_packs::{PinTable, StackId, Step, required_packs},
    },
};
use serde_json::Value;

pub const QA_API: &str = "qa-api";
pub const QA_WEB: &str = "qa-web";
pub const QA_CONTRACTS: &str = "qa-contracts";

const API_JOB: &str = include_str!("../../../../../templates/qa/fragments/api-job.yml");
const WEB_JOB: &str = include_str!("../../../../../templates/qa/fragments/web-job.yml");
const CONTRACTS_JOB: &str = include_str!("../../../../../templates/qa/fragments/contracts-job.yml");
/// The first lines of the compare and upload steps of `contracts-job.yml`.
const COMPARE_STEP: &str = "  - name: Compare the contracts with the base\n";
const UPLOAD_STEP: &str = "  - name: Upload the contracts report\n";
/// Refuses an external `$ref`, lints, and compares with `HEAD^1` (#1016).
pub const CONTRACTS_CHECK: &str =
    include_str!("../../../../../templates/qa/fragments/contracts-check.sh");
/// What a seeded web runs: the seeded config starts the web (`webServer`).
const SEEDED_RUN: &str = "npx playwright test";
/// The web directory's install, at the fragment's `{{npm_ci}}` line.
const NPM_CI: &str = "  - name: Install the web tests' dependencies\n    working-directory: {{web_dir}}\n    run: |\n      npm ci\n";
/// Starts the application in its own session; writes the PID file and the log.
pub const START_APP: &str = include_str!("../../../../../templates/qa/fragments/start-app.sh");
/// Ends the process group `START_APP` started; prints the log tail on failure.
pub const STOP_APP: &str = include_str!("../../../../../templates/qa/fragments/stop-app.sh");

/// `text` with every non-empty line indented by `n` spaces; no trailing newline.
fn indent(text: &str, n: usize) -> String {
    let pad = " ".repeat(n);
    text.lines()
        .map(|line| {
            if line.is_empty() {
                String::new()
            } else {
                format!("{pad}{line}")
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// A YAML double-quoted scalar for an answer: JSON string escaping is valid
/// YAML, so a quote, a backslash or a newline in the answer stays data.
fn quoted(text: &str) -> String {
    Value::String(text.to_owned()).to_string()
}

/// Replaces every `{{key}}` of `pairs` in `template`, in order: a value can
/// only be reached by a later key, so the answers go last and the embedded
/// shells carry no `{{`.
fn fill(template: &str, pairs: &[(&str, String)]) -> String {
    pairs
        .iter()
        .fold(template.to_owned(), |text, (key, value)| {
            text.replace(&format!("{{{{{key}}}}}"), value)
        })
}

/// The `runs-on` label `ci-baseline`'s `runner` answer picks.
fn runner(cx: &Context<'_>) -> Result<&'static str> {
    let answer = cx
        .answers_of(CI_BASELINE)?
        .get("runner")
        .and_then(Value::as_str);
    let runner = Runner::ALL
        .into_iter()
        .find(|r| Some(r.as_str()) == answer)
        .unwrap_or(Runner::Configured);
    Ok(runner_label(runner))
}

/// The `ci_setup` steps of the stack-packs app at `path` and its stack; none
/// and `None` without one.
fn setup_at(cx: &Context<'_>, path: &str, pins: &PinTable) -> Result<(Vec<Step>, Option<StackId>)> {
    for (app, pack) in required_packs(cx)? {
        if app.path == path {
            return Ok(((pack.ci_setup)(&app, pins)?, Some(app.stack)));
        }
    }
    Ok((Vec::new(), None))
}

/// `steps` as items of a fragment's `steps:` list (column two), each line
/// ending in a newline; empty for none. `render::step` writes a step at the
/// workflow's depth (six spaces), so four are removed.
fn steps_block(steps: &[Step]) -> String {
    let mut out = String::new();
    for step in steps {
        let mut text = String::new();
        crate::modules::ci_baseline::render::step(&mut text, step);
        for line in text.lines() {
            out.push_str(line.strip_prefix("    ").unwrap_or(line));
            out.push('\n');
        }
    }
    out
}

/// The job of one target: `qa-<kind>` for the root, `<app>-qa-<kind>` for a
/// listed app (T13, #1011).
pub fn job_id(app: Option<&str>, kind: &str) -> String {
    match app {
        Some(app) => format!("{app}-qa-{kind}"),
        None => format!("qa-{kind}"),
    }
}

/// A fragment's header for the job `id`: its `name` and its artifact's, and for an app job the
/// skippable-list condition `ci-baseline`'s own app jobs use (#1097), which
/// covers the tier skip too.
fn header(fragment: &str, id: &str, app: Option<&str>) -> String {
    let kind = if fragment.starts_with("name: qa-api\n") {
        QA_API
    } else if fragment.starts_with("name: qa-contracts\n") {
        QA_CONTRACTS
    } else {
        QA_WEB
    };
    // The job's name and its report artifact's: two app jobs of one run never
    // upload under the same artifact name.
    let named = fragment.replace(&format!("name: {kind}\n"), &format!("name: {id}\n"));
    let skippable =
        format!("if: contains(fromJSON(needs.scope.outputs.skippable), '{id}') == false\n");
    match app {
        None => named,
        // `qa-contracts` has no tier condition to replace: it never skips by tier.
        Some(_) if kind == QA_CONTRACTS => {
            named.replacen("needs: scope\n", &format!("needs: scope\n{skippable}"), 1)
        }
        Some(_) => named.replacen("if: needs.scope.outputs.tier != 'docs'\n", &skippable, 1),
    }
}

/// `qa-api` for one target (the root, or the listed `app` at `target.path`):
/// checkout, that app's `ci_setup`, Hurl by checksum, the API started from
/// `api_start` in the background from the app's directory, readiness by Hurl's
/// own retry on `00-ready.hurl` only, every `.hurl` file once with a JUnit
/// report, then the stop and the report upload whatever happened.
pub fn api(
    cx: &Context<'_>,
    target: &AppQa,
    app: Option<&str>,
    qa_dir: &str,
    pins: &PinTable,
) -> Result<CiJob> {
    let id = job_id(app, "api");
    let Some(start) = target.api_start.as_deref() else {
        return crate::refuse(format!("qa: {id} needs api_start"));
    };
    let mut hurl_env = pins.tool_binary("hurl")?;
    hurl_env.sort();
    let hurl_env = hurl_env
        .iter()
        .map(|(key, value)| format!("      {key}: {}", quoted(value)))
        .collect::<Vec<_>>()
        .join("\n");
    let (setup, _) = setup_at(cx, &target.path, pins)?;
    let start_dir = match target.path.as_str() {
        "." => String::new(),
        path => format!("    working-directory: {}\n", quoted(path)),
    };
    // The pull-request use of the files `delivery` and `observability` share.
    let files = QaFiles::of(
        app.map(str::to_owned),
        &target.path,
        qa_dir,
        target.api_ready_timeout,
    );
    let hurl = hurl_command(&files, "QA_API_URL")?;
    let job = header(API_JOB, &id, app)
        .replace("{{setup_steps}}\n", &steps_block(&setup))
        .replace("{{start_dir}}", &start_dir);
    let yaml = fill(
        &job,
        &[
            ("runner", runner(cx)?.to_owned()),
            (
                "timeout",
                within_job_max(api_job_minutes(target.api_ready_timeout)).to_string(),
            ),
            ("checkout", pins.action("actions/checkout")?.uses()),
            (
                "upload_artifact",
                pins.action("actions/upload-artifact")?.uses(),
            ),
            ("hurl_env", hurl_env),
            ("install_tool", indent(INSTALL_TOOL, 6)),
            ("start_app", indent(START_APP, 6)),
            ("stop_app", indent(STOP_APP, 6)),
            ("hurl_ready", hurl.ready),
            ("hurl_run", hurl.run),
            // Answers last: nothing is substituted after them.
            ("qa_dir", quoted(&files.dir)),
            ("api_url", quoted(&target.api_url)),
            ("api_start", quoted(start)),
        ],
    );
    Ok(CiJob {
        id,
        yaml,
        skippable_under: vec![CiTier::Docs],
        app: app.map(str::to_owned),
    })
}

/// `qa-web` for one target, inside the pinned `images.playwright` container,
/// the environment the local baseline is generated in (#1283): checkout, that
/// app's `ci_setup` (and `actions/setup-node` at `tools.node` when the app is
/// not node), the lockfile check, `npm ci` (unless a node app's `ci_setup`
/// already ran it in `web_dir: .`), the Chromium of the installed
/// `@playwright/test` without system packages, then `npx playwright test` (seeded) or `web_command` (project) from the web
/// directory, and the report upload whatever happened. Never
/// `--update-snapshots`: the baseline is evidence the job only compares with.
pub fn web(cx: &Context<'_>, target: &AppQa, app: Option<&str>, pins: &PinTable) -> Result<CiJob> {
    let id = job_id(app, "web");
    let Some(start) = target.web_start.as_deref() else {
        return crate::refuse(format!("qa: {id} needs web_start"));
    };
    let (mut setup, stack) = setup_at(cx, &target.path, pins)?;
    let node = stack == Some(StackId::Node);
    // A node app's `ci_setup` already installed its directory; `web_dir: .` is it.
    let npm_ci = if node && target.web_dir == "." {
        ""
    } else {
        NPM_CI
    };
    if !node {
        setup.push(
            Step::new("Set up Node for Playwright")
                .uses(pins.action("actions/setup-node")?)
                .with("node-version", pins.tool("node")?.version.clone())
                .with("package-manager-cache", "false"),
        );
    }
    let mut env = vec![
        ("QA_WEB_START", start),
        ("QA_WEB_URL", target.web_url.as_str()),
    ];
    let run = match target.web {
        Web::Project => {
            env.push(("QA_WEB_COMMAND", target.web_command.as_str()));
            "bash -euo pipefail -c \"$QA_WEB_COMMAND\"".to_owned()
        }
        _ => SEEDED_RUN.to_owned(),
    };
    let env = env
        .iter()
        .map(|(key, value)| format!("      {key}: {}", quoted(value)))
        .collect::<Vec<_>>()
        .join("\n");
    let web_dir = join(&target.path, &target.web_dir);
    let report_dir = match web_dir.as_str() {
        "." => String::new(),
        dir => format!("{dir}/"),
    };
    // A web directory outside the app (#1211) holds tests the scope job does not
    // watch for it: the job skips by tier only, never with an unchanged app.
    let inside = target.path == "."
        || web_dir == target.path
        || web_dir.starts_with(&format!("{}/", target.path));
    let app = app.filter(|_| inside);
    let job = header(WEB_JOB, &id, app)
        .replace("{{setup_steps}}\n", &steps_block(&setup))
        .replace("{{npm_ci}}", npm_ci);
    let yaml = fill(
        &job,
        &[
            ("runner", runner(cx)?.to_owned()),
            (
                "playwright_image",
                quoted(&pins.image("playwright")?.pinned()),
            ),
            ("checkout", pins.action("actions/checkout")?.uses()),
            (
                "upload_artifact",
                pins.action("actions/upload-artifact")?.uses(),
            ),
            ("web_run", indent(&run, 6)),
            // Answers last: nothing is substituted after them.
            ("report_dir", report_dir),
            ("web_dir", quoted(&web_dir)),
            ("web_env", env),
        ],
    );
    Ok(CiJob {
        id,
        yaml,
        skippable_under: vec![CiTier::Docs],
        app: app.map(str::to_owned),
    })
}

/// An install step at column two: `env:` from the pin table's binary fields,
/// then `install-tool.sh`.
fn install_step(pins: &PinTable, tool: &str) -> Result<String> {
    let mut env = pins.tool_binary(tool)?;
    env.sort();
    let env = env
        .iter()
        .map(|(key, value)| format!("      {key}: {}\n", quoted(value)))
        .collect::<String>();
    Ok(format!(
        "  - name: Install {tool}\n    env:\n{env}    run: |\n{}\n",
        indent(INSTALL_TOOL, 6)
    ))
}

/// `qa-contracts` (T17, #1016; SPEC-qa.md, Contracts): checkout with the merge
/// commit's parents (`fetch-depth: 2`), vacuum and oasdiff by checksum for an
/// OpenAPI contract, Node and `@asyncapi/cli` at its exact version (no install
/// scripts) for an AsyncAPI one, then `contracts-check.sh` to lint on every
/// event and to compare with the base on pull requests only, and the report
/// upload whatever happened. Never skippable by tier: a contract under `docs/`
/// would otherwise skip its own check.
pub fn contracts(
    cx: &Context<'_>,
    c: &Contracts,
    app: Option<&str>,
    path: &str,
    pins: &PinTable,
) -> Result<CiJob> {
    let id = job_id(app, "contracts");
    let mut install = String::new();
    let mut env: Vec<(&str, String)> = Vec::new();
    if !c.openapi.is_empty() {
        install.push_str(&install_step(pins, "vacuum")?);
        // A declared compatibility command compares instead (#1182): no oasdiff.
        if c.compat_by.is_none() {
            install.push_str(&install_step(pins, "oasdiff")?);
        }
        env.push(("QA_OPENAPI", c.openapi.join(",")));
        if let Some(ruleset) = &c.ruleset {
            env.push(("QA_CONTRACT_RULESET", ruleset.clone()));
        }
        env.push(("QA_VACUUM_VERSION", pins.tool("vacuum")?.version.clone()));
    }
    if !c.asyncapi.is_empty() {
        let cli = pins.tool("asyncapi-cli")?.version.clone();
        install.push_str(&steps_block(&[Step::new(
            "Set up Node for the AsyncAPI CLI",
        )
        .uses(pins.action("actions/setup-node")?)
        .with("node-version", pins.tool("node")?.version.clone())
        .with("package-manager-cache", "false")]));
        install.push_str(&format!(
            "  - name: Install the AsyncAPI CLI\n    env:\n      QA_ASYNCAPI_CLI: {}\n    run: |\n      npm install --prefix \"$RUNNER_TEMP/qa/asyncapi-cli\" --ignore-scripts --no-audit --no-fund \"@asyncapi/cli@$QA_ASYNCAPI_CLI\"\n      echo \"$RUNNER_TEMP/qa/asyncapi-cli/node_modules/.bin\" >> \"$GITHUB_PATH\"\n",
            quoted(&cli)
        ));
        env.push(("QA_ASYNCAPI", c.asyncapi.join(",")));
        env.push(("QA_ASYNCAPI_VERSION", cli));
    }
    if !c.published.is_empty() {
        let pairs: Vec<String> = c
            .published
            .iter()
            .map(|(live, copy)| format!("{live}={copy}"))
            .collect();
        env.push(("QA_PUBLISHED", pairs.join(",")));
    }
    let env = env
        .iter()
        .map(|(key, value)| format!("      {key}: {}", quoted(value)))
        .collect::<Vec<_>>()
        .join("\n");
    // An app's contracts are relative to its directory; the script runs there.
    let work_dir = match path {
        "." => String::new(),
        path => format!("    working-directory: {}\n", quoted(path)),
    };
    let mut job = header(CONTRACTS_JOB, &id, app)
        .replace("{{install_steps}}\n", &install)
        .replace("{{work_dir}}", &work_dir);
    if c.compat_by.is_some() {
        // The declared command compares (#1182): the job lints only.
        let start = job.find(COMPARE_STEP).expect("the contracts job compares");
        let end = job.find(UPLOAD_STEP).expect("the contracts job uploads");
        job.replace_range(start..end, "");
    }
    let yaml = fill(
        &job,
        &[
            ("runner", runner(cx)?.to_owned()),
            ("checkout", pins.action("actions/checkout")?.uses()),
            (
                "upload_artifact",
                pins.action("actions/upload-artifact")?.uses(),
            ),
            ("check", indent(CONTRACTS_CHECK, 6)),
            // Answers last: nothing is substituted after them.
            ("check_env", env),
        ],
    );
    Ok(CiJob {
        id,
        yaml,
        skippable_under: Vec::new(),
        app: app.map(str::to_owned),
    })
}

/// The jobs in contribution order: the root target's `qa-api` and `qa-web`,
/// then each listed app's `<app>-qa-api` and `<app>-qa-web` in app id order,
/// each when its target has an API or a web application; then `qa-contracts` when
/// the root has a contract (#1016; monorepo contracts are not yet answered).
pub fn contributed(cx: &Context<'_>) -> Result<Vec<CiJob>> {
    let answers = QaAnswers::load(cx)?;
    let pins = PinTable::embedded()?;
    let root = answers.root_target();
    let targets = std::iter::once((None, &root)).chain(
        answers
            .apps
            .iter()
            .map(|(id, app)| (Some(id.as_str()), app)),
    );
    let mut jobs = Vec::new();
    for (app, target) in targets {
        if target.api {
            jobs.push(api(cx, target, app, &answers.qa_dir, &pins)?);
        }
        if target.web != Web::None {
            jobs.push(web(cx, target, app, &pins)?);
        }
        if target.contracts.any() {
            jobs.push(contracts(cx, &target.contracts, app, &target.path, &pins)?);
        }
    }
    Ok(jobs)
}
