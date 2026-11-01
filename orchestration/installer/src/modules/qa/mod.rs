//! The qa module: tests of what the user sees, Hurl for the API and Playwright
//! for the web (`SPEC-qa.md`). T3 (#1000) the `Module` impl: the question
//! schema, `QaAnswers::load` with every refusal of the spec, registration and
//! `requires`. T4 (#1001) derives unanswered `api` and `web` from the files of
//! each recorded stack-packs app (`detect`) and notes each derived value with
//! its evidence. T5 (#1002) renders the seeds, the managed guide and the
//! `never-touch` listing (`seeds`), and checks that no `.hurl` seed names a
//! host (`hurl`). T6 (#1003) contributes `qa-api` through `ci_jobs` (`jobs`);
//! T7 (#1004) adds `qa-web`; the protected baseline is T8 (`protected`); the
//! manual steps are T9 (`manual`).
//!
//! In `modules::all()` after `security` and before `ci-baseline`: like every
//! module it is active only when recorded in the lock or requested with
//! `install --module`, and the plan refuses it unless `ci-baseline` and
//! `stack-packs` are active too.
use crate::{
    Result,
    engine::{Context, Module, Rendered, answers::Schema, manual::ManualStep},
    modules::{
        ci_baseline::{
            CI_BASELINE,
            model::heldout_dir,
            render::{JOB_TIMEOUT_MAX, measurement_minutes, over_job_max_note},
        },
        stack_packs::{self, STACK_PACKS},
    },
    refuse,
};
use detect::Derivation;
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path};

pub mod audit;
pub mod contracts;
pub mod detect;
pub mod files;
pub mod hurl;
pub mod jobs;
pub mod manual;
pub mod protected;
pub mod seeds;

pub const QA: &str = "qa";
pub const QA_VERSION: &str = "1.0.0";

pub const DEFAULT_QA_DIR: &str = "qa";
pub const DEFAULT_API_URL: &str = "http://127.0.0.1:8080";
pub const DEFAULT_API_READY_PATH: &str = "/livez";
/// `api_ready_timeout` without an answer or a declared budget, in seconds (#1243):
/// ten of `qa-api`'s fifteen minutes, five left for setup and the tests.
pub const DEFAULT_API_READY_TIMEOUT: u32 = 600;
/// The shortest `api_ready_timeout`, in seconds.
pub const API_READY_TIMEOUT_MIN: u32 = 10;
/// The longest `api_ready_timeout`, in seconds: with [`READY_SLACK_MINUTES`]
/// `qa-api` stays within GitHub's 360-minute job maximum.
pub const API_READY_TIMEOUT_MAX: u32 = (JOB_TIMEOUT_MAX - READY_SLACK_MINUTES) * 60;
/// The minutes `qa-api` keeps beyond its readiness wait, for setup and the tests.
pub const READY_SLACK_MINUTES: u32 = 5;
/// `localhost`, not `127.0.0.1` (#1250): a development server may refuse its own
/// resources to other hosts (Next.js `allowedDevOrigins`), leaving the page unhydrated.
pub const DEFAULT_WEB_URL: &str = "http://localhost:3000";
pub const DEFAULT_WEB_COMMAND: &str = "npx playwright test";
/// Directory names the module never writes in or under: the project's tests.
pub const TEST_DIRS: [&str; 4] = ["tests", "test", "e2e", "spec"];
/// The project's own Playwright configuration that `web: project` needs.
pub const PLAYWRIGHT_CONFIGS: [&str; 3] = [
    "playwright.config.ts",
    "playwright.config.js",
    "playwright.config.mjs",
];

/// The answers that apply per target, at the root and under `apps.<id>.*`.
const TARGET_FIELDS: [&str; 15] = [
    "api",
    "api_start",
    "api_url",
    "api_ready_path",
    "api_ready_timeout",
    "web",
    "web_start",
    "web_url",
    "web_command",
    "web_dir",
    "openapi",
    "asyncapi",
    "contract_ruleset",
    "contract_published",
    "contract_compat_by",
];

pub struct Qa;

/// How the web application is tested.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Web {
    /// No web job.
    None,
    /// The module's `web/` seeds.
    Seeded,
    /// The project's own Playwright; only the job is contributed.
    Project,
}

impl Web {
    pub const ALL: [Web; 3] = [Web::None, Web::Seeded, Web::Project];
    pub const fn as_str(self) -> &'static str {
        match self {
            Web::None => "none",
            Web::Seeded => "seeded",
            Web::Project => "project",
        }
    }
}

/// The answers of one app of a monorepo (`apps.<id>.*`), resolved like the
/// root ones; its paths are relative to the app directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppQa {
    /// The app directory from `stack-packs`.
    pub path: String,
    pub api: bool,
    pub api_start: Option<String>,
    pub api_url: String,
    pub api_ready_path: String,
    /// Seconds `00-ready.hurl` is retried before the job fails (#1243).
    pub api_ready_timeout: u32,
    pub web: Web,
    pub web_start: Option<String>,
    pub web_url: String,
    pub web_command: String,
    pub web_dir: String,
    /// The contracts its `qa-contracts` judges, relative to `path` (#1115).
    pub contracts: contracts::Contracts,
}

/// The module's answers with every default resolved and every rule applied.
/// `api_start` is `Some` exactly when `api`; `web_start` exactly when `web` is
/// not `None`. The URLs, `api_ready_path`, `web_command` and `web_dir` always
/// carry their resolved value; a job reads them only when it applies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QaAnswers {
    /// Normalised: no leading `./`, no trailing `/`.
    pub qa_dir: String,
    pub api: bool,
    pub api_start: Option<String>,
    pub api_url: String,
    pub api_ready_path: String,
    /// Seconds `00-ready.hurl` is retried before the job fails (#1243).
    pub api_ready_timeout: u32,
    pub web: Web,
    pub web_start: Option<String>,
    pub web_url: String,
    pub web_command: String,
    pub web_dir: String,
    /// Monorepo: the apps that get their own jobs, by `stack-packs` app id.
    pub apps: BTreeMap<String, AppQa>,
    /// Each value derived because it was unanswered, with its evidence, as the
    /// plan notes it: `api derived true: Dockerfile`,
    /// `apps.web.web derived seeded: web/package.json names react`; then each
    /// seeded web directory under a `tsconfig.json` (#1211).
    pub derived: Vec<String>,
    /// The contracts `qa-contracts` judges (T17, #1016); root target only.
    pub contracts: contracts::Contracts,
}

/// The question table of the spec, in asking order, then one pattern per
/// field for `apps.<id>.*`. `api` and `web` carry no default and the answers
/// they gate no `when`: both are derived when unanswered (`detect`), which the
/// engine's `when` cannot read, so `QaAnswers::load` applies the gates and the
/// defaults (as `security` does for `deps`); a recorded default would stop the
/// derivation.
pub fn schema() -> Schema {
    let webs: Vec<&str> = Web::ALL.iter().map(|w| w.as_str()).collect();
    let mut questions = vec![
        json!({"id": "qa_dir", "type": "string", "minLength": 1, "default": DEFAULT_QA_DIR,
         "description": "Directory of the module's files: a relative path inside the repository that is not, and does not contain, a test directory."}),
        json!({"id": "api", "type": "boolean",
         "description": "Adds qa-api and the api/ seeds; default: whether a stack pack declares a service."}),
        json!({"id": "api_start", "type": "string", "minLength": 1,
         "description": "When api: the full command that starts the API in the foreground on api_url; required, never invented."}),
        json!({"id": "api_url", "type": "string", "minLength": 1,
         "description": "When api: Hurl's base_url, http://127.0.0.1:<port> or http://localhost:<port>; default http://127.0.0.1:8080."}),
        json!({"id": "api_ready_path", "type": "string", "minLength": 1,
         "description": "When api: the path 00-ready.hurl polls; default /livez."}),
        json!({"id": "api_ready_timeout", "type": "integer",
         "minimum": API_READY_TIMEOUT_MIN, "maximum": API_READY_TIMEOUT_MAX,
         "description": "When api: seconds qa-api waits for 00-ready.hurl to pass; default one measurement of ci.cycle_budget_minutes when declared, else 600."}),
        json!({"id": "web", "type": "string", "enum": webs,
         "description": "`seeded`: the module's web/ seeds; `project`: the project's own Playwright; default derived from the repository."}),
        json!({"id": "web_start", "type": "string", "minLength": 1,
         "description": "When web is not none: the command that serves the web on web_url; required, never invented; may equal api_start."}),
        json!({"id": "web_url", "type": "string", "minLength": 1,
         "description": "When web is not none: Playwright's baseURL, local only as api_url; default http://localhost:3000."}),
        json!({"id": "web_command", "type": "string", "minLength": 1,
         "description": "When web is project: the project's own test command; default npx playwright test."}),
        json!({"id": "web_dir", "type": "string", "minLength": 1,
         "description": "When web is not none: where package.json, the config and the snapshots live; default <qa_dir>/web when seeded, . when project."}),
        json!({"id": "openapi", "type": "string", "minLength": 1,
         "description": "The OpenAPI 3 contracts qa-contracts lints and compares, separated by commas, or none; derived: the only OpenAPI 3 document."}),
        json!({"id": "asyncapi", "type": "string", "minLength": 1,
         "description": "The AsyncAPI 2 or 3 contracts qa-contracts lints and compares, separated by commas, or none; derived: the only AsyncAPI document."}),
        json!({"id": "contract_ruleset", "type": "string", "minLength": 1,
         "description": "With openapi: the Spectral ruleset vacuum lints with, or none; derived: the only .spectral.{yaml,yml,json} at the root."}),
        json!({"id": "contract_published", "type": "string", "minLength": 1,
         "description": "live=published pairs separated by commas, or none: each live contract is compared with its frozen published copy instead of the base branch's; a published copy is a baseline, never linted."}),
        json!({"id": "contract_compat_by", "type": "string",
         "enum": [contracts::COMPAT_BY_QA, "lint", "test", "verify", "build"],
         "description": "Who checks backwards compatibility: qa (qa-contracts, the default) or the declared command of project.json that required already runs on every contract change."}),
        json!({"id": "apps", "type": "array", "items": {"type": "string"},
         "description": "Monorepo: the stack-packs apps that get their own qa jobs; their answers go under apps.<id>.*."}),
    ];
    let root: Vec<Value> = questions.clone();
    for field in TARGET_FIELDS {
        let mut question = root
            .iter()
            .find(|q| q["id"] == field)
            .expect("every target field is a root question")
            .clone();
        question["id"] = json!(format!("apps.*.{field}"));
        questions.push(question);
    }
    Schema::parse(&Value::Array(questions)).expect("the qa schema parses")
}

impl QaAnswers {
    /// The root target's answers as an [`AppQa`] at `.`, the shape every
    /// listed app has, so jobs and steps treat both alike.
    pub fn root_target(&self) -> AppQa {
        AppQa {
            path: ".".to_owned(),
            api: self.api,
            api_start: self.api_start.clone(),
            api_url: self.api_url.clone(),
            api_ready_path: self.api_ready_path.clone(),
            api_ready_timeout: self.api_ready_timeout,
            web: self.web,
            web_start: self.web_start.clone(),
            web_url: self.web_url.clone(),
            web_command: self.web_command.clone(),
            web_dir: self.web_dir.clone(),
            contracts: self.contracts.clone(),
        }
    }

    /// The validated answers in `cx` with the module's rules applied; every
    /// refusal of the spec, so `configure` and `install` refuse before a write.
    pub fn load(cx: &Context<'_>) -> Result<Self> {
        let a = cx.answers;
        let qa_dir = qa_dir(
            cx.root,
            a.get("qa_dir")
                .and_then(Value::as_str)
                .unwrap_or(DEFAULT_QA_DIR),
        )?;
        let packs = stack_packs::required_packs(cx)?;
        let mut derived = Vec::new();
        // The root target derives from the stack-packs app at the root, if any.
        let at_root = match packs.iter().find(|(app, _)| app.path == ".") {
            Some((app, _)) => detect::derive(cx.root, ".", app.container)?,
            None => Derivation::none(),
        };
        let ready = ready_timeout_default(cx);
        let root = target(
            cx.root,
            ".",
            &qa_dir,
            &at_root,
            ready,
            &mut derived,
            |field| (field.to_owned(), a.get(field)),
        )?;
        let listed: Vec<String> = a
            .get("apps")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        for key in a.keys() {
            if let Some((id, _)) = key.strip_prefix("apps.").and_then(|r| r.split_once('.'))
                && !listed.iter().any(|app| app == id)
            {
                return refuse(format!(
                    "qa: {key} answers app {id}, which apps does not list; add it to apps"
                ));
            }
        }
        let mut apps = BTreeMap::new();
        if !listed.is_empty() {
            for id in &listed {
                let Some((app, _)) = packs.iter().find(|(app, _)| &app.id == id) else {
                    return refuse(format!(
                        "qa: apps lists {id}, which is not an app of stack-packs; record it there first"
                    ));
                };
                refuse_tests_inside(&cx.root.join(&app.path), &qa_dir)?;
                let found = detect::derive(cx.root, &app.path, app.container)?;
                let mut target = target(
                    cx.root,
                    &app.path,
                    &qa_dir,
                    &found,
                    ready,
                    &mut derived,
                    |field| {
                        let key = format!("apps.{id}.{field}");
                        let value = a.get(&key);
                        (key, value)
                    },
                )?;
                target.contracts = contracts::load(
                    cx.root,
                    &app.path,
                    &format!("apps.{id}."),
                    std::slice::from_ref(&qa_dir),
                    |field| {
                        a.get(&format!("apps.{id}.{field}"))
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    },
                    &mut derived,
                )?;
                compat_by(cx, &app.path, &format!("apps.{id}."), &target.contracts)?;
                apps.insert(id.clone(), target);
            }
        }
        let targets: Vec<(String, &AppQa)> = std::iter::once((String::new(), &root))
            .chain(apps.iter().map(|(id, app)| (format!("apps.{id}."), app)))
            .collect();
        check_seeded_web_dirs(cx.root, &targets, &mut derived)?;
        // The root's walk skips every listed app: an app's contract is its own job's.
        let skip: Vec<String> = std::iter::once(qa_dir.clone())
            .chain(apps.values().map(|app: &AppQa| app.path.clone()))
            .collect();
        let contracts = contracts::load(
            cx.root,
            ".",
            "",
            &skip,
            |id| a.get(id).and_then(Value::as_str).map(str::to_owned),
            &mut derived,
        )?;
        compat_by(cx, ".", "", &contracts)?;
        Ok(Self {
            qa_dir,
            api: root.api,
            api_start: root.api_start,
            api_url: root.api_url,
            api_ready_path: root.api_ready_path,
            api_ready_timeout: root.api_ready_timeout,
            web: root.web,
            web_start: root.web_start,
            web_url: root.web_url,
            web_command: root.web_command,
            web_dir: root.web_dir,
            apps,
            derived,
            contracts,
        })
    }
}

/// Refuses a `contract_compat_by` command that `required` does not run on
/// every change of the target's contracts (#1182): the declaration is taken at
/// its word only where the aggregate runs it.
fn compat_by(cx: &Context<'_>, path: &str, prefix: &str, c: &contracts::Contracts) -> Result<()> {
    let Some(name) = &c.compat_by else {
        return Ok(());
    };
    let ci = cx.answers_of(CI_BASELINE)?;
    let profile_file = seeds::join(path, crate::PROFILE);
    let profile = if path == "." {
        cx.profile.value.clone()
    } else {
        crate::read(cx.root, &profile_file)?
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or(Value::Null)
    };
    contracts::compat_command_runs(name, path, c, ci, &profile, &profile_file).or_else(|reason| {
        refuse(format!(
            "qa: {prefix}contract_compat_by {name} is not a command required runs: {reason}"
        ))
    })
}

/// One target's answers, read through `answer` (which returns the answer id as
/// written and its value), its paths checked under `path`. An unanswered `api`
/// or `web` takes the value `found` derives (`web` also `seeded` when its
/// `web_url` is answered), and pushes its note on `derived`. An unanswered
/// `api_ready_timeout` is `ready_default`.
fn target<'v>(
    root: &Path,
    path: &str,
    qa_dir: &str,
    found: &Derivation,
    ready_default: u32,
    derived: &mut Vec<String>,
    answer: impl Fn(&str) -> (String, Option<&'v Value>),
) -> Result<AppQa> {
    let text = |field: &str| -> Result<(String, Option<String>)> {
        let (key, value) = answer(field);
        let value = value.and_then(Value::as_str).map(str::to_owned);
        if let Some(text) = &value
            && text.contains("${{")
        {
            return refuse(format!(
                "qa: {key} `{text}` contains `${{{{`, which GitHub would evaluate; answers reach the job only through env:, write it without it"
            ));
        }
        Ok((key, value))
    };
    let (api_key, api) = answer("api");
    let (api, api_evidence) = match api.and_then(Value::as_bool) {
        Some(api) => (api, None),
        None => (found.api.is_some(), found.api.clone()),
    };
    let (web_key, web) = answer("web");
    let (web, web_evidence) = match web.and_then(Value::as_str) {
        Some(text) => (
            *Web::ALL
                .iter()
                .find(|w| w.as_str() == text)
                .expect("the engine validated the enum"),
            None,
        ),
        None => match (&found.web_evidence, answer("web_url")) {
            (Some(evidence), _) => (found.web, Some(evidence.clone())),
            (None, (url_key, Some(_))) => (Web::Seeded, Some(format!("{url_key} answered"))),
            (None, (_, None)) => (Web::None, None),
        },
    };
    let api_start = match (text("api_start")?, &api_evidence) {
        ((_, Some(command)), _) if api => Some(command),
        ((key, None), Some(evidence)) => {
            return refuse(format!(
                "qa: {api_key} derived true ({evidence}) but {key} has no value; answer {key}, or {api_key}=false"
            ));
        }
        ((key, None), None) if api => {
            return refuse(format!(
                "qa: {api_key} is true but {key} has no value; the command that starts the API is never invented"
            ));
        }
        _ => None,
    };
    let web_start = match (text("web_start")?, &web_evidence) {
        ((_, Some(command)), _) if web != Web::None => Some(command),
        ((key, None), Some(evidence)) => {
            return refuse(format!(
                "qa: {web_key} derived {} ({evidence}) but {key} has no value; answer {key}, or {web_key}=none",
                web.as_str()
            ));
        }
        ((key, None), None) if web != Web::None => {
            return refuse(format!(
                "qa: {web_key} is {} but {key} has no value; the command that serves the web is never invented",
                web.as_str()
            ));
        }
        _ => None,
    };
    if let Some(evidence) = &api_evidence {
        derived.push(format!("{api_key} derived true: {evidence}"));
    }
    if let Some(evidence) = &web_evidence {
        derived.push(format!("{web_key} derived {}: {evidence}", web.as_str()));
    }
    let api_url = local_url(text("api_url")?, DEFAULT_API_URL)?;
    let web_url = local_url(text("web_url")?, DEFAULT_WEB_URL)?;
    let api_ready_path = match text("api_ready_path")? {
        (_, None) => DEFAULT_API_READY_PATH.to_owned(),
        (key, Some(path)) => {
            if !path.starts_with('/') || path.chars().any(|c| c.is_whitespace() || c.is_control()) {
                return refuse(format!(
                    "qa: {key} `{path}` is not a path starting with / without spaces; it is the request line of 00-ready.hurl"
                ));
            }
            path
        }
    };
    // The schema bounds the answer; an integer is all it can be here.
    let api_ready_timeout = answer("api_ready_timeout")
        .1
        .and_then(Value::as_u64)
        .map_or(ready_default, |s| s as u32);
    let web_command = text("web_command")?
        .1
        .unwrap_or_else(|| DEFAULT_WEB_COMMAND.to_owned());
    let web_dir = match text("web_dir")? {
        (key, Some(dir)) => climbing(&key, path, &dir)?,
        (_, None) if web == Web::Project => ".".to_owned(),
        (_, None) => format!("{qa_dir}/web"),
    };
    // The seeded project is written under `web_dir`: never inside, nor
    // around, a test directory that exists (SPEC-qa.md, Project Structure). A
    // project-owned web only names where the project's own files are.
    if web == Web::Seeded {
        let (key, _) = answer("web_dir");
        let base = root.join(path);
        let mut prefix = base.clone();
        let within = web_dir.split('/').find(|segment| {
            prefix.push(segment);
            TEST_DIRS.contains(segment) && prefix.is_dir()
        });
        let target = base.join(&web_dir);
        let around = || TEST_DIRS.into_iter().find(|t| target.join(t).is_dir());
        if let Some(test) = within.or_else(around) {
            return refuse(format!(
                "qa: {key} {web_dir} is or contains the test directory {test}; the module never writes where a test already is"
            ));
        }
    }
    if web == Web::Project {
        let base = if path == "." {
            root.to_path_buf()
        } else {
            root.join(path)
        };
        if !PLAYWRIGHT_CONFIGS.iter().any(|c| base.join(c).is_file()) {
            let place = if path == "." {
                "the repository root".to_owned()
            } else {
                path.to_owned()
            };
            return refuse(format!(
                "qa: {web_key} is project but no playwright.config.ts, playwright.config.js or playwright.config.mjs is at {place}; answer {web_key}=seeded or add the project's config"
            ));
        }
    }
    Ok(AppQa {
        contracts: contracts::Contracts::default(),
        path: path.to_owned(),
        api,
        api_start,
        api_url,
        api_ready_path,
        api_ready_timeout,
        web,
        web_start,
        web_url,
        web_command,
        web_dir,
    })
}

/// `api_ready_timeout` when unanswered (#1243): one measurement of the suite
/// (`ci-baseline`'s unit, #1213) when the profile declares a budget, within
/// [`API_READY_TIMEOUT_MAX`]; else [`DEFAULT_API_READY_TIMEOUT`].
fn ready_timeout_default(cx: &Context<'_>) -> u32 {
    measurement_minutes(cx).map_or(DEFAULT_API_READY_TIMEOUT, |m| {
        m.saturating_mul(60).min(API_READY_TIMEOUT_MAX)
    })
}

/// `ci-baseline`'s note for each `qa-api` whose unanswered readiness wait, one
/// measurement of the declared budget, puts the job above GitHub's maximum
/// (#1228): the wait renders [`API_READY_TIMEOUT_MAX`], the job 360 minutes.
fn budget_note(cx: &Context<'_>, answers: &QaAnswers) -> Option<String> {
    let measurement = measurement_minutes(cx)?;
    let root = answers.root_target();
    let over: Vec<(String, u32)> = std::iter::once((None, "api_ready_timeout".to_owned(), &root))
        .chain(answers.apps.iter().map(|(id, app)| {
            (
                Some(id.as_str()),
                format!("apps.{id}.api_ready_timeout"),
                app,
            )
        }))
        .filter(|(_, key, target)| target.api && !cx.answers.contains_key(key))
        .map(|(app, _, _)| {
            let uncapped = api_job_minutes(measurement.saturating_mul(60));
            (jobs::job_id(app, "api"), uncapped)
        })
        .collect();
    over_job_max_note(cx, &over)
}

/// `qa-api`'s uncapped `timeout-minutes` for a readiness wait of `seconds`:
/// fifteen, or the wait in whole minutes plus [`READY_SLACK_MINUTES`] when
/// that is more.
pub fn api_job_minutes(seconds: u32) -> u32 {
    seconds
        .div_ceil(60)
        .saturating_add(READY_SLACK_MINUTES)
        .max(15)
}

/// `qa_dir` validated as `heldout_dir` is, and never a test directory nor one
/// that holds a test directory: by name, or on disk at plan time.
fn qa_dir(root: &Path, dir: &str) -> Result<String> {
    let normalised = relative("qa_dir", dir)?;
    if let Some(test) = normalised.split('/').find(|s| TEST_DIRS.contains(s)) {
        return refuse_test_dir(&normalised, test);
    }
    refuse_tests_inside(root, &normalised)?;
    Ok(normalised)
}

/// Refuses when `<base>/<qa_dir>` holds a test directory on disk; `base` is
/// the repository root, or an app directory in monorepo mode.
fn refuse_tests_inside(base: &Path, qa_dir: &str) -> Result<()> {
    match TEST_DIRS
        .into_iter()
        .find(|t| base.join(qa_dir).join(t).is_dir())
    {
        Some(test) => refuse_test_dir(qa_dir, test),
        None => Ok(()),
    }
}

fn refuse_test_dir<T>(qa_dir: &str, test: &str) -> Result<T> {
    refuse(format!(
        "qa: qa_dir {qa_dir} is or contains the test directory {test}; the module never writes where a test already is"
    ))
}

/// A relative path inside the repository (`ci-baseline`'s `heldout_dir` rule);
/// `.` is the directory itself.
fn relative(key: &str, dir: &str) -> Result<String> {
    if dir == "." {
        return Ok(dir.to_owned());
    }
    heldout_dir(dir).or_else(|_| {
        refuse(format!(
            "qa: {key} {dir} is not a relative path inside the repository"
        ))
    })
}

/// A `web_dir` answer relative to the target at `path`: as [`relative`], plus
/// leading `..` segments that climb out of an app while the path stays inside
/// the repository (#1211: seeds inside a TypeScript app reach its type check).
/// Normalised to `../`… then the rest, or `..`… when nothing follows.
fn climbing(key: &str, path: &str, dir: &str) -> Result<String> {
    let outside = || {
        refuse(format!(
            "qa: {key} {dir} is not a relative path inside the repository"
        ))
    };
    let trimmed = dir.strip_prefix("./").unwrap_or(dir);
    let trimmed = trimmed.strip_suffix('/').unwrap_or(trimmed);
    let mut rest = trimmed;
    let mut up = 0;
    while let Some(after) = rest.strip_prefix("../") {
        up += 1;
        rest = after;
    }
    if rest == ".." {
        up += 1;
        rest = "";
    }
    if up == 0 {
        return relative(key, dir);
    }
    let depth = if path == "." {
        0
    } else {
        path.split('/').count()
    };
    if up > depth {
        return outside();
    }
    let climb = vec![".."; up].join("/");
    match rest {
        "" => Ok(climb),
        rest => match relative(key, rest) {
            Ok(rest) if rest != "." => Ok(format!("{climb}/{rest}")),
            _ => outside(),
        },
    }
}

/// Refuses two targets whose seeded web directories are one path, and notes
/// each seeded web directory with a `tsconfig.json` above it, the nearest
/// named (#1211): the project's type check may compile the seeds without
/// `@playwright/test`, which only the web directory installs.
fn check_seeded_web_dirs(
    root: &Path,
    targets: &[(String, &AppQa)],
    derived: &mut Vec<String>,
) -> Result<()> {
    let mut seen: Vec<(String, String)> = Vec::new();
    for (prefix, target) in targets {
        if target.web != Web::Seeded {
            continue;
        }
        let key = format!("{prefix}web_dir");
        let dir = seeds::join(&target.path, &target.web_dir);
        if let Some((other, _)) = seen.iter().find(|(_, d)| *d == dir) {
            return refuse(format!(
                "qa: {other} and {key} both seed {dir}; give each target its own web directory"
            ));
        }
        // The directories above `dir`, nearest first, up to the repository root.
        let segments: Vec<&str> = dir.split('/').filter(|s| *s != ".").collect();
        let config = (0..segments.len())
            .rev()
            .map(|n| seeds::join(&segments[..n].join("/"), "tsconfig.json"))
            .find(|config| root.join(config).is_file());
        if let Some(config) = config {
            derived.push(format!(
                "{key} {dir} lies under {config}, which may type-check the Playwright seeds; exclude {dir} there or answer {key} outside it"
            ));
        }
        seen.push((key, dir));
    }
    Ok(())
}

/// The answered URL, or `default`, when it is `http://127.0.0.1:<port>` or
/// `http://localhost:<port>` and nothing else: the pull-request job tests the
/// checkout, never a deployment.
fn local_url((key, value): (String, Option<String>), default: &str) -> Result<String> {
    let Some(url) = value else {
        return Ok(default.to_owned());
    };
    let port = url
        .strip_prefix("http://127.0.0.1:")
        .or_else(|| url.strip_prefix("http://localhost:"));
    let valid = port.is_some_and(|port| {
        !port.is_empty()
            && port.len() <= 5
            && port.chars().all(|c| c.is_ascii_digit())
            && port.parse::<u32>().is_ok_and(|n| (1..=65535).contains(&n))
    });
    if !valid {
        return refuse(format!(
            "qa: {key} {url} is not http://127.0.0.1:<port> or http://localhost:<port>; the pull-request job tests the checkout, never a deployment"
        ));
    }
    Ok(url)
}

impl Module for Qa {
    fn id(&self) -> &'static str {
        QA
    }
    fn version(&self) -> &'static str {
        QA_VERSION
    }
    /// The jobs join the workflow through `ci-baseline`'s `ci_jobs`; the jobs
    /// reuse each app's `ci_setup` from `stack-packs` (`Context::answers_of`).
    fn requires(&self) -> &'static [&'static str] {
        &[CI_BASELINE, STACK_PACKS]
    }
    fn questions(&self) -> Schema {
        schema()
    }
    /// The seeds of every target, the managed guide, then the `never-touch`
    /// listing. It loads the answers, so every rule refuses at `configure` and
    /// `install`.
    fn render(&self, cx: &Context<'_>) -> Result<Vec<Rendered>> {
        let answers = QaAnswers::load(cx)?;
        // `ci_jobs` cannot refuse; rendering the jobs here makes any reason they
        // would fail (a missing pin, an invalid stack-packs record) refuse the plan.
        jobs::contributed(cx)?;
        let pins = stack_packs::PinTable::embedded()?;
        let mut rendered = seeds::seeds(&answers, &pins)?;
        rendered.push(seeds::guide(&pins)?);
        let listed = seeds::never_touch(cx.root, &answers, &rendered);
        rendered.extend(listed);
        Ok(rendered)
    }
    /// `qa-api` when the root target has an API and `qa-web` when it has a web
    /// application (SPEC-qa.md, Contributed CI jobs); `ci-baseline` inserts
    /// them and adds them to `required`'s `needs`.
    fn ci_jobs(&self, cx: &Context<'_>) -> Vec<crate::engine::CiJob> {
        jobs::contributed(cx).unwrap_or_default()
    }
    /// Each unanswered `api` or `web` with the value derived and its evidence
    /// (`api derived true: Dockerfile`); an answered one prints nothing.
    fn notes(&self, cx: &Context<'_>) -> Result<Vec<String>> {
        let answers = QaAnswers::load(cx)?;
        let mut notes = answers.derived.clone();
        notes.extend(budget_note(cx, &answers));
        Ok(notes)
    }
    /// `qa-web-lockfile` and `qa-web-baseline` for `web: seeded`,
    /// `qa-api-reported` when `api` (`manual`). Empty only when `render`
    /// refuses in the same plan.
    fn manual_steps(&self, cx: &Context<'_>) -> Vec<ManualStep> {
        QaAnswers::load(cx)
            .and_then(|answers| {
                manual::steps(cx.root, &answers, &stack_packs::PinTable::embedded()?)
            })
            .unwrap_or_default()
    }
}
