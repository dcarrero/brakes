//! The three uses of a `.hurl` file (`SPEC-qa.md`, Objective; Slices, 3; T18,
//! #1017): the pull-request test (`qa-api`), `delivery`'s post-deploy smoke and
//! `observability`'s uptime probe run the same files with the same flags, each
//! with its own `base_url`. [`files`] says where a repository's files are, one
//! entry per target with an API; [`hurl_command`] renders the two commands
//! every user runs. A file never names a host, so the base URL is always a
//! variable the user sets.
use super::{QA, Qa, QaAnswers, seeds};
use crate::{Result, engine::Context, refuse};

/// Where one target's `.hurl` files are, relative to the repository root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QaFiles {
    /// The listed app (monorepo mode); `None` for the root target.
    pub app: Option<String>,
    /// The target's `qa_dir`, under the app's directory for an app.
    pub dir: String,
    /// The readiness request, the only file a runner retries.
    pub ready: String,
    /// Every request file, readiness included.
    pub glob: String,
    /// Seconds the readiness request is retried: the target's
    /// `api_ready_timeout` (#1243).
    pub ready_timeout: u32,
}

impl QaFiles {
    /// The files of the target at `path` (`.` for the root) with `qa_dir`,
    /// whose readiness is retried for `ready_timeout` seconds.
    pub fn of(app: Option<String>, path: &str, qa_dir: &str, ready_timeout: u32) -> Self {
        let dir = seeds::join(path, qa_dir);
        Self {
            app,
            ready: seeds::join(&dir, seeds::READY_HURL),
            glob: seeds::join(&dir, "api/**/*.hurl"),
            dir,
            ready_timeout,
        }
    }
}

/// The commands of one use: `env` to set (the files' directory as `QA_DIR`),
/// then `ready` (Hurl's own retry on the readiness file, once a second for
/// [`QaFiles::ready_timeout`] seconds) and `run` (every file
/// once, with a JUnit report under `$RUNNER_TEMP/qa`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HurlCommand {
    pub env: Vec<(String, String)>,
    pub ready: String,
    pub run: String,
}

/// The variable the commands read the files' directory from.
pub const DIR_VAR: &str = "QA_DIR";

/// The `.hurl` files of every target with an API, the root first and then
/// each listed app in app id order. `cx` is the reader's context; qa's
/// answers are loaded as `qa` itself loads them (T4's derivation included).
/// Refuses when qa is not active in the plan, or no target has an API.
pub fn files(cx: &Context<'_>) -> Result<Vec<QaFiles>> {
    let Some(answers) = cx.answers_if_active(QA) else {
        return refuse(
            "qa is not active in this plan; install it with --module qa before reading its .hurl files",
        );
    };
    let qa = QaAnswers::load(&Context {
        answers,
        module: &Qa,
        ..*cx
    })?;
    let root = qa.root_target();
    let targets = std::iter::once((None, &root))
        .chain(qa.apps.iter().map(|(id, app)| (Some(id.clone()), app)));
    let found: Vec<QaFiles> = targets
        .filter(|(_, target)| target.api)
        .map(|(app, target)| QaFiles::of(app, &target.path, &qa.qa_dir, target.api_ready_timeout))
        .collect();
    if found.is_empty() {
        return refuse("qa: no target has api: true, so there are no .hurl files to run");
    }
    Ok(found)
}

/// The commands every use of `files` runs, reading the base URL from the
/// environment variable `base_url_var` and the files through [`DIR_VAR`].
pub fn hurl_command(files: &QaFiles, base_url_var: &str) -> Result<HurlCommand> {
    let name = !base_url_var.is_empty()
        && base_url_var
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        && !base_url_var.starts_with(|c: char| c.is_ascii_digit());
    if !name {
        return refuse(format!(
            "qa: hurl_command needs an environment variable name for base_url, got {base_url_var}"
        ));
    }
    let under_dir = |path: &str| {
        let rest = path.strip_prefix(&files.dir).unwrap_or(path);
        format!("\"${DIR_VAR}{rest}\"")
    };
    let base_url = format!("--variable base_url=\"${base_url_var}\"");
    Ok(HurlCommand {
        env: vec![(DIR_VAR.to_owned(), files.dir.clone())],
        ready: format!(
            "hurl --test --jobs 1 --retry {} --retry-interval 1000 --max-time 20 {base_url} {}",
            files.ready_timeout,
            under_dir(&files.ready)
        ),
        run: format!(
            "hurl --test --max-time 20 {base_url} --report-junit \"$RUNNER_TEMP/qa/hurl-junit.xml\" --glob {}",
            under_dir(&files.glob)
        ),
    })
}
