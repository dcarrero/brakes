//! qa T3 (#1000): the `Module` impl — question schema, `QaAnswers::load` with
//! every refusal of the spec, registration after `security` and before
//! `ci-baseline`, and `requires`. T4 (#1001): the derived `api` and `web`.
//! T5 (#1002): the seeds, the managed guide, the `never-touch` listing and
//! `literal_host`. Everything runs through the binary on a real git checkout
//! with the real `stack-packs` and `ci-baseline`; every `install`, `configure`
//! and `remove` is guarded by `Repo::cli`, which asserts the project's tests and
//! pre-existing `.hurl` files are byte-identical afterwards.
mod support;
use brakes::engine::Module;
use brakes::engine::answers::{self, AnswersFile};
use brakes::modules::{self, qa::QA, qa::Qa};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::TempDir;

struct Repo {
    _temp: TempDir,
    root: PathBuf,
}

const REQUIREMENTS: [&str; 2] = ["stack-packs", "ci-baseline"];

impl Repo {
    /// A personal rust repository with two stack-packs apps (`root` at `.` and
    /// `api` at `api/`), the project's tests and a pre-existing `.hurl` file.
    fn new() -> Self {
        let repo = Self::single();
        repo.write("api/Cargo.toml", "");
        repo.write("api/Cargo.lock", "");
        // Two apps make a monorepo: ci-baseline reads each app's own profile (Decision 8).
        repo.write(
            "api/.agent-setup/project.json",
            r#"{"commands": {"test": "cargo test --locked"}}"#,
        );
        repo.answer(
            "stack-packs",
            json!({"apps.root.path": ".", "apps.root.stack": "rust", "apps.root.container": false,
                   "apps.api.path": "api", "apps.api.stack": "rust", "apps.api.container": false}),
        );
        repo
    }
    /// The same repository whose root profile declares no command: in a
    /// monorepo without an app at `.` a root command runs in ci-baseline's
    /// root `checks` job (#1165), which these fixtures do not exercise.
    fn without_root_commands(self) -> Self {
        let path = ".agent-setup/project.json";
        let mut profile: Value = serde_json::from_str(&self.read(path)).unwrap();
        profile["commands"]["test"] = Value::Null;
        self.write(
            path,
            &(serde_json::to_string_pretty(&profile).unwrap() + "\n"),
        );
        self
    }
    /// The same repository with one stack-packs app, `root` at `.`.
    fn single() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("project");
        fs::create_dir(&root).unwrap();
        let status = Command::new("git")
            .args(["init", "-q"])
            .arg(&root)
            .status()
            .unwrap();
        assert!(status.success());
        let repo = Self { _temp: temp, root };
        repo.ok(&["install", "<repo>", "--new-personal", "--apply"]);
        let path = ".agent-setup/project.json";
        let mut profile: Value = serde_json::from_str(&repo.read(path)).unwrap();
        profile["commands"]["test"] = "cargo test --locked".into();
        repo.write(
            path,
            &(serde_json::to_string_pretty(&profile).unwrap() + "\n"),
        );
        repo.write("Cargo.toml", "");
        repo.write("Cargo.lock", "");
        repo.answer(
            "stack-packs",
            json!({"apps.root.path": ".", "apps.root.stack": "rust", "apps.root.container": false}),
        );
        // The project's own tests: what the module must never write or change.
        repo.write("tests/integration.rs", "#[test]\nfn it_works() {}\n");
        repo.write("e2e/login.spec.ts", "// the project's journey\n");
        repo.write("checks/legacy.hurl", "GET https://example.com/\nHTTP 200\n");
        repo
    }
    /// Every file under a test directory (`tests`, `test`, `e2e`, `spec`, at
    /// any depth) and every `.hurl` file, with whether it is under a test
    /// directory and its bytes; `.git` is skipped.
    fn tests_snapshot(&self) -> BTreeMap<String, (bool, Vec<u8>)> {
        fn walk(
            root: &Path,
            dir: &Path,
            inside: bool,
            out: &mut BTreeMap<String, (bool, Vec<u8>)>,
        ) {
            let Ok(entries) = fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().into_owned();
                if path.is_dir() {
                    if name != ".git" {
                        let test = ["tests", "test", "e2e", "spec"].contains(&name.as_str());
                        walk(root, &path, inside || test, out);
                    }
                } else if inside || name.ends_with(".hurl") {
                    let relative = path.strip_prefix(root).unwrap().to_string_lossy();
                    out.insert(relative.into_owned(), (inside, fs::read(&path).unwrap()));
                }
            }
        }
        let mut out = BTreeMap::new();
        walk(&self.root, &self.root, false, &mut out);
        out
    }
    fn write(&self, path: &str, text: &str) {
        let full = self.root.join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, text).unwrap();
    }
    fn read(&self, path: &str) -> String {
        fs::read_to_string(self.root.join(path)).unwrap()
    }
    fn answer(&self, module: &str, raw: Value) {
        let file = AnswersFile {
            module: module.to_owned(),
            version: "1.0.0".to_owned(),
            profile: None,
            answers: serde_json::from_value(raw).unwrap(),
        };
        self.write(&answers::path(module), &file.to_json_string().unwrap());
    }
    /// The binary on this repository, `<repo>` replaced by its path. Every
    /// file of `tests_snapshot` before the command is byte-identical after it,
    /// and no new file appears under a test directory.
    fn cli(&self, args: &[&str]) -> std::process::Output {
        let before = self.tests_snapshot();
        let root = self.root.to_string_lossy().into_owned();
        let out = Command::new(env!("CARGO_BIN_EXE_brakes"))
            .args(
                args.iter()
                    .map(|a| if *a == "<repo>" { root.as_str() } else { a }),
            )
            .output()
            .unwrap();
        let after = self.tests_snapshot();
        for (path, bytes) in &before {
            assert_eq!(after.get(path), Some(bytes), "{args:?} changed {path}");
        }
        // A test directory that existed before: every file under it is the project's.
        let dirs: Vec<String> = before
            .iter()
            .filter(|(_, (inside, _))| *inside)
            .filter_map(|(path, _)| {
                let segments: Vec<&str> = path.split('/').collect();
                let at = segments
                    .iter()
                    .position(|s| ["tests", "test", "e2e", "spec"].contains(s))?;
                Some(segments[..=at].join("/") + "/")
            })
            .collect();
        let created: Vec<&String> = after
            .keys()
            .filter(|p| !before.contains_key(*p) && dirs.iter().any(|d| p.starts_with(d)))
            .collect();
        assert!(
            created.is_empty(),
            "{args:?} wrote under a test directory: {created:?}"
        );
        out
    }
    fn ok(&self, args: &[&str]) -> String {
        let out = self.cli(args);
        assert!(out.status.success(), "{args:?}: {out:?}");
        String::from_utf8(out.stdout).unwrap()
    }
    /// `install --module` for the requirements and `qa`, plus `extra`.
    fn install(&self, extra: &[&str]) -> String {
        let mut args = vec!["install", "<repo>"];
        for id in REQUIREMENTS.iter().chain([&QA]) {
            args.extend(["--module", id]);
        }
        args.extend(extra);
        self.ok(&args)
    }
    /// The REFUSED line of `install --module …qa` with these recorded answers.
    fn refusal(&self, answers: Value) -> String {
        self.answer(QA, answers);
        let mut args = vec!["install", "<repo>"];
        for id in REQUIREMENTS.iter().chain([&QA]) {
            args.extend(["--module", id]);
        }
        let out = self.cli(&args);
        assert!(!out.status.success(), "{out:?}");
        String::from_utf8_lossy(&out.stderr).trim().to_owned()
    }
}

// ---- the module -------------------------------------------------------------------

#[test]
fn module_is_registered_after_security_and_before_ci_baseline() {
    assert_eq!(Qa.id(), "qa");
    assert_eq!(Qa.version(), "1.0.0");
    assert_eq!(Qa.requires(), ["ci-baseline", "stack-packs"]);
    assert_eq!(modules::find("qa").map(|m| m.version()), Some("1.0.0"));
    let ids: Vec<&str> = modules::all().iter().map(|m| m.id()).collect();
    assert_eq!(
        ids,
        crate::support::with_core(&[
            "stack-packs",
            "merge-guard",
            "repo-baseline",
            "agent-guardrails",
            "security",
            "qa",
            "ci-baseline"
        ])
    );
}

#[test]
fn schema_declares_the_spec_table_and_the_per_app_patterns() {
    let schema = Qa.questions();
    let ids: Vec<&str> = schema.questions.iter().map(|q| q.id.as_str()).collect();
    let fields = [
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
    ];
    let mut expected = vec!["qa_dir"];
    expected.extend(fields);
    // T17 (#1016): the contract answers, root target only until T13.
    // #1182: published copies and a declared compatibility command.
    let contract_fields = [
        "openapi",
        "asyncapi",
        "contract_ruleset",
        "contract_published",
        "contract_compat_by",
    ];
    expected.extend(contract_fields);
    expected.push("apps");
    // #1115: the contract answers per app too.
    let patterns: Vec<String> = fields
        .iter()
        .chain(&contract_fields)
        .map(|f| format!("apps.*.{f}"))
        .collect();
    expected.extend(patterns.iter().map(String::as_str));
    assert_eq!(ids, expected);
    schema.check(QA).unwrap();
    // The derived answers carry no schema default: `configure` would record it
    // and the derivation (T4) could never apply.
    for id in ["api", "web", "openapi", "asyncapi", "contract_ruleset"] {
        assert_eq!(schema.question(id).unwrap().default, None, "{id}");
    }
    assert_eq!(
        schema.question("qa_dir").unwrap().default,
        Some(json!("qa"))
    );
    assert!(schema.question("apps.backend.api_start").is_some());
}

#[test]
fn without_api_or_web_only_the_guide_and_the_never_touch_listing_are_recorded() {
    let repo = Repo::new();
    repo.install(&["--apply"]);
    let lock: Value = serde_json::from_str(&repo.read(".agent-setup/lock.json")).unwrap();
    assert_eq!(lock["modules"][QA]["version"], "1.0.0", "{lock:#}");
    let qa_paths: Vec<(String, String)> = lock["files"]
        .as_object()
        .unwrap()
        .iter()
        .filter(|(_, entry)| entry["module"] == QA)
        .map(|(path, entry)| (path.clone(), entry["class"].as_str().unwrap().to_owned()))
        .collect();
    let expected: Vec<(String, String)> = [
        ("checks/legacy.hurl", "never-touch"),
        ("docs/agent-setup/qa.md", "managed"),
        ("e2e/**", "never-touch"),
        ("tests/**", "never-touch"),
    ]
    .iter()
    .map(|(p, c)| ((*p).to_owned(), (*c).to_owned()))
    .collect();
    assert_eq!(qa_paths, expected, "{lock:#}");
    let again = repo.ok(&["install", "<repo>"]);
    assert!(again.lines().any(|l| l == "No changes."), "{again}");
}

#[test]
fn install_module_qa_without_ci_baseline_refuses_naming_the_dependency() {
    let repo = Repo::new();
    let out = repo.cli(&["install", "<repo>", "--module", QA]);
    assert!(!out.status.success(), "{out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stderr).trim(),
        "REFUSED: Module qa requires module ci-baseline, which is not installed; add it with --module ci-baseline"
    );
    let out = repo.cli(&[
        "install",
        "<repo>",
        "--module",
        "ci-baseline",
        "--module",
        QA,
    ]);
    assert_eq!(
        String::from_utf8_lossy(&out.stderr).trim(),
        "REFUSED: Module qa requires module stack-packs, which is not installed; add it with --module stack-packs"
    );
    assert!(!repo.root.join(answers::path(QA)).exists());
}

#[test]
fn configure_records_the_answers_file() {
    let repo = Repo::new();
    repo.install(&["--apply"]);
    let start = "cargo run --locked -- --port 8080";
    let api_start = format!("api_start={start}");
    repo.ok(&[
        "configure",
        "<repo>",
        QA,
        "--set",
        "api=true",
        "--set",
        &api_start,
        "--apply",
    ]);
    let file = AnswersFile::parse(QA, &repo.read(&answers::path(QA))).unwrap();
    assert_eq!(file.version, "1.0.0");
    assert_eq!(file.answers["api"], json!(true));
    assert_eq!(file.answers["api_start"], json!(start));
    assert_eq!(file.answers["qa_dir"], json!("qa"));
    let again = repo.ok(&["install", "<repo>"]);
    assert!(again.lines().any(|l| l == "No changes."), "{again}");
}

// ---- refusals ---------------------------------------------------------------------

#[test]
fn api_true_without_api_start_refuses() {
    let repo = Repo::new();
    assert_eq!(
        repo.refusal(json!({"api": true})),
        "REFUSED: qa: api is true but api_start has no value; the command that starts the API is never invented"
    );
}

#[test]
fn web_without_web_start_refuses() {
    let repo = Repo::new();
    assert_eq!(
        repo.refusal(json!({"web": "seeded"})),
        "REFUSED: qa: web is seeded but web_start has no value; the command that serves the web is never invented"
    );
}

#[test]
fn a_remote_url_refuses() {
    let repo = Repo::new();
    assert_eq!(
        repo.refusal(
            json!({"api": true, "api_start": "run", "api_url": "https://staging.example.com"})
        ),
        "REFUSED: qa: api_url https://staging.example.com is not http://127.0.0.1:<port> or http://localhost:<port>; the pull-request job tests the checkout, never a deployment"
    );
    assert_eq!(
        repo.refusal(json!({"web": "seeded", "web_start": "run", "web_url": "http://localhost"})),
        "REFUSED: qa: web_url http://localhost is not http://127.0.0.1:<port> or http://localhost:<port>; the pull-request job tests the checkout, never a deployment"
    );
    assert_eq!(
        repo.refusal(
            json!({"api": true, "api_start": "run", "api_url": "http://127.0.0.1:8080@evil.example"})
        ),
        "REFUSED: qa: api_url http://127.0.0.1:8080@evil.example is not http://127.0.0.1:<port> or http://localhost:<port>; the pull-request job tests the checkout, never a deployment"
    );
}

#[test]
fn a_local_url_without_a_valid_port_refuses() {
    let repo = Repo::new();
    for url in [
        "http://localhost:",
        "http://localhost:80ab",
        "http://127.0.0.1:0",
        "http://127.0.0.1:65536",
    ] {
        assert_eq!(
            repo.refusal(json!({"api": true, "api_start": "run", "api_url": url})),
            format!(
                "REFUSED: qa: api_url {url} is not http://127.0.0.1:<port> or http://localhost:<port>; the pull-request job tests the checkout, never a deployment"
            )
        );
    }
}

#[test]
fn a_local_url_with_a_port_is_accepted() {
    let repo = Repo::new();
    repo.answer(
        QA,
        json!({"api": true, "api_start": "run", "api_url": "http://localhost:9000",
               "web": "seeded", "web_start": "run", "web_url": "http://127.0.0.1:3000"}),
    );
    repo.install(&["--apply"]);
}

#[test]
fn an_expression_in_an_answer_refuses() {
    let repo = Repo::new();
    assert_eq!(
        repo.refusal(json!({"api": true, "api_start": "run --token ${{ secrets.T }}"})),
        "REFUSED: qa: api_start `run --token ${{ secrets.T }}` contains `${{`, which GitHub would evaluate; answers reach the job only through env:, write it without it"
    );
    assert_eq!(
        repo.refusal(json!({"web": "seeded", "web_start": "${{ github.head_ref }}"})),
        "REFUSED: qa: web_start `${{ github.head_ref }}` contains `${{`, which GitHub would evaluate; answers reach the job only through env:, write it without it"
    );
}

#[test]
fn qa_dir_refuses_test_directories_and_paths_outside_the_repository() {
    let repo = Repo::new();
    for (dir, test) in [
        ("tests", "tests"),
        ("tests/qa", "tests"),
        ("qa/e2e", "e2e"),
        ("spec", "spec"),
        ("src/test", "test"),
    ] {
        assert_eq!(
            repo.refusal(json!({"qa_dir": dir})),
            format!(
                "REFUSED: qa: qa_dir {dir} is or contains the test directory {test}; the module never writes where a test already is"
            )
        );
    }
    repo.write("checks/e2e/login.spec.ts", "");
    assert_eq!(
        repo.refusal(json!({"qa_dir": "checks"})),
        "REFUSED: qa: qa_dir checks is or contains the test directory e2e; the module never writes where a test already is"
    );
    repo.write("api/qa/test/smoke.hurl", "");
    assert_eq!(
        repo.refusal(json!({"apps": ["api"]})),
        "REFUSED: qa: qa_dir qa is or contains the test directory test; the module never writes where a test already is"
    );
    assert_eq!(
        repo.refusal(json!({"qa_dir": "../qa"})),
        "REFUSED: qa: qa_dir ../qa is not a relative path inside the repository"
    );
}

#[test]
fn web_project_without_a_root_playwright_config_refuses() {
    let repo = Repo::new();
    assert_eq!(
        repo.refusal(json!({"web": "project", "web_start": "npm run dev"})),
        "REFUSED: qa: web is project but no playwright.config.ts, playwright.config.js or playwright.config.mjs is at the repository root; answer web=seeded or add the project's config"
    );
    repo.write("playwright.config.mjs", "export default {};\n");
    repo.answer(QA, json!({"web": "project", "web_start": "npm run dev"}));
    repo.install(&["--apply"]);
}

#[test]
fn a_per_app_answer_refuses_like_the_root_one() {
    let repo = Repo::new();
    assert_eq!(
        repo.refusal(json!({"apps": ["api"], "apps.api.api": true})),
        "REFUSED: qa: apps.api.api is true but apps.api.api_start has no value; the command that starts the API is never invented"
    );
    assert_eq!(
        repo.refusal(
            json!({"apps": ["api"], "apps.api.api": true, "apps.api.api_start": "run",
                            "apps.api.api_url": "http://10.0.0.1:80"})
        ),
        "REFUSED: qa: apps.api.api_url http://10.0.0.1:80 is not http://127.0.0.1:<port> or http://localhost:<port>; the pull-request job tests the checkout, never a deployment"
    );
    assert_eq!(
        repo.refusal(
            json!({"apps": ["api"], "apps.api.web": "project", "apps.api.web_start": "run"})
        ),
        "REFUSED: qa: apps.api.web is project but no playwright.config.ts, playwright.config.js or playwright.config.mjs is at api; answer apps.api.web=seeded or add the project's config"
    );
}

#[test]
fn apps_name_stack_packs_apps_and_per_app_keys_need_their_app_listed() {
    let repo = Repo::new();
    assert_eq!(
        repo.refusal(json!({"apps": ["web"]})),
        "REFUSED: qa: apps lists web, which is not an app of stack-packs; record it there first"
    );
    assert_eq!(
        repo.refusal(json!({"apps.api.api": true})),
        "REFUSED: qa: apps.api.api answers app api, which apps does not list; add it to apps"
    );
}

// ---- resolved answers -------------------------------------------------------------

mod resolved {
    use brakes::engine::answers::Answers;
    use brakes::engine::{Context, Module};
    use brakes::modules::qa::{Qa, QaAnswers, Web};
    use brakes::{Source, engine::lock::Lock, profile_for};
    use serde_json::{Value, json};
    use std::collections::BTreeMap;

    /// `QaAnswers::load` over `raw`, validated by the schema as the engine does,
    /// with stack-packs resolved to one root rust app.
    pub(super) fn load(raw: Value) -> QaAnswers {
        let repo = super::Repo::new();
        repo.write("playwright.config.ts", "export default {};\n");
        let profile = profile_for(&repo.root).unwrap();
        let source = Source::embedded();
        let lock = Lock {
            schema: brakes::engine::lock::SCHEMA,
            version: "0.1.0".to_owned(),
            source_commit: None,
            source_dirty: false,
            personal_owner: brakes::config::current_owner(),
            modules: BTreeMap::new(),
            files: BTreeMap::new(),
        };
        let raw: Answers = serde_json::from_value(raw).unwrap();
        let answers = Qa.questions().validate("qa", &raw, "P1").unwrap();
        let mut resolved = BTreeMap::new();
        resolved.insert(
            "stack-packs".to_owned(),
            serde_json::from_value::<Answers>(
                json!({"apps.root.path": ".", "apps.root.stack": "rust",
                "apps.root.container": false}),
            )
            .unwrap(),
        );
        resolved.insert("ci-baseline".to_owned(), Answers::new());
        let cx = Context::new(
            &repo.root, &profile, &source, &lock, &answers, &Qa, &resolved,
        );
        QaAnswers::load(&cx).unwrap()
    }

    /// A module that reads qa's files, as `delivery` or `observability` will.
    struct Consumer;
    impl Module for Consumer {
        fn id(&self) -> &'static str {
            "consumer"
        }
        fn version(&self) -> &'static str {
            "1.0.0"
        }
        fn render(&self, _: &Context<'_>) -> brakes::Result<Vec<brakes::engine::Rendered>> {
            Ok(Vec::new())
        }
    }

    /// Runs `f` with a consumer's context in which qa is active with `raw`
    /// (validated) unless `inactive` names it, stack-packs records `packs`.
    fn with_cx(raw: Value, inactive: &[&str], packs: Value, f: impl FnOnce(&Context<'_>)) {
        let repo = super::Repo::new();
        let profile = profile_for(&repo.root).unwrap();
        let source = Source::embedded();
        let lock = Lock {
            schema: brakes::engine::lock::SCHEMA,
            version: "0.1.0".to_owned(),
            source_commit: None,
            source_dirty: false,
            personal_owner: brakes::config::current_owner(),
            modules: BTreeMap::new(),
            files: BTreeMap::new(),
        };
        let raw: Answers = serde_json::from_value(raw).unwrap();
        let qa = Qa.questions().validate("qa", &raw, "P1").unwrap();
        let mut resolved = BTreeMap::new();
        resolved.insert(
            "stack-packs".to_owned(),
            serde_json::from_value::<Answers>(packs).unwrap(),
        );
        resolved.insert("ci-baseline".to_owned(), Answers::new());
        if !inactive.contains(&"qa") {
            resolved.insert("qa".to_owned(), qa);
        }
        let own = Answers::new();
        let cx = Context::new(
            &repo.root, &profile, &source, &lock, &own, &Consumer, &resolved,
        );
        f(&cx)
    }

    /// `with_cx` with stack-packs recording one root rust app.
    pub(super) fn load_cx(raw: Value, inactive: &[&str], f: impl FnOnce(&Context<'_>)) {
        with_cx(
            raw,
            inactive,
            json!({"apps.root.path": ".", "apps.root.stack": "rust", "apps.root.container": false}),
            f,
        )
    }

    /// `with_cx` with stack-packs recording the root app and `api` at `api/`.
    pub(super) fn load_cx_with_api_app(raw: Value, f: impl FnOnce(&Context<'_>)) {
        with_cx(
            raw,
            &[],
            json!({"apps.root.path": ".", "apps.root.stack": "rust", "apps.root.container": false,
                   "apps.api.path": "api", "apps.api.stack": "rust", "apps.api.container": false}),
            f,
        )
    }

    #[test]
    fn unanswered_is_no_api_and_no_web_with_the_spec_defaults() {
        let answers = load(json!({}));
        assert_eq!(answers.qa_dir, "qa");
        assert!(!answers.api);
        assert_eq!(answers.web, Web::None);
        assert_eq!(answers.api_start, None);
        assert_eq!(answers.web_start, None);
        assert!(answers.apps.is_empty());
    }

    #[test]
    fn defaults_fill_the_api_and_the_seeded_web() {
        let answers = load(
            json!({"qa_dir": "./checks/", "api": true, "api_start": "run",
                                  "web": "seeded", "web_start": "serve"}),
        );
        assert_eq!(answers.qa_dir, "checks");
        assert_eq!(answers.api_start.as_deref(), Some("run"));
        assert_eq!(answers.api_url, "http://127.0.0.1:8080");
        assert_eq!(answers.api_ready_path, "/livez");
        assert_eq!(answers.web, Web::Seeded);
        assert_eq!(answers.web_start.as_deref(), Some("serve"));
        // #1250: a development server may refuse 127.0.0.1 as a cross-origin host.
        assert_eq!(answers.web_url, "http://localhost:3000");
        assert_eq!(answers.web_command, "npx playwright test");
        assert_eq!(answers.web_dir, "checks/web");
    }

    #[test]
    fn a_project_web_lives_at_the_root_and_runs_its_own_command() {
        let answers = load(json!({"web": "project", "web_start": "npm run dev",
                                  "web_command": "npm run e2e", "web_url": "http://localhost:5173"}));
        assert_eq!(answers.web, Web::Project);
        assert_eq!(answers.web_dir, ".");
        assert_eq!(answers.web_command, "npm run e2e");
        assert_eq!(answers.web_url, "http://localhost:5173");
        assert!(!answers.api);
    }
}

// ---- derived api and web (T4, #1001) ----------------------------------------------

mod derive {
    use brakes::modules::qa::Web;
    use brakes::modules::qa::detect::{Derivation, derive};
    use std::path::{Path, PathBuf};

    fn fixtures() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/qa")
    }

    fn of(dir: &str) -> Derivation {
        derive(&fixtures(), dir, false).unwrap()
    }

    #[test]
    fn python_uv_with_fastapi_is_an_api() {
        let found = of("python-uv-fastapi");
        assert_eq!(
            found.api.as_deref(),
            Some("python-uv-fastapi/pyproject.toml names fastapi")
        );
        assert_eq!(found.web, Web::None);
        assert_eq!(found.web_evidence, None);
    }

    #[test]
    fn a_framework_only_in_uv_lock_counts_by_its_normalised_name() {
        assert_eq!(
            of("django-lock").api.as_deref(),
            Some("django-lock/uv.lock names django")
        );
    }

    #[test]
    fn rust_with_axum_is_an_api_and_a_dev_dependency_is_not() {
        assert_eq!(
            of("rust-axum").api.as_deref(),
            Some("rust-axum/Cargo.toml names axum")
        );
        assert_eq!(of("rust-dev-only").api, None);
    }

    #[test]
    fn go_registering_net_http_handlers_is_an_api_and_tests_do_not_count() {
        assert_eq!(
            of("go-nethttp").api.as_deref(),
            Some("go-nethttp/cmd/server/main.go registers net/http handlers")
        );
    }

    #[test]
    fn node_with_express_and_playwright_is_an_api_with_a_project_web() {
        let found = of("node-express-playwright");
        assert_eq!(
            found.api.as_deref(),
            Some("node-express-playwright/package.json names express")
        );
        assert_eq!(found.web, Web::Project);
        assert_eq!(
            found.web_evidence.as_deref(),
            Some(
                "node-express-playwright/package.json names @playwright/test and node-express-playwright/playwright.config.ts exists"
            )
        );
    }

    #[test]
    fn playwright_without_a_config_is_not_a_project_web() {
        let temp = tempfile::tempdir().unwrap();
        let from = fixtures().join("node-express-playwright/package.json");
        std::fs::copy(from, temp.path().join("package.json")).unwrap();
        let found = derive(temp.path(), ".", false).unwrap();
        assert_eq!(found.api.as_deref(), Some("package.json names express"));
        assert_eq!(found.web, Web::None);
    }

    #[test]
    fn node_with_only_react_is_a_seeded_web() {
        let found = of("node-react");
        assert_eq!(found.api, None);
        assert_eq!(found.web, Web::Seeded);
        assert_eq!(
            found.web_evidence.as_deref(),
            Some("node-react/package.json names react")
        );
    }

    #[test]
    fn a_rust_library_without_a_dockerfile_is_neither() {
        let found = of("rust-lib");
        assert_eq!(found.api, None);
        assert_eq!(found.web, Web::None);
    }

    #[test]
    fn a_dockerfile_on_disk_or_seeded_by_stack_packs_is_a_service() {
        assert_eq!(
            derive(&fixtures(), "rust-lib", true)
                .unwrap()
                .api
                .as_deref(),
            Some("rust-lib/Dockerfile, seeded by stack-packs")
        );
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("Dockerfile"), "FROM scratch\n").unwrap();
        assert_eq!(
            derive(temp.path(), ".", false).unwrap().api.as_deref(),
            Some("Dockerfile")
        );
    }
}

#[test]
fn a_derived_api_without_api_start_refuses_naming_the_evidence() {
    let repo = Repo::new();
    repo.write("Cargo.toml", "[dependencies]\naxum = \"0.8\"\n");
    assert_eq!(
        repo.refusal(json!({})),
        "REFUSED: qa: api derived true (Cargo.toml names axum) but api_start has no value; answer api_start, or api=false"
    );
}

#[test]
fn the_plan_notes_a_derived_value_with_its_evidence() {
    let repo = Repo::new();
    repo.write("Cargo.toml", "[dependencies]\naxum = \"0.8\"\n");
    repo.answer(QA, json!({"api_start": "cargo run --locked"}));
    let plan = repo.install(&[]);
    assert!(
        plan.lines()
            .any(|l| l == "NOTE [qa] api derived true: Cargo.toml names axum"),
        "{plan}"
    );
}

#[test]
fn an_explicit_answer_wins_over_the_derivation() {
    let repo = Repo::new();
    repo.write("Cargo.toml", "[dependencies]\naxum = \"0.8\"\n");
    repo.answer(QA, json!({"api": false}));
    let plan = repo.install(&[]);
    assert!(!plan.contains("NOTE [qa]"), "{plan}");
}

#[test]
fn an_answered_web_url_derives_a_seeded_web() {
    let repo = Repo::new();
    assert_eq!(
        repo.refusal(json!({"web_url": "http://127.0.0.1:5173"})),
        "REFUSED: qa: web derived seeded (web_url answered) but web_start has no value; answer web_start, or web=none"
    );
    repo.answer(
        QA,
        json!({"web_url": "http://127.0.0.1:5173", "web_start": "npm run dev"}),
    );
    let plan = repo.install(&[]);
    assert!(
        plan.lines()
            .any(|l| l == "NOTE [qa] web derived seeded: web_url answered"),
        "{plan}"
    );
}

#[test]
fn a_monorepo_derives_per_recorded_app() {
    let repo = Repo::new();
    repo.write("api/Cargo.toml", "[dependencies]\nactix-web = \"4\"\n");
    repo.answer(
        QA,
        json!({"apps": ["api"], "apps.api.api_start": "cargo run --locked"}),
    );
    let plan = repo.install(&[]);
    assert!(
        plan.lines()
            .any(|l| l == "NOTE [qa] apps.api.api derived true: api/Cargo.toml names actix-web"),
        "{plan}"
    );
    assert!(!plan.contains("NOTE [qa] api derived"), "{plan}");
}

// ---- T8 (#1005): the protected screenshot baseline --------------------------------

#[test]
fn install_puts_the_seeded_snapshot_glob_in_the_scope_job() {
    let repo = Repo::new();
    repo.answer(QA, json!({"web": "seeded", "web_start": "npm start"}));
    repo.install(&["--apply"]);
    let workflow = repo.read(".github/workflows/ci.yml");
    assert!(
        workflow.contains("            tests/heldout/**\n            qa/web/*-snapshots/**\n"),
        "{workflow}"
    );
    assert!(repo.install(&[]).contains("No changes."));
}

mod protected {
    use brakes::modules::qa::protected::{codeowners_line, protected_glob, web_dirs};
    use brakes::modules::qa::{AppQa, QaAnswers, Web};
    use serde_json::json;

    /// Loaded answers with no web, then edited per case.
    fn none() -> QaAnswers {
        super::resolved::load(json!({}))
    }

    fn app(path: &str, web: Web, web_dir: &str) -> AppQa {
        let root = none();
        AppQa {
            path: path.to_owned(),
            api: false,
            api_start: None,
            api_url: root.api_url,
            api_ready_path: root.api_ready_path,
            api_ready_timeout: root.api_ready_timeout,
            web,
            web_start: Some("serve".to_owned()),
            web_url: root.web_url,
            web_command: root.web_command,
            web_dir: web_dir.to_owned(),
            contracts: Default::default(),
        }
    }

    #[test]
    fn globs_and_lines_name_the_web_dir_or_every_snapshots_directory_at_the_root() {
        assert_eq!(protected_glob("qa/web"), "qa/web/*-snapshots/**");
        assert_eq!(protected_glob("."), "**/*-snapshots/**");
        assert_eq!(codeowners_line("qa/web", "me"), "/qa/web/ @me");
        assert_eq!(codeowners_line(".", "me"), "**/*-snapshots/ @me");
    }

    #[test]
    fn only_a_target_with_a_web_has_a_directory() {
        assert!(web_dirs(&none()).is_empty());
        let seeded = QaAnswers {
            web: Web::Seeded,
            web_dir: "qa/web".to_owned(),
            ..none()
        };
        assert_eq!(web_dirs(&seeded), ["qa/web"]);
        let project = QaAnswers {
            web: Web::Project,
            web_dir: ".".to_owned(),
            ..none()
        };
        assert_eq!(web_dirs(&project), ["."]);
        // The loaded answers resolve the defaults web_dirs reads.
        let loaded = super::resolved::load(
            json!({"qa_dir": "./checks/", "web": "seeded", "web_start": "serve"}),
        );
        assert_eq!(web_dirs(&loaded), ["checks/web"]);
    }

    #[test]
    fn apps_join_their_path_each_directory_once_after_the_root() {
        let mut qa = QaAnswers {
            web: Web::Project,
            web_dir: ".".to_owned(),
            ..none()
        };
        for (id, path, web, dir) in [
            ("api", "api", Web::Seeded, "qa/web"),
            ("root", ".", Web::Project, "."),
            ("site", "apps/site", Web::Project, "."),
            ("worker", "worker", Web::None, "qa/web"),
        ] {
            qa.apps.insert(id.to_owned(), app(path, web, dir));
        }
        assert_eq!(web_dirs(&qa), [".", "api/qa/web", "apps/site"]);
    }
}

// ---- seeds, guide, never-touch (T5, #1002) ----------------------------------------

mod seeds {
    use super::{QA, Repo};
    use brakes::modules::qa::hurl::{check_seed, literal_host};
    use brakes::modules::qa::seeds::{BASELINE, GUIDE_PATH};
    use brakes::modules::stack_packs::PinTable;
    use serde_json::{Value, json};

    const API: [&str; 2] = ["qa/api/00-ready.hurl", "qa/api/smoke.hurl"];
    const WEB: [&str; 3] = [
        "qa/web/package.json",
        "qa/web/playwright.config.ts",
        "qa/web/smoke.spec.ts",
    ];

    fn template(path: &str) -> String {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../templates/qa");
        std::fs::read_to_string(root.join(path)).unwrap()
    }

    fn plan_has(plan: &str, line: &str) {
        assert!(plan.lines().any(|l| l == line), "{line}\n{plan}");
    }

    #[test]
    fn api_only_writes_the_two_hurl_seeds_and_the_guide() {
        let repo = Repo::new();
        repo.answer(
            QA,
            json!({"api": true, "api_start": "cargo run", "api_ready_path": "/healthz"}),
        );
        let plan = repo.install(&[]);
        for path in API {
            plan_has(&plan, &format!("PLAN {path} [seed:qa]"));
        }
        plan_has(&plan, &format!("PLAN {GUIDE_PATH} [managed:qa]"));
        assert!(!plan.contains("qa/web/"), "{plan}");
        repo.install(&["--apply"]);
        assert_eq!(
            repo.read("qa/api/00-ready.hurl"),
            template("seeds/api/00-ready.hurl").replace("{{api_ready_path}}", "/healthz")
        );
        assert!(
            repo.read("qa/api/00-ready.hurl")
                .contains("GET {{base_url}}/healthz\n")
        );
        assert_eq!(
            repo.read("qa/api/smoke.hurl"),
            template("seeds/api/smoke.hurl").replace("{{api_ready_path}}", "/healthz")
        );
        assert!(!repo.root.join("qa/web").exists());
        let again = repo.ok(&["install", "<repo>"]);
        assert!(again.lines().any(|l| l == "No changes."), "{again}");
    }

    /// #1216: the first smoke requests the one path the installer knows the API
    /// serves, the answered `api_ready_path`, and invents no media type for it;
    /// a seeded `GET /` was red on first install for an API without a root route.
    #[test]
    fn the_smoke_seed_requests_the_answered_ready_path_and_asserts_no_media_type() {
        let repo = Repo::new();
        repo.answer(
            QA,
            json!({"api": true, "api_start": "uvicorn app:app", "api_ready_path": "/openapi.json"}),
        );
        repo.install(&["--apply"]);
        let smoke = repo.read("qa/api/smoke.hurl");
        let requests: Vec<&str> = smoke.lines().filter(|l| l.starts_with("GET ")).collect();
        assert_eq!(requests, ["GET {{base_url}}/openapi.json"], "{smoke}");
        assert!(smoke.contains("\nHTTP 200\n"), "{smoke}");
        assert!(!smoke.contains("Content-Type"), "{smoke}");
        assert!(!smoke.contains("{{api_ready_path}}"), "{smoke}");
    }

    #[test]
    fn web_seeded_adds_the_three_web_files_under_web_dir_with_the_pinned_playwright() {
        let repo = Repo::new();
        repo.answer(
            QA,
            json!({"web": "seeded", "web_start": "npm run dev", "web_dir": "ui-checks"}),
        );
        repo.install(&["--apply"]);
        let pins = PinTable::embedded().unwrap();
        let version = &pins.tool("playwright").unwrap().version;
        let package: Value = serde_json::from_str(&repo.read("ui-checks/package.json")).unwrap();
        assert_eq!(
            package["devDependencies"]["@playwright/test"],
            json!(version)
        );
        assert_eq!(
            repo.read("ui-checks/playwright.config.ts"),
            template("seeds/web/playwright.config.ts")
        );
        assert_eq!(
            repo.read("ui-checks/smoke.spec.ts"),
            template("seeds/web/smoke.spec.ts")
        );
        for path in API.iter().chain(WEB.iter()) {
            assert!(!repo.root.join(path).exists(), "{path}");
        }
    }

    #[test]
    fn the_rendered_web_seed_screenshots_a_settled_page() {
        // #1244: a first baseline caught entrance animations at opacity 0
        // and reveal-on-scroll sections never scrolled into view.
        let repo = Repo::new();
        repo.answer(QA, json!({"web": "seeded", "web_start": "npm run dev"}));
        repo.install(&["--apply"]);
        let config = repo.read("qa/web/playwright.config.ts");
        assert!(config.contains("reducedMotion: 'reduce'"), "{config}");
        let spec = repo.read("qa/web/smoke.spec.ts");
        let steps = [
            "await page.goto('/');",
            "await page.waitForLoadState('networkidle');",
            "await page.evaluate(async () => { await document.fonts.ready; });",
            "window.scrollTo(0, y);",
            "window.scrollTo(0, 0);",
            "toHaveScreenshot('home.png', { fullPage: true, animations: 'disabled' })",
        ];
        let mut from = 0;
        for step in steps {
            let at = spec[from..]
                .find(step)
                .unwrap_or_else(|| panic!("{step} missing or out of order:\n{spec}"));
            from += at + step.len();
        }
        let guide = repo.read("docs/agent-setup/qa.md");
        assert!(
            guide.contains("Open every image and look at it before committing"),
            "{guide}"
        );
        assert!(guide.contains("reducedMotion"), "{guide}");
    }

    #[test]
    fn the_rendered_web_seed_falls_back_to_localhost() {
        // #1250: `next dev` blocks its dev resources for 127.0.0.1, so the page never hydrated.
        let repo = Repo::new();
        repo.answer(QA, json!({"web": "seeded", "web_start": "npm run dev"}));
        repo.install(&["--apply"]);
        let config = repo.read("qa/web/playwright.config.ts");
        assert_eq!(
            config
                .matches("process.env.QA_WEB_URL ?? 'http://localhost:3000'")
                .count(),
            2,
            "{config}"
        );
        assert!(!config.contains("127.0.0.1"), "{config}");
        let guide = repo.read("docs/agent-setup/qa.md");
        assert!(guide.contains("allowedDevOrigins"), "{guide}");
    }

    #[test]
    fn the_seeded_baseline_name_stays_deterministic() {
        // T9's probe: Playwright names it <test file>-snapshots/<arg>-<project>-<platform>.png.
        assert_eq!(BASELINE, "smoke.spec.ts-snapshots/home-chromium-linux.png");
        let spec = template("seeds/web/smoke.spec.ts");
        assert!(spec.contains("toHaveScreenshot('home.png'"), "{spec}");
        let config = template("seeds/web/playwright.config.ts");
        assert!(config.contains("projects: [{ name: 'chromium'"), "{config}");
        assert!(!config.contains("snapshotPathTemplate"), "{config}");
        assert!(!config.contains("snapshotDir"), "{config}");
    }

    #[test]
    fn web_project_writes_nothing_under_web_dir_and_lists_the_root_config() {
        let repo = Repo::new();
        repo.write("playwright.config.ts", "export default {};\n");
        repo.answer(QA, json!({"web": "project", "web_start": "npm run dev"}));
        let plan = repo.install(&["--apply"]);
        plan_has(&plan, "WRITE docs/agent-setup/qa.md [managed:qa]");
        assert!(!plan.contains("[seed:qa]"), "{plan}");
        assert_eq!(repo.read("playwright.config.ts"), "export default {};\n");
        let lock: Value = serde_json::from_str(&repo.read(".agent-setup/lock.json")).unwrap();
        assert_eq!(
            lock["files"]["playwright.config.ts"]["class"], "never-touch",
            "{lock:#}"
        );
        assert_eq!(
            lock["files"]["playwright.config.ts"]["module"], QA,
            "{lock:#}"
        );
    }

    #[test]
    fn an_existing_seed_is_skipped_and_kept() {
        let repo = Repo::new();
        repo.write("qa/api/smoke.hurl", "GET {{base_url}}/mine\nHTTP 200\n");
        repo.answer(QA, json!({"api": true, "api_start": "cargo run"}));
        let plan = repo.install(&["--apply"]);
        plan_has(&plan, "SKIP qa/api/smoke.hurl [seed:qa]");
        assert_eq!(
            repo.read("qa/api/smoke.hurl"),
            "GET {{base_url}}/mine\nHTTP 200\n"
        );
        let plan = repo.install(&[]);
        assert!(plan.lines().any(|l| l == "No changes."), "{plan}");
    }

    #[test]
    fn an_edited_guide_refuses() {
        let repo = Repo::new();
        repo.install(&["--apply"]);
        repo.write(GUIDE_PATH, "# mine\n");
        let out = repo.cli(&["install", "<repo>"]);
        assert!(!out.status.success(), "{out:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains(GUIDE_PATH),
            "{out:?}"
        );
    }

    #[test]
    fn the_guide_carries_its_last_verified_line_and_the_pinned_image() {
        let repo = Repo::new();
        repo.install(&["--apply"]);
        let guide = repo.read(GUIDE_PATH);
        assert!(
            guide.lines().any(|l| l.starts_with("Last verified: ")),
            "{guide}"
        );
        let pins = PinTable::embedded().unwrap();
        assert!(
            guide.contains(&pins.image("playwright").unwrap().pinned()),
            "{guide}"
        );
        assert!(
            guide.contains(&pins.tool("playwright").unwrap().version),
            "{guide}"
        );
        assert!(
            !guide.contains("{{tools.") && !guide.contains("{{images."),
            "{guide}"
        );
    }

    #[test]
    fn remove_lists_the_seeds_and_deletes_the_unchanged_guide() {
        let repo = Repo::new();
        repo.answer(QA, json!({"api": true, "api_start": "cargo run"}));
        repo.install(&["--apply"]);
        let plan = repo.ok(&["remove", "<repo>", QA, "--apply"]);
        plan_has(&plan, &format!("DELETE {GUIDE_PATH} [managed:qa]"));
        for path in API {
            plan_has(&plan, &format!("KEEP {path} [seed:qa]"));
            assert!(repo.root.join(path).exists(), "{path}");
        }
        assert!(!repo.root.join(GUIDE_PATH).exists());
    }

    #[test]
    fn configure_keeps_the_project_tests() {
        let repo = Repo::new();
        repo.install(&["--apply"]);
        repo.ok(&[
            "configure",
            "<repo>",
            QA,
            "--set",
            "api=true",
            "--set",
            "api_start=cargo run",
            "--apply",
        ]);
        assert!(repo.root.join("qa/api/smoke.hurl").exists());
    }

    #[test]
    fn a_ready_path_that_is_not_an_absolute_path_refuses() {
        let repo = Repo::new();
        assert_eq!(
            repo.refusal(json!({"api": true, "api_start": "run", "api_ready_path": "livez\nGET http://evil/"})),
            "REFUSED: qa: api_ready_path `livez\nGET http://evil/` is not a path starting with / without spaces; it is the request line of 00-ready.hurl"
        );
    }

    #[test]
    fn a_seeded_web_dir_in_an_existing_test_directory_refuses() {
        let repo = Repo::new();
        assert_eq!(
            repo.refusal(json!({"web": "seeded", "web_start": "run", "web_dir": "e2e/visual"})),
            "REFUSED: qa: web_dir e2e/visual is or contains the test directory e2e; the module never writes where a test already is"
        );
        repo.write("ui/spec/home.spec.ts", "");
        assert_eq!(
            repo.refusal(json!({"web": "seeded", "web_start": "run", "web_dir": "ui"})),
            "REFUSED: qa: web_dir ui is or contains the test directory spec; the module never writes where a test already is"
        );
        // A directory named like a test directory that does not exist yet is the module's.
        repo.answer(
            QA,
            json!({"web": "seeded", "web_start": "run", "web_dir": "frontend/e2e"}),
        );
        repo.install(&["--apply"]);
        assert!(repo.root.join("frontend/e2e/smoke.spec.ts").exists());
    }

    #[test]
    fn literal_host_finds_a_host_only_on_a_request_line() {
        assert_eq!(literal_host("GET http://x/"), Some("http://x/"));
        assert_eq!(
            literal_host("  POST https://api.example.com/v1"),
            Some("https://api.example.com/v1")
        );
        assert_eq!(literal_host("GET {{base_url}}/"), None);
        assert_eq!(literal_host("# GET http://example.com/ in a comment"), None);
        assert_eq!(literal_host("[Asserts]"), None);
        assert_eq!(literal_host("header \"Location\" == \"http://x/\""), None);
        assert_eq!(literal_host("HTTP 200"), None);
        assert_eq!(
            literal_host("jsonpath \"$.url\" startsWith \"https://\""),
            None
        );
    }

    #[test]
    fn a_seed_whose_request_line_names_a_host_refuses() {
        assert_eq!(
            check_seed(
                "qa/api/smoke.hurl",
                "# ok\nGET https://staging.example.com/\nHTTP 200\n"
            )
            .unwrap_err()
            .to_string(),
            "qa: qa/api/smoke.hurl:2 names a host; use {{base_url}} so the file serves test, smoke and uptime"
        );
        check_seed("qa/api/smoke.hurl", &template("seeds/api/smoke.hurl")).unwrap();
    }
}

// ---- qa-api through ci_jobs (T6, #1003) -------------------------------------------

mod api_job {
    use super::{QA, Repo};
    use crate::support::SetupCore;
    use brakes::engine::{self, CiJob, Context, Module, Rendered};
    use brakes::modules::qa::Qa;
    use brakes::modules::qa::jobs::QA_API;
    use brakes::modules::{CiBaseline, StackPacks};
    use brakes::{Result, Source, profile_for};
    use serde_json::json;
    use std::{fs, path::PathBuf};

    pub(super) const WORKFLOW: &str = ".github/workflows/ci.yml";
    const START: &str = "cargo run --locked -- --port 8080";
    const GOLDENS: &str = "../../templates/qa/goldens";

    /// A single-app repository with `qa` answered `api: true`.
    fn api_repo() -> Repo {
        let repo = Repo::single();
        repo.answer(QA, json!({"api": true, "api_start": START}));
        repo
    }

    /// Compares `text` with the golden byte for byte; `UPDATE_GOLDENS=1` rewrites it.
    pub(super) fn golden(name: &str, text: &str) {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(GOLDENS)
            .join(name);
        if std::env::var_os("UPDATE_GOLDENS").is_some() {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, text).unwrap();
        }
        let expected = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{}: {e}; run with UPDATE_GOLDENS=1", path.display()));
        assert!(text == expected, "{name} differs from the golden:\n{text}");
    }

    /// The job blocks of a workflow: id -> its lines.
    pub(super) fn job_blocks(text: &str) -> Vec<(String, Vec<String>)> {
        let body = text.split_once("\njobs:\n").unwrap().1;
        let mut out: Vec<(String, Vec<String>)> = Vec::new();
        for line in body.lines() {
            if let Some(id) = line.strip_prefix("  ").filter(|l| !l.starts_with(' ')) {
                out.push((id.trim_end_matches(':').to_owned(), Vec::new()));
            } else {
                out.last_mut().unwrap().1.push(line.to_owned());
            }
        }
        out
    }

    pub(super) fn job<'a>(blocks: &'a [(String, Vec<String>)], id: &str) -> &'a [String] {
        &blocks
            .iter()
            .find(|(j, _)| j == id)
            .unwrap_or_else(|| panic!("no job {id}"))
            .1
    }

    fn api_golden() -> String {
        fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join(GOLDENS)
                .join("api.yml"),
        )
        .unwrap()
    }

    #[test]
    fn the_composed_workflow_matches_the_api_golden() {
        let repo = api_repo();
        let plan = repo.install(&["--apply"]);
        assert!(
            plan.lines()
                .any(|l| l == format!("NOTE [ci-baseline] JOB [qa] {QA_API} → {WORKFLOW}")),
            "{plan}"
        );
        let text = repo.read(WORKFLOW);
        golden("api.yml", &text);
        let again = repo.ok(&["install", "<repo>"]);
        assert!(again.lines().any(|l| l == "No changes."), "{again}");
    }

    #[test]
    fn qa_api_reaches_required_and_skips_under_docs() {
        let text = api_golden();
        let blocks = job_blocks(&text);
        let ids: Vec<&str> = blocks.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "scope",
                "checks",
                "heldout",
                "workflow-lint",
                QA_API,
                "required"
            ]
        );
        assert!(
            job(&blocks, "required")
                .contains(&"    needs: [scope, checks, heldout, workflow-lint, qa-api]".to_owned())
        );
        let scope = job(&blocks, "scope").join("\n");
        let docs = scope.split_once("DOCS_SKIPPABLE: |-\n").unwrap().1;
        let docs: Vec<&str> = docs
            .lines()
            .take_while(|l| l.starts_with("            "))
            .map(str::trim)
            .collect();
        assert_eq!(docs, ["checks", "heldout", QA_API]);
        let api = job(&blocks, QA_API);
        for line in [
            "    needs: scope",
            "    if: needs.scope.outputs.tier != 'docs'",
            "    timeout-minutes: 15",
            "          persist-credentials: \"false\"",
            "          retention-days: \"7\"",
        ] {
            assert!(api.contains(&line.to_owned()), "{line}\n{api:#?}");
        }
        assert!(
            !api.iter()
                .any(|l| l.trim_start().starts_with("permissions:")),
            "{api:#?}"
        );
    }

    #[test]
    fn the_golden_carries_no_forbidden_construct_and_pins_every_action() {
        let text = api_golden();
        let blocks = job_blocks(&text);
        let api = job(&blocks, QA_API).join("\n");
        for forbidden in ["continue-on-error", "|| true", "--update-snapshots"] {
            assert!(!api.contains(forbidden), "qa-api contains {forbidden}");
        }
        // No shell retry loop: readiness is Hurl's own `--retry`.
        assert!(
            !api.lines().any(|l| l.trim_start().starts_with("until ")),
            "qa-api has an until loop"
        );
        for line in text
            .lines()
            .filter(|l| l.trim_start().starts_with("uses: "))
        {
            let reference = line.split_once('@').map(|(_, r)| r).unwrap_or("");
            let sha = reference.split(' ').next().unwrap();
            assert!(
                sha.len() == 40 && sha.chars().all(|c| c.is_ascii_hexdigit()),
                "{line}"
            );
        }
        // Hurl's own retry, on the readiness file only; no host in a hurl command.
        let hurl: Vec<&str> = api
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with("hurl --test"))
            .collect();
        assert_eq!(hurl.len(), 2, "{api}");
        assert!(
            hurl[0].contains("--retry 600 --retry-interval 1000"),
            "{}",
            hurl[0]
        );
        assert!(
            hurl[0].ends_with("\"$QA_DIR/api/00-ready.hurl\""),
            "{}",
            hurl[0]
        );
        assert!(!hurl[1].contains("--retry"), "{}", hurl[1]);
        assert!(
            hurl[1].contains("--report-junit \"$RUNNER_TEMP/qa/hurl-junit.xml\""),
            "{}",
            hurl[1]
        );
        for line in &hurl {
            assert!(!line.contains("http"), "{line}");
        }
        // The start command is data in `env:` only.
        let occurrences: Vec<&str> = text.lines().filter(|l| l.contains(START)).collect();
        assert_eq!(occurrences, [format!("          QA_START: \"{START}\"")]);
        // Stop and upload run whatever happened; the stop needs a started API.
        assert!(api.contains("      - name: Stop the API\n        if: always() && steps.start.outcome == 'success'"), "{api}");
        assert!(
            api.contains("      - name: Upload the QA report\n        if: always()\n"),
            "{api}"
        );
    }

    /// The readiness command and the timeout of `qa-api` in `text`.
    fn readiness(text: &str) -> (String, String) {
        let blocks = job_blocks(text);
        let api = job(&blocks, QA_API);
        let ready = api
            .iter()
            .map(|l| l.trim())
            .find(|l| l.starts_with("hurl --test --jobs 1"))
            .unwrap()
            .to_owned();
        let timeout = api
            .iter()
            .map(|l| l.trim())
            .find(|l| l.starts_with("timeout-minutes:"))
            .unwrap()
            .to_owned();
        (ready, timeout)
    }

    fn with_budget(repo: &Repo, minutes: u32) {
        let path = ".agent-setup/project.json";
        let mut profile: serde_json::Value = serde_json::from_str(&repo.read(path)).unwrap();
        profile["ci"]["cycle_budget_minutes"] = json!(minutes);
        repo.write(
            path,
            &(serde_json::to_string_pretty(&profile).unwrap() + "\n"),
        );
    }

    #[test]
    fn the_readiness_wait_defaults_to_ten_minutes_within_the_fifteen_minute_job() {
        // #1243: a cold `docker compose up --build` outlived the fixed 60 s.
        let repo = api_repo();
        repo.install(&["--apply"]);
        let (ready, timeout) = readiness(&repo.read(WORKFLOW));
        assert!(
            ready.contains("--retry 600 --retry-interval 1000"),
            "{ready}"
        );
        assert_eq!(timeout, "timeout-minutes: 15");
    }

    #[test]
    fn an_answered_readiness_wait_sets_the_retries_and_widens_the_job() {
        let repo = Repo::single();
        repo.answer(
            QA,
            json!({"api": true, "api_start": START, "api_ready_timeout": 1230}),
        );
        repo.install(&["--apply"]);
        let (ready, timeout) = readiness(&repo.read(WORKFLOW));
        assert!(
            ready.contains("--retry 1230 --retry-interval 1000"),
            "{ready}"
        );
        // ceil(1230 / 60) = 21 minutes of readiness, plus five.
        assert_eq!(timeout, "timeout-minutes: 26");
    }

    #[test]
    fn a_declared_cycle_budget_sets_the_unanswered_readiness_wait() {
        let repo = api_repo();
        with_budget(&repo, 10);
        repo.install(&["--apply"]);
        let (ready, timeout) = readiness(&repo.read(WORKFLOW));
        // One measurement: ceil(10 * 1.5) = 15 minutes.
        assert!(
            ready.contains("--retry 900 --retry-interval 1000"),
            "{ready}"
        );
        assert_eq!(timeout, "timeout-minutes: 20");
    }

    #[test]
    fn an_answer_wins_over_the_cycle_budget() {
        let repo = Repo::single();
        repo.answer(
            QA,
            json!({"api": true, "api_start": START, "api_ready_timeout": 120}),
        );
        with_budget(&repo, 10);
        repo.install(&["--apply"]);
        let (ready, timeout) = readiness(&repo.read(WORKFLOW));
        assert!(ready.contains("--retry 120 "), "{ready}");
        assert_eq!(timeout, "timeout-minutes: 15");
    }

    #[test]
    fn a_budget_beyond_the_job_maximum_caps_the_wait_and_notes_it() {
        let repo = api_repo();
        with_budget(&repo, 300);
        let plan = repo.install(&["--apply"]);
        let (ready, timeout) = readiness(&repo.read(WORKFLOW));
        assert!(ready.contains("--retry 21300 "), "{ready}");
        assert_eq!(timeout, "timeout-minutes: 360");
        // One measurement is 450 minutes; plus five.
        assert!(
            plan.lines().any(|l| l
                == "NOTE [qa] ci.cycle_budget_minutes 300 derives timeouts above GitHub's 360-minute job maximum (qa-api 455); those jobs render timeout-minutes: 360"),
            "{plan}"
        );
    }

    #[test]
    fn an_answered_wait_under_a_large_budget_renders_without_the_note() {
        let repo = Repo::single();
        repo.answer(
            QA,
            json!({"api": true, "api_start": START, "api_ready_timeout": 600}),
        );
        with_budget(&repo, 300);
        let plan = repo.install(&["--apply"]);
        let (ready, timeout) = readiness(&repo.read(WORKFLOW));
        assert!(ready.contains("--retry 600 "), "{ready}");
        assert_eq!(timeout, "timeout-minutes: 15");
        assert!(
            !plan.contains("NOTE [qa] ci.cycle_budget_minutes"),
            "{plan}"
        );
    }

    #[test]
    fn a_readiness_wait_outside_its_range_refuses() {
        for value in [9, 21301] {
            let repo = Repo::single();
            let line =
                repo.refusal(json!({"api": true, "api_start": START, "api_ready_timeout": value}));
            assert!(line.contains("api_ready_timeout"), "{line}");
        }
    }

    #[test]
    fn an_app_answers_its_own_readiness_wait() {
        let repo = Repo::new();
        repo.answer(
            QA,
            json!({"apps": ["api"], "apps.api.api": true, "apps.api.api_start": START,
                   "apps.api.api_ready_timeout": 1800}),
        );
        repo.install(&["--apply"]);
        let text = repo.read(WORKFLOW);
        let api = job(&job_blocks(&text), "api-qa-api").join("\n");
        assert!(api.contains("--retry 1800 --retry-interval 1000"), "{api}");
        assert!(api.contains("    timeout-minutes: 35\n"), "{api}");
    }

    #[test]
    fn an_answer_with_quotes_stays_one_yaml_scalar() {
        let repo = Repo::single();
        repo.answer(QA, json!({"api": true, "api_start": "echo \"a\\b\" 'c'"}));
        repo.install(&["--apply"]);
        let text = repo.read(WORKFLOW);
        assert!(
            text.contains(r#"          QA_START: "echo \"a\\b\" 'c'""#),
            "{text}"
        );
    }

    #[test]
    fn without_api_no_job_is_contributed() {
        let repo = Repo::single();
        repo.answer(QA, json!({"api": false}));
        repo.install(&["--apply"]);
        assert!(!repo.read(WORKFLOW).contains("qa-api"));
    }

    /// A contributor whose single job takes the id `qa-api`.
    struct Squatter;
    impl Module for Squatter {
        fn id(&self) -> &'static str {
            "fixture"
        }
        fn version(&self) -> &'static str {
            "1.0.0"
        }
        fn render(&self, _: &Context<'_>) -> Result<Vec<Rendered>> {
            Ok(Vec::new())
        }
        fn ci_jobs(&self, _: &Context<'_>) -> Vec<CiJob> {
            vec![CiJob {
                id: QA_API.to_owned(),
                yaml: "name: qa-api\nneeds: scope\nruns-on: ubuntu-24.04\ntimeout-minutes: 5\nsteps:\n  - name: Echo\n    run: echo\n".to_owned(),
                skippable_under: Vec::new(),
                app: None,
            }]
        }
    }

    #[test]
    fn a_contributor_taking_qa_api_collides_with_qa() {
        let repo = api_repo();
        let profile = profile_for(&repo.root).unwrap();
        let modules: [&dyn Module; 5] = [&SetupCore, &StackPacks, &Qa, &Squatter, &CiBaseline];
        let error = engine::plan(&repo.root, &Source::embedded(), &profile, &modules, &|_| {
            true
        })
        .unwrap_err()
        .to_string();
        assert_eq!(
            error,
            "Module fixture contributes CI job qa-api, which collides with module qa"
        );
    }

    #[test]
    fn under_workflow_existing_qa_api_lands_in_agentic_security_under_agentic_required() {
        const OWN: &str = ".github/workflows/orchestration.yml";
        const OWN_YML: &str = "name: Orchestration\non:\n  pull_request:\npermissions:\n  contents: read\njobs:\n  rust:\n    name: Rust (linux)\n    runs-on: ubuntu-24.04\n    timeout-minutes: 10\n    steps:\n      - name: Verify\n        run: echo verify\n";
        const SEPARATE: &str = ".github/workflows/agentic-security.yml";
        let repo = api_repo();
        repo.write(OWN, OWN_YML);
        repo.answer(
            "ci-baseline",
            json!({"workflow": "existing", "aggregate_check": "Rust (linux)"}),
        );
        let plan = repo.install(&["--apply"]);
        assert!(
            plan.lines()
                .any(|l| l == format!("NOTE [ci-baseline] JOB [qa] {QA_API} → {SEPARATE}")),
            "{plan}"
        );
        let text = repo.read(SEPARATE);
        let blocks = job_blocks(&text);
        let ids: Vec<&str> = blocks.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(ids, ["scope", QA_API, "agentic-required"]);
        assert!(
            job(&blocks, "agentic-required").contains(&"    needs: [scope, qa-api]".to_owned()),
            "{text}"
        );
        assert_eq!(repo.read(OWN), OWN_YML);
        assert!(!repo.root.join(WORKFLOW).exists());
    }
}

// ---- qa-web through ci_jobs (T7, #1004) -------------------------------------------

mod web_job {
    use super::api_job::{WORKFLOW, golden, job, job_blocks};
    use super::{QA, Repo};
    use crate::support::SetupCore;
    use brakes::engine::{self, CiJob, Context, Module, Rendered};
    use brakes::modules::qa::Qa;
    use brakes::modules::qa::jobs::{QA_API, QA_WEB};
    use brakes::modules::stack_packs::PinTable;
    use brakes::modules::{CiBaseline, StackPacks};
    use brakes::{Result, Source, profile_for};
    use serde_json::{Value, json};

    const WEB_START: &str = "npm run dev -- --port 3000";

    /// A single node app at the root that runs its own Playwright.
    fn node_project_repo() -> Repo {
        let repo = Repo::single();
        let path = ".agent-setup/project.json";
        let mut profile: Value = serde_json::from_str(&repo.read(path)).unwrap();
        profile["commands"]["test"] = "npm test".into();
        repo.write(
            path,
            &(serde_json::to_string_pretty(&profile).unwrap() + "\n"),
        );
        std::fs::remove_file(repo.root.join("Cargo.toml")).unwrap();
        std::fs::remove_file(repo.root.join("Cargo.lock")).unwrap();
        repo.write(
            "package.json",
            "{\n  \"private\": true,\n  \"devDependencies\": {\"@playwright/test\": \"1.64.1\"}\n}\n",
        );
        repo.write("package-lock.json", "{}\n");
        repo.write("playwright.config.ts", "export default {};\n");
        repo.answer(
            "stack-packs",
            json!({"apps.root.path": ".", "apps.root.stack": "node", "apps.root.container": false,
                   "apps.root.toolchain": false}),
        );
        repo.answer(
            QA,
            json!({"web": "project", "web_start": WEB_START, "web_command": "npm run e2e"}),
        );
        repo
    }

    fn workflow_of(repo: &Repo) -> String {
        repo.install(&["--apply"]);
        repo.read(WORKFLOW)
    }

    fn web_job(text: &str) -> String {
        job(&job_blocks(text), QA_WEB).join("\n")
    }

    #[test]
    fn a_seeded_web_matches_its_golden() {
        let repo = Repo::single();
        repo.answer(QA, json!({"web": "seeded", "web_start": WEB_START}));
        let text = workflow_of(&repo);
        golden("web-seeded.yml", &text);
        let blocks = job_blocks(&text);
        let ids: Vec<&str> = blocks.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "scope",
                "checks",
                "heldout",
                "workflow-lint",
                QA_WEB,
                "required"
            ]
        );
        let web = web_job(&text);
        for line in [
            "    needs: scope",
            "    if: needs.scope.outputs.tier != 'docs'",
            "    timeout-minutes: 20",
            "          persist-credentials: \"false\"",
            "          retention-days: \"7\"",
            "        working-directory: \"qa/web\"",
            "          npx playwright test",
            "          npm ci",
        ] {
            assert!(web.lines().any(|l| l == line), "{line}\n{web}");
        }
        // A rust app: Node comes from setup-node at the pinned major.
        let pins = PinTable::embedded().unwrap();
        let node = &pins.tool("node").unwrap().version;
        assert!(
            web.contains(
                "      - name: Set up Node for Playwright\n        uses: actions/setup-node@"
            ),
            "{web}"
        );
        assert!(
            web.contains(&format!("          node-version: \"{node}\"")),
            "{web}"
        );
        let again = repo.ok(&["install", "<repo>"]);
        assert!(again.lines().any(|l| l == "No changes."), "{again}");
    }

    #[test]
    fn a_project_web_runs_its_own_command_and_seeds_nothing() {
        let repo = node_project_repo();
        let plan = repo.install(&[]);
        assert!(!plan.contains("[seed:qa]"), "{plan}");
        let text = workflow_of(&repo);
        golden("web-project.yml", &text);
        let web = web_job(&text);
        assert!(
            web.contains("          QA_WEB_COMMAND: \"npm run e2e\""),
            "{web}"
        );
        assert!(!web.contains("npx playwright test"), "{web}");
        assert!(web.contains("        working-directory: \".\""), "{web}");
        // A node app: its ci_setup brings Node; no second setup-node.
        assert_eq!(web.matches("uses: actions/setup-node@").count(), 1, "{web}");
        assert!(!web.contains("Set up Node for Playwright"), "{web}");
        // Its ci_setup already ran `npm ci` at the root, which is `web_dir`: once only.
        let installs: Vec<&str> = web
            .lines()
            .filter(|l| l.trim().ends_with("npm ci"))
            .collect();
        assert_eq!(installs, ["        run: npm ci"], "{web}");
        assert!(
            !web.contains("Install the web tests' dependencies"),
            "{web}"
        );
    }

    #[test]
    fn api_and_web_reach_required_in_module_order() {
        let repo = Repo::single();
        repo.answer(
            QA,
            json!({"api": true, "api_start": "cargo run", "web": "seeded", "web_start": WEB_START}),
        );
        let text = workflow_of(&repo);
        golden("both.yml", &text);
        let blocks = job_blocks(&text);
        let ids: Vec<&str> = blocks.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "scope",
                "checks",
                "heldout",
                "workflow-lint",
                QA_API,
                QA_WEB,
                "required"
            ]
        );
        assert!(job(&blocks, "required").contains(
            &"    needs: [scope, checks, heldout, workflow-lint, qa-api, qa-web]".to_owned()
        ));
        let scope = job(&blocks, "scope").join("\n");
        let docs = scope.split_once("DOCS_SKIPPABLE: |-\n").unwrap().1;
        let docs: Vec<&str> = docs
            .lines()
            .take_while(|l| l.starts_with("            "))
            .map(str::trim)
            .collect();
        assert_eq!(docs, ["checks", "heldout", QA_API, QA_WEB]);
    }

    #[test]
    fn the_web_goldens_never_update_snapshots_and_pin_the_browser_by_the_package() {
        for repo in [
            {
                let repo = Repo::single();
                repo.answer(QA, json!({"web": "seeded", "web_start": WEB_START}));
                repo
            },
            node_project_repo(),
        ] {
            let text = workflow_of(&repo);
            let web = web_job(&text);
            for forbidden in [
                "--update-snapshots",
                "UPDATE_SNAPSHOTS",
                "continue-on-error",
                "|| true",
            ] {
                assert!(!web.contains(forbidden), "qa-web contains {forbidden}");
            }
            // #1283: the job runs in the pinned image the baseline is generated in,
            // with its system fonts; the browser install adds no system package.
            let pins = PinTable::embedded().unwrap();
            let image = pins.image("playwright").unwrap();
            let container = format!(
                "    container:\n      image: \"{}@{}\"\n    steps:",
                image.reference, image.digest
            );
            assert!(web.contains(&container), "{container}\n{web}");
            let install: Vec<&str> = web
                .lines()
                .map(str::trim)
                .filter(|l| l.starts_with("npx playwright install"))
                .collect();
            assert_eq!(install, ["npx playwright install chromium"]);
            // The start command and URL are data in `env:` only.
            let starts: Vec<&str> = web.lines().filter(|l| l.contains(WEB_START)).collect();
            assert_eq!(starts, [format!("          QA_WEB_START: \"{WEB_START}\"")]);
            assert!(
                web.contains("          QA_WEB_URL: \"http://localhost:3000\""),
                "{web}"
            );
            for line in text
                .lines()
                .filter(|l| l.trim_start().starts_with("uses: "))
            {
                let sha = line.split_once('@').unwrap().1.split(' ').next().unwrap();
                assert!(
                    sha.len() == 40 && sha.chars().all(|c| c.is_ascii_hexdigit()),
                    "{line}"
                );
            }
        }
    }

    #[test]
    fn a_missing_lockfile_fails_naming_the_web_dir() {
        let repo = Repo::single();
        repo.answer(
            QA,
            json!({"web": "seeded", "web_start": WEB_START, "web_dir": "checks/ui"}),
        );
        let web = web_job(&workflow_of(&repo));
        assert!(
            web.contains("echo \"::error::qa-web: $QA_WEB_DIR/package-lock.json missing; run npm install locally and commit it\""),
            "{web}"
        );
        assert!(web.contains("          QA_WEB_DIR: \"checks/ui\""), "{web}");
        assert!(web.contains("          path: |\n            checks/ui/playwright-report/\n            checks/ui/test-results/"), "{web}");
    }

    /// A contributor whose single job takes the id `qa-web`.
    struct Squatter;
    impl Module for Squatter {
        fn id(&self) -> &'static str {
            "fixture"
        }
        fn version(&self) -> &'static str {
            "1.0.0"
        }
        fn render(&self, _: &Context<'_>) -> Result<Vec<Rendered>> {
            Ok(Vec::new())
        }
        fn ci_jobs(&self, _: &Context<'_>) -> Vec<CiJob> {
            vec![CiJob {
                id: QA_WEB.to_owned(),
                yaml: "name: qa-web\nneeds: scope\nruns-on: ubuntu-24.04\ntimeout-minutes: 5\nsteps:\n  - name: Echo\n    run: echo\n".to_owned(),
                skippable_under: Vec::new(),
                app: None,
            }]
        }
    }

    #[test]
    fn a_contributor_taking_qa_web_collides_with_qa() {
        let repo = Repo::single();
        repo.answer(QA, json!({"web": "seeded", "web_start": WEB_START}));
        let profile = profile_for(&repo.root).unwrap();
        let modules: [&dyn Module; 5] = [&SetupCore, &StackPacks, &Qa, &Squatter, &CiBaseline];
        let error = engine::plan(&repo.root, &Source::embedded(), &profile, &modules, &|_| {
            true
        })
        .unwrap_err()
        .to_string();
        assert_eq!(
            error,
            "Module fixture contributes CI job qa-web, which collides with module qa"
        );
    }
}

// ---- monorepo: one qa pair per app (T13, #1011) -------------------------------------

mod monorepo {
    use super::api_job::{WORKFLOW, golden, job, job_blocks};
    use super::{QA, Repo};
    use crate::support::SetupCore;
    use brakes::engine::{self, CiJob, Context, Module, Rendered};
    use brakes::modules::qa::Qa;
    use brakes::modules::{CiBaseline, StackPacks};
    use brakes::{Result, Source, profile_for};
    use serde_json::json;

    const BACKEND_START: &str = "cargo run --locked -- --port 8080";

    /// Two apps under `apps/`: `backend` (rust) serves its API and its web
    /// (one start command for both jobs, Open question 7), `front` (node) a
    /// seeded web of its own.
    fn monorepo() -> Repo {
        let repo = Repo::single().without_root_commands();
        repo.write("apps/backend/Cargo.toml", "");
        repo.write("apps/backend/Cargo.lock", "");
        repo.write(
            "apps/backend/.agent-setup/project.json",
            r#"{"commands": {"test": "cargo test --locked"}}"#,
        );
        repo.write("apps/front/package.json", "{\"private\": true}\n");
        repo.write("apps/front/package-lock.json", "{}\n");
        repo.write(
            "apps/front/.agent-setup/project.json",
            r#"{"commands": {"test": "npm test"}}"#,
        );
        repo.answer(
            "stack-packs",
            json!({"apps.backend.path": "apps/backend", "apps.backend.stack": "rust",
                   "apps.backend.container": false,
                   "apps.front.path": "apps/front", "apps.front.stack": "node",
                   "apps.front.container": false, "apps.front.toolchain": false}),
        );
        repo.answer(
            QA,
            json!({"apps": ["backend", "front"],
                   "apps.backend.api": true, "apps.backend.api_start": BACKEND_START,
                   "apps.backend.web": "seeded", "apps.backend.web_start": BACKEND_START,
                   "apps.backend.web_url": "http://127.0.0.1:8080",
                   "apps.front.api": false,
                   "apps.front.web": "seeded", "apps.front.web_start": "npm run dev"}),
        );
        repo
    }

    fn scope_env(text: &str, key: &str) -> Vec<String> {
        let scope = job(&job_blocks(text), "scope").to_vec();
        let start = scope
            .iter()
            .position(|l| l.trim_start().starts_with(&format!("{key}:")))
            .unwrap_or_else(|| panic!("no {key} in scope"));
        let indent = scope[start].len() - scope[start].trim_start().len();
        scope[start + 1..]
            .iter()
            .take_while(|l| l.len() - l.trim_start().len() > indent)
            .map(|l| l.trim().to_owned())
            .collect()
    }

    #[test]
    fn two_apps_render_a_pair_each_and_match_the_golden() {
        let repo = monorepo();
        let plan = repo.install(&["--apply"]);
        for id in ["backend-qa-api", "backend-qa-web", "front-qa-web"] {
            assert!(
                plan.lines()
                    .any(|l| l == format!("NOTE [ci-baseline] JOB [qa] {id} → {WORKFLOW}")),
                "{id}\n{plan}"
            );
        }
        assert!(!plan.contains("front-qa-api"), "{plan}");
        let text = repo.read(WORKFLOW);
        golden("monorepo.yml", &text);
        let blocks = job_blocks(&text);
        let required = job(&blocks, "required").join("\n");
        assert!(
            required.contains("backend-qa-api, backend-qa-web, front-qa-web]"),
            "{required}"
        );
        assert_eq!(
            scope_env(&text, "APP_JOBS"),
            [
                "backend-qa-api=backend",
                "backend-qa-web=backend",
                "front-qa-web=front"
            ]
        );
        let again = repo.ok(&["install", "<repo>"]);
        assert!(again.lines().any(|l| l == "No changes."), "{again}");
    }

    #[test]
    fn each_app_job_skips_with_its_app_and_runs_in_its_directory() {
        let repo = monorepo();
        repo.install(&["--apply"]);
        let text = repo.read(WORKFLOW);
        let blocks = job_blocks(&text);
        let api = job(&blocks, "backend-qa-api").join("\n");
        for line in [
            "    name: backend-qa-api",
            "    if: contains(fromJSON(needs.scope.outputs.skippable), 'backend-qa-api') == false",
            "        working-directory: \"apps/backend\"",
            "          QA_DIR: \"apps/backend/qa\"",
            "          QA_START: \"cargo run --locked -- --port 8080\"",
        ] {
            assert!(api.lines().any(|l| l == line), "{line}\n{api}");
        }
        assert!(api.contains("uses: dtolnay/rust-toolchain@"), "{api}");
        assert!(!api.contains("tier != 'docs'"), "{api}");
        let web = job(&blocks, "front-qa-web").join("\n");
        for line in [
            "    name: front-qa-web",
            "    if: contains(fromJSON(needs.scope.outputs.skippable), 'front-qa-web') == false",
            "        working-directory: \"apps/front/qa/web\"",
            "            apps/front/qa/web/playwright-report/",
        ] {
            assert!(web.lines().any(|l| l == line), "{line}\n{web}");
        }
        // Each job uploads under its own artifact name.
        assert!(
            web.contains("          name: front-qa-web\n          path: |"),
            "{web}"
        );
        assert!(
            api.contains("          name: backend-qa-api\n          path: |"),
            "{api}"
        );
        // The node app's own setup brings Node; the rust app's web gets setup-node.
        assert!(!web.contains("Set up Node for Playwright"), "{web}");
        let backend_web = job(&blocks, "backend-qa-web").join("\n");
        assert!(
            backend_web.contains("Set up Node for Playwright"),
            "{backend_web}"
        );
        // The backend serves its web: both jobs start the same command.
        assert!(backend_web.contains(&format!("QA_WEB_START: \"{BACKEND_START}\"")));
    }

    #[test]
    fn the_manual_steps_carry_the_app_id() {
        let repo = monorepo();
        let plan = repo.install(&[]);
        for line in [
            "STEP [pending:qa] backend-qa-web-lockfile — Commit the web lockfile",
            "STEP [pending:qa] front-qa-web-lockfile — Commit the web lockfile",
        ] {
            assert!(plan.lines().any(|l| l == line), "{line}\n{plan}");
        }
        assert!(
            plan.lines()
                .any(|l| l.contains(":qa] backend-qa-api-reported — CI reports backend-qa-api on ")),
            "{plan}"
        );
        assert!(!plan.contains("] qa-web-lockfile"), "{plan}");
    }

    /// `monorepo()` with `front`'s answers replaced by `extra` on top of the rest.
    fn front_answers(repo: &Repo, extra: serde_json::Value) {
        let mut answers = json!({"apps": ["backend", "front"],
               "apps.backend.api": true, "apps.backend.api_start": BACKEND_START,
               "apps.backend.web": "seeded", "apps.backend.web_start": BACKEND_START,
               "apps.backend.web_url": "http://127.0.0.1:8080",
               "apps.front.api": false,
               "apps.front.web": "seeded", "apps.front.web_start": "npm run dev"});
        for (key, value) in extra.as_object().unwrap() {
            answers[key] = value.clone();
        }
        repo.answer(QA, answers);
    }

    /// #1211: a TypeScript app's `tsconfig.json` compiles seeds written inside
    /// the app; its `web_dir` may leave the app while it stays in the repository.
    #[test]
    fn an_app_web_dir_may_leave_the_app_and_its_seeds_land_outside_it() {
        let repo = monorepo();
        front_answers(&repo, json!({"apps.front.web_dir": "../../qa/front-web"}));
        let plan = repo.install(&["--apply"]);
        for name in ["package.json", "playwright.config.ts", "smoke.spec.ts"] {
            assert!(
                plan.lines()
                    .any(|l| l == format!("WRITE qa/front-web/{name} [seed:qa]")),
                "{name}\n{plan}"
            );
            assert!(repo.root.join("qa/front-web").join(name).is_file());
        }
        assert!(!repo.root.join("apps/front/qa").exists(), "{plan}");
        assert!(
            plan.lines()
                .any(|l| l == "STEP [pending:qa] front-qa-web-lockfile — Commit the web lockfile"),
            "{plan}"
        );
        let text = repo.read(WORKFLOW);
        assert!(
            text.contains("            qa/front-web/*-snapshots/**\n"),
            "{text}"
        );
        let blocks = job_blocks(&text);
        let web = job(&blocks, "front-qa-web").join("\n");
        for line in [
            "    name: front-qa-web",
            // Its tests lie outside the app: a change to them alone must run it.
            "    if: needs.scope.outputs.tier != 'docs'",
            "        working-directory: \"qa/front-web\"",
            "            qa/front-web/playwright-report/",
        ] {
            assert!(web.lines().any(|l| l == line), "{line}\n{web}");
        }
        assert_eq!(
            scope_env(&text, "APP_JOBS"),
            ["backend-qa-api=backend", "backend-qa-web=backend"]
        );
        let again = repo.ok(&["install", "<repo>"]);
        assert!(again.lines().any(|l| l == "No changes."), "{again}");
    }

    #[test]
    fn an_app_web_dir_that_leaves_the_repository_or_climbs_midway_refuses() {
        let repo = monorepo();
        for dir in ["../../../qa/web", "qa/../../web", "../../.."] {
            front_answers(&repo, json!({"apps.front.web_dir": dir}));
            let mut args = vec!["install", "<repo>"];
            for id in super::REQUIREMENTS.iter().chain([&QA]) {
                args.extend(["--module", id]);
            }
            let out = repo.cli(&args);
            assert!(!out.status.success(), "{dir}: {out:?}");
            assert_eq!(
                String::from_utf8_lossy(&out.stderr).trim(),
                format!(
                    "REFUSED: qa: apps.front.web_dir {dir} is not a relative path inside the repository"
                )
            );
        }
    }

    #[test]
    fn two_targets_seeding_one_web_directory_refuse() {
        let repo = monorepo();
        front_answers(&repo, json!({"apps.front.web_dir": "../backend/qa/web"}));
        let mut args = vec!["install", "<repo>"];
        for id in super::REQUIREMENTS.iter().chain([&QA]) {
            args.extend(["--module", id]);
        }
        let out = repo.cli(&args);
        assert!(!out.status.success(), "{out:?}");
        assert_eq!(
            String::from_utf8_lossy(&out.stderr).trim(),
            "REFUSED: qa: apps.backend.web_dir and apps.front.web_dir both seed apps/backend/qa/web; give each target its own web directory"
        );
    }

    #[test]
    fn seeds_under_a_tsconfig_are_noted_and_seeds_outside_it_are_not() {
        let repo = monorepo();
        repo.write("apps/front/tsconfig.json", "{\"include\": [\"**/*.ts\"]}\n");
        let plan = repo.install(&[]);
        assert!(
            plan.lines().any(|l| l
                == "NOTE [qa] apps.front.web_dir apps/front/qa/web lies under apps/front/tsconfig.json, which may type-check the Playwright seeds; exclude apps/front/qa/web there or answer apps.front.web_dir outside it"),
            "{plan}"
        );
        assert!(
            !plan.contains("apps.backend.web_dir apps/backend"),
            "{plan}"
        );
        front_answers(&repo, json!({"apps.front.web_dir": "../../qa/front-web"}));
        let plan = repo.install(&[]);
        assert!(!plan.contains("may type-check"), "{plan}");
    }

    /// A contributor taking `backend-qa-api`.
    struct Squatter;
    impl Module for Squatter {
        fn id(&self) -> &'static str {
            "fixture"
        }
        fn version(&self) -> &'static str {
            "1.0.0"
        }
        fn render(&self, _: &Context<'_>) -> Result<Vec<Rendered>> {
            Ok(Vec::new())
        }
        fn ci_jobs(&self, _: &Context<'_>) -> Vec<CiJob> {
            vec![CiJob {
                id: "backend-qa-api".to_owned(),
                yaml: "name: backend-qa-api\nneeds: scope\nruns-on: ubuntu-24.04\ntimeout-minutes: 5\nsteps:\n  - name: Echo\n    run: echo\n".to_owned(),
                skippable_under: Vec::new(),
                app: None,
            }]
        }
    }

    #[test]
    fn a_contributor_taking_an_app_qa_id_collides_with_qa() {
        let repo = monorepo();
        let profile = profile_for(&repo.root).unwrap();
        let modules: [&dyn Module; 5] = [&SetupCore, &StackPacks, &Qa, &Squatter, &CiBaseline];
        let error = engine::plan(&repo.root, &Source::embedded(), &profile, &modules, &|_| {
            true
        })
        .unwrap_err()
        .to_string();
        assert_eq!(
            error,
            "Module fixture contributes CI job backend-qa-api, which collides with module qa"
        );
    }
}

// ---- the three uses of a .hurl file: QaFiles and hurl_command (T18, #1017) ----------

mod files {
    use super::QA;
    use super::resolved::load_cx;
    use brakes::modules::qa::files::{QaFiles, files, hurl_command};
    use serde_json::json;

    #[test]
    fn the_root_target_gives_one_entry_and_the_shared_command() {
        load_cx(json!({"api": true, "api_start": "run"}), &[], |cx| {
            let found = files(cx).unwrap();
            assert_eq!(
                found,
                [QaFiles {
                    app: None,
                    dir: "qa".to_owned(),
                    ready: "qa/api/00-ready.hurl".to_owned(),
                    glob: "qa/api/**/*.hurl".to_owned(),
                    ready_timeout: 600,
                }]
            );
            let command = hurl_command(&found[0], "QA_API_URL").unwrap();
            assert_eq!(command.env, [("QA_DIR".to_owned(), "qa".to_owned())]);
            assert_eq!(
                command.ready,
                "hurl --test --jobs 1 --retry 600 --retry-interval 1000 --max-time 20 --variable base_url=\"$QA_API_URL\" \"$QA_DIR/api/00-ready.hurl\""
            );
            assert_eq!(
                command.run,
                "hurl --test --max-time 20 --variable base_url=\"$QA_API_URL\" --report-junit \"$RUNNER_TEMP/qa/hurl-junit.xml\" --glob \"$QA_DIR/api/**/*.hurl\""
            );
        });
    }

    #[test]
    fn a_consumer_renders_the_same_flags_with_its_own_base_url() {
        // delivery's post-deploy smoke, as a fake consumer would render it.
        load_cx(json!({"api": true, "api_start": "run"}), &[], |cx| {
            let smoke = hurl_command(&files(cx).unwrap()[0], "DEPLOY_URL").unwrap();
            assert_eq!(
                smoke.run,
                "hurl --test --max-time 20 --variable base_url=\"$DEPLOY_URL\" --report-junit \"$RUNNER_TEMP/qa/hurl-junit.xml\" --glob \"$QA_DIR/api/**/*.hurl\""
            );
            assert!(smoke.ready.contains("base_url=\"$DEPLOY_URL\""));
            assert!(!smoke.run.contains("http"), "no host in the command");
        });
    }

    #[test]
    fn a_base_url_variable_must_be_an_environment_name() {
        load_cx(json!({"api": true, "api_start": "run"}), &[], |cx| {
            let found = files(cx).unwrap();
            assert_eq!(
                hurl_command(&found[0], "https://example.com")
                    .unwrap_err()
                    .to_string(),
                "qa: hurl_command needs an environment variable name for base_url, got https://example.com"
            );
        });
    }

    #[test]
    fn without_api_or_without_qa_files_refuses() {
        load_cx(json!({"api": false}), &[], |cx| {
            assert_eq!(
                files(cx).unwrap_err().to_string(),
                "qa: no target has api: true, so there are no .hurl files to run"
            );
        });
        load_cx(json!({"api": true, "api_start": "run"}), &["qa"], |cx| {
            assert_eq!(
                files(cx).unwrap_err().to_string(),
                "qa is not active in this plan; install it with --module qa before reading its .hurl files"
            );
        });
    }

    #[test]
    fn a_monorepo_gives_one_entry_per_app_with_an_api() {
        let answers = json!({"apps": ["api"], "apps.api.api": true, "apps.api.api_start": "run"});
        super::resolved::load_cx_with_api_app(answers, |cx| {
            let found = files(cx).unwrap();
            assert_eq!(
                found,
                [QaFiles {
                    app: Some("api".to_owned()),
                    dir: "api/qa".to_owned(),
                    ready: "api/qa/api/00-ready.hurl".to_owned(),
                    glob: "api/qa/api/**/*.hurl".to_owned(),
                    ready_timeout: 600,
                }]
            );
            assert_eq!(
                hurl_command(&found[0], "UPTIME_URL").unwrap().env,
                [("QA_DIR".to_owned(), "api/qa".to_owned())]
            );
        });
    }

    #[test]
    fn qa_is_the_module_these_files_belong_to() {
        assert_eq!(QA, "qa");
    }
}

// ---- contract answers and their derivation (T17, #1016) ---------------------------

mod contract_answers {
    use super::{QA, Repo};
    use serde_json::json;

    const OPENAPI: &str = "openapi: 3.1.0\ninfo:\n  title: Shop\n  version: 1.0.0\npaths: {}\n";
    const ASYNCAPI: &str = "asyncapi: 3.0.0\ninfo:\n  title: Events\n  version: 1.0.0\n";

    /// A single-app repository with `qa` answered `api: false` plus `answers`.
    fn repo(answers: serde_json::Value) -> Repo {
        let repo = Repo::single();
        let mut all = json!({"api": false});
        all.as_object_mut()
            .unwrap()
            .extend(answers.as_object().unwrap().clone());
        repo.answer(QA, all);
        repo
    }

    fn notes(repo: &Repo) -> Vec<String> {
        repo.install(&[])
            .lines()
            .filter(|l| l.starts_with("NOTE [qa] "))
            .map(str::to_owned)
            .collect()
    }

    fn refusal(repo: &Repo, answers: serde_json::Value) -> String {
        let mut all = json!({"api": false});
        all.as_object_mut()
            .unwrap()
            .extend(answers.as_object().unwrap().clone());
        repo.refusal(all)
    }

    #[test]
    fn the_only_openapi_document_is_derived_even_under_docs() {
        let repo = repo(json!({}));
        repo.write("docs/openapi.yaml", OPENAPI);
        assert_eq!(
            notes(&repo),
            ["NOTE [qa] openapi docs/openapi.yaml (derived: the only OpenAPI document)"]
        );
    }

    #[test]
    fn a_json_contract_and_an_asyncapi_document_are_derived() {
        let repo = repo(json!({}));
        repo.write(
            "api/openapi.json",
            "{\n  \"openapi\": \"3.0.3\",\n  \"info\": {\"title\": \"x\", \"version\": \"1\"},\n  \"paths\": {}\n}\n",
        );
        repo.write("events/asyncapi.yml", &format!("# events\n---\n{ASYNCAPI}"));
        assert_eq!(
            notes(&repo),
            [
                "NOTE [qa] openapi api/openapi.json (derived: the only OpenAPI document)",
                "NOTE [qa] asyncapi events/asyncapi.yml (derived: the only AsyncAPI document)",
            ]
        );
    }

    #[test]
    fn no_contract_derives_nothing_and_two_derive_none_with_a_note() {
        let repo = repo(json!({}));
        assert!(notes(&repo).is_empty());
        repo.write("a/openapi.yaml", OPENAPI);
        repo.write("b/openapi.yaml", OPENAPI);
        assert_eq!(
            notes(&repo),
            [
                "NOTE [qa] openapi: several documents (a/openapi.yaml, b/openapi.yaml); answer openapi with the live contracts, separated by commas"
            ]
        );
    }

    #[test]
    fn swagger_2_is_never_derived_and_refuses_when_answered() {
        let repo = repo(json!({}));
        repo.write("swagger.yaml", "swagger: \"2.0\"\ninfo:\n  title: old\n");
        assert_eq!(
            notes(&repo),
            ["NOTE [qa] swagger.yaml is Swagger 2.0; oasdiff compares OpenAPI 3 only"]
        );
        assert_eq!(
            refusal(&repo, json!({"openapi": "swagger.yaml"})),
            "REFUSED: qa: openapi swagger.yaml is Swagger 2.0; convert it to OpenAPI 3 or leave openapi unset"
        );
    }

    #[test]
    fn skipped_directories_and_depth_hide_a_document() {
        let repo = repo(json!({}));
        for dir in [
            "node_modules/x",
            "vendor",
            "target",
            "dist",
            "build",
            "qa",
            ".git/x",
            "a/b/c/d/e",
        ] {
            repo.write(&format!("{dir}/openapi.yaml"), OPENAPI);
        }
        assert!(notes(&repo).is_empty(), "{:?}", notes(&repo));
        repo.write("a/b/c/d/openapi.yaml", OPENAPI);
        assert_eq!(
            notes(&repo),
            ["NOTE [qa] openapi a/b/c/d/openapi.yaml (derived: the only OpenAPI document)"]
        );
    }

    #[test]
    fn an_answer_wins_and_none_switches_the_derivation_off() {
        let repo = repo(json!({}));
        repo.write("a/openapi.yaml", OPENAPI);
        repo.write("b/openapi.yaml", OPENAPI);
        repo.answer(QA, json!({"api": false, "openapi": "b/openapi.yaml"}));
        assert!(notes(&repo).is_empty(), "{:?}", notes(&repo));
        repo.answer(QA, json!({"api": false, "openapi": "none"}));
        assert!(notes(&repo).is_empty(), "{:?}", notes(&repo));
    }

    #[test]
    fn a_path_that_is_not_a_contract_file_in_the_repository_refuses() {
        let repo = repo(json!({}));
        repo.write("notes.txt", "openapi: 3.1.0\n");
        for (id, path) in [
            ("openapi", "/etc/openapi.yaml"),
            ("openapi", "../openapi.yaml"),
            ("openapi", "missing.yaml"),
            ("openapi", "notes.txt"),
            ("asyncapi", "missing.json"),
        ] {
            assert_eq!(
                refusal(&repo, json!({id: path})),
                format!("REFUSED: qa: {id} {path} is not a contract file in the repository"),
                "{id} {path}"
            );
        }
    }

    #[test]
    fn every_contract_and_the_ruleset_are_never_touch() {
        let repo = repo(json!({}));
        repo.write("docs/openapi.yaml", OPENAPI);
        repo.write("events/asyncapi.yaml", ASYNCAPI);
        repo.write(".spectral.yaml", "extends: [[spectral:oas, recommended]]\n");
        repo.install(&["--apply"]);
        let lock: serde_json::Value =
            serde_json::from_str(&repo.read(".agent-setup/lock.json")).unwrap();
        for path in [
            "docs/openapi.yaml",
            "events/asyncapi.yaml",
            ".spectral.yaml",
        ] {
            assert_eq!(lock["files"][path]["module"], QA, "{path}");
            assert_eq!(lock["files"][path]["class"], "never-touch", "{path}");
        }
    }

    #[test]
    fn the_spectral_ruleset_is_derived_only_when_one_exists() {
        let repo = repo(json!({}));
        repo.write("openapi.yaml", OPENAPI);
        repo.write(".spectral.yaml", "extends: [[spectral:oas, recommended]]\n");
        assert_eq!(
            notes(&repo),
            [
                "NOTE [qa] openapi openapi.yaml (derived: the only OpenAPI document)",
                "NOTE [qa] contract_ruleset .spectral.yaml (derived: the only Spectral ruleset at the root)",
            ]
        );
        repo.write(".spectral.json", "{}\n");
        assert_eq!(
            notes(&repo),
            ["NOTE [qa] openapi openapi.yaml (derived: the only OpenAPI document)"]
        );
        assert_eq!(
            refusal(&repo, json!({"contract_ruleset": "missing.yaml"})),
            "REFUSED: qa: contract_ruleset missing.yaml is not a contract file in the repository"
        );
    }
}

// ---- qa-contracts through ci_jobs (T17, #1016) ------------------------------------

mod contracts_job {
    use super::api_job::{WORKFLOW, golden, job, job_blocks};
    use super::{QA, Repo};
    use crate::support::SetupCore;
    use brakes::engine::{self, CiJob, Context, Module, Rendered};
    use brakes::modules::qa::Qa;
    use brakes::modules::qa::jobs::QA_CONTRACTS;
    use brakes::modules::{CiBaseline, StackPacks};
    use brakes::{Result, Source, profile_for};
    use serde_json::json;

    const OPENAPI: &str = "openapi: 3.1.0\ninfo:\n  title: Shop\n  version: 1.0.0\npaths: {}\n";
    const ASYNCAPI: &str = "asyncapi: 3.0.0\ninfo:\n  title: Events\n  version: 1.0.0\n";

    /// A single-app repository with `qa` answered `api: false` and the
    /// contracts `files` names.
    fn repo(files: &[(&str, &str)]) -> Repo {
        let repo = Repo::single();
        repo.answer(QA, json!({"api": false}));
        for (path, text) in files {
            repo.write(path, text);
        }
        repo
    }

    fn workflow_of(repo: &Repo) -> String {
        let plan = repo.install(&["--apply"]);
        assert!(
            plan.lines()
                .any(|l| l == format!("NOTE [ci-baseline] JOB [qa] {QA_CONTRACTS} → {WORKFLOW}")),
            "{plan}"
        );
        repo.read(WORKFLOW)
    }

    fn contracts(text: &str) -> String {
        job(&job_blocks(text), QA_CONTRACTS).join("\n")
    }

    #[test]
    fn an_openapi_contract_matches_its_golden() {
        let repo = repo(&[("docs/openapi.yaml", OPENAPI)]);
        let text = workflow_of(&repo);
        golden("contracts-openapi.yml", &text);
        let again = repo.ok(&["install", "<repo>"]);
        assert!(again.lines().any(|l| l == "No changes."), "{again}");
    }

    #[test]
    fn an_asyncapi_contract_matches_its_golden() {
        let repo = repo(&[("events/asyncapi.yaml", ASYNCAPI)]);
        golden("contracts-asyncapi.yml", &workflow_of(&repo));
    }

    #[test]
    fn both_contracts_and_a_ruleset_match_their_golden() {
        let repo = repo(&[
            ("docs/openapi.yaml", OPENAPI),
            ("events/asyncapi.yaml", ASYNCAPI),
            (".spectral.yaml", "extends: [[spectral:oas, recommended]]\n"),
        ]);
        golden("contracts-both.yml", &workflow_of(&repo));
    }

    #[test]
    fn qa_contracts_reaches_required_and_is_never_skippable_by_tier() {
        let text = workflow_of(&repo(&[("docs/openapi.yaml", OPENAPI)]));
        let blocks = job_blocks(&text);
        let ids: Vec<&str> = blocks.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "scope",
                "checks",
                "heldout",
                "workflow-lint",
                QA_CONTRACTS,
                "required"
            ]
        );
        assert!(
            job(&blocks, "required").contains(
                &"    needs: [scope, checks, heldout, workflow-lint, qa-contracts]".to_owned()
            ),
            "{text}"
        );
        // Only the built-ins `checks` and `heldout` (#1362), never qa-contracts.
        let scope = job(&blocks, "scope").join("\n");
        assert!(
            scope.contains(
                "          DOCS_SKIPPABLE: |-\n            checks\n            heldout\n          "
            ),
            "{scope}"
        );
        let c = job(&blocks, QA_CONTRACTS);
        assert!(!c.iter().any(|l| l.starts_with("    if:")), "{c:#?}");
        for line in [
            "    needs: scope",
            "    timeout-minutes: 10",
            "          fetch-depth: \"2\"",
            "          persist-credentials: \"false\"",
            "          retention-days: \"7\"",
        ] {
            assert!(c.contains(&line.to_owned()), "{line}\n{c:#?}");
        }
        assert!(!c.iter().any(|l| l.trim_start().starts_with("permissions:")));
    }

    #[test]
    fn compatibility_runs_on_pull_requests_with_the_labels_and_lint_always() {
        let text = workflow_of(&repo(&[("docs/openapi.yaml", OPENAPI)]));
        let c = contracts(&text);
        assert!(
            c.contains("      - name: Compare the contracts with the base\n        if: github.event_name == 'pull_request'\n"),
            "{c}"
        );
        assert!(
            c.contains(
                "          PR_LABELS: \"${{ toJSON(github.event.pull_request.labels.*.name) }}\""
            ),
            "{c}"
        );
        assert!(
            c.contains("      - name: Lint the contracts\n        env:\n"),
            "{c}"
        );
        assert!(
            c.contains("          QA_OPENAPI: \"docs/openapi.yaml\""),
            "{c}"
        );
        assert!(
            c.contains("      - name: Upload the contracts report\n        if: always()\n"),
            "{c}"
        );
        // The tools by checksum, never a marketplace action; no network read of the base.
        for tool in ["vacuum", "oasdiff"] {
            assert!(
                c.contains(&format!("          TOOL_NAME: \"{tool}\"")),
                "{tool}"
            );
        }
        for forbidden in [
            "oasdiff-action",
            "spectral-action",
            "--fetch",
            "continue-on-error",
            "|| true",
        ] {
            assert!(!c.contains(forbidden), "{forbidden}");
        }
        for line in text
            .lines()
            .filter(|l| l.trim_start().starts_with("uses: "))
        {
            let sha = line
                .split_once('@')
                .map(|(_, r)| r)
                .unwrap_or("")
                .split(' ')
                .next()
                .unwrap();
            assert!(
                sha.len() == 40 && sha.chars().all(|c| c.is_ascii_hexdigit()),
                "{line}"
            );
        }
    }

    #[test]
    fn the_asyncapi_cli_is_installed_at_its_exact_version_without_scripts() {
        let c = contracts(&workflow_of(&repo(&[("events/asyncapi.yaml", ASYNCAPI)])));
        assert!(c.contains("npm install --prefix \"$RUNNER_TEMP/qa/asyncapi-cli\" --ignore-scripts --no-audit --no-fund \"@asyncapi/cli@$QA_ASYNCAPI_CLI\""), "{c}");
        assert!(c.contains("          QA_ASYNCAPI_CLI: \"6.2.1\""), "{c}");
        assert!(c.contains("          node-version: \"24\""), "{c}");
        assert!(!c.contains("TOOL_NAME: \"vacuum\""), "{c}");
        assert!(!c.contains("npx "), "{c}");
    }

    #[test]
    fn without_a_contract_no_job_is_contributed() {
        let repo = repo(&[]);
        repo.install(&["--apply"]);
        assert!(!repo.read(WORKFLOW).contains(QA_CONTRACTS));
    }

    /// A contributor whose single job takes the id `qa-contracts`.
    struct Squatter;
    impl Module for Squatter {
        fn id(&self) -> &'static str {
            "fixture"
        }
        fn version(&self) -> &'static str {
            "1.0.0"
        }
        fn render(&self, _: &Context<'_>) -> Result<Vec<Rendered>> {
            Ok(Vec::new())
        }
        fn ci_jobs(&self, _: &Context<'_>) -> Vec<CiJob> {
            vec![CiJob {
                id: QA_CONTRACTS.to_owned(),
                yaml: "name: qa-contracts\nneeds: scope\nruns-on: ubuntu-24.04\ntimeout-minutes: 5\nsteps:\n  - name: Echo\n    run: echo\n".to_owned(),
                skippable_under: Vec::new(),
                app: None,
            }]
        }
    }

    #[test]
    fn a_contributor_taking_qa_contracts_collides_with_qa() {
        let repo = repo(&[("docs/openapi.yaml", OPENAPI)]);
        let profile = profile_for(&repo.root).unwrap();
        let modules: [&dyn Module; 5] = [&SetupCore, &StackPacks, &Qa, &Squatter, &CiBaseline];
        let error = engine::plan(&repo.root, &Source::embedded(), &profile, &modules, &|_| {
            true
        })
        .unwrap_err()
        .to_string();
        assert_eq!(
            error,
            "Module fixture contributes CI job qa-contracts, which collides with module qa"
        );
    }

    #[test]
    fn under_workflow_existing_qa_contracts_joins_agentic_required() {
        const OWN: &str = ".github/workflows/orchestration.yml";
        const OWN_YML: &str = "name: Orchestration\non:\n  pull_request:\npermissions:\n  contents: read\njobs:\n  rust:\n    name: Rust (linux)\n    runs-on: ubuntu-24.04\n    timeout-minutes: 10\n    steps:\n      - name: Verify\n        run: echo verify\n";
        const SEPARATE: &str = ".github/workflows/agentic-security.yml";
        let repo = repo(&[("docs/openapi.yaml", OPENAPI)]);
        repo.write(OWN, OWN_YML);
        repo.answer(
            "ci-baseline",
            json!({"workflow": "existing", "aggregate_check": "Rust (linux)"}),
        );
        repo.install(&["--apply"]);
        let text = repo.read(SEPARATE);
        let blocks = job_blocks(&text);
        assert!(
            job(&blocks, "agentic-required")
                .contains(&"    needs: [scope, qa-contracts]".to_owned()),
            "{text}"
        );
        assert_eq!(repo.read(OWN), OWN_YML);
    }
}

#[test]
fn the_guide_explains_contracts_bundling_and_the_label() {
    let guide = include_str!("../../../templates/qa/qa.md");
    let section = guide
        .split_once("\n## Contracts\n")
        .expect("a Contracts section")
        .1;
    for needle in [
        "vacuum bundle",
        "$ref",
        "human-approved",
        "openapi",
        "asyncapi",
        "HEAD^1",
    ] {
        assert!(section.contains(needle), "{needle}");
    }
}

// ---- per-app contracts in monorepos (#1115) -----------------------------------------

mod app_contracts {
    use super::{QA, Repo};
    use serde_json::json;

    const OPENAPI: &str = "openapi: 3.1.0\ninfo:\n  title: Shop\n  version: 1.0.0\npaths: {}\n";

    /// The two-app repository (root and `api`), `api` listed, no API or web.
    fn repo() -> Repo {
        let repo = Repo::new();
        repo.answer(
            QA,
            json!({"api": false, "apps": ["api"], "apps.api.api": false}),
        );
        repo
    }

    fn notes(repo: &Repo) -> Vec<String> {
        repo.install(&[])
            .lines()
            .filter(|l| l.starts_with("NOTE [qa] "))
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn an_app_contract_is_derived_relative_to_the_app_and_not_at_the_root() {
        let repo = repo();
        repo.write("api/docs/openapi.yaml", OPENAPI);
        assert_eq!(
            notes(&repo),
            ["NOTE [qa] apps.api.openapi docs/openapi.yaml (derived: the only OpenAPI document)"]
        );
    }

    #[test]
    fn an_app_answer_refuses_naming_its_key() {
        let repo = repo();
        repo.answer(
            QA,
            json!({"api": false, "apps": ["api"], "apps.api.api": false,
                   "apps.api.openapi": "missing.yaml"}),
        );
        let out = repo.cli(&[
            "install",
            "<repo>",
            "--module",
            "stack-packs",
            "--module",
            "ci-baseline",
            "--module",
            QA,
        ]);
        assert!(!out.status.success(), "{out:?}");
        assert_eq!(
            String::from_utf8_lossy(&out.stderr).trim(),
            "REFUSED: qa: apps.api.openapi missing.yaml is not a contract file in the repository"
        );
    }

    #[test]
    fn the_schema_has_the_per_app_contract_patterns_and_the_contract_is_never_touch() {
        use brakes::engine::Module;
        let schema = brakes::modules::qa::Qa.questions();
        for id in [
            "apps.*.openapi",
            "apps.*.asyncapi",
            "apps.*.contract_ruleset",
        ] {
            assert!(schema.questions.iter().any(|q| q.id == id), "{id}");
        }
        let repo = repo();
        repo.write("api/openapi.yaml", OPENAPI);
        repo.install(&["--apply"]);
        let lock: serde_json::Value =
            serde_json::from_str(&repo.read(".agent-setup/lock.json")).unwrap();
        assert_eq!(lock["files"]["api/openapi.yaml"]["class"], "never-touch");
    }
}

mod app_contracts_job {
    use super::api_job::{WORKFLOW, golden, job, job_blocks};
    use super::{QA, Repo};
    use serde_json::json;

    const OPENAPI: &str = "openapi: 3.1.0\ninfo:\n  title: Shop\n  version: 1.0.0\npaths: {}\n";
    const ASYNCAPI: &str = "asyncapi: 3.0.0\ninfo:\n  title: Events\n  version: 1.0.0\n";

    /// Two apps under `apps/`: `shop` (rust) with an OpenAPI contract and a
    /// ruleset, `events` (node) with an AsyncAPI one; no API or web job.
    fn monorepo() -> Repo {
        let repo = Repo::single().without_root_commands();
        repo.write("apps/shop/Cargo.toml", "");
        repo.write("apps/shop/Cargo.lock", "");
        repo.write(
            "apps/shop/.agent-setup/project.json",
            r#"{"commands": {"test": "cargo test --locked"}}"#,
        );
        repo.write("apps/shop/docs/openapi.yaml", OPENAPI);
        repo.write(
            "apps/shop/.spectral.yaml",
            "extends: [[spectral:oas, recommended]]\n",
        );
        repo.write("apps/events/package.json", "{\"private\": true}\n");
        repo.write("apps/events/package-lock.json", "{}\n");
        repo.write(
            "apps/events/.agent-setup/project.json",
            r#"{"commands": {"test": "npm test"}}"#,
        );
        repo.write("apps/events/asyncapi.yaml", ASYNCAPI);
        repo.answer(
            "stack-packs",
            json!({"apps.shop.path": "apps/shop", "apps.shop.stack": "rust",
                   "apps.shop.container": false,
                   "apps.events.path": "apps/events", "apps.events.stack": "node",
                   "apps.events.container": false, "apps.events.toolchain": false}),
        );
        repo.answer(
            QA,
            json!({"apps": ["events", "shop"],
                   "apps.events.api": false, "apps.shop.api": false}),
        );
        repo
    }

    #[test]
    fn each_app_with_a_contract_gets_its_job_and_the_golden_matches() {
        let repo = monorepo();
        let plan = repo.install(&["--apply"]);
        for id in ["events-qa-contracts", "shop-qa-contracts"] {
            assert!(
                plan.lines()
                    .any(|l| l == format!("NOTE [ci-baseline] JOB [qa] {id} → {WORKFLOW}")),
                "{id}\n{plan}"
            );
        }
        assert!(!plan.contains("JOB [qa] qa-contracts"), "{plan}");
        let text = repo.read(WORKFLOW);
        golden("contracts-monorepo.yml", &text);
        let required = job(&job_blocks(&text), "required").join("\n");
        assert!(
            required.contains("events-qa-contracts, shop-qa-contracts]"),
            "{required}"
        );
        let again = repo.ok(&["install", "<repo>"]);
        assert!(again.lines().any(|l| l == "No changes."), "{again}");
    }

    #[test]
    fn an_app_contracts_job_skips_only_with_its_unchanged_app_and_runs_from_it() {
        let repo = monorepo();
        repo.install(&["--apply"]);
        let text = repo.read(WORKFLOW);
        let blocks = job_blocks(&text);
        let shop = job(&blocks, "shop-qa-contracts").join("\n");
        for line in [
            "    name: shop-qa-contracts",
            "    if: contains(fromJSON(needs.scope.outputs.skippable), 'shop-qa-contracts') == false",
            "        working-directory: \"apps/shop\"",
            "          QA_OPENAPI: \"docs/openapi.yaml\"",
            "          QA_CONTRACT_RULESET: \".spectral.yaml\"",
            "          name: shop-qa-contracts",
        ] {
            assert!(shop.lines().any(|l| l == line), "{line}\n{shop}");
        }
        assert_eq!(
            shop.matches("        working-directory: \"apps/shop\"")
                .count(),
            2,
            "lint and compare run from the app"
        );
        let events = job(&blocks, "events-qa-contracts").join("\n");
        assert!(
            events.contains("          QA_ASYNCAPI: \"asyncapi.yaml\""),
            "{events}"
        );
        // Never in the docs list: only the app's own change flag skips it.
        let scope = job(&blocks, "scope").join("\n");
        let docs = scope.split_once("DOCS_SKIPPABLE:").unwrap().1;
        let docs = docs.split_once("EVENT:").unwrap().0;
        assert!(!docs.contains("qa-contracts"), "{docs}");
        assert!(scope.contains("shop-qa-contracts=shop"), "{scope}");
    }
}

// ---- several contracts per target (#1182) ------------------------------------------

mod several_contracts {
    use super::api_job::{WORKFLOW, golden, job, job_blocks};
    use super::{QA, Repo};
    use brakes::modules::qa::jobs::QA_CONTRACTS;
    use serde_json::json;

    const OPENAPI: &str = "{\"openapi\": \"3.1.0\", \"info\": {\"title\": \"x\", \"version\": \"1\"}, \"paths\": {}}\n";
    const ASYNCAPI: &str = "asyncapi: 3.0.0\ninfo:\n  title: Events\n  version: 1.0.0\n";
    const LIVE_A: &str = "contratos/ventas/openapi.json";
    const LIVE_B: &str = "contratos/precios/openapi.json";
    const PUBLISHED_A: &str = "contratos/ventas/publicado/v1.openapi.json";
    const PUBLISHED_B: &str = "contratos/precios/publicado/v1.openapi.json";

    /// A two-domain shape: two live contracts and their frozen published copies.
    fn repo() -> Repo {
        let repo = Repo::single();
        for path in [LIVE_A, LIVE_B, PUBLISHED_A, PUBLISHED_B] {
            repo.write(path, OPENAPI);
        }
        repo
    }

    fn with(answers: serde_json::Value) -> serde_json::Value {
        let mut all = json!({"api": false});
        all.as_object_mut()
            .unwrap()
            .extend(answers.as_object().unwrap().clone());
        all
    }

    fn lists() -> String {
        format!("{LIVE_A},{LIVE_B}")
    }

    fn pairs() -> String {
        format!("{LIVE_A}={PUBLISHED_A},{LIVE_B}={PUBLISHED_B}")
    }

    fn notes(repo: &Repo) -> Vec<String> {
        repo.install(&[])
            .lines()
            .filter(|l| l.starts_with("NOTE [qa] "))
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn several_documents_note_asks_for_the_live_contracts() {
        let repo = repo();
        repo.answer(QA, with(json!({})));
        assert_eq!(
            notes(&repo),
            [format!(
                "NOTE [qa] openapi: several documents ({LIVE_B}, {PUBLISHED_B}, {LIVE_A}, {PUBLISHED_A}); answer openapi with the live contracts, separated by commas"
            )]
        );
    }

    #[test]
    fn declared_published_copies_are_left_out_of_the_derivation() {
        let repo = Repo::single();
        repo.write(LIVE_A, OPENAPI);
        repo.write(PUBLISHED_A, OPENAPI);
        repo.answer(
            QA,
            with(json!({"contract_published": format!("{LIVE_A}={PUBLISHED_A}")})),
        );
        assert_eq!(
            notes(&repo),
            [format!(
                "NOTE [qa] openapi {LIVE_A} (derived: the only OpenAPI document)"
            )]
        );
    }

    #[test]
    fn every_listed_contract_and_published_copy_is_checked_and_never_touch() {
        let repo = repo();
        repo.answer(
            QA,
            with(json!({"openapi": lists(), "contract_published": pairs()})),
        );
        repo.install(&["--apply"]);
        let text = repo.read(WORKFLOW);
        golden("contracts-several.yml", &text);
        let c = job(&job_blocks(&text), QA_CONTRACTS).join("\n");
        assert!(
            c.contains(&format!("          QA_OPENAPI: \"{}\"", lists())),
            "{c}"
        );
        assert!(
            c.contains(&format!("          QA_PUBLISHED: \"{}\"", pairs())),
            "{c}"
        );
        let lock: serde_json::Value =
            serde_json::from_str(&repo.read(".agent-setup/lock.json")).unwrap();
        for path in [LIVE_A, LIVE_B, PUBLISHED_A, PUBLISHED_B] {
            assert_eq!(lock["files"][path]["class"], "never-touch", "{path}");
        }
    }

    #[test]
    fn a_declared_compatibility_command_renders_lint_only() {
        let repo = repo();
        repo.answer("ci-baseline", json!({"commands": ["test"]}));
        repo.answer(
            QA,
            with(json!({"openapi": lists(), "contract_published": pairs(), "contract_compat_by": "test"})),
        );
        repo.install(&["--apply"]);
        let text = repo.read(WORKFLOW);
        let c = job(&job_blocks(&text), QA_CONTRACTS).join("\n");
        assert!(c.contains("Lint the contracts"), "{c}");
        assert!(!c.contains("Compare the contracts"), "{c}");
        assert!(!c.contains("Install oasdiff"), "{c}");
        assert!(c.contains("Install vacuum"), "{c}");
    }

    #[test]
    fn lists_and_pairs_refuse_what_they_cannot_mean() {
        let repo = repo();
        repo.write("events/asyncapi.yaml", ASYNCAPI);
        let refused = |answers: serde_json::Value| repo.refusal(with(answers));
        assert_eq!(
            refused(json!({"openapi": format!("{LIVE_A},{LIVE_A}")})),
            format!("REFUSED: qa: openapi lists {LIVE_A} twice")
        );
        assert_eq!(
            refused(json!({"openapi": format!("{LIVE_A},missing.json")})),
            "REFUSED: qa: openapi missing.json is not a contract file in the repository"
        );
        assert_eq!(
            refused(json!({"openapi": LIVE_A, "contract_published": LIVE_A})),
            format!("REFUSED: qa: contract_published {LIVE_A} is not live=published")
        );
        assert_eq!(
            refused(
                json!({"openapi": LIVE_A, "contract_published": format!("{LIVE_B}={PUBLISHED_B}")})
            ),
            format!(
                "REFUSED: qa: contract_published {LIVE_B}={PUBLISHED_B} names {LIVE_B}, which openapi and asyncapi do not list"
            )
        );
        assert_eq!(
            refused(
                json!({"openapi": LIVE_A, "contract_published": format!("{LIVE_A}=missing.json")})
            ),
            format!(
                "REFUSED: qa: contract_published {LIVE_A}=missing.json names missing.json, which is not a contract file in the repository"
            )
        );
        assert_eq!(
            refused(
                json!({"openapi": LIVE_A, "contract_published": format!("{LIVE_A}=events/asyncapi.yaml")})
            ),
            format!(
                "REFUSED: qa: contract_published {LIVE_A}=events/asyncapi.yaml names events/asyncapi.yaml, which is not an OpenAPI document"
            )
        );
        assert_eq!(
            refused(
                json!({"openapi": lists(), "contract_published": format!("{LIVE_A}={LIVE_B}")})
            ),
            format!(
                "REFUSED: qa: contract_published {LIVE_A}={LIVE_B} names {LIVE_B} as a live contract too"
            )
        );
    }

    #[test]
    fn a_compatibility_command_must_be_one_required_runs() {
        let repo = repo();
        let refused =
            |by: &str| repo.refusal(with(json!({"openapi": LIVE_A, "contract_compat_by": by})));
        // The profile declares test only; ci-baseline derives its commands unless answered.
        assert_eq!(
            refused("verify"),
            "REFUSED: qa: contract_compat_by verify is not a command required runs: .agent-setup/project.json does not declare commands.verify"
        );
        assert_eq!(
            refused("test"),
            "REFUSED: qa: contract_compat_by test is not a command required runs: ci-baseline does not answer commands with test"
        );
        repo.answer(
            "ci-baseline",
            json!({"commands": ["test"], "workflow": "existing"}),
        );
        assert_eq!(
            refused("test"),
            "REFUSED: qa: contract_compat_by test is not a command required runs: ci-baseline's workflow is existing"
        );
        repo.answer(
            "ci-baseline",
            json!({"commands": ["test"], "inert_paths": ["contratos/**"]}),
        );
        assert_eq!(
            refused("test"),
            format!(
                "REFUSED: qa: contract_compat_by test is not a command required runs: {LIVE_A} is an inert path of ci-baseline, so a pull request changing only it skips checks"
            )
        );
        repo.answer("ci-baseline", json!({"commands": ["test"]}));
        repo.answer(
            QA,
            with(json!({"openapi": LIVE_A, "contract_compat_by": "test"})),
        );
        repo.install(&[]);
    }
}
