//! `brakes mcp` (SPEC-questions.md, MCP server; #727, #729): the fixture
//! suite under `tests/fixtures/mcp/`, run against the binary over stdio one line
//! at a time, as a client talks to it. Each fixture line is `{"send": <message>}`
//! (or `"send_raw": <text>`) with `"expect"`: the next frame (a response, or a
//! request the server sends, such as `elicitation/create`), or `null` when none
//! may come. An expected object matches when every key it names matches (a
//! subset); arrays match element by element and in length. Placeholders:
//! `$VERSION`, `$TOKEN` (22 base64url characters), `$REFUSED` (any `REFUSED: `
//! text), `$TEXT` (any non-empty string) and `$LINES` (a non-empty array of
//! strings) in expectations; `$REPO`, `$SECOND`, `$OTHER` and `$PLAN_TOKEN` (the
//! token the last `plan` returned) in what is sent. On every fixture, stdout
//! carries nothing but frames and never the `.env` sentinel.
//!
//! The elicitation rounds of `plan` run in-process against modules written for
//! the test, with a scripted client (`Server::with_modules`).
use serde_json::{Value, json};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const SENTINEL: &str = "MCP_ENV_SENTINEL_d41d8cd9";

fn git(root: &Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?}");
}

/// A personal repository with a Rust app, a hand-written workflow, a `.env`
/// carrying the sentinel and an ignored directory with its own Cargo files;
/// and, beside it, a repository whose origin names another owner.
struct Repos {
    _temp: tempfile::TempDir,
    repo: PathBuf,
    second: PathBuf,
    other: PathBuf,
}

fn repos() -> Repos {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("project");
    fs::create_dir(&repo).unwrap();
    git(&repo, &["init", "-q"]);
    git(
        &repo,
        &[
            "remote",
            "add",
            "origin",
            "git@github.com:example-owner/demo.git",
        ],
    );
    fs::write(
        repo.join("Cargo.toml"),
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    fs::write(repo.join("Cargo.lock"), "version = 4\n").unwrap();
    fs::create_dir_all(repo.join(".github/workflows")).unwrap();
    fs::write(repo.join(".github/workflows/build.yml"), "on: push\n").unwrap();
    fs::write(repo.join(".env"), format!("TOKEN={SENTINEL}\n")).unwrap();
    fs::write(repo.join(".gitignore"), "ignored/\n.env\n").unwrap();
    fs::create_dir(repo.join("ignored")).unwrap();
    fs::write(repo.join("ignored/Cargo.toml"), "[package]\nname = \"x\"\n").unwrap();
    fs::write(repo.join("ignored/Cargo.lock"), "version = 4\n").unwrap();
    let other = temp.path().join("other");
    fs::create_dir(&other).unwrap();
    git(&other, &["init", "-q"]);
    git(
        &other,
        &[
            "remote",
            "add",
            "origin",
            "git@github.com:someone-else/demo.git",
        ],
    );
    let second = temp.path().join("second");
    fs::create_dir(&second).unwrap();
    git(&second, &["init", "-q"]);
    git(
        &second,
        &[
            "remote",
            "add",
            "origin",
            "git@github.com:example-owner/second.git",
        ],
    );
    Repos {
        _temp: temp,
        repo,
        second,
        other,
    }
}

/// The fixture placeholders a line sends: `$REPO`, `$SECOND`, `$OTHER` and
/// `$PLAN_TOKEN` (the token of the last `plan` result), anywhere in a string.
fn substitute(value: &Value, repos: &Repos, token: &str) -> Value {
    match value {
        Value::String(s) => json!(
            s.replace("$PLAN_TOKEN", token)
                .replace("$SECOND", &repos.second.to_string_lossy())
                .replace("$OTHER", &repos.other.to_string_lossy())
                .replace("$REPO", &repos.repo.to_string_lossy())
        ),
        Value::Array(items) => {
            Value::Array(items.iter().map(|v| substitute(v, repos, token)).collect())
        }
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), substitute(v, repos, token)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn token_shaped(text: &str) -> bool {
    text.len() == 22
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// `actual` matches `expected` as the module doc says; the error names the path.
fn matches(expected: &Value, actual: &Value, at: &str) -> Result<(), String> {
    let fail = || Err(format!("at {at}: expected {expected}, got {actual}"));
    let check = |ok: bool| if ok { Ok(()) } else { fail() };
    match (expected, actual) {
        (Value::String(e), Value::String(a)) if e == "$VERSION" => {
            check(a == include_str!("../../../VERSION").trim())
        }
        (Value::String(e), Value::String(a)) if e == "$TOKEN" => check(token_shaped(a)),
        // The Linux runner the configuration names: the default `runner` answer
        // comes from it, so a fixture carries no value (product-boundary T6d).
        (Value::String(e), Value::String(a)) if e == "$RUNNER" => {
            check(brakes::config::linux_runner().is_some_and(|runner| *a == runner.name))
        }
        (Value::String(e), Value::String(a)) if e == "$REFUSED" => {
            check(a.starts_with("REFUSED: "))
        }
        (Value::String(e), Value::String(a)) if e == "$TEXT" => check(!a.is_empty()),
        (Value::String(e), Value::Array(a)) if e == "$LINES" => {
            check(!a.is_empty() && a.iter().all(Value::is_string))
        }
        (Value::Object(e), Value::Object(a)) => {
            for (key, value) in e {
                let Some(found) = a.get(key) else {
                    return Err(format!("at {at}: missing key `{key}` in {actual}"));
                };
                matches(value, found, &format!("{at}.{key}"))?;
            }
            Ok(())
        }
        (Value::Array(e), Value::Array(a)) => {
            if e.len() != a.len() {
                return fail();
            }
            for (index, (e, a)) in e.iter().zip(a).enumerate() {
                matches(e, a, &format!("{at}[{index}]"))?;
            }
            Ok(())
        }
        _ if expected == actual => Ok(()),
        _ => fail(),
    }
}

/// One frame: a JSON-RPC 2.0 response (exactly one of `result` and `error`)
/// or a request the server sends (a `method` and an `id`).
fn frame(line: &str) -> Value {
    let frame: Value = serde_json::from_str(line)
        .unwrap_or_else(|e| panic!("stdout line is not a frame ({e}): {line}"));
    assert_eq!(frame["jsonrpc"], "2.0", "{line}");
    assert!(frame.get("id").is_some(), "{line}");
    let response = frame.get("result").is_some() != frame.get("error").is_some();
    let request = frame.get("method").is_some()
        && frame.get("result").is_none()
        && frame.get("error").is_none();
    assert!(response || request, "{line}");
    frame
}

/// Every stdout line is one frame.
fn frames(stdout: &str) -> Vec<Value> {
    assert!(stdout.is_empty() || stdout.ends_with('\n'));
    stdout.lines().map(frame).collect()
}

/// Runs the binary with `lines` on stdin; returns stdout and stderr.
fn serve(lines: &[String]) -> (String, String) {
    let mut session = Session::start();
    for line in lines {
        session.send(line);
    }
    session.finish()
}

/// `brakes mcp` driven one line at a time, the way a client talks to it:
/// a request, then the frames it answers with, before the next line is sent.
struct Session {
    child: std::process::Child,
    stdin: Option<std::process::ChildStdin>,
    stdout: BufReader<std::process::ChildStdout>,
    seen: String,
}

impl Session {
    fn start() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_brakes"))
            .arg("mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Self {
            child,
            stdin,
            stdout,
            seen: String::new(),
        }
    }
    fn send(&mut self, line: &str) {
        let stdin = self.stdin.as_mut().unwrap();
        writeln!(stdin, "{line}").unwrap();
        stdin.flush().unwrap();
    }
    /// The next frame on stdout; panics when stdout closes first.
    fn frame(&mut self) -> Value {
        let mut line = String::new();
        let read = self.stdout.read_line(&mut line).unwrap();
        assert!(read > 0 && line.ends_with('\n'), "stdout closed: {line}");
        self.seen.push_str(&line);
        frame(line.trim_end())
    }
    /// Sends `message` and returns the frame it gets back.
    fn ask(&mut self, message: &Value) -> Value {
        self.send(&message.to_string());
        self.frame()
    }
    /// Closes stdin, waits for exit 0 and returns all of stdout and stderr.
    fn finish(mut self) -> (String, String) {
        drop(self.stdin.take());
        let mut rest = String::new();
        self.stdout.read_to_string(&mut rest).unwrap();
        let output = self.child.wait_with_output().unwrap();
        assert!(output.status.success(), "mcp exits 0 when stdin closes");
        self.seen.push_str(&rest);
        (self.seen, String::from_utf8(output.stderr).unwrap())
    }
}

fn run_fixture(name: &str) {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("tests/fixtures/mcp/{name}.jsonl"));
    let text = fs::read_to_string(&path).unwrap();
    let repos = repos();
    let mut session = Session::start();
    let mut token = String::new();
    let mut answered = 0;
    for (index, line) in text.lines().filter(|l| !l.trim().is_empty()).enumerate() {
        let case: Value = serde_json::from_str(line).unwrap();
        session.send(&match (&case["send"], &case["send_raw"]) {
            (Value::Null, Value::String(raw)) => raw.clone(),
            (send, _) => substitute(send, &repos, &token).to_string(),
        });
        if case["expect"].is_null() {
            continue;
        }
        let frame = session.frame();
        answered += 1;
        if let Some(t) = frame["result"]["structuredContent"]["confirmation_token"].as_str() {
            token = t.to_owned();
        }
        let expected = substitute(&case["expect"], &repos, &token);
        if let Err(error) = matches(&expected, &frame, "$") {
            panic!("{name}, line {}: {error}", index + 1);
        }
    }
    let (stdout, _) = session.finish();
    assert!(
        !stdout.contains(SENTINEL),
        "{name}: the .env sentinel left on stdout"
    );
    assert_eq!(
        frames(&stdout).len(),
        answered,
        "{name}: one frame per expectation, none left over\n{stdout}"
    );
}

/// Fixtures whose expected frames name `setup-core`: they run with the
/// feature only (product-boundary T7a).
macro_rules! setup_core_fixtures {
    ($($name:ident),* $(,)?) => {$(
        #[test]
        #[cfg_attr(
            not(feature = "setup-core"),
            ignore = "lists setup-core; product-boundary T7a"
        )]
        fn $name() {
            run_fixture(stringify!($name));
        }
    )*};
}

// One fixture per line, as `every_fixture_file_has_a_test` reads them.
#[rustfmt::skip]
setup_core_fixtures!(
    list_modules,
);

macro_rules! fixtures {
    ($($name:ident),* $(,)?) => {$(
        #[test]
        fn $name() {
            run_fixture(stringify!($name));
        }
    )*};
}

fixtures!(
    initialize_2025_11_25,
    initialize_2025_06_18,
    initialize_unsupported_version,
    tools_list,
    get_questions,
    propose_answers,
    plan,
    apply_without_elicitation,
    apply_url_only_elicitation,
    apply_confirmed,
    apply_2025_06_18,
    apply_declined,
    apply_cancelled,
    apply_stale_token,
    unknown_method,
    invalid_params,
    out_of_scope_repo,
    second_repository,
);

#[test]
fn every_fixture_file_has_a_test() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/mcp");
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            e.unwrap()
                .path()
                .file_stem()
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    let source = include_str!("mcp_server.rs");
    for name in names {
        assert!(
            source.contains(&format!("    {name},\n")),
            "fixture {name} is not run"
        );
    }
}

fn call(id: u64, name: &str, arguments: Value) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
           "params": {"name": name, "arguments": arguments}})
    .to_string()
}

#[test]
fn propose_answers_twice_is_identical_and_never_shows_the_env_file_or_an_ignored_path() {
    let repos = repos();
    let repo = repos.repo.to_string_lossy().into_owned();
    let mut lines = Vec::new();
    for module in ["stack-packs", "ci-baseline", "repo-baseline", "security"] {
        for id in 0..2 {
            lines.push(call(
                id,
                "propose_answers",
                json!({"module": module, "repo": repo}),
            ));
        }
    }
    let (stdout, _) = serve(&lines);
    let frames = frames(&stdout);
    assert_eq!(frames.len(), 8);
    for pair in frames.chunks(2) {
        assert_eq!(pair[0]["result"], pair[1]["result"]);
        assert_eq!(pair[0]["result"]["isError"], false, "{}", pair[0]);
    }
    assert!(!stdout.contains(SENTINEL));
    assert!(!stdout.contains(".env"), "{stdout}");
    assert!(
        !stdout.contains("ignored"),
        "an ignored path is never evidence: {stdout}"
    );
}

#[test]
fn plan_prints_the_answers_file_line_and_binds_its_token_to_the_answers() {
    let repos = repos();
    let repo = repos.repo.to_string_lossy().into_owned();
    let plan = |id, approvals: &str| {
        call(
            id,
            "plan",
            json!({"module": "repo-baseline", "repo": repo, "answers": {"approvals": approvals}}),
        )
    };
    let (stdout, _) = serve(&[
        plan(1, "checks-only"),
        plan(2, "checks-only"),
        plan(3, "checks-only-owner-bypass"),
    ]);
    let frames = frames(&stdout);
    let result = |i: usize| &frames[i]["result"]["structuredContent"];
    let lines: Vec<&str> = result(0)["lines"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l.as_str().unwrap())
        .collect();
    assert!(
        lines.contains(&"PLAN .agent-setup/modules/repo-baseline.json [answers:repo-baseline]"),
        "{lines:?}"
    );
    assert!(result(0)["steps"].is_array());
    assert_eq!(
        result(0)["confirmation_token"],
        result(1)["confirmation_token"],
        "the same plan in one session carries the same token"
    );
    assert_ne!(
        result(0)["confirmation_token"],
        result(2)["confirmation_token"],
        "another answer is another token"
    );
    assert!(
        !repos.repo.join(".agent-setup").exists(),
        "plan writes nothing"
    );
}

#[test]
fn the_token_is_drawn_per_process() {
    let repos = repos();
    let repo = repos.repo.to_string_lossy().into_owned();
    let line = call(
        1,
        "plan",
        json!({"module": "repo-baseline", "repo": repo, "answers": {}}),
    );
    let token = |stdout: String| {
        frames(&stdout)[0]["result"]["structuredContent"]["confirmation_token"].clone()
    };
    assert_ne!(
        token(serve(std::slice::from_ref(&line)).0),
        token(serve(&[line]).0)
    );
}

#[test]
fn mcp_takes_no_argument() {
    let output = Command::new(env!("CARGO_BIN_EXE_brakes"))
        .args(["mcp", "/tmp"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "REFUSED: Usage: brakes mcp (no argument; MCP over stdio)\n"
    );
}

// ---- apply: token plus the elicitation confirmation (#729) -------------------

fn initialize(capabilities: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": 0, "method": "initialize",
           "params": {"protocolVersion": "2025-11-25", "capabilities": capabilities,
                      "clientInfo": {"name": "test", "version": "1"}}})
}

fn tool(id: u64, name: &str, arguments: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
           "params": {"name": name, "arguments": arguments}})
}

fn reply(id: &Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

/// Every file under `root` but `.git`, by relative path.
fn tree(root: &Path) -> std::collections::BTreeMap<String, Vec<u8>> {
    fn walk(root: &Path, dir: &Path, out: &mut std::collections::BTreeMap<String, Vec<u8>>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.file_name().unwrap() == ".git" {
                continue;
            }
            if path.is_dir() {
                walk(root, &path, out);
            } else {
                let name = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                out.insert(name, fs::read(&path).unwrap());
            }
        }
    }
    let mut out = std::collections::BTreeMap::new();
    walk(root, root, &mut out);
    out
}

/// `plan` then `apply` with its token on `repo`; returns the elicitation request
/// the apply sent, the session still waiting for the client's answer.
fn plan_then_apply(session: &mut Session, repo: &str, approvals: &str) -> Value {
    let answers = json!({"approvals": approvals});
    assert_eq!(
        session.ask(&initialize(json!({"elicitation": {}})))["result"]["protocolVersion"],
        "2025-11-25"
    );
    let planned = session.ask(&tool(
        1,
        "plan",
        json!({"module": "repo-baseline", "repo": repo, "answers": answers}),
    ));
    let token = planned["result"]["structuredContent"]["confirmation_token"].clone();
    let request = session.ask(&tool(
        2,
        "apply",
        json!({"module": "repo-baseline", "repo": repo, "answers": answers,
               "confirmation_token": token}),
    ));
    assert_eq!(request["method"], "elicitation/create", "{request}");
    request
}

#[test]
fn apply_confirmed_in_the_client_writes_exactly_what_configure_set_apply_writes() {
    let over_mcp = repos();
    let by_cli = repos();
    let repo = over_mcp.repo.to_string_lossy().into_owned();
    let mut session = Session::start();
    let request = plan_then_apply(&mut session, &repo, "checks-only");
    let message = request["params"]["message"].as_str().unwrap();
    let canonical = fs::canonicalize(&over_mcp.repo).unwrap();
    assert!(
        message.starts_with(&format!(
            "brakes: apply this plan for repo-baseline to {}? ",
            canonical.display()
        )),
        "{message}"
    );
    let summary = message.lines().next().unwrap();
    assert!(
        summary.contains(" writes, 3 seeds, ") && summary.contains(" steps, token "),
        "{summary}"
    );
    assert!(
        message.contains("\nPLAN .github/rulesets/main.json [managed:repo-baseline]"),
        "the plan lines follow the summary: {message}"
    );
    let applied = session.ask(&reply(
        &request["id"],
        json!({"action": "accept", "content": {"confirm": true}}),
    ));
    assert_eq!(applied["result"]["isError"], false, "{applied}");
    let lines = applied["result"]["structuredContent"]["lines"]
        .as_array()
        .unwrap();
    assert!(lines.contains(&json!(
        "WRITE .agent-setup/modules/repo-baseline.json [answers:repo-baseline]"
    )));
    session.finish();

    let output = Command::new(env!("CARGO_BIN_EXE_brakes"))
        .arg("configure")
        .arg(&by_cli.repo)
        .args(["repo-baseline", "--set", "approvals=checks-only", "--apply"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(tree(&over_mcp.repo), tree(&by_cli.repo));
}

#[test]
fn decline_cancel_and_an_unchecked_confirm_leave_the_repository_untouched() {
    for answer in [
        json!({"action": "decline"}),
        json!({"action": "cancel"}),
        json!({"action": "accept", "content": {"confirm": false}}),
        json!({"action": "accept", "content": {}}),
    ] {
        let repos = repos();
        let before = tree(&repos.repo);
        let mut session = Session::start();
        let request = plan_then_apply(&mut session, &repos.repo.to_string_lossy(), "checks-only");
        let refused = session.ask(&reply(&request["id"], answer.clone()));
        assert_eq!(refused["result"]["isError"], true, "{answer}: {refused}");
        session.finish();
        assert_eq!(tree(&repos.repo), before, "{answer}");
    }
}

#[test]
fn a_file_changed_after_plan_invalidates_the_token() {
    let repos = repos();
    let repo = repos.repo.to_string_lossy().into_owned();
    let answers = json!({"approvals": "checks-only"});
    let mut session = Session::start();
    session.ask(&initialize(json!({"elicitation": {}})));
    let planned = session.ask(&tool(
        1,
        "plan",
        json!({"module": "repo-baseline", "repo": repo, "answers": answers}),
    ));
    let token = planned["result"]["structuredContent"]["confirmation_token"].clone();
    fs::write(repos.repo.join(".github/SECURITY.md"), "# Ours\n").unwrap();
    let before = tree(&repos.repo);
    let refused = session.ask(&tool(
        2,
        "apply",
        json!({"module": "repo-baseline", "repo": repo, "answers": answers,
               "confirmation_token": token}),
    ));
    assert_eq!(
        refused["result"]["content"][0]["text"],
        "REFUSED: the confirmation token does not match the plan for these answers in this repository; call plan again and review it"
    );
    session.finish();
    assert_eq!(tree(&repos.repo), before);
}

// ---- elicitation during plan, in-process (#729) -----------------------------

use brakes::Source;
use brakes::engine::answers::Schema;
use brakes::engine::{Context, ManualStep, Module, Rendered};
use brakes::mcp::{Client, Server};
use brakes::questions::configure_new;
use std::collections::VecDeque;

/// Two groups, a `when` across them, an enum with a plan-dependency note, an
/// array of enum and an ungrouped question; nothing required has a default.
struct Order;
impl Module for Order {
    fn id(&self) -> &'static str {
        "order"
    }
    fn version(&self) -> &'static str {
        "1.0.0"
    }
    fn questions(&self) -> Schema {
        Schema::parse(&json!([
            {"id": "size", "type": "string", "enum": ["small", "large"], "required": true,
             "description": "The cup size.",
             "x-ui": {"label": "Size", "group": "Cup", "help": "Large needs the big cups."},
             "x-plan-dependency": {"feature": "big-cups", "values": ["large"]}},
            {"id": "scoops", "type": "integer", "minimum": 1, "maximum": 4, "required": true,
             "description": "How many scoops.", "x-ui": {"label": "Scoops", "group": "Cup"}},
            {"id": "delivery", "type": "boolean", "required": true,
             "description": "Deliver the order.", "x-ui": {"group": "Cup"}},
            {"id": "address", "type": "string", "minLength": 3, "maxLength": 40, "required": true,
             "when": "delivery", "description": "Where to deliver.",
             "x-ui": {"label": "Address", "group": "Delivery"}},
            {"id": "toppings", "type": "array",
             "items": {"type": "string", "enum": ["sprinkles", "nuts"]},
             "minItems": 1, "maxItems": 2, "required": true, "description": "What goes on top."},
        ]))
        .unwrap()
    }
    fn render(&self, cx: &Context<'_>) -> brakes::Result<Vec<Rendered>> {
        Ok(vec![Rendered {
            path: "docs/agent-setup/order.json".to_owned(),
            class: brakes::engine::Ownership::Managed,
            content: Some(serde_json::to_string(cx.answers)? + "\n"),
            scaffold: None,
        }])
    }
}

/// No question; a manual step whose probe asks whether a secret exists.
struct Vault;
impl Module for Vault {
    fn id(&self) -> &'static str {
        "vault"
    }
    fn version(&self) -> &'static str {
        "1.0.0"
    }
    fn render(&self, _: &Context<'_>) -> brakes::Result<Vec<Rendered>> {
        Ok(Vec::new())
    }
    fn manual_steps(&self, _: &Context<'_>) -> Vec<ManualStep> {
        vec![configure_new::secret_exists("DEPLOY_KEY", "production")]
    }
}

/// A client whose human answers from a script; it records what it was asked.
#[derive(Default)]
struct Scripted {
    answers: VecDeque<Value>,
    asked: Vec<Value>,
}
impl Client for Scripted {
    fn request(&mut self, method: &str, params: Value) -> Option<Result<Value, Value>> {
        assert_eq!(method, "elicitation/create");
        self.asked.push(params);
        self.answers.pop_front().map(Ok)
    }
}

fn source() -> Source {
    Source {
        documents: std::collections::BTreeMap::new(),
        version: "0.1.0".to_owned(),
        revision: None,
        dirty: false,
    }
}

/// A server over `Order` and `Vault`, initialized at `version` with
/// `capabilities`, and the `plan` result for `answers` on `repo`.
fn plan_in_process(
    version: &str,
    capabilities: Value,
    repo: &Path,
    module: &str,
    answers: Value,
    client: &mut Scripted,
) -> Value {
    let mut server = Server::with_modules(vec![&Order, &Vault], source());
    let mut log = Vec::new();
    let init = json!({"jsonrpc": "2.0", "id": 0, "method": "initialize",
        "params": {"protocolVersion": version, "capabilities": capabilities,
                   "clientInfo": {"name": "test", "version": "1"}}});
    server.handle(&init.to_string(), client, &mut log).unwrap();
    let call = tool(
        1,
        "plan",
        json!({"module": module, "repo": repo.to_string_lossy(), "answers": answers}),
    );
    server.handle(&call.to_string(), client, &mut log).unwrap()["result"].clone()
}

fn accept(content: Value) -> Value {
    json!({"action": "accept", "content": content})
}

fn text(result: &Value) -> &str {
    result["content"][0]["text"].as_str().unwrap()
}

#[test]
fn plan_elicits_one_group_at_a_time_in_order_and_when_resolves_between_groups() {
    let repos = repos();
    let mut client = Scripted {
        answers: VecDeque::from([
            accept(json!({"size": "large", "scoops": 2, "delivery": true})),
            accept(json!({"address": "Main Street 1"})),
            accept(json!({"toppings": ["nuts"]})),
        ]),
        ..Scripted::default()
    };
    let result = plan_in_process(
        "2025-11-25",
        json!({"elicitation": {}}),
        &repos.repo,
        "order",
        json!({}),
        &mut client,
    );
    assert_eq!(result["isError"], false, "{result}");
    assert_eq!(
        result["structuredContent"]["answers"],
        json!({"size": "large", "scoops": 2, "delivery": true,
               "address": "Main Street 1", "toppings": ["nuts"]})
    );
    assert_eq!(client.asked.len(), 3);
    assert_eq!(
        client.asked[0],
        json!({"mode": "form", "message": "brakes: order needs answers (Cup).",
            "requestedSchema": {"type": "object", "properties": {
                "size": {"type": "string", "title": "Size", "description": "Large needs the big cups.",
                         "enum": ["small", "large"],
                         "enumNames": ["small", "large  (needs GitHub feature big-cups: not checked)"]},
                "scoops": {"type": "integer", "title": "Scoops", "description": "How many scoops.",
                           "minimum": 1, "maximum": 4},
                "delivery": {"type": "boolean", "title": "delivery", "description": "Deliver the order."}},
            "required": ["size", "scoops", "delivery"]}})
    );
    assert_eq!(
        client.asked[1]["requestedSchema"]["properties"],
        json!({"address": {"type": "string", "title": "Address", "description": "Where to deliver.",
                           "minLength": 3, "maxLength": 40}})
    );
    assert_eq!(
        client.asked[2]["requestedSchema"]["properties"],
        json!({"toppings": {"type": "array", "title": "toppings", "description": "What goes on top.",
                            "items": {"type": "string", "enum": ["sprinkles", "nuts"]},
                            "minItems": 1, "maxItems": 2}})
    );
    assert!(
        !repos.repo.join(".agent-setup").exists(),
        "plan writes nothing"
    );
}

#[test]
fn a_gated_question_whose_when_fails_is_never_elicited() {
    let repos = repos();
    let mut client = Scripted {
        answers: VecDeque::from([accept(
            json!({"size": "small", "scoops": 1, "delivery": false}),
        )]),
        ..Scripted::default()
    };
    let result = plan_in_process(
        "2025-11-25",
        json!({"elicitation": {}}),
        &repos.repo,
        "order",
        json!({"toppings": ["sprinkles"]}),
        &mut client,
    );
    assert_eq!(result["isError"], false, "{result}");
    assert_eq!(client.asked.len(), 1);
}

#[test]
fn an_invalid_answer_is_elicited_again_with_the_engine_message_at_most_three_rounds() {
    let repos = repos();
    let mut client = Scripted {
        answers: VecDeque::from([
            accept(json!({"address": "x"})),
            accept(json!({"address": "Main Street 1"})),
        ]),
        ..Scripted::default()
    };
    let answers = json!({"size": "small", "scoops": 1, "delivery": true, "toppings": ["nuts"]});
    let result = plan_in_process(
        "2025-11-25",
        json!({"elicitation": {}}),
        &repos.repo,
        "order",
        answers.clone(),
        &mut client,
    );
    assert_eq!(result["isError"], false, "{result}");
    assert_eq!(client.asked.len(), 2);
    assert_eq!(
        client.asked[1]["requestedSchema"]["properties"]["address"]["description"],
        "Module order: answer `address` must have at least 3 characters. Where to deliver."
    );

    let mut client = Scripted {
        answers: VecDeque::from(vec![accept(json!({"address": "x"})); 4]),
        ..Scripted::default()
    };
    let result = plan_in_process(
        "2025-11-25",
        json!({"elicitation": {}}),
        &repos.repo,
        "order",
        answers,
        &mut client,
    );
    assert_eq!(client.asked.len(), 3, "three rounds, then the error");
    assert_eq!(result["isError"], true);
    assert_eq!(
        text(&result),
        "REFUSED: Module order: answer `address` must have at least 3 characters"
    );
}

#[test]
fn decline_returns_the_missing_ids_and_cancel_records_nothing() {
    let repos = repos();
    let mut client = Scripted {
        answers: VecDeque::from([json!({"action": "decline"})]),
        ..Scripted::default()
    };
    let result = plan_in_process(
        "2025-11-25",
        json!({"elicitation": {}}),
        &repos.repo,
        "order",
        json!({"scoops": 1}),
        &mut client,
    );
    assert_eq!(result["isError"], true);
    assert_eq!(
        text(&result),
        "REFUSED: Module order: no answer for size, delivery, toppings; pass them in `answers`"
    );

    let mut client = Scripted {
        answers: VecDeque::from([json!({"action": "cancel"})]),
        ..Scripted::default()
    };
    let result = plan_in_process(
        "2025-11-25",
        json!({"elicitation": {}}),
        &repos.repo,
        "order",
        json!({}),
        &mut client,
    );
    assert_eq!(result["isError"], true);
    assert_eq!(text(&result), "Cancelled by the user; nothing recorded.");
    assert!(!repos.repo.join(".agent-setup").exists());
}

#[test]
fn a_client_without_elicitation_gets_the_missing_ids() {
    let repos = repos();
    let mut client = Scripted::default();
    let result = plan_in_process(
        "2025-11-25",
        json!({}),
        &repos.repo,
        "order",
        json!({"size": "small"}),
        &mut client,
    );
    assert!(client.asked.is_empty());
    assert_eq!(
        text(&result),
        "REFUSED: Module order: no answer for scoops, delivery, toppings; pass them in `answers`"
    );
}

#[test]
fn an_array_of_enum_needs_a_2025_11_25_client_or_an_explicit_answer() {
    let repos = repos();
    let mut client = Scripted::default();
    let result = plan_in_process(
        "2025-06-18",
        json!({"elicitation": {}}),
        &repos.repo,
        "order",
        json!({"size": "small", "scoops": 1, "delivery": false}),
        &mut client,
    );
    assert!(client.asked.is_empty(), "{:?}", client.asked);
    assert_eq!(
        text(&result),
        "REFUSED: Module order: question toppings needs a 2025-11-25 client or an explicit answer"
    );

    // Under 2025-06-18 the request carries no `mode`.
    let mut client = Scripted {
        answers: VecDeque::from([accept(json!({"scoops": 3}))]),
        ..Scripted::default()
    };
    let result = plan_in_process(
        "2025-06-18",
        json!({"elicitation": {}}),
        &repos.repo,
        "order",
        json!({"size": "small", "delivery": false, "toppings": ["nuts"]}),
        &mut client,
    );
    assert_eq!(result["isError"], false, "{result}");
    assert!(client.asked[0].get("mode").is_none(), "{}", client.asked[0]);
}

#[test]
fn a_module_with_a_secret_exists_step_returns_the_step_and_no_prompt() {
    let repos = repos();
    let mut client = Scripted::default();
    let result = plan_in_process(
        "2025-11-25",
        json!({"elicitation": {}}),
        &repos.repo,
        "vault",
        json!({}),
        &mut client,
    );
    assert_eq!(result["isError"], false, "{result}");
    assert!(client.asked.is_empty());
    let steps = result["structuredContent"]["steps"].as_array().unwrap();
    assert!(
        steps
            .iter()
            .any(|s| s["id"] == "secret-exists-deploy-key" && s["module"] == "vault"),
        "{steps:?}"
    );
}
