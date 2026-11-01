//! The credential proxy of agent-guardrails (`templates/agent-guardrails/model-proxy.py`),
//! run as it runs on a runner: `python3` reads the real token on stdin, listens on
//! 127.0.0.1 and forwards to its fixed upstream. Here the upstream is a local fake: the
//! harness swaps `http.client.HTTPSConnection` for a plain connection to the fake that
//! also reports which host the proxy asked for, and changes nothing in the template.
//! Every case sends real HTTP to the proxy and asserts what it answers and what reached
//! the fake: it forwards only what the pinned Claude Code CLI and Codex were measured to
//! send, with the runner's credential, and refuses the rest before any byte reaches the
//! API. A broken copy of the proxy fails these checks (the last test).
use std::{
    collections::BTreeMap,
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};
use tempfile::TempDir;

const MEASURED: &str = "claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,context-management-2025-06-27,per-turn-control-2026-07-01,mid-conversation-tool-changes-2026-07-01,thinking-token-count-2026-05-13,advanced-tool-use-2025-11-20,effort-2025-11-24,extended-cache-ttl-2025-04-11";
const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;
const VERDICT_SCHEMA: &str =
    include_str!("../../../templates/agent-guardrails/cross-review-schema.json");

fn template() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../templates/agent-guardrails/model-proxy.py")
}

/// One request the fake upstream received: method, target and headers (lower-cased names).
#[derive(Clone, Debug)]
struct Seen {
    method: String,
    target: String,
    headers: BTreeMap<String, String>,
}

/// A fake upstream on 127.0.0.1 that records every request and answers `200 {}`.
struct Upstream {
    port: u16,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Upstream {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let log = Arc::clone(&log);
                thread::spawn(move || {
                    if let Some(request) = read_request(&stream) {
                        log.lock().unwrap().push(request);
                    }
                    let mut stream = stream;
                    let _ = stream.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                    );
                    let _ = stream.shutdown(Shutdown::Both);
                });
            }
        });
        Self { port, seen }
    }
    fn take(&self) -> Vec<Seen> {
        std::mem::take(&mut *self.seen.lock().unwrap())
    }
}

/// Reads a request line, the headers and a `Content-Length` body.
fn read_request(stream: &TcpStream) -> Option<Seen> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let (method, target) = (parts.next()?.to_owned(), parts.next()?.to_owned());
    let mut headers = BTreeMap::new();
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).ok()?;
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        let (name, value) = header.split_once(':')?;
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
    }
    let length: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0; length];
    reader.read_exact(&mut body).ok()?;
    Some(Seen {
        method,
        target,
        headers,
    })
}

/// The proxy, started from `script` with `python3` for `provider`, its HTTPS upstream
/// replaced by `upstream`.
struct Proxy {
    child: Child,
    port: u16,
    _dir: TempDir,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

const HARNESS: &str = r#"
import http.client, importlib.util, sys
sys.dont_write_bytecode = True
script, port_file, provider, upstream_port = sys.argv[1:5]
extra = sys.argv[5:]
spec = importlib.util.spec_from_file_location("model_proxy", script)
proxy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proxy)

class Fake(http.client.HTTPConnection):
    def __init__(self, host, timeout=None):
        super().__init__("127.0.0.1", int(upstream_port), timeout=timeout)
        self.upstream = host
    def request(self, method, url, body=None, headers={}, **kwargs):
        headers = dict(headers)
        headers["X-Test-Upstream"] = self.upstream
        super().request(method, url, body=body, headers=headers, **kwargs)

http.client.HTTPSConnection = Fake
sys.argv = ["model-proxy.py", port_file, provider] + extra
proxy.main()
"#;

impl Proxy {
    fn start(script: &Path, provider: &str, token: &str, upstream: &Upstream) -> Self {
        Self::start_with(script, provider, token, upstream, &[])
    }

    /// `extra` follows the provider on the proxy's command line (the DeepInfra mode's
    /// schema file, #1144).
    fn start_with(
        script: &Path,
        provider: &str,
        token: &str,
        upstream: &Upstream,
        extra: &[&Path],
    ) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let port_file = dir.path().join("port");
        let mut child = Command::new("python3")
            .arg("-c")
            .arg(HARNESS)
            .arg(script)
            .arg(&port_file)
            .arg(provider)
            .arg(upstream.port.to_string())
            .args(extra)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("python3 runs the proxy template");
        writeln!(child.stdin.take().unwrap(), "{token}").unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let port = loop {
            if let Some(port) = fs::read_to_string(&port_file)
                .ok()
                .and_then(|t| t.trim().parse().ok())
            {
                break port;
            }
            assert!(Instant::now() < deadline, "the proxy did not start");
            thread::sleep(Duration::from_millis(20));
        };
        Self {
            child,
            port,
            _dir: dir,
        }
    }

    /// Sends one request and returns the status and the response body.
    fn send(
        &self,
        method: &str,
        target: &str,
        headers: &[(&str, String)],
        body: &[u8],
    ) -> (u16, String) {
        self.send_raw(method, target, headers, Some(body))
    }

    /// `body: None` sends the headers only (with whatever `Content-Length` they carry).
    fn send_raw(
        &self,
        method: &str,
        target: &str,
        headers: &[(&str, String)],
        body: Option<&[u8]>,
    ) -> (u16, String) {
        let mut stream = TcpStream::connect(("127.0.0.1", self.port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut head = format!(
            "{method} {target} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n",
            self.port
        );
        for (name, value) in headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        if let Some(body) = body
            && !headers
                .iter()
                .any(|(n, _)| n.eq_ignore_ascii_case("content-length"))
        {
            head.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        head.push_str("\r\n");
        stream.write_all(head.as_bytes()).unwrap();
        if let Some(body) = body {
            stream.write_all(body).unwrap();
        }
        let mut response = Vec::new();
        let _ = stream.read_to_end(&mut response);
        let text = String::from_utf8_lossy(&response).into_owned();
        let status = text
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let body = text
            .split_once("\r\n\r\n")
            .map_or("", |(_, b)| b)
            .to_owned();
        (status, body)
    }
}

fn anthropic_body(extra: serde_json::Value) -> Vec<u8> {
    let mut data = serde_json::json!({
        "model": "claude-sonnet-5-5",
        "max_tokens": 32000,
        "messages": [{"role": "user", "content": "hi"}],
        "tools": [{"name": "Read", "description": "read", "input_schema": {"type": "object"}}],
        "stream": true,
    });
    for (k, v) in extra.as_object().unwrap() {
        data[k] = v.clone();
    }
    data.to_string().into_bytes()
}

fn anthropic_headers(beta: &str) -> Vec<(&'static str, String)> {
    vec![
        ("Content-Type", "application/json".to_owned()),
        ("anthropic-version", "2023-06-01".to_owned()),
        ("anthropic-beta", beta.to_owned()),
        (
            "Authorization",
            "Bearer agent-model-holds-no-credential".to_owned(),
        ),
        ("x-api-key", "dummy".to_owned()),
    ]
}

fn responses_body(extra: serde_json::Value) -> Vec<u8> {
    let mut data = serde_json::json!({
        "client_metadata": {},
        "include": ["reasoning.encrypted_content"],
        "input": [{"role": "user", "content": "hi"}],
        "model": "gpt-6",
        "parallel_tool_calls": false,
        "prompt_cache_key": "k",
        "reasoning": {"effort": "medium"},
        "store": false,
        "stream": true,
        "text": {"format": {"type": "json_schema"}},
        "tool_choice": "auto",
    });
    for (k, v) in extra.as_object().unwrap() {
        data[k] = v.clone();
    }
    data.to_string().into_bytes()
}

fn openai_headers() -> Vec<(&'static str, String)> {
    vec![
        ("Authorization", "Bearer dummy".to_owned()),
        ("Content-Type", "application/json".to_owned()),
    ]
}

fn chat_body(extra: serde_json::Value) -> Vec<u8> {
    let mut data = serde_json::json!({
        "max_tokens": 32000,
        "messages": [{"role": "system", "content": "s"}, {"role": "user", "content": "hi"}],
        "model": "deepseek-ai/DeepSeek-V4-Pro",
        "stream": true,
        "stream_options": {"include_usage": true},
        "tool_choice": "auto",
        "tools": [{"type": "function", "function": {"name": "read", "parameters": {"type": "object"}}}],
    });
    for (k, v) in extra.as_object().unwrap() {
        data[k] = v.clone();
    }
    data.to_string().into_bytes()
}

fn chat_headers() -> Vec<(&'static str, String)> {
    vec![
        (
            "Authorization",
            "Bearer agent-model-holds-no-credential".to_owned(),
        ),
        ("Content-Type", "application/json".to_owned()),
        ("x-opencode-session-id", "ses_1".to_owned()),
    ]
}

/// Checks over a proxy started from `script`; each returns the broken expectations.
struct Checks<'a> {
    script: &'a Path,
    failures: Vec<String>,
}

impl<'a> Checks<'a> {
    fn new(script: &'a Path) -> Self {
        Self {
            script,
            failures: Vec::new(),
        }
    }
    fn expect(&mut self, ok: bool, what: impl Into<String>) {
        if !ok {
            self.failures.push(what.into());
        }
    }
    /// A request the proxy must refuse with `status`, saying "refused", forwarding nothing.
    fn refused(
        &mut self,
        proxy: &Proxy,
        upstream: &Upstream,
        status: u16,
        case: &str,
        sent: (u16, String),
    ) {
        let reached = upstream.take();
        self.expect(
            sent.0 == status,
            format!("{case}: status {} instead of {status}", sent.0),
        );
        self.expect(
            sent.1.contains("refused"),
            format!("{case}: no refusal in {:?}", sent.1),
        );
        self.expect(reached.is_empty(), format!("{case}: reached the upstream"));
        let _ = proxy;
    }

    fn anthropic(&mut self) {
        let upstream = Upstream::start();
        let proxy = Proxy::start(self.script, "anthropic", "real-token", &upstream);

        // A measured request is forwarded with the runner's credential.
        let sent = proxy.send(
            "POST",
            "/v1/messages?beta=true",
            &anthropic_headers(MEASURED),
            &anthropic_body(serde_json::json!({})),
        );
        let reached = upstream.take();
        self.expect(
            sent.0 == 200,
            format!("measured request: status {}", sent.0),
        );
        match reached.as_slice() {
            [seen] => {
                self.expect(
                    seen.method == "POST" && seen.target == "/v1/messages?beta=true",
                    format!("forwarded as {} {}", seen.method, seen.target),
                );
                self.expect(
                    seen.headers.get("authorization").map(String::as_str)
                        == Some("Bearer real-token"),
                    "the runner's token replaces the model's",
                );
                self.expect(
                    !seen.headers.contains_key("x-api-key"),
                    "x-api-key is not forwarded",
                );
                self.expect(
                    seen.headers
                        .get("host")
                        .is_none_or(|h| !h.contains(&proxy.port.to_string())),
                    "the model's Host is not forwarded",
                );
                self.expect(
                    seen.headers.get("anthropic-beta").map(String::as_str) == Some(MEASURED),
                    "the measured betas are kept",
                );
                self.expect(
                    seen.headers.get("x-test-upstream").map(String::as_str)
                        == Some("api.anthropic.com"),
                    "the upstream is api.anthropic.com",
                );
            }
            other => self.failures.push(format!(
                "measured request reached the upstream {} times",
                other.len()
            )),
        }
        for path in [
            "/v1/messages",
            "/v1/messages/count_tokens",
            "/v1/messages/count_tokens?beta=true",
        ] {
            let sent = proxy.send(
                "POST",
                path,
                &anthropic_headers(MEASURED),
                &anthropic_body(serde_json::json!({})),
            );
            let reached = upstream.take();
            self.expect(
                sent.0 == 200 && reached.len() == 1,
                format!("{path} is forwarded"),
            );
        }

        // Only POST to the messages endpoints.
        for (method, path) in [
            ("GET", "/v1/messages"),
            ("DELETE", "/v1/messages"),
            ("POST", "/v1/models"),
            ("POST", "/v1/files"),
            ("POST", "/v1/messages/batches"),
            ("POST", "/api/oauth/profile"),
            ("POST", "//evil.example/v1/messages"),
            ("POST", "http://evil.example/v1/messages"),
            ("POST", "/v1/messages?beta=true&x=1"),
            ("POST", "/v1/messages/../models"),
            ("POST", "v1/messages"),
            ("POST", "/v1/responses"),
        ] {
            let sent = proxy.send(
                method,
                path,
                &anthropic_headers(MEASURED),
                &anthropic_body(serde_json::json!({})),
            );
            self.refused(&proxy, &upstream, 403, &format!("{method} {path}"), sent);
        }

        // Server tools, MCP servers and containers are refused.
        for extra in [
            serde_json::json!({"mcp_servers": [{"type": "url", "url": "https://evil.example/mcp", "name": "x"}]}),
            serde_json::json!({"container": "container_1"}),
            serde_json::json!({"tools": [{"type": "web_fetch_20250910", "name": "web_fetch"}]}),
            serde_json::json!({"tools": [{"name": "Read", "input_schema": {}}, {"type": "web_search_20250305", "name": "web_search"}]}),
            serde_json::json!({"tools": [{"type": "custom", "name": "x", "input_schema": {}}]}),
        ] {
            let sent = proxy.send(
                "POST",
                "/v1/messages",
                &anthropic_headers(MEASURED),
                &anthropic_body(extra.clone()),
            );
            self.refused(&proxy, &upstream, 403, &format!("body {extra}"), sent);
        }

        // A body that is not a JSON object is refused.
        for payload in [&b""[..], b"not json", b"[1]", b"\xff"] {
            let sent = proxy.send(
                "POST",
                "/v1/messages",
                &anthropic_headers(MEASURED),
                payload,
            );
            self.refused(&proxy, &upstream, 403, &format!("body {payload:?}"), sent);
        }

        // Betas that were not measured are dropped.
        let sent = proxy.send(
            "POST",
            "/v1/messages",
            &anthropic_headers("oauth-2025-04-20, mcp-client-2025-04-04,web-fetch-2025-09-10"),
            &anthropic_body(serde_json::json!({})),
        );
        let reached = upstream.take();
        self.expect(sent.0 == 200, "a request with extra betas is forwarded");
        self.expect(
            reached
                .first()
                .and_then(|s| s.headers.get("anthropic-beta"))
                .map(String::as_str)
                == Some("oauth-2025-04-20"),
            format!(
                "only the measured beta is kept: {:?}",
                reached.first().map(|s| &s.headers)
            ),
        );

        // A body over the cap, or without a length, is refused before it is read; so is a
        // target outside the endpoints, judged before the body.
        let mut no_length = anthropic_headers(MEASURED);
        no_length.retain(|(n, _)| *n != "Content-Length");
        let sent = proxy.send_raw("POST", "/v1/messages", &no_length, None);
        self.refused(&proxy, &upstream, 413, "no Content-Length", sent);
        for length in ["abc".to_owned(), (MAX_BODY_BYTES + 1).to_string()] {
            let mut headers = anthropic_headers(MEASURED);
            headers.push(("Content-Length", length.clone()));
            let sent = proxy.send_raw("POST", "/v1/messages", &headers, None);
            self.refused(
                &proxy,
                &upstream,
                413,
                &format!("Content-Length {length}"),
                sent,
            );
        }
        for (method, target) in [
            ("GET", "/v1/messages"),
            ("GET", "/v1/models"),
            ("POST", "/v1/files"),
        ] {
            let mut headers = anthropic_headers(MEASURED);
            headers.push(("Content-Length", (MAX_BODY_BYTES + 1).to_string()));
            let sent = proxy.send_raw(method, target, &headers, None);
            self.refused(
                &proxy,
                &upstream,
                403,
                &format!("{method} {target} before its body"),
                sent,
            );
        }
    }

    fn openai(&mut self) {
        let upstream = Upstream::start();
        let proxy = Proxy::start(self.script, "openai", "real-key", &upstream);

        // The measured request is forwarded with the runner's key, to the fixed upstream.
        let sent = proxy.send(
            "POST",
            "/v1/responses",
            &openai_headers(),
            &responses_body(serde_json::json!({})),
        );
        let reached = upstream.take();
        self.expect(
            sent.0 == 200,
            format!("measured Responses request: status {}", sent.0),
        );
        match reached.as_slice() {
            [seen] => {
                self.expect(
                    seen.headers.get("authorization").map(String::as_str)
                        == Some("Bearer real-key"),
                    "the runner's key replaces the model's",
                );
                self.expect(
                    seen.headers.get("x-test-upstream").map(String::as_str)
                        == Some("api.openai.com"),
                    "the upstream is api.openai.com",
                );
            }
            other => self.failures.push(format!(
                "measured Responses request reached the upstream {} times",
                other.len()
            )),
        }
        for tool in [
            serde_json::json!({"type": "function", "name": "shell"}),
            serde_json::json!({"type": "custom", "name": "apply_patch"}),
            serde_json::json!({"type": "local_shell"}),
        ] {
            let sent = proxy.send(
                "POST",
                "/v1/responses",
                &openai_headers(),
                &responses_body(serde_json::json!({"tools": [tool.clone()]})),
            );
            let reached = upstream.take();
            self.expect(
                sent.0 == 200 && reached.len() == 1,
                format!("client tool {tool} is forwarded"),
            );
        }

        // Only POST to /v1/responses, without a query.
        for (method, target) in [
            ("GET", "/v1/responses"),
            ("POST", "/v1/responses?stream=true"),
            ("POST", "/v1/chat/completions"),
            ("POST", "/v1/files"),
            ("POST", "/v1/messages"),
            ("POST", "//evil.example/v1/responses"),
        ] {
            let sent = proxy.send(
                method,
                target,
                &openai_headers(),
                &responses_body(serde_json::json!({})),
            );
            self.refused(
                &proxy,
                &upstream,
                403,
                &format!("openai {method} {target}"),
                sent,
            );
        }

        // Server tools, and an untyped tool, are refused.
        for kind in [
            "web_search",
            "web_search_preview",
            "file_search",
            "code_interpreter",
            "computer_use_preview",
            "image_generation",
            "mcp",
            "something_new",
        ] {
            let sent = proxy.send(
                "POST",
                "/v1/responses",
                &openai_headers(),
                &responses_body(serde_json::json!({"tools": [{"type": kind}]})),
            );
            self.refused(&proxy, &upstream, 403, &format!("openai tool {kind}"), sent);
        }
        let sent = proxy.send(
            "POST",
            "/v1/responses",
            &openai_headers(),
            &responses_body(serde_json::json!({"tools": [{"name": "untyped"}]})),
        );
        self.refused(&proxy, &upstream, 403, "openai untyped tool", sent);

        // Keys beyond the measured shape are refused.
        for extra in [
            serde_json::json!({"prompt": {"id": "pmpt_1"}}),
            serde_json::json!({"background": true}),
            serde_json::json!({"conversation": "conv_1"}),
            serde_json::json!({"previous_response_id": "resp_1"}),
            serde_json::json!({"tool_choice": {"type": "web_search"}}),
        ] {
            let sent = proxy.send(
                "POST",
                "/v1/responses",
                &openai_headers(),
                &responses_body(extra.clone()),
            );
            self.refused(
                &proxy,
                &upstream,
                403,
                &format!("openai body {extra}"),
                sent,
            );
        }
    }

    fn deepinfra(&mut self) {
        let upstream = Upstream::start();
        let proxy = Proxy::start(self.script, "deepinfra", "real-key", &upstream);
        const CHAT: &str = "/v1/openai/chat/completions";

        // Both measured shapes (the title request has no tools) are forwarded with the
        // runner's key, to the fixed upstream, at the same path.
        for (case, body) in [
            ("main request", chat_body(serde_json::json!({}))),
            (
                "title request's effort and temperature (run 41051499103)",
                chat_body(serde_json::json!({"reasoning_effort": "low", "temperature": 0.5})),
            ),
            ("title request", {
                let mut d: serde_json::Value =
                    serde_json::from_slice(&chat_body(serde_json::json!({}))).unwrap();
                d.as_object_mut().unwrap().remove("tools");
                d.as_object_mut().unwrap().remove("tool_choice");
                d.to_string().into_bytes()
            }),
        ] {
            let sent = proxy.send("POST", CHAT, &chat_headers(), &body);
            let reached = upstream.take();
            self.expect(
                sent.0 == 200,
                format!("deepinfra {case}: status {}", sent.0),
            );
            match reached.as_slice() {
                [seen] => {
                    self.expect(
                        seen.target == CHAT,
                        format!("deepinfra {case}: forwarded to {}", seen.target),
                    );
                    self.expect(
                        seen.headers.get("authorization").map(String::as_str)
                            == Some("Bearer real-key"),
                        "deepinfra: the runner's key replaces the model's",
                    );
                    self.expect(
                        seen.headers.get("x-test-upstream").map(String::as_str)
                            == Some("api.deepinfra.com"),
                        "deepinfra: the upstream is api.deepinfra.com",
                    );
                }
                other => self.failures.push(format!(
                    "deepinfra {case} reached the upstream {} times",
                    other.len()
                )),
            }
        }

        // Only POST to the chat path, without a query.
        for (method, target) in [
            ("GET", CHAT),
            ("POST", "/v1/openai/chat/completions?x=1"),
            ("POST", "/v1/openai/completions"),
            ("POST", "/v1/openai/embeddings"),
            ("GET", "/v1/openai/models"),
            ("POST", "/v1/openai/files"),
            ("POST", "/v1/openai/batches"),
            ("POST", "/v1/chat/completions"),
            ("POST", "/v1/inference/deepseek-ai/DeepSeek-V4-Pro"),
            ("POST", "/v1/messages"),
            ("POST", "/v1/responses"),
            ("POST", "//evil.example/v1/openai/chat/completions"),
            ("POST", "/v1/openai/chat/completions/../embeddings"),
        ] {
            let sent = proxy.send(
                method,
                target,
                &chat_headers(),
                &chat_body(serde_json::json!({})),
            );
            self.refused(
                &proxy,
                &upstream,
                403,
                &format!("deepinfra {method} {target}"),
                sent,
            );
        }

        // Another model, an unmeasured key, a server-side or untyped tool, a named
        // tool_choice: refused.
        for extra in [
            serde_json::json!({"model": "deepseek-ai/DeepSeek-V4-Flash"}),
            serde_json::json!({"model": "meta-llama/Llama-4"}),
            serde_json::json!({"response_format": {"type": "json_object"}}),
            serde_json::json!({"web_search_options": {}}),
            serde_json::json!({"n": 4}),
            serde_json::json!({"tools": [{"type": "web_search"}]}),
            serde_json::json!({"tools": [{"function": {"name": "untyped"}}]}),
            serde_json::json!({"tool_choice": {"type": "function", "function": {"name": "read"}}}),
            serde_json::json!({"reasoning_effort": {"effort": "high"}}),
            serde_json::json!({"reasoning_effort": "unbounded"}),
            serde_json::json!({"temperature": 7}),
            serde_json::json!({"temperature": "hot"}),
            serde_json::json!({"temperature": true}),
        ] {
            let sent = proxy.send("POST", CHAT, &chat_headers(), &chat_body(extra.clone()));
            self.refused(
                &proxy,
                &upstream,
                403,
                &format!("deepinfra body {extra}"),
                sent,
            );
        }
        let mut no_model: serde_json::Value =
            serde_json::from_slice(&chat_body(serde_json::json!({}))).unwrap();
        no_model.as_object_mut().unwrap().remove("model");
        let sent = proxy.send(
            "POST",
            CHAT,
            &chat_headers(),
            no_model.to_string().as_bytes(),
        );
        self.refused(
            &proxy,
            &upstream,
            403,
            "deepinfra body without a model",
            sent,
        );
    }

    /// Malformed values in `provider`'s body (#1140): a tool type, a model or an effort of
    /// the wrong JSON type, an object where a list goes, a list where an object or a
    /// string goes, nesting too deep to parse. Each is refused with 403, never a dropped
    /// connection, and nothing reaches the upstream.
    fn malformed(&mut self, provider: &str) {
        let upstream = Upstream::start();
        let proxy = Proxy::start(self.script, provider, "real-key", &upstream);
        let (target, headers, body, extras): (_, _, fn(serde_json::Value) -> Vec<u8>, _) =
            match provider {
                "anthropic" => (
                    "/v1/messages",
                    anthropic_headers(MEASURED),
                    anthropic_body as fn(serde_json::Value) -> Vec<u8>,
                    vec![
                        serde_json::json!({"tools": {"name": "Read", "input_schema": {}}}),
                        serde_json::json!({"tools": ["web_search"]}),
                        serde_json::json!({"tools": [{"type": ["web_search_20250305"], "name": "x"}]}),
                        serde_json::json!({"tools": [{"type": {"name": "web_fetch"}, "name": "x"}]}),
                        serde_json::json!({"tools": [{"type": null, "name": "x"}]}),
                        serde_json::json!({"tools": null}),
                        serde_json::json!({"mcp_servers": null}),
                        serde_json::json!({"container": {"id": "container_1"}}),
                    ],
                ),
                "openai" => (
                    "/v1/responses",
                    openai_headers(),
                    responses_body as fn(serde_json::Value) -> Vec<u8>,
                    vec![
                        serde_json::json!({"tools": [{"type": ["web_search"]}]}),
                        serde_json::json!({"tools": [{"type": {"name": "web_search"}}]}),
                        serde_json::json!({"tools": [{"type": null}]}),
                        serde_json::json!({"tools": [{"type": 1}]}),
                        serde_json::json!({"tools": [{"type": true}]}),
                        serde_json::json!({"tools": {"type": "function"}}),
                        serde_json::json!({"tools": ["function"]}),
                        serde_json::json!({"tools": null}),
                        serde_json::json!({"tool_choice": ["auto"]}),
                        serde_json::json!({"tool_choice": null}),
                    ],
                ),
                _ => (
                    "/v1/openai/chat/completions",
                    chat_headers(),
                    chat_body as fn(serde_json::Value) -> Vec<u8>,
                    vec![
                        serde_json::json!({"tools": [{"type": ["function"], "function": {"name": "read"}}]}),
                        serde_json::json!({"tools": [{"type": {"function": true}}]}),
                        serde_json::json!({"tools": [{"type": null}]}),
                        serde_json::json!({"tools": {"type": "function"}}),
                        serde_json::json!({"tools": ["function"]}),
                        serde_json::json!({"model": ["deepseek-ai/DeepSeek-V4-Pro"]}),
                        serde_json::json!({"model": {"id": "deepseek-ai/DeepSeek-V4-Pro"}}),
                        serde_json::json!({"model": null}),
                        serde_json::json!({"tool_choice": ["auto"]}),
                        serde_json::json!({"reasoning_effort": ["high"]}),
                        serde_json::json!({"reasoning_effort": null}),
                        serde_json::json!({"temperature": [0.5]}),
                        serde_json::json!({"temperature": {"value": 0.5}}),
                        serde_json::json!({"temperature": null}),
                    ],
                ),
            };
        for extra in extras {
            let sent = proxy.send("POST", target, &headers, &body(extra.clone()));
            self.refused(
                &proxy,
                &upstream,
                403,
                &format!("{provider} malformed body {extra}"),
                sent,
            );
        }
        // Nesting past the parser's recursion limit (2 MB, under the cap), inside a key the
        // mode accepts: the parser raises RecursionError, which is not a ValueError.
        let depth = 1_000_000;
        let deep = format!(
            "{{\"messages\":{}{}}}",
            "[".repeat(depth),
            "]".repeat(depth)
        );
        let deep = if provider == "openai" {
            deep.replace("messages", "input")
        } else {
            deep
        };
        let sent = proxy.send("POST", target, &headers, deep.as_bytes());
        self.refused(
            &proxy,
            &upstream,
            403,
            &format!("{provider} body nested {depth} deep"),
            sent,
        );
    }

    /// #1144: the structured verdict request. `response_format` passes only on a
    /// request without tools, and only as the exact json_schema of the verdict the
    /// runner names on the proxy's command line.
    fn deepinfra_verdict(&mut self) {
        const CHAT: &str = "/v1/openai/chat/completions";
        let dir = tempfile::tempdir().unwrap();
        let schema_file = dir.path().join("schema.json");
        fs::write(&schema_file, format!("{VERDICT_SCHEMA}\n")).unwrap();
        let schema: serde_json::Value = serde_json::from_str(VERDICT_SCHEMA).unwrap();
        let format = serde_json::json!({"type": "json_schema", "json_schema": {"name": "cross_review_verdict", "strict": true, "schema": schema}});
        let extraction = |extra: serde_json::Value| {
            let mut d = serde_json::json!({
                "model": "deepseek-ai/DeepSeek-V4-Pro",
                "stream": false,
                "temperature": 0,
                "max_tokens": 8000,
                "response_format": format,
                "messages": [{"role": "system", "content": "s"}, {"role": "user", "content": "review"}],
            });
            for (k, v) in extra.as_object().unwrap() {
                d[k] = v.clone();
            }
            d.to_string().into_bytes()
        };

        let upstream = Upstream::start();
        let proxy = Proxy::start_with(
            self.script,
            "deepinfra",
            "real-key",
            &upstream,
            &[&schema_file],
        );
        let sent = proxy.send(
            "POST",
            CHAT,
            &chat_headers(),
            &extraction(serde_json::json!({})),
        );
        let reached = upstream.take();
        self.expect(
            sent.0 == 200 && reached.len() == 1,
            format!("the verdict request is forwarded: status {}", sent.0),
        );
        let mut other_schema = schema.clone();
        other_schema["properties"]["verdict"] = serde_json::json!({"type": "string"});
        for (case, extra) in [
            (
                "with tools",
                serde_json::json!({"tools": [{"type": "function", "function": {"name": "read"}}]}),
            ),
            (
                "with a tool choice",
                serde_json::json!({"tool_choice": "auto"}),
            ),
            (
                "json_object",
                serde_json::json!({"response_format": {"type": "json_object"}}),
            ),
            (
                "another schema",
                serde_json::json!({"response_format": {"type": "json_schema", "json_schema": {"name": "cross_review_verdict", "strict": true, "schema": other_schema}}}),
            ),
            (
                "not strict",
                serde_json::json!({"response_format": {"type": "json_schema", "json_schema": {"name": "cross_review_verdict", "strict": false, "schema": schema}}}),
            ),
            (
                "another name",
                serde_json::json!({"response_format": {"type": "json_schema", "json_schema": {"name": "x", "strict": true, "schema": schema}}}),
            ),
            ("a string", serde_json::json!({"response_format": "json"})),
            (
                "a list",
                serde_json::json!({"response_format": [format.clone()]}),
            ),
            ("null", serde_json::json!({"response_format": null})),
        ] {
            let sent = proxy.send("POST", CHAT, &chat_headers(), &extraction(extra));
            self.refused(
                &proxy,
                &upstream,
                403,
                &format!("deepinfra verdict request {case}"),
                sent,
            );
        }

        // Without the schema file, no response_format passes at all.
        let upstream = Upstream::start();
        let proxy = Proxy::start(self.script, "deepinfra", "real-key", &upstream);
        let sent = proxy.send(
            "POST",
            CHAT,
            &chat_headers(),
            &extraction(serde_json::json!({})),
        );
        self.refused(
            &proxy,
            &upstream,
            403,
            "deepinfra verdict request without the schema file",
            sent,
        );
    }

    /// The constants the template fixes: the body cap, the concurrency cap and the two
    /// upstream hosts, read from the module itself.
    fn constants(&mut self) {
        let out = Command::new("python3")
            .arg("-c")
            .arg("import importlib.util, json, sys\nsys.dont_write_bytecode = True\nspec = importlib.util.spec_from_file_location('m', sys.argv[1])\nm = importlib.util.module_from_spec(spec)\nspec.loader.exec_module(m)\nprint(json.dumps({'max_body': m.MAX_BODY_BYTES, 'max_concurrent': m.MAX_CONCURRENT, 'anthropic': m.PROVIDERS['anthropic']['upstream'], 'openai': m.PROVIDERS['openai']['upstream'], 'deepinfra': m.PROVIDERS['deepinfra']['upstream']}))")
            .arg(self.script)
            .output()
            .expect("python3 reads the template");
        let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_default();
        self.expect(
            value["max_body"] == MAX_BODY_BYTES,
            format!("MAX_BODY_BYTES is 32 MiB: {value}"),
        );
        let concurrent = value["max_concurrent"].as_u64().unwrap_or(0);
        self.expect(
            (1..=8).contains(&concurrent),
            format!("MAX_CONCURRENT within 1..=8: {concurrent}"),
        );
        self.expect(
            value["anthropic"] == "api.anthropic.com",
            "the Anthropic upstream is fixed",
        );
        self.expect(
            value["openai"] == "api.openai.com",
            "the OpenAI upstream is fixed",
        );
        self.expect(
            value["deepinfra"] == "api.deepinfra.com",
            "the DeepInfra upstream is fixed",
        );
    }
}

#[test]
fn the_anthropic_mode_forwards_only_what_the_cli_was_measured_to_send() {
    let script = template();
    let mut checks = Checks::new(&script);
    checks.anthropic();
    assert!(checks.failures.is_empty(), "{:#?}", checks.failures);
}

#[test]
fn the_openai_mode_forwards_only_what_codex_was_measured_to_send() {
    let script = template();
    let mut checks = Checks::new(&script);
    checks.openai();
    assert!(checks.failures.is_empty(), "{:#?}", checks.failures);
}

#[test]
fn the_deepinfra_mode_forwards_only_what_opencode_was_measured_to_send() {
    let script = template();
    let mut checks = Checks::new(&script);
    checks.deepinfra();
    assert!(checks.failures.is_empty(), "{:#?}", checks.failures);
}

#[test]
fn the_anthropic_mode_refuses_malformed_values_with_403() {
    let script = template();
    let mut checks = Checks::new(&script);
    checks.malformed("anthropic");
    assert!(checks.failures.is_empty(), "{:#?}", checks.failures);
}

#[test]
fn the_openai_mode_refuses_malformed_values_with_403() {
    let script = template();
    let mut checks = Checks::new(&script);
    checks.malformed("openai");
    assert!(checks.failures.is_empty(), "{:#?}", checks.failures);
}

#[test]
fn the_deepinfra_mode_refuses_malformed_values_with_403() {
    let script = template();
    let mut checks = Checks::new(&script);
    checks.malformed("deepinfra");
    assert!(checks.failures.is_empty(), "{:#?}", checks.failures);
}

#[test]
fn the_deepinfra_mode_lets_only_the_exact_verdict_schema_through() {
    let script = template();
    let mut checks = Checks::new(&script);
    checks.deepinfra_verdict();
    assert!(checks.failures.is_empty(), "{:#?}", checks.failures);
}

#[test]
fn the_caps_and_the_upstreams_are_fixed() {
    let script = template();
    let mut checks = Checks::new(&script);
    checks.constants();
    assert!(checks.failures.is_empty(), "{:#?}", checks.failures);
}

/// The template with `old` replaced by `new` (which must occur), in `dir`.
fn broken(dir: &Path, old: &str, new: &str) -> PathBuf {
    let text = fs::read_to_string(template()).unwrap();
    assert!(
        text.contains(old),
        "the mutation names text the template has: {old}"
    );
    let path = dir.join("model-proxy.py");
    fs::write(&path, text.replacen(old, new, 1)).unwrap();
    path
}

#[test]
fn a_broken_copy_of_the_proxy_fails_the_checks() {
    let dir = tempfile::tempdir().unwrap();
    // Forwards server tools and MCP servers.
    let script = broken(
        dir.path(),
        "for key in (\"mcp_servers\", \"container\"):",
        "for key in ():",
    );
    let mut checks = Checks::new(&script);
    checks.anthropic();
    assert!(
        checks.failures.iter().any(|f| f.contains("mcp_servers")),
        "{:#?}",
        checks.failures
    );
    // Accepts any method.
    let script = broken(dir.path(), "return method == \"POST\" and", "return");
    let mut checks = Checks::new(&script);
    checks.anthropic();
    checks.openai();
    assert!(
        checks
            .failures
            .iter()
            .any(|f| f.starts_with("GET /v1/messages")),
        "{:#?}",
        checks.failures
    );
    // Lets another model spend the key (#1134).
    let script = broken(
        dir.path(),
        "if data.get(\"model\") != DEEPINFRA_MODEL:",
        "if False:",
    );
    let mut checks = Checks::new(&script);
    checks.deepinfra();
    assert!(
        checks
            .failures
            .iter()
            .any(|f| f.contains("DeepSeek-V4-Flash")),
        "{:#?}",
        checks.failures
    );
    // Keeps the model's credential.
    let script = broken(
        dir.path(),
        "forwarded[\"Authorization\"] = f\"Bearer {token}\"",
        "pass",
    );
    let mut checks = Checks::new(&script);
    checks.openai();
    assert!(
        checks.failures.iter().any(|f| f.contains("runner's key")),
        "{:#?}",
        checks.failures
    );
}
