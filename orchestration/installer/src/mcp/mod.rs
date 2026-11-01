//! `brakes mcp`: the installer's fourth entry point (decision 2026-10-28,
//! point 9; SPEC-questions.md, MCP server). An MCP server over stdio for one
//! agent host at a time: JSON-RPC 2.0 written by hand on `serde_json`, one
//! message per line, no async runtime and no network. It implements
//! `initialize`, `ping`, `tools/list` and `tools/call`; every other request is
//! `-32601` and every notification is read and ignored. stdout carries only
//! response frames; logging goes to stderr.
//!
//! Sources (MCP specification, revision 2025-11-25):
//! - stdio framing: <https://modelcontextprotocol.io/specification/2025-11-25/basic/transports#stdio>
//!   ("Messages are delimited by newlines, and MUST NOT contain embedded
//!   newlines"; "The server MUST NOT write anything to its stdout that is not a
//!   valid MCP message").
//! - messages: <https://modelcontextprotocol.io/specification/2025-11-25/basic#messages>
//!   (a request id is a string or an integer, never `null`; a notification gets
//!   no response).
//! - version negotiation: <https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle#version-negotiation>
//!   (a supported requested version is echoed; otherwise the server answers the
//!   latest it supports).
//! - tool errors: <https://modelcontextprotocol.io/specification/2025-11-25/server/tools#error-handling>
//!   (unknown tools and malformed calls are protocol errors; everything a tool
//!   refuses is a result with `isError: true`).
//! - requests from the server: <https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation>
//!   (`elicitation/create` is a request the server sends while a `tools/call`
//!   is open; the client's response carries the same `id`). While it waits, this
//!   server answers `ping`, ignores notifications and answers any other request
//!   with `-32600`: one call at a time.
pub mod elicit;
pub mod tools;

use crate::{Result, Source, engine::Module, modules};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::io::{BufRead, Lines, Write};

/// The protocol revisions this server speaks, latest first: the one it answers
/// when a client asks for any other.
pub const PROTOCOL_VERSIONS: [&str; 2] = ["2025-11-25", "2025-06-18"];

const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;

const USAGE: &str = "Usage: brakes mcp (no argument; MCP over stdio)";

/// The other end of the connection, as a tool sees it: a request this server
/// sends and the client's answer, `Ok(result)` or `Err(error object)`; `None`
/// when the client went away first.
pub trait Client {
    fn request(&mut self, method: &str, params: Value)
    -> Option<std::result::Result<Value, Value>>;
}

/// What `initialize` told this server about the client: the negotiated
/// revision and whether it declared form-mode elicitation. Before `initialize`,
/// the latest revision and no elicitation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    pub version: &'static str,
    pub elicitation: bool,
}

/// One server process: the nonce its plan tokens are bound to, drawn once; the
/// modules and source it plans with; the client it is talking to.
pub struct Server {
    nonce: [u8; 32],
    modules: Vec<&'static dyn Module>,
    source: Source,
    peer: Peer,
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

impl Server {
    /// The compiled modules and the embedded source, as `brakes mcp` runs.
    pub fn new() -> Self {
        Self::with_modules(modules::all(), Source::embedded())
    }

    /// A server over other modules and another source (the tests' modules).
    pub fn with_modules(modules: Vec<&'static dyn Module>, source: Source) -> Self {
        Self {
            nonce: nonce(),
            modules,
            source,
            peer: Peer {
                version: PROTOCOL_VERSIONS[0],
                elicitation: false,
            },
        }
    }

    /// The response frame for one input line, or `None` for a notification
    /// (or a response, which this server never asked for). A tool may send
    /// requests to `client` before the frame is returned.
    pub fn handle(
        &mut self,
        line: &str,
        client: &mut dyn Client,
        log: &mut impl Write,
    ) -> Option<Value> {
        let message: Value = match serde_json::from_str(line) {
            Ok(message) => message,
            Err(_) => return Some(error(Value::Null, PARSE_ERROR, "Parse error")),
        };
        // An array is a JSON-RPC batch, which MCP no longer accepts.
        let Some(message) = message.as_object() else {
            return Some(error(Value::Null, INVALID_REQUEST, "Invalid Request"));
        };
        let id = match message.get("id") {
            None => return None,
            Some(id @ Value::String(_)) => id.clone(),
            Some(id @ Value::Number(n)) if n.is_i64() || n.is_u64() => id.clone(),
            Some(_) => return Some(error(Value::Null, INVALID_REQUEST, "Invalid Request")),
        };
        let method = message.get("method").and_then(Value::as_str);
        let (true, Some(method)) = (message.get("jsonrpc") == Some(&json!("2.0")), method) else {
            // A response to a request this server never sent carries no method.
            if message.contains_key("result") || message.contains_key("error") {
                return None;
            }
            return Some(error(id, INVALID_REQUEST, "Invalid Request"));
        };
        let params = message.get("params").cloned().unwrap_or(json!({}));
        let outcome = match method {
            "initialize" => self.initialize(&params),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({"tools": tools::list()})),
            "tools/call" => self.call(&params, client, log),
            other => Err((METHOD_NOT_FOUND, format!("Method not found: {other}"))),
        };
        Some(match outcome {
            Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
            Err((code, message)) => error(id, code, &message),
        })
    }

    /// `tools/call`: a malformed call or an unknown tool is a protocol error;
    /// whatever the tool refuses is a result with `isError: true` and the exact
    /// `REFUSED:` text the CLI prints.
    fn call(
        &self,
        params: &Value,
        client: &mut dyn Client,
        log: &mut impl Write,
    ) -> std::result::Result<Value, (i64, String)> {
        let invalid = |what: &str| (INVALID_PARAMS, format!("Invalid params: {what}"));
        let Some(name) = params.get("name").and_then(Value::as_str) else {
            return Err(invalid("tools/call needs a tool name"));
        };
        let arguments = match params.get("arguments") {
            None => Map::new(),
            Some(Value::Object(arguments)) => arguments.clone(),
            Some(_) => return Err(invalid("tools/call arguments must be an object")),
        };
        if !tools::NAMES.contains(&name) {
            return Err((INVALID_PARAMS, format!("Unknown tool: {name}")));
        }
        Ok(match tools::call(name, &arguments, self, client) {
            Ok(structured) => json!({
                "content": [{"type": "text", "text": structured.to_string()}],
                "structuredContent": structured,
                "isError": false,
            }),
            Err(error) if error.is::<elicit::Stopped>() => {
                let _ = writeln!(log, "mcp: {name}: {error}");
                json!({"content": [{"type": "text", "text": error.to_string()}], "isError": true})
            }
            Err(refusal) => {
                let _ = writeln!(log, "mcp: {name}: REFUSED: {refusal}");
                json!({
                    "content": [{"type": "text", "text": format!("REFUSED: {refusal}")}],
                    "isError": true,
                })
            }
        })
    }

    /// The requested revision when this server speaks it, the latest
    /// otherwise; remembers it and whether the client elicits forms.
    fn initialize(&mut self, params: &Value) -> std::result::Result<Value, (i64, String)> {
        let Some(requested) = params.get("protocolVersion").and_then(Value::as_str) else {
            return Err((
                INVALID_PARAMS,
                "Invalid params: initialize needs a protocolVersion".to_owned(),
            ));
        };
        let version = PROTOCOL_VERSIONS
            .iter()
            .find(|v| **v == requested)
            .unwrap_or(&PROTOCOL_VERSIONS[0]);
        let capabilities = params.get("capabilities").cloned().unwrap_or(json!({}));
        self.peer = Peer {
            version,
            elicitation: elicit::supports_form(&capabilities, version),
        };
        Ok(json!({
            "protocolVersion": version,
            "capabilities": {"tools": {}},
            "serverInfo": {
                "name": "brakes",
                "version": include_str!("../../../../VERSION").trim(),
            },
        }))
    }
}

fn error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

/// stdio as the `Client`: frames out on `output`, one per line and flushed;
/// messages in from `lines`. Its own requests are numbered `server-1`, …
struct Stdio<'a, R, W> {
    lines: Lines<R>,
    output: &'a mut W,
    sent: u64,
}

impl<R: BufRead, W: Write> Stdio<'_, R, W> {
    /// The next non-blank input line, `None` at the end of input.
    fn next_line(&mut self) -> Option<std::io::Result<String>> {
        self.lines
            .by_ref()
            .find(|line| line.as_ref().map_or(true, |l| !l.trim().is_empty()))
    }

    fn send(&mut self, frame: &Value) -> std::io::Result<()> {
        // Compact JSON escapes every newline inside strings: one frame, one line.
        writeln!(self.output, "{frame}")?;
        self.output.flush()
    }
}

impl<R: BufRead, W: Write> Client for Stdio<'_, R, W> {
    fn request(
        &mut self,
        method: &str,
        params: Value,
    ) -> Option<std::result::Result<Value, Value>> {
        self.sent += 1;
        let id = json!(format!("server-{}", self.sent));
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
            .ok()?;
        loop {
            let line = self.next_line()?.ok()?;
            let Ok(Value::Object(message)) = serde_json::from_str::<Value>(&line) else {
                self.send(&error(Value::Null, PARSE_ERROR, "Parse error"))
                    .ok()?;
                continue;
            };
            let other = message.get("id").cloned();
            match (message.get("method").and_then(Value::as_str), other) {
                (None, Some(other)) if other == id => {
                    return Some(match message.get("error") {
                        Some(error) => Err(error.clone()),
                        None => Ok(message.get("result").cloned().unwrap_or(Value::Null)),
                    });
                }
                (Some("ping"), Some(other)) => {
                    let pong = json!({"jsonrpc": "2.0", "id": other, "result": {}});
                    self.send(&pong).ok()?;
                }
                (Some(_), Some(other)) => {
                    let busy =
                        format!("Invalid Request: waiting for the client's answer to {method}");
                    self.send(&error(other, INVALID_REQUEST, &busy)).ok()?;
                }
                // A notification, or a response to nothing pending.
                _ => {}
            }
        }
    }
}

/// Reads one message per line until `input` closes and writes one frame per
/// request, each on its own line, flushed. Blank lines are skipped.
pub fn serve(
    server: &mut Server,
    input: impl BufRead,
    output: &mut impl Write,
    log: &mut impl Write,
) -> Result<()> {
    let mut stdio = Stdio {
        lines: input.lines(),
        output,
        sent: 0,
    };
    while let Some(line) = stdio.next_line() {
        let line = line?;
        if let Some(frame) = server.handle(&line, &mut stdio, log) {
            stdio.send(&frame)?;
        }
    }
    Ok(())
}

/// `brakes mcp`: no argument; serves stdin to stdout until stdin closes.
pub fn cli(args: &[std::ffi::OsString]) -> std::process::ExitCode {
    if !args.is_empty() {
        eprintln!("REFUSED: {USAGE}");
        return std::process::ExitCode::from(2);
    }
    let mut server = Server::new();
    match serve(
        &mut server,
        std::io::stdin().lock(),
        &mut std::io::stdout().lock(),
        &mut std::io::stderr(),
    ) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("REFUSED: {error}");
            std::process::ExitCode::from(2)
        }
    }
}

/// 32 bytes no other process can predict, without a random-number crate: std's
/// `RandomState` keys are seeded from the operating system's randomness, hashed
/// with the time and the process id.
fn nonce() -> [u8; 32] {
    use std::hash::{BuildHasher, Hasher};
    let mut seed = Sha256::new();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    for round in 0..4u8 {
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u128(now);
        hasher.write_u8(round);
        seed.update(hasher.finish().to_le_bytes());
    }
    seed.update(now.to_le_bytes());
    seed.update(std::process::id().to_le_bytes());
    seed.finalize().into()
}

/// Unpadded base64url (RFC 4648, section 5), written by hand: the token is the
/// only use, and a crate for it is ask-first (#727).
pub fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for i in 0..=chunk.len() {
            out.push(char::from(ALPHABET[(n >> (18 - 6 * i) & 63) as usize]));
        }
    }
    out
}

/// `base64url(sha256(nonce ‖ root ‖ module ‖ answers ‖ plan digest))[..22]`
/// (SPEC-questions.md): each field is followed by a zero byte, so no two field
/// splits hash alike. 22 characters carry 132 bits of the digest.
pub fn confirmation_token(
    nonce: &[u8; 32],
    root: &str,
    module: &str,
    canonical_answers: &str,
    plan_digest: &str,
) -> String {
    let mut hash = Sha256::new();
    hash.update(nonce);
    for field in [root, module, canonical_answers, plan_digest] {
        hash.update(field.as_bytes());
        hash.update([0]);
    }
    base64url(&hash.finalize())[..22].to_owned()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn base64url_matches_the_rfc_4648_test_vectors_without_padding() {
        // RFC 4648, section 10, with the padding dropped.
        for (input, expected) in [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64url(input.as_bytes()), expected, "{input}");
        }
        assert_eq!(base64url(&[0xfb, 0xff]), "-_8", "the url-safe alphabet");
    }

    #[test]
    fn the_token_changes_with_every_bound_field() {
        let nonce = [7; 32];
        let token = |n: &[u8; 32], r, m, a, p| confirmation_token(n, r, m, a, p);
        let base = token(&nonce, "/r", "m", "{}", "d");
        assert_eq!(base.len(), 22);
        assert_eq!(base, token(&nonce, "/r", "m", "{}", "d"));
        for other in [
            token(&[8; 32], "/r", "m", "{}", "d"),
            token(&nonce, "/s", "m", "{}", "d"),
            token(&nonce, "/r", "n", "{}", "d"),
            token(&nonce, "/r", "m", "{\"a\":1}", "d"),
            token(&nonce, "/r", "m", "{}", "e"),
            token(&nonce, "/rm", "", "{}", "d"),
        ] {
            assert_ne!(base, other);
        }
    }
}
