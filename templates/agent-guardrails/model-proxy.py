# model-proxy.py (brakes agent-guardrails; #971, #1095): the model's
# credential stays with the runner, and so does the choice of what it may be spent
# on. Three fixed providers, chosen by the second argument: `anthropic` (default; the
# Claude Code CLI points ANTHROPIC_BASE_URL here), `openai` (codex-action's proxy
# points its responses-api-endpoint here; Codex 0.165.0 measured on both runner kinds
# sends POST /v1/responses only, with the body keys in OPENAI_KEYS and no server tool)
# and `deepinfra` (#1134; OpenCode 1.19.5's provider baseURL points here; measured on
# both runner kinds it sends POST /v1/openai/chat/completions only, with the body keys
# in CHAT_KEYS, the one model DEEPINFRA_MODEL, `function` tools and an effort).
# The Anthropic mode is described below. Started
# as the runner before the model, it reads the real token from stdin, listens on
# 127.0.0.1 only and forwards to the fixed upstream https://api.anthropic.com only
# what the pinned Claude Code CLI was measured to send (2026-10-30, 2.1.312, both
# runner kinds): POST to /v1/messages or /v1/messages/count_tokens, with or without
# `?beta=true`; a JSON object body of at most MAX_BODY_BYTES, without `mcp_servers`,
# `container` or any `tools` entry carrying a `type` (the API's server tools, which
# would make Anthropic fetch or run things for the model); the measured
# `anthropic-beta` values only. Everything else is refused before a byte reaches the
# API. The model, as agent-model, holds a dummy token with ANTHROPIC_BASE_URL here.
# Every value the model sends is type-checked before a membership test or a
# comparison, and a body nested past the parser's limit is not JSON, so a malformed
# request is refused with 403, never a dropped connection (#1140). Standard library
# only. It logs the method, path and status, never a header value.
import http.client
import http.server
import json
import socketserver
import sys
import threading

PATHS = {"/v1/messages", "/v1/messages/count_tokens"}
QUERIES = {"", "beta=true"}
MAX_BODY_BYTES = 32 * 1024 * 1024
MAX_CONCURRENT = 4
# What the pinned Claude Code CLI sends (measured; spike #1089, run 40982484216).
BETAS = {
    "claude-code-20250219",
    "oauth-2025-04-20",
    "interleaved-thinking-2025-05-14",
    "context-management-2025-06-27",
    "per-turn-control-2026-07-01",
    "mid-conversation-tool-changes-2026-07-01",
    "thinking-token-count-2026-05-13",
    "advanced-tool-use-2025-11-20",
    "effort-2025-11-24",
    "extended-cache-ttl-2025-04-11",
}
# What Codex 0.165.0 sends to the Responses API (measured; spike #1096, run
# 40984402028), plus `tools`, whose entries must be client-executed.
OPENAI_KEYS = {
    "client_metadata",
    "include",
    "input",
    "model",
    "parallel_tool_calls",
    "prompt_cache_key",
    "reasoning",
    "store",
    "stream",
    "text",
    "tool_choice",
    "tools",
}
OPENAI_TOOL_TYPES = {"function", "custom", "local_shell"}
# What OpenCode 1.19.5 sends to an OpenAI-compatible chat endpoint (measured; spike
# #1137, run 41030515183, and the rendered job's run 41051499103, whose title request
# adds `temperature` 0.5 and `reasoning_effort` "low"), and the one model the
# DeepSeek judge may use (#1134).
CHAT_KEYS = {
    "max_tokens",
    "messages",
    "model",
    "reasoning_effort",
    "stream",
    "stream_options",
    "temperature",
    "tool_choice",
    "tools",
}
EFFORTS = {"none", "minimal", "low", "medium", "high", "xhigh", "max"}
# The one structured request the DeepSeek judge's verdict step makes (#1144): no tools,
# and this exact response_format around the verdict schema the runner names as the
# proxy's third argument. Without that argument no response_format passes.
VERDICT_FORMAT = None


def verdict_format(schema):
    """The exact response_format the verdict request must carry."""
    return {"type": "json_schema", "json_schema": {"name": "cross_review_verdict", "strict": True, "schema": schema}}
DEEPINFRA_MODEL = "deepseek-ai/DeepSeek-V4-Pro"


def anthropic_body(data):
    """Why an Anthropic body is refused, or None."""
    for key in ("mcp_servers", "container"):
        if key in data:
            return f"refused: `{key}` asks the API to reach out for the model"
    tools = data.get("tools", [])
    if not isinstance(tools, list) or any(not isinstance(t, dict) or "type" in t for t in tools):
        return "refused: a server tool asks the API to reach out for the model"
    return None


def openai_body(data):
    """Why a Responses API body is refused, or None."""
    extra = sorted(set(data) - OPENAI_KEYS)
    if extra:
        return f"refused: `{extra[0]}` is not what Codex sends"
    tools = data.get("tools", [])
    if not isinstance(tools, list) or any(
        not isinstance(t, dict) or not isinstance(t.get("type"), str) or t["type"] not in OPENAI_TOOL_TYPES
        for t in tools
    ):
        return "refused: a server tool asks the API to reach out for the model"
    if not isinstance(data.get("tool_choice", "auto"), str):
        return "refused: `tool_choice` names a tool"
    return None


def chat_body(data):
    """Why a DeepInfra chat completions body is refused, or None."""
    if "response_format" in data:
        if VERDICT_FORMAT is None or data["response_format"] != VERDICT_FORMAT:
            return "refused: `response_format` is not the verdict's schema"
        if "tools" in data or "tool_choice" in data:
            return "refused: the verdict request runs no tools"
    extra = sorted(set(data) - CHAT_KEYS - {"response_format"})
    if extra:
        return f"refused: `{extra[0]}` is not what OpenCode sends"
    if data.get("model") != DEEPINFRA_MODEL:
        return f"refused: the model is not {DEEPINFRA_MODEL}"
    tools = data.get("tools", [])
    if not isinstance(tools, list) or any(not isinstance(t, dict) or t.get("type") != "function" for t in tools):
        return "refused: only function tools run, on the client"
    if not isinstance(data.get("tool_choice", "auto"), str):
        return "refused: `tool_choice` names a tool"
    temperature = data.get("temperature", 0)
    if isinstance(temperature, bool) or not isinstance(temperature, (int, float)) or not 0 <= temperature <= 2:
        return "refused: `temperature` is not a number from 0 to 2"
    effort = data.get("reasoning_effort", "high")
    if not isinstance(effort, str) or effort not in EFFORTS:
        return "refused: `reasoning_effort` is not an effort"
    return None


PROVIDERS = {
    "anthropic": {"upstream": "api.anthropic.com", "paths": PATHS, "queries": QUERIES, "body": anthropic_body, "betas": BETAS},
    "openai": {"upstream": "api.openai.com", "paths": {"/v1/responses"}, "queries": {""}, "body": openai_body, "betas": None},
    "deepinfra": {"upstream": "api.deepinfra.com", "paths": {"/v1/openai/chat/completions"}, "queries": {""}, "body": chat_body, "betas": None},
}
# Hop-by-hop headers (RFC 9110, 7.6.1) and the credentials the model sends.
DROP = {
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "authorization",
    "x-api-key",
    "content-length",
}


def length_ok(value):
    """A Content-Length that is a number within the cap."""
    return value is not None and value.isdigit() and int(value) <= MAX_BODY_BYTES


def target_ok(method, target, provider="anthropic"):
    """POST to the provider's inference endpoints, judged before any body is read."""
    rules = PROVIDERS[provider]
    path, _, query = target.partition("?")
    return method == "POST" and path in rules["paths"] and query in rules["queries"]


def decide(method, target, headers, body, token, provider="anthropic"):
    """(True, headers to forward) or (False, why it is refused)."""
    rules = PROVIDERS[provider]
    if not target_ok(method, target, provider):
        return False, f"refused: {method} {target.partition('?')[0]} is not an inference call"
    try:
        data = json.loads(body)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return False, "refused: the body is not JSON"
    if not isinstance(data, dict):
        return False, "refused: the body is not a JSON object"
    reason = rules["body"](data)
    if reason:
        return False, reason
    forwarded = {k: v for k, v in headers.items() if k.lower() not in DROP}
    for name in [k for k in forwarded if k.lower() == "anthropic-beta"]:
        value = forwarded.pop(name)
        kept = [b.strip() for b in value.split(",") if rules["betas"] and b.strip() in rules["betas"]]
        if kept:
            forwarded["anthropic-beta"] = ",".join(kept)
    forwarded["Authorization"] = f"Bearer {token}"
    return True, forwarded


def main():
    token = sys.stdin.readline().strip()
    port_file = sys.argv[1]
    provider = sys.argv[2] if len(sys.argv) > 2 else "anthropic"
    if provider not in PROVIDERS:
        sys.exit(f"model-proxy: unknown provider {provider}")
    global VERDICT_FORMAT
    if provider == "deepinfra" and len(sys.argv) > 3:
        with open(sys.argv[3]) as schema:
            VERDICT_FORMAT = verdict_format(json.load(schema))
    upstream_host = PROVIDERS[provider]["upstream"]
    if not token:
        sys.exit("model-proxy: no token on stdin")
    slots = threading.BoundedSemaphore(MAX_CONCURRENT)

    class Proxy(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format, *args):
            return

        def refuse(self, status, reason):
            print(f"model-proxy: {self.command} {self.path.split('?')[0]} {reason}", flush=True)
            payload = json.dumps(
                {"type": "error", "error": {"type": "permission_error", "message": f"model-proxy {reason}"}}
            ).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)
            self.close_connection = True

        def forward(self):
            if not slots.acquire(blocking=False):
                self.refuse(429, "refused: too many requests at once")
                return
            try:
                self.relay()
            finally:
                slots.release()

        def relay(self):
            if not target_ok(self.command, self.path, provider):
                self.refuse(403, f"refused: {self.command} {self.path.split('?')[0]} is not an inference call")
                return
            if "transfer-encoding" in {k.lower() for k in self.headers}:
                self.refuse(411, "refused: a chunked body")
                return
            if not length_ok(self.headers.get("Content-Length")):
                self.refuse(413, "refused: no length, or a body over the cap")
                return
            body = self.rfile.read(int(self.headers["Content-Length"]))
            ok, result = decide(self.command, self.path, dict(self.headers.items()), body, token, provider)
            if not ok:
                self.refuse(403, result)
                return
            upstream = http.client.HTTPSConnection(upstream_host, timeout=600)
            try:
                upstream.request(self.command, self.path, body=body, headers=result)
                response = upstream.getresponse()
                print(f"model-proxy: {self.command} {self.path.split('?')[0]} -> {response.status}", flush=True)
                self.send_response(response.status, response.reason)
                for k, v in response.getheaders():
                    if k.lower() not in DROP:
                        self.send_header(k, v)
                self.send_header("Connection", "close")
                self.end_headers()
                while True:
                    chunk = response.read1(65536)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    self.wfile.flush()
            except Exception as error:
                print(f"model-proxy: {self.command} {self.path.split('?')[0]} failed: {type(error).__name__}", flush=True)
            finally:
                upstream.close()
                self.close_connection = True

        do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = forward

    class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True

    server = Server(("127.0.0.1", 0), Proxy)
    with open(port_file, "w") as out:
        out.write(str(server.server_address[1]))
    print(f"model-proxy: {provider}, listening on 127.0.0.1:{server.server_address[1]}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
