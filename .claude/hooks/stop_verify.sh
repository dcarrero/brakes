#!/bin/sh
# Stop -> verify: the Claude Code Stop hook rendered by brakes (agent-guardrails).
#
# Claude Code runs this when the agent wants to stop. The hook runs the project's
# declared `verify` command, baked in below at install time, and when it fails exits 2
# with the reason and the last lines of output on stderr, so the agent continues
# instead of claiming it is done. It never blocks twice on an identical tree: the
# digest of the working tree (a git tree id over tracked and untracked, not ignored,
# files) and the last outcome live under the gitdir in brakes/stop-verify.json,
# inside the checkout and never versioned.
#
# Needs POSIX sh and git only. The payload on stdin is read for `cwd` alone; anything
# unparsable falls back to this file's directory. A rendered POSIX sh hook is an
# accepted exception to Rust-only (docs/decisions.md, 2026-10-28, point 6). Do not
# edit: a local edit refuses the next install; change `verify` in
# .agent-setup/project.json and run the installer again.
set -u

verify=$(cat <<'AGENTIC_SETUP_VERIFY'
cargo test --locked
AGENTIC_SETUP_VERIFY
)
timeout='600'
tail_lines=60

message() {
    printf '{"systemMessage":"%s"}\n' "$1"
}
skip() {
    echo "stop_verify: $1; verify was not run" >&2
    exit 0
}
# Every process below $1, deepest last; `ps -A -o pid= -o ppid=` is POSIX.
descendants() {
    echo "$1"
    ps -A -o pid= -o ppid= 2>/dev/null | while read -r child parent; do
        [ "$parent" = "$1" ] && descendants "$child"
    done
}
# The value of a string field of the state file, or nothing.
field() {
    sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" "$state" 2>/dev/null | head -n 1
}

if [ -z "$verify" ]; then
    message "Stop hook: no verify command declared in .agent-setup/project.json; nothing was run."
    exit 0
fi

payload=
if [ ! -t 0 ]; then
    payload=$(cat 2>/dev/null) || payload=
fi
cwd=$(printf '%s' "$payload" | sed -n 's/.*"cwd"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)
if [ -z "$cwd" ] || [ ! -d "$cwd" ]; then
    cwd=$(dirname "$0")
fi

command -v git >/dev/null 2>&1 || skip "git not found"
root=$(cd "$cwd" 2>/dev/null && git rev-parse --show-toplevel 2>/dev/null) || root=
[ -n "$root" ] || skip "$cwd is not inside a git checkout"
cd "$root" || skip "cannot enter $root"
git_dir=$(git rev-parse --git-dir 2>/dev/null) || skip "cannot resolve the gitdir"
case $git_dir in /*) ;; *) git_dir=$root/$git_dir ;; esac
state_dir=$git_dir/brakes
state=$state_dir/stop-verify.json
mkdir -p "$state_dir" 2>/dev/null || skip "cannot write $state_dir"

head_sha=$(git rev-parse --verify HEAD 2>/dev/null) || head_sha=
if [ -n "$head_sha" ] && [ -z "$(git status --porcelain --untracked-files=all 2>/dev/null)" ]; then
    # Clean tree: its digest is HEAD's tree, no index needed.
    digest=$(git rev-parse "HEAD^{tree}" 2>/dev/null) || digest=
else
    rm -f "$state_dir/index"
    digest=$(GIT_INDEX_FILE=$state_dir/index git add -A -- . >/dev/null 2>&1 &&
        GIT_INDEX_FILE=$state_dir/index git write-tree 2>/dev/null) || digest=
    rm -f "$state_dir/index"
fi
[ -n "$digest" ] || skip "cannot digest the working tree"

if [ "$digest" = "$(field verified)" ]; then
    exit 0
fi
if [ "$digest" = "$(field blocked)" ]; then
    message "Stop hook: verify failed on this exact tree before and nothing changed; stopping so the failure can be reported, not fixed by blocking again."
    exit 0
fi

output=$state_dir/verify-output.log
expired=$state_dir/verify-timed-out
rm -f "$expired"
started=$(date +%s)
( exec sh -c "$verify" ) </dev/null >"$output" 2>&1 &
pid=$!
(
    sleep "$timeout"
    : >"$expired"
    # shellcheck disable=SC2046
    kill -s TERM $(descendants "$pid") 2>/dev/null
) >/dev/null 2>&1 &
watchdog=$!
{ wait "$pid"; } 2>/dev/null
code=$?
# shellcheck disable=SC2046
kill -s TERM $(descendants "$watchdog") 2>/dev/null
{ wait "$watchdog"; } 2>/dev/null
elapsed=$(( $(date +%s) - started ))

if [ -f "$expired" ]; then
    rm -f "$expired"
    printf '{"blocked":"%s"}\n' "$digest" >"$state"
    echo "verify failed (timeout after ${timeout}s, exit $code): $verify" >&2
    tail -n "$tail_lines" "$output" >&2
    exit 2
fi
if [ "$code" -ne 0 ]; then
    printf '{"blocked":"%s"}\n' "$digest" >"$state"
    echo "verify failed (exit $code, ${elapsed}s): $verify" >&2
    tail -n "$tail_lines" "$output" >&2
    exit 2
fi
printf '{"verified":"%s","head":"%s","at":"%s"}\n' "$digest" "$head_sha" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$state"
message "verify green (${elapsed}s)."
exit 0
