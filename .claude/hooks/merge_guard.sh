#!/bin/sh
# Never merge on red: the Claude Code PreToolUse hook for Bash.
#
# The guard itself is `brakes guard pre-bash` (Rust). This wrapper only
# finds that binary: BRAKES_BIN, then brakes on PATH, then
# ${CARGO_HOME:-$HOME/.cargo}/bin/brakes (where `cargo install` puts it;
# #1151), then the newest
# ~/.local/state/agentic-build-*/orchestration/target/release/brakes;
# then the same four for the binary's former name `agentic-setup`
# (AGENTIC_SETUP_BIN, ...; for one release, #1067) and for the frozen
# `agentic-run` (AGENTIC_RUN_BIN, ...), so a machine without brakes keeps its
# guard. A candidate counts only if its
# --help lists `guard pre-bash`.
#
# Without a binary it warns on stderr and denies only what could merge (`gh pr
# merge`, `gh api .../merge`), touch the `human-approved` label (a `gh` word and
# then that word on one line; #1151), run `brakes apply --remote` (an
# `apply` word and a `--remote` word, as through `cargo run`; #850) or name a
# secret `.env` file (#1309), matched loosely on the raw payload, and allows
# every other command, so a session without the binary keeps Bash. Accepted exception to
# Rust-only, 2026-10-22, restated 2026-10-28 (docs/decisions.md).

has_guard() {
    [ -f "$1" ] && [ -x "$1" ] && "$1" --help 2>/dev/null | grep -q 'guard pre-bash'
}

# find_guard NAME PINNED: sets guard to PINNED, else NAME on PATH, else NAME in
# the cargo bin directory, else the newest state build of NAME, whichever first
# has the guard; fails if none.
find_guard() {
    if [ -n "$2" ] && has_guard "$2"; then
        guard=$2
    elif on_path=$(command -v "$1" 2>/dev/null) && has_guard "$on_path"; then
        guard=$on_path
    elif has_guard "${CARGO_HOME:-${HOME:-/nonexistent}/.cargo}/bin/$1"; then
        guard=${CARGO_HOME:-${HOME:-/nonexistent}/.cargo}/bin/$1
    else
        for candidate in "${HOME:-/nonexistent}"/.local/state/agentic-build-*/orchestration/target/release/"$1"; do
            has_guard "$candidate" || continue
            if [ -z "$guard" ] || [ "$candidate" -nt "$guard" ]; then
                guard=$candidate
            fi
        done
    fi
    [ -n "$guard" ]
}

guard=
if find_guard brakes "${BRAKES_BIN:-}" ||
    find_guard agentic-setup "${AGENTIC_SETUP_BIN:-}" ||
    find_guard agentic-run "${AGENTIC_RUN_BIN:-}"; then
    exec "$guard" guard pre-bash
fi

printf '%s\n' 'merge guard: the guard binary (brakes with `guard pre-bash`) was not found; running on the loose fallback, which checks only merges, `apply --remote` and the `human-approved` label. Install it with `cargo install --locked --git https://github.com/gemba-app/brakes`, or set BRAKES_BIN.' >&2

# A `gh` word with a `merge` word anywhere after it, in the JSON text: a
# newline or tab before `gh` arrives as `\n` or `\t`. Else a `gh` word with a
# `human-approved` word after it, in any case, before the next `\n` escape
# (`\\` is an escaped backslash, not the start of one), as the guard's
# `mentions_label`. Else an `apply` word and a `--remote` word, in either order.
payload=$(cat)
# A secret `.env` file named as a whole path component, or followed by a glob,
# as the guard's `names_secret_env`; a `\t` or `\n` escape counts as a separator.
if printf '%s' "$payload" |
    grep -Eq '(^|[^A-Za-z0-9_.$\\-]|\\[nt])\.env((\.(local|development|production|test|staging))?([^A-Za-z0-9_.-]|$)|(\.[A-Za-z0-9_-]*)?[*?[])'; then
    printf '%s\n' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"The merge guard binary (brakes with `guard pre-bash`) was not found; agent sessions may not read, copy or source a secret `.env` file (#1309), and this command names one. Install it with `cargo install --locked --git https://github.com/gemba-app/brakes`, or set BRAKES_BIN to its path."}}'
elif printf '%s' "$payload" |
    grep -Eq '(^|[^A-Za-z0-9_.-]|\\[nt])gh([^A-Za-z0-9_.-]|$).*merge([^A-Za-z0-9_-]|$)'; then
    printf '%s\n' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"The merge guard binary (brakes with `guard pre-bash`) was not found, so this merge cannot be checked; never merge on red. Install it with `cargo install --locked --git https://github.com/gemba-app/brakes`, or set BRAKES_BIN to its path."}}'
elif printf '%s' "$payload" |
    grep -Eiq '(^|[^A-Za-z0-9_-]|\\[nt])gh([^A-Za-z0-9_\\-]|\\[^n])(([^\\]|\\[^n])*([^A-Za-z0-9_-]|\\t))?human-approved([^A-Za-z0-9_-]|$)'; then
    printf '%s\n' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"The merge guard binary (brakes with `guard pre-bash`) was not found, so this command cannot be checked; agent sessions may not set, remove or redefine the label `human-approved`. Install it with `cargo install --locked --git https://github.com/gemba-app/brakes`, or set BRAKES_BIN to its path."}}'
elif printf '%s' "$payload" | grep -Eq '(^|[^A-Za-z0-9_-]|\\[nt])apply([^A-Za-z0-9_-]|$)' &&
    printf '%s' "$payload" | grep -Eq -e '(^|[^A-Za-z0-9_-]|\\[nt])--remote([^A-Za-z0-9_-]|$)'; then
    printf '%s\n' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"The merge guard binary (brakes with `guard pre-bash`) was not found, so this command cannot be checked; agent sessions may not run `brakes apply --remote`, the owner runs it by hand. Install it with `cargo install --locked --git https://github.com/gemba-app/brakes`, or set BRAKES_BIN to its path."}}'
fi
exit 0
