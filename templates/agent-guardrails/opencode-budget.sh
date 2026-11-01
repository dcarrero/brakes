#!/usr/bin/env bash
# agent-guardrails: the DeepSeek reviewer's step budget (#1240; SPEC-agent-guardrails.md,
# "CI hardening for agent workflows", DeepSeek; decision "The DeepSeek judge", amended
# #1240). A fixed cap could not finish a large change, and a review that does not
# finish blocks (#1223). The runner counts the change in its own checkout before the
# model starts: one step per changed file (the prompt reads file by file), one per
# thousand changed lines (what OpenCode cuts at 50 KB is read in parts), and twenty
# for the plan, the description, failed calls and the answer; never below the floor,
# never above the hard cap that bounds the cost. Prints the budget alone on stdout and
# one log line on stderr; never a path or a line of the change.
#
# Inputs, through the environment:
#   REPO_DIR             the runner's checkout of the head
#   BASE_SHA, HEAD_SHA   the pull request's base and head commits
#   OPENCODE_STEP_FLOOR  the least budget (60 since #1256: small changes read around their diff)
#   OPENCODE_STEP_MAX    the hard cap
set -euo pipefail

fail() {
  printf '::error::cross-review: %s; refusing to review\n' "$1" >&2
  exit 1
}

repo=${REPO_DIR:?REPO_DIR names the checkout}
floor=${OPENCODE_STEP_FLOOR:?OPENCODE_STEP_FLOOR names the least budget}
max=${OPENCODE_STEP_MAX:?OPENCODE_STEP_MAX names the hard cap}
[[ $floor =~ ^[0-9]+$ && $max =~ ^[0-9]+$ ]] || fail "the step bounds are not numbers"
for sha in "${BASE_SHA:-}" "${HEAD_SHA:-}"; do
  [[ $sha =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]] || fail "the base or head is not a commit SHA"
done

# --numstat: added, deleted and path per file ("-" for a binary file); no renames, so
# a moved file counts as read; no external diff or textconv driver ever runs.
numstat=$(git -C "$repo" diff --numstat --no-renames --no-ext-diff --no-textconv \
  "$BASE_SHA...$HEAD_SHA" 2>/dev/null) || fail "could not count the change between the base and the head"
read -r files lines < <(printf '%s\n' "$numstat" | awk -F '\t' '
  NF >= 3 { files++; if ($1 ~ /^[0-9]+$/) lines += $1; if ($2 ~ /^[0-9]+$/) lines += $2 }
  END { printf "%d %d\n", files, lines }')

budget=$((20 + files + (lines + 999) / 1000))
if [ "$budget" -lt "$floor" ]; then budget=$floor; fi
if [ "$budget" -gt "$max" ]; then budget=$max; fi
printf 'cross-review: deepseek step budget %s (%s files, %s lines changed; floor %s, cap %s)\n' \
  "$budget" "$files" "$lines" "$floor" "$max" >&2
printf '%s\n' "$budget"
