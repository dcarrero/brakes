#!/usr/bin/env bash
# agent-guardrails: the `cross-review` gate job (SPEC-agent-guardrails.md,
# "Cross-family review as a required check" and "CI hardening for agent workflows").
# Neither reviewer action fails on findings by itself, so this job reads the verdict
# `cross-review-model` emitted as its job output, posts it as one pull-request
# comment and decides with its exit code, never with prose. This job is the only
# one that holds `pull-requests: write`, and it runs no model: before anything is
# posted it fails closed on an empty verdict (GitHub drops a job output that
# contains a secret, so a leaked secret arrives empty), on one over 60 000 bytes,
# on one carrying a credential-shaped token, and on one that is not the findings
# object; each message names the check and never the text. A verdict that says the
# review did not cover the whole change (`reviewed_all` false or a non-empty
# `not_reviewed`; #1223) gains one blocking P0 "Review incomplete" naming what was
# skipped, whatever `BLOCKING` lists: a partial review never passes.
#
# Inputs, all through the environment (reviewer text never reaches this shell inline):
#   FINDINGS     the verdict: {"summary": str, "reviewed_all": bool,
#                "not_reviewed": [str], "findings": [{"severity": "P0".."P3",
#                "path": str, "line": int, "title": str, "detail": str}]}
#   BLOCKING     the severities that block, space-separated (`P0 P1` or `P0`)
#   REVIEWER     the reviewer's family, for messages
#   PR_NUMBER    the pull request to comment on
#   RUNNER_TEMP  where the comment body is written
#   GH_TOKEN, GH_REPO  read by `gh pr comment`
#   VERDICT_MAX_BYTES  the size cap (60000 unless the job says otherwise)
set -euo pipefail

reviewer=${REVIEWER:-the reviewer}
max_bytes=${VERDICT_MAX_BYTES:-60000}
verdict=${FINDINGS:-}
if [ -z "${verdict//[[:space:]]/}" ]; then
  printf '::error::cross-review: %s returned an empty verdict (GitHub drops a job output that contains a secret); refusing to pass\n' "$reviewer"
  exit 1
fi
bytes="$(LC_ALL=C; printf '%s' "${#verdict}")"
if [ "$bytes" -gt "$max_bytes" ]; then
  printf '::error::cross-review: %s returned a verdict of %s bytes, over the %s allowed; refusing to pass\n' "$reviewer" "$bytes" "$max_bytes"
  exit 1
fi
# Credential shapes, each at a word boundary (a JSON-escaped line break counts as
# one): vendor and GitHub token prefixes followed by at least 20 token characters,
# an AWS access key id, a PEM private key.
boundary='(^|[^A-Za-z0-9_]|\\[nrt])'
credential="$boundary(sk-ant-|sk-|ghp_|gho_|ghs_|ghu_|github_pat_|xoxb-)[A-Za-z0-9_-]{20}"
credential="$credential|${boundary}AKIA[A-Z0-9]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----"
if printf '%s' "$verdict" | LC_ALL=C grep -q -E -e "$credential"; then
  printf '::error::cross-review: the verdict carries a credential-shaped token; refusing to post it\n'
  exit 1
fi
blocking=${BLOCKING:-}
for level in $blocking; do
  case "$level" in
    P0 | P1 | P2 | P3) ;;
    *)
      printf "::error::cross-review: BLOCKING must list P0 to P3, got '%s'\\n" "$blocking"
      exit 1
      ;;
  esac
done
blocking_json="$(jq -n -c --arg levels "$blocking" '$levels | split(" ") | map(select(length > 0))')"

shape='type == "object"
  and (.summary | type == "string")
  and (.reviewed_all | type == "boolean")
  and (.not_reviewed | type == "array")
  and all(.not_reviewed[]; type == "string")
  and (.findings | type == "array")
  and all(.findings[];
    type == "object"
    and (.severity | IN("P0", "P1", "P2", "P3"))
    and (.path | type == "string")
    and (.line | type == "number")
    and (.title | type == "string")
    and (.detail | type == "string"))'
if ! printf '%s' "${FINDINGS:-}" | jq -e "$shape" >/dev/null 2>&1; then
  printf '::error::cross-review: %s returned no findings object; refusing to pass\n' "$reviewer"
  exit 1
fi

# An incomplete review: one blocking P0 naming what was skipped (escaped as below).
if printf '%s' "$FINDINGS" | jq -e '(.reviewed_all | not) or (.not_reviewed | length > 0)' >/dev/null; then
  skipped="$(printf '%s' "$FINDINGS" | jq -r '
    if (.not_reviewed | length) > 0 then .not_reviewed | join(", ") else "" end')"
  FINDINGS="$(printf '%s' "$FINDINGS" | jq -c --arg skipped "$skipped" '.findings += [{
    severity: "P0", path: "", line: 0, title: "Review incomplete",
    detail: "Not reviewed: \(if $skipped == "" then "unnamed by the reviewer" else $skipped end)"}]')"
  blocking_json="$(jq -n -c --argjson levels "$blocking_json" '$levels + ["P0"] | unique')"
  if [ -z "$skipped" ]; then
    printf '::error::cross-review: %s did not review everything and named nothing it skipped\n' "$reviewer"
  else
    printf '%s' "$skipped" | jq -R -s -r --arg reviewer "$reviewer" '
      "cross-review: \($reviewer) did not review \(.)"
      | gsub("%"; "%25") | gsub("\r"; "%0D") | gsub("\n"; "%0A")
      | "::error::" + .'
  fi
fi

comment="${RUNNER_TEMP:?RUNNER_TEMP is not set}/cross-review-comment.md"
printf '%s' "$FINDINGS" | jq -r --arg reviewer "$reviewer" --argjson blocking "$blocking_json" '
  "## Cross-family review (\($reviewer))\n\n\(.summary)\n\n"
  + if (.findings | length) == 0 then "No findings.\n"
    else (.findings
      | map("- **\(.severity)**"
          + (if (.severity | IN($blocking[])) then " (blocking)" else "" end)
          + " `\(.path):\(.line)` \(.title)\n  \(.detail)")
      | join("\n")) + "\n"
    end' >"$comment"
if ! gh pr comment "${PR_NUMBER:?PR_NUMBER is not set}" --body-file "$comment"; then
  printf '::warning::cross-review: could not post the findings comment on #%s\n' "$PR_NUMBER"
fi

# One ::error:: line per blocking finding; `%`, CR and LF escaped as GitHub's
# workflow commands require, so reviewer text cannot start a command of its own.
printf '%s' "$FINDINGS" | jq -r --argjson blocking "$blocking_json" '
  .findings[]
  | select(.severity | IN($blocking[]))
  | "\(.severity) \(.path):\(.line) \(.title)"
  | gsub("%"; "%25") | gsub("\r"; "%0D") | gsub("\n"; "%0A")
  | "::error::" + .'
count="$(printf '%s' "$FINDINGS" | jq --argjson blocking "$blocking_json" \
  '[.findings[] | select(.severity | IN($blocking[]))] | length')"
printf 'cross-review: %s blocking findings (%s)\n' "$count" "$blocking"
if [ "$count" -ne 0 ]; then
  exit 1
fi
