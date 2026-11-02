#!/usr/bin/env bash
# gitleaks-scan.sh: the secrets scan of `security-gate` (SPEC-security.md,
# "Contributed CI jobs"; decision 2026-11-01, #1253). Each event scans the commits
# it adds: a pull request its base..head, a push its before..after. A push that
# creates the branch (before is all zeros), `workflow_dispatch`, any other event, or
# a range that cannot be computed scans the full history ("unknown means full"). The
# checkout has the full history; a missing commit is fetched explicitly once, and a
# failed fetch means full. A full scan of a push, `workflow_dispatch` or `schedule`
# run skips the findings of the owner's reviewed `.gitleaks-baseline.json`, which
# gitleaks matches by commit, so it never hides a new one; a pull request or a merge
# group never reads it, since the change under review may have edited it. A baseline
# that is not a redacted gitleaks JSON report fails on every event.
# Prints `history: <base>..<head>`, `history: pushed <before>..<after>` or
# `history: full` before scanning; the report is SARIF with every secret redacted.
# After the scan it prints one `::error file=<path>,line=<n>::<rule>` per finding,
# read from that report: rule, path and line only, never a message or snippet
# (#1317, "A gate never re-publishes a secret"), then the count; it exits with
# gitleaks' status, or 1 when gitleaks exited 0 with findings or no readable report.
# Inputs, through `env:` only:
#   EVENT        github.event_name
#   BASE_SHA     github.event.pull_request.base.sha (empty outside pull requests)
#   HEAD_SHA     github.event.pull_request.head.sha
#   PUSH_BEFORE  github.event.before (empty outside pushes)
#   PUSH_AFTER   github.event.after
set -euo pipefail

baseline=.gitleaks-baseline.json

is_sha() {
  [[ "$1" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]] && [[ ! "$1" =~ ^0+$ ]]
}

present() {
  git cat-file -e "$1^{commit}" 2>/dev/null
}

# Sets `range` to `<from>..<to>` when both are commits of this repository, fetching
# them once; leaves it empty otherwise.
range_of() {
  local from="$1" to="$2"
  is_sha "$from" && is_sha "$to" || return 0
  if ! present "$from" || ! present "$to"; then
    if ! git fetch --no-tags --quiet origin "$from" "$to"; then
      echo "::warning::could not fetch $from and $to; scanning the full history"
    fi
  fi
  if present "$from" && present "$to"; then
    range="$from..$to"
  fi
}

if [ -e "$baseline" ] &&
  ! jq -e 'type == "array" and all(.[]; type == "object" and .Secret == "REDACTED")' \
    "$baseline" >/dev/null 2>&1; then
  echo "::error::$baseline is not a redacted gitleaks JSON report; regenerate it with --redact"
  exit 1
fi

scan=(gitleaks git --redact --exit-code 1 --report-format sarif --report-path gitleaks.sarif)
range=""
case "${EVENT:-}" in
  pull_request) range_of "${BASE_SHA:-}" "${HEAD_SHA:-}" && claim="$range" ;;
  push) range_of "${PUSH_BEFORE:-}" "${PUSH_AFTER:-}" && claim="pushed $range" ;;
esac

status=0
if [ -n "$range" ]; then
  echo "history: $claim"
  "${scan[@]}" --log-opts "$range" . || status=$?
else
  echo "history: full"
  case "${EVENT:-}" in
    push | workflow_dispatch | schedule)
      if [ -e "$baseline" ]; then
        echo "baseline: $baseline"
        scan+=(--baseline-path "$baseline")
      fi
      ;;
  esac
  "${scan[@]}" . || status=$?
fi

report=gitleaks.sarif
if ! jq -e 'type == "object"' "$report" >/dev/null 2>&1; then
  echo "::error::gitleaks wrote no readable report (exit $status)"
  if [ "$status" -eq 0 ]; then
    exit 1
  fi
  exit "$status"
fi

# Path and rule id are data from the change under review: escaped as workflow
# command properties and message, so neither can end the line or the command.
findings='[.runs[]?.results[]? | [(.locations[0].physicalLocation.artifactLocation.uri // "unknown"), (.locations[0].physicalLocation.region.startLine // 0), (.ruleId // "unknown")] | map(tostring)]'
escape='def data: gsub("%"; "%25") | gsub("\r"; "%0D") | gsub("\n"; "%0A");
  def property: data | gsub(":"; "%3A") | gsub(","; "%2C");'
jq -r "$escape $findings"' | .[] | "::error file=\(.[0] | property),line=\(.[1] | property)::\(.[2] | data)"' "$report"
count=$(jq "$findings | length" "$report")

if [ "$count" -gt 0 ]; then
  echo "::error::$count gitleaks finding(s); values withheld from the log, rotate any real credential"
  if [ "$status" -eq 0 ]; then
    exit 1
  fi
elif [ "$status" -eq 0 ]; then
  echo "gitleaks: no findings"
fi
exit "$status"
