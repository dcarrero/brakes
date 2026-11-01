#!/usr/bin/env bash
# scanner-findings.sh: what a scanner job prints of its findings (#1173,
# SPEC-security.md, "A gate never re-publishes a secret"). A run log is
# readable by anyone who can read the repository, so a matched value never
# reaches it, masked or not: one line per finding with the rule id, the path
# and the line, and for Semgrep's errors the type and the path. Messages,
# snippets, matches and metavariables stay in the report, which the job never
# prints or uploads. Arguments, through `set --`:
#   $1  semgrep | trivy
#   $2  the scanner's JSON report
#   $3  the scanner's exit status
# Exits with the scanner's status, or 1 when it exited 0 with findings.
set -euo pipefail

scanner="$1"
report="$2"
status="$3"

if ! jq -e 'type == "object"' "$report" > /dev/null 2>&1; then
  echo "::error::$scanner wrote no readable report (exit $status)"
  if [ "$status" -eq 0 ]; then
    exit 1
  fi
  exit "$status"
fi

case "$scanner" in
  semgrep)
    findings='[.results[]? | [.check_id, .path, .start.line]]'
    errors='[.errors[]? | [(.type | if type == "array" then .[0] else . end), (.path // "no path")]]'
    ;;
  trivy)
    findings='[.Results[]? | {target: .Target, secret: .Secrets[]?} | [.secret.RuleID, .target, .secret.StartLine]]'
    errors='[]'
    ;;
  *)
    echo "::error::scanner-findings.sh does not know $scanner"
    exit 1
    ;;
esac

# A path or rule id is data from the pull request: one line each, so no value
# can start a line of its own (a workflow command).
line='map(tostring | gsub("[\\r\\n]"; " "))'
jq -r --arg s "$scanner" "$findings | .[] | $line | \"\(\$s) finding: \(.[0]) at \(.[1]):\(.[2])\"" "$report"
jq -r --arg s "$scanner" "$errors | .[] | $line | \"\(\$s) error: \(.[0]) at \(.[1])\"" "$report"
count=$(jq "$findings | length" "$report")

if [ "$count" -gt 0 ]; then
  echo "::error::$count $scanner finding(s); values withheld from the log, rotate any real credential"
  if [ "$status" -eq 0 ]; then
    exit 1
  fi
elif [ "$status" -eq 0 ]; then
  echo "$scanner: no findings"
fi
exit "$status"
