#!/usr/bin/env bash
# coverage-ratchet.sh: the comparison step of `coverage-ratchet`
# (SPEC-security.md, "Coverage ratchet as built"). Each covered app's
# measurement step has written its report; this reads one number from each,
# the line percentage, with the stack pack's jq filter, and compares it with
# the app's entry of .agent-setup/coverage.json. It needs bash and jq only.
#
# Usage: coverage-ratchet.sh [repository-root]
#   COVERAGE_APPS       JSON array of {"app", "report", "metric"}: the app id,
#                       its report relative to the root and the jq filter
#   COVERAGE_TOLERANCE  percentage points a measurement may fall below the
#                       record (default 0.5)
#
# Below `record - tolerance` is an error, above `record + 1` a warning to
# ratchet the record up. A lower record is a pull request of its own, which
# the exceptions check of `security-gate` lets through only with an active
# coverage-reset. Exit 1 when any line is an error.
set -euo pipefail

cd "${1:-.}"
record=.agent-setup/coverage.json
apps="${COVERAGE_APPS:?COVERAGE_APPS is required}"
tolerance="${COVERAGE_TOLERANCE:-0.5}"

if [ ! -e "$record" ]; then
  echo "::error::$record is absent"
  exit 1
fi
if ! jq -e 'type == "object" and .schema == 1 and (.apps | type) == "object" and (.apps | all(type == "number"))' \
  "$record" > /dev/null 2>&1; then
  echo "::error::$record does not parse"
  exit 1
fi

failed=false
while IFS=$'\t' read -r app report metric; do
  if [ ! -e "$report" ]; then
    echo "::error::Coverage report $report of $app is absent"
    failed=true
    continue
  fi
  if ! line=$(jq -r --arg app "$app" --arg record "$record" --argjson t "$tolerance" \
    --slurpfile rec "$record" "
    ($metric) as \$m
    | if (\$m | type) != \"number\" then \"::error::Coverage metric of \\(\$app) is not a number\"
      else \$rec[0].apps[\$app] as \$r
      | ((\$m * 100 | round) / 100) as \$shown
      | if \$r == null then \"::error::\\(\$record) has no record for \\(\$app)\"
        elif \$m < \$r - \$t then \"::error title=coverage \\(\$app)::Coverage \\(\$shown) below recorded \\(\$r + 0) (tolerance \\(\$t))\"
        elif \$m > \$r + 1 then \"::warning title=coverage \\(\$app)::Coverage \\(\$shown); ratchet the record up\"
        else \"coverage \\(\$app): \\(\$shown) (recorded \\(\$r + 0))\" end
      end" "$report" 2> /dev/null); then
    line="::error::Coverage metric of $app is not a number"
  fi
  echo "$line"
  case "$line" in
    "::error"*) failed=true ;;
  esac
done < <(jq -r '.[] | [.app, .report, .metric] | @tsv' <<< "$apps")

if [ "$failed" = true ]; then
  exit 1
fi
