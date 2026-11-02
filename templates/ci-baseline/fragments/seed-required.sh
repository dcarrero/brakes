#!/usr/bin/env bash
# ci-baseline seed: the project's aggregate check. It passes only when every job
# it needs succeeded; a failed, cancelled or skipped job fails it, so a red or
# missing check never passes as green. NEEDS (`toJSON(needs)`) arrives through `env:`.
set -euo pipefail

: "${NEEDS:?NEEDS is not set}"
if ! failed="$(printf '%s' "$NEEDS" | jq -er 'if type == "object" and length > 0 then [to_entries[] | select(.value.result != "success") | "\(.key): \(.value.result)"] | join("\n") else error("no jobs") end')"; then
  echo "::error::required: cannot read the results of the jobs it needs"
  exit 1
fi
if [ -n "$failed" ]; then
  while IFS= read -r line; do
    printf '::error::required: %s\n' "$line"
  done <<< "$failed"
  exit 1
fi
echo "required: every job succeeded"
