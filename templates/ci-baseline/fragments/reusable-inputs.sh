#!/usr/bin/env bash
# ci-baseline: the reusable verify workflow's first step. Checks the caller's
# inputs before anything runs: the stack and the runner label from the two
# enums the installer renders, the tier, the command names, and two paths that
# stay inside the checkout. Every input arrives through `env:`.
#   STACK, RUNS_ON, TIER, COMMANDS, WORKING_DIRECTORY, PROFILE_PATH  the inputs
#   STACKS   the stacks this workflow sets up, space-separated
#   LABELS   the runner labels a caller may pass, JSON-quoted, space-separated
set -euo pipefail

fail() {
  printf '::error::%s\n' "$1"
  exit 1
}

case " ${STACKS:?} " in *" ${STACK:-} "*) ;; *) fail "stack '${STACK:-}' is not one of: $STACKS" ;; esac
case " ${LABELS:?} " in *" ${RUNS_ON:-} "*) ;; *) fail "runs-on '${RUNS_ON:-}' is not one of: $LABELS" ;; esac
case "${TIER:-}" in full | docs) ;; *) fail "tier '${TIER:-}' is not full or docs" ;; esac
if ! printf '%s' "${COMMANDS:-}" | jq -e 'type == "array" and length > 0 and all(.[]; . == "lint" or . == "test" or . == "verify" or . == "build")' >/dev/null 2>&1; then
  fail "commands '${COMMANDS:-}' is not a JSON array of lint, test, verify and build"
fi
for path in "${WORKING_DIRECTORY:-}" "${PROFILE_PATH:-}"; do
  case "/$path/" in //* | */../* | *//*) fail "path '$path' is not a relative path inside the checkout" ;; esac
done
echo "inputs: stack $STACK, runs-on $RUNS_ON, tier $TIER, commands $COMMANDS"
