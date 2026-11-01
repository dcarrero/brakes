#!/usr/bin/env bash
# ci-baseline: runs the held-out properties, the property-based tests an agent
# may neither read nor edit, with the seed the previous step drew.
# HELDOUT_PROPERTIES_COMMAND (the answer, baked in at render time),
# HELDOUT_SEED and HELDOUT_EXAMPLES arrive through `env:`; a missing one fails
# the job red, so it never passes on a deterministic or empty run.
set -euo pipefail

: "${HELDOUT_PROPERTIES_COMMAND:?HELDOUT_PROPERTIES_COMMAND is not set}"
: "${HELDOUT_SEED:?HELDOUT_SEED is not set}"
: "${HELDOUT_EXAMPLES:?HELDOUT_EXAMPLES is not set}"
echo "heldout-properties: seed $HELDOUT_SEED, at least $HELDOUT_EXAMPLES examples: $HELDOUT_PROPERTIES_COMMAND"
status=0
bash -euo pipefail -c "$HELDOUT_PROPERTIES_COMMAND" || status=$?
if (( status != 0 )); then
  echo "heldout-properties: failed; replay with HELDOUT_SEED=$HELDOUT_SEED HELDOUT_EXAMPLES=$HELDOUT_EXAMPLES and the same command"
  exit "$status"
fi
