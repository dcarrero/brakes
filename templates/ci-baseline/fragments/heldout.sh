#!/usr/bin/env bash
# ci-baseline: runs the held-out tests, the suite an agent may not edit.
# HELDOUT_COMMAND (the heldout_command answer, baked in at render time) arrives
# through `env:`; it runs under pipefail like a declared command. An empty
# command fails the job red, so the job never passes without running them.
set -euo pipefail

: "${HELDOUT_COMMAND:?HELDOUT_COMMAND is not set}"
echo "heldout: $HELDOUT_COMMAND"
bash -euo pipefail -c "$HELDOUT_COMMAND"
