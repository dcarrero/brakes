#!/usr/bin/env bash
# ci-baseline: the held-out job before the first held-out test (#1362).
# HELDOUT_DIR (the heldout_dir answer, baked in at render time) arrives through
# `env:`. It passes only while the directory holds no file; any file fails red,
# naming it, so the job never passes over tests it did not run. The plan
# refuses the same case: heldout_command is never invented.
set -euo pipefail

: "${HELDOUT_DIR:?HELDOUT_DIR is not set}"
files=""
if [ -e "$HELDOUT_DIR" ]; then
  files="$(find "$HELDOUT_DIR" ! -type d | LC_ALL=C sort)"
fi
if [ -n "$files" ]; then
  echo "heldout: $HELDOUT_DIR holds tests and heldout_command is not answered; answer it so the job runs them"
  printf '%s\n' "$files"
  exit 1
fi
echo "heldout: no held-out tests yet under $HELDOUT_DIR; answer heldout_command when the first one lands"
