#!/usr/bin/env bash
# ci-baseline: draws the held-out properties' seed, fresh on every run. A
# property drawn from new random inputs each run cannot be memorised; the
# printed seed is what replays a failure locally with the same command.
# The step's output `seed` reaches the next step through its `env:`.
set -euo pipefail

: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is not set}"
seed="$(od -An -N4 -tu4 /dev/urandom | tr -d ' \n')"
[[ "$seed" =~ ^[0-9]+$ ]] || { echo "heldout-seed: no seed drawn from /dev/urandom" >&2; exit 1; }
echo "seed: $seed"
echo "seed=$seed" >> "$GITHUB_OUTPUT"
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  printf 'Held-out properties\n\nseed: %s\n\nReplay a failure locally with HELDOUT_SEED=%s and the same command.\n' "$seed" "$seed" >> "$GITHUB_STEP_SUMMARY"
fi
