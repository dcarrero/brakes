#!/usr/bin/env bash
# ci-baseline: the reusable verify workflow's run step. Runs each declared
# command the caller names, in order, read at run time from its profile; the
# workflow never carries a command. A null or absent command fails red, so a
# deleted command cannot pass the gate.
#   COMMANDS      JSON array of lint, test, verify, build (checked before)
#   PROFILE_PATH  the profile, relative to the working directory
set -euo pipefail

: "${COMMANDS:?COMMANDS is not set}"
: "${PROFILE_PATH:?PROFILE_PATH is not set}"
names="$(printf '%s' "$COMMANDS" | jq -r '.[]')"
while IFS= read -r name; do
  [ -n "$name" ] || continue
  cmd="$(jq -r --arg name "$name" '.commands[$name] // empty' "$PROFILE_PATH")"
  if [ -z "$cmd" ]; then
    echo "::error::Verification command missing: commands.$name is not declared in $PROFILE_PATH"
    exit 1
  fi
  echo "$name: $cmd"
  bash -euo pipefail -c "$cmd"
done <<< "$names"
