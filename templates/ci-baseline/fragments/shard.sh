#!/usr/bin/env bash
# ci-baseline: runs one shard of the declared ci.shards.command, read at run
# time from .agent-setup/project.json with `<i>` replaced by this shard's index.
# SHARD (1-based) and COUNT arrive through `env:`. An absent command fails red.
set -euo pipefail

: "${SHARD:?SHARD is not set}"
: "${COUNT:?COUNT is not set}"
template="$(jq -r '.ci.shards.command // empty' .agent-setup/project.json)"
if [ -z "$template" ]; then
  echo "::error::Verification command missing: ci.shards.command is not declared in .agent-setup/project.json"
  exit 1
fi
cmd=${template//"<i>"/"$SHARD"}
echo "shard $SHARD/$COUNT: $cmd"
bash -euo pipefail -c "$cmd"
