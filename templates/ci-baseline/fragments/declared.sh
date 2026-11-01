#!/usr/bin/env bash
# ci-baseline: runs one declared command, read at run time from
# .agent-setup/project.json; the workflow never carries the command itself.
# NAME (the commands.<name> key) arrives through `env:`. A null or absent
# command fails the job red, so a deleted command cannot pass the gate.
set -euo pipefail

: "${NAME:?NAME is not set}"
cmd="$(jq -r --arg name "$NAME" '.commands[$name] // empty' .agent-setup/project.json)"
if [ -z "$cmd" ]; then
  echo "::error::Verification command missing: commands.$NAME is not declared in .agent-setup/project.json"
  exit 1
fi
echo "$NAME: $cmd"
bash -euo pipefail -c "$cmd"
