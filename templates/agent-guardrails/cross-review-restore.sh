#!/usr/bin/env bash
# agent-guardrails: a step of the `cross-review-model` job (SPEC-agent-guardrails.md,
# "CI hardening for agent workflows", "Instruction files from the base"). The
# reviewer reads the agent instruction files of the checkout as instructions, so
# before it starts every `AGENTS.md`, `AGENTS.override.md`, `CLAUDE.md` and
# `CLAUDE.local.md`, at any depth, comes from the pull request's base: the ones the
# base has are restored from it, the ones only the head has are deleted. The diff
# the reviewer is asked to read still shows their changes, as data. Each restored
# or deleted path is printed. Needs git and a checkout that holds the base commit.
# The Claude reviewer runs as the CLI, not the action (#971), so what the action
# restored from the base for a pull request (its docs/security.md at the pin) comes
# from the base too: every file under a `.claude/` directory at any depth, one file
# at a time like the instruction files, and `.mcp.json`, `.claude.json`,
# `.gitmodules`, `.ripgreprc` and `.husky/` at the root, whole, or deleted when the
# base lacks them.
#
# Inputs, through the environment:
#   BASE_SHA  the base commit of the pull request
set -euo pipefail

base=${BASE_SHA:?BASE_SHA is not set}

instruction_file() {
  case "$1" in
    .claude/* | */.claude/*) return 0 ;;
  esac
  case "${1##*/}" in
    AGENTS.md | AGENTS.override.md | CLAUDE.md | CLAUDE.local.md) return 0 ;;
    *) return 1 ;;
  esac
}

restored=0
deleted=0
# A tracked path whose last component is `.claude` is a file or a link, never the
# directory the base's files go into: it goes first (a link would send them elsewhere).
while IFS= read -r -d '' path; do
  case "$path" in
    .claude | */.claude)
      rm -f -- "$path"
      printf 'cross-review: deleted %s, which is not a directory\n' "$path"
      deleted=$((deleted + 1))
      ;;
  esac
done < <(git ls-files -z)

while IFS= read -r -d '' path; do
  if instruction_file "$path"; then
    git --literal-pathspecs checkout --quiet "$base" -- "$path"
    printf 'cross-review: restored %s from the base\n' "$path"
    restored=$((restored + 1))
  fi
done < <(git ls-tree -r -z --name-only "$base")

while IFS= read -r -d '' path; do
  if instruction_file "$path" && ! git cat-file -e "$base:$path" 2>/dev/null; then
    rm -f -- "$path"
    printf 'cross-review: deleted %s, which the base lacks\n' "$path"
    deleted=$((deleted + 1))
  fi
done < <(git ls-files -z)

for path in .mcp.json .claude.json .gitmodules .ripgreprc .husky; do
  if git cat-file -e "$base:$path" 2>/dev/null; then
    rm -rf -- "$path"
    git --literal-pathspecs checkout --quiet "$base" -- "$path"
    printf 'cross-review: restored %s from the base\n' "$path"
    restored=$((restored + 1))
  elif [ -e "$path" ]; then
    rm -rf -- "$path"
    printf 'cross-review: deleted %s, which the base lacks\n' "$path"
    deleted=$((deleted + 1))
  fi
done

printf 'cross-review: instruction files from the base: %s restored, %s deleted\n' "$restored" "$deleted"
