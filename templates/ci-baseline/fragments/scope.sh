#!/usr/bin/env bash
# ci-baseline: the scope job. Decides the tier of this run and which jobs may
# report `skipped` on purpose. Anything unknown, any event but a pull request
# and any failure to list the changed files means tier `full` with no verification
# job skippable (only the push-only `macos`, which never runs on another event), so
# a filter can never turn the gate green over unverified work.
#
# Inputs, all through the environment (untrusted values never reach this shell
# inline), one entry per line where a list is expected:
#   EVENT           github.event_name
#   BASE_SHA        github.event.pull_request.base.sha (empty outside pull requests)
#   HEAD_SHA        github.event.pull_request.head.sha
#   INERT_PATHS     prefix globs (`docs/**`, `**/*.md`); a change made only of
#                   these is tier `docs`; `.github/workflows/**` is never inert;
#                   a negation is never evaluated and keeps `full`
#   DOCS_SKIPPABLE  job ids that may skip under tier `docs` (checks, lint, shards,
#                   contributed jobs that opted in)
#   APPS            `<id>=<path>` per app in monorepo mode; a changed path outside
#                   every app runs every app
#   PROTECTED_PATHS prefix globs whose change in a pull request needs the
#                   `human-approved` label; a protected path is never inert; a
#                   negation is never evaluated and protects nothing less
#   GITHUB_OUTPUT   the step output file
# Outputs, written to $GITHUB_OUTPUT and printed on stdout as the same lines:
#   tier=full|docs
#   skippable=<JSON array of job ids>
#   protected=<JSON array of changed protected paths>; `["<unknown>"]` when a
#             pull request's files cannot be listed; `[]` outside pull requests
#   changed-<id>=true|false   one per app, in APPS order
set -euo pipefail

: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is not set}"
event=${EVENT:-}
inert_paths=${INERT_PATHS:-}
docs_skippable=${DOCS_SKIPPABLE:-}
apps=${APPS:-}
protected_paths=${PROTECTED_PATHS:-}

emit() {
  printf '%s=%s\n' "$1" "$2" | tee -a "$GITHUB_OUTPUT"
}

# 1. List the changed files; only a pull request with both SHAs can. `diffed`
#    says the list was computed (possibly empty); `listed` that it is not empty.
#    The three-dot range compares the head with its merge base with the base, so
#    what the base branch changed after the branch point is never this pull
#    request's change (#1280); no merge base in the checkout fails the diff.
tier=full
diffed=false
listed=false
files=""
if [ "$event" = pull_request ] && [ -n "${BASE_SHA:-}" ] && [ -n "${HEAD_SHA:-}" ] \
  && files="$(git -c diff.renames=false -c core.quotePath=false diff --name-only "$BASE_SHA...$HEAD_SHA")"; then
  diffed=true
  [ -z "$files" ] || listed=true
fi

matches() {
  local glob
  while IFS= read -r glob; do
    case "$glob" in '' | '!'*) continue ;; esac
    # shellcheck disable=SC2254 # the glob must stay unquoted to act as a pattern
    case "$1" in $glob | ${glob#"**/"}) return 0 ;; esac
  done <<< "$2"
  return 1
}

# 2. The tier: docs only when every listed file matches an inert prefix glob.
negated=""
while IFS= read -r glob; do
  case "$glob" in '!'*) negated="$negated $glob" ;; esac
done <<< "$inert_paths"
if [ -n "$negated" ]; then
  echo "::warning::inert_paths carries a negation (${negated# }); negations are never evaluated, tier stays full"
fi

is_inert() {
  case "$1" in .github/workflows/*) return 1 ;; esac
  if matches "$1" "$protected_paths"; then
    return 1
  fi
  matches "$1" "$inert_paths"
}

if $listed && [ -z "$negated" ]; then
  tier=docs
  while IFS= read -r file; do
    if ! is_inert "$file"; then
      tier=full
      break
    fi
  done <<< "$files"
fi

# 3. The skippable list.
ids=""
# Each id once: an app's checks can be skippable both under docs and unchanged.
add() {
  case $'\n'"$ids" in *$'\n'"$1"$'\n'*) return 0 ;; esac
  ids="$ids$1"$'\n'
}

if [ "$event" = pull_request ]; then
  if $listed; then
    if [ "$tier" = docs ]; then
      while IFS= read -r id; do
        [ -n "$id" ] && add "$id"
      done <<< "$docs_skippable"
    fi
    workflow=false
    while IFS= read -r file; do
      case "$file" in .github/*) workflow=true ;; esac
    done <<< "$files"
    if ! $workflow; then
      add workflow-lint
    fi
  fi
fi
# The macOS job runs on pushes only (`if: github.event_name == 'push'`), so on any
# other event its skip is by design, whether or not the files could be listed
# (#784); it never stands in for a verification job.
if [ "$event" != push ]; then
  add macos
fi

# 4. Per-app change flags; an unlisted change set or a path outside every app
#    means every app changed.
changed_apps=""
outside=false
if $listed; then
  while IFS= read -r file; do
    owner=""
    while IFS= read -r app; do
      [ -n "$app" ] || continue
      id=${app%%=*}
      path=${app#*=}
      path=${path%/}
      case "$file" in "$path"/*) owner=$id; changed_apps="$changed_apps $id " ;; esac
    done <<< "$apps"
    if [ -z "$owner" ]; then
      outside=true
    fi
  done <<< "$files"
fi

flags=""
while IFS= read -r app; do
  [ -n "$app" ] || continue
  id=${app%%=*}
  changed=true
  if $listed && ! $outside; then
    case "$changed_apps" in *" $id "*) ;; *) changed=false; add "$id-checks" ;; esac
  fi
  flags="$flags$id=$changed"$'\n'
done <<< "$apps"

skippable="$(printf '%s' "$ids" | jq -R . | jq -cs .)"

# 5. The protected paths this pull request changed; unknown when it could not list.
negated=""
while IFS= read -r glob; do
  case "$glob" in '!'*) negated="$negated $glob" ;; esac
done <<< "$protected_paths"
if [ -n "$negated" ]; then
  echo "::warning::protected_paths carries a negation (${negated# }); negations are never evaluated and protect nothing less"
fi
changed_protected=""
if [ "$event" = pull_request ] && ! $diffed; then
  changed_protected='<unknown>'$'\n'
elif $listed; then
  while IFS= read -r file; do
    if matches "$file" "$protected_paths"; then
      changed_protected="$changed_protected$file"$'\n'
    fi
  done <<< "$files"
fi
protected="$(printf '%s' "$changed_protected" | jq -R . | jq -cs .)"

# 6. The claim: the same lines the workflow reads and the doctor parses.
emit tier "$tier"
emit skippable "$skippable"
emit protected "$protected"
while IFS= read -r flag; do
  [ -n "$flag" ] || continue
  emit "changed-${flag%%=*}" "${flag#*=}"
done <<< "$flags"
