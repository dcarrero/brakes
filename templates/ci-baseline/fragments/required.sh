#!/usr/bin/env bash
# The aggregate `required` job: the one required status check of the generated
# workflow (SPEC-ci-baseline.md, "Aggregate job: exact logic"). It runs with
# `if: always()` and needs `scope` and every verification job, because GitHub counts
# a skipped job as a passing required check. Inputs come through `env:` only:
#   SCOPE      needs.scope.result
#   TIER       needs.scope.outputs.tier       (full | docs)
#   SKIPPABLE  needs.scope.outputs.skippable  (JSON array of job ids that may be skipped)
#   NEEDS      toJSON(needs)                  (job id -> { result, outputs })
#   EVENT      github.event_name
#   PROTECTED  needs.scope.outputs.protected  (JSON array of changed protected paths;
#                                              ["<unknown>"] when they could not be listed)
#   PR_LABELS  toJSON(github.event.pull_request.labels.*.name)
#   PR_NUMBER, REPOSITORY, GH_TOKEN   github.event.pull_request.number, github.repository,
#                                     github.token (issues: read, pull-requests: read)
#   EVENT_ACTION, EVENT_LABEL         github.event.action, github.event.label.name
#   SENDER_LOGIN, SENDER_TYPE         github.event.sender.login, github.event.sender.type
# On a pull request that changed a protected path, the label `human-approved` must be
# present (rule 3); a PROTECTED that is not a JSON array of strings counts as
# "<unknown>" and labels that are not one count as no label, so the gate fails closed.
# The label counts only when a person added it (#1255), checked whenever it is on the
# pull request: the most recent `labeled` event for it, read through the API, and the sender of a run triggered
# by adding it, must be a `User` whose login does not end in `[bot]`, not acting
# through an App. Anything that cannot be read fails closed.
# Exit 0 only when every job besides scope is `success`, or `skipped` and listed in
# SKIPPABLE. Anything else fails, naming the job and its result, one line per job.
set -euo pipefail

# One tab-separated verdict for an actor: `person` or `other`, the login and type
# reduced to the characters GitHub allows (so a log line cannot carry a workflow
# command; `-` when empty), and `, via an App` when an App acted for the user.
# shellcheck disable=SC2016 # a jq program: its $names are jq variables.
VERDICT='def verdict($login; $type; $app):
  [ (if $type == "User" and $login != "" and ($login | endswith("[bot]") | not) and $app == null
     then "person" else "other" end),
    ($login | gsub("[^A-Za-z0-9\\[\\]-]"; "") | if . == "" then "-" else . end),
    ($type | gsub("[^A-Za-z]"; "") | if . == "" then "-" else . end),
    (if $app == null then "" else ", via an App" end) ] | @tsv;'

if [ "${SCOPE:-}" != success ]; then
  printf '::error::scope did not run; refusing to pass (scope result: %s)\n' "${SCOPE:-missing}"
  exit 1
fi
case "${TIER:-}" in
  full | docs) ;;
  *)
    printf "::error::scope did not decide a tier (tier: '%s')\\n" "${TIER:-}"
    exit 1
    ;;
esac
# Rule 3: a protected path changed in a pull request needs a human's label.
if [ "${EVENT:-}" = pull_request ]; then
  if ! protected="$(printf '%s' "${PROTECTED:-}" | jq -er 'if type == "array" and all(type == "string") then (if index("<unknown>") != null then "<unknown>" else join(", ") end) else error("unreadable") end' 2>/dev/null)"; then
    protected='<unknown>'
  fi
  approved=false
  if printf '%s' "${PR_LABELS:-}" | jq -e 'type == "array" and index("human-approved") != null' >/dev/null 2>&1; then
    approved=true
  fi
  # Checked whenever the label is present, a protected path or not: other jobs
  # (the contract check of qa) accept a change because of it.
  if $approved; then
    tab="$(printf '\t')"
    refuse_actor() {
      printf '::error::Label human-approved was last added by %s (%s)%s, not by a person; a person must remove it and add it again\n' "$2" "$3" "$4"
      exit 1
    }
    # A run triggered by adding the label: its sender, from the payload, must be a person
    # too, so an events list that lags behind the event cannot approve.
    if [ "${EVENT_ACTION:-}" = labeled ] &&
      [ "$(printf '%s' "${EVENT_LABEL:-}" | tr '[:upper:]' '[:lower:]')" = human-approved ]; then
      sender="$(jq -nr --arg l "${SENDER_LOGIN:-}" --arg t "${SENDER_TYPE:-}" "$VERDICT"' verdict($l; $t; null)')"
      IFS="$tab" read -r kind login type via <<EOF
$sender
EOF
      [ "$kind" = person ] || refuse_actor "$kind" "$login" "$type" "$via"
    fi
    last=''
    if [ -n "${PR_NUMBER:-}" ] && [ -n "${REPOSITORY:-}" ] &&
      events="$(gh api --paginate "repos/${REPOSITORY}/issues/${PR_NUMBER}/events?per_page=100" 2>/dev/null)"; then
      last="$(printf '%s' "$events" | jq -ser "$VERDICT"'
        if length > 0 and all(.[]; type == "array") and all(.[][]; type == "object") then
          [ .[][] | select(.event == "labeled" and ((.label.name // "") | ascii_downcase) == "human-approved") ]
          | sort_by([(.created_at // ""), (.id // 0)])
          | if length == 0 then "none"
            else last | verdict((.actor.login // "") | tostring; (.actor.type // "") | tostring; .performed_via_github_app)
            end
        else error("unreadable") end' 2>/dev/null)" || last=''
    fi
    if [ -z "$last" ]; then
      printf '::error::Could not read who added the label human-approved; refusing to pass\n'
      exit 1
    fi
    if [ "$last" = none ]; then
      printf '::error::No labeled event for human-approved was found; refusing to pass\n'
      exit 1
    fi
    IFS="$tab" read -r kind login type via <<EOF
$last
EOF
    [ "$kind" = person ] || refuse_actor "$kind" "$login" "$type" "$via"
  fi
  if [ -z "$protected" ] && $approved; then
    printf 'protected: none (label human-approved added by %s)\n' "$login"
  elif [ -z "$protected" ]; then
    printf 'protected: none\n'
  elif $approved; then
    printf 'protected: %s (label human-approved added by %s)\n' "$protected" "$login"
  elif [ "$protected" = '<unknown>' ]; then
    printf '::error::Protected paths could not be computed; refusing to pass\n'
    exit 1
  else
    printf '::error::Protected path changed without human approval: %s\n' "$protected"
    exit 1
  fi
fi
if ! printf '%s' "${SKIPPABLE:-}" | jq -e 'type == "array" and all(type == "string")' >/dev/null 2>&1; then
  printf "::error::scope did not list skippable jobs as a JSON array of job ids (skippable: '%s')\\n" "${SKIPPABLE:-}"
  exit 1
fi
if ! printf '%s' "${NEEDS:-}" | jq -e 'type == "object"' >/dev/null 2>&1; then
  printf '::error::needs is not a JSON object; refusing to pass\n'
  exit 1
fi

# One tab-separated line per job besides scope: id, result (`missing` when absent),
# and whether scope listed the id as skippable.
verdicts="$(printf '%s' "$NEEDS" | jq -r --argjson skippable "$SKIPPABLE" '
  to_entries
  | map(select(.key != "scope"))
  | .[]
  | .key as $id
  | [ $id,
      ((.value | objects | .result | strings) // "missing"),
      (if ($skippable | index($id)) != null then "listed" else "unlisted" end) ]
  | @tsv')"
if [ -z "$verdicts" ]; then
  printf '::error::needs lists no job besides scope; refusing to pass\n'
  exit 1
fi

total=0
failed=0
while IFS="$(printf '\t')" read -r job result listed; do
  total=$((total + 1))
  case "$result" in
    success)
      printf '%s: success\n' "$job"
      ;;
    skipped)
      if [ "$listed" = listed ]; then
        printf '%s: skipped on purpose (listed as skippable under tier %s)\n' "$job" "$TIER"
      else
        printf '::error::%s: skipped, but scope did not list it as skippable under tier %s\n' "$job" "$TIER"
        failed=$((failed + 1))
      fi
      ;;
    missing)
      printf '::error::%s: no result in needs\n' "$job"
      failed=$((failed + 1))
      ;;
    *)
      printf '::error::%s: %s\n' "$job" "$result"
      failed=$((failed + 1))
      ;;
  esac
done <<EOF
$verdicts
EOF

if [ "$failed" -ne 0 ]; then
  printf 'required: %s of %s jobs did not pass under tier %s; refusing to pass\n' "$failed" "$total" "$TIER"
  exit 1
fi
printf 'required: %s jobs passed under tier %s\n' "$total" "$TIER"
