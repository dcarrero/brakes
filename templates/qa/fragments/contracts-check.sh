#!/usr/bin/env bash
# contracts-check.sh, the check of qa-contracts (SPEC-qa.md, Contracts): lint the
# answered contracts and, on a pull request, compare each with the base's file
# or with its declared published copy (#1182).
# Inputs, all from `env:`:
#   QA_STAGE             lint | compat
#   QA_OUT               the report directory (default $RUNNER_TEMP/qa/contracts),
#                        uploaded as the artifact
#   QA_OPENAPI           the OpenAPI 3 contracts, separated by commas, or empty
#   QA_ASYNCAPI          the AsyncAPI contracts, separated by commas, or empty
#   QA_PUBLISHED         <live>=<published> pairs separated by commas, or empty
#   QA_CONTRACT_RULESET  vacuum's ruleset, or empty
#   QA_VACUUM_VERSION, QA_ASYNCAPI_VERSION   for the claim lines
#   PR_LABELS            the pull request's labels as a JSON array
# Before any tool runs, a `$ref` that does not start with `#` refuses: the
# tools would read other files or the network. The base is the merge commit's
# first parent, read from the checkout's object store.
set -euo pipefail

out=${QA_OUT:-${RUNNER_TEMP:?RUNNER_TEMP is not set}/qa/contracts}
mkdir -p "$out"

fail() {
  printf '::error::qa-contracts: %s\n' "$1"
  exit 1
}

# `<file>:<line> has an external $ref (<value>)` for the first `$ref` whose
# value does not start with `#`, YAML `$ref:` and JSON `"$ref":` alike.
external_ref() {
  awk -v file="$1" '
    {
      line = $0
      while (match(line, /"?\$ref"?[[:space:]]*:[[:space:]]*/)) {
        rest = substr(line, RSTART + RLENGTH)
        quote = substr(rest, 1, 1)
        if (quote == "\"" || quote == "\047") {
          rest = substr(rest, 2)
          value = substr(rest, 1, index(rest, quote) - 1)
        } else {
          match(rest, /^[^,}[:space:]]*/)
          value = substr(rest, 1, RLENGTH)
        }
        if (substr(value, 1, 1) != "#") {
          printf "%s:%d has an external $ref (%s)\n", file, NR, value
          exit
        }
        line = rest
      }
    }' "$1"
}

# The comma-separated lists as arrays.
IFS=, read -r -a openapi <<< "${QA_OPENAPI:-}"
IFS=, read -r -a asyncapi <<< "${QA_ASYNCAPI:-}"
IFS=, read -r -a published <<< "${QA_PUBLISHED:-}"

# The declared published copy of live contract `$1`, or nothing.
published_of() {
  local pair
  for pair in ${published[@]+"${published[@]}"}; do
    if [ "${pair%%=*}" = "$1" ]; then
      printf '%s\n' "${pair#*=}"
      return 0
    fi
  done
}

# `$out/<dir>/<contract>.<ext>`, its directory created.
report_of() {
  mkdir -p "$out/$1/$(dirname "$2")"
  printf '%s\n' "$out/$1/$2.$3"
}

for contract in ${openapi[@]+"${openapi[@]}"} ${asyncapi[@]+"${asyncapi[@]}"}; do
  found=$(external_ref "$contract")
  [ -z "$found" ] || fail "$found; bundle the contract into one file (docs/agent-setup/qa.md)"
  copy=$(published_of "$contract")
  if [ -n "$copy" ]; then
    found=$(external_ref "$copy")
    [ -z "$found" ] || fail "$found; bundle the contract into one file (docs/agent-setup/qa.md)"
  fi
done

lint() {
  for contract in ${openapi[@]+"${openapi[@]}"}; do
    args=(lint --details --no-style --no-banner --no-update-check --remote=false --fail-severity error)
    [ -z "${QA_CONTRACT_RULESET:-}" ] || args+=(--ruleset "$QA_CONTRACT_RULESET")
    if vacuum "${args[@]}" "$contract" 2>&1 | tee "$(report_of vacuum-lint "$contract" txt)"; then
      printf 'contract-lint: %s ok (vacuum %s)\n' "$contract" "${QA_VACUUM_VERSION:-}"
    else
      fail "$contract fails lint (vacuum); see the report artifact"
    fi
  done
  for contract in ${asyncapi[@]+"${asyncapi[@]}"}; do
    if asyncapi validate "$contract" --fail-severity error 2>&1 | tee "$(report_of asyncapi-validate "$contract" txt)"; then
      printf 'contract-lint: %s ok (asyncapi %s)\n' "$contract" "${QA_ASYNCAPI_VERSION:-}"
    else
      fail "$contract fails lint (asyncapi); see the report artifact"
    fi
  done
}

# Writes HEAD^1's copy of `$1` under `$out/base/` and prints its path; prints
# nothing when the base lacks the file. `./` makes git read the path relative
# to the current directory, an app's in monorepo mode (gitrevisions(7)).
base_of() {
  if ! git cat-file -e "HEAD^1:./$1" 2>/dev/null; then
    return 0
  fi
  mkdir -p "$out/base/$(dirname "$1")"
  git show "HEAD^1:./$1" > "$out/base/$1"
  printf '%s\n' "$out/base/$1"
}

# Judges `$2` breaking changes in contract `$1` against `$3` (`the base` or a
# published copy): red unless `human-approved`.
judge() {
  if [ "$2" -eq 0 ]; then
    printf 'contract-compatible: %s ok\n' "$1"
  elif [ "$approved" = true ]; then
    printf '::warning::qa-contracts: %s breaking changes accepted by human-approved\n' "$1"
    printf 'contract-compatible: %s accepted (%s breaking)\n' "$1" "$2"
  else
    fail "$1 breaks clients of $3 ($2 breaking changes); add the human-approved label if the break is intended"
  fi
}

# Sets `base` to the baseline of live contract `$1` and `against` to how the
# failure names it: its declared published copy, which must not change unless
# `human-approved`, else HEAD^1's copy of it (`the base`); `base` is empty when
# the base lacks the contract.
baseline_of() {
  local copy previous
  copy=$(published_of "$1")
  if [ -z "$copy" ]; then
    base=$(base_of "$1")
    against="the base"
    return 0
  fi
  previous=$(base_of "$copy")
  if [ -n "$previous" ] && ! cmp -s "$previous" "$copy"; then
    if [ "$approved" = true ]; then
      printf '::warning::qa-contracts: %s published copy changed under human-approved\n' "$copy"
    else
      fail "$copy is a published copy and changes in this pull request; add the human-approved label if the new version is intended"
    fi
  fi
  base=$copy
  against=$copy
}

compat() {
  parents=$(git rev-list --parents -n 1 HEAD | wc -w)
  [ "$parents" -ge 3 ] || fail "HEAD is not a merge commit; cannot find the base"
  approved=false
  if printf '%s' "${PR_LABELS:-[]}" | jq -e 'type == "array" and index("human-approved") != null' > /dev/null 2>&1; then
    approved=true
  fi
  for contract in ${openapi[@]+"${openapi[@]}"}; do
    baseline_of "$contract"
    if [ -z "$base" ]; then
      printf 'contract-compatible: %s new in this pull request; nothing to compare\n' "$contract"
      continue
    fi
    report=$(report_of oasdiff-breaking "$contract" txt)
    code=0
    oasdiff breaking --fail-on ERR --allow-external-refs=false --format text "$base" "$contract" > "$report" 2>&1 || code=$?
    cat "$report"
    case $code in
      0) judge "$contract" 0 "$against" ;;
      1)
        # The title line oasdiff prints: `<n> changes: <e> error, <w> warning, <i> info`.
        errors=$(sed -n 's/^[0-9][0-9]* changes: \([0-9][0-9]*\) error.*/\1/p' "$report" | head -n 1)
        judge "$contract" "${errors:-1}" "$against"
        ;;
      *) fail "$contract could not be compared (oasdiff exit $code); see the report artifact" ;;
    esac
  done
  for contract in ${asyncapi[@]+"${asyncapi[@]}"}; do
    baseline_of "$contract"
    if [ -z "$base" ]; then
      printf 'contract-compatible: %s new in this pull request; nothing to compare\n' "$contract"
      continue
    fi
    report=$(report_of asyncapi-diff "$contract" json)
    code=0
    asyncapi diff "$base" "$contract" --type breaking --format json --no-error > "$report" || code=$?
    [ "$code" -eq 0 ] || fail "$contract could not be compared (asyncapi exit $code); see the report artifact"
    count=$(node -e 'const a = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")); if (!Array.isArray(a)) process.exit(2); console.log(a.length)' "$report") \
      || fail "$contract could not be compared (asyncapi diff wrote no JSON array); see the report artifact"
    judge "$contract" "$count" "$against"
  done
}

case ${QA_STAGE:?QA_STAGE is not set} in
  lint) lint ;;
  compat) compat ;;
  *) fail "unknown stage $QA_STAGE" ;;
esac
