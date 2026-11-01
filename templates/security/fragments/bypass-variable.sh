#!/usr/bin/env bash
# bypass-variable.sh: the one sanctioned emergency switch (SPEC-security.md,
# "Bypass variable"). The first step of every scanning job except
# `security-gate`, which admits no variable bypass: a false positive there is a
# registered `.gitleaksignore` fingerprint.
#
# Usage: bypass-variable.sh <job-id> [repository-root]
#   SECURITY_BYPASS           `vars.SECURITY_BYPASS`: a JSON array of exception ids
#                             (empty by default)
#   SECURITY_TODAY            the date to judge expiry against (default: UTC today)
#   SECURITY_BYPASS_MAX_DAYS  bound of the short kinds (default 30)
#
# An id that names an active `job-bypass` for this job prints
# `::warning::bypass <id> until <expires> (<issue>)` and `bypass: <id>` (and
# `id=<id>` to $GITHUB_OUTPUT when set) and exits 0; the job's later steps skip
# on that output. An unknown id, another kind, another job, an invalid entry or
# an expired one fails the job with one `::error::` line each, for example
# `Bypass <id> expired on <date>; remove the variable or renew the exception`.
# The Rust twin is `exceptions::bypass`; `tests/security_gate_shell.rs` proves
# they agree. Needs bash and jq; nothing is downloaded.
set -euo pipefail

job="${1:?usage: bypass-variable.sh <job-id> [repository-root]}"
cd "${2:-.}"
today="${SECURITY_TODAY:-$(date -u +%Y-%m-%d)}"
max_days="${SECURITY_BYPASS_MAX_DAYS:-30}"
inventory=.agent-setup/security-exceptions.json
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

if [ ! -e "$inventory" ]; then
  printf '"__absent__"\n' > "$work/inventory.json"
elif jq -e . "$inventory" > /dev/null 2>&1; then
  cp "$inventory" "$work/inventory.json"
else
  printf '"__unparsed__"\n' > "$work/inventory.json"
fi

result=$(jq -n -r \
  --slurpfile inv "$work/inventory.json" \
  --arg raw "${SECURITY_BYPASS:-}" --arg job "$job" \
  --arg today "$today" --argjson max "$max_days" --arg inventory "$inventory" '
  def is_text: type == "string" and length > 0;
  def leap: . % 4 == 0 and (. % 100 != 0 or . % 400 == 0);
  def dim($y; $m): if $m == 2 then (if ($y | leap) then 29 else 28 end)
                   elif $m == 4 or $m == 6 or $m == 9 or $m == 11 then 30 else 31 end;
  def valid_date: is_text and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
    and (split("-") | map(tonumber) | .[1] >= 1 and .[1] <= 12 and .[2] >= 1 and .[2] <= dim(.[0]; .[1]));
  def days: split("-") | map(tonumber)
    | (if .[1] <= 2 then .[0] - 1 else .[0] end) as $y | (.[1] + (if .[1] > 2 then -3 else 9 end)) as $m | .[2] as $d
    | ($y / 400 | floor) as $era | ($y - $era * 400) as $yoe | (((153 * $m + 2) / 5 | floor) + $d - 1) as $doy
    | ($yoe * 365 + ($yoe / 4 | floor) - ($yoe / 100 | floor) + $doy) as $doe | $era * 146097 + $doe - 719468;
  def issue_ref: is_text and (test("^#[0-9]+$") or test("^https?://."));

  # The same verdict as exceptions-check.sh, entry by entry.
  def entry_verdict($i):
    . as $e | (if (.id | is_text) then .id else "exceptions[\($i)]" end) as $label
    | (["id", "kind", "target", "reason", "issue", "owner", "created", "expires"]
        | map(select(($e[.] | is_text) | not) | "Exception \($label) is missing \(.)"))
      + (if (.kind | is_text) and (.kind | IN("job-bypass", "ruleset-bypass-actor", "repo-variable", "continue-on-error", "allowlist", "coverage-reset", "accepted-risk") | not)
         then ["Exception \($label) has an unknown kind \(.kind)"] else [] end)
      + (if (.created | is_text) and (.created | valid_date | not) then ["Exception \($label) has an invalid created date \(.created)"] else [] end)
      + (if (.expires | is_text) and (.expires | valid_date | not) then ["Exception \($label) has an invalid expires date \(.expires)"] else [] end)
      + (if (.issue | is_text) and (.issue | issue_ref | not) then ["Exception \($label) has an invalid issue reference \(.issue)"] else [] end)
      | if length > 0 then {state: "invalid", findings: .} else
        (($e.expires | days) - ($e.created | days)) as $days
        | (if $e.kind == "allowlist" or $e.kind == "ruleset-bypass-actor" or $e.kind == "accepted-risk" then 365 else $max end) as $bound
        | if $days < 0 then {state: "invalid", findings: ["Exception \($label) expires on \($e.expires), before it was created on \($e.created)"]}
          elif $days > $bound then {state: "invalid", findings: ["Exception \($label) lasts \($days) days; \($e.kind) allows at most \($bound)"]}
          elif ($e.expires | days) < ($today | days) then {state: "expired", findings: ["Exception \($label) expired on \($e.expires)"]}
          else {state: "active", findings: []} end end;

  def ids: if ($raw | test("^\\s*$")) then [] else (try ($raw | fromjson) catch "__invalid__") end;
  def valid_ids: type == "array" and all(type == "string" and length > 0);

  def judge($id):
    $inv[0] as $doc
    | if $doc == "__absent__" then {error: "Bypass \($id) is not registered in \($inventory)"}
      elif $doc == "__unparsed__" or ($doc | type) != "object" or ($doc.schema | type) != "number"
           or ($doc.exceptions | type) != "array" or ($doc.exceptions | all(type == "object") | not)
        then {error: "\($inventory) does not parse"}
      elif $doc.schema != 1 then {error: "\($inventory) has an unsupported schema \($doc.schema)"}
      else ([$doc.exceptions | keys[] | select($doc.exceptions[.].id == $id)] | first) as $i
        | if $i == null then {error: "Bypass \($id) is not registered in \($inventory)"}
          else $doc.exceptions[$i] as $e | ($e | entry_verdict($i)) as $v
          | if $v.state == "invalid" then {error: "Bypass \($id) is not a valid exception; see security-gate"}
            elif $e.kind != "job-bypass" then {error: "Bypass \($id) is a \($e.kind) exception, not a job-bypass"}
            elif $e.target != $job then {error: "Bypass \($id) targets \($e.target), not \($job)"}
            elif $v.state == "expired" then {error: "Bypass \($id) expired on \($e.expires); remove the variable or renew the exception"}
            else {grant: {id: $id, expires: $e.expires, issue: $e.issue}} end end end;

  (if $job == "security-gate" then [{error: "security-gate admits no bypass variable"}]
   elif (ids | valid_ids | not) then [{error: "SECURITY_BYPASS is not a JSON array of exception ids"}]
   else [ids[] | judge(.)] end) as $verdicts
  | ($verdicts | map(select(.error) | "::error::" + .error))
    + ($verdicts | map(select(.grant) | .grant | "::warning::bypass \(.id) until \(.expires) (\(.issue))", "bypass: \(.id)"))
    + (if ($verdicts | length) == 0 then ["bypass: none"] else [] end)
  | .[]
')
printf '%s\n' "$result"
case "$result" in
  *"::error::"*) exit 1 ;;
esac
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  printf '%s\n' "$result" | awk '/^bypass: / && $2 != "none" { print "id=" $2 }' >> "$GITHUB_OUTPUT"
fi
