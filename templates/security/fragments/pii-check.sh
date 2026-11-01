#!/usr/bin/env bash
# pii-check.sh: the PII declaration check that runs inside `security-gate` beside
# the exceptions check (SPEC-security.md, "PII pack"). The shell twin of
# `orchestration/installer/src/modules/security/pii.rs`: the same file, the same
# shape, the same finding texts, proven by `tests/security_gate_shell.rs` over the
# same fixture matrix. It needs bash, jq and awk; nothing is downloaded.
#
# Usage: pii-check.sh [repository-root]
#   SECURITY_CRITICALITY  `internal`, `customers`, `personal-data-or-payments` or
#                         `undeclared` (default: `.criticality` of
#                         .agent-setup/project.json, `undeclared` when absent)
#
# Reads .agent-setup/pii.yaml in the shape the installer seeds: the top-level keys
# `schema`, `controller`, `dsar_contact`, `sla_days`, `fields` (`[]` or a list of
# `- path:` entries whose seven keys sit two spaces deeper; `exclude_from` is an
# inline `[a, b]` list). One `::error::` line per finding, then the claim line
# `pii: required|not required, <n> fields` (or `absent`). Exit 1 on any finding;
# a file outside the seeded shape is a finding (`<file> is unverified: line <n>`).
set -euo pipefail

cd "${1:-.}"
file=.agent-setup/pii.yaml
profile=.agent-setup/project.json
criticality="${SECURITY_CRITICALITY:-}"
if [ -z "$criticality" ]; then
  if [ -e "$profile" ] && jq -e . "$profile" > /dev/null 2>&1; then
    criticality=$(jq -r '.criticality // "undeclared"' "$profile")
  else
    criticality=undeclared
  fi
fi
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# 1. The declaration as rows: top<TAB>key<TAB>value, field<TAB>i<TAB>key<TAB>value,
#    start<TAB>i, or unverified<TAB>line. Values keep their quotes stripped.
if [ -e "$file" ]; then
  awk '
    function unquote(s) {
      if (length(s) >= 2 && ((substr(s, 1, 1) == "\"" && substr(s, length(s), 1) == "\"") ||
                             (substr(s, 1, 1) == "\047" && substr(s, length(s), 1) == "\047")))
        return substr(s, 2, length(s) - 2)
      return s
    }
    function strip_comment(s,   i, c, q) {
      q = ""
      for (i = 1; i <= length(s); i++) {
        c = substr(s, i, 1)
        if (q == "") { if (c == "\"" || c == "\047") q = c; else if (c == "#") return substr(s, 1, i - 1) }
        else if (c == q) q = ""
      }
      return s
    }
    function unverified() { printf "unverified\t%d\n", NR; exit }
    BEGIN { in_fields = 0; i = -1 }
    {
      sub(/\r$/, ""); line = strip_comment($0); sub(/[ \t]+$/, "", line)
      t = line; sub(/^[ \t]+/, "", t)
      if (t == "" || line == "---") next
      if (line ~ /^[A-Za-z_]+:/) {
        key = line; sub(/:.*/, "", key)
        v = line; sub(/^[A-Za-z_]+:[ \t]*/, "", v); v = unquote(v)
        if (key == "fields") { in_fields = 1; if (v != "" && v != "[]") unverified(); printf "top\tfields\t%s\n", v; next }
        in_fields = 0
        printf "top\t%s\t%s\n", key, v; next
      }
      if (!in_fields) unverified()
      if (substr(line, 1, 4) == "  - ") {
        rest = substr(line, 5)
        if (rest !~ /^[a-z_]+:/) unverified()
        i++; printf "start\t%d\n", i
        key = rest; sub(/:.*/, "", key); v = rest; sub(/^[a-z_]+:[ \t]*/, "", v)
        printf "field\t%d\t%s\t%s\n", i, key, unquote(v); next
      }
      if (substr(line, 1, 4) == "    " && substr(line, 5, 1) != " " && i >= 0) {
        rest = substr(line, 5)
        if (rest !~ /^[a-z_]+:/) unverified()
        key = rest; sub(/:.*/, "", key); v = rest; sub(/^[a-z_]+:[ \t]*/, "", v)
        printf "field\t%d\t%s\t%s\n", i, key, unquote(v); next
      }
      unverified()
    }
  ' "$file" > "$work/rows.tsv"
  present=true
else
  : > "$work/rows.tsv"
  present=false
fi

result=$(jq -n -r \
  --rawfile rows "$work/rows.tsv" --arg present "$present" \
  --arg criticality "$criticality" --arg file "$file" '
  def trim: sub("^[ \\t]+"; "") | sub("[ \\t]+$"; "");
  def is_int: test("^[0-9]+$");
  def mentions_obligation: ascii_downcase | test("obligation|legal|law");
  def inline_list: if . == "[]" or . == "" then []
    elif test("^\\[.*\\]$") then .[1:-1] | split(",") | map(trim) | map(select(length > 0))
    else null end;

  ($rows | split("\n") | map(select(length > 0) | split("\t"))) as $rows
  | ($rows | map(select(.[0] == "unverified")) | first) as $bad
  | ($rows | map(select(.[0] == "top")) | map({key: .[1], value: .[2]}) | from_entries) as $top
  | ($rows | map(select(.[0] == "start")) | length) as $n
  | ([range(0; $n) as $i
      | ($rows | map(select(.[0] == "field" and (.[1] | tonumber) == $i)) | map({key: .[2], value: .[3]}) | from_entries)]) as $fields
  | ($criticality == "personal-data-or-payments") as $required
  | (if $present == "false" then
       (if $required then ["\($file) is missing: criticality personal-data-or-payments needs a PII declaration"] else [] end)
     elif $bad then ["\($file) is unverified: line \($bad[1]) is outside the seeded shape"]
     else
       (if ($top.schema // "") != "1" then ["\($file) has an unsupported schema \($top.schema // "none")"] else [] end)
       + (if $required and (($top.controller // "") == "" or ($top.controller | test("^<.*>$"))) then ["\($file) controller is not declared"] else [] end)
       + (if $required and (($top.dsar_contact // "") == "" or ($top.dsar_contact | test("^<.*>$"))) then ["\($file) dsar_contact is not declared"] else [] end)
       + (if (($top.sla_days // "") | is_int | not) or (($top.sla_days | tonumber) < 1) then ["\($file) sla_days must be a positive integer"] else [] end)
       + (if $required and $n == 0 then ["\($file) declares no fields; criticality personal-data-or-payments needs at least one"] else [] end)
       + ([range(0; $n) as $i | $fields[$i] as $f
           | (if ($f.path // "") != "" then $f.path else "fields[\($i)]" end) as $label
           | (["path", "category", "purpose", "lawful_basis", "retention", "exclude_from", "erasure"]
              | map(select(($f[.] // "") == "") | "Field \($label) is missing \(.)"))
           + (if ($f.category // "") != "" and ($f.category | IN("identifier", "contact", "financial", "health", "location", "biometric", "behavioural", "credentials") | not)
              then ["Field \($label) has an unknown category \($f.category)"] else [] end)
           + (if ($f.lawful_basis // "") != "" and ($f.lawful_basis | IN("consent", "contract", "legal-obligation", "vital-interests", "public-task", "legitimate-interests") | not)
              then ["Field \($label) has an unknown lawful_basis \($f.lawful_basis)"] else [] end)
           + (if ($f.erasure // "") != "" and ($f.erasure | IN("delete", "anonymise", "retain-legal") | not)
              then ["Field \($label) has an unknown erasure \($f.erasure)"] else [] end)
           # `as` after `+` parses differently in jq 1.7 and 1.8: the parentheses
           # bind `$ex` to exclude_from alone in both.
           + ((($f.exclude_from // "") | inline_list) as $ex
           | (if $ex == null then ["Field \($label) exclude_from is not an inline list"]
              else ($ex | map(select(IN("logs", "traces", "analytics", "cdc") | not)) | map("Field \($label) excludes from an unknown consumer \(.)")) end)
           + (if $f.erasure == "retain-legal" and (($f.purpose // "") | mentions_obligation | not)
              then ["Field \($label) is retain-legal and its purpose names no obligation"] else [] end)
           + (if $f.category == "credentials" and ($ex != null) and (($ex | index("logs")) == null or ($ex | index("traces")) == null)
              then ["Field \($label) is credentials and must exclude logs and traces"] else [] end))
          ] | add // [])
     end) as $findings
  | ($findings | map("::error::" + .))
    + [ "pii: " + (if $required then "required" else "not required" end)
        + (if $present == "false" then ", absent" elif $bad then ", 0 fields" else ", \($n) fields" end) ]
  | .[]
')
printf '%s\n' "$result"
case "$result" in
  *"::error::"*) exit 1 ;;
esac
