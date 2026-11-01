#!/usr/bin/env bash
# exceptions-check.sh: the bypass inventory check that runs inside `security-gate`
# (SPEC-security.md, "The bypass inventory"). The shell twin of
# `orchestration/installer/src/modules/security/exceptions.rs`: the same files,
# the same states, the same finding texts, proven by `tests/security_gate_shell.rs`
# over the same fixture matrix. It needs bash, jq and awk; nothing is downloaded.
#
# Usage: exceptions-check.sh [repository-root]
#   SECURITY_TODAY            the date to judge expiry against (default: UTC today)
#   SECURITY_BYPASS_MAX_DAYS  bound of the short kinds (default 30; 365 for
#                             allowlist, ruleset-bypass-actor and accepted-risk)
#   BASE_SHA                  the pull request's base commit; when set, a
#                             decrease of .agent-setup/coverage.json against
#                             it needs an active coverage-reset (empty: none)
#   PR_NUMBER                 the pull request's number; when set, a
#                             coverage-reset this pull request adds (an id
#                             absent from the inventory at BASE_SHA) whose
#                             target is diff-coverage#<n> must name it
#
# One `::error::` line per finding, then the claim line
# `exceptions: <active> active, <expired> expired, <unregistered> unregistered`.
# Exit 1 when there is any finding; a file outside the shape the installer
# seeds is a finding too (`<file> is unverified: line <n> ...`).
set -euo pipefail

cd "${1:-.}"
today="${SECURITY_TODAY:-$(date -u +%Y-%m-%d)}"
max_days="${SECURITY_BYPASS_MAX_DAYS:-30}"
inventory=.agent-setup/security-exceptions.json
# Semgrep CE 1.182.0's built-in ignore list (exceptions::SEMGREP_DEFAULTS): a root
# .semgrepignore replaces it, so the seed restates it; an entry equal to one of
# these needs no inventory entry (#1194).
semgrep_defaults='[".git",".svn",".hg","_darcs","CVS","build/","vendor/","dist/","*.min.js",".env/",".tox/","node_modules/",".npm/",".yarn/",".venv/","_opam/","_build/","_cargo/","test/","tests/","testsuite/","*_test.go"]'
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# 1. The inventory: the document when it is JSON, a sentinel otherwise.
if [ ! -e "$inventory" ]; then
  printf '"__absent__"\n' > "$work/inventory.json"
elif jq -e . "$inventory" > /dev/null 2>&1; then
  cp "$inventory" "$work/inventory.json"
else
  printf '"__unparsed__"\n' > "$work/inventory.json"
fi

# 2. .trivyignore.yaml in the seeded shape: sections, `  - id:` entries,
#    `    statement:`, `    expired_at:`, `    paths:`/`    purls:` lists.
#    Rows: entry<TAB>id<TAB>has_expiry<TAB>expiry<TAB>issue, or unverified<TAB>line.
#    Values are read as YAML reads them (yaml_scalar): a plain scalar ends where a
#    `#` at its start or after a blank starts a comment (#1195).
read_trivy() {
  awk '
    function unquote(s) {
      if (length(s) >= 2 && ((substr(s, 1, 1) == "\"" && substr(s, length(s), 1) == "\"") ||
                             (substr(s, 1, 1) == "\047" && substr(s, length(s), 1) == "\047")))
        return substr(s, 2, length(s) - 2)
      return s
    }
    function yaml_scalar(s,   i) {
      sub(/^[ \t]+/, "", s)
      if (substr(s, 1, 1) == "\"" || substr(s, 1, 1) == "\047") return unquote(s)
      for (i = 1; i <= length(s); i++)
        if (substr(s, i, 1) == "#" && (i == 1 || substr(s, i - 1, 1) ~ /[ \t]/)) { s = substr(s, 1, i - 1); break }
      sub(/[ \t]+$/, "", s)
      return s
    }
    function mentions(s) { return (s ~ /#[0-9]/ || s ~ /https?:\/\//) }
    function flush() { if (have) { printf "entry\t%s\t%d\t%s\t%d\n", id, has_expiry, expiry, issue; have = 0 } }
    function unverified() { have = 0; printf "unverified\t%d\n", NR; exit }
    BEGIN { section = 0; inline_empty = 0; have = 0; list = 0 }
    {
      sub(/\r$/, ""); line = $0; sub(/[ \t]+$/, "", line)
      t = line; sub(/^[ \t]+/, "", t)
      if (t == "" || substr(t, 1, 1) == "#" || line == "---") next
      if (line ~ /^(vulnerabilities|misconfigurations|secrets|licenses):[ \t]*(\[\])?$/) {
        flush(); section = 1; inline_empty = (line ~ /\[\]$/); list = 0; next
      }
      if (substr(line, 1, 7) == "  - id:") {
        v = yaml_scalar(substr(line, 8))
        if (!section || inline_empty || v == "") unverified()
        flush(); have = 1; id = v; has_expiry = 0; expiry = ""; issue = 0; list = 0; next
      }
      if (!have) unverified()
      if (substr(line, 1, 4) == "    " && substr(line, 5, 1) != " ") {
        kv = substr(line, 5); i = index(kv, ":")
        if (i == 0) unverified()
        key = substr(kv, 1, i - 1); val = yaml_scalar(substr(kv, i + 1))
        if (key == "statement") { issue = mentions(val); list = 0; next }
        if (key == "expired_at") { has_expiry = (val != ""); expiry = val; list = 0; next }
        if ((key == "paths" || key == "purls") && val == "") { list = 1; next }
        unverified()
      }
      if (list && substr(line, 1, 8) == "      - " && length(line) > 8) next
      unverified()
    }
    END { flush() }
  ' "$1"
}

# 3. osv-scanner.toml in the seeded shape: `[[IgnoredVulns]]` tables with
#    `id = "..."`, `ignoreUntil = <date>` and `reason = "..."`; any other table
#    (`[[PackageOverrides]]` included) is outside the shape. Same rows.
read_osv() {
  awk '
    function quoted(s) { return (length(s) >= 2 && substr(s, 1, 1) == "\"" && substr(s, length(s), 1) == "\"") }
    function unquote(s) {
      if (length(s) >= 2 && ((substr(s, 1, 1) == "\"" && substr(s, length(s), 1) == "\"") ||
                             (substr(s, 1, 1) == "\047" && substr(s, length(s), 1) == "\047")))
        return substr(s, 2, length(s) - 2)
      return s
    }
    function mentions(s) { return (s ~ /#[0-9]/ || s ~ /https?:\/\//) }
    function unverified(n) { have = 0; printf "unverified\t%d\n", n; exit }
    function flush() {
      if (have) { if (id == "") unverified(header); printf "entry\t%s\t%d\t%s\t%d\n", id, has_expiry, expiry, issue; have = 0 }
    }
    BEGIN { have = 0 }
    {
      sub(/\r$/, ""); line = $0; sub(/[ \t]+$/, "", line)
      t = line; sub(/^[ \t]+/, "", t)
      if (t == "" || substr(t, 1, 1) == "#") next
      if (line == "[[IgnoredVulns]]") { flush(); have = 1; header = NR; id = ""; has_expiry = 0; expiry = ""; issue = 0; next }
      if (!have) unverified(NR)
      i = index(line, "=")
      if (i == 0) unverified(NR)
      key = substr(line, 1, i - 1); sub(/^[ \t]+/, "", key); sub(/[ \t]+$/, "", key)
      val = substr(line, i + 1); sub(/^[ \t]+/, "", val)
      if (key == "id" && quoted(val)) { id = unquote(val); next }
      if (key == "ignoreUntil" && val != "") { has_expiry = 1; expiry = unquote(val); next }
      if (key == "reason" && quoted(val)) { issue = mentions(unquote(val)); next }
      unverified(NR)
    }
    END { flush() }
  ' "$1"
}

# 4. .gitleaksignore / .semgrepignore: one entry per non-blank, non-comment line.
read_ignore() {
  awk '
    { sub(/\r$/, ""); t = $0; sub(/^[ \t]+/, "", t); sub(/[ \t]+$/, "", t)
      if (t == "" || substr(t, 1, 1) == "#") next
      printf "entry\t%s\n", t }
  ' "$1"
}

# 5. The [allowlist] table of .gitleaks.toml: `description`/`regexTarget`
#    scalars and arrays written `[]` or one quoted entry per line.
#    Rows: entry<TAB>key:value, or unverified<TAB>line.
read_gitleaks_allowlist() {
  awk '
    function tomlstr(s) {
      sub(/,$/, "", s); sub(/[ \t]+$/, "", s)
      if (length(s) >= 6 && substr(s, 1, 3) == "\047\047\047" && substr(s, length(s) - 2, 3) == "\047\047\047") return substr(s, 4, length(s) - 6)
      if (length(s) >= 2 && ((substr(s, 1, 1) == "\"" && substr(s, length(s), 1) == "\"") ||
                             (substr(s, 1, 1) == "\047" && substr(s, length(s), 1) == "\047"))) return substr(s, 2, length(s) - 2)
      return "\001"
    }
    function unverified(n) { arr = ""; printf "unverified\t%d\n", n; exit }
    BEGIN { inside = 0; arr = ""; last = 0 }
    {
      last = NR
      sub(/\r$/, ""); t = $0; sub(/^[ \t]+/, "", t); sub(/[ \t]+$/, "", t)
      if (t == "" || substr(t, 1, 1) == "#") next
      if (substr(t, 1, 1) == "[") { if (arr != "") unverified(NR); inside = (t == "[allowlist]"); next }
      if (!inside) next
      if (arr != "") {
        if (t == "]") { arr = ""; next }
        v = tomlstr(t)
        if (v == "\001") unverified(NR)
        printf "entry\t%s:%s\n", arr, v; next
      }
      i = index(t, "=")
      if (i == 0) unverified(NR)
      key = substr(t, 1, i - 1); sub(/[ \t]+$/, "", key); val = substr(t, i + 1); sub(/^[ \t]+/, "", val)
      if (key == "description" || key == "regexTarget" || val == "[]") next
      if (val == "[") { arr = key; next }
      unverified(NR)
    }
    END { if (arr != "") unverified(last) }
  ' "$1"
}

: > "$work/trivy.tsv"; [ -e .trivyignore.yaml ] && read_trivy .trivyignore.yaml > "$work/trivy.tsv"
: > "$work/osv.tsv"; [ -e osv-scanner.toml ] && read_osv osv-scanner.toml > "$work/osv.tsv"
: > "$work/gitleaksignore.tsv"; [ -e .gitleaksignore ] && read_ignore .gitleaksignore > "$work/gitleaksignore.tsv"
: > "$work/semgrepignore.tsv"; [ -e .semgrepignore ] && read_ignore .semgrepignore > "$work/semgrepignore.tsv"
: > "$work/gitleaks-toml.tsv"; [ -e .gitleaks.toml ] && read_gitleaks_allowlist .gitleaks.toml > "$work/gitleaks-toml.tsv"
plain=false; [ -e .trivyignore ] && plain=true

# 6. The coverage record at the pull request's base and in the working tree.
record=.agent-setup/coverage.json
base_sha="${BASE_SHA:-}"
compare=false
unavailable=false
printf '"__absent__"\n' > "$work/coverage-base.json"
printf '"__absent__"\n' > "$work/coverage-head.json"
if [ -n "$base_sha" ]; then
  if ! git cat-file -e "$base_sha^{commit}" 2> /dev/null; then
    printf '::error::Base commit %s is not available; %s cannot be compared\n' "$base_sha" "$record"
    unavailable=true
  elif git cat-file -e "$base_sha:$record" 2> /dev/null; then
    compare=true
    git show "$base_sha:$record" > "$work/coverage-base.raw"
    if jq -e . "$work/coverage-base.raw" > /dev/null 2>&1; then
      cp "$work/coverage-base.raw" "$work/coverage-base.json"
    else
      printf '"__unparsed__"\n' > "$work/coverage-base.json"
    fi
  fi
fi
# The inventory at the base: which ids this pull request adds.
printf '"__absent__"\n' > "$work/inventory-base.json"
if [ -n "$base_sha" ] && [ "$unavailable" = false ] && git cat-file -e "$base_sha:$inventory" 2> /dev/null; then
  git show "$base_sha:$inventory" > "$work/inventory-base.raw"
  if jq -e . "$work/inventory-base.raw" > /dev/null 2>&1; then
    cp "$work/inventory-base.raw" "$work/inventory-base.json"
  fi
fi
pr_number="${PR_NUMBER:-}"
if [ "$compare" = true ] && [ -e "$record" ]; then
  if jq -e . "$record" > /dev/null 2>&1; then
    cp "$record" "$work/coverage-head.json"
  else
    printf '"__unparsed__"\n' > "$work/coverage-head.json"
  fi
fi

# 7. One jq program judges everything, in the order the Rust twin prints it.
result=$(jq -n -r \
  --slurpfile inv "$work/inventory.json" \
  --rawfile trivy "$work/trivy.tsv" \
  --rawfile osv "$work/osv.tsv" \
  --rawfile gitleaksignore "$work/gitleaksignore.tsv" \
  --rawfile semgrepignore "$work/semgrepignore.tsv" \
  --argjson semgrep_defaults "$semgrep_defaults" \
  --rawfile gitleakstoml "$work/gitleaks-toml.tsv" \
  --slurpfile coveragebase "$work/coverage-base.json" \
  --slurpfile coveragehead "$work/coverage-head.json" \
  --slurpfile invbase "$work/inventory-base.json" \
  --arg pr "$pr_number" \
  --arg record "$record" \
  --arg today "$today" --argjson max "$max_days" --argjson plain "$plain" \
  --arg inventory "$inventory" '
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
  def rows: split("\n") | map(select(length > 0) | split("\t"));
  def tally($state): if $state == "active" then .active += 1 elif $state == "expired" then .expired += 1 else . end;

  # An inventory entry: findings in a fixed order, then the bound, then the expiry.
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

  def inventory_report:
    $inv[0] as $doc
    | if $doc == "__absent__" then {findings: [], active: 0, expired: 0, targets: []}
      elif $doc == "__unparsed__" or ($doc | type) != "object" or ($doc.schema | type) != "number"
           or ($doc.exceptions | type) != "array" or ($doc.exceptions | all(type == "object") | not)
        then {findings: ["\($inventory) does not parse"], active: 0, expired: 0, targets: []}
      elif $doc.schema != 1 then {findings: ["\($inventory) has an unsupported schema \($doc.schema)"], active: 0, expired: 0, targets: []}
      else reduce ($doc.exceptions | keys[]) as $i ({findings: [], active: 0, expired: 0};
             ($doc.exceptions[$i] | entry_verdict($i)) as $v | tally($v.state) | .findings += $v.findings)
           + {targets: [$doc.exceptions[] | select(.kind == "allowlist") | .target | select(is_text)]}
      end;

  # A native file: the first out-of-shape line, or every entry judged.
  def native_report($rows; $file; $expiry_field; $issue_field):
    ($rows | map(select(.[0] == "unverified")) | first) as $u
    | if $u then {findings: ["\($file) is unverified: line \($u[1]) is outside the generated shape"], active: 0, expired: 0}
      else reduce ($rows[] | select(.[0] == "entry")) as $r ({findings: [], active: 0, expired: 0};
        $r[1] as $id | ($r[2] == "1") as $has | $r[3] as $exp | ($r[4] == "1") as $issue
        | ([(if ($has | not) then "Exception \($id) in \($file) has no \($expiry_field)"
             elif ($exp | valid_date | not) then "Exception \($id) in \($file) has an invalid \($expiry_field) date \($exp)" else empty end),
            (if ($issue | not) then "Exception \($id) in \($file) has no issue in \($issue_field)" else empty end)]) as $f
        | if ($f | length) > 0 then .findings += $f
          elif ($exp | days) < ($today | days) then .findings += ["Exception \($id) in \($file) expired on \($exp)"] | .expired += 1
          else .active += 1 end)
      end;

  def unregistered($rows; $file; $noun; $targets):
    [$rows[] | select(.[0] == "entry") | .[1] | select(IN($targets[]; "\($file)#\(.)") | not)
     | "\($file) \($noun) \(.) is not registered in \($inventory)"];

  # The coverage record: [[app, value]] in the generated shape, null otherwise.
  def coverage_apps: if type == "object" and .schema == 1 and (.apps | type) == "object"
      and (.apps | all(type == "number")) then (.apps | to_entries | map([.key, (.value + 0)])) else null end;
  def coverage_decreases:
    ($coveragebase[0] | coverage_apps) as $base
    | if $base == null then []
      else (if $coveragehead[0] == "__absent__" then [] else ($coveragehead[0] | coverage_apps) end) as $head
      | if $head == null then ["\($record) does not parse"]
        elif ($inv[0] | type) == "object" and $inv[0].schema == 1 and ($inv[0].exceptions | type) == "array"
             and ($inv[0].exceptions | all(type == "object"))
             and ([$inv[0].exceptions | keys[] as $i | $inv[0].exceptions[$i]
                   | select(.kind == "coverage-reset" and .target == $record)
                   | select(entry_verdict($i).state == "active")] | length > 0) then []
        else [$base[] | .[0] as $app | .[1] as $old
              | ([$head[] | select(.[0] == $app) | .[1]] | first) as $new
              | select($new == null or $new < $old)
              | "\($record) lowers \($app) from \($old) to \(if $new == null then "absent" else $new end) without an active coverage-reset"]
        end
      end;

  # coverage-reset entries this pull request adds whose diff-coverage#<n> target
  # names another pull request (an id absent from the base inventory is added).
  def foreign_diff_coverage_resets:
    if $pr == "" or ($inv[0] | type) != "object" or $inv[0].schema != 1
       or ($inv[0].exceptions | type) != "array" or ($inv[0].exceptions | all(type == "object") | not)
    then []
    else ($invbase[0] | if type == "object" and (.schema | type) == "number"
            and (.exceptions | type) == "array" and (.exceptions | all(type == "object"))
          then [.exceptions[] | .id | select(is_text)] else [] end) as $base_ids
      | "diff-coverage#\($pr)" as $own
      | [$inv[0].exceptions | keys[] as $i | $inv[0].exceptions[$i]
         | select((.id | is_text | not) or (.id as $id | IN($base_ids[]; $id) | not))
         | select(.kind == "coverage-reset" and (.target | is_text) and (.target | startswith("diff-coverage#")) and .target != $own)
         | "Exception \(if (.id | is_text) then .id else "exceptions[\($i)]" end) targets \(.target); a coverage-reset added in pull request #\($pr) must target \($own)"]
    end;

  inventory_report as $inventory_report
  | native_report($trivy | rows; ".trivyignore.yaml"; "expired_at"; "statement") as $t
  | native_report($osv | rows; "osv-scanner.toml"; "ignoreUntil"; "reason") as $o
  | (if $plain then [".trivyignore cannot carry an expiry; use .trivyignore.yaml"] else [] end) as $p
  | unregistered($gitleaksignore | rows; ".gitleaksignore"; "entry"; $inventory_report.targets) as $g
  | unregistered($semgrepignore | rows | map(select(.[1] as $e | IN($semgrep_defaults[]; $e) | not));
      ".semgrepignore"; "entry"; $inventory_report.targets) as $s
  | (($gitleakstoml | rows) | map(select(.[0] == "unverified")) | first) as $tu
  | (if $tu then [".gitleaks.toml is unverified: line \($tu[1]) is outside the generated shape"]
     else unregistered($gitleakstoml | rows; ".gitleaks.toml"; "allowlist entry"; $inventory_report.targets) end) as $c
  | foreign_diff_coverage_resets as $f
  | ($inventory_report.findings + $t.findings + $o.findings + $p + $g + $s + $c + coverage_decreases + $f) as $findings
  | ($findings | map("::error::" + .)) + ["exceptions: \($inventory_report.active + $t.active + $o.active) active, \($inventory_report.expired + $t.expired + $o.expired) expired, \(($g | length) + ($s | length) + (if $tu then 0 else ($c | length) end) + ($f | length)) unregistered"]
  | .[]
')
printf '%s\n' "$result"
case "$result" in
  *"::error::"*) exit 1 ;;
esac
if [ "$unavailable" = true ]; then
  exit 1
fi
