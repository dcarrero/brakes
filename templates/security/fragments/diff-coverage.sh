#!/usr/bin/env bash
# diff-coverage.sh changed|characterization [root]: steps 2 and 3 of the
# `diff-coverage` job; inputs through the environment, documented in
# SPEC-security.md, "Changed-line coverage as built". Needs bash, git, jq, awk.
set -euo pipefail
# Every variable read from the environment (#1222); the tests parse the next line.
# inputs=(SECURITY_TODAY BASE_REF PR_NUMBER DIFF_REPORT DIFF_FORMAT APP_ID APP_PATH EXCLUDE_PATHS MIN DIFF_COVER SOURCE_EXT ABSENT ABSENT_HINT BASE_REPORT)

mode="${1:?usage: diff-coverage.sh changed|characterization [repository-root]}"
cd "${2:-.}"
today="${SECURITY_TODAY:-$(date -u +%Y-%m-%d)}"
base_ref="${BASE_REF:?BASE_REF is required}"
report="${DIFF_REPORT:?DIFF_REPORT is required}"
format="${DIFF_FORMAT:?DIFF_FORMAT is required}"
app="${APP_ID:?APP_ID is required}"
inventory=.agent-setup/security-exceptions.json
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# An active coverage-reset for this pull request lets the step pass, loudly.
if [ -n "${PR_NUMBER:-}" ] && [ -e "$inventory" ]; then
  grant=$(jq -r --arg target "diff-coverage#$PR_NUMBER" --arg today "$today" '
    [(.exceptions // [])[] | objects
     | select(.kind == "coverage-reset" and .target == $target
              and (.expires | type) == "string" and (.expires | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}$"))
              and .expires >= $today)]
    | first // empty | "\(.id)\t\(.expires)\t\(.issue)"' "$inventory" 2> /dev/null) || grant=""
  if [ -n "$grant" ]; then
    IFS=$'\t' read -r id expires issue <<< "$grant"
    echo "::warning::coverage-reset $id until $expires ($issue)"
    echo "bypass: $id"
    exit 0
  fi
fi

if ! merge_base=$(git merge-base "origin/$base_ref" HEAD 2> /dev/null); then
  echo "::error::No merge base with origin/$base_ref; the job needs fetch-depth 0"
  exit 1
fi

case "$mode" in
  changed)
    if [ ! -e "$report" ]; then
      echo "::error::Coverage report $report is absent"
      exit 1
    fi
    min="${MIN:?MIN is required}"
    read -ra diff_cover <<< "${DIFF_COVER:-diff-cover}"
    rc=0
    "${diff_cover[@]}" "$report" "--compare-branch=origin/$base_ref" "--fail-under=$min" \
      --format "json:$work/diff-cover.json" > "$work/diff-cover.log" 2>&1 || rc=$?
    if [ ! -s "$work/diff-cover.json" ]; then
      cat "$work/diff-cover.log"
      echo "::error::diff-cover wrote no report (exit $rc)"
      exit 1
    fi
    read -r measured percent < <(jq -r '"\(.total_num_lines) \(.total_percent_covered)"' "$work/diff-cover.json")
    if [ "$measured" = 0 ]; then
      echo "changed lines of $app: none measured"
      exit 0
    fi
    echo "diff-coverage $app: $percent % of $measured changed lines"
    if [ "$rc" -ne 0 ]; then
      if jq -e --argjson min "$min" '.total_percent_covered < $min' "$work/diff-cover.json" > /dev/null; then
        echo "::error::Changed lines of $app covered $percent %, below $min %"
      else
        cat "$work/diff-cover.log"
        echo "::error::diff-cover failed (exit $rc)"
      fi
      exit 1
    fi
    ;;

  characterization)
    ext="${SOURCE_EXT:?SOURCE_EXT is required}"
    absent="${ABSENT:-warn}"
    # Why an absent file is not judged: coverage.py without a source setting, or a
    # rust selection narrowed by coverage_test_args (#1177).
    absent_hint="${ABSENT_HINT:-set [tool.coverage.run] source so it can be judged}"
    base_report="${BASE_REPORT:-}"
    if [ -n "$base_report" ] && [ -s "$base_report" ]; then
      cp "$base_report" "$work/base-report"
      echo "base report: cache ($merge_base)"
    else
      # Never recomputed (#22): that would run the tests; the next push to the
      # default branch keeps a base report.
      echo "::warning::$app: no base report for $merge_base; not judged"
      exit 0
    fi

    # Per file of the base report: <path><TAB><1 if a line was executed, else 0>.
    case "$format" in
      lcov)
        awk -F'[:,]' '
          /^SF:/ { file = substr($0, 4); hit[file] += 0; next }
          /^DA:/ && file != "" { if ($3 + 0 > 0) hit[file] = 1; next }
          /^end_of_record/ { file = ""; next }
          END { for (f in hit) printf "%s\t%d\n", f, hit[f] }
        ' "$work/base-report" > "$work/files.tsv"
        ;;
      cobertura)
        awk '
          function attr(line, name,    rest) {
            if (match(line, name "=\"[^\"]*\"") == 0) return ""
            rest = substr(line, RSTART + length(name) + 2, RLENGTH - length(name) - 3)
            return rest
          }
          /<class / { file = attr($0, "filename"); hit[file] += 0; next }
          /<\/class>/ { file = ""; next }
          /<line / && file != "" { if (attr($0, "hits") + 0 > 0) hit[file] = 1; next }
          END { for (f in hit) printf "%s\t%d\n", f, hit[f] }
        ' "$work/base-report" > "$work/files.tsv"
        ;;
      *)
        echo "::error::Unknown report format $format"
        exit 1
        ;;
    esac

    # The modified (and renamed) source files, test files left out.
    git diff --name-status --diff-filter=MR "$merge_base"...HEAD \
      | awk -F'\t' '{ print ($1 ~ /^R/) ? $3 : $2 }' \
      | APP_PATH="${APP_PATH:-.}" EXCLUDE_PATHS="${EXCLUDE_PATHS:-}" awk -v ext="$ext" '
          BEGIN { app_path = ENVIRON["APP_PATH"]; n = split(ENVIRON["EXCLUDE_PATHS"], skip, "\n") }
          app_path != "." && index($0, app_path "/") != 1 { next }
          { for (i = 1; i <= n; i++) if (skip[i] != "" && index($0, skip[i] "/") == 1) next }
          $0 !~ ("\\." ext "$") { next }
          $0 ~ /(^|\/)(tests?|benches|examples)\// { next }
          $0 ~ /(^|\/)(test_[^\/]*\.py|[^\/]*_test\.py|conftest\.py|build\.rs)$/ { next }
          { print }
        ' > "$work/modified.txt"

    # Each modified file against the base report, by path suffix: the report
    # may hold absolute paths (LCOV) or paths relative to a source root.
    awk -F'\t' -v absent="$absent" -v hint="$absent_hint" -v sha="$merge_base" -v table="$work/files.tsv" -v app="$app" '
      BEGIN {
        while ((getline row < table) > 0) {
          split(row, cell, "\t"); file[++n] = cell[1]; hit[n] = cell[2]
        }
      }
      {
        path = $0; found = 0; executed = 0
        for (i = 1; i <= n; i++) {
          f = file[i]
          if (f == path || substr(f, length(f) - length(path)) == "/" path ||
              substr(path, length(path) - length(f)) == "/" f) {
            found = 1; if (hit[i]) executed = 1
          }
        }
        judged++
        if (found && executed) next
        if (!found && absent == "warn") {
          printf "::warning::characterization: %s is not in the base report; %s\n", path, hint
          next
        }
        failed++
        printf "::error::Characterization first: %s had no test executing it at %s; add tests of its current behaviour in a separate pull request before changing it\n", path, sha
      }
      END {
        printf "characterization %s: %d modified source files judged at %s, %d without a test\n", app, judged, sha, failed
        exit (failed > 0)
      }
    ' "$work/modified.txt"
    ;;

  *)
    echo "usage: diff-coverage.sh changed|characterization [repository-root]" >&2
    exit 1
    ;;
esac
