#!/usr/bin/env bash
# mutation-diff.sh: mutation testing of the code a pull request changes
# (SPEC-security.md, "Mutation testing on the diff"). Runs in the app directory.
#
# Usage: mutation-diff.sh cargo-mutants <min-score>
#        mutation-diff.sh mutmut <min-score>
#        mutation-diff.sh module <path>    prints mutmut's module pattern of <path>
# Inputs, through `env:` only:
#   BASE_SHA          github.event.pull_request.base.sha
#   MUTATION_COMMAND  the stack pack's `mutation.command`; mutmut's reads
#                     $MUTATION_MODULE, the module pattern of one changed file
#   MUTATION_STATS    mutmut only: the pack's `mutation.stats`
#
# cargo-mutants: `git diff <merge base>...HEAD > git.diff`, then the command
# (`--in-diff git.diff`); exit codes 0, 2 and 3 are judged from
# `mutants.out/{caught,missed,timeout,unviable}.txt`, score =
# caught / (caught + missed + timeout); 4, 5 and 6 fail with the tool's message
# above and the meaning of the code (cargo-mutants `src/exit_code.rs`, v27.1.0).
# mutmut: needs `mutate_only_covered_lines = true` in its own configuration
# (`[tool.mutmut]` of pyproject.toml, else `[mutmut]` of setup.cfg: mutmut 3.8.1
# `configuration.py` reads no flag for it); runs the command once per changed
# Python file; keeps only the changed files' `mutants/<path>.meta` before
# `export-cicd-stats`, whose `total` otherwise counts every unchecked mutant of
# the project; score = (killed + timeout) / (total - skipped), the badge's.
# Prints `mutation: <score> % of <n> mutants killed`, or
# `mutation: no mutants in the diff`, and fails below <min-score> with
# `::error::Mutation score <score> % on changed code, below <min> %`.
# Needs bash, git and jq; nothing is downloaded.
set -euo pipefail

mode="${1:?usage: mutation-diff.sh cargo-mutants|mutmut <min-score> | module <path>}"

# mutmut's module name of a source path (`format_utils.get_mutant_name`, 3.8.1):
# the path without `.py`, `/` as `.`, a leading `src.` dropped; a package's
# `__init__` names the package.
module_of() {
  local name="${1%.py}"
  name="${name//\//.}"
  name="${name#src.}"
  name="${name%.__init__}"
  printf '%s\n' "$name"
}

if [ "$mode" = module ]; then
  module_of "${2:?usage: mutation-diff.sh module <path>}"
  exit 0
fi

min="${2:?usage: mutation-diff.sh $mode <min-score>}"
base="${BASE_SHA:?BASE_SHA is the pull request base}"
command="${MUTATION_COMMAND:?MUTATION_COMMAND is the mutation command of the pack}"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# The verdict over <killed> of <n> viable mutants.
judge() {
  local killed="$1" n="$2"
  if [ "$n" -eq 0 ]; then
    echo "mutation: no mutants in the diff"
    return 0
  fi
  local score=$((killed * 100 / n))
  echo "mutation: $score % of $n mutants killed"
  if [ "$score" -lt "$min" ]; then
    echo "::error::Mutation score $score % on changed code, below $min %"
    return 1
  fi
}

# Non-empty lines of a file, 0 when it is absent.
count() {
  if [ -f "$1" ]; then
    awk 'NF { n++ } END { print n + 0 }' "$1"
  else
    echo 0
  fi
}

run_cargo_mutants() {
  git diff --relative "$base...HEAD" > git.diff
  local code=0
  bash -c "$command" || code=$?
  case "$code" in
    0 | 2 | 3) ;;
    4)
      echo "::error::cargo mutants exited 4: the tests fail on the unmutated tree"
      return 4
      ;;
    5)
      echo "::error::cargo mutants exited 5: the diff does not match the source tree"
      return 5
      ;;
    6)
      echo "::error::cargo mutants exited 6: the diff could not be parsed"
      return 6
      ;;
    *)
      echo "::error::cargo mutants exited $code"
      return "$code"
      ;;
  esac
  local caught missed timeout
  caught=$(count mutants.out/caught.txt)
  missed=$(count mutants.out/missed.txt)
  timeout=$(count mutants.out/timeout.txt)
  judge "$caught" $((caught + missed + timeout))
}

# The value of `mutate_only_covered_lines` in `section` of `file`, empty when unset.
setting() {
  awk -v section="$2" '
    /^[[:space:]]*\[/ { inside = ($0 ~ "^[[:space:]]*\\[" section "\\][[:space:]]*(#.*)?$") ; next }
    inside && /^[[:space:]]*mutate_only_covered_lines[[:space:]]*=/ {
      value = $0
      sub(/^[^=]*=[[:space:]]*/, "", value)
      sub(/[[:space:]]*(#.*)?$/, "", value)
      print tolower(value)
      exit
    }
  ' "$1"
}

covered_only() {
  local value=""
  if [ -f pyproject.toml ] && grep -Eq '^[[:space:]]*\[tool\.mutmut\][[:space:]]*(#.*)?$' pyproject.toml; then
    value=$(setting pyproject.toml 'tool\\.mutmut')
    [ "$value" = true ]
  else
    if [ -f setup.cfg ]; then
      value=$(setting setup.cfg mutmut)
    fi
    case "$value" in
      1 | t | true) return 0 ;;
      *) return 1 ;;
    esac
  fi
}

run_mutmut() {
  if ! covered_only; then
    echo "::error::mutmut reads mutate_only_covered_lines only from its configuration; set mutate_only_covered_lines = true under [tool.mutmut] in pyproject.toml (or [mutmut] in setup.cfg)"
    return 1
  fi
  local stats="${MUTATION_STATS:?MUTATION_STATS is the mutation stats command of the pack}"
  local changed=() ran=() path code log="$work/run.log"
  while IFS= read -r path; do
    [ -n "$path" ] && changed+=("$path")
  done < <(git diff --relative --name-only --diff-filter=AMR "$base...HEAD" -- '*.py')
  for path in "${changed[@]+"${changed[@]}"}"; do
    code=0
    MUTATION_MODULE=$(module_of "$path") bash -c "$command" > "$log" 2>&1 || code=$?
    cat "$log"
    if [ "$code" -eq 0 ]; then
      ran+=("mutants/$path.meta")
    elif grep -q "Filtered for specific mutants, but nothing matches" "$log"; then
      echo "mutation: no mutants in $path"
    else
      echo "::error::mutmut exited $code on $path"
      return 1
    fi
  done
  if [ "${#ran[@]}" -eq 0 ]; then
    judge 0 0
    return
  fi
  local meta keep
  while IFS= read -r -d '' meta; do
    keep=no
    for path in "${ran[@]}"; do
      [ "$meta" = "$path" ] && keep=yes
    done
    [ "$keep" = yes ] || rm -f "$meta"
  done < <(find mutants -name '*.meta' -print0)
  bash -c "$stats"
  local results=mutants/mutmut-cicd-stats.json
  if [ ! -f "$results" ]; then
    judge 0 0
    return
  fi
  local killed n
  killed=$(jq -r '(.killed // 0) + (.timeout // 0)' "$results")
  n=$(jq -r '(.total // 0) - (.skipped // 0)' "$results")
  judge "$killed" "$n"
}

case "$mode" in
  cargo-mutants) run_cargo_mutants ;;
  mutmut) run_mutmut ;;
  *)
    echo "::error::mutation-diff.sh: unknown tool $mode"
    exit 1
    ;;
esac
