#!/usr/bin/env bash
# start-app.sh: starts the application a QA job tests, in the background and
# in its own session, so stop-app.sh can end every process it spawned.
#   QA_START  the declared start command, run by bash from the current directory
#   QA_NAME   api | web; names the PID file and the log
#   QA_TMP    where both go (default: $RUNNER_TEMP/qa)
# Writes $QA_TMP/<name>.pid (the process-group leader) and $QA_TMP/<name>.log
# (stdout and stderr). Readiness is not checked here: Hurl's --retry or
# Playwright's webServer waits. A missing variable is one ::error:: line and exit 1.
# Needs bash and setsid (util-linux).
set -euo pipefail

fail() {
  echo "::error::qa: start-app.sh $*"
  exit 1
}

if [ -z "${QA_START:-}" ]; then
  fail "needs QA_START"
fi
if [ -z "${QA_NAME:-}" ]; then
  fail "needs QA_NAME"
fi
case "$QA_NAME" in
  api | web) ;;
  *) fail "QA_NAME must be api or web, got $QA_NAME" ;;
esac
qa_tmp="${QA_TMP:-}"
if [ -z "$qa_tmp" ] && [ -n "${RUNNER_TEMP:-}" ]; then
  qa_tmp="$RUNNER_TEMP/qa"
fi
if [ -z "$qa_tmp" ]; then
  fail "needs QA_TMP or RUNNER_TEMP"
fi
if ! command -v setsid >/dev/null 2>&1; then
  fail "needs setsid (util-linux)"
fi

mkdir -p "$qa_tmp"
log="$qa_tmp/$QA_NAME.log"
pid_file="$qa_tmp/$QA_NAME.pid"

# A background job of a non-interactive shell is not a group leader, so setsid
# execs in place: $! is the new session's leader and its process-group id.
setsid bash -euo pipefail -c "$QA_START" </dev/null >"$log" 2>&1 &
pid=$!
echo "$pid" >"$pid_file"
echo "start: $QA_NAME pid $pid log $log"
