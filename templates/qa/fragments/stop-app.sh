#!/usr/bin/env bash
# stop-app.sh: ends the process group start-app.sh started; runs in an
# `if: always()` step.
#   QA_NAME   api | web; names the PID file and the log
#   QA_TMP    where both are (default: $RUNNER_TEMP/qa)
#   QA_FAILED 1 prints the last 50 lines of the log
# Sends TERM to the group, then KILL when it is still alive after 5 s. A group
# already gone (checked with kill -0) is success; a missing PID file is one
# ::error:: line and exit 1.
set -euo pipefail

fail() {
  echo "::error::qa: stop-app.sh $*"
  exit 1
}

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

log="$qa_tmp/$QA_NAME.log"
pid_file="$qa_tmp/$QA_NAME.pid"
if [ ! -f "$pid_file" ]; then
  fail "found no $pid_file; nothing was started"
fi
pid="$(cat "$pid_file")"
case "$pid" in
  '' | *[!0-9]*) fail "found no PID in $pid_file" ;;
esac

# Right after start-app.sh the leader may not have called setsid yet: until
# then its group does not exist and the leader is signalled by its PID.
group_alive() {
  kill -0 -- "-$pid" 2>/dev/null || kill -0 "$pid" 2>/dev/null
}

signal() {
  kill -"$1" -- "-$pid" 2>/dev/null || kill -"$1" "$pid" 2>/dev/null
}

# Waits up to $1 seconds for the group to be gone; the status says whether it is.
# A background sleep is the deadline, so what each poll costs (a fork and an
# exec, slow on a loaded host) does not stretch the wait.
gone_within() {
  sleep "$1" >/dev/null 2>&1 &
  local deadline=$!
  while group_alive; do
    if ! kill -0 "$deadline" 2>/dev/null; then
      return 1
    fi
    sleep 0.1
  done
  # The deadline may have run out a moment ago (kill then returns 1, no such
  # process); any other failure stops the script.
  kill "$deadline" 2>/dev/null || [ "$?" -eq 1 ]
}

if group_alive; then
  if ! signal TERM && group_alive; then
    fail "could not send TERM to group $pid"
  fi
  if ! gone_within 5; then
    echo "stop: $QA_NAME pid $pid ignored TERM for 5 s; sent KILL"
    if ! signal KILL && group_alive; then
      fail "could not send KILL to group $pid"
    fi
    if ! gone_within 1; then
      fail "group $pid still alive after KILL"
    fi
  fi
  echo "stop: $QA_NAME pid $pid group ended"
else
  echo "stop: $QA_NAME pid $pid already gone"
fi

if [ "${QA_FAILED:-0}" = "1" ]; then
  echo "::group::qa: last 50 lines of $log"
  tail -n 50 "$log"
  echo "::endgroup::"
fi
