# actor-check.sh (brakes agent-guardrails; #971): the checks
# anthropics/claude-code-action made before running Claude, kept now that the model
# runs as the Claude Code CLI (src/github/validation/actor.ts and permissions.ts at
# the pin). The actor must be ALLOWED_BOT, or a person (`type` User) whose
# permission on the repository is admin or write; otherwise the model never starts.
# Reads GitHub with the job's token (metadata, which every job token has).
set -euo pipefail

fail() {
  echo "::error::actor: $*"
  exit 1
}
: "${ACTOR:?ACTOR is the actor of the run}"
: "${GH_REPO:?GH_REPO is owner/name}"

normal() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed 's/\[bot\]$//'; }
if [ -n "${ALLOWED_BOT:-}" ] && [ "$(normal "$ACTOR")" = "$(normal "$ALLOWED_BOT")" ]; then
  echo "actor: $ACTOR is the allowed bot"
  exit 0
fi
type=$(gh api "users/$ACTOR" --jq .type 2>/dev/null) || fail "$ACTOR is not a GitHub user; the model does not run for it"
[ "$type" = "User" ] || fail "$ACTOR is a $type, not a person; the model does not run for it"
permission=$(gh api "repos/$GH_REPO/collaborators/$ACTOR/permission" --jq .permission) ||
  fail "cannot read the permission of $ACTOR on $GH_REPO"
case "$permission" in
admin | write) ;;
*) fail "$ACTOR has $permission access to $GH_REPO; only people with write access start the model" ;;
esac
echo "actor: $ACTOR is a person with $permission access"
