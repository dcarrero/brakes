#!/usr/bin/env bash
# Mints a one-hour installation access token of the agents' GitHub App and prints it
# for command substitution only: GH_TOKEN="$(installation-token.sh)" (decision "Agents
# act through a GitHub App, and `human-approved` counts only when a person set it",
# #1255). The private key and the JWT never reach a process argument, a log or a
# terminal, and the token is refused to a terminal.
#
#   AGENT_APP_CLIENT_ID          the App's client ID (or its numeric App ID): the JWT `iss`
#   AGENT_APP_INSTALLATION_ID    the installation; else resolved from AGENT_APP_REPOSITORY
#   AGENT_APP_REPOSITORY         owner/repo: resolves the installation and narrows the token
#                                to that one repository
#   AGENT_APP_KEY_PATH           a PEM file; unset, the key is read from the macOS Keychain:
#   AGENT_APP_KEYCHAIN_SERVICE   generic password service (default agent-app-private-key),
#   AGENT_APP_KEYCHAIN_ACCOUNT   its account (default AGENT_APP_CLIENT_ID); the password is
#                                the PEM base64-encoded on one line:
#     security add-generic-password -s agent-app-private-key -a <client id> \
#       -w "$(base64 < key.pem | tr -d '\n')"
#   GITHUB_API_URL               default https://api.github.com (https only)
#
# Sources (read 2026-11-01): JWT claims and RS256,
# https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app
# installation tokens, https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app
set -euo pipefail
set +x

fail() {
  printf 'installation-token: %s\n' "$1" >&2
  exit 1
}

client_id="${AGENT_APP_CLIENT_ID:-}"
installation="${AGENT_APP_INSTALLATION_ID:-}"
repository="${AGENT_APP_REPOSITORY:-}"
api="${GITHUB_API_URL:-https://api.github.com}"
api="${api%/}"

[[ "$client_id" =~ ^[A-Za-z0-9._-]+$ ]] || fail 'AGENT_APP_CLIENT_ID is unset or not a client ID'
[ -z "$installation" ] || [[ "$installation" =~ ^[0-9]+$ ]] ||
  fail 'AGENT_APP_INSTALLATION_ID is not a number'
if [ -n "$repository" ]; then
  [[ "$repository" =~ ^[A-Za-z0-9-]+/[A-Za-z0-9_.-]+$ ]] && [[ "$repository" != */. && "$repository" != */.. ]] ||
    fail 'AGENT_APP_REPOSITORY is not owner/repo'
fi
[ -n "$installation" ] || [ -n "$repository" ] ||
  fail 'set AGENT_APP_INSTALLATION_ID or AGENT_APP_REPOSITORY'
[[ "$api" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?(/[A-Za-z0-9._/-]*)?$ ]] ||
  fail 'GITHUB_API_URL must be an https URL'
if [ -t 1 ]; then
  # shellcheck disable=SC2016 # the usage is printed, not expanded.
  fail 'refusing to print a token to a terminal; use GH_TOKEN="$(installation-token.sh)"'
fi

# The key stays in this shell's memory: never exported, never an argument.
if [ -n "${AGENT_APP_KEY_PATH:-}" ]; then
  [ -r "$AGENT_APP_KEY_PATH" ] || fail 'AGENT_APP_KEY_PATH is not a readable file'
  pem="$(cat -- "$AGENT_APP_KEY_PATH")"
else
  service="${AGENT_APP_KEYCHAIN_SERVICE:-agent-app-private-key}"
  account="${AGENT_APP_KEYCHAIN_ACCOUNT:-$client_id}"
  encoded="$(security find-generic-password -s "$service" -a "$account" -w 2>/dev/null)" ||
    fail "no Keychain entry for service $service and account $account"
  pem="$(printf '%s' "$encoded" | openssl base64 -d -A 2>/dev/null)" ||
    fail 'the Keychain entry is not a base64-encoded key'
  unset encoded
fi
case "$pem" in
  *'-----BEGIN'*'PRIVATE KEY-----'*) ;;
  *) fail 'the key is not a PEM private key' ;;
esac

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

now="$(date +%s)"
header="$(printf '%s' '{"alg":"RS256","typ":"JWT"}' | b64url)"
payload="$(printf '{"iat":%s,"exp":%s,"iss":"%s"}' "$((now - 60))" "$((now + 540))" "$client_id" | b64url)"
signature="$(printf '%s' "$header.$payload" |
  openssl dgst -sha256 -sign <(printf '%s\n' "$pem") -binary 2>/dev/null | b64url)" ||
  fail 'could not sign the JWT with the key'
unset pem
[ -n "$signature" ] || fail 'could not sign the JWT with the key'
jwt="$header.$payload.$signature"

# The Authorization header reaches curl on its standard input (-K -), never argv.
github() {
  printf 'header = "Authorization: Bearer %s"\n' "$jwt" |
    curl -fsS --proto '=https' --max-time 30 -K - \
      -H 'Accept: application/vnd.github+json' \
      -H 'X-GitHub-Api-Version: 2022-11-28' "$@" 2>/dev/null
}

if [ -z "$installation" ]; then
  installation="$(github "$api/repos/$repository/installation" | jq -er '.id | numbers')" ||
    fail "could not find the App's installation on $repository"
fi
body='{}'
if [ -n "$repository" ]; then
  body="$(jq -cn --arg repo "${repository#*/}" '{repositories: [$repo]}')"
fi
token="$(github -X POST --data "$body" "$api/app/installations/$installation/access_tokens" |
  jq -er '.token | strings | select(length > 0)' 2>/dev/null)" ||
  fail "could not mint an installation token for installation $installation"
unset jwt
printf '%s\n' "$token"
