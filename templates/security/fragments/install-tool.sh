#!/usr/bin/env bash
# install-tool.sh: downloads one scanner pinned in security/pins.rs for the
# runner's architecture, verifies its SHA-256 and only then installs the
# binary. Nothing is extracted or copied before the digest matches; a mismatch
# is one ::error:: line and exit 1. Parameters come from the pin table:
#   TOOL_NAME TOOL_VERSION TOOL_BIN TOOL_FORMAT (tgz|bin)
#   TOOL_URL_AMD64 TOOL_SHA256_AMD64 TOOL_URL_ARM64 TOOL_SHA256_ARM64
# Optional: TOOL_BIN_DIR, the workspace-local bin dir (default: under
# RUNNER_TEMP, or the working directory); it is appended to GITHUB_PATH.
# Optional: TOOL_BIN_PATH (tgz only), the binary's path inside the archive
# when it is not at the root, `*` allowed (Hurl: hurl-*/bin/hurl); it must
# resolve to exactly one regular file inside the extracted archive.
# Needs bash, curl, tar, install and sha256sum or shasum.
set -euo pipefail

for name in TOOL_NAME TOOL_VERSION TOOL_BIN TOOL_FORMAT \
  TOOL_URL_AMD64 TOOL_SHA256_AMD64 TOOL_URL_ARM64 TOOL_SHA256_ARM64; do
  if [ -z "${!name:-}" ]; then
    echo "::error::security: install-tool.sh needs $name"
    exit 1
  fi
done

fail() {
  echo "::error::security: $TOOL_NAME $TOOL_VERSION $*"
  exit 1
}

digest() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

case "$TOOL_FORMAT" in
  tgz | bin) ;;
  *) fail "unknown format $TOOL_FORMAT" ;;
esac

bin_path="${TOOL_BIN_PATH:-}"
if [ -n "$bin_path" ]; then
  if [ "$TOOL_FORMAT" != tgz ]; then
    fail "TOOL_BIN_PATH needs format tgz, got $TOOL_FORMAT"
  fi
  case "/$bin_path/" in
    //* | */../*) fail "TOOL_BIN_PATH $bin_path must be relative to the archive root without .." ;;
  esac
fi

# Sets member to the one file TOOL_BIN_PATH names under the extract dir $1:
# globbed by compgen -G (no word splitting), exactly one match, a regular file
# (not a link) whose directory resolves inside $1. Runs in this shell so fail
# exits it.
archive_member() {
  local root dir found
  local matches=()
  root="$(cd -P "$1" && pwd -P)"
  while IFS= read -r found; do
    matches+=("$found")
  done < <(compgen -G "$1/$bin_path")
  if [ "${#matches[@]}" -ne 1 ]; then
    fail "($arch) TOOL_BIN_PATH $bin_path matches ${#matches[@]} files in the archive; exactly one is required"
  fi
  if [ -L "${matches[0]}" ] || [ ! -f "${matches[0]}" ]; then
    fail "($arch) TOOL_BIN_PATH $bin_path is not a regular file inside the archive"
  fi
  dir="$(cd -P "$(dirname "${matches[0]}")" && pwd -P)"
  case "$dir/" in
    "$root"/*) ;;
    *) fail "($arch) TOOL_BIN_PATH $bin_path is not a regular file inside the archive" ;;
  esac
  member="${matches[0]}"
}

machine="$(uname -m)"
case "$machine" in
  x86_64 | amd64)
    arch=amd64
    url="$TOOL_URL_AMD64"
    expected="$TOOL_SHA256_AMD64"
    ;;
  aarch64 | arm64)
    arch=arm64
    url="$TOOL_URL_ARM64"
    expected="$TOOL_SHA256_ARM64"
    ;;
  *) fail "has no pin for architecture $machine" ;;
esac

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
file="$tmp/$TOOL_NAME-$arch.download"

echo "install: $TOOL_NAME $TOOL_VERSION $arch from $url"
if ! curl -fsSL --retry 3 -o "$file" "$url"; then
  fail "($arch) download failed: $url"
fi

actual="$(digest "$file")"
if [ "$actual" != "$expected" ]; then
  fail "($arch) checksum mismatch: expected $expected, got $actual; nothing was installed"
fi

bin_dir="${TOOL_BIN_DIR:-${RUNNER_TEMP:-$PWD}/brakes-bin}"
mkdir -p "$bin_dir"
case "$TOOL_FORMAT" in
  tgz)
    mkdir "$tmp/extract"
    tar -xzf "$file" -C "$tmp/extract"
    member="$tmp/extract/$TOOL_BIN"
    if [ -n "$bin_path" ]; then
      archive_member "$tmp/extract"
    elif [ ! -f "$member" ]; then
      fail "($arch) archive has no $TOOL_BIN at its root"
    fi
    install -m 0755 "$member" "$bin_dir/$TOOL_BIN"
    ;;
  bin)
    install -m 0755 "$file" "$bin_dir/$TOOL_BIN"
    ;;
esac

if [ -n "${GITHUB_PATH:-}" ]; then
  echo "$bin_dir" >>"$GITHUB_PATH"
fi
echo "tool: $TOOL_NAME $TOOL_VERSION sha256=$actual"
