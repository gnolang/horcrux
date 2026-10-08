#!/usr/bin/env bash
# Checks the contract of a horcrux release image: the binary runs, the image
# holds no shell, it works under the hardened runtime the cosigners use, it
# runs as the horcrux user, it contains only the four files it is meant to
# ship with the home owned by uid and gid 2345, and it declares no ENTRYPOINT.
#
# Usage: check-image.sh <image>
set -euo pipefail

image="${1:?usage: check-image.sh <image>}"
failed=0

fail() {
  echo "FAIL: $*" >&2
  failed=1
}

if ! command -v docker >/dev/null 2>&1; then
  echo "FAIL: docker CLI not found" >&2
  exit 1
fi

if ! out="$(docker run --rm --entrypoint horcrux "$image" version 2>&1)"; then
  fail "horcrux version does not run:"$'\n'"$out"
fi

# docker run exits 127 when, and only when, the command is not found. Any other
# status (a daemon error, a missing image) proves nothing about a shell.
status=0
out="$(docker run --rm --entrypoint sh "$image" -c true 2>&1)" || status=$?
if [[ "$status" -ne 127 ]]; then
  fail "sh probe exited $status, want 127 (no shell):"$'\n'"$out"
fi

if ! out="$(docker run --rm --user 2345:2345 --read-only --cap-drop ALL \
  --security-opt no-new-privileges --entrypoint horcrux "$image" version 2>&1)"; then
  fail "horcrux version does not run under the hardened runtime:"$'\n'"$out"
fi

entrypoint="$(docker image inspect --format '{{json .Config.Entrypoint}}' "$image")"
if [[ "$entrypoint" != "null" && "$entrypoint" != "[]" ]]; then
  fail "the image declares an ENTRYPOINT: $entrypoint"
fi

user="$(docker image inspect --format '{{.Config.User}}' "$image")"
if [[ "$user" != "horcrux" ]]; then
  fail "the image runs as user '$user', want 'horcrux'"
fi

# Exactly the files Docker injects into every container, which docker export
# includes.
injected='^(\.dockerenv|dev/(console|pts/|shm/)?|proc/|sys/|etc/(hostname|hosts|mtab|resolv\.conf))$'
expected="bin/
bin/horcrux
etc/
etc/passwd
etc/ssl/
etc/ssl/cert.pem
home/
home/horcrux/"

container=""
archive="$(mktemp)"
# shellcheck disable=SC2329 # invoked by the EXIT trap below
cleanup() {
  # A failed cleanup must not turn a passing check into a failing one.
  if [[ -n "$container" ]]; then
    docker rm -f "$container" >/dev/null || true
  fi
  rm -f "$archive"
}
trap cleanup EXIT

container="$(docker create "$image" horcrux)"
if ! out="$(docker export -o "$archive" "$container" 2>&1)"; then
  echo "FAIL: cannot export the image's files:"$'\n'"$out" >&2
  exit 1
fi
if ! listing="$(tar -tf "$archive" 2>&1)"; then
  echo "FAIL: cannot export the image's files:"$'\n'"$listing" >&2
  exit 1
fi

contents="$(printf '%s\n' "$listing" | { grep -Ev "$injected" || true; } | LC_ALL=C sort)"
if [[ "$contents" != "$expected" ]]; then
  fail "unexpected image contents:"$'\n'"$(diff <(echo "$expected") <(echo "$contents") || true)"
fi

# GNU tar prints the owner as "2345/2345"; bsdtar prints a link count, then
# uid and gid as separate fields.
owner="$(tar --numeric-owner -tvf "$archive" |
  awk '$NF == "home/horcrux/" { if ($2 ~ /\//) print $2; else print $3 "/" $4 }')"
if [[ "$owner" != "2345/2345" ]]; then
  fail "home/horcrux/ is owned by '$owner', want '2345/2345'"
fi

exit "$failed"
