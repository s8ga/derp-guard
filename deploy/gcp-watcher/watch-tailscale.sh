#!/usr/bin/env bash
# Tailscale upstream release watcher:
# polls the latest stable tag via the GitHub API using ETag/304 (zero quota),
# and when a new tag appears that has not been dispatched yet, sends a
# repository_dispatch to the build repo.
#
# Environment variables (provided by /etc/default/watch-tailscale):
#   GH_PAT       a GitHub PAT with repo scope (auth + dispatch)
#   TARGET_REPO  the build repo, e.g. "s8ga/derp-guard"
set -euo pipefail

: "${GH_PAT:?GH_PAT environment variable is required}"
: "${TARGET_REPO:?TARGET_REPO environment variable is required (e.g. s8ga/derp-guard)}"

ETAG_FILE=/var/tmp/ts_release.etag
LAST_TAG_FILE=/var/tmp/ts_last_dispatched.tag

# On an ETag hit GitHub returns 304 with no body; curl still exits 0.
RESP="$(curl -fsS --etag-compare "$ETAG_FILE" --etag-save "$ETAG_FILE" \
  -H "Authorization: Bearer ${GH_PAT}" \
  -H "Accept: application/vnd.github+json" \
  https://api.github.com/repos/tailscale/tailscale/releases/latest || true)"

[ -z "$RESP" ] && exit 0 # 304 Not Modified: no new upstream release

TAG="$(printf '%s' "$RESP" | grep -oP '(?<="tag_name": ")[^"]+' || true)"
[ -z "$TAG" ] && exit 0

LAST="$(cat "$LAST_TAG_FILE" 2>/dev/null || true)"
if [ "$TAG" = "$LAST" ]; then
  exit 0 # already dispatched
fi

HTTP_CODE="$(curl -fsS -o /dev/null -w '%{http_code}' -X POST \
  -H "Authorization: Bearer ${GH_PAT}" \
  -H "Accept: application/vnd.github+json" \
  -d "{\"event_type\":\"upstream_release\",\"client_payload\":{\"tailscale_tag\":\"${TAG}\"}}" \
  "https://api.github.com/repos/${TARGET_REPO}/dispatches")"

printf '%s dispatched upstream_release %s -> %s (HTTP %s)\n' \
  "$(date -Is)" "$TAG" "$TARGET_REPO" "$HTTP_CODE"
printf '%s' "$TAG" > "$LAST_TAG_FILE"
