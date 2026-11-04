#!/usr/bin/env bash
# Fetch exactly the commit pinned in upstream.lock into DEST (default: ./vscode).
# Idempotent: an existing checkout at the pinned SHA is reset to pristine source
# but keeps untracked build state (node_modules, .build) for fast rebuilds.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="${1:-$ROOT/vscode}"

# shellcheck source=/dev/null
. "$ROOT/upstream.lock"
: "${UPSTREAM_REPO:?}" "${UPSTREAM_TAG:?}" "${UPSTREAM_SHA:?}"
[[ "$UPSTREAM_SHA" =~ ^[0-9a-f]{40}$ ]] || { echo "upstream.lock: UPSTREAM_SHA must be a full 40-char SHA" >&2; exit 1; }

# The tag must still point at the pinned commit (peeled entry wins for annotated tags).
refs="$(git ls-remote "$UPSTREAM_REPO" "refs/tags/$UPSTREAM_TAG" "refs/tags/$UPSTREAM_TAG^{}")"
tag_sha="$(awk '/\^\{\}$/{print $1; f=1} END{}' <<<"$refs")"
[[ -n "$tag_sha" ]] || tag_sha="$(awk 'NR==1{print $1}' <<<"$refs")"
if [[ "$tag_sha" != "$UPSTREAM_SHA" ]]; then
	echo "refusing: tag $UPSTREAM_TAG resolves to '$tag_sha', lock says $UPSTREAM_SHA" >&2
	exit 1
fi

if [[ -d "$DEST/.git" ]] && [[ "$(git -C "$DEST" rev-parse HEAD 2>/dev/null)" == "$UPSTREAM_SHA" ]]; then
	git -C "$DEST" reset -q --hard "$UPSTREAM_SHA"
	git -C "$DEST" clean -q -fd -- extensions/ src/ build/ product.json product.json.seclab .seclab-builtin-ui.json
	echo "upstream: reusing $DEST at $UPSTREAM_TAG ($UPSTREAM_SHA), reset to pristine"
	exit 0
fi

mkdir -p "$DEST"
git -C "$DEST" init -q
git -C "$DEST" remote remove origin 2>/dev/null || true
git -C "$DEST" remote add origin "$UPSTREAM_REPO"
git -C "$DEST" fetch -q --depth 1 origin "$UPSTREAM_SHA"
git -C "$DEST" -c advice.detachedHead=false checkout -q --force FETCH_HEAD
got="$(git -C "$DEST" rev-parse HEAD)"
[[ "$got" == "$UPSTREAM_SHA" ]] || { echo "fetched $got != $UPSTREAM_SHA" >&2; exit 1; }
echo "upstream: $UPSTREAM_TAG @ $UPSTREAM_SHA -> $DEST"
