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

# Make the checkout exactly the pinned tree. A reused volume's index may carry stat info that
# hides a modified file, or skip-worktree/sparse state, so it is rebuilt: with no index, the
# reset compares every tracked file's content. `clean -ffd` without a pathspec removes every
# untracked file (files earlier patches or a test variant added); ignored build state
# (node_modules, .build, out*) stays. Git config and exclude files on the volume could hide a
# planted file from both the clean and the check, so neither is read here (review FU-10).
gd() { GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null git -C "$DEST" -c core.excludesFile=/dev/null \
	-c core.sparseCheckout=false -c core.sparseCheckoutCone=false -c status.showUntrackedFiles=normal "$@"; }
pristine() {
	local gitdir common
	gitdir="$(gd rev-parse --absolute-git-dir)" && common="$(gd rev-parse --path-format=absolute --git-common-dir)" \
		|| { echo "upstream: can't resolve $DEST's git directory" >&2; exit 1; }
	gd config --unset-all core.sparseCheckout 2>/dev/null || true
	rm -f "$gitdir/index" "$gitdir/info/sparse-checkout" "$common/info/sparse-checkout" "$common/info/exclude"
	gd reset -q --hard "$UPSTREAM_SHA"
	gd clean -q -ffd
	local left
	left="$(gd status --porcelain)"
	[[ -z "$left" ]] || { echo "upstream: $DEST still differs from $UPSTREAM_SHA after the reset:" >&2; head -20 <<<"$left" >&2; exit 1; }
}

# Our volumes hold a plain checkout. A .git that is a file or a symlink points the checks above
# at another repository, so it is refused (review FU-9).
if [[ -L "$DEST/.git" ]] || { [[ -e "$DEST/.git" ]] && [[ ! -d "$DEST/.git" ]]; }; then
	echo "upstream: $DEST/.git is not a directory (refusing)" >&2
	exit 1
fi

if [[ -d "$DEST/.git" ]] && [[ "$(git -C "$DEST" rev-parse HEAD 2>/dev/null)" == "$UPSTREAM_SHA" ]]; then
	pristine
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
# A checkout left at another pin keeps the files earlier patches added; they would make this
# pin's patches fail to apply (or, if identical, ship a previous build's file).
pristine
echo "upstream: $UPSTREAM_TAG @ $UPSTREAM_SHA -> $DEST"
