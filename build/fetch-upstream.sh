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
# untracked file (files earlier patches or a test variant added), ignored or not, except the
# install and download caches (node_modules, .build). No git config, attribute, hook or
# replacement ref outside our control is read: system and global config are off (review FU-10), and the checkout's own repository
# state is rewritten before any command acts on the tree, because a kept clean/smudge filter or
# core.worktree would make the tree differ from what the check sees (Copilot review on PR 25).
gd() { GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_NO_REPLACE_OBJECTS=1 git -C "$DEST" -c core.excludesFile=/dev/null \
	-c core.attributesFile=/dev/null -c core.hooksPath=/dev/null -c core.fsmonitor=false \
	-c core.sparseCheckout=false -c core.sparseCheckoutCone=false -c status.showUntrackedFiles=normal "$@"; }
scrub() {
	local g="$DEST/.git"
	# Git makes no symlink here; one would point a write or a delete outside DEST (a linked
	# config truncated, a linked info/ emptied, a linked objects/ written by the fetch).
	if [[ -n "$(find "$g" -type l -print -quit)" ]]; then
		echo "upstream: $g holds a symlink (refusing)" >&2
		exit 1
	fi
	# Unlinked first, so a hard-linked config's other name is left alone.
	rm -f "$g/config"
	printf '[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n' > "$g/config"
	rm -rf "$g/config.worktree" "$g/commondir" "$g/worktrees" "$g/hooks" "$g/index" "$g/info"
	local top
	top="$(gd rev-parse --show-toplevel)" && [[ "$top" == "$(cd "$DEST" && pwd -P)" ]] \
		|| { echo "upstream: $DEST's work tree resolves elsewhere (refusing)" >&2; exit 1; }
}
pristine() {
	scrub
	gd reset -q --hard "$UPSTREAM_SHA"
	# -x: no ignore file decides what stays, since an untracked .gitignore of `*` would hide itself
	# and its directory from both this and the check (Copilot review on PR 25). Only the install
	# and download caches stay; build outputs are made again by every build.
	gd clean -q -ffdx -e node_modules -e /.build
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

if [[ -d "$DEST/.git" ]]; then
	scrub
	if [[ "$(gd rev-parse -q --verify HEAD 2>/dev/null)" == "$UPSTREAM_SHA" ]]; then
		pristine
		echo "upstream: reusing $DEST at $UPSTREAM_TAG ($UPSTREAM_SHA), reset to pristine"
		exit 0
	fi
else
	mkdir -p "$DEST"
	gd init -q
	scrub
fi

gd remote add origin "$UPSTREAM_REPO"
gd fetch -q --depth 1 origin "$UPSTREAM_SHA"
gd -c advice.detachedHead=false checkout -q --force FETCH_HEAD
got="$(gd rev-parse HEAD)"
[[ "$got" == "$UPSTREAM_SHA" ]] || { echo "fetched $got != $UPSTREAM_SHA" >&2; exit 1; }
# A checkout left at another pin keeps the files earlier patches added; they would make this
# pin's patches fail to apply (or, if identical, ship a previous build's file).
pristine
echo "upstream: $UPSTREAM_TAG @ $UPSTREAM_SHA -> $DEST"
