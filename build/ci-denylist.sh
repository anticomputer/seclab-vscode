#!/usr/bin/env bash
# CI: the publish gate (EDR 20261112-publish-gate; the same engine and driver as the pre-push
# hook) over main's whole tree, with the known-names list from the SECLAB_DENYLIST secret of the
# `denylist` environment. Run only by the `denylist` job of workflow-lint.yml on a push to main;
# the environment's deployment-branch rule admits main only, so no code a branch or pull request
# controls ever runs with the secret (review round 17). There is no branch scan: a scan of
# branch-controlled input would print, in a public log, which candidate names are on the list
# (review round 19, R19-1). The list is never in the repo, in clear or hashed.
#   DENYLIST  the secret, one identifier per line ('#' comments)
#   GH_TOKEN  for the live repository-visibility check
#   ci-denylist.sh [BASE]  the tree at HEAD; with BASE (the previous main tip), also the
#                          allowlist-commit discipline over BASE..HEAD
# Fails closed when the secret is missing or empty. Every entry is masked before anything else
# runs; the list reaches the scan only as a private temp file outside the checkout, mounted
# read-only into a container with no network. CI prints counts per layer, never a location, so
# main's public log is no oracle for the list (R19-1, R20-1).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
base=''
if [[ $# -eq 1 && "$1" =~ ^[0-9a-f]{40}$ && ! "$1" =~ ^0+$ ]] && git -C "$ROOT" merge-base --is-ancestor "$1" HEAD 2>/dev/null; then
	base="$1"
elif [[ $# -gt 1 ]]; then
	echo "usage: ci-denylist.sh [BASE]" >&2
	exit 2
elif [[ $# -eq 1 && -n "$1" && ! "$1" =~ ^0+$ ]]; then
	# A force-push, an unfetched or a malformed base: the allowlist discipline can't run over the range.
	echo "::notice title=publish-gate::the previous main tip is not an ancestor here; scanning the tree without the allowlist-commit check (R20-5)"
fi

if [[ -z "${DENYLIST:-}" ]]; then
	echo "::error title=denylist::the SECLAB_DENYLIST secret (environment denylist) is missing or empty; failing closed"
	exit 1
fi

# Mask every entry for the rest of the job. Workflow-command data is percent-decoded by the
# runner, so encode %, CR and LF first or a different string would be registered.
while IFS= read -r line || [[ -n "$line" ]]; do
	entry="${line%%#*}"
	entry="${entry#"${entry%%[![:space:]]*}"}"
	entry="${entry%"${entry##*[![:space:]]}"}"
	[[ -z "$entry" ]] && continue
	entry="${entry//%/%25}"
	entry="${entry//$'\r'/%0D}"
	echo "::add-mask::$entry"
done <<<"$DENYLIST"

# The temp list lives outside the checkout (the checkout is mounted into other containers).
if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
	[[ -n "${RUNNER_TEMP:-}" && -d "$RUNNER_TEMP" ]] || { echo "::error title=denylist::RUNNER_TEMP is not set"; exit 1; }
	parent="$RUNNER_TEMP"
else
	parent="${TMPDIR:-/tmp}"
fi
case "$parent/" in "$ROOT"/*) echo "denylist: refusing a temp dir inside the checkout" >&2; exit 1 ;; esac
umask 077
dir="$(mktemp -d "$parent/seclab-denylist.XXXXXX")"
trap 'rm -rf "$dir"' EXIT
printf '%s\n' "$DENYLIST" >"$dir/list"
unset DENYLIST

# shellcheck source=build/hooks/publish-gate.sh
. "$ROOT/build/hooks/publish-gate.sh"
image="$("$ROOT/seclab" print-node-image)"
docker image inspect "$image" >/dev/null 2>&1 || docker pull -q "$image" >/dev/null
gitdir="$(cd "$(git -C "$ROOT" rev-parse --git-common-dir)" && pwd -P)"
rc=0
publish_gate "$image" "$ROOT/build" "$gitdir" "$dir/list" '' -- \
	git-tree --git-dir /git --ref refs/heads/main --denylist-counts ${base:+--base "$base"} "$(git -C "$ROOT" rev-parse HEAD)" || rc=$?
case "$rc" in
	0) echo "publish-gate: clean" ;;
	3) echo "::notice title=publish-gate::lines that may record a private conversation; run ./seclab lint publish with the list to see where" ;;
	*) echo "::error title=publish-gate::blocked (counts above; run ./seclab lint publish with the list to see where)"; exit 1 ;;
esac
