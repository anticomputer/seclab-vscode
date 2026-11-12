#!/usr/bin/env bash
# The publish gate's real mount path with a private list (EDR 20261112-publish-gate): the
# driver, its docker flags and the pinned node image, with a fake list written exactly as
# build/ci-denylist.sh writes the secret (umask 077, mode 600, a private temp dir outside the
# checkout, owned by the invoking user). An in-process self-test can't see a list the container
# can't open; this can. Run by the lint job on every push and PR, where the engine is Linux and
# bind-mount ownership is real, and by `./seclab lint publish --mount-test` locally.
#   build/test-publish-mount.sh
# Exit 0 only if the gate read the list: a clean text passes, and a text naming a listed (fake)
# entry is blocked by the known-names layer.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=build/hooks/publish-gate.sh
. "$ROOT/build/hooks/publish-gate.sh"
image="$("$ROOT/seclab" print-node-image)"
docker image inspect "$image" >/dev/null 2>&1 || docker pull -q "$image" >/dev/null

parent="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
case "$parent/" in "$ROOT"/*) echo "mount-test: refusing a temp dir inside the checkout" >&2; exit 1 ;; esac
umask 077
dir="$(mktemp -d "$parent/seclab-mount-test.XXXXXX")"
trap 'rm -rf "$dir"' EXIT
printf '%s\n' 'zq-seclab-fake-entry-7731' >"$dir/list"
mode="$(stat -c '%a' "$dir/list" 2>/dev/null || stat -f '%Lp' "$dir/list")"
[[ "$mode" == 600 ]] || { echo "mount-test: the fake list is mode $mode, not 600" >&2; exit 1; }

fail=0
check() { # name want-rc text
	local rc=0
	printf '%s\n' "$3" | publish_gate "$image" "$ROOT/build" "$ROOT/build/publish-allow.json" "$dir/list" '' -- text >"$dir/out" 2>&1 || rc=$?
	if [[ "$rc" == "$2" ]] && { [[ "$2" != 1 ]] || grep -q '^publish-gate: denylist: ' "$dir/out"; }; then
		echo "ok   $1"
	else
		echo "FAIL $1 (exit $rc, want $2)"
		grep -v 'zq-seclab' "$dir/out" | tail -3
		fail=1
	fi
}
check 'a clean text passes with the private list mounted' 0 'Nothing to see here.'
check 'a listed name is found, so the list was read' 1 'the zq_seclab_fake_entry_7731 job'
[[ "$fail" == 0 ]] && echo "mount-test: the gate reads a mode-600 list through its real mount as $(id -u):$(id -g)"
exit "$fail"
