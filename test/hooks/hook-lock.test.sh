#!/usr/bin/env bash
# Downgrade protection for the shared pre-push hook (EDR 20261112-publish-gate): an older
# installer can't replace the gate hook, and the gate hook fails closed when it was edited or
# when core.hooksPath moved. Uses the real hook template and the real lock functions; replays
# the exact write sequence of the installers that predate the gate. No docker, no network.
#   test/hooks/hook-lock.test.sh
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=build/hooks/publish-gate.sh
. "$ROOT/build/hooks/publish-gate.sh"
sha256() { (command -v sha256sum >/dev/null && sha256sum || shasum -a 256) | cut -d' ' -f1; }

work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/seclab-hook-lock.XXXXXX")"
cleanup() { publish_gate_unlock_hooks "$work/repo/.git/seclab-hooks" 2>/dev/null; rm -rf "$work"; }
trap cleanup EXIT
git init -q "$work/repo"
cd "$work/repo" || exit 1
hookdir="$(cd .git && pwd -P)/seclab-hooks"
z64="$(printf '0%.0s' $(seq 64))"
install_gate() { # what ./seclab hooks install leaves behind, with placeholder pins
	publish_gate_unlock_hooks "$hookdir"
	mkdir -p "$hookdir"
	local hook
	hook="$(<"$ROOT/build/hooks/pre-push")"
	hook="${hook//@GITLEAKS_IMAGE@/sha256:$z64}"
	hook="${hook//@GITLEAKS_SHA256@/$z64}"
	hook="${hook//@NODE_IMAGE@/sha256:$z64}"
	hook="${hook//@GATE_SUMS@/x}"
	hook="${hook//@DRIVER_SHA256@/$z64}"
	printf '%s\n' "$hook" >"$hookdir/pre-push" && chmod 0755 "$hookdir/pre-push"
	printf '%s\n%s\n' "$(sha256 <"$hookdir/pre-push")" "$z64" >"$hookdir/.installed"
	git config core.hooksPath "$hookdir"
	publish_gate_lock_hooks "$hookdir"
}
fail=0
ok() { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }
run_hook() { bash "$hookdir/pre-push" origin x </dev/null 2>&1; }

install_gate
before="$(sha256 <"$hookdir/pre-push")"

# The installers that predate the gate (main up to 607873da): their exact write sequence.
(
	set +e
	hook='#!/usr/bin/env bash
echo gitleaks only'
	mkdir -p "$hookdir"
	printf '%s\n' "$hook" > "$hookdir/pre-push.tmp" && chmod 0755 "$hookdir/pre-push.tmp" && mv "$hookdir/pre-push.tmp" "$hookdir/pre-push"
	git config core.hooksPath "$hookdir"
) 2>/dev/null
[[ "$(sha256 <"$hookdir/pre-push")" == "$before" && ! -e "$hookdir/pre-push.tmp" ]] \
	&& ok 'an installer that predates the gate cannot replace the locked hook' \
	|| bad 'an installer that predates the gate replaced the locked hook'
# The gate's first installers wrote publish-gate.tmp before the hook.
( set +e; mkdir -p "$hookdir/publish-gate.tmp" ) 2>/dev/null
[[ ! -e "$hookdir/publish-gate.tmp" ]] && ok 'an unlocking-unaware gate installer cannot write either' || bad 'publish-gate.tmp was written into the locked directory'

out="$(run_hook)"
[[ "$out" == *'the publish gate is not installed next to the hook'* || "$out" == *'no docker'* ]] \
	&& ok 'the installed hook passes its own checks' || { bad 'the installed hook failed its own checks'; echo "$out" | tail -2; }

publish_gate_unlock_hooks "$hookdir"
printf '# edited\n' >>"$hookdir/pre-push"
publish_gate_lock_hooks "$hookdir"
out="$(run_hook)"
[[ "$out" == *'is not the one ./seclab hooks install wrote'* ]] && ok 'an edited hook fails closed' || { bad 'an edited hook ran'; echo "$out" | tail -2; }

install_gate
mkdir -p "$work/elsewhere"
git config core.hooksPath "$work/elsewhere"
out="$(run_hook)"
[[ "$out" == *'core.hooksPath no longer points at the gate hook'* ]] && ok 'a moved core.hooksPath fails closed' || { bad 'a moved core.hooksPath went unnoticed'; echo "$out" | tail -2; }
git config --unset core.hooksPath
out="$(run_hook)"
[[ "$out" == *'core.hooksPath no longer points at the gate hook'* ]] && ok 'an unset core.hooksPath fails closed' || { bad 'an unset core.hooksPath went unnoticed'; echo "$out" | tail -2; }

[[ "$fail" == 0 ]] && echo "hook-lock: downgrade protection holds"
exit "$fail"
