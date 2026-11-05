#!/usr/bin/env sh
# Regenerate the runtime policy module the filter patch ships, and keep the
# patch queue carrying it in sync.
#
#   rpc-filter/tools/emit.sh            # write both
#   rpc-filter/tools/emit.sh --check    # CI gate: fail if either is stale
#
# The second step matters: the filter's TypeScript lives both as editable
# source under rpc-filter/patch-src/ and as a new-file hunk inside the patch
# that ships it. build/apply-patches.sh --check verifies the patch *applies*,
# not that it carries what we think it carries, so regenerating the policy
# without resyncing the patch leaves the build shipping the previous verdicts.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
IMAGE=python:3.12-slim@sha256:b18b261e1b4974b4f321451ad5251ded85abb22c2b8b262da527dda1d031ab30

# No --platform: the digest is a multi-arch index, so docker selects the host
# architecture. Pinning linux/arm64 would run under emulation on CI's amd64.
run() {
	docker run --rm --network none \
		-v "$REPO":/repo -w /repo/rpc-filter/tools \
		"$IMAGE" "$@"
}

run python3 emit_policy.py "$@"

# emit_policy.py takes --check; sync_patch.py needs --check or --write.
case "${1:-}" in
	--check) run python3 sync_patch.py --check ;;
	*) run python3 sync_patch.py --write ;;
esac
