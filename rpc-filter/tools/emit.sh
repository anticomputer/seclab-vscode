#!/usr/bin/env sh
# Regenerate the runtime policy module the filter patch ships.
#   rpc-filter/tools/emit.sh            # write it
#   rpc-filter/tools/emit.sh --check    # CI gate: fail if it is stale
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
exec docker run --rm --network none \
	-v "$REPO":/repo -w /repo/rpc-filter/tools \
	--platform linux/arm64 python:3.12-slim \
	python3 emit_policy.py "$@"
