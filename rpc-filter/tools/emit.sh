#!/usr/bin/env sh
# Regenerate the runtime policy module the filter patch ships.
#   rpc-filter/tools/emit.sh            # write it
#   rpc-filter/tools/emit.sh --check    # CI gate: fail if it is stale
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
exec docker run --rm --network none \
	-v "$REPO":/repo -w /repo/rpc-filter/tools \
	--platform linux/arm64 python:3.12-slim@sha256:b18b261e1b4974b4f321451ad5251ded85abb22c2b8b262da527dda1d031ab30 \
	python3 emit_policy.py "$@"
