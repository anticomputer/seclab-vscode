#!/usr/bin/env sh
# Run the RPC policy drift check in a container.
#
#   rpc-filter/tools/check.sh            # verify; non-zero on drift
#   rpc-filter/tools/check.sh --accept   # record the current mapping as reviewed
#
# This is the build-time gate: it fails when upstream adds or changes a surface
# that the policy table has not classified.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)

exec docker run --rm \
	--network none \
	-v "$REPO":/repo \
	-w /repo/rpc-filter/tools \
	python:3.12-slim@sha256:b18b261e1b4974b4f321451ad5251ded85abb22c2b8b262da527dda1d031ab30 \
	python3 check_drift.py "$@"
