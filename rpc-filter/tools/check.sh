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
	python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b \
	python3 check_drift.py "$@"
