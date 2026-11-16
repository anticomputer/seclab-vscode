#!/usr/bin/env sh
# Render or check the generated regions of the RPC-lockdown docs.
#
#   rpc-filter/tools/docs.sh --check   # CI gate: fails when a doc restates
#                                      # stale numbers from the inventory,
#                                      # the policy table or the probe registry
#   rpc-filter/tools/docs.sh --write   # update them in place
#
# Run --write in the SAME commit as whatever moved the numbers.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)

exec docker run --rm \
	--network none \
	-v "$REPO":/repo \
	-w /repo/rpc-filter/tools \
	python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b \
	python3 render_docs.py "$@"
