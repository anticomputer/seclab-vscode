#!/usr/bin/env sh
# Lint the probe payloads for anything that could harm the host.
#
#   rpc-filter/tools/lint.sh
#
# Runs with the probe safety rules in rpc-filter/AGENTS.md section 8.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
exec docker run --rm --network none \
	-v "$REPO":/repo -w /repo/rpc-filter/tools \
	python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b \
	python3 lint_probes.py "$@"
