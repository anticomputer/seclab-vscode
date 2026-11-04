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
	--platform linux/arm64 python:3.12-slim \
	python3 lint_probes.py "$@"
