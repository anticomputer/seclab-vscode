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
	python:3.12-slim@sha256:b18b261e1b4974b4f321451ad5251ded85abb22c2b8b262da527dda1d031ab30 \
	python3 lint_probes.py "$@"
