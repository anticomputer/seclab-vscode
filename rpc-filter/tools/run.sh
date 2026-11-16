#!/usr/bin/env sh
# Regenerate the RPC attack-surface inventory.
#
# Runs in a container so nothing is installed on the host. The generator is
# standard-library Python, so the stock image needs no build step and no
# network access at run time.
#
#   rpc-filter/tools/run.sh [path-to-vscode-checkout]
#
# With no argument it uses .work/upstream/vscode, which is where
# fetch-upstream.sh puts the pinned source.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
SRC=${1:-"$REPO/.work/upstream/vscode"}

if [ ! -d "$SRC/src/vs" ]; then
	echo "error: $SRC is not a vscode checkout; run rpc-filter/tools/fetch-upstream.sh first" >&2
	exit 2
fi

SRC_ABS=$(cd "$SRC" && pwd)

exec docker run --rm \
	--network none \
	-v "$REPO":/repo \
	-v "$SRC_ABS":/src:ro \
	-w /repo/rpc-filter/tools \
	python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b \
	python3 extract_inventory.py --source /src --out /repo/rpc-filter/inventory
