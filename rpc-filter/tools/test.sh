#!/usr/bin/env sh
# Run the inventory generator's own tests in a container.
#
#   rpc-filter/tools/test.sh [path-to-vscode-checkout]
#
# Covers the generator's determinism and constant resolution: the inventory
# must depend on the pinned source, not on the order the filesystem happened to
# enumerate it in. A command's policy category is derived from its id, so
# anything that can change an id can silently change a security classification.
#
# The synthetic-fixture tests need no source and always run. The full
# double-run over upstream runs too when a checkout is available (CI fetches
# one for the inventory job); otherwise it is skipped.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
SRC=${1:-"$REPO/.work/upstream/vscode"}

IMAGE=python:3.12-slim@sha256:b18b261e1b4974b4f321451ad5251ded85abb22c2b8b262da527dda1d031ab30

if [ -d "$SRC/src/vs" ]; then
	SRC_ABS=$(cd "$SRC" && pwd)
	exec docker run --rm \
		--network none \
		-v "$REPO":/repo \
		-v "$SRC_ABS":/src:ro \
		-w /repo/rpc-filter/tools \
		--platform linux/arm64 "$IMAGE" \
		python3 test_generator.py
fi

echo "note: no upstream checkout at $SRC; running fixture tests only" >&2
exec docker run --rm \
	--network none \
	-v "$REPO":/repo \
	-w /repo/rpc-filter/tools \
	--platform linux/arm64 "$IMAGE" \
	python3 test_generator.py
