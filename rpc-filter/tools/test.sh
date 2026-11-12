#!/usr/bin/env sh
# Run the inventory generator's own tests in a container.
#
#   rpc-filter/tools/test.sh [path-to-vscode-checkout]     (default .work/upstream/vscode)
#
# Covers the generator's determinism and constant resolution, the
# server-initiated push sweep, and the enforcement gate: the inventory
# must depend on the pinned source, not on the order the filesystem happened to
# enumerate it in. A command's policy category is derived from its id, so
# anything that can change an id can silently change a security classification.
#
# The upstream checkout is REQUIRED (build/fetch-upstream.sh .work/upstream/vscode; the unit
# job fetches it). Without it this fails, and so does any skipped test: running only the
# fixture tests and exiting 0 meant the upstream double-run never ran in CI (gate audit
# GATE-12).
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
SRC=${1:-"$REPO/.work/upstream/vscode"}

IMAGE=python:3.12-slim@sha256:b18b261e1b4974b4f321451ad5251ded85abb22c2b8b262da527dda1d031ab30

if [ ! -d "$SRC/src/vs" ]; then
	echo "test.sh: no upstream checkout at $SRC; the upstream tests are required." >&2
	echo "         fetch it with: build/fetch-upstream.sh $SRC" >&2
	exit 1
fi
SRC_ABS=$(cd "$SRC" && pwd)
# A skipped test is a failure here: every test in these modules must run.
exec docker run --rm \
	--network none \
	-e SECLAB_REQUIRE_UPSTREAM=1 \
	-v "$REPO":/repo \
	-v "$SRC_ABS":/src:ro \
	-w /repo/rpc-filter/tools \
	"$IMAGE" \
	python3 -c '
import sys, unittest
suite = unittest.defaultTestLoader.loadTestsFromNames(["test_generator", "test_enforcement", "test_lint_probes"])
result = unittest.TextTestRunner(verbosity=1).run(suite)
for test, reason in result.skipped:
    print("SKIPPED (not allowed here): %s: %s" % (test.id(), reason), file=sys.stderr)
sys.exit(0 if result.wasSuccessful() and not result.skipped and result.testsRun > 0 else 1)
'
