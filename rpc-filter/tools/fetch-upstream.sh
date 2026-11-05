#!/usr/bin/env sh
# Fetch the pinned upstream Code-OSS source for the inventory generator.
#
# Read-only source, no build, no npm install. Lands in .work/ which is
# gitignored and durable (never /tmp: sessions outlive /tmp pruning).
#
# Provenance: git, not a tarball. A commit SHA is a hash over the commit's
# content and git verifies objects against it, so the result is
# content-addressed from the project's own official source. An earlier version
# downloaded codeload .../tar.gz/<sha> over HTTPS and checked nothing: a
# .tar.gz is a *derived* archive, so naming a SHA in the URL does not verify
# the bytes received. That matters more here than it looks, because the whole
# policy table is derived from this source: unverified source would mean an
# unverified policy that the drift gate would happily bless.
#
#   rpc-filter/tools/fetch-upstream.sh
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
DEST="$REPO/.work/upstream"

# Prefer the build's pin so the inventory and the build never diverge.
if [ -f "$REPO/upstream.lock" ]; then
	SHA=$(grep -oE '[0-9a-f]{40}' "$REPO/upstream.lock" | head -1)
else
	SHA=a717861c07586a53d83b80d742cd3f59b20a6273
	echo "note: no upstream.lock; using fallback $SHA" >&2
fi

if [ -d "$DEST/vscode/.git" ] && [ "$(git -C "$DEST/vscode" rev-parse HEAD 2>/dev/null)" = "$SHA" ]; then
	echo "already at $SHA"
	exit 0
fi

mkdir -p "$DEST"
rm -rf "$DEST/vscode"
echo "fetching microsoft/vscode@$SHA ..."
# Blobless partial clone: enough to check out one commit without the whole
# history's blobs, and git still verifies everything it receives.
git clone --quiet --filter=blob:none --no-checkout \
	https://github.com/microsoft/vscode.git "$DEST/vscode"
git -C "$DEST/vscode" checkout --quiet --detach "$SHA"

got=$(git -C "$DEST/vscode" rev-parse HEAD)
if [ "$got" != "$SHA" ]; then
	echo "fetch-upstream: HEAD is $got, expected $SHA" >&2
	exit 1
fi
echo "upstream source at $DEST/vscode, verified at $SHA"
