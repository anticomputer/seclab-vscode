#!/usr/bin/env sh
# Fetch the pinned upstream Code-OSS source for the inventory generator.
#
# Read-only source, no build, no npm install. Lands in .work/ which is
# gitignored and durable (never /tmp: sessions outlive /tmp pruning).
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

if [ -f "$DEST/vscode/.seclab-sha" ] && [ "$(cat "$DEST/vscode/.seclab-sha")" = "$SHA" ]; then
	echo "already at $SHA"
	exit 0
fi

mkdir -p "$DEST"
rm -rf "$DEST/vscode" "$DEST/vscode-$SHA"
echo "fetching microsoft/vscode@$SHA ..."
curl -sSL -o "$DEST/src.tar.gz" "https://codeload.github.com/microsoft/vscode/tar.gz/$SHA"
tar -xzf "$DEST/src.tar.gz" -C "$DEST"
rm -f "$DEST/src.tar.gz"
mv "$DEST/vscode-$SHA" "$DEST/vscode"
printf '%s' "$SHA" > "$DEST/vscode/.seclab-sha"
echo "upstream source at $DEST/vscode"
