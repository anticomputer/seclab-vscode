#!/usr/bin/env bash
# Prepare a pinned upstream checkout for building:
#   1. fetch/reset upstream (upstream.lock)
#   2. overlay our built-in extensions (extensions/seclab-*)
#   3. apply product.json overrides with jq (build/product/)
#   4. apply the ordered patch queue (patches/NNNN-*.patch)
# Usage: build/prepare.sh [DEST]   (default DEST=./vscode)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="${1:-$ROOT/vscode}"

"$ROOT/build/fetch-upstream.sh" "$DEST"

# 2. Built-in extensions live in our repo and are copied in, so upstream stays pristine.
shopt -s nullglob
for ext in "$ROOT"/extensions/seclab-*/; do
	name="$(basename "$ext")"
	rm -rf "$DEST/extensions/$name"
	mkdir -p "$DEST/extensions/$name"
	# Copy sources only; no node_modules/out/dist from the developer's tree.
	tar -C "$ext" --exclude=node_modules --exclude=out --exclude=dist -cf - . | tar -C "$DEST/extensions/$name" -xf -
	echo "prepare: overlay extensions/$name"
done

# 3. product.json as data.
tmp="$DEST/product.json.seclab"
jq --tab --slurpfile ov "$ROOT/build/product/overrides.json" -f "$ROOT/build/product/product.jq" "$DEST/product.json" > "$tmp"
mv "$tmp" "$DEST/product.json"
echo "prepare: product.json overrides applied"

# 4. Patch queue, in lexical order; any failure aborts the build.
for p in "$ROOT"/patches/[0-9][0-9][0-9][0-9]-*.patch; do
	git -C "$DEST" apply --whitespace=nowarn "$p"
	echo "prepare: applied $(basename "$p")"
done
echo "prepare: done ($DEST)"
