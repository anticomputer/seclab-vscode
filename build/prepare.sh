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
	# Copy sources only; no node_modules/out/dist from the developer's tree. -h dereferences
	# the tabd-src symlink so the supervisor sources ship inside the extension.
	tar -C "$ext" -h --exclude=node_modules --exclude=out --exclude=dist -cf - . | tar -C "$DEST/extensions/$name" -xf -
	echo "prepare: overlay extensions/$name"
done

# 3. product.json as data. The ui allowlist is generated from the upstream built-in
#    manifests (publisher "vscode", extensionKind preferring "ui"), excluding test-only ones.
ui_json="$DEST/.seclab-builtin-ui.json"
for m in "$DEST"/extensions/*/package.json; do
	jq -c 'select(.publisher == "vscode" and (.extensionKind // [] | .[0]) == "ui" and (.name | test("test") | not))
		| {("vscode." + .name): .extensionKind}' "$m"
done | jq -s 'add // {}' > "$ui_json"
tmp="$DEST/product.json.seclab"
jq --tab --slurpfile ov "$ROOT/build/product/overrides.json" --slurpfile ui "$ui_json" \
	-f "$ROOT/build/product/product.jq" "$DEST/product.json" > "$tmp"
mv "$tmp" "$DEST/product.json"
rm -f "$ui_json"
echo "prepare: product.json overrides applied (ui-kind built-ins: $(jq -c '.extensionKind | with_entries(select(.value|index("ui"))) | keys' "$DEST/product.json"))"

# 4. Patch queue: exactly what patches/series lists (build/apply-patches.sh, EDR patch-series).
"$ROOT/build/apply-patches.sh" "$DEST"
echo "prepare: done ($DEST)"
