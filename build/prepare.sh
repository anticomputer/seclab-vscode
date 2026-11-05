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
#    Exactly those listed in extensions/series ship; any other extensions/seclab-* fails.
shopt -s nullglob
shipped=" $(sed -e 's/#.*//' "$ROOT/extensions/series" | tr -s '[:space:]' ' ') "
for ext in "$ROOT"/extensions/seclab-*/; do
	name="$(basename "$ext")"
	case "$shipped" in *" $name "*) ;; *) echo "prepare: extensions/$name is not in extensions/series (refusing to build)" >&2; exit 1 ;; esac
done
for name in $shipped; do
	ext="$ROOT/extensions/$name/"
	[ -d "$ext" ] || { echo "prepare: extensions/series lists a missing extension: $name" >&2; exit 1; }
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

# 5. Upstream security defaults we rely on, asserted (not patched): a bump that changes one
#    fails the build. task.allowAutomaticTasks must default to "off" at application scope,
#    so folderOpen tasks never run without a user action and a workspace can't enable them
#    (EDR automatic-tasks-off; tasks.json campaigns).
tc="$DEST/src/vs/workbench/contrib/tasks/browser/task.contribution.ts"
if ! awk '/\[TaskSettingId.AllowAutomaticTasks\]: \{/{f=1} f&&/^\t\t\}/{exit} f' "$tc" \
	| tr -d '\t\n' | grep -q "default: 'off',scope: ConfigurationScope.APPLICATION,restricted: true"; then
	echo "prepare: upstream task.allowAutomaticTasks is no longer default 'off' at application scope (refusing to build)" >&2
	exit 1
fi

# 6. The builder image's Node is exactly upstream's .nvmrc (ADR supply-chain provenance): a
#    bot bump of the build image must not silently change the toolchain Code-OSS expects.
want="$(tr -d ' \t\r\nv' < "$DEST/.nvmrc")"
pinned="$(sed -n 's/^FROM node:\([0-9.]*\)-.*/\1/p' "$ROOT/build/linux/Dockerfile")"
if [ "$want" != "$pinned" ]; then
	echo "prepare: build/linux/Dockerfile pins node $pinned but upstream .nvmrc wants $want (refusing to build)" >&2
	exit 1
fi
echo "prepare: done ($DEST)"
