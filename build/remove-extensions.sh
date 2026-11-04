#!/usr/bin/env bash
# Remove upstream built-in extensions listed in build/product/remove-extensions.txt.
# Runs after `npm ci` (whose postinstall expects the upstream extension dirs).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${1:?usage: remove-extensions.sh SRC}"
while IFS= read -r line; do
	name="${line%%#*}"; name="${name//[[:space:]]/}"
	[[ -z "$name" ]] && continue
	[[ "$name" =~ ^[a-z0-9][a-z0-9.-]*$ ]] || { echo "bad extension name: $name" >&2; exit 1; }
	rm -rf "${SRC:?}/extensions/$name"
	echo "remove-extensions: removed extensions/$name"
done < "$ROOT/build/product/remove-extensions.txt"
