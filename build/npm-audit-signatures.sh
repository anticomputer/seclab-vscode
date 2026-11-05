#!/usr/bin/env bash
# npm registry signatures (and provenance attestations, where published) over every installed
# Code-OSS project: the root and each nested package (build/, remote/, extensions/*, …) that
# upstream's postinstall installed. `npm ci` checks lockfile integrity (bytes); this checks the
# registry signed what the lockfile names (origin). Fails closed on any invalid or missing
# signature. ADR supply-chain provenance; EDR 20261105-pinned-tools.
#   build/npm-audit-signatures.sh SRC
set -euo pipefail
SRC="${1:?usage: npm-audit-signatures.sh SRC}"
cd "$SRC"
n=0
while IFS= read -r -d '' lock; do
	dir="$(dirname "$lock")"
	[[ -d "$dir/node_modules" ]] || continue
	n=$((n + 1))
	out="$(cd "$dir" && npm audit signatures 2>&1)" || { echo "npm audit signatures FAILED in $dir:" >&2; printf '%s\n' "$out" | tail -20 >&2; exit 1; }
	printf '%s: %s\n' "$dir" "$(printf '%s\n' "$out" | grep -E 'verified (registry signature|attestation)' | tr '\n' ' ')"
done < <(find . -name node_modules -prune -o -name package-lock.json -print0)
[[ $n -gt 0 ]] || { echo "npm audit signatures: no installed project found under $SRC" >&2; exit 1; }
echo "npm audit signatures: $n project(s) verified"
