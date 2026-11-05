#!/usr/bin/env bash
# npm registry signatures (and provenance attestations, where published) over every installed
# Code-OSS project: the root and each nested package (build/, remote/, extensions/*, …) that
# upstream's postinstall installed. `npm ci` checks lockfile integrity (bytes); this checks the
# registry signed what the lockfile names (origin), and that every package resolves from the
# npm registry (anything else would have no registry signature to check). It runs after
# `npm ci`, so it detects rather than prevents a bad package's install script (upstream's
# postinstall needs scripts); a failure leaves the build stamp unwritten. Fails closed on any
# invalid or missing signature. ADR supply-chain provenance; EDR 20261105-pinned-tools.
#   build/npm-audit-signatures.sh SRC
set -euo pipefail
SRC="${1:?usage: npm-audit-signatures.sh SRC}"
cd "$SRC"
n=0
while IFS= read -r -d '' lock; do
	dir="$(dirname "$lock")"
	[[ -d "$dir/node_modules" ]] || continue
	n=$((n + 1))
	# `npm audit signatures` skips what isn't from a registry with keys (git, tarball URLs,
	# other registries), so anything resolved elsewhere fails here (TT-6). Links are local.
	off="$(node -e '
		const l = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
		for (const [k, p] of Object.entries(l.packages ?? {})) {
			if (k && !p.link && p.resolved && !p.resolved.startsWith("https://registry.npmjs.org/")) console.log(k + " " + p.resolved);
		}' "$lock")"
	[[ -z "$off" ]] || { echo "npm packages not from registry.npmjs.org in $lock (no registry signature to check):" >&2; printf '%s\n' "$off" | head -20 >&2; exit 1; }
	out="$(cd "$dir" && npm audit signatures 2>&1)" || { echo "npm audit signatures FAILED in $dir:" >&2; printf '%s\n' "$out" | tail -20 >&2; exit 1; }
	printf '%s: %s\n' "$dir" "$(printf '%s\n' "$out" | grep -E 'verified (registry signature|attestation)' | tr '\n' ' ')"
done < <(find . -name node_modules -prune -o -name package-lock.json -print0)
[[ $n -gt 0 ]] || { echo "npm audit signatures: no installed project found under $SRC" >&2; exit 1; }
echo "npm audit signatures: $n project(s) verified"
