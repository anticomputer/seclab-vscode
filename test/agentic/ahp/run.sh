#!/usr/bin/env bash
# Agents-in-the-tab spike, protocol-level probes (plan §11.1, EDR agents-in-the-tab spike).
# Bundles the real upstream agent-host client from the pinned source and drives it from
# a rogue agent host, first unmodified (every probe must come out vulnerable), then
# through the gate prototype. Network-less container; writes only under the run dir.
#
#   test/agentic/ahp/run.sh [--disarmed]
#
# Needs: the pinned source at .work/vscode (build/fetch-upstream.sh .work/vscode) and the
# builder volume seclab-vscode-work (read-only: esbuild and node_modules).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SRC="$ROOT/.work/vscode"
IMG='node:24.22.1-trixie@sha256:f1e034976f948cf212ef1f659c12e5dd58ac7eab947831813e81a62401ca38be'
. "$ROOT/upstream.lock"
[[ "$(git -C "$SRC" rev-parse HEAD)" == "$UPSTREAM_SHA" ]] || { echo "run: $SRC is not at $UPSTREAM_SHA" >&2; exit 2; }
[[ -z "$(git -C "$SRC" status --porcelain -- src)" ]] || { echo "run: $SRC/src is modified; baseline must be pristine upstream" >&2; exit 2; }

NONCE="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
ARM="$NONCE"; [[ "${1:-}" == "--disarmed" ]] && ARM=""
RUN="$ROOT/.work/agentic/runs/$(date -u +%Y%m%dT%H%M%SZ)-$NONCE"
mkdir -p "$RUN"
printf '{"nonce":"%s","upstream":"%s","image":"%s","armed":%s}\n' "$NONCE" "$UPSTREAM_SHA" "$IMG" "$([[ -n $ARM ]] && echo true || echo false)" > "$RUN/run.json"

# Same absolute path inside the container, so on-disk evidence paths mean the same thing.
status=0
docker run --rm --network none -u "$(id -u):$(id -g)" \
	-v seclab-vscode-work:/shared:ro \
	-v "$SRC":/src:ro \
	-v "$ROOT/test/agentic/ahp":/harness:ro \
	-v "$RUN":/run \
	-e RUN_DIR=/run -e NONCE="$NONCE" -e ARM_NONCE="$ARM" \
	"$IMG" sh -c 'MODE=baseline node /harness/bundle.mjs && MODE=gated node /harness/bundle.mjs && MODE=baseline node /run/bundle-baseline.mjs && MODE=gated node /run/bundle-gated.mjs && node /harness/verdict.mjs' || status=$?
rm -f "$RUN"/bundle-*.mjs
echo "run: $RUN (exit $status)"
exit $status
