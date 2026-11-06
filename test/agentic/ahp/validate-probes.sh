#!/usr/bin/env bash
# Protocol-level validation of the probe runner's probes, against the REAL upstream
# agent-host client. No editor, no window, no network.
#
# Each probe in test/agentic/runner/probes.js declares what it must reach in the client;
# this fails if any probe does not reach it. That is the gate that stops a malformed probe
# from reporting "no host effect" in a real run and being read as containment.
#
#   test/agentic/ahp/validate-probes.sh
#
# Needs: the pinned source at .work/vscode (build/fetch-upstream.sh .work/vscode) and the
# builder volume seclab-vscode-work (read-only: esbuild and node_modules).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SRC="$ROOT/.work/vscode"
IMG='node:24.22.1-trixie@sha256:f1e034976f948cf212ef1f659c12e5dd58ac7eab947831813e81a62401ca38be'
. "$ROOT/upstream.lock"
[[ "$(git -C "$SRC" rev-parse HEAD)" == "$UPSTREAM_SHA" ]] || { echo "validate-probes: $SRC is not at $UPSTREAM_SHA" >&2; exit 2; }
[[ -z "$(git -C "$SRC" status --porcelain -- src)" ]] || { echo "validate-probes: $SRC/src is modified; the client must be pristine upstream" >&2; exit 2; }

NONCE="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
RUN="$ROOT/.work/agentic/validate/$(date -u +%Y%m%dT%H%M%SZ)-$NONCE"
mkdir -p "$RUN"

status=0
docker run --rm --network none -u "$(id -u):$(id -g)" \
	-v seclab-vscode-work:/shared:ro \
	-v "$SRC":/src:ro \
	-v "$ROOT/test/agentic/ahp":/harness:ro \
	-v "$ROOT/test/agentic/runner":/probes:ro \
	-v "$RUN":/run \
	-e RUN_DIR=/run -e NONCE="$NONCE" \
	"$IMG" sh -c 'MODE=baseline ENTRY=/harness/probe-validate.ts OUT=/run/bundle-validate.mjs node /harness/bundle.mjs && node /run/bundle-validate.mjs' || status=$?
rm -f "$RUN"/bundle-*.mjs
echo "validate-probes: $RUN (exit $status)"
exit $status
