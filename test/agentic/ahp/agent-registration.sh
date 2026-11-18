#!/usr/bin/env bash
# Patch 0019's probe, both arms, against the REAL upstream registries. No editor, no window,
# no network.
#
#   test/agentic/ahp/agent-registration.sh
#
# The point of running BOTH arms every time: the gated arm alone cannot distinguish "the patch
# contains this" from "the probe never looked". The baseline arm is the control, and it must
# report `vulnerable`, from pristine upstream, or this exits non-zero and says so. A probe whose
# control has stopped failing is not evidence, and this project has shipped that mistake before.
#
# The gated tree is DERIVED here, by applying patches/series to a pristine worktree of the
# pinned upstream, rather than taken from a tree someone prepared by hand. What is probed is
# therefore what the patch queue actually produces.
#
# Needs: the pinned source at .work/vscode (build/fetch-upstream.sh .work/vscode) and the
# builder volume seclab-vscode-work (read-only: esbuild and node_modules).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SRC="$ROOT/.work/vscode"
GATED="$ROOT/.work/agentic/gated-tree"
IMG='node:24.22.1-trixie@sha256:f1e034976f948cf212ef1f659c12e5dd58ac7eab947831813e81a62401ca38be'
. "$ROOT/upstream.lock"

[[ "$(git -C "$SRC" rev-parse HEAD)" == "$UPSTREAM_SHA" ]] || { echo "agent-registration: $SRC is not at $UPSTREAM_SHA" >&2; exit 2; }
[[ -z "$(git -C "$SRC" status --porcelain -- src)" ]] || { echo "agent-registration: $SRC/src is modified; the baseline must be pristine upstream" >&2; exit 2; }

NONCE="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
RUN="$ROOT/.work/agentic/agent-registration/$(date -u +%Y%m%dT%H%M%SZ)-$NONCE"
mkdir -p "$RUN"

# The gated tree: pristine upstream at the verified pin plus every patch `series` lists, in order.
. "$ROOT/test/agentic/ahp/derive-tree.sh"
derive_tree "$GATED"

run_arm() { # arm, source tree
	docker run --rm --network none -u "$(id -u):$(id -g)" \
		-v seclab-vscode-work:/shared:ro \
		-v "$2":/src:ro \
		-v "$ROOT/test/agentic/ahp":/harness:ro \
		-v "$ROOT/agentic/patch-src/src/vs/platform/agentHost/common":/patchsrc:ro \
		-v "$RUN":/run \
		-e PROBE_MODE="$1" \
		"$IMG" sh -c "MODE=baseline ENTRY=/harness/agent-registration-probe.ts OUT=/run/bundle-$1.mjs node /harness/bundle.mjs >/dev/null && node /run/bundle-$1.mjs" \
		> "$RUN/$1.json"
}

status=0
run_arm baseline "$SRC" || status=$?
[[ $status -eq 0 ]] || { echo "agent-registration: the BASELINE control did not report vulnerable; the probe is not evidence until it does" >&2; }
[[ $status -ne 0 ]] || run_arm gated "$GATED" || status=$?

rm -f "$RUN"/bundle-*.mjs
echo "agent-registration: $RUN (exit $status)"
[[ $status -eq 0 ]] && echo "agent-registration: baseline vulnerable, gated contained"
exit $status
