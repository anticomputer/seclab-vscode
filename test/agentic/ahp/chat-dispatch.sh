#!/usr/bin/env bash
# Chat dispatch in a tab window, through the real ChatService, in three trees. No editor, no
# window, no network.
#
#   test/agentic/ahp/chat-dispatch.sh
#
# Each tree has its own expectation, and all three must hold:
#   gated     the patch series: sendRequest refused by 0009; resend and the queue drain refuse
#             every foreign session, by 0018, with the reason in the gate log
#   upstream  pristine upstream, the control for 0009: sendRequest in a tab window dispatches
#   no-0018   the series without 0018, the control for 0018: sendRequest is refused (0009), and
#             resend and the drain dispatch
# A control that stops failing makes the gated result meaningless, so a control that passes the
# wrong way fails the run exactly as a gated regression does. Every tree must also dispatch in an
# ordinary window, or a refusal could be a harness that never runs an agent.
#
# Needs: the pinned source at .work/vscode (build/fetch-upstream.sh .work/vscode) and the
# builder volume seclab-vscode-work (read-only: esbuild and node_modules).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SRC="$ROOT/.work/vscode"
TREES="$ROOT/.work/agentic/chat-dispatch"
IMG='node:24.22.1-trixie@sha256:f1e034976f948cf212ef1f659c12e5dd58ac7eab947831813e81a62401ca38be'
. "$ROOT/upstream.lock"
. "$ROOT/test/agentic/ahp/derive-tree.sh"

[[ "$(git -C "$SRC" rev-parse HEAD)" == "$UPSTREAM_SHA" ]] || { echo "chat-dispatch: $SRC is not at $UPSTREAM_SHA" >&2; exit 2; }
[[ -z "$(git -C "$SRC" status --porcelain -- src)" ]] || { echo "chat-dispatch: $SRC/src is modified; the upstream control must be pristine" >&2; exit 2; }

NONCE="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
RUN="$ROOT/.work/agentic/chat-dispatch-runs/$(date -u +%Y%m%dT%H%M%SZ)-$NONCE"
mkdir -p "$RUN" "$TREES"

derive_tree "$TREES/gated"
derive_tree "$TREES/no-0018" '^0018-'

run_tree() { # tree, source dir, expectation
	docker run --rm --network none -u "$(id -u):$(id -g)" \
		-v seclab-vscode-work:/shared:ro \
		-v "$2":/src:ro \
		-v "$ROOT/test/agentic/ahp":/harness:ro \
		-v "$RUN":/run \
		-e PROBE_TREE="$1" -e PROBE_EXPECT="$3" \
		"$IMG" sh -c "MODE=baseline ENTRY=/harness/chat-dispatch-probe.ts OUT=/run/bundle-$1.mjs node /harness/bundle.mjs >/dev/null && node /run/bundle-$1.mjs" \
		> "$RUN/$1.expect-$3.json"
}

# Each baseline twice: once with its own expectation (the control dispatches where its patch is
# missing), and once with the GATED assertions, which must fail there exactly as predicted.
status=0
for run in upstream:upstream upstream:gated no-0018:no-0018 no-0018:gated gated:gated; do
	tree="${run%%:*}" expect="${run#*:}"
	src="$TREES/$tree"; [[ $tree == upstream ]] && src="$SRC"
	if run_tree "$tree" "$src" "$expect"; then
		echo "chat-dispatch: $tree with the $expect expectation: ok"
	else
		echo "chat-dispatch: $tree with the $expect expectation: FAILED (see $RUN/$tree.expect-$expect.json)" >&2
		status=1
	fi
done

rm -f "$RUN"/bundle-*.mjs
echo "chat-dispatch: $RUN (exit $status)"
[[ $status -eq 0 ]] && echo "chat-dispatch: both controls dispatch where their patch is missing, the gated assertions fail on both exactly as predicted, and the series refuses every path"
exit $status
