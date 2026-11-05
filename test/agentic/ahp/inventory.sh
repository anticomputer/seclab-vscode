#!/usr/bin/env bash
# Class (f) draft inventory: the Agent Host Protocol surface (plan §3.3). Imports the
# RPC-lockdown generator's string-aware stripper from that branch, read-only, never a
# copy. Network-less container; writes .work/agentic/ahp-inventory.json.
#
#   test/agentic/ahp/inventory.sh [--self-test]
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
RPC_REF="${RPC_REF:-5104309}"   # anticomputer-rpc-filter-patches; stripper fixed at 8d92392
IMG='python:3.12-slim@sha256:b18b261e1b4974b4f321451ad5251ded85abb22c2b8b262da527dda1d031ab30'
TOOLS="$ROOT/.work/agentic/rpc-tools-$RPC_REF"
if [[ ! -d "$TOOLS" ]]; then
	mkdir -p "$TOOLS"
	git -C "$ROOT" archive "$RPC_REF" rpc-filter/tools/seclab_inventory | tar -x -C "$TOOLS"
fi
mkdir -p "$ROOT/.work/agentic/selftest"
ARGS=(--source /src --out /out/ahp-inventory.json)
[[ "${1:-}" == "--self-test" ]] && ARGS=(--self-test)
docker run --rm --network none -u "$(id -u):$(id -g)" \
	-v "$ROOT/.work/vscode":/src:ro \
	-v "$TOOLS/rpc-filter/tools":/rpc:ro \
	-v "$ROOT/test/agentic/ahp":/harness:ro \
	-v "$ROOT/.work/agentic":/out \
	-e PYTHONPATH=/rpc -e SELFTEST_DIR=/out/selftest -e PYTHONDONTWRITEBYTECODE=1 \
	"$IMG" python3 /harness/ahp_inventory.py "${ARGS[@]}"
