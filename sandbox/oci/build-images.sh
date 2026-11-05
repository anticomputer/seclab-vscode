#!/usr/bin/env bash
# Build the OCI tab images from the container-built REH: seclab-tab-oci:local, the tab broker
# seclab-broker:dev (broker/build.sh) and seclab-broker-placeholder:local (`--broker none`).
# Usage: sandbox/oci/build-images.sh
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ARCH="${ARCH:-$(uname -m | sed -e s/aarch64/arm64/ -e s/x86_64/x64/)}"
REH_TGZ="$ROOT/.work/out/seclab-reh-linux-${ARCH}.tar.gz"
CTX="$ROOT/.work/oci-ctx"
[[ -f "$REH_TGZ" ]] || { echo "missing $REH_TGZ; run ./seclab build linux reh" >&2; exit 1; }

rm -rf "$CTX" && mkdir -p "$CTX/reh"
tar -xzf "$REH_TGZ" --strip-components=1 -C "$CTX/reh"
cp -R "$ROOT/sandbox/rootfs/opt/seclab" "$CTX/seclab"
docker build -q -t seclab-tab-oci:local -f "$ROOT/sandbox/oci/Dockerfile.tab" "$CTX"
docker build -q -t seclab-broker-placeholder:local -f "$ROOT/sandbox/oci/Dockerfile.broker-placeholder" "$ROOT/sandbox/oci"
# The tab's broker (plan tabd-broker-wiring B1; OCI tabs use it by default). broker/build.sh
# verifies the base image's signed provenance first (online with gh locally; offline from
# downloaded bundles in CI) and fails closed.
"$ROOT/broker/build.sh" seclab-broker:dev
# The observability sensor OCI tabs need (ADR tab-observability): signature-verified, by digest.
mkdir -p "$ROOT/.work"
"$ROOT/sandbox/oci/verify-falco.sh"
# The pre-mount secret scanner tabd runs before any mount (built from pinned gitleaks source).
"$ROOT/build/tools/tool.sh" gitleaks >/dev/null
echo "images: seclab-tab-oci:local seclab-broker:dev seclab-broker-placeholder:local (+ verified Falco, gitleaks from source)"
