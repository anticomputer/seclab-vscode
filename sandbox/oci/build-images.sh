#!/usr/bin/env bash
# Build the OCI tab images from the container-built REH: seclab-tab-oci:local and
# seclab-broker-placeholder:local. Usage: sandbox/oci/build-images.sh
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
echo "images: seclab-tab-oci:local seclab-broker-placeholder:local"
