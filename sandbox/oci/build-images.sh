#!/usr/bin/env bash
# Build the OCI tab images from the container-built REH: seclab-tab-oci:local, the tab broker
# seclab-broker:dev (broker/build.sh) and seclab-broker-placeholder:local (`--broker none`).
# Usage: sandbox/oci/build-images.sh [--test-variant VARIANT]
#   --test-variant: the tab image only, from a test build variant's REH (.work/test-builds/,
#   `./seclab fetch macos-VARIANT` or `SECLAB_TEST_VARIANT=VARIANT ./seclab build linux reh`),
#   tagged seclab-tab-oci:test-VARIANT; never :local (EDR test-build-variants).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ARCH="${ARCH:-$(uname -m | sed -e s/aarch64/arm64/ -e s/x86_64/x64/)}"
VARIANT=""
if [[ "${1:-}" == --test-variant ]]; then
	VARIANT="${2:-}"
	[[ "$VARIANT" =~ ^[a-z][a-z0-9-]{0,31}$ ]] || { echo "usage: build-images.sh --test-variant VARIANT" >&2; exit 2; }
fi
REH_TGZ="$ROOT/.work/out/seclab-reh-linux-${ARCH}.tar.gz"
TAG=seclab-tab-oci:local
[[ -z "$VARIANT" ]] || { REH_TGZ="$ROOT/.work/test-builds/$VARIANT/seclab-reh-linux-${ARCH}-test-${VARIANT}.tar.gz"; TAG="seclab-tab-oci:test-$VARIANT"; }
CTX="$ROOT/.work/oci-ctx${VARIANT:+-test-$VARIANT}"
[[ -f "$REH_TGZ" ]] || { echo "missing $REH_TGZ; run ./seclab build linux reh" >&2; exit 1; }

rm -rf "$CTX" && mkdir -p "$CTX/reh"
tar -xzf "$REH_TGZ" --strip-components=1 -C "$CTX/reh"
# The REH's own record decides: a test build only ever under its test tag, and only its own.
got="$(jq -r '.seclabTestBuild.variant // ""' "$CTX/reh/product.json")"
[[ "$got" == "$VARIANT" ]] || { echo "refusing: $REH_TGZ is ${got:+test build '$got'}${got:-a release REH}, building $TAG" >&2; exit 1; }
cp -R "$ROOT/sandbox/rootfs/opt/seclab" "$CTX/seclab"
docker build -q -t "$TAG" -f "$ROOT/sandbox/oci/Dockerfile.tab" "$CTX"
if [[ -n "$VARIANT" ]]; then
	echo "images: $TAG (UNSAFE test build; tabd --image $TAG)"
	exit 0
fi
docker build -q -t seclab-broker-placeholder:local -f "$ROOT/sandbox/oci/Dockerfile.broker-placeholder" "$ROOT/sandbox/oci"
# The tab's broker (plan tabd-broker-wiring B1; OCI tabs use it by default). broker/build.sh
# verifies the base image's signed provenance first (online with gh locally; offline from
# downloaded bundles in CI) and fails closed. Its one stdout line is the image identity; tabd
# resolves the tag to that ID, checks the labels and creates brokers by ID (review XX-6).
mkdir -p "$ROOT/.work"
"$ROOT/broker/build.sh" seclab-broker:dev > "$ROOT/.work/broker-image.json"
echo "broker: $(cat "$ROOT/.work/broker-image.json")"
# The observability sensor OCI tabs need (ADR tab-observability): signature-verified, by digest.
"$ROOT/sandbox/oci/verify-falco.sh"
# The pre-mount secret scanner tabd runs before any mount (built from pinned gitleaks source).
"$ROOT/build/tools/tool.sh" gitleaks >/dev/null
echo "images: seclab-tab-oci:local seclab-broker:dev seclab-broker-placeholder:local (+ verified Falco, gitleaks from source)"
