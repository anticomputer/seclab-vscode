#!/usr/bin/env bash
# Build the OCI tab images from the container-built REH: seclab-tab-oci:local, the tab broker
# seclab-broker:dev (broker/build.sh) and seclab-broker-placeholder:local (`--broker none`).
# Usage: sandbox/oci/build-images.sh [--test-variant VARIANT | --tag b-NAME]
#   --test-variant: the tab image only, from a test build variant's REH (.work/test-builds/,
#   `./seclab fetch macos-VARIANT` or `SECLAB_TEST_VARIANT=VARIANT ./seclab build linux reh`),
#   tagged seclab-tab-oci:test-VARIANT; never :local (EDR test-build-variants).
#   --tag b-NAME: the tab image only, from this worktree's release REH, tagged
#   seclab-tab-oci:b-NAME, so a proof build (an upstream bump, say) never swaps the shared :local
#   tag under other sessions. Harnesses take it through SECLAB_TAB_IMAGE.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ARCH="${ARCH:-$(uname -m | sed -e s/aarch64/arm64/ -e s/x86_64/x64/)}"
VARIANT=""
PERBUILD=""
if [[ "${1:-}" == --test-variant ]]; then
	VARIANT="${2:-}"
	[[ "$VARIANT" =~ ^[a-z][a-z0-9-]{0,31}$ ]] || { echo "usage: build-images.sh --test-variant VARIANT" >&2; exit 2; }
elif [[ "${1:-}" == --tag ]]; then
	PERBUILD="${2:-}"
	[[ "$PERBUILD" =~ ^b-[a-z0-9][a-z0-9.-]{0,40}$ ]] || { echo "usage: build-images.sh --tag b-NAME (lowercase letters, digits, . and -)" >&2; exit 2; }
fi
REH_TGZ="$ROOT/.work/out/seclab-reh-linux-${ARCH}.tar.gz"
TAG=seclab-tab-oci:local
[[ -z "$VARIANT" ]] || { REH_TGZ="$ROOT/.work/test-builds/$VARIANT/seclab-reh-linux-${ARCH}-test-${VARIANT}.tar.gz"; TAG="seclab-tab-oci:test-$VARIANT"; }
[[ -z "$PERBUILD" ]] || TAG="seclab-tab-oci:$PERBUILD"
CTX="$ROOT/.work/oci-ctx${VARIANT:+-test-$VARIANT}${PERBUILD:+-$PERBUILD}"
[[ -f "$REH_TGZ" ]] || { echo "missing $REH_TGZ; run ./seclab build linux reh" >&2; exit 1; }
if [[ -n "$VARIANT" ]]; then
	# The fetched REH is the commit under test, as its app is (EDR fetched-app-binding, review FAB-8):
	# SECLAB_APP_SHA when set, else this checkout's HEAD.
	info="$ROOT/.work/test-builds/$VARIANT/build-info-test-$VARIANT.json"
	for v in $(compgen -e); do [[ "$v" == GIT_* ]] && unset "$v"; done
	want="${SECLAB_APP_SHA:-$(git -C "$ROOT" rev-parse HEAD)}"
	[[ -f "$info" && ! -L "$info" ]] && [[ "$want" =~ ^[0-9a-f]{40}$ ]] \
		&& jq -e --arg w "$want" '.repoSha == $w' "$info" >/dev/null \
		|| { echo "refusing: $info doesn't record $want (fetch the build of the commit under test, or set SECLAB_APP_SHA)" >&2; exit 1; }
fi

rm -rf "$CTX" && mkdir -p "$CTX/reh"
tar -xzf "$REH_TGZ" --strip-components=1 -C "$CTX/reh"
# The REH's own record decides: a test build only ever under its test tag, and only its own.
got="$(jq -r '.seclabTestBuild.variant // ""' "$CTX/reh/product.json")"
if [[ "$got" != "$VARIANT" ]]; then
	what="a release REH"; [[ -z "$got" ]] || what="test build '$got'"
	echo "refusing: $REH_TGZ is $what, building $TAG" >&2; exit 1
fi
cp -R "$ROOT/sandbox/rootfs/opt/seclab" "$CTX/seclab"
if [[ -n "$PERBUILD" ]]; then
	# The tag's lease for clean-host, written before the tag exists so a concurrent clean-host
	# never sees it unleased (Copilot review on PR 25): a cached build reuses an older image, so its
	# creation time isn't when this proof tag was made.
	lease="$(git -C "$ROOT" rev-parse --path-format=absolute --git-common-dir)/seclab-image-leases"
	# Separate commands: under set -e a failing `mkdir` in an && list wouldn't stop the build.
	mkdir -p "$lease"
	# One lock per tag, shared with clean-host: held from the lease until the tag is published, so a
	# cleanup that decided earlier can't delete the tag this build renews (Copilot review on PR 25).
	# Only its holder ever removes it: breaking a "stale" lock races another contender's fresh one.
	# Locks have a directory of their own: a lease and a lock never share a name (Copilot review
	# on PR 25: a tag ending in .lock would otherwise lease another tag's lock path).
	mkdir -p "$lease/locks"
	lock="$lease/locks/$TAG" got=0
	for _ in $(seq 1 600); do
		if mkdir "$lock" 2>/dev/null; then got=1; break; fi
		sleep 1
	done
	[[ $got = 1 ]] || { echo "$TAG: its lease lock $lock is still held after 10 minutes (another build, clean-host, or a crashed build: once none runs, rmdir it)" >&2; exit 1; }
	trap 'rmdir "$lock" 2>/dev/null || true' EXIT
	date +%s > "$lease/$TAG"
fi
docker build -q -t "$TAG" -f "$ROOT/sandbox/oci/Dockerfile.tab" "$CTX"
[[ -z "$PERBUILD" ]] || { rmdir "$lock"; trap - EXIT; }
if [[ -n "$VARIANT" ]]; then
	echo "images: $TAG (UNSAFE test build; tabd --image $TAG)"
	exit 0
fi
if [[ -n "$PERBUILD" ]]; then
	echo "images: $TAG (SECLAB_TAB_IMAGE=$TAG; the broker images are shared and unchanged)"
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
