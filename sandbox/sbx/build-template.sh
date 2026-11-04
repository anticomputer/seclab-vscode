#!/usr/bin/env bash
# Build the sbx tab template: the sbx `shell` kit + our REH + in-sandbox scripts, saved
# with `sbx template save` (sbx's native snapshot mechanism). Runs on the host; uses only sbx.
# Usage: sandbox/sbx/build-template.sh [TAG]   (default seclab-tab:local)
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TAG="${1:-seclab-tab:local}"
ARCH="${ARCH:-arm64}"
REH_TGZ="$ROOT/.work/out/seclab-reh-linux-${ARCH}.tar.gz"
B=seclab-template-builder
[[ -f "$REH_TGZ" ]] || { echo "missing $REH_TGZ; run ./seclab build linux reh" >&2; exit 1; }
[[ "$TAG" =~ ^[a-z0-9][a-z0-9._/-]*:[a-zA-Z0-9._-]+$ ]] || { echo "bad tag" >&2; exit 2; }

sbx rm --force "$B" >/dev/null 2>&1 || true
sbx create --name "$B" --no-progress shell
trap 'sbx rm --force "$B" >/dev/null 2>&1 || true' EXIT

sbx cp "$REH_TGZ" "$B:/tmp/seclab-reh.tgz"
sbx cp "$ROOT/sandbox/rootfs/opt/seclab" "$B:/tmp/seclab-overlay"
sbx exec -u root "$B" sh -euc '
	rm -rf /opt/seclab-reh /opt/seclab
	mkdir -p /opt/seclab-reh
	tar -xzf /tmp/seclab-reh.tgz --strip-components=1 -C /opt/seclab-reh
	mv /tmp/seclab-overlay /opt/seclab
	chown -R root:root /opt/seclab-reh /opt/seclab
	chmod 0755 /opt/seclab/bin/*
	rm -f /tmp/seclab-reh.tgz
	# Defence in depth inside the VM: the tab user gets no sudo and no inner docker.
	gpasswd -d agent sudo >/dev/null 2>&1 || true
	gpasswd -d agent docker >/dev/null 2>&1 || true
	rm -f /etc/sudoers.d/agent* 2>/dev/null || true
	/opt/seclab-reh/node --version
'
sbx stop "$B" >/dev/null
sbx template save "$B" "$TAG"
echo "template: $TAG"
