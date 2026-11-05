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

# Observability (ADR tab-observability): strace from a pinned deb. sbx's global policy blocks
# deb.debian.org inside sandboxes, so apt runs in the pinned debian image and the deb is
# checked against sandbox/sbx/obs-debs.lock before it is copied in.
LOCK="$ROOT/sandbox/sbx/obs-debs.lock"
DEB_IMAGE="$(awk '$1=="image"{print $2}' "$LOCK")"
STRACE_DEB="$(awk -v a="_${ARCH}.deb" '$1=="deb" && index($2,a){print $2}' "$LOCK")"
STRACE_SHA="$(awk -v d="$STRACE_DEB" '$1=="deb" && $2==d{print $3}' "$LOCK")"
[[ -n "$STRACE_DEB" && "$STRACE_SHA" =~ ^[0-9a-f]{64}$ && "$DEB_IMAGE" == *@sha256:* ]] || { echo "bad $LOCK" >&2; exit 2; }
DEBS="$ROOT/.work/obs-debs"
mkdir -p "$DEBS"
if [[ ! -f "$DEBS/$STRACE_DEB" ]]; then
	docker run --rm --platform "linux/$ARCH" -v "$DEBS:/out" "$DEB_IMAGE" \
		sh -euc 'apt-get -qq update >/dev/null; cd /out; apt-get -qq download "$1"' sh "${STRACE_DEB%%_*}=$(echo "$STRACE_DEB" | cut -d_ -f2)"
fi
echo "$STRACE_SHA  $DEBS/$STRACE_DEB" | shasum -a 256 -c - >/dev/null || { echo "checksum mismatch: $STRACE_DEB" >&2; exit 1; }

# Write-back gate (ADR write-back-gate): fuse-overlayfs and its libfuse, same route as strace,
# every deb checked against sandbox/sbx/wb-debs.lock before it is copied in.
WB_LOCK="$ROOT/sandbox/sbx/wb-debs.lock"
WB_IMAGE="$(awk '$1=="image"{print $2}' "$WB_LOCK")"
[[ "$WB_IMAGE" == *@sha256:* ]] || { echo "bad $WB_LOCK" >&2; exit 2; }
WB_DEBS="$ROOT/.work/wb-debs/$ARCH"
mkdir -p "$WB_DEBS"
rm -f "$WB_DEBS"/*.deb.ok
while read -r kind deb sha; do
	[[ "$kind" == deb && "$deb" == *"_${ARCH}.deb" ]] || continue
	[[ "$sha" =~ ^[0-9a-f]{64}$ && "$deb" =~ ^[a-z0-9.+-]+_[A-Za-z0-9.+:~-]+_[a-z0-9]+\.deb$ ]] || { echo "bad $WB_LOCK line: $deb" >&2; exit 2; }
	if [[ ! -f "$WB_DEBS/$deb" ]]; then
		docker run --rm --platform "linux/$ARCH" -v "$WB_DEBS:/out" "$WB_IMAGE" \
			sh -euc 'apt-get -qq update >/dev/null; cd /out; apt-get -qq download "$1"' sh "${deb%%_*}=$(echo "$deb" | cut -d_ -f2)"
	fi
	echo "$sha  $WB_DEBS/$deb" | shasum -a 256 -c - >/dev/null || { echo "checksum mismatch: $deb" >&2; exit 1; }
	: > "$WB_DEBS/$deb.ok"
done < "$WB_LOCK"
[[ "$(ls "$WB_DEBS"/*.deb.ok 2>/dev/null | wc -l)" -eq 2 ]] || { echo "expected 2 write-back debs for $ARCH in $WB_LOCK" >&2; exit 2; }

sbx rm --force "$B" >/dev/null 2>&1 || true
sbx create --name "$B" --no-progress shell
trap 'sbx rm --force "$B" >/dev/null 2>&1 || true' EXIT

sbx cp "$REH_TGZ" "$B:/tmp/seclab-reh.tgz"
sbx cp "$ROOT/sandbox/rootfs/opt/seclab" "$B:/tmp/seclab-overlay"
sbx cp "$DEBS/$STRACE_DEB" "$B:/tmp/strace.deb"
mkdir -p "$ROOT/.work/wb-debs/stage-$ARCH" && rm -f "$ROOT/.work/wb-debs/stage-$ARCH"/*.deb
for f in "$WB_DEBS"/*.deb.ok; do cp "${f%.ok}" "$ROOT/.work/wb-debs/stage-$ARCH/"; done
sbx cp "$ROOT/.work/wb-debs/stage-$ARCH" "$B:/tmp/wb-debs"
sbx cp "$ROOT/sandbox/sbx/seclab-obs-guard.c" "$B:/tmp/seclab-obs-guard.c"
sbx exec -u root "$B" sh -euc '
	rm -rf /opt/seclab-reh /opt/seclab
	mkdir -p /opt/seclab-reh
	tar -xzf /tmp/seclab-reh.tgz --strip-components=1 -C /opt/seclab-reh
	mv /tmp/seclab-overlay /opt/seclab
	# Observability: strace, the seccomp guard, and the relay uid (ADR tab-observability).
	dpkg -i /tmp/strace.deb >/dev/null
	# Write-back gate overlay (ADR write-back-gate): root mounts it with the mount syscall, so
	# no fuse3 (setuid fusermount3) and no `mount` package; nothing setuid is added.
	dpkg -i --ignore-depends=fuse3 /tmp/wb-debs/*.deb >/dev/null
	# Keep apt from ever pulling fuse3 (setuid fusermount3) in to satisfy the ignored dependency;
	# seclab-wb-mount also refuses at run time if a setuid fusermount appears (JJ-5).
	apt-mark hold fuse-overlayfs libfuse3-4 >/dev/null
	mkdir -p /var/lib/seclab/wb && chmod 0700 /var/lib/seclab /var/lib/seclab/wb
	gcc -O2 -Wall -Werror -o /opt/seclab/bin/seclab-obs-guard /tmp/seclab-obs-guard.c
	# Fixed ids: tabd runs the relay as exactly 990:990 (a bare uid would pick up gid 999 = docker).
	getent group 990 >/dev/null || groupadd --system -g 990 seclab-relay
	id seclab-relay >/dev/null 2>&1 || useradd --system -u 990 -g 990 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin seclab-relay
	[ "$(id -u seclab-relay):$(id -g seclab-relay):$(id -G seclab-relay)" = "990:990:990" ]
	chown -R root:root /opt/seclab-reh /opt/seclab
	chmod 0755 /opt/seclab/bin/*
	rm -rf /tmp/seclab-reh.tgz /tmp/strace.deb /tmp/seclab-obs-guard.c /tmp/wb-debs
	# Defence in depth inside the VM: the tab user gets no sudo and no inner docker.
	gpasswd -d agent sudo >/dev/null 2>&1 || true
	gpasswd -d agent docker >/dev/null 2>&1 || true
	rm -f /etc/sudoers.d/agent* 2>/dev/null || true
	/opt/seclab-reh/node --version
	strace -V | head -1
	fuse-overlayfs --version 2>/dev/null | head -1
	[ ! -e /usr/bin/fusermount3 ]
	python3 -I -c "import ctypes, json, select"
'
sbx stop "$B" >/dev/null
sbx template save "$B" "$TAG"
echo "template: $TAG"
