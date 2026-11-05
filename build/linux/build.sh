#!/usr/bin/env bash
# Runs INSIDE the builder container. Builds the Linux desktop app and the matching
# REH server from the same prepared source.
#   /repo  : this repo (read-only bind mount)
#   /work  : named volume with the upstream checkout + node_modules (durable cache)
#   /out   : output (named volume or bind mount)
# Env: ARCH (arm64|x64; default from uname), TARGETS ("editor reh" default)
set -euo pipefail

ARCH="${ARCH:-$(uname -m | sed -e s/aarch64/arm64/ -e s/x86_64/x64/)}"
TARGETS="${TARGETS:-editor reh}"
SRC=/work/vscode

/repo/build/prepare.sh "$SRC"
cd "$SRC"
# `./seclab build` runs this once with PHASE=prepare locally, to export the lockfiles for the
# CFS fetch (EDR cfs-local-builds), then again to build.
[[ "${PHASE:-}" == prepare ]] && exit 0

want_node="$(cat .nvmrc)"
have_node="$(node --version | sed s/^v//)"
[[ "$want_node" == "$have_node" ]] || { echo "node $have_node != upstream .nvmrc $want_node; bump build/linux/Dockerfile" >&2; exit 1; }

export NODE_OPTIONS="--max-old-space-size=${MAX_OLD_SPACE_SIZE:-6144}"
export VSCODE_SKIP_NODE_VERSION_CHECK=1
# npm's content-addressed cache on the volume (EDR local-install-cache): entries are checked
# against the lockfile's integrity on extraction, and a reinstall needs fewer registry fetches.
export npm_config_cache=/work/.npm-cache
# Local builds (EDR cfs-local-builds): the cache was filled through GitHub CFS by a separate,
# token-holding fetch with no install scripts. Here, with no token, npm installs strictly from
# that cache: offline, with the same CFS registry rewrite so cache keys match, every tarball
# checked against the lockfile's integrity. Nested installs from upstream's postinstall inherit
# all of this. Registry signatures can't be audited through CFS, so the stamp says so.
audit=(/repo/build/npm-audit-signatures.sh)
stamp_kind=sig1
if [[ "${SECLAB_NPM_OFFLINE:-}" == 1 ]]; then
	export npm_config_offline=true npm_config_replace_registry_host=npmjs \
		npm_config_registry=https://pkgs.dev.azure.com/github-cfs/GitHubCFS/_packaging/github-cfs-oss/npm/registry/
	# Registry-origin check only: signatures can't be audited through CFS (review YY-1).
	audit=(/repo/build/npm-audit-signatures.sh --origin-only)
	stamp_kind=cfs1
	# Lockfiles whose upstream entries lack `integrity` get it filled in the fetch, so the offline
	# install finds them by hash. Each filled file is checked against the pristine upstream
	# lockfile at the same path first (lock-fill.mjs --verify; review YY-5): only `integrity` and
	# canonical `resolved` added to entries that lacked them. This tree is reset to pristine
	# upstream by prepare.sh on every build; nothing is committed.
	if [[ -d /work/.npm-locks-filled ]]; then
		while IFS= read -r -d '' f; do
			rel="${f#/work/.npm-locks-filled/}"
			[[ "$(basename "$rel")" == package-lock.json && -f "$SRC/$rel" && ! -L "$SRC/$rel" ]] || { echo "build: unexpected filled lockfile $rel" >&2; exit 1; }
			node /repo/build/linux/lock-fill.mjs --verify "$SRC/$rel" "$f"
			cp "$f" "$SRC/$rel"
		done < <(find /work/.npm-locks-filled -type f -print0)
	fi
fi
# Reinstall deps only when the lockfiles change (stamp keyed by their hash). The `sig1-` prefix
# makes trees installed before the signature check get audited once (TT-6); `cfs1-` marks a
# local install verified by lockfile integrity only.
# A failed install must not destroy a working one (EDR local-install-cache): every existing
# node_modules is kept aside in /work/.nm-prev (same volume, outside the tree fetch-upstream
# cleans) and moved back if the install, the ripgrep check or the signature audit fails.
KEEP=/work/.nm-prev
. /repo/build/linux/nm-keep.sh
# A previous run that died mid-install left the old install aside: put it back first.
if [[ -d "$KEEP" ]]; then
	echo "build: restoring the install kept aside by an interrupted run" >&2
	nm_restore "$SRC" "$KEEP"
fi
stamp="${stamp_kind}-$(cat package-lock.json build/package-lock.json remote/package-lock.json 2>/dev/null | sha256sum | cut -c1-16)"
if [[ ! -f node_modules/.seclab-stamp ]] || [[ "$(cat node_modules/.seclab-stamp)" != "$stamp" ]]; then
	nm_keep_aside "$SRC" "$KEEP"
	# Pinned prebuilt ripgrep in the postinstall's cache (a fresh private TMPDIR): no GitHub API
	# call, no unverified binary; the installed rg is checked against its pin afterwards (VV-5).
	TMPDIR="$(mktemp -d)"; export TMPDIR
	# Registry signatures over every installed project; the stamp is written only after it passes.
	if node /repo/build/seed-ripgrep.mjs "$SRC" && npm ci \
		&& node /repo/build/seed-ripgrep.mjs --verify-installed "$SRC" \
		&& "${audit[@]}" "$SRC"; then
		echo "$stamp" > node_modules/.seclab-stamp
		rm -rf "$KEEP"
	else
		echo "build: install failed; the previous install is restored unchanged" >&2
		nm_restore "$SRC" "$KEEP"
		exit 1
	fi
fi
# Every build, cached tree or not: the installed rg is the pinned binary.
node /repo/build/seed-ripgrep.mjs --verify-installed "$SRC"
/repo/build/remove-extensions.sh "$SRC"

for t in $TARGETS; do
	case "$t" in
		editor) npm run gulp "vscode-linux-${ARCH}-min"
			# The trusted app ships no agent runtime and no test hook (I8; check-release --desktop).
			sh /repo/build/check-release.sh --inner /work/.check-release desktop "/work/VSCode-linux-${ARCH}/resources/app"
			tar -C /work -czf "/out/seclab-vscode-linux-${ARCH}.tar.gz" "VSCode-linux-${ARCH}" ;;
		reh) npm run gulp "vscode-reh-linux-${ARCH}-min"
			tar -C /work -czf "/out/seclab-reh-linux-${ARCH}.tar.gz" "vscode-reh-linux-${ARCH}" ;;
		*) echo "unknown target $t" >&2; exit 2 ;;
	esac
done

. /repo/upstream.lock
printf '{"upstreamTag":"%s","upstreamSha":"%s","arch":"%s","targets":"%s"}\n' \
	"$UPSTREAM_TAG" "$UPSTREAM_SHA" "$ARCH" "$TARGETS" > /out/build-info.json
ls -la /out
