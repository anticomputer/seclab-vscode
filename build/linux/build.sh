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

want_node="$(cat .nvmrc)"
have_node="$(node --version | sed s/^v//)"
[[ "$want_node" == "$have_node" ]] || { echo "node $have_node != upstream .nvmrc $want_node; bump build/linux/Dockerfile" >&2; exit 1; }

export NODE_OPTIONS="--max-old-space-size=${MAX_OLD_SPACE_SIZE:-6144}"
export VSCODE_SKIP_NODE_VERSION_CHECK=1
# npm's content-addressed cache on the volume (EDR local-install-cache): entries are checked
# against the lockfile's integrity on extraction, and a reinstall needs fewer registry fetches.
export npm_config_cache=/work/.npm-cache
# Reinstall deps only when the lockfiles change (stamp keyed by their hash). The `sig1-` prefix
# makes trees installed before the signature check get audited once (TT-6).
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
stamp="sig1-$(cat package-lock.json build/package-lock.json remote/package-lock.json 2>/dev/null | sha256sum | cut -c1-16)"
if [[ ! -f node_modules/.seclab-stamp ]] || [[ "$(cat node_modules/.seclab-stamp)" != "$stamp" ]]; then
	nm_keep_aside "$SRC" "$KEEP"
	# Pinned prebuilt ripgrep in the postinstall's cache (a fresh private TMPDIR): no GitHub API
	# call, no unverified binary; the installed rg is checked against its pin afterwards (VV-5).
	TMPDIR="$(mktemp -d)"; export TMPDIR
	# Registry signatures over every installed project; the stamp is written only after it passes.
	if node /repo/build/seed-ripgrep.mjs "$SRC" && npm ci \
		&& node /repo/build/seed-ripgrep.mjs --verify-installed "$SRC" \
		&& /repo/build/npm-audit-signatures.sh "$SRC"; then
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
