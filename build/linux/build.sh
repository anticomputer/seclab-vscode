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
# Reinstall deps only when the lockfiles change (stamp keyed by their hash). The `sig1-` prefix
# makes trees installed before the signature check get audited once (TT-6).
stamp="sig1-$(cat package-lock.json build/package-lock.json remote/package-lock.json 2>/dev/null | sha256sum | cut -c1-16)"
if [[ ! -f node_modules/.seclab-stamp ]] || [[ "$(cat node_modules/.seclab-stamp)" != "$stamp" ]]; then
	# Pinned prebuilt ripgrep in the postinstall's cache: no GitHub API call, no unverified binary.
	node /repo/build/seed-ripgrep.mjs "$SRC"
	npm ci
	# Registry signatures over every installed project; the stamp is written only after it passes.
	/repo/build/npm-audit-signatures.sh "$SRC"
	echo "$stamp" > node_modules/.seclab-stamp
fi
/repo/build/remove-extensions.sh "$SRC"

for t in $TARGETS; do
	case "$t" in
		editor) npm run gulp "vscode-linux-${ARCH}-min"
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
