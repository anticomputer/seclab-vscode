#!/usr/bin/env bash
# Build the unsigned darwin app on a macOS host (GitHub Actions runner only;
# never run on a developer Mac - host hygiene). Output: $OUT_DIR/*.zip + checksums.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCH="${ARCH:-arm64}"
SRC="${SRC:-$ROOT/vscode}"
OUT_DIR="${OUT_DIR:-$ROOT/.work/out}"

[[ "${GITHUB_ACTIONS:-}" == "true" ]] || { echo "refusing: macOS builds run on GitHub Actions only (see AGENTS.md)" >&2; exit 1; }

"$ROOT/build/prepare.sh" "$SRC"
# A test build variant (EDR test-build-variants): the series plus its reviewed test-only hooks,
# under an unmistakable identity. Never released; check-release fails it (verified below).
VARIANT="${SECLAB_TEST_VARIANT:-}"
[[ -z "$VARIANT" ]] || "$ROOT/build/test-variant.sh" apply "$VARIANT" desktop "$SRC"
cd "$SRC"
export NODE_OPTIONS="--max-old-space-size=${MAX_OLD_SPACE_SIZE:-6144}"
# Pinned prebuilt ripgrep in the postinstall's cache (a fresh private TMPDIR): no GitHub API call,
# no unverified binary; the installed rg is checked against its pin afterwards (VV-5).
TMPDIR="$(mktemp -d)"; export TMPDIR
node "$ROOT/build/seed-ripgrep.mjs" "$SRC"
npm ci
node "$ROOT/build/seed-ripgrep.mjs" --verify-installed "$SRC"
"$ROOT/build/npm-audit-signatures.sh" "$SRC"
"$ROOT/build/remove-extensions.sh" "$SRC"
npm run gulp "vscode-darwin-${ARCH}-min"

APP_DIR="$(cd .. && pwd)/VSCode-darwin-${ARCH}"
app="$(find "$APP_DIR" -maxdepth 1 -name '*.app' -print -quit)"
[[ -n "$app" ]] || { echo "no .app in $APP_DIR" >&2; exit 1; }
# No test hooks in what ships (EDR patch-series), and no agent runtime anywhere in the bundle
# (I8; --desktop scans the whole .app, not only Resources/app). Hosted macOS runners have no
# docker, so check-release.sh runs its POSIX scan natively under CI.
CI="${CI:-1}"; export CI
if [[ -z "$VARIANT" ]]; then
	"$ROOT/build/check-release.sh" --desktop "$app"
else
	# Every hook is in the bundle, the bundle records them, and check-release refuses it on the
	# test markers alone (no agent runtime: the I8 scan still runs and must find nothing).
	"$ROOT/build/test-variant.sh" verify "$VARIANT" desktop "$app"
fi

mkdir -p "$OUT_DIR"
zip="$OUT_DIR/seclab-vscode-darwin-${ARCH}.zip"
[[ -z "$VARIANT" ]] || zip="$OUT_DIR/seclab-vscode-TEST-${VARIANT}-darwin-${ARCH}.zip"
ditto -c -k --sequesterRsrc --keepParent "$app" "$zip"
# shellcheck source=/dev/null
. "$ROOT/upstream.lock"
test_build=null
[[ -z "$VARIANT" ]] || test_build="$("$ROOT/build/test-variant.sh" record "$VARIANT" desktop)"
jq -nc --arg t "$UPSTREAM_TAG" --arg u "$UPSTREAM_SHA" --arg a "$ARCH" --arg r "${GITHUB_SHA:-}" --arg i "${GITHUB_RUN_ID:-}" --argjson tb "$test_build" \
	'{upstreamTag: $t, upstreamSha: $u, arch: $a, repoSha: $r, runId: $i} + (if $tb == null then {} else {testBuild: $tb} end)' > "$OUT_DIR/build-info.json"
(cd "$OUT_DIR" && shasum -a 256 "$(basename "$zip")" build-info.json > SHA256SUMS)
cat "$OUT_DIR/SHA256SUMS"
