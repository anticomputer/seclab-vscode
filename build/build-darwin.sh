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
cd "$SRC"
export NODE_OPTIONS="--max-old-space-size=${MAX_OLD_SPACE_SIZE:-6144}"
# Pinned prebuilt ripgrep in the postinstall's cache: no GitHub API call, no unverified binary.
node "$ROOT/build/seed-ripgrep.mjs" "$SRC"
npm ci
"$ROOT/build/npm-audit-signatures.sh" "$SRC"
"$ROOT/build/remove-extensions.sh" "$SRC"
npm run gulp "vscode-darwin-${ARCH}-min"

APP_DIR="$(cd .. && pwd)/VSCode-darwin-${ARCH}"
app="$(find "$APP_DIR" -maxdepth 1 -name '*.app' -print -quit)"
[[ -n "$app" ]] || { echo "no .app in $APP_DIR" >&2; exit 1; }
# No test hooks in what ships (EDR patch-series). Hosted macOS runners have no docker, so
# check-release.sh runs its POSIX scan natively under CI.
CI="${CI:-1}" "$ROOT/build/check-release.sh" "$app/Contents/Resources/app"

mkdir -p "$OUT_DIR"
zip="$OUT_DIR/seclab-vscode-darwin-${ARCH}.zip"
ditto -c -k --sequesterRsrc --keepParent "$app" "$zip"
# shellcheck source=/dev/null
. "$ROOT/upstream.lock"
printf '{"upstreamTag":"%s","upstreamSha":"%s","arch":"%s","repoSha":"%s","runId":"%s"}\n' \
	"$UPSTREAM_TAG" "$UPSTREAM_SHA" "$ARCH" "${GITHUB_SHA:-}" "${GITHUB_RUN_ID:-}" > "$OUT_DIR/build-info.json"
(cd "$OUT_DIR" && shasum -a 256 "$(basename "$zip")" build-info.json > SHA256SUMS)
cat "$OUT_DIR/SHA256SUMS"
