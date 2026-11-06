#!/bin/sh
# Release-artifact check (EDR patch-series): a shipped build must contain no test hooks.
#   build/check-release.sh [--desktop] PATH...   (.app/Contents/Resources/app dir, a dir, or .tar.gz/.zip)
# Fails on:
#   - test-hook markers: SECLAB_TEST_ONLY / seclab-test-hook / rogue-reh / rogue-extension
#     (any code meant only for tests must carry SECLAB_TEST_ONLY so this finds it), and
#     `seclabTestBuild`, the positive marker every test build variant's product.json carries
#     (build/test-variant.sh; EDR test-build-variants);
#   - environment-controlled module loading: require()/import() of a path taken from
#     process.env (a classic test hook that becomes a backdoor in a release);
#   - a path with no JS at all (wrong path = no check), or any scan error (fail closed).
# --desktop (the trusted app, never the REH; invariant I8, EDR agent-runtimes-exception): also
# fails on any agent runtime, on disk or listed in an asar header (the Copilot SDK and its
# platform package, runtime.node, Codex, the Claude agent SDK), and on `agentSdks` in product.json.
# Locally it runs in a container (nothing on the host). On CI runners without docker
# (hosted macOS) it runs the same POSIX sh/find/grep logic natively.
set -eu

if [ "${1:-}" = "--inner" ]; then
	shift
	WORK="$1"; MODE="$2"; shift 2
	mkdir -p "$WORK"; : > "$WORK/roots"; n=0
	for p in "$@"; do
		n=$((n+1)); d="$WORK/$n"
		case "$p" in
			*.tar.gz|*.tgz) mkdir -p "$d"; tar -xzf "$p" -C "$d" ;;
			*.zip) mkdir -p "$d"; unzip -q "$p" -d "$d" ;;
			*) d="$p" ;;
		esac
		echo "$d" >> "$WORK/roots"
	done
	bad=0
	scan() { # $1 = ERE, $2 = label; grep exit 1 = no match, >1 = error (fail closed)
		set +e
		# -a: a NUL byte must not hide a file. JS/JSON plus shell launchers (bin/, *.sh).
		out=$(find "$d" -type f \( -name "*.js" -o -name "*.mjs" -o -name "*.cjs" -o -name "*.json" -o -name "*.sh" -o -path "*/bin/*" \) -exec grep -HaoE "$1" {} + 2>&1)
		rc=$?
		set -e
		if [ "$rc" -gt 1 ]; then echo "check-release: scan error ($2): $(echo "$out" | head -3)"; bad=1; return 0; fi
		[ -z "$out" ] || { echo "check-release: $2:"; echo "$out" | head -20; bad=1; }
	}
	while IFS= read -r d; do
		[ -n "$(find "$d" -type f -name "*.js" | head -1)" ] || { echo "check-release: no JS files under $d (wrong path?)"; bad=1; }
		scan "SECLAB_TEST_ONLY|seclab-test-hook|rogue-reh|rogue-extension|seclabTestBuild" "test-hook marker"
		scan "(require|import)\([[:space:]]*process\.env(\.[A-Za-z_]+|\[)[^)]{0,80}\)" "env-controlled module load"
		if [ "$MODE" = desktop ]; then
			set +e
			out=$(find "$d" \( -path "*/@github/copilot*" -o -path "*copilot-shim*" -o -name copilot -o -name runtime.node -o -name "copilot-runtime*" -o -path "*/@openai/codex*" -o -name codex -o -name "codex-*" -o -path "*claude-agent-sdk*" -o -path "*/@anthropic-ai/claude-code*" -o -name "*agent-sdk*" -o -name "*agent-runtime*" -o -name "*agentsdk*" \) -print 2>&1)
			rc=$?
			hdr=$(find "$d" -type f -name "*.asar" -exec grep -HaoE '"(copilot|copilot-shim|copilot-sdk[^"]*|copilot-runtime[^"]*|claude-agent-sdk[^"]*|claude-code|codex|codex-[^"]*|runtime\.node|[^"]*agent-?(sdk|runtime)[^"]*)":\{' {} + 2>&1)
			hrc=$?
			prod=$(find "$d" -type f -name product.json -exec grep -lE '"agentSdks"[[:space:]]*:' {} + 2>&1)
			prc=$?
			set -e
			if [ "$rc" -ne 0 ] || [ "$hrc" -gt 1 ] || [ "$prc" -gt 1 ]; then echo "check-release: scan error (agent runtime)"; bad=1; fi
			[ -z "$out" ] || { echo "check-release: agent runtime in the desktop app (I8):"; echo "$out" | head -20; bad=1; }
			[ -z "$hdr" ] || { echo "check-release: agent runtime listed in an asar (I8):"; echo "$hdr" | sort -u | head -20; bad=1; }
			[ -z "$prod" ] || { echo "check-release: product.json has agentSdks (runtime download path):"; echo "$prod"; bad=1; }
		fi
	done < "$WORK/roots"
	[ "$bad" = 0 ] || exit 1
	echo "check-release: clean ($n)"
	exit 0
fi

MODE=release
if [ "${1:-}" = "--desktop" ]; then MODE=desktop; shift; fi
[ $# -ge 1 ] || { echo "usage: check-release.sh [--desktop] PATH..." >&2; exit 2; }
SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
if ! command -v docker >/dev/null 2>&1 && [ -n "${CI:-}" ]; then
	W="$(cd "$(dirname "$SELF")/.." && pwd)/.work/check-release"
	rm -rf "$W"
	exec sh "$SELF" --inner "$W" "$MODE" "$@"
fi
set --  "$@"
mounts=""; args=""; i=0
for p in "$@"; do
	abs="$(cd "$(dirname "$p")" && pwd)/$(basename "$p")"
	[ -e "$abs" ] || { echo "check-release: no such path: $p" >&2; exit 2; }
	mounts="$mounts -v $abs:/in/$i/$(basename "$abs"):ro"
	args="$args /in/$i/$(basename "$abs")"
	i=$((i+1))
done
# shellcheck disable=SC2086 # paths are repo/build paths without spaces; split on purpose
exec docker run --rm --network none -v "$SELF:/check-release.sh:ro" $mounts alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f sh /check-release.sh --inner /x "$MODE" $args
