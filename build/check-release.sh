#!/bin/sh
# Release-artifact check (EDR patch-series): a shipped build must contain no test hooks.
#   build/check-release.sh PATH...   (.app/Contents/Resources/app dir, a dir, or .tar.gz/.zip)
# Fails on:
#   - test-hook markers: SECLAB_TEST_ONLY / seclab-test-hook / rogue-reh / rogue-extension
#     (any code meant only for tests must carry SECLAB_TEST_ONLY so this finds it);
#   - environment-controlled module loading: require()/import() of a path taken from
#     process.env (a classic test hook that becomes a backdoor in a release);
#   - a path with no JS at all (wrong path = no check), or any scan error (fail closed).
# Locally it runs in a container (nothing on the host). On CI runners without docker
# (hosted macOS) it runs the same POSIX sh/find/grep logic natively.
set -eu

if [ "${1:-}" = "--inner" ]; then
	shift
	WORK="$1"; shift
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
		scan "SECLAB_TEST_ONLY|seclab-test-hook|rogue-reh|rogue-extension" "test-hook marker"
		scan "(require|import)\([[:space:]]*process\.env(\.[A-Za-z_]+|\[)[^)]{0,80}\)" "env-controlled module load"
	done < "$WORK/roots"
	[ "$bad" = 0 ] || exit 1
	echo "check-release: clean ($n)"
	exit 0
fi

[ $# -ge 1 ] || { echo "usage: check-release.sh PATH..." >&2; exit 2; }
SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
if ! command -v docker >/dev/null 2>&1 && [ -n "${CI:-}" ]; then
	W="$(cd "$(dirname "$SELF")/.." && pwd)/.work/check-release"
	rm -rf "$W"
	exec sh "$SELF" --inner "$W" "$@"
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
exec docker run --rm --network none -v "$SELF:/check-release.sh:ro" $mounts alpine:3.22 sh /check-release.sh --inner /x $args
