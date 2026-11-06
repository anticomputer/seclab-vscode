#!/usr/bin/env bash
# Apply the patch queue: exactly what patches/series lists, in that order (EDR
# patch-series). Any other file in patches/ fails, so a test-only patch can't ship by
# being dropped in the directory. Any apply failure aborts.
#   build/apply-patches.sh DEST       apply to the checkout at DEST
#   build/apply-patches.sh --check    validate patches/ against the series only (CI)
# Works with bash 3.2 (macOS runners).
set -euo pipefail

PATCHES="${SECLAB_PATCHES_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/patches}"
DEST="${1:?usage: apply-patches.sh DEST|--check}"

listed=""
while IFS= read -r line || [ -n "$line" ]; do
	line="${line%%#*}"
	line="$(printf '%s' "$line" | tr -d '[:space:]')"
	[ -n "$line" ] || continue
	case "$line" in
		[0-9][0-9][0-9][0-9]-*.patch) ;;
		*) echo "apply-patches: bad entry in patches/series: $line" >&2; exit 1 ;;
	esac
	case " $listed " in *" $line "*) echo "apply-patches: duplicate entry in patches/series: $line" >&2; exit 1 ;; esac
	[ -f "$PATCHES/$line" ] || { echo "apply-patches: patches/series lists a missing patch: $line" >&2; exit 1; }
	listed="$listed $line"
done < "$PATCHES/series"
[ -n "$listed" ] || { echo "apply-patches: patches/series is empty" >&2; exit 1; }

for f in "$PATCHES"/* "$PATCHES"/.[!.]*; do
	[ -e "$f" ] || [ -L "$f" ] || continue
	name="$(basename "$f")"
	case "$name" in README.md|series|reach.json|unreachable.json|sole-consumer.json) continue ;; esac
	case " $listed " in
		*" $name "*) [ -f "$f" ] && [ ! -L "$f" ] || { echo "apply-patches: patches/$name is not a regular file" >&2; exit 1; } ;;
		*) echo "apply-patches: patches/$name is not in patches/series (refusing to build)" >&2; exit 1 ;;
	esac
done

if [ "$DEST" = "--check" ]; then
	# Every listed patch must be a patch git can read. Checking only that the
	# file exists is not the same question, and the difference is not academic:
	# a hand-edited hunk header shipped a corrupt 0007 past this gate, past
	# every unit test and past the local drift check, because nothing between
	# the edit and the 60-minute patch-build ever tried to parse it.
	#
	# --check needs no upstream tree, so this stays cheap enough to run in the
	# fast unit job. Structural errors (bad hunk counts, truncated hunks) fail
	# here. Context mismatches against a real tree still need patch-build.
	fail=0
	for name in $listed; do
		# A corrupt patch fails to parse against any tree, including an empty
		# one. "does not exist in index" means it parsed and simply has nothing
		# to apply to, which is not what we are asking about here.
		err=$(git apply --check --numstat "$PATCHES/$name" 2>&1 >/dev/null || true)
		case "$err" in
			"") ;;
			*"corrupt patch"*|*"malformed"*|*"unrecognized input"*|*"fatal:"*)
				echo "apply-patches: patches/$name is not a readable patch: $err" >&2
				fail=1 ;;
			*) ;;
		esac
	done
	[ "$fail" -eq 0 ] || exit 1
	echo "apply-patches: series ok (parsed $(echo $listed | wc -w | tr -d ' ') patches):$listed"
	exit 0
fi
for name in $listed; do
	git -C "$DEST" apply --whitespace=nowarn "$PATCHES/$name"
	echo "apply-patches: applied $name"
done
