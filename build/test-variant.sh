#!/usr/bin/env bash
# Test build variants (EDR test-build-variants): patches/series plus a reviewed list of
# test-only hooks (test/builds/variants.json). Never a release: check-release fails any
# artifact that carries `seclabTestBuild` or a hook marker, and `verify` proves it does.
#   build/test-variant.sh apply  VARIANT TARGET SRC     after prepare.sh: apply TARGET's hooks
#                                                       (each must apply), mark product.json
#   build/test-variant.sh verify VARIANT TARGET OUTDIR  after the build: every hook's marker is
#                                                       in the output, the product marker names
#                                                       exactly these hooks, check-release fails
#                                                       on the markers and nothing else
#   build/test-variant.sh record VARIANT TARGET         the hooks as JSON (for build-info.json)
# TARGET is desktop or reh. Works with bash 3.2 (macOS runners). Fails closed.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$ROOT/test/builds/variants.json"
die() { echo "test-variant: $*" >&2; exit 1; }
sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -c1-64; else shasum -a 256 "$1" | cut -c1-64; fi; }

cmd="${1:-}"; variant="${2:-}"; target="${3:-}"
if [[ "$cmd" == check-all ]]; then
	# CI (patch-build): every variant's hooks, both targets, still apply on top of the series
	# at SRC, so a series change that breaks a hook fails on the PR, not at dispatch.
	src="${2:?usage: test-variant.sh check-all SRC}"
	# A failed jq in a `for` word list would not trip set -e (review CCC-4): read it on its own.
	vs="$(jq -r 'keys[] | select(startswith("$") | not)' "$MANIFEST")"
	[[ -n "$vs" ]] || die "no variants in $MANIFEST"
	for v in $vs; do
		for t in desktop reh; do
			"${BASH_SOURCE[0]}" record "$v" "$t" >/dev/null
			ps=()
			while IFS= read -r p; do
				[[ -n "$p" ]] && ps+=("$ROOT/$p")
			done < <(jq -r --arg v "$v" --arg t "$t" '.[$v].hooks[] | select(.target == $t) | .patch' "$MANIFEST")
			[[ ${#ps[@]} -gt 0 ]] || continue
			# All of a target's hooks together, in order, as the build applies them.
			git -C "$src" apply --check "${ps[@]}" || die "$v/$t: its hooks do not apply on top of patches/series"
			echo "test-variant: $v/$t: ${#ps[@]} hook(s) apply" >&2
		done
	done
	exit 0
fi
[[ "$variant" =~ ^[a-z][a-z0-9-]{0,31}$ ]] || die "bad variant name"
jq -e --arg v "$variant" 'has($v) and ($v | startswith("$") | not)' "$MANIFEST" >/dev/null || die "unknown variant '$variant' (test/builds/variants.json)"
[[ "$target" == desktop || "$target" == reh ]] || die "target must be desktop or reh"

# This target's hooks, validated: an id, a regular file under test/ (no traversal, no symlink),
# a marker that is a plain token, and the bundle (path in the target's app root) its code is
# built into. Prints "id<TAB>patch<TAB>marker<TAB>bundle" lines.
hooks() {
	jq -r --arg v "$variant" --arg t "$target" '.[$v].hooks // error("no hooks list") | .[] | select(.target == $t) | [.id, .patch, .marker, .bundle] | @tsv' "$MANIFEST" \
		| while IFS=$'\t' read -r id patch marker bundle; do
			[[ "$id" =~ ^[a-z][a-z0-9-]{0,31}$ ]] || die "bad hook id '$id'"
			[[ "$patch" =~ ^test/[A-Za-z0-9._/-]+\.patch$ && "$patch" != *..* ]] || die "$id: hook patch must be a .patch under test/"
			[[ -f "$ROOT/$patch" && ! -L "$ROOT/$patch" ]] || die "$id: $patch is missing or not a regular file"
			[[ "$marker" =~ ^SECLAB_TEST_ONLY:[a-z0-9-]{1,48}$ ]] || die "$id: marker must be SECLAB_TEST_ONLY:<name>"
			grep -qF "$marker" "$ROOT/$patch" || die "$id: $patch does not contain its marker $marker"
			[[ "$bundle" =~ ^out/[A-Za-z0-9._/-]+\.(c|m)?js$ && "$bundle" != *..* ]] || die "$id: bundle must be an out/**.js path"
			printf '%s\t%s\t%s\t%s\n' "$id" "$patch" "$marker" "$bundle"
		done
}
# Every hook of the variant targets desktop or reh; a typo must not silently drop one.
jq -e --arg v "$variant" '[.[$v].hooks[] | select(.target != "desktop" and .target != "reh")] | length == 0' "$MANIFEST" >/dev/null \
	|| die "$variant: a hook has a target other than desktop or reh"

record() {
	# No marker here (review CCC-1): product.json is inlined into the bundles, so a marker in the
	# record would make the presence check match the record instead of the hook's code.
	hooks | while IFS=$'\t' read -r id patch marker bundle; do
		jq -nc --arg id "$id" --arg p "$patch" --arg s "$(sha256 "$ROOT/$patch")" '{id: $id, patch: $p, sha256: $s}'
	done | jq -sc --arg v "$variant" --arg t "$target" '{variant: $v, target: $t, hooks: .}'
}

case "$cmd" in
record) record ;;
apply)
	src="${4:?usage: test-variant.sh apply VARIANT TARGET SRC}"
	[[ -f "$src/product.json" ]] || die "no product.json in $src"
	jq -e 'has("seclabTestBuild") | not' "$src/product.json" >/dev/null || die "$src is already a test build; run prepare.sh first"
	hooks | while IFS=$'\t' read -r id patch marker bundle; do
		git -C "$src" apply --check "$ROOT/$patch" || die "$id: $patch does not apply"
		git -C "$src" apply --whitespace=nowarn "$ROOT/$patch"
		echo "test-variant: applied $id ($patch)" >&2
	done
	rec="$(record)"
	# The positive marker (check-release fails on `seclabTestBuild`), and for the desktop app an
	# identity that can't be mistaken for the release or share its data: name, bundle id, data
	# folder and URL scheme. The REH keeps its server names (tabd and the tab image use them).
	tmp="$src/product.json.seclab-test"
	jq --tab --argjson rec "$rec" --arg t "$target" --arg v "$variant" \
		--arg sha "$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)" '
		.seclabTestBuild = ($rec + {repoSha: $sha, warning: "UNSAFE TEST BUILD: contains test-only hooks; never use as a release"})
		| if $t == "desktop" then
			.nameShort = "seclab-vscode-TEST-\($v)"
			| .nameLong = "seclab-vscode UNSAFE TEST BUILD (\($v))"
			| .applicationName = "seclab-code-test-\($v)"
			| .dataFolderName = ".seclab-vscode-test-\($v)"
			| .darwinBundleIdentifier = "dev.seclab.vscode.test.\($v)"
			| .urlProtocol = "seclab-vscode-test-\($v)"
		  else . end' "$src/product.json" > "$tmp"
	mv "$tmp" "$src/product.json"
	echo "test-variant: $variant/$target marked: $(jq -c '.seclabTestBuild.hooks | map(.id)' "$src/product.json")" >&2
	;;
verify)
	out="${4:?usage: test-variant.sh verify VARIANT TARGET OUTDIR}"
	[[ -d "$out" ]] || die "no output directory $out"
	hooks | while IFS=$'\t' read -r id patch marker bundle; do
		# The marker in the hook's own bundle (review CCC-1: product.json is inlined elsewhere, and
		# the record carries no marker). The app root: the REH dir, or the .app's Resources/app.
		base="$out"; [[ "$target" == desktop ]] && base="$out/Contents/Resources/app"
		[[ -f "$base/$bundle" ]] || die "$id: bundle $bundle is not in the $target output"
		grep -qaF "$marker" "$base/$bundle" || die "$id: marker $marker is not in $bundle (the hook is absent)"
		echo "test-variant: $id present ($bundle)" >&2
	done
	# The product marker in the built output names exactly this variant's hooks for this target.
	prod="$(find "$out" -type f -name product.json -not -path '*/node_modules/*' -not -path '*/extensions/*' | head -1)"
	[[ -n "$prod" ]] || die "no product.json in $out"
	want="$(record | jq -c '.hooks | map(.id)')"
	jq -e --arg v "$variant" --arg t "$target" --argjson w "$want" \
		'.seclabTestBuild.variant == $v and .seclabTestBuild.target == $t and (.seclabTestBuild.hooks | map(.id)) == $w' "$prod" >/dev/null \
		|| die "$prod: seclabTestBuild does not record $variant/$target with hooks $want"
	# The release gate refuses this artifact, on the test markers and nothing else (an agent
	# runtime or an env-controlled module load would fail a release for another reason).
	mode=release; [[ "$target" == desktop ]] && mode=desktop
	# Scratch next to the output (writable in the build container and on the runner; /repo is not).
	crw="$(dirname "$out")/.check-release-variant.$$"
	set +e
	res="$(sh "$ROOT/build/check-release.sh" --inner "$crw" "$mode" "$out" 2>&1)"
	rc=$?
	set -e
	rm -rf "$crw"
	[[ "$rc" -ne 0 ]] || die "check-release passed a test build (it must fail on seclabTestBuild)"
	other="$(printf '%s\n' "$res" | grep '^check-release: ' | grep -v '^check-release: test-hook marker:$' || true)"
	[[ -z "$other" ]] || { printf '%s\n' "$res" >&2; die "check-release found more than the test markers"; }
	printf '%s\n' "$res" | grep -qF 'seclabTestBuild' || die "check-release did not flag the seclabTestBuild marker"
	echo "test-variant: $variant/$target verified; check-release refuses it" >&2
	;;
*) die "usage: test-variant.sh apply|verify|record VARIANT TARGET [DIR]" ;;
esac
