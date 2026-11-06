#!/usr/bin/env bash
# Verify and build a pinned tool image (build/tools/tools.json, build/tools/Dockerfile); prints the
# local image tag on stdout. ADR supply-chain provenance; EDR 20261105-pinned-tools.
#   build/tools/tool.sh NAME              (./seclab tool NAME)
#   build/tools/tool.sh --bins gitleaks DIR   export the reproducible gitleaks binaries (CI attests them)
# release: download (curl, https only), sha256 against the pin, then the publisher's provenance,
#   always with sigstore-python (hash-locked, broker/tools/attest), never with the tool itself:
#   sigstoreBundle      -> the release's own bundle, against identity + issuer (cosign);
#   sigstoreAttestation -> a committed, pinned attestation bundle (build/tools/attestations),
#                          against the signer workflow, repository, ref, commit and trigger, and
#                          a GitHub-hosted runner. Offline from GitHub's API: no token anywhere.
# source: built from the pinned commit; gitleaks' binaries must match binarySha256 for both arches,
# and the image build re-checks the one it ships.
# A cached image is reused only if its tag (a hash of the pin, the Dockerfile, this script, the
# verifier's lockfile and any committed bundle) matches. Fails closed.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOCK="$ROOT/build/tools/tools.json"
DOCKERFILE="$ROOT/build/tools/Dockerfile"
ATTEST_REQ="$ROOT/broker/tools/attest/requirements.txt"
log() { echo "tool: $*" >&2; }
die() { log "$*"; exit 1; }
sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -c1-64; else shasum -a 256 "$1" | cut -c1-64; fi; }
verifier() {
	# broker/tools/attest/build.sh is the only supported build (wheels via CFS locally, PyPI in CI); it fails closed.
	"$ROOT/broker/tools/attest/build.sh" seclab-attest:local || die "cannot build the attestation verifier image (broker/tools/attest/build.sh)"
	docker run --rm -v "$ctx:/w:ro" -e PYTHONDONTWRITEBYTECODE=1 --entrypoint python seclab-attest:local -m sigstore "$@"
}
# Both gitleaks binaries must exist and match their pins, whatever the host arch (the build
# cross-compiles both). A missing one is a failed build, never skipped. LOCK_FOR_CHECK overrides
# the pin file (self-test only).
check_bins() {
	local dir="$1" a got want lock="${LOCK_FOR_CHECK:-$LOCK}"
	for a in arm64 amd64; do
		want="$(jq -r --arg a "$a" '.gitleaks.binarySha256[$a] // ""' "$lock")"
		[[ "$want" =~ ^[0-9a-f]{64}$ ]] || { log "gitleaks-linux-$a: no sha256 pin"; return 1; }
		[[ -f "$dir/gitleaks-linux-$a" ]] || { log "gitleaks-linux-$a: not built (the build produced: $(ls "$dir" 2>/dev/null | tr '\n' ' '))"; return 1; }
		got="$(sha256 "$dir/gitleaks-linux-$a")"
		[[ "$got" == "$want" ]] || { log "gitleaks-linux-$a: built sha256 $got, pinned $want (reproducibility check; pin it only from a CI build)"; return 1; }
	done
}

if [[ "${1:-}" == --self-test ]]; then
	# CI (workflow-lint, amd64) and local (arm64): check_bins fails closed for a missing or
	# mismatched binary of either arch, and passes only when both match.
	st="$ROOT/.work/tools/self-test"; rm -rf "$st"; mkdir -p "$st/b"
	trap 'rm -rf "$st"' EXIT
	printf 'arm' >"$st/b/gitleaks-linux-arm64"; printf 'amd' >"$st/b/gitleaks-linux-amd64"
	jq -n --arg a "$(sha256 "$st/b/gitleaks-linux-arm64")" --arg b "$(sha256 "$st/b/gitleaks-linux-amd64")" \
		'{gitleaks: {binarySha256: {arm64: $a, amd64: $b}}}' >"$st/lock.json"
	export LOCK_FOR_CHECK="$st/lock.json"
	check_bins "$st/b" 2>/dev/null || die "self-test: both binaries match, but check_bins failed"
	for a in arm64 amd64; do
		c="${a:0:3}"
		mv "$st/b/gitleaks-linux-$a" "$st/x"
		! check_bins "$st/b" 2>/dev/null || die "self-test: missing gitleaks-linux-$a passed"
		mv "$st/x" "$st/b/gitleaks-linux-$a"
		printf '%sx' "$c" >"$st/b/gitleaks-linux-$a"
		! check_bins "$st/b" 2>/dev/null || die "self-test: mismatched gitleaks-linux-$a passed"
		printf '%s' "$c" >"$st/b/gitleaks-linux-$a"
	done
	check_bins "$st/b" 2>/dev/null || die "self-test: restored binaries failed"
	grep -q '^RUN set -eu; for a in arm64 amd64' "$DOCKERFILE" || die "self-test: the gitleaks build loop must run under set -eu"
	log "self-test: ok"
	exit 0
fi

bins_dir=""
if [[ "${1:-}" == --bins ]]; then
	[[ "${2:-}" == gitleaks && -n "${3:-}" ]] || die "usage: tool.sh --bins gitleaks DIR"
	bins_dir="$3"; set -- gitleaks
fi
NAME="${1:-}"
[[ "$NAME" =~ ^[a-z][a-z0-9-]{0,31}$ ]] && jq -e --arg n "$NAME" 'has($n)' "$LOCK" >/dev/null || die "unknown tool '$NAME' (see $LOCK)"
pin() { jq -er --arg n "$NAME" ".[\$n]$1" "$LOCK"; }
kind="$(pin .kind)"; ver="$(pin .version)"
case "$(docker info --format '{{.Architecture}}')" in
	aarch64|arm64) arch=arm64 ;; x86_64|amd64) arch=amd64 ;; *) die "unsupported docker architecture" ;;
esac
bundle_file=""
if jq -e --arg n "$NAME" '.[$n].sigstoreAttestation' "$LOCK" >/dev/null; then
	bundle_file="$ROOT/$(pin .sigstoreAttestation.bundle)"
	[[ -f "$bundle_file" ]] || die "$NAME: missing $bundle_file"
fi
key="$( { jq -c --arg n "$NAME" '.[$n]' "$LOCK"; cat "$DOCKERFILE" "${BASH_SOURCE[0]}" "$ATTEST_REQ" ${bundle_file:+"$bundle_file"}; echo "$arch"; } | { sha256sum 2>/dev/null || shasum -a 256; } | cut -c1-12)"
tag="seclab-tool-$NAME:$ver-$key"
if [[ -z "$bins_dir" ]] && docker image inspect "$tag" >/dev/null 2>&1; then
	# The stable name always points at the image built from these pins (TT-2).
	docker tag "$tag" "seclab-tool-$NAME:$ver"
	echo "$tag"; exit 0
fi
ctx="$ROOT/.work/tools/$NAME-$ver-$arch"
rm -rf "$ctx" && mkdir -p "$ctx"

case "$kind" in
release)
	url="$(pin .url)"; url="${url//\{arch\}/$arch}"
	want="$(pin ".sha256.$arch")"
	[[ "$url" == https://github.com/* && "$want" =~ ^[0-9a-f]{64}$ ]] || die "$NAME: bad pin"
	curl -fsSL --proto '=https' -o "$ctx/artifact" "$url"
	[[ "$(sha256 "$ctx/artifact")" == "$want" ]] || die "$NAME: $url does not match its sha256 pin"
	if jq -e --arg n "$NAME" '.[$n].sigstoreBundle' "$LOCK" >/dev/null; then
		burl="$(pin .sigstoreBundle.url)"; burl="${burl//\{arch\}/$arch}"
		curl -fsSL --proto '=https' -o "$ctx/bundle.json" "$burl"
		# An independent verifier (not the tool vouching for itself); TUF root fetched over the network.
		verifier verify identity --bundle /w/bundle.json --cert-identity "$(pin .sigstoreBundle.identity)" \
			--cert-oidc-issuer "$(pin .sigstoreBundle.issuer)" /w/artifact >/dev/null 2>"$ctx/verify.err" \
			|| { tail -3 "$ctx/verify.err" >&2; die "$NAME: sigstore bundle does not verify"; }
		log "$NAME $ver: sha256 pinned, sigstore signature verified ($(pin .sigstoreBundle.identity))"
	elif [[ -n "$bundle_file" ]]; then
		cp "$bundle_file" "$ctx/bundle.json"
		# GitHub artifact attestation (public-good Sigstore), from the committed bundle: the signer
		# workflow at the ref, repository, source commit, trigger, and the artifact as a subject.
		verifier verify github --bundle /w/bundle.json --cert-identity "$(pin .sigstoreAttestation.identity)" \
			--repository "$(pin .sigstoreAttestation.repository)" --ref "$(pin .sigstoreAttestation.ref)" \
			--sha "$(pin .sigstoreAttestation.sha)" --trigger "$(pin .sigstoreAttestation.trigger)" /w/artifact >"$ctx/statement" 2>"$ctx/verify.err" \
			|| { tail -3 "$ctx/verify.err" >&2; die "$NAME: attestation does not verify"; }
		grep -q '"runner_environment":"github-hosted"' "$ctx/statement" || die "$NAME: attestation is not from a GitHub-hosted runner"
		log "$NAME $ver: sha256 pinned, attestation verified ($(pin .sigstoreAttestation.identity))"
	else
		die "$NAME: a release needs sigstoreBundle or sigstoreAttestation"
	fi
	docker build -q --target "$NAME" -f "$DOCKERFILE" --build-arg SHA256="$want" -t "$tag" "$ctx" >/dev/null
	;;
source)
	git_url="$(pin .git)"; tg="$(pin .tag)"; commit="$(pin .commit)"
	[[ "$git_url" == https://github.com/*.git && "$commit" =~ ^[0-9a-f]{40}$ ]] || die "$NAME: bad pin"
	args=(--build-arg GIT="$git_url" --build-arg TAG="$tg" --build-arg COMMIT="$commit")
	if [[ "$NAME" == gitleaks ]]; then
		out="${bins_dir:-$ctx/bins}"
		docker build --progress=plain --target gitleaks-bins -f "$DOCKERFILE" "${args[@]}" --output "type=local,dest=$out" "$ctx" >"$ctx/build.log" 2>&1 \
			|| { tail -30 "$ctx/build.log" >&2; die "gitleaks: build failed (log: $ctx/build.log)"; }
		check_bins "$out" || { tail -30 "$ctx/build.log" >&2; exit 1; }
		log "gitleaks $ver: built from $commit; both binaries match their pinned sha256"
		[[ -n "$bins_dir" ]] && exit 0
		args+=(--build-arg BIN_SHA256="$(jq -r --arg a "$arch" '.gitleaks.binarySha256[$a]' "$LOCK")")
	fi
	docker build -q --target "$NAME" -f "$DOCKERFILE" "${args[@]}" -t "$tag" "$ctx" >/dev/null
	log "$NAME $ver: built from ${git_url%.git}@$commit"
	;;
*) die "$NAME: unknown kind $kind" ;;
esac
# A stable name for consumers that can't compute the content tag (tabd's pre-mount scan).
docker tag "$tag" "seclab-tool-$NAME:$ver"
echo "$tag"
