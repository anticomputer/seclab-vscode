#!/usr/bin/env bash
# Verify the pinned Falco image (sandbox/oci/falco.lock): pull by digest, then check its keyless
# cosign signature against the exact release workflow identity and issuer. Fails closed.
# Usage: sandbox/oci/verify-falco.sh   (also run by sandbox/oci/build-images.sh)
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOCK="$ROOT/sandbox/oci/falco.lock"
get() { awk -v k="$1" '$1==k{print $2}' "$LOCK"; }
IMAGE="$(get image)"; ISSUER="$(get issuer)"; IDENTITY="$(get identity)"
[[ "$IMAGE" =~ ^docker\.io/falcosecurity/falco:[0-9.]+@sha256:[0-9a-f]{64}$ ]] || { echo "verify-falco: bad image pin" >&2; exit 2; }
COSIGN="$("$ROOT/build/tools/tool.sh" cosign)"
[[ "${ISSUER#https://}" == token.actions.githubusercontent.com ]] || { echo "verify-falco: bad issuer" >&2; exit 2; }
# Signature identities (not network targets): Falco's release workflow, at a release tag.
ID_PATH="${IDENTITY#https://}"
[[ "$ID_PATH" =~ ^github\.com/falcosecurity/falco/\.github/workflows/[A-Za-z0-9_.-]+@refs/tags/[0-9.]+$ && "$IDENTITY" == "https://$ID_PATH" ]] || { echo "verify-falco: bad identity" >&2; exit 2; }

docker pull -q "$IMAGE" >/dev/null
docker run --rm "$COSIGN" verify "$IMAGE" --certificate-oidc-issuer "$ISSUER" --certificate-identity "$IDENTITY" >/dev/null 2>"$ROOT/.work/verify-falco.err" \
	|| { echo "verify-falco: signature verification FAILED for $IMAGE" >&2; tail -3 "$ROOT/.work/verify-falco.err" >&2; exit 1; }
echo "verify-falco: $IMAGE signed by $IDENTITY"
