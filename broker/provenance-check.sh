#!/bin/sh
# Dependency provenance gate for the broker (online). Fails closed.
#   1. every requirements*.txt under broker/ (discovered, strictly parsed) pins only files
#      PyPI serves, with the publisher recorded in broker/deps.json, and every attestation
#      of every applicable file verifies against the pinned sha256 and the registered
#      repository and workflow (sigstore, in a hash-locked verifier image);
#   2. every attested image is verified against its recorded signer, ref and commit.
# Usage: broker/provenance-check.sh
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
"$here/tools/attest/build.sh" seclab-attest:local
docker run --rm -v "$repo:/repo:ro" -w /repo -e PYTHONDONTWRITEBYTECODE=1 --entrypoint python seclab-attest:local \
  broker/tools/provenance.py verify
"$here/tools/verify-images.sh"
