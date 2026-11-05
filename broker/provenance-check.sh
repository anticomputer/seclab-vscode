#!/bin/sh
# Dependency provenance gate for the broker (online). Fails closed.
#   1. every pinned Python file is one PyPI serves, its publisher matches broker/deps.json,
#      and every attested file that applies here is verified cryptographically
#      (pypi-attestations / sigstore, in a hash-locked verifier image);
#   2. every attested image is verified against its recorded signer, ref and commit.
# Usage: broker/provenance-check.sh
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
docker build -q -t seclab-attest:local "$here/tools/attest" >/dev/null
docker run --rm -v "$repo:/repo:ro" -w /repo -e PYTHONDONTWRITEBYTECODE=1 --entrypoint python seclab-attest:local \
  broker/tools/provenance.py verify \
  broker/requirements.txt broker/requirements-test.txt \
  broker/tests/integration/images/upstream/requirements.txt \
  broker/tests/integration/images/harness/requirements.txt \
  broker/tools/attest/requirements.txt
"$here/tools/verify-images.sh"
