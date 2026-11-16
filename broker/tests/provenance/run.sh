#!/bin/sh
# Finding provenance #5's regression test, in the attestation verifier image (it has
# pypi-attestations and sigstore), with no network: sigstore's embedded trust root only.
#   broker/tests/provenance/run.sh
set -eu
here=$(cd "$(dirname "$0")" && pwd)
broker=$(cd "$here/../.." && pwd)
"$broker/tools/attest/build.sh" seclab-attest:test-provenance
exec docker run --rm --network none -u "$(id -u):$(id -g)" -e HOME=/tmp -e PYTHONDONTWRITEBYTECODE=1 \
  -v "$broker:/broker:ro" --entrypoint python seclab-attest:test-provenance \
  /broker/tests/provenance/test_verify_binding.py
