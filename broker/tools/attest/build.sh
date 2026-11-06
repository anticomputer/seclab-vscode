#!/bin/sh
# Build the hash-locked PEP 740 / sigstore verifier image. Usage: broker/tools/attest/build.sh [tag]
# (default seclab-attest:local). The only supported way to build it: the wheels come
# through tools/pybuild.sh (CFS locally, public PyPI in CI) with broker/ as the context.
# Used by broker/provenance-check.sh and build/tools/tool.sh. Fails closed.
set -eu
broker=$(cd "$(dirname "$0")/../.." && pwd)
. "$broker/tools/pybuild.sh"
pybuild -q -t "${1:-seclab-attest:local}" -f "$broker/tools/attest/Dockerfile" "$broker" >&2
