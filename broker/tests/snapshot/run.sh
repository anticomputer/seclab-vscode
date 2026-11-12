#!/bin/sh
# Replay the snapshot writer's review probes (broker/tests/snapshot/probes.sh) in the pinned Node
# image (Debian: git, dash, bash, GNU coreutils), with no network and the repo read-only.
#   broker/tests/snapshot/run.sh
set -eu
here=$(cd "$(dirname "$0")" && pwd)
broker=$(cd "$here/../.." && pwd)
NODE_IMAGE=node:24.22.1-trixie@sha256:f1e034976f948cf212ef1f659c12e5dd58ac7eab947831813e81a62401ca38be
exec docker run --rm --network none -u "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$broker/build.sh:/probe/build.sh:ro" -v "$here/probes.sh:/probe/probes.sh:ro" \
  "$NODE_IMAGE" sh /probe/probes.sh /probe/build.sh
