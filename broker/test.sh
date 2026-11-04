#!/bin/sh
# Run the whole broker suite in containers: unit tests inside the broker image
# (no network), then the pod-shaped integration suite driven by a harness
# container that talks to the local Docker engine.
# Usage: broker/test.sh [pytest args for the integration suite]
set -eu
here=$(cd "$(dirname "$0")" && pwd)
it="$here/tests/integration"

docker build -q --target broker -t seclab-broker:test "$here" >/dev/null
docker build -q --target unit -t seclab-broker-unit:test "$here" >/dev/null
echo "== unit tests"
docker run --rm --network none seclab-broker-unit:test

docker build -q -t seclab-broker-it-upstream:test "$it/images/upstream" >/dev/null
docker build -q -t seclab-broker-it-workspace:test "$it/images/workspace" >/dev/null
docker build -q -t seclab-broker-it-harness:test -f "$it/images/harness/Dockerfile" "$it" >/dev/null
echo "== integration tests"
exec docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e BROKER_IMAGE=seclab-broker:test \
  -e UPSTREAM_IMAGE=seclab-broker-it-upstream:test \
  -e WORKSPACE_IMAGE=seclab-broker-it-workspace:test \
  ${KEEP_POD:+-e KEEP_POD=1} \
  seclab-broker-it-harness:test "$@"
