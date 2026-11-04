#!/bin/sh
# Fixture-safety lint, docker only (no host toolchain). See test/safety/fixture-lint.ts.
#   test/safety/fixture-lint.sh [PATH...]   paths relative to the repo root
# Exit 0 clean, 1 violations.
set -eu
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
exec docker run --rm --network none -v "$ROOT:/repo:ro" -w /repo node:24.22.1-trixie node test/safety/fixture-lint.ts "$@"
