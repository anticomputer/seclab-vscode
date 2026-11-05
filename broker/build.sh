#!/bin/sh
# Build the broker image. Usage: broker/build.sh [tag]   (default seclab-broker:dev)
# Verifies the base image's signed provenance first (broker/tools/verify-images.sh); fails closed.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
"$here/tools/verify-images.sh"
exec docker build --target broker -t "${1:-seclab-broker:dev}" "$here"
