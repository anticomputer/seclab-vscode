#!/bin/sh
# Build the broker image. Usage: broker/build.sh [tag]   (default seclab-broker:dev)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
exec docker build --target broker -t "${1:-seclab-broker:dev}" "$here"
