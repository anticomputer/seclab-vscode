#!/bin/sh
# Keep the broker docs in lock-step with the code. Runs inside the broker unit
# image (Python + fastjsonschema); only docker is needed on the host.
#   broker/docs-check.sh                 check generated sections, JSON examples, cross-checks
#   broker/docs-check.sh --write         regenerate generated sections in place
#   broker/docs-check.sh --run-commands  also run every `ci: run` shell block in the broker docs
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
docker build -q --target unit -t seclab-broker-unit:docs "$here" >/dev/null
mode=check
mount=ro
case "${1:-}" in
  --write) mode=write; mount=rw ;;
  --run-commands|"") ;;
  *) echo "usage: $0 [--write|--run-commands]" >&2; exit 2 ;;
esac
dock() {
  docker run --rm --network none -u "$(id -u):$(id -g)" -v "$repo:/repo:$mount" \
    -e PYTHONPATH=/repo/broker -e PYTHONDONTWRITEBYTECODE=1 --entrypoint python \
    seclab-broker-unit:docs /repo/broker/tools/docs.py "$@"
}
dock "$mode"
if [ "${1:-}" = "--run-commands" ]; then
  script=$(dock commands)
  cd "$repo"
  printf '%s\n' "$script" | bash
fi
