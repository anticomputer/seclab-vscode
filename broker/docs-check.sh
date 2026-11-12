#!/bin/sh
# Keep the broker docs in lock-step with the code. Runs inside the broker unit
# image (Python + fastjsonschema); only docker is needed on the host.
#   broker/docs-check.sh                 check generated sections, JSON examples, cross-checks
#   broker/docs-check.sh --write         regenerate generated sections in place
#   broker/docs-check.sh --run-commands  also run every `ci: run` shell block in the broker docs
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
. "$here/tools/pybuild.sh"
pybuild -q --target unit -t seclab-broker-unit:docs "$here" >/dev/null
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
dock commands --self-test
# broker/build.sh refuses any tracked path git would quote (non-ASCII, control characters,
# `"`, `\`); catch one here first. Only tracked paths matter: they are what it snapshots.
quoted=$(git -C "$repo" -c core.quotePath=true ls-files -- broker | grep '^"' || true)
if [ -n "$quoted" ]; then
  printf 'docs-check: tracked path under broker/ needs git quoting; broker/build.sh refuses it: %s\n' $quoted >&2
  exit 1
fi
docker run --rm --network none -u "$(id -u):$(id -g)" -v "$repo:/repo:ro" \
  -e PYTHONPATH=/repo/broker -e PYTHONDONTWRITEBYTECODE=1 --entrypoint python \
  seclab-broker-unit:docs /repo/broker/tools/fixture_lint.py
docker run --rm --network none -u "$(id -u):$(id -g)" -v "$repo:/repo:ro" \
  -e PYTHONDONTWRITEBYTECODE=1 --entrypoint sh \
  seclab-broker-unit:docs -c 'python /repo/broker/tools/pin_check.py --self-test && python /repo/broker/tools/pin_check.py'
if [ "${1:-}" = "--run-commands" ]; then
  # Fails (set -e) when docs.py finds a missing doc or no block: never a pass that ran nothing.
  script=$(dock commands)
  [ -n "$script" ] || { echo "docs-check: no commands to run" >&2; exit 1; }
  cd "$repo"
  printf '%s\n' "$script" | bash
fi
