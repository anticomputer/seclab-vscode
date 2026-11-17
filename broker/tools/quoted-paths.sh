#!/bin/sh
# broker/build.sh refuses any tracked path under broker/ that git would quote (non-ASCII, control
# characters, `"`, `\`); this catches one first. Only tracked paths matter, because they are what
# build.sh snapshots: the index is read, never the working tree (finding 10c-3), so an untracked
# local file can't fail the check and a tracked path missing from the checkout can't pass it.
#   broker/tools/quoted-paths.sh REPO     exit 1 and list the paths when any needs quoting
#   broker/tools/quoted-paths.sh --self-test
set -eu

check() {
  # git's own failure (not a repository, a broken index) fails the check; only grep's
  # no-match is a pass (review BRK20-4).
  listed=$(git -C "$1" -c core.quotePath=true ls-files -- broker) || {
    echo "docs-check: git ls-files failed in $1; can't check tracked paths" >&2
    return 1
  }
  quoted=$(printf '%s\n' "$listed" | grep '^"' || true)
  if [ -n "$quoted" ]; then
    printf 'docs-check: tracked path under broker/ needs git quoting; broker/build.sh refuses it: %s\n' "$quoted" >&2
    return 1
  fi
}

case_() {  # name, expect (pass|fail), shell code run in a fresh repo
  r=$scratch/$(printf %s "$1" | tr -c 'A-Za-z0-9' _)
  mkdir -p "$r/broker"
  git -C "$r" init -q
  echo plain > "$r/broker/plain.txt"
  git -C "$r" add broker/plain.txt
  (cd "$r" && eval "$3")
  if check "$r" 2>/dev/null; then got=pass; else got=fail; fi
  [ "$got" = "$2" ] || { echo "quoted-paths self-test: FAIL [$1]: got $got" >&2; fails=$((fails + 1)); }
}

self_test() {
  here=$(cd "$(dirname "$0")" && pwd)
  base=${RUNNER_TEMP:-$here/../../.work}
  mkdir -p "$base"
  scratch=$(mktemp -d "$base/seclab-quoted-paths.XXXXXX")
  trap 'rm -rf "$scratch"' EXIT INT TERM
  fails=0
  odd=$(printf 'broker/odd\tname.txt')
  case_ "quoting: plain tracked paths pass" pass ':'
  case_ "10c-3: a tracked path that needs quoting fails" fail 'echo x > "$odd" && git add "$odd"'
  case_ "10c-3: an untracked path that needs quoting is ignored" pass 'echo x > "$odd"'
  case_ "10c-3: a tracked path missing from the checkout still fails" fail \
    'echo x > "$odd" && git add "$odd" && rm "$odd"'
  case_ "quoting: a tracked non-ASCII path fails" fail \
    'f=$(printf "broker/caf\303\251.txt") && echo x > "$f" && git add "$f"'
  case_ "BRK20-4: git failing (a corrupt index) fails, never an empty pass" fail 'echo junk > .git/index'
  [ "$fails" -eq 0 ] || return 1
  echo "quoted-paths self-test: ok (6 cases)" >&2
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit $?
fi
check "${1:?usage: $0 REPO | --self-test}"
