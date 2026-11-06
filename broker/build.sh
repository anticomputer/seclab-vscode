#!/bin/sh
# Build the broker image. Usage: broker/build.sh [tag]   (default seclab-broker:dev)
# 1. Snapshots broker/'s git-tracked files and builds only that snapshot: ignored and
#    untracked files never enter the context, and every check and label below is read from
#    the snapshot, never from the working tree.
# 2. Verifies the mitmproxy base image's signed provenance (tools/verify-images.sh); fails closed.
# 3. Builds through tools/pybuild.sh (CFS locally, public PyPI in CI) and stamps the image's
#    identity as OCI labels: source revision (`-dirty` unless broker/ is exactly HEAD's tree:
#    no uncommitted, untracked, assume-unchanged or skip-worktree files), the verified base
#    digest, broker version, protocol and policy schema revision.
# 4. Prints one JSON line on stdout: {"id","tag","revision","base","version","policyRevision"}.
#    `id` is exactly `docker image inspect --format '{{.Id}}'` (the manifest/index digest under
#    the containerd image store, else the config digest; content-addressed over every layer
#    and label either way). tabd records it and runs the broker by ID, never by tag (XX-6).
#    All other output goes to stderr.
# The label vouches for the snapshot, given an honest build.sh: a modified build.sh is itself
# a change to broker/ and marks the revision `-dirty`, but it could lie about that.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
tag=${1:-seclab-broker:dev}
top=$(git -C "$here" rev-parse --show-toplevel) || { echo "build: broker/ must be in a git checkout" >&2; exit 1; }
prefix=$(git -C "$here" rev-parse --show-prefix)
revision=$(git -C "$here" rev-parse HEAD)
# The snapshot comes first: nothing from the working tree is read or run before it.
# `git stash create` records the working tree's tracked files as a commit object and touches
# no ref, index or file; it prints nothing when the tree is clean.
snap=$(GIT_AUTHOR_NAME=seclab-build GIT_AUTHOR_EMAIL=build@invalid \
  GIT_COMMITTER_NAME=seclab-build GIT_COMMITTER_EMAIL=build@invalid git -C "$here" stash create)
[ -n "$snap" ] || snap=$revision
dirty=
git -C "$here" diff --quiet "$revision" "$snap" -- . || dirty=1
# Untracked files can't enter the context, but still mark the revision (agreed with tabd).
[ -z "$(git -C "$here" status --porcelain --untracked-files=all -- .)" ] || dirty=1
# assume-unchanged and skip-worktree entries hide edits from `git status` and `stash create`.
[ -z "$(git -C "$here" ls-files -v -- . | grep -v '^H ')" ] || dirty=1
[ -z "$dirty" ] || revision="$revision-dirty"
# gh cfs accepts only a local directory as the context, so the snapshot is written into a
# fresh directory under .work/ (gitignored), removed on exit. It is written from the git
# objects themselves (`git cat-file blob`, no filters), not with `git archive`, so committed
# .gitattributes (export-ignore, eol, filters) can't make the context differ from the tree.
# Three passes so nothing is written through a symlink: every parent directory first, then
# regular files, then symlinks. No path may already exist when it is written, so a crafted
# tree (duplicate entries, a symlink named like a directory) fails instead of escaping.
# Anything other than a file or a symlink (e.g. a submodule) fails the build. Paths git
# would quote (non-ASCII, control characters, `"` or `\`) are refused; pin_check.py lints
# for them so this never surprises a build.
mkdir -p "$top/.work"
ctx=$(mktemp -d "$top/.work/broker-context.XXXXXX")
trap 'rm -rf "$ctx" "$ctx.list"' EXIT
trap 'exit 1' HUP INT TERM
git -C "$top" -c core.quotePath=true ls-tree -r "$snap:$prefix" > "$ctx.list"
tab=$(printf '\t')
for pass in dirs files links; do
  while IFS= read -r entry; do
    meta=${entry%%"$tab"*} path=${entry#*"$tab"}
    mode=${meta%% *} obj=${meta##* }
    case $path in
      '' | '"'* | /* | .. | ../* | */.. | */../* | . | ./* | */. | */./* | *//*)
        echo "build: refusing snapshot path '$path'" >&2; exit 1 ;;
    esac
    case $path in */*) dir=${path%/*} ;; *) dir=. ;; esac
    out=$ctx/$path
    case $pass:$mode:${meta#* } in
      dirs:100644:blob\ * | dirs:100755:blob\ * | dirs:120000:blob\ *) mkdir -p "$ctx/$dir" ;;
      files:100644:blob\ * | files:100755:blob\ * | links:120000:blob\ *)
        if [ -e "$out" ] || [ -L "$out" ] || [ -L "$ctx/$dir" ]; then
          echo "build: snapshot path '$path' collides with another entry" >&2; exit 1
        fi
        if [ "$pass" = links ]; then
          target=$(git -C "$top" cat-file blob "$obj")
          [ -n "$target" ] || { echo "build: snapshot symlink '$path' is empty" >&2; exit 1; }
          ln -s -- "$target" "$out"
        else
          git -C "$top" cat-file blob "$obj" > "$out"
          [ "$mode" = 100644 ] || chmod 755 "$out"
        fi ;;
      files:120000:blob\ * | links:100644:blob\ * | links:100755:blob\ *) ;;
      *) echo "build: snapshot entry '$path' is '$meta'; only files and symlinks are built" >&2; exit 1 ;;
    esac
  done < "$ctx.list"
done
[ -f "$ctx/Dockerfile" ] || { echo "build: snapshot context has no Dockerfile" >&2; exit 1; }
# From here on, everything is read and run from the snapshot.
. "$ctx/tools/pybuild.sh"
# verify-images.sh uses cached bundles when $CI or $SECLAB_ATTESTATION_DIR is set, and
# otherwise verifies online. Its default bundle directory is relative to itself, so under CI
# it is pointed at the repo's .work/attestations; an explicit SECLAB_ATTESTATION_DIR is
# passed through unchanged (forged bundles still fail cryptographically).
if [ -n "${CI:-}" ] && [ -z "${SECLAB_ATTESTATION_DIR:-}" ]; then
  SECLAB_ATTESTATION_DIR="$top/.work/attestations" "$ctx/tools/verify-images.sh" >&2
else
  "$ctx/tools/verify-images.sh" >&2
fi
base=$(sed -n 's/^FROM mitmproxy\/mitmproxy:[^@]*@\(sha256:[0-9a-f]\{64\}\) AS broker$/\1/p' "$ctx/Dockerfile")
grep -q "\"ref\": \"mitmproxy/mitmproxy:[^\"]*@$base\"" "$ctx/deps.json" \
  || { echo "build: broker base digest '$base' is not the registered (verified) mitmproxy digest" >&2; exit 1; }
version=$(sed -n 's/^VERSION = "\(.*\)"$/\1/p' "$ctx/seclab_broker/__init__.py")
policy_revision=$(sed -n 's/^POLICY_SCHEMA_REVISION = \([0-9]*\)$/\1/p' "$ctx/seclab_broker/__init__.py")
# Build output goes to stderr: the JSON identity is the only line on stdout.
pybuild -q --target broker -t "$tag" \
  --build-arg SECLAB_REVISION="$revision" --build-arg SECLAB_BASE_DIGEST="$base" \
  --build-arg SECLAB_VERSION="$version" --build-arg SECLAB_POLICY_REVISION="$policy_revision" \
  "$ctx" >&2
# Exactly what `docker image inspect` reports (with the containerd image store this is the
# manifest/index digest; it is content-addressed down to config and layers either way).
id=$(docker image inspect --format '{{.Id}}' "$tag")
printf '{"id":"%s","tag":"%s","revision":"%s","base":"%s","version":"%s","policyRevision":%s}\n' \
  "$id" "$tag" "$revision" "$base" "$version" "$policy_revision"
