#!/bin/sh
# Build the broker image. Usage: broker/build.sh [tag]   (default seclab-broker:dev)
# 1. Verifies the mitmproxy base image's signed provenance (tools/verify-images.sh); fails closed.
# 2. Builds through tools/pybuild.sh (CFS locally, public PyPI in CI).
# 3. Builds from a snapshot of broker/'s git-tracked files only (ignored and untracked files
#    never enter the context) and stamps the image's identity as OCI labels: source revision
#    (`-dirty` if broker/ has uncommitted or untracked files), the verified base digest,
#    broker version, protocol and policy schema revision.
# 4. Prints one JSON line on stdout: {"id","tag","revision","base","version","policyRevision"}.
#    `id` is exactly `docker image inspect --format '{{.Id}}'` (the manifest/index digest under
#    the containerd image store, else the config digest; content-addressed over every layer
#    and label either way). tabd records it and runs the broker by ID, never by tag (XX-6).
#    All other output goes to stderr.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
tag=${1:-seclab-broker:dev}
. "$here/tools/pybuild.sh"
"$here/tools/verify-images.sh" >&2
base=$(sed -n 's/^FROM mitmproxy\/mitmproxy:[^@]*@\(sha256:[0-9a-f]\{64\}\) AS broker$/\1/p' "$here/Dockerfile")
grep -q "\"ref\": \"mitmproxy/mitmproxy:[^\"]*@$base\"" "$here/deps.json" \
  || { echo "build: broker base digest '$base' is not the registered (verified) mitmproxy digest" >&2; exit 1; }
version=$(sed -n 's/^VERSION = "\(.*\)"$/\1/p' "$here/seclab_broker/__init__.py")
policy_revision=$(sed -n 's/^POLICY_SCHEMA_REVISION = \([0-9]*\)$/\1/p' "$here/seclab_broker/__init__.py")
top=$(git -C "$here" rev-parse --show-toplevel) || { echo "build: broker/ must be in a git checkout" >&2; exit 1; }
prefix=$(git -C "$here" rev-parse --show-prefix)
revision=$(git -C "$here" rev-parse HEAD)
# The build context holds git-tracked files only, so ignored files (__pycache__, *.pyc) and
# untracked files can never reach the image under any revision label. It is a snapshot of
# the working tree's tracked files (`git stash create` makes a commit object and touches no
# ref, index or file; it prints nothing when the tree is clean), and `-dirty` is decided from
# that same snapshot, so a file edited mid-build can't ship under a clean label.
snap=$(GIT_AUTHOR_NAME=seclab-build GIT_AUTHOR_EMAIL=build@invalid \
  GIT_COMMITTER_NAME=seclab-build GIT_COMMITTER_EMAIL=build@invalid git -C "$here" stash create)
[ -n "$snap" ] || snap=$revision
git -C "$here" diff --quiet "$revision" "$snap" -- . || revision="$revision-dirty"
# Untracked files can't enter the context, but still mark the revision (agreed with tabd).
[ -z "$(git -C "$here" status --porcelain --untracked-files=all -- .)" ] || case $revision in *-dirty) ;; *) revision="$revision-dirty" ;; esac
# gh cfs accepts only a local directory as the context, so the snapshot is extracted into a
# fresh directory under .work/ (gitignored) and removed on exit.
mkdir -p "$top/.work"
ctx=$(mktemp -d "$top/.work/broker-context.XXXXXX")
trap 'rm -rf "$ctx" "$ctx.tar"' EXIT
trap 'exit 1' HUP INT TERM
git -C "$top" archive --format=tar -o "$ctx.tar" "$snap:$prefix"
tar -xf "$ctx.tar" -C "$ctx"
[ -f "$ctx/Dockerfile" ] || { echo "build: snapshot context has no Dockerfile" >&2; exit 1; }
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
