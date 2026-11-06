#!/bin/sh
# Build the broker image. Usage: broker/build.sh [tag]   (default seclab-broker:dev)
# 1. Verifies the mitmproxy base image's signed provenance (tools/verify-images.sh); fails closed.
# 2. Builds through tools/pybuild.sh (CFS locally, public PyPI in CI).
# 3. Stamps the image's identity as OCI labels: source revision (`-dirty` if broker/ has
#    uncommitted changes), the verified base digest, broker version, protocol and policy
#    schema revision.
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
revision=$(git -C "$here" rev-parse HEAD 2>/dev/null || echo unknown)
# The build context is broker/, so only broker/ can change the image; untracked files count.
[ -z "$(git -C "$here" status --porcelain --untracked-files=all -- . 2>/dev/null)" ] || revision="$revision-dirty"
# Build output goes to stderr: the JSON identity is the only line on stdout.
pybuild -q --target broker -t "$tag" \
  --build-arg SECLAB_REVISION="$revision" --build-arg SECLAB_BASE_DIGEST="$base" \
  --build-arg SECLAB_VERSION="$version" --build-arg SECLAB_POLICY_REVISION="$policy_revision" \
  "$here" >&2
# Exactly what `docker image inspect` reports (with the containerd image store this is the
# manifest/index digest; it is content-addressed down to config and layers either way).
id=$(docker image inspect --format '{{.Id}}' "$tag")
printf '{"id":"%s","tag":"%s","revision":"%s","base":"%s","version":"%s","policyRevision":%s}\n' \
  "$id" "$tag" "$revision" "$base" "$version" "$policy_revision"
