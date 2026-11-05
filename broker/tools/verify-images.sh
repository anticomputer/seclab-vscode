#!/bin/sh
# Verify every image in broker/deps.json whose tier is "attested" (GitHub artifact
# attestations, sigstore) against the exact signer workflow, source ref and source
# commit recorded in the register. Fails closed. Needs: gh (user-approved host tool),
# docker. Usage: broker/tools/verify-images.sh
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
command -v gh >/dev/null || { echo "verify-images: gh is required to verify image attestations" >&2; exit 1; }
docker run --rm -i --network none --entrypoint python \
  python:3.13-slim-trixie@sha256:ae14d4ce8771606477a81446e7ef429edd6762305fc50c84507c1041fa8285d1 -c '
import json, sys
for i in json.load(sys.stdin)["images"]:
    v = i.get("verify") or {}
    if i["tier"] == "attested":
        assert v.get("kind") == "github-attestation", i["name"]
        print(i["ref"].split(":", 1)[0] + "@" + i["ref"].split("@", 1)[1], v["repo"], v["signerWorkflow"], v["sourceRef"], v["sourceDigest"])
' < "$here/deps.json" | while read -r ref repo workflow sref sdigest; do
  if out=$(gh attestation verify "oci://docker.io/$ref" --repo "$repo" --signer-workflow "$workflow" \
       --source-ref "$sref" --source-digest "$sdigest" 2>&1); then
    echo "verify-images: ok $ref (signed by $workflow @ $sref)" >&2
  else
    printf '%s\n' "$out" >&2
    echo "verify-images: FAILED $ref" >&2
    exit 1
  fi
done
