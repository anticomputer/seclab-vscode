#!/bin/sh
# Verify every image in broker/deps.json whose tier is "attested" (GitHub artifact
# attestations, sigstore) against the exact signer workflow, source ref and source
# commit recorded in the register, signed on a GitHub-hosted runner. Fails closed: the
# list is produced and checked before any verification, an empty or malformed register
# fails, and "ok" is printed only when every attested image verified.
# Needs: gh (user-approved host tool), docker. Usage: broker/tools/verify-images.sh
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
command -v gh >/dev/null || { echo "verify-images: gh is required to verify image attestations" >&2; exit 1; }
list=$(docker run --rm -i --network none --entrypoint python \
  python:3.13-slim-trixie@sha256:ae14d4ce8771606477a81446e7ef429edd6762305fc50c84507c1041fa8285d1 -c '
import json, re, sys
images = [i for i in json.load(sys.stdin)["images"] if i["tier"] == "attested"]
if not images:
    sys.exit("verify-images: no attested images in broker/deps.json")
for i in images:
    v, name = i.get("verify") or {}, i["name"]
    if v.get("kind") != "github-attestation":
        sys.exit("verify-images: " + name + ": unsupported verify kind")
    m = re.fullmatch(r"([\w./-]+):[\w.-]+@(sha256:[0-9a-f]{64})", i["ref"])
    fields = [v.get(k) or "" for k in ("repo", "signerWorkflow", "sourceRef", "sourceDigest")]
    if not m or not all(re.fullmatch(r"[\w./@-]+", f) for f in fields):
        sys.exit("verify-images: " + name + ": malformed ref or verify fields")
    print(m.group(1) + "@" + m.group(2), *fields)
' < "$here/deps.json")
expected=$(printf '%s\n' "$list" | grep -c .)
verified=0
while read -r ref repo workflow sref sdigest; do
  if out=$(gh attestation verify "oci://docker.io/$ref" --repo "$repo" --signer-workflow "$workflow" \
       --source-ref "$sref" --source-digest "$sdigest" --deny-self-hosted-runners 2>&1); then
    echo "verify-images: verified $ref (signed by $workflow @ $sref)" >&2
    verified=$((verified + 1))
  else
    printf '%s\n' "$out" >&2
    echo "verify-images: FAILED $ref" >&2
    exit 1
  fi
done <<EOF
$list
EOF
[ "$verified" -eq "$expected" ] && [ "$verified" -gt 0 ] || { echo "verify-images: FAILED ($verified of $expected verified)" >&2; exit 1; }
echo "verify-images: ok ($verified attested image(s))" >&2
