#!/bin/sh
# Verify every image in broker/deps.json whose tier is "attested" (GitHub artifact
# attestations, sigstore) against the exact signer workflow, source ref and source
# commit recorded in the register, signed on a GitHub-hosted runner. Fails closed: the
# list is produced and checked before any verification, an empty or malformed register
# fails, and "ok" is printed only when every attested image verified.
#
#   broker/tools/verify-images.sh --download [DIR]
#       Fetch each attested image's attestation bundle into DIR. The only step that
#       talks to the GitHub API (it may need GH_TOKEN). Downloads are not trusted:
#       verification below checks them cryptographically.
#   broker/tools/verify-images.sh
#       Verify. A bundle DIR/<digest>.jsonl is used (`--bundle`; no GitHub token
#       needed) only when $CI or $SECLAB_ATTESTATION_DIR is set, i.e. when the same job
#       has just downloaded it. Otherwise gh fetches the attestation online, so a local
#       run never trusts a stale cached bundle that could predate a revocation.
# DIR defaults to $SECLAB_ATTESTATION_DIR, else <repo>/.work/attestations.
# Needs: gh (user-approved host tool), docker.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
dir=${SECLAB_ATTESTATION_DIR:-$(cd "$here/.." && pwd)/.work/attestations}
mode=verify
case "${1:-}" in
  --download) mode=download; dir=${2:-$dir} ;;
  "") ;;
  *) echo "usage: $0 [--download [DIR]]" >&2; exit 2 ;;
esac
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
done_n=0
if [ "$mode" = download ]; then
  mkdir -p "$dir"
fi
while read -r ref repo workflow sref sdigest; do
  digest=${ref#*@}
  if [ "$mode" = download ]; then
    (cd "$dir" && gh attestation download "oci://docker.io/$ref" --repo "$repo" >/dev/null) \
      || { echo "verify-images: download FAILED $ref" >&2; exit 1; }
    [ -s "$dir/$digest.jsonl" ] || { echo "verify-images: no bundle written for $ref" >&2; exit 1; }
    echo "verify-images: downloaded $dir/$digest.jsonl" >&2
    done_n=$((done_n + 1))
    continue
  fi
  if [ -n "${CI:-}${SECLAB_ATTESTATION_DIR:-}" ] && [ -f "$dir/$digest.jsonl" ]; then
    set -- --bundle "$dir/$digest.jsonl"
    how="bundle"
  else
    set --
    how="online"
  fi
  if out=$(gh attestation verify "oci://docker.io/$ref" --repo "$repo" --signer-workflow "$workflow" "$@" \
       --source-ref "$sref" --source-digest "$sdigest" --deny-self-hosted-runners 2>&1); then
    echo "verify-images: verified $ref (signed by $workflow @ $sref; $how)" >&2
    done_n=$((done_n + 1))
  else
    printf '%s\n' "$out" >&2
    echo "verify-images: FAILED $ref ($how)" >&2
    exit 1
  fi
done <<EOF
$list
EOF
[ "$done_n" -eq "$expected" ] && [ "$done_n" -gt 0 ] || { echo "verify-images: FAILED ($done_n of $expected)" >&2; exit 1; }
echo "verify-images: ok ($done_n attested image(s) $( [ "$mode" = download ] && echo downloaded || echo verified))" >&2
