#!/bin/sh
# Negative tests for broker/tools/verify-images.sh (finding provenance #3: a failing register
# reader once gave an empty loop and exit 0, and build.sh then built unverified). The real script
# runs in a scratch tree against crafted registers, with a fake `gh` on PATH that records each
# call and answers as the case says; no network. Every case that must fail must exit non-zero
# without printing "ok"; the passing case must call `gh attestation verify` once per attested
# image with exactly the register's signer, source ref, source digest and the self-hosted ban.
#   broker/tests/verify-images/run.sh
set -eu
here=$(cd "$(dirname "$0")" && pwd)
broker=$(cd "$here/../.." && pwd)
base=${RUNNER_TEMP:-$broker/../.work}
mkdir -p "$base"
scratch=$(mktemp -d "$base/seclab-verify-images.XXXXXX")
trap 'rm -rf "$scratch"' EXIT INT TERM
fails=0
fail() { echo "verify-images tests: FAIL [$1]: $2" >&2; fails=$((fails + 1)); }

mkdir -p "$scratch/bin"
cat > "$scratch/bin/gh" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$GH_LOG"
case "${GH_MODE:-ok}:$*" in
  fail-second:*sha256:2222*) echo "fake gh: verification failed" >&2; exit 1 ;;
esac
exit 0
EOF
chmod +x "$scratch/bin/gh"

D1=sha256:1111111111111111111111111111111111111111111111111111111111111111
D2=sha256:2222222222222222222222222222222222222222222222222222222222222222
img() {  # name digest tier [verify-kind] [repo]
  printf '{"name":"%s","ref":"%s:1.0@%s","tier":"%s","verify":{"kind":"%s","repo":"%s","signerWorkflow":"%s/.github/workflows/release.yml","sourceRef":"refs/tags/v1.0","sourceDigest":"0123456789abcdef0123456789abcdef01234567"}}' \
    "$1" "$1" "$2" "$3" "${4:-github-attestation}" "${5:-example/$1}" "${5:-example/$1}"
}
GOOD="{\"images\":[$(img example/one $D1 attested),$(img example/two $D2 attested),$(img example/plain $D1 hash-pinned)]}"

run_case() {  # name, deps.json content, gh mode, expect (ok|fail), [stderr must contain]
  t=$scratch/$(printf %s "$1" | tr -c 'A-Za-z0-9' _)
  mkdir -p "$t/tools"
  cp "$broker/tools/verify-images.sh" "$t/tools/verify-images.sh"
  printf '%s' "$2" > "$t/deps.json"
  : > "$t/gh.log"
  if PATH="$scratch/bin:$PATH" GH_LOG="$t/gh.log" GH_MODE=$3 CI= SECLAB_ATTESTATION_DIR= \
     sh "$t/tools/verify-images.sh" > "$t/out" 2> "$t/err"; then rc=0; else rc=$?; fi
  case $4 in
    ok) [ "$rc" -eq 0 ] && grep -q 'verify-images: ok (2 attested' "$t/err" || fail "$1" "exit $rc: $(cat "$t/err")" ;;
    fail)
      [ "$rc" -ne 0 ] || fail "$1" "exited 0"
      ! grep -q 'verify-images: ok' "$t/err" || fail "$1" "printed ok"
      [ -z "${5:-}" ] || grep -q -- "$5" "$t/err" || fail "$1" "no '$5' in: $(cat "$t/err")" ;;
  esac
}

# The passing case, and what it asked gh to check.
run_case "every attested image verified against the register" "$GOOD" ok ok
t=$scratch/every_attested_image_verified_against_the_register
[ "$(grep -c '^attestation verify ' "$t/gh.log")" -eq 2 ] || fail "register binding" "gh verify calls: $(cat "$t/gh.log")"
for pair in "$D1 one" "$D2 two"; do
  dg=${pair%% *}; n=${pair#* }; ns=example
  # The register's repo field is the image name prefixed by the fixture owner (see img()).
  grep -q -- "^attestation verify oci://docker.io/$ns/$n@$dg --repo $ns/$ns/$n --signer-workflow $ns/$ns/$n/.github/workflows/release.yml --source-ref refs/tags/v1.0 --source-digest 0123456789abcdef0123456789abcdef01234567 --deny-self-hosted-runners$" "$t/gh.log" \
    || fail "register binding" "no exact verify call for $dg: $(cat "$t/gh.log")"
done

# Fail closed: the register reader, the list, and each verification.
run_case "the register reader fails (not JSON): no empty pass" '{"images": [' ok fail
run_case "no attested image in the register" "{\"images\":[$(img example/plain $D1 hash-pinned)]}" ok fail "no attested images"
run_case "an empty register" '{"images":[]}' ok fail "no attested images"
run_case "an unsupported verify kind" "{\"images\":[$(img example/one $D1 attested cosign)]}" ok fail "unsupported verify kind"
run_case "a ref without a digest" '{"images":[{"name":"x","ref":"example/x:1.0","tier":"attested","verify":{"kind":"github-attestation","repo":"example/x","signerWorkflow":"w","sourceRef":"r","sourceDigest":"d"}}]}' ok fail "malformed ref"
run_case "a verify field with shell metacharacters" "{\"images\":[$(img example/one $D1 attested github-attestation 'example/one;true')]}" ok fail "malformed ref or verify fields"
run_case "one image fails verification" "$GOOD" fail-second fail "FAILED example/two"

[ "$fails" -eq 0 ] || exit 1
echo "verify-images tests: ok (1 pass with exact register binding; 7 fail-closed cases)"
