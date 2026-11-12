#!/bin/sh
# The local CFS build path, tested without CFS (EDR cfs-config-outside-repo). Hosted CI builds
# from public PyPI, so this is what keeps the local path from breaking unseen:
#   A. tools/pybuild.sh reads the host config through build/cfs-config.ts and hands the index to
#      `gh cfs -- docker build` as the BuildKit secret cfs_feed_index (a fake `gh` records the
#      call); a missing, group-readable or malformed config stops the build before gh runs.
#   B. tools/pip-fetch.py in CFS mode, with both secrets mounted where BuildKit puts them,
#      fetches a hash-pinned wheel from a stub feed (TLS, as the feed host, on an --internal
#      network) using Basic cfs:<token>; without the index secret, or with a bad one, it fails.
# Example values only (tools/cfs-config.vectors.json); the token is an obvious canary.
#   broker/tests/cfs-path/run.sh
set -eu
here=$(cd "$(dirname "$0")" && pwd)
broker=$(cd "$here/../.." && pwd)
root=$(cd "$broker/.." && pwd)
NODE_IMAGE=node:24.22.1-trixie@sha256:f1e034976f948cf212ef1f659c12e5dd58ac7eab947831813e81a62401ca38be
PY_IMAGE=python:3.13-slim-trixie@sha256:ae14d4ce8771606477a81446e7ef429edd6762305fc50c84507c1041fa8285d1
id=$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')
# Scratch outside any git repository (the config refuses one inside), never the repo.
base=${RUNNER_TEMP:-$HOME/.cache}
mkdir -p "$base"
scratch=$(mktemp -d "$base/seclab-cfs-path.XXXXXX")
net=seclab-cfspath-$id
stub=seclab-cfspath-stub-$id
cleanup() {
  docker rm -f "$stub" >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  rm -rf "$scratch"
}
trap cleanup EXIT INT TERM
fail() { echo "cfs-path: FAIL: $*" >&2; exit 1; }

vec="$broker/tools/cfs-config.vectors.json"
cfg_json=$(jq -c '.valid[0]' "$vec")
index=$(jq -r '.valid[0].pypiIndex' "$vec")
download=$(jq -r '.valid[0].pypiDownload' "$vec")
index_path=/${index#https://*/}
download_path=/${download#https://*/}

# build/cfs-config.ts needs Node with type stripping; older host Node runs it in the pinned image.
if node -e 'process.exit(+process.versions.node.split(".")[0] >= 23 ? 0 : 1)' 2>/dev/null; then
  node_cmd=node
else
  node_cmd="$scratch/bin/node"
  mkdir -p "$scratch/bin"
  cat > "$node_cmd" <<EOF
#!/bin/sh
exec docker run --rm --network none -u "\$(id -u):\$(id -g)" -e HOME=/tmp -e SECLAB_CFS_CONFIG \\
  -v "$root:$root:ro" -v "$scratch:$scratch:ro" -w "$root" $NODE_IMAGE node "\$@"
EOF
  chmod +x "$node_cmd"
fi

# ---------------------------------------------------------------- A. pybuild wiring
mkdir -p "$scratch/fakegh" "$scratch/cfg"
cat > "$scratch/fakegh/gh" <<'EOF'
#!/bin/sh
printf '%s\n' "$@" > "$GH_RECORD"
printf '%s' "${SECLAB_CFS_FEED_INDEX-UNSET}" > "$GH_RECORD.index"
EOF
chmod +x "$scratch/fakegh/gh"
cfg="$scratch/cfg/cfs.json"
pyb() {
  rm -f "$scratch/gh.rec" "$scratch/gh.rec.index"
  ( PATH="$scratch/fakegh:$PATH" GH_RECORD="$scratch/gh.rec" SECLAB_PIP_SOURCE=cfs SECLAB_REPO_ROOT="$root" \
    SECLAB_NODE="$node_cmd" SECLAB_CFS_CONFIG="$1" CI=; export PATH GH_RECORD SECLAB_PIP_SOURCE SECLAB_REPO_ROOT \
    SECLAB_NODE SECLAB_CFS_CONFIG CI; . "$broker/tools/pybuild.sh"; pybuild -q -t seclab-cfspath:none "$broker" ) \
    2>"$scratch/pyb.err"
}

(umask 077 && printf '%s\n' "$cfg_json" > "$cfg")
pyb "$cfg" || fail "pybuild with a valid config: $(cat "$scratch/pyb.err")"
expect="cfs -- docker build --build-arg PIP_SOURCE=cfs --secret id=cfs_feed_index,env=SECLAB_CFS_FEED_INDEX -q -t seclab-cfspath:none $broker"
[ "$(tr '\n' ' ' < "$scratch/gh.rec" | sed 's/ $//')" = "$expect" ] || fail "pybuild called gh with: $(tr '\n' ' ' < "$scratch/gh.rec")"
[ "$(cat "$scratch/gh.rec.index")" = "$index" ] || fail "the cfs_feed_index secret is not the config's pypiIndex"

check_refused() {
  if pyb "$1"; then fail "pybuild accepted $2"; fi
  [ ! -e "$scratch/gh.rec" ] || fail "pybuild ran gh despite $2"
  grep -q 'run ./seclab cfs config' "$scratch/pyb.err" || fail "no setup hint for $2: $(cat "$scratch/pyb.err")"
}
check_refused "$scratch/cfg/missing.json" "a missing config"
# Each case is a fresh file: Docker Desktop's file sharing caches modes briefly after a chmod.
(umask 027 && printf '%s\n' "$cfg_json" > "$scratch/cfg/readable.json")
check_refused "$scratch/cfg/readable.json" "a group-readable config"
printf '%s\n' "$cfg_json" | jq -c '.pypiIndex |= sub("^https"; "http")' > "$scratch/cfg/bad.json"; chmod 600 "$scratch/cfg/bad.json"
check_refused "$scratch/cfg/bad.json" "a malformed config"
echo "cfs-path: A ok (pybuild passes the config's index as cfs_feed_index; missing, readable or malformed config refused)"

# ---------------------------------------------------------------- B. pip-fetch against a stub feed
mkdir -p "$scratch/tls" "$scratch/secrets" "$scratch/req"
docker run --rm --network none -u "$(id -u):$(id -g)" -v "$scratch/tls:/t" -w /t $NODE_IMAGE sh -c '
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=seclab cfs-path test CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" -keyout ca.key -out ca.pem 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -subj "/CN=feed" -keyout server.key -out server.csr 2>/dev/null
  printf "subjectAltName=DNS:pkgs.dev.azure.com\nextendedKeyUsage=serverAuth\n" > ext.cnf
  openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 1 -extfile ext.cnf -out server.pem 2>/dev/null
  chmod 644 server.key'
token="seclab-canary-cfs-path-$id$id"
printf '%s' "$token" > "$scratch/secrets/cfs_feed_token"
hash=$(docker run --rm --network none -v "$here/stub_index.py:/srv/stub_index.py:ro" $PY_IMAGE python3 /srv/stub_index.py --hash)
printf 'seclab-cfs-probe==1.0 --hash=sha256:%s\n' "$hash" > "$scratch/req/requirements.txt"

docker network create --internal "$net" >/dev/null
docker run -d --name "$stub" --network "$net" --network-alias pkgs.dev.azure.com \
  -v "$here/stub_index.py:/srv/stub_index.py:ro" -v "$scratch/tls:/srv/tls:ro" \
  $PY_IMAGE python3 /srv/stub_index.py "$index_path" "$download_path" "$token" >/dev/null
for _ in $(seq 1 50); do docker logs "$stub" 2>&1 | grep -q 'stub index ready' && break; sleep 0.2; done

fetch() {  # $1: index secret file, or "" for none
  docker run --rm --network "$net" --tmpfs /run/cfs-auth -e PIP_SOURCE=cfs -e SSL_CERT_FILE=/srv/tls/ca.pem \
    -v "$scratch/tls:/srv/tls:ro" -v "$scratch/secrets/cfs_feed_token:/run/secrets/cfs_feed_token:ro" \
    ${1:+-v "$1:/run/secrets/cfs_feed_index:ro"} \
    -v "$broker/tools/pip-fetch.py:/opt/pipfetch/pip-fetch.py:ro" \
    -v "$scratch/req/requirements.txt:/opt/pipfetch/requirements.txt:ro" \
    $PY_IMAGE sh -c 'python3 -I /opt/pipfetch/pip-fetch.py /opt/pipfetch/requirements.txt && ls /wheels'
}

printf '%s' "$index" > "$scratch/secrets/cfs_feed_index"
out=$(fetch "$scratch/secrets/cfs_feed_index" 2>&1) || fail "pip-fetch against the stub feed: $out"
printf '%s\n' "$out" | grep -qx 'seclab_cfs_probe-1.0-py3-none-any.whl' || fail "the wheel was not fetched: $out"
case "$out" in *"$token"*) fail "the token appeared in pip-fetch's output";; esac
log=$(docker exec "$stub" cat /srv/requests.log)
printf '%s\n' "$log" | grep -q "^${index_path}seclab-cfs-probe/ auth=ok" || fail "the index was not read with the token: $log"
printf '%s\n' "$log" | grep -q "^${download_path}seclab-cfs-probe/1.0/.* auth=ok" || fail "the wheel was not fetched with the token: $log"

out=$(fetch "" 2>&1) && fail "pip-fetch ran without the cfs_feed_index secret"
case "$out" in *"needs the cfs_feed_index secret"*) ;; *) fail "no clear message without the index secret: $out";; esac
printf '%s' "https://feed.example.test${index_path}" > "$scratch/secrets/bad_index"
out=$(fetch "$scratch/secrets/bad_index" 2>&1) && fail "pip-fetch accepted an index on another host"
case "$out" in *"malformed cfs_feed_index secret"*) ;; *) fail "no clear message for a bad index: $out";; esac
echo "cfs-path: B ok (pip-fetch fetched the hash-pinned wheel from the stub feed with Basic auth; no or bad index secret refused)"
