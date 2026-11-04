#!/bin/sh
# Validate the broker behind the sbx fence (Docker Sandboxes). Host tools used:
# docker and sbx only. The broker runs on Docker Desktop, published on
# 127.0.0.1:$P; the sandbox may reach only localhost:$P (per-sandbox allow).
# Global sbx policy is never changed. Results: .work/broker/sbx-validation/.
# Usage: broker/tests/sbx/validate.sh
set -eu
here=$(cd "$(dirname "$0")" && pwd)
broker_dir=$(cd "$here/../.." && pwd)
repo=$(cd "$broker_dir/.." && pwd)
P=${P:-18480}
P2=$((P + 1))
tag=brkval
sb=seclab-$tag
out="$repo/.work/broker/sbx-validation"
rm -rf "$out"
mkdir -p "$out/ws"
: > "$out/results.txt"
: > "$out/tab-output.txt"

cleanup() {
  sbx rm -f "$sb" >/dev/null 2>&1 || sbx rm "$sb" >/dev/null 2>&1 || true
  for c in upstream broker broker2; do docker rm -f "seclab-$tag-$c" >/dev/null 2>&1 || true; done
  for n in inet egress egress2; do docker network rm "seclab-$tag-$n" >/dev/null 2>&1 || true; done
}
trap cleanup EXIT
cleanup

docker build -q --target broker -t seclab-broker:test "$broker_dir" >/dev/null
docker build -q -t seclab-broker-it-upstream:test "$broker_dir/tests/integration/images/upstream" >/dev/null
docker build -q -t seclab-broker-it-harness:test -f "$broker_dir/tests/integration/images/harness/Dockerfile" \
  "$broker_dir/tests/integration" >/dev/null

API_CANARY="seclab-canary-api-$(openssl rand -hex 16)"
GIT_CANARY="seclab-canary-git-$(openssl rand -hex 16)"
SECLAB_PW=$(openssl rand -base64 24 | tr '+/' '-_' | tr -d '=\n')
export API_CANARY GIT_CANARY SECLAB_PW

docker network create --subnet 11.251.7.0/24 "seclab-$tag-inet" >/dev/null
docker network create -o com.docker.network.bridge.enable_icc=false "seclab-$tag-egress" >/dev/null
docker network create -o com.docker.network.bridge.enable_icc=false "seclab-$tag-egress2" >/dev/null
docker run -d --name "seclab-$tag-upstream" --network "seclab-$tag-inet" \
  --network-alias api.example.test --network-alias gist.example.test \
  --network-alias git.example.test --network-alias blocked.example.test \
  -e "UPSTREAM_GIT_TOKEN=$GIT_CANARY" seclab-broker-it-upstream:test >/dev/null
i=0
until docker exec "seclab-$tag-upstream" test -s /srv/tls/ca.pem 2>/dev/null; do
  i=$((i + 1)); [ $i -lt 100 ] || { echo "upstream never ready"; exit 1; }; sleep 0.2
done
UP_CA=$(docker exec "seclab-$tag-upstream" cat /srv/tls/ca.pem)

hardening="--read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit 256"
tmpfs="/run/seclab:rw,nosuid,nodev,noexec,size=16m,uid=1000,gid=1000,mode=0700"
# shellcheck disable=SC2086
docker create --name "seclab-$tag-broker" --network "seclab-$tag-egress" -p "127.0.0.1:$P:8080" \
  $hardening --tmpfs "$tmpfs" -e SECLAB_TAB_ID=sbx-validation -e "SECLAB_EXTRA_UPSTREAM_CA_PEM=$UP_CA" \
  seclab-broker:test >/dev/null
docker network connect "seclab-$tag-inet" "seclab-$tag-broker"
docker start "seclab-$tag-broker" >/dev/null
# A second tab's broker, to prove one tab cannot reach another's.
# shellcheck disable=SC2086
docker run -d --name "seclab-$tag-broker2" --network "seclab-$tag-egress2" -p "127.0.0.1:$P2:8080" \
  $hardening --tmpfs "$tmpfs" seclab-broker:test >/dev/null

ctl() {
  docker run --rm -i -v /var/run/docker.sock:/var/run/docker.sock -v "$here/ctl.py:/ctl.py:ro" \
    -v "$out:/out" -e SECLAB_PW -e API_CANARY -e GIT_CANARY --entrypoint python \
    seclab-broker-it-harness:test /ctl.py "$1" "seclab-$tag-broker" /out
}
ctl setup
# shellcheck disable=SC1091
. "$out/env"

sbx create --name "$sb" --no-progress shell "$out/ws" >/dev/null
sbx policy allow network --sandbox "$sb" "localhost:$P" >/dev/null
sbx exec -i -u root "$sb" sh -c 'cat > /usr/local/share/ca-certificates/seclab-tab.crt && update-ca-certificates >/dev/null' \
  < "$out/ca.pem"

PROXY="http://seclab:$SECLAB_PW@host.docker.internal:$P"
inbroker() {  # run in the tab with both cases of the proxy variables pointed at the broker
  sbx exec -e "HTTPS_PROXY=$PROXY" -e "https_proxy=$PROXY" -e "HTTP_PROXY=$PROXY" -e "http_proxy=$PROXY" \
    -e "NO_PROXY=localhost,127.0.0.1,::1" -e "no_proxy=localhost,127.0.0.1,::1" -e "API_SENTINEL=$API_SENTINEL" \
    -e "GIT_SENTINEL=$GIT_SENTINEL" "$sb" sh -c "$1" 2>&1 | tee -a "$out/tab-output.txt"
}
raw() { sbx exec "$sb" sh -c "$1" 2>&1 | tee -a "$out/tab-output.txt"; }
check() {  # name expected actual
  if [ "$2" = "$3" ]; then r=PASS; else r=FAIL; fi
  printf '%s  %-58s expected=%s actual=%s\n' "$r" "$1" "$2" "$3" | tee -a "$out/results.txt"
}
code() { inbroker "curl -s -o /dev/null --max-time 15 -w '%{http_code}' $1" | tail -c 3; }

check "allowed host through broker (CONNECT chain via sbx)" 200 "$(code https://api.example.test/echo/x)"
check "default deny" 403 "$(code https://blocked.example.test/echo/x)"
check "HTTP/2 through broker" 2 "$(inbroker "curl -s -o /dev/null --http2 -w '%{http_version}' https://api.example.test/echo/h2" | tail -c 1)"
want=$(printf 'Bearer %s' "$API_CANARY" | shasum -a 256 | cut -d' ' -f1)
got=$(inbroker 'curl -s -H "Authorization: Bearer $API_SENTINEL" https://api.example.test/echo/repos/o/r' \
  | sed -n 's/.*"auth_sha256": "\([0-9a-f]*\)".*/\1/p')
check "sentinel swapped on binding match" "$want" "$got"
check "sentinel on wrong path not swapped (blocked)" 403 \
  "$(code "-H \"Authorization: Bearer \$API_SENTINEL\" https://api.example.test/echo/other")"
check "sentinel posted to unbound allowed host (gist) blocked" 403 \
  "$(code "-X POST -d \"t=\$API_SENTINEL\" https://gist.example.test/gists")"
check "wrong proxy password -> 407" 407 "$(inbroker "env -u HTTPS_PROXY -u https_proxy curl -s -o /dev/null -w '%{http_connect}' \
  -x http://seclab:wrong-password-wrong-pw@host.docker.internal:$P https://api.example.test/" | tail -c 3)"
check "no proxy credentials -> 407" 407 "$(inbroker "env -u HTTPS_PROXY -u https_proxy curl -s -o /dev/null -w '%{http_connect}' \
  -x http://host.docker.internal:$P https://api.example.test/" | tail -c 3)"
r=$(inbroker "env -u HTTPS_PROXY -u https_proxy curl -s -o /dev/null --max-time 10 -w '%{http_connect}' \
  -x http://seclab:$SECLAB_PW@host.docker.internal:$P2 https://api.example.test/; echo \" rc=\$?\"")
check "other tab's broker port is not reachable" blocked "$(echo "$r" | grep -Eq '^(000|403) rc=|rc=[1-9]' && echo blocked || echo "$r")"
r=$(raw "env -u HTTPS_PROXY -u https_proxy -u HTTP_PROXY -u http_proxy curl -s -o /dev/null --max-time 5 \
  -w '%{http_code}' http://host.docker.internal:$P2/; echo \" rc=\$?\"")
check "direct to other loopback port blocked" blocked "$(echo "$r" | grep -Eq 'rc=[1-9]|^403' && echo blocked || echo "$r")"
r=$(raw "env -u HTTPS_PROXY -u https_proxy -u HTTP_PROXY -u http_proxy curl -s -o /dev/null --max-time 5 \
  -w '%{http_code}' http://host.docker.internal:22/; echo \" rc=\$?\"")
check "direct to host.docker.internal:22 blocked" blocked "$(echo "$r" | grep -Eq 'rc=[1-9]|^403' && echo blocked || echo "$r")"
r=$(raw "curl -s -o /dev/null --max-time 10 -w '%{http_code}' https://api.example.test/; echo \" rc=\$?\"")
check "sbx's own proxy cannot reach broker-only upstreams" blocked "$(echo "$r" | grep -Eq 'rc=[1-9]|^(000|403|502|503)' && echo blocked || echo "$r")"
r=$(raw "getent hosts api.example.test >/dev/null; echo rc=\$?")
check "tab cannot resolve broker-side names" "rc=2" "$(echo "$r" | tail -n1)"
r=$(raw "getent hosts example.com >/dev/null; echo rc=\$?")
printf 'INFO  tab resolves public names directly: %s\n' "$(echo "$r" | tail -n1)" | tee -a "$out/results.txt"

inbroker "git config --global credential.helper '!f() { echo username=x-access-token; echo password=\$GIT_SENTINEL; }; f'" >/dev/null
r=$(inbroker "cd /tmp && rm -rf demo && git clone -q https://git.example.test/demo.git demo && cat demo/README")
check "git clone over HTTPS with sentinel" "hello from the test upstream" "$(echo "$r" | tail -n1)"

ctl audit
if grep -F -q -e "$API_CANARY" -e "$GIT_CANARY" "$out/tab-output.txt" "$out/audit.json"; then
  check "no canary in tab output or audit" none found
else
  check "no canary in tab output or audit" none none
fi
docker logs "seclab-$tag-broker" > "$out/broker.log" 2>&1
sbx policy log "$sb" > "$out/sbx-policy-log.txt" 2>&1 || true
echo "results: $out/results.txt"
! grep -q '^FAIL' "$out/results.txt"
