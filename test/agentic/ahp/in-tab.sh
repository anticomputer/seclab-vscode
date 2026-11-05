#!/usr/bin/env bash
# Agents-in-the-tab spike, step 2: start the agent host from our shipped REH build offline
# in a network-less container (stand-in for the fenced tab until tab-broker wiring lands),
# and observe it with the real upstream client. No real credential: authenticate carries
# a seclab sentinel. Writes .work/agentic/runs/<id>-intab/.
#
#   test/agentic/ahp/in-tab.sh
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
IMG='node:24.22.1-trixie@sha256:f1e034976f948cf212ef1f659c12e5dd58ac7eab947831813e81a62401ca38be'
NONCE="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
RUN="$ROOT/.work/agentic/runs/$(date -u +%Y%m%dT%H%M%SZ)-$NONCE-intab"
mkdir -p "$RUN"
status=0
docker run --rm --network none -u "$(id -u):$(id -g)" \
	-v seclab-vscode-work:/shared:ro \
	-v "$ROOT/.work/vscode":/src:ro \
	-v "$ROOT/test/agentic/ahp":/harness:ro \
	-v "$RUN":/run \
	-e RUN_DIR=/run -e AH_ADDRESS=127.0.0.1:8081 -e AH_TOKEN="ah-$NONCE" -e SENTINEL="seclab-sentinel-github-$NONCE" -e PROXY_MODE="${PROXY_MODE:-proxy+ca}" \
	"$IMG" sh -c '
set -e
export HOME=/run/home; mkdir -p "$HOME" /run/logs /run/ud /run/ca
REH=/shared/vscode-reh-linux-arm64
# Per-run test CA and one leaf for the hosts the runtime contacts. The recorder below
# serves it; nothing is contacted (no network).
cd /run/ca
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 1 -subj "/CN=seclab spike test CA" -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout leaf.key -out leaf.csr -subj "/CN=seclab-spike-leaf" 2>/dev/null
printf "subjectAltName=DNS:api.github.com,DNS:*.github.com,DNS:api.githubcopilot.com,DNS:*.githubcopilot.com,DNS:*.individual.githubcopilot.com\nextendedKeyUsage=serverAuth\n" > leaf.ext # fixture-lint: allow non-test-host -- certificate names for the loopback recorder; never contacted
openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out leaf.pem -days 1 -extfile leaf.ext 2>/dev/null
cat /etc/ssl/certs/ca-certificates.crt ca.pem > bundle.pem
cd /
node /harness/proxy-recorder.mjs 3128 /run/ca/leaf.key /run/ca/leaf.pem /run/proxy-events.json &
PROXY="HTTPS_PROXY=http://127.0.0.1:3128 https_proxy=http://127.0.0.1:3128 HTTP_PROXY=http://127.0.0.1:3128 http_proxy=http://127.0.0.1:3128 NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost"
case "$PROXY_MODE" in
	none) AHENV="" ;;
	proxy+ca) AHENV="$PROXY SSL_CERT_FILE=/run/ca/bundle.pem NODE_EXTRA_CA_CERTS=/run/ca/ca.pem" ;;
	proxy+sslcertfile) AHENV="$PROXY SSL_CERT_FILE=/run/ca/bundle.pem" ;;
	proxy+nodeextra) AHENV="$PROXY NODE_EXTRA_CA_CERTS=/run/ca/ca.pem" ;;
	proxy-noca) AHENV="$PROXY" ;;
	*) echo "unknown PROXY_MODE" >&2; exit 2 ;;
esac
export VSCODE_NLS_CONFIG="{\"userLocale\":\"en\",\"osLocale\":\"en\",\"resolvedLanguage\":\"en\",\"defaultMessagesFile\":\"$REH/out/nls.messages.json\",\"locale\":\"en\",\"availableLanguages\":{}}"
( cd "$REH" && env $AHENV VSCODE_ESM_ENTRYPOINT=vs/platform/agentHost/node/agentHostMain VSCODE_PIPE_LOGGING=true VSCODE_VERBOSE_LOGGING=true \
	VSCODE_AGENT_HOST_PORT=8081 VSCODE_AGENT_HOST_HOST=127.0.0.1 VSCODE_AGENT_HOST_CONNECTION_TOKEN="$AH_TOKEN" \
	timeout 60 ./node out/bootstrap-fork.js --logsPath /run/logs --user-data-dir /run/ud > /run/agent-host.stdout 2>&1 & )
MODE=baseline ENTRY=/harness/in-tab.ts OUT=/run/in-tab.mjs node /harness/bundle.mjs
for i in $(seq 1 50); do grep -q "listening" /run/agent-host.stdout 2>/dev/null && break; sleep 0.2; done
node /run/in-tab.mjs
echo "--- proxy events"; cat /run/proxy-events.json
' || status=$?
rm -f "$RUN/in-tab.mjs"
echo "run: $RUN (exit $status)"
exit $status
