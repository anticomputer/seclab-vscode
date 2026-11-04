#!/bin/sh
# Containment probe. Every malicious-workspace vector (and the rogue extension) runs
# this. It records WHERE it ran and WHAT it could reach as JSON in
# .seclab-evidence/<vector>.json inside the workspace. The harness checks the evidence
# (and the host side) afterwards. It must never succeed at anything it tries.
# Usage: probe.sh <vector>
VECTOR="$(printf '%s' "${1:-unknown}" | tr -cd 'a-z0-9-')"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$HERE/.seclab-evidence"
mkdir -p "$OUT"
TARGETS="$HERE/.seclab/targets"

get() { sed -n "s/^$1=//p" "$TARGETS" 2>/dev/null | head -1; }
clean() { printf '%s' "$1" | tr -cd 'A-Za-z0-9._:/@+= -' | cut -c1-200; }
code() { curl -s -m 6 -o /dev/null -w '%{http_code}' "$@" 2>/dev/null || true; }

CANARY="$(get canary)"
OTHERTAB="$(get othertab)"
MARKER="$(get marker)"
LOOPBACK="$(get loopback)"

canary_read=no
[ -n "$CANARY" ] && cat "$CANARY" >/dev/null 2>&1 && canary_read=yes
othertab_read=no
[ -n "$OTHERTAB" ] && cat "$OTHERTAB" >/dev/null 2>&1 && othertab_read=yes
host_write=attempted
[ -n "$MARKER" ] && { echo "pwned by $VECTOR" > "$MARKER"; } 2>/dev/null
docker_sock=no
for s in /var/run/docker.sock /run/docker.sock "$HOME/.docker/run/docker.sock"; do
	[ -S "$s" ] && [ -w "$s" ] && docker_sock=yes
done
sudo_ok=no
command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1 && sudo_ok=yes
secret_env="$(env | cut -d= -f1 | grep -E 'TOKEN|_KEY$|SECRET|PASSWORD|SSH_AUTH_SOCK|GITHUB_|AWS_' | tr '\n' ' ')"
# REH plumbing that bridges back to the UI (git askpass -> UI auth providers): reported
# separately as a known M4 gap. ELECTRON_RUN_AS_NODE is a mode flag, not a secret.
ui_bridge="$(env | cut -d= -f1 | grep -E '^VSCODE_GIT_(IPC_HANDLE|ASKPASS)' | tr '\n' ' ')"

# Egress: everything must fail. Using the env proxies (as tools do) and directly.
eg_example="$(code https://example.com/)"
eg_example_direct="$(code --noproxy '*' https://example.com/)"
eg_global_allow="$(code https://api.anthropic.com/)"
eg_global_allow_direct="$(code --noproxy '*' https://api.anthropic.com/)"
eg_sbx_proxy="$(code -x http://gateway.docker.internal:3128 https://api.anthropic.com/)"
eg_hostloop=""
[ -n "$LOOPBACK" ] && eg_hostloop="$(code --noproxy '*' "http://host.docker.internal:$LOOPBACK/")"
eg_hostloop_proxy=""
[ -n "$LOOPBACK" ] && eg_hostloop_proxy="$(code "http://host.docker.internal:$LOOPBACK/")"
dns_external="$(getent hosts example.com >/dev/null 2>&1 && echo resolved || echo blocked)"

cat > "$OUT/$VECTOR.json" <<EOF
{
  "vector": "$VECTOR",
  "hostname": "$(clean "$(uname -n)")",
  "uid": "$(id -u)",
  "user": "$(clean "$(id -un)")",
  "seclab_tab_env": "$(clean "${SECLAB_TAB:-}")",
  "kernel": "$(clean "$(uname -sr)")",
  "pid1": "$(clean "$(tr '\0' ' ' < /proc/1/cmdline 2>/dev/null)")",
  "canary_read": "$canary_read",
  "othertab_read": "$othertab_read",
  "host_write": "$host_write",
  "docker_sock_writable": "$docker_sock",
  "sudo": "$sudo_ok",
  "secret_env": "$(clean "$secret_env")",
  "ui_bridge": "$(clean "$ui_bridge")",
  "http_proxy": "$(clean "${http_proxy:-}")",
  "HTTPS_PROXY": "$(clean "${HTTPS_PROXY:-}")",
  "egress": {
    "example_via_env_proxy": "$eg_example",
    "example_direct": "$eg_example_direct",
    "global_allow_via_env_proxy": "$eg_global_allow",
    "global_allow_direct": "$eg_global_allow_direct",
    "global_allow_via_sbx_proxy": "$eg_sbx_proxy",
    "host_loopback_direct": "$eg_hostloop",
    "host_loopback_via_env_proxy": "$eg_hostloop_proxy",
    "dns_external": "$dns_external"
  }
}
EOF
