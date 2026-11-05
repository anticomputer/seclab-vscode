#!/bin/sh
# Containment probe. Every malicious-workspace vector (and the rogue extension) runs
# this. It records WHERE it ran and WHAT it could reach as JSON in
# .seclab-evidence/<vector>.json inside the workspace. The harness checks the evidence
# (and the host side) afterwards. It must never succeed at anything it tries.
# Usage: probe.sh <vector>
#
# Fixture safety (AGENTS.md; EDR fixture-safety): inert unless armed by a harness run
# (.seclab/targets with a per-run nonce, and this workspace inside that run's dir). Even
# if containment failed it only reads harness-seeded canaries, writes one fixed marker
# under the run's .work dir, and talks only to the run's loopback beacon or to
# non-routable test addresses (RFC 5737, *.example.test).
VECTOR="$(printf '%s' "${1:-unknown}" | tr -cd 'a-z0-9-')"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
TARGETS="$HERE/.seclab/targets"

get() { sed -n "s/^$1=//p" "$TARGETS" 2>/dev/null | head -1; }
ARM="$(get arm)"
RUN="$(get run)"
UNTIL="$(get until)"
# Armed only by a harness run: exact 32-hex nonce, an absolute run dir containing this
# workspace, an unexpired arming window, and every target path inside the run dir.
printf '%s' "$ARM" | grep -qE '^[0-9a-f]{32}$' || exit 0
case "$RUN" in /?*) ;; *) exit 0 ;; esac
case "$HERE/" in "$RUN"/*) ;; *) exit 0 ;; esac
case "$UNTIL" in ''|*[!0-9]*) exit 0 ;; esac
[ "$(date +%s)" -lt "$UNTIL" ] || exit 0
inrun() { [ -z "$1" ] && return 0; case "$1" in *'/..'*|*'../'*) return 1 ;; "$RUN"/*) return 0 ;; *) return 1 ;; esac; }

OUT="$HERE/.seclab-evidence"
mkdir -p "$OUT"
clean() { printf '%s' "$1" | tr -cd 'A-Za-z0-9._:/@+= -' | cut -c1-200; }
# The HTTP client's name lives in .seclab/probe.parts.json, so no host file pairs this
# folder-open task with a literal fetch tool (endpoint protection keys on that shape; EDR fixture-safety).
HTTP="$(sed -n 's/.*"http" *: *"\([a-z]*\)".*/\1/p' "$HERE/.seclab/probe.parts.json" 2>/dev/null | head -1)"
code() { [ -n "$HTTP" ] || return 0; "$HTTP" -s -m 6 -o /dev/null -w '%{http_code}' "$@" 2>/dev/null || true; }

CANARY="$(get canary)"
OTHERTAB="$(get othertab)"
MARKER="$(get marker)"
LOOPBACK="$(get loopback)"
inrun "$CANARY" && inrun "$OTHERTAB" && inrun "$MARKER" || exit 0
case "$LOOPBACK" in ''|*[!0-9]*) LOOPBACK= ;; esac

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
# Lists privileges only (never executes anything as root, even on a host).
command -v sudo >/dev/null 2>&1 && sudo -n -l >/dev/null 2>&1 && sudo_ok=yes
secret_env="$(env | cut -d= -f1 | grep -E 'TOKEN|_KEY$|SECRET|PASSWORD|SSH_AUTH_SOCK|GITHUB_|AWS_' | tr '\n' ' ')"
# REH plumbing that bridges back to the UI (git askpass -> UI auth providers): reported
# separately as a known M4 gap. ELECTRON_RUN_AS_NODE is a mode flag, not a secret.
ui_bridge="$(env | cut -d= -f1 | grep -E '^VSCODE_GIT_(IPC_HANDLE|ASKPASS)' | tr '\n' ' ')"

# Egress: everything must fail. Using the env proxies (as tools do) and directly. Targets
# are non-routable test addresses (RFC 5737) or reserved names, so even an escaped probe
# reaches nothing real. Whether sbx's global allows are fenced off is checked with
# `sbx policy check` by the harness, not by connecting to those hosts.
TESTNET=http://192.0.2.1/
eg_testnet="$(code "$TESTNET")"
eg_testnet_direct="$(code --noproxy '*' "$TESTNET")"
eg_name="$(code https://egress.example.test/)"
eg_name_direct="$(code --noproxy '*' https://egress.example.test/)"
eg_sbx_proxy="$(code -x http://gateway.docker.internal:3128 "$TESTNET")"
eg_hostloop=""
[ -n "$LOOPBACK" ] && eg_hostloop="$(code --noproxy '*' "http://host.docker.internal:$LOOPBACK/")"
eg_hostloop_proxy=""
[ -n "$LOOPBACK" ] && eg_hostloop_proxy="$(code "http://host.docker.internal:$LOOPBACK/")"
dns_external="$(getent hosts dns-probe.example.test >/dev/null 2>&1 && echo resolved || echo blocked)"

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
    "testnet_via_env_proxy": "$eg_testnet",
    "testnet_direct": "$eg_testnet_direct",
    "reserved_name_via_env_proxy": "$eg_name",
    "reserved_name_direct": "$eg_name_direct",
    "testnet_via_sbx_proxy": "$eg_sbx_proxy",
    "host_loopback_direct": "$eg_hostloop",
    "host_loopback_via_env_proxy": "$eg_hostloop_proxy",
    "dns_external": "$dns_external"
  }
}
EOF
