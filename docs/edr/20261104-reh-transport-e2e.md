# REH transport over `sbx exec -i` stdio works end to end

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** fork-build session
- **Supersedes:** [20261104-reh-transport-exec-stdio](20261104-reh-transport-exec-stdio.md) (viability-only)
- **Related:** [ADR remote extension host](../adr/20261104-reuse-remote-extension-host.md), [ADR tab supervisor](../adr/20261104-tab-supervisor.md)

## Context
The viability spike showed `sbx exec -i` is binary-safe. This record covers
the full path with our own REH (built from 1.145.0) inside an sbx tab, driven
by `seclab-tabd`.

## Decision
Keep exec stdio as the only REH transport.
- The REH listens on `/run/user/1000/seclab/reh.sock` (`--socket-path`,
  `--connection-token-file`) and is started by `/opt/seclab/bin/seclab-reh-start`
  with the token on stdin.
- Each connection is `sbx exec -i -u agent <tab> /opt/seclab/bin/seclab-reh-connect`
  (`socat - UNIX-CONNECT:…`), multiplexed by tabd onto a protocol channel.
- **No fallback to `ports --publish` is needed.**

## Results (`node tabd/test/e2e.ts sbx`)
- Claim, then create the sandbox with 187 mirrored per-sandbox denies, then
  verify the fence, then start the REH: **3.5 s** from a cold template.
- Each `tab.connect` (fence re-verify plus exec) followed by the managed-socket
  upgrade request (exactly what `managedSocket.ts` sends) returned
  `HTTP/1.1 101 Switching Protocols` in **0.49–0.55 s**. A second connection
  reused the same REH.
- Inside the tab: `curl https://api.anthropic.com/` returned **403** (a global
  allow, mirrored as a deny). `agent` has no sudo, and the inner docker.sock
  is not accessible.
- When the client disconnected, the supervisor stopped the sandbox (fail
  closed when no supervisor is present).

## Alternatives considered
- **`ports --publish` plus connection token**: unnecessary; rejected in the
  viability EDR.

## Consequences
- Connect latency is dominated by the fence verify (several `sbx policy`
  invocations). That is acceptable for connect and reconnect.
- The REH log is at `/run/user/1000/seclab/reh.log` inside the tab.
