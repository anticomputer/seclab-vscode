# REH transport over `exec -i` stdio (viability spike)

- **Status:** superseded-by [20261104-reh-transport-e2e](20261104-reh-transport-e2e.md) (viability confirmed end to end)
- **Date:** 2026-11-04
- **Deciders:** fork-build session
- **Related:** [ADR remote extension host](../adr/20261104-reuse-remote-extension-host.md)

## Context
The `seclab` resolver returns a `ManagedResolvedAuthority`. VS Code opens one
managed socket per REH connection (management, extension host, and so on) and
writes a raw HTTP upgrade (`GET ws://localhost/?…&skipWebSocketFrames=true`)
followed by protocol bytes. We want each connection to be `<runtime> exec -i
<tab> socat - UNIX-CONNECT:/run/seclab/reh.sock`, with the REH started with
`--socket-path`. Then there is no host listener and no published port.

## Decision
Use exec stdio as the transport for both providers (`sbx exec -i`,
`docker exec -i`). Fall back to `ports --publish` plus a connection token only
if end-to-end testing shows exec stdio is unworkable, and document why.

## Results
- Binary safety: a 5 MB random blob round-tripped through
  `sbx exec -i seclab-spike-a cat` with a matching SHA-256 in 0.17 s.
- Per-exec overhead: `sbx exec -i <tab> true` takes 0.12–0.17 s. It is paid
  once per REH connection (initial and reconnect), not per message.
- The sbx `shell` kit already ships `socat`.

## Alternatives considered
- **`ports --publish` plus connection token**: rejected unless forced. It
  needs a host listener reachable by every local process.
- **SSH (`sbx setup ssh`)**: rejected. It adds an sshd, keys and a listener.

## Consequences
- Each managed connection is one child process (`sbx` or `docker`) in the
  local extension host. The Tab Manager must kill it on `end()` or close, and
  surface stderr in its log.

## Evidence
```
$ head -c 5000000 /dev/urandom > blob.bin
$ time (sbx exec -i seclab-spike-a cat < blob.bin > back.bin)   # real 0m0.169s
$ shasum -a 256 blob.bin back.bin                               # identical (b4136cc6404011a5…)
$ /usr/bin/time -p sbx exec -i seclab-spike-a true              # real 0.12 / 0.16 / 0.17
```
Managed socket handshake: [managedSocket.ts](https://github.com/microsoft/vscode/blob/6e35f5ceffa04ac728a0fb3a0dd6fb9cdb4ff100/src/vs/platform/remote/common/managedSocket.ts#L20-L30), [extHostTunnelService.ts ExtHostManagedSocket](https://github.com/microsoft/vscode/blob/6e35f5ceffa04ac728a0fb3a0dd6fb9cdb4ff100/src/vs/workbench/api/node/extHostTunnelService.ts#L377-L399)
