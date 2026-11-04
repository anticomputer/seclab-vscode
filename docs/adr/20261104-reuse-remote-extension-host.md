# Reuse the remote extension host split via a built-in `seclab+` resolver

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** anticomputer (user); seclab-vscode coordinator

## Context
VS Code already separates the trusted UI (sandboxed renderer plus Electron
main) from a **remote extension host (REH)** that can run on another machine or
container. Workspace-kind extensions, tasks, terminals, debug adapters, LSPs,
git and MCP stdio servers all run on the REH side. That split exists for
connectivity, not security, but it is the seam we need.

## Decision
Every tab is a remote window whose REH runs inside that tab's sandbox.
- A **built-in, UI-side "Tab Manager" extension** registers the `seclab`
  resolver prefix (authority `seclab+<tabId>`). It is granted the `resolvers`
  proposed API through `product.json#extensionEnabledApiProposals`.
- The resolver returns a **`ManagedResolvedAuthority`**. Each REH connection is
  a byte stream over `<runtime> exec -i … socat - UNIX-CONNECT:<sock>` stdio.
  The REH listens on a Unix socket inside the sandbox, so nothing listens on
  the host and the sandbox publishes no ports. Each tab gets its own
  connection token.
- The REH is built from the **same pinned Code-OSS source** as the editor
  (`gulp vscode-reh-linux-<arch>`). Microsoft's VS Code Server and Remote
  extensions are never used, because their licence restricts them to Microsoft
  builds.
- Third-party extensions are forced to `workspace` kind through
  `product.json#extensionKind`, so they run in the tab.

## Alternatives considered
- **A new process model or extension host kind**: rejected. Large core patch;
  high maintenance cost on every upstream bump.
- **`ResolvedAuthority` host:port (loopback publish plus connection token)**:
  kept as the fallback only. It needs a listener and a published port, and the
  token is the only protection against other local processes.
- **SSH into the sandbox (as sbx's `<name>.sbx` offers)**: rejected. It adds
  an sshd, keys and a listener, and VS Code's SSH remote is a closed Microsoft
  extension.

## Consequences
- The resolver is the single choke point for creating tabs. Folder-open
  routing into `vscode-remote://seclab+<tabId>/<path>` is needed (the M1 Tab
  Manager).
- The RPC channel from the REH back to the UI becomes a trust boundary that
  needs a filter ([RPC filter ADR](20261104-rpc-capability-filter.md)).
- Per-connection `exec` latency (~150 ms under sbx) is paid on connect and
  reconnect only.

## Evidence
- Managed resolver API: [vscode.proposed.resolvers.d.ts#L33-L51](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vscode-dts/vscode.proposed.resolvers.d.ts#L33-L51)
- Managed sockets send a raw HTTP upgrade with `skipWebSocketFrames=true`, so the bytes are exactly what the REH listener expects: [managedSocket.ts](https://github.com/microsoft/vscode/blob/6e35f5ceffa04ac728a0fb3a0dd6fb9cdb4ff100/src/vs/platform/remote/common/managedSocket.ts#L20-L30)
- REH `--socket-path` and `--connection-token-file`: [serverEnvironmentService.ts](https://github.com/microsoft/vscode/blob/6e35f5ceffa04ac728a0fb3a0dd6fb9cdb4ff100/src/vs/server/node/serverEnvironmentService.ts#L156-L183)
- Proposed-API gate: [extensionsProposedApi.ts#L20-L48](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/services/extensions/common/extensionsProposedApi.ts#L20-L48); VSCodium precedent: [product.json#L477-L489](https://github.com/VSCodium/vscodium/blob/ca7f7b44b5e5c3faa663f6cdc043998f71936653/product.json#L477-L489)
- Transport viability spike: [EDR 20261104-reh-transport-exec-stdio](../edr/20261104-reh-transport-exec-stdio.md)
