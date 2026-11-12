# RPC capability filter: choke points, policy as data, and a build-time gate

- **Status:** accepted (approved by the project owner; extended by [20261104-tab-command-taint.md](20261104-tab-command-taint.md))
- **Date:** 2026-11-04
- **Deciders:** RPC-lockdown session; seclab-vscode coordinator
- **Supersedes:** [20261104-rpc-capability-filter.md](20261104-rpc-capability-filter.md)
- **Full design:** [docs/RPC-LOCKDOWN.md](../RPC-LOCKDOWN.md)
- **Review:** [20261104-rpc-lockdown-design.md](../security-reviews/20261104-rpc-lockdown-design.md)
- **Editorial redaction (2026-11-12):** quotations of project conversations replaced with neutral statements; decisions unchanged.

## Context

The superseded record scoped the filter to `MainThread*` RPC. The generated
inventory and the design review showed that scope is too narrow in two ways.

The REH **server** process runs inside the tab, so it is hostile, and the client
registers IPC channels *on that connection* which the server calls directly.
Those never reach `RPCProtocol`. Two exist today: `download`, which revives both
URIs from server-supplied arguments, and `mcpGatewayToolBroker`, which exposes
`callToolForServer` — invoking a trusted-side MCP tool, running as a host
process with host credentials, with arguments the tab chooses.

Separately, the declared interface is not the boundary.
`RPCProtocol._doInvokeHandler` resolves `actor[methodName]` and checks only that
it is a function, so every `$` method on the customer class is callable whether
or not it appears in a `MainThread*Shape`.

The measured surface is 3768 items across four kinds: `MainThread*` RPC (89
services, 546 methods), the command registry reachable via `$executeCommand`
(3205 ids), client-served channels and server-initiated callbacks, and
tab-supplied data the trusted side interprets with authority.

## Decision

1. **Three choke points, not per-class patches.**
   - `RPCProtocol._receiveRequest`, attached where `extensionHostManager`
     constructs the protocol — the only construction site, on the path taken for
     every host kind including restart. Attachment fails closed.
   - `ChannelServer`/`IPCClient.registerChannel` for `seclab+*` connections,
     covering the server-to-client direction. Deliberately *not*
     `AbstractRemoteAgentService.registerChannel`, which is a convenience
     wrapper rather than the mechanism.
   - An argument validator on `$executeCommand`, whose walker shares code with
     `marshalling.revive`.
2. **Key on the wire `sid`**, never the `MainContext` property name (7 diverge)
   and never the numeric `nid` (assigned by module load order).
3. **Policy is data** in `rpc-filter/policy/policy.json`: verdict, capability,
   unmitigated `impact`, `residual_impact`, constraint, rationale, evidence.
4. **Default-deny, and categories may only withhold authority.** A substring
   category may carry `deny` and nothing else; reachability is granted per item,
   individually reviewed. The allowlist starts empty and is built from measured
   need in Phase 3.
5. **A build-time gate** pins the whole surface-to-verdict mapping by digest,
   with reachable entries pinned by the hash of their full policy entry, and
   fails the build naming each new, changed or removed surface.

## Alternatives considered

- **Patch each dangerous `MainThread*` class.** Rejected: 89 files against a
  "one concern, under ~50 lines" patch rule; no mechanism notices a new upstream
  method; cannot see undeclared methods; and the "am I sandboxed?" test would
  drift between call sites.
- **Denylist known-dangerous commands.** Rejected: drifts silently as upstream
  adds commands, which is the failure mode this project cannot afford.
- **Category-based allowlisting.** Tried, then rejected during review: the
  heuristic mis-grouped host-authority commands as editor-local. A heuristic may
  withhold authority; it may not grant it.
- **Rely on the sandbox alone.** Rejected: the RPC channel terminates on the
  trusted side of the boundary.
- **Guard at `AbstractRemoteAgentService.registerChannel`.** Rejected during
  review: a connection holder can register straight on `ChannelServer`.

## Consequences

- The reachable surface is 14 items. This is not a safety claim; it is a claim
  that nothing has been granted without review. Phase 3 grows it from measured
  extension need, and each addition is new risk.
- Extensions depending on denied capabilities break, as errors rather than
  prompts. The compatibility cost is unmeasured until Phase 3.
- Upstream bumps become a JSON edit plus a review instead of a rebase conflict,
  because the table and inventory live in this repo, not in the patch.
- The command-chaining bypass (an allowed command invoking a denied one) is
  **undesigned** and must be closed before the filter ships.

## Evidence

- Dispatcher resolves `actor[methodName]`: [rpcProtocol.ts L449-L461](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/services/extensions/common/rpcProtocol.ts#L449-L461)
- Single construction site: [extensionHostManager.ts L249-L270](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/services/extensions/common/extensionHostManager.ts#L249-L270)
- `nid` from load order: [proxyIdentifier.ts L33-L50](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/services/extensions/common/proxyIdentifier.ts#L33-L50)
- `download` channel revives server URIs: [remote.contribution.ts L77-L81](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/remote/common/remote.contribution.ts#L77-L81), [downloadIpc.ts L18-L26](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/download/common/downloadIpc.ts#L18-L26)
- MCP gateway tool broker: [mcpGatewayToolBrokerContribution.ts L13-L21](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/mcp/browser/mcpGatewayToolBrokerContribution.ts#L13-L21)
- Remote terminal `onExecuteCommand`: [remoteTerminalBackend.ts L102-L121](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/terminal/browser/remoteTerminalBackend.ts#L102-L121)
- Caller-supplied secret identity: [mainThreadSecretState.ts L38-L80](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/api/browser/mainThreadSecretState.ts#L38-L80)
- Later registration beats a built-in: [commands.ts L99-L110](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/commands/common/commands.ts#L99-L110)
- Gate proven: injected surfaces exit 1 and are named; clean tree exits 0.
