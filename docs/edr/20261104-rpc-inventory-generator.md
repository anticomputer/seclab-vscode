# RPC attack-surface inventory is generated, not hand-written

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** RPC-lockdown session
- **Related:** [ADR: RPC filter enforcement points](../adr/20261104-rpc-filter-enforcement-points.md)

## Context

The filter's policy table is only as good as the list of surfaces it covers. A
hand-curated list is wrong the day upstream moves, and nothing tells you. The
surface is also large enough that hand-curation is not credible: 3768 items.

## Decision

`rpc-filter/tools/` generates the inventory from pinned upstream source.
Standard-library Python only, so it runs in a stock `python:3.12-slim` with
`--network none` and no install step. `fetch-upstream.sh` pins the source into
`.work/` (gitignored, durable; never `/tmp`). The SHA comes from
`upstream.lock` when present, so the inventory cannot drift from the build's
pin; otherwise it falls back to a named constant and says so in the output.

Output is deterministic — same source in, byte-identical files out — which is
what makes the drift digest meaningful.

Four extractors, one per surface: `rpc.py`, `commands.py`, `channels.py`,
`tabdata.py`.

## Alternatives considered

- **Runtime dump from a running build.** Would be more accurate for commands,
  since it sees what actually registered. Rejected for now: it needs a built
  editor, which M0 does not yet produce, and it cannot run in CI before the
  build it is meant to gate. Worth revisiting as a cross-check once M0 lands.
- **TypeScript compiler API.** More precise than regexes. Rejected: it needs
  `npm install` in the generator path, against the host-hygiene rule, and ties
  the tool to upstream's toolchain version.
- **Hand-curated table.** Rejected as above.

## What the spikes found

Writing the extractors, and then checking their output against source, found
four defects that a hand-written list would have reproduced silently:

1. **The declared interface is not the callable surface.** `_doInvokeHandler`
   resolves `actor[methodName]`, so `$` methods absent from `MainThread*Shape`
   are still callable. Two exist. The generator now diffs declared against
   implemented and reports `undeclared_methods`.
2. **Two registration paths, not one.** Scanning only for
   `@extHostNamedCustomer` missed 9 services registered via
   `context.set(MainContext.X, …)`, including the entire webview family.
3. **The wire name is not the property name.** `createProxyIdentifier`'s `sid`
   differs from the `MainContext` key for 7 services. A policy keyed on the
   property name would never match. The same class of bug hit the channel
   extractor, which recorded `McpGatewayToolBrokerChannelName` instead of its
   value `'mcpGatewayToolBroker'`.
4. **Named-helper scanning misses commands.** Matching
   `CommandsRegistry.registerCommand` and `registerAction2` missed
   `workbench.action.terminal.newLocal` — registered through
   `registerTerminalAction` — in a 2792-id scan. Matching the *shape*
   `register*({ id: … })` instead, and resolving constants and enum members,
   added 413 commands and cut unresolved ids from 1192 to 168.

## Consequences

- Regenerating is one command and the output is reviewable as a diff.
- Regexes will keep missing forms. Default-deny makes each miss a compatibility
  cost rather than a containment hole, and the drift check's `keys` test turns a
  miss into a build failure as soon as anyone writes a policy entry for the
  missing id. A miss nobody notices stays invisible: see residual risk 4.
- 168 command id expressions remain unresolved and are therefore denied.

## Evidence

- Verified counts at `microsoft/vscode@a717861c07586a53d83b80d742cd3f59b20a6273`:
  89 services, 546 methods, 3205 commands, 2 client-served channels, 15
  tab-data sink classes over 475 sites.
- `actor[methodName]` dispatch: [rpcProtocol.ts L449-L461](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/services/extensions/common/rpcProtocol.ts#L449-L461)
- `sid` vs `nid`: [proxyIdentifier.ts L33-L50](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/services/extensions/common/proxyIdentifier.ts#L33-L50)
- `newLocal` via `registerTerminalAction`: [terminalRemote.ts L16-L42](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/terminal/electron-browser/terminalRemote.ts#L16-L42)
