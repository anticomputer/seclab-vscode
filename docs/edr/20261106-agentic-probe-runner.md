# Agentic probe runner: taking over the tab's agent-host socket, and evidence for the AHP gate

- **Status:** accepted
- **Date:** 2026-11-06
- **Deciders:** anticomputer (user: "Approve; build the probe runner and increment 1 (the agent connection gate) first"); coordinator conditions: no test hook, host-side evidence only, background windows, unsafe builds never in the release location; secure-agentic-experiences session (design).
- **Related:** [implementation plan](../plans/agentic-implementation.md) §2, §3, §4 (increment 1), [real-tab spike EDR](20261106-agents-in-real-tab-spike.md), [EDR fixture safety](20261104-fixture-safety.md), [EDR harness teardown](20261104-harness-teardown.md)

## Context
Increment 0 needs the shipped workbench to face a hostile agent host in a real tab, with
no hook that exists only in test builds. Increment 1 needs runtime evidence that patch
0015 executes in the shipped desktop build. Before building either, three facts about
the code as it stands were checked. All upstream lines are at
`a717861c07586a53d83b80d742cd3f59b20a6273`.

## Findings
1. **Main ships no RPC filter.** `patches/series` on `main` (`7a84d01`) is 0001–0004 and
   0012–0014. Patches 0005–0011, including 0009 (no built-in chat in tabs) and 0010 (no
   agent-host client in tabs), exist only on `rpc-core`, whose own review is marked
   DO-NOT-LAND (`fd3d1b5`).
   - So today a `seclab+` window on main gets upstream's `EditorRemoteAgentHostServiceClient`,
     ungated. That includes the token push for resources the agent host advertises
     (design review, round 1).
   - Consequences for the plan:
     - The **U baseline for increment 1 is main's own release build**, fetched with
       `./seclab fetch macos` at a pre-0015 SHA. No deliberately weakened build is needed
       until F (increment 1's inner layer, 0016).
     - **0015 must stand alone.** In a `seclab+` window it gates the transport whether or
       not 0010 has landed. With `seclab.agents.enabled` off, the gate refuses the
       connection outright, which closes the token push on main. When 0010 lands, it
       calls the `seclabAgentHostAllowed` predicate that 0015 defines.
2. **No renderer-to-tabd event path exists.** tabd accepts `tab.events.report` only from
   the sources `rpc-filter` and `gate` (`tabd/src/obs/glue.ts` `CLIENT_SOURCES`). The RPC
   filter's `seclabOnDecision` listeners have no consumer, even on `rpc-core`.
   - So 0015's runtime evidence is a **dedicated per-window log file**, created by
     `ILoggerService` under the window's log directory (`seclabAhpGate.log`). It is
     written only by the gate, one JSON object per line, and the runner reads it on the
     host.
   - The tab cannot write that file. Every tab-chosen string in it is a JSON value, never
     the line's structure.
   - Forwarding these lines to `tab.events.report` (the Tab Manager tails the file) waits
     for the observability session to add the `ahp.decision` class and sources.
3. **How the REH reaches its agent host.**
   - The REH registers the `agentHostProxy` channel lazily. The socket path is a
     `createRandomIPCHandle()` in the REH user's runtime directory, and the connection
     token is a fresh UUID
     ([serverServices.ts#L362-L395](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/server/node/serverServices.ts#L362-L395)).
   - The bridge opens one upstream WebSocket per renderer client, to that path, after
     `ensureStarted()`
     ([agentHostChannel.ts#L120-L171](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/server/node/agentHostChannel.ts#L120-L171)).
   - The starter removes a stale socket at that path before each spawn, and passes the
     path as `VSCODE_AGENT_HOST_SOCKET_PATH`
     ([nodeAgentHostStarter.ts#L130-L205](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/agentHost/node/nodeAgentHostStarter.ts#L130-L205)).
   - `ServerAgentHostManager` restarts the agent host after an unexpected exit, up to
     `MaxRestarts = 5`, and resets the budget only after it gives up
     ([serverAgentHostManager.ts#L100](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/server/node/serverAgentHostManager.ts#L100),
     [#L243-L273](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/server/node/serverAgentHostManager.ts#L243-L273)).
   - The agent host, the REH and every extension in the tab run as the same user
     (`agent` in sbx).

## Decision
**The takeover: the rogue extension becomes a man in the middle, with no hook.** The armed
rogue extension (`test/containment/rogue-extension`, nonce-armed as today) does the
following:
1. It finds the agent-host socket: a `vscode-ipc-*.sock` in its own runtime directory
   whose holder runs `agentHostMain`, read from `/proc` (same user).
2. It renames that socket to a private name and listens on the original path. A Unix
   socket is reached by its inode, so the real agent host stays reachable at the new
   name, and the renaming is atomic.
3. It proxies every frame between the bridge and the real agent host, so positive
   controls run against the real agent host, and it injects the probes (§Probes).
4. If the workbench is already connected, it kills the real agent host once. The manager
   restarts it and the starter unlinks the path. The rogue watches the directory, and
   renames and listens again as soon as the new socket appears, before the bridge
   reconnects. At most three attempts; the runner records how many it took.

A working takeover is itself evidence for the threat model: the REH's agent-host socket
is within reach of any extension in the tab. If the race can't be won reliably, the
fallback is upstream's own `--agent-host-bridge-path`, which is recorded as a test-only
launch and refused by `check-release`. It is never used silently.

**Evidence is host-side, and sound in both directions.**
- **Vulnerable (U).** Two kinds of evidence count:
  - a host marker file appears, or the host beacon is hit;
  - the rogue reports the content of a **per-run random host canary**. The value exists
    only on the host, so a tab can report it only if it read it; a forged report is
    impossible.
- **Contained (G).** Both must hold:
  - the gate's own `deny` line for that probe is in `seclabAhpGate.log`;
  - no host marker, no beacon hit, and no canary value anywhere in the tab's output.
  
  Absence alone never counts (verdict rules as in the spike).
- **Positive control (G).** `ahp-gate.verified` appears for the connection, and the real
  agent host's root state (its agent list) passes the gate. This shows the gate is not
  passing the deny probes by blocking everything.

**Probes for increment 1**, each injected by the MITM after `initialize`:
- A16: `resourceRead` of the host canary and `resourceWrite` to a host marker path;
- A5 and A26: URIs outside the tab and special schemes;
- A14: an unknown method and action type in each direction;
- A7: `createTcpConnection` to the host beacon;
- A20: an MCP resource at the beacon;
- A21: MCP App `ui://` content;
- A1, trigger form: `protectedResources` whose authorization server is the beacon;
- A19: canaries in host settings and `mcp.json`, which must not appear in frames the MITM
  sees.

**Runner shape:** `test/agentic/runner/`.
- **Profile and tab.** It reuses `check-evidence.ts prepare`'s profile, tab claim and
  rogue extension packaging, with a short isolated user-data-dir under `~/.seclab-test/`.
  The profile sets `seclab.agents.enabled` (G).
- **Launch.** `launchEditorInBackground` against a given app path.
- **Evidence.** The host canary and marker under the run directory, plus the loopback
  beacon.
- **Teardown.** The shared teardown gate.
- **Builds.** U is the release app (`.work/app`). G is the branch app (`.work/app-branch`).
  Each launch records the app's `product.json` commit, and the verdict refuses a run whose
  build is not the one requested.

## The gate's placement and log, as built (0015)
Derived from the pinned source, for patch 0015:
- **One transport, one place.** In a remote window `WorkbenchAgentHostService` picks
  `EditorRemoteAgentHostServiceClient`
  ([agentHostService.ts#L49-L57](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/services/agentHost/electron-browser/agentHostService.ts#L49-L57)),
  whose `createTransport` factory builds an `AgentHostIpcChannelTransport` over the
  `agentHostProxy` channel
  ([editorRemoteAgentHostServiceClient.ts#L116-L135](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/services/agentHost/browser/editorRemoteAgentHostServiceClient.ts#L116-L135)).
  The factory runs again for every transport-level reconnect.
- **The gate wraps the channel, not the parsed messages.** The transport reads raw JSON
  text from `listen('frame')` and writes it with `call('send', text)`
  ([agentHostIpcChannelTransport.ts#L63-L90](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/agentHost/browser/agentHostIpcChannelTransport.ts#L63-L90)).
  Wrapping the `IChannel` lets the gate cap sizes on the raw text, parse once, and
  re-serialise only what it allows. The transport built over the gated channel is branded
  in a module-private `WeakMap`; nothing in a tab can reach the renderer's module scope.
- **Construction invariant.** `AgentHostProtocolClient._installTransport` runs for the
  first transport and every replacement
  ([agentHostProtocolClient.ts#L737-L760](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/agentHost/browser/agentHostProtocolClient.ts#L737-L760)).
  0015 adds one call there: in a `seclab+` window every transport reports
  `ahp-gate.opened`, and an unbranded one is refused (it throws) after reporting
  `ahp-gate.refused`; a branded one reports `ahp-gate.verified`.
- **Reverse requests** all arrive through `_handleMessage` → `_handleReverseRequest`
  ([#L3025-L3026](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/agentHost/browser/agentHostProtocolClient.ts#L3025-L3026)).
  The gate answers every inbound request itself with a JSON-RPC error, so none reaches it.
- **The surface.** `CommandMap`, `ServerCommandMap`, `ClientNotificationMap` and
  `ServerNotificationMap` in the generated protocol
  ([messages.ts#L86-L200](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/agentHost/common/state/protocol/common/messages.ts#L86-L200))
  are the method list the gate's table covers; anything else is denied.
- **The setting's write paths.** `seclab.agents.enabled` is `APPLICATION` scope, so the
  remote-user layer can't supply it. `MainThreadConfiguration.$updateConfigurationOption`
  writes with the target the extension asks for and does not check scope
  ([mainThreadConfiguration.ts#L48-L70](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/api/browser/mainThreadConfiguration.ts#L48-L70)),
  so on main a tab extension may be able to turn it on. That is A23's to measure. The
  setting is an off switch, not the boundary: with it on, the connection is still gated.
- **MCP authentication never reaches the window** (security review rounds 1 and 2). The agent
  host does not get to choose a URL the trusted renderer fetches. Three things enforce that:
  `chat/toolCallAuthRequired`, `session/mcpServerStateChanged` and
  `session/customizationsChanged` are denied inbound, because they reach
  `autoAuthenticateMcpServer` with no user interaction; any auth-required node (`kind` of
  `authRequired` or `auth-required`, `status` of `auth-required` or `authRequired`) is replaced
  by a well-formed inert error state wherever it is embedded; and `auth`,
  `authorization_servers`, `oauthClient`, `protectedResourceMetadata`, `protectedResources` and
  `mcpApp` are stripped everywhere. Matching the key names alone is deliberately not the only
  line of defence: round 1's fix matched a discriminant that does not exist upstream and was
  dead code, which the unit tests did not catch because the fixture used the same wrong shape.
- **Enablement is only what a tab cannot write** (review round 1). `seclabAgentHostAllowed`
  reads `inspect().policyValue`, the registered `defaultValue`, and
  `SECLAB_AGENTS_ENABLED=1` in the **host main process** environment, which `updateConfiguration`
  stamps onto the window configuration on every load. It never calls `getValue`, which merges
  the user, remote and workspace layers that `$updateConfigurationOption` can reach (A23).
- **Log lines** use the shape `tab.events.report` accepts today (`tabd/src/obs/glue.ts`
  on `f19cf49`), so the Tab Manager can forward them unchanged:
  `{source:'ahp-gate', class:'ahp.decision', priority, summary, detail}` with `detail`
  flat, at most 16 scalar keys, `detail.gateRule` the rule id, `detail.connection` an
  integer per transport, and `detail.verdict` one of `allow`, `deny`, `strip`. The
  connection rules are exactly `ahp-gate.opened` and `ahp-gate.verified`, which
  `ahp.ungated` pairs within 2 s; every `deny` counts toward `ahp.deny-burst`.

## Consequences
- Increment 1 needs no unsafe build, so the fork-build preconditions (positive release
  marker, separate destination, distinct bundle id) are needed by increment 1's F probe for
  0016, not by 0015.
- Main's current release is exposed in `seclab+` windows until 0015 or 0010 lands. This is
  reported to the coordinator.
- Clearing quarantine on the fetched apps needs the user's approval (AGENTS.md).

## The in-tab takeover, as built and measured (2026-11-06)
The takeover is an **extension** (`test/agentic/runner/mitm-extension/`), not a host-injected
process. That is what made it work across the tab restart the run needs: `prepare` claims the
tab and then releases it so the editor's own tabd can claim it, and stopping a tab kills
everything inside. Every host-side way of restarting the takeover was worse (findings 4 and 5
above). The REH restarts an extension by itself, so there is no host polling, no liveness
signal and no `sbx exec` in the loop.

**It works.** On the release build U, in one run:

```
armed
watching            sock=/run/user/1000/vscode-ipc-535fd040-….sock
takeover  attempt 1 real=…sock.real-…
listening
forcing-reconnect   attempt 1, killed 1
takeover  attempt 1 (the replacement socket)
listening
client-connected    url=/?tkn=…
upstream-ready
from-client         method=reconnect
from-client         method=initialize
probe-sent × 12
```

Two things this settles:
7. **The bridge opens one upstream WebSocket per renderer client**, so taking the socket while
   a client is already attached wins the path but sees no traffic. Killing the real agent host
   once makes `ServerAgentHostManager` restart it, the starter unlinks the path, the
   replacement binds it, and the takeover lands again **before** the bridge reconnects. The
   measured attempt count is **1**, and the renderer does reconnect (it sends `reconnect`, then
   `initialize`). That answers the "Not done yet" question below.
8. **The whole chain is real.** A hostile agent host inside the tab reached the trusted
   renderer of the shipped, attested macOS build, which then spoke AHP to it and stayed
   connected (steady `ping`s). The takeover needed no product hook and no test-only build.

**Why the first probes produced no host effect on U, and what does (2026-11-06).** Both leads
were right, and reading upstream at `a717861c` found two more defects and, more importantly,
that **most of the probes could never have produced a host effect**, for reasons that have
nothing to do with the gate. Each is a false-negative source of exactly the class reviews 2 and
3 flagged, so each is recorded with its line.

9. **The action probes named a channel nobody subscribed to.** `RootStateSubscription`
   accepts an envelope only when `isAhpRootChannel(envelope.channel)`
   ([agentSubscription.ts#L303-L305](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/agentHost/common/state/agentSubscription.ts#L303-L305)),
   and the root channel is the literal `ahp-root://`
   ([sessionState.ts#L366](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/agentHost/common/state/sessionState.ts#L366)).
   The probes sent `channel: 'c'`, or omitted it, and carried no `serverSeq`, which
   `_handleMessage` folds into `_serverSeq`
   ([#L3068-L3072](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/agentHost/browser/agentHostProtocolClient.ts#L3068-L3072)).
   Fixed: root probes use `ahp-root://` with a `serverSeq`.
   - The session and chat probes stay **gate-surface only**: a window with no open session
     holds no session or chat subscription, so their envelopes are dropped before any
     reducer whatever they say. They are now labelled as such rather than counted.
10. **`resourceWrite` was malformed.** `ResourceWriteParams` is `{ channel, uri, data,
    encoding }`
    ([commands.ts#L876-L890](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/agentHost/common/state/protocol/common/commands.ts#L876-L890)),
    and the handler rejects anything without `data` before any permission check
    ([#L3347-L3352](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/agentHost/browser/agentHostProtocolClient.ts#L3347-L3352)).
    The probe sent `content`. Fixed to base64 `data`.
11. **`createTcpConnection` is a client-to-server command, not a reverse request.** The client
    *calls* it ([#L3450](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/agentHost/browser/agentHostProtocolClient.ts#L3450));
    inbound it reaches `_handleReverseRequest`'s `default:` and is answered "Unknown method".
    It can never open a tunnel on U, so it is a gate-surface probe too.
12. **The resource probes are refused by upstream's own gate on U, correctly.** Every
    `resource*` reverse request goes through `IAgentHostResourceService`, whose `_isCovered`
    short-circuits only for `LOCAL_AGENT_HOST_RESOURCE_IDENTITY`
    ([agentHostResourceService.ts#L408-L411](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/services/agentHost/common/agentHostResourceService.ts#L408-L411)).
    A `seclab+` window's identity is the string `vscode-remote://seclab+<tab>`
    ([editorRemoteAgentHostServiceClient.ts#L137-L143](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/services/agentHost/browser/editorRemoteAgentHostServiceClient.ts#L137-L143)),
    so with no persisted grant the check enqueues a user prompt and the call throws
    `PermissionDenied`. A16, A5 and A26 therefore **cannot** mark the host without the user,
    and absence of a marker on U says nothing about the gate. The implicit-read grants that
    would bypass this are granted only for **outgoing** actions
    ([#L2883-L2895](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/agentHost/browser/agentHostProtocolClient.ts#L2883-L2895)),
    so a hostile host cannot induce them.
13. **One probe does land, and it is the one that matters.**
    `vscode/requestMcpAuthentication`
    ([agentHostExtensionProtocol.ts#L81](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/agentHost/common/agentHostExtensionProtocol.ts#L81))
    is an unsolicited server-to-client request that the client answers by calling the handler
    the remote chat contribution registers
    ([remoteAgentHostChatContribution.ts#L313-L317](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/chat/browser/remoteAgentHost/remoteAgentHostChatContribution.ts#L313-L317)),
    which is `autoAuthenticateMcpServer` with `allowInteraction: false`. When the agent host
    **omits** `authorization_servers`, `resolveMcpServerAuthentication` calls
    `IAgentHostMcpOAuthMetadataService.resolveResource(resource)` unconditionally, before any
    `allowCreation` check
    ([agentHostAuth.ts#L1159-L1170](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/chat/browser/agentSessions/agentHost/agentHostAuth.ts#L1159-L1170)),
    and that service is a shared-process remote service whose fetch leaves the **trusted host**
    through `IRequestService`
    ([agentHostMcpOAuthMetadataService.ts#L59-L96](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/agentHost/common/agentHostMcpOAuthMetadataService.ts#L59-L96),
    registered in
    [sharedProcessMain.ts#L451](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/code/electron-utility/sharedProcess/sharedProcessMain.ts#L451)).
    So a tab that owns its agent-host socket makes the host fetch a URL of its choosing, with
    no user action and outside the tab's broker. That is the host beacon hit, and it is what
    0015 denies as `ahp-gate.reverse-request`.
    - Supplying `authorization_servers` instead is a dead end:
      `getOrCreateProviderForMcpResource` returns before the metadata fetcher whenever
      `allowCreation` is false.
    - The probe is re-sent on a timer, because the handler is registered only once the
      contribution has the connection's root state, which is after `initialize`.
14. **The `protectedResources` token push needs a signed-in account.**
    `authenticateProtectedResources` runs on every root-state change with no user action
    ([remoteAgentHostChatContribution.ts#L602-L625](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/chat/browser/remoteAgentHost/remoteAgentHostChatContribution.ts#L602-L625)),
    but each resource resolves through `resolveSessionForProtectedResource` and pushes nothing
    when the profile is signed out. The run profile is isolated and signed out, and no real
    credential may enter a fixture, so A1-protected stays a gate-surface probe. The
    `chat.agentHost.unsafeTestToken` path is not used: it needs `--enable-smoke-test-driver`,
    which would be a deliberately weakened launch.

## Measured, 2026-11-06 (increment 0, first runs)
Seven runs of `test/agentic/runner/` against the attested release build U
(`.work/app`, main `f19cf49`) on the sbx driver. What they established, with the evidence:

1. **A `seclab+` window on main connects to its tab's agent host with no user action.** The
   REH log in the tab shows, within two seconds of the window opening:
   `[AgentHostChannel] Renderer ctx=… requested connect to upstream` →
   `ServerAgentHostManager: agent host started` →
   `[AgentHostChannel] Opening upstream to /run/user/1000/vscode-ipc-….sock`. This is the
   runtime confirmation that main's release is exposed, and it is what patch 0015's
   `ahp-gate.disabled` deny closes.
2. **The takeover needs no race.** The REH computes `createRandomIPCHandle()` and logs the
   path at **startup**, when it registers the lazy `agentHostProxy` channel
   ([serverServices.ts#L362-L395](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/server/node/serverServices.ts#L362-L395)),
   long before any window connects. Only the agent-host *spawn* is lazy. So tab code reads
   the path first and waits for the socket to appear.
   - Pre-binding that path does **not** work: the starter unlinks it immediately before each
     spawn ([nodeAgentHostStarter.ts `_removeStaleSocket`](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/agentHost/node/nodeAgentHostStarter.ts#L188-L207)),
     so the rename-on-appearance in the Decision above is the right shape.
3. **The REH log is in two places, depending on who started the REH.** tabd's own launch
   writes `/run/user/1000/seclab/reh.log`; the REH the **editor** starts writes
   `~/.seclab-vscode-server/data/logs/<timestamp>/remoteagent.log`. A takeover that reads only
   the first latches a stale path from a previous REH and never fires. `mitm.js` reads the
   newest of both on every tick, and falls back to `VSCODE_AGENT_HOST_SOCKET_PATH` in the
   agent host's own `/proc/<pid>/environ`.
4. **The tab's workspace is an overlay, so in-tab writes are not host-visible.** The same
   `.mitm.jsonl` was 7722 bytes inside the tab and 4 lines on the host bind mount. Two
   consequences:
   - it confirms the evidence rule from the Decision: only the host marker, the host beacon
     and the host canary decide anything, and the tab's own record is unreadable from the
     host anyway;
   - a host-side liveness file written by tab code cannot work, so arming must ask the tab.
5. **Polling the tab with `sbx exec` during the editor's tab startup breaks the tab.**
   `tab.ensureRunning` failed with `REH failed to start: collector: workspace overlay not
   mounted`. The arming loop must not exec while the editor is bringing the tab up.
6. **The editor restarts the tab, which kills anything running in it.** `prepare` claims the
   tab and then releases it so the editor's own tabd can claim it; that stop kills a takeover
   started during `prepare`. Re-injection after the editor's tab is up is therefore required,
   and it still lands before the agent host is spawned (point 2).

**Status: the runner does not yet produce probe evidence.** The takeover arms and watches, but
each injected process is replaced before it sees the socket, because findings 4 and 5 together
leave the arming loop without a sound liveness signal: the host cannot read the tab's
heartbeat, and it must not poll the tab while the editor is starting it. The next step is to
arm through a channel that survives a tab restart without host polling at all. The most
promising is the one the plan already names: package the takeover as the rogue extension
(`check-evidence.ts prepare` already installs one into the tab), so the REH itself starts it
when the window's extension host comes up, with no host exec in the loop.

Patch 0015 therefore lands on finding 1 plus its unit tests, with `ahp-gate.disabled` as the
runtime evidence to collect once the runner is finished.

## Not done yet
- The race in the takeover is unmeasured. This record is updated with the measured
  attempt counts.
- Whether the workbench client reconnects after the agent host's restart, and with what
  backoff, is to be measured with the runner.

## Where this stopped (2026-11-06, end of session)
Branch `anticomputer-agentic-gate-0015-v3`, rebased onto `main` (`f669584`). 0015 is still
**HELD**: the probes are fixed and the reason the old ones could not land is now understood
and recorded (findings 9–14), but **no U run has yet shown a host effect**, so there is still
no runtime proof in the shipped build.

Done this session:
- Findings 9–14 above: why each old probe could not produce a host effect, and the one that
  can (`vscode/requestMcpAuthentication` with `authorization_servers` omitted).
- `test/agentic/runner/mitm.js`: probes corrected, the host-effect probe added and re-sent on
  a timer, gate-surface probes labelled as such.
- Rebased the whole 0015 stack onto current `main`, resolving the `seclab` unit-test list
  twice.
- Fixed the two checks that were already red on the old head: `ci-unit` (the marks test
  needed `~/.seclab-test/` to exist, which it never does in the container) and `docs-check`.
  Locally `test unit` is 147/147 and `docs check --run-commands --paired` is green.

Next step, in order:
1. **Rebuild the shared broker image before any run.** The host's `seclab-broker:dev` was at
   policy revision 5 while `main`'s tabd expects 4, so `tab.ensureRunning` failed with
   `broker image seclab-broker:dev refused … policy revision "5", expected 4`. `./seclab build
   linux reh` has been run; `./seclab image oci` still needs to follow. The revision is a
   host-wide shared tag, so check it matches the tree under test before blaming the run.
2. Re-run U (`prepare --build u`, background launch, `check`) and confirm the beacon log has a
   hit for `/.well-known/oauth-protected-resource/mcp-<arm>`.
3. Then G: dispatch `build-macos` on the branch head, `./seclab fetch macos-branch <run>`, run
   with `SECLAB_AGENTS_ENABLED=1`, expect `ahp-gate.reverse-request` denies, no beacon hit and
   `ahp-gate.verified` plus the real agent list passing.
4. Security-review round, then land.

**Open problem, not worked around: the editor took focus during the U run.** Teardown's focus
gate failed with three samples (`editor pid 60644 is the frontmost app`, ~22 s after launch),
even though the window was started through `test/window.ts launch`, which exits 1 on a
frontmost editor and did not. So the launch path's own check passes while the window becomes
frontmost slightly later. This is the hard rule in AGENTS.md ("you keep popping up on top of
my ongoing work") and it is reported rather than suppressed: the next session must find out
whether `SECLAB_BACKGROUND_WINDOWS=1` is reaching this build, or whether something after
window creation (the `seclab+` resolver's progress UI is the first suspect) activates the app.
No further editor windows should be launched until that is answered.

### Host state at halt
Teardown ran and passed every check except the focus gate: no process, sandbox, container,
network or volume from the run is alive, the run profile is removed, and no watched host path
changed. `./seclab clean-host` lists nothing of this session's. `.work/agentic-runner/` is kept
on purpose: it holds the run's evidence, it is gitignored, and fixture lint is clean on it.
