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

## Consequences
- Increment 1 needs no unsafe build, so the fork-build preconditions (positive release
  marker, separate destination, distinct bundle id) are needed by increment 1's F probe for
  0016, not by 0015.
- Main's current release is exposed in `seclab+` windows until 0015 or 0010 lands. This is
  reported to the coordinator.
- Clearing quarantine on the fetched apps needs the user's approval (AGENTS.md).

## Not done yet
- The race in the takeover is unmeasured. This record is updated with the measured
  attempt counts.
- Whether the workbench client reconnects after the agent host's restart, and with what
  backoff, is to be measured with the runner.
