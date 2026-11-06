# Agentic experiences: implementation plan for Tier A

- **Status:** accepted
- **Date:** 2026-11-06
- **Deciders:** coordinator, forwarding the user's "Next phase for agentic experiences" ("write up the §10 patch series (0015 onward) and its probes as increments, with the transport gate (AHP) first. Coordinate with the RPC session"); secure-agentic-experiences session (plan). Accepted 2026-11-06 by the user: "Approve; build the probe runner and increment 1 (the agent connection gate) first". Runner and increment 1 findings: [EDR agentic probe runner](../edr/20261106-agentic-probe-runner.md) (U for increment 1 is main's release, which has no RPC filter; 0015 stands alone).
- **Related:** [design plan](secure-agentic-experiences.md) (§3, §4, §10, §11), [ADR agents run in the tab](../adr/20261105-agents-run-in-the-tab.md), [spike EDR](../edr/20261105-agents-in-tab-spike.md), [real-tab spike EDR](../edr/20261106-agents-in-real-tab-spike.md), [patch-build gate](../edr/20261105-patch-build-gate.md), [patch queue](../../patches/README.md)

This plan turns the design's §10 table into ordered increments. Each increment is one or
more patches, a probe that fails on a stated baseline, and runtime evidence from the
shipped build. Nothing here is built until the user approves.

## 1. Rules every increment is held to
- **Done means executing.** A patch is done only when:
  - `patch-build` type-checks the patched tree;
  - `check-patch-reach` places every patched file in the `desktop` target (pinned in
    `patches/reach.json`);
  - a runtime probe shows the patched code executing in a shipped build, with an event
    the patched code itself emits.
  
  "Applies cleanly" and "a probe passed" are not evidence on their own (AGENTS.md).
- **Every probe fails first.** A probe is `not-implemented` until it has failed on its
  baseline (§2) with host-side evidence, and then passed on the gated build with the
  gate's own decision recorded. The spike's `verdict.mjs` rules carry over: a disarmed run
  is INVALID, and absence of a marker is never containment.
- **Every control is shown executing.** Primary controls are probed on the gated build G.
  A layer behind another control never runs there, so it is probed on a fault-injection
  build F (§2), where the outer control is disabled and the inner one must still contain
  the probe. Without F, a green result for an inner layer would be the absence-of-evidence
  error the RPC session hit with its own AI probes.
  - **F alone is not enough** (RPC-lockdown, 2026-11-06). F shows that an inner layer can
    refuse; it does not show that the layer is present and wired in the shipped build.
    Patch 0011 compiled and reviewed well, but never loaded. So every inner layer and every
    null provider also emits an `armed` event when it is constructed or registered in a
    `seclab+` window (`ahp-reverse.armed`, `ahp-credential.armed`,
    `seclab.null-provider.registered` with the service id). Every G run asserts these
    events. A probe that infers a control from the absence of an effect is not accepted.
  - **Inner layers are kept where the surface is critical.** Reverse requests (host file
    read and write, A16) get their own refusal in `agentHostProtocolClient.ts` (0016).
    Credential issuance (`authenticate`) is a separate module with its own invariant
    (0020), not part of the content filter. Tool execution keeps 0009's `invokeTool`
    refusal (RPC-lockdown, A18). Egress keeps the broker and the fence.
  - **Folded into the gate**, with the drift-checked policy as the single list: client
    capabilities and tool advertisement, configuration and customization forwarding, and
    MCP App resources. These are design §10 rows that would otherwise each be a patch
    duplicating a gate verdict. The construction invariant (no protocol client on an
    ungated transport) guards the gate's placement.
  - This changes design §10 in part. The security review for increment 1 must look at it
    specifically (round 1 recommended this split: "keep the credential path as a separate
    module … add the fault-injection build").
- **Off by default, same binary.** Agents in tab windows sit behind a new setting,
  `seclab.agents.enabled`, default `false`.
  - It is registered at `APPLICATION` scope in every window, so the remote-user layer
    cannot supply it (`REMOTE_MACHINE_SCOPES` excludes `APPLICATION`).
  - The other tab-side write path is an extension in the tab calling
    `getConfiguration().update(…, Global)`. RPC-lockdown's policy marks
    `MainThreadConfiguration.$updateConfigurationOption` as denied, but its own warning
    (2026-11-06) is that a verdict in that table records intent, not enforcement, until its
    enforcement-mapping gate lands: one `deny` there was never implemented. So the plan
    does not rely on the table. A23 asserts both paths itself, with host-side evidence.
  - The gate reads the setting again at each connection, not once at startup.
  - The probe runner sets it in the isolated test profile, so the probed build is the
    shipped build.
  - Turning it on for the user is the user's decision at the Tier A exit.
- **Patch size.** Edits to upstream files stay within one concern and about 50 lines.
  Gate logic lives in new files, as `seclabRpcFilter.ts` does for 0005.
- **No focus stealing.** Editor windows open only through `test/window.ts launch`
  (patch 0012).

## 2. Builds the probes run against

| Build | What it is | Where it comes from |
|---|---|---|
| **G** (gated) | `main`'s series plus the increments so far | `build-macos` on the branch: an attested branch test build, `./seclab fetch macos-branch` into `.work/app-branch/` |
| **U** (unpatched agentic baseline) | `main`'s series with 0010's tab-window refusal and 0009's `sendRequest` refusal reverted, so a `seclab+` window gets upstream's agent-host client and chat. Everything else is identical | The same workflow on a `test/agentic-baseline` branch |
| **F** (fault injection) | G plus a test-only patch that turns the gate's filtering into a pass-through, keeping the construction invariant. Inner layers (0016, 0020's invariant, 0009) must contain their probes on F | The same workflow on a `test/agentic-fault` branch; the test-only patch lives under `test/`, never in `patches/series` |
| **v0** | `main` today (agents off in tabs) | `./seclab fetch macos` |

**U and F are deliberately unsafe, and nothing protects against that today** (review round
1, finding 2). `check-release` has only negative scans, and `fetch macos-branch` puts every
branch build in the same `.work/app-branch/`. Before either is built, the fork-build
session adds:
- a positive marker: `check-release` requires a string that 0010 and 0015 emit, failing
  closed, so U and F can never pass as a release;
- a separate destination (`.work/app-unsafe/<build>/`) and a distinct product name and
  bundle identifier ("seclab-vscode UNSAFE test build");
- in the probe runner, a check of the launched app's build-info field rather than its
  path.

The tab side is the same for all three: `seclab-tab:local` with the REH from
`./seclab build linux reh`. The increments touch only `workbench/` and
`platform/agentHost/browser|common`, so the REH does not change. Every Tier A probe must
also hold on v0, where it is contained trivially by 0010; v0 is the regression check.

## 3. Increment 0: the probe runner (no patch)
The spike harnesses drive a protocol client or a bare agent host. Probes on the shipped
build need the workbench itself facing a hostile agent host. The runner is shared with
RPC-lockdown, which will wire A17, A18 and A23 behind it.

- **Editor.** The shipped build (G or U) is launched in the background with an isolated
  profile (`~/.seclab-test/<n>`) and `--folder-uri vscode-remote://seclab+<tab><path>`.
  The profile's user settings set `seclab.agents.enabled` (for G and U).
- **Tab.** It is driven by tabd with `--broker required`, reusing `tab-spike.ts`: the
  broker image with the fixture CA, the `*.test` fixture network and the fake GitHub
  credential.
- **Hostile agent host, with no test hook.** Under the threat model the rogue extension
  controls the tab's REH side.
  - The REH starts its agent host lazily on a socket from `createRandomIPCHandle()`, in
    the tab user's runtime directory
    ([serverServices.ts#L362-L395](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/server/node/serverServices.ts#L362-L395)).
  - The armed rogue extension runs as the same user. It unlinks that path and listens
    there with `rogue-agent-host.ts`. The REH's bridge then connects the workbench to the
    rogue agent host.
  - A working takeover is itself a finding to record: it shows that the REH's agent-host
    socket is inside the attacker's reach, as the design assumes.
  - Fallback: a test-only REH launch with upstream's own `--agent-host-bridge-path`
    ([serverServices.ts#L260-L356](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/server/node/serverServices.ts#L340-L356)),
    recorded as test-only and refused by `check-release`.
- **Real agent host as well.** Positive controls (a turn completes, a tool runs in the tab)
  use the real agent host with the fake model fixture.
- **Host-side evidence only.**
  - The loopback beacon (`test/containment/beacon.ts`) counts host fetches.
  - Host canary files and marker paths sit under the run directory.
  - Broker audit.
  - The gate's events, read with `./seclab tab logs <tab> --format json`; integrity
    `trusted` comes only from the gate.
  - The rogue agent host's record of what it received is `tab-reported` and is never the
    deciding fact.
- **Credentials.** A1's first measurement needs no credential:
  - on U, upstream fetches OAuth metadata for an authorization server the agent host
    chose, from the host network, before any token exists (design §4.2 step 0);
  - pointing it at the beacon makes U fail with a host-side hit.
  
  Measuring "only a sentinel" (increment 5) needs a canary GitHub session in the test
  profile without touching the keychain. **Open:** in-memory secret storage plus a seeded
  canary session is the candidate; it is to be settled in this increment, and
  `seclabcanary_` values only.
- **Exit:**
  - the runner reproduces A16 (`resourceRead` of a host canary) and A20 (a host fetch of
    an advertised MCP resource) as **vulnerable on U** from the shipped macOS build, with
    host evidence;
  - teardown is clean;
  - RPC-lockdown confirms that A17, A18 and A23 run behind it.

## 4. Increments

| Inc | Patch | Upstream files touched | Concern |
|---|---|---|---|
| 1 | **0015** `seclab-ahp-gate` | `workbench/services/agentHost/browser/editorRemoteAgentHostServiceClient.ts` (transport construction), `platform/agentHost/browser/agentHostProtocolClient.ts` (constructor invariant), 0010's selection line | The AHP gate on the only transport, the enablement setting, gate events |
| 1 | **0016** `seclab-ahp-reverse-requests` | `agentHostProtocolClient.ts` `_handleReverseRequest` | Inner layer: reverse requests refused in `seclab+` windows, shown on F |
| 2 | **0017** `seclab-tab-window-agent-settings` | the reading sites | Values fixed in `seclab+` windows for the confirmed tab-writable agent settings |
| 3 | **0018** `seclab-agent-host-sessions-only` | 0009's `chatServiceImpl.ts` guard | Chat requests in `seclab+` reach only this window's own gated agent-host sessions |
| 4 | **0019** `seclab-no-other-agent-host-providers` | cloud sandbox, Mission Control and connection-customization registrations | Null providers in `seclab+` windows |
| 5 | **0020** `seclab-ahp-authenticate` | the `authenticate` path only, as a module separate from the gate, plus the Tab Manager and tabd | The rewrite: trusted provider table, consent, broker import, sentinel |
| 6 | **0021** `seclab-ahp-rendering` (only if needed) | `stateToProgressAdapter.ts` | Inert rendering of tab content where the gate cannot strip it |

### Increment 1: 0015, the AHP gate (transport first)
- **What.**
  - `EditorRemoteAgentHostServiceClient` builds its transport over `agentHostProxy` in
    one place
    ([editorRemoteAgentHostServiceClient.ts#L116-L160](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/services/agentHost/browser/editorRemoteAgentHostServiceClient.ts#L116-L160)).
    For a `seclab+` authority the patch wraps it in `SeclabAhpGate`, a new file under
    `workbench/services/agentHost/browser/`. The window identity is the authority,
    resolved once at construction.
  - The gate applies the class (f) policy as data. Every AHP method, action type, channel
    kind, field and reverse request has a verdict, and the default is deny. Its effects:
    - **inbound:** schema validation for the negotiated version, size caps, and unknown
      items dropped and reported;
    - **reverse requests:** refused with a JSON-RPC error. The gate is primary for A16, A5
      and A26 on G; 0016 is the inner layer, shown on F;
    - **outbound `initialize`:** capabilities pinned (no client tools, no proxy, no
      client certificates). This replaces the client-capabilities patch;
    - **outbound tool lists:** stripped from active-client actions;
    - **outbound configuration and customizations:** filtered to the allowlist (empty in
      this increment). This replaces the customizations patch;
    - **inbound `ui://` and MCP App resources:** stripped, so `getMcpAppData` finds
      nothing (A21). This replaces the MCP App patch;
    - **`authenticate`:** passed to the separate credential module (0020). Until 0020
      lands, every `authenticate` frame is dropped and reported.
  - **Construction invariant.** The `AgentHostProtocolClient` constructor refuses a
    non-gated transport in a `seclab+` window and emits `ahp-gate.verified` once per
    connection. That is the runtime evidence that the gate is on the path, and a guard
    against a second transport (relay, IPC) being wired in later.
  - **Enablement.**
    - 0010 selects the client at
      [agentHostService.ts#L49-L57](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/services/agentHost/electron-browser/agentHostService.ts#L49-L57).
      RPC-lockdown's rework of 0010 calls the named predicate `seclabAgentHostAllowed`, and
      0015 implements it: setting off, 0010's refusal as today; setting on,
      `EditorRemoteAgentHostServiceClient` with the gate. 0015 does not edit 0010's lines.
    - The setting is registered in the gate file at `APPLICATION` scope.
    - With the setting off, nothing changes from v0.
  - **Events.** Each decision is reported over `tab.events.report` as class
    `ahp.decision`, from sources `ahp-gate`, `ahp-reverse` and `ahp-credential`. tabd fixes
    integrity to `trusted` for those three sources. The path is the trusted client's, as
    for `rpc-filter`, and never a command (the `seclab.*` prefix is denied). The shape was
    agreed with the observability session on 2026-11-06:
    - fields are `{source, class, priority, summary, detail}`;
    - `detail` is flat, with at most 16 keys and scalar values, and the gate's rule id is
      `detail.gateRule`;
    - priorities use the Falco names;
    - tabd tags untrusted strings itself.
    
    The client reports `ahp-gate.opened` for **every** agent-host connection it opens,
    gated or not, and `ahp-gate.verified` from the construction invariant.
    Observability's critical `ahp.ungated` detection fires on `opened` with no `verified`
    for that connection within about two seconds. Both events are trusted, so the tab can
    neither raise the detection nor suppress it.
- **Size.** About 25 lines in upstream files. The gate, the policy loader and the
  setting registration are new files.
- **Probes** (each must fail on U first):
  - A14: an unknown method, action type or vendor extension method, in each direction,
    plus the drift check failing on a seeded unclassified surface;
  - A16: `resourceRead` and `resourceWrite`;
  - A5 and A26: URIs outside the tab and special schemes;
  - A7: `createTcpConnection`;
  - A20: an advertised MCP resource at the beacon;
  - A21: MCP App UI;
  - A1 (trigger form only): no host fetch of a tab-chosen authorization server. The
    token half of A1 is meaningful only once credentials exist, so it is increment 5's;
  - A19 (config and customizations): canaries in host settings and `mcp.json` do not
    reach the tab;
  - A23 gains `seclab.agents.enabled`, through both the remote-user layer and
    `$updateConfigurationOption`.
- **Runtime evidence:** `ahp-gate.verified` and the deny events for each probe in the
  shipped G build.
- **0016, the inner layer.** `_handleReverseRequest`
  ([agentHostProtocolClient.ts#L3188](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/agentHost/browser/agentHostProtocolClient.ts#L3188))
  refuses every reverse request in a `seclab+` window and emits its own event. Probes:
  - A16 on F (the gate passing everything) is contained by 0016, with 0016's event as the
    deciding fact, and is vulnerable on U;
  - every G run asserts `ahp-reverse.armed` for each connection, which shows the layer is
    wired in what ships.
- **Depends on:**
  - RPC-lockdown's class (f) verdicts in `rpc-filter/policy/`, pinned by `check_drift.py`,
    landed after its name-based exemptions are removed;
  - the probe runner;
  - the signature of the `seclabAgentHostAllowed` predicate from RPC-lockdown's 0009/0010
    rework (§5).

### Increment 2: 0017, fixed values in tab windows
- **What.** In `seclab+` windows only, the agent settings confirmed tab-writable get a
  fixed value: `workbench.browser.enableRemoteProxy` is `false`, and
  `chat.automations.enabled` and `chat.automations.cloud.enabled` are `false`. The setting
  lists are those in design §3.5.
  - The user's decision on 0011 rules out global re-registration: lock tab windows,
    leave ordinary windows alone. So the patch overrides the read in tab windows; it does
    not change any registration.
  - `chat.agentHost.localFilePermissions` stays covered by 0011 and by the gate (reverse
    requests are refused).
- **Probes.** A23 (RPC-lockdown's) for these keys, on U and then G.
  `enableRemoteProxy`'s effect must first be shown on U with host evidence; the
  measurement to settle is which host-side fetch it enables.
- **Depends on:** RPC-lockdown's inventory at the then-current SHA. The "ambiguous" keys
  stay out until a probe shows an editor-window read.

### Increment 3: 0018, agent-host sessions only
- **What.**
  - 0009 refuses `chatService.sendRequest` in every `seclab+` window. Every chat
    submission goes through that call
    ([chatWidget.ts#L4088](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/chat/browser/widget/chatWidget.ts#L4088)),
    so with the setting on, the agent-host session would also be refused.
  - 0018 implements the 0009 side of the named predicate `seclabAgentHostAllowed` (RPC-lockdown
    calls it; it does not edit 0009's lines). It allows a request only when the session
    belongs to this window's own gated connection.
    - The check is bound to that connection's provider object (identity), not to a
      session-type string.
    - A string would be safe today only because the RPC filter denies
      `MainThreadChatAgents2.$register*` to tab extension hosts. The predicate must not
      silently depend on that.
  - Built-in agents, extension participants and every other session stay refused.
  - 0009's tool-registration and `invokeTool` refusals are unchanged; the agent host's
    tools run in the tab.
- **Probes.**
  - **0018's own assertion, on G with the setting on:**
    - a request to a session that is not from this window's gated connection is still
      refused, with 0018's event;
    - the window's own agent-host session is allowed, also with 0018's event.
    
    On U both are allowed.
  - Positive control: a turn with the real agent host and the fake model completes, and
    its tool marker appears in the tab, not on the host (A10).
  - Regression, which shows 0009 rather than 0018: workspace
    `.github/copilot-instructions.md` steers the built-in agent to a host-side fetch of
    the beacon. U has a beacon hit; G has none.
  - A6: tab-written remote settings change no trusted-side gate.
  - A13: agent writes to instructions, `tasks.json` or hooks are held by the write-back
    gate.
- **Depends on:** RPC-lockdown owns 0009 (§5).

### Increment 4: 0019, no other agent-host providers
- **What.** Null `ICloudSandboxAgentHostService`, Mission Control services and the
  connection-customization contribution in `seclab+` windows (design §3.5).
  `IRemoteAgentHostService` is already locked by 0011, and 0013 refuses the local agent
  host.
- **Probes.**
  - A positive assertion on every G run: in a `seclab+` window, each of these services
    resolves to the null provider, shown by its `seclab.null-provider.registered` event.
    It is not inferred from the absence of a connection.
  - A12.
  - A new probe, A17b: Mission Control's "connect to environment" against a fixture. That
    action is user-initiated, so the probe needs the runner to drive one command in the
    window. **Open:** how the runner drives UI without a test hook; if it cannot, A17b
    stays `not-implemented` and is said so.
- **Depends on:** the class (f) connection-provider verdicts (RPC-lockdown).

### Increment 5: 0020, the `authenticate` rewrite
- **What.** Design §4.2, as amended on 2026-11-06. It is a module separate from the gate
  (review round 1), so that one bug in the content filter does not also leave the tab
  credentialed:
  - it emits `ahp-credential.armed` when constructed in a `seclab+` window (asserted on every G run);
  - it accepts `authenticate` work only from a gate that has emitted `ahp-gate.verified`
    for this connection; otherwise it issues nothing;
  - it matches the advertised resource against a trusted provider table (product data,
    `APPLICATION` scope);
  - it asks once per tab;
  - it resolves the session on the trusted side, and hands the real value to tabd;
  - tabd calls the broker's `credential.import` with the table's bindings: the GitHub
    credential bound to the Copilot API model endpoints by exact path and method, plus
    `/copilot_internal/user` and the three org-policy `GET`s;
  - the module sends the returned sentinel in `authenticate`, and emits its own event.
    Unknown resources get an empty token.
- **What the user's token now does.** The tab's model traffic carries the durable GitHub
  credential, not a short-lived derived token (amended D7). The only limits on what a
  rogue tab puts in those requests are:
  - the exact path and method binding;
  - the broker's provider field and tool-type lists.
  
  The spike showed those lists must widen (`custom` tools, `snippy`, `system`,
  `thinking`, `/v1/messages`). Each widening is justified in the broker's records against
  what the field does server-side, not only as "measured". **[interface: broker]**
- **Interfaces.**
  - **tabd:** a new supervisor method for a trusted-side credential import. Tab Manager
    to tabd only; it never takes a value from the tab. **[interface: tabd]**
  - **Broker:** the provider table rows. **[interface: broker]** The three org-policy
    responses have never been measured. Until a real one is, their check fails closed on
    any key not on the allowlist, rather than matching a pattern.
- **Probes:**
  - A1 (sentinel form): only sentinels reach the tab, and real-token canaries never
    appear in tab memory, disk, frames or broker-forwarded traffic;
  - A1 on F: with the gate passing everything, the credential module still issues only
    sentinels for table resources, with its own event;
  - A2 (MCP OAuth);
  - A25 (sealed values, Codex sign-in);
  - A9 (budget, broker side);
  - A22 (broker).
- **Depends on:** the canary session (increment 0, open) and the broker's amended
  provider table.

### Increment 6: 0021, rendering (only if needed)
- **What.** The first task is a measurement: how upstream's adapter renders AHP content
  (markdown trust, command links, images, links to `seclab-vscode://`).
  - Where the gate can strip it inbound, there is no patch.
  - Where the adapter adds trusted affordances itself (for example the add-comment
    command link, design §3.4), a small patch in `stateToProgressAdapter.ts` makes them
    inert for `seclab+`.
- **Probes:** A4 and A24, which must fail on U first.

### Tier A exit
- Every Tier A probe passes on sbx and OCI against G, fails on U, and holds on v0. Every
  inner-layer probe also passes on F.
- A security review with no open high or critical finding.
- The user decides whether `seclab.agents.enabled` is turned on for them.

## 5. Coordination

| Session | Ask | Needed by |
|---|---|---|
| RPC-lockdown | The class (f) AHP verdicts in `rpc-filter/policy/`, pinned by `check_drift.py`, as the gate's policy data. They land only after RPC-lockdown removes the name-based coverage exemptions, so that every verdict is in the digest; until its enforcement-mapping gate exists, a verdict is intent, and the gate's own probes prove enforcement | Inc 1 |
| RPC-lockdown | The named predicate `seclabAgentHostAllowed(authority, …)`, called from 0009 and 0010 and implemented by 0015 and 0018 (agreed 2026-11-06). The exact signature arrives with RPC-lockdown's 0009/0010 rework, and the predicate is the enforcement point its mapping gate will cite | Inc 1, Inc 3 |
| RPC-lockdown | The shared probe runner (§3) and A17, A18 and A23 behind it; 0009's `invokeTool` refusal stays primary for A18; A23 covers `$updateConfigurationOption` as well as remote settings | Inc 0 |
| RPC-lockdown | Review of the layering in §1 (gate, inner layers on F) | Inc 1 review |
| Fork-build | `patches/reach.json` entries pinning 0015–0021 to `desktop`; for U and F: a positive release marker in `check-release`, a separate fetch destination, a distinct product name and bundle id, and a build-info field (§2) | Inc 0 |
| Broker | Provider-table rows per the amended D7 and the org-policy exceptions (in progress); fail closed on unknown keys for the unmeasured org-policy responses; a justification per widened field or tool type | Inc 5 |
| Observability | The class `ahp.decision` and sources `ahp-gate`, `ahp-reverse` and `ahp-credential` in the `tab.events.report` allowlist, with integrity fixed to `trusted`; the `ahp.ungated` detection; the vocabulary keys. Agreed on 2026-11-06; to be added with a review round once the renderer side emits | Inc 1 |
| tabd owner | A supervisor method for trusted-side credential import (Tab Manager to tabd) | Inc 5 |

## 6. Risks to this plan
- **The takeover may not work** (for example, if the REH holds one long-lived connection
  to the agent host). Fallback: the test-only bridge path; that is recorded as a test
  hook, not used to hide a gap.
- **U and F are unsafe by design.** They differ from G by reverting or disabling controls.
  The §2 safeguards must exist before either is built; until then increment 0 stops at
  the runner.
- **The macOS build cadence.** Each increment needs branch builds from Actions (G, and U
  or F when they change). A slow build slows every increment; there is no local fallback
  for the editor (8 GB Docker VM, AGENTS.md).
- **The gate concentrates content filtering.** It is mitigated by:
  - the construction invariant;
  - the drift check failing on any unclassified surface;
  - the inner reverse-request layer (0016);
  - the separate credential module (0020);
  - 0009 staying primary for tool execution;
  - the broker and the fence staying primary for egress.
