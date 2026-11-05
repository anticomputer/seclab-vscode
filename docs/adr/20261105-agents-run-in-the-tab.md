# Run agents inside the tab; the trusted editor only renders them

- **Status:** proposed
- **Date:** 2026-11-05
- **Deciders:** anticomputer (user; requests: "make a plan to move chat into sandboxed tabs", "agentic experiences are central to vscode, but we want to implement them securely with limited blast radius"); secure-agentic-experiences session (design). Pending the user's decisions D1 to D9 in the [plan](../plans/secure-agentic-experiences.md#13-decisions-for-the-user).
- **Related:** [plan](../plans/secure-agentic-experiences.md), [agentic surfaces research](../research/agentic-surfaces.md), [prior art](../research/agentic-prior-art.md), [threat model](20261104-threat-model-rogue-extension.md), [no real secret enters a tab](20261104-no-real-secret-enters-a-tab.md), [broker output is data](20261104-broker-output-is-data.md), [RPC filter enforcement points](20261104-rpc-filter-enforcement-points.md), [write-back gate](20261104-write-back-gate.md), [tab observability](20261104-tab-observability.md), [security review](../security-reviews/20261105-secure-agentic-experiences-design.md)

## Context
- Code-OSS 1.145.0's built-in chat runs in the trusted workbench, reads workspace
  instruction files as authority, and has tools that act on the host even in a remote
  window. A tab can steer it by writing a file, with no RPC crossing the boundary
  ([research §1, §4, §5](../research/agentic-surfaces.md#1-summary)). v0 turns it off in
  tab windows; this decides how to turn agents back on.
- Upstream already has a second agent architecture, the agent host, and in a remote
  window the REH spawns it on the remote machine and the workbench renders it over the
  remote connection
  ([research §3.2](../research/agentic-surfaces.md#32-remote-windows-the-reh-hosts-it)).
  In our fork the remote machine is the tab.
- That upstream path forwards real tokens into the remote for resources and scopes the
  remote chooses, and offers the remote every enabled workbench tool as a "client tool"
  ([research §4.3, §12](../research/agentic-surfaces.md#12-credentials)).
- The tab controls every settings scope except `APPLICATION`
  ([research §11](../research/agentic-surfaces.md#11-settings-a-tab-controls)), and
  `IToolData.runsInWorkspace` affects only which settings layers may auto-approve a tool
  ([research §4.1](../research/agentic-surfaces.md#41-runsinworkspace-does-not-place-anything)).
- Every mature agent system runs the loop away from the UI and keeps consequential
  credentials out of the agent's reach
  ([prior art §7](../research/agentic-prior-art.md#7-what-we-take-from-it)).

## Decision
**An agent for tab *T* runs inside *T*, with *T*'s authority; the trusted editor renders
it and carries the user's input and decisions, and nothing else.** Concretely:

- **Vehicle:** upstream's agent host, spawned by the tab's REH in its default mode and
  rendered by the workbench's remote agent-host client. The local (host) agent host is
  disabled in the fork.
- **AHP gate:** a choke point on the agent-host transport for `seclab+` windows, with
  policy as data and a drift check, like the RPC filter. Inbound messages are
  schema-validated against the generated protocol; outbound `authenticate` carries only
  broker sentinels for resources in a trusted provider table; the client offers no tools
  except reviewed safe outputs; client proxy, certificates and TCP are off.
- **Models:** called from inside the tab through the tab's broker with sentinels, never
  trusted-side on the tab's behalf.
- **Tiers:** A (default) acts only inside the tab; B turns host-affecting actions into
  schema-validated safe outputs that trusted code applies after the user approves the
  exact effect; C is opt-in, scoped, time-boxed grants. Some capabilities are never
  grantable (host shell, host writes outside the write-back gate, other tabs, real
  secrets).
- **Trust inputs:** only trusted UI input, `APPLICATION` settings, the trusted profile,
  product data and code set policy. Workspace instructions are data.
- **One agent, one tab.** Global chat runs in the empty tab a folder-less window already
  gets; cross-tab questions are answered by trusted code over structured data, with at
  most a quarantined, tool-less model call.

## Alternatives considered
- **Keep chat trusted-side and mediate its tools:** rejected. The trusted context would
  hold tab content, and tab-written settings and instructions steer it.
- **Extension-hosted chat participants in the tab as the primary vehicle:** deferred to a
  later compatibility tier. It needs `MainThreadChatAgents2`, chat sessions and tools
  re-opened under a progress filter, and its core tools are workbench tools.
- **Our own agent:** rejected; a parallel stack against a fast-moving upstream.
- **Trusted-side model calls on the tab's behalf:** rejected, as in the broker ADR: a
  credentialed channel outside the broker.
- **Rely on `runsInWorkspace` or upstream's agent sandbox:** rejected. The first does not
  place execution; the second is a process sandbox on the same host and is configured by
  tab-writable settings.

## Consequences
- Prompt injection against a tab agent can do at most what a rogue extension in that tab
  can do; the existing containment carries the argument. In-tab defences (labels,
  instruction policy) are defence in depth against honest-agent steering only.
- New work: the AHP gate and its inventory (class (f)), the `authenticate` rewrite and a
  trusted provider table, a broker derivation rule for the Copilot token, safe outputs and
  a host-action inbox, a `tab-reported` event label, and rendering hardening.
- About four small patches, each one concern, plus policy data. Upstream proposals U1 to
  U5 are drafted, not filed.
- Opaque prebuilt agent runtimes would run inside tabs; they need a supply-chain decision.
- A rogue extension can spend the user's model quota up to the tab's budget.
- Phases, probes and residual risks: [plan §11, §12](../plans/secure-agentic-experiences.md#11-phases-exit-criteria-and-probes).

## Evidence
- [Agentic surfaces research](../research/agentic-surfaces.md), every claim pinned to
  `microsoft/vscode@a717861c07586a53d83b80d742cd3f59b20a6273`.
- REH agent-host wiring:
  [serverServices.ts#L253-L395](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/server/node/serverServices.ts#L253-L395);
  remote client selection:
  [agentHostService.ts#L49-L57](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/services/agentHost/electron-browser/agentHostService.ts#L49-L57).
- Credential forwarding chosen by the remote:
  [agentHostAuth.ts#L895-L951](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/chat/browser/agentSessions/agentHost/agentHostAuth.ts#L895-L951).
- Client tools:
  [agentHostActiveClientService.ts#L474-L512](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/chat/browser/agentSessions/agentHost/agentHostActiveClientService.ts#L474-L512).
- Class (e) inventory, RPC-lockdown session, branch `anticomputer-rpc-filter-patches`
  commit `5e28803`.
