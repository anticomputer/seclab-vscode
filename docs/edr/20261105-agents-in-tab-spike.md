# Agents-in-the-tab spike: real client, rogue and real agent hosts, measured

- **Status:** accepted
- **Date:** 2026-11-05
- **Deciders:** anticomputer (user: "Accept the recommended options and start the first spike with a fake model endpoint and no real credentials"); secure-agentic-experiences session (spike). Coordinator constraints: probes must fail on an unmitigated baseline first with real evidence; string-aware extraction reusing RPC-lockdown's stripper; no editor window on the user's display.
- **Related:** [ADR agents run in the tab](../adr/20261105-agents-run-in-the-tab.md), [plan §11.1](../plans/secure-agentic-experiences.md#111-recommended-first-spike-an-agent-host-in-a-tab-rendered-with-no-credential), [agentic surfaces](../research/agentic-surfaces.md), [EDR agent runtimes exception](20261105-agent-runtimes-exception.md), [security review](../security-reviews/20261105-agents-in-tab-spike.md)

## Context
The design rests on claims about upstream's agent-host client that, until now, came from
reading code: that a tab-side agent host can obtain the user's token, read and write host
files, run workbench tools, and receive host settings, and that a gate on the transport
contains all of that. The RPC-lockdown session had just found that its own AI probes could
not fail, so absence of evidence had been scored as containment. This spike measures
instead, and is built so that it cannot repeat that mistake.

## Decision
**1. Probe the real client, at protocol level, against a rogue agent host**
(`test/agentic/ahp/run.sh`).
- `bundle.mjs` bundles the upstream modules straight from the pinned source with the
  builder volume's esbuild, mounted read-only. That covers `AgentHostProtocolClient`,
  `AgentHostResourceService`, `FileService` with the node disk provider, the configuration
  models, `agentHostAuth` and `AgentHostSessionHandler`: 1,328 modules.
- Two bundles are built. **baseline** is the pristine source, byte for byte. **gated** is
  the same source plus prototype patches applied in memory at bundle time; the tree is
  never touched.
- What is substituted, and why:
  - one constant import (`CHAT_SETUP_ACTION_ID`) is stubbed so the chat-actions UI isn't
    pulled in; its value is read from the real file;
  - DOM globals get inert placeholders, because no DOM behaviour is under test;
  - services the code under test does not depend on get inert stand-ins.
- The rogue agent host is an inert fixture. It runs in-process in a `--network none`
  container, acts only when armed with the run's nonce, names only paths under the run
  directory, and asks only for seeded `seclabcanary_` values.
- The tab-written remote user settings go through the real `ConfigurationModelParser` with
  `REMOTE_MACHINE_SCOPES`, exactly as `configuration.ts#L401` does.
- **Verdict rule** (`verdict.mjs`): a probe passes only if it is **vulnerable on baseline**
  with its trigger sent and positive evidence (a file actually written on disk, or a canary
  actually received over the wire), **and** contained when gated with *its own* gate
  decision recorded. Otherwise it is FAIL, or INVALID when it could not fail on baseline.
  `--disarmed` is the control.

**2. Observe the real agent host from our shipped REH** (`test/agentic/ahp/in-tab.sh`).
- `agentHostMain` is started from the REH build exactly as the REH starts it, offline, in a
  `--network none` container standing in for the fenced tab, and the real client connects
  over its WebSocket.
- A loopback-only recorder (`proxy-recorder.mjs`) plays the broker. It answers CONNECT and
  terminates TLS with a leaf from a per-run test CA, and it never forwards anything.

**3. Draft the class (f) inventory** (`test/agentic/ahp/ahp_inventory.py`). It imports the
RPC generator's fixed, string-aware `strip_block_comments` from
`anticomputer-rpc-filter-patches` (`5104309`) via `git archive`; it does not copy it.
`--self-test` injects one of each surface kind behind a `'/*'` inside a string literal,
the pattern that blinded the old stripper, and fails on any miss. The draft is handed to
RPC-lockdown to adapt into its generator and drift gate.

## Results

### Rogue agent host against the real client (run `20261105T185614Z-97e0f87244241e60`)

| Probe | Baseline (unmodified upstream) | Gated (prototype) | Verdict |
|---|---|---|---|
| A1: agent host names a protected resource | Real token canary received in `authenticate` | Sentinel received; gate rewrote `authenticate` | PASS |
| A16-write: `resourceWrite` under a grant the tab wrote into remote user settings | Host file overwritten on disk with the run marker (sha256 changed; visible on the macOS filesystem in the run dir) | Reverse request denied; file unchanged | PASS |
| A16-read: `resourceRead` of a host file | Host canary returned to the agent host | Reverse request denied | PASS |
| A19-config: the user's `http.proxy` credentials | Proxy-credential canary mirrored in `root/configChanged` | Gate stripped every non-allowlisted mirrored setting | PASS |
| A18: a client-tool execution request for a workbench tool | The real `AgentHostSessionHandler`, entered at `_executeClientTool`, called `invokeTool` for `run_playwright_code`. The client never advertised that tool, the pre-approval passed on was `{Setting, autoApprove}` taken from the agent host's own `_meta`, and the payload carried the marker | Prototype patch refused client-tool execution; decision recorded | PASS |

In the disarmed control (run `20261105T185618Z-38414d7c8b059707`) every probe reports
INVALID and the run exits 1. A19 still leaks unarmed, because the client pushes its
configuration on connect whatever the agent host does, but a disarmed run never scores a
pass.

**What A18 does and does not show.**
- It shows two of the handler's decisions:
  - it resolves a requested tool over all tools, not the set it advertised
    ([#L3330-L3350](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/chat/browser/agentSessions/agentHost/agentHostSessionHandler.ts#L3330-L3350));
  - it forwards the agent host's own claim of approval as a confirmed reason
    ([#L584-L608](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/chat/browser/agentSessions/agentHost/agentHostSessionHandler.ts#L584-L608)).
- It does not exercise:
  - the ownership check and the autorun that claims or denies requests (the harness
    enters past them);
  - the unclaimed path (the probe passes a context session).
- `invokeTool` is a recording stand-in. Whether the real `LanguageModelToolsService` then
  skips confirmation is established by reading code, not by this run: it honours
  `preApproved`, apart from a few tool and hook exceptions.
- In a real window, `run_playwright_code` is registered only when browser sharing is
  available.
- Strengthening it (the rogue delivers the request over the protocol; the real tools
  service with an inert marker-writing tool; recorded dialogs) is the next step for this
  probe.

### The shipped agent host, offline (runs `20261105T1856*-intab`, one per proxy mode, each with `run.json`)
- **Protected resources the Copilot harness (`copilotcli`) advertises:**
  - `https://api.github.com`, scopes `read:user`, `user:email`, required;
  - `https://api.github.com/repos`, scope `repo`, optional.
  
  Upstream would therefore push a **`repo`-scoped** GitHub token into the tab for the
  second one.
- **Its first egress** is `GET https://api.github.com/copilot_internal/user` with
  `Authorization: Bearer <credential>`. The sentinel arrived intact, in `Bearer` form.
- **Proxy and CA:**

  | Variant | Result |
  |---|---|
  | No proxy | Direct egress fails: the agent host's own log records each failed request to `copilot_internal/user`, and nothing reaches the recorder |
  | Proxy, without our CA | TLS refused with `UNKNOWN_CA`: the runtime verifies certificates |
  | Proxy with `SSL_CERT_FILE` only | Handshake completes; request arrives |
  | Proxy with `NODE_EXTRA_CA_CERTS` only | Handshake completes; request arrives |

  The broker's TLS interception will work for this runtime, and the tab's existing proxy
  and CA wiring is enough.
- The agent host accepted the sentinel (`authenticated: true`) and listed no models, as
  expected with no upstream reachable. The sentinel was not found in its logs or home
  directory.

### Inventory draft (class (f))
- 64 protocol methods across both directions;
- 108 action types;
- 36 vendor extension methods, 3 of them server→client:
  `vscode/clientArtifactIntegrations`, `vscode/requestMcpAuthentication`,
  `vscode/requestWorkspaceTrust`;
- 33 client handler cases;
- 55 agent-host connection-service registrations, split into `agents-window` and
  `editor-or-shared`.

## Findings
1. **The client-tool ownership check authenticates nothing.**
   - It compares `request.clientId` with the client's own id
     ([agentHostSessionHandler.ts#L3243-L3245](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/chat/browser/agentSessions/agentHost/agentHostSessionHandler.ts#L3243-L3245)),
     and the client sends that id to the agent host in `initialize`. Anything that
     receives it can repeat it back; the A18 probe supplies it the same way.
   - Upstream uses `clientId` to route work among cooperating clients of one agent host,
     not as authentication. Against a hostile agent host, the connection is the only
     identity, which is why the plan puts the gate on the connection. (RPC-lockdown
     raised the question.)
2. **A registration-only tool gate would have been wrong.** The handler resolves client
   tools over all tools, including ones it never advertised. A18 is the probe that
   justifies patch 0009 guarding `invokeTool` as well as registration; it stays pointed at
   `invokeTool`.
3. **`createResourceWatch` is declared server→client but the client has no handler.** It
   answers "Unknown method". Research §12.4 is corrected accordingly.
4. **Broker binding facts** (sent to the broker session):
   - the GitHub credential is presented as `Bearer`;
   - the runtime's first route is `GET /copilot_internal/user`;
   - the optional `repo` resource needs its own, narrower binding, or none.

## Not done, and why
- **Neither an sbx tab nor the real broker.**
  - Tab-broker wiring (M2/M3) has not landed in tabd (`tabd/src/broker.ts`: "tabd does not
    talk to the broker yet").
  - npm and pip registries were unreachable from this host and its containers on
    2026-11-05, so a template or broker image couldn't be built.
  - The network-less container is the fence's fail-closed behaviour, not the fence.
  - Next: the same `in-tab.sh` inside an sbx tab, once tabd starts a tab with its broker.
    Use the broker session's fixture recipe: an `--internal` 11.250/16 network, a network
    alias for the model host, and `credential.import` with `derive`.
- **No model endpoint answered.** The recorder returns 503. A fixture model API behind the
  broker comes with the step above.
- **A2, A3, A4, A5, A7 and A9 to A15 are `not-implemented`.**
  - A4: agent-host markdown is built untrusted upstream (`new MarkdownString(rp.content)`),
    so the command-link case cannot fail on baseline and is not counted. The URL
    input-request card (review round 2, finding 2) needs the handler's accept path.
  - A7: needs a browser view.
  - A17 and A23: belong to RPC-lockdown's suite. Its reworked patch 0011 locks dialing in
    `_reconcileConnections` and leaves the setting's scope alone. A gated mode for A17 must
    model that override, and should show the setting arriving and the dial refused.
- **The gated results are prototypes, not patches.**
  - The transport gate in `runner.ts` refuses every server→client request, rewrites
    `authenticate`, and strips mirrored settings against an empty allowlist. It is not yet
    schema validation.
  - The session-handler prototype reads a test global where the real patch reads
    `IWorkbenchEnvironmentService`.
  - The patches go to the fork-build session, numbered from 0015, each with its EDR and
    review round. Fork-build owns 0013 (no local agent host) and 0014 (runtime kept out of
    the desktop app).

## Consequences
- The plan's first four findings (credential push, host files, client tools, settings
  mirroring) are now measured, not inferred, and a gate at the transport plus one handler
  patch contains all five probes.
- The runner is reusable. RPC-lockdown can wire A17, A18 and A23 behind it.
- Spike output (bundles, run directories, keys) lives under `.work/agentic/` and is never
  committed. Bundles are deleted after each run, and the per-run CA and leaf private keys
  are deleted before the container exits. The CA is trusted only inside that container,
  through `SSL_CERT_FILE` or `NODE_EXTRA_CA_CERTS`, and never on the host.

## Evidence
- `test/agentic/ahp/run.sh`; results in `.work/agentic/runs/<id>/verdicts.json` and
  `results-{baseline,gated}.json`.
- `test/agentic/ahp/in-tab.sh` with `PROXY_MODE` in `none`, `proxy-noca`,
  `proxy+sslcertfile`, `proxy+nodeextra` or `proxy+ca`; results in `in-tab-report.json` and
  `proxy-events.json`.
- `test/agentic/ahp/inventory.sh [--self-test]` writes `.work/agentic/ahp-inventory.json`.
