# Agentic surfaces in Code-OSS 1.145.0: where chat and agents run in a tab window

**Scope.** Every `microsoft/vscode` citation is pinned to
`a717861c07586a53d83b80d742cd3f59b20a6273` (1.145.0, `upstream.lock`). Line numbers were
checked against a checkout of that SHA. **[inference]** marks a claim drawn from reading
code that was not exercised by a probe. Upstream source, comments, prompts and docs were
read as data; none of them contained text addressed to the reader.

**Question.** For a `seclab+<tabId>` window (a remote window whose REH runs in the tab),
which layer does each piece of chat and agent machinery run in, what crosses the
boundary, and which upstream mechanism is the right vehicle for "agent in the tab, chat
UI trusted"? The design built on this is
[secure agentic experiences](../plans/secure-agentic-experiences.md).

The class (e) inventory from the RPC-lockdown session (54 tool definitions, 67 agent
settings) is the source of truth for the tool and setting lists; this note adds the
placement, credential and rendering facts the inventory does not carry.

---

## 1. Summary

| Piece | Where it runs in a tab window | Evidence |
|---|---|---|
| Chat UI (widget, markdown, tool and confirmation parts, diff views) | Trusted workbench renderer | §8 |
| `IChatService.sendRequest` dispatch | Trusted workbench; the loop belongs to the participant | §2.1 |
| Extension chat participants and their loop (e.g. Copilot's `ToolCallingLoop`) | The extension host that registered them: the tab, since every non-built-in is forced to `workspace` | §2.1, §10 |
| Agent host (AHP) for a remote window | **The REH spawns it, inside the tab**; the workbench connects through the remote connection | §3 |
| Agent host for a local window and the Agents window | Electron utility process on the host, with the user's full environment | §3.1 |
| Extension-contributed tools (`vscode.lm.registerTool`) | The registering extension host (the tab) | §4 |
| Built-in workbench tools (browser/Playwright, fetch, install extension, sessions tools) | Trusted workbench or Electron main, on the host | §4.2 |
| Terminal and task tools | Workbench-side tool, but the pty is the remote pty host: the command runs in the tab **[inference]** | §4.2 |
| Instruction, prompt, agent and skill discovery | Workbench; reads go through the remote file system provider into the tab | §5 |
| `vscode.lm` model calls | Trusted workbench (the provider's host), with the user's credentials | §6 |
| stdio MCP servers in a remote window | Remote (the tab) | §7 |
| Agent sandbox (Seatbelt, bubblewrap, `@vscode/sandbox-runtime`) | An inner layer around a process; not a VM or container boundary | §7.2 |
| Chat edits to workspace files | Workbench `IFileService` onto the remote URI, so the bytes land in the tab | §9 |
| Settings that steer agents | Every scope except `APPLICATION` can come from the tab | §11 |

The two findings that shape the design most:

1. **Upstream already runs the agent host in the remote.** In a remote window the
   workbench's `IAgentHostService` is a client of an agent host that the REH spawns on
   its own machine (§3). For us that is the tab. It is the closest upstream vehicle for
   "agent loop in the tab".
2. **That path pushes real credentials into the remote, chosen by the remote.** The
   agent host advertises protected resources and scopes; the workbench resolves a
   matching session and sends its access token (§12.1). The same happens for MCP OAuth
   (§12.2). A `seclab+` tab would receive the user's GitHub token. This was raised to
   the RPC-lockdown session as an interim finding on 2026-11-05.
3. **The agent-host client is a two-way capability channel, and not the only one.** The
   agent host can ask the client to read and write host files, run any workbench tool
   with pre-approval it asserts itself, and receive the user's MCP configurations, and a
   workspace setting can point the editor at an attacker's agent host from the host
   network (§4.3, §12.4 to §12.6). These were found by the design review.

## 2. Two agent architectures

### 2.1 Extension-hosted participants (classic chat)

- `ChatService.sendRequest` validates and queues the request, then delegates to the
  selected agent through `IChatAgentService`. It has no model, tool, model loop of its
  own ([chatServiceImpl.ts#L1528-L1540](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/chat/common/chatService/chatServiceImpl.ts#L1528-L1540) **[inference: read, not traced through every agent kind]**).
- A participant registered by an extension streams progress back over
  `MainThreadChatAgents2.$handleProgressChunk`, which the workbench revives into
  markdown, tool invocations, edits and buttons
  ([mainThreadChatAgents2.ts#L480-L570](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/api/browser/mainThreadChatAgents2.ts#L480-L570)).
- Extensions can also contribute a whole session type rendered by the workbench through
  `MainThreadChatSessions`
  ([#L869](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/api/browser/mainThreadChatSessions.ts#L869),
  [`$handleProgressChunk` #L897](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/api/browser/mainThreadChatSessions.ts#L897)).
- The Copilot extension's agent loop is `ToolCallingLoop` in the extension host
  ([toolCallingLoop.ts](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/extensions/copilot/src/extension/intents/node/toolCallingLoop.ts#L1-L31)).
  Its core tools (run in terminal, subagent, ask questions) are invoked through
  `vscode.lm.invokeTool`, so they execute in the workbench
  ([toolsService.ts#L126-L129](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/extensions/copilot/src/extension/tools/vscode-node/toolsService.ts#L126-L129),
  [toolDeferralService.ts#L11-L25](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/extensions/copilot/src/extension/tools/common/toolDeferralService.ts#L11-L25)).

In v0 every one of these RPC surfaces is denied to a tab by the RPC filter
(`MainThreadChatAgents2`, `MainThreadLanguageModels` explicitly; chat sessions and tools
by default-deny, [policy](../../rpc-filter/policy/policy.json)). A chat extension in a
tab therefore runs but cannot show anything.

### 2.2 The agent host and the Agent Host Protocol (AHP)

The agent host is a separate Node process that owns the loop, providers (Copilot,
Claude, Codex harnesses), terminals, MCP, customization discovery and persistence. Its
protocol is state and action based. The generated protocol has root, session, chat,
terminal, changeset, resource-watch, automation, automation-run, annotations, canvas,
OTLP, TCP and `mcp:/` channels
([commands.ts#L10-L17](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/agentHost/common/state/protocol/commands.ts#L10-L17)
re-exports the per-channel commands). The method maps in both directions are in
[messages.ts](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/agentHost/common/state/protocol/common/messages.ts#L120-L145)
and the version registry in `protocol/version/registry.ts`. On top of that, the client
handles 36 vendor extension methods defined in
[agentHostExtensionProtocol.ts](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/agentHost/common/agentHostExtensionProtocol.ts),
outside the generated protocol. Some requests go from the agent host **to the client**,
and the client serves them on the host: `resource*` file operations, workspace trust,
client certificates, proxy resolution and Kerberos, and MCP authentication
([agentHostProtocolClient.ts#L3291-L3365](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/agentHost/browser/agentHostProtocolClient.ts#L3291-L3365)).
Upstream's own design notes: [AGENTS.md](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/agentHost/AGENTS.md).

## 3. Where the agent host runs

### 3.1 Local windows

Electron main starts it as a utility process with `process.env` plus the resolved login
shell environment
([electronAgentHostStarter.ts#L206-L227](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/agentHost/electron-main/electronAgentHostStarter.ts#L206-L227)).
That is a host process with the user's full privileges and environment. Our fork never
opens a folder in a local window, but the Agents window and a folder-less window can
still use it (§13).

### 3.2 Remote windows: the REH hosts it

The REH wires an agent host three ways: spawn (`--agent-host-port`/`--agent-host-path`),
bridge (`--agent-host-bridge-*`), or by default a **lazy agent host on a fresh local
socket, started when the first renderer connects**. In every case it registers the IPC
channel `agentHostProxy` on the remote connection
([serverServices.ts#L253-L395](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/server/node/serverServices.ts#L253-L395),
[channel name agentService.ts#L88](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/agentHost/common/agentService.ts#L88)).
In the default mode the starter takes environment overrides that the client sends
([#L378-L388](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/server/node/serverServices.ts#L378-L388)); the client sends the
resolver's `extensionHostEnv`, which our Tab Manager controls.

On the desktop workbench, a window with a remote authority gets
`EditorRemoteAgentHostServiceClient` instead of the local agent host
([agentHostService.ts#L49-L57](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/services/agentHost/electron-browser/agentHostService.ts#L49-L57)).
It builds an AHP client over `agentHostProxy`
([editorRemoteAgentHostServiceClient.ts#L116-L160](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/services/agentHost/browser/editorRemoteAgentHostServiceClient.ts#L116-L160))
and connects as soon as the agent host is enabled
([#L166-L170](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/services/agentHost/browser/editorRemoteAgentHostServiceClient.ts#L166-L170)).
Enablement is "desktop and `chat.disableAIFeatures` is false"
([agentHostEnablementService.ts#L31-L33](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/agentHost/browser/agentHostEnablementService.ts#L31-L33)),
and that setting is `WINDOW` scope, so a tab can set it
([chat.shared.contribution.ts#L2381-L2386](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/chat/browser/chat.shared.contribution.ts#L2381-L2386), §11).

The client offers proxy resolution and Kerberos tickets to the agent host only when the
remote shares the client's network: WSL or a container with `useHostProxy`
([#L141](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/services/agentHost/browser/editorRemoteAgentHostServiceClient.ts#L141),
[agentHostClientProxy.ts#L16-L24](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/agentHost/browser/agentHostClientProxy.ts#L16-L24)).
A `seclab+` authority is neither, so that path is off.

**Consequence.** With the REH in the tab, upstream's own remote path puts the agent
loop, its provider SDK, its terminals, MCP servers and instruction discovery inside the
tab, and the workbench renders AHP state. That is the placement we want. What the
workbench sends back into the tab (§12) and what it agrees to run for the tab (§4.3) are
what must change.

## 4. Tools

### 4.1 `runsInWorkspace` does not place anything

`IToolData.runsInWorkspace` is documented as "true if the tool runs in the (possibly
remote) workspace, false if it runs on the host"
([languageModelToolsService.ts#L64-L68](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/chat/common/tools/languageModelToolsService.ts#L64-L68)).
Its only consumer is auto-approval: it chooses which settings layers may auto-approve a
tool, and `true` admits workspace, folder and remote-user values
([languageModelToolsService.ts#L1414-L1460](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/chat/browser/tools/languageModelToolsService.ts#L1414-L1460)).
It never moves execution. Extension tools run where the extension runs: invocation is
proxied back to the registering host
([mainThreadLanguageModelTools.ts#L92-L160](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/api/browser/mainThreadLanguageModelTools.ts#L92-L160)).

In the class (e) inventory, no tool declares `runsInWorkspace: true`; the
`src/vs/sessions` tools declare `false`; 38 declare nothing. Setting it to `true` on a
tool that can reach the host would let tab-written settings auto-approve that tool
(§11). The design must never do that.

### 4.2 Built-in tools, by host effect in a tab window

From the inventory, with placement checked for the ones that matter:

| Tool(s) | Runs in | Host effect |
|---|---|---|
| `run_playwright_code`, `open_browser_page`, `navigate_page`, `click_element`, `type_in_page`, `read_page`, `screenshot_page`, `handle_dialog`, `hover_element`, `drag_element`, `list_browser_pages` | `electron-browser` workbench, through `IPlaywrightService` ([runPlaywrightCodeTool.ts#L58](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/browserView/electron-browser/tools/runPlaywrightCodeTool.ts#L58)) | Code execution in a host browser session, host network, host `localhost` **[inference]**. Confirmation is a dialog ([#L75-L76](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/browserView/electron-browser/tools/runPlaywrightCodeTool.ts#L75-L76)) |
| `vscode_fetchWebPage_internal` | `electron-browser` workbench ([fetchPageTool.ts](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/chat/electron-browser/builtInTools/fetchPageTool.ts#L238-L258)) | Host network egress that bypasses the broker; `file:` reads on the host. Auto-approved only for URLs in the user's own messages ([#L240-L258](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/chat/electron-browser/builtInTools/fetchPageTool.ts#L240-L258)) |
| `vscode_installExtensions`, `vscode_searchExtensions_internal` | Workbench | Install is routed by extension kind; with patches 0002–0004 a third-party extension lands in the tab **[inference]** |
| `run_in_terminal`, `send_to_terminal`, `get_terminal_output`, `kill_terminal`, `terminal_*`, `create_and_run_task`, `run_task`, `get_task_output` | Workbench tool; terminals and tasks on the remote pty and task backends **[inference]** | None if the pty is remote. Probe required, because a local terminal in a remote window is one command away (`workbench.action.terminal.newLocal`, RPC-LOCKDOWN §4.6) |
| `vscode_editFile_internal`, `runSubagent`, confirmation tools, `task_complete`, artifacts | Workbench | Writes go to the URI named; a non-tab URI is a host write |
| `vscode_create_remote_session`, `vscode_send_remote_message`, `vscode_*Automation`, `vscode_readSessionsList`, `vscode_screenshotWindow`, theme and background tools | Workbench (`src/vs/sessions`), all `runsInWorkspace: false` | Start work on other agent hosts, create durable automations, read other sessions, screenshot the window. Cross-tab by construction |
| MCP-backed tools | Where the MCP server runs (§7) | Per server |

### 4.3 Client tools: the agent host can ask the workbench to run its tools

An AHP client advertises "client tools" to the agent host: **every enabled, non-MCP
workbench tool** in the session's tool sets
([agentHostActiveClientService.ts#L474-L512](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/chat/browser/agentSessions/agentHost/agentHostActiveClientService.ts#L474-L512)).
The agent host then requests execution with a `ToolClientExecution` input request, and
the workbench runs the tool trusted-side
([agentHostSessionHandler.ts#L3090-L3170](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/chat/browser/agentSessions/agentHost/agentHostSessionHandler.ts#L3090-L3170)).
The advertised set is **not** a limit. The requested tool is resolved by name over all
tools, including disabled ones
([#L3330-L3350](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/chat/browser/agentSessions/agentHost/agentHostSessionHandler.ts#L3330-L3350)),
and pre-approval asserted by the agent host (`_meta.autoApproveBySetting`, or status
`Running` with `confirmed: NotNeeded`) is honoured
([#L584-L608](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/chat/browser/agentSessions/agentHost/agentHostSessionHandler.ts#L584-L608)).
With the agent host in a tab, every workbench tool is therefore reachable and can run
without a confirmation. Execution must be refused in the handler, not only in the
advertisement (found by the design review).

## 5. Context: instructions, prompt files, agents, skills

- Automatic instructions are collected by `ComputeAutomaticInstructions`, which reads
  the workspace through workbench services, so in a remote window the reads are served
  from the tab. It builds paths with the remote OS
  ([computeAutomaticInstructions.ts#L359-L362](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/chat/common/promptSyntax/computeAutomaticInstructions.ts#L359-L362)).
- The generated prompt says: "When an instruction file applies to your task …, follow
  the rules specified in it", and "When modifying or creating files, check for
  instructions whose applyTo pattern matches the file path and follow them"
  ([#L368-L377](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/chat/common/promptSyntax/computeAutomaticInstructions.ts#L368-L377)).
  Tests cover `copilot-instructions.md`, `AGENTS.md`, `CLAUDE.md` and
  `.github/instructions/*.instructions.md`
  ([computeAutomaticInstructions.test.ts#L230-L273](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/chat/test/common/promptSyntax/computeAutomaticInstructions.test.ts#L230-L273)).
- The agent host does its own discovery of agents, skills, instructions and workspace
  MCP config for the session's working directories, so with the agent host in the tab,
  discovery runs in the tab ([AGENTS.md](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/agentHost/AGENTS.md)).

Workspace instructions are therefore authority, not data, in both architectures. The
write-back gate already holds `.github/**`, `AGENTS.md`, `CLAUDE.md`, `.claude/**`,
`.mcp.json` and similar ([ADR](../adr/20261104-write-back-gate.md)), so a tab cannot
plant them in the host checkout unreviewed; it can still write them inside the tab.

## 6. Models and `vscode.lm`

- A provider's `sendChatRequest` is served by the extension host that registered it.
  The workbench serializes the whole message array to that host
  ([mainThreadLanguageModels.ts#L118-L135](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/api/browser/mainThreadLanguageModels.ts#L118-L135)).
  A tab that registers a provider becomes the model for any trusted-side caller.
- `$tryStartChatRequest` runs the model call trusted-side with the user's credentials
  ([#L219-L231](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/api/browser/mainThreadLanguageModels.ts#L219-L231)).
- Both are denied in v0, and the broker ADR fixed the rule that `vscode.lm` never becomes
  a broker binding ([ADR](../adr/20261104-broker-output-is-data.md)).

## 7. MCP and agent sandboxing

### 7.1 MCP

- In a remote window, stdio MCP launch is resolved against the remote environment, and
  `.vscode/mcp.json` discovery records the remote authority
  ([mcpSandboxService.ts#L97-L112](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/mcp/common/mcpSandboxService.ts#L97-L112),
  [workspaceDotMcpDiscovery.ts#L23-L38](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/mcp/common/discovery/workspaceDotMcpDiscovery.ts#L23-L38)).
  So a workspace MCP server runs in the tab **[inference: confirmed for the sandbox
  wrapper's OS choice, not for every launch path]**.
- User-level (host) MCP servers are host processes with host credentials. The
  `mcpGatewayToolBroker` channel lets the remote call them; it is denied by the channel
  guard (RPC-LOCKDOWN §2.4).

### 7.2 Upstream agent sandboxing is an inner layer

- Terminal sandboxing launches commands under the `@vscode/sandbox-runtime` CLI
  (Seatbelt on macOS, bubblewrap on Linux, per the prior-art note) with filesystem
  allowlists and domain filtering
  ([terminalSandboxEngine.ts#L18-L19](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/sandbox/common/terminalSandboxEngine.ts#L18-L19),
  [#L40-L49](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/sandbox/common/terminalSandboxEngine.ts#L40-L49),
  [bubblewrap check #L312](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/sandbox/common/terminalSandboxEngine.ts#L312),
  [terminalChatAgentToolsConfiguration.ts#L526-L580](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/terminalContrib/chatAgentTools/common/terminalChatAgentToolsConfiguration.ts#L526-L580)).
  MCP stdio servers can be wrapped by `@vscode/sandbox-runtime`
  ([mcpSandboxService.ts#L108-L145](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/mcp/common/mcpSandboxService.ts#L108-L145)).
- Microsoft says it is not a VM or container boundary
  ([docs](https://code.visualstudio.com/docs/agents/run/agent-sandboxing)). Its allow
  lists are settings, most of them tab-writable (§11). In a tab it is useful only as
  defence in depth inside the VM.

## 8. Rendering: what tab-supplied content can make the trusted UI do

Through `$handleProgressChunk` (classic) or AHP state (agent host), the producer
controls content that the trusted renderer turns into: markdown (with `isTrusted`
carried in the DTO, [extHostTypeConverters.ts#L392](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/api/common/extHostTypeConverters.ts#L392)),
command buttons that execute a named command on click
([#L3239-L3252](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/api/common/extHostTypeConverters.ts#L3239-L3252)),
references and citations with URIs, tool-confirmation dialogs whose title and message
the producer writes, terminal output, diffs, and edits applied by the workbench. The
RPC-LOCKDOWN surface (d) mechanisms (forcing `isTrusted=false`, command taint) cover
part of this; an agent UI needs them for every part type (plan §4.3).

## 9. Edits

Chat edits are applied by the workbench editing session through `IFileService`, so a
`vscode-remote://seclab+<tab>` URI is written into the tab, and from there the write-back
gate decides what reaches the host checkout **[inference]**
([externalEdits, mainThreadChatAgents2.ts#L495-L503](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/api/browser/mainThreadChatAgents2.ts#L495-L503)).
Edit auto-approval, `chat.tools.edits.autoApprove`, defaults to approving everything
except files such as `**/.vscode/*.json`. It is `APPLICATION` scope, so a tab cannot
widen it, and the workbench forwards it to the agent host
([chat.shared.contribution.ts#L900-L913](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/chat/browser/chat.shared.contribution.ts#L900-L913)).
It is a UX gate, not containment: whatever it approves lands in the tab and then meets
the write-back gate.

## 10. Extension placement on main

`build/product/product.jq` forces every extension to `["workspace", "-web"]` except
`vscode.*` built-ins that declare `ui` and the Tab Manager, and the build fails if
anything else is `ui`. At this SHA those built-ins are `github-authentication`,
`microsoft-authentication`, `simple-browser`, `handlebars` and `vscode-test-resolver`;
none contributes chat participants, tools, model providers or chat sessions (checked
from their manifests). The Copilot extension (`GitHub.copilot-chat`) declares no
`extensionKind` ([package.json#L1-L39](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/extensions/copilot/package.json#L1-L39)), is
removed from our build ([EDR](../edr/20261104-remove-builtin-copilot.md)), and would be
forced into the tab if installed. So **no extension can host an agent trusted-side in our
build**; the trusted-side agents are core: the local agent host and built-in chat (§13).

## 11. Settings a tab controls

In a remote window the workbench reads **remote user settings** from a `settingsPath`
that the REH supplies, with `REMOTE_MACHINE_SCOPES`
([configuration.ts#L401](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/services/configuration/browser/configuration.ts#L401),
[scopes #L32](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/services/configuration/common/configuration.ts#L32),
[server side remoteAgentEnvironmentImpl.ts#L117](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/server/node/remoteAgentEnvironmentImpl.ts#L117)).
Those scopes are `MACHINE`, `APPLICATION_MACHINE`, `WINDOW`, `RESOURCE`,
`LANGUAGE_OVERRIDABLE` and `MACHINE_OVERRIDABLE`: everything except `APPLICATION`.
`APPLICATION_MACHINE` is documented as settable "only in default profile user settings
and remote user settings"
([configurationRegistry.ts#L202-L205](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/configuration/common/configurationRegistry.ts#L202-L205)).

So in a `seclab+` window the tab can set `chat.tools.global.autoApprove`
(`APPLICATION_MACHINE`), `chat.permissions.default`, `chat.disableAIFeatures`, and the terminal auto-approve rules and agent-sandbox allowlists, which declare no scope and so
default to `WINDOW`
([terminalChatAgentToolsConfiguration.ts#L104-L130](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/terminalContrib/chatAgentTools/common/terminalChatAgentToolsConfiguration.ts#L104-L130),
**[inference: some consumers may read only selected layers]**).

A setting that is **not registered in the window that reads it** is not filtered by scope
at all. `chat.agentHost.localFilePermissions`, which grants an agent host access to host
files (§12.4), is registered only in the Agents window, so in an editor window the tab
can set it (found by the design review). The rule is therefore: **only settings that are
registered in that window at `APPLICATION` scope, and code, are trusted inputs.**
Reported to the RPC-lockdown session on 2026-11-05.

## 12. Credentials

### 12.1 Agent-host authentication push

- The agent host lists `protectedResources` (resource, authorization servers,
  `scopes_supported`) for each agent in its root state. The workbench resolves a matching
  auth session and forwards its access token with `authenticate`
  ([agentHostChatContribution.ts#L487-L526](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/chat/browser/agentSessions/agentHost/agentHostChatContribution.ts#L487-L526),
  [agentHostAuth.ts#L627-L668](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/chat/browser/agentSessions/agentHost/agentHostAuth.ts#L627-L668),
  [#L710-L725](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/chat/browser/agentSessions/agentHost/agentHostAuth.ts#L710-L725)).
- The resource and scopes come from the agent host
  ([#L895-L951](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/chat/browser/agentSessions/agentHost/agentHostAuth.ts#L895-L951)).
  It is re-run on account and session changes without user action
  ([agentHostChatContribution.ts#L240-L247](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/chat/browser/agentSessions/agentHost/agentHostChatContribution.ts#L240-L247)).
- It is a client→server call over `agentHostProxy`, so neither the `MainThread*` filter
  nor the client-served channel guard sees it.

### 12.2 MCP OAuth push

The same contribution registers an MCP authentication handler that resolves and forwards
OAuth tokens for MCP servers the agent host names, silently (`allowInteraction: false`),
keyed with an empty agent-host authority
([agentHostChatContribution.ts#L228-L231](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/chat/browser/agentSessions/agentHost/agentHostChatContribution.ts#L228-L231),
[agentHostAuth.ts#L1115-L1135](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/chat/browser/agentSessions/agentHost/agentHostAuth.ts#L1115-L1135)).
Remembered MCP grants are therefore not scoped to a tab.

### 12.3 Copilot's token flow

The Copilot extension mints its Copilot token by calling the CAPI token endpoint with
`Authorization: token <GitHub token>`
([copilotTokenManager.ts#L250-L262](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/extensions/copilot/src/platform/authentication/node/copilotTokenManager.ts#L250-L262));
the response is a `TokenEnvelope` from `/copilot_internal/v2/token` whose `token` is an
HMAC-signed proxy token with an expiry
([copilotToken.ts#L340-L350](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/extensions/copilot/src/platform/authentication/common/copilotToken.ts#L340-L350)).
That maps onto the broker as a GitHub credential bound to that path, with the minted
token re-sentinelised as a derived credential (broker already detects a Copilot token
pattern, [ADR](../adr/20261104-no-real-secret-enters-a-tab.md)). Endpoint hosts come from
the envelope **[inference]**.

### 12.4 Host files through `resource*` requests

The agent host can ask the client to read, write, delete, move, copy, list and watch
files, and the client serves the raw URI from the host
([agentHostProtocolClient.ts#L3335-L3365](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/agentHost/browser/agentHostProtocolClient.ts#L3335-L3365)).
Access is decided by grants in `chat.agentHost.localFilePermissions`, read with
`getGlobalConfigurationValue`
([agentHostResourceService.ts#L542](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/services/agentHost/common/agentHostResourceService.ts#L542)),
or by an "Allow / Always Allow" prompt. Because the setting is tab-writable in an editor
window (§11), a tab-side agent host can grant itself `file:///` and write host files.
Found by the design review.

### 12.5 Workspace-listed remote agent hosts

`chat.workspaceRemoteAgentHosts` is `WINDOW` scope and `restricted`
([remoteAgentHost.contribution.ts#L76-L90](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/chat/browser/remoteAgentHost/remoteAgentHost.contribution.ts#L76-L90)),
and `EditorWindowRemoteAgentHostService` dials those addresses from the host network
([remoteAgentHostServiceImpl.ts#L1251-L1256](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/agentHost/browser/remoteAgentHostServiceImpl.ts#L1251-L1256),
auto-connect at [#L1077-L1081](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/agentHost/browser/remoteAgentHostServiceImpl.ts#L1077-L1081)).
Tabs report trusted, so a workspace `.vscode/settings.json` or the tab's remote user
settings can make the trusted renderer connect to an attacker's agent host outside the
broker, and that connection gets §12.1, §12.2 and §12.4. Its own description says
"connected hosts receive your GitHub credentials". Found by the design review; reported
to the RPC-lockdown session on 2026-11-05 as a v0 issue, and closed for v0 by its patches
0010 (no agent-host client in tab windows) and 0011 (no remote agent-host dialing, with
the settings re-registered at `APPLICATION` scope).

### 12.6 Customizations and configuration forwarded to the agent host

The client sends the user's host-side prompts, skills, plugins and user-level `mcp.json`
servers to the agent host. `${env:…}` variables are resolved on the host, and literal
`env` and `headers` values are included
([agentHostMcpServerSupport.ts#L296-L333](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/chat/browser/agentSessions/agentHost/agentHostMcpServerSupport.ts#L296-L333)).
It also mirrors every setting registered for agent-host sync, including `http.proxy`.
With the agent host in a tab, those values would enter the tab. Found by the design
review.

## 13. Trusted-side agents that remain

- The **local agent host** (utility process, user's environment, §3.1), used by
  folder-less windows and the Agents window. It can be pointed at any host path,
  including the host checkout a tab is backed by, and reads its instructions there.
  Electron main always creates its starter and process manager
  ([app.ts#L760-L769](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/code/electron-main/app.ts#L760-L769)),
  so a renderer-side null service does not remove it.
- **Other agent-host connections** from the editor: workspace-listed hosts (§12.5), SSH,
  WSL, dev tunnels, dev containers, the cloud sandbox and Mission Control.
- **Built-in chat** in folder-less windows, with workbench tools on the host.
- `src/vs/sessions` tools that reach other agent hosts, sessions and automations.

None of these is a tab. Each is either host-privileged by design or must be disabled.

## 14. Supply chain

The REH depends on `@github/copilot-sdk` (MIT-labelled) whose platform package ships
prebuilt `copilot-runtime` and `runtime.node` binaries, and on `@vscode/copilot-api`
("SEE LICENSE")
([remote/package.json](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/remote/package.json#L5-L12),
[build/lib/copilot.ts#L216-L250](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/build/lib/copilot.ts#L216-L250)). Neither is in
`deps/registry.json`. Running the Copilot harness in a tab means running an opaque
prebuilt binary there: contained by the tab, but it needs a provenance bar (plan §13,
D3). Upstream also downloads the Claude and Codex SDKs at run time from
`product.agentSdks` URL templates, and the only integrity check is a completion marker
([agentSdkDownloader.ts#L414-L528](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/agentHost/node/agentSdkDownloader.ts#L414-L528)).

## 15. Prior art

See [prior art for agent containment](agentic-prior-art.md).
