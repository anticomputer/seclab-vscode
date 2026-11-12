# Security review: the agent-host patches 0009–0011 (Phase 3, increment 4)

- **Date:** 2026-11-05
- **Round:** 6 (trusted-side AI surfaces)
- **Reviewer:** independent `security-review` agent
- **Subject:** `patches/0009-seclab-no-builtin-chat-in-tabs.patch`,
  `patches/0010-seclab-no-agent-host-client-in-tabs.patch`,
  `patches/0011-seclab-no-remote-agent-host-dialing.patch`,
  `rpc-filter/tools/seclab_inventory/ai.py`, `rpc-filter/tools/check_drift.py`,
  `rpc-filter/probes/expectations.json`,
  `test/containment/rogue-extension/ai-probes.js`,
  `docs/adr/20261105-no-builtin-chat-in-tabs.md`
- **Upstream:** `microsoft/vscode@a717861c07586a53d83b80d742cd3f59b20a6273`,
  read-only at `.work/upstream/vscode`
- **Branch:** `anticomputer-rpc-filter-patches` at `ae47e66`
- **Verdict: DO-NOT-LAND.** Findings 1, 2 and 3 block. The enforcement in
  0009–0011 is directionally right and the dialling path 0011 closes is real
  and automatic — but one of 0009's two enforcement layers does not exist, the
  scanner that is supposed to pin this surface is silently blind to 134 of the
  settings on it, and the six probes that claim to measure all of this have no
  implementation at all.

## Why this round mattered

This is the first round on the surface the RPC filter structurally cannot see:
the agent runs in the trusted workbench, so a tab that writes a file and a
trusted tool that reads it produce a host effect with no RPC crossing the
sandbox boundary. The patches respond by turning the feature off rather than
filtering it, which is the right call. The failures below are not in that
decision. They are in the two things this project keeps getting wrong:
**claiming a mechanism is enforcing when it is not reachable**, and **building
a gate that passes because it never asked the question.**

## Findings

| # | Severity | Finding | Recommended fix |
|---|---|---|---|
| 1 | **Critical** | **The inventory scanner deletes half the file that registers the settings this surface exists to watch.** `strip_block_comments` (`rpc-filter/tools/seclab_inventory/sources.py:93`) applies `re.sub(r"/\*.*?\*/", "", text, flags=re.S)` with no string-literal awareness. In `src/vs/workbench/contrib/chat/browser/chat.shared.contribution.ts` the default glob `'**/*plan*.md'` (line ~1005) opens a fake block comment that runs to the next `*/` and **deletes 94,646 characters**; the file goes from 205,566 to 99,651 chars. Measured against a string-aware stripper, **134 registered `chat.*`/`mcp.*` settings in that one file are invisible to surface (e)**, including `chat.agent.enabled` (WINDOW), `chat.disableAIFeatures` (WINDOW), `chat.extensionTools.enabled` (WINDOW), `chat.tools.edits.autoApprove`, `chat.tools.urls.autoApprove` (WINDOW), `chat.tools.eligibleForAutoApproval` (WINDOW), `chat.mcp.access`/`autostart`/`discovery.enabled`/`workspaceRootConfig.enabled` (WINDOW), `chat.useHooks`, `chat.useClaudeHooks`, `chat.hookFilesLocations`, `chat.agentSkillsLocations`, `chat.instructionsFilesLocations` (WINDOW), `chat.pluginLocations` (MACHINE), `chat.copilot.localModel.llamaServerPath` (MACHINE). Every one of those is `tab_writable` by the project's own rule. 52 files repo-wide lose content this way, including `languageModelToolsService.ts` (2,133 chars) — the file 0009 patches. `check_drift.py` pins the blinded output, so the digest will never notice. **The two settings the AI probes name by id — `chat.agent.enabled` and `chat.disableAIFeatures` — are both in the deleted span.** | Replace `strip_block_comments` with a scanner that tracks `'`, `"` and `` ` `` state, and add a regression test asserting a known in-string `/*` does not truncate. Regenerate the inventory and re-review every newly visible setting before accepting the new digest. |
| 2 | **High** | **0009's registration choke point is not a choke point.** The patch gates `LanguageModelToolsService.registerTool` only (hunk at `patches/0009-…:24`). `registerToolData` (`.work/upstream/vscode/src/vs/workbench/contrib/chat/browser/tools/languageModelToolsService.ts:310`) and `registerToolImplementation` (`:353`) are separate public interface methods and are **not** gated, and two production callers use them directly instead of `registerTool`: `src/vs/workbench/contrib/terminalContrib/chatAgentTools/browser/terminal.chatAgentTools.contribution.ts:180-181` registers `run_in_terminal` (data **and** implementation), and `src/vs/workbench/contrib/chat/common/tools/languageModelToolsContribution.ts:337` registers every **extension-contributed** tool, with `src/vs/workbench/api/browser/mainThreadLanguageModelTools.ts:93` supplying the implementation. So in a tab window the host-shell tool and every tool a rogue tab extension declares in `contributes.languageModelTools` still register — including their attacker-authored `inputSchema`, which `registerToolData` publishes into the window-global `jsonSchemaRegistry` (`languageModelToolsService.ts:326-328`). The ADR's claim (`docs/adr/20261105-no-builtin-chat-in-tabs.md:55`, and the patch comment itself) that "a tab window registers no tools, so the agent has none to choose and tab-authored instructions cannot name one" is **false as written**. Invocation is still refused by the `invokeTool` gate, so this is not currently an escape — but it reduces a two-layer design to one `throw` in one method, and that layer is exactly the one the ADR leans on. | Gate `registerToolData` and `registerToolImplementation` instead of (or as well as) `registerTool`, so the gate sits on the mechanism rather than on one convenience wrapper — the same reasoning that put the channel guard on `ChannelServer`. Correct the ADR and the patch comment. |
| 3 | **High** | **All six AI probes are declared `required: true` and none exists.** `rpc-filter/probes/expectations.json` declares `ai-instructions-tool-call`, `ai-settings-reenable`, `ai-agent-host-token-push`, `ai-disable-ai-features-reenable`, `ai-remote-agent-host-dial`, `ai-agent-host-autoapprove-setting`. `git grep` finds **zero** references to any of those ids outside `expectations.json` and `rpc-filter/AGENTS.md`, where lines 98–103 record them as `denied` as if measured. `test/containment/rogue-extension/ai-probes.js` — the only code that could implement them — has **zero importers**; `extension.js:95` requires `./rpc-probes.js` and nothing else. Worse, the six entries cannot pass the checker even once implemented: their `policyRef`s (`ai-tool:fetch_webpage`, `ai-setting:chat.agent.enabled`, `push:agentHostProxy`, …) are absent from `coverage.json` **by construction**, because `check_drift.py:140` records AI tools as `ai-tool:<id>\|host=<bool>` and `:158` records settings as `ai-setting:<id>\|scope=…\|unreg=…\|tab_writable=…`, so `check-probes.ts:181`'s `spec.policyRef in coverage.mapping` is never true. Verified by injection: feeding the checker a fabricated `succeeded` result produces `FAIL [probe-policy-link] … not present in coverage.json` for every AI probe. That check has therefore never been run against this file. | Implement the probes and wire `ai-probes.js` into `extension.js`; align the probe `policyRef` grammar with the keys `check_drift.build_mapping` actually emits (or teach `check-probes.ts` to match the key prefix); delete the "denied" column from `AGENTS.md` until a run produces it. |
| 4 | **High** | **The new `hostEffect` strings are free text that the patched-mode check turns into a guaranteed pass.** `check-probes.ts:66-73` resolves `hostEffect` as a path under `SECLAB_PROBE_RUNDIR`. The six new entries give it prose: `"beacon hit from the host, or a marker written outside the tab"`, `"chat becomes usable in the tab window after the setting is written"`, `"a canary auth token reaches the tab"`. Demonstrated executably: with `SECLAB_PROBE_RUNDIR` set, `check-probes.ts patched` emits `PASS [host-effect] ai-instructions-tool-call did not change the host (beacon hit from the host, or a marker written outside the tab)` — it asserts the non-existence of a file literally named after the sentence, so the real host effect (`$RUNDIR/PWNED`, or a beacon hit) would never be observed. This is the same defect the 2026-11-04 round recorded as fixed ("free-text 'also assert …' asserts nothing"), reintroduced in the new entries. | Restrict `hostEffect` to the `marker`/`marker.<suffix>`/relative-path grammar `hostEffectPath` understands, and have `check-probes.ts` **fail** on a `hostEffect` value it cannot parse rather than resolving it to a path that cannot exist. |
| 5 | Medium | **0011's token-forwarding backstop covers one of six entry points.** The early return is placed in `authenticateProtectedResources` (`.work/upstream/vscode/src/vs/workbench/contrib/chat/browser/agentSessions/agentHost/agentHostAuth.ts:710`). The same module exports `authenticateAgentProtectedResourcesWithToken` (`:729`), `authenticateProtectedResourcesWithToken` (`:736`), `resolveAuthenticationInteractively`, `autoAuthenticateMcpServer` (`:1383`) and `revokeAuthenticationForRemovedSessions` (`:1011`), all of which reach `forwardAuthenticationToken` for a `protectedResources` list **chosen by the agent host**. Both consumers import and call several of them: `remoteAgentHostChatContribution.ts:608,695,701` and `agentHostChatContribution.ts:501,579,586`. Since the patch states its purpose as defence in depth "even if a future [dialling path] is not" closed, covering one sixth of the forwarding surface does not meet its own stated bar. | Put the refusal in `forwardAuthenticationToken` (`agentHostAuth.ts:627`) — the single function every path funnels through — rather than in one of its callers. |
| 6 | Medium | **0011 silently clobbers upstream's `chat.agentHost.localFilePermissions` schema in the Agents window.** The patch adds the key to `src/vs/workbench/contrib/chat/browser/remoteAgentHost/remoteAgentHost.contribution.ts` (hunk `patches/0011-…:64`). That file is imported by the Agents-window entry point at `src/vs/sessions/contrib/providers/remoteAgentHost/browser/remoteAgentHost.contribution.ts:15`, i.e. **before** the sessions module body runs, so the seclab stub registers first and upstream's registration at `:85` hits `validateProperty`'s duplicate branch (`configurationRegistry.ts:1172`) and is `delete`d at `:858-860` with the message discarded. Both are APPLICATION + restricted, so the containment posture is unchanged — but the Agents window, which is where the permission prompts actually write this setting, loses the real `additionalProperties` value schema and description, and the loss is invisible. | Register the editor-window entry conditionally (skip when the Agents-window registration already owns the key), or patch the key's scope at its single upstream site instead of adding a second registration. |
| 7 | Medium | **Functional regression from pinning `chat.workspaceRemoteAgentHosts` to APPLICATION in every window.** See answer (b) below. | Scope the change to tab windows, or record an explicit product decision that the per-workspace form is removed in the fork. |
| 8 | Medium | **`ai.py` cannot see a setting that is registered nowhere, and its `unregistered_where_read` rule is one-directional.** `_settings` (`rpc-filter/tools/seclab_inventory/ai.py:186`) enumerates only *registered* properties, so a setting read in an editor-window-loaded file and registered in no entry point — the maximally permissive case — produces no inventory row at all and no drift key. Demonstrated by injection against a synthetic tree: a `getValue('chat.totallyUnregisteredDangerousHostCommand')` with no registration anywhere yields no entry. Upstream has real instances (`chat.agentHost.unsafeTestToken`, read at `remoteAgentHostAuthenticationResolver.ts:24`, `agentHostChatContribution.ts:600`, `agentHostAutoTierScope.ts:54`; not exploitable because `enableSmokeTestDriver` gates it, but invisible to the gate either way). Separately, `unregistered_where_read` (`ai.py:249`) fires only when `registered_in == "agents"`; the converse — registered in the editor entry point, read where the Agents window runs — is never evaluated. And `if … key in seen: continue` (`ai.py:220`) keeps only the **first** registration of a key, so a doubly-registered setting reports one scope and hides the other — a condition patch 0011 has just created (finding 6). | Enumerate read sites first and emit a row for every `chat.*`/`mcp.*` id read in an editor-window-loaded file, registered or not, with `scope: null, tab_writable: true`. Make the duplicate-key case an error rather than a silent first-wins. |
| 9 | Low | **`_read_sites` infers window membership from directory, and matches only string literals.** `_window_of` (`ai.py:139`) maps `src/vs/platform/` to `"platform"` and treats that as "loaded in every window". Loading is decided by entry-point imports, not by directory: `SSHRemoteAgentHostService` and `WSLRemoteAgentHostService` live under `src/vs/platform/agentHost/electron-browser/` but are registered **only** by `sessions.desktop.main.ts:252` and `:253`, so they never exist in an editor window. That produces false `tab_writable: true` on `chat.sshRemoteAgentHostCommand`, `chat.wslRemoteAgentHostCommand`, `chat.remoteAgentHosts`, `chat.remoteAgentTunnels`, `chat.agentHost.forwardSSHAgent`, `chat.agentHost.wsl.autoStart` — six of the twelve `unregistered_where_read` hits, diluting a signal that is supposed to stop a build. In the other direction, the scan matches `'<id>'`/`"<id>"` in raw text, so a read through an imported constant (the common form) is invisible unless the literal happens to appear in the same window class. | Resolve read sites through the entry-point import graph, or at minimum record `read_in` as "files mentioning", not "windows loading", so the conclusion is not overstated. |
| 10 | Low | **ADR arithmetic does not match the inventory it cites.** `docs/adr/20261105-no-builtin-chat-in-tabs.md:117` states "55 of the 67 agent settings"; `rpc-filter/inventory/inventory.json` records `setting_count: 146`, `tab_writable_setting_count: 89`. Both numbers are wrong anyway given finding 1. | Regenerate after fixing finding 1 and quote the generated figure. |

## (a) `chat.sshRemoteAgentHostCommand` and `chat.wslRemoteAgentHostCommand`

**Conclusion: a tab cannot get a host process spawned through either setting,
and it is not a latent trap either.** The premise in the brief is correct as
far as it goes but stops one step short, and the missing step is decisive.

The three established facts hold:

- read at `.work/upstream/vscode/src/vs/platform/agentHost/electron-browser/sshRemoteAgentHostServiceImpl.ts:424`
  (`_getRemoteAgentHostCommand`), and the WSL sibling at
  `wslRemoteAgentHostServiceImpl.ts:613`;
- registered only at
  `src/vs/sessions/contrib/providers/remoteAgentHost/browser/remoteAgentHost.contribution.ts:32` and `:39`;
- an unregistered setting has `scope === undefined`, and
  `ConfigurationModelParser.shouldInclude` returns `true` when
  `scope === undefined` (`src/vs/platform/configuration/common/configurationModels.ts:519-524`),
  so nothing filters it out of workspace or remote user settings.

What that argument assumes is that *being under `src/vs/platform/` means being
loaded in every window*. It is not. `SSHRemoteAgentHostService` and
`WSLRemoteAgentHostService` are registered by exactly one entry point:

```
src/vs/sessions/sessions.desktop.main.ts:252  import '../platform/agentHost/electron-browser/sshRemoteAgentHostService.js';
src/vs/sessions/sessions.desktop.main.ts:253  import '../platform/agentHost/electron-browser/wslRemoteAgentHostService.js';
```

and `registerSingleton(ISSHRemoteAgentHostService, …)` lives in those two
shim files (`sshRemoteAgentHostService.ts:11`, `wslRemoteAgentHostService.ts:11`).
The editor window (`workbench.desktop.main`) never imports them, so
`ISSHRemoteAgentHostService` does not exist in its service collection and no
code in an editor window reads either setting. Every consumer is under
`src/vs/sessions/` (`remoteAgentHostActions.ts:1158`, `remotesModel.ts:120`,
`wslAgentHost.contribution.ts:55`).

So the only reader is the Agents window, and the Agents window's configuration
service is a different class with a different layer stack
(`src/vs/sessions/services/configuration/browser/configurationService.ts:92-96`):

- `userConfiguration` is a plain `UserConfiguration` over the local profile's
  `settingsResource`. There is **no `RemoteUserConfiguration`** — the Agents
  window has no remote authority, so `environment.settingsPath` (the REH-supplied
  path a tab controls) is never read;
- `workspaceConfiguration` is constructed over a stubbed cache
  (`read: async () => ''`), and any folder settings that are loaded are parsed
  with `FOLDER_SCOPES`/`WORKSPACE_SCOPES`, neither of which includes
  `ConfigurationScope.APPLICATION` — and both settings **are** registered at
  APPLICATION in that window.

Both of the tab's write channels therefore miss the reader: the layer a tab
controls (remote user settings) does not exist in the reading window, and the
layer that does exist (workspace/folder) is scope-filtered because the setting
is registered there. A tab *can* place either key into the effective
configuration of its own editor window, and that value will sit there
unfiltered — but nothing in that window ever reads it.

**On the "latent trap" question specifically:** no. A latent trap would require
the poisoned value to be live in the process that later performs the
user-initiated SSH/WSL connection. It is not: the user-initiated action runs in
the Agents window, against a configuration the tab has no layer in. The
distinction the brief asks for therefore does not arise — this is neither a
tab-triggered spawn nor a hijack of a later user action. The node-side execution
path is otherwise exactly as dangerous as it looks
(`src/vs/platform/agentHost/node/sshRemoteAgentHostService.ts:913-923`,
`wslRemoteAgentHostHelpers.ts:278-280` builds `export …=… && <command>` for a
shell), so the conclusion rests entirely on reachability and should be
re-verified on every upstream bump — in particular if the SSH/WSL singletons
are ever moved into `workbench.desktop.main`.

Two consequences follow:

1. **0011 correctly does not touch them.** They are not part of this patch's
   problem.
2. **The inventory is wrong about them**, in the safe direction, and for a
   reason that is unsafe in general — see finding 9. `chat.sshRemoteAgentHostCommand`,
   `chat.wslRemoteAgentHostCommand`, `chat.remoteAgentHosts`,
   `chat.remoteAgentTunnels`, `chat.agentHost.forwardSSHAgent` and
   `chat.agentHost.wsl.autoStart` are all reported `tab_writable: true,
   unregistered_where_read: true` purely because their reader's *path* starts
   with `src/vs/platform/`. Six of the twelve `unregistered_where_read` hits in
   the current inventory are this artefact.

## (b) Does pinning to APPLICATION break ordinary windows?

**`chat.workspaceRemoteAgentHosts` — yes, it breaks its entire documented
purpose, in every window.**

The setting's own `markdownDescription` (preserved verbatim by the patch) reads
"WebSocket remote agent hosts that editor windows connect to **while this
workspace is open**", and upstream deliberately contrasts it with
`chat.remoteAgentHosts`, which "belong to the Agents window". The per-workspace
form *is* the feature. `EditorWindowRemoteAgentHostService` overrides
`webSocketEntriesSettingId` to this key precisely so that editor windows dial
only the hosts their workspace lists
(`src/vs/platform/agentHost/browser/remoteAgentHostServiceImpl.ts:1251-1257`).

After 0011 it is APPLICATION-scoped, so:

- `.vscode/settings.json` and `*.code-workspace` entries are filtered out
  (`WORKSPACE_SCOPES`, `configuration.ts:33`, excludes APPLICATION), silently —
  the value simply disappears, no diagnostic. Anyone who legitimately pins a
  dev agent host per repository today loses it;
- **less obvious and worth stating:** under a non-default user profile it also
  stops working from the user's own settings. Profile user settings are parsed
  with `PROFILE_SCOPES` (`configuration.ts:29`), which excludes APPLICATION;
  APPLICATION-scoped keys are read only from the **default profile's**
  `settingsResource` with `{ scopes: APPLICATION_SCOPES, skipUnregistered: true }`
  (`src/vs/workbench/services/configuration/browser/configuration.ts:142`). So a
  user on a non-default profile must move the key to the default profile's
  `settings.json`. With only the default profile in play this is invisible, which
  is how it will reach someone else's bug report rather than this review;
- legitimate remote-dev windows (SSH/WSL/containers) can no longer set it from
  remote user settings either — `REMOTE_MACHINE_SCOPES`
  (`configuration.ts:32`) excludes APPLICATION. That is the intended effect for
  tabs and an unintended one for ordinary remote development.

The patch is a global change made to solve a tab-only problem, and nothing in
the patch or the ADR records the trade. 0009 and 0010 both gate on
`seclabAiDisabled(remoteAuthority)`; 0011 does not, and the asymmetry is
undiscussed. A tab-only alternative exists — refuse the dial in
`RemoteAgentHostService`'s reconcile autorun when `seclabAiDisabled` holds for
the window, which is the same shape as 0010 — and would leave ordinary windows
untouched. If the global pin is deliberate, it needs to be an explicit product
decision in the ADR, not a side effect of a security fix.

**`chat.agentHost.localFilePermissions` — the registration is not a no-op, and
the two entry points *are* loaded in one process.**

They are. `src/vs/sessions/contrib/providers/remoteAgentHost/browser/remoteAgentHost.contribution.ts:15`
statically imports the editor-window contribution file, so the Agents window
evaluates both. ES module imports are evaluated before the importing module's
body, so the patched editor-window `registerConfiguration` runs **first**. The
Agents window's own registration at `:85` then hits
`validateProperty`'s duplicate branch
(`src/vs/platform/configuration/common/configurationRegistry.ts:1172`) and is
dropped by `delete properties[key]; continue;` at `:858-860` — the returned
message is never logged. This is finding 6.

Security-wise the outcome is a wash: both declare
`scope: ConfigurationScope.APPLICATION, restricted: true`, so the filtering that
matters is identical and the editor-window gap the patch targets is genuinely
closed. Functionally the Agents window loses upstream's full value schema (the
`r`/`rw` enum, the `{mode, lexicalUri}` alternative, `additionalProperties`) and
its user-facing description, in the one window where the agent-host permission
prompts maintain the value. No runtime read is affected —
`AgentHostResourceService` reads it through `inspect()`
(`src/vs/workbench/services/agentHost/common/agentHostResourceService.ts:606`)
and `getGlobalConfigurationValue`, whose only use of the schema is
`matchesSchemaType(value, property?.type)`, and `type: 'object'` is preserved.

## What I checked and found sound

- **The dialling path 0011 closes is real, automatic, and correctly diagnosed.**
  `RemoteAgentHostService`'s constructor registers a `WebSocketConnectionFactory`
  over `webSocketEntriesSettingId` and runs an `autorun` that reconciles
  connections whenever `_configuredEntries` changes
  (`remoteAgentHostServiceImpl.ts:270-281`). No user action is required. In an
  editor window that id is `chat.workspaceRemoteAgentHosts`
  (`:1251-1257`), WINDOW-scoped upstream, hence settable from both
  `.vscode/settings.json` and REH-supplied remote user settings. The host
  renderer then dials the attacker's address over the host network, outside the
  broker, and the dialled connection has no `seclab+` authority so the window
  predicate never fires. Closing it at the scope is the right lever.
- **`restricted: true` really does nothing here**, as the patch comment says.
  `skipRestricted` is only applied for untrusted workspaces
  (`configurationModels.ts:511-513`), and a tab reports trusted.
- **`REMOTE_MACHINE_SCOPES` excludes `APPLICATION` and includes
  `APPLICATION_MACHINE`** (`src/vs/workbench/services/configuration/common/configuration.ts:32`),
  so the corrected rule in the ADR and in `ai.py`'s docstring is right, and the
  earlier claim that `chat.tools.global.autoApprove` was out of reach was indeed
  wrong in the unsafe direction.
- **`tab_writable = scope != APPLICATION` is sound for the layers I could
  enumerate.** I specifically checked the extension `configurationDefaults`
  channel as a possible bypass: an extension in the tab's host can contribute
  defaults, and defaults are not scope-filtered — but the handler rejects any
  key whose registered scope is outside
  `[MACHINE_OVERRIDABLE, WINDOW, RESOURCE, LANGUAGE_OVERRIDABLE]`
  (`src/vs/workbench/api/common/configurationExtensionPoint.ts:215-228`), so both
  APPLICATION and APPLICATION_MACHINE are blocked. The check is skipped for
  **unregistered** keys (`registeredPropertyScheme?.scope` is undefined), which
  is another reason finding 8 matters, but it does not defeat 0011's two fixes.
- **MCP tools do go through the gated path.** `mcpLanguageModelToolContribution.ts:120`
  uses `registerTool`, so 0009 covers them. (`createToolSet` at
  `languageModelToolsService.ts:1794` is ungated but is presentation only.)
- **`invokeTool` has only two production callers**, both covered:
  `mainThreadLanguageModelTools.ts:64` (the `vscode.lm` / extension bridge) and
  `agentHostSessionHandler.ts:3463` (the local agent-host session loop). I found
  no path that resolves an `IToolImpl` and calls it directly — `_tools` is private.
- **0010's local branch does not introduce a new host process.**
  `AgentHostPrewarmContribution` returns early when `remoteAuthority` is set
  (`src/vs/workbench/services/agentHost/electron-browser/agentHostService.ts:135-136`),
  so a tab window does not prewarm or start the local utility-process agent host.
  The claim 0010 rests on is also accurate: `forwardAuthenticationToken`
  (`agentHostAuth.ts:627`) is reached from the client with no tab-originated call,
  so neither the RPC choke point nor the channel guard can see it.
- **The ADR's measured justification survives.** Re-running the tool extraction
  with a string-aware stripper still yields 54 tools and **zero** with
  `runsInWorkspace: true`, so "there is no safe subset to keep" holds. Surfaces
  (a)–(d) are not materially affected by finding 1 (one stray `registerSingleton`
  in a deleted span; no `registerAction2` or `CommandsRegistry.registerCommand`).
- **The drift gate does fail on the two changes it claims to pin**, verified by
  injection rather than by reading:
  - appending a tool to `inventory.json` →
    `FAIL [coverage] … NEW ai-tool:seclab_injected_tool|host=True -> deny`, exit 1;
  - changing `chat.tools.global.autoApprove` from `APPLICATION_MACHINE` to
    `WINDOW` → `FAIL [coverage] … NEW … |scope=WINDOW … / REMOVED … |scope=APPLICATION_MACHINE`,
    exit 1.
  It fails on the third case (a new `unregistered_where_read` setting) **only if
  `ai.py` can see it** — which is finding 8.
- `./build/apply-patches.sh --check` (series applies cleanly, 11 patches),
  `node test/containment/policy-invariants.test.ts` and
  `node test/containment/uri-constraint.test.ts` all exit 0.

## What I could not determine

- **Whether `check-probes.ts` is wired into any CI job.** I did not trace the
  workflow files. Findings 3 and 4 are stated as properties of the checker and
  the expectations file, which I verified by running the checker directly; if it
  *is* in CI then the branch does not currently pass it, and if it is not, that
  is a separate gap I did not characterise.
- **Whether `.vscode/mcp.json` in a tab's workspace can launch a server process
  on the host.** `mcp` is WINDOW-scoped and `MCP_CONFIGURATION_KEY` is a
  workspace standalone configuration (`configuration.ts:43`), and the inventory
  already flags it `tab_writable: true`. None of 0009–0011 addresses it; 0009's
  gates stop the *tools* reaching the model, but I did not establish where the
  server process itself is spawned in a remote window. This needs its own round.
- **The Agents window operating on a tab's workspace.** `seclabAiDisabled` is
  per-window and the Agents window has no remote authority, so chat and tools
  are fully enabled there. Whether a user can open a `seclab+` folder as an
  agent session in the Agents window — and therefore get the full
  instruction-file confused-deputy path with none of 0009's gates — I did not
  establish. If it is possible, the predicate has a third blind side.
- **Whether the `invokeTool` refusal is observed by every caller** rather than
  swallowed. `agentHostSessionHandler.ts:3463` is inside a larger flow I did not
  read in full; the tool does not run either way, but a swallowed exception could
  make a containment failure look like a tool error in the logs.

## Before re-review

1. Fix `strip_block_comments` to be string-aware, regenerate the inventory, and
   review the ~134 newly visible settings — several of them (`chat.agent.enabled`,
   `chat.tools.*.autoApprove`, `chat.useHooks`, `chat.pluginLocations`,
   `chat.mcp.*`) are on the critical path for this very patch set.
2. Move 0009's registration gate onto `registerToolData`/`registerToolImplementation`,
   and correct the ADR claim that a tab window registers no tools.
3. Implement the six AI probes, wire `ai-probes.js` in, and reconcile the probe
   `policyRef` grammar with the keys the drift gate emits, so `check-probes.ts`
   can pass at all.
4. Replace the free-text `hostEffect` values with the grammar the checker
   understands, and make an unparseable `hostEffect` a failure.
5. Move 0011's refusal to `forwardAuthenticationToken`.
6. Decide, explicitly, whether `chat.workspaceRemoteAgentHosts` is pinned
   globally or only for tabs, and record it.
7. Demonstrate at least one AI probe succeeding unpatched and failing patched.
   This was item 6 on the 2026-11-04 list and is still outstanding for this
   surface.
