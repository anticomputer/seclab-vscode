# Disable the built-in chat and agent tools in sandboxed tab windows

- **Status:** accepted
- **Date:** 2026-11-05
- **Deciders:** user (scope), coordinator (mechanism)
- **Upstream:** `a717861c07586a53d83b80d742cd3f59b20a6273` (`upstream.lock`)

## Context

A tab's sandbox contains its extension host. It does not contain the
*workbench*, and VS Code's chat agent runs there.

That matters because the agent reads the tab's content and acts with host
privileges. The path needs no RPC at all:

1. `.github/copilot-instructions.md` and `.github/instructions/` are located in
   **workspace root folders**
   ([promptsServiceImpl.ts#L925](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/chat/common/promptSyntax/service/promptsServiceImpl.ts#L925)),
   so a tab writes them.
2. A file whose `applyTo` is `**` is attached to every request automatically,
   with the reason *"automatically attached as pattern is `**`"*
   ([computeAutomaticInstructions.ts#L230](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/chat/common/promptSyntax/computeAutomaticInstructions.ts#L230)).
   No user action, no attachment step.
3. The generated system prompt then instructs the model to *"follow the rules
   specified in it"*
   ([#L373](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/chat/common/promptSyntax/computeAutomaticInstructions.ts#L373)).
4. The agent then invokes a trusted-side tool — host network via
   `fetchPageTool`, arbitrary browser automation via `run_playwright_code`,
   extension installation via `installExtensionsTool`.

**The RPC capability filter cannot help.** Its choke point is RPC arriving from
a sandboxed extension host, keyed on (proxy id, method). Here the tab makes no
call: it writes a file, and a trusted component chooses to act. There is
nothing for the filter to inspect. A tab does not need a confused deputy over
RPC if it can write text that a trusted agent obeys.

Upstream is not careless about injection, and some defences I expected to be
broken are not: the fetch tool's "URL was in prompt" auto-approval
reads only the user's typed request text, and parses at token granularity
specifically to defeat `?u=file:///…` smuggling. The gap is a **threat-model
mismatch, not a missing check**: upstream assumes workspace content is
semi-trusted and that the user approves host actions. We assume the tab is
hostile, and a confirmation dialog is a social control, not a containment
boundary — the user cannot distinguish an action the agent chose on their
behalf from one a hostile repository induced.

## Decision

**For v0, VS Code's built-in chat and agent tools are disabled in any window
whose remote authority is `seclab+*`.**

Enforced in code, at two choke points (patch 0009):

- `LanguageModelToolsService.registerTool` returns `Disposable.None`, so a tab
  window registers no tools and the agent has none to choose;
- `LanguageModelToolsService.invokeTool` throws, because registration alone
  would depend on every future caller going through it;
- `ChatServiceImpl.sendRequest` throws, so there is no agent loop. Without
  this, the loop still runs with no tools and tab-authored instructions still
  reach the model along with whatever workspace content it gathers.

> **Correction, 2026-11-06: 0010 is an unconditional refusal, deliberately,
> for this landing.** Patch 0015 (the AHP gate, now on main) introduces
> `seclabAgentHostAllowed`, and its comment says 0009 and 0010 call it. They do
> not: 0010 calls `seclabAiDisabled` and refuses the agent-host client in a
> `seclab+` window **always**, where the predicate would permit it when agents
> are enabled by policy, the registered default, or the host main process's
> environment.
>
> The consequence is accepted and is the point: **agents cannot be enabled in
> tab windows at all while this stands**, not even through the host
> environment. That is fail-closed, and a narrower refusal is not worth taking
> on trust. At 0010's call site the permitted branch yields
> `remoteAgentService.getConnection()` directly, and 0015 performs its own
> selection elsewhere, so it is not established from this side whether a tab
> would receive the *gated* client or the ungated one. Switching 0010 to the
> predicate would convert a hard refusal into a conditional one, and if that
> reading is wrong it reopens precisely the token-forwarding path described
> below.
>
> Interim, not a position: superseded once the agentic-gate work identifies
> every selection point and a probe runs both patches together with agents
> enabled. Until then the predicate is not the single source of truth, and
> 0015's comment overstates the current state.

And in patch 0010, because disabling the callers was not enough:

- `WorkbenchAgentHostService` takes the **local** branch in a tab window, the
  same one an ordinary non-remote window takes.
  `EditorRemoteAgentHostServiceClient` connects to the REH's own
  `agentHostProxy` channel and then forwards a **real `accessToken`** for every
  entry the remote advertises in `protectedResources`
  ([agentHostAuth.ts#L736](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/chat/browser/agentSessions/agentHost/agentHostAuth.ts#L736)).
  A rogue REH advertising `api.github.com` is handed the user's token.

  That one is a **client to server push**: the tab makes no call, so neither
  the RPC choke point nor the channel guard sees it, and the connection is
  established eagerly rather than on demand -- so removing chat's callers in
  0009 left it open. It is a different shape of hole from everything the filter
  was built for, and it is why surface (f) now enumerates the channels the
  *client* calls on the REH.

All of these call one predicate, `seclabAiDisabled(remoteAuthority)`.

### Why disable rather than filter

Not caution — measurement. Surface (e) of the inventory enumerates 54 tool
definitions at the pinned SHA, and **not one statically declares
`runsInWorkspace: true`**. Upstream's own name for "this runs in the
(possibly remote) workspace rather than on the host" is unset everywhere it
would have mattered, so a policy of *allow only tools that run in the
workspace* would have an empty allow set. There is no safe subset to keep.

### Why code and not `configurationDefaults`

A default is a value, and values are overridden. `product.json`
`configurationDefaults` is also global, so it would disable chat in ordinary
local windows too. Worse, the override could come from a **setting the tab
itself writes**, letting the sandboxed side switch its own containment back on.
The probe `ai-settings-reenable` exists to keep that true: it writes settings
turning the features back on, and must fail.

**Correction (2026-11-05).** An earlier revision of this ADR said
`chat.tools.global.autoApprove` could not be set from a tab because it is
`APPLICATION_MACHINE`. That was wrong, and wrong in the unsafe direction. A
*workspace* file cannot set it, but a tab does not need the workspace file: in
a remote window the client reads **remote user settings** from
`environment.settingsPath` -- a path the REH supplies, so a file inside the tab
-- using `REMOTE_MACHINE_SCOPES`
([configuration.ts#L32](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/services/configuration/common/configuration.ts#L32),
[browser/configuration.ts#L401](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/services/configuration/browser/configuration.ts#L401)),
which includes `MACHINE` **and** `APPLICATION_MACHINE`.

So a tab can set every scope except `APPLICATION`: 55 of the 67 agent settings,
not the 53 first reported. The inventory field is now `tab_writable`, computed
as `scope != APPLICATION`. This strengthens the case for enforcing in code
rather than weakening it -- had this been a `configurationDefaults` value, the
tab could have overridden it.

## Consequences

- Chat is unavailable in tab windows. This is a real loss of function in the
  windows where untrusted code is opened, and it is the point of v0 rather
  than an accident of it.
- Chat in ordinary local windows is untouched.
- Surface (e) is in the scripted inventory and pinned by the drift gate,
  including the two facts worth stopping a build for: a tool that stops
  declaring `runsInWorkspace`, and a setting whose scope becomes
  workspace-writable.
- `vscode.lm` is separately denied by the RPC filter, including
  `$registerLanguageModelProvider` — the inverted case where a tab *becomes*
  the model for the trusted agent and returns tool calls it will execute.

### Correction 2 (2026-11-05): the predicate has a blind side

`seclabAiDisabled` keys on *this window's* remote authority. That covers a tab
dialling in. It does **not** cover the host renderer dialling **out**, and that
path is reachable from workspace content alone:

- `chat.workspaceRemoteAgentHosts` is `WINDOW` scope and `restricted`. The
  restriction only withholds it in *untrusted* workspaces, and a tab reports
  trusted. Its own description says *"connected hosts receive your GitHub
  credentials"*.
- `EditorWindowRemoteAgentHostService` dials those entries and auto-connects.
  **The dialled connection is not `seclab+`**, so the predicate never fires.
- The attacker's host then receives the real token via
  `authenticateProtectedResources`, server-to-client `resourceRead`/`Write`/
  `Delete`/`Move`/`Copy` on raw host URIs, and pre-approved tool execution.

Patch 0011 refuses to **dial** in a tab window, and leaves the settings alone:

- `SeclabEditorWindowRemoteAgentHostService` overrides `_reconcileConnections`
  to return early when `seclabAiDisabled`. Ordinary windows keep upstream's
  per-workspace semantics exactly;
- `authenticateProtectedResources` refuses outright in a tab window, as defence
  in depth behind the dialling refusal.

**The override point was chosen to avoid failing open.** The obvious one,
`webSocketEntriesSettingId`, is read *inside the base constructor*, before any
subclass field is assigned — a subclass deciding there would read `undefined`
and dial anyway. `_reconcileConnections` runs from an autorun after
construction and on every settings change, so a refusal there holds for the
object's life and cannot be outrun by a setting arriving later. It is `private`
upstream, so the patch widens it to `protected`: one word of core change, and
the reason is recorded here so nobody narrows it back.

An earlier revision re-scoped `chat.workspaceRemoteAgentHosts` to `APPLICATION`
and registered `chat.agentHost.localFilePermissions` in the editor window.
Both were withdrawn after review. The first **broke the setting's documented
per-workspace purpose in every window**, silently, and also made it unreadable
under a non-default profile, since `APPLICATION` keys are read only from the
default profile. The second was a **double registration**: the Agents window
imports the editor contribution, so the stub registered first and upstream's
full schema was silently deleted. Neither was a containment hole, but a
security change that quietly breaks a feature is how security work gets
reverted wholesale later. The user's decision was to lock tab windows and leave
ordinary windows alone.

The generalisable lesson, and the reason the inventory rule changed: **scope is
only enforced where a setting is registered.** `tab_writable` is now true when
`scope != APPLICATION` **or** the setting is unregistered in the window that
reads it. Applying that rule found **10** agent-host settings in this class,
including `chat.sshRemoteAgentHostCommand` and `chat.wslRemoteAgentHostCommand`
— command strings for launching a host.

Fixing the computed-key gap in the same scan took the settings surface from 67
to **146**. The earlier number was not a smaller surface; it was a scan that
could not see the dangerous half, and it reported a clean sheet for the wrong
reason.

### Correction 3 (2026-11-05): 0011 was never built, and does not load

An independent re-review
([record](../security-reviews/20261105-rpc-filter-rereview.md)) found three
things wrong with the patch this ADR describes. All three are now recorded
here rather than quietly fixed, because the earlier text claimed a protection
that did not exist.

1. **Wrong entry point.** The registration change was made in
   `workbench.web.main.ts`. The fork builds `vscode-darwin-*-min` and
   `vscode-reh-linux-*-min`, and a `seclab+` tab is a **desktop** editor
   window, which loads `workbench.desktop.main.ts` — a file that does not
   import the web entry point. The unpatched service registers, so the lock
   does not load and the outbound dial path remains open.
2. **It does not compile.** `SeclabEditorWindowRemoteAgentHostService` uses
   five DI decorators and the file imports none of them. That is independent
   proof the code was never built or exercised — and it passed
   `build/apply-patches.sh --check` and `sync_patch.py --check`, because
   neither type-checks. A gate that verifies a patch *applies* says nothing
   about whether it runs.
3. **The construction-order reasoning above is wrong, in the direction it
   claimed to avoid.** `autorun` runs **synchronously inside** the base
   constructor, while TypeScript parameter properties are assigned after
   `super()`. The first, dialling-relevant reconcile therefore sees
   `_seclabEnvironmentService === undefined`, and the resulting `TypeError` is
   swallowed by `onBugIndicatingError`. The guard is skipped by accident
   rather than refusing by design, and a later tidy to `?.` would turn that
   into a silent fail-open. The refusal is moving to `_connectTo` with a
   non-injected authority source, so it cannot depend on construction order at
   all.

### Correction 4 (2026-11-05): the tool count was measured over the wrong set

"54 tool definitions, and not one declares `runsInWorkspace: true`" is the
measurement this decision rests on. The scan behind it matched only
`const x: IToolData = {` and `getToolData(): IToolData`, so tools produced by
a factory were never counted — including `run_in_terminal`
(`createRunInTerminalToolData()`) and `fetch_webpage`, which are among the
most dangerous members of the set. Six unresolved expressions were meanwhile
pinned as if they were tools.

The conclusion is unlikely to change, since the missing tools are host-side
and do not declare `runsInWorkspace: true` either, but **the number will**, and
a decision resting on a measurement deserves the measurement to be right. The
scan is being rebuilt to enumerate registration call sites and to **fail the
gate on an unresolved id** rather than pin it.

### Residual risks

- **Extension-contributed chat.** This disables VS Code's built-in surface.
  A UI-kind extension providing its own agent runs trusted-side and is outside
  this patch.
- **The predicate is the whole boundary.** Everything rests on
  `seclabAiDisabled` and on the authority being trustworthy. It is derived from
  the connection, never from a call argument, but a future call site that
  forgets the check is unguarded — which is why the dead-entry-point gate in
  `sync_patch.py` exists.
- **Upstream adds a fourth entry point.** Two choke points cover today's paths.
  A new one would not be covered, and only the drift gate noticing a new tool
  would hint at it.
- **This is a withdrawal, not containment.** The vulnerable architecture is
  unchanged; we have stopped using it in tab windows. Moving chat into the tab
  is the real answer, and is owned by the Secure agentic experiences session.

## Alternatives rejected

- **Filter tools by `runsInWorkspace`.** Empty allow set, as measured above.
- **`product.json` configurationDefaults.** Overridable, and global.
- **Rely on confirmation dialogs.** They are upstream's design for a
  semi-trusted workspace. Against a hostile one they are a social control: the
  click is the user's, but the prompt is the attacker's.
- **Sanitise instruction files.** Instructions are natural language. There is
  no validator, and claiming one would be false assurance.
