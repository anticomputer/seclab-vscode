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

Upstream is not careless about injection, and several defences I expected to be
broken are not. `chat.tools.global.autoApprove` is `APPLICATION_MACHINE`, so a
workspace cannot set it. The fetch tool's "URL was in prompt" auto-approval
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

All three call one predicate, `seclabAiDisabled(remoteAuthority)`.

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
local windows too. Worse, the override could come from a **workspace setting
the tab itself writes**, letting the sandboxed side switch its own containment
back on. The probe `ai-settings-reenable` exists to keep that true: it writes
`.vscode/settings.json` turning the features back on, and must fail.

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
