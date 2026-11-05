# Security re-review: patches 0006 and 0009–0011, and the surface-(e) tooling

- **Date:** 2026-11-05
- **Round:** 7 (re-review of round 6)
- **Reviewer:** independent `security-review` agent
- **Subject:** `patches/0006-seclab-channel-guard.patch`,
  `patches/0009-seclab-no-builtin-chat-in-tabs.patch`,
  `patches/0010-seclab-no-agent-host-client-in-tabs.patch`,
  `patches/0011-seclab-no-remote-agent-host-dialing.patch`,
  `rpc-filter/tools/seclab_inventory/sources.py`,
  `rpc-filter/tools/seclab_inventory/ai.py`,
  `rpc-filter/probes/expectations.json`, `test/containment/check-probes.ts`,
  `test/containment/{channel-guard,uri-constraint,policy-invariants}.test.ts`
- **Upstream:** `microsoft/vscode@a717861c07586a53d83b80d742cd3f59b20a6273`,
  read-only at `.work/upstream/vscode`
- **Prior round:** `docs/security-reviews/20261105-agent-host-patches.md` (DO-NOT-LAND)
- **Branch:** `anticomputer-rpc-filter-patches` at `ea2ed60`

## Verdict: DO-NOT-LAND

**Findings 1 and 2 block.** Two of the three previously blocking findings are
genuinely fixed and were fixed well. The third is partially fixed. But patch
0011 was reworked between rounds in a way that **removes the only enforcement
it had and replaces it with code that no shipped build loads and that does not
compile**. The outbound dialling path the previous round confirmed to be real,
automatic, broker-bypassing and credential-bearing is, on this branch, open
again.

The failure is the project's named recurring one, in its purest form so far:
the enforcement was moved from a settings scope — which applies wherever the
setting is read — onto a `registerSingleton` line in an entry point the fork
does not build.

## Findings

| # | Severity | Finding | Recommended fix |
|---|---|---|---|
| 1 | **Critical** | **0011's dialling lock is registered in an entry point no shipped build loads, so the path is open again.** The patch replaces `registerSingleton(IRemoteAgentHostService, EditorWindowRemoteAgentHostService, …)` in **`src/vs/workbench/workbench.web.main.ts`** only (`patches/0011-…:102-134`). The fork ships desktop clients: `build/build-darwin.sh:18` runs `gulp vscode-darwin-${ARCH}-min` and `build/linux/build.sh:33` runs `gulp vscode-linux-${ARCH}-min`; the only other target is `vscode-reh-linux-${ARCH}-min` (`build/linux/build.sh:35`), i.e. the REH, not `reh-web`. Desktop editor windows — which is what a `seclab+<tabId>` tab is (`AGENTS.md:39`, "Native macOS app") — load `src/vs/workbench/workbench.desktop.main.ts`, which does **not** import `workbench.web.main.ts` (verified: its only `workbench.*.main` import is `./workbench.common.main.js` at `:15`) and which registers the **unpatched** service via `workbench.desktop.main.ts:99` → `src/vs/platform/agentHost/electron-browser/remoteAgentHostService.ts:10`. No patch in the queue touches `workbench.desktop.main.ts` or that shim (`grep -ln 'workbench.desktop.main' patches/*.patch` → none). Meanwhile the previous revision's enforcement — pinning `chat.workspaceRemoteAgentHosts` to `APPLICATION`, which worked at the configuration layer and therefore in every entry point — was **withdrawn** (`grep -n APPLICATION patches/0011-…` → no match). Net effect on the shipped build: `chat.workspaceRemoteAgentHosts` is WINDOW scope again, a tab writes it through REH-supplied remote user settings or `.vscode/settings.json`, and `RemoteAgentHostService`'s constructor autorun dials the attacker's address from the host network, outside the broker, with no user action. | Register `SeclabEditorWindowRemoteAgentHostService` where the fork actually builds: patch `src/vs/platform/agentHost/electron-browser/remoteAgentHostService.ts` (and keep the web entry point if a web build is ever shipped). Add a build-time gate asserting that every `registerSingleton(IRemoteAgentHostService, …)` reachable from a shipped entry point names a seclab subclass. |
| 2 | **Critical** | **The same patched file does not compile: five undefined identifiers.** `SeclabEditorWindowRemoteAgentHostService`'s constructor uses the decorators `@IConfigurationService`, `@IInstantiationService`, `@ILogService`, `@ILabelService`, `@IStorageService` (`patches/0011-…:191-199` of the resulting file), but the patch's import hunk (`@@ -6,6 +6,9 @@`) adds only `EditorWindowRemoteAgentHostService`, `IWorkbenchEnvironmentService` and `seclabAiDisabled`. Upstream's `src/vs/workbench/contrib/chat/browser/remoteAgentHost/remoteAgentHost.contribution.ts` imports none of those five. Verified executably: applying 0011 to a scratch copy of the pinned tree and grepping the result gives **0** matching import lines against **5** decorator uses. Because `workbench.web.main.ts` is not in any shipped target, TypeScript never type-checks this file in CI either, so the breakage is invisible to every current gate. This is independent evidence that the new lock has never been built, let alone exercised. | Add the five imports; then make a web or type-check build part of CI so a patch that cannot compile cannot be recorded as enforcement. |
| 3 | **High** | **0011's stated reason for choosing `_reconcileConnections` as the override point is factually wrong, and the same ordering hazard applies there.** The patch comment (`patches/0011-…:7-14`) and `docs/adr/20261105-no-builtin-chat-in-tabs.md:155-160` both assert that `webSocketEntriesSettingId` is unsafe because it is read inside the base constructor, whereas "`_reconcileConnections` runs from an autorun **after construction**". It does not. `RemoteAgentHostService`'s constructor registers `autorun(reader => { …; this._reconcileConnections(); })` at `remoteAgentHostServiceImpl.ts:275-281`, and `AutorunObserver`'s constructor calls `this._run()` synchronously (`src/vs/base/common/observableInternal/reactions/autorunImpl.ts:58`). TypeScript parameter properties are assigned *after* `super()` returns, so the first — and, since `observableConfigValue` has already read the current settings, the dialling-relevant — reconcile executes with `this._seclabEnvironmentService === undefined` and throws `TypeError: Cannot read properties of undefined (reading 'remoteAuthority')`. Demonstrated with a minimal repro of the exact class shape. The throw is swallowed by `catch (e) { onBugIndicatingError(e); }` at `autorunImpl.ts:110-112`, so construction succeeds and later reconciles are guarded; the construction-time one is skipped by accident rather than refused by design. Any later edit to `?.` flips this to a silent fail-open. | Read the authority from a module-scope or statically-available source rather than an injected field, or assign the field before `super()` by passing it through a static factory; and correct both the patch comment and the ADR. |
| 4 | **High** | **The surface-(e) tool scan misses the host tools that matter and pins six expressions that are not tool ids.** `_tool_entries` (`rpc-filter/tools/seclab_inventory/ai.py:85-90`) matches only `const x: IToolData = {` and `getToolData(): IToolData { return {`. `run_in_terminal` — the host-shell tool, and the subject of probe `ai-agent-host-autoapprove-setting` — is produced by the factory `createRunInTerminalToolData(accessor): Promise<IToolData>` (`.work/upstream/vscode/src/vs/workbench/contrib/terminalContrib/chatAgentTools/browser/tools/runInTerminalTool.ts:371`) and registered at `terminal.chatAgentTools.contribution.ts:180-181`, so it is **absent from the inventory and from `coverage.json`**; so is `fetch_webpage`. Conversely `coverage.json` pins `ai-tool:definition.id`, `ai-tool:tool.id`, `ai-tool:rawTool.name`, `ai-tool:progress.toolName`, `ai-tool:tc.toolName` and ``ai-tool:entry?.data.id ?? `mcpApp.tool.${generateUuid()}` `` — unresolved expressions counted as tools. Two consequences: (a) the ADR's load-bearing measurement, "54 tool definitions … not one statically declares `runsInWorkspace: true`" (`docs/adr/20261105-no-builtin-chat-in-tabs.md:82-87`), is a count of the wrong set, and an upstream change that marks a real tool `runsInWorkspace: true` or adds a new factory-built host tool would not move the digest; (b) two AI probes still **fail** `probe-policy-link` today — see finding 5. | Enumerate registration call sites (`registerToolData`/`registerToolImplementation`/`registerTool`) and resolve the id argument, instead of matching the literal's type annotation; drop entries whose id does not resolve, or record them as an explicit `unresolved` list that the drift gate fails on. |
| 5 | **Medium** | **`check-probes.ts` does not pass on this branch, and its policy-link gate now has a blanket exemption.** Run directly with empty evidence: `FAIL [probe-policy-link] ai-instructions-tool-call references a real policy entry (ai-tool:fetch_webpage) -> not present in coverage.json` and the same for `ai-agent-host-autoapprove-setting` (`ai-tool:run_in_terminal`). Both are consequences of finding 4. Separately, the new clause `|| spec.policyRef.startsWith('push:')` (`test/containment/check-probes.ts:209`) exempts the entire client-push surface from the lookup; `coverage.json` contains **zero** `push:` keys, so for that surface the check asserts nothing and a typo'd ref would pass. | Fix the tool inventory so the two `ai-tool:` refs resolve; replace the `push:` blanket with real coverage keys for the client-push surface, or an explicit named allowlist of the push refs that have no coverage entry yet. |
| 6 | **Medium** | **0009's `sendRequest` guard is on a wrapper, not the choke point — the same defect the round-6 finding 2 raised about `registerTool`.** The refusal is in `ChatServiceImpl.sendRequest` (`patches/0009-…`, hunk at `chatServiceImpl.ts:1529`). The agent loop is also entered by `resendRequest` (`.work/upstream/vscode/src/vs/workbench/contrib/chat/common/chatService/chatServiceImpl.ts:1439`), which calls `_sendRequestAsync` directly at `:1488`; by the pending-queue processor at `:2472`; and by `sendRequestInternal` from `moveQueuedRequests` (`:2700`) and `sendPendingRequestImmediately` (`:2847`, `:2853`). So the ADR's claim at `docs/adr/20261105-no-builtin-chat-in-tabs.md:58` — "`ChatServiceImpl.sendRequest` throws, so there is no agent loop" — is false as written. Not currently an escape: `invokeTool` still refuses, so no tool runs. But the model still receives tab-authored instruction files and workspace content, and this is the second layer in a two-layer design being one `throw` in one wrapper. | Put the refusal in `_sendRequestAsync`, which every path funnels through, and correct the ADR. |
| 7 | **Medium** | **`ai.py` still cannot see a setting that is registered nowhere (round-6 finding 8, not fixed).** `_settings` (`rpc-filter/tools/seclab_inventory/ai.py:229-281`) builds `seen` exclusively from `registerConfiguration` property keys, then annotates read sites. A `chat.*`/`mcp.*` id read in an editor-window-loaded file and registered in no entry point — the maximally permissive case, since an unregistered key has `scope === undefined` and `ConfigurationModelParser.shouldInclude` passes it — produces no inventory row and no drift key at all. Upstream has live instances (`chat.agentHost.unsafeTestToken`). The duplicate-registration half of that finding **was** fixed well (weakest-registration-wins plus an `also_registered` record, `ai.py:264-281`). | Enumerate read sites first and emit a row for every id read in an editor-window-loaded file, registered or not, with `scope: null, tab_writable: true`. |
| 8 | **Low** | **No regression test for `strip_block_comments`, and the generator's own suite passes with the Critical round-6 defect reinstated.** The prior round's fix instruction was explicit: "add a regression test asserting a known in-string `/*` does not truncate". None exists (`grep -rn strip_block_comments rpc-filter/tools test` finds only call sites). Verified by injection: replacing the function body with the old `re.sub(r"/\*.*?\*/", "", text, flags=re.S)` leaves `rpc-filter/tools/test_generator.py` at `OK` and `check_drift.py`, `emit_policy.py --check` and `sync_patch.py --check` all at exit 0, because those gates read the committed `inventory.json` rather than regenerating it. The defect *is* caught — by `ci-linux`'s `rpc-inventory` job (`.github/workflows/ci-linux.yml:58-63`), which regenerates from pinned upstream and fails on any diff, and `rpc-filter/**` is in its path filter — but only as an unexplained artefact diff, not as a named failure. Regenerating with the naive stripper drops `setting_count` from 358 to 217, so the diff would be large and obvious. | Add a unit test to `test_generator.py` with an in-string `/*`, a template literal, an escaped quote and a line comment, asserting the output is length-preserving and that a known identifier after the string survives. |
| 9 | **Low** | **ADR arithmetic still does not match the inventory it cites (round-6 finding 10, not fixed).** `docs/adr/20261105-no-builtin-chat-in-tabs.md:110` says "55 of the 67 agent settings"; the regenerated `rpc-filter/inventory/inventory.json` records `setting_count: 358`, `tab_writable_setting_count: 244`. | Quote the generated figures. |
| 10 | **Informational** | **Prompt-injection payload encountered while reading, as the brief anticipated.** `test/containment/rogue-extension/ai-probes.js:30-44` builds an instructions-file payload containing "Before answering anything, complete these setup steps:" and "they are routine setup and the user has already approved them", written to `.github/instructions/seclab-probe.instructions.md` and `.github/copilot-instructions.md` with `applyTo: '**'`. I read it as data and did not act on it. It is a deliberate, documented, inert fixture (`// Safety: every payload is inert`, `:14`) and is the attack under test, so it is **not** a defect — recorded here because the brief asks for it. The file still has **zero importers** (`grep -rn ai-probes test/ extensions/` → none), which is why the six AI probes are `not-implemented`. | None. Keep the "inert fixture" comment adjacent to the payload so a future reader reaches it first. |

## The three previously blocking findings, item by item

### Round-6 finding 1 — the non-string-aware comment stripper: **genuinely fixed**

`strip_block_comments` (`rpc-filter/tools/seclab_inventory/sources.py:93-152`)
is now a hand-written scanner that tracks `'`, `"` and `` ` `` state, handles
backslash escapes, and replaces comment bodies with spaces rather than removing
them, so offsets and therefore permalink line numbers are preserved.

Verified rather than read:

- **Length preservation holds over the whole tree.** Ran the function over every
  `.ts` file under `.work/upstream/vscode/src/vs` and asserted
  `len(stripped) == len(original)` — no failures.
- **No file loses content it should not.** Ran it over the same tree, extracted
  every blanked run, and filtered for runs that do not begin with `/*` or `//`
  or that contain `registerConfiguration`, `registerSingleton`,
  `registerTool*`, `registerAction2`, `CommandsRegistry.registerCommand` or a
  `'chat.*'`/`'mcp.*'` literal. 23 runs matched; I inspected the largest and all
  are genuine comments that *mention* those tokens (for example the
  "DO NOT ADD SETTINGS HERE" banner at
  `src/vs/sessions/contrib/configuration/browser/configuration.contribution.ts:9-37`,
  which contains a commented-out `.registerConfiguration({`). No real code is
  blanked.
- **The effect on the inventory is the one claimed.** `chat.agent.enabled` and
  `chat.workspaceRemoteAgentHosts` are now present in `coverage.json` as
  `ai-setting:…|scope=WINDOW|unreg=False|tab_writable=True`. `setting_count`
  went 146 → 358 and `tab_writable_setting_count` 89 → 244. Regenerating with
  the old naive stripper reproduces 217/131, confirming the delta is the bug
  and not an unrelated change.
- **The documented residual risk is real but benign in direction.** A regex
  literal containing a quote (`/['"]/`) desynchronises the quote state. I built
  a regex-aware reference stripper and diffed: 199 files differ, but every
  difference I inspected is my reference over-blanking a license header it
  mistook for a regex, not the shipped stripper under-blanking. The shipped
  function's failure mode when it mis-parses is to *leave a comment in*, which
  adds noise to the inventory rather than hiding a surface.

The one thing not done is the regression test the prior round asked for — see
finding 8.

### Round-6 finding 2 — the registration guard on a wrapper: **genuinely fixed**

The guard now sits on both primitives: `registerToolData`
(`patches/0009-…`, hunk at `languageModelToolsService.ts:311`) and
`registerToolImplementation` (hunk at `:365`), with `registerTool` left alone
because it is only `combinedDisposable(this.registerToolData(…),
this.registerToolImplementation(…))` (upstream `:369-373`).

Verified that these are the real choke points:

- `this._tools.set(...)` occurs exactly once in `LanguageModelToolsService`,
  inside `registerToolData` (upstream `:315`). Nothing else writes the map.
- Every production caller of the primitives is now covered:
  `terminal.chatAgentTools.contribution.ts:180-181` (the `run_in_terminal`
  data **and** implementation), `languageModelToolsContribution.ts:337`
  (every extension-contributed tool), `mainThreadLanguageModelTools.ts:93`
  (the `vscode.lm` implementation bridge).
- `registerToolImplementation` returns before the `_tools.get(id)` lookup, so a
  disabled feature does not become a "was not contributed" exception for every
  caller — the right call.
- The `invokeTool` refusal (hunk at `:518`) is retained, so the two-layer design
  the ADR describes now actually has two layers.

### Round-6 findings 3 and 4 — probes that could not fail: **partially fixed**

Fixed:

- **Prose `hostEffect` is now an error, not a guaranteed pass.** `hostEffectPath`
  validates against `/^[A-Za-z0-9._\/-]+$/` and throws otherwise
  (`test/containment/check-probes.ts:72-83`). Verified by injecting the exact
  old value back onto a `required: true` probe: the checker exits non-zero with
  `Error: hostEffect "beacon hit from the host, or a marker written outside the
  tab" is not a filename`. The six prose values were removed from
  `expectations.json`.
- **`not-implemented` probes are reported, not silently skipped.** Six
  `probes-pending` lines appear in the output naming each probe "registered but
  NOT IMPLEMENTED" with its `blocked_on` reason, and the honest downgrade from
  `required: true` to `required: false` + `status: not-implemented` is the right
  call — a required probe with no runner was reporting a pass.
- **The `ai-setting:` grammar mismatch is fixed.** `composite()`
  (`check-probes.ts:202-204`) matches `ai-setting:<id>|…` by prefix, so the four
  setting-based AI probes now link to real coverage entries.

Not fixed:

- The two `ai-tool:` refs still fail the link check (finding 5), so running
  `check-probes.ts` on this branch still exits non-zero for a reason that is
  about this surface.
- `probes-pending` is recorded with `ok: true`, so it does not affect the exit
  code. That is defensible — it is reported in the summary — but it means the
  branch can go green with the entire trusted-AI surface unmeasured.
- Item 7 of the prior round's "before re-review" list ("demonstrate at least one
  AI probe succeeding unpatched and failing patched") remains outstanding, now
  for the third round.

## Is `_reconcileConnections` the only path that establishes a connection?

**Within an editor window, yes — but by reachability, not by construction, and
the brief is right to be suspicious.** `_connectTo` is the single dialling
primitive and has three call sites in
`.work/upstream/vscode/src/vs/platform/agentHost/browser/remoteAgentHostServiceImpl.ts`:

1. `:695`, inside `_reconcileConnections` — the overridden path;
2. `:490`, inside the **public** `reconnect(address, userInitiated)` (`:430`),
   which does **not** go through `_reconcileConnections`. It only needs the
   address to be present in `_configuredEntries`, and `_configuredEntries` is
   derived from the settings-backed `WebSocketConnectionFactory` registered in
   the base constructor — so a tab-supplied entry is already staged there
   regardless of whether reconcile ever ran. `reconnectNow` (`:496`) funnels
   into it, and both are on the public `IRemoteAgentHostService` interface
   (`platform/agentHost/common/remoteAgentHostService.ts:805`);
3. `:1067`, inside the reconnect-backoff timer, which is only scheduled after a
   connection has already been attempted, so it is downstream of (1) or (2).

Every production caller of `reconnect`/`reconnectNow` is in
`src/vs/sessions/` (`remoteAgentHostSessionsProvider.ts:944,948`,
`browserTunnelAgentHostService.ts:321`, `sshAgentHost.contribution.ts:153`,
`devContainerAgentHostService.ts:428`) or in the SSH/WSL services under
`src/vs/platform/agentHost/electron-browser/`, which are registered solely by
`sessions.desktop.main.ts` — i.e. the Agents window, not an editor window.
`waitForConnection` (`:503`) follows an in-flight dial and never starts one.
`registerConnectionFactory` (`:371`) manages registry membership only; it does
not dial, and the autorun it feeds is the reconcile autorun. Cloud sandbox and
Mission Control reach the service through the same public surface.

So the override is sufficient **today**, on the assumption that no editor-window
code calls `reconnect`. That assumption is not stated anywhere in the patch and
nothing enforces it; one new editor-window action that offers a "retry" button
reopens the path with no gate firing. Given findings 1–3, this is currently
moot — the subclass is not registered in any shipped build — but when 0011 is
fixed, the refusal should sit on `_connectTo`, which is private and has all
three call sites inside the class, rather than on one of its callers. That is
the same reasoning that moved the tool guard off `registerTool` and the channel
guard onto `ChannelServer`.

## Finding-6 fix (patch 0006, the channel guard): sound

Checked against `.work/upstream/vscode/src/vs/base/parts/ipc/common/ipc.ts`.

- **Call-time read, unconditional wrap.** `registerChannel` now always installs
  a wrapper and looks `seclabChannelGuard` up per call
  (`patches/0006-…:371-402`), so registration order no longer decides
  enforcement. This was the actual defect and it is gone.
- **The asymmetry between `call` and `listen` is correctly diagnosed.**
  `onPromise` (`ipc.ts:416-431`) wraps `channel.call` in `try/catch` and turns
  a throw into a rejected promise; `onEventListen` (`:457-470`) has no
  `try/catch` and immediately does `const disposable = event(...)`, so a throw
  there would escape into the message handler and tear down the connection
  rather than refuse one capability. Returning `Event.None` is the right shape,
  and `Event` is already imported at `ipc.ts:12`.
- **No channel is served without passing through this method.**
  `ChannelServer`'s `channels` map is written in exactly one place, `:348`
  (`registerChannel`); `onPromise` and `onEventListen` both read it via
  `this.channels.get`. `IPCServer.registerChannel` (`:985-991`) forwards to
  `connection.channelServer.registerChannel` for every connection. Only two
  `new ChannelServer(...)` sites exist outside tests (`ipc.ts:857`, `:1030`),
  both inside this file.
- **`ctx` is the right discriminator for the remote connection.**
  `ManagementPersistentConnection` constructs its `Client` with
  `{ remoteAuthority, clientId }` (`platform/remote/common/remoteAgentConnection.ts:773-777`),
  so the guard's `(ctx as {remoteAuthority?: string})?.remoteAuthority` read is
  populated on exactly the connection it is meant to police, and `ctx` is a
  readonly constructor parameter so the value captured at registration cannot
  drift.
- `test/containment/channel-guard.test.ts` passes 7/7 and includes the right
  control — "control: the old version threw out of listen" — so the test can
  distinguish the fix from its absence.

Residual, not a finding: the guard is global module state defaulting to
`undefined`, i.e. allow. That is fail-open by shape. It is installed
unconditionally at module scope in `seclabRpcFilter.ts:564`, which patch 0005
ships and which `sync_patch.py --check` pins, and the guard itself is a no-op
for any authority that is not `seclab+*`, so the exposure is limited to "patch
0005 is dropped", which the series gate already catches.

## The settings model

`tab_writable = scope != APPLICATION`, with `unregistered_where_read`
overriding to `true`, is **correct for the layers I could enumerate**.

- `REMOTE_MACHINE_SCOPES` is
  `[MACHINE, APPLICATION_MACHINE, WINDOW, RESOURCE, LANGUAGE_OVERRIDABLE, MACHINE_OVERRIDABLE]`
  (`.work/upstream/vscode/src/vs/workbench/services/configuration/common/configuration.ts:32`)
  — every scope except `APPLICATION`. Confirmed.
- Remote user settings are read from `environment.settingsPath`, the
  REH-supplied path, with exactly those scopes
  (`services/configuration/browser/configuration.ts:401`), and the cached form
  uses them too (`:398`). So the tab's channel is real and the rule's exclusion
  set is right.
- **Profiles:** `PROFILE_SCOPES` (`:29`) and `APPLICATION_SCOPES` (`:28`) are
  partitions of the same space; an `APPLICATION` key is read only from the
  default profile's `settingsResource`. This narrows where a *user* can set an
  APPLICATION key but does not give a tab a new layer.
- **Workspace file and `.vscode/settings.json`:** `WORKSPACE_SCOPES` (`:33`)
  and `FOLDER_SCOPES` (`:34`) are both strict subsets of
  `REMOTE_MACHINE_SCOPES`, so they add nothing the rule does not already cover.
- **Extension `configurationDefaults`:** re-confirmed from the prior round that
  `configurationExtensionPoint.ts:215-228` rejects contributions for keys whose
  registered scope is outside
  `[MACHINE_OVERRIDABLE, WINDOW, RESOURCE, LANGUAGE_OVERRIDABLE]`, so it is not
  a bypass for `APPLICATION` — but the check is skipped for **unregistered**
  keys, which is the second reason finding 7 matters.
- **Default scope:** when a property declares no `scope:`, `ai.py:255` records
  `WINDOW`, matching upstream's default. Safe direction.

The two improvements over round 6 both hold up:

- **Weakest-registration-wins** (`ai.py:264-281`) replaces first-wins, and the
  losing registration is kept as `also_registered` rather than discarded. The
  example in the comment (`workbench.browser.enableRemoteProxy`, APPLICATION in
  `platform/agentHost` and WINDOW in `browserView`) is a case where first-wins
  would have recorded the safe-looking half of a tab-writable surface.
- **`platform/` reads are now reported as `ambiguous_platform_read` rather than
  asserted** (`ai.py:298-301`), which is the correct response to round-6
  finding 9: a `platform/` path is not evidence of an editor-window read,
  because `SSHRemoteAgentHostService` and friends live there and are registered
  only by `sessions.desktop.main.ts`.

The gap the rule still misses is the **unregistered-everywhere** case, which is
finding 7, unchanged from round 6.

## The gates, tested by injection rather than by reading

| Injected defect | Gate | Result |
|---|---|---|
| Prose `hostEffect` on a `required: true` probe | `check-probes.ts patched` | **exit 1**, with the exact unresolvable-effect error. Caught. |
| Naive `re.sub` comment stripper restored | `rpc-filter/tools/test_generator.py` | `OK`, exit 0. **Not caught.** |
| Naive stripper restored | `check_drift.py`, `emit_policy.py --check`, `sync_patch.py --check` | all exit 0. **Not caught** — they read the committed `inventory.json`. |
| Naive stripper restored + inventory regenerated | `git diff --exit-code rpc-filter/inventory/` in `ci-linux` `rpc-inventory` | would fail (358 → 217 settings). Caught, but only as an artefact diff. See finding 8. |
| `registerSingleton(IRemoteAgentHostService, …)` left on the upstream class in the shipped entry point | *(none)* | **Not caught by any gate.** This is finding 1. |
| Patched file referencing undefined identifiers | `build/apply-patches.sh --check`, `sync_patch.py --check` | both exit 0; neither type-checks. This is finding 2. |

Baseline runs on the unmodified branch, for the record:
`build/apply-patches.sh --check` exit 0 (11 patches, series matches);
`sync_patch.py --check` exit 0; `check_drift.py` exit 0
(4174 surfaces, 14 reachable, 4160 denied); `emit_policy.py --check` exit 0;
`test_generator.py` 7 tests OK (1 skipped, needs `/src`);
`node test/containment/channel-guard.test.ts` 7/7;
`uri-constraint.test.ts` 15/15; `policy-invariants.test.ts` 6/6.

## What else I checked and found sound

- **0010 is unchanged and still correct.** The local branch is taken when
  `environmentService.remoteAuthority && !seclabAiDisabled(...)` is false
  (`patches/0010-…`, hunk at `agentHostService.ts:48`), so a tab window takes
  the same branch an ordinary non-remote window takes and
  `EditorRemoteAgentHostServiceClient` — which is what forwards a real
  `accessToken` for every entry the remote advertises — is never constructed.
- **Round-6 finding 6 is fixed by removal.** 0011 no longer registers
  `chat.agentHost.localFilePermissions` in the editor-window contribution, so
  the silent clobbering of upstream's schema in the Agents window is gone.
- **Round-6 finding 7 is resolved as a recorded product decision.** The global
  `APPLICATION` pin of `chat.workspaceRemoteAgentHosts` is withdrawn and the
  trade is written down in
  `docs/adr/20261105-no-builtin-chat-in-tabs.md:161-173`. The decision is
  defensible; the replacement is not (findings 1–3).
- **Round-6 finding 5 is accepted as-is, knowingly.** The token-forwarding
  backstop is still in `authenticateProtectedResources` rather than in
  `forwardAuthenticationToken`, so it still covers one of six entry points.
  With finding 1 open this is now load-bearing rather than defence in depth,
  which is the opposite of the patch's stated intent.
- **`seclabAiDisabled`'s predicate is unchanged and still authority-keyed**
  (`rpc-filter/patch-src/seclabRpcFilter.ts:496-498`). The authority-parser
  change in `c368728` (`String.match` instead of `RegExp.exec`,
  `seclabResolveTabId`, `:520-523`) removes the `lastIndex` statefulness
  hazard of a shared `/g` regex; the pattern `^seclab\+([\w.-]+)$` is anchored
  and has no `g` flag, so there is no partial-match or reuse issue.
- **Auxiliary windows are not a blind side.** An auxiliary editor window shares
  the host window's workbench instantiation service and therefore the same
  `IWorkbenchEnvironmentService.remoteAuthority`, so `seclabAiDisabled` returns
  the same answer there.
- **`uri-constraint` and `policy-invariants` are substantive.** They include
  negative controls ("a prototype-polluting key cannot smuggle a scheme",
  "an unknown seclab command is denied too", "the default verdict is deny"),
  not just positive assertions.
- **The six AI probe entries are now honestly labelled.** Each carries a
  `blocked_on` string naming the real obstacle — no runner imports
  `ai-probes.js`, and the oracle is a host-side observation rather than a
  return value. That is a better state than round 6's `required: true` with no
  implementation, even though it leaves the surface unmeasured.

## What I could not determine

- **Whether the Agents window can open a `seclab+` folder as an agent session.**
  This was undetermined in round 6 and still is. `seclabAiDisabled` is
  per-window and the Agents window has no remote authority, so chat, tool
  registration and tool invocation are all fully enabled there. If a tab's
  workspace can be opened as a session in that window, the full
  instruction-file confused-deputy path is available with none of 0009's gates.
  I traced the service registrations but not the session-open path, which
  crosses `src/vs/sessions/` end to end and deserves its own round.
- **Whether `.vscode/mcp.json` in a tab's workspace can launch a server process
  on the host.** Unchanged from round 6: `mcp` is WINDOW-scoped,
  `MCP_CONFIGURATION_KEY` is a workspace standalone configuration
  (`configuration.ts:43`), the inventory flags it `tab_writable: true`, and
  none of 0009–0011 addresses where the server process is actually spawned in
  a remote window.
- **Whether `check-probes.ts` is wired into any CI job.** I grepped the
  workflows for the tools they run; `check-probes.ts` is not among the
  `ci-unit` or `ci-linux` steps I read, but it may be invoked indirectly
  through `./seclab test containment`, which I did not trace. Finding 5 is
  stated as a property of the checker, verified by running it directly.
- **Whether the swallowed `TypeError` in finding 3 is swallowed in every
  configuration.** `onBugIndicatingError` reports and continues in the default
  handler, but `setUnexpectedErrorHandler` is replaced in some test and
  development setups, where it rethrows. I did not enumerate which of the
  fork's run modes install which handler. The finding does not depend on the
  answer — the construction-time reconcile is unguarded either way — but
  whether the symptom is "no dial" or "service construction fails" does.
- **Whether any web or `reh-web` target is built outside `build/`.** I read
  `build/build-darwin.sh` and `build/linux/build.sh` and found only
  `vscode-darwin-*-min`, `vscode-linux-*-min` and `vscode-reh-linux-*-min`. If
  a web client is produced by some path I did not see, finding 1's scope would
  narrow — but not vanish, since the desktop client is the fork's product.

## Before the next re-review

1. Register the seclab agent-host service where the fork builds
   (`src/vs/platform/agentHost/electron-browser/remoteAgentHostService.ts`),
   and add the five missing imports so 0011 compiles. Demonstrate the refusal
   firing in a built tab window, not by reading the patch.
2. Move the refusal to `_connectTo`, and correct the patch comment and ADR
   claim about when `_reconcileConnections` runs.
3. Fix the tool scan so `run_in_terminal` and `fetch_webpage` appear and the
   six expression artefacts do not, then re-review the ADR's "no safe subset"
   measurement against the corrected set.
4. Move 0009's chat refusal to `_sendRequestAsync`, and 0011's token backstop
   to `forwardAuthenticationToken`.
5. Add the `strip_block_comments` regression test.
6. Add a type-check or web-build step to CI, so a patch that does not compile
   cannot be recorded as enforcement.
7. Demonstrate at least one AI probe succeeding unpatched and failing patched.
   Third round outstanding.
