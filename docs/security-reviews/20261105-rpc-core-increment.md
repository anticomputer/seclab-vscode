# Security review: the rpc-core increment, patches 0005–0010

- **Date:** 2026-11-05
- **Round:** 8 (core RPC filter, split out ahead of the agent-host work)
- **Reviewer:** independent `security-review` agent
- **Subject:** `patches/0005-seclab-rpc-capability-filter.patch`,
  `0006-seclab-channel-guard.patch`, `0007-seclab-command-taint.patch`,
  `0008-seclab-route-tab-commands.patch`,
  `0009-seclab-no-builtin-chat-in-tabs.patch`,
  `0010-seclab-no-agent-host-client-in-tabs.patch`,
  `rpc-filter/patch-src/seclabRpcFilter.ts`, `rpc-filter/policy/policy.json`,
  `rpc-filter/tools/{check_drift.py,sync_patch.py}`,
  `test/containment/{channel-guard,uri-constraint,policy-invariants}.test.ts`
- **Upstream:** `microsoft/vscode@a717861c07586a53d83b80d742cd3f59b20a6273`,
  read-only at `.work/upstream/vscode`
- **Branch:** `rpc-core` at `742db7c`, rebased on main `5f41596`
- **Out of scope by instruction:** patch 0011 (lives on
  `anticomputer-rpc-filter-patches`). Nothing in 0005–0010 turned out to depend
  on it.

## Verdict: DO-NOT-LAND

**Finding 1 blocks.** The answer to the question the brief puts first is *yes*:
after 0005–0010 a tab can still reach host code execution through the command
path. Not through `$executeCommand` — that is genuinely and completely closed —
but through the **server-initiated** `remoteTerminal.onExecuteCommand` callback,
which the policy table classifies `deny` and which no patch in this increment
enforces. The channel guard in 0006 guards the channels the client *serves*;
this one arrives on the channel the client *consumes*, and lands in a
constructor-injected `ICommandService` that neither the taint nor its backstop
can see.

Finding 2 does not block landing as the table stands today, because the command
allow set is empty, but it **blocks the first entry added to
`policy.commands.exact` with a reachable verdict**.

Everything else is Medium or below.

## Findings

| # | Severity | Finding | Recommended fix |
|---|---|---|---|
| 1 | **Critical** | **Host code execution from a tab, via the server-initiated terminal callback.** `remoteTerminalBackend` subscribes to `this._remoteTerminalChannel.onExecuteCommand` and, for any id in a four-entry allowlist, calls `this._commandService.executeCommand(e.commandId, ...commandArgs)` (`.work/upstream/vscode/src/vs/workbench/contrib/terminal/browser/remoteTerminalBackend.ts:102-121`; `_commandService` is constructor-injected at `:71`). The channel is obtained with `connection.getChannel(REMOTE_TERMINAL_CHANNEL_NAME)` (`:45`), i.e. the workbench is the **ChannelClient** here and the hostile REH is the server, so 0006's guard on `ChannelServer.registerChannel` (`patches/0006-…`, hunk at `ipc.ts:371`) never sees it. The call carries no `seclabOrigin`, so `seclabTaintInFlight` takes the `origin === undefined` branch, and `seclabInFlight` is `0` whenever no tab command happens to be running, so it returns `undefined` and the command executes (`rpc-filter/patch-src/seclabRpcFilter.ts:391-404`). All four allowlisted ids are host-authority: `_remoteCLI.windowOpen` opens a host folder in a new window (a local extension host over host files), `_remoteCLI.manageExtensions` installs an extension, `_remoteCLI.openExternal` opens a caller-chosen URI with `allowTunneling: true`. The only precondition is one live remote PTY in the tab, whose `persistentProcessId` the REH already knows. The policy records the surface as `deny` (`rpc-filter/policy/policy.json:758`, `server_initiated.remoteTerminal.onExecuteCommand`), `docs/RPC-LOCKDOWN.md:201-207` describes it correctly, and `rpc-filter/AGENTS.md:131` publishes the expectation "denied" — but no patch in the queue touches `remoteTerminalBackend.ts` (`grep -rln 'remoteTerminal\|onExecuteCommand\|_remoteCLI' patches/` matches only 0005, and only inside the policy *data*). A verdict with no enforcement is being read as containment, which is the same failure mode as the `rewrite` finding of round 5. | Enforce it where the event is consumed. The cheapest sound form is to drop the `onExecuteCommand` subscription entirely when `seclabAiDisabled`-style authority test matches (the fork's REH never needs it); failing that, route it through `seclabExecuteCommandFromTab` with the origin derived from `connection.remoteAuthority`, so the four ids hit `commandVerdict` and deny. Then make the surface visible to the gates — see Finding 7. |
| 2 | **High** | **The taint's fail-closed backstop is armed only at depth ≥ 2; the depth-1 escape it was written for is open.** `seclabInFlight` is incremented *only* inside `seclabTaintedCommandService.executeCommand` (`rpc-filter/patch-src/seclabRpcFilter.ts:423-425`). The entry point `CommandService.seclabExecuteFromTab` (`patches/0007-…:49`) does not increment it. So when a tab-originated command's handler reaches a **constructor-injected or module-imported** `ICommandService` — the exact shape the backstop's own docstring names (`:371-377`, "While any tab command is in flight, a denied command is refused whoever asks") — the global `_tryExecuteCommand` is called with `seclabOrigin === undefined` while `seclabInFlight === 0`, and the denied command runs. Demonstrated executably by transliterating the shipped `_tryExecuteCommand`, `seclabTaintInFlight` and `seclabTaintedCommandService` and stubbing only the policy table so one command is allowed: case A (accessor/tainted) `refused`, case B (global, depth 1) **`RAN`**, case C (global, depth 2) `refused`. Not exploitable on this branch only because `SECLAB_COMMANDS` contains six entries and all six are `deny`, so `commandVerdict` returns `deny` for every id and no handler ever runs with an origin. `policy.json` states the allow set will be grown "from measured need", and the first such entry opens this. | Increment `seclabInFlight` around the whole tab-originated execution, i.e. in `seclabExecuteFromTab`/`_tryExecuteCommand` when `seclabOrigin` is set, not only in the tainted wrapper. Add the case-B shape to `test/containment/` as a regression test with the current (broken) implementation as the negative control. |
| 3 | **Medium** | **A tab-supplied extension manifest can bind a host-authority command id into the trusted UI, and the surface is in no inventory.** Extensions installed in a tab are scanned by the tab's REH, which is hostile under the threat model; the workbench registers their `contributes.menus` and `contributes.keybindings` into `MenuRegistry`/`KeybindingsRegistry`, where the `command` field is an arbitrary id and is not required to be one the extension registered. Triggering such an item runs through `ICommandService` with no origin, so neither `commandVerdict` nor the backstop applies — the same untainted sink as Finding 1, reached by user action instead of by a push. This is not one of the 15 sinks in `rpc-filter/inventory/inventory.json` surface (d) (`as-external-uri … workspace-configuration`), so it has no coverage key and no gate will ever surface it. I did not build a running tab to confirm end to end, so I state the reachability as derived from upstream registration code rather than observed. | Add `extension-manifest-contributions` as a surface-(d) sink with a verdict, and constrain the `command` id of menu/keybinding contributions from a tab to ids that tab registered. |
| 4 | **Medium** | **Two of the three containment tests named in the brief have no runner.** `test/containment/channel-guard.test.ts` and `test/containment/policy-invariants.test.ts` are referenced by no workflow and by no `seclab` subcommand: `.github/workflows/ci-unit.yml:54` and `seclab:378` run only `uri-constraint`, and `ci-linux.yml:90,102` run only `teardown.test.ts` and `containment oci`. Both pass when run by hand (7/7 and 6/6), but they are the regression pins for round 5's finding 6 (call-time guard lookup, `Event.None` instead of a throw) and for the "nothing in the exact table is reachable yet" claim, and nothing executes them. An assertion that exists but is never run is this project's named recurring defect. | Add `channel-guard` and `policy-invariants` cases to `seclab test` alongside `uri-constraint`, and steps to `ci-unit.yml`. |
| 5 | **Medium** | **0009's chat refusal is still on a wrapper, not the funnel (round 7, finding 6 — not fixed).** The hunk is in `ChatServiceImpl.sendRequest` (`patches/0009-…`, `chatServiceImpl.ts:1529`). `resendRequest` (`.work/upstream/vscode/…/chatServiceImpl.ts:1439`) calls `_sendRequestAsync` directly at `:1488`, and the pending-queue paths at `:2472`, `:2700`, `:2847`, `:2853` enter through `sendRequestInternal`. Not an escape today — the `invokeTool` refusal at `languageModelToolsService.ts:518` still holds, so no tool runs — but the second of two layers is one `throw` in one of several entry points, and `docs/adr/20261105-no-builtin-chat-in-tabs.md:58` remains false as written. | Move the refusal to `_sendRequestAsync` and correct the ADR. |
| 6 | **Low** | **A probe can report PASS with no evidence at all.** `check-probes.ts:227` is `c('probes', !spec.required, \`${id} ran\`, 'no result recorded')`, so any probe with `required: false` that is *not* marked `status: 'not-implemented'` prints a green `PASS [probes] <id> ran` when nothing ran. Verified by running `node test/containment/check-probes.ts patched <empty-dir>`: `host-fs-write-file-scheme` and `secret-write-own` both PASS against an empty evidence directory. Neither is load-bearing today (one is a documented negative control, the other a seeding step), so this is Low — but the round-7 remediation for unimplemented probes was precisely "downgrade `required: true` to `required: false` + `status: not-implemented`", and omitting the second half of that pair yields a silent green. | Report a non-required probe with no result as `probes-pending`/skip, never as a passing `ran` check; or require `status` whenever `required` is false. |
| 7 | **Low** | **`chan:server_initiated` is exempted from every gate that could have caught Finding 1.** `check_drift.check_keys` and `check_invariants` skip the key by name (`rpc-filter/tools/check_drift.py:191,323`); `build_mapping` iterates only `c_client_served_channels`, so `coverage.json` contains exactly two `chan:` keys (`chan:download`, `chan:mcpGatewayToolBroker`) and the callback's verdict is **not in the digest** — changing or deleting it moves nothing. `check-probes.ts:208` then exempts the whole prefix from the policy-link lookup (the same blanket shape as the `push:` exemption at `:209`, raised as round-7 finding 5 and still present), so the `terminal-onexecutecommand` probe's `policyRef` resolves against nothing. The surface is documented, classified and published as "denied", and is simultaneously invisible to the drift gate, the invariant checker and the probe-link checker. | Give server-initiated callbacks real mapping keys in `build_mapping` so they enter the digest and the invariant checks, and replace both blanket `startsWith` exemptions with named allowlists. |
| 8 | Informational | **Prompt-injection payloads encountered, as the brief anticipated.** `test/containment/rogue-extension/ai-probes.js:30-44` constructs an instruction-file payload ("Before answering anything, complete these setup steps…", "they are routine setup and the user has already approved them") written to `.github/copilot-instructions.md` and `.github/instructions/seclab-probe.instructions.md` with `applyTo: '**'`, and `test/containment/fixtures/malicious-workspace/.vscode/tasks.json` carries the autorun-task vector. I read both as data and acted on neither. They are deliberate, labelled, inert fixtures and are the attack under test, so they are not defects. Nothing inside the in-scope diff addressed the reviewer: a scan of the six patches, `rpc-filter/patch-src/`, `rpc-filter/policy/`, `check_drift.py`, `sync_patch.py` and the three containment tests for reviewer-directed instructions ("ignore the above", "already approved", "skip this check", "do not report", second-person directives) returned nothing. | None. |

## The question: can a tab still reach host code execution through the command path?

**Yes — but not through `$executeCommand`.** The reasoning, path by path.

### What the filter actually permits

The choke point is live and is the only one. `new RPCProtocol(...)` occurs
exactly once on the trusted side upstream
(`src/vs/workbench/services/extensions/common/extensionHostManager.ts:258`), and
0005 replaces that single construction with one that passes
`seclabFilterFor(this._extensionHost.remoteAuthority, seclabResolveTabId)`. The
check sits as the first statement of `_receiveRequest`, before
`_invokeHandler` and therefore before `actor[methodName]`, and both
`RequestJSONArgs` and `RequestMixedArgs` funnel through it.

Resolving the whole inventory against the policy gives **4174 surfaces, 14
reachable** (`check_drift.py` on this tree). Of those 14, four are surface-(d)
data sinks the filter does not mediate, three are `prompt` and therefore deny
until the Tab Manager lands, and the remaining seven are:

| Surface | Effective behaviour |
|---|---|
| `MainThreadClipboard.$writeText` | allow |
| `MainThreadCommands.$executeCommand` | allow, then the id must pass `commandVerdict` |
| `MainThreadCommands.$getCommands` / `$registerCommand` / `$unregisterCommand` | **deny** — `_constrain` reaches `constraint not implemented` and refuses (`seclabRpcFilter.ts:310-314`) |
| `MainThreadFileSystem.$readFile` / `$writeFile` | allow only for `vscode-remote://seclab+<this tab>` or `untitled:` |

### `$executeCommand` is closed

`SECLAB_COMMANDS` has six entries and every one is `deny`;
`SECLAB_DEFAULT_VERDICT` is `deny`; `SECLAB_COMMAND_DENY_PREFIXES` is checked
before the table. So `commandVerdict(id)` returns `deny` for **every** id, and
`_constrain`'s `MainThreadCommands.$executeCommand` branch
(`seclabRpcFilter.ts:261-271`) refuses unconditionally. The specific evasions
the brief lists are all closed, and for reasons that do not depend on the allow
set staying empty:

- **A denied id.** Refused at the RPC layer, and refused again in
  `seclabTaintInFlight` via the origin — two independent checks.
- **Nested commands from an allowed handler.** The capability taint replaces
  `ICommandService` in a child injector (`patches/0007-…`, `createChild(new
  ServiceCollection([ICommandService, seclabTaintedCommandService(...)]))`),
  and recursion carries the same origin, so depth is unbounded and every level
  is checked. This is sound for handlers that resolve the service from their
  accessor. It is **not** sound for handlers that hold an injected reference —
  Finding 2.
- **`command:` URIs through `IOpenerService`.** `MainThreadWindow.$openUri` and
  `$asExternalUri` are `prompt`, which fails closed today; `MainThreadUrls`
  has no entry and no service default, so it takes `SECLAB_DEFAULT_VERDICT`.
- **`$registerCommand` shadowing an allowed id.** Denied outright, so the
  `commands.unshift` / head-wins behaviour of `CommandsRegistry` cannot be
  reached from a tab at all.
- **`MenuRegistry` / keybindings from the extension host.** Unreachable the same
  way — the ext host cannot register anything. The *manifest* route is a
  different matter: see Finding 3.
- **Every other `MainThread*` method.** Absent from both `SECLAB_RPC` and
  `SECLAB_SERVICE_DEFAULTS`, so `deny` by default, and a non-`$` method name is
  refused before the table is consulted.

### What is left open

Two sinks execute commands without ever passing through
`ICommandService.executeCommand` *with an origin*, and both are reachable by a
hostile tab:

1. **The REH pushes a command to the workbench.** `remoteTerminalBackend`'s
   `onExecuteCommand` handler is a *consumer* of an event the tab's REH fires.
   It never passes through `RPCProtocol`, so 0005 cannot see it; it arrives on
   a `ChannelClient`, not a `ChannelServer`, so 0006 cannot see it; and it calls
   an injected `ICommandService` with no origin, so 0007's taint cannot see it.
   `seclabInFlight` is `0` at that moment unless a tab command happens to be
   running concurrently, so 0007's backstop returns `undefined` and
   `_remoteCLI.windowOpen` / `manageExtensions` / `openExternal` execute on the
   host. This is Finding 1 and it is the answer to the question.

2. **A manifest contribution the user clicks.** Finding 3, same untainted sink,
   different trigger.

The shape is identical in both cases and worth naming: the increment's three
mechanisms are all keyed on *the tab making a call*. Every path where the
trusted side acts on tab-supplied data without the tab having made a call —
a pushed event, a scanned manifest, a settings file — is outside all three, and
`seclabInFlight` is the only thing that was supposed to cover that class. It
covers it at depth ≥ 2 only, and not at all when no tab command is running.

## Checked and found sound

Recorded so coverage is visible; none of these produced a finding.

**The choke point (0005).**

- Single trusted-side `RPCProtocol` construction, filter attached there,
  check is the first statement of `_receiveRequest`, ahead of
  `actor[methodName]`. Non-`$` method names are refused before the table.
- Fail-closed by construction: `seclabFilterFor` returns `undefined` only for
  `remoteAuthority === null` (local/worker hosts, trusted by design), returns a
  deny-all filter for an unrecognised authority, and **throws** for a `seclab+`
  authority whose tab id will not parse — inside the `ExtensionHostManager`
  constructor, so the host does not come up unfiltered.
- `rewrite` denies unless registered and nothing registers, so all seven rewrite
  surfaces deny; `prompt` denies; a named constraint with no implementation
  denies. Each of the three closed directions verified by reading the branch
  order in `checkRpc`/`_constrain`, and the third exercised by the
  `$registerCommand` family above.
- `_entry` is keyed on the wire `sid` from `getStringIdentifierForProxy`, and
  `check_keys` rejects a policy key that is a `MainContext` property name
  instead — the mis-key that would silently fall through to the default.

**The URI constraint.** `SECLAB_URI_ARGS` carries 71 methods / 36 services, the
positions are generated from the `UriComponents` parameters declared in
`extHost.protocol.ts`, and the filter revives with the same `URI.revive` the
consumer uses, so the two cannot disagree by shape. `uri-constraint.test.ts`
passes 15/15, including the marker-less-components payload that defeated the
old shape walk (kept with the old walker as a negative control), both URI
positions of the two-URI methods, the prototype-pollution key, and a generated
differential over filter-versus-consumer. For the only two URI methods that are
actually reachable (`$readFile`, `$writeFile`) I confirmed the declared
position `[0]` matches what `MainThreadFileSystem` revives. A non-object in a
declared position is refused rather than reasoned about; `null`/`undefined`
pass through exactly as `URI.revive` does, and then hit the
`constraint not implemented` deny rather than being treated as satisfied.

**The channel guard (0006).** `RemoteAgentConnectionContext` is
`{ remoteAuthority, clientId }` (`remoteAgentConnection.ts:771-776`), so
`ctx.remoteAuthority` is the right discriminator for the remote connection and
is `undefined` for every string-context `IPCClient` (shared process, Electron
main, pty host, agent host), which correctly no-ops. Wrapping is unconditional
and the guard is read per call, so registration order cannot decide
enforcement; `flushPendingRequests` re-reads `this.channels`, so pre-registration
requests are wrapped too. A refused `listen` returns `Event.None`, which matters
because `onEventListen` has no `try/catch`. `channel-guard.test.ts` passes 7/7
with controls that reproduce both old bugs — though nothing runs it (Finding 4).
Channel verdicts are default-deny, so both inventoried client-served channels
and anything upstream adds are refused.

**Identity.** The tab id is derived from the connection authority in all three
places (`seclabResolveTabId`, `seclabOriginFor`, the channel-guard closure) and
never from a call argument, which is the specific mistake
`$getPassword(extensionId, …)` represents. `MainThreadCommands` captures
`_seclabOrigin` in its constructor from `extHostContext.remoteAuthority`, not
per call. 0008 fails closed if `seclabExecuteFromTab` is missing rather than
falling back to an untainted `executeCommand`.

**0009 / 0010.** The tool guards are on both primitives (`registerToolData`,
`registerToolImplementation`) with `registerTool` correctly left alone as a
wrapper over them, plus the `invokeTool` refusal, so the two-layer design has
two layers; `registerToolImplementation` returns before the `_tools.get` lookup,
which is the right call. 0010's `environmentService.remoteAuthority &&
!seclabAiDisabled(...)` takes the local branch in a tab, which is what stops
`EditorRemoteAgentHostServiceClient` forwarding a real `accessToken` to a REH
that advertises whatever it likes in `protectedResources` — a client→server
push neither the filter nor the guard would see.

**The gates, tested by injection rather than read.**

- Flipping `workbench.action.terminal.newLocal` to `allow` in `policy.json`:
  `check_drift.py` exits 1 with
  `CHANGED cmd:workbench.action.terminal.newLocal: deny -> allow#dc7e04bbdcaa`.
- Weakening `$readFile`'s `constraint` text with **no** verdict change:
  exits 1 with the entry fingerprint moving
  `allow_with_constraint#715583795805 -> #bb1daf81bcd6`. The digest does pin
  the whole entry, not just the verdict.
- `emit.sh --check` is green, and I independently extracted both new-file
  sections from `0005` and diffed them against `rpc-filter/patch-src/` —
  byte-identical, so the patch ships what the source says.
- `sync_patch.check_callers` correctly excludes the sections that carry
  `patch-src` files, so the dead-entry-point check is not vacuous, and matches a
  bare symbol rather than a call shape so `seclabFilterFor(a,
  seclabResolveTabId)` counts as a use. Import statements are stripped before
  matching; over-stripping would produce false failures, not false passes.
- `ci-linux.yml:56-63` regenerates the inventory from the pinned upstream and
  fails on any diff *including untracked files*, so the drift gate compares the
  policy against what ships rather than against a committed artefact. This
  closes the stale-inventory concern for surfaces (a)–(c).
- `check_drift.check_citations` resolves `path::symbol` citations, which is why
  my partial-tree copy failed until I restored `broker/` — the citation check
  genuinely reads the files.
- `check-probes.ts` against an empty evidence directory exits 1 with 32
  failures, the six `not-implemented` AI probes are reported as
  `probes-pending` rather than counted, and the prose-`hostEffect` path
  validation is in place. Two exceptions: Finding 6, and the two
  `probe-policy-link` failures carried over below.

## Carried over, still open from round 7

Not re-litigated; confirmed still present on this branch.

- `ai-tool:fetch_webpage` and `ai-tool:run_in_terminal` are absent from
  `coverage.json`, so `check-probes.ts` has two standing
  `probe-policy-link` failures and the ADR's "54 tool definitions, none
  `runsInWorkspace`" measurement is over the wrong set (round 7, finding 4/5).
- No regression test for `strip_block_comments` (round 7, finding 8).
- `ai.py` still cannot see a setting registered nowhere (round 7, finding 7).

## What I could not determine

- **Finding 3's end-to-end reachability.** I traced it from upstream
  registration code and the fact that the tab's REH supplies extension
  descriptions, but I did not build a tab and click a contributed menu item.
  The surface's *absence from the inventory* is certain; its exploitability is
  derived, not observed.
- **Whether a tab window has a live remote PTY in practice.** Finding 1 needs
  one `persistentProcessId` in `_ptys`. I did not run the harness, so I cannot
  state how early in a tab's life that becomes true — only that nothing
  prevents it and that the project already ships a `required: true` rogue-REH
  probe for exactly this surface.
- **Module-load ordering for the channel guard.** The guard is installed as a
  side effect of importing `seclabRpcFilter.ts`, which reaches the bundle
  through `extensionHostManager.ts`. In a bundled desktop build everything is
  evaluated before the workbench starts, so the call-time lookup should always
  find it; I did not verify this against a produced bundle.
- **Functional cost.** With the allow set empty, a tab's extension host is
  denied even its startup chatter (`MainThreadExtensionService.*`,
  `MainThreadTelemetry.*`, `MainThreadConsole.*` are all default-deny). That is
  the correct direction for security and I raise it only so it is not mistaken
  for a reviewed decision about usability.

## Before re-review

1. Enforce `server_initiated.remoteTerminal.onExecuteCommand` (Finding 1), and
   give server-initiated callbacks real `coverage.json` keys so the gate can see
   the change (Finding 7).
2. Increment `seclabInFlight` for the depth-1 execution, with the case-B
   regression test and the current implementation as its negative control
   (Finding 2).
3. Run `channel-guard.test.ts` and `policy-invariants.test.ts` from CI
   (Finding 4).
4. Move 0009's refusal to `_sendRequestAsync` (Finding 5).
5. Add `extension-manifest-contributions` to surface (d) with a verdict
   (Finding 3).
