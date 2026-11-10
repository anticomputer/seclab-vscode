# Measure an ordinary session's RPC calls once, then classify them by name

- **Date:** 2026-11-06
- **Status:** accepted
- **Follows:** [the extension host's own plumbing](20261106-extension-host-plumbing.md)

## Context
The last two patched builds each found one more layer of denied plumbing. A denial stops
the code path that would have made the next call, so measuring through the filter can only
ever show the first wall. With a build cycle per layer, that is the slowest way to learn
what an extension needs.

## Decision
Measure once, on an **unfiltered** build, with upstream's own tracer.
`--logExtensionHostCommunication` makes `RPCLogger` (`extensionHostManager.ts` L252 at
`a717861c`) log every Ext → Win request to the renderer console. Chromium's
`--enable-logging=file --log-file=` puts that console in a file. No build variant, no hook,
nothing new in the shipped app.

`test/containment/rpc-trace.ts` does it end to end:
- `prepare` sets up a benign workspace (`fixtures/trace-workspace`: a `.ts`, `.md` and
  `.json` file in a git repo, fake data) and the benign extension only. It refuses
  everything else.
- The editor is launched through the background harness. `test/window.ts --rpc-trace`
  accepts only a plain path under this checkout's `.work/`.
- In the trace workspace the benign extension also opens files, so the built-in language
  extensions activate, and reloads once for a warm start.
- `check` derives method names, counts and `$executeCommand` ids. It **deletes the raw
  trace**, which carries argument values, then runs the teardown gate. Only the derived
  list enters the repo:
  [`rpc-filter/probes/traces/20261106-ordinary-session.json`](../../rpc-filter/probes/traces/20261106-ordinary-session.json).

The benign control gained the ordinary shapes it lacked:
- `globalState` with `setKeysForSync`;
- a contributed command;
- a completion provider;
- a status bar item;
- its own secret, with a fake value.

## Result
Run on main `bc85925` (run 42288509087): one pass, 2,677 requests, **69 distinct remote
calls**. The benign control activated with every step passing, nothing took focus, and
teardown was clean. Against the policy at the time, **64 of the 69 were denied**. The
patched builds had shown at most a dozen of them, one layer at a time.

Two things the trace showed that no build had:
1. **Storage blocks every activation.** Every activation awaits both
   `$initializeExtensionStorage(true, …)` and `(false, …)`, so allowing only the
   workspace scope would still have left every extension dead. Reading the main-thread
   side showed the id is a raw storage key. The answer is the per-tab partition
   ([ADR](../adr/20261106-tab-state-partition.md)), not an id check.
2. **Every extension calls trusted commands:** `_setContext` ×129, and
   `_executeHoverProvider` / `_executeCompletionItemProvider`. The deferred-laundering
   residual kept every command at deny. The user approved these three as the residual's
   only **leaf exceptions**:
   - each handler is shown never to reach `ICommandService`;
   - each is argument-validated, because a leaf can still leak or spoof host state on its
     own. The provider commands open a model on the caller's URI, and `file:` is the host
     disk; `_setContext` writes the window's global context.

   `check_residuals` now enforces exactly that. The residual stays open; fixing it properly
   is a follow-up after landing.

The trace also exposed a scanner gap. `registerModelAndPositionCommand` was not a
recognised registration form, so `_executeHoverProvider` and 15 siblings were missing from
the inventory. The generator now recognises it; the policy was not bent to fit.

## What this landing allows (the core set), and what it defers
Two independent review passes drafted a classification for every traced method and its
lifecycle companions: 100 methods, kept unenforced in
[`rpc-filter/policy/drafts/`](../../rpc-filter/policy/drafts/20261106-ordinary-session.json).
The user chose a **core set** for this landing. It is what ordinary activation and basic
editing need, each entry with a simple validator and a host probe:

| Method | Validator | Host probe |
|---|---|---|
| `MainThreadDocuments.$tryOpenDocument` | `tabDocumentOpen`: a canonical `vscode-remote` URI of this tab only | `host-doc-open-userdata` |
| `MainThreadTextEditors.$tryShowTextDocument` | `tabDocumentShow`: same URI rule, known options only | `host-doc-show-userdata` |
| `MainThreadWorkspace.$startFileSearch` | `tabFileSearch`: folder and every nested URI the tab's, whitelisted options | `host-file-search-nested-uri` |
| `MainThreadFileSystem.$ensureActivation` | `tabFileSystemActivation`: `vscode-remote` only | `host-fs-activation-scheme` |
| `MainThreadWindow.$getInitialState` | (allow: focus and activity booleans only) | none needed |
| `MainThreadCommands.$unregisterCommand` | `tabCommandUnregistration`: ids this tab registered | none needed |
| `MainThreadLanguageFeatures.$unregister` | (allow: per-host handle map) | none needed |

A tab's extension host turns `file:` into `vscode-remote` on the way out, so a probe that
means the host names `vscode-userdata:`, which resolves against the host profile. The
harness seeds a canary in the profile's settings.

**Deferred: every registration whose results reach trusted UI.** Hover and completion
registration were in the first core-set proposal. They came out because the filter screens
requests, not responses. A tab-provided completion item's `command` runs through the global
`ICommandService` when the user accepts the suggestion, and hover markdown can carry
`command:` links and remote images. Code lens, code actions, the status bar, tree items,
SCM, decorations and notifications with actions all have the same flaw. The follow-up is one
structural response-side control, not a sanitiser per feature:
- any command id or `command:` link that came from a `seclab+` host's data executes through
  the filter's command verdict (taint by origin);
- trusted markdown and remote images from tab data are neutralised in the trusted renderer.

Its proof includes a completion item and a hover link carrying
`workbench.action.terminal.newLocal`, reproduced on the unfiltered baseline and denied
after the fix. In order of usefulness, the follow-up covers SCM and git, then output, the
status bar and tree views, then decorations. Decorations need an egress-safe icon-URI
validator, because the trusted renderer must not fetch tab-chosen remote URLs.

**DTO sweep of the core set (before landing).** No core-set method or its result carries a
command, markdown, or a URI that the trusted side later fetches or executes:
- `$tryOpenDocument` and `$startFileSearch` return URIs to the tab.
- `$tryShowTextDocument` returns an editor id.
- `$ensureActivation` and the two unregisters return nothing.
- `$getInitialState` returns two booleans.

Among what was already allowed, one path needs recording. A tab-registered command
invoked by trusted UI returns the tab's value to that caller. Menus and keybindings
ignore it; a trusted caller that acts on another extension's command result is not known.
It is listed as an open question for the response-side control.

**The positive control's provider steps.** With hover and completion registration denied,
the benign extension's providers never reach the UI. Its `languageFeature` and
`completionProvider` steps only check that the `_execute*` commands return a result, which
needs no registration. Whether they pass is measured on the build, not assumed: if they
fail, they are recorded as expected failures for this reason.

## Findings beyond this increment
- **Every text model in the window is synced to the tab's extension host** (no scheme check
  in `shouldSynchronizeModel`). Opening user settings or an output channel in a tab window
  hands it to the tab. It is a Win → Ext push the filter cannot see; open on main
  ([RPC-LOCKDOWN §7](../RPC-LOCKDOWN.md#7-residual-risks) item 10).
- `$setEnvironmentVariableCollection` merges tab mutators into **local** terminals, except
  `PATH` (`BASH_ENV`, `NODE_OPTIONS`, `DYLD_INSERT_LIBRARIES`): host code execution.
  `$registerUriHandler` takes the extension id as its only authorisation and can take over
  the auth extensions' OAuth redirects. `$registerQuickFixProvider` returns fixes that run
  arbitrary command ids. All three stay denied, and the drafts record why.

## Named argument validators
`rpc-filter/patch-src/seclabArgValidators.ts`, shipped in 0005, holds every validator. It
has **no imports**: whatever needs the workbench (URI revival, the command registry,
context keys) is injected. So `test/containment/arg-validators.test.ts` tests the shipped
code, not a model of it.
- A policy entry names its validator (`"validator"`). An unknown name, a throw, or a
  constraint with no validator denies.
- `check_validators` fails on:
  - an undefined validator;
  - a validator nothing names;
  - a validator on a verdict that never runs it;
  - a constrained command with no validator.
- Each validator is proved by injection: the check is deleted from a copy of the source, and
  the dangerous shape must then pass (8 defects).

Revival needed a hardening found while writing them. `URI.revive` takes `external` and
`fsPath` from the wire as the URI's cached string and path, and on macOS a missing `_sep`
satisfies the marker check. So a URI with this tab's scheme and authority could carry a
host `fsPath`. Every tab URI is now compared with a canonical rebuild, and refused if its
cached forms differ.

## Review rounds 10 and 11
Round 10 ([record](../security-reviews/20261106-rpc-core-landing-v2.md)) found two blockers in
the core set and the log:
- **`tabFileSearch` let a pattern choose the search roots.** With `expandPatterns`,
  `QueryBuilder` derives the roots from the include pattern and ignores the folder argument.
  In a window without a folder, those roots are host paths. The validator now refuses
  `expandPatterns`, and separately refuses any pattern segment `parseSearchPaths` would
  make a root.
- **The decision log could be made to write invalid JSON.** It cut the serialized line,
  and `reason` was tab-chosen. Fields are now bounded before serialization, and an
  over-budget line is replaced by a well-formed record rather than cut.
  `decision-line.test.ts` runs the shipped formatter, not a model.

Each regression test fails against the round's source. Also from round 10:
- A named constraint is now discharged only by its validator, or by the positional URI rule
  where an entry declares that rule is its whole constraint (`$readFile`, `$writeFile`).
- `$getCommands`, documented as constrained but always enforced as a deny, is now `deny`.
- A stale liveness exemption is gone, and the gate fails on the next one.

Round 11 re-reviewed the fixes: **no high or critical**. Its two lows are applied:
- the trusted-id list adds `vscode-testresolver.newWindowWithError`;
- the `$startFileSearch` constraint text states the new rule.

## First patched run (9ce593a, run 42651935290): two validators stricter than their producers
The benign control activated on the patched containment build. The storage rewrites,
command registration, `$getInitialState` and `$startFileSearch` were all permitted as
designed. But **`benign.json` was never written**, so the control fails. The decision log
and the tab's extension host log gave two causes, both in validators that refused shapes
upstream's own extension host sends:
- **`$ensureActivation('file')`.** The extension host calls it before *every*
  `workspace.fs` operation on a scheme it serves itself (`extHostFileSystemConsumer.ts`
  L43-L47). In a remote extension host the tab's files are `file:`, so `file` arrives on
  every call. The validator allowed only `vscode-remote`, so every `workspace.fs` call failed,
  including the control's own evidence write. Now `file` and `vscode-remote`. This is not
  quite a no-op, as review round 12 found: `activateProvider` fires the activation event
  before its existing-provider check. So `file` triggers `onFileSystem:file` activation in
  the trusted UI host. No UI-side extension declares that event (the Tab Manager, upstream
  built-ins at `a717861c`), and it is recorded as a residual.
- **`$tryOpenDocument(uri, <the uri>)`.** `openTextDocument(uri)` sets
  `options = options ?? uriOrFileNameOrOptions` (`extHost.api.impl.ts` L1305), so argument 1
  is the URI itself. The reachable main-side branch reads only `encoding` from it. The
  validator required an object whose only key was `encoding`; it now accepts any plain
  object and checks `encoding`.

Unit tests for both shapes fail against the built validators (40/43) and pass now. The other
core-set validators were checked against their upstream producers and agree:
`showTextDocument` options, the activation-error triple, storage, secrets and the command
calls.

The lesson matches the plumbing EDR: **a validator must be tested against what the
producer sends, not what the protocol type says.** The protocol declares
`options?: { encoding?: string }`, and the producer sends a URI.

The baseline half of the new probes ran on main `bc85925`, in two runs; the first exposed
the probe bugs below. The escapes reproduce:
- the Tab Manager's state, read and written by a claimed id;
- a secret written under the Tab Manager's id;
- host settings read through open, show, completion and hover;
- userdata read and write;
- a core context key flipped;
- `PWNED-newlocal`.

It also exposed probe bugs, now fixed:
- `vscode-userdata:` needs the profile's absolute path;
- `clipboard-read` read the user's real clipboard without the opt-in;
- `check-evidence` read `benign.where` instead of `results.where`.

`host-file-search-nested-uri` did not reproduce, so it no longer counts as evidence.

## First run with the matching REH (816c15c, run 42717470458): patch 0006 bricked the REH
The 9ce593a run above used an sbx tab, whose template REH comes from `.work/out`, an older
build and not the commit under test. A test variant ships its REH only as the OCI image
(`seclab-tab-oci:test-<variant>`, [EDR](20261106-test-build-variants.md)). So
`check-evidence.ts prepare` now takes `SECLAB_TAB_IMAGE` (only `seclab-tab[-oci]:<tag>`),
passes it to tabd as `--image`, and writes `seclab.tabs.image` so the editor's Tab Manager
uses the same image.

With the patched client and the patched REH from the same commit, **no extension host
started at all**. The decision log held only the install line. The renderer reported
`Cannot provide init data for remote extension host!`, and every management call (remote
environment, profiles, marketplace, MCP environment) was rejected by the REH with
`Unsupported operation`. The cause is patch 0006, not the RPC filter:
- Round 9 alert 5 made `ChannelServer` refuse a `seclab+` context while no guard is
  installed, so the desktop is fail-closed regardless of bundle evaluation order.
- The REH serves the trusted client over the same class, with the client's
  `RemoteAgentConnectionContext` (`remoteAuthority: 'seclab+<tab>'`) as the context, and
  nothing in the REH installs a guard. So the REH refused everything.
- Every earlier patched run paired the patched client with an REH that lacked 0006, which
  is why it never showed.

The fix is a second hunk in 0006. `createServer` (`remoteExtensionHostAgentServer.ts`)
installs an explicit allow-all guard as its first statement. The REH runs inside the tab, so
there is nothing there to guard. The desktop default is unchanged. Desktop may not reach
`src/vs/server/` (`patches/unreachable.json`), and `reach.json` pins 0006 to the `server`
target, so the hunk must ship in the REH. `channel-guard.test.ts` models the REH case (no
guard: refused; opt-out: served). It also checks the shipped patch: one allow-all, imported,
first statement of `createServer`, and none in `ipc.ts`. That check fails on the unfixed
patch, and its injected-defect controls (no hunk, the call moved after upstream code, a
denying guard) are caught. The runtime proof is the benign control on a rebuilt app.

The rule this adds: **a patched client is proved only against the REH from the same
commit.** A run whose tab image or template comes from another build proves nothing about
the patches under test.

## Three-condition proof (6cc61c4, run 42866683703): passed
The containment test build of `6cc61c4` is the patched app with 0006's REH opt-out. Its tab
ran on `seclab-tab-oci:test-containment`, the same commit's REH, behind its broker, with
the beacon up. There were two runs, 2026-11-10. Between them the only change was to two probes'
aim (below), and both gave the same result. Conditions were read from structured fields:
evidence from the tab's own view (`docker exec … cat`), the decision log and marker on the host,
and `check-evidence.ts` was not used:
- **(a) The fixture ran.** `benign.json`: `activated: true`, where
  `{remoteName: seclab, seclabTab: 1}`. 12 of its 13 steps passed (command round trip,
  workspace read/write/open, configuration, output channel, workspace and global state, hover
  and completion invocation, contributed command, status bar item, its own secret). The one
  failure is `findFiles`, timed out after 20 s: the tab's file search provider registration
  is denied, so the search service waits forever. The user accepted it as a known loss for
  this landing (RPC-LOCKDOWN §7.1). The search providers are the first follow-up.
  `rogue-extension-host.json` shows the rogue extension reached its first line in the tab.
- **(b) Trusted-side denial.** `seclabRpcFilter.log` holds `deny` lines for
  `cmd:workbench.action.terminal.newLocal` and `cmd:workbench.action.terminal.sendSequence`.
  It also denies `cmd:workbench.action.restartExtensionHost`, but that probe has no baseline
  yet, so it is not part of the proof.
- **(c) No host marker.** `.work/containment-editor/PWNED-newlocal`, unique to the
  newLocal chain, is absent on the host, and so is every other `PWNED*` marker.

The baseline half is main `90fc1fa` and `bc85925`, where the same chain wrote
`PWNED-newlocal`.

`check-probes.ts patched`, with the run's beacon log, deny lines, profile and tab id, gives
112 of 125. No probe expected to be denied succeeded. The succeeded set is
`secret-write-own` (a partitioned rewrite), `secret-read-cross-tab` and the three
Tab Manager claim probes, and each one's patched predicate holds: the claimed id addresses only the
tab's own partition. The 13 failures:
- **harness gaps already recorded:**
  - the beacon port does not reach the tab, so `launder-open-external` refuses to run;
  - the fake auth provider is not seeded (`auth-get-session`);
  - the clipboard is opt-in (`clipboard-read` refused, as it must);
  - three unimplemented AI probes have no coverage key;
  - this runner does not run `as-external-uri`, `open-external-silent` or `webview-egress`;
- **the four REH probes for the held patches 0030/0031**, proved separately.

The first run exposed two probes that were contained at a gate other than the one they
name:
- `host-fs-activation-scheme` stat'ed a scheme the extension host does not serve, which goes
  to `$stat` rather than `$ensureActivation`. It now serves the scheme from an in-memory
  provider first.
- `host-doc-show-userdata` is refused at `$tryOpenDocument`, the open probe's gate, because
  `showTextDocument(uri)` opens the document first. Corroborating it there let the sibling's
  denial stand in for it (review round 14). It now shows the tab's own file and rewrites the
  outgoing `$tryShowTextDocument` resource, which reaches its own gate.

The new `host-restart-extension-host` probe (Fork build review OOO-2) runs once, last.
Without the filter it restarts the extension host running it, so the attempt and that host's
pid are recorded first. The call is bounded at 20 s. `succeeded` needs a different extension
host process to settle the attempt in the same window session within 60 s; a missing write is
not enough (review rounds 14 and 15).
Every install, uninstall and restart-style command id is `deny` in coverage. Its baseline half
needs a main build at or after `3d22b25` and is still to run.

Both runs tore down clean, and the background watcher saw no focus change. A third run on
the same build (run 42866683703), after the round-14 fixes, gave the same three conditions
and the same 13 known failures. The show probe was denied at `$tryShowTextDocument` itself
(`scheme vscode-userdata is not this tab's file system`), and the restart probe recorded its
host's pid and was denied.

## Liveness evidence
What ran these fixtures, for the liveness register (`build/liveness/register.json`):
- **`fixture:test/containment/fixtures/trace-workspace`:** `test/containment/rpc-trace.ts` on
  main `bc85925` (run 42288509087), sbx, 2026-11-06. The workspace was materialised, the
  built-in language extensions activated on its files, and the trace gave 2,677 requests
  (69 distinct). Teardown was clean.
- **`fixture:test/containment/benign-extension`:** the same trace run, where it activated
  with every step passing. Then `check-evidence.ts` with `SECLAB_BENIGN_ONLY=1` on the
  containment build of `9ce593a` (run 42651935290), sbx, 2026-11-09. There it activated and
  was stopped by the two over-strict validators above. Then the containment build of `6cc61c4`
  (run 42866683703), OCI with that build's own REH, 2026-11-10: activated, 12 of 13 steps,
  in all three proof runs.

## Rules this keeps
- The trace is what a session **needs**, not what is safe. Every method on it gets its own
  classification from its upstream body; anything not classified stays denied.
- The raw trace is sensitive and is never kept. Only names, counts and command ids are
  recorded.
