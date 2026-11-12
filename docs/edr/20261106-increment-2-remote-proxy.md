# Increment 2 (0017): what `workbench.browser.enableRemoteProxy` actually does, measured from the source

- **Status:** accepted
- **Date:** 2026-11-06
- **Deciders:** anticomputer (increment 2 of the agentic plan); coordinator (same bar as 0015: patch-build, U-vs-G runtime proof, a review round)
- **Related:** [implementation plan](../plans/agentic-implementation.md) §"Increment 2", [design §3.5](../plans/secure-agentic-experiences.md), [AHP gate EDR](20261106-agentic-probe-runner.md)

## Context
The plan requires, before 0017 is written: "`enableRemoteProxy`'s effect must first be shown
on U with host evidence; the measurement to settle is which host-side fetch it enables."
Read first, at `a717861c`, because the setting's direction is not what its name suggests and
getting it backwards would force the *less* contained behaviour.

## Findings
1. **The setting is tab-writable and defaults to ON in our builds.** It is registered once at
   `ConfigurationScope.WINDOW` with `default: product.quality !== 'stable'`
   ([browserRemoteFeatures.ts#L124-L136](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/browserView/electron-browser/features/browserRemoteFeatures.ts#L124-L136)).
   Our builds are not `stable`, so **ON is the default**, and `WINDOW` scope is inside
   `REMOTE_MACHINE_SCOPES`, so a tab can write it through the REH's remote user settings.
2. **ON routes a browser view's traffic through the tab; OFF uses the host network.** That is
   the opposite of what the name suggests to a reader expecting "proxy = more exposure".
   `_isNetworkProxyEnabled` gates whether a network is resolved at all
   ([browserViewWorkbenchService.ts#L246-L250](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/browserView/electron-browser/browserViewWorkbenchService.ts#L246-L250)),
   and the "network" is the remote authority, i.e. the tab. With a network, the local
   extension host opens the page's destination sockets **on the agent host connection**
   ([mainThreadBrowserTunnelProxy.ts#L48-L66](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/api/browser/mainThreadBrowserTunnelProxy.ts#L48-L66)),
   so the fetch happens in the tab, behind the tab's broker.
3. **The two open paths differ, and only one falls back to the host network.** This is the
   finding that decides 0017's value.
   - **Embedded pages (what a canvas uses) refuse rather than fall back.**
     `createExternalBrowserView` resolves the owner's network with the *private*
     `_resolveNetwork`, "resolved even while proxying is disabled, rather than silently load
     from the local network", and then throws `The required remote network is unavailable.`
     when the proxy is off
     ([#L474-L491](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/browserView/electron-browser/browserViewWorkbenchService.ts#L474-L491)).
     So for tab-driven pages, **OFF means the view never opens**.
   - **A user-opened browser view does fall back.** `_resolveSessionRequest` uses the public
     `resolveNetwork`, which returns `undefined` when the proxy is off
     ([#L586-L598](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/browserView/electron-browser/browserViewWorkbenchService.ts#L586-L598)),
     and the view then loads on the **host** network, with a visible network indicator.
     Upstream says as much: "Browsers using global storage always use the local network."

## Decision (settled; two earlier versions are kept below)
**0017 fixes four settings in a `seclab+` window: `chat.automations.enabled` and
`chat.automations.cloud.enabled` to `false`, `workbench.browser.enableRemoteProxy` to
`true`, and `workbench.browser.dataStorage` to `ephemeral`.**

Decided by the project owner (2026-11-06), option 1 from the round 6 list: force the proxy **on**, which is
the opposite of what the plan's increment 2 first said, and lock the storage scope so a tab
cannot undo it. The reasoning and the measurement that got there are in the two superseded
sections below and in "What round 6 found".

**The two browser keys are one control, and neither works without the other.**
- `enableRemoteProxy: true` keeps every browser view's traffic on the **tab's** network, on
  all three open paths: embedded pages, user-opened views, and the browser tools'
  model-chosen URL.
- `dataStorage: ephemeral` is what stops a tab taking the network away again.
  `toBrowserViewSessionOptions` returns `{ scope }` with **no network** for `global`
  ([browserView.ts#L517-L521](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/browserView/common/browserView.ts#L517-L521)),
  so a tab writing `global` would move its page onto the host network and into the host's
  shared persistent cookie jar. The setting is `WINDOW` scope
  ([browserDataStorageFeatures.ts#L160-L182](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/browserView/electron-browser/features/browserDataStorageFeatures.ts#L160-L182)),
  so a tab can write it. `ephemeral` keeps the network and gives each view a session cleaned
  up when it closes; `workspace` would also keep the network but persists, so `ephemeral` is
  the one chosen.

**What "on the tab's network" means, and what it does not** (security review round 7). The
destination socket is a raw TCP connect from inside the sbx
(`extHostBrowserTunnelProxy` → `connectRemoteAgentTunnel`), and a raw socket does not honour
the tab's `HTTP_PROXY`/`HTTPS_PROXY` variables, which is the only way tab egress reaches the
broker. The tab's fence allows exactly one network resource, the broker port, and denies
everything else. So:
- a **tab-local** destination (the §3.5 case, a service on the tab's own `:3000`) is reached
  directly;
- an **external** destination is **denied by the fence**, not brokered.

The containment is real but it comes from the fence; this traffic is not brokered and does
not appear in the broker's audit. Saying otherwise would matter later: if a tab's fence is
ever widened by a grant, browser-view traffic would leave the tab unmediated and unlogged,
and anyone reading a claim of "behind the broker" would not look for it.

This implements the **traffic direction** of the design's "Host view of a tab service" row
(§3.5), but **not its gate**. That row says the setting is "pinned for `seclab+` so only the
grant opens it"; pinning it to `true` unconditionally means every browser view in a tab
window is tunnel-capable with no grant anywhere on the path, including one opened by
`open_page` on a model-chosen URL with `allowAutoConfirm: true`. The grant remains
unimplemented and is a later increment. 0015's denial of agent-host-chosen canvas URLs stays
load-bearing: it is what prevents unattended host-Chromium page loads chosen by the agent
host, and this pin does not substitute for it.

### What the proof must show, on U and on F
1. the browser tool's **model-chosen URL** goes through the tab's broker, not the host
   network;
2. a **tab-written `dataStorage: global`** does not move the page onto the host network.

Both need host-side evidence, as always: the host beacon must be hit on the unfixed build and
not on the fixed one, and the tab's broker must show the request on the fixed one. The second
is what makes the pair a control rather than two independent settings.

### Superseded: the round 6 decision
**0017 ships the two automations keys and NOT `workbench.browser.enableRemoteProxy`.**
Round 6 found a third open path the original measurement had missed, and it reversed the
conclusion for that one key, which was then held for a decision by the project owner.

### The original decision, superseded for `enableRemoteProxy`
**0017 fixes the value to `false` in `seclab+` windows, as the plan says.** Finding 3 is why
that is right rather than backwards: the path a hostile tab or agent host can drive is the
embedded one, and for that path `false` is a refusal, not a fallback to the host network.

**The host-side effect to measure on U is therefore the embedded-page open**, not a fetch
that `false` would enable. Concretely, with the setting ON (our default) an agent-host-chosen
page can be loaded by **host Chromium**; the measurable host evidence is the beacon being hit
for a URL the hostile agent host chose. 0015 already denies `CanvasState.url` inbound, so
this probe must be run with the gate's canvas rule in mind: on U it is the browser view that
produces the hit, and on G there are two independent reasons for silence. The probe has to
distinguish them, or it is another absence-proves-nothing result.

### Superseded consequences (they argue the `false` case)
- The one genuine trade-off, recorded rather than hidden: in a `seclab+` window a **user**
  who opens a browser view gets the host network, because `false` disables the proxy for
  that path too. The design's end state (design §3.5, "Host view of a tab service") is the
  opposite: traffic through the tab's broker, opened by an explicit grant. 0017 is the safe
  default; the grant is a later increment, and until it exists a tab window's user-opened
  browser is host-network browsing with an indicator, exactly as upstream behaves today with
  the setting off.
- `chat.automations.enabled` and `chat.automations.cloud.enabled` are unregistered where an
  editor window reads them, so they have no registration to fight and a forced read is the
  only option for those two.


## What round 6 found: a third path, and why `enableRemoteProxy` is held back
The measurement above enumerated two open paths and concluded that the one an attacker can
drive refuses rather than falls back. There is a **third**, and it falls back.

**The browser tools resolve the network with the public resolver.** `openBrowserTool.invoke`
calls `resolveNetwork({ type: 'agent', … })`
([openBrowserTool.ts#L161](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/browserView/electron-browser/tools/openBrowserTool.ts#L161)),
and the public `resolveNetwork` returns `undefined` whenever the proxy is off
([browserViewWorkbenchService.ts#L246-L250](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/browserView/electron-browser/browserViewWorkbenchService.ts#L246-L250)).
The page is then created with no network and loads on the **host** network. `navigateBrowserTool`
uses the same resolver. The URL on this path is model-chosen, so hostile workspace content or
a hostile agent host influences it, and the tool declares `allowAutoConfirm: true`.

**The caveat that would have voided this does not apply.** `getNetworkStatus` returns
`proxySupported: true` unconditionally for the window's own authority -- "The window's remote
connection always supports proxying"
([#L275-L280](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/browserView/electron-browser/browserViewWorkbenchService.ts#L275-L280)).
So for a `seclab+` tab window, ON really does proxy this path through the tab, and forcing
`false` really does move it to the host network.

**So forcing `false` would make this path worse than leaving the setting alone**, which is the
one outcome the increment must not produce. The two automations keys are unaffected and ship
now. `enableRemoteProxy` is held back rather than guessed, with three candidate resolutions,
in the order they should be considered:
1. **Force `true`.** It matches the design's own end state for this row (§3.5: traffic to the
   tab's broker, "with no fallback to the host network") and closes all three paths at once,
   including the user-opened one that `false` leaves on the host network. The question to
   settle is what a tab can do with a browser view it can cause to open, given 0015 already
   denies agent-host-chosen canvas URLs inbound.
2. **Force `false` and separately refuse the tool path**, so the fallback cannot happen. More
   code, and it leaves the user-opened path on the host network.
3. **Leave it tab-writable** and rely on the broker. Weakest: a tab could then turn it off to
   move its own traffic onto the host network.

This needs the user's or the coordinator's decision, because it changes an increment the plan
already fixed in writing. It is recorded here rather than resolved quietly.


## Consequences of the settled decision (`true` + `ephemeral`)
- **No persistent browser storage in a tab window.** `ephemeral` gives each view a session
  cleaned up when it closes, so pages in a tab window always start logged out, lose state on
  close, and the Clear Storage actions have nothing to clear. `workspace` would also keep the
  network and would preserve logins, but it persists tab-influenced data on host disk;
  `ephemeral` is the security choice and this is its cost, recorded rather than discovered.
- **External browsing in a tab window fails** rather than being brokered, because the fence
  denies everything but the broker port (see above). A tab-local service works, which is the
  case §3.5 is about.
- **The grant is still missing.** Every browser view in a tab window is tunnel-capable; the
  design's gate is not implemented by this increment.
- **A restored browser editor could have bypassed the pin, and no longer can** (round 7). A
  saved session carries its scope, so a view stored while a tab could still choose `global`
  came back with `global` and no network, i.e. on the host network and the host's shared
  cookie jar. 0017 drops a saved session request in a `seclab+` window and rebuilds it under
  the fixed setting.
- **The upstream invariant the pin rests on is now held in CI.** That `global` drops the
  network and `ephemeral` keeps it is upstream's behaviour, not ours; it is asserted over the
  patched tree by `patches/sole-consumer.json`, which `patch-build` already runs, because the
  unit-test container has no upstream checkout.

## Liveness evidence for the probe's build hook
The repo-wide liveness gate ([EDR](20261109-liveness-gate.md)) requires evidence that a test
hook actually ran, not just that it was built.

- **`hook:agentic-browser/browser-drive`:** ran in a real `seclab+` tab window on macOS, on
  the U baseline build of 2026-11-09, and drove a browser view exactly as
  `openBrowserTool._openNewPage` would. Its own lines in the window log, in two separate
  runs:
  - `[SECLAB_TEST_ONLY:browser-drive-hook] opening http://127.0.0.1:<beacon>/browser-probe-<nonce> network=seclab+t-q6e62bfkumso…`
    followed by `failed: ERR_EMPTY_RESPONSE (-324)`, i.e. the page was really created and
    really attempted its fetch;
  - `[SECLAB_TEST_ONLY:browser-drive-hook] ready=no: the tab's remote settings never arrived;
    this run is inconclusive`, from the later build, which is the readiness gate refusing to
    measure (see below).

  The hook is applied only by `build-macos.yml` dispatched with
  `test_variant=agentic-browser`; the pinned run in the register is the build that carries
  it. `check-release` refuses any artifact containing its marker.

### What those two runs already established, before the full U/F verdict
1. **The probe measured too early, and would have reported a false "contained".** The first
   run resolved the **tab's** network on a build with **no 0017**, while the tab's hostile
   settings were present and correct inside the tab. The hook had run before the window's
   remote configuration layer loaded, so it read the registered defaults. An unfixed build
   looked contained. The fix is a positive readiness signal, not a longer sleep: the tab
   writes a neutral key and the hook waits until it can read that value back, logging
   `ready=yes`; otherwise it logs `ready=no` and the run is reported **inconclusive**.
2. **A readiness sentinel has to be a scope a tab can write.** The first one was
   `workbench.browser.maxHistoryEntries`, which is `APPLICATION` -- exactly the scope
   `REMOTE_MACHINE_SCOPES` withholds from a tab -- so it could never arrive and every run was
   inconclusive. That is the gate working: an inconclusive run was reported as inconclusive,
   never as contained. The sentinel is now `workbench.browser.newTabPlacement`, `WINDOW`
   scope like the two keys under test, and fixed by no patch.
3. **Two harness defects, both found by running it.** `process.exit(ok && teardownGate(base) ? 0 : 1)`
   short-circuits, so a failing verdict skipped teardown and left an editor running, which is
   the hard rule teardown exists for; and the arming directory was created after the host
   snapshot, so teardown reported `~/` as changed.

**The U-vs-F verdict is below, and it holds.**


## MEASURED: the U-vs-F proof (2026-11-10), and what it does NOT show
Security review round 8 cut this section down. The first version claimed four things; two are
measured, two were not, and the review was right. What follows is only what the runs support.

Both runs on the sbx driver, each window launched in the background through `test/window.ts`
on a build at or after the Spaces focus fix, each ended by the teardown gate. The tab is
hostile in both: before the window starts it writes `enableRemoteProxy: false` and
`dataStorage: global` into the REH's remote user settings, the layer a tab controls.

### Proven: `enableRemoteProxy` is fixed, and it decides where the page is fetched
| | U (main + variant, `18c2843`, **no 0017**) | F (branch, `bab99d0`, **with 0017**) |
|---|---|---|
| tab's remote layer applied before measuring | `ready=yes` | `ready=yes` |
| network the service resolved for the open call | **`none`** (the host) | **`seclab+t-co3ocz…`** (the tab) |
| host beacon | **2 hits** | 0 hits |

On U the host beacon recorded the fetch, with the editor's own Chromium user agent:

```
GET /browser-probe-<run-nonce>
ua: … seclab-vscode-TEST-agentic-browser/1.145.0 Chrome/150 Electron/43 …
GET /favicon.ico
```

The page ran in **host** Chromium on the **host** network, so `127.0.0.1` was the host's
loopback and the beacon saw it. On F the same probe with the same tab settings resolved the
tab's authority, so `127.0.0.1` was the *tab's* loopback and the host beacon could not see it.
The builds differ only by 0017 (same upstream SHA, same variant, same hook hash; the only
src-affecting delta is the patch and its module), so the difference is attributable to 0017.

`ready=yes` matters: upstream's registered default for the sentinel is `activeGroup`, so
`sideGroup` can only have come from the tab's remote layer, which proves the tab's settings
were in force when the measurement happened.

### NOT proven, and why
1. **The `dataStorage` half is not exercised at all.** The hook opens with an explicit
   `session: { scope: Agent, … }`, and upstream's `_resolveSessionRequest` returns a request
   that already carries a scope **without reading** `workbench.browser.dataStorage`. So that
   setting was never consulted on either build, and the tab could have omitted `global`
   without changing a single number above. The F check "the tab's `dataStorage: global` did
   not take the network away" is also implied by the check above it and cannot fail
   independently. The pin is still justified by the source reading in the Decision; it is
   simply not what these runs measured.
2. **The restored-editor case measured nothing.** The harness reads every `.log` in the
   profile and takes the last `opening` line, so the restore phase re-read the first launch's
   lines. The retained artifacts show it: `verdict-first.json` and `verdict-restore.json`
   report `hookLines: 3` for both phases, i.e. the relaunched window contributed none. Three
   lines is exactly one window's sequence. The round 7 restore gap therefore remains
   **unverified at runtime**. A fresh hook-driven open would not exercise it anyway: the
   restore path is about a *persisted* session request, and the hook supplies its own.
3. **`ERR_EMPTY_RESPONSE` is not evidence of the fence.** From inside the tab, `127.0.0.1` is
   the guest's own loopback and never reaches the fence; a fence refusal would also be
   `ERR_CONNECTION_REFUSED`. The earlier wording inferred a mechanism the run did not measure.
4. **F has no positive control that its beacon was listening.** The beacon is spawned
   detached with no readiness probe and no end-of-run self-hit, so a beacon that failed to
   bind would produce F's evidence exactly. U's beacon worked, but that is a different
   process, port and run.
5. **The probe target is outside the hook's reviewed validity envelope.** The hook's own
   review states it measures the browser tool faithfully only against a **non-localhost**
   target, because it omits `rewriteRemoteLocalhostUrl`. The probe uses loopback, so this is a
   measurement of `resolveNetwork`, not of the whole tool path.

### Consequence
Increment 2's `enableRemoteProxy` claim is proven at runtime, in the shipped shape, with
host-side evidence and a working negative control. The `dataStorage` pin, the restored-editor
gap and the full tool path are **not**, and are not claimed to be. Closing them needs a hook
that opens without an explicit session, a restore phase that reads only lines the relaunched
window produced, a beacon liveness control, and a non-loopback target.

### Neither run took focus, and neither left anything
Both report `OK  the editor never took focus from the user during the run` on the fixed build,
and both teardowns are clean. One host artefact does survive: `~/.seclab-test/`, whose parent
is pre-created before the snapshot so changes beneath it are invisible to the "nothing outside
the run directory changed" check; the arming file under it is removed only on the restore
phase, so a run stopped after phase 1 leaves it armed until its ten-minute expiry.

## The corrected proof (design, 2026-11-10)
Round 8 did not find a defect in 0017; it found that the proof could not see two of the
three things it claimed. Rather than re-run the same harness, each gap is closed by a change
that makes the corresponding check **able to fail**, and that property is itself tested.

1. **Attribution by byte offset, not by "the last line".** Each phase records the size of
   every `.log` in the profile before its launch and reads only what was appended past those
   offsets. A phase whose window produced nothing therefore reads as nothing and fails,
   instead of silently inheriting the previous launch's evidence.
2. **One key per run.** `--probe proxy` writes `enableRemoteProxy: false` with
   `dataStorage: ephemeral`; `--probe storage` writes `dataStorage: global` with
   `enableRemoteProxy: true`. Each writes the hostile value for one key and the contained
   value for the other, so exactly one check decides the run. Writing both at once is what
   let the storage result ride along on the proxy result: with the proxy off, the network is
   dropped before the storage scope is consulted at all. `enableRemoteProxy` is written
   explicitly in both, never left at its default, because that default is
   `product.quality !== 'stable'` and would otherwise make the storage probe depend on how
   the variant happened to be branded.
3. **The hook no longer supplies a session.** Passing `{ scope: Agent }` is precisely what
   stopped `workbench.browser.dataStorage` from ever being read, because upstream's
   `_resolveSessionRequest` returns a request that already carries a scope without consulting
   the configured storage. (See the round 9 correction below: this makes the hook diverge
   from the agent tool, which supplies a scope of its own, so the storage probe measures the
   non-agent create path.) A second, authoritative
   log line in `_resolveViewSession` records the scope and network upstream actually settled
   on, after trust, proxy availability and storage isolation have had their say. The old
   `opening` line recorded only what was asked for.
4. **The storage result is read off the SCOPE, not the network.** A global scope keeps a
   network value but hands the view the host's shared session;
   `toBrowserViewSessionOptions` returns `{ scope }` with no network for `Global`, and
   upstream documents it as "Browsers using global storage always use the local network". So
   the network alone cannot distinguish the two keys, and the scope can.
5. **The restore phase is cross-build, on one profile.** The unconditional log line fires for
   views the hook never opened, including a browser editor restored from persisted state,
   which is the only way to observe that path at runtime. Launch 1 runs **U**, which obeys the
   tab and persists `global`; the relaunch runs **F** against byte-for-byte the same state. So
   the only difference between the two observations is the patch. Running F's own first launch
   would persist `ephemeral`, and then F's restore could not fail however broken 0017 was. The
   phase also asserts it really saw `requestedScope=global`, so a run where U failed to persist
   the hostile state is reported as inconclusive rather than as containment.
6. **Two listeners, and exactly one may be hit.** The probe URL is loopback, and `127.0.0.1`
   means a different machine depending on who fetches it: the host's loopback for a page on
   the host network, the guest's for a page inside the tab. The first attempt at removing
   that ambiguity bound the beacon to a private host address, which cannot work here: the
   address binds, but nothing on the host can then reach it, and getting past that would mean
   changing the user's host network settings. The ambiguity is instead **resolved** by running
   a second listener on the same port INSIDE the tab, and requiring exactly one of the two to
   have seen the probe:

   | host beacon | tab listener | reading |
   |---|---|---|
   | hit | quiet | the page was fetched on the HOST network |
   | quiet | hit | the page was fetched INSIDE the tab |
   | both, or neither | | inconclusive, and the run says so |

   This is strictly stronger than what it replaced, because it removes absence-based
   reasoning from the proof altogether: F's result no longer rests on "the host beacon saw
   nothing", which a dead listener or a page that never loaded satisfies equally well, but on
   the tab's own listener having seen the fetch. Both listeners are liveness-probed from
   their own side after the measurement, and each records only requests carrying this run's
   nonce.

   Ordering matters and was got wrong first: `prepare` stops the tab so the editor can take
   it over, which kills anything running inside it, so a listener started there is dead by
   the time the page is fetched. The hook is therefore armed by a separate `arm` step, after
   the window is up and both listeners are confirmed live. The first real run caught this,
   because the tab-side liveness check can fail.

7. **The verdict is a pure function with a defect-injection test.** `browserProbeChecks` in
   `test/agentic/browser/verdict.ts` is what the runner calls, and
   `verdict.test.ts` injects each defect 0017 is meant to prevent, one at a time, asserting
   that **exactly one** check goes red: the proxy force removed, the storage scrub removed,
   the persisted-request drop removed, a page escaping to the host, a dead beacon, a silent
   launch, and a restore phase with no hostile saved state. This is the direct answer to
   round 8: a check that cannot fail is not evidence, and the only way to show one can fail
   is to make it fail on purpose.

The arming file is now removed on every `check`, not only the last, so a run stopped after
the first phase no longer leaves it armed until its expiry.

**Status: the corrected harness is written and its own tests pass; the U and F variants have
not yet been rebuilt against it, so the increment 2 claims above remain as round 8 left
them.** Landing waits on that run.

### Correction (security review round 9): what the storage probe measures
Round 9 found that §5.3 above, and the hook comment, were wrong to say the hook "opens the
way the tool does". Upstream's `openBrowserTool._openNewPage` spreads
`getAgentBrowserViewCreationDefaults(...)`, which **does** supply
`session: { scope: Agent, … }`, and `_resolveSessionRequest` returns a request with a scope
verbatim. So the agent tool path never reads `workbench.browser.dataStorage` at all.

Round 8 observed that correctly; the fix inverted its meaning, by changing the hook to
diverge from the tool instead of recording what the tool does. The consequence for the
record:

- the `--probe storage` run measures the **non-agent** create path, which is what a restored
  editor and a user-opened view take, not the browser tool;
- the `dataStorage` pin is still worth having for exactly those paths, and the restore phase
  is its real demonstration;
- for the agent tool specifically, the containment that matters is `enableRemoteProxy`, which
  is the probe that was already proven.

The divergence pushes toward over-stating the vulnerability rather than toward a false
"contained", so it does not weaken the F result; but it is outside the faithfulness envelope
recorded in the variant's own review, which described the inlined agent creation defaults.
That document is corrected in the same change.

### What the first real run of the corrected harness found (2026-11-10)
Two defects, both caught by checks added in this round, before any claim was made:

1. **The tab-side listener was dead during the measurement.** It was started in `prepare`,
   which then stops the tab so the editor can take it over; that kills everything inside.
   The host beacon saw the fetch and the tab listener saw nothing, which would have read as a
   clean U result, but the tab-side liveness check failed and the run was refused. Arming now
   happens in a separate `arm` step, after both listeners answer.
2. **The `requestedNetwork` discriminator was unsatisfiable on U.** Round 9 finding 6
   correctly said `network=none` is not specific to the setting, but the fix required
   `requestedNetwork=seclab+<tab>` on the same launch — and `resolveNetwork` returns
   `undefined` at the proxy gate itself, so with the proxy off there is no requested network
   to see. Another check that could not pass, found only by running it. The discriminator is
   now the **effective setting value as the window read it**, which the hook logs
   (`proxySetting=`, `storageSetting=`): that is the thing 0017 overrides, so it ties cause
   to effect directly. The F checks require both the override and its effect.

## Probe-safety incident: a leaked beacon (2026-11-10)
**What happened.** A run's beacon was left running on the host after the run ended, and after
this session had reported the host clean. It was found by the coordinator, not by our tooling,
and it was bound to a non-loopback address, so it was reachable beyond this machine.

**Why it escaped.** The beacon was spawned and only afterwards recorded in `run.json`. In
between sat the new liveness probe, and when that probe failed the runner exited on the
failure path — before `writeManifest`. The listener therefore existed with no record of it
anywhere, and both `teardown.ts` and `clean-host` ask the manifest what to look for, so both
reported the host clean while it was still running. `clean-host` compounded it by only ever
looking for editor and tabd processes; no helper listener was in its vocabulary at all.

**Why it mattered more than usual.** The non-loopback bind, added for the round 8 finding
about loopback ambiguity, meant the leak was not confined to this machine's loopback. That
design is gone: the ambiguity is now resolved with a second listener inside the tab, and
`AGENTS.md` forbids binding a test oracle to anything but loopback.

**Fixes, each proven by injecting the fault first.**
1. The mark is written to the manifest **before** the helper is spawned, so no window exists
   in which a live helper is unrecorded; and the liveness failure path now runs the teardown
   gate before it exits.
2. `teardownGate` gained a **manifest-independent** net: `strayHelpers()` scans the process
   table for helpers running from this worktree's absolute path, which is ours by
   construction and can never claim another session's process. A teardown with any such
   survivor fails. The first version of it spared our own descendants, which made the
   regression test pass while the real leak would still have escaped; only ourselves and our
   ancestors are spared now.
3. `clean-host` learned the `helper process` kind: helpers from this worktree are removed,
   and the same script from another worktree is reported for review, never removed.
4. `teardown.test.ts` injects a leaked beacon with no manifest entry, asserts it is found,
   kills it and asserts it is no longer reported, so the check cannot silently become
   always-true.

**The general lesson,** which is the same one this whole increment keeps teaching: a safety
check that depends on bookkeeping written by the thing being checked is not a safety check.
Teardown's manifest is a list of what a run *meant* to start; the process table is what it
*did* start.

## MEASURED: the two-sided U-vs-F proof (2026-11-10, second attempt)
Builds: **U** = `b7bda15` (main's base + the variant, no 0017), **F** = `6f4cc62` (the same
plus 0017). Same upstream `a717861`, same hook `c33b733a43`; the binaries stamp their own
repo SHA and every run checks it, so the lines are known to come from the build claimed. Each
run ends with the teardown gate, and every window was launched in the background and never
took focus.

Each run writes the hostile value for **one** key and the contained value for the other, so
exactly one check decides it. Every verdict requires **exactly one** of the two listeners to
have seen the page, so no result rests on silence.

| run | tab wrote | resolved | host beacon | tab listener | verdict |
|---|---|---|---|---|---|
| U proxy | `enableRemoteProxy: false` | `network=none` | **1 hit** | 0 | **7/7 VULNERABLE** |
| U storage | `dataStorage: global` (proxy **on**) | `scope=global` | **1 hit** | 0 | **7/7 VULNERABLE** |
| F proxy | `enableRemoteProxy: false` | `network=seclab+<tab>` | 0 | **1 hit** | **7/7 CONTAINED** |
| F storage | `dataStorage: global` (proxy **on**) | `scope=ephemeral`, `network=seclab+<tab>` | 0 | **1 hit** | **7/7 CONTAINED** |

Both halves of increment 2 are now proven at runtime, independently of each other:

- **`enableRemoteProxy`.** On U the tab's `false` was honoured and the page was fetched on the
  HOST. On F the window read `true` despite the tab writing `false`, and the page was fetched
  INSIDE THE TAB. Both directions are positive evidence from the listener on that side.
- **`dataStorage`.** This is the half round 8 found was never exercised. With the proxy left
  ON, so it cannot be the cause, the tab's `global` alone moved the page onto the host on U;
  on F the window read `ephemeral` and the page stayed in the tab. The hook no longer supplies
  a session, which is what lets the setting be read at all.

### The restore path: proven at resolution, NOT at the network
The cross-build restore phase ran on one profile: launch 1 on **U**, which honoured the tab
and persisted the hostile scope, then a relaunch on **F** reading byte-for-byte the same
state. It shows:

- `savedScope=global` — the restored view really did carry the hostile persisted scope, logged
  before 0017 can discard it, so this is not an assumption;
- `scope=ephemeral`, `network=seclab+<tab>` — 0017 rebuilt it under the fixed setting.

That is the security-relevant difference, and it is a clean differential. But **neither
listener saw a fetch** in that phase, so the run is reported as inconclusive at the network
level and must not be read as containment.

**Correction (security review round 10): the cause recorded here first was wrong.** It was
attributed to a missing arming gate on the restore path. The real cause was that the harness
destroyed the evidence: the `listen` watcher respawned the tab listener every 1.5 seconds
unconditionally, and the listener truncated its log on start, so every probe line the live
instance recorded was erased within a second or two. The restore phase's network check could
therefore never pass, whatever the build did — the same shape of defect as rounds 8 and 9, in
the plumbing rather than the verdict. The `listen` loop now probes before starting anything
and starts a listener only when nothing answers; the listener appends and never truncates, and
a duplicate exits on `EADDRINUSE` without touching the log. The beacon logs are also read from
BYTE offsets with the same shrink-is-an-error rule the window logs use, because `slice()` on a
truncated log silently returned no hits, and "that side saw nothing" is half of a containment
verdict.

A missing restore-path gate remains a real second cause, since a restored editor is loaded by
the editor itself with no point at which the listener can be guaranteed up first. The restore
phase therefore still needs a re-run under the corrected harness before any network-level
claim is made for it.

### Defects this round's own checks caught before any claim was made
Each would have produced a false "contained" or a false "vulnerable":

1. The tab-side listener was dead during the first measurement, because it was started in
   `prepare`, which stops the tab so the editor can take it over. Caught by its liveness check.
2. Round 9's `requestedNetwork` discriminator was unsatisfiable on U: `resolveNetwork` returns
   `undefined` at the proxy gate itself. Replaced by the effective setting value the window
   read, which the hook logs.
3. The beacon hit counts were not phase-scoped, so the restore phase inherited the first
   launch's host hit and reported an escape on a build that had contained the page. Both
   listener logs are now read from a per-phase offset, as the window log already was.
4. Stamping the repo SHA into the hook *record* broke `fetch` verification, which compares
   that record against the local checkout exactly; it goes into product.json at apply time.

### The restore path, re-run under the corrected harness (2026-11-10)
With the log truncation fixed, the restore phase was run again. It still shows:

- `savedScope=global` — the restored view carried the hostile persisted scope, logged before
  0017 can discard it;
- `scope=ephemeral`, `network=seclab+<tab>` — 0017 rebuilt it under the fixed setting;
- **and still no fetch on either side.**

The remaining cause is now measured rather than guessed, and it is structural. The relaunch
is what creates the tab, and the tab's listener dies with the old tab, so there is an
unavoidable window at startup in which no listener exists inside the tab. The restored editor
loads its page inside that window. The listener's own heartbeats show it: the gap across the
relaunch exceeds the continuity threshold, which is why the phase correctly refuses to
conclude anything from the silence.

**So the restore path is proven at resolution and cannot be proven at the network by this
design.** The resolution evidence is a genuine differential on byte-for-byte identical
persisted state, and it is the layer 0017 acts on — the scope decides whether the view gets
the host's shared session or the tab's. But it is not a network observation, and this record
does not claim one. Closing it needs the page load gated on the listener, which means a hook
that defers a restored view until an arming file appears: a larger change to the test build
than this increment needs, and one that would itself have to be reviewed for faithfulness.

The other four runs are unaffected: each gates its page load on arming, which happens only
once both listeners answer, and each shows continuous heartbeats across its measurement.
