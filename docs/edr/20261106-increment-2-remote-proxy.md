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

The user chose option 1 from the round 6 list (2026-11-06): force the proxy **on**, which is
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
conclusion for that one key, which was then held for the user's decision.

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
