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

## Decision
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

## Consequences
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
