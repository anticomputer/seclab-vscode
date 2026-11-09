# Telling the user when a setting is withheld from a tab

- **Status:** accepted
- **Date:** 2026-11-09
- **Deciders:** coordinator (scope and the three requirements: no forgery, tab-chosen key text, agree the shape first); Document sync leak session (patch 0036, the shared classifier); tab-observability session
- **Related:** [ADR detection notifications](../adr/20261106-detection-notifications.md), [ADR no real secret in a tab](../adr/20261104-no-real-secret-in-a-tab.md), [security review](../security-reviews/20261104-tab-observability.md) round 13

## Context
Patch 0036 (Document sync leak session) filters the configuration snapshot a tab's
extension host receives. When it withholds a host user setting that looks like a
credential, the user should be told, so they move it to the broker. The renderer reports
this by calling a command the Tab Manager registers, `seclab.tabs.settingsWithheld`.

A command handler can't tell who called it: `MainThreadCommands.$executeCommand` passes no
origin, so a tab extension can call the same command. Today it can call any command id; once
the RPC filter lands, its `seclab.*` deny prefix and capability taint refuse it. The
requirement is not to rely on that alone.

## Decision
1. **The shape** (agreed with the Document sync leak session). The renderer calls the local
   extension host's `seclab.tabs.settingsWithheld` directly, not through `ICommandService`
   (see "Shadowing" under Consequences), with
   `{ v: "seclabSettingsWithheld:v1", authority: "seclab+<tab>", settings: [{ key, reason }] }`:
   - `reason` is `credential-name` or `secret-value`;
   - at most 64 settings per call, keys of at most 256 characters;
   - each key once per window, never a value;
   - only top-level keys withheld from the host's `userLocal` layer. Policy, defaults,
     local-workspace and `[lang]`-section withholdings are withheld silently (a gap in
     0036's EDR).
2. **The payload is a hint; every claim is checked against host state**
   (`tabd/src/obs/withheld.ts`):
   - the tab is the window's own `remoteAuthority`. A payload naming any other authority
     is ignored as a whole;
   - the key must have a value in the host's own user settings, as the window's local
     extension host sees it (`inspect(key).globalLocalValue`). 0036 filters only non-local
     extension hosts, so this layer is unfiltered here, and the tab's remote layer and
     workspace settings don't count;
   - re-running 0036's own classifier, `withholdReason(key, hostValue)`, must give the
     claimed reason. The classifier is shared code (`build/secret-rules/src`, synced into
     0036 with a drift check), bundled into the Tab Manager by symlink as `tabd/src` is;
   - the build must carry 0036: the workbench bundle contains `seclabSettingsWithheld:v1`
     (0036 passes it in every payload, so it can't be tree-shaken). Without 0036 nothing was
     withheld, so every call is ignored.

   A forged call can therefore only produce a notice that is true (that key really is in
   the user's settings, and 0036 really withholds it). It also can't use up the rate limit
   with keys that weren't withheld. The command returns nothing.
3. **One path for the notice.** Each verified key, once per window, goes to tabd as a trusted
   `tab.events.report` event: source `config-filter` (allowed only class `config.withheld`),
   priority `warning`, fixed summary, `detail: { key, reason }`. tabd tags `detail.key`
   untrusted and caps it at 256 characters. `config-filter` has its own rate bucket, so a
   flood of RPC-filter denials can't drop it. The notification comes back through the event
   stream, like every other alert (ADR detection notifications).
4. **The notification** (non-modal, never takes focus):
   - text: "Tab “acme-app”: A setting that looked like a credential was withheld from this
     tab. Setting: `seclabProbe.apiToken` (its name looks like a credential). Your settings
     are copied into each tab, but a credential must never enter one, so the tab's
     extensions don't get this setting. Move the credential to the broker, which gives the
     tab a placeholder instead.";
   - the key is shown as code: control, bidi, zero-width and line-separator characters are
     removed, markdown brackets, URI schemes and codicon syntax are broken, and it is capped
     at 120 characters;
   - actions: **Open Settings** (`workbench.action.openSettingsJson` with
     `revealSetting: { key }`, the host user settings.json where the key was verified),
     **Open Activity**, **Dismiss**. No Stop Tab: the tab did nothing wrong;
   - rate: coalesced per tab (one notification per 5 minutes, then one "N more"), within
     the global per-minute budget.
5. **Forged calls are refused: what is proven now.** Unit tests (`tabd/test/obs.test.ts`,
   "settings withheld (0036)") run the handler (`WithheldReceiver`, the command's whole
   logic with the editor API injected) against a real tabd event hub:
   - the in-tab forger's five calls, verbatim (a key not in host settings, a host key that
     isn't a credential, another tab's authority, bidi and markdown text, a 64-key flood),
     report nothing, return nothing, and are each logged as refused;
   - in a build without 0036 or without its classifier, every call is ignored;
   - the real claim produces one trusted event, a replay produces none, and a claim tabd
     dropped under the rate limit is retried once.
6. **Probe in a real editor** (`test/observability/withheld-probe.ts` with the in-tab
   forger `test/observability/withheld-forger`; lands with its first run, which records the
   liveness evidence). It puts a canary `seclabProbe.apiToken: seclabcanary_…` in an
   isolated profile, and installs the forger, armed by the run, in the tab. The forger makes
   the five calls above and records whether the canary is visible in the tab (yes or no,
   never the value). The probe asserts one notification naming the key, exactly one trusted
   `config.withheld` event, no forged key anywhere, and the value in no notification or
   event. With `--forged-only`, on a build without 0036, it asserts that each forged call
   reached the Tab Manager's handler (its log) and produced nothing. Not yet run: editor
   launches are on hold until the Space-switch focus fix lands.

## Alternatives considered
- **Trust the command, rely on the RPC filter:** a single control, and absent until the
  filter lands.
- **A per-window decision log** (as for the AHP gate and RPC filter): before the filter, a
  tab can write those logs through `MainThreadLogger`, so forwarding is held until the
  filter ships. Verification works now and doesn't depend on it.
- **Ignore the payload and recompute the withheld set at window open:** the same
  classifier and the same data would give the same answer, but the notice would no longer
  follow what 0036 actually did.

## Consequences
- The notice works before the RPC filter lands, and after it the filter is a second control.
- **Shadowing (review round 13, CW-1).** `$registerCommand` has no collision check, and the
  newest registration of a command id wins. If 0036 called through `ICommandService`, a tab
  extension registering `seclab.tabs.settingsWithheld` would receive the call: the notice
  would be suppressed, and the tab would see key names (never values). 0036 doesn't use that
  route. When the window's LocalProcess extension host connects, its `MainThreadConfiguration`
  registers that host's `ExtHostCommands` proxy as the sink, and the tab host's instance calls
  `$executeContributedCommand` on it. That resolves only among the local host's own commands,
  so a shadow in the tab's host is never consulted. Reports queue (at most 16) until the
  local host connects; a restarted local host replaces the sink. The first report is made
  while the tab host's initial snapshot is built, before any tab extension activates. The
  tab host never sees the payload. The RPC filter's `$registerCommand` collision rule is a
  second control.
- **Before the filter**, a tab can write host user settings
  (`$updateConfigurationOption`, default target userLocal). It could plant a
  credential-looking key and then trigger a true notice about it. The filter's deny on
  that method closes this.
- A shared classifier means the Tab Manager ships 0036's rule table (about 86 KB).
- Until `build/secret-rules` is on main, the Tab Manager registers the command with no
  classifier and refuses every claim.
