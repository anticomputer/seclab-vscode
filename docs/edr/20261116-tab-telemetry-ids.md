# Host telemetry ids stay out of tabs: telemetry off, checked at build and release

- **Status:** accepted
- **Date:** 2026-11-16
- **Deciders:** coordinator, 2026-11-16 (no core patch while telemetry is off; enforce it on the shipped artefact with a release check and its self-test; keep the probe as the runtime regression test; the drafted patch becomes the plan if telemetry is ever enabled). Document-sync session: measurement and implementation.
- **Related:** [document sync provenance](20261109-document-sync-provenance.md) (0035); [tab configuration snapshot](20261112-tab-configuration-snapshot.md) (0036); [RPC lockdown](../RPC-LOCKDOWN.md) §7 item 10; [no real secret in a tab](../adr/20261104-no-real-secret-in-a-tab.md)

## Context
The 0035 work listed the extension host's init data as a window-to-tab push that may carry host
data (register entry DOCSYNC-R4). `RemoteExtensionHost` copies the window's telemetry identifiers
into every remote host's init data: session, machine, SQM and device ids, the first session date
and `msftInternal`
([remoteExtensionHost.ts#L250-L257](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/services/extensions/common/remoteExtensionHost.ts#L250-L257)).
A tab extension reads them as `vscode.env.machineId`, `sessionId` and `devDeviceId`
([extHost.api.impl.ts#L426-L429](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/api/common/extHost.api.impl.ts#L426-L429)).
With the host's real ids, every tab would carry the same stable host identifier, so extensions in
different tabs (and their back ends) could correlate one user's tabs and machine.

Whether the real ids flow depends on the product. In a built app the workbench uses its telemetry
service only if `productService.enableTelemetry` is set
([telemetryUtils.ts#L96-L102](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/telemetry/common/telemetryUtils.ts#L96-L102),
[telemetryService.ts#L47-L72](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/services/telemetry/electron-browser/telemetryService.ts#L47-L72)).
Otherwise it is `NullTelemetryService`, whose ids are fixed placeholders such as
`someValue.machineId`
([telemetryUtils.ts#L29-L35](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/telemetry/common/telemetryUtils.ts#L29-L35)).
Our product sets `enableTelemetry: false` (`build/product/overrides.json`), but nothing enforced
it: an override change, or an upstream product default, would have let the real ids reach every
tab without any test failing.

## Measurement
`test/telemetryid/probe.ts` seeds generated machine, SQM and device ids into the isolated
profile's `User/globalStorage/storage.json` (where the editor keeps them) before a background
launch. A probe extension in the tab reports only the SHA-256 and the shape (letters and digits
masked) of `vscode.env.machineId` and `sessionId`. On main's attested build (`607873da`, run
43264609543), the tab's machineId had the placeholder's shape `xxxxxxxxx.xxxxxxxxx` and was not
the seeded value. So the leak is latent, not live: it opens only if telemetry is turned on.

## Decision
No core patch. Telemetry stays off, and that is enforced where the artefact is made and where it
is checked:
1. **Build:** `build/product/product.jq` gets an invariant: `prepare.sh` fails if the merged
   product doesn't set `enableTelemetry` to `false`.
2. **Release:** `build/check-release.sh` requires every app `product.json` (desktop app and REH,
   vendored copies under `node_modules` excluded as for the RPC stamp) to name `enableTelemetry`
   exactly once in the file, on a top-level line `"enableTelemetry": false` (the build writes the
   file tab-indented, so top level is one tab), with no `\u` escape anywhere in the file (an escaped
   duplicate key would beat the text match; jq writes none). Anything else fails closed: `true`,
   missing, twice, only inside a nested object, an escaped duplicate, or a file not tab-indented.
   The self-test (run by `ci-unit`) injects each of those.
3. **Runtime:** `test/telemetryid/probe.ts` is the regression test: no id the tab can read
   (`machineId`, `sessionId`, and `devDeviceId` where the proposal is enabled) may be any seeded
   host id. `sqmId` reaches an extension only in telemetry common properties, which are not sent
   while telemetry is off.

DOCSYNC-R4 is closed as fixed, with the release check's self-test as its CI-run test and the probe
as its runtime test.

A dev build uses a real telemetry service whatever the product says
([telemetryUtils.ts#L98-L100](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/telemetry/common/telemetryUtils.ts#L98-L100)).
"Dev" is decided at run time, not by the build: `isBuilt` is false when the window's environment
has `VSCODE_DEV`
([environmentService.ts#L231](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/environment/common/environmentService.ts#L231)),
and a window takes the launching CLI's environment
([windowsMainService.ts#L1569](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/windows/electron-main/windowsMainService.ts#L1569)).
So a host process that opens a tab window with `VSCODE_DEV=1` set gives that tab the real ids.
Only the host can set it; a tab can't. Neither check here sees it. It is recorded as a residual
(review TEL-2) and reported to the coordinator for a decision on stripping `VSCODE_DEV` from the
shipped app.

## Alternatives considered
- **Patch the init data now (the appendix).** Give each tab ids derived from its own authority and
  drop `msftInternal`. Correct, but it changes core code to protect placeholders while telemetry is
  off. Kept as the plan for the day telemetry is enabled.
- **Probe only.** It runs on macOS with sbx, not in CI, so a product change could ship before
  anyone ran it. The release check closes that gap.
- **Check only the override file.** The product is merged from upstream's `product.json` and our
  overrides; a check on the shipped file covers both.

## Consequences
- Enabling telemetry now fails the build and the release check. Turning it on means landing the
  appendix patch first (or an equivalent), with its own review and proof.
- The probe stays a manual, macOS-only test, recorded in the liveness register.
- `msftInternal` and `firstSessionDate` are placeholders too while telemetry is off.

## Evidence
- **`fixture:test/telemetryid/probe-extension`:** `test/telemetryid/probe.ts` on main `607873da`
  (run 43264609543), sbx tab, background launch through `test/window.ts`, 2026-11-16: the seeded
  ids never reached the tab (`DOCSYNC-R4 the tab's machineId is not the host's` and the all-ids
  assertion passed; `devDeviceId` was not readable, the proposal being off); the tab read the
  product placeholder; no focus steal; the teardown gate passed.
- `build/check-release.sh --self-test`, on GNU and BusyBox `sh`: every injected defect fails on
  the telemetry check's own message, and the clean product passes. A mutation that drops the
  check's failure is caught by the first telemetry case.
- `product.jq` with `enableTelemetry` set to `true` in the overrides stops on the invariant; the
  real overrides pass.
- `check-release` on the attested desktop app and the REH from main reports nothing about
  telemetry; neither file has a `\u` escape.
- Review: [20261116-tab-telemetry-ids](../security-reviews/20261116-tab-telemetry-ids.md), no high
  or critical finding.

## Appendix: the plan if telemetry is ever enabled
A core patch to `remoteExtensionHost.ts` (33 lines, typechecked against the pinned tree on
2026-11-16; not in `patches/`). For a `seclab+` authority, each id becomes a SHA-1 over a label,
the authority and the host value, written into the host value's own shape, so formats like a
64-hex machine id or a UUID still parse. Ids are stable per tab, distinct across tabs and not
reversible to the host's. `msftInternal` (a fact about the user's machine) is dropped. Before it
ships: the probe's assertion that the tab's id is not the host's must fail on a telemetry-on build
without the patch and pass with it, two tabs must see different ids, and a review round.

```diff
--- a/src/vs/workbench/services/extensions/common/remoteExtensionHost.ts
+++ b/src/vs/workbench/services/extensions/common/remoteExtensionHost.ts
@@ -4,6 +4,7 @@
  *--------------------------------------------------------------------------------------------*/
 
 import { VSBuffer } from '../../../../base/common/buffer.js';
+import { StringSHA1 } from '../../../../base/common/hash.js';
 import { Emitter, Event } from '../../../../base/common/event.js';
 import { Disposable } from '../../../../base/common/lifecycle.js';
 import { Schemas } from '../../../../base/common/network.js';
@@ -45,6 +46,26 @@
 	getInitData(): Promise<IRemoteExtensionHostInitData>;
 }
 
+/**
+ * seclab: the identifier a `seclab+<tab>` extension host sees in place of the host's
+ * telemetry `value` (machine, SQM, device and session ids). SHA-1 over a label, the tab authority and the host value, written into the
+ * host value's own shape (letters and digits replaced, separators kept), so formats such as a
+ * 64-hex machine id or a UUID still parse. Other authorities get the value unchanged.
+ */
+function seclabTabTelemetryId(authority: string, label: string, value: string): string {
+	if (!authority.startsWith('seclab+')) {
+		return value;
+	}
+	let stream = '';
+	for (let i = 0; stream.length < value.length; i++) {
+		const sha = new StringSHA1();
+		sha.update(`seclab-tab-telemetry\0${label}\0${authority}\0${i}\0${value}`);
+		stream += sha.digest();
+	}
+	let n = 0;
+	return value.replace(/[0-9a-zA-Z]/g, c => c !== c.toLowerCase() ? stream[n++].toUpperCase() : stream[n++]);
+}
+
 export class RemoteExtensionHost extends Disposable implements IExtensionHost {
 
 	public readonly pid = null;
@@ -248,12 +269,15 @@
 			},
 			extensions: this.extensions.toSnapshot(),
 			telemetryInfo: {
-				sessionId: this._telemetryService.sessionId,
-				machineId: this._telemetryService.machineId,
-				sqmId: this._telemetryService.sqmId,
-				devDeviceId: this._telemetryService.devDeviceId ?? this._telemetryService.machineId,
+				// seclab: a tab gets identifiers derived from its own identity, never the host's:
+				// stable per tab, distinct across tabs, and not reversible to the host's.
+				sessionId: seclabTabTelemetryId(this._initDataProvider.remoteAuthority, 'sessionId', this._telemetryService.sessionId),
+				machineId: seclabTabTelemetryId(this._initDataProvider.remoteAuthority, 'machineId', this._telemetryService.machineId),
+				sqmId: this._telemetryService.sqmId && seclabTabTelemetryId(this._initDataProvider.remoteAuthority, 'sqmId', this._telemetryService.sqmId),
+				devDeviceId: seclabTabTelemetryId(this._initDataProvider.remoteAuthority, 'devDeviceId', this._telemetryService.devDeviceId ?? this._telemetryService.machineId),
 				firstSessionDate: this._telemetryService.firstSessionDate,
-				msftInternal: this._telemetryService.msftInternal
+				// A host fact about the user (their machine's domain), not the tab's.
+				msftInternal: this._initDataProvider.remoteAuthority.startsWith('seclab+') ? undefined : this._telemetryService.msftInternal
 			},
 			remoteExtensionTips: this._productService.remoteExtensionTips,
 			virtualWorkspaceExtensionTips: this._productService.virtualWorkspaceExtensionTips,
```
