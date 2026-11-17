# A tab can't take over a host scheme: provider registrations refused (DOCSYNC-R7)

- **Status:** accepted
- **Date:** 2026-11-16
- **Deciders:** coordinator, 2026-11-16 (record DOCSYNC-R7 as closed by patch 0005, with a runtime probe whose refusals appear in the filter's decision log). Document-sync session: probe and record.
- **Related:** [document sync provenance](20261109-document-sync-provenance.md) (0035); [RPC lockdown](../RPC-LOCKDOWN.md) §7 item 10

## Context
An extension can register a filesystem provider or a text-content provider for a URI scheme
([extHostFileSystem.ts#L132-L180](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/api/common/extHostFileSystem.ts#L132-L180)).
If a tab's provider served a scheme the window also uses for host data (`vscode-userdata`,
`output`, …), host-side features could read the tab's content as if it were the host's, or route
host reads through the tab. Patch 0035 stops that for the document sync with per-model provenance;
the register's DOCSYNC-R7 covered every other channel.

## Decision
DOCSYNC-R7 is closed by the RPC filter (patch 0005). A tab's
`MainThreadFileSystem.$registerFileSystemProvider` and
`MainThreadDocumentContentProviders.$registerTextContentProvider` have no policy entry, so they take
the filter's default verdict, deny: no provider a tab registers serves any scheme in the window.
`test/squat/probe.ts` is the regression test.

Should either registration ever be allowed (for example so a tab extension can offer its own
virtual files), the allow must be limited to schemes no host feature uses, and 0035's per-model
rule and 0038's editor-tab rule already judge such a provider's content per model.

## Evidence
- **`fixture:test/squat/probe-extension`:** `test/squat/probe.ts drive` on main `6589051b` (run
  43929230851), sbx tab, headless driver, 2026-11-16. The tab registered a filesystem provider for
  `vscode-userdata` and a text-content provider for `output`, each serving a generated marker. The
  window's decision log shows both registrations refused; the window then opened the user's
  settings with their real content, never called either provider, and never showed the marker. No
  focus steal; the teardown gate passed.
- **Correction (PR #33 review, SQ-2):** that run's window-log step never ran. The settings modal
  was still open, and the step had no positive control, so nothing noticed. The probe now closes
  the modal first and requires an output editor for the window log (`output:` `rendererLog`) with
  content. With the final probe, three runs on main `6589051b`, 2026-11-17, pass every assertion,
  with the window log open and no provider call. (The settings control now polls for the content
  while the modal is open; read once, it failed one earlier run on timing.)
- **Hostile workspace (PR #33 review, SQ-4/SQ-5):** the extension also makes the harness's stop
  file a symlink to a host sentinel and deletes its arming file. The harness no longer writes into
  or reads back from the tab's workspace once the tab runs. Two runs on main `6589051b`,
  2026-11-17, pass every assertion. On sbx the share doesn't carry the tab's symlink to the host:
  the link exists in the tab right after creation and is gone on both sides by the end of the run.
- **SQ-3 injection:** the probe extension adds unvalidated `note` fields carrying the marker inside
  its report's `registered` and `calls`. With the harness's projection reverted to copy those
  objects whole, the SQ-3 assertion fails; with the projection, it passes.
- A build without the filter can't be driven by the headless driver (it predates the background
  bootstrap policy), so the probe has no failing baseline run. Its two refusal assertions fail
  closed: with no decision log, or a log without the refusals, they fail.
