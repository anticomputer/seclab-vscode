# Security review: probe harnesses and the tab's workspace (follow-up to PR #24, #33, #37)

- **Date:** 2026-11-17
- **Scope:** the configsync, docsync, edtabs, nbsync and telemetryid probe harnesses on main, for
  the patterns the pull-request reviews found in the edtabs, squat and wsdata harnesses
  (EDT-15 to EDT-18, SQ-4 to SQ-8, WSD-1 to WSD-4).
- **Reviewer:** the document-sync session, applying those findings. Finding IDs `PH-n`.
- **Threat model:** a rogue extension owns the tab's extension host and its workspace, symlinks
  included. A harness must not write through a path the running tab controls, must reach its
  teardown gate whatever the tab leaves, and must leave nothing behind.
- **Related:** [squat probe review](20261117-scheme-squatting-probe.md),
  [workspace-data probe review](20261117-workspace-data-probe.md),
  [editor-tab review](20261116-editor-tab-provenance.md).
- **Prompt injection:** none found.

## Findings
| # | Sev | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| PH-1 | Low | harness | configsync, docsync, nbsync and telemetryid copied the probe's VSIX into the tab's workspace from the host after the tab was running (as SQ-7). | fixed | The VSIX is staged before the tab is claimed. Nothing in the tab runs before the probe is installed, so no run plants a symlink. | none |
| PH-2 | Low | harness | The same four read the arm back from the tab's workspace unguarded (as SQ-5): a tab that deleted or replaced the arming file ended the check before its teardown gate. | fixed | The harness keeps the arm in its own run directory outside the workspace, read guarded. | none |
| PH-3 | Low | harness | Their `sbx exec` calls had no timeout (as SQ-6): a FIFO at the report path stalled the check forever. | fixed | Every `sbx exec` has a hard timeout and SIGKILL (install: 5 minutes); a timed-out read is no data. | none |
| PH-4 | Low | harness | Their report checks ran regexes on tab-controlled values before checking their types (as EDT-18): a crafted object threw before the teardown gate. | fixed | Every value is type-checked before a regex, and the real report is checked inside a guard. Each check first feeds its validator a hostile value that passes every earlier condition; without the type check telemetryid's fails. | test/telemetryid/probe.ts "the report check rejects a malformed tab value without throwing" |
| PH-5 | Low | harness | None of the five listed its generated directories in the run manifest (as SQ-8, WSD-4), so the teardown gate left the workspace (with the arming file and staged VSIX), the packaged VSIX and the host fixtures in `.work`. | fixed | Each manifest lists them; the teardown gate removes and checks them. | test/containment/teardown.ts "generated fixture workspaces removed from the host" |

Runs on main `6589051b` (edtabs on `ca643062`), 2026-11-17: nbsync, telemetryid, configsync and
edtabs pass every assertion, with nothing left in `.work` beyond the run record. docsync passes the
new assertions; its other failures are EDT-11 (its probe steps are refused on filtered builds),
open independently of this change.
