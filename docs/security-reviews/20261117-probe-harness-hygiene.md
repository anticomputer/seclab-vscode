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
  [editor-tab review](20261116-editor-tab-provenance.md); the workspace-data probe's review is in
  PR #37.
- **Prompt injection:** none found.

## Findings
| # | Sev | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| PH-1 | Low | harness | configsync, docsync, nbsync and telemetryid copied the probe's VSIX into the tab's workspace from the host after the tab was running (as SQ-7). | fixed | The VSIX is staged before the tab is claimed. Nothing in the tab runs before the probe is installed, so no run plants a symlink. | none |
| PH-2 | Low | harness | The same four read the arm back from the tab's workspace unguarded (as SQ-5): a tab that deleted or replaced the arming file ended the check before its teardown gate. | fixed | The harness keeps the arm in its own run directory outside the workspace, read guarded. | none |
| PH-3 | Low | harness | Their `sbx exec` calls had no timeout (as SQ-6): a FIFO at the report path stalled the check forever. | fixed | Every `sbx exec` has a hard timeout and SIGKILL (install: 5 minutes); a timed-out read is no data. | none |
| PH-4 | Low | harness | Their report checks ran regexes on tab-controlled values before checking their types (as EDT-18): a crafted object threw before the teardown gate. | fixed | Every value is type-checked before a regex, and the real report is checked inside a guard. Each check first feeds its validator a hostile value that passes every earlier condition; without the type check telemetryid's fails. | test/telemetryid/probe.ts "the report schema check rejects a malformed tab value without throwing" |
| PH-5 | Low | harness | None of the five listed its generated directories in the run manifest (as SQ-8, WSD-4), so the teardown gate left the workspace (with the arming file and staged VSIX), the packaged VSIX and the host fixtures in `.work`. | fixed | Each manifest lists them; the teardown gate removes and checks them. | test/containment/teardown.ts "generated fixture workspaces removed from the host" |

Runs on main `6589051b` (edtabs on `ca643062`), 2026-11-17: nbsync, telemetryid, configsync and
edtabs pass every assertion, with nothing left in `.work` beyond the run record. docsync passes the
new assertions; its other failures are EDT-11 (its probe steps are refused on filtered builds),
open independently of this change.

## Copilot review (PR #45)
Five threads, each checked against the code and fixed before merge.

| # | Sev | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| PH-6 | Low | harness | The bounded `sbx exec` still returned stdout produced before a timeout or a failure, so a FIFO could emit a whole report and then stall, and the report was accepted (PH-3's no-data contract, as `tabExec` holds it). | fixed | Every probe's `inTab` (and wsdata's and edtabs') returns no stdout unless the command succeeded. | none |
| PH-7 | Low | harness | With the host arm file missing or malformed, `armed` was undefined, so a report with no `arm` passed the run-provenance check in configsync, nbsync and telemetryid. | fixed | The check requires a host arm before comparing it. | none |
| PH-8 | Info | harness | In `check --measure`, configsync and docsync judge only assertions whose names match `schema` or `focus`, so the new self-test was ignored there. | fixed | It is named as a schema assertion in every probe. | none |
| PH-9 | Low | harness | docsync's summary converted the tab's `hijack` counters and strings, which the check didn't validate: `{ "toString": null }` there threw before the teardown gate. | fixed | The check validates all four counters and both strings; the self-test feeds an otherwise valid report with one poisoned counter, and fails without the check. | test/docsync/probe.ts "the report schema check rejects a malformed tab value without throwing" |
| PH-10 | Info | harness | docsync's hostile hit had a malformed scheme, which the scheme check rejected before the hash check ran, so removing the hash's type check left the self-test passing. | fixed | The self-test feeds a malformed scheme with a valid hash and a valid scheme with a malformed hash; removing either type check fails it. | test/docsync/probe.ts "the report schema check rejects a malformed tab value without throwing" |

Each self-test was also run offline (`check` with no recorded run) with one guard removed at a time:
configsync, nbsync and docsync (hash, scheme, hijack) all fail it; with the guards in, they pass.
Live runs after these fixes on main `6589051b`: nbsync, telemetryid and configsync pass every assertion.

## Copilot review (PR #45, second pass)

| # | Sev | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| PH-11 | Low | harness | PH-6's no-data rule also covered docsync's tab-log collection, so a failed or timed-out log read erased a canary already emitted, and the absence checks passed on missing evidence. | fixed | The logs come from their own bounded call that keeps what it read, and a control requires the collection to complete. A docsync run on main `6589051b` passes it. | test/docsync/probe.ts "control: the tab-side logs were collected (no timeout or failure)" |

## Copilot review (PR #45, third pass)

| # | Sev | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| PH-12 | Low | harness | docsync's check accepted scheme counters with an extra `toString: null`, and its summary's default `.sort()` stringified each entry, so two such schemes threw before the teardown gate. | fixed | The summary sorts by scheme name only. Each check passes two such counters through the summary, which must print them without throwing; with the default sort it fails. | test/docsync/probe.ts "the report schema check passes nothing the summary cannot print (PH-12)" |
