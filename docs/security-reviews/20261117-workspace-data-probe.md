# Security review: the workspace-data probe (Copilot review, PR #37)

- **Date:** 2026-11-17
- **Scope:** `test/wsdata/probe.ts` and its probe extension, the runtime regression test for
  DOCSYNC-R6, as opened in PR #37.
- **Reviewer:** the automated pull-request review; triage and fixes by the document-sync session.
  Finding IDs `WSD-n`.
- **Threat model:** a rogue extension owns the tab's extension host. The probe must catch any host
  path in the tab's workspace data, write nothing through a path the running tab controls, and
  reach its teardown gate whatever the tab's report holds.
- **Related:** [EDR workspace-data](../edr/20261116-workspace-data.md).
- **Prompt injection:** none found.

## Findings
None from a security-review round: the probe was covered by the document-sync session's own
triage. The PR review below found three issues.

## Copilot review (PR #37)
Three threads, each checked against the code and fixed before merge.

| # | Sev | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| WSD-1 | Low | harness | The harness copied the probe's VSIX into the tab's workspace from the host after the tab was running, so a tab symlink there could redirect the copy onto a host file. | fixed | The VSIX is staged before the tab is claimed. Nothing in the tab runs before the probe is installed, so no run plants the symlink. | none |
| WSD-2 | Medium | harness | The host folder is named `<canary>_folder`, and the extension's tokenizer keeps underscores, so the folder's URI or name reaching the tab hashed to a token the leak check never looked for: the DOCSYNC-R6 assertion could pass with the host folder in the tab's workspace data. | fixed | The folder's own name is a marker. Each run checks that the leak check flags the folder's URI split as the extension splits it; with the canary alone it doesn't. | test/wsdata/probe.ts "WSD-2 the leak check catches the host folder" |
| WSD-3 | Low | harness | The report check ran a regex on a tab-controlled `sha256` before checking its type: an object with a null `toString` threw and ended the run before its teardown gate. | fixed | Every value is type-checked before a regex, and the check runs inside a guard. Each run first feeds it a hostile token, which it must reject without throwing; without the type check it throws. | test/wsdata/probe.ts "WSD-3 the report check rejects a malformed tab value without throwing" |
