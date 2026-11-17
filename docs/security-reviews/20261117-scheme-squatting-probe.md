# Security review: the scheme-squatting probe (Copilot review, PR #33)

- **Date:** 2026-11-17
- **Scope:** `test/squat/probe.ts` and its probe extension, the runtime regression test for
  DOCSYNC-R7, as opened in PR #33.
- **Reviewer:** the automated pull-request review; triage and fixes by the document-sync session.
  Finding IDs `SQ-n`.
- **Threat model:** a rogue extension owns the tab's extension host. The probe must exercise each
  host read it claims to, and nothing the tab writes into its report may reach host output or
  evidence beyond the validated fields.
- **Related:** [EDR scheme-squatting](../edr/20261116-scheme-squatting.md).
- **Prompt injection:** none found.

## Findings
None from a security-review round: the probe's first version was covered by the document-sync
session's own triage. The PR review below found three issues.

## Copilot review (PR #33)
Three threads from the automated pull-request review, each checked against the code and fixed
before merge.

| # | Sev | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| SQ-1 | Info | harness | The probe's profile was shared by every worktree while its run guard is per worktree, so one worktree's teardown could stop or delete another's run. | fixed | The profile name carries a hash of its worktree, as the other probes do since TEL-6. | none |
| SQ-2 | Low | harness | The window-log step had no positive control. It had in fact never run: the settings modal was still open. So "the window opened its own log and never called the tab's provider" passed without the window opening its log. | fixed | The probe closes the modal first and requires an output editor for the window log with content. | test/squat/probe.ts "control: the window opened its own log in an output editor" |
| SQ-3 | Low | harness | The report check validated named fields, but the harness printed and stored the tab's whole `registered` and `calls` objects, so a rogue report could carry arbitrary text into host output and the results file. | fixed | Only the validated keys are copied out. The probe extension adds marker-bearing fields to both objects; injecting the old whole-object copy fails the check. | test/squat/probe.ts "reach neither host output nor evidence (SQ-3)" |

## Copilot review (PR #33, second pass)
Two threads on the fixed probe, both checked against the code and fixed before merge.

| # | Sev | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| SQ-4 | Low | harness | After the run the harness wrote `.seclab/stop` into the tab's workspace from the host. A tab that made it a symlink to a host file would have had that file truncated with the harness user's rights. The extension never read the stop file anyway. | fixed | The harness writes nothing into the tab's workspace once the tab runs, and reads its report through the tab. The extension now makes `.seclab/stop` a symlink to a host sentinel outside its workspace; the sentinel must be unchanged. On sbx the share doesn't carry the tab's symlink to the host (it exists in the tab right after creation and is gone on both sides by the end), so the check can't fail there; it guards shares that do. | test/squat/probe.ts "SQ-4 no host write followed a tab symlink" |
| SQ-5 | Low | harness | The harness read `.seclab/targets` back from the tab's workspace unguarded, so a tab that deleted it made the run throw before the teardown gate. | fixed | The harness keeps the arm it generated and compares against that; nothing it reads from the tab's workspace can throw. The extension deletes its arming file, and the run must still reach its assertions and the gate. | test/squat/probe.ts "control (SQ-5)" |

## Copilot review (PR #33, third pass)

| # | Sev | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| SQ-6 | Low | harness | The harness read the tab's report with `sbx exec cat` and no timeout, so a tab that made `report.json` a FIFO with no writer stalled the run forever, before the editor closed and the teardown gate ran. | fixed | A shared `tabExec` (test/harness.ts) runs `sbx exec` with a hard timeout and SIGKILL, and maps any failure or timeout to no data. Without the timeout the unit test hangs. | test/harness/tab-exec.test.ts "a FIFO with no writer at the read path times out to no data (SQ-6)" |

## Found while fixing the same in other probes
| # | Sev | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| SQ-7 | Low | harness | As the PR #24 and #37 reviews found in the edtabs and wsdata probes (EDT-17, WSD-1), this harness copied its VSIX into the tab's workspace from the host after the tab was running, where a tab symlink could redirect the copy onto a host file. | fixed | The VSIX is staged before the tab is claimed. Nothing in the tab runs before the probe is installed, so no run plants the symlink. | none |
