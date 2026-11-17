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
