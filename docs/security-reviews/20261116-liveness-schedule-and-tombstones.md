# Security review: scheduled workflows and removed exemptions in the liveness gate (round LSR)

- **Date:** 2026-11-16
- **Scope:** round LSR, by an Opus-class model. It covers two changes to `build/liveness/liveness.ts`
  and `build/liveness/register.json`:
  - every scheduled workflow becomes a subject, even when it also runs on push;
    `liveness-refresh` gets dispatched-run evidence, closing the open low finding of review
    [MMM](20261109-liveness-refresh.md);
  - a self-test case shows that a union merge which re-adds an exemption for an export that has
    since gone live is refused.
- **Threat model:** the gate must not be satisfiable falsely. That includes a register resolved
  by union in a merge, and a workflow written so that the gate's parser misreads it.

## Round LSR
Two mediums. Confirmed:
- the register evidence and findings entry are sound;
- both new self-test cases fail when the rule they prove is disabled. The stale-exemption
  rule had no injection before this round;
- replaying the register from before c5cb491c's fix gives exactly seven `it is live` errors;
- a commented-out cron still makes the workflow a subject (fail-closed), and so do renamed
  subjects and removed bin exemptions.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| LSR-1 | Medium | discovery | Finding a scheduled workflow is a positive match on `schedule`. A quoted or spaced key (`"schedule":`, `'schedule' :`) or a quoted inline list didn't match, so a schedule+push workflow needed no evidence. | Fixed | Trigger keys are unquoted before matching, in both the block and the inline form. The self-test injects all three spellings. |
| LSR-2 | Medium | evidence | A workflow subject could be satisfied by a `ci` mark from its own push-triggered job, or by another workflow's run, contrary to the rule that push runs don't prove the schedule. | Fixed | Every piece of a workflow subject's evidence must be a `run` of that workflow. Injections cover a `ci` mark and another workflow's run. |
| LSR-3 | Low | exemptions | The stale rule refuses a re-added exemption only when the export went live or is gone. A union merge that keeps both an old and a superseding exemption for a still-dead subject passed, and so did one that brings a removed exemption back along with its deleted code. | Fixed | A subject exempted twice fails. A new `removed` list holds tombstones: re-adding a tombstoned exemption fails. The seven exemptions re-added once are tombstoned. Injections cover a superseded entry, a resurrection with its code, and a duplicate tombstone. |
