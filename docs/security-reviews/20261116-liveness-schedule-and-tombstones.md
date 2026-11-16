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

## Round LSR, follow-up
The reviewer verified LSR-1 to LSR-3 against every spelling and evidence shape it could build,
and confirmed each injection fails with its rule disabled. A `--union` merge can't defeat a
tombstone: it keeps both main's tombstone and the branch's re-add. It found two more bypasses
of the same shape, and a residual.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| LSR-4 | Medium | discovery | The push and pull_request filter keys were still quote- and space-sensitive, so `"branches": [nope]` let a decoy push trigger make a dispatch-only workflow look live (the KKK-7 and MMM-1 fail-open). | Fixed | Filter keys are unquoted like trigger keys. Three spellings are injected. |
| LSR-5 | Medium | discovery | `x.yml` and `x.yaml` are two workflows to GitHub but one subject to the gate, so the twin needed no evidence of its own. | Fixed | Two workflow files with one stem fail. |
| LSR-6 | Low | exemptions | A change that drops a tombstone together with the re-add (taking a branch's whole register in a merge, or an edit) still passed. | Fixed | Tombstones are append-only against the base register, the same base the findings register uses. `check` requires `--base`. A deliberate return marks the tombstone `restored`. |

## Round LSR, second follow-up
The reviewer confirmed LSR-5 and LSR-6 closed and the base wiring sound. The comparison is never
against the change's own register. `--base` can't be omitted or redirected. A pull request is
judged against main's tip. A branch forked before the register existed goes unenforced only on
its own branch-push run; the pull request and main runs still enforce. It also confirmed that a
union merge can't defeat a tombstone, `restored` included.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| LSR-7 | Medium | discovery | LSR-4 was fixed only at exactly 4-space indentation. A filter at 3 or 6 spaces is valid YAML that GitHub acts on, and still disarmed the push filter. | Fixed | The `on:` scanner follows YAML indentation and fails closed on what it can't read: an unparseable trigger line makes the workflow a subject, and an inline or unreadable push filter counts as off main. Column-0 comments no longer end the block. Six shapes are injected. |
| LSR-8 | Low | exemptions | A tombstone marked `restored` with no exemption (armed ahead of time, or left on afterwards) protected nothing, so a later merge could bring the exemption back silently. | Fixed | `restored` stands only while its exemption exists. |

## Round LSR, third follow-up
LSR-7 and LSR-8 were confirmed closed, and six of the scanner's branches were confirmed to fail
their own cases when mutated. A 24-shape differential corpus, with a YAML parser as ground
truth, found one remaining root cause.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| LSR-9 | Medium | discovery | The scanner reads a line at a time, so a flow collection or quoted scalar continued on the next line was read short: `branches-ignore: [foo,` then `main]` dropped `main`, so the push counted as live. A quoted input default continued at column 0 ended the block before `schedule:`. | Fixed | A line of the `on:` block that leaves a flow collection or quoted scalar open makes the whole block unreadable, and so the workflow a subject. Brackets and quotes count only where YAML starts a collection or scalar, and block scalars are skipped. Four injections, and four controls that keep ordinary workflows readable. |
| LSR-10 | Low | self-test | Three fail-closed branches had no injection (trigger-level dedent, unreadable filter line, filter-level dedent), so a refactor could delete them unnoticed. | Fixed | One injection each; each fails when its branch is mutated. |

## Round LSR, fourth follow-up
LSR-9 and LSR-10 were confirmed closed: the 24-shape corpus is clean, and none of the
repository's own workflows reads as unparsed. The reviewer judged that a hand-rolled scanner
keeps producing new bypasses because an unread fragment reads as "nothing found". That makes
every parse gap in an ignore list fail open. A YAML library would end the class of bugs, but so
would inverting the default, and that needs no new dependency. The scanner now has to recognise
each filter item positively, and a YAML construct it doesn't know costs a visible false subject
rather than a silent bypass.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| LSR-11 | Medium | discovery | An item the scanner couldn't read was dropped from the list. In `branches-ignore` or `paths-ignore` that reads as "main not ignored", so live: a block-scalar item (`- >-` then `main`), a bare `-` with the value below, a continuation line, or an empty list. | Fixed | Filter items must be plain or quoted scalars. Anything else makes the trigger count as off main. Eight shapes are injected. |
| LSR-12 | Low | discovery | An anchor or tag before a flow collection or quoted scalar (`&b [foo,`, `!!str "a`) hid that the line was left open. | Fixed | `lineOpen` skips an anchor or tag where a node can start. A tagged quoted default continued at column 0 is injected; a control pins the comment rule. |

## Round LSR, fifth follow-up
LSR-11 and LSR-12 were confirmed closed. A 30-shape corpus found no syntax bypass, and every new
branch fails its own case when mutated. The reviewer then audited `triggers()` for any remaining
path where unread input reads as "found nothing". It found that the inversion stopped at syntax:
input the gate read but doesn't model still resolved to "no disqualifying filter".

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| LSR-13 | Medium | filters | Ignore lists were compared literally, so a glob covering main (`branches-ignore: ['m*']`, `['main*']`, `['ma?n']`, `paths-ignore: ['**/**']`) read as "main not ignored". | Fixed | Entries are matched as globs. An entry using glob syntax the gate doesn't model (`?`, `+`, `[]`, `!`) counts against the trigger on either side, and a `paths-ignore` covering every tracked file disqualifies it. |
| LSR-14 | Medium | filters | A key under push or pull_request that the gate doesn't model was ignored, so a tags-only push (`tags: [nope]`) read as a live branch push. | Fixed | `tags`/`tags-ignore` without a branches filter, pull_request `types` with no default activity type, and any unknown key count against the trigger. |

## Round LSR, final pass
LSR-13 and LSR-14 were confirmed closed. Every historical shape still counts against the trigger,
all ten repository workflows keep the verdicts they had before (no over-strictness), and every
new branch fails its own case when mutated. One input still resolved to "live" without the gate
establishing anything, upstream of all the hardening.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| LSR-15 | Medium | discovery | The `on:` line was found by a bare first-line match. A value left open on an earlier line (a flow mapping, a quoted scalar) can continue at column 0 with a decoy `on: push`, which was read instead of the real, filtered or scheduled trigger block. | Fixed | Only one line may look like `on:`, and every line before it must be closed; otherwise the workflow is unparsed, and so a subject. Four injections, one isolating each rule. |
