# The decision log cannot be silenced, and four gates that could not fail

- **Date:** 2026-11-06
- **Status:** accepted. Second landing attempt for the core RPC filter.
- **Follows:** [the failed proof run](20261106-rpc-core-proof-run.md) and
  [review round 9](../security-reviews/20261106-rpc-core-landing.md).

## 1. The decision log is a budget, not a switch

The proof run silenced a window's log in 666 ms of ordinary startup. Review
alert 1 showed a tab could do it deliberately with ~512 crafted calls. Either
way the `cmd:workbench.action.terminal.newLocal` denial — the artefact proof
condition 2 rests on — is never written, while enforcement still holds. A
control whose refusals nobody can see is the thing this log exists to prevent.

Four changes, in `seclabRpcFilter.ts`:

- **Every verdict aggregates.** `seclabRecord` used to collapse only allows,
  on the reasoning that denials are what an investigator acts on. An
  investigator acts on the *first* denial; the repeats are what drowned the
  log. The first occurrence of a `(surface, id, verdict)` key is now delivered
  **immediately** — delaying it by the aggregation window would lose it in a
  short-lived window — and repeats are collapsed into one follow-up carrying
  `count`. The line rate is bounded by distinct keys, not by call volume. The
  4932-copy storm becomes two lines.
- **The byte budget rolls; it never latches.** `SECLAB_LOG_BYTES_PER_WINDOW`
  (512 KiB) refills every `SECLAB_LOG_WINDOW_MS` (60 s). The old `capped` flag
  latched for the life of the window on the first second that overran.
- **A first-seen key always gets quota**, even over budget, bounded by
  `SECLAB_LOG_KEYS_MAX` so a tab cannot grow the set without limit by inventing
  method names. A flood of one key therefore cannot hide the first occurrence
  of another, which is exactly what the proof needs.
- **Suppression is reported, not silent.** A suppressed run is summarised with
  its count as an ordinary `rpc.decision`, so a gap is visible.

`SECLAB_LOG_REF_MAX` drops from 1024 to 256. `ref` is tab-chosen for an
unmatched method and for every `cmd:` id, and 1024 is what let ~512 calls spend
the whole budget.

`test/containment/log-throttle.test.ts` (12 assertions) replays both the
measured storm and the review's crafted flood, and pairs each with the **old**
implementation as a negative control: a regression test that also passes
against the broken version pins nothing. The model is tied to the shipped
source — constants are read out of it, and the control flow is asserted — so a
change the model does not mirror fails here rather than passing quietly.
Proved by injection: removing the first-seen reservation fails exactly the
assertion that names it.

## 2. Four gates that could not fail

Review round 9 found two more instances of this increment's recurring defect,
both in artefacts added to stop it. With the two from the proof run, this round
fixed four.

**Alert 4 — the dead-entry-point gate was satisfied by prose.** The *only*
match for `seclabOnDecision` in the patch-added text was the sentence
"Until this existed `seclabOnDecision` had no subscriber at all". Delete the
subscriber and the gate stayed green: the check written to catch a mechanism
nothing invokes was passing on a comment describing that exact history.

Two fixes, because stripping comments alone would then have failed honestly but
unhelpfully — the real subscription is intra-file, in a section
`_patch_added_text` deliberately skips:

- `_without_comments` drops `//` and `/* */` text. Stripping is crude on
  purpose: a `//` inside a string takes the rest of that line, which can only
  *hide* a use (fail the gate), while leaving comments in can only invent one.
- Liveness is now computed, not pattern-matched. Symbols referenced outside
  their declaring file seed a live set; an intra-file reference counts only if
  it sits in the body of a symbol that is itself live, propagated to a fixed
  point. A helper called by a live entry point is live; a cluster that only
  calls itself never becomes live, because seeds come exclusively from outside.

Proved as the reviewer asked: deleting the real `seclabOnDecision(...)`
subscription now fails the gate, with two comment mentions still present.

**Alert 5 — the channel guard's uninstalled state was allow**, and a test
pinned that as intended. The guard is installed by a top-level side effect that
runs only when something imports the workbench module; "installed before the
hostile server's first channel call" was an assumption about bundle evaluation
order, and the REH inside the tab chooses when to make that call.

`ipc.ts` now refuses a channel call when no guard is installed **and** the
context is a tab (`seclab+` authority, as a bare string or via
`remoteAuthority`). Only tab contexts: the trusted side serves channels over
the same class before any tab exists, and refusing those would brick the
window. `'removing the guard restores service'` is replaced by its opposite for
tab contexts, kept for trusted ones, with a negative control asserting the
previous wrapper served the tab.

**Alert 3 — `checkChannel` was fail-open** for `prompt`, `rewrite` and
`allow_with_constraint`, while `checkRpc` was fail-closed for exactly those.
It now has the same ladder. A channel is call-and-event, not an argument list,
so there is no positional constraint to apply: a constraint that cannot be
enforced here is not a constraint. Latent today, because only `deny` channels
exist — it would have gone live the first time a reviewer wrote
`"verdict": "prompt"` believing it would be held.

**Alert 2 — tab-authored evidence could veto its own teardown.** The new
evidence channel routes bytes the rogue extension chose into the host-side
harness, and `JSON.parse` had no `try`, `Evidence` declared `string` fields
that arbitrary JSON filled, and the `check` branch registered none of the
`uncaughtException` handlers `prepare` has. One malformed field threw out of
`checkEvidence`, skipping `report()`, the `.git` disarm and `teardownGate()` —
leaving the editor running with the armed rogue `.vsix` on the host.

- `Evidence` fields are `unknown`, so the compiler enforces narrowing. The
  declared shape was a claim, not a fact.
- A present field of the wrong type is **malformed**, not the benign value.
  `"ui_bridge": 7` read as `''` and passed the credential-bridge check;
  narrowing must not convert an unparseable claim into a reassuring one. This
  was caught by the new suite, not by review.
- Reads are bounded (`EVIDENCE_MAX_BYTES`), names from the tab cannot contain a
  separator, and `readJsonInTab` returns `undefined` for anything that is not a
  JSON object.
- The `check` branch disarms and tears down on `uncaughtException` and
  `unhandledRejection`, through the same single path as the normal exit.

`test/containment/evidence-shape.test.ts` (15 assertions) asserts, for each
hostile shape, both that it does not throw **and** that it fails a check —
"it did not throw" alone would be satisfied by a harness that silently passed.
A benign evidence object must still pass, so the guards cannot have just failed
everything.

## 3. Patch numbering

The held-back REH-push patches are renumbered out of the 0015–0021 range, which
belongs to the agentic series: `patches/series` already ships
`0015-seclab-ahp-gate.patch` while the handoff and `policy.json` named a
held-back `0015-seclab-no-remote-cli-push-in-tabs.patch`. `prepare.sh` applies
the queue by filename, so one would have silently displaced the other.

- `0015-seclab-no-remote-cli-push-in-tabs` → **`0030-`**
- `0016-seclab-no-variable-resolution-for-tab-pty-hosts` → **`0031-`**

References are updated here; the patch files live on
`anticomputer-rpc-filter-patches` and are Fork-build's to rename in `series`.

## 4. Still open

The extension-host plumbing entries (`MainThreadErrors.$onUnexpectedError` and
the activation lifecycle) are **not** in this record. They are derived from a
measured clean boot of a build carrying the log fix, because the previous
measurement was taken through a log that had already capped. That is the next
step, with a benign-extension positive control, and the three-condition proof
after it.

## Links

- Failed proof run: [`20261106-rpc-core-proof-run.md`](20261106-rpc-core-proof-run.md)
- Review round 9: [`../security-reviews/20261106-rpc-core-landing.md`](../security-reviews/20261106-rpc-core-landing.md)
- Evidence channel: [`20261106-containment-proof-reads-the-tab.md`](20261106-containment-proof-reads-the-tab.md)
