# The containment proof reads the tab, not the host checkout

- **Date:** 2026-11-06
- **Status:** accepted.
- **Supersedes nothing.** Resolves step 2 of
  [`20261106-rpc-core-handoff.md`](20261106-rpc-core-handoff.md), which left the
  `.seclab-evidence/` write-back question open.

## The question

The three-condition proof for the `newLocal` host-code-execution chain needs
condition 1, "the fixture demonstrably ran", to be readable. The editor-driven
check (`test/containment/check-evidence.ts`) read the fixture's evidence from
the **host** copy of the workspace. Tab writes reach the host only through
tabd's write-back gate, so the handoff asked whether `.seclab-evidence/` is
held.

## Where the hold set actually is

`tabd/src/obs/workspace-watch.ts:12` is a notification-quiet regex and decides
nothing. The hold set is `tabd/src/writeback-policy.ts`: `held`, `tabLocal`,
`gitAuto`, `heldWhenKeysChange` and `dependencyKeys`. `.seclab-evidence`
appears in none of them.

But the policy is not the only thing that keeps a path off the host.
`WriteBackEngine.sync` (`tabd/src/writeback.ts:360-400`) also:

- refuses anything the **host's git ignores**, permanently, as "invisible to
  review" (review Z-1);
- **holds** anything at all when `hostGitIgnored` returns `null`, i.e. when the
  ignore state could not be determined, which includes a workspace whose `.git`
  the tab has broken;
- holds on the per-sync file and byte caps, and on the mass-deletion rule.

So "not in the policy's hold list" does not mean "on the host", and none of
those outcomes is distinguishable, from the host side, from a fixture that
never ran. That is exactly how the first patched run reported
`rogue-extension ran -> no evidence file` with 13 checks instead of 32 and
still looked like containment.

## Decision

**Condition 1 does not depend on write-back at all.** The check reads the
tab's own view of the workspace, the way the automated runner
(`test/containment/run.ts:145`) already did, via `runtime exec <tab> cat`,
falling back to the host copy only if the tab is gone. The tab is found from
`run.json`, which `prepare` already writes; `prepare` now also records the
driver there, so `check` no longer guesses `sbx` and no longer picks the wrong
broker-proxy expectation for an OCI run.

The write-back gate is **not** weakened and `.seclab-evidence/` is **not**
exempted from it. The gate is a separate control with its own end-to-end
assertions in `run.ts`; this is only about where the proof reads from.

The canary scan over the evidence directory now reads through the tab too. It
previously listed the host directory, so when nothing synced it scanned zero
files and the "no editor-side canary observed by the tab" check passed
vacuously.

## The fifth artefact that ran nothing

Condition 2 is "the trusted-side denial is observed, not inferred". Patch 0005
writes every verdict to `<userData>/logs/<session>/window<N>/seclabRpcFilter.log`
through `ILoggerService`, host-side, where a tab cannot reach it. **Nothing
read that file.** This is the same shape as the four cases the handoff
recorded, found the same way: by asking what runs it.

`rpcDecisions()` in `test/containment/assert.ts` is the reader, and
`check-evidence.ts` now fails the run unless the log holds a `deny` whose
`ref` is exactly `cmd:workbench.action.terminal.newLocal`.

The log is trusted-side, but `ref` and `claimedExtensionId` carry strings the
tab chose, so the reader matches exact JSON fields and never free text (EDR
[prompt-injection-hygiene](20261104-prompt-injection-hygiene.md)). A line whose
`claimedExtensionId` merely *contains* the ref must not count as an acquittal.

## Proving the new gate

`test/containment/decision-log.test.ts` (10 assertions, pure, no network;
`./seclab test decision-log`, and in the `rpc-filter` aggregate). Per
AGENTS.md, the defect each claim catches was injected before the gate was
trusted:

| Injection | Expected | Observed |
|---|---|---|
| `d.class === 'rpc.decision'` → `true` | a foreign log class counts as a decision | 9/10, "2 !== 1" |
| `e.name === 'seclabRpcFilter.log'` → `e.name.endsWith('.log')` | any window log is read as decisions | 9/10, on "a log file by any other name is not read" |

Both failures landed on the assertion that names the defect, not elsewhere.

## Links

- Handoff: [`20261106-rpc-core-handoff.md`](20261106-rpc-core-handoff.md)
- Write-back gate: [`../adr/20261104-write-back-gate.md`](../adr/20261104-write-back-gate.md)
- Harness teardown: [`20261104-harness-teardown.md`](20261104-harness-teardown.md)
