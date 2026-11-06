# RPC core increment: state, and what runs next

- **Date:** 2026-11-06
- **Status:** accepted. Handoff note, now closed out: the core RPC filter was
  built on `rpc-core` and handed over for landing.
- **Branch:** `rpc-core`, final head `597b92c`, pushed, every gate and suite
  green. **Ownership moved** to the RPC-core landing session, which is bringing
  `597b92c` onto `anticomputer-rpc-core-landing` and fixing what the runtime
  proof found (see the outcome section). No further commits from this session.

Written because the session that built this ran long, and the remaining work
depends on facts that are cheap to state and expensive to rediscover.

## Where the increment stands

Landing set is patches 0005–0010 plus the gates. Two patches that *would*
close real holes are deliberately **held back** on
`anticomputer-rpc-filter-patches` (`6906cfd`), because nothing unproven
ships:

| Patch | Closes | Why held |
|---|---|---|
| `0015-seclab-no-remote-cli-push-in-tabs` | `remoteTerminal.$onExecuteCommand` — host code execution | rogue-REH fixture has never been runnable |
| `0016-seclab-no-variable-resolution-for-tab-pty-hosts` | `$onPtyHostRequestResolveVariablesEvent` — host shell environment, incl. tokens, no pty needed | same |

Both paths are **open on main** and say so in `RPC-LOCKDOWN.md` §7 and the
README's M4 row. They are recorded as accepted-unenforced in `policy.json`,
so `check.sh` prints them on every run; that list stands at 25.

## The proof: outcome (2026-11-06, later)

> **Superseded by the run.** The section below described the state before the
> proof completed. It is kept because the three conditions still stand, but the
> run happened and the patched half failed for a reason **internal to this
> increment**, not an environmental one:
>
> * baseline reproduced `PWNED-newlocal`, as before;
> * the patched build **broke the extension host**: the default verdict denied
>   `$onUnexpectedError` and the activation methods, so the host could neither
>   report errors nor activate extensions;
> * the decision log's cap **latched after about 4,900 denials in 666 ms**.
>
> Both are mine, and both are one mistake in two places: a default-deny table
> and a per-window cap each sized for a hostile tab making occasional calls,
> when the real traffic is an extension host doing ordinary work. Default-deny
> is right; denying the host's own lifecycle plumbing is not a policy anyone
> chose, it is a classification gap nothing had exercised. The cap figures
> (5000 lines, 2 MB) were argued against an attacker's budget rather than a
> normal session's, and 666 ms shows how far out that was.
>
> The honest reading: the **earlier** patched run that produced "no marker and
> no fixture evidence" was most likely this, not a timing or write-back
> problem. Refusing to call it a proof was right; the cause was nearer to hand
> than the overlay theory being pursued at the time. An absent marker had a
> reason, and the reason was the filter breaking the thing it was filtering.
>
> Anyone sizing a cap or a default here should measure a normal session first.
> The RPC-core landing session owns the fix.

## The proof, and why it was not done

The baseline half **passed**: on main's `24fea4c` build, `newLocal` +
`sendSequence` wrote `PWNED-newlocal` to the host. Host code execution from a
tab, reproduced, with its own named check.

The patched half produced no marker — and that is **not** a result. The same
run reported `rogue-extension ran -> no evidence file`, and 13 checks instead
of 32. An absent marker is equally consistent with a fixture that never
started. Three conditions must hold together:

1. the fixture demonstrably ran;
2. the trusted-side denial for `cmd:workbench.action.terminal.newLocal` is
   observed, not inferred;
3. no marker.

Condition 2 had no producer until `889cbf7`; see below.

## Four artefacts that were complete except for the part that runs them

This is the session's main finding, and it is a pattern rather than four
accidents. We review what code *says* far more carefully than whether
anything *calls* it.

1. **The rogue-REH hook.** `patches/README.md` and the escape-probes EDR both
   said it was "applied by the containment harness for a dedicated probe
   build". No such mechanism existed. Corrected in `d70c8db`.
2. **Eight rogue-REH probes** that have therefore never executed. They are
   specifications, not results, and must not be cited as evidence.
3. **The decision stream.** `seclabOnDecision` was exported with no
   subscriber: every denial went into an in-memory array nothing read. A
   `CALLER_EXEMPT` entry claiming the Tab Manager consumed it is what kept the
   dead-entry-point gate quiet.
4. **`seclabTaintEscapes`**, same shape, found only because the new exemption
   gate asked. A laundering attempt caught by the backstop is still recorded
   and read by nobody.

The approved follow-up is a **liveness gate**: every exported seclab symbol,
test hook, fixture, probe, gate and exemption must name what runs it, with
evidence it ran at least once. Build the rpc-filter/patch-queue half here;
Fork-build generalises it repo-wide.

## Next steps, in order

1. **`product.json` stamp.** Observability needs
   `"seclabRpcFilter": { "policy": "<sha256>" }` before it will forward window
   logs as trusted, and chose **option 2**: stamp *after* patching, hashing the
   applied `src/vs/workbench/services/extensions/common/seclabPolicyData.ts`,
   because the point is to detect a build where the filter is absent.

   `build/prepare.sh` stamps `product.json` at **step 3** and applies patches
   at **step 4**, so this needs a second jq pass at the end, not an entry in
   `build/product/overrides.json`. The invariant matters more than the hash:
   the key must be present **iff** `0005-seclab-rpc-capability-filter.patch` is
   in `patches/series`, failing in both directions. `prepare.sh` and
   `product.jq` are Fork-build's files — coordinate before editing.

2. **`.seclab-evidence/` write-back.** Unresolved. Workspace writes reach the
   host only when tabd syncs, and some paths are held. `.seclab-evidence`
   appears in `tabd/src/obs/workspace-watch.ts:12`, but that is a
   notification-quiet list, **not** a hold list — the hold set was not located.
   Check whether it is held, then either move the fixture's evidence out of the
   held set or sync before reading. Do not exempt it from the gate. The
   decision log is unaffected: it is written host-side through `ILoggerService`.

3. **Rebuild, then the three-condition proof.** `889cbf7` and `8be17a6` change
   `patches/0005`, so the fetched `cbd62d2` artifacts in `.work/app-branch` are
   **stale**. `.work/app` (baseline, main `24fea4c`, run `42239273354`) is
   still valid and de-quarantined.

   Dispatch `build-macos.yml --ref rpc-core`, **then stop pushing**: a push
   cancels the required checks on the built SHA and `./seclab fetch
   macos-branch` correctly refuses it. That cost two build cycles in this
   session.

4. **Land**, then write the liveness-gate EDR.

## Facts worth not rediscovering

- **Regenerate patches with `diff -ruN` against a tree.** Never hand-edit hunk
  headers: it corrupted 0007 (`640f084`) and failed again on the first attempt
  at the 0005 wiring. `apply-patches.sh --check` now parses every patch, so
  that class of breakage fails fast.
- **`patch-src` covers only the two new files** (`seclabRpcFilter.ts`,
  `seclabPolicyData.ts`). Edits to existing upstream files live as hunks in the
  patch and must be regenerated from a tree.
- **The decision log's trustworthiness is gated**, not documented:
  `check_drift.py::check_log_trust` fails if any `MainThreadLogger.*` method
  stops being denied, if `$writeFile` loses its URI constraint, or if
  `$mkdir`/`$copy`/`$rename` are allowed.
- **Deferred laundering is an open residual** and is gated: no command may be
  given a verdict other than `deny` until it is fixed
  (`check_drift.py::check_residuals`).
- **Prove a gate by injecting the defect it claims to catch, and when the
  injection harness reports the *control* failing, establish whether the gate
  or the harness failed before believing either.** That happened three times in
  one session, and every time the harness was at fault, not the thing under
  test:

  1. appending `process.exit(1)` to a suite that already calls `process.exit`,
     so the injected line was unreachable, and concluding the aggregate runner
     swallowed failures;
  2. granting an injection the exemption it was meant to defeat, by setting
     `whole_class: true` while testing whether `whole_class` could be abused,
     which is why that rule is now structural rather than a flag;
  3. restoring a backed-up file inside a shell `&&` chain, so the control ran
     against a still-modified tree.

  Each would have produced a "fix" to a gate that was working. The habit that
  catches it is cheap: re-run the control alone, in a clean invocation, before
  concluding anything. A gate and its prover are two pieces of code, and only
  one of them is under test at a time.

  This generalises to the approved liveness gate: a liveness gate with a broken
  prover is the same failure wearing a new hat. "Name what runs this" needs
  "and show that the thing proving it ran can itself fail".

## Links

- Architecture and residuals: [`docs/RPC-LOCKDOWN.md`](../RPC-LOCKDOWN.md)
- Review driving the five fixes:
  [`20261105-rpc-core-increment.md`](../security-reviews/20261105-rpc-core-increment.md)
- Agent-host seam:
  [`20261105-no-builtin-chat-in-tabs.md`](../adr/20261105-no-builtin-chat-in-tabs.md)
