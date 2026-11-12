# RPC core increment: state, and what runs next

- **Date:** 2026-11-06
- **Status:** accepted. Handoff note, now closed out: the core RPC filter was
  built on `rpc-core` and handed over for landing.
- **Branch:** `rpc-core`, final head `74a6d78`, pushed, every gate and suite
  green. **Ownership moved** to the RPC-core landing session, which is bringing
  `74a6d78` onto `anticomputer-rpc-core-landing` and fixing what the runtime
  proof found (see the outcome section). No further commits from this session.

Written because the session that built this ran long, and the remaining work
depends on facts that are cheap to state and expensive to rediscover.

## Where the increment stands

Landing set is patches 0005–0010 plus the gates. Two patches that *would*
close real holes are deliberately **held back** on
`anticomputer-rpc-filter-patches` (`17d9f51`), because nothing unproven
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

The baseline half **passed**: on main's `ec43825` build, `newLocal` +
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

Condition 2 had no producer until `a7f4fb1`; see below.

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

3. **Rebuild, then the three-condition proof.** `a7f4fb1` and `338134b` change
   `patches/0005`, so the fetched `cbd62d2` artifacts in `.work/app-branch` are
   **stale**. `.work/app` (baseline, main `ec43825`, run `42239273354`) is
   still valid.

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

## Landing v2: state at the weekend stop (2026-11-06, evening)

Owner: the "RPC core landing v2" session, branch `anticomputer-rpc-core-landing-v2`
(continues `anticomputer-rpc-core-landing` @ `dde0b9b`). **Not landed.** No build has been
dispatched from this branch.

**Done and proven:**
- **Measured once, not layer by layer.** Upstream's own RPC tracer on the unfiltered main
  build `1cfa18a` (benign fixtures only) gives every call an ordinary session makes: 69
  distinct, of which 64 were denied. The raw trace was deleted; the derived list is
  committed. Teardown was clean and focus was never stolen
  ([EDR](20261106-ordinary-session-rpc-trace.md)).
- **Named, fail-closed argument validators.** `seclabArgValidators.ts` ships in 0005 with
  `check_validators` gating it. The 39 unit assertions import the shipped module, including
  16 injected defects, and the harness was seen to fail on a broken mutant.
- **Per-tab partition of `globalState`, `workspaceState` and secrets**
  ([ADR](../adr/20261106-tab-state-partition.md)).
- **What this landing allows:**
  - the core set: open, show and search documents, file system activation,
    initial window state, the two unregisters;
  - three leaf-exception commands (`_setContext`, `_executeHoverProvider`,
    `_executeCompletionItemProvider`), each validated;
  - `$onExtensionActivationError` with no install prompt;
  - `$registerCommand` with no trusted or registered id.
- **Everything whose results reach trusted UI stays denied.** That covers providers, SCM,
  tree views, output, the status bar and decorations. Their drafted classifications are kept
  in `rpc-filter/policy/drafts/`.
- All local gates pass: drift, emit and sync, docs, the rpc-filter suites, the
  `test_enforcement`/`test_generator` tests, source and fixture lint.

**Not proven: no runtime result exists for any of this.**
- The benign control activating in a patched tab is unmeasured. Its hover and completion
  steps may fail now that provider registration is denied; if they do, record them as
  expected failures.
- The three-condition proof has not run.
- The new probes have never executed: the Tab Manager id claims, `vscode-userdata:` reads
  through open, show, search and the provider commands, and the core context key. Nothing
  may be cited until they run, baseline first.
- Security review round 10 (an Opus-class model) finished at the stop
  ([record](../security-reviews/20261106-rpc-core-landing-v2.md)). It found **one high and one
  medium that block landing**, both unfixed: `tabFileSearch` accepts `expandPatterns`, which
  lets the pattern pick host search roots, and the decision log's line cap can be made to
  emit invalid JSON. There are three more, non-blocking.

**Patch numbering (coordinator decision).** The partition patch is
**`0032-seclab-partition-tab-extension-state`** (storage and secrets in one patch, 35
lines), listed after 0015 in `patches/series`. 0011 stays with the held-back
`0011-seclab-no-remote-agent-host-dialing`, 0030/0031 with the REH-push patches, 0034 is
free for this branch, and 0035 belongs to the document-sync session.

**`0011-no-remote-agent-host-dialing` is still needed.** 0015 does not subsume it: 0015
refuses an ungated agent-host protocol client in a tab window, but
`RemoteAgentHostService._connectTo` has already opened the transport to the tab-chosen
address over the host network by then. The held patch refuses the dial itself.

**The document-sync leak** (RPC-LOCKDOWN §7 item 10) has its own session. It stays out of
this landing.

**Exact next step:**
1. Fix round 10's findings 1 and 2, with regression tests and the `expandPatterns` probe,
   then 3 to 5. Re-review until nothing high or critical remains, and record it.
2. Push, and wait for `unit`, `lint`, `docs` and `patch-build` green on that SHA.
   `workflow-lint` failed once on a transient pin-age fetch of `pygments`; it is unrelated,
   so re-run it.
3. Dispatch `gh workflow run build-macos.yml --ref anticomputer-rpc-core-landing-v2 -f test_variant=containment`, then **stop pushing**.
4. `./seclab fetch macos-containment <RUN>`, `./seclab image oci --test-variant containment`,
   then `node test/builds/require-hooks.ts --variant containment --hook rogue-reh --image seclab-tab-oci:test-containment`.
5. `SECLAB_BENIGN_ONLY=1` evidence run on the patched app, which shows whether the benign
   control activates. Then `node test/focus/probe.ts` against it.
6. Run the new probes on the baseline (`.work/app` is main `1cfa18a`),
   then the three-condition proof on the patched build. Check with
   `check-evidence.ts check` and
   `check-probes.ts patched|unpatched … --user-data DIR --tab ID`.
7. Land. Then the response-side control increment: SCM and git first, then output, the
   status bar and tree views, then decorations. Its proof includes the newLocal completion
   and hover-link probe. After that, the deferred-laundering fix, 0030/0031, and the
   liveness-gate EDR.

## Landing v2: the proof passed (2026-11-10)
Superseding the next step above:
- Rounds 10 and 11 were fixed and reviewed, then main was merged at `3b7fe70`, which has the
  Spaces focus fix.
- The first patched app paired with its own REH, which ships as the OCI variant image, showed
  that patch 0006 bricked a patched REH. 0006 now carries the REH opt-out (review round 13).
- On the containment build of `e69c1e6` (run 42866683703), the benign control activated
  (12/13 steps; `findFiles` is a user-accepted loss) and the three-condition proof passed
  twice ([EDR](20261106-ordinary-session-rpc-trace.md#three-condition-proof-e69c1e6-run-42866683703-passed)).

**Next:**
1. Land as one squashed commit on main.
2. Delete the superseded remote branches `anticomputer-rpc-core-landing`,
   `anticomputer-rpc-core-landing-v2` and `rpc-core`.
3. Apply Fork build's probe-safety and rpc-probes diffs.
4. Run the baseline half of `host-restart-extension-host` on a main build at or after
   `3b7fe70`.
5. First follow-up: file and text search providers, as RPC-LOCKDOWN §7.1 specifies.
6. Next: implement the `ai-*` probes (`test/containment/rogue-extension/ai-probes.js` has no
   runner yet; findings baseline agent-host-patches#3). Owner: the RPC core landing session.
7. Then the response-side control, the deferred-laundering fix, proofs for 0030 and 0031
   with the containment variant, and the liveness-gate EDR.

## Links

- Architecture and residuals: [`docs/RPC-LOCKDOWN.md`](../RPC-LOCKDOWN.md)
- Review driving the five fixes:
  [`20261105-rpc-core-increment.md`](../security-reviews/20261105-rpc-core-increment.md)
- Agent-host seam:
  [`20261105-no-builtin-chat-in-tabs.md`](../adr/20261105-no-builtin-chat-in-tabs.md)
