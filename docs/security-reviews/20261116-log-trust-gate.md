# Security review: the decision log's trust gate (`check_log_trust`)

- **Date:** 2026-11-16
- **Reviewer:** the tab-observability workstream's own review round, reading this gate against
  the claims its EDR relies on; the fourth finding came from fixing the first three.
- **Subject:** `rpc-filter/tools/check_drift.py::check_log_trust` as landed, and the
  `rpc-filter-log-is-trustworthy` invariant it enforces.
- **Context:** the Tab Manager forwards each window's `seclabRpcFilter.log` to tabd as
  *trusted*. That is sound only while a tab can neither forge lines in the log, write the file,
  nor delete it. `check_log_trust` exists so those policy facts cannot be relaxed by someone who
  does not know a log depends on them.

## Verdict

No high or critical finding, and **nothing exploitable**: every surface named below was already
`deny` or URI-constrained in the landed policy, and remained so throughout. The defect was in
the check, not in the policy.

That is precisely why it mattered. The gate was green on the real policy and would have stayed
green through every one of these changes, so it asserted more than it established. A control
that cannot fail for the reason it claims to exist is worth no more than the comment it
replaced.

| ID | Sev | Component | Finding | Status |
|---|---|---|---|---|
| LT-1 | low | drift gate / decision log | `$writeFile` was accepted on its verdict alone: any `allow_with_constraint` passed, whatever the constraint said | fixed |
| LT-2 | low | drift gate / decision log | `$delete` was not pinned, so nothing stopped a future policy letting a tab delete the log | fixed |
| LT-3 | low | drift gate / decision log | Other host-file writers (`$tryApplyWorkspaceEdit`, `$trySaveDocument`) were not pinned | fixed |
| LT-4 | low | drift gate / decision log | A pinned surface absent from the mapping was skipped, so the check went quiet rather than failing | fixed |

## LT-1: a constraint the gate could not read

The check required `$writeFile` to be `deny` or `allow_with_constraint` and stopped there. The
constraint itself is free text — the entry reads `"same as $readFile"` — so the gate had **no
machine-readable handle on it**. An entry rewritten to constrain something else entirely would
have passed unchanged.

This is worth stating precisely, because the obvious reading is wrong: it was not a loose
comparison that needed tightening. There was nothing to compare. The fix had to *add* a handle,
not sharpen one. The check now requires the method to carry generated `uri_arg_positions`, which
is the table the filter actually enforces from, so the gate is tied to enforcement data rather
than to a sentence describing it.

`deny` still passes. Stricter than constrained must never be reported as a problem, or the gate
argues for the weaker verdict.

## LT-2: guarding content but not its absence

Every existing check guarded against *forged* log content. None guarded against *no* content.
Deleting `seclabRpcFilter.log` ends forwarding, and silence is not a safe failure for an audit
log — a consumer that sees nothing cannot distinguish quiet from gone.

## LT-3: enumerating an API rather than a capability

The check listed file-system methods. A workspace edit and a document save reach the file system
just as surely, so the enumeration described one interface rather than the capability the log's
integrity depends on.

## LT-4: absence treated as nothing to check

A pinned key missing from the surface mapping was skipped. In this repository the scanner has
lost surfaces more than once — the user-input command primitives, server-initiated pushes and
factory-produced AI tools were each absent from a scan that reported itself complete. Absence is
therefore at least as likely to be a scanner regression as an upstream removal, and the log's
integrity depends on the verdict either way, so a human should establish which.

## How the fix was validated

Each case was confirmed to pass **unnoticed** against the previous version of the gate before
being confirmed to fail against the new one, with the control passing in both. A hardening that
cannot be shown to catch something the old version missed is a rewrite, not a fix.

Seven tests in `rpc-filter/tools/test_enforcement.py`, including the two negative controls that
keep the gate honest: the shipped policy passes, and `$writeFile` denied outright passes.

## Residual

The gate establishes that the policy facts the log rests on still hold. It does not establish
that the log is written, that its lines are well formed, or that the forwarder reads them; those
belong to the forwarder's own record. Pinning a capability by enumerating the methods that reach
it stays inherently open-ended — LT-3 is an instance, and a method added upstream that writes
host files would not be noticed by this check until someone adds it here.
