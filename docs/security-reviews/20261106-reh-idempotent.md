# Security review: idempotent ensureRunning on a running tab (B3c part 3)

- **Date:** 2026-11-06
- **Scope:** round III:
  - `seclab-reh-start` liveness through `/proc` and `--check`; `Driver.rehAlive` (sbx, OCI);
    the `Supervisor.ensureRunning` fast path; tests;
  - `1435784`: the e2e REH kill as the tab user, test only;
  - their fixes.
- **Threat model:** the tab controls `/run/user/<uid>/seclab` (`reh.pid`, `token`, socket) and
  everything that runs as the tab user. The fast path must not skip a security step, run
  anything outside the guard and collector, leak the token, or cause a host-side effect.
- **Records:** [EDR egress-prompts](../edr/20261106-egress-prompts.md).
- **Prompt injection:** none found.

## Round III
One medium. Confirmed:
- `--check` as the tab user via `sbx exec` runs no tab code: fixed argv, `-w /`, docker-exec
  semantics (no login shell), root-owned script and tools;
- guarded tab processes can't signal or ptrace it (Landlock scoping);
- tab-owned files only change its exit code (a FIFO hangs it until the 15 s timeout);
- the token arrives on stdin and is already in the tab's own `$RUN/token`;
- a reused process ID is handled by the command-line match;
- an OCI user mismatch falls through to the full path;
- the `1435784` e2e kill runs as the OCI tab user and must kill at least one process.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| III-1 | Medium | tabd | `alreadyRunning` called `rehAlive` on a tab whose phase was stale. After an external VM stop, phase stayed Running and broker control survived. `sbx exec` booted the stopped VM before the identity re-check and the secret scan, and a failed scan left it running. A race with quarantine could restart a quarantined VM. | Fixed | `runningSandboxes()` is checked before `rehAlive`. The monitor sets phase Stopped when the sandbox stopped. Quarantine sets phase Failed first, and stops the VM under the per-tab probe lock. The unit test's fake answers like the real exec; with the check removed, the test fails (it probes a stopped tab). |
| III-2 | Low | sandbox | `--check` liveness is tab-forgeable (pid file, token, socket, `exec -a` command line). It grants nothing beyond the tab's own REH, but lets the tab make full starts fail. | Fixed | `rehAlive` is documented as tab-asserted, never a security gate (`types.ts`, EDR). `--check` creates nothing, not even the run dir. |
| III-3 | Low | tabd | The fast path drops the per-connection secret rescan and the deny sync. The fence is still covered by `connect` and the monitor; the rescan was detection only. | Accepted | Recorded in the EDR as a trade-off. |
| III-4 | Low | tabd | The fast path didn't require a live collector. An adopted sbx tab has none, and observation resumes only on its next full `ensureRunning`, so the fast path would have left it unobserved. | Fixed | `Driver.usesCollector` (sbx); the fast path requires `ObsGlue.collectorAlive`, else the full start runs. |
