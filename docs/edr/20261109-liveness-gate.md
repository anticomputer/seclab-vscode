# Liveness gate: everything that only matters if it runs names what runs it

- **Status:** accepted
- **Date:** 2026-11-09
- **Deciders:** Coordinator (repo-wide half of the approved liveness gate; "don't wait for the
  RPC EDR any longer"; scheduled workflows need a dispatch run on record). Fork-build session:
  implementation. The RPC session builds the rpc-filter and patch-queue half.
- **Related:** [RPC core handoff](https://github.com/anticomputer/seclab-vscode/blob/7e8167dccb2ce59f12e942bdf71be1add7c27bd5/docs/edr/20261106-rpc-core-handoff.md)
  (the four instances and "check the prover before believing it"),
  [test build variants](20261106-test-build-variants.md),
  [pin-age cooldown](20261106-pin-age-cooldown.md) (the fifth instance)

## Context
Five artefacts were complete except for the part that runs them:
1. the rogue-REH hook, documented as "applied by the containment harness"; no harness applied it;
2. eight rogue-REH probes that had never executed;
3. `seclabOnDecision`, a decision-listener API with no listener, kept quiet by an exemption
   claiming the Tab Manager consumed it;
4. `seclabTaintEscapes`, an array of caught laundering attempts that nothing read;
5. `deps-updates`, a weekly workflow nobody had run: its first scheduled run failed with
   `ERR_MODULE_NOT_FOUND`, a week after it landed.

Reviews ask what code says. Nothing asked whether anything calls it.

## Decision
`build/liveness/liveness.ts`, run by `./seclab liveness` in the required `workflow-lint` check.

- **Static half (offline):**
  - **Exports.** Every exported value in `tabd/src` (observability included), `tabd/tools`,
    the Tab Manager, `broker/seclab_broker` and `broker/tools` must be reached from code that
    runs. Seeds are each file's top-level statements and declared host `entry` points
    (`activate`). From a live declaration, its references to declarations in its own file, or
    to exports of files it imports, become live. A cluster that only references itself never
    vouches for itself (the RPC gate's rule). Tests don't count, and nor do comments, imports
    or names inside strings: a small lexer strips them, because a regex stripper read
    `'/**'` in `supervisor.ts` as a comment and hid 560 lines.
  - **In-tab programs.** Each file in `sandbox/rootfs/opt/seclab/bin` is named by product
    code or the image build.
  - **Exemptions** name a consumer, which must exist and use the symbol in code, or say
    `consumer: null` and why. Null-consumer exemptions are printed on every run. An
    exemption for something live is stale and fails.
- **Runtime half.** Discovered from the tree, and matched exactly against the register's
  `subjects`:
  - workflows with no `push` or `pull_request` trigger;
  - test-only hooks in `test/builds/variants.json`;
  - each child of a test `fixtures` dir, and each test extension (a dir with `package.json`
    under `test/`).

  Each names what runs it and has at least one piece of evidence:
  - **`run`:** an Actions run, pinned by its head `sha` and `date`. `./seclab liveness
    verify-runs` checks it in CI (`actions: read`), in a container that mounts only the
    register and the checker. The run must be a successful dispatch or scheduled run of
    that workflow, at that sha and date, with a successful `job` if named (not an artifact:
    artifacts expire within days, which turned workflow-lint red on main once). A run deleted at the
    retention horizon (older than 85 days) becomes a printed note; it never blocks every PR.
  - **`ci`:** a job, a mark and the `runner` file. The runner calls `liveMark(mark)` in code
    (not in a comment or a string) where it has proof the subject ran: in-tab evidence read
    back, or an exec observed. It doesn't mark where it merely started the subject. The job
    must run on push or pull_request, with no `if:` or `continue-on-error:`. Its last step
    must be exactly `./seclab liveness marks <job> "$SECLAB_LIVENESS_LOG"`, unconditional,
    which fails the job when a mark is missing.
  - **`record`:** a doc line `- **\`<id>\`:** …` naming the evidence, only for runs CI can't
    do (macOS editor, sbx). These are listed on every run.
- **Entry points** are only a VS Code extension's `activate`/`deactivate`, in the module its
  own `package.json` `main` names. They are listed on every run.
- **Uses** are bindings: `x.name`, `{ name: … }` and `f(name=…)` don't count, except through
  a module alias (`ns.fn`, Python `mod.fn`).
- **The prover is checked first.** `--self-test` builds a clean synthetic tree, which must
  pass: a prover that fails everything is as broken as one that passes everything. It then
  injects each of the five failures alone into a fresh copy:
  - a hook with no subject;
  - a fixture whose runner never marks it;
  - an exemption whose consumer only mentions the symbol in a comment;
  - an array only test code reaches;
  - a scheduled workflow with no run.

  Two more injections cover a CI job missing its marks step and a name that appears only
  inside a string. Review [KKK](../security-reviews/20261109-liveness-gate.md) added one
  injection per way the first version could be satisfied falsely, ten in all: a skipped job,
  `|| true`, `continue-on-error`, a dispatch-only CI job, a push filtered off main, a mark in
  a string or in another file, a passing mention as a record, a fake entry, and a key-only
  use. It also added seven `verify-runs` cases against a fake API. Each must fail with its
  own message. The self-test was itself checked by breaking the gate four ways: no dead
  exports reported, workflows not discovered, any marks log accepted, module aliases
  ignored. Each broke the self-test: three through the control, one through the marks cases.

## Evidence on record
- **`hook:containment/rogue-reh`:** build-macos run 42252088798 (`66af5e9`) applied it, and
  `test/builds/rogue-reh-arming.ts` armed it once in a real OCI tab of that REH. A valid run
  loaded the payload once; no targets, an expired run and a malformed nonce left it disarmed
  ([test build variants](20261106-test-build-variants.md), Consequences).
- **`fixture:test/focus/probe-extension`:** `test/focus/probe.ts` on branch build 42707557651
  (`eff9437`), 2026-11-09. The battery ran every step with no focus steal
  ([background windows](20261105-background-windows.md), path c).
- **`fixture:test/agentic/runner/mitm-extension`:** seven runs of `test/agentic/runner/`
  against release build U on sbx, 2026-11-06
  ([agentic probe runner](20261106-agentic-probe-runner.md), "Measured, 2026-11-06").
- **`fixture:test/containment/rogue-extension`:** `test/containment/check-evidence.ts` (Level
  B) on branch build 42707557651 (`eff9437`), sbx, 2026-11-09, after its repair and review
  NNN: 43 of 47 checks passed, 4 known gaps, teardown clean. The rogue extension was forced
  into the tab, and its chat participant and `vscode.lm` caller ran there. Its RPC probes'
  host effects are their own rows; the host-terminal one is open without the RPC filter, as
  documented. One of three runs that day failed: the `http.proxyAuthorization` canary
  reached the tab (findings below).

## Findings from the first run
- **Dead exports:**
  - `assertPort` (tabd): deleted.
  - `scannerProblem` (tabd): test-only since `5cd79f6` moved the check into
    `scanWorkspace`. Exempted, naming its test.
  - `TAB_EVENTS` and `random_password` (broker): leftovers; the protocol schema validates
    `tab.event`. Deleted by the broker session on 2026-11-09.
- **Level B (`check-evidence.ts`) has rotted.** Nothing runs it in CI. On `486f2d6` three
  checks fail:
  - **`[task] cannot write host file outside the workspace`.** The file is the documented
    open host-terminal hole (`workbench.action.terminal.newLocal` + `sendSequence`, closed
    by the unlanded RPC filter): the rogue extension's RPC probe `touch`es
    `<run>/PWNED` through a host terminal. Because the probe and `probe.sh` share one
    marker path, the harness blames the task. A raw sbx tab writing to its workspace's
    parent stays in the VM (checked separately).
  - **`[fsmonitor] ran` and `[rogue-extension] ran`.** There is no evidence file on the
    host. The rogue extension deliberately no longer spawns `probe.sh`, and the harness
    reads evidence from the host checkout, which the write-back gate holds.
  - The teardown gate also reported `~` changed: the editor wrote its data folders in the
    home dir.

  **Repaired (harness side only; `probe-safety.js` and `rpc-probes.js` are unchanged):**
  - `probe.sh` writes one marker per vector (`<marker>.<vector>`). The RPC probes' markers
    (`<run>/PWNED`, `PWNED.rpcwrite`) are their own rows, expected open without the RPC
    filter (product.json `seclabRpcPolicy` absent) and failures with it.
  - Evidence is read through the tab, as in Level A.
  - The fsmonitor repo was disarmed when `prepare` exited, before the editor opened, so that
    vector could never fire. It is now armed inside the tab (sbx only, behind the write-back
    gate) and never exists on the host.
  - The stale `rogue-extension` probe-evidence check is gone; the extension's own evidence
    rows remain.
  - Launches keep the editor's data in the run's profile (`VSCODE_PORTABLE`), so `~` is
    untouched.
  - Record evidence now carries its date. The weekly `liveness-refresh` job fails once a
    record is more than 30 days old, so Level B and the other local-only runs are asked for
    again instead of rotting.
  - Review [NNN](../security-reviews/20261109-level-b-repair.md):
    - the RPC host-effect rows are derived from the probes' expectations, and any
      unattributed marker fails;
    - a file the tab won't let the harness read fails;
    - the build is identified from the launch record and the policy-stamp digest.
- **Found by the repaired Level B:** in one of three runs on `eff9437` (2026-11-09), the
  rogue extension's configuration dump in the tab contained the `http.proxyAuthorization`
  canary, raw and URL-encoded. Upstream registers that setting at `APPLICATION` or `MACHINE`
  scope depending on `http.useLocalProxyConfiguration`, at run time, which can race the
  remote extension host's start. The harness keeps it a failure, not a known gap: it is a
  credential. Patch 0036 (credential-looking settings withheld from tabs) is not on main yet.
  The old harness never surfaced this.

## Consequences
- A new export, fixture, hook or dispatch-only workflow fails `workflow-lint` until it names
  what runs it. A scheduled workflow lands with a dispatch run on record.
- A CI-run fixture whose runner stops reaching it fails its job, even when every assertion
  that does run passes.
- Record evidence is the weakest kind: it proves a run happened once, not that the subject
  still works. It is allowed only where CI can't run the subject, and it is listed on every
  run.
- A mark proves that a line was appended to the job's log, by the runner the register names.
  Any host-side code in that job could append one. That includes the escape the containment
  suite exists to detect, which would forge every mark at once. Tabs can't reach the log.
  This is accepted in review KKK.
- `run` evidence doesn't go stale when the workflow changes. deps-updates was re-dispatched
  by hand after its fix. Requiring a fresh run when a workflow's inputs change is a possible
  next step.
- **Evidence must outlive its check.** The first version checked a test-variant run's artifact.
  Artifacts are kept 3 days, and they were deleted between the branch's green run and main's.
  Main went red with no commit. Evidence now names a job, which lives as long as the run.
  Runs carry a note from day 75 and degrade to a note after 85 days (90 days is the default
  retention), so age never fails the required check.
- **Lapsing evidence is caught weekly.** The `liveness-refresh` workflow (Mondays, and on any
  push that changes it, `build/liveness/` or `seclab`) runs `verify-runs --refresh`. That turns
  every day-75 and expired note into a failure, listing the entries to re-run before day 85. It
  must print `liveness: refresh mode`, so a lost flag can't pass. It is not a required check.
  Because it runs on push, the gate counts it as live. It can't be dispatch-only anyway: a
  workflow can be dispatched only once it is on main, where the gate would refuse it without a
  run on record. Review [MMM](../security-reviews/20261109-liveness-refresh.md) also made
  `paths` filters count: a push or pull_request that can match no tracked file, or ignores
  everything, doesn't make a workflow live.
- Discovery depends on convention: fixtures live in a directory named `fixtures`, and test
  extensions have a `package.json` (AGENTS.md).
- The analysis is lexical. It can miss a use, which fails the gate and is safe, or, rarely,
  invent one through a same-named binding across an import edge. Upstream patch code is
  covered by the RPC session's half.
