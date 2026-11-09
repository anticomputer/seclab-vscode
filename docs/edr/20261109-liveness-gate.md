# Liveness gate: everything that only matters if it runs names what runs it

- **Status:** accepted
- **Date:** 2026-11-09
- **Deciders:** Coordinator (repo-wide half of the approved liveness gate; "don't wait for the
  RPC EDR any longer"; scheduled workflows need a dispatch run on record). Fork-build session:
  implementation. The RPC session builds the rpc-filter and patch-queue half.
- **Related:** [RPC core handoff](https://github.com/anticomputer/seclab-vscode/blob/5652f9f0c760049e1bc5da143433c0beac6f77d0/docs/edr/20261106-rpc-core-handoff.md)
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
  - **`run`:** an Actions run. In CI (`--verify-runs`, `actions: read`) it must be a
    successful dispatch or scheduled run of that workflow, carrying `artifact` if named.
  - **`ci`:** a job and a mark. The runner calls `liveMark(mark)` where it has proof the
    subject ran (in-tab evidence read back, an exec observed), not where it started it. The
    job's last step, `./seclab liveness marks`, fails the job when a mark is missing. The gate
    requires that step to be last, and the mark to appear in a runner's code.
  - **`record`:** a doc naming the subject id, only for runs CI can't do (macOS editor, sbx).
    These are listed on every run.
- **The prover is checked first.** `--self-test` builds a clean synthetic tree, which must
  pass: a prover that fails everything is as broken as one that passes everything. It then
  injects each of the five failures alone into a fresh copy:
  - a hook with no subject;
  - a fixture whose runner never marks it;
  - an exemption whose consumer only mentions the symbol in a comment;
  - an array only test code reaches;
  - a scheduled workflow with no run.

  Two more injections cover a CI job missing its marks step and a name that appears only
  inside a string. Each must fail with its own message. The self-test was itself checked by
  breaking the gate three ways: no dead exports reported, workflows not discovered, any marks
  log accepted. Each broke the self-test: the first two through the control, the third
  through the marks cases.

## Evidence on record
- **`hook:containment/rogue-reh`:** build-macos run 42252088798 (`66af5e9`) applied it, and
  `test/builds/rogue-reh-arming.ts` armed it once in a real OCI tab of that REH. A valid run
  loaded the payload once; no targets, an expired run and a malformed nonce left it disarmed
  ([test build variants](20261106-test-build-variants.md), Consequences).
- **`fixture:test/focus/probe-extension`:** `test/focus/probe.ts` on branch build 42295175158
  (`fd73500`), 2026-11-06. The battery ran from step 0 to `server-connection-lost`, with no
  focus steal ([egress prompts](20261106-egress-prompts.md), B3c part 3).
- **`fixture:test/agentic/runner/mitm-extension`:** seven runs of `test/agentic/runner/`
  against release build U on sbx, 2026-11-06
  ([agentic probe runner](20261106-agentic-probe-runner.md), "Measured, 2026-11-06").
- **`fixture:test/containment/rogue-extension`:** `test/containment/check-evidence.ts` on
  branch build 42295175158 (`fd73500`), sbx, 2026-11-09. The rogue extension ran in the tab:
  it was forced into the tab (`remoteName=seclab`), and its chat participant and `vscode.lm`
  caller ran there. The same run shows the Level B harness itself has rotted (findings below).

## Findings from the first run
- **Dead exports:**
  - `assertPort` (tabd): deleted.
  - `scannerProblem` (tabd): test-only since `0ae1eeb` moved the check into
    `scanWorkspace`. Exempted, naming its test.
  - `TAB_EVENTS` and `random_password` (broker): leftovers; the protocol schema validates
    `tab.event`. Exempted with no consumer, for the broker session to delete.
- **Level B (`check-evidence.ts`) has rotted.** Nothing runs it in CI. On `fd73500` three
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
  - The teardown gate also reported `~` changed, on a host shared with other sessions.

  Reported to the coordinator; the RPC session owns the probes.

## Consequences
- A new export, fixture, hook or dispatch-only workflow fails `workflow-lint` until it names
  what runs it. A scheduled workflow lands with a dispatch run on record.
- A CI-run fixture whose runner stops reaching it fails its job, even when every assertion
  that does run passes.
- Record evidence is the weakest kind: it proves a run happened once, not that the subject
  still works. It is allowed only where CI can't run the subject, and it is listed on every
  run.
- `run` evidence doesn't go stale when the workflow changes. deps-updates was re-dispatched
  by hand after its fix. Requiring a fresh run when a workflow's inputs change is a possible
  next step.
- The analysis is lexical. It can miss a use (that fails the gate, so it's safe) and,
  rarely, invent one through a name shared across an import edge. Upstream patch code is
  covered by the RPC session's half.
