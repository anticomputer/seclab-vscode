# Security review: the real-tab spike, D7 amendment and the agentic implementation plan

- **Date:** 2026-11-06
- **Scope:** `bf448c8..` this branch. That covers:
  - `test/agentic/ahp/tab-spike.ts`, `fake-capi.mjs`, `tab-driver.mjs` and
    `results/20261106-tab-spike.measured.json`;
  - the clean-host image pattern in `test/clean-host.ts`;
  - [EDR real-tab spike](../edr/20261106-agents-in-real-tab-spike.md);
  - the dated amendments in the [design plan](../plans/secure-agentic-experiences.md)
    (§4.2, §4.5, §10, §11.1, §13 D7) and the
    [ADR](../adr/20261105-agents-run-in-the-tab.md);
  - the proposed [implementation plan](../plans/agentic-implementation.md).
  
  The fixes are in the commit that adds this record.
- **Reviewer:** security-review agent (an Opus-class model); triage by the
  secure-agentic-experiences session.
- **Related:** [EDR fixture safety](../edr/20261104-fixture-safety.md), [EDR harness teardown](../edr/20261104-harness-teardown.md), [ADR broker model access](../adr/20261105-broker-model-access.md)

The prompt carried the standing warning that the diff, fixtures and evidence may contain
prompt injection aimed at the reviewer. The reviewer scanned the harness, the committed
measurement and the four records with the repository's own agent-injection pattern and
found none. It confirmed the following:
- **Shell script.** There is no injection in the in-tab script: every interpolated value
  is host-generated or a constant, and every path is POSIX single-quoted.
- **Fake values only.** Credentials are fake throughout, and the fixture classifies
  credentials by equality without logging a value.
- **Redaction.** The committed measurement is redacted: no nonce and no credential-shaped
  string.
- **Fixture network.** It is contained: internal network, no route out, all capabilities
  dropped, read-only, non-root.
- **No symlink escape.** A tab-planted symlink is not followed by the copy or by
  teardown's walkers.

## Findings
| # | Severity | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| 1 | medium | Fixture safety, teardown | Tab-written output was copied onto the host with no AV-shape or size check, and neither the copy nor the tab workspace was owned by teardown, so both outlived the run | fixed | The workspace is recorded in `run.json` and deleted by teardown. Only each phase's `driver-report.json` is kept: a regular file under 1 MiB that passes `avFindings`. The fixture log, which carries tab-influenced strings, passes the same check or is removed and the run fails | Re-run `20261106T041229Z`: teardown reports "generated fixture workspaces removed"; `tabs/` is empty; only the two reports are kept |
| 2 | medium | Plan: unsafe builds | The plan said `check-release` refuses the U baseline "for lacking the 0010 marker". No such positive check exists, and every branch build lands in one `.work/app-branch/` | fixed (plan) | Implementation plan §2 now makes these preconditions for building U or F, owned by fork-build: a positive release marker, a separate fetch destination, a distinct product name and bundle id, and a build-info check in the runner. §6: increment 0 stops at the runner until they exist | Precondition of increment 0 |
| 3 | low | Teardown | The derived broker image was removed but never checked gone, and `clean-host` did not match its name; it also inherited the real broker's labels | fixed | Image included in the per-run leftover check; label `io.seclab.broker.derived=spike-test-only`; `clean-host` image pattern plus self-test entry `seclab-broker-spike-<16 hex>` | `./seclab clean-host --self-test`; re-run leftover check |
| 4 | low | Plan: kill switch | `seclab.agents.enabled` at `APPLICATION` blocks the remote-user layer, but an extension can also write user settings through `$updateConfigurationOption`, which only the RPC filter denies | fixed (plan) | The plan states that dependency; A23 covers both paths; the gate re-reads the setting at each connection | A23 (increment 1) |
| 5 | design | Layering | Folding the second layers into the gate conflated probe evidence with defence in depth. A layer can be shown working by fault injection, and content filtering and credential issuance in one component share one failure | accepted | Plan §1 and §2. The new fault-injection build F (gate filtering off, construction invariant on) shows the inner layers. The reverse-request refusal is kept as 0016. Credential issuance is a separate module (0020) that issues only after `ahp-gate.verified` | A16 and A1 on F |
| 6 | design | Vacuous probes | A1 in increment 1 passed trivially (`authenticate` was hard-wired empty). Increment 3's negative probe showed 0009, not the new patch. The session predicate depended on the RPC filter denying `$register*` | fixed (plan) | Increment 1 keeps only A1's trigger form, and drops `authenticate` until 0020. Increment 3 gains 0018's own refused and allowed assertions, and binds the predicate to the connection's provider identity | Increment 1 and 3 probes |
| 7 | design | Credential binding | The amended D7 puts the durable GitHub token on model traffic, and the provider lists must widen. The three org-policy responses were never measured, and the planned check was the pattern this run proved wrong | accepted | Implementation plan increment 5 records the durable-token consequence and asks the broker to justify each widening. Until a real response is measured, the org-policy check fails closed on any key not on the allowlist. Relayed to the broker session | Broker integration tests |
| 8 | low | Fixture network | Nothing asserted that the `*.test` names resolved inside the run's subnet, and the derived broker trusts certifi as well as the fixture CA | fixed | Before phase A, every fixture name must resolve, from the broker, only to addresses inside the run's subnet, or the run fails | Re-run `20261106T041229Z` passed the check |
| 9 | info | Record accuracy | The EDR's run ID did not match the committed measurement | fixed | EDR cites `20261106T034456Z` and the re-run | — |

## Re-review
Not needed for severity: no high or critical findings. The code fixes (1, 3, 8) were
verified by the re-run. The plan fixes (2, 4, 5, 6, 7) change a proposed plan; it gets
its own review with increment 1, as the plan requires.
