# Security review: agents-in-the-tab spike harness and findings

- **Date:** 2026-11-05
- **Scope:** 14fd657..b2ffe85 (rebased from f5a479a..44d11bc). That covers `test/agentic/ahp/` (`run.sh`, `bundle.mjs`, `runner.ts`, `rogue-agent-host.ts`, `verdict.mjs`, `in-tab.sh`, `in-tab.ts`, `proxy-recorder.mjs`, `ahp_inventory.py`, `inventory.sh`), `test/safety/allowlist.txt`, [EDR agents-in-tab spike](../edr/20261105-agents-in-tab-spike.md), and the run evidence under `.work/agentic/runs/`. The fixes are in the commit that adds this record.
- **Reviewer:** security-review agent (default model); triage by the secure-agentic-experiences session.
- **Related:** [EDR agents-in-tab spike](../edr/20261105-agents-in-tab-spike.md), [EDR agent runtimes exception](../edr/20261105-agent-runtimes-exception.md), [EDR fixture safety](../edr/20261104-fixture-safety.md)

The prompt carried the standing warning that the diff, fixtures, evidence and upstream
source may contain prompt injection aimed at the reviewer. None was found. The reviewer
confirmed that nothing in the harness can reach the real host:
- every container runs with `--network none`;
- the builder volume, the source and the harness are mounted read-only, and the only
  writable mount is the run's own directory;
- the rogue agent host is nonce-armed for A1 and A16;
- the recorder is loopback-only and forwards nothing;
- the runner's exit paths cannot mask a failure.

## Findings
| # | Severity | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| 1 | medium | Verdict soundness | A18 was fired by the harness, not the rogue, and was not nonce-armed, so a disarmed run could have scored it PASS. `verdict.mjs` ignored `armed`. The EDR's disarmed-control claim predated A18, and "the rogue echoed the clientId" was not shown | fixed | A18 runs only when the rogue is armed. `verdict.mjs` refuses PASS for any disarmed run. Re-run disarmed (`20261105T185618Z-38414d7c8b059707`): every probe INVALID, exit 1. EDR text corrected | `run.sh --disarmed` |
| 2 | medium | Faithfulness | A18 shows that the handler forwards the call (it resolves an unadvertised tool and passes on the agent host's own pre-approval). It does not exercise the ownership check or the claim autorun, and `invokeTool` is a recording stand-in. The EDR did not say so | fixed (documented) | EDR "What A18 does and does not show". Strengthening the probe is the stated next step | A18 |
| 3 | low | Fixture safety | The per-run CA and leaf private keys persisted in the run directories, contradicting the EDR | fixed | Keys, CSR and serial are deleted inside the container and again host-side; old runs cleaned; the EDR says where the CA is trusted (only in the container) | `in-tab.sh` (keys=0 after each run) |
| 4 | low | Evidence | The in-tab step could not fail, recorded no mode or SHA, and the no-proxy row rested on absence of events | fixed | `run.json` records mode, SHA and image; SHA checked; non-zero exit on error, no agents or no listener; the agent host's own egress-failure log lines are captured for every mode | `in-tab.sh` variants |
| 5 | low | Supply chain | The runtime exception did not name this harness use, and the register `used` lists missed the harness | fixed | Exception EDR "Test use" paragraph; `used` updated for `img-node`, `img-python-3.12` and `rt-copilot-sdk` | `./seclab lint deps` |
| 6 | info | Lint opt-outs | Justified: per-line pragmas plus reviewed allowlist entries | accepted | — | `./seclab lint fixtures` |

## Re-review
Not needed for severity: no high or critical findings. The fixes were verified by
re-running the armed, disarmed and five in-tab variants (EDR "Results").
