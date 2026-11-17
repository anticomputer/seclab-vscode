# Review: automated PR review threads on the RPC follow-ups (#9, #14, #20)

- **Date:** 2026-11-17
- **Reviewer:** GitHub's automated pull request reviewer, on PRs #9, #14 and #20 after they
  merged. Each thread was checked against the code; the review text was treated as data.
- **Subject:** `check_drift.py`'s log-trust gate (#9), the rogue-REH profile probe and the probe
  lint (#14), and the host-terminal proof harness (#20).

## Verdict
All five threads point at real gaps. Two are as stated. One wasn't as stated but hid a wider gap.
Two were narrower than stated. None is exploitable on main; each is a gate or harness that
could pass, or leave things behind, for the wrong reason.

| ID | Sev | Component | Finding | Status |
|---|---|---|---|---|
| PRR-1 | low | `check_drift.py` `check_log_trust` (#9) | The logger check walked only keys the inventory found. A `$log` the inventory lost, with an allow entry policy.json could still emit, would have passed the gate | fixed |
| PRR-2 | low | `lint_probes.py` (#14) | The thread said the computed key in `rogue-reh/probes.js` failed the lint; on main it didn't, which pointed to a wider gap. The lint blanked whole comment lines, which dropped a block comment's closing `*/`, so the scanner read the code after it as comment. Most of a payload was hidden from the record and clipboard rules. With comments stripped properly, that computed key was the only violation | fixed |
| PRR-3 | low | `check-probes.ts`, expectations (#14) | The five REH probes the payload arms only on the reh-push path were required by every REH evidence check, so a full run without that selection failed them. No harness runs such a check today | fixed |
| PRR-4 | low | proof harnesses (#20) | A rerun after an interrupted or `KEEP=1` run wiped the previous `run.json` and tab state before reaping them, orphaning that run's tabs and processes | fixed |
| PRR-5 | low | proof harnesses (#20) | Ctrl+C or SIGTERM skipped the teardown gate: Node's default handling for both signals runs no `exit` handler | fixed |

## What changed
- PRR-1: `MainThreadLogger.$log` joins the presence-pinned must-deny set. A
  `LogTrustGateTest` case deletes it from the mapping and expects the gate to fail.
- PRR-2: comments are stripped with a scanner that keeps strings, and the computed key is a
  literal. `CommentScopeTest` fails on the old line blanking.
- PRR-3: those probes carry `runner: reh-push`. Without that selection they are reported as
  not judged, never as passed; with it, a missing result still fails. There is a
  `check-probes.test.ts` case for each.
- PRR-4, PRR-5: `teardown.ts` gains two helpers, and `host-terminal.ts` and `reh-push.ts` use
  both:
  - `reapOrRefuse`, which reaps the previous run from its manifest, or refuses to wipe it;
  - `exitOnSignals`, which ends the process through `exit` on SIGINT or SIGTERM.

  `harness-hygiene.test.ts` checks the signals in a child process, and the ordering on each
  harness's source, against mutants.
