# Security review: gates that pass when their config or input can't be read

- **Date:** 2026-11-12
- **Scope:** every CI and local gate reached from `seclab` and `.github/workflows/*.yml` at
  `81b2b10`, audited for one defect class: a config, input list, register, rule file, log or
  argument that is missing, empty, unreadable or unparseable, and the gate still passes. Also
  near-variants: a list or glob that matches nothing; a swallowed read or parse error;
  `|| true` and `2>/dev/null ||` in wrappers; a missing argument defaulting to "nothing to check".
  Prompted by GATE-1 ([the agentic gate record](20261106-agentic-ahp-gate.md), on its branch):
  `soleConsumerProblems` returned no problems when its config was missing.
- **Reviewer:** an audit agent (an Opus-class model), read-only; triage by the
  findings-register session. GATE-2 and GATE-3 were confirmed by reading
  `build/check-patch-reach.ts` and `build/apply-patches.sh`.
- **Threat model:** a gate that verifies nothing while printing success. A required check on
  main that can be emptied that way is a silent removal of a security invariant.
- **Prompt injection:** none found. The instruction-shaped regexes in the fixture lints are
  detectors.

## Findings
About 45 gates were confirmed fail-closed. Among them, `build/liveness/liveness.ts` and
`test/containment/check-probes.ts` already implement the right pattern (a missing input is a
problem), and they are the model for the fixes below. All findings are open and owned by the
sessions named in the register.

| # | Sev | Area | Finding | Disposition | Fix / recommendation |
|---|---|---|---|---|---|
| GATE-2 | High | patch-build | `check-patch-reach.ts` reads a missing `patches/unreachable.json` as `{}`, so invariant I8 (no agent-host code reachable from the desktop app) checks nothing and passes; `apply-patches.sh` exempts the file, so nothing else notices. | Open | Fail when the file is missing; a deliberately empty rule set must be an explicit `{}` in the tree. |
| GATE-3 | High | patch-build | The same for `patches/reach.json`: per-patch target pinning for security patches silently stops applying. | Open | As GATE-2. |
| GATE-4 | Medium | lint pins | `check-pins.ts` reports `clean (0 files)` on an empty or truncated file list; no reverse check. | Open | Fail on an empty list, and cross-check that known pinned files were scanned. |
| GATE-5 | Medium | fixture lint | `fixture-lint --av` reports `clean (0 tracked files)` on an empty list. | Open | Fail on an empty list. |
| GATE-6 | Medium | fixture lint | A missing default root is only noted; with every root absent the lint scans nothing and reports clean. | Open | Fail when nothing was scanned. |
| GATE-7 | Medium | scanners | `check-pins.ts`, `deps.ts` and `fixture-lint.ts` skip a tracked file they can't read, without recording it. | Open | Report unreadable tracked files as problems. |
| GATE-8 | Medium | image verification | Locally, the existence of `.work/deps-verified/<key>` skips cosign and attestation verification; the marker's content is never checked. | Open | Bind the marker to the verified result (or re-verify); CI already re-verifies. |
| GATE-9 | Medium | broker docs | `broker/tools/docs.py` `commands()` emits an empty script when a doc lost its `ci: run` blocks, and `--run-commands` passes. | Open | Fail on zero blocks, as `build/docs/docs-check.ts` does. |
| GATE-10 | Medium | focus harness | A missing focus-steal log reads as "the editor never took focus"; nothing proves the watcher was alive. | Open | A watcher heartbeat or start marker that teardown requires. |
| GATE-11 | Medium | AHP inventory | `ahp_inventory.py` exits 0 with scanner gaps in `problems`. | Open (fixed with a test on the agentic branch, unlanded) | Exit non-zero when `problems` is non-empty, as the self-test does. |
| GATE-12 | Medium | rpc-filter tests | `rpc-filter/tools/test.sh` drops the upstream-driven tests without an upstream checkout, which is the normal path in the required `unit` job. | Open | Make the skip explicit in CI, or run the upstream tests where the tree exists. |
| GATE-13 | Low | pre-push hook | `pre-push` exits 0 when it receives no ref lines. | Open | Fail when no ref was checked. |
| GATE-14 | Low | pin age | `pin-age` dates no npm pins on an empty list; `--days 0` passes everything. | Open | Fail on an empty npm list; refuse `--days 0`. |
| GATE-15 | Low | lint pins | The `supplychain.py` purity probe in `check-pins.ts` sits in a swallowing `catch`. | Open | Fail when the file can't be read while it is skipped by name. |
| GATE-16 | Low | lint source | `check-source.ts` scans only `tabd/src` when `extensions/series` is empty. | Open | Fail on an empty `extensions/series`. |
| GATE-17 | Low | cleanup | `seclab` masks a best-effort image prune with `\|\| true`; it certifies nothing. | Open | None needed beyond keeping it out of any gate. |
