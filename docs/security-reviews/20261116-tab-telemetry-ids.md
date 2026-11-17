# Security review: telemetry ids stay out of tabs (release check and product invariant)

- **Date:** 2026-11-16
- **Scope:** origin/main..branch head: `build/check-release.sh` (telemetry check and self-test),
  `build/product/product.jq` (invariant), `test/telemetryid`, the DOCSYNC-R1/R4 register entries.
  - Round 1: `ebe6d08b` and the register commit on `32674b61`.
- **Reviewer:** security-review agent (an Opus-class model), triage by the document-sync session. Finding IDs `TEL-n`.
- **Threat model:** a rogue extension owns the tab's extension host. Host telemetry ids (machine,
  SQM, device, session) must not reach it. The release check must catch any shipped app whose
  product turns telemetry on.
- **Related:** [EDR tab-telemetry-ids](../edr/20261116-tab-telemetry-ids.md).
- **Prompt injection:** none found.

## Findings
| # | Sev | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| TEL-1 | Low | release check | The check matched the literal name, but the app parses JSON: `"enable\u0054elemetry": true` after the real key passes the text match, and the last duplicate wins in JSON.parse. Only a file tampered with after the build has it (jq writes no escapes). | fixed | Any `\u` in a product.json fails; the shipped files have none. | build/check-release.sh self-test "product.json with an escaped duplicate enableTelemetry true (review TEL-1)" |
| TEL-2 | Low | run time | `isBuilt` is `!VSCODE_DEV`, read from the window's environment, which takes the launching CLI's. A host process that opens a tab window with `VSCODE_DEV=1` gets a real telemetry service, and that tab the real ids. A tab can't set it; neither check sees it. | accepted-residual | Host-only precondition, outside the threat model; kept as a residual with no patch (coordinator, 2026-11-16). | none |
| TEL-3 | Info | harness | The probe seeded SQM and device ids but checked only `machineId`. | fixed | It checks `machineId`, `sessionId` and `devDeviceId` (where readable) against every seeded id. | test/telemetryid/probe.ts "no id the tab can read is any seeded host id (machine, SQM, device)" |

The reviewer confirmed: the `prods` set covers both shipped product.json files and fails closed
when none is found; CRLF, comments and nested decoys are handled; GNU and BusyBox grep agree; the
product.jq invariant stops `prepare.sh` (`set -euo pipefail`) in both build scripts; with
telemetry off the init data carries only placeholders, and REH-side telemetry sees only the
tab's own machine. No high or critical finding.

## Copilot review (PR #12)
Three threads from the automated pull-request review, triaged against the code after the merge
and fixed in a follow-up.

| # | Sev | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| TEL-4 | Low | release check | The check took one-tab indentation as the root level, so a nested `"enableTelemetry": false` indented like a top-level key passed it while the root key was missing. A missing key leaves telemetry off, so no ids flowed; the gate didn't check what it claimed. | fixed | The key must be on its own line at JSON depth 1, counted from braces and brackets outside strings. | build/check-release.sh self-test "a nested enableTelemetry false indented as if top level (TEL-4)" |
| TEL-5 | Info | harness | The nbsync probe's prepare, launch, check flow read the serializer refusal only in `drive`, so it couldn't pass on a filtered build. | fixed | `check` reads the window's decision log itself, before teardown; the flow passed on main `6589051b`. | none |
| TEL-6 | Info | harness | The telemetryid and nbsync profiles (and the docsync and configsync ones) were shared by every worktree, while each run's guard is per worktree, so one worktree's run could wipe or tear down another's. | fixed | Each profile name carries a hash of its worktree. | none |
