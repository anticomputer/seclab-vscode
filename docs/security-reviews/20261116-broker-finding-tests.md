# Security review: regression tests for broker findings, and MODEL-R4 (round 19)

- **Date:** 2026-11-16
- **Scope:**
  - "broker: regression tests for four medium fixed-untested findings": `build.sh --label` and
    the label probes (10-1), `broker/tests/verify-images` (provenance 3),
    `broker/tests/provenance` with `verify_file(offline=...)` (provenance 5), and the GATE-9
    self-test renamed with named cases.
  - "broker: GHE.com Copilot hosts are known model hosts": an anchored-pattern entry form in
    `model-hosts.v1.json`, checked at policy load, and `copilot*.<tenant>.ghe.com` as a known
    model host (MODEL-R4); the register entry that follows.
  - **Threat model:** a test-only mode that changes what is built or labelled, an `offline`
    flag that reaches the gate, tests that pass vacuously or touch anything outside their
    scratch, a host pattern that matches too much or loads malformed data, and any change that
    makes the broker more permissive.
- **Reviewer:** a security-review agent on an Opus-class model with long context, read-only.
  Triage by the broker session, which mutation-checked each new test against its finding's
  original defect.

## Findings
None.

Probed and held:
- **`--label`** prints the label and exits before any context or image work; a tag named
  `--label` builds nothing. The snapshot is still the first thing read, and the label comes
  from the build's own dirty checks.
- **`offline`** defaults to false, and the gate's only call passes none; the policy still comes
  from the register and the digest from the pin.
- **Tests.** The verify-images test asserts the exact `gh attestation verify` arguments and
  call count; its fake `gh` is on `PATH` for that one invocation only. The provenance test runs
  with no network and includes a passing case, so it can't pass vacuously. All scratch is
  removed on exit.
- **MODEL-R4.** The pattern is anchored and `fullmatch`ed against normalised hosts; malformed
  data fails at policy load. The change only adds denials: a known model host gets the model
  gate, and nothing downstream is relaxed. A tenant CAPI host not named `copilot*` is still
  outside the match, as the ADR records.
- **Data.** The recorded provenance is public PEP 740 attestation material; its subject digest
  is the pinned wheel's.
