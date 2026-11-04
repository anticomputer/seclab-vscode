# Security reviews

Every major change gets a recorded security review round. This directory is
the process and the index.

## When a review is required
- A new component, trust boundary or privileged code path.
- A new or changed patch in `patches/`.
- `product.json` policy changes (the jq program or its data).
- A provider, fence or transport change (`SandboxProvider` implementations,
  sbx or docker invocations, resolver transport, broker wiring).
- CI and workflow changes: token `permissions:`, triggers (never
  `pull_request_target`), third-party actions (pin by SHA), artifact
  provenance.
- Each milestone, before it is called done.

## How to run a round
1. Fix the scope to a commit range (`git diff <base>..<head>`) plus the threat
   model in [ARCHITECTURE.md §2](../ARCHITECTURE.md#2-threat-model).
2. Run the `security-review` agent on that scope. If it refuses, re-run it
   with model an Opus-class model.
3. Triage every finding: **fixed** (with commit), **accepted** (with reason)
   or **false positive** (with reason).
4. Re-review after fixes until no **high** or **critical** findings remain
   open.
5. For every real finding, add a regression test to the containment suite.
6. Record the round here, and link it from the related ADR or EDR.

## Record format
File: `YYYYMMDD-short-slug.md`.

```markdown
# Security review: <scope title>

- **Date:** YYYY-MM-DD
- **Scope:** <base sha>..<head sha> (+ files/areas given explicit attention)
- **Reviewer:** security-review agent (<model>), triage by <session>
- **Related:** <ADR/EDR links>

## Findings
| # | Severity | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|

## Re-review
<range, result: "no open high/critical">
```

## Index

| Date | Review | Scope | Open high/critical |
|---|---|---|---|
| 2026-11-04 | [seclab-tabd design (protocol, process model)](20261104-tabd-protocol-design.md) | design docs before code | 1 critical (REH server→client IPC; owned by M4) |
| 2026-11-04 | [M0 pipeline, tabd, Tab Manager, containment suite, pre-mount secret scan](20261104-m0-tabd-code.md) | 296594c..d02dec5 (rounds 1–11) | none (scanner series closed in round 11) |
| 2026-11-04 | [Test fixtures are host-safe](20261104-fixture-safety.md) | d02dec5..cf6738e + test trees | none (2 rounds) |
| 2026-11-04 | [Patch queue and release guard](20261104-patch-guard.md) | patches/series, extensions/series, check-source, check-release | none |
