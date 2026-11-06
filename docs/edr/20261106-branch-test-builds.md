# Branch test builds of the macOS app

- **Status:** accepted
- **Date:** 2026-11-06
- **Deciders:** Coordinator (the RPC core filter's landing waits on a real-app test of the unlanded patches). Fork-build session: implementation.
- **Related:** [CI hardening](20261104-ci-hardening.md), [patch-build gate](20261105-patch-build-gate.md)

## Context
`build-macos.yml` uploaded the app only from main, so a dispatched build of a branch was a
compile check with nothing to run. A core patch, such as the RPC capability filter that
closes host code execution from a tab, must be shown working in the shipped app before it
lands (AGENTS.md: a patch isn't done until a runtime probe shows it running). That needs the
branch's own build.

## Decision
- A `workflow_dispatch` run on a non-main branch uploads the attested build as a separate
  artifact, `seclab-vscode-darwin-arm64-branch`, kept for 3 days. Main push builds keep the
  release artifact name; nothing else changes for them.
- `./seclab fetch macos-branch RUN_ID` accepts only a successful dispatched run of a non-main
  branch. It enforces the same checks as a release fetch:
  - the required checks (`unit`, `lint`, `docs`) succeeded on the branch head;
  - SHA256SUMS matches;
  - `gh attestation verify` passes with `--source-ref refs/heads/<branch>`, the head SHA,
    this repo's `build-macos.yml` as signer and hosted runners only.

  It extracts into `.work/app-branch/`, never `.work/app/`, so a test build can't stand in
  for a release.
- `./seclab fetch macos` is unchanged: main push builds only.

## Consequences
- An unlanded branch can be tested in the real app with the same provenance bar, before it
  lands.
- A branch build is unreviewed code. It is for test profiles only; the release path never
  reads it.
