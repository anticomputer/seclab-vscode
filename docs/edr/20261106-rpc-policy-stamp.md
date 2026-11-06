# RPC filter stamp in product.json

- **Status:** accepted
- **Date:** 2026-11-06
- **Deciders:** Coordinator (from the RPC session's handoff; observability chose option 2: detect a build with the RPC filter absent from a product.json stamp). Fork-build session: implementation.
- **Related:** [patch series](20261104-patch-series.md), [test build variants](20261106-test-build-variants.md)

## Context
Observability needs to tell, from a running build, whether the RPC capability filter (patch
0005) is in it. The filter's policy table is a generated file that 0005 creates,
`src/vs/workbench/services/extensions/common/seclabPolicyData.ts`. `prepare.sh` writes
product.json at step 3 and applies patches at step 4, so a stamp of the applied table needs a
second pass.

## Decision
- **Stamp** (`prepare.sh` step 7): after patching, product.json gets
  `seclabRpcPolicy {sha256, file}`, with the sha256 of the applied table. The stamp is
  present if and only if `patches/series` lists 0005. The build refuses each of these:
  - 0005 is listed but the table is missing (or is a symlink);
  - the table exists without 0005;
  - product.json already has the key before stamping, for example from upstream or the
    overrides.
- **Check** (`check-release`): every app product.json in an artifact, outside extensions and
  node_modules, must match what `patches/series` implies. With 0005 listed, the stamp must
  equal the sha256 of the table that 0005's new-file hunk creates. Without 0005, there must
  be no stamp. Both directions fail. The expected hash comes from the reviewed patch, not from
  the build, so a build can't vouch for itself.
  - If another listed patch also changes the table, the expectation can't be derived, and the
    check fails closed until this check is extended.
  - No pipelines in the derivation: dash, the builder's `/bin/sh`, has no `pipefail`, and a
    failed extraction must never hash to a value.
- **Self-test:** `sh build/check-release.sh --self-test` runs in ci-unit. It covers no 0005
  with no stamp, 0005 with the right hash, a missing stamp, a stamp without 0005, a wrong
  hash, a table without a final newline, a second patch touching the table, and no
  product.json at all. It passes under macOS sh, dash and busybox.

## Consequences
- **What the stamp proves** (review DDD-3): the reviewed policy table that 0005 creates was
  applied to the source this build came from. It doesn't prove that the enforcing code was
  bundled, or that the rest of the filter series (0006–0011) is listed. Observability
  should label it "RPC policy table applied (hash)", not "filter active". A stronger signal
  would be a literal emitted by the table and required in the built JS, as the test hooks'
  markers are; that is passed to the RPC session.
- Review DDD's other fixes:
  - an expectation that isn't `absent` or a sha256 fails, as does a missing or failing hasher;
  - the series is read on its own, so a read error fails;
  - product.json must carry exactly one `seclabRpcPolicy`;
  - the self-test also covers a commented-out 0005, a CRLF series and a duplicate nested key.
- Checked against the real 0005 on the RPC branch: the hash derived from its hunk equals the
  sha256 of `rpc-filter/patch-src/seclabPolicyData.ts`.
- Every check-release run now also needs `patches/`: next to the script, or mounted
  read-only at `/patches` in the container path.
- Until 0005 lands, every release build is checked to have no stamp. When it lands, every
  release build must carry the matching stamp, with no further change here.
