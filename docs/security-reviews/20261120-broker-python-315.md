# Security review: broker Python base image 3.13 to 3.15 (round 21)

- **Date:** 2026-11-20
- **Scope:** "deps: broker python base image 3.13 to 3.15". The broker's Python tool images move
  from `python:3.13-slim-trixie` to `python:3.15-slim-trixie` (3.15.2, its Docker Hub tag pushed
  2026-11-07, past the 7-day hold):
  - the integration harness and upstream images;
  - the attestation verifier;
  - the CFS path test;
  - verify-images.sh's register reader.

  `broker/deps.json`, the dependency register and the supply-chain self-test vectors follow.
  The broker image itself stays on mitmproxy's base.
  - **Threat model:**
    - a stale pin left in something that builds or runs;
    - a lock whose installed wheel escapes attestation on the new interpreter;
    - a register field that no longer describes its pin;
    - any weakened gate.
- **Reviewer:** a security-review agent on an Opus-class model with long context, read-only.
  The broker session triaged it.

## Findings
| # | Severity | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| BRK21-1 | Low | dependency register | The python image's register entry (`purpose`, `used`) and `broker/deps.json` (`usedBy`) left out `broker/tests/cfs-path/run.sh`, which runs the image. This predates the bump. No gate is affected: the pin itself is registered and matched tree-wide. | fixed-untested | The entry now names the CFS path test and verify-images.sh's register reader. Nothing checks `used` against the tree (the register check in `build/deps.ts` validates pins only), so no test can pin this. | none |

Probed and held:
- **No stale pin.** The old digest appears nowhere in the tree. The remaining `3.13` text is in
  append-only records, one interpreter-agnostic rejected-installer vector, and an `ssl` note that
  still holds on 3.15.
- **Provenance.** The verifier's base and the purity partition are unchanged: all three native
  images moved together. A lock installed outside the verifier's base is still forced to
  `py3-none-any`. The verifier's own lock is matched against its own tags, now 3.15 on both
  sides, so a `cp313`-only pin fails closed: no applicable wheel, and the binary-only install
  fails first. The provenance check verified all 35 attestations on 3.15.
- **verify-images.sh** uses only `json` and `re` in `python -I`; it behaves the same on 3.15.
- **Gates.** The supply-chain and pin-check self-tests pass; the edited vectors are cosmetic.
- **Prompt injection.** None found.
