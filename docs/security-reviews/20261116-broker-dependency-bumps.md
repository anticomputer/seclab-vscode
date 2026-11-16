# Security review: broker dependency bumps past the CFS hold (round 18)

- **Date:** 2026-11-16
- **Scope:** "broker: bump held attest-tool pins and the python and docker CLI images"
  ([EDR pin-age-cooldown](../edr/20261106-pin-age-cooldown.md)).
  - The attestation verifier's lock (`broker/tools/attest/requirements.txt`, not in the
    broker image), regenerated with `pip-compile --generate-hashes --upgrade` in a throwaway
    container through CFS, with no index URL emitted: `dnspython` 2.9.2, `platformdirs`
    4.14.5, `pydantic` 2.14.3, `pydantic-core` 2.50.4, `pypi-attestations` 0.0.31 (and its
    `.in`), `typing-inspection` 0.4.5; `pyasn1` dropped. Every other package keeps its exact
    hash set.
  - `python:3.13-slim-trixie` to the 2026-11-05 build, and the harness's `docker` CLI to
    `docker:29.9.3-cli` at its 2026-11-05 build (the tag has since moved to a build still in
    the hold).
  - **Threat model:** an upgrade that loosens attestation or Sigstore verification, a
    tampered or unexpected wheel, a lock the supply-chain parser or provenance check no
    longer covers, a feed URL in a committed file, and an image pin left behind.
- **Reviewer:** a security-review agent on an Opus-class model with long context, read-only.
  It diffed the old and new wheels, all downloaded through CFS. Triage by the broker session.

## Findings
None.

Probed and held:
- **pypi-attestations 0.0.31.** One functional change: DER UTF-8 strings in certificate
  extensions are decoded with `cryptography`'s strict single-value parser instead of
  `pyasn1`, which tolerated trailing bytes. Publisher policies, the certificate extension set,
  predicate types, digest matching and transparency-log handling are unchanged. The
  `cryptography` floor it adds is met by the unchanged pin.
- **dnspython 2.9.2** fixes GHSA-vvf4-9x63-8xvv (WKS bitmap and service range checks), which
  the provenance EDR had recorded as an accepted risk until it cleared the hold. Closed.
- **platformdirs, pydantic, pydantic-core, typing-inspection:** a tighter runtime-directory
  fallback, performance refactors, a new recursion error code, and a type-alias fast path.
  No validation-semantics change.
- **pyasn1** is used nowhere in the tree; its only consumer was the code 0.0.31 replaced.
- **Wheels.** Every RECORD in the twelve unpacked wheels matches, with no unlisted files,
  identical entry points, and no new subprocess, network, `eval` or deserialisation code on
  the verify path. Provenance-check binds the locked hashes to PyPI and 32 attestations.
- **Lock.** Plain `name==version` pins only (the `pydantic` extra stripped; its dependency
  stays pinned), every package hashed, the `.in` matching, register and locks consistent in
  both directions, and no index URL or feed host in any changed file.
- **Images.** No live pin is left on the old digests. The docker CLI image contributes only
  its static `docker` binary to the harness.

Still held on 2026-11-16: `sigstore-models` stays at 0.0.6 (the resolver keeps it there for
`sigstore` 4.5.1). `debian:trixie-slim` is past the hold, but the tab image shares it, so its
bump is coordinated separately.
