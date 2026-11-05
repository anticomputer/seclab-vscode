# Broker dependency provenance: every dependency registered, pinned, and verified at use time

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** anticomputer (user). Verbatim: "make sure that any dependency we pull in has a strong security provenance". Coordinator (the bar); broker session (implementation). The repo-wide register `deps/registry.json` is owned by the Fork-build session; `broker/deps.json` holds the broker's entries.
- **Related:** [EDR engine](20261104-broker-engine-mitmproxy.md), [security review](../security-reviews/20261104-broker-dependency-provenance.md)

## Context
The project's bar: every dependency must meet one of these tiers. Anything else
needs an approved exception, recorded in an EDR.
- **attested:** signed or attested by its publisher, and verified at use time;
- **hash-pinned:** pinned by digest or hash from the project's own official
  source, with checksums verified;
- **built-from-source:** built by us from pinned source.

Before this change the broker pinned every base image by digest, and every pip
install used `--require-hashes`. Nothing yet checked publisher signatures or
attestations, or that a pinned hash is the artifact the project actually
publishes.

## Decision
**`broker/deps.json` is the broker's register.** It records every image, Python
pin, system package set and host tool, with its tier, source and, for attested
entries, the expected publisher identity. Two checks keep it honest.

**Offline: `tools/pin_check.py`** (run by `docs-check.sh`, so in CI and
`test.sh`). It fails if:
- a Dockerfile `FROM` is not digest-pinned, or not in the register;
- a `pip install` lacks `--require-hashes`;
- a requirements pin lacks a hash, or is not in the register.

So nothing can be added without a register entry.

**Online: `provenance-check.sh`** (run by `test.sh`; it fails closed). It runs
two parts:
- **Python** (`tools/provenance.py verify`, in the hash-locked verifier image
  `tools/attest`). For every pin:
  - every pinned sha256 must be a file PyPI serves for that release;
  - a pinned wheel must install on this platform (no source builds).
  - For files that apply here, the PEP 740 publisher (kind, repository,
    workflow) must match the register. A dropped attestation, or a new
    repository or workflow, fails the check.
  - Each attested file is then verified cryptographically with PyPA's
    `pypi-attestations` (sigstore) against the repository **recorded in the
    register**, never the one the provenance claims.
- **Images** (`tools/verify-images.sh`, also run by `build.sh` before every
  build). Attested images are checked with `gh attestation verify` against the
  exact signer workflow, source ref and source commit in the register.

**Findings** (2026-11-04):

| Dependency | Tier | Evidence |
|---|---|---|
| `mitmproxy/mitmproxy:12.3.1@sha256:2711066c…` (broker base) | **attested** | Sigstore-signed SLSA build provenance (`actions/attest-build-provenance`). Signer `mitmproxy/mitmproxy/.github/workflows/main.yml@refs/tags/v12.3.1`, source commit `51c1d6b2…` (the commit the broker's code citations use), GitHub-hosted runner. It covers mitmproxy and its whole Python closure inside the image. |
| `python:3.13-slim-trixie`, `debian:trixie-slim`, `docker:29-cli` (test and tool images) | hash-pinned | Docker Official Images pinned by index digest. They carry in-registry BuildKit SLSA provenance bound to that digest, but **no publisher signature**: `cosign tree` finds no sigstore artifacts, and Docker Content Trust is being retired. |
| Python: 43 pins across the broker runtime, unit tests, integration images and the verifier tool | 25 attested, 18 hash-pinned | Every pinned hash is a PyPI-served file. 32 attestation files verified for linux/arm64. |
| Broker runtime Python: `fastjsonschema` 2.22.3 | hash-pinned | The project publishes no attestations; pinned by sha256 from PyPI, its official index. |
| apt packages in the two test images | attested (Debian archive signature) | apt verifies the signed `InRelease` against `debian-archive-keyring` from the digest-pinned base, and each package's sha256 from the signed index. Versions are not pinned (see below). The broker image installs no apt packages. |
| `seclab-broker`, `seclab-attest` images | built-from-source | Built from this repository's Dockerfiles, using only registered inputs. |

Every broker dependency meets the bar. **No exception is needed.**

## Alternatives considered
- **Rebuild the broker on `python:slim` plus a hash-locked `pip install
  mitmproxy`:** rejected. It would drop the strongest artifact we have (a
  signed, source-commit-bound image provenance), and gain only that the Python
  closure is pinned by us rather than attested by mitmproxy's CI. It would also
  pull ~30 more packages into our register.
- **Pin apt via `snapshot.debian.org`:** tried and rejected. The base images
  record their snapshot timestamp, and apt 3 can use it, which would make apt
  versions as fixed as the base digest. In practice snapshot.debian.org ran at
  ~217 kB/s and dropped a package (`liblmdb0`) mid-build. That makes CI flaky
  for test-only images whose packages are already signature-verified by apt.
  Revisit if a reliable snapshot mirror is available.
- **Verify attestations for every platform's wheel:** rejected. The verifier's
  lock pins every platform wheel (cffi alone has 100 files), which costs
  hundreds of requests per run. We verify the files that can install on the
  running platform, which is the use-time artifact; CI covers linux/amd64.
- **Treat in-registry BuildKit provenance as "attested":** rejected. It is
  bound to the digest we already pin, but it is not signed by the publisher, so
  it adds no trust beyond the digest.

## Consequences
- **`broker/build.sh` and `broker/test.sh` now need network access and `gh`.**
  Both are present in CI; locally, `gh` is a user-approved host tool. A PyPI or
  GitHub outage fails the gate rather than skipping it.
- **Adding or bumping a dependency** means updating the lock, then
  `broker/deps.json`. The tier and publisher come from `python
  broker/tools/provenance.py report …` inside the verifier image.
- **Watch items:** if `fastjsonschema`, `h11`, `h2`, `hpack`, `hyperframe`,
  `priority`, `wsproto` or `pygments` start publishing attestations, the check
  prints a note so their tier can be raised. If the Docker Official Images gain
  cosign signatures, move them to attested.

## Evidence
- `broker/provenance-check.sh` on 2026-11-04: `provenance: ok (43 pins, 32
  attestations cryptographically verified)` and `verify-images: ok
  mitmproxy/mitmproxy@sha256:2711066c… (signed by
  mitmproxy/mitmproxy/.github/workflows/main.yml @ refs/tags/v12.3.1)`.
- **Negative tests:**
  - a register publisher changed to `pytest-dev/not-pytest` fails both the
    metadata check and sigstore verification;
  - a wrong source digest for the mitmproxy image fails
    `gh attestation verify`;
  - `pypi-attestations` exits 1 on a wrong repository.
- `cosign tree` (cosign v2.6.1 pinned by digest) on each pinned image digest:
  no sigstore artifacts.
- mitmproxy release workflow at `v12.3.1`: `.github/workflows/main.yml` uses
  `actions/attest-build-provenance` for both the image and the release
  artifacts.
