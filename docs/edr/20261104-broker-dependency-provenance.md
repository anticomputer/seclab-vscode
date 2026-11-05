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
`test.sh`). It uses the strict parsers in `tools/supplychain.py`, shared with
the online check, so both gates see exactly what pip and BuildKit act on. Any
form they would honour that the parser does not understand is an error, never
a skipped line. It fails if:
- a requirements file has anything but plain `name==version` pins followed by
  `--hash=sha256:<64 lowercase hex>`. That rules out extras, direct URLs,
  markers, other operators, `-r`/`-c`/`-e`, index and find-links options,
  other hash algorithms or spellings, and uppercase digests;
- a pin is not in the register, or a requirements file is not installed by any
  Dockerfile (its target interpreter would be unknown);
- a Dockerfile `FROM` is not digest-pinned, or not in the register;
- a Dockerfile has a parser directive (`# syntax=` makes BuildKit run an
  unpinned frontend image), `ADD`, `ONBUILD`, `RUN` flags, `COPY --from=`
  anything but an earlier stage, or pip configuration (`PIP_*`, `pip.conf`);
- a Python install is anything but exactly `pip install --no-cache-dir
  --no-deps --require-hashes --only-binary=:all: -r <path>`, where `<path>` is
  the destination of a `COPY` of one checked requirements file.

So nothing can be added without a register entry. `pin_check.py --self-test`
(also run by `docs-check.sh`) proves that every bypass form found in review is
rejected.

**Online: `provenance-check.sh`** (run by `test.sh`; it fails closed). It runs
two parts:
- **Python** (`tools/provenance.py verify`, in the hash-locked verifier image
  `tools/attest`). It discovers the same files as `pin_check.py`. For every
  pin:
  - every pinned sha256 must be a file PyPI serves for that release;
  - the files that apply are those pip could install into the lockfile's
    target interpreter. A lockfile installed into the verifier's own base is
    matched against its tags. A lockfile installed into any other base (the
    mitmproxy image) may pin only pure `py3-none-any` wheels, so every file
    that could be installed is the one verified. Installs are binary-only, so
    no sdist is ever built.
  - For applicable files, the PEP 740 publisher (kind, repository, workflow)
    must match the register. A dropped attestation, or a new repository or
    workflow, fails the check.
  - Each attestation is then verified cryptographically (sigstore DSSE, PyPA's
    `pypi-attestations` library). It is checked against a distribution whose
    digest is the **pinned sha256**, under a Trusted Publisher policy built
    from the **register's** repository and workflow. The provenance is fetched
    once, so the bytes whose publisher was compared are the bytes verified.
    The signature must cover exactly the pinned file and come from the
    registered workflow, and neither link relies on PyPI's metadata being
    honest.
- **Images** (`tools/verify-images.sh`, also run by `build.sh` before every
  build). Attested images are checked with `gh attestation verify` against the
  exact signer workflow, source ref and source commit in the register, with
  `--deny-self-hosted-runners`. The image list is produced and validated before
  any check runs. An empty or malformed register fails, and "ok" is printed
  only if every attested image verified.

**Findings** (2026-11-04):

| Dependency | Tier | Evidence |
|---|---|---|
| `mitmproxy/mitmproxy:12.3.1@sha256:2711066c…` (broker base) | **attested** | Sigstore-signed SLSA build provenance (`actions/attest-build-provenance`). Signer `mitmproxy/mitmproxy/.github/workflows/main.yml@refs/tags/v12.3.1`, source commit `51c1d6b2…` (the commit the broker's code citations use), GitHub-hosted runner. It covers mitmproxy and its whole Python closure inside the image. |
| `python:3.13-slim-trixie`, `debian:trixie-slim`, `docker:29-cli` (test and tool images) | hash-pinned | Docker Official Images pinned by index digest. They carry in-registry BuildKit SLSA provenance bound to that digest, but **no publisher signature**: `cosign tree` finds no sigstore artifacts, and Docker Content Trust is being retired. |
| Python: 43 pins across the broker runtime, unit tests, integration images and the verifier tool | 25 attested, 18 hash-pinned | Every pinned hash is a PyPI-served file. 32 attestation files verified for linux/arm64. |
| Broker runtime Python: `fastjsonschema` 2.22.3 | hash-pinned | The project publishes no attestations; pinned by sha256 from PyPI, its official index. |
| apt packages in the two test images | attested (Debian archive signature), **with an exception** | apt verifies the signed `InRelease` against `debian-archive-keyring` from the digest-pinned base, and each package's sha256 from the signed index. The broker image installs no apt packages. See the exception below. |
| `seclab-broker`, `seclab-attest` images | built-from-source | Built from this repository's Dockerfiles, using only registered inputs. No BuildKit frontend is pulled (no `# syntax=` directive). |

Every broker **runtime** dependency meets the bar.

**Exception (test-only): apt versions float and the index can be replayed.**
The workspace and harness test images run `apt-get install` from
`http://deb.debian.org`. Signatures are verified, but:
- versions are not pinned;
- trixie's main suite `InRelease` has no `Valid-Until`, so a mirror or network
  attacker can serve an older, still-signed index (freeze or rollback to
  known-vulnerable package versions).

Accepted because these images never ship. They run only in the test harness,
on `--internal` networks, against test-owned endpoints. A rolled-back package
could at worst weaken a test, not a user's tab. Pinning through
snapshot.debian.org was tried and rejected (see Alternatives). Revisit if a
reliable snapshot mirror is available, or if any apt package enters a shipped
image.

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
  target interpreter, which is the use-time artifact; CI covers linux/amd64.
  Lockfiles installed into an interpreter other than the verifier's must be
  pure-Python wheels, so this never misses a file that could be installed.
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
- `broker/provenance-check.sh` on 2026-11-04, after security review round 4:
  `provenance: ok (5 files, 43 pins, 32 attestations verified against pinned
  digests)` and `verify-images: ok (1 attested image(s))`.
- **Negative tests:**
  - `pin_check.py --self-test` rejects every bypass form in the review:
    - extras, `==` with spaces, direct URLs, `-r`/`-c`/`-e`, index and
      find-links options;
    - sha384/sha512, uppercase digests, `--hash sha256:`;
    - `# syntax=`, `ADD`, foreign `COPY --from`, `RUN --mount`,
      non-canonical pip, `uv`/`python -m pip`/`sh -c 'pip …'`, `PIP_*`.
  - Attestation verification against a wrong pinned digest, wrong workflow or
    wrong repository each raises `VerificationError`.
  - `verify-images.sh` with an attested entry of unsupported kind exits 1
    (previously the pipeline exited 0).
  - A register publisher changed to `pytest-dev/not-pytest` fails both the
    metadata check and sigstore verification.
  - A wrong source digest for the mitmproxy image fails
    `gh attestation verify`.
- `cosign tree` (cosign v2.6.1 pinned by digest) on each pinned image digest:
  no sigstore artifacts.
- mitmproxy release workflow at `v12.3.1`: `.github/workflows/main.yml` uses
  `actions/attest-build-provenance` for both the image and the release
  artifacts.
