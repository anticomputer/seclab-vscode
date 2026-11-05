# Supply-chain exceptions: host prerequisites, and apt without version pins

- **Status:** accepted
- **Date:** 2026-11-05
- **Deciders:** anticomputer (user). Verbatim: "Approve: host prerequisites as recorded exceptions, plus apt from Debian's signed archive without version pins". Coordinator: record each exception in the register with this EDR; verify gh with `gh attestation verify`.
- **Related:** [ADR supply-chain provenance](../adr/20261104-supply-chain-provenance.md), [EDR broker dependency provenance](20261104-broker-dependency-provenance.md), [review](../security-reviews/20261104-supply-chain.md)

## Context
The [provenance bar](../adr/20261104-supply-chain-provenance.md) admits a dependency that is
signed and verified, pinned from its official source, or built by us from pinned source.
Anything else needs a recorded, user-approved exception. Two groups fell short.

**Host prerequisites.** sbx, Docker Desktop and gh run on the user's Mac. The user installs and
updates them, so we can't pin them. Each is the root for something we do:
- sbx runs every tab;
- Docker Desktop runs every container build, lint and OCI tab;
- gh verifies attestations (macOS app fetch, the broker's images, actionlint) and drives CI.

**apt.** The builder, OCI tab and broker test images install Debian packages from the live
signed archive. apt verifies each package against the GPG-signed `InRelease` and the
SHA-256 sums in `Packages`, but we don't pin versions. The ADR explains why: a version pin
breaks as soon as a security update replaces that version on the mirror, and
snapshot.debian.org was too slow and unreliable to build from. trixie's `InRelease` carries
no `Valid-Until`, so an attacker able to serve an older signed index could replay it. The
broker EDR had recorded that replay risk as a test-only exception.

## Decision
Both are recorded exceptions. In `deps/registry.json` each affected entry carries
`exception {record, approved, covers}`. `./seclab lint deps` requires the record to be an
existing EDR and requires the approval and the scope to be filled in. `docs/DEPENDENCIES.md`
lists them under "Recorded exceptions".

**Host prerequisites: covered, with a check we can run.** `./seclab deps host` is read-only
and installs nothing:
- **gh:** it downloads cli/cli's release archive for the installed version and verifies
  its attestation with `gh attestation verify --repo cli/cli --signer-workflow
  cli/cli/.github/workflows/deployment.yml`. The installed binary must be byte-identical to
  the one in that archive. Verified 2026-11-05: the Copilot app's gh 2.102.1 matches
  `gh_2.102.1_macOS_arm64.zip` (sha256 `b547134b…`).
- **Docker Desktop, the docker CLI and sbx:** each must pass `codesign --verify --strict`
  with Docker, Inc.'s Developer ID team (`9BNSXJN65R`). Verified for Docker Desktop and sbx
  0.51.0.

**apt: covered for every apt set.** The builder, the OCI tab image and the broker test
images install unpinned versions from Debian's signed archive. apt's default signature
checks stay on. Installed versions are recorded by the image build. This exception
supersedes the broker EDR's test-only apt-replay exception, which it subsumes.

## Consequences
- What the gh check can't do: a malicious gh could lie about itself. GitHub signs cli/cli's
  attestations with its own Sigstore instance (Fulcio "GitHub, Inc." intermediate, a TSA
  timestamp, no Rekor entry), so sigstore-python with the public-good root can't act as a
  second verifier. The check catches a substituted or differently built binary. A Homebrew
  build fails it, by design, and the failure is reported, not hidden.
- What the codesign check covers: it proves the binaries are Docker's signed builds as
  installed. It doesn't pin a version. The sbx kit image's own signature is still
  unconfirmed and stays recorded as part of the sbx entry.
- What apt can't give us: rebuilds are not byte-reproducible, and an old signed index can
  be replayed by someone who controls the mirror path. In exchange, every rebuild gets
  Debian's security updates.
- Revisit if Debian adds `Valid-Until` to trixie's `InRelease`, if a fast and reliable
  snapshot mirror appears, or if sbx publishes signed kits.
- Replacement plan:
  - Docker Desktop and sbx: none planned. They are the user's platform.
  - gh: if cli/cli moves its attestations to the public-good instance, add sigstore-python
    as an independent verifier.
