# Pinned tools: verified release binaries and source builds instead of third-party images

- **Status:** accepted
- **Date:** 2026-11-05
- **Deciders:** coordinator, from the user's bar ("make sure that any dependency we pull in has a strong security provenance"); fork-build session (implementation).
- **Related:** [ADR supply-chain provenance](../adr/20261104-supply-chain-provenance.md), [EDR supply-chain exceptions](20261105-supply-chain-exceptions.md), [review](../security-reviews/20261104-supply-chain.md)

## Context
Four tools ran as third-party images pinned only by digest, below the bar:
- **cosign** (our verifier for zizmor and Falco): the image's own signature wasn't found.
- **actionlint:** the image is unattested; the release binaries are attested.
- **gitleaks** (the pre-mount secret scan, a security control): upstream publishes nothing
  signed.
- **lychee:** the `attest` job in its release workflow has failed for every release since
  v0.24.2, so no release binary verifies, and the Docker Hub image is never attested.

## Decision
One mechanism: `build/tools/tools.json` (the pins), `build/tools/Dockerfile` (one target per
tool on our pinned Debian base), and `build/tools/tool.sh`, also run as `./seclab tool NAME`.
`tool.sh` verifies the tool, builds a local image tagged with a hash of the pin and the
Dockerfile, and prints that tag. Images are never pulled under these names.
- **cosign 3.1.4, release binary.** sha256 pinned per arch. Its Sigstore bundle (keyless,
  `keyless@projectsigstore.iam.gserviceaccount.com`, issuer `accounts.google.com`) is
  verified by sigstore-python in the broker's hash-locked verifier image. That is an
  independent implementation, so cosign never vouches for itself. This replaces the
  `ghcr.io/sigstore/cosign` 3.0.3 image for zizmor and Falco, and it is the one cosign pin.
- **actionlint 1.7.12, release archive.** sha256 pinned per arch, plus `gh attestation
  verify` with the signer workflow (`release.yaml`), source ref, source digest and
  `--deny-self-hosted-runners`. It runs with Debian's `shellcheck`.
- **gitleaks 8.30.1, built from source.** Tag `v8.30.1` is cloned and HEAD must equal the
  pinned commit. Go modules are checked against `go.sum`. The build is CGO-free with
  `-trimpath` and an empty build id in the pinned Go image, and both arches come from one
  build. Their sha256 are pinned (`binarySha256`), and every build, local or CI, must
  reproduce them. CI's `tools` job rebuilds on an amd64 runner and, on main, attests both
  binaries (`actions/attest-build-provenance`). tabd runs it as `seclab-tool-gitleaks:8.30.1`
  with `--pull never`. A missing image fails the scan, and opens fail closed. The runtime is
  Debian, not upstream's Alpine: the approved apt exception covers Debian only. The scan
  script needs `bzip2` and `xz-utils` for GNU tar.
- **lychee 0.24.2, built from source.** Tag `lychee-v0.24.2`, commit pinned,
  `cargo build --locked` in the pinned Rust image, with crates checked against Cargo.lock.
  It is not a security control (an external link check with a read-only mount), so there
  is no reproducibility pin.

Every hash and commit in `tools.json` is a register pin (`tool:NAME:ARCH@sha256:…`,
`git:URL@COMMIT`), so `./seclab lint deps` fails on an unregistered or stale one.

**Code-OSS npm tree.** `npm ci` pins bytes (lockfile integrity), not origin. After it,
`build/npm-audit-signatures.sh` runs `npm audit signatures` in every installed project (the
root and each nested package upstream's postinstall installs). It fails on any invalid or
missing registry signature, and the Linux build writes its install stamp only after it passes.

## Consequences
- More build work: the first `./seclab tool lychee` compiles Rust for several minutes, and
  CI's docs job builds it on every run (timeout raised to 45 min). gitleaks takes about a
  minute. Images are cached locally by content tag.
- Bumps go through the same verification: a new pin in `tools.json`, then `tool.sh`, which
  refuses a hash or attestation mismatch. For gitleaks the new binary hashes come from the
  build and are confirmed by CI's cross-host rebuild. Dependabot watches the toolchain
  images in `build/tools/`. The weekly deps report tracks the tool releases.
- `gh attestation verify` for actionlint needs a token on the runner (`workflow-lint`).
  It goes to gh on the runner, never into a container.
- Verified 2026-11-05 (arm64):
  - cosign: sigstore bundle verified for both arches;
  - actionlint: attestation verified;
  - gitleaks: binaries `862cec60…` (arm64) and `4e4bcd80…` (amd64);
  - lychee: built;
  - `./seclab lint workflows` passes with the new actionlint;
  - zizmor and Falco are re-verified with cosign 3.1.4.
