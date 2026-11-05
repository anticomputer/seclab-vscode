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
- **actionlint 1.7.12, release archive.** sha256 pinned per arch. Its GitHub artifact
  attestation (public-good Sigstore) is committed next to the pins
  (`build/tools/attestations/`). It is verified by sigstore-python `verify github` against the
  signer workflow at the tag, the repository, the ref, the source commit and the push
  trigger, with the archive as a subject. The statement must also name a GitHub-hosted runner.
  This needs no GitHub API and no token anywhere (review TT-4). It runs with Debian's
  `shellcheck`.
- **gitleaks 8.30.1, built from source.** Tag `v8.30.1` is cloned and HEAD must equal the
  pinned commit. Go modules are checked against `go.sum`. The build is CGO-free with
  `-trimpath` and an empty build id in the pinned Go image, and both arches come from one
  build. Their sha256 are pinned (`binarySha256`), and every build, local or CI, must
  reproduce them; the image build re-checks the binary it ships. CI's `tools` job rebuilds on
  an amd64 runner with read-only permissions. On main, a separate `attest-tools` job with no
  checkout and no repository code attests both binaries (`actions/attest-build-provenance`,
  review TT-1). tabd runs it as `seclab-tool-gitleaks:8.30.1` with `--pull never`, and before
  its first scan checks that the image's `/usr/bin/gitleaks` has a pinned hash. Any local
  `docker tag` can produce the name, so a mismatch fails the scan (TT-2). A missing image
  fails the scan too, and opens fail closed. The runtime is Debian, not upstream's Alpine: the
  approved apt exception covers Debian only. The scan script needs `bzip2` and `xz-utils` for
  GNU tar, and parses GNU find's C-quoted error paths (TT-3).
- **lychee 0.24.2, built from source.** Tag `lychee-v0.24.2`, commit pinned,
  `cargo build --locked` in the pinned Rust image, with crates checked against Cargo.lock.
  It is not a security control (an external link check with a read-only mount), so there
  is no reproducibility pin.

Every hash and commit in `tools.json` is a register pin (`tool:NAME:ARCH@sha256:…`,
`git:URL@COMMIT`), so `./seclab lint deps` fails on an unregistered or stale one.

**Code-OSS npm tree.** `npm ci` pins bytes (lockfile integrity), not origin. After it,
`build/npm-audit-signatures.sh` checks every installed project (the root and each nested
package upstream's postinstall installs). Every lockfile entry must resolve from
`registry.npmjs.org`, because `npm audit signatures` silently skips anything else. Then
`npm audit signatures` must pass, failing on any invalid or missing signature. The Linux
build writes its (versioned) install stamp only after both pass. It runs after `npm ci`,
because upstream's postinstall needs install scripts, so it detects a tampered package
rather than preventing its install script (TT-6).

**ripgrep.** `@vscode/ripgrep`'s postinstall asks the GitHub API for its prebuilt binary,
which returns 403 on shared runners once their IP is rate-limited (the macOS build failed this
way). It also installs the binary without checking any hash. `build/seed-ripgrep.mjs` runs
before `npm ci`. It fetches the pinned asset from the release-download URL (not the API),
checks its sha256 against `build/ripgrep.lock`, and places it in the postinstall's cache,
which the postinstall then uses. It refuses if upstream's lockfile moves to another
`@vscode/ripgrep` version. No token is involved. The cache sits in a fresh private `TMPDIR`, and
after `npm ci` (and on every Linux build, cached tree or not) `--verify-installed` checks the
installed `rg` against the binary's own pinned sha256, whatever path the postinstall took
(review VV-5).

**The tab's seccomp guard.** sbx now resolves its shell kit as `:latest`, and the 2026-11 kit
ships no `gcc`. So `sandbox/sbx/seclab-obs-guard.c` is compiled statically in our pinned
Debian image (`sandbox/sbx/Dockerfile.guard`), not with whatever compiler the kit carries,
and copied into the template.

## Consequences
- More build work: the first `./seclab tool lychee` compiles Rust for several minutes, and
  CI's docs job builds it on every run (timeout raised to 45 min). gitleaks takes about a
  minute. Images are cached locally by content tag.
- Bumps go through the same verification: a new pin in `tools.json`, then `tool.sh`, which
  refuses a hash or attestation mismatch. For gitleaks the new binary hashes come from the
  build and are confirmed by CI's cross-host rebuild. Dependabot watches the toolchain
  images in `build/tools/`. The weekly deps report tracks the tool releases.
- `gh attestation verify` is no longer needed for any tool: both release verifications run
  sigstore-python in a container, offline from GitHub's API.
- Verified 2026-11-05 (arm64):
  - cosign: sigstore bundle verified for both arches;
  - actionlint: attestation verified;
  - gitleaks: binaries `862cec60…` (arm64) and `4e4bcd80…` (amd64);
  - lychee: built;
  - `./seclab lint workflows` passes with the new actionlint;
  - zizmor and Falco are re-verified with cosign 3.1.4.
