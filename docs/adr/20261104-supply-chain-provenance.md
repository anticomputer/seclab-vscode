# Supply-chain provenance: a register, a bar, and checks before use

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** anticomputer ("make sure that any dependency we pull in has a strong security provenance"); coordinator; fork-build session
- **Related:** [EDR ci-hardening](../edr/20261104-ci-hardening.md), [ADR vscodium-style fork](20261104-vscodium-style-fork.md), [register](../DEPENDENCIES.md), [EDR prompt-injection hygiene](../edr/20261104-prompt-injection-hygiene.md)

## Context
We build the editor the user runs, unsigned, and every tab and CI job runs third-party
code. Until now every image and action was pinned by digest or SHA ([EDR
ci-hardening](../edr/20261104-ci-hardening.md)). A pin proves *which* bytes; it says
nothing about *who* made them. A digest pinned from a compromised publisher, or bumped by
an unreviewed bot PR, is still a compromise.

Research (2026-11-04, primary sources) on what publishers actually provide:
- **Docker Official Images** carry BuildKit SLSA provenance and SBOMs, but they are
  unsigned in-toto statements. Docker Content Trust is being retired for them, with no
  Sigstore replacement yet ([Docker](https://www.docker.com/blog/retiring-docker-content-trust/)).
  The `node` images verify Node's GPG-signed `SHASUMS256` inside their own build.
- **mitmproxy** images carry a GitHub artifact attestation (SLSA v1, Sigstore).
- **zizmor** images are cosign-signed through `docker/github-builder`, and **Falco**
  images are cosign-signed by its publish workflow.
- **lychee** 0.24.2 has no attestation (the attest job didn't run for that tag). The
  **actionlint** image is unattested, though its release binaries are. **gitleaks**
  publishes nothing signed.
- **apt:** Debian archives are GPG-signed, and apt verifies every `.deb` against the
  signed `InRelease` by default.
- **Code-OSS** verifies the Electron and Node downloads against SHA-256 manifests
  checked into the pinned source: `build/checksums/{electron,nodejs}.txt`, enforced in
  [`build/lib/fetch.ts`](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/build/lib/fetch.ts#L74-L80).
  Its downloaded built-in extensions are hash-pinned in upstream `product.json`.
- **PyPI** attestations (PEP 740) exist for some packages, but pip doesn't verify them.
  `--require-hashes` pins bytes without proving origin.
- **npm:** `npm ci` checks lockfile integrity. Registry signatures and provenance need
  `npm audit signatures`.

## Decision
1. **One register.** [`deps/registry.json`](../../deps/registry.json) is the single source
   of truth for every third-party input that is built, run or shipped, plus the host tools
   we rely on. It covers:
   - upstream source and what its build downloads;
   - images, actions, pip, npm and apt sets;
   - bundled extensions;
   - `sbx`, Docker Desktop and `gh`.

   Each entry records the publisher, why we need it, the exact pin, the provenance
   evidence, how it is verified and where, the bar it meets, its decision record, and who
   bumps it and how. [`docs/DEPENDENCIES.md`](../DEPENDENCIES.md) is generated from it.
   Component sessions may keep a detailed sub-register (for example `broker/deps.json`),
   referenced from their entries.
2. **The bar.** A dependency is admitted only if it meets at least one of these:
   - **signed-verified:** signed or attested by its publisher, and verified before use.
     That means cosign pinned to the expected certificate identity and issuer, `gh
     attestation verify` pinned to the signer workflow, apt's signed archive, or GPG-signed
     checksums.
   - **official-pinned:** pinned by digest or hash from an official source whose publisher
     is the project itself (a Docker Official Image, or the project's own org), with
     checksums verified against the publisher's signed checksum file where one exists.
     A pinned *image digest* is content-addressed. A pinned *URL* is not: a tarball at
     `…/archive/<sha>.tar.gz` is a derived archive, not the git object the SHA names, so a
     URL download must check a hash we hold, or fetch through git and verify the commit.
   - **built-from-source:** built by us, in our CI, from pinned and verified source.
   - **exception:** none of the above. That needs an EDR with the reason, a replacement
     plan, and the user's approval.

   Where a publisher offers a signature or attestation, we verify it; a digest pin alone
   is not enough then. Prefer fewer dependencies. Never `curl | sh`.
3. **No credentials into third-party containers.** Tool images get no tokens and, where
   the tool allows, no network: lychee and zizmor already run that way. A publisher
   verifier (`gh`, cosign) gets only what verification needs.
4. **Enforcement in CI, fail closed:**
   - `./seclab lint deps` (in the required `docs` and `unit` checks) fails if:
     - any pin in the tree is unregistered, or a registered pin is gone;
     - an entry is incomplete;
     - an exception lacks an EDR;
     - an artifact derived from upstream (the RPC inventory and policy) names a SHA other
       than `upstream.lock`'s;
     - `DEPENDENCIES.md` is stale.
   - Each entry's `record` must exist, so a new entry comes with its ADR or EDR, and it
     goes through the review loop like any other change.
   - Signature and attestation checks run before use, in CI and in `seclab` and harness
     scripts, for every entry whose bar is signed-verified.
   - pip uses `--require-hashes`; npm uses `npm ci` and `--ignore-scripts` where possible.
   - apt relies on the signed archive. We don't pin apt package versions or use
     snapshot.debian.org: a version pin breaks the build as soon as a security update
     replaces the version on the live mirror. The broker session measured snapshot at
     217 kB/s, with a package dropped mid-build. Instead, the image build records the
     installed versions. The trade-off: rebuilds aren't byte-reproducible, but they always
     get Debian's signed security updates.
   - Upstream is fetched by exact SHA through git (`build/fetch-upstream.sh` verifies tag
     → SHA). The build image's Node version must equal upstream's `.nvmrc`, which
     `build/prepare.sh` asserts.
5. **Updates.** Dependabot covers Dockerfiles, workflows and pip. For what it can't see
   (image pins in shell and TS, tracked tools' releases), the weekly `deps-updates`
   workflow runs `./seclab deps outdated` and files or updates **one tracking issue**.
   It reports image tags that moved and newer releases; it never changes a pin. It's an
   issue rather than a PR on purpose: a PR opened with `GITHUB_TOKEN` triggers no CI, so
   it could never pass the ruleset, and opening one would need `contents: write` on a
   scheduled job, where an issue needs only `issues: write`. Every update, bot or human,
   goes through the same verification and review. A Node bump on the build image is
   refused until upstream's `.nvmrc` moves.

## Consequences
- Dependencies that meet only the digest bar today, where something stronger exists, are
  listed as **open gaps** in the register with a proposed fix: gitleaks, lychee, the
  actionlint image, and Docker Official Images (Docker Hardened Images are signed, but
  paid).
- Verification needs the network (the Sigstore TUF root, GitHub's attestation API). It
  runs where network is already allowed (image builds, CI setup) and is cached per digest
  under `.work/`, so offline lint runs stay offline.
- The register is now the third place a pin lives, after the file that uses it and the
  update bot. The check makes drift a CI failure rather than a silent gap.
