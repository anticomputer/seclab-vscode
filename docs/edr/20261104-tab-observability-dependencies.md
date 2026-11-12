# Tab observability dependencies and their provenance

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** Project owner (2026-11-04): every dependency the project pulls in must have strong security provenance; coordinator (the provenance bar); tab-observability session
- **Related:** [ADR tab observability](../adr/20261104-tab-observability.md), [EDR sensor spike](20261104-tab-observability-sensor-spike.md), [security review](../security-reviews/20261104-tab-observability.md)
- **Editorial redaction (2026-11-12):** quotations of project conversations replaced with neutral statements; decisions unchanged.

## Context
The observability layer pulls in third-party software that runs with privilege:
- strace runs as root inside every sbx tab VM;
- Falco runs as a privileged container on the user's Docker host while OCI tabs are open.

The project bar: every dependency is either
- signed or attested by its publisher and verified at use time;
- pinned by digest or hash from its official source, with checksums verified; or
- built by us from pinned source.

Anything else is an exception recorded in an EDR.

## Decision
The layer adds three runtime dependencies and one verifier. There are no exporter libraries: the SIEM path is a file sink, `seclab tab logs --format falco`. There are no Falco rules artefacts or extra plugins: tabd generates its own capture-only ruleset and loads it with `-r`, which replaces the image's rules.

| Dependency | Used for | Provenance | Verified when |
|---|---|---|---|
| `docker.io/falcosecurity/falco@sha256:1562a643…698e` (0.45.2) | OCI host sensor | **Signed by the publisher:** keyless cosign, certificate identity `https://github.com/falcosecurity/falco/.github/workflows/reusable_publish_docker.yaml@refs/tags/0.45.2`, issuer `https://token.actions.githubusercontent.com`, logged in Rekor. **Pinned by digest.** | `sandbox/oci/verify-falco.sh` (run by `./seclab image oci`, so on every OCI image build, locally and in CI) checks the exact identity, not a pattern; tabd only ever runs this digest (`tabd/src/obs/falco.ts`). A unit test keeps the digest equal to `sandbox/oci/falco.lock`. |
| `ghcr.io/sigstore/cosign/cosign@sha256:b03690aa…5b31` (v2.4.1) | Verifier for the above | **Pinned by digest** from sigstore's official registry. | Docker checks the digest on pull. |
| `strace_6.13+ds-1` (arm64, amd64) | sbx in-VM collector | **Debian's signed apt:** apt checks the deb against the signed Release/Packages indexes. **Version pinned**, and the **sha256 is pinned** in `sandbox/sbx/obs-debs.lock`. | `sandbox/sbx/build-template.sh` on every template build: apt's signature chain, then our sha256 check before the deb enters the template. |
| `debian@sha256:2dc419c6…e7f1` (trixie) | Runs apt to fetch the strace deb | **Pinned by digest** (Docker Official Image). | Docker checks the digest on pull. |
| `seclab-obs-guard` | seccomp guard in the template | **Built by us** from `sandbox/sbx/seclab-obs-guard.c` in the template builder. | Every template build. |

Rejected:
- Falco's `falcoctl` artefact downloads (rules, plugins) at runtime: an unverified network fetch inside a privileged container. Falco runs with `--network none` and only our ruleset.
- Building strace from source: Debian's signed binary package already meets the bar, at lower cost.

## Consequences
- An OCI image build fails closed if Falco's signature or identity doesn't match. Bumping Falco means a new digest **and** the new release's identity in `falco.lock`, a re-verify and a security review.
- The cosign and debian images are trusted by digest only; they are verifier and fetch tooling and never run at tab time.
- These entries go into the project's dependency register (`deps/registry.json`, owned by fork-build) once it lands.

## Addendum (2026-11-04): one cosign verifier, tagged pins
- The verifier is now the project's single cosign pin,
  `ghcr.io/sigstore/cosign/cosign:v3.0.3@sha256:774391ac9f0c137ee419ce56522df5fd3b1f52be90c5b77e97f7c053bdd67a67`
  (fork-build's `verify_signed_image` uses the same one). It verifies the Falco digest against the
  same exact identity. The v2.4.1 pin above is retired.
- Pins carry their tag as well as the digest so the dependency register
  ([ADR supply-chain provenance](../adr/20261104-supply-chain-provenance.md), `deps/registry.json`)
  can match them exactly: `falcosecurity/falco:0.45.2@sha256:1562a643…` and
  `debian:trixie@sha256:2dc419c6…`. Docker resolves by digest; the tag is informational.

## Evidence
```
$ sandbox/oci/verify-falco.sh
verify-falco: docker.io/falcosecurity/falco@sha256:1562a643953f938e02f47319b5214d93a235f11f646d60e9b8a516fd5a64698e signed by https://github.com/falcosecurity/falco/.github/workflows/reusable_publish_docker.yaml@refs/tags/0.45.2
# negative control: identity changed to …@refs/tags/0.45.1
verify-falco: signature verification FAILED … none of the expected identities matched … got subjects [https://github.com/falcosecurity/falco/.github/workflows/reusable_publish_docker.yaml@refs/tags/0.45.2]
```
cosign claims for the signature: workflow "Release Packages and Docker images",
repository `falcosecurity/falco`, ref `refs/tags/0.45.2`, commit
`7625e203c17c88c91fa1b1b8e2937907f22a1523`; tlog inclusion verified.
