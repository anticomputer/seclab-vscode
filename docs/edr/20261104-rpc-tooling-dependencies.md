# Dependency provenance for the RPC filter tooling

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** user; RPC-lockdown session
- **Related:** the dependency register and CI provenance bar (fork-build session)

## Context

The user's requirement: *"make sure that any dependency we pull in has a strong
security provenance."* The bar is that every dependency must be signed or
attested and verified at use time, pinned by digest or hash from the project's
own official source, or built by us from pinned source.

This records what the RPC filter tooling and probes pull in, and one gap of
mine that the audit found.

## What this component depends on

| Dependency | Where | Provenance |
|---|---|---|
| `python:3.12-slim` | the five `rpc-filter/tools/*.sh` wrappers | Official Docker Hub image, **pinned by digest** (`sha256:b18b261e…`). Runs with `--network none` for every gate except `run.sh`. |
| `node:24.22.1-trixie` | `test/containment/probe-safety.test.ts` | Pinned by digest, **reusing the digest `test/harness.ts` already pins** rather than introducing a second source of truth for the same image. |
| upstream Code-OSS source | `rpc-filter/tools/fetch-upstream.sh` | Cloned with git and **verified against the commit SHA** from `upstream.lock`. See below. |
| *(none)* | the generator itself | **Standard library Python only**, deliberately. No package manager runs, so there is no install step to attest. |
| *(none)* | the probe payloads and guards | Node built-ins only. |

The strongest position here is the absence: the generator, the drift check, the
docs renderer, the probe lint and the safety guards pull in **no packages at
all**. That was a deliberate constraint from the start — a stdlib-only tool has
no dependency surface to vet, and it is why these gates can run in a stock image
with the network off.

## The gap this audit found

`fetch-upstream.sh` originally downloaded
`codeload.github.com/microsoft/vscode/tar.gz/<sha>` over HTTPS and verified
**nothing**. Naming a commit SHA in a URL does not verify the bytes you receive:
a `.tar.gz` is a *derived* archive, not the git object the SHA names, so
nothing tied the content to the hash. Transport security is not provenance.

That mattered more than it first appears. The entire policy table is derived
from this source: the inventory, the verdicts, the coverage digest and every
permalink in the design docs. Unverified source would have meant an unverified
policy, and the drift gate would have blessed it without complaint, because the
gate compares the policy to the inventory rather than either to upstream.

**Fixed.** The script now clones with git and checks out the pinned commit, then
asserts `git rev-parse HEAD` equals the expected SHA and fails otherwise. Git
verifies objects against their hashes, so the result is content-addressed from
the project's own official source — the same mechanism `build/fetch-upstream.sh`
already used for the build. The inventory generator and the build now obtain
upstream the same way.

**Verified, not assumed:** regenerating the inventory from the freshly cloned
and verified source produced byte-identical upstream-derived output. The only
difference was `broker/` now being present in our own repo, which is local state
the inventory reports deliberately. So the previously fetched tarball was not
tampered with; this is hardening, not an incident.

## Consequences

- The first fetch is slower: a blobless partial clone rather than a tarball.
  Acceptable for a cache that is populated once per upstream bump.
- `git` becomes a requirement of the generator path. It already was, for the
  repo itself.
- A future reviewer gets the same guarantee as the build: the source the
  inventory describes is the source the build compiles.
