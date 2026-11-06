# Broker image identity: pinned by ID, checked by label (review XX-6)

- **Status:** accepted
- **Date:** 2026-11-05
- **Deciders:** Fork-build session (tabd side) and broker session (`broker/build.sh`), agreed over the project's session messages.
- **Related:** [B1 EDR](20261105-oci-tab-broker.md), [B2 EDR](20261105-sbx-tab-broker.md), [review record](../security-reviews/20261105-tab-broker.md), [broker protocol](../broker-protocol.md)

## Context
tabd trusted the broker image by its mutable local tag, `seclab-broker:dev`. B1 added
`--pull never`, so a missing image fails instead of pulling. But any local `docker tag`,
another worktree's build, or a stale build from before a protocol change could still stand
behind the name. The broker parses all of a tab's traffic and will hold its credentials (B4),
so tabd must know which image it runs.

## Decision
- **The broker side** (`broker/build.sh`, the only supported build):
  - It verifies the mitmproxy base's attestation, and fails if the Dockerfile's base isn't
    the registered digest.
  - It stamps `org.opencontainers.image.{revision,base.digest,version}`,
    `io.seclab.broker.protocol` and `io.seclab.broker.policy-revision`. The revision gets a
    `-dirty` suffix when `broker/` has uncommitted or untracked changes.
  - It prints one stdout line: `{"id","tag","revision","base","version","policyRevision"}`.
    `sandbox/oci/build-images.sh` (`./seclab image oci`) keeps it in
    `.work/broker-image.json`.
- **The tabd side** (`tabd/src/broker-image.ts`):
  - The configured reference (`--broker-image`, default `seclab-broker:dev`) is resolved
    once to its `docker image inspect` `.Id`. Under Docker Desktop's containerd store that's
    the manifest digest, which is content-addressed down to the config (with its labels) and
    every layer.
  - Before first use, the labels must match: the base digest equals tabd's pinned mitmproxy
    digest; the protocol and policy revision are what tabd speaks; the version is a release
    version; the revision is a git commit, and not `-dirty` unless tabd runs with
    `--broker-dev`.
  - A unit test pins tabd's constants to `broker/deps.json` and
    `broker/schema/protocol.v1.json`, because the shipped app contains neither.
  - Every broker container (OCI and sbx) is created from that ID with `--pull never`. An
    existing broker container from a different image is removed with its anonymous volume
    and recreated, which is safe because every start re-runs the whole bring-up. A container
    that isn't labelled for this tab is refused, never used or removed, and a failed inspect
    is never read as "absent". After `start`, the container's image is checked again.
  - The fence check (at start, adoption, connect and every periodic re-verify) also requires
    the running broker to be the checked image, so a tab started by an earlier tabd, or from
    a stale image, is quarantined.
  - `--broker none` runs the placeholder by ID too, and replaces a real broker left from an
    earlier `required` run, removing its egress network.
  - After `broker.hello`, the reported version must equal the image's version label.
  - The reference is resolved at every tab start, not cached: creating by ID is race-free
    either way, and a rebuilt image reaches new tabs without restarting tabd.

## Why labels and an ID, not an attestation
Local builds have no Sigstore identity, so an attestation would be self-signed and prove
nothing more. The ID binds tabd to exact bytes, and the labels tie those bytes to a clean
`build.sh` build of a compatible broker. Labels are self-asserted: they protect against
mistakes (stale, unlabelled, dirty or foreign images), not against someone with docker
access, who already controls the VM. A signed broker image from CI comes once tabs run
released builds.

## Consequences
- An image built before the labels inherits mitmproxy's own `revision` and `version` labels,
  which look valid. The base-digest and protocol labels are what refuse it; a unit test
  covers this case, and it was confirmed against the real local image.
- Every local broker image built before 2026-11-05 is refused; `./seclab image oci`
  rebuilds it. Local builds go through CFS, whose 7-day hold blocks the broker's newest pins
  until about 2026-11-06, so this landed only once a labelled broker built locally.
- A broker version bump needs no tabd change. A protocol or policy-revision change does;
  those were already pinned.
