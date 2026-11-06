# Security review: tabs wired to their broker (plan tabd-broker-wiring)

- **Date:** 2026-11-05
- **Scope:**
  - Round XX (B1, OCI tabs get a real broker): `7d1c94d..325097f`, plus `32c3289` (the naming rule and the `clean-host` report).
  - Round ZZ (B2, sbx tabs get a real broker): the B2 commit on `a139cdc`.
  - Threat model: a rogue extension in full control of its tab, trying to reach the network
    other than through its broker, to tamper with what tabd installs into the tab, or to read
    the tab's proxy credential from the host. A compromised broker (it parses tab traffic)
    trying to harm tabd or the host through the control channel.
  - Records: [plan](../plans/tabd-broker-wiring.md), [EDR](../edr/20261105-oci-tab-broker.md).
- **Prompt injection:** none found.

## Round XX
Nothing medium or higher. The review answered six questions:
- **The tab can't write the root-owned tmpfs or influence what's written there.** The script
  is fixed, the input arrives on stdin, and the renames are atomic.
- **The proxy password is in no argv, audit record or container config.**
- **A compromised broker can only slow tabd down.** Lines are capped, malformed messages close
  the channel, and the CA must be a single PEM certificate.
- **The workspace has one `--internal` network, and no route out except via the broker.**
- **Adoption without a control connection doesn't fail open:** the broker keeps its last
  policy.
- **The `clean-host` report never removes anything.**

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| XX-1 | Low | CI | The token step ran after hostile fixtures and the privileged Falco sensor in the same job. | Fixed | The download-only token step is now first in the `oci` job, before any fixture or privileged step. |
| XX-2 | Low | tabd | A stalling broker could hold `ensureRunning` for minutes (60 retries, 15 s per request). | Fixed | One 60 s deadline for the whole setup: connect retries, health and each request. Tests: a broker that's never up, or never answers, is given up on at the deadline. |
| XX-3 | Low (inferred) | tab env | The proxy credential is in every tab process's environment. The terminal backend may report that to the trusted side and persist it there. | Accepted | The credential works only on the tab's own `--internal` network, against its own broker. It grants nothing a process in the tab doesn't already have, and it rotates on every start. |
| note | Info | tabd | The `ca.get` sha256 check is the broker vouching for itself. | Recorded | Described as a format check. The control is `PEM_RE` (exactly one certificate), written only to the tab's tmpfs. |
| note | Info | clean-host | Register images include Docker Official images, so a user's own containers from them are reported as "possibly ours". | Accepted | Report only, as the coordinator specified. |

## Round XX, part 2: the OCI broker becomes the default (`3b7a9db..40d6025`)
Nothing medium or higher, and nothing fails open: a missing image, a placeholder container
left over from older tabs, or a wrong schema revision all refuse the start.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| XX-4 | Low | containment | The proxy check accepted the blackhole *or* a broker URL for every tab, so an OCI tab that silently lost its broker would still pass. | Fixed | The check takes the expected mode. OCI requires exactly the broker URL; sbx (until B2) requires exactly the blackhole. |
| XX-5 | Low | CI | On PR runs the broker build has no attestation bundle (the token step is push-only), so the `oci` job fails on PRs. | Accepted | Same as HH-2: changes land by branch push and fast-forward, never by PR. It fails closed. |
| XX-6 | Low | tabd | The broker image is trusted by its mutable local tag (`seclab-broker:dev`). A missing image made `docker create` try a registry pull. | Fixed | `--pull never` on every tab, broker and placeholder container; then the broker is pinned by image ID with checked build labels ([EDR](../edr/20261105-broker-image-identity.md)). |

## Round ZZ: sbx tabs get a real broker (B2)
Nothing medium or higher. A tab reaches only its own broker: the fence's one allow is its
broker's live loopback port, every other applicable allow is mirrored as a per-sandbox deny,
OCI tabs have no route to host loopback, and the proxy requires the tab's password.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| ZZ-1 | Low | sbx | For up to 60 s after a broker dies, the fence still allows its old loopback port; anything that binds that port in the window is reachable from the tab (another tab's broker still demands its own password). | Accepted | The periodic fence check reads the port live, so a dead or moved broker quarantines the tab. B3 adds a live control connection; a broker `die` watch can close the window then. |
| ZZ-2 | Low | sbx | A failed start left the broker running, with a published port and no tab behind it. | Fixed | Any failure after the broker starts stops it. |
| ZZ-3 | Low | sbx | Cleanup keyed on tabd's current `--broker` setting, so a restart with `--broker none` leaked a tab's earlier broker and network. | Fixed | Stop and remove act on what exists and carries the tab's `seclab.tab` label, whatever the mode; failures throw. |
| ZZ-4 | Low | tab | The install script fixed up a group- or other-writable broker directory instead of refusing it, and wrote `*.new` files by path. | Fixed | It refuses a symlink, a non-directory, a non-root owner or any group/other write bit, and removes stale `*.new` entries first. Exercised against a planted `.new` symlink, a world-writable directory, a symlinked directory and a non-root owner. |
| ZZ-5 | Low | sbx | Stale-allow removal also removes user-added `localhost:<n>` allows scoped to the tab, and ignored `rm` failures. | Fixed | Documented (the fence forbids them anyway); a failed `rm` now fails the start. |
| ZZ-6 | Low | tests | The tests checked the fence rules but never tried another loopback port from inside the tab. | Fixed / accepted | The sbx e2e starts a host listener (with a host-side control) and asserts the tab can't reach it, directly or as a proxy. Accepted: the containment check accepts any `host.docker.internal` port (the e2e pins the exact one), and "no direct route" accepts any curl failure. |

XX-6 is closed by the broker image identity change below.

## Round ZZ, part 2: broker image identity (XX-6)
Scope: `broker/build.sh` labels (broker session, `4d55351`, reviewed there) and the tabd side
([EDR](../edr/20261105-broker-image-identity.md)). Findings and dispositions are recorded below
once the round completes.
