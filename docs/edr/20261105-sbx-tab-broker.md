# sbx tabs get a real broker (plan increment B2)

- **Status:** accepted
- **Date:** 2026-11-05
- **Deciders:** Coordinator (priority 3, and the plan's decisions on policy source, keychain and prompts). Fork-build session: implementation.
- **Related:** [plan tabd-broker-wiring](../plans/tabd-broker-wiring.md), [B1: OCI tabs get a real broker](20261105-oci-tab-broker.md), [broker protocol](../broker-protocol.md), [sbx fence spike](20261104-sbx-fence-spike.md), [review round ZZ](../security-reviews/20261105-tab-broker.md)

## Context
B1 gave OCI tabs a broker. sbx tabs still pointed egress at a blackhole, and tabd refused
`--broker required` on sbx. An sbx tab is a microVM; it has no pod network to share with a
broker container. Its only way out is sbx's own network policy, which tabd fences down to
deny-everything (one per-sandbox deny for every allow that applies to it).

## Decision
- **Where the broker runs.** One broker container per sbx tab, on Docker Desktop beside the
  VM, named `seclab-t-<id>-broker` (`drivers/sbx.ts` `ensureBroker`).
  - It is hardened as in B1: read-only, no capabilities, `no-new-privileges`, pids and
    memory limits, its own tmpfs, `SECLAB_TAB_ID`, `--pull never`.
  - It sits on its own ICC-off egress network, `seclab-t-<id>-egress`.
  - Its proxy port is published on `127.0.0.1` only, with an ephemeral host port. tabd reads
    the binding live from `docker port` and requires exactly one `127.0.0.1:<P>` binding.
- **The fence's one allow.** At every start, tabd makes the tab's only sandbox-scoped
  `localhost:*` allow be `localhost:<P>` (`syncBrokerAllow`). A stale allow for an old port
  is removed first. All other allows stay mirrored as per-sandbox denies, and `checkFence`
  exempts only `localhost:<P>`. Periodic re-verification reads `<P>` live, so a broker that
  isn't running, or has moved ports, fails the check and quarantines the tab.
- **The tab side.** Inside the VM, the proxy is `host.docker.internal:<P>`.
  - tabd runs the same bring-up as B1 over `docker exec -i <broker> seclab-broker control`:
    hello, health, `proxy.auth.set`, `policy.load`, `ca.get`.
  - It then writes `proxy-url`, `ca.pem` and `bundle.pem` into `/run/seclab-broker` in the VM,
    as root via `sbx exec -i -u root`, with the URL and PEM on stdin. The script is shared
    with OCI (`drivers/broker-install.ts`). It refuses a directory that isn't root-owned, and
    validates the URL host against `broker:8080` or `host.docker.internal:<port>`.
  - This happens before the REH starts, so every tab process starts behind the broker.
  - `seclab-tab-env` is unchanged; it already accepts the URL form.
- **The default** is now `--broker required` for both drivers. `--broker none` keeps the
  blackhole. tabd refuses `required` on sbx when there is no docker.
- **Lifecycle.** stop and quarantine stop the broker container; remove deletes it and its
  egress network. Cleanup acts on what exists with the tab's `seclab.tab` label, not on the
  current `--broker` mode, and a start that fails after the broker is up stops it again.

## Why not the alternatives
- **Broker inside the VM.** The tab's own root would be next to it, and the credentials B4
  imports would sit in the tab's kernel. The broker is the trust boundary; it must not share
  one with the code it constrains.
- **A fixed or shared host port.** One broker per tab keeps per-tab policy, credentials and
  rate limits separate (the coordinator's prompt decision 3). Ephemeral ports avoid
  collisions; reading them live means a restarted broker can't leave a stale allow.

## Consequences
- **Who can reach a tab's broker.** Host processes can connect to `127.0.0.1:<P>`, but the
  proxy requires the tab's 32-character password (407 otherwise). Another sbx tab can't
  connect at all, because its fence allows only its own broker's port. OCI tabs have no route
  to host loopback.
- **Verified locally on 2026-11-05** (`./seclab test e2e-broker sbx`, broker 0.3.1, sbx
  0.51). From inside the sbx tab:
  - the environment points at `host.docker.internal:<P>` with the broker CA;
  - `docker port` shows only `127.0.0.1:<P>`; `checkFence` with `<P>` finds nothing
    uncovered, and without it finds exactly that one allow;
  - a listener on another host loopback port, which answers on the host, gets no request
    from the tab, directly or as a proxy;
  - an unlisted host gets `403` with `X-Seclab-Broker: denied`;
  - `--noproxy '*'` can't connect;
  - the policy's `GET` host returns `200` through the tab CA, and a `POST` gets `403`;
  - wrong proxy credentials get `407`;
  - the password appears in no file in the state directory;
  - remove leaves no broker container and no network; teardown is clean.
- The containment check "runtime-injected proxy env never wins" now requires exactly the
  driver's broker URL (`broker:8080` on OCI, `host.docker.internal:<P>` on sbx).
- `clean-host` maps a tab's `-egress` network to its tab, so a real tab's network is never
  classified as a test resource. A self-test case covers every per-tab suffix.
- **A broker restart breaks egress until the next `ensureRunning`.** The port changes, so
  the fence check fails and the tab is quarantined. This fails closed. Until that check runs
  (up to 60 s), the old port stays allowed (review ZZ-1, accepted). B3 reconnects control at
  adoption and can re-run the allow and the in-VM install then.
- **Containment on both drivers, 2026-11-05:** `containment sbx` 120/121 (1 known gap),
  `containment oci` with only its known gaps, `e2e-broker oci` unchanged.
- **Broker image:** pinned by ID with checked build labels, on both drivers
  ([broker image identity](20261105-broker-image-identity.md), review XX-6).
