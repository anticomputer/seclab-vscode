# OCI tabs get a real broker (plan increment B1)

- **Status:** accepted
- **Date:** 2026-11-05
- **Deciders:** Coordinator (priority 3, and the plan's decisions on policy source, keychain and prompts). Fork-build session: implementation.
- **Related:** [plan tabd-broker-wiring](../plans/tabd-broker-wiring.md), [broker protocol](../broker-protocol.md), [review](../security-reviews/20261105-tab-broker.md), [ADR tab supervisor](../adr/20261104-tab-supervisor.md)

## Context
Until now the OCI pod's broker slot held a placeholder, and every tab's egress pointed at a
blackhole. The broker (0.3.x, policy schema revision 3) is built and tested standalone, with a
stdio control protocol. B1 wires it into OCI tabs: default deny, with no prompts and no
credentials yet.

## Decision
- **tabd control client** (`tabd/src/broker-control.ts`). Newline-delimited JSON-RPC over
  `docker exec -i <broker> seclab-broker control`; nothing listens on the host.
  - `broker.hello` is checked first: protocol, tab, and policy schema pinned to revision 3,
    which follows the protocol changelog's head.
  - Lines are capped at 1 MiB, and anything malformed closes the channel.
  - No request or param is ever logged.
  - One 60 s deadline covers the whole bring-up.
- **Bring-up** (`supervisor.ts` `brokerHooks`), in the order of protocol §2:
  - `health`;
  - `proxy.auth.set` with a fresh 32-character password on every start;
  - `policy.load`: the user's `broker-policy.json` from tabd's state directory (0700, outside
    every mount; a regular file, not group- or world-writable, version 1, no other tab's id),
    else the built-in deny-all. Prompts are off until B3 and the broker's gallery baseline is
    kept. The broker validates the policy against its schema, and a rejection fails the start;
  - `ca.get`.

  `broker.shutdown` runs on stop and quarantine.
- **Pod** (`drivers/oci.ts`, protocol §6):
  - The broker runs read-only with no capabilities, its own tmpfs and `SECLAB_TAB_ID`.
  - It sits on its own egress network (ICC off), connected to the pod's `--internal` network
    under the alias `broker` before it starts.
  - The workspace stays on the internal network only.
- **Getting the proxy and CA into the tab.**
  - `seclab-tab-env` starts every tab process with `env -i`, so `docker exec -e` can't reach
    them. Instead, tabd writes `proxy-url`, `ca.pem` and `bundle.pem` into a root-owned tmpfs
    in the workspace, `/run/seclab-broker`, mounted `nosuid,nodev,noexec`.
  - It uses a fixed root script, with the URL and PEM on stdin. The password is in no argv,
    audit record or container config.
  - `seclab-tab-env` validates the URL's characters, then sets the proxy variables (both cases)
    and `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` and
    `GIT_SSL_CAINFO`.
- **Opt-in for now:** `seclab-tabd --broker required` (OCI only; sbx refuses it until B2).
  `./seclab test e2e-broker` and the CI `oci` job (on pushes) run it.

## Deviation from the protocol doc
Protocol §7 asks for the CA in the tab's system store, installed as root at creation. The OCI
workspace's root filesystem is read-only, and the broker's CA changes on every broker start.
So the CA goes into a root-owned tmpfs, and every TLS client is pointed at it through the
environment variables above. A client that ignores all of them would fail TLS through the
broker, which fails closed.

## Consequences
- **Verified locally on 2026-11-05** (`./seclab test e2e-broker`, broker 0.3.1). From inside
  the tab:
  - an unlisted host gets `403` with `X-Seclab-Broker: denied`;
  - `--noproxy '*'` can't connect at all;
  - the policy's `GET` host returns `200`, with TLS trusted through the tab CA;
  - a `POST` to it gets `403`;
  - wrong proxy credentials get `407`;
  - the password appears in no file in the state directory;
  - removing the tab removes both networks;
  - teardown is clean.
- **Adoption.** A tab adopted by a restarted tabd has no control connection until its next
  `ensureRunning`. The broker keeps its last policy meanwhile. B3, which needs live
  notifications, reconnects at adoption.
- **Accepted: the proxy credential is in the tab's environment** (XX-3). It is tab-scoped.
- **Next:**
  - make the broker the OCI default once CI has run it;
  - B2: sbx, with the broker on loopback and the fence allowing only its port;
  - B3: prompts through the Tab Manager.
