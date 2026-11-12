# One broker engine for every provider; sbx is only the outer fence

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** Project owner (2026-11-04); seclab-vscode coordinator
- **Editorial redaction (2026-11-12):** quotations of project conversations replaced with neutral statements; decisions unchanged.

## Context
Egress policy, credential injection and scope-expansion prompts are the
product, and they must behave the same on every provider (OCI, sbx, VM,
cloud). sbx ships its own proxy with per-host secrets and network rules.

## Decision
- **Our mitmproxy-based broker is the single policy and credential engine.**
  It runs per tab: on Docker Desktop as a container driven over `docker exec -i`
  stdio; under OCI as the pod's sidecar.
- **Under sbx, sbx's policy is only an outer fence.** The per-tab sbx policy
  allows exactly that tab's broker endpoint (`localhost:<port>`, reached as
  `host.docker.internal:<port>`) and denies everything else, including any
  global allows. The tab's `HTTP(S)_PROXY` and `http(s)_proxy` point at the
  broker, and the per-tab CA is installed.

## Alternatives considered
- **sbx's native proxy as the engine**: rejected. As of v0.39, secrets and
  rules bind to a host only, so a POST to an allowed gist host would carry the
  real token. It also could not hold a request while the user is prompted.
  **Re-evaluate against 0.51**: it adds HTTP method and path network rules and
  a `policy approval` verb, but `secret set-custom` still binds by `--host`
  only (see [EDR](../edr/20261104-sbx-upgrade-0-51.md)).
- **sbx only, no broker**: rejected. Behaviour would differ per provider.

## Consequences
- Chaining works (spike): sbx does not re-target or intercept inside a
  CONNECT/SOCKS tunnel to an allowed loopback port, and our CA terminates TLS.
- The published loopback port is reachable by any local process, so the broker
  needs per-tab proxy auth.
- Global sbx allows leak into tabs unless they are mirrored as per-sandbox
  denies (or the global policy becomes deny-all, which needs the user's
  consent).
- Gaps against ARCHITECTURE.md §4.4–4.5 under sbx: the broker is a separate
  Docker Desktop container rather than a pod sidecar.

## Evidence
- [EDR 20261104-sbx-fence-spike](../edr/20261104-sbx-fence-spike.md)
- [`docs/research/cred-broker.md`](../research/cred-broker.md)
- sbx network rules docs: https://docs.docker.com/ai/governance/local/network-rules/
