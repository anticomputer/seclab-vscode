# DNS on an `--internal` network: no exfiltration path through Docker's embedded resolver (Docker 29.8)

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** broker session
- **Related:** ARCHITECTURE.md §4.4 and §7 ("we must verify there is no DNS exfiltration path")

## Context
In the OCI pod the workspace sits only on a `--internal` network whose one peer
is the broker. Docker's embedded resolver (127.0.0.11) still answers in that
container. Older Docker versions forwarded external queries for
internal-network containers from the host namespace, which is a known
exfiltration channel: CVE-2024-29018 /
[GHSA-mq39-4gv4-mvpx](https://github.com/moby/moby/security/advisories/GHSA-mq39-4gv4-mvpx),
fixed in Moby 26.0.0, 25.0.5 and 23.0.11. Current Moby starts the resolver
with `proxyDNS=false` when the sandbox has no gateway
([sandbox_dns_unix.go](https://github.com/moby/moby/blob/43cc79083a4364c548703bc9fffa88105c680d25/daemon/libnetwork/sandbox_dns_unix.go),
[resolver.go](https://github.com/moby/moby/blob/43cc79083a4364c548703bc9fffa88105c680d25/daemon/libnetwork/resolver.go)).

## Decision
- **Rely on the topology for name resolution.** The tab resolves nothing
  external; the broker resolves names itself.
- **Make the behaviour a regression test** instead of trusting the advisory:
  [`test_no_dns_exfiltration_via_embedded_resolver`](https://github.com/anticomputer/seclab-vscode/blob/b398fedca43f78e5152a26bec0b3d5e9de7a579f/broker/tests/integration/test_network.py).
  It runs every time the suite runs.

## Test design
A logging DNS server (UDP and TCP on 53) runs on the broker's fake-internet
network and records every query name. Each probe uses a unique random label:
- **Positive control:** a container on a normal network with `--dns <logger>`.
  It **must** be logged, which proves the detector works.
- **Probe 1:** from the workspace, `getent hosts` and `dig @127.0.0.11`
  (embedded resolver).
- **Probe 2:** from the workspace, `dig` straight at the logger's IP, over UDP
  and TCP.
- **Probe 3:** a container on the internal network that is explicitly started
  with `--dns <logger>` (the CVE-2024-29018 scenario), queried through
  `getent` and `dig @127.0.0.11`.

## Result (Docker Desktop, engine 29.8.0, linux/arm64)
- The positive control was logged.
- None of probes 1–3 reached the logger.
- From the workspace, `getent hosts api.example.test` fails, and a
  proxy-unaware `curl` fails with "Could not resolve host". Direct-IP
  connections fail with no route.

**There is no DNS exfiltration path from an internal-only container on this
engine.**

**Under sbx** (validated separately, see the
[sbx EDR](20261104-broker-behind-sbx-fence.md)), sbx's DNS proxy blocks lookups
that its policy doesn't allow. `sbx policy log` shows `DNS lookup blocked by
proxy policy` for `api.example.test` and `example.com`.

## Consequences
- The test must stay in the suite. A Docker or Docker Desktop regression would
  surface as a failure there.
- Providers other than OCI (sbx, VM) need their own DNS check. sbx's is
  covered by the sbx validation script.

## Evidence
- `broker/test.sh` at `b398fed`: `test_no_dns_exfiltration_via_embedded_resolver
  PASSED`, `test_proxy_unaware_clients_fail_closed PASSED`.
