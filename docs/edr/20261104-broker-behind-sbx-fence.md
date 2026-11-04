# Broker behind the sbx 0.51 fence: chaining, proxy auth and isolation validated

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** broker session. This extends the Fork-build session's [fence spike](20261104-sbx-fence-spike.md) with the real broker.
- **Related:** [ADR single broker, sbx fence](../adr/20261104-single-broker-sbx-fence.md)

## Context
Under the sbx provider:
- the broker is a Docker Desktop container published on `127.0.0.1:P`;
- the tab is an sbx microVM whose per-sandbox policy allows only
  `localhost:P`.

The spike used a stock mitmdump. This record checks the real broker end to
end: proxy auth, policy, sentinel swapping, HTTP/2 and git. It also covers
what sbx 0.51 can and cannot do on its own.

## Decision
Use the mitmproxy broker behind the sbx fence, as the ADR says. Make
`broker/tests/sbx/validate.sh` the repeatable check. It needs only `docker`
and `sbx` on the host, and never changes sbx's global policy.

## Results (sbx v0.51.0, Docker 29.8.0, macOS, 2026-11-04)
All 15 checks passed (`.work/broker/sbx-validation/results.txt`):

| Check (from inside the sbx tab) | Result |
|---|---|
| Allowed host through the broker (CONNECT chained via sbx to `host.docker.internal:P`) | 200 |
| Default deny | 403 from the broker |
| HTTP/2 through the broker | `http_version` 2 |
| Sentinel swapped on a binding match | upstream `sha256(Authorization)` equals `sha256("Bearer " + real)` |
| Sentinel on a wrong path of the bound host | 403, not swapped |
| Sentinel POSTed to an allowed but unbound host (gist) | 403, not swapped |
| Wrong proxy password / no proxy credentials | 407 / 407 |
| Another tab's broker port (`host.docker.internal:P+1`) through a proxy | blocked by sbx (curl rc 56) |
| Direct to another loopback port / `host.docker.internal:22` | blocked by sbx |
| sbx's own proxy to broker-only upstreams | blocked (default deny) |
| Tab resolves broker-side names | no (`getent` rc 2) |
| Tab resolves public names (`example.com`) | no: `DNS lookup blocked by proxy policy` |
| git clone over HTTPS using the sentinel | works |
| Canaries in tab output or audit log | none |

`sbx policy log` evidence: `localhost:18480` was allowed (9 times). Denied:
`localhost:18481`, `localhost:22` and `api.example.test:443` (forward proxy,
"No matching allow rule"). The DNS lookups for `api.example.test` and
`example.com` were blocked by the proxy policy.

### What sbx 0.51 can and cannot do (as the engine)
- **Can:** live per-sandbox network rules; HTTP method, path and query network
  rules (per its CLI help); host-bound secrets via `secret set-custom --host
  --placeholder`; DNS policy enforcement; HTTP/2.
- **Cannot:** bind a secret to a path or a method. A sentinel sent to an allowed
  path on the bound host (a gist POST to github.com) would get the real token.
  It also cannot hold a request while a user decides (the client has to retry
  after `sbx policy allow`), rewrite or scan responses, or re-sentinelise minted
  tokens. So it is used only as the outer fence. An sbx-native adapter would be
  a documented fallback with reduced guarantees; it is not built.

## Alternatives considered
- **Run the broker inside the sbx VM:** rejected. Real secrets would then sit
  in the tab's isolation domain.
- **Use sbx's proxy as the engine:** rejected. See "Cannot" above.

## Consequences
- **Proxy auth is required and was validated.** Without it, any process on the
  Mac could use a tab's broker. The supervisor generates the credential and
  delivers it over stdio (`proxy.auth.set`).
- **Each broker needs its own port, and each sandbox may allow only its own
  port.** Cross-tab access was shown to be blocked by sbx.
- **The global sbx allows remain the Fork-build session's concern** (mirror and
  verify). This script adds only a per-sandbox allow. According to the
  [spike EDR](20261104-sbx-fence-spike.md), global allows such as
  `api.anthropic.com` therefore stay reachable directly through sbx's own
  proxy. In production the per-tab mirrored denies close that path.

## Evidence
- Script: [`broker/tests/sbx/validate.sh`](https://github.com/anticomputer/seclab-vscode/blob/1e83fdc951ffccab6a2ae645f5ee90c441d178dd/broker/tests/sbx/validate.sh)
  (run 2026-11-04; all PASS).
- sbx CLI help (`sbx policy allow network --help`, `sbx exec --help`) on v0.51.0.

## Update 2026-11-04: fixture safety
The script has been hardened (see
[EDR docs and safe fixtures](20261104-broker-docs-from-sources-and-safe-fixtures.md)):
- random per-run names;
- ephemeral loopback-only ports;
- verified teardown of the user's global sbx state.

The `host.docker.internal:22` and `example.com` probes in the table above were
**removed**: if the fence had failed, they would have touched the user's real
sshd and an external name. Isolation is still shown by the probes to the other
tab's broker port. A re-run passed every remaining check, plus "global policy
and secrets unchanged" and "nothing left behind".
