# sbx per-tab egress fence and broker chaining (spike)

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** Project owner (2026-11-04): mirror-plus-verify decision; fork-build session (spike); coordinator
- **Related:** [ADR single broker](../adr/20261104-single-broker-sbx-fence.md)
- **Editorial redaction (2026-11-12):** quotations of project conversations replaced with neutral statements; decisions unchanged.

## Context
The design puts our mitmproxy broker in front of every tab, with sbx's policy
acting only as a fence. Open questions: can a sandbox reach a Docker-published
loopback port when only that port is allowed? Does sbx intercept or re-target
traffic inside a proxy tunnel? What else is reachable?

## Decision
`SbxProvider` fences each tab as follows:
1. The broker for tab *T* is published on `127.0.0.1:<P_T>` by Docker Desktop.
2. Add a per-sandbox rule `sbx policy allow network --sandbox T localhost:<P_T>`.
   **Use the resource `localhost:P`.** sbx normalises `host.docker.internal:P`
   to `localhost:P`, so a rule naming `host.docker.internal:P` never matches.
3. **Mirror and verify, failing closed** (project owner decision: mirror plus
   verify; add per-tab denies for every global allow, re-check the effective
   policy whenever a tab connects or reconnects, and refuse to connect the tab
   on any mismatch).
   - **At create:** read `sbx policy ls --wide --json`. For every network
     `allow` rule that applies to *T* (global, kit-scoped or sandbox-scoped),
     add a per-sandbox `deny` for each of its resources. Deny beats allow.
   - **On every resolve and reconnect (every `makeConnection`):** re-read the
     effective policy. If any allow resource that applies to *T*, other than
     `localhost:<P_T>`, is not covered by a per-sandbox deny with the same
     resource string, **refuse the connection** and show the reason in the UI.
     A cheap `sbx policy check network` probe set backs this up: `localhost:<P_T>`
     must be allowed; a fixed external canary, another loopback port and each
     non-wildcard global allow must be denied.
   - **While connected:** re-verify every 60 s. On a mismatch, end all of
     *T*'s managed connections (which kills the `exec` children) and notify.
     The global policy is never changed without the user's consent, because
     it is shared with their other sandboxes.
4. Inside the tab, set **both** `HTTP_PROXY`/`HTTPS_PROXY` **and**
   `http_proxy`/`https_proxy` to `http://host.docker.internal:<P_T>` (plus
   per-tab proxy credentials), and install the per-tab CA. sbx pre-sets the
   lowercase variables to its own proxy, and curl prefers lowercase. A
   containment test asserts that sbx's injected values never win.

### Drift-window trade-off
A global allow added after the last check is reachable from *T* until the next
check. Checks run on connect and reconnect, then every 60 s while connected,
so the window is at most about 60 s plus the time to run `sbx policy ls`
(~0.1 s). Shorter intervals cost one `sbx` process per tab per interval. sbx
offers no policy-change event to subscribe to, so polling is the only option.
60 s was chosen because global policy changes are rare and made by the user,
and an exploit needs the user to widen the global policy first. If sbx gains
a change feed, switch to it.

## Results
With only `localhost:18080`, `localhost:18081` and `localhost:18082` allowed on
sandbox `seclab-spike-a`:

| Probe from inside the sandbox | Result |
|---|---|
| `curl http://host.docker.internal:18080/` (nginx), via sbx proxy and direct | 200 / 200 |
| `curl http://host.docker.internal:18080/` with the rule written as `host.docker.internal:18080` | 403 / blocked: policy log shows `localhost:18080 … default deny` |
| `host.docker.internal:<other port>` (another tab's broker) | proxy 403, direct blocked |
| `gateway.docker.internal:18080`, `127.0.0.1:18080` (VM loopback) | blocked |
| `example.com` direct | blocked (DNS blocked by proxy policy) |
| HTTP proxy chain: `curl -x http://host.docker.internal:18081 http://example.com/` (mitmproxy) | 200; mitmproxy logged the request |
| CONNECT chain: `curl -k -x … https://example.com/` | 200; mitmproxy logged `GET https://example.com/ HTTP/2.0`, so **our** CA terminated TLS and sbx did not intercept inside the tunnel |
| SOCKS5 chain via `--socks5-hostname host.docker.internal:18082` (http and https) | 200 / 200 |
| `api.anthropic.com:443` (global allow), before / after per-sandbox `deny` | 404 (reachable) / 403 |

Pitfall seen while probing: `curl --noproxy "*"` also disables an explicit
`-x` or `--socks5-hostname`. Unset the env proxies instead.

## Alternatives considered
- **Global `deny-all`**: simpler, but it changes the user's other sandboxes.
  Needs consent; it is the fallback if the mirroring proves brittle.
- **TLS or SOCKS to the broker** to hide proxy semantics from sbx: unneeded,
  because a plain HTTP CONNECT chain works.
- **A per-tab policy profile (`sbx create --profile`)**: rejected. In 0.51
  `sbx policy profile` only lists profiles "provided by remote governance
  policies" (only `ls` exists), so profiles can't be defined locally.
- **Mirror only, without verify**: rejected by the project owner. Drift would leave a
  tab silently able to bypass the broker.

## Consequences
- The loopback-published broker port is reachable by any local macOS process.
  The broker **must** require per-tab proxy auth. Owner: broker session.
- Drift is bounded by the 60 s re-verify (see the trade-off above).
- Containment tests to add: the tab can't reach another tab's broker port,
  other host loopback ports, `gateway.docker.internal`, or global-allow hosts
  directly. sbx's lowercase proxy variables don't win.
- Proxy-credential format: agree with the broker session (owner: broker
  session).

## Evidence
Commands, run on 2026-11-04 with sbx v0.51.0 on macOS 26.7.2:
```
docker run -d --rm --name seclab-spike-web   -p 127.0.0.1:18080:80   nginx:alpine
docker run -d --rm --name seclab-spike-proxy -p 127.0.0.1:18081:8080 mitmproxy/mitmproxy mitmdump --listen-port 8080 --set block_global=false
docker run -d --rm --name seclab-spike-socks -p 127.0.0.1:18082:1080 mitmproxy/mitmproxy mitmdump --mode socks5@1080 --set block_global=false
sbx create --name seclab-spike-a --no-progress shell "$PWD/.work/spike/ws-a"
sbx policy allow network --sandbox seclab-spike-a localhost:18080   # likewise 18081, 18082
sbx exec seclab-spike-a env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy sh -c \
  'curl -sk -x http://host.docker.internal:18081 -o /dev/null -w "%{http_code}\n" https://example.com/'
sbx policy log seclab-spike-a
```

## Addendum (2026-11-05): sandbox-scoped kit allows
sbx 0.51 attaches a sandbox-scoped allow for its kit (`deb.debian.org:80`, `dhi.io:80`, a rule
id per sandbox) at create time. The mirror covered only `applies_to: all` allows, so the fence
check rightly refused every new tab. `resourcesToMirror(rules, sandbox, brokerPort)` now also
mirrors allows scoped to the sandbox, except the broker's own `localhost:<port>`. The driver
runs the mirror right after create and on every start, before the fence check. Unit test with
the 0.51 rule shape; `./seclab test containment sbx` 119/120 (the XFAIL is the known
attribution gap).
