# Broker engine: mitmproxy 12.3.1 with our addon (over smokescreen and Envoy)

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** broker session (within ARCHITECTURE §4.5, which names mitmproxy as the first engine)
- **Related:** [ADR policy and protocol](../adr/20261104-broker-policy-and-control-protocol.md)

## Context
The broker has to do several things:
- terminate TLS with a per-tab CA;
- see HTTP/1.1, HTTP/2 and WebSocket traffic inside CONNECT tunnels;
- hold a request while a human decides;
- rewrite exactly one header;
- scan and rewrite responses;
- change policy live.

The user asked us not to reinvent wheels.

## Decision
- **Base image.** We use the official `mitmproxy/mitmproxy:12.3.1` image,
  pinned by manifest-list digest `sha256:2711066c…829d4` (Python 3.15). Our
  addon runs in-process via `DumpMaster` with termlog and dumper off.
- **Dependencies.** The only extra runtime dependency is `fastjsonschema`,
  hash-pinned.
- **Engine-specific code** is confined to
  [`engine_mitmproxy.py`](https://github.com/anticomputer/seclab-vscode/blob/b398fedca43f78e5152a26bec0b3d5e9de7a579f/broker/seclab_broker/engine_mitmproxy.py).
- **Options that matter:**
  - `connection_strategy=lazy`: no upstream connection before the policy
    decision.
  - `rawtcp=False`, plus kill in `tcp_start`/`udp_start`.
  - `http2` and `websocket` on.
  - `ssl_insecure=False`.
  - `block_global` and `block_private` off: our own auth and guard replace
    them.
  - No `stream_large_bodies`, so bodies are scanned whole.
- **We reuse rather than rebuild:**
  - CA generation (`certs.CertStore.create_store`);
  - TLS interception and HTTP/2 and WebSocket handling;
  - `Flow.intercept()`/`resume()`;
  - upstream verification against certifi.
- **We built our own proxy auth.** mitmproxy's `SingleUser` validator compares
  with `==`, which is not constant-time
  ([proxyauth.py](https://github.com/mitmproxy/mitmproxy/blob/51c1d6b2d8d3367a773411eb7a3eeccec82b3ea7/mitmproxy/addons/proxyauth.py)),
  and its credential would sit in an option. Ours follows the same
  per-connection pattern but uses `hmac.compare_digest`.

## Alternatives considered
- **smokescreen**: rejected for v0. It is a solid CONNECT ACL and SSRF proxy,
  and can MITM and `AddHeaders` per domain
  ([smokescreen.go L1010-L1033](https://github.com/stripe/smokescreen/blob/5b4b7aabca9bc70a8435358d648edd03294c299e/pkg/smokescreen/smokescreen.go#L1010-L1033)).
  But it has no hold-and-resume, no response rewriting, and no path or method
  matching inside the tunnel. Policy is file-loaded, not live. It remains a
  candidate adapter, and its SSRF ideas are reflected in our address guard.
- **Envoy** (`credential_injector` plus xDS): rejected for v0. It needs a full
  xDS control plane. Holding requests for a human needs `ext_authz` or a Wasm
  filter, and the credential injector is aimed at workload identity. It is
  heavy per tab.
- **sbx's native proxy**: rejected as the engine (see the
  [single-broker ADR](../adr/20261104-single-broker-sbx-fence.md)). Its secrets
  are host-only, and it cannot hold a request.
- **A bespoke Go or Python proxy**: rejected. It would reinvent TLS
  interception, HTTP/2 and WebSockets.

## Consequences
- **Cost:** about 380 MB per image and one Python process per tab. Throughput
  is fine for an editor tab.
- **mitmproxy behaviour we had to work around:**
  - Hook exceptions are logged and the flow continues, so every hook is
    wrapped fail-closed.
  - Pinning the vetted IP into `server.address` disables upstream connection
    reuse.
  - Inside tunnels the HTTP/1 absolute-form authority is kept, so we reject
    mismatches and force origin-form.

  The first two are documented in the README's open issues; the third was a
  security review finding.
- **mitmproxy upgrades:** re-run `broker/test.sh` and check these hook
  semantics against the new source.

## Evidence
- **How hooks are dispatched:**
  - Each hook runs as its own task: `ConnectionHandler.server_event` calls
    `create_task(self.hook_task(...))`
    ([server.py](https://github.com/mitmproxy/mitmproxy/blob/51c1d6b2d8d3367a773411eb7a3eeccec82b3ea7/mitmproxy/proxy/server.py)).
  - The handler awaits the hook, then `wait_for_resume`, with the idle
    watchdog disarmed
    ([mode_servers.py](https://github.com/mitmproxy/mitmproxy/blob/51c1d6b2d8d3367a773411eb7a3eeccec82b3ea7/mitmproxy/proxy/mode_servers.py)).
- **Lazy connections and SNI:**
  - `eager` would open the upstream at CONNECT time (`handle_connect_regular`).
  - The upstream SNI comes from the request host before `server_connect`
    (`get_connection`)
    ([http/\_\_init\_\_.py](https://github.com/mitmproxy/mitmproxy/blob/51c1d6b2d8d3367a773411eb7a3eeccec82b3ea7/mitmproxy/proxy/layers/http/__init__.py)).
- **Tests:** HTTP/2 (`test_http2_end_to_end`), WebSocket
  (`test_websocket_handshake_injection_and_message_scanning`) and hold and
  resume (`test_held_request_resumes_without_retry`) all pass.
