# Security review: broker WebSocket credential opt-in

- **Date:** 2026-11-05
- **Scope:**
  - Round 6: `b1558e9` and `83a00cf`.
    - `b1558e9`: the `websocket: true` binding opt-in (policy schema
      revision 2).
    - `83a00cf`: upgrade-signal detection and the 101 block.
  - Threat model: a rogue extension in full control of its tab, and possibly
    of an upstream on an allowed host, trying to get a real credential into a
    connection that becomes a WebSocket or any other piped stream, without an
    opted-in binding. Invariant: no real or derived secret enters a tab
    ([ADR](../adr/20261104-no-real-secret-enters-a-tab.md)).
- **Reviewer:** `security-review` agent (default model; it did not refuse).
  - It ran mitmproxy 12.3.1's `DumpMaster` with `SeclabAddon` from the HEAD
    source, with `--network none`.
  - The upstream was a malicious TLS server that answers 101 to every request
    and streams a token split across frames.
  - It confirmed mitmproxy's behaviour by reading the source in the image.
- **Found by the broker session before review:** mitmproxy switches to
  WebSocket on a 101 response plus the request's `Sec-WebSocket-Version`,
  whether or not the request has an `Upgrade` header. So an upstream could have
  switched a credentialed plain GET. Fixed in `83a00cf`:
  - every upgrade signal counts (`Upgrade`, `Sec-WebSocket-*`,
    `Connection: upgrade`, CONNECT);
  - the response hook blocks a 101 on an injected flow that was not approved
    as a WebSocket.

  Regression test: `test_protocol_switch_on_credentialed_request_needs_approval`.

## Findings
| # | Severity | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| — | — | — | No vulnerabilities found. | — | — | — |

End-to-end results from the reviewer:

| Case | Result |
|---|---|
| Plain credentialed GET; upstream answers 101 | Upstream gets the real value (bound route); the tab gets a 502; no frame bytes reach the tab; the next request on the tunnel opens a fresh upstream connection |
| GET with only `Sec-WebSocket-Version: 13` | 403 before upstream |
| Full handshake, binding without `websocket: true` | 403 before upstream |
| Malformed header names (space before the colon) | mitmproxy returns 400; nothing reaches the upstream |
| Full handshake, opted-in binding | Relayed; a token split mid-way loses its second half (the documented opt-in residual) |

Confirmed sound:
- **Request-side checks:**
  - `_upgrade_token`, and the upgrade gate in `Binding.matches`;
  - `seclab.ws_ok` only when the request upgrades to `websocket` and every
    planned binding opts in;
  - `ws_refused` with several sentinels.
- **The 101 block:** it runs in the response hook before `flow_done`, and the
  replaced status keeps mitmproxy from upgrading.
- **mitmproxy behaviour:**
  - HTTP/2 extended CONNECT is unsupported (`:protocol` is rejected), and
    CONNECT never reaches the `request` hook;
  - HTTP/2 101s are swallowed;
  - `rawtcp` is off, so non-WebSocket 101s close the connection.
- **Approval and credential paths:**
  - unconfirmed imports are prompted only for non-upgrade requests;
  - allow-once and allow-tab bindings never carry `websocket`;
  - only the trusted controller can set it;
  - `cred.proposed` contributes only `inject`;
  - derived credentials inherit the parent's bindings, opt-in included.
- **Schema:** it accepts only a literal boolean.

**After review:** no high or critical findings remain.
