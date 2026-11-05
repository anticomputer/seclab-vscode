# No real or derived secret ever enters a tab

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** anticomputer (user). Verbatim: "a core design stipulation is that we never allow a sandboxed environment to obtain a real secret" and "our threat model is that of someone installing a rogue extension". Also: secrets found in a workspace before mounting move into the broker.
- **Related:** [ADR policy and protocol](20261104-broker-policy-and-control-protocol.md), [EDR sentinels](../edr/20261104-sentinel-format-and-binding.md), [security review](../security-reviews/20261104-broker-m2-m3.md)

## Context
ARCHITECTURE.md §4.5 already swaps sentinels for real values on egress. A
rogue extension in full control of its tab can still try several things:
- put a sentinel where a find-and-replace would turn it into the real token
  (a gist body);
- get an upstream to echo the token back;
- use the injected token to **mint** a new one (installation tokens, OAuth
  exchanges, session cookies), or to register its own durable credential (SSH
  or deploy keys, runner tokens).

## Decision
The broker enforces all of the following. Each item has a regression test.

1. **Injection by placement only.** The real value is written only into
   `binding.inject.header`, only on a request matching the binding's host,
   path, method and port, over HTTPS, and only when the sentinel is in that
   header (raw, or inside Basic). Sentinels are never find-and-replaced in
   bodies, URLs, query strings, trailers, other headers or WebSocket frames.
   Any such occurrence is audited as `sentinel.misplaced` and blocked
   (default) or forwarded unswapped.
2. **Response scanning.**
   - Every response, header, trailer and server WebSocket frame is checked for
     known real values in raw, base64 (any alignment, standard and URL-safe),
     URL-encoded, hex or JSON-escaped form. A raw echo is rewritten to the
     sentinel; any other encoding blocks the response.
   - On credentialed flows and bound hosts, newly minted tokens are
     re-sentinelised as **derived credentials** that inherit the parent's
     bindings (`credential.derived`), or are redacted. Detection uses gitleaks
     rules (GitHub token formats, JWT, npm, PyPI), a Copilot token pattern, and
     generic JSON/form `token` fields.
   - `Set-Cookie` and similar session headers on credentialed flows are
     stripped.
3. **Endpoints that create credentials.**
   - Bindings are allowlists by method and path.
   - A data-driven per-provider **backstop deny-list**
     ([`providers/github.json`](../../broker/seclab_broker/data/providers/github.json),
     checked against the pinned GitHub REST OpenAPI description) blocks
     credentialed calls that mint or register durable credentials, even when a
     binding would allow them.
4. **Custody.**
   - Real values live only in broker memory.
   - There are no core dumps, and the process is non-dumpable
     (`PR_SET_DUMPABLE=0`).
   - The root filesystem is read-only, and the only writable path is a tmpfs.
   - Every audit string is scrubbed.
   - Nothing is persisted to mitmproxy flows (no `save_stream_file`, no
     termlog or dumper).
   - `broker.shutdown` drops everything on tab close.
   - Imported credentials are persisted by the supervisor in the macOS
     keychain, never by the broker.
5. **Isolation domain.**
   - Under sbx, the tab is a microVM and the broker lives in Docker Desktop's
     VM.
   - Under OCI they share a kernel. This is a weaker class, documented in the
     [capability matrix](../../broker/README.md#engine-capability-matrix).
6. **Credential import.** `credential.import` moves secrets found in the
   workspace, or captured password input, into the broker:
   - the supervisor can choose the sentinel, so rewritten files keep working;
   - the binding is confirmed on first use by a prompt;
   - the confirmed binding is returned for keychain persistence.

## Alternatives considered
- **Find-and-replace sentinels anywhere in a request:** rejected. A sentinel in
  a gist body would become the real token on github.com.
- **Host-only binding (sbx `secret set-custom --host`):** rejected. It has the
  same gist problem, and there is no method or path.
- **Block every token-looking string in responses:** too broad; it would break
  normal APIs. Instead, scan on credentialed flows and bound hosts only, and
  use derived sentinels so OAuth-style flows keep working.
- **Strip and forget minted tokens:** breaks token-exchange flows.
  Re-sentinelising keeps them working without the tab holding a real value.

## Consequences
- Endpoints that legitimately return tokens work: the tab receives a sentinel,
  and the broker swaps it back on the same bindings.
- The scanner is pattern based: it decides what a token is from its *shape*,
  while the client in the tab reads tokens by *position* (whatever field its
  API defines). So two things get through it:
  - an upstream that mints a credential in an unrecognised format, or in a
    header the scanner doesn't look at;
  - an upstream that echoes the real value in an encoding the scanner doesn't
    check (split, reversed, re-encrypted).

  The second needs a malicious bound upstream, which already received the value
  when it was injected. The positional controls are therefore the first line of
  defence:
  - **Injection is positional.** The broker writes its own rendering into the
    binding's header, and only on a route the binding names. The sentinel is
    only a trigger, and is never swapped in place.
  - **Bindings and the backstop** decide by route which endpoints receive a
    credential at all.

  The scanners are defence in depth.
- **Credentials go into WebSocket upgrades only by opt-in** (policy schema
  revision 2, decided by the coordinator on 2026-11-05). A binding injects into
  an upgraded connection only if it has `websocket: true`, and only for the
  WebSocket protocol. Without it, a credentialed upgrade is refused with 403.
  An unconfirmed imported credential is never offered for an upgrade through
  a first-use prompt, because the suggestion cannot carry the opt-in. This is
  a route decision, made before any byte flows, so by default the scanner
  below is not what stands between a minted token and the tab
  (`test_websocket_credential_needs_binding_opt_in`).
- **For opt-in bindings, WebSocket streams are scanned as a stream**, as
  defence in depth. Each server message is scanned
  together with the last 8 KiB the tab already received on that connection, so
  a token whose key and value arrive in separate messages is still
  re-sentinelised. HTTP bodies are buffered whole, so the response scanner
  always sees complete content.

  **Residual, opt-in bindings only.** A match that starts in bytes the tab
  already has cannot be recalled. The broker drops that message and every
  later one on the connection, and audits `response.blocked`. If the match
  only became recognisable once its terminator arrived (for example the JSON
  token field's closing quote), the tab already holds the whole token. That
  case is detected, not prevented. Preventing it would mean holding and
  reframing messages, which breaks message-oriented protocols.

  Two kinds of stream are not reassembled at all:
  - tokens split across structured deltas (JSON-wrapped chunks), whether the
    pieces are adjacent or spread more than the 8 KiB window apart;
  - tokens split across separate HTTP responses.

  The window is over raw bytes, while the consumer accumulates a field, so no
  window size closes this. Opt in only for an upstream you trust not to mint
  tokens on that connection (`test_websocket_token_split_across_messages`).
- A rogue extension can still **use** the credential through its binding
  while the tab lives. That is the accepted per-tab blast radius.
  Per-extension attribution is later work (ARCHITECTURE §8).

## Evidence
- Canary tests:
  [`test_canary_sweep`](https://github.com/anticomputer/seclab-vscode/blob/b34dfb907f2550e1eae792253a4086cf844b2bae/broker/tests/integration/test_zz_custody.py)
  checks every tab output, the audit log, notifications, broker logs and the
  tab environment for each canary in every encoding.
  `test_reflection_in_other_encodings_blocked`,
  `test_minted_token_is_resentinelised`,
  `test_session_cookies_from_credentialed_requests_are_stripped` and
  `test_provider_backstop_beats_binding` cover the individual rules.
- GitHub endpoints come from
  [rest-api-description@99b1432](https://github.com/github/rest-api-description/blob/99b1432b55b9a71d0881fd792a87f1807cf4c8f2/descriptions/api.github.com/api.github.com.json).
  Each entry in `providers/github.json` carries its operationId and docs URL.
- Token rules come from
  [gitleaks@5f6ec56](https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/config/gitleaks.toml).
- The custody tests pass: `test_broker_process_custody` checks that
  `/proc/1/environ` and `/proc/1/mem` are unreadable, the core limit is 0, the
  CA key is mode 0600 on tmpfs, and no canary is on the broker's filesystem.
