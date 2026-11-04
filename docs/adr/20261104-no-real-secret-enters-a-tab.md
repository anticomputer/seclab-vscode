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
- The scanner is pattern based. An upstream that mints a credential in an
  unrecognised format, in a header the scanner doesn't look at, would get
  through. Bindings are therefore the first line of defence, and the backstop
  and scanners are defence in depth.
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
