# Security review: backstop derive exemption and `GET /copilot_internal/user` exception

- **Date:** 2026-11-05
- **Scope:** round 8.
  - `defba0a`: a confirmed credential's request on the exact `from` route of
    one of its own `derive` rules passes the provider backstop (needed for D7:
    the Copilot token endpoint is backstopped).
  - `ee7e053`: the coordinator-approved, data-level exception for exactly
    `GET /copilot_internal/user`, with no body, query or upgrade. Its response
    must be a strict JSON object with no credential-named key and no
    token-shaped value.
  - Design: [ADR broker model access](../adr/20261105-broker-model-access.md).
  - Threat model: a rogue extension in full control of the tab, possibly
    choosing or controlling an upstream on an allowed host, trying to get a
    real minted token or any backstopped capability into the tab.
- **Reviewer:** `security-review` agent (default model; it did not refuse).
  It called `SeclabAddon.request()` and `response()` directly on mitmproxy
  test flows, from the HEAD source, with `--network none`. Triage and
  hardening by the broker session.

## Findings
| # | Severity | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| — | — | — | No vulnerabilities found. | — | — | — |
| H1 | Hardening | Derive route | Non-2xx responses on a derive route were not derived, only pattern-scanned, so an opaque token in a 3xx/4xx would pass. Not a finding: the route is on `api.github.com`, which the tab cannot choose. | applied | Non-2xx responses on a declared derive route get the exception response check (strict JSON, no credential-named key, no token-shaped value), so "derived or blocked" holds for any status. | `it:test_backstop_exempts_only_a_declared_derive_route` (path), unit coverage of the check |
| H2 | Hardening | Exception response | Response header names were not matched against the credential-key pattern (`X-Copilot-Token` with an opaque value passed). | applied | Header names are matched too. | `it:test_backstop_exception_copilot_user_is_narrow_and_its_response_is_checked` |
| H3 | Hardening | Derive route | `DeriveRule.matches` ignored the query (`?callback=x`; a JSONP 200 was blocked anyway as non-JSON). | applied | A derive route requires an empty query, like the exception. | `test_trusted_derivation_rules_are_exact_and_controller_bound` |

Confirmed sound by the reviewer:
- **Route match, both mechanisms:** exact. `HEAD`/`POST`, a trailing slash, a
  case variant, another port, `?a=1`, a body and an upgrade are all denied.
  Percent-encoded forms of the same path reach the same endpoint, and
  `canonical_path` refuses `%2F`, `%2E`, `%25`, `;`, `//` and dot segments.
- **Several credentials:** each credential's exemption is decided on its own
  backstop and exception. The flow-level exception flag only adds the
  stricter response check.
- **Unconfirmed imports and `proposedBind`:** they can't trigger the derive
  exemption.
- **Derive responses:**
  - a JSON 2xx is replaced, and a duplicate token is caught by `_scrub_real`;
  - non-JSON, 206, empty and undecodable 2xx responses are blocked;
  - there is no streaming, and HTTP/2 bodies are buffered.
- **Exception response check:** runs on every status. A nested or escaped
  `token` key, `ghu_…` values, undecodable compressed bodies, a non-JSON 401
  and an empty 302 are blocked.
- **Residual (accepted):** a credential the upstream sends under a key or in a
  shape the check doesn't recognise would pass. That needs `api.github.com`
  itself to send it, which the tab can't choose. A field allowlist replaces
  the key pattern once real traffic is measured.

**After review:** no high or critical findings remain.
