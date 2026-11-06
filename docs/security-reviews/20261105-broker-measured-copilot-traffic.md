# Security review: measured Copilot traffic and the user's decisions (round 11)

- **Date:** 2026-11-05
- **Scope:**
  - "broker: measured Copilot traffic and the user's decisions" (schema
    revision 4, broker 0.4.0). See
    [ADR broker model access, Amendment 1](../adr/20261105-broker-model-access.md#amendment-1-2026-11-05-measured-copilot-traffic-and-the-users-decisions).
    - D7 amended by the user: the GitHub token is bound to the CAPI model
      routes by exact path and method.
    - The three org-policy GETs, approved by the user.
    - The `/copilot_internal/user` field allowlist.
    - `/mcp/readonly` behind a per-tab grant (coordinator decision).
    - The measured, per-endpoint `copilot` provider.
  - The round 10c fixes (re-checked).
  - Fixes: the round 11, 11b and 11c commits. The round 11 commit
    also adopts the secure-agentic review's two asks:
    - strict allowlists for the org-policy responses;
    - a server-side justification for each body-policy widening.
  - Threat model:
    - a rogue tab using the durable GitHub token, now on model traffic,
      beyond the measured routes and shapes;
    - a rogue or compromised upstream returning a credential through an
      exception route;
    - a typo in shipped data silently opening a gate.
- **Reviewer:** a general-purpose agent on an Opus-class CVP model with long
  context. It probed the code directly in containers and ran the full suite
  (257 unit, 58 integration). Triage and fixes by the broker session.

## Findings
| # | Severity | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| 11-1 | Medium | Shipped data | Built-in model providers were never validated against the `modelProvider` schema: they were substituted after the policy had been validated. A misspelt `requiresGrant` in `model-providers.v1.json` would silently open `/mcp/readonly`. The backstop data in `providers/*.json` had no schema at all, so a misspelt `responseFields` would disable the `/user` filter. | fixed (round 11 commit) | Every built-in provider is validated against `modelProvider` when loaded, plus the endpoint checks. Backstop files are checked for exact key sets. `strictFields` and `dropPaths` require `responseFields`. Any error fails the load. | `test_r11_shipped_provider_data_is_validated` |
| 11-2 | Low | Exception responses | The exception check looked at response headers, never at HTTP/2 trailers. A credential-named trailer with an opaque value passed. Session headers were stripped from headers only. | fixed (round 11 commit) | Headers and trailers are checked alike. Session headers (`Set-Cookie` and others) are stripped from trailers on credentialed flows too. | Code review; no fixture yet can send HTTP/2 trailers |
| 11-3 | Low | Exception responses | `benignKeys` were accepted at any depth, though they were measured only at specific places. | fixed (round 11 commit) | Benign keys are exact JSON paths (`$.token_based_billing`, `$.cloud_session_storage_enabled`, `$.quota_snapshots.*.token_based_billing`; `*` is one key). | `test_copilot_user_exception_has_the_measured_field_allowlist` |
| 11-4 | Low | Grants | `toolType` grants apply to every endpoint of their provider; `remote-content` disables the URL check on all of them. | documented | Kept provider-wide, and now stated in the schema's `grants` description, so the controller grants knowingly. Grants are controller policy, given per tab by the user. | n/a |
| 11-5 | Low | Body policy | Endpoint and provider selection is first match. A policy-declared endpoint listed before a grant-only one shadowed it, and a second provider could claim a built-in provider's host. | fixed (round 11 commit) | Refused at load: a grant-only endpoint reachable through an earlier endpoint with overlapping methods; providers whose host patterns overlap. | `test_r11_grant_only_endpoints_cannot_be_shadowed_and_hosts_cannot_overlap` |
| 11-6 | Info | Records | That only known token shapes are detected was not stated as a residual. | fixed (round 11 commit) | The ADR states it. The controls are the credential-name check, the field allowlists and `dropPaths`, not detection of the value. Token-shaped keys and URL userinfo now block as well. | `test_r11_url_userinfo_pattern` |
| 11-7 | Info | Exception responses | A bodiless 204 or 304 was blocked as "not strict JSON", and an error body lost its fields to the allowlist. | fixed (round 11 commit) | A bodiless response passes after the header and trailer checks. Error bodies get every check except the field allowlist. | Code review |
| 11-8 | Info | Harness | The first test run used a stale upstream fixture image. | not a defect | The broker session was rebuilding the same tags at the same time. The tags are shared, so concurrent runs race. | n/a |
| 11-9 | Info | Lock drift | `lockSources[].source` was only checked for existence; the drift comparison still used `<lock>.in`. | fixed (round 11 commit) | The registered source path is the one compared. | `broker/docs-check.sh` |
| 11b-1 | Medium | Exception responses | The 11-7 fix applied the field allowlist to 2xx only, so any other status (chosen by the upstream) skipped it, including the strict org-policy lists. That was also a regression for `/user`. | fixed (round 11b commit) | The allowlist and `strictFields` apply on every status. GitHub's error fields (`message`, `documentation_url`) are listed for `/user`; the strict org lists block an unlisted error body. | `test_org_policy_gets_are_narrow_and_their_responses_checked` (`unlisted-error`: a 403 carrying unlisted fields is blocked) |
| 11b-2 | Medium | Exception responses | The `telemetry.headers` drop walked only an exact chain of dicts with exact case. A list, a case variant or a deeper nesting delivered the OTLP credential unchanged, and a `*` in `dropPaths` silently matched nothing. | fixed (round 11b commit) | `dropPaths` replaced by `dropFields`, top-level names only and checked at load. `managed_settings` drops the whole `telemetry` field, whatever its shape. | Same test (`telemetry-list`, `telemetry-nested`); `test_r11b_backstop_data_is_checked_when_a_policy_loads` |
| 11b-3 | Low | Body policy | Shadow detection sampled one path and guarded only grant-only endpoints: a glob grant-only endpoint behind a literal one, or a stricter endpoint behind a looser one, was accepted. | fixed (round 11b commit) | A grant-only endpoint must be a literal path. No endpoint may sit behind an earlier one with an overlapping method that matches it. | `test_r11b_endpoint_shadowing_is_refused_both_ways` |
| 11b-4 | Low | Exception responses | URL userinfo missed an encoded colon (`user%3Apass@`) and the scheme-relative `//user:pass@`, and wasn't checked in headers or trailers. | fixed (round 11b commit) | Both forms are matched, in headers and trailers too. | `test_r11_url_userinfo_pattern` |
| 11b-5 | Low | Shipped data | Backstop files were checked at first request, not at load. | fixed (round 11b commit) | `Policy.from_json` loads them first, so malformed data rejects every policy. | `test_r11b_backstop_data_is_checked_when_a_policy_loads` |
| 11b-6 | Low | Approvals | `request.queryKeys` reached approval prompts without being listed in `untrusted`. | fixed (round 11b commit) | Listed whenever present. | Code review; the protocol's `requestSummary` marks it tab-controlled |
| 11b-7 | Info | Request summary | Query key truncation could split a `%XX` escape, and a sealed agent-host token in a key name was exported verbatim. | fixed (round 11b commit) | Truncation never splits an escape; a key containing `copilot-sealed.v1.` becomes `[sealed]`. The prefix now has one definition, in `policy.py`. | `test_r11_request_summary_carries_query_key_names_only` |
| 11c-1 | Low | Exception responses | A `dropFields` field was scanned before it was dropped. A realistic OTLP header (a token-shaped bearer) in `telemetry` blocked the whole `managed_settings` response, so the org lost its restrictions, and raised a false finding. | fixed (round 11c commit) | `dropFields` are removed before the whole-document scan: they never reach the tab, so their contents can't block the rest. | `test_org_policy_gets_are_narrow_and_their_responses_checked` (`telemetry-token`) |
| 11c-2 | Low | Exception responses | With the allowlist on every status, a routine GitHub 403, 404 or 429 on an org route became a 502 plus a security finding. | fixed (round 11c commit) | All three org lists include GitHub's REST error envelope (`message`, `documentation_url`, `status`). Its values get every other check. | `test_org_policy_backstop_exceptions_are_exact` |
| 11c-3 | Low | Exception responses | With the scheme optional, any text containing `//`, `:` and `@` matched as URL userinfo (`a//b:c@d`). | fixed (round 11c commit) | The scheme-less form must start at a boundary (start, whitespace, quote, `(`, `,`, `=`), and a host-like character must follow the `@`. | `test_r11_url_userinfo_pattern` |
| 11c-4 | Info | Request summary | Query keys kept raw `[` and `]`, so a tab could forge the `[sealed]` marker. | fixed (round 11c commit) | Keys are fully percent-encoded; the marker is inserted after encoding. | `test_r11_request_summary_carries_query_key_names_only` |
| 11c-5 | Info | Request summary | A sealed token in the path was exported verbatim, despite the docstring. | fixed (round 11c commit) | The summary's path replaces it with `[sealed]`, after encoding. | Same test |

**Adopted from the secure-agentic review** (same commit):
- **Strict org-policy allowlists.**
  - `managed_settings` follows the public `IManagedSettingsResponse`; its
    whole `telemetry` field (OTLP credentials) is always dropped (since 11b).
  - `team_customizations` and `content_exclusion` pass only `{}` (or GitHub's
    error envelope, since 11c) until their shapes are known.
  - Any unlisted top-level key blocks the response as a finding.
- **`queryKeys` in request summaries** (names only), so the next spike run
  measures the query names the runtime sends to `managed_settings?` and
  `content_exclusion?`.
- **A server-side justification for each widening** in the ADR: `/v1/messages`,
  `custom` with grammar, `snippy`, `system` and `thinking`.

Probed and held:
- **Untyped and `function` tools** go only where measured.
- **Path and host canonicalisation** (trailing slash, `//`, case, `;`, `%2F`,
  a trailing dot) fails the endpoint match.
- **Content type and encoding** strictness holds.
- **The endpoint grant** opens only `/mcp/readonly`, with its own four fields.
- **`custom` tools** carry their grammar inline: no URL, nothing executed on
  the provider.
- **Token placement.** Bindings are exact, so the GitHub token reaches no
  other CAPI path, and no redirect moves it.
- **Exception requests** with a body, query, upgrade or wrong case stay
  backstopped.
- **Response parsing.** Duplicate and case-variant keys are refused, and
  re-encoding follows `Content-Encoding`.
- **Audit** never carries a real value.
- **Versions** (0.4.0, revision 4) are consistent across the code, schema,
  changelog and docs.
- **The 10c fixes** hold on dash, bash 5.2 and macOS `/bin/sh`.
