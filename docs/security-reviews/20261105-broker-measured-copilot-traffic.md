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
  - Fixes: the round 11 commit, which also adopts the secure-agentic
    review's two asks:
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

**Adopted from the secure-agentic review** (same commit):
- **Strict org-policy allowlists.**
  - `managed_settings` follows the public `IManagedSettingsResponse`;
    `telemetry.headers` (OTLP credentials) is always dropped.
  - `team_customizations` and `content_exclusion` pass only `{}` until their
    shapes are known.
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
