# Security review: broker model access (body policy, budgets, trusted derivation)

- **Date:** 2026-11-05
- **Scope:**
  - Round 7: `dcda94b`, which adds:
    - the model-host body policy and strict JSON parser (`models.py`,
      `_model_gate`);
    - the per-tab model budget;
    - sealed-token denial;
    - trusted derivation (`DeriveRule`, `derive_trusted`, `_derive`).

    Design: [ADR broker model access](../adr/20261105-broker-model-access.md).
  - Threat model: a rogue extension or prompt-injected agent in full control of
    the tab, which may also choose an upstream on an allowed host. Two goals
    for it: use a model provider as a relay to an attacker URL, or get a real
    or derived secret into the tab.
- **Reviewer:** `security-review` agent (default model; it did not refuse).
  It ran `check_request` and engine-level probes (`SeclabAddon` on mitmproxy
  test flows) from the mounted source, with `--network none`. Triage and
  fixes by the broker session.

## Findings
| # | Severity | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| 1 | High | Body policy | Only top-level keys and `tools[].type` were checked. Content parts the provider fetches passed and made it a relay without any tool: OpenAI `image_url`, Responses `input_file.file_url` and `input_image.image_url`, Anthropic `image` and `document` with `source.type: url`. | fixed | The whole body is walked (except tool definitions and a client `tool_use.input`). URL-bearing keys and URL source types, matched case-insensitively at any depth, must be inline `data:` URIs. A `remote-content` grant lifts this per provider. | `test_r7_remote_content_the_provider_would_fetch_is_denied`, `test_r7_inline_content_and_client_tool_calls_pass`, `it:test_a22_relay_shapes_denied_before_upstream` |
| 2 | Medium | Sentinel-only | Only `Authorization`, `x-api-key` and `api-key` were checked, so a tab-held key in `x-goog-api-key`, `Ocp-Apim-Subscription-Key` or `?key=` reached a declared model host. | fixed | Built-in credential headers and query parameters, plus the provider's `authHeaders` and `authQueryParams`; every value must hold this tab's sentinel. | `test_r7_every_credential_location_is_found`, `it:test_model_host_credentials_are_sentinels_only` |
| 3 | Low | Derivation | A derived child outlived its parent when the policy removed the parent or its rule, or when the parent was re-imported. | fixed | `_drop_children` runs on policy removal, rule withdrawal, re-import and a changed value. | `test_r7_derived_children_never_outlive_their_parent` |
| 4 | Note | Strict JSON | `"type"` and `"Type"` were distinct keys, so a case-insensitive decoder (Go) could see the second one. | fixed | The parser refuses keys that differ only in case; the tool check refuses a non-exact `type` key. | `test_r7_case_variant_keys_are_refused` |
| 5 | Note | Sealed tokens | Only headers were checked for `copilot-sealed.v1.`. | fixed | The URL and the body are checked too. | `it:test_model_host_credentials_are_sentinels_only` |
| 6 | Note | Audit | `detail` and `tools` were scrubbed with upstream-derived values (the review-5 class). | fixed | Added to `REQUEST_KEYS`. | none: same mechanism as `test_upstream_derived_values_cannot_erase_request_fields_from_audit` |

Confirmed sound by the reviewer:
- **Strict parser:** duplicate and escaped keys, lone surrogates, BOM, trailing
  data, top-level arrays, depth.
- **Headers and body:**
  - one JSON Content-Type, identity Content-Encoding;
  - `Transfer-Encoding: gzip` fails closed;
  - `raw_content` is forwarded unmodified;
  - HTTP/1 and HTTP/2 behave the same.
- **Routing:** path canonicalisation; agreement between `is_model_host` and
  `provider_for`; upgrades refused.
- **Budget:** check and increment are synchronous, so concurrent HTTP/2
  streams can't skip counting.
- **Audit reasons:** no tab-chosen text reaches them.
- **Trusted derivation:**
  - it needs the parent injected and confirmed, an exact route and a 2xx;
  - any other shape blocks;
  - child bindings come only from the controller;
  - `endpoints` is ignored;
  - the sentinel is stable;
  - a duplicated token in another field is re-sentinelised by `_scrub_real`.

**After fixes:** no high or critical findings remain.
