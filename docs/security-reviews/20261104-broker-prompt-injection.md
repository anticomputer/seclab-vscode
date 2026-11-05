# Security review: broker prompt-injection hardening

- **Date:** 2026-11-04
- **Scope:**
  - Round 5: `42327fb`, prompt-injection hardening:
    - `seclab_broker/untrusted.py`;
    - `untrusted` tagging of approvals and audit;
    - literal binding suggestions;
    - ASCII `inject.fmt`;
    - the content-never-decides integration test;
    - the [ADR](../adr/20261104-broker-output-is-data.md).
  - Threat model:
    - a rogue extension or prompt-injected agent with full control of its tab
      and of any upstream on an allowed host;
    - text that reaches a human prompt or an LLM triaging audit;
    - any path from request or response content to a broker decision.
- **Reviewer:** `security-review` agent (default model; it did not refuse).
  It ran in-process PoCs in the unit image with `--network none`. Triage and
  fixes by the broker session.
- **Related:** [ADR broker output is data](../adr/20261104-broker-output-is-data.md), [ADR no real secret enters a tab](../adr/20261104-no-real-secret-enters-a-tab.md)

## Findings
| # | Severity | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| 1 | Medium | Audit integrity | `json-token-field` derives any JSON `"token"` value of 16+ characters from a credentialed response, and audit scrubbed every real value, derived ones included, from every field. An upstream (for example a model's `tool_use.input`) could return `{"token":"exfil.example.test"}` and turn the tab's later exfiltration host and path into `[redacted:…derived-N]` in `audit.event`/`audit.tail`. | fixed | The tab's own request fields (`host`, `method`, `path`) are scrubbed only for host- or policy-supplied values and sentinels, never for upstream-derived values. A real value can't be in them, since none enters the tab. Other fields (`location` and the like) are still scrubbed for everything. | `test_upstream_derived_values_cannot_erase_request_fields_from_audit` |
| 2 | Medium | Untrusted tagging | The tab-chosen `suggestedBinding.inject.header` and `suggestedBinding.methods` were not tagged in binding prompts. Approval-created rules and bindings appeared untagged in `policy.changed`, `credential.bindingConfirmed`, `policy.get` and `credential.list`. | fixed | Both fields are now tagged. Rules and bindings carry their provenance (`source="approval"`), and every surface that shows them carries an `untrusted` list (schema updated). They are schema-restricted ASCII and are not truncated, so they persist as-is. | `test_approval_and_policy_surfaces_tag_tab_chosen_fields` |
| 3 | Low | Spoofing | When request validation failed, the audit `host` was the raw `Host` header, which could carry homoglyphs, spaces, markdown and invisible non-Cf characters (variation selectors, Hangul fillers). `response.blocked.reason` interpolated the upstream's header name. | fixed | The raw authority and method are percent-encoded to ASCII (`display_host`). The header name moved to the tagged `header` field. `clean()` also strips the remaining default-ignorable characters. | `test_ignorables_and_raw_authorities_are_neutralised` |
| 4 | Functional | Approvals | `allow-tab` rebuilt the held request from the *display* path, so literal paths over 512 characters were offered `allow-tab` but always failed. The double cap also showed a misleading truncation count. | fixed | Approvals keep the real `RequestView`. Display paths are elided in the middle within one cap, using an ASCII marker the tab can't forge (brackets are always encoded). | `test_long_literal_path_binding_can_be_confirmed`, `test_long_paths_are_elided_in_the_middle_and_marker_is_unforgeable` |

Confirmed sound by the reviewer:
- **Suggested bindings:** exact normalized host, literal case-sensitive path,
  exact methods and ports. `rpc_approval_decide` enforces offered decisions,
  coverage of the held request, and the raw-IP and risky-destination checks.
- **No content-driven permissive decision:** there is no path from request or
  response content to allow, `allow-tab`, policy mutation, binding
  confirmation or `deny-new-destinations`. Derived credentials copy their
  parent's bindings; fail-closed and timeout-to-deny hold.
- **ASCII output:** hosts in approvals are IDNA/LDH ASCII; origin labels, the
  inject header and fmt are ASCII; JSON output uses `ensure_ascii`, so neither
  notifications nor stderr lines can be forged.
- **Payloads with no tab text:** `approval.resolved`, `credential.needed`,
  `credential.derived` and `health` carry only broker or controller data.

**After fixes:** no high or critical findings were found, and none remain.
