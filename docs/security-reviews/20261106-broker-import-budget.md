# Security review: budget on credential.import, and names-only field audits (round 14)

- **Date:** 2026-11-06
- **Scope:** three commits on the broker branch, and the round 14 fix commit.
  - "broker: exception-route audits carry the response's top-level field
    names (names only)": `fields` on `credential.backstop_exception_filtered`
    and `_blocked`.
  - "test(agentic): consented names-only /copilot_internal/user field
    measurement": the `user-fields.ts` harness and its dry-run fixture.
  - "broker: budget on credential.import" (policy schema revision 7, broker
    0.7.0): `credentialBudget` shared by policy credentials and imports, and
    the websocket byte-cap rule extended to `proposedBind` and
    approval-confirmed bindings.
  - **Threat model:** a real or derived secret reaching the tab, the broker's
    stderr or the audit; a tab resetting or escaping a credential budget; a
    consented real sign-in leaving its token, or response values, anywhere on
    disk.
- **Reviewer:** a security-review agent on an Opus-class model with long
  context, read-only. Triage and fixes by the broker session.

## Findings
| # | Severity | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| 14-1 | Low | Audit | `fields` cut unrecognised key names to 64 characters before the audit scrubber ran. The scrubber matches whole encoded values, so a long hex or base64 encoding of a credential used as a key, cut down, would pass it and reach stderr and the audit. Only the upstream that was just sent the credential can choose the key, so no new party learns it, but the audit must never hold a value. | fixed (round 14 commit) | Names are listed as is only if they are plain field names (`[A-Za-z0-9_-]{1,64}`, as provider data accepts). Anything else is masked whole as `[unusual-name]`, never truncated. | `test_r14_audited_field_names_are_never_truncated_values` |

Probed and held:
- **`fields` carries names only.** Values are never read. A non-object or
  non-strict body yields no `fields`. Token-shaped and URL-userinfo names are
  masked before anything else. At most 128 names. Tagged untrusted, and never
  sent to the tab, which sees only the fixed block reason or the filtered body.
- **Harness.** The real token never enters argv, container env, tabd's env,
  `run.json` or `measured.json`. It reaches the broker over the control
  channel's stdin. The derived image really drops every field
  (`responseFields: []`), and its removal is checked. Teardown runs in
  `finally` and verifies no labelled resource remains. The leak check scans
  the raw token, which is the only form the broker injects on this route; the
  dry run's canary covers the value paths.
- **Budget on import.** Only the controller sets budgets. Usage is keyed by
  id and never cleared by `policy.load`, `credential.provide`,
  `credential.revoke` or a re-import. Ids can't collide between policy
  credentials and imports. The check runs before the binding prompt and again
  right before injection on every path (allow-once, HTTP/2, the WebSocket
  upgrade). A budget of 0 denies. The websocket byte-cap rule now covers
  `bind`, `proposedBind`, `derive` and approval-confirmed bindings; a refused
  approval leaves the credential unbound and the approval pending.
- **No regression** in `credential.import` validation, and the shared
  `credentialBudget` definition resolves in the merged protocol schema.
- **Versions** (0.7.0, revision 7) are consistent across the code, schema,
  changelog and tabd.
