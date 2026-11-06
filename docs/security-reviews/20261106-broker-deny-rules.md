# Security review: deny rules and clientPort (round 12)

- **Date:** 2026-11-06
- **Scope:** "broker: deny rules and clientPort" (policy schema revision 5,
  broker 0.5.0), and its fixes in the round 12 commit.
  - **Deny rules.** Policy `deny`; `policy.update` takes `addDeny` and
    `removeDeny`; capability `denyRules`. Requested by tab observability for
    its user-approved Block destination action.
  - **`clientPort`.** Request summaries carry the tab-side source port, for
    process attribution on OCI tabs (requested through the coordinator).
  - **Threat model:**
    - any way a request to a blocked destination reaches an upstream, is
      prompted, or gets a real credential;
    - a block the user can't fully undo;
    - a block that's silently lost on persist and reload.
- **Reviewer:** a general-purpose agent on an Opus-class CVP model with long
  context. It confirmed each finding with a PoC in the unit image. Triage and
  fixes by the broker session.

## Findings
| # | Severity | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| 12-1 | High | Deny precedence | `request()` checked deny rules only at its top. A block added while the request waited for a just-in-time credential (`wait_for_value`, up to the prompt timeout) wasn't seen: the request was forwarded with the real value injected. The controller was even asked for the value after the block. | fixed (round 12 commit) | One `_blocked()` check runs before anything else and again after every suspension: after the egress prompt, after each binding prompt, and immediately before any real value is written. Defence in depth: `server_connect` refuses a blocked destination before any DNS lookup (audit `upstream.denied`). | `test_r12_block_during_a_jit_credential_hold_is_never_injected` |
| 12-2 | Medium | Deny matching | `*.x` on a deny rule didn't block the apex `x`; it inherited the allow rule's strict-subdomain wildcard. A Block action written as `*.evil.test` left `evil.test` reachable. | fixed (round 12 commit) | On a deny rule, `*.x` also matches `x`. Stated in the schema and `docs/broker-policy.md`. | `test_deny_rules_are_every_port_and_scheme_and_validated` |
| 12-3 | Low | Prompts | A prompt resolved by a deny rule set the 300-second prompt cooldown, so after an unblock the destination stayed denied, unprompted, for up to five minutes. | fixed (round 12 commit) | A `deny-rule` resolution sets no cooldown. | `test_a_new_deny_rule_resolves_a_waiting_prompt` |
| 12-4 | Low | Prompts | Each deny-rule resolution counted as a prompt refusal, so three blocks offered `deny-new-destinations`. | fixed (round 12 commit) | A `deny-rule` resolution isn't counted. | Same test |
| 12-5 | Low | Audit | A request denied because a prompt resolved by a block was audited as `egress denied (deny:deny-rule)`, with no `ruleId`, so observability couldn't attribute it to the block. | fixed (round 12 commit) | After the prompt the deny rule is checked again, and its canonical `denied by rule <id>` with `ruleId` is emitted. The binding-prompt path does the same. | `test_adding_a_deny_rule_resolves_pending_prompts` |
| 12-6 | Low | Runtime policy | Repeated `addDeny` could grow the deny list past the schema's 1024 cap. `policy.get` then returned a policy `policy.load` rejects, so a controller that persists and replays would lose every block on the next tab. The same applied to `allow`. | fixed (round 12 commit) | `policy.update` refuses to grow `allow` or `deny` past 1024. | `test_a_new_deny_rule_resolves_a_waiting_prompt` |
| 12-7 | Info | CONNECT | A CONNECT to a blocked host was accepted. The tab completed TLS against the per-tab CA before the inner request got 403. Nothing reached upstream (lazy connection strategy), but nothing was audited until the inner request. | fixed (round 12 commit) | CONNECT to a host matched by a deny rule is refused with the canonical audit. | Code review |
| 12-8 | Info | Performance | The fragment validator cache held 4 entries for 8 fragment names, so validation recompiled on request paths. | fixed (round 12 commit) | Unbounded cache (8 fixed names). | n/a |

Probed and held:
- **Host normalisation:** case, trailing dot, IDNA, IPv4-mapped IPv6 and
  wildcards on IP literals.
- **Defaults:** every port and both schemes.
- **Authority confusion** (Host versus `:authority`, SNI and the CONNECT
  target) is refused before deny matching.
- **Keep-alive:** every request re-enters `requestheaders`.
- **Lazy upstream connections:** nothing connects before `requestheaders`.
- **WebSockets:** both directions are dropped after a block.
- **The egress-prompt hold path** gets 403 and forwards nothing.
- **`_resolve_denied_prompts`** touches only matching approvals, and a
  hostile controller sink can't strand held flows.
- **RPC validation:** duplicates, a rule added and removed in one call,
  unknown ids, extra properties.
- **Round trips:** `policy.get` to `policy.load`, and `deny_all()`.
- **`clientPort`:** present on every summary path, within the schema, tagged
  untrusted, and excluded from request identity.
- **Versions** (0.5.0, revision 5) are consistent, including tabd's pin.
