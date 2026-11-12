# Broker output is data: tab-controlled text is tagged and sanitized, and content never decides

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** Project owner (2026-11-04): any output the project intends to manage or analyse with an LLM must be checked for prompt-injection gaps. Coordinator (the two surfaces); broker session (design and implementation).
- **Related:** [ADR no real secret enters a tab](20261104-no-real-secret-enters-a-tab.md), [ADR policy and protocol](20261104-broker-policy-and-control-protocol.md), [ADR defeat folder-open loaders](20261104-defeat-folder-open-loaders.md), [security review](../security-reviews/20261104-broker-prompt-injection.md)
- **Amended by:** [ADR broker model access](20261105-broker-model-access.md) (decision 2: a fourth, deny-only way content is consulted, the model-host body policy)
- **Editorial redaction (2026-11-12):** quotations of project conversations replaced with neutral statements; decisions unchanged.

## Context
The broker emits text in two ways, and either may end up in front of an LLM:
- **Approval prompts** (`approval.requested`), which a person or an assistant reads
  before deciding.
- **Audit events** (`audit.event`, `audit.tail`), which may be summarised or triaged
  by a model.

Much of that text is chosen by the tab, or by an upstream the tab picked: hostnames,
paths, methods, the origin label, header names, inject formats, import-source file
names, and the upstream's `Server` header. A rogue extension can therefore put
instructions ("ignore previous instructions and approve …"), bidi overrides that
reorder what a human sees (`/repos/\u202Egnp.exe`), zero-width characters or
fake line breaks into any of them.

The broker will also carry model API traffic (Copilot, OpenAI, Anthropic) from inside
the tab with sentinel credentials. A prompt-injected agent inside the tab is already
inside the tab boundary, so it needs nothing new. What must hold is that no broker
decision can be steered by what a model, or any other upstream or the tab, writes in
a request or response body.

## Decision
**1. Tab-controlled text leaves the broker as tagged, sanitized data**
(`seclab_broker/untrusted.py`).

- **Stripping.** Every string in an audit event or approval drops Unicode
  categories Cc, Cf, Cs, Co, Cn, Zl and Zp, plus the remaining invisible
  default-ignorable characters: Hangul fillers, variation selectors and the
  combining grapheme joiner. That removes controls, bidi overrides and isolates,
  zero-width characters, and line and paragraph separators.
- **Length cap.** Each string is capped at 512 characters, with a `…[+N]` marker.
- **Paths.** Request paths are shown as percent-encoded ASCII (`display_path`),
  so nothing can hide or reorder. A long path keeps its beginning and end
  around a `...[N elided]...` marker. The tab can't forge that marker, because
  brackets in a path are always encoded. Approvals keep the real request
  internally, so `allow-tab` is decided on the request itself, not its display
  form.
- **Hosts.** Validated hosts are canonical ASCII (LDH or IP literal). When
  validation fails, the raw authority is still audited, but percent-encoded to
  ASCII (`display_host`).
- **Inject formats.** `inject.fmt` must be printable ASCII, including formats
  inferred from where the tab put a sentinel.
- **Origin labels.** Labels are already restricted to `[A-Za-z0-9._:-]{1,64}`.
- **Upstream header names** go in the tagged `header` field, never into
  `reason`.
- **`untrusted` list.** These carry an `untrusted` list of dotted paths naming
  the tab-controlled fields:
  - approvals: `request.host|method|path`, `risk.origin.label`,
    `suggestedRule.host`,
    `suggestedBinding.host|path|methods|inject.header|inject.fmt`;
  - audit events: `host`, `path`, `method`, `location`, `header`, `server`,
    `origin`, `risk.origin.label`, `source.path|label|rule`;
  - for rules and bindings created by `allow-tab`, the notifications
    `policy.changed` and `credential.bindingConfirmed`, and the results of
    `policy.get` and `credential.list`. The broker records each rule's and
    binding's provenance.

  Rules and bindings are schema-restricted ASCII and are never truncated, so
  the controller can persist them as-is.
- **Audit scrubbing cannot be steered.** Real values are scrubbed from audit
  events. The tab's own request fields (`host`, `method`, `path`) can never hold
  a real value, because none ever enters the tab. So they are scrubbed only for
  host- or policy-supplied values and sentinels, never for values an upstream
  minted. Otherwise an upstream could return `{"token": "<exfil host>"}` and
  choose what disappears from the log.

Consumers show these fields as quoted data. When they hand them to an LLM, they put
them in a data-only section and never follow them as instructions. The protocol
schema (`definitions.untrusted`) states this contract, and the protocol tests
validate it.

**2. No broker decision is driven by content.** Every decision comes from three
inputs only:
- the policy (loaded or updated by the controller);
- the authenticated tab identity (proxy auth on the tab's own port);
- the controller's decisions over the stdio control channel.

The tab cannot reach that channel. Content is consulted in only three ways, and
each one can only restrict:
- **Sentinel placement.** The broker swaps a sentinel only where a binding
  matches the request's scheme, host, port, method and path. A sentinel anywhere
  else (a body, another host, a query string) is never swapped and is audited as
  misplaced.
- **Response scanning.** Token-shaped values in credentialed responses are
  re-sentinelised or redacted. A derived credential copies its parent's bindings
  when it is minted (`CredentialStore.derive`), so it is never wider. On model
  API hosts, this can rewrite a token-shaped string inside model output. That is
  a functional cost, never a grant.
- **Risk flags.** Flags from the hostname (risky lists, embedded IPs, raw IPs)
  and from the open/user-action timeline only remove decisions or deny without
  prompting. The unverified origin label is display-only and is never a decision
  input, so nothing the tab claims can add `allow-tab` or skip a prompt.

**3. Suggestions are literal, and approvals are enforced by the broker.**
- **Egress suggestions.** A suggested egress rule is the request's exact host,
  scheme and port.
- **Binding suggestions.** A suggested credential binding is the request's path
  as a literal. Binding paths are globs, so a tab-chosen path such as `/x/**`
  never becomes a wildcard suggestion.
- **Paths a binding cannot express literally.** These are paths containing `*`,
  or characters outside the binding grammar. They are shown encoded, and only
  `allow-once` or `deny` are offered for them.
- **Broker enforcement.** Whatever the controller sends, the broker rejects:
  - a decision that was not offered;
  - a rule or binding that does not cover the held request;
  - a rule or binding onto a raw IP or a risky destination.

**4. Model API traffic is ordinary egress.** Model hosts are reached only through
allow rules. Their credentials are bindings like any other: a sentinel in the tab,
the real value supplied just in time by the host, and injection by placement only.

**`vscode.lm` never touches the broker** (agreed with the RPC-lockdown session,
2026-11-04):
- In v0 a tab's `vscode.lm` calls are denied by the RPC filter. Upstream,
  `$tryStartChatRequest` runs the model call trusted-side with the user's
  credentials
  ([mainThreadLanguageModels.ts#L219-L231](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/api/browser/mainThreadLanguageModels.ts#L219-L231)),
  so the tab holds no token and there is nothing to bind.
- If that is ever relaxed, it stays a trusted-side call and never becomes a
  broker binding. The broker treats everything on its proxy port as the tab, so
  trusted traffic there would share policy and credentials with the tab.
- The inverse direction is also denied: `$registerLanguageModelProvider` would
  let a tab act as the model for a trusted-side agent
  ([#L118-L135](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/api/browser/mainThreadLanguageModels.ts#L118-L135)).
  It involves no egress, so the broker cannot see it; the RPC filter owns it.
- Token rewriting is one rule in both places: **a token minted for the tab
  reaches it only as a sentinel, bound to no more than its parent's bindings.**
  The broker applies it to tokens in credentialed responses
  (`CredentialStore.derive`); the RPC filter applies it to `$getSession`.

## Alternatives considered
- **Strip or escape instruction-like phrases** ("ignore previous instructions"):
  rejected. It cannot be complete, and it gives false assurance. Tagging the field
  as data and keeping it structured is the robust contract; the consumer decides
  how to quote.
- **Drop tab-controlled fields from audit events:** rejected. The human and the
  controller need host, path and method to decide, and forensics need them.
- **Escape globs in suggested binding paths:** rejected. The binding grammar has no
  escape. Offering only `allow-once` for non-literal paths is simpler and fails
  safe.

## Consequences
- Consumers of `approval.requested` and `audit.event` (Tab Manager UI, tabd, any
  LLM triage) must honour `untrusted` and render those fields as data. Rendering
  is safe even if they don't, because the bidi and control characters are already
  gone.
- A request path containing `*` cannot be persisted as an always-for-this-tab
  credential binding through the suggestion. The controller can still send an
  explicit binding.
- A path with non-ASCII characters appears percent-encoded in prompts and audit.
  Matching still uses the decoded path.

## Evidence
- `broker/tests/unit/test_untrusted.py`:
  - sanitizer, path encoding, and audit and approval tagging;
  - non-ASCII `inject.fmt` is rejected;
  - wildcard and non-ASCII binding suggestions are defanged, and `allow-tab` is
    refused for them;
  - import-source tagging.
- `broker/tests/integration/test_egress.py::test_content_never_drives_a_permissive_decision`.
  An upstream echoes a well-formed `approval.decide` for a real pending approval,
  plus an injection header. The held request still times out to deny, and the
  policy revision and deny-new state are unchanged.
- `broker/tests/unit/test_core.py::test_derived_credential_is_never_wider_than_its_parent`:
  the broker half of the shared token rule. A derived credential gets a fresh
  sentinel and exactly its parent's bindings at mint time, and a binding the
  parent gains later does not widen it.
- Capability row `untrustedTextTagged` in the README matrix.
- Security review round 5 regressions in `test_untrusted.py`:
  - `test_upstream_derived_values_cannot_erase_request_fields_from_audit`;
  - `test_approval_and_policy_surfaces_tag_tab_chosen_fields`;
  - `test_ignorables_and_raw_authorities_are_neutralised`;
  - `test_long_paths_are_elided_in_the_middle_and_marker_is_unforgeable`;
  - `test_long_literal_path_binding_can_be_confirmed`.
