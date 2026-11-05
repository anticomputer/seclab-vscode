# Broker model access: budgets, a fail-closed body policy, and trusted derivation

- **Status:** accepted
- **Date:** 2026-11-05
- **Deciders:** anticomputer (user), via the secure-agentic design: D2 (model calls stay
  in the tab, through the broker) and D7 (derived Copilot token bound by path and
  method through a trusted provider table), both accepted 2026-11-05 (plan
  `docs/plans/secure-agentic-experiences.md` §13 and ADR
  `docs/adr/20261105-agents-run-in-the-tab.md`, on branch
  `anticomputer-secure-agentic-experiences` @ `f5a479a`; link them here when that
  branch lands). Broker session (design and implementation).
- **Amends:**
  - [ADR broker output is data](20261104-broker-output-is-data.md), decision 2:
    content is now consulted in a fourth way, which is also deny-only.
  - [ADR no real secret enters a tab](20261104-no-real-secret-enters-a-tab.md):
    a derived credential can be bound beyond its parent, but only by a
    controller-declared rule.
- **Related:** [security review](../security-reviews/20261105-broker-model-access.md)

## Context
Agents run inside the tab. Their model calls go out through the tab's broker,
carrying sentinel credentials. Three gaps follow.
- **The model API can be a relay.** Host, path and method bindings never look
  at bodies. Model APIs accept server-side tools: remote MCP, web fetch and
  search, code execution, connectors. With one, a tab could have the provider
  deliver workspace data to a URL the tab chooses, over an allowed model host
  (plan §4.4).
- **Quota.** A rogue extension can spend the user's model quota (plan §4.3).
- **The Copilot token is minted on one host and used on others.** The
  extension calls `GET api.github.com/copilot_internal/v2/token` with a GitHub
  token, then uses the returned token on the Copilot API hosts. Today a
  derived credential is bound to exactly its parent's bindings, so the minted
  token would be useless (plan §4.2).

## Decision
**1. Model hosts get a fail-closed body policy** (policy `models`, schema
revision 3; `seclab_broker/models.py`). A request is a model request when its
host belongs to a provider the policy declares, or appears on the broker's
known model-host list (`data/model-hosts.v1.json`). Before forwarding, the
broker denies it unless all of the following hold:
- **Provider.** The host belongs to a declared provider. A known model host
  with no declared provider is denied, so a model host is never reachable
  without the body policy.
- **Endpoint.** The method and path are one of the provider's endpoints.
- **No upgrades.** WebSocket and any other upgrade are refused on model hosts,
  regardless of a binding's `websocket` opt-in.
- **Strict JSON body:** identity `Content-Encoding`, one JSON media type, UTF-8
  with no byte order mark, no duplicate keys, no escapes in keys, no
  NaN/Infinity, no lone surrogates, and bounded depth. Anything unparseable is
  denied. Duplicate and escaped keys are refused because two parsers can read
  them differently.
- **Fields.** Every top-level field is on the provider's list. Fields that
  name remote resources or server-side state are left out of the built-ins:
  OpenAI `web_search_options`, Responses `prompt`, `background` and
  `conversation`, and Anthropic `mcp_servers` and `container`.
- **Tools.** Every element of a tool field has an allowed `type`: `function`
  for OpenAI and Copilot, custom (untyped) tools for Anthropic. A server-side
  tool type passes only if a Tier C grant names it (`models.grants`). A tool
  object with a `type` key in another case (`Type`) is refused.
- **No remote content** (security review round 7). Content parts are a relay
  without any tool: OpenAI `image_url`, Responses `input_file.file_url`, and
  Anthropic `source: {type: "url"}`. So the whole body is walked, apart from
  tool definitions and the `input` of a client `tool_use`. Any URL-bearing key
  (`url`, `image_url`, `file_url`, `server_url`, ..., matched case-insensitively
  at any depth), and any part whose `type` is a URL source, must hold an
  inline `data:` URI. A Tier C grant of `remote-content` lifts this for one
  provider. URLs inside text are not fetched by the provider and pass.
- **Strict JSON** also refuses keys that differ only in case, since
  case-insensitive decoders would merge them.
- **Credentials.** Every credential location on a model request must carry a
  sentinel of this tab:
  - built-in headers: `Authorization`, `x-api-key`, `api-key`,
    `x-goog-api-key`, `Ocp-Apim-Subscription-Key`, `openai-api-key`,
    `anthropic-api-key`, `x-auth-token`, `Cookie`;
  - built-in query parameters: `key`, `api_key`, `subscription-key`,
    `access_token`, `token`, `sig`, ...;
  - the provider's own `authHeaders` and `authQueryParams`.

  A tab-held key never authenticates to a model host, so every model call is
  the user's, budgeted and audited here.

Built-in providers (`copilot`, `openai`, `anthropic`) live in
`data/model-providers.v1.json`. They are drafts from the public API references
until the secure-agentic spike confirms them against the runtimes' real
traffic.

**2. Per-tab model budget** (`models.budget`). Requests and bytes (request
plus response bodies) on model hosts are counted over the tab's lifetime.
Defaults are 5000 requests and 1 GiB. Over budget, a request is denied with
`429`, never prompted. Every completed model request emits `model.call`:
provider, host, path, method, request and response bytes, status, duration,
and the declared tool types, never bodies. This is the single producer of
model-call facts for observability. `health.models` reports usage.

**3. Sealed agent-host tokens are never forwarded.** A request carrying a value
with the `copilot-sealed.v1.` prefix, to any host, in a header, the URL or the
body, is denied and audited as `sentinel.misplaced`. Upstream seals tokens to a key the agent host
advertises. The AHP gate always replaces them, and this is the broker-side
backstop (probe A25).

**4. Trusted derivation** (secure-agentic D7). A credential that the controller
defines, in the policy or by a `credential.import` with `bind`, may carry
`derive` rules. Each rule names one exact route (host, literal path, method),
a top-level JSON field, and child bindings with exact hosts. When a request
injected with that credential on exactly that route gets a 2xx response:
- The body must be a strict JSON object whose field is a string. Anything else
  blocks the response, so a token-format change can never let the real value
  through.
- The field's value becomes the real value of child `<parent>.<rule>`, and the
  response carries the child's sentinel instead.
- The child's sentinel is stable across re-mints.
- The child is bound to the rule's bindings, nothing else. The response's own
  fields (for example the Copilot `endpoints` map) are never read.

An unconfirmed import can't derive. A child never outlives its grant (security
review round 7). It is dropped when:
- the parent is revoked or removed from the policy;
- the parent is re-imported, or given a different value (possibly another
  account);
- the parent's rule is withdrawn by a `policy.load`.

Credential lifetime is a broker property only. The RPC filter hands out a
sentinel and never revisits it, so withdrawal, re-import and revocation are
enforced here and nowhere else. An identical re-import also drops the child.
Only a `credential.provide` of the same value, a just-in-time refresh, keeps
it.

**The amended rule** (shared with the RPC filter's `$getSession` wording): *a
token minted for the tab reaches it only as a sentinel, bound to no more than
its parent's bindings, or to the bindings of a derivation rule the controller
declared for that exact route.* Pattern-based minted-token detection
(`CredentialStore.derive`) still copies the parent's bindings, and
`test_derived_credential_is_never_wider_than_its_parent` still checks it.

**5. Content is consulted in four ways, all of which only deny or replace.**
This amends output-is-data decision 2. The fourth way is the model body
policy, and it can only deny. The derivation in decision 4 is a structural
replacement on a controller-declared route. Like the scanner, it can only
withhold a real value from the tab; the widening of where the child may be
used comes from the controller's rule, not from content. No broker decision
grants access because of content.

## Alternatives considered
- **A denylist of server-side tool types and fields:** rejected. Providers add
  tools faster than a denylist can follow, so it fails open.
- **Bind the Copilot token to every host in the response's `endpoints`:**
  rejected. That is tab-steerable through the upstream, and those hosts also
  serve agent and job endpoints that act as the user.
- **Pattern-scan for the Copilot token (`json-token-field`) and bind it to the
  parent:** rejected. It is unusable, and pattern-based. A structural rule on
  one route fails closed instead.
- **Per-endpoint field lists:** deferred. Per-provider lists are simpler, and
  every field is still allowlisted. Split them if a provider needs it.

## Consequences
- **Built-in field and tool lists are drafts.** A provider adding a field
  breaks calls (fail closed) until the list is updated. The spike confirms the
  lists against real traffic.
- **A policy that allows a known model host must also declare its provider.**
- **Tier C grants are controller policy** (`policy.load`). The broker never
  infers one.
- **Model requests are buffered** for the body check, as all requests already
  are (README, open issues).
- **Known residual:** a client tool (`function`) still lets the model ask the
  agent in the tab to fetch something. That fetch is ordinary tab egress, under
  the egress policy and prompts. Out of scope here: it never involves the
  provider as a relay.

## Evidence
- `broker/tests/unit/test_models.py`: the strict parser, every A22 smuggling
  shape, field and tool denials, grants, known hosts, and budget wiring.
- `broker/tests/integration/test_models.py`:
  - `test_model_call_allowed_audited_and_budgeted` (A9 budget, `model.call`);
  - `test_a22_relay_shapes_denied_before_upstream` (nothing reaches the
    upstream);
  - `test_model_host_credentials_are_sentinels_only` (including sealed tokens,
    A25);
  - `test_trusted_derivation_binds_child_where_the_controller_said`;
  - `test_trusted_derivation_fails_closed`.
- `broker/tests/unit/test_core.py`:
  - `test_trusted_derivation_rules_are_exact_and_controller_bound`;
  - `test_derive_trusted_widens_only_to_the_rule_and_keeps_its_sentinel`;
  - `test_unconfirmed_import_cannot_derive`.
