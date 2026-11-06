# Broker model access: budgets, a fail-closed body policy, and trusted derivation

- **Status:** accepted; amended 2026-11-05 (Amendment 1: measured Copilot traffic, D7
  amended by the user)
- **Date:** 2026-11-05
- **Deciders:** anticomputer (user), via the secure-agentic design: D2 (model calls stay
  in the tab, through the broker) and D7 (derived Copilot token bound by path and
  method through a trusted provider table), both accepted 2026-11-05
  ([plan §13](../plans/secure-agentic-experiences.md#13-decisions-for-the-user),
  [ADR agents run in the tab](20261105-agents-run-in-the-tab.md)). Broker session
  (design and implementation).
- **Amends:**
  - [ADR broker output is data](20261104-broker-output-is-data.md), decision 2:
    content is now consulted in a fourth way, which is also deny-only.
  - [ADR no real secret enters a tab](20261104-no-real-secret-enters-a-tab.md):
    a derived credential can be bound beyond its parent, but only by a
    controller-declared rule.
- **Related:** [plan §4](../plans/secure-agentic-experiences.md#4-model-and-credential-access), [EDR agents-in-tab spike](../edr/20261105-agents-in-tab-spike.md), [security review](../security-reviews/20261105-broker-model-access.md), [security review: backstop exceptions](../security-reviews/20261105-broker-backstop-exceptions.md)

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

**The provider backstop exempts only a declared derive route.** The GitHub
backstop denies credentialed calls to `/copilot_internal/**`, because the tab
must never mint its own Copilot token. D7 changes how that guarantee is kept:
the broker makes the mint call, and the token comes back to the tab only as a
sentinel.

So a confirmed credential's request on the exact `from` route of one of its
own `derive` rules (empty query) passes the backstop, and is audited as
`credential.backstop_exempt`. A 2xx response must yield a structurally
replaced token, or it is blocked. Any other status gets the same response
check as the exception below, so "derived or blocked" holds whatever the
upstream returns
([review](../security-reviews/20261105-broker-backstop-exceptions.md)). Every
other backstopped route, including the rest of `/copilot_internal/**`, stays
denied (`test_backstop_exempts_only_a_declared_derive_route`).

**Measured traffic** ([spike EDR](../edr/20261105-agents-in-tab-spike.md), 2026-11-05):
- the parent credential's inject format is `Authorization: Bearer <value>`,
  and the example policy uses it;
- its first call is `GET /copilot_internal/user`.

**Approved backstop exception: `GET /copilot_internal/user`** (coordinator
decision, 2026-11-05). It is data in `providers/github.json` (`exceptions`).

Why: it is read-only user information, not a mint as far as public client
code shows. Without it the Copilot harness fails at its first request. The rest
of `/copilot_internal/**` stays denied.

Conditions, all enforced:
- **Exact request.** Exact method and path, case-sensitive with no
  trailing-slash variant (plus the GHES `/api/v3` prefix); no query, no body,
  no upgrade. Anything else on that path is backstopped.
- **Checked response.** The response must be a strict JSON object with no
  credential-named key (`token`, `secret`, `passw…`, `credential`, `api_key`,
  `session`, `cookie`, `bearer`, `jwt`) or header name, and no token-shaped
  value anywhere, including in headers. Otherwise it is blocked and audited as
  `credential.backstop_exception_blocked`. That is a finding: the route's
  response shape needs review.
- **Field allowlist.** Its top-level fields are allowlisted since Amendment
  1 (stub-derived); fields outside it are dropped after the check.

The secure-agentic spike ran with no real credential, so the response shape
used here is a fixture's, not measured. Probe:
`test_backstop_exception_copilot_user_is_narrow_and_its_response_is_checked`.
A rogue upstream on that route returns a credential-named field, a
token-shaped value, or non-JSON; every case is blocked, and no real value
reaches the tab.

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

## Amendment 1 (2026-11-05): measured Copilot traffic and the user's decisions
**Source.** The secure-agentic session ran the shipped agent host and Copilot
runtime in a real sbx tab, behind its real broker. It used fake GitHub and
CAPI upstreams and a fake GitHub credential imported with `bind` and
`derive`. That is the B2 run: `test/agentic/ahp/tab-spike.ts` at `c759e5c` on
the secure-agentic branch. It took the GHES route (`githubEnterpriseUri`).
What it measured:
- **No mint.** The runtime never calls `/copilot_internal/v2/token`. Every
  CAPI request (`GET /models`, `POST /responses`, `/chat/completions`,
  `/v1/messages`, `/mcp/readonly`) carries the GitHub token itself, as
  `Bearer`. Decision 4's derive rule never fired.
- **More org-policy reads.** The runtime also reads
  `/copilot_internal/managed_settings`, `/team_customizations` and
  `/content_exclusion`. The backstop denied them; the turns still completed.
- **Request shapes.** The body fields and tool types per endpoint are in the
  decisions below.

**D7 amended** (user decision: "Accept: bind the GitHub token to the Copilot
API model endpoints by exact path and method").
- The controller binds the GitHub credential to exactly `GET /models`,
  `POST /responses`, `POST /chat/completions` and `POST /v1/messages` on the
  CAPI hosts its provider table lists. Those hosts never come from a
  response's `endpoints` field.
- The tab still holds only the sentinel.
- The real token now reaches CAPI, as it does from any Copilot client. The
  GitHub backstop still applies there, because it follows the credential's
  provider, not the host.
- Decision 4's derive mechanism is unchanged and stays for a runtime that
  does mint. The example policy no longer declares a derive rule, because
  this runtime never mints.
- The code agrees with the measurement:
  [`copilotApiService.ts` L384-397](https://github.com/microsoft/vscode/blob/a717861c/src/vs/platform/agentHost/node/shared/copilotApiService.ts#L384-L397)
  says "The GitHub user token IS the credential. There is no Copilot
  session-token mint", and that this mirrors the `@github/copilot` CLI.

**Org-policy GETs** (user decision: "Allow exactly those three GETs, with the
same strict checks as /user").
- They are `exceptions` in `providers/github.json`: exact method and path, no
  query, body or upgrade.
- The response must be a strict JSON object with no credential-named key and
  no token-shaped value.
- Their fields are unmeasured: the fixture saw no real response. So they have
  no field allowlist: every key and value is checked, and nothing is dropped.
- Denying them silently dropped an enterprise's Copilot content exclusions,
  which is a policy regression, not a leak.

**The `/user` response has a field allowlist** (`responseFields`). It is the
union of two lists:
- what the agent host reads
  ([`copilotApiService.ts` L80-98](https://github.com/microsoft/vscode/blob/a717861c/src/vs/platform/agentHost/node/shared/copilotApiService.ts#L80-L98));
- what upstream's own stub serves (`test/node/e2e/harness/capiStubs.ts`).

It is stub-derived, not measured: the run used no real credential, by rule.
The order matters:
1. **The whole document is checked first,** unknown fields included. A
   token-shaped value, or a credential-named key, blocks it as before.
2. **Then unlisted top-level fields are dropped** and audited as
   `credential.backstop_exception_filtered`, a finding.

So a rogue upstream still fails loudly, and a benign new field degrades the
tab gracefully instead of breaking Copilot. Two measured false positives,
`token_based_billing` and `cloud_session_storage_enabled` (`benignKeys`),
pass the credential-name check by exact name only. Token-shaped values are
refused everywhere.

**GitHub's remote MCP server is denied by default** (coordinator decision).
- `POST <capi>/mcp/readonly` is JSON-RPC to an MCP server that acts on the
  user's GitHub.
- The `copilot` provider marks it `requiresGrant`. It opens only with a
  per-tab Tier C grant (`models.grants: [{provider, endpoint}]`) and a
  binding; both are controller policy.
- The grant opens that endpoint with its own field list (`id`, `jsonrpc`,
  `method`, `params`) and no tools. The remote-content check still applies.

**The body policy is measured and per endpoint** (schema revision 4; this
reverses "Per-endpoint field lists: deferred" below).
- `POST /responses`: `include`, `input`, `instructions`, `model`,
  `parallel_tool_calls`, `reasoning`, `store`, `stream`, `text`, `tools`.
- `POST /chat/completions`: `messages`, `model`, `reasoning_effort`,
  `snippy`, `stream`, `stream_options`, `temperature`, `tools`.
- `POST /v1/messages`: `max_tokens`, `messages`, `model`, `stream`, `system`,
  `temperature`, `thinking`, `tools`.
- `/embeddings` and the draft fields the runtime never sent are gone.
- **Tool types:** `function` and `custom` on `/responses` and
  `/chat/completions`; on `/v1/messages`, untyped Anthropic tools count as
  `custom`.
- **Why `custom` is allowed.** A `custom` tool (`apply_patch`, with a
  `grammar` format) is executed by the client, like `function`: the model
  emits free-form text that the agent in the tab runs. Its grammar only
  constrains the model's output. It names no URL and runs nothing on the
  provider, so it can't make the provider a relay. Server-side types (web
  search, file search, code interpreter, MCP, computer use, image generation,
  versioned Anthropic server tools) stay denied.

**The github.com route** (the coordinator asked for this to be confirmed
before calling it verified).
- **Agent host: verified by code.**
  [`deriveGitHubEndpoints`](https://github.com/microsoft/vscode/blob/a717861c/src/vs/platform/github/common/githubEndpoints.ts#L42-L72)
  gives `https://api.github.com` for github.com, `https://api.<tenant>` for
  `*.ghe.com`, and `https://<host>/api/v3` for GHES. That is the same code
  path the run took, with only the base differing.
  - The CAPI base is discovered from `/copilot_internal/user`'s
    `endpoints.api`
    ([L1121-L1199](https://github.com/microsoft/vscode/blob/a717861c/src/vs/platform/agentHost/node/shared/copilotApiService.ts#L1121-L1199)).
  - Its default is `https://api.githubcopilot.com`
    ([L27](https://github.com/microsoft/vscode/blob/a717861c/src/vs/platform/github/common/githubEndpoints.ts#L27)).
  - The backstop exceptions cover both path forms (`""` and `/api/v3`), and
    any host whose credential has provider `github`.
- **Copilot runtime: inferred, not verified.** It is closed source. In the run
  it used the ghe.com form (`api.<host>`) while the agent host used the GHES
  form. That github.com maps to `api.github.com` for it too is an inference
  from the shared shape, until a github.com run or its source confirms it.

**Open: GHE.com data-residency CAPI hosts.**
- A GHE.com tenant's CAPI host is outside the built-in `copilot` provider's
  hosts and the known model-host list (patterns have no inner wildcard).
- A policy that binds the GitHub token to such a host must also declare a
  provider for it, for example a copy of `copilot` with that host. Otherwise
  the body policy does not apply there.
- The secure-agentic provider table must do this until the broker can match
  those hosts.

**Probes:**
- `broker/tests/unit/test_models.py`: `test_measured_copilot_requests_pass`,
  `test_measured_copilot_denials`,
  `test_github_remote_mcp_needs_a_per_tab_endpoint_grant`,
  `test_endpoint_grants_are_validated`,
  `test_revision4_policy_shapes_validate`.
- `broker/tests/unit/test_policy.py`:
  `test_org_policy_backstop_exceptions_are_exact`,
  `test_copilot_user_exception_has_the_measured_field_allowlist`.
- `broker/tests/integration/test_models.py`:
  `test_d7_amended_github_token_reaches_the_measured_capi_routes_only`,
  `test_github_remote_mcp_is_denied_until_a_tab_grant`,
  `test_org_policy_gets_are_narrow_and_their_responses_checked`,
  `test_copilot_user_benign_keys_pass_and_unlisted_fields_are_dropped`.

## Alternatives considered
- **A denylist of server-side tool types and fields:** rejected. Providers add
  tools faster than a denylist can follow, so it fails open.
- **Bind the Copilot token to every host in the response's `endpoints`:**
  rejected. That is tab-steerable through the upstream, and those hosts also
  serve agent and job endpoints that act as the user.
- **Pattern-scan for the Copilot token (`json-token-field`) and bind it to the
  parent:** rejected. It is unusable, and pattern-based. A structural rule on
  one route fails closed instead.
- **Per-endpoint field lists:** deferred at first, then adopted in Amendment
  1, when the measured shapes differed by endpoint.

## Consequences
- **Built-in field and tool lists:** `copilot` is measured (Amendment 1);
  `openai` and `anthropic` are still drafts. A provider adding a field breaks
  calls (fail closed) until the list is updated.
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
