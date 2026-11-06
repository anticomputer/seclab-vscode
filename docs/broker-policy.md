# Broker policy (`version: 1`)

A policy is a per-tab JSON document that tells the broker:
- which egress is allowed;
- which credentials exist;
- where each credential's real value may be injected.

Load it with `policy.load` ([protocol](broker-protocol.md)). It is
engine-agnostic: it names hosts, ports, schemes, methods and paths, never
engine internals. Default is deny.

**This document cannot drift.** Sections marked *generated* are rendered by
`broker/tools/docs.py` from these sources:
- [`policy.v1.schema.json`](../broker/schema/policy.v1.schema.json);
- the broker's data files (baseline, provider backstop, token rules);
- [`broker/examples/`](../broker/examples/).

Every example is validated by the broker's own parser. `broker/docs-check.sh`
fails on any difference.

## How matching works

These semantics live in [`policy.py`](../broker/seclab_broker/policy.py) and
are pinned by its unit tests (see the matcher invariants in
[broker/AGENTS.md](../broker/AGENTS.md#matcher-invariants-that-must-never-regress)).

**Hosts**
- Hosts are compared after normalisation: lowercase, no trailing dot, IDNA,
  IPv4-mapped IPv6 converted to IPv4.
- Numeric or hex IPv4 spellings are rejected.
- `*.example.com` matches strict subdomains only.

**Paths**
- Paths are matched on the decoded canonical path. Requests with dot
  segments, encoded `/ . \ ; %`, NUL or `//` are rejected before matching.
- In globs, `*` stays within one segment and `**` crosses segments.
- Allow and binding globs are case-sensitive.

**Rules**
- A rule defaults to `https` on the scheme's default port, any method, and
  `/**`.

**Deny rules** (`deny`, revision 5)
- A deny rule blocks a destination: host pattern, optional `ports` and
  `schemes`, and a required `id`.
- It is checked before everything else: allow rules, the baseline,
  `allow-tab` grants, prompts and credential bindings. A matching request
  gets `403` and the audit event `request.denied` (reason
  `denied by rule <id>`), and is never prompted.
- Omitted `ports` means every port, and omitted `schemes` means http and
  https. This is the opposite of an allow rule's defaults, so a block can't be
  sidestepped by a non-default port or scheme.
- At runtime, `policy.update` takes `addDeny` and `removeDeny`. A new deny
  rule resolves any pending prompt it matches as `deny`. It applies to every
  new request on an open connection, and an open WebSocket relays nothing
  more.
- It matches the request's host name. A destination reached by IP literal
  needs its own rule; IP literals are denied anyway unless allowed.

**Credentials**
- A credential's real value is written only into its binding's
  `inject.header`, only when the tab put the sentinel in that header, and only
  on a request that matches the binding (HTTPS, host, path, method, port).
- The request must also be allowed by a rule (or an approval).
- A sentinel anywhere else is never swapped (`sentinelMismatch`).
- The provider backstop below is checked first and beats any binding.

## Top-level fields (generated)

<!-- BEGIN GENERATED: policy-fields (broker/tools/docs.py; do not edit) -->
Per-tab egress and credential policy. Engine-agnostic: it names hosts, ports, schemes, methods and paths, never engine internals. Default is deny.

| Field | Type | Required | Description |
|---|---|---|---|
| `version` | `1` | yes | Schema major version. Additive optional fields keep 1. Behaviour changes within a major version bump the schema's `x-revision`, reported by `broker.hello` as `policySchema.revision` and listed in the protocol changelog. |
| `tabId` | [`id`](broker-policy.md#id) |  | If set, must equal the broker's `SECLAB_TAB_ID`. |
| `baseline` | `boolean` |  | Merge the broker's built-in baseline allow rules (extension gallery). (default `true`) |
| `prompt` | `object` |  | Hold-and-prompt behaviour for requests no rule allows. |
| `prompt.enabled` | `boolean` |  | When false, unmatched requests are denied at once. (default `true`) |
| `prompt.timeoutSeconds` | `number` |  | A held request is denied when no decision (or JIT credential) arrives in time. (min `0.1`; max `600`; default `60`) |
| `prompt.maxPending` | `integer` |  | Open prompts at once; more are denied. (min `1`; max `256`; default `16`) |
| `prompt.maxHeldFlows` | `integer` |  | Requests held at once, across all prompts and JIT waits. (min `1`; max `4096`; default `256`) |
| `prompt.denyCooldownSeconds` | `number` |  | After a deny or timeout, the same prompt key is denied without asking for this long. Keeps a polling beacon from becoming a prompt stream. (min `0`; max `3600`; default `300`) |
| `prompt.maxPerMinute` | `integer` |  | New prompts per tab per rolling minute. Beyond this, unmatched requests are denied without a prompt. (min `1`; max `120`; default `6`) |
| `prompt.offerDenyNewAfter` | `integer` |  | After this many denials (including timeouts) in the broker's session, egress prompts also offer `deny-new-destinations`, which denies every new destination for the rest of the session without asking. (min `1`; max `100`; default `3`) |
| `prompt.rawIpDestinations` | `"deny"` \| `"prompt-once"` |  | Requests to an IP literal that no rule allows. `deny`: denied without a prompt. `prompt-once`: prompted, but only `allow-once` or `deny` is offered, never `allow-tab`. (default `"deny"`) |
| `prompt.quietPeriodSeconds` | `number` |  | Requests made this soon after the tab opened, with no user action yet, are flagged `early-after-open` in prompts and audit. (min `0`; max `3600`; default `30`) |
| `prompt.autoDenyRiskyBeforeUserAction` | `boolean` |  | Until the supervisor reports the first user action (`tab.event userAction`), requests to raw IPs and risky destinations are denied without a prompt. This defeats folder-open loaders that need no click. (default `true`) |
| `sentinelMismatch` | `"block"` \| `"log"` |  | What to do when a sentinel appears anywhere other than the header a matching binding names. It is never swapped either way. (default `"block"`) |
| `allow` | [`rule`](broker-policy.md#rule)[] |  | Egress allow rules. Anything not matched is held for a prompt, or denied. (max items `1024`) |
| `deny` | [`denyRule`](broker-policy.md#denyrule)[] |  | Blocked destinations (revision 5), checked before everything else. See `denyRule`. (max items `1024`) |
| `credentials` | [`credential`](broker-policy.md#credential)[] |  | Sentinel credentials. A binding does not imply egress: the request must also be allowed. (max items `256`) |
| `models` | `object` |  | Model-host policy (revision 3; per-endpoint allowlists and endpoint grants in revision 4). A request to a host of a declared provider, or to any host on the broker's known model-host list, is checked before forwarding: the provider must be declared, the method and path must be one of its endpoints (an endpoint marked `requiresGrant` also needs a grant), no upgrades, the body must be strict JSON with only listed top-level fields, and every tool must have an allowed `type`. Requests and bytes on model hosts count against a per-tab budget; over budget is denied, never prompted. All of this only denies. |
| `models.providers` | `"copilot"` \| `"openai"` \| `"anthropic"` \| [`modelProvider`](broker-policy.md#modelprovider)[] |  | (max items `32`) |
| `models.budget` | `object` |  | Per-tab totals over the broker's lifetime. |
| `models.budget.requests` | `integer` |  | (min `0`; default `5000`) |
| `models.budget.bytes` | `integer` |  | Request plus response body bytes. (min `0`; default `1073741824`) |
| `models.grants` | `object` \| `object`[] |  | Tier C exceptions the user granted for this tab: a server-side tool type (`toolType`), or (revision 4) an endpoint the provider marks `requiresGrant` (`endpoint`, its `id`; for example the built-in copilot provider's `github-mcp-readonly`). A `toolType` grant applies to every endpoint of its provider, and `remote-content` turns off the fetchable-URL check on all of them; grant it knowing that. (max items `64`) |
| `riskyDestinations` | `object`[] |  | Extra risky destinations for this tab, added to the broker's maintained list (see docs/broker-policy.md). Same treatment: no `allow-tab`, auto-deny before the first user action. (max items `1024`) |
<!-- END GENERATED: policy-fields -->

## Types (generated)

<!-- BEGIN GENERATED: policy-definitions (broker/tools/docs.py; do not edit) -->
<a id="id"></a>
### `id`

Identifier for rules, credentials and tabs.

Type: `string` (pattern `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

<a id="tooltype"></a>
### `toolType`

Type: `string` (pattern `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

<a id="modelprovider"></a>
### `modelProvider`

A model API and what may be sent to it. Every list is an allowlist.

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | [`id`](broker-policy.md#id) | yes |  |
| `hosts` | [`host`](broker-policy.md#host)[] | yes | (min items `1`; max items `32`) |
| `endpoints` | `object`[] | yes | (min items `1`; max items `64`) |
| `fields` | `string`[] | yes | Top-level JSON body fields allowed. Any other field is denied. (max items `256`) |
| `toolFields` | `string`[] |  | Top-level fields holding arrays of tool objects. (max items `8`; default `["tools"]`) |
| `toolTypes` | [`toolType`](broker-policy.md#tooltype)[] |  | Tool `type` values allowed (client-side tools only, for example `function`). (max items `64`) |
| `untypedTool` | [`toolType`](broker-policy.md#tooltype) |  | The type a tool object with no `type` counts as (Anthropic custom tools). |
| `authHeaders` | `string`[] |  | Extra headers this provider takes a credential in. With the broker's built-in set (`Authorization`, `x-api-key`, `api-key`, `x-goog-api-key`, `Ocp-Apim-Subscription-Key`, `Cookie`, ...), every value must hold a sentinel of this tab. (max items `16`) |
| `authQueryParams` | `string`[] |  | Extra query parameters this provider takes a credential in; same rule (built in: `key`, `api_key`, `subscription-key`, `access_token`, `token`, `sig`, ...). (max items `16`) |

<a id="host"></a>
### `host`

Lowercase ASCII hostname, '*.' + hostname for strict subdomains, or an IPv4/IPv6 literal (no brackets). Non-ASCII names must be given in punycode.

Type: `string` (pattern `^(\*\.)?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$|^[0-9a-f:.]+$`; max length `253`)

<a id="method"></a>
### `method`

Upper-case HTTP method, or `*` (any; not allowed in bindings).

Type: `string` (pattern `^([A-Z]{1,16}|\*)$`)

<a id="methods"></a>
### `methods`

Type: [`method`](broker-policy.md#method)[] (min items `1`)

<a id="path"></a>
### `path`

Glob over the decoded, canonical request path (no query). '*' matches within one segment, '**' matches across segments.

Type: `string` (pattern `^/[A-Za-z0-9._~!\$&'()*+,=:@/-]*$`; max length `1024`)

<a id="ports"></a>
### `ports`

Type: `integer`[] (min items `1`)

<a id="schemes"></a>
### `schemes`

Type: `"https"` \| `"http"`[] (min items `1`)

<a id="rule"></a>
### `rule`

An egress allow rule. A request matches if every field matches.

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | [`id`](broker-policy.md#id) |  | Needed to remove the rule with `policy.update`. |
| `host` | [`host`](broker-policy.md#host) | yes |  |
| `schemes` | [`schemes`](broker-policy.md#schemes) |  | Cleartext must be named explicitly. (default `["https"]`) |
| `ports` | [`ports`](broker-policy.md#ports) |  | Defaults to the scheme's default port. |
| `methods` | [`methods`](broker-policy.md#methods) |  | (default `["*"]`) |
| `path` | [`path`](broker-policy.md#path) |  | (default `"/**"`) |

<a id="denyrule"></a>
### `denyRule`

A blocked destination (revision 5). It takes precedence over every allow rule, the baseline, `allow-tab` grants, prompts and credential bindings: a matching request is denied (`request.denied`, reason `denied by rule <id>`) and never prompted. Unlike an allow rule, omitted `ports` means every port and omitted `schemes` means http and https. It matches the request's host name; a destination reached by IP literal needs its own rule.

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | [`id`](broker-policy.md#id) | yes | Required: `policy.update` removes deny rules by id. |
| `host` | [`host`](broker-policy.md#host) | yes |  |
| `schemes` | [`schemes`](broker-policy.md#schemes) |  | (default `["http", "https"]`) |
| `ports` | [`ports`](broker-policy.md#ports) |  | Defaults to every port. |

<a id="inject"></a>
### `inject`

Where and how the real value is written. Some headers are refused; the list is in docs/broker-policy.md.

| Field | Type | Required | Description |
|---|---|---|---|
| `header` | `string` | yes | The only header the real value is ever written to. Chosen by the host, never by the caller. (pattern `^[A-Za-z0-9][A-Za-z0-9-]{0,63}$`) |
| `fmt` | `string` | yes | Template. '{value}' is the real secret; '{base64:TEXT}' base64-encodes TEXT after substituting {value}. Example: 'Basic {base64:x-access-token:{value}}'. Printable ASCII only. (pattern `^[ -~]*$`; max length `256`) |

<a id="binding"></a>
### `binding`

Where a credential may be injected. Matches HTTPS only. Methods must be explicit.

| Field | Type | Required | Description |
|---|---|---|---|
| `host` | [`host`](broker-policy.md#host) | yes |  |
| `path` | [`path`](broker-policy.md#path) | yes |  |
| `methods` | [`methods`](broker-policy.md#methods) | yes |  |
| `ports` | [`ports`](broker-policy.md#ports) |  | (default `[443]`) |
| `inject` | [`inject`](broker-policy.md#inject) |  | Overrides the credential's `inject`. |
| `websocket` | `boolean` |  | Also inject into a WebSocket upgrade matching this binding. Off by default: without it, a request carrying an `Upgrade` header (or an HTTP/2 extended CONNECT) never gets this credential and is refused with 403. Token scanning of WebSocket server messages is per message plus a window of earlier ones, so a token an upstream streams across structured messages can reach the tab whole; opt in only for upstreams you trust not to mint tokens on that connection. Revision 2. (default `false`) |

<a id="credential"></a>
### `credential`

A sentinel credential. The broker mints its sentinel (returned by `policy.load`); the host supplies the real value (`credential.provide`).

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | [`id`](broker-policy.md#id) | yes |  |
| `bind` | [`binding`](broker-policy.md#binding) \| [`binding`](broker-policy.md#binding)[] | yes | One binding or a list of bindings. |
| `inject` | [`inject`](broker-policy.md#inject) |  | Default for bindings without their own `inject`. |
| `provider` | `string` |  | Extra provider backstop deny-list to apply (by name). Providers are also applied automatically by host. (pattern `^[a-z0-9-]{1,32}$`) |
| `sentinelPrefix` | `string` |  | Replaces `SECLAB_SNTL_` for clients that check a token format. (pattern `^[A-Za-z0-9_-]{0,16}$`) |
| `derive` | [`derive`](broker-policy.md#derive)[] |  | Trusted derivation rules (revision 3). See `derive`. (max items `8`) |

<a id="derive"></a>
### `derive`

A credential minted by one exact route, declared by the controller. When a request carrying this credential to `from` succeeds (2xx), the response must be a strict JSON object whose top-level string `field` is the minted token, or the response is blocked. The token reaches the tab only as a sentinel (stable across re-mints), bound to `bind`, which may name other hosts than the parent's. That widening comes from this trusted rule only, never from the response (for example a response's `endpoints` field is ignored). `bind` names exact hosts, explicit paths and methods.

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | [`id`](broker-policy.md#id) | yes |  |
| `from` | `object` | yes |  |
| `from.host` | [`host`](broker-policy.md#host) | yes |  |
| `from.path` | [`path`](broker-policy.md#path) | yes |  |
| `from.method` | [`method`](broker-policy.md#method) | yes |  |
| `field` | `string` | yes | (pattern `^[A-Za-z0-9_]{1,64}$`) |
| `inject` | [`inject`](broker-policy.md#inject) |  | Default for `bind` entries without their own `inject`. |
| `bind` | [`binding`](broker-policy.md#binding)[] | yes | (min items `1`; max items `32`) |
<!-- END GENERATED: policy-definitions -->

## Forbidden headers (generated)

<!-- BEGIN GENERATED: policy-forbidden-headers (broker/tools/docs.py; do not edit) -->
`inject.header` may not be any of: `connection`, `content-encoding`, `content-length`, `content-type`, `cookie2`, `expect`, `host`, `keep-alive`, `proxy-authorization`, `proxy-connection`, `te`, `trailer`, `transfer-encoding`, `upgrade`, or any header starting with `proxy-`.

Requests carrying any of `x-http-method-override`, `x-http-method`, `x-method-override`, or a `_method` query parameter, are rejected with `400`.
<!-- END GENERATED: policy-forbidden-headers -->

## Baseline (generated)

Merged into every policy unless it sets `baseline: false`.

<!-- BEGIN GENERATED: policy-baseline (broker/tools/docs.py; do not edit) -->
Built-in baseline merged into every policy unless it sets baseline:false. Read-only access to the Open VSX extension gallery only. Package registries are opt-in per tab.

| Id | Host | Methods | Path |
|---|---|---|---|
| `baseline-openvsx` | `open-vsx.org` | GET, HEAD | `/**` |
| `baseline-openvsx-blob` | `openvsxorg.blob.core.windows.net` | GET, HEAD | `/**` |
<!-- END GENERATED: policy-baseline -->

## Model hosts (generated)

The `models` section puts model APIs under a request body policy and a
per-tab budget. Both only deny, and over budget is never a prompt. The policy
names built-in providers by id, or declares its own. See the
[ADR](adr/20261105-broker-model-access.md).

<!-- BEGIN GENERATED: policy-models (broker/tools/docs.py; do not edit) -->
Built-in providers (`seclab_broker/data/model-providers.v1.json`; `copilot` is measured from real runtime traffic, the others are drafts from public API references):

**`copilot`**: hosts `api.githubcopilot.com`, `api.individual.githubcopilot.com`, `api.business.githubcopilot.com`, `api.enterprise.githubcopilot.com`.
- `GET /models`.
- `POST /responses`: fields `include`, `input`, `instructions`, `model`, `parallel_tool_calls`, `reasoning`, `store`, `stream`, `text`, `tools`; tool types `function`, `custom`.
- `POST /chat/completions`: fields `messages`, `model`, `reasoning_effort`, `snippy`, `stream`, `stream_options`, `temperature`, `tools`; tool types `function`, `custom`.
- `POST /v1/messages`: fields `max_tokens`, `messages`, `model`, `stream`, `system`, `temperature`, `thinking`, `tools`; tool types `custom`; untyped tools count as `custom`.
- `POST /mcp/readonly` (denied unless a grant names `github-mcp-readonly`): fields `id`, `jsonrpc`, `method`, `params`; tool types none.

**`openai`**: hosts `api.openai.com`.
- `POST /v1/chat/completions`.
- `POST /v1/responses`.
- `GET /v1/models`.
- `POST /v1/embeddings`.

**`anthropic`**: hosts `api.anthropic.com`.
- `POST /v1/messages`.
- `POST /v1/messages/count_tokens`.
- `GET /v1/models`.

Known model hosts (`seclab_broker/data/model-hosts.v1.json`). A request to one of these is denied unless the policy declares a provider for its host:

`api.openai.com`, `api.anthropic.com`, `api.githubcopilot.com`, `*.githubcopilot.com`, `generativelanguage.googleapis.com`, `aiplatform.googleapis.com`, `*.openai.azure.com`, `*.services.ai.azure.com`, `models.inference.ai.azure.com`, `models.github.ai`, `api.mistral.ai`, `api.cohere.com`, `api.cohere.ai`, `api.x.ai`, `api.groq.com`, `api.together.xyz`, `api.fireworks.ai`, `api.deepseek.com`, `api.perplexity.ai`, `openrouter.ai`.
<!-- END GENERATED: policy-models -->

## Risky destinations (generated)

<!-- BEGIN GENERATED: policy-risky-destinations (broker/tools/docs.py; do not edit) -->
General-purpose hosting, paste, raw-content, IP-echo, tunnel and request-capture services. Anyone can publish on them in seconds, so a destination on these hosts says nothing about who is on the other end. The broker never offers 'always allow' for them, auto-denies them before the first user action in a tab, and the built-in baseline (and the shipped examples) must never match them. Policies may add entries with `riskyDestinations`. Matching uses policy host patterns: `*.x` is strict subdomains, so list the apex separately when it serves content too.

Source: Contagious Interview (DPRK) VS Code tasks.json campaign: loader on *.vercel.app, public-IP lookup via ipify.org, fallback C2 on api.npoint.io, raw-IP C2 on port 1224. https://www.jamf.com/blog/threat-actors-expand-abuse-of-visual-studio-code/ and https://opensourcemalware.com/blog/latest-contagious-interview-malware-campaign-abuses-microsoft-vscode-tasks (both read 2026-11-04). Other entries are the same service classes.

Reviewed baseline exceptions (exact hosts the baseline may name despite the list):

- `openvsxorg.blob.core.windows.net`: Open VSX's own extension download bucket (exact host, GET/HEAD only), part of the baseline extension gallery. Reviewed 2026-11-04.

| Host | Category | Note |
|---|---|---|
| `vercel.app` | hosting |  |
| `*.vercel.app` | hosting |  |
| `*.netlify.app` | hosting |  |
| `*.pages.dev` | hosting |  |
| `*.workers.dev` | hosting |  |
| `*.herokuapp.com` | hosting |  |
| `*.onrender.com` | hosting |  |
| `*.glitch.me` | hosting |  |
| `*.replit.app` | hosting |  |
| `*.repl.co` | hosting |  |
| `*.fly.dev` | hosting |  |
| `*.web.app` | hosting |  |
| `*.firebaseapp.com` | hosting |  |
| `*.github.io` | hosting |  |
| `*.gitlab.io` | hosting |  |
| `*.surge.sh` | hosting |  |
| `*.azurewebsites.net` | hosting |  |
| `*.appspot.com` | hosting |  |
| `npoint.io` | paste |  |
| `api.npoint.io` | paste |  |
| `pastebin.com` | paste |  |
| `paste.ee` | paste |  |
| `hastebin.com` | paste |  |
| `rentry.co` | paste |  |
| `jsonbin.io` | paste |  |
| `api.jsonbin.io` | paste |  |
| `transfer.sh` | paste |  |
| `gist.github.com` | raw-content |  |
| `gist.githubusercontent.com` | raw-content |  |
| `raw.githubusercontent.com` | raw-content |  |
| `bitbucket.org` | raw-content | listed for its raw/download endpoints; bind specific paths if needed |
| `cdn.discordapp.com` | raw-content |  |
| `ipify.org` | ip-echo |  |
| `*.ipify.org` | ip-echo |  |
| `ifconfig.me` | ip-echo |  |
| `ifconfig.co` | ip-echo |  |
| `icanhazip.com` | ip-echo |  |
| `ipinfo.io` | ip-echo |  |
| `ip-api.com` | ip-echo |  |
| `checkip.amazonaws.com` | ip-echo |  |
| `api.myip.com` | ip-echo |  |
| `ident.me` | ip-echo |  |
| `ipecho.net` | ip-echo |  |
| `*.ngrok.io` | tunnel |  |
| `*.ngrok-free.app` | tunnel |  |
| `*.ngrok.app` | tunnel |  |
| `*.trycloudflare.com` | tunnel |  |
| `*.loca.lt` | tunnel |  |
| `*.serveo.net` | tunnel |  |
| `*.localhost.run` | tunnel |  |
| `webhook.site` | request-capture |  |
| `*.pipedream.net` | request-capture |  |
| `*.requestcatcher.com` | request-capture |  |
| `*.burpcollaborator.net` | request-capture |  |
| `*.oast.fun` | request-capture |  |
| `*.interact.sh` | request-capture |  |
| `*.oastify.com` | request-capture |  |
| `*.devtunnels.ms` | tunnel |  |
| `*.ngrok.dev` | tunnel |  |
| `bore.pub` | tunnel |  |
| `nip.io` | ip-dns | wildcard DNS: <ip>.nip.io resolves to <ip>, a raw IP in disguise |
| `*.nip.io` | ip-dns |  |
| `sslip.io` | ip-dns |  |
| `*.sslip.io` | ip-dns |  |
| `*.traefik.me` | ip-dns |  |
| `*.xip.io` | ip-dns |  |
| `*.nip.direct` | ip-dns |  |
| `*.s3.amazonaws.com` | object-storage |  |
| `storage.googleapis.com` | object-storage |  |
| `*.blob.core.windows.net` | object-storage |  |
| `*.r2.dev` | object-storage |  |
| `objects.githubusercontent.com` | raw-content | GitHub release assets |
| `release-assets.githubusercontent.com` | raw-content | GitHub release assets |
<!-- END GENERATED: policy-risky-destinations -->

## Provider backstop (generated)

A credentialed request (one that would carry a real value) to any of these
endpoints is refused with `403`, whatever the bindings say. These endpoints let
a tab mint or register its own durable credential.

<!-- BEGIN GENERATED: policy-backstop (broker/tools/docs.py; do not edit) -->
#### `github`

Hosts: `api.github.com`. Path prefixes: `/`, `/api/v3`. Source: https://github.com/github/rest-api-description/blob/99b1432b55b9a71d0881fd792a87f1807cf4c8f2/descriptions/api.github.com/api.github.com.json

Approved exceptions (exact method and path, no body, query or upgrade; the response is checked):

- `GET /copilot_internal/user`: Copilot runtime's and agent host's first call (secure-agentic spike, 2026-11-05; measured in a tab behind its broker, B2 run at secure-agentic c759e5c): read-only user info, not a mint. Coordinator-approved 2026-11-05 with conditions: exact path, case-sensitive; no body, no query, no upgrade; the response must be a strict JSON object with no credential-named key (bar benignKeys) and no token-shaped value anywhere, else it is blocked and audited as credential.backstop_exception_blocked (a finding). Top-level fields outside responseFields are then dropped and audited as credential.backstop_exception_filtered. responseFields is the union of what the agent host reads (src/vs/platform/agentHost/node/shared/copilotApiService.ts L84-98 @ microsoft/vscode a717861c) and upstream's own stub (test/node/e2e/harness/capiStubs.ts); STUB-DERIVED, the real response is unmeasured (no real credential, by rule). ADR 20261105-broker-model-access.
  - Response fields allowed (others dropped): `access_type_sku`, `analytics_tracking_id`, `chat_enabled`, `cli_enabled`, `cloud_session_storage_enabled`, `codex_agent_enabled`, `copilot_plan`, `copilotignore_enabled`, `documentation_url`, `editor_preview_features_enabled`, `endpoints`, `is_mcp_enabled`, `is_staff`, `login`, `message`, `organization_list`, `organization_login_list`, `quota_snapshots`, `restricted_telemetry`, `token_based_billing`
  - Benign key names: `$.cloud_session_storage_enabled`, `$.token_based_billing`, `$.quota_snapshots.*.token_based_billing`
- `GET /copilot_internal/managed_settings`: Org policy the runtime enforces on the agent (measured in the B2 run; denied then, turns completed). User-approved 2026-11-05: 'Allow exactly those three GETs, with the same strict checks as /user'. The response is the enterprise's .github/copilot/settings.json; responseFields are the top-level keys of IManagedSettingsResponse (src/vs/workbench/services/accounts/browser/managedSettings.ts L40-85 @ microsoft/vscode a717861c) plus its compatibility-error fields (L118-122). strictFields: any other top-level key blocks the response, on every status (secure-agentic review: fail closed until measured). telemetry is dropped whole, whatever its shape (dropFields): its headers map carries an OTLP endpoint's credentials under names the credential-key pattern can't see, and the org's restrictions don't depend on it (review 11b-2). ADR 20261105-broker-model-access.
  - Response fields allowed (others dropped): `permissions`, `model`, `enabledPlugins`, `extraKnownMarketplaces`, `strictKnownMarketplaces`, `allowedMcpServers`, `deniedMcpServers`, `strictPluginOnlyCustomization`, `allowManagedMcpServersOnly`, `allowManagedHooksOnly`, `forceRemoteSettingsRefresh`, `error_code`, `client_version`, `minimum_client_version`, `message`, `documentation_url`, `status`
- `GET /copilot_internal/team_customizations`: One of the three user-approved org-policy GETs (2026-11-05). Its response shape is unmeasured and not in public client code, so responseFields lists only GitHub's REST error envelope (message, documentation_url, status) and is strict: only an empty object or that envelope passes; anything else is blocked as a finding until the shape is known.
  - Response fields allowed (others dropped): `message`, `documentation_url`, `status`
- `GET /copilot_internal/content_exclusion`: One of the three user-approved org-policy GETs (2026-11-05): an enterprise's Copilot content exclusions. The runtime's response shape is unmeasured; the Copilot extension parses an array of {rules, last_updated_at} from its own content-exclusion endpoint (extensions/copilot/src/platform/ignore/node/remoteContentExclusion.ts L30-40 @ a717861c), not proven to be this route's shape. So responseFields lists only GitHub's REST error envelope (message, documentation_url, status) and is strict: only an empty object or that envelope passes; anything else (including a top-level array) is blocked as a finding until the shape is measured.
  - Response fields allowed (others dropped): `message`, `documentation_url`, `status`

| Methods | Path | Why |
|---|---|---|
| POST | `/user/keys` | users/create-public-ssh-key-for-authenticated-user https://docs.github.com/rest/users/keys#create-a-public-ssh-key-for-the-authenticated-user |
| POST | `/user/ssh_signing_keys` | users/create-ssh-signing-key-for-authenticated-user https://docs.github.com/rest/users/ssh-signing-keys#create-a-ssh-signing-key-for-the-authenticated-user |
| POST | `/user/gpg_keys` | users/create-gpg-key-for-authenticated-user https://docs.github.com/rest/users/gpg-keys#create-a-gpg-key-for-the-authenticated-user |
| POST | `/repos/*/*/keys` | repos/create-deploy-key https://docs.github.com/rest/deploy-keys/deploy-keys#create-a-deploy-key |
| POST | `/app/installations/*/access_tokens` | apps/create-installation-access-token https://docs.github.com/rest/apps/apps#create-an-installation-access-token-for-an-app |
| POST | `/app-manifests/*/conversions` | apps/create-from-manifest (returns an app private key and client secret) https://docs.github.com/rest/apps/apps#create-a-github-app-from-a-manifest |
| POST, PATCH | `/applications/*/token` | apps/check-token, apps/reset-token (reset mints a new token) https://docs.github.com/rest/apps/oauth-applications#reset-a-token |
| POST | `/applications/*/token/scoped` | apps/scope-token https://docs.github.com/rest/apps/apps#create-a-scoped-access-token |
| POST | `/repos/*/*/actions/runners/registration-token` | actions/create-registration-token-for-repo https://docs.github.com/rest/actions/self-hosted-runners#create-a-registration-token-for-a-repository |
| POST | `/repos/*/*/actions/runners/remove-token` | actions/create-remove-token-for-repo https://docs.github.com/rest/actions/self-hosted-runners#create-a-remove-token-for-a-repository |
| POST | `/repos/*/*/actions/runners/generate-jitconfig` | actions/generate-runner-jitconfig-for-repo https://docs.github.com/rest/actions/self-hosted-runners#create-configuration-for-a-just-in-time-runner-for-a-repository |
| POST | `/orgs/*/actions/runners/registration-token` | actions/create-registration-token-for-org https://docs.github.com/rest/actions/self-hosted-runners#create-a-registration-token-for-an-organization |
| POST | `/orgs/*/actions/runners/remove-token` | actions/create-remove-token-for-org https://docs.github.com/rest/actions/self-hosted-runners#create-a-remove-token-for-an-organization |
| POST | `/orgs/*/actions/runners/generate-jitconfig` | actions/generate-runner-jitconfig-for-org https://docs.github.com/rest/actions/self-hosted-runners#create-configuration-for-a-just-in-time-runner-for-an-organization |
| POST | `/enterprises/*/actions/runners/registration-token` | enterprise runner registration token; not in the api.github.com description at the pinned SHA, included as defence in depth for GHEC/GHES |
| POST | `/enterprises/*/actions/runners/remove-token` | enterprise runner remove token; defence in depth (see above) |
| POST | `/enterprises/*/actions/runners/generate-jitconfig` | enterprise JIT runner config; defence in depth (see above) |
| * | `/authorizations` | legacy OAuth Authorizations API (removed upstream; absent from the pinned description). Denied in case a GHES version still serves it |
| * | `/authorizations/**` | legacy OAuth Authorizations API (see above) |
| POST | `/user/codespaces` | codespaces/create-for-authenticated-user: a codespace runs outside the tab with its own GitHub token https://docs.github.com/rest/codespaces/codespaces#create-a-codespace-for-the-authenticated-user |
| POST | `/repos/*/*/codespaces` | codespaces/create-with-repo-for-authenticated-user https://docs.github.com/rest/codespaces/codespaces#create-a-codespace-in-a-repository |
| POST | `/repos/*/*/pulls/*/codespaces` | codespaces/create-with-pr-for-authenticated-user https://docs.github.com/rest/codespaces/codespaces#create-a-codespace-from-a-pull-request |
| POST | `/user/codespaces/*/start` | codespaces/start-for-authenticated-user https://docs.github.com/rest/codespaces/codespaces#start-a-codespace-for-the-authenticated-user |
| POST | `/user/codespaces/*/exports` | codespaces/export-for-authenticated-user https://docs.github.com/rest/codespaces/codespaces#export-a-codespace-for-the-authenticated-user |
| POST | `/user/codespaces/*/publish` | codespaces/publish-for-authenticated-user https://docs.github.com/rest/codespaces/codespaces#create-a-repository-from-an-unpublished-codespace |
| * | `/copilot_internal/**` | undocumented Copilot internal API, including the Copilot session-token endpoint /copilot_internal/v2/token. No first-party public reference; widely observed in third-party Copilot clients. Copilot tokens must be minted by the host, not the tab |
<!-- END GENERATED: policy-backstop -->

## Minted-token rules (generated)

On credentialed flows and bound hosts, response text matching these rules is
re-sentinelised as a derived credential, or redacted.

<!-- BEGIN GENERATED: policy-token-rules (broker/tools/docs.py; do not edit) -->
Rules marked gitleaks are taken from https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/config/gitleaks.toml (MIT). Length quantifiers on GitHub token bodies are widened from {36} to {36,255} because GitHub documents that token lengths may grow.

| Rule | Origin | Note |
|---|---|---|
| `github-app-token` | gitleaks |  |
| `github-fine-grained-pat` | gitleaks |  |
| `github-oauth` | gitleaks |  |
| `github-pat` | gitleaks |  |
| `github-refresh-token` | gitleaks |  |
| `jwt` | gitleaks |  |
| `npm-access-token` | gitleaks |  |
| `pypi-upload-token` | gitleaks |  |
| `copilot-session-token` | seclab | Format observed in third-party Copilot clients (tid=...;exp=...;...). No first-party documentation. |
| `json-token-field` | seclab | Generic: any JSON token field on a bound host, whatever its format. |
| `form-token-field` | seclab | Generic: form-encoded OAuth token responses (GitHub's default for /login/oauth/access_token). |
<!-- END GENERATED: policy-token-rules -->

## Examples (generated)

<!-- BEGIN GENERATED: policy-examples (broker/tools/docs.py; do not edit) -->
#### [`broker/examples/copilot-agent.policy.json`](../broker/examples/copilot-agent.policy.json)

<!-- check: policy -->
```json
{
 "version": 1,
 "tabId": "example-copilot-agent",
 "baseline": true,
 "prompt": {
  "enabled": true,
  "timeoutSeconds": 60
 },
 "allow": [
  {
   "id": "copilot-user",
   "host": "api.github.com",
   "methods": [
    "GET"
   ],
   "path": "/copilot_internal/user"
  },
  {
   "id": "copilot-org-managed-settings",
   "host": "api.github.com",
   "methods": [
    "GET"
   ],
   "path": "/copilot_internal/managed_settings"
  },
  {
   "id": "copilot-org-team-customizations",
   "host": "api.github.com",
   "methods": [
    "GET"
   ],
   "path": "/copilot_internal/team_customizations"
  },
  {
   "id": "copilot-org-content-exclusion",
   "host": "api.github.com",
   "methods": [
    "GET"
   ],
   "path": "/copilot_internal/content_exclusion"
  },
  {
   "id": "capi-models",
   "host": "*.githubcopilot.com",
   "methods": [
    "GET"
   ],
   "path": "/models"
  },
  {
   "id": "capi-responses",
   "host": "*.githubcopilot.com",
   "methods": [
    "POST"
   ],
   "path": "/responses"
  },
  {
   "id": "capi-chat",
   "host": "*.githubcopilot.com",
   "methods": [
    "POST"
   ],
   "path": "/chat/completions"
  },
  {
   "id": "capi-messages",
   "host": "*.githubcopilot.com",
   "methods": [
    "POST"
   ],
   "path": "/v1/messages"
  }
 ],
 "credentials": [
  {
   "id": "github",
   "provider": "github",
   "inject": {
    "header": "Authorization",
    "fmt": "Bearer {value}"
   },
   "bind": [
    {
     "host": "api.github.com",
     "path": "/copilot_internal/user",
     "methods": [
      "GET"
     ]
    },
    {
     "host": "api.github.com",
     "path": "/copilot_internal/managed_settings",
     "methods": [
      "GET"
     ]
    },
    {
     "host": "api.github.com",
     "path": "/copilot_internal/team_customizations",
     "methods": [
      "GET"
     ]
    },
    {
     "host": "api.github.com",
     "path": "/copilot_internal/content_exclusion",
     "methods": [
      "GET"
     ]
    },
    {
     "host": "api.githubcopilot.com",
     "path": "/models",
     "methods": [
      "GET"
     ]
    },
    {
     "host": "api.githubcopilot.com",
     "path": "/responses",
     "methods": [
      "POST"
     ]
    },
    {
     "host": "api.githubcopilot.com",
     "path": "/chat/completions",
     "methods": [
      "POST"
     ]
    },
    {
     "host": "api.githubcopilot.com",
     "path": "/v1/messages",
     "methods": [
      "POST"
     ]
    },
    {
     "host": "api.individual.githubcopilot.com",
     "path": "/models",
     "methods": [
      "GET"
     ]
    },
    {
     "host": "api.individual.githubcopilot.com",
     "path": "/responses",
     "methods": [
      "POST"
     ]
    },
    {
     "host": "api.individual.githubcopilot.com",
     "path": "/chat/completions",
     "methods": [
      "POST"
     ]
    },
    {
     "host": "api.individual.githubcopilot.com",
     "path": "/v1/messages",
     "methods": [
      "POST"
     ]
    },
    {
     "host": "api.business.githubcopilot.com",
     "path": "/models",
     "methods": [
      "GET"
     ]
    },
    {
     "host": "api.business.githubcopilot.com",
     "path": "/responses",
     "methods": [
      "POST"
     ]
    },
    {
     "host": "api.business.githubcopilot.com",
     "path": "/chat/completions",
     "methods": [
      "POST"
     ]
    },
    {
     "host": "api.business.githubcopilot.com",
     "path": "/v1/messages",
     "methods": [
      "POST"
     ]
    },
    {
     "host": "api.enterprise.githubcopilot.com",
     "path": "/models",
     "methods": [
      "GET"
     ]
    },
    {
     "host": "api.enterprise.githubcopilot.com",
     "path": "/responses",
     "methods": [
      "POST"
     ]
    },
    {
     "host": "api.enterprise.githubcopilot.com",
     "path": "/chat/completions",
     "methods": [
      "POST"
     ]
    },
    {
     "host": "api.enterprise.githubcopilot.com",
     "path": "/v1/messages",
     "methods": [
      "POST"
     ]
    }
   ]
  }
 ],
 "models": {
  "providers": [
   "copilot"
  ],
  "budget": {
   "requests": 2000,
   "bytes": 536870912
  }
 }
}
```

#### [`broker/examples/default-deny.policy.json`](../broker/examples/default-deny.policy.json)

<!-- check: policy -->
```json
{
 "version": 1,
 "baseline": true
}
```

#### [`broker/examples/github.policy.json`](../broker/examples/github.policy.json)

<!-- check: policy -->
```json
{
 "version": 1,
 "tabId": "example-github",
 "baseline": true,
 "prompt": {
  "enabled": true,
  "timeoutSeconds": 60
 },
 "sentinelMismatch": "block",
 "allow": [
  {
   "id": "github-web",
   "host": "github.com",
   "methods": [
    "GET",
    "HEAD",
    "POST"
   ],
   "path": "/**"
  },
  {
   "id": "github-api-read",
   "host": "api.github.com",
   "methods": [
    "GET",
    "HEAD"
   ],
   "path": "/**"
  },
  {
   "id": "npm-registry",
   "host": "registry.npmjs.org",
   "methods": [
    "GET"
   ],
   "path": "/**"
  }
 ],
 "credentials": [
  {
   "id": "github",
   "provider": "github",
   "bind": [
    {
     "host": "github.com",
     "path": "/*/*/info/refs",
     "methods": [
      "GET"
     ],
     "inject": {
      "header": "Authorization",
      "fmt": "Basic {base64:x-access-token:{value}}"
     }
    },
    {
     "host": "github.com",
     "path": "/*/*/git-upload-pack",
     "methods": [
      "POST"
     ],
     "inject": {
      "header": "Authorization",
      "fmt": "Basic {base64:x-access-token:{value}}"
     }
    },
    {
     "host": "api.github.com",
     "path": "/repos/**",
     "methods": [
      "GET"
     ],
     "inject": {
      "header": "Authorization",
      "fmt": "Bearer {value}"
     }
    }
   ]
  }
 ]
}
```
<!-- END GENERATED: policy-examples -->
