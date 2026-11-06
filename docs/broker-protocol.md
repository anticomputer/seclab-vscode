# Broker control protocol (`seclab-broker/1`)

The per-tab broker (`broker/`) is driven by exactly one kind of trusted
client: the host-side tab supervisor (today `seclab-tabd`). This document is
the whole contract between them. It is runtime-neutral: the same messages
are used whether the broker is a Docker Desktop container in front of an sbx
microVM, an OCI pod sidecar, or a Kubernetes sidecar.

**This document cannot drift from the code.** Sections marked *generated* are
rendered from [`broker/schema/protocol.v1.json`](../broker/schema/protocol.v1.json).
The broker validates every request against that file, and the tests validate
every result and notification against it. Every JSON example here is
validated, and every shell block is either run in CI or carries a reason to
skip. `broker/docs-check.sh` enforces all of this. To change the protocol,
edit `protocol.v1.json` and the code together, then run
`broker/docs-check.sh --write`.

- Decision record: [ADR 20261104-broker-policy-and-control-protocol](adr/20261104-broker-policy-and-control-protocol.md).
- Policy document: [docs/broker-policy.md](broker-policy.md).

## 1. Transport

- The client starts `seclab-broker control` **inside the broker container** with
  stdio attached: `docker exec -i <broker> seclab-broker control` (or the
  `kubectl exec -i` / runtime equivalent). That process bridges its stdio to a
  private Unix socket (`/run/seclab/control/control.sock`, directory `0700`,
  on the broker's tmpfs). **Nothing listens on the host or on any network.**
- Framing: **newline-delimited JSON**. One UTF-8 JSON object per line, no
  embedded newlines, at most 1 MiB per line. No LSP `Content-Length` headers.
- Messages are [JSON-RPC 2.0](https://www.jsonrpc.org/specification).
  Batches are rejected (`-32600`).
- Direction: the **client sends requests**, the **broker sends notifications**.
  The broker never sends requests, so the client never answers anything.
- Several clients may be connected at once. All of them receive every
  notification, and any of them may decide an approval. The supervisor should
  keep one long-lived connection and reconnect if it drops. The broker keeps
  running and keeps its state while no client is connected.
- If the socket is not up yet (broker still starting), `seclab-broker control`
  prints one JSON-RPC error with `id: null` and code `-32002` and exits 2.
  Retry.
- Params are validated against the method's schema below. Unknown fields are
  rejected with `-32602`, so a client must check `broker.hello` before using
  anything newer than this document.

A session, one message per line (client lines are requests, the broker line
without `id` is a notification):

<!-- check: jsonrpc -->
```json
{"jsonrpc": "2.0", "id": 1, "method": "broker.hello"}
{"jsonrpc": "2.0", "id": 2, "method": "proxy.auth.set", "params": {"username": "seclab", "password": "example_only_xxxxxxxxxxxx"}}
{"jsonrpc": "2.0", "id": 3, "method": "policy.load", "params": {"policy": {"version": 1, "allow": [{"host": "api.github.com", "methods": ["GET"]}]}}}
{"jsonrpc": "2.0", "method": "audit.event", "params": {"seq": 4, "ts": 1793800000.0, "type": "policy.loaded", "revision": 1}}
```

### Errors (generated)

<!-- BEGIN GENERATED: protocol-errors (broker/tools/docs.py; do not edit) -->
| Code | Name | Meaning |
|---|---|---|
| -32700 | `parse-error` | Line is not JSON. |
| -32600 | `invalid-request` | Not a JSON-RPC 2.0 request, a batch, or a bad `id`. |
| -32601 | `method-not-found` | Unknown method. |
| -32602 | `invalid-params` | Params fail the method's schema or a semantic check. The message is safe to show and never contains a credential value. |
| -32603 | `internal-error` | Unexpected failure inside the broker. |
| -32001 | `not-ready` | The broker is not ready for this call yet, for example `ca.get` before the CA exists. |
| -32002 | `control-unavailable` | Emitted by the `seclab-broker control` bridge itself (`id: null`) when the control socket is not up yet. Retry. |
<!-- END GENERATED: protocol-errors -->

## 2. Lifecycle

1. Create the broker's networks and attach them **before** starting it. The
   upstream address guard reads the routing table once, at start.
2. Start the broker (see [§6](#6-running-the-broker)).
3. Connect: `docker exec -i <broker> seclab-broker control`. Call `health`
   until `status` is `"ok"`.
4. `proxy.auth.set`: until this succeeds every proxy request gets `407`.
5. `policy.load`. Keep the returned sentinels for the tab.
6. `ca.get`, then install the public cert in the tab (see [§7](#7-tab-configuration)).
7. Optionally `credential.provide` now, or wait for `credential.needed`.
8. Handle notifications for the lifetime of the tab.
9. On tab close: `broker.shutdown`. It drops every credential from memory and
   exits the process.

## 3. Methods: client → broker (generated)

<!-- BEGIN GENERATED: protocol-methods (broker/tools/docs.py; do not edit) -->
### `broker.hello`

Identify the broker. Clients must check `protocol` and degrade explicitly when a capability they rely on is `false` or absent (see the engine capability matrix in broker/README.md).

**Params**

none

**Result**

| Field | Type | Required | Description |
|---|---|---|---|
| `protocol` | `"seclab-broker/1"` | yes | Protocol name and major version. |
| `version` | `string` | yes | Broker package version. |
| `tabId` | `string` \| `null` | yes | `SECLAB_TAB_ID` the broker was started with. |
| `engine` | `string` | yes | Enforcement engine, for example `mitmproxy`. |
| `engineVersion` | `string` | yes |  |
| `policySchema` | `object` | yes | Policy schema major version and revision this broker enforces. A revision changes behaviour within a major version; see the changelog. |
| `policySchema.version` | `integer` | yes |  |
| `policySchema.revision` | `integer` | yes |  |
| `capabilities` | map of `boolean` | yes | Feature flags; see the capability matrix. |


Example:

<!-- check: method.params broker.hello -->
```json
{}
```
<!-- check: method.result broker.hello -->
```json
{
 "protocol": "seclab-broker/1",
 "version": "0.2.0",
 "tabId": "tab-1",
 "engine": "mitmproxy",
 "engineVersion": "12.3.1",
 "policySchema": {
  "version": 1,
  "revision": 2
 },
 "capabilities": {
  "holdAndResume": true
 }
}
```


### `health`

Liveness and counters. `status` is `starting` until the proxy is listening.

**Params**

none

**Result**

| Field | Type | Required | Description |
|---|---|---|---|
| `status` | `"ok"` \| `"starting"` | yes |  |
| `uptimeSeconds` | `number` | yes |  |
| `proxy` | `object` | yes |  |
| `proxy.listening` | `boolean` | yes |  |
| `proxy.authConfigured` | `boolean` | yes |  |
| `policy` | `object` | yes |  |
| `policy.revision` | `integer` | yes |  |
| `policy.rules` | `integer` | yes |  |
| `policy.credentials` | `integer` | yes |  |
| `pendingApprovals` | `integer` | yes |  |
| `heldFlows` | `integer` | yes | Requests currently held waiting for a decision or a credential. |
| `credentials` | `integer` | yes | Credentials known to the broker (policy, imported and derived). |
| `controllers` | `integer` | yes | Connected control clients. |
| `prompt` | `object` | yes | Session prompt state (see `tab.event`, `prompt.reset`). |
| `prompt.denyNewDestinations` | `boolean` | yes |  |
| `prompt.sessionDenials` | `integer` | yes |  |
| `prompt.promptsLastMinute` | `integer` | yes |  |
| `prompt.userActionSeen` | `boolean` | yes |  |
| `models` | `object` | yes | Model-host usage over the tab's lifetime and the budget (policy `models.budget`). |
| `models.requests` | `integer` | yes |  |
| `models.bytes` | `integer` | yes |  |
| `models.maxRequests` | `integer` | yes |  |
| `models.maxBytes` | `integer` | yes |  |


Example:

<!-- check: method.params health -->
```json
{}
```
<!-- check: method.result health -->
```json
{
 "status": "ok",
 "uptimeSeconds": 12.3,
 "proxy": {
  "listening": true,
  "authConfigured": true
 },
 "policy": {
  "revision": 3,
  "rules": 4,
  "credentials": 1
 },
 "pendingApprovals": 0,
 "heldFlows": 0,
 "credentials": 2,
 "controllers": 1,
 "prompt": {
  "denyNewDestinations": false,
  "sessionDenials": 0,
  "promptsLastMinute": 0,
  "userActionSeen": true
 },
 "models": {
  "requests": 12,
  "bytes": 48213,
  "maxRequests": 5000,
  "maxBytes": 1073741824
 }
}
```


### `proxy.auth.set`

Set the per-tab proxy credential. The tab sends it as HTTP Basic `Proxy-Authorization`, normally via userinfo in its proxy URL. Until this succeeds every proxy request gets `407`; unauthenticated clients are never held, prompted, resolved or connected upstream. Comparison is constant time; the value is never logged or echoed. Calling it again rotates the credential, and tunnels opened under the old one must re-authenticate. The tab may append an origin label to the username, `seclab+<label>` (label `[A-Za-z0-9._:-]{1,96}`, for example `seclab+task.env`; percent-encode `:` in a proxy URL), set by whatever launched the client inside the tab. The broker shows it in prompts and audit as `origin: {label, verified: false}`: any process in the tab can claim any label, so it is a hint, never an access decision.

**Params**

| Field | Type | Required | Description |
|---|---|---|---|
| `username` | `string` | yes | Convention: `seclab`. (pattern `^[A-Za-z0-9._-]{1,64}$`) |
| `password` | `string` | yes | At least 128 bits as base64url, from a CSPRNG (for example `secrets.token_urlsafe(16)`). (pattern `^[A-Za-z0-9_-]{22,128}$`) |

**Result**

| Field | Type | Required | Description |
|---|---|---|---|
| `epoch` | `integer` | yes | Increments on every rotation. |


Example:

<!-- check: method.params proxy.auth.set -->
```json
{
 "username": "seclab",
 "password": "example_only_xxxxxxxxxxxx"
}
```
<!-- check: method.result proxy.auth.set -->
```json
{
 "epoch": 1
}
```


### `policy.load`

Replace the tab's policy. Rules added at runtime by `allow-tab` are discarded (persist them from `policy.changed`). Sentinels are stable across reloads for the same credential id, and already-provided values are kept. Credentials no longer in the policy are dropped from memory; imported credentials are unaffected. A `tabId` that differs from the broker's `SECLAB_TAB_ID` is rejected.

**Params**

| Field | Type | Required | Description |
|---|---|---|---|
| `policy` | [`Policy`](broker-policy.md) | yes | A policy document (see docs/broker-policy.md). |

**Result**

| Field | Type | Required | Description |
|---|---|---|---|
| `revision` | `integer` | yes |  |
| `sentinels` | map of `string` | yes | Credential id to sentinel, for policy credentials. |


Example:

<!-- check: method.params policy.load -->
```json
{
 "policy": {
  "version": 1,
  "allow": [
   {
    "host": "api.github.com",
    "methods": [
     "GET"
    ]
   }
  ]
 }
}
```
<!-- check: method.result policy.load -->
```json
{
 "revision": 1,
 "sentinels": {}
}
```


### `policy.get`

The effective policy, including rules added at runtime. Never includes credential values.

**Params**

none

**Result**

| Field | Type | Required | Description |
|---|---|---|---|
| `revision` | `integer` | yes |  |
| `policy` | [`Policy`](broker-policy.md) | yes |  |
| `untrusted` | [`untrusted`](#untrusted) |  |  |


### `policy.update`

Live edit of the allow list and (revision 5) the deny list. Emits `policy.changed`. Removing a rule requires that it has an `id`. A deny rule takes precedence over every allow rule, the baseline, `allow-tab` grants, prompts and credential bindings; adding one resolves any pending prompt it matches as `deny`.

**Params**

| Field | Type | Required | Description |
|---|---|---|---|
| `addAllow` | [`rule`](broker-policy.md#rule)[] |  | (max items `256`) |
| `removeAllow` | [`id`](broker-policy.md#id)[] |  | Ids of runtime or policy rules to remove. (max items `256`) |
| `addDeny` | [`denyRule`](broker-policy.md#denyrule)[] |  | Destinations to block (revision 5). (max items `256`) |
| `removeDeny` | [`id`](broker-policy.md#id)[] |  | Ids of deny rules to remove (revision 5). (max items `256`) |

**Result**

| Field | Type | Required | Description |
|---|---|---|---|
| `revision` | `integer` | yes |  |


Example:

<!-- check: method.params policy.update -->
```json
{
 "addAllow": [
  {
   "id": "npm",
   "host": "registry.npmjs.org",
   "methods": [
    "GET"
   ]
  }
 ]
}
```
<!-- check: method.result policy.update -->
```json
{
 "revision": 2
}
```


### `credential.provide`

Supply a credential's real value just in time. After `expiresAt` the value is dropped and the next use raises `credential.needed` again. Held requests waiting for this credential resume immediately.

**Params**

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | `string` | yes | (min length `1`; max length `200`) |
| `value` | [`secretValue`](#secretvalue) | yes |  |
| `expiresAt` | `number` \| `null` |  | Unix seconds. |

**Result**

none


Example:

<!-- check: method.params credential.provide -->
```json
{
 "id": "github",
 "value": "<real value from the keychain>",
 "expiresAt": 1793900000
}
```
<!-- check: method.result credential.provide -->
```json
{}
```


### `credential.revoke`

Drop a credential's real value, and every credential derived from it. With `rotateSentinel` the credential gets a new sentinel and the old one stops matching.

**Params**

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | `string` | yes | (min length `1`; max length `200`) |
| `rotateSentinel` | `boolean` |  | (default `false`) |

**Result**

| Field | Type | Required | Description |
|---|---|---|---|
| `sentinel` | `string` | yes | Current sentinel (new if rotated). |


### `credential.import`

Import a user-supplied secret: one found by the pre-mount workspace scan, or captured password input. The broker never writes the value anywhere; the supervisor persists `{id, sentinel, value, bind}` (keychain) and re-imports with `bind` on every broker start.

With no `bind` the credential is *unconfirmed*. On first use (its sentinel in a request header, over HTTPS, to a host the tab may reach) the broker holds the request and emits `approval.requested` with `kind: credential-binding`. **That path is attacker-steerable**: the tab chooses which host, path and header it first sends the sentinel to, so `suggestedBinding` is advisory only and the broker never confirms a binding on its own. Supervisors should show the host prominently, default to deny, never pre-select `allow-tab`, and prefer importing with `bind` from a trusted host-side prompt.

**Params**

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | [`id`](broker-policy.md#id) | yes |  |
| `value` | [`secretValue`](#secretvalue) | yes |  |
| `sentinel` | `string` |  | Host-chosen sentinel, so a sentinel already written into a workspace file stays valid across restarts. Must be unique. Minted by the broker if absent. (pattern `^[A-Za-z0-9_.~-]{32,256}$`) |
| `bind` | [`bindOrBindings`](#bindorbindings) |  | Confirmed bindings. |
| `proposedBind` | [`bindOrBindings`](#bindorbindings) |  | Only shapes the first-use prompt. |
| `inject` | [`inject`](broker-policy.md#inject) |  | Default inject for bindings that have none. |
| `derive` | [`derive`](broker-policy.md#derive)[] |  | Trusted derivation rules (revision 3), for example the Copilot token minted from a GitHub token. Requires `bind`: an unconfirmed import never derives. (max items `8`) |
| `provider` | `string` |  | (pattern `^[a-z0-9-]{1,32}$`) |
| `source` | `object` |  | Where the secret came from (audit only). Defaults to `{kind: host}`. |
| `source.kind` | `"workspace-scan"` \| `"password-input"` \| `"user"` \| `"host"` | yes |  |
| `source.path` | `string` |  | (max length `512`) |
| `source.rule` | `string` |  | (max length `512`) |
| `source.label` | `string` |  | (max length `512`) |

**Result**

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | `string` | yes |  |
| `sentinel` | `string` | yes |  |
| `confirmed` | `boolean` | yes |  |


Example:

<!-- check: method.params credential.import -->
```json
{
 "id": "dotenv-openai",
 "value": "<real value from the scan>",
 "sentinel": "seclab_sentinel_openai_0123456789abcdef0123456789abcdef",
 "bind": [
  {
   "host": "api.openai.com",
   "path": "/v1/**",
   "methods": [
    "GET",
    "POST"
   ]
  }
 ],
 "inject": {
  "header": "Authorization",
  "fmt": "Bearer {value}"
 },
 "source": {
  "kind": "workspace-scan",
  "path": ".env",
  "rule": "openai-api-key"
 }
}
```
<!-- check: method.result credential.import -->
```json
{
 "id": "dotenv-openai",
 "sentinel": "seclab_sentinel_openai_0123456789abcdef0123456789abcdef",
 "confirmed": true
}
```


### `credential.list`

Every credential the broker knows. Values are never included.

**Params**

none

**Result**

| Field | Type | Required | Description |
|---|---|---|---|
| `credentials` | [`credentialInfo`](#credentialinfo)[] | yes |  |
| `untrusted` | [`untrusted`](#untrusted) |  |  |


### `approval.list`

Pending approvals. Use after reconnecting.

**Params**

none

**Result**

| Field | Type | Required | Description |
|---|---|---|---|
| `approvals` | [`approval`](#approval)[] | yes |  |


### `approval.decide`

Answer an approval with one of the `decisions` it offers; anything else is `-32602`. For `kind: egress`, `allow-tab` adds `rule` (or `suggestedRule`) to the tab's runtime policy. For `kind: credential-binding`, `allow-tab` confirms `binding` (or `suggestedBinding`); a binding that does not cover the held request causes that request to be denied. `allow-once` releases the held request(s) only. `deny-new-destinations` denies this request and every pending egress prompt, and every new destination for the rest of the broker's session (until `prompt.reset`). `allow-tab` is never offered for raw IPs or risky destinations. Deciding an unknown or already resolved approval is `-32602`.

**Params**

| Field | Type | Required | Description |
|---|---|---|---|
| `approvalId` | `string` | yes | (max length `64`) |
| `decision` | [`decision`](#decision) | yes |  |
| `rule` | [`rule`](broker-policy.md#rule) |  | Egress `allow-tab` only: the rule to add instead of `suggestedRule`. |
| `binding` | [`binding`](broker-policy.md#binding) |  | Credential-binding `allow-tab` only: the binding to confirm instead of `suggestedBinding`. |

**Result**

none


Example:

<!-- check: method.params approval.decide -->
```json
{
 "approvalId": "9f2c6d0e5b8a4f7e9d1c3b5a7e9f1d2c",
 "decision": "allow-once"
}
```
<!-- check: method.result approval.decide -->
```json
{}
```


### `ca.get`

The tab CA's public certificate. The private key never leaves the broker's tmpfs.

**Params**

none

**Result**

| Field | Type | Required | Description |
|---|---|---|---|
| `certPem` | `string` | yes |  |
| `pemSha256` | `string` | yes | (pattern `^[0-9a-f]{64}$`) |


### `audit.tail`

The most recent audit events (the broker keeps at most 2000).

**Params**

| Field | Type | Required | Description |
|---|---|---|---|
| `limit` | `integer` |  | (min `1`; max `2000`; default `100`) |

**Result**

| Field | Type | Required | Description |
|---|---|---|---|
| `events` | [`auditEvent`](#auditevent)[] | yes |  |


### `tab.event`

Tell the broker about the tab's lifecycle, as seen by the trusted editor. `opened`: the workspace was just opened (resets the user-action clock). `userAction`: the user did ordinary work in this tab after it opened: typing in an editor, running a command they chose, clicking in the workbench. **Consent interactions are not user actions**: accepting Workspace Trust, allowing automatic tasks, dismissing the broker's own prompts or other security dialogs must not send `userAction`, because a folder-open loader runs right after them. Until the first `userAction`, requests to raw IPs, IP-in-hostname names and risky destinations are denied without a prompt (policy `prompt.autoDenyRiskyBeforeUserAction`), and requests within `prompt.quietPeriodSeconds` of `opened` are flagged `early-after-open`. This defeats folder-open loaders such as tasks.json `runOn: folderOpen`: they run before anyone has touched the tab. After the first user action the gate stays open for the session; what remains is the flagged allow-once/deny prompt. The tab cannot send this; only the control client can. Send `userAction` at most about once a second.

**Params**

| Field | Type | Required | Description |
|---|---|---|---|
| `kind` | `"opened"` \| `"userAction"` | yes |  |

**Result**

none


Example:

<!-- check: method.params tab.event -->
```json
{
 "kind": "opened"
}
```
<!-- check: method.result tab.event -->
```json
{}
```


Example 2:

<!-- check: method.params tab.event -->
```json
{
 "kind": "userAction"
}
```
<!-- check: method.result tab.event -->
```json
{}
```


### `prompt.reset`

Clear the session's prompt state: `deny-new-destinations`, the denial count, per-destination deny cooldowns and the prompt rate window. Use it when the user explicitly asks to be prompted again.

**Params**

none

**Result**

none


### `broker.shutdown`

Drop every credential and sentinel from memory, then stop the proxy and exit. Call it when the tab closes.

**Params**

| Field | Type | Required | Description |
|---|---|---|---|
| `reason` | `string` |  | (max length `64`) |

**Result**

none
<!-- END GENERATED: protocol-methods -->

## 4. Notifications: broker → client (generated)

<!-- BEGIN GENERATED: protocol-notifications (broker/tools/docs.py; do not edit) -->
### `approval.requested`

A request is held. Show a prompt with the `risk` flags and origin, offering exactly `decisions`, and answer with `approval.decide` before `expiresAt`, or the broker denies. Egress approvals are per origin (every request to the same `scheme, host, port` waits on one prompt). Credential-binding approvals are per exact request shape (credential, origin, method, path, inject header and format). New prompts are rate-limited per tab (`prompt.maxPerMinute`), and a denied destination is not prompted again for `prompt.denyCooldownSeconds`, so a polling beacon produces one prompt, not a stream.

**Params**: [`approval`](#approval)

Example:

<!-- check: notification approval.requested -->
```json
{
 "approvalId": "9f2c6d0e5b8a4f7e9d1c3b5a7e9f1d2c",
 "kind": "egress",
 "request": {
  "scheme": "https",
  "host": "api.example.com",
  "port": 443,
  "method": "GET",
  "path": "/x"
 },
 "createdAt": 1793800000.0,
 "expiresAt": 1793800060.0,
 "waiting": 1,
 "decisions": [
  "allow-once",
  "allow-tab",
  "deny"
 ],
 "suggestedRule": {
  "host": "api.example.com",
  "schemes": [
   "https"
  ],
  "ports": [
   443
  ],
  "methods": [
   "*"
  ],
  "path": "/**"
 },
 "risk": {
  "flags": [
   "early-after-open",
   "no-user-action-yet"
  ],
  "origin": {
   "label": "task.env",
   "verified": false
  },
  "secondsSinceOpen": 2.5,
  "userActionSeen": false
 },
 "untrusted": [
  "request.host",
  "request.method",
  "request.path",
  "risk.origin.label",
  "suggestedRule.host"
 ]
}
```

Example:

<!-- check: notification approval.requested -->
```json
{
 "approvalId": "0c1d2e3f405162738495a6b7c8d9e0f1",
 "kind": "egress",
 "request": {
  "scheme": "https",
  "host": "loader.vercel.app",
  "port": 443,
  "method": "GET",
  "path": "/settings/mac"
 },
 "createdAt": 1793800100.0,
 "expiresAt": 1793800160.0,
 "waiting": 1,
 "decisions": [
  "allow-once",
  "deny",
  "deny-new-destinations"
 ],
 "suggestedRule": {
  "host": "loader.vercel.app",
  "schemes": [
   "https"
  ],
  "ports": [
   443
  ],
  "methods": [
   "*"
  ],
  "path": "/**"
 },
 "risk": {
  "flags": [
   "risky-destination:hosting"
  ],
  "origin": {
   "label": "task.env",
   "verified": false
  },
  "secondsSinceOpen": 412.0,
  "userActionSeen": true
 },
 "untrusted": [
  "request.host",
  "request.method",
  "request.path",
  "risk.origin.label",
  "suggestedRule.host"
 ]
}
```

### `approval.resolved`

Dismiss the prompt.

**Params**: | Field | Type | Required | Description |
|---|---|---|---|
| `approvalId` | `string` | yes |  |
| `decision` | [`decision`](#decision) | yes |  |
| `by` | `"controller"` \| `"timeout"` \| `"deny-rule"` | yes | `deny-rule` (revision 5): a deny rule added by `policy.update` or `policy.load` matched the waiting request. |

### `policy.changed`

The allow list changed at runtime. Persist it if the user chose "always".

**Params**: | Field | Type | Required | Description |
|---|---|---|---|
| `revision` | `integer` | yes |  |
| `added` | [`rule`](broker-policy.md#rule)[] | yes |  |
| `removed` | `string`[] | yes |  |
| `addedDeny` | [`denyRule`](broker-policy.md#denyrule)[] |  | Deny rules added (revision 5); present when the update touched the deny list. |
| `removedDeny` | `string`[] |  | Ids of deny rules removed (revision 5). |
| `by` | `"controller"` \| `"approval"` | yes |  |
| `approvalId` | `string` |  |  |
| `untrusted` | [`untrusted`](#untrusted) |  |  |

### `credential.needed`

A request is held for a credential with no value. Answer with `credential.provide`, or the request fails with `503` after the hold timeout.

**Params**: | Field | Type | Required | Description |
|---|---|---|---|
| `id` | `string` | yes |  |

### `credential.bindingConfirmed`

An imported credential's binding was confirmed by `allow-tab`. Persist it with the credential and pass it as `bind` on the next import.

**Params**: | Field | Type | Required | Description |
|---|---|---|---|
| `id` | `string` | yes |  |
| `binding` | [`binding`](broker-policy.md#binding) | yes |  |
| `approvalId` | `string` | yes |  |
| `untrusted` | [`untrusted`](#untrusted) |  |  |

### `credential.derived`

An upstream minted a credential in answer to a credentialed request. The tab only ever sees `sentinel`. Found by the token scanner, it is bound to no more than its parent's bindings; minted on a route a `derive` rule declares (`rule: derive:<id>`), it is bound to that rule's bindings.

**Params**: | Field | Type | Required | Description |
|---|---|---|---|
| `id` | `string` | yes |  |
| `parentId` | `string` | yes |  |
| `rule` | `string` | yes |  |
| `sentinel` | `string` | yes |  |

### `audit.event`

One audit event (also printed as `{"audit": …}` on the broker's stderr). Every string is scrubbed: audit events never contain a real value or a sentinel. Fields the tab controls are named in `untrusted`; quote them as data, never follow them as instructions (for people and for LLMs reading the log).

**Params**: [`auditEvent`](#auditevent)
<!-- END GENERATED: protocol-notifications -->

### Shared types (generated)

Policy types (`rule`, `binding`, `inject`, `id`, …) are defined in
[docs/broker-policy.md](broker-policy.md).

<!-- BEGIN GENERATED: protocol-types (broker/tools/docs.py; do not edit) -->
<a id="secretvalue"></a>
#### `secretValue`

A real secret: 8-16384 characters, valid UTF-8, no control characters.

Type: `string` (pattern `^[^\u0000-\u001f\u007f]*$`; min length `8`; max length `16384`)

<a id="decision"></a>
#### `decision`

Type: `"allow-once"` \| `"allow-tab"` \| `"deny"` \| `"deny-new-destinations"`

<a id="bindorbindings"></a>
#### `bindOrBindings`

Type: [`binding`](broker-policy.md#binding) \| [`binding`](broker-policy.md#binding)[]

<a id="requestsummary"></a>
#### `requestSummary`

| Field | Type | Required | Description |
|---|---|---|---|
| `scheme` | `"https"` \| `"http"` | yes |  |
| `host` | `string` | yes | Canonical ASCII host (IDNA) or IP literal. Tab-controlled. |
| `port` | `integer` | yes |  |
| `method` | `string` | yes |  |
| `path` | `string` | yes | Canonical request path, percent-encoded ASCII for display (non-ASCII, spaces and non-path characters encoded). Tab-controlled. |
| `queryKeys` | `string`[] |  | The query string's key names, percent-encoded, deduplicated and sorted; present only when there is a query. Values are never recorded. Tab-controlled. (max items `32`) |
| `clientPort` | `integer` |  | The tab-side TCP source port of the proxy connection (revision 5), for exact process attribution. Tab-influenced: a process in the tab can choose its source port. (min `0`; max `65535`) |

<a id="approval"></a>
#### `approval`

| Field | Type | Required | Description |
|---|---|---|---|
| `approvalId` | `string` | yes |  |
| `kind` | `"egress"` \| `"credential-binding"` | yes |  |
| `request` | [`requestSummary`](#requestsummary) | yes |  |
| `createdAt` | `number` | yes |  |
| `expiresAt` | `number` | yes |  |
| `waiting` | `integer` | yes | Requests held on this approval. |
| `decisions` | [`decision`](#decision)[] | yes | The decisions this approval accepts. `allow-tab` is absent for raw IPs and risky destinations; `deny-new-destinations` appears after `offerDenyNewAfter` denials. |
| `suggestedRule` | [`rule`](broker-policy.md#rule) |  | Egress only. |
| `credentialId` | `string` |  | Credential-binding only. |
| `suggestedBinding` | [`binding`](broker-policy.md#binding) |  | Credential-binding only. Advisory and tab-steerable. |
| `risk` | [`risk`](#risk) | yes |  |
| `untrusted` | [`untrusted`](#untrusted) | yes |  |

<a id="credentialinfo"></a>
#### `credentialInfo`

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | `string` | yes |  |
| `origin` | `"policy"` \| `"import"` \| `"derived"` | yes |  |
| `sentinel` | `string` | yes |  |
| `confirmed` | `boolean` | yes |  |
| `hasValue` | `boolean` | yes |  |
| `bind` | [`binding`](broker-policy.md#binding)[] | yes |  |
| `proposedBind` | [`binding`](broker-policy.md#binding)[] | yes |  |
| `provider` | `string` \| `null` | yes |  |
| `parentId` | `string` \| `null` | yes |  |

<a id="auditevent"></a>
#### `auditEvent`

`type` is one of the audit types below; other fields depend on the type. Tab-controlled fields (`host`, `path`, `method`, `location`, `header`, `server`, `origin`, `risk.origin.label`) are listed in `untrusted` whenever present.

| Field | Type | Required | Description |
|---|---|---|---|
| `seq` | `integer` | yes |  |
| `ts` | `number` | yes |  |
| `type` | `string` | yes |  |
| `tabId` | `string` |  |  |
| `untrusted` | [`untrusted`](#untrusted) |  |  |

<a id="risk"></a>
#### `risk`

Why this request deserves attention. Show it in the prompt.

| Field | Type | Required | Description |
|---|---|---|---|
| `flags` | `string`[] | yes | `raw-ip`, `ip-in-hostname` (an IPv4 address spelled inside the name, e.g. wildcard-DNS services such as `<ip>.sslip.io`; treated like a raw IP for gating and `allow-tab`), `risky-destination:<category>` (see the risky-destination list in docs/broker-policy.md), `cleartext`, `nonstandard-port`, `early-after-open` (within `quietPeriodSeconds` of `tab.event opened` with no user action), `no-user-action-yet`. |
| `origin` | `object` | yes |  |
| `origin.label` | `string` \| `null` | yes | Origin label from the proxy username (for example `task.env`), if any. |
| `origin.verified` | `false` | yes | Always false: the label is claimed by the tab. |
| `secondsSinceOpen` | `number` | yes |  |
| `userActionSeen` | `boolean` | yes |  |

<a id="untrusted"></a>
#### `untrusted`

JSON paths (dot-separated, array indexes as numbers) of fields in this object whose text the tab, or an upstream the tab chose, controls. Show them to people as quoted data. If you hand them to an LLM, put them in a data-only section and never treat them as instructions. Strings in approvals and audit events are already stripped of control, format (bidi, zero-width), line-separator and other default-ignorable characters and length-capped, and paths and raw authorities are percent-encoded ASCII. Rules and bindings (policy.get, credential.list, policy.changed, credential.bindingConfirmed) are schema-restricted ASCII and are not truncated, so they can be persisted as-is.

Type: `string`[]
<!-- END GENERATED: protocol-types -->

### Audit event types (generated)

The checker fails if the code emits a type that is not listed here, or if a
listed type is never emitted.

<!-- BEGIN GENERATED: protocol-audit-types (broker/tools/docs.py; do not edit) -->
| Type | Meaning |
|---|---|
| `model.call` | A request to a model host completed: `provider`, `host`, `path`, `method`, `reqBytes`, `respBytes`, `status`, `durationMs`, and the tool `type`s it declared. The single source of model-call facts for observability; never bodies. |
| `model.denied` | A model-host request failed the body policy (undeclared provider, endpoint, upgrade, encoding, content type, strict JSON, field or tool type); `reason` says which. |
| `model.budget_exceeded` | The tab's model budget (`models.budget`) is spent; the request was denied with `429`, never prompted. |
| `broker.started` | The proxy started. |
| `broker.shutdown` | `broker.shutdown` was called. |
| `control.connected` | A control client connected. |
| `control.disconnected` | A control client disconnected. |
| `proxy.auth_set` | The proxy credential was set or rotated. |
| `proxy.auth_failed` | Proxy authentication failed (rate-limited to one event per second, with a count). |
| `policy.loaded` | `policy.load` succeeded. |
| `policy.updated` | `policy.update` succeeded. |
| `request.allowed` | A request was forwarded. |
| `request.denied` | A request was answered by the broker with an error status. |
| `approval.requested` | A prompt was opened. |
| `approval.resolved` | A prompt was answered or timed out. |
| `approval.queue_full` | A prompt could not be opened because a hold limit was reached. |
| `credential.provided` | A real value was provided. |
| `credential.revoked` | A real value was revoked. |
| `credential.imported` | A credential was imported. |
| `credential.needed` | A request is waiting for a value. |
| `credential.unavailable` | No value arrived before the hold timeout. |
| `credential.injected` | A real value was written into a request header. |
| `credential.derived` | A minted token was re-sentinelised. |
| `credential.backstop_denied` | A credentialed request hit the provider backstop. |
| `credential.backstop_exempt` | A credentialed request on the exact route of a confirmed credential's `derive` rule passed the provider backstop; its response must yield a structurally replaced token or is blocked. |
| `credential.backstop_exception_blocked` | A response on an approved backstop exception route (provider data `exceptions`) was not a strict JSON object, or carried a credential-named field or a token-shaped value; it was blocked. A finding: the route's response shape needs review (`detail` is the JSON path or header, tab- or upstream-chosen). |
| `credential.backstop_exception_filtered` | A response on an approved backstop exception route with a field allowlist passed the check but carried top-level fields outside the allowlist; they were dropped before the tab saw the response. A finding: the measured allowlist may need review (`detail` is the comma-joined field names, upstream-chosen). |
| `sentinel.misplaced` | A sentinel appeared outside its binding. |
| `token.redacted` | A minted token was redacted (no parent credential, or a limit was reached). |
| `session.stripped` | A session header was stripped from a credentialed response. |
| `response.blocked` | A response or WebSocket frame was blocked by the scanner. |
| `upstream.blocked` | The upstream address guard refused a connection. |
| `upstream.dns_failed` | The broker could not resolve an upstream name. |
| `tcp.blocked` | A non-HTTP TCP stream was killed. |
| `udp.blocked` | A UDP flow was killed. |
| `engine.error` | A hook failed and the flow was failed closed. |
| `request.denied_unprompted` | A request was denied without a prompt: raw IP, risky destination before any user action, or `deny-new-destinations` in force. Carries `reason` and `risk`. |
| `approval.rate_limited` | A prompt was not opened because `prompt.maxPerMinute` was reached; the request was denied. |
| `tab.event` | `tab.event` was called. |
| `prompt.reset` | `prompt.reset` was called. |
| `prompt.deny_new` | The user chose `deny-new-destinations`. |
<!-- END GENERATED: protocol-audit-types -->

## 5. Proxy behaviour the tab observes

| Situation | Response |
|---|---|
| Missing or wrong proxy credentials | `407` + `Proxy-Authenticate: Basic realm="seclab-broker"` |
| Denied by policy, prompt off, denied, timed out, queue full, cooldown | `403`, `X-Seclab-Broker: denied`, JSON body `{error, status, reason}` |
| Host, SNI, `:authority` or CONNECT target disagree | `421` |
| Non-canonical path (`..`, encoded `/` `.` `\` `;` `%` NUL, `//`), method-override header or `_method` | `400` |
| Sentinel used outside its binding (`sentinelMismatch: block`) | `403` |
| Unconfirmed credential used on a path that can't be an exact binding (contains `*`) | `403` |
| Endpoint on the provider backstop with a credential | `403` |
| Credential has no value and none arrives before the hold timeout | `503` |
| Upstream resolves to a non-public or broker-local address | `502` |
| Response echoes a real value in a non-raw encoding, or a non-text credentialed response contains token-like material | `502`, `X-Seclab-Broker: blocked` |

A held request is answered when the decision arrives. The client sees one
slow request, not a retry.

## 6. Running the broker

This block runs in CI, exactly as written. It assumes `broker/build.sh` has
already built `seclab-broker:dev`.

<!-- ci: run -->
```sh
tab="seclab-doc-$$"
trap 'docker rm -f "$tab-broker" >/dev/null 2>&1; docker network rm "$tab-egress" "$tab-internal" >/dev/null 2>&1' EXIT
docker network create -o com.docker.network.bridge.enable_icc=false "$tab-egress"
docker network create --internal "$tab-internal"
docker create --name "$tab-broker" --network "$tab-egress" \
  --read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit 256 \
  --tmpfs /run/seclab:rw,nosuid,nodev,noexec,size=16m,uid=1000,gid=1000,mode=0700 \
  -e SECLAB_TAB_ID="$tab" \
  seclab-broker:dev
docker network connect "$tab-internal" "$tab-broker"
docker start "$tab-broker"
for i in $(seq 1 60); do
  if printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"health"}' \
     | docker exec -i "$tab-broker" seclab-broker control | grep -q '"status":"ok"'; then break; fi
  sleep 0.5
done
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"health"}' \
  | docker exec -i "$tab-broker" seclab-broker control | grep -q '"status":"ok"'
```
- `<tab>-egress` is the broker's own network, with ICC disabled. Under the OCI
  provider, `<tab>-internal` is the pod's `--internal` network, shared with the
  workspace.
- Under sbx, add `-p 127.0.0.1::8080` to `docker create`. That publishes the
  proxy on an ephemeral loopback port, which `docker port <tab>-broker 8080`
  reports. Never publish on a non-loopback address.
- Environment: `SECLAB_TAB_ID` (optional), `SECLAB_BODY_SIZE_LIMIT` (default
  `512m`), `SECLAB_CA_EXPORT_DIR` (optional: the public cert is also written
  there as `ca.pem`). Credentials are never passed through the environment.
- `SECLAB_EXTRA_UPSTREAM_CA_PEM` adds a trusted upstream CA. It exists **only
  for tests**; never set it in production.

## 7. Tab configuration

- **Proxy variables:** set `HTTPS_PROXY`, `HTTP_PROXY`, `https_proxy` and
  `http_proxy` to `http://seclab:<password>@<broker>:<port>`. `<broker>` is
  `host.docker.internal:<P>` under sbx and `broker:8080` in the OCI pod. Set
  both cases because sbx pre-sets the lowercase ones, and curl prefers them.
- **No-proxy list:** set both `NO_PROXY` and `no_proxy` to `localhost,127.0.0.1,::1`.
- **CA:** install the `ca.get` certificate in the tab's system store, as root
  at creation. Point `NODE_EXTRA_CA_CERTS` at it, and `REQUESTS_CA_BUNDLE`
  and `SSL_CERT_FILE` at the system bundle.
- **git:** git over HTTPS needs no special plumbing. The credential helper or
  askpass returns `x-access-token` with the sentinel as the password. The
  broker swaps it only on the bound git endpoints.

## 8. Versioning

`protocol` is `seclab-broker/<major>`.
- **Minor change, keeps the major:** adding methods, notification types,
  optional params or result fields.
- **Major bump:** removing anything, or changing what it means in a way that
  grants more or breaks a valid message. The supervisor must check
  `broker.hello` first.

The policy schema is versioned separately (`version: 1`); see
[`broker/AGENTS.md`](../broker/AGENTS.md#changing-the-schema-or-protocol-safely).
A change that only **restricts** (fails closed) and keeps every valid policy
valid keeps the major version. It bumps the schema's `x-revision` and the
broker's minor version, and must be listed below. `broker.hello` reports both
as `version` and `policySchema.revision`, so a supervisor can detect it.
`broker/docs-check.sh` fails if the latest entry, `seclab_broker.VERSION`,
`POLICY_SCHEMA_REVISION` and the schema's `x-revision` disagree.

### Changelog (generated)

<!-- BEGIN GENERATED: protocol-changelog (broker/tools/docs.py; do not edit) -->
**0.5.0** (2026-11-06; policy schema revision 5)

- Deny rules (policy `deny`, `policy.update` `addDeny`/`removeDeny`; capability `denyRules`). A deny rule (`id`, `host`, optional `ports` and `schemes`) takes precedence over every allow rule, the baseline, `allow-tab` grants, prompts and credential bindings. A matching request is denied with `403` and audited as `request.denied` (reason `denied by rule <id>`, key `ruleId`), never prompted. Omitted `ports` means every port and omitted `schemes` means http and https. Adding one resolves a pending prompt it matches as `deny` (`approval.resolved` `by: deny-rule`), denies new requests on open connections, and stops relaying on an open WebSocket. `policy.changed` carries `addedDeny`/`removedDeny`. Requested by tab observability for its user-approved Block destination action.
- Request summaries (audit events, approvals) carry `clientPort`, the tab-side TCP source port of the proxy connection, for exact process attribution on OCI tabs. It is tagged untrusted: a process in the tab can choose its source port.

**0.4.0** (2026-11-05; policy schema revision 4)

- **Behaviour change:** the built-in `copilot` model provider is now measured, not drafted (secure-agentic B2 run in a real tab). Endpoints: `GET /models`, `POST /responses`, `POST /chat/completions`, `POST /v1/messages`; each POST has its own top-level field list and tool types (`function` and `custom` on `/responses` and `/chat/completions`; untyped tools count as `custom` on `/v1/messages`). `/embeddings` and the never-sent draft fields are gone. `POST /mcp/readonly` (GitHub's remote MCP server) is denied unless a grant names it.
- Model provider endpoints may carry `id`, `fields`, `toolTypes`, `untypedTool` and `requiresGrant`; a model grant may name an `endpoint` instead of a `toolType` (Tier C).
- User-approved backstop exceptions: exactly `GET /copilot_internal/managed_settings`, `/team_customizations` and `/content_exclusion` on GitHub (no body, query or upgrade). Their responses get the `/user` checks plus a strict top-level field allowlist on every status (an unlisted key blocks): `managed_settings` per the public `IManagedSettingsResponse`, with `telemetry` (which carries OTLP credentials) always dropped whatever its shape; the other two allow only `{}` or GitHub's error envelope (`message`, `documentation_url`, `status`, also listed for `managed_settings`) until their shapes are known.
- The `/copilot_internal/user` exception has a field allowlist (on every status; it includes GitHub's error fields `message` and `documentation_url`): once the whole response has passed the check, top-level fields outside it are dropped (audit `credential.backstop_exception_filtered`, the names in `detail`). Three measured benign keys pass the credential-name check only at their exact JSON paths; token-shaped values are still refused everywhere.
- Exception responses: headers and trailers are checked alike; token-shaped keys and URL userinfo (also encoded or scheme-relative) block, in the body, headers and trailers; a bodiless response passes after the header checks. Session headers are stripped from trailers on credentialed flows too.
- Request summaries (audit events, approvals) carry `queryKeys`: the query's key names, never values (a sealed agent-host token becomes `[sealed]`); approvals list `request.queryKeys` as untrusted. Shipped provider data is validated whenever a policy loads (built-in model providers against `modelProvider`; backstop files' keys and names). A model provider is refused if its providers' hosts overlap, a grant-only endpoint isn't a literal path, or an earlier endpoint with an overlapping method shadows a later one.

**0.3.1** (2026-11-05; policy schema revision 3)

- The provider backstop exempts a confirmed credential's request on the exact `from` route of one of its own `derive` rules (audit `credential.backstop_exempt`); the response must yield a structurally replaced token or is blocked. Needed for D7: the Copilot token endpoint is backstopped. Every other backstopped route stays denied.
- Derived children are also dropped on an identical re-import; a same-value `credential.provide` keeps them.
- Coordinator-approved backstop exception (provider data `exceptions`): exactly `GET /copilot_internal/user` on GitHub, no body, query or upgrade; its response must be a strict JSON object with no credential-named key or token-shaped value, else it is blocked (audit `credential.backstop_exception_blocked`).

**0.3.0** (2026-11-05; policy schema revision 3)

- **Behaviour change:** model hosts get a fail-closed body policy (policy `models`). A request to a declared provider's host, or to any host on the broker's known model-host list, is denied with `403` unless the provider is declared, the method and path are one of its endpoints, it is not an upgrade, and its body is strict JSON (identity encoding, JSON media type, no duplicate or escaped keys) with only listed top-level fields and tool `type`s. Tier C exceptions are `models.grants`. Why: a model API with server-side tools can relay workspace data to a URL the tab chooses (secure-agentic plan 4.4).
- **Behaviour change:** every credential location on a model request (built-in headers and query parameters, plus a provider's `authHeaders`/`authQueryParams`) must carry a sentinel of this tab; a value containing `copilot-sealed.v1.` in a header, the URL or the body is never forwarded to any host.
- **Behaviour change:** model bodies may not name content the provider would fetch (URL-bearing keys and URL sources, at any depth, must be inline `data:` URIs) unless a `remote-content` grant names the provider; keys differing only in case are refused.
- Per-tab model budget (`models.budget`, requests and bytes over the tab's lifetime, default 5000 and 1 GiB); over budget is `429`, never prompted. `health` reports `models` usage.
- Audit types `model.call`, `model.denied`, `model.budget_exceeded`; audit key `detail` (tab-chosen field or tool name) is tagged untrusted.
- Trusted derivation: a credential (policy or `credential.import` with `bind`) may carry `derive` rules. On exactly the declared route, a 2xx response's top-level JSON string field is replaced by a sentinel for child `<parent>.<rule>` (stable across re-mints), bound to the rule's bindings; any other response shape on that route is blocked. The only way a derived credential is bound beyond its parent (secure-agentic D7).
- Capabilities `modelBodyPolicy`, `modelBudget`, `trustedDerivation`.

**0.2.0** (2026-11-05; policy schema revision 2)

- **Behaviour change:** credentials are injected into a WebSocket upgrade only when the matching binding has `websocket: true` (new optional binding field, default `false`). A credentialed upgrade without the opt-in is refused with `403`, and an unconfirmed imported credential is never offered for an upgrade by prompt. Why: a minted token streamed across structured WebSocket messages can't be reliably recognised, so it could reach the tab whole. Supervisors that relied on credentialed WebSockets must add `websocket: true` to those bindings.
- `broker.hello` returns `policySchema` (`version`, `revision`).
- Capability `websocketOptIn`.

**0.1.0** (2026-11-04; policy schema revision 1)

- Initial protocol.
<!-- END GENERATED: protocol-changelog -->
