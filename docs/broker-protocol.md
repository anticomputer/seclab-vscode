# Broker control protocol (`seclab-broker/1`)

The per-tab broker (`broker/`) is driven by exactly one kind of trusted
client: the host-side tab supervisor (today `seclab-tabd`). This document is
the whole contract between them. It is runtime-neutral: the same messages
are used whether the broker is a Docker Desktop container in front of an sbx
microVM, an OCI pod sidecar, or a Kubernetes sidecar.

Decision record: [ADR 20261104-broker-policy-and-control-protocol](adr/20261104-broker-policy-and-control-protocol.md).
Policy schema: [`broker/schema/policy.v1.schema.json`](../broker/schema/policy.v1.schema.json).

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

### Error codes

| Code | Meaning |
|---|---|
| -32700 | Parse error (line is not JSON) |
| -32600 | Invalid request (not a JSON-RPC 2.0 request, batch, bad `id`) |
| -32601 | Unknown method |
| -32602 | Invalid params (message is safe to show; it never contains a credential value) |
| -32603 | Internal error |
| -32001 | Not ready (for example `ca.get` before the CA exists) |
| -32002 | Control socket unavailable (emitted by the bridge, `id: null`) |

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

## 3. Methods (client → broker)

All `params` are objects. Omitted `params` means `{}`.

### `broker.hello` → `{protocol, version, tabId, engine, engineVersion, capabilities}`
`protocol` is `"seclab-broker/1"`. `capabilities` is a map of feature flags
(see the [engine capability matrix](../broker/README.md#engine-capability-matrix)).
Clients must degrade explicitly when a flag they rely on is `false` or absent.

### `health` → status object
```json
{"status": "ok", "uptimeSeconds": 12.3,
 "proxy": {"listening": true, "authConfigured": true},
 "policy": {"revision": 3, "rules": 4, "credentials": 1},
 "pendingApprovals": 0, "heldFlows": 0, "credentials": 2, "controllers": 1}
```
`status` is `"starting"` until the proxy is listening.

### `proxy.auth.set {username, password}` → `{epoch}`
Sets the per-tab proxy credential. The tab sends it as HTTP Basic
`Proxy-Authorization` (normally through userinfo in its proxy URL).
- `username`: `[A-Za-z0-9._-]{1,64}`. Convention: `"seclab"`.
- `password`: `[A-Za-z0-9_-]{22,128}`, which is at least 128 bits as
  base64url. Generate it with a CSPRNG, for example `secrets.token_urlsafe(16)`.
- Comparison is constant time. The value is never logged or echoed.
- Calling it again rotates the credential. Tunnels opened under the old
  credential stop being accepted, and their next request gets `407`.
- Unauthenticated clients are answered `407` before anything else happens.
  They are never held, never prompted, never resolved and never connected
  upstream.

### `policy.load {policy}` → `{revision, sentinels: {credentialId: sentinel}}`
Replaces the tab's policy. `policy` must validate against
[`policy.v1.schema.json`](../broker/schema/policy.v1.schema.json).
- Rules added by approvals (`allow-tab`) are discarded. Persist them from
  `policy.changed` and include them next time.
- Credential sentinels are **stable** across reloads for the same credential
  id. Real values that were already provided are kept.
- Credentials no longer in the policy are dropped from memory.
- Imported credentials (`credential.import`) are not affected.
- A `tabId` that differs from the broker's `SECLAB_TAB_ID` is rejected.

### `policy.get` → `{revision, policy}`
The effective policy, including rules added at runtime. It never includes
credential values.

### `policy.update {addAllow?: Rule[], removeAllow?: ruleId[]}` → `{revision}`
Live edit of the allow list, emitting `policy.changed`. Removing a rule
requires that it has an `id`.

### `credential.provide {id, value, expiresAt?}` → `{}`
Supplies the real value for a credential, just in time. `expiresAt` is unix
seconds; after it, the value is dropped and the next use raises
`credential.needed` again. `value` must be 8–16384 characters, valid UTF-8,
with no control characters. Held requests waiting for this credential resume
immediately.

### `credential.revoke {id, rotateSentinel?}` → `{sentinel}`
Drops the real value, and any credentials derived from it. With
`rotateSentinel: true` the credential gets a new sentinel; the old one stops
matching.

### `credential.import {...}` → `{id, sentinel, confirmed}`
Imports a user-supplied secret. It is used when a workspace scan finds a
secret before mounting (`source.kind: "workspace-scan"`) and for captured
password input (`"password-input"`).
```json
{"id": "dotenv-openai", "value": "<real>", "sentinel": "<optional, host-chosen>",
 "bind": [Binding], "proposedBind": [Binding],
 "inject": {"header": "Authorization", "fmt": "Bearer {value}"},
 "provider": "github",
 "source": {"kind": "workspace-scan", "path": ".env", "rule": "openai-api-key", "label": "OpenAI key"}}
```
- **`sentinel`** may be supplied (`[A-Za-z0-9_.~-]{32,256}`) so that a
  sentinel already written into a workspace file stays valid across tab
  restarts. Otherwise the broker mints one.
- **`bind`** holds confirmed bindings; with none, the credential is
  *unconfirmed*. **`proposedBind`** only shapes the first-use prompt. The
  `Binding` shape is the same as in the policy schema.
- **First use of an unconfirmed credential:** its sentinel appears in a request
  header, over HTTPS, to a host the tab may already reach. The broker holds
  that request and emits `approval.requested` with
  `kind: "credential-binding"`. `allow-tab` confirms the binding and emits
  `credential.bindingConfirmed`, which the supervisor should persist (keychain)
  and pass as `bind` on the next import. `allow-once` injects for that single
  request.
- **Storage:** the broker never writes the value anywhere. Persistence is the
  supervisor's job, in the macOS keychain.

### `credential.list` → `{credentials: [...]}`
For each credential: `{id, origin: policy|import|derived, sentinel, confirmed,
hasValue, bind, proposedBind, provider, parentId}`. Values are never included.

### `approval.list` → `{approvals: [Approval]}`
Pending approvals. Use it after reconnecting.

### `approval.decide {approvalId, decision, rule?, binding?}` → `{}`
`decision` is `"allow-once"`, `"allow-tab"` or `"deny"`.
- For `kind: "egress"`, `allow-tab` adds `rule` to the tab's runtime policy,
  or `suggestedRule` if `rule` is absent.
- For `kind: "credential-binding"`, `allow-tab` confirms `binding`, or
  `suggestedBinding` if `binding` is absent.
- A binding that does not cover the held request causes that request to be
  denied.
- Deciding an unknown or already resolved approval is `-32602`.

### `ca.get` → `{certPem, pemSha256}`
The tab CA's **public** certificate. The private key never leaves the
broker's tmpfs.

### `audit.tail {limit?}` → `{events: [...]}`
The most recent audit events (at most 2000 are kept).

### `broker.shutdown {reason?}` → `{}`
Drops every credential and sentinel from memory, then stops the proxy and
exits. Use it when the tab closes.

## 4. Notifications (broker → client)

| Method | Params | Client action |
|---|---|---|
| `approval.requested` | `Approval` | Show a prompt; answer with `approval.decide` before `expiresAt`, or the broker denies |
| `approval.resolved` | `{approvalId, decision, by: controller\|timeout}` | Dismiss the prompt |
| `policy.changed` | `{revision, added: Rule[], removed: id[], by, approvalId?}` | Persist if the user chose "always" |
| `credential.needed` | `{id}` | `credential.provide` (JIT) or ignore (request fails after the hold timeout) |
| `credential.bindingConfirmed` | `{id, binding, approvalId}` | Persist the binding with the imported credential |
| `credential.derived` | `{id, parentId, rule, sentinel}` | Informational: an upstream minted a credential, which the tab only sees as `sentinel` |
| `audit.event` | audit event | Log or display |

**Approval** object:
```json
{"approvalId": "…", "kind": "egress" | "credential-binding",
 "request": {"scheme": "https", "host": "api.example.com", "port": 443, "method": "GET", "path": "/x"},
 "createdAt": 1793800000.0, "expiresAt": 1793800060.0, "waiting": 1,
 "decisions": ["allow-once", "allow-tab", "deny"],
 "suggestedRule": Rule,                      // egress only
 "credentialId": "…", "suggestedBinding": Binding}   // credential-binding only
```
- **Egress approvals** are per origin: every request to the same
  `(scheme, host, port)` that arrives while the prompt is open waits on it,
  and `allow-once` releases all of them.
- **Credential-binding approvals** are per exact request shape: credential,
  origin, method, path, and inject header and format. Two different requests
  never share one.

**Audit events** carry `{seq, ts, type, tabId?, …}`. Every string is
scrubbed, so audit events never contain a real value or a sentinel. Types
emitted today: `broker.started`, `broker.shutdown`, `control.connected`,
`control.disconnected`, `proxy.auth_set`, `proxy.auth_failed`, `policy.loaded`,
`policy.updated`, `request.allowed`, `request.denied`, `approval.requested`,
`approval.resolved`, `approval.queue_full`, `credential.provided`,
`credential.revoked`, `credential.imported`, `credential.needed`,
`credential.unavailable`, `credential.injected`, `credential.derived`,
`credential.backstop_denied`, `sentinel.misplaced`, `token.redacted`,
`session.stripped`, `response.blocked`, `upstream.blocked`,
`upstream.dns_failed`, `tcp.blocked`, `udp.blocked`, `engine.error`.

## 5. Proxy behaviour the tab observes

| Situation | Response |
|---|---|
| Missing or wrong proxy credentials | `407` + `Proxy-Authenticate: Basic realm="seclab-broker"` |
| Denied by policy, prompt off, denied, timed out, queue full, cooldown | `403`, `X-Seclab-Broker: denied`, JSON body `{error, status, reason}` |
| Host, SNI, `:authority` or CONNECT target disagree | `421` |
| Non-canonical path (`..`, encoded `/` `.` `\` `;` `%` NUL, `//`), method-override header or `_method` | `400` |
| Sentinel used outside its binding (`sentinelMismatch: block`) | `403` |
| Endpoint on the provider backstop with a credential | `403` |
| Credential has no value and none arrives before the hold timeout | `503` |
| Upstream resolves to a non-public or broker-local address | `502` |
| Response echoes a real value in a non-raw encoding, or a non-text credentialed response contains token-like material | `502`, `X-Seclab-Broker: blocked` |

A held request is answered when the decision arrives. The client sees one
slow request, not a retry.

## 6. Running the broker

```sh
docker create --name <tab>-broker \
  --network <tab>-egress \                 # own network, ICC disabled
  -p 127.0.0.1:<P>:8080 \                  # sbx provider only
  --read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit 256 \
  --tmpfs /run/seclab:rw,nosuid,nodev,noexec,size=16m,uid=1000,gid=1000,mode=0700 \
  -e SECLAB_TAB_ID=<tab> \
  seclab-broker:<version>
docker network connect <tab>-internal <tab>-broker   # OCI provider: the pod's --internal network
docker start <tab>-broker
```
- Create `<tab>-egress` with `-o com.docker.network.bridge.enable_icc=false`.
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
- **No-proxy list:** set both `NO_PROXY` and `no_proxy` to `localhost,127.0.0.1`.
- **CA:** install the `ca.get` certificate in the tab's system store, as root
  at creation. Point `NODE_EXTRA_CA_CERTS` at it, and `REQUESTS_CA_BUNDLE`
  and `SSL_CERT_FILE` at the system bundle.
- **git:** git over HTTPS needs no special plumbing. The credential helper or
  askpass returns `x-access-token` with the sentinel as the password. The
  broker swaps it only on the bound git endpoints.

## 8. Versioning

`protocol` is `seclab-broker/<major>`. Adding methods, notification types,
optional params or result fields is a minor change and keeps the major.
Removing or changing the meaning of anything bumps the major, and the
supervisor must check `broker.hello` first. The policy schema is versioned
separately (`version: 1`); see
[`broker/AGENTS.md`](../broker/AGENTS.md#changing-the-schema-or-protocol-safely).
