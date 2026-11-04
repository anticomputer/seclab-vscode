# seclab-tabd protocol, v0.1 (`seclab-tabd/0.1`)

Status: **draft for v0.1**. Changes are versioned (§6). This protocol connects
**clients** (the editor's Tab Manager, the containment test harness, a CLI, or
other editors and agents) to the **tab supervisor** `seclab-tabd`. Rationale:
[ADR tab supervisor](../adr/20261104-tab-supervisor.md).

## 1. Transport and framing
- The client spawns `seclab-tabd` as a child process. The protocol runs over
  the child's **stdin** (client → supervisor) and **stdout** (supervisor →
  client). **stderr** carries human-readable logs only and is never parsed.
- The byte stream is a sequence of **frames**:

  | Offset | Size | Field |
  |---|---|---|
  | 0 | 4 | `length`: uint32 big-endian, payload byte count, 0 … 1 048 576 |
  | 4 | 4 | `channel`: uint32 big-endian |
  | 8 | `length` | payload |

- **Channel 0** carries exactly one UTF-8 JSON-RPC 2.0 message per frame.
- **Channels ≥ 1** carry raw bytes of a stream the supervisor opened in a
  `tab.connect` result. Stream ends and closes are signalled on channel 0
  (§4).
- A frame longer than the maximum, data for a channel that is not open, or
  invalid JSON on channel 0 is a **fatal protocol error**: the receiver logs
  it and terminates the connection (the supervisor exits).

## 2. Resource model
Vocabulary borrowed from kubernetes-sigs/agent-sandbox (pinned in the ADR).
Objects use `apiVersion: tabd.seclab.dev/v1alpha1`.

```jsonc
// Tab  (≈ agent-sandbox Sandbox)
{ "apiVersion": "tabd.seclab.dev/v1alpha1", "kind": "Tab",
  "metadata": { "name": "t-<26 base32 chars>", "createdAt": "…" },
  "spec": { "workspace": { "hostPath": "/Users/me/src/a", "mountPath": "/Users/me/src/a" },
            "templateRef": { "name": "default" }, "driver": "sbx" },
  "status": { "phase": "Pending|Starting|Running|Stopped|Failed",
              "conditions": [ { "type": "Ready|FenceVerified|RehReady|BrokerReady",
                                "status": "True|False|Unknown", "reason": "…", "message": "…" } ] } }

// TabTemplate  (≈ SandboxTemplate). Read-only to clients in v0.1; defined in supervisor config.
{ "kind": "TabTemplate", "metadata": { "name": "default" },
  "spec": { "driver": "sbx", "image": "…", "resources": { "cpus": 2, "memory": "4g" },
            "envVarsInjectionPolicy": "Disallowed", "fence": "required", "broker": "required|none" } }

// DriverInfo
{ "name": "sbx", "available": true, "version": "0.51.0",
  "capabilities": { "isolationClass": "microvm|namespaces|vm|remote",
                    "networkFence": "sbx-policy|internal-network|none",
                    "liveMounts": false, "holdAndResume": false,
                    "fileWatch": "native|virtiofs|polling", "sameAbsolutePathMount": true } }
```

**Tab IDs** (`metadata.name`) are minted by the supervisor from 128 random
bits: `t-` followed by 26 lowercase base32 characters. They are opaque and
never derived from paths or other input. The editor uses the authority
`seclab+<tabId>`.

## 3. Methods (client → supervisor)
| Method | Params | Result | Notes |
|---|---|---|---|
| `initialize` | `{ protocolVersion: "seclab-tabd/0.1", client: { name, version } }` | `{ protocolVersion, supervisor: { version }, drivers: DriverInfo[], templates: TabTemplate[] }` | Must be first. A major-version mismatch is an error. |
| `tab.claim` | `{ workspace: { hostPath }, templateRef?: { name } }` | `{ tab }` | The **only** method that accepts a host path. Validates it (absolute, canonical, an existing directory, not a denylisted root) and returns the existing tab for that path or mints a new one. Persists the mapping. Does not start anything. |
| `tab.get` | `{ tabId }` | `{ tab }` | Unknown ID → error `-32004`. |
| `tab.list` | `{}` | `{ tabs: Tab[] }` | |
| `tab.ensureRunning` | `{ tabId }` | `{ tab, connectionToken }` | Creates or starts the sandbox, REH and broker; applies the fence. Emits `tab.status` notifications. |
| `tab.connect` | `{ tabId }` | `{ channel, connectionToken }` | **Re-verifies the fence first.** On mismatch: error `-32010` with the reason. Opens an exec stream to the REH socket on a new channel. |
| `tab.stop` | `{ tabId }` | `{ tab }` | Ends the tab's channels, then stops the sandbox. |
| `tab.remove` | `{ tabId }` | `{}` | Removes the sandbox and fence rules; forgets the mapping. |
| `stream.end` | `{ channel }` | — (notification) | Client half-close (client → REH EOF). |
| `stream.close` | `{ channel }` | — (notification) | Client abort; the supervisor kills the exec child. |
| `shutdown` | `{ stopTabs?: boolean }` | `{}` | Graceful: ends channels; leaves tabs running unless `stopTabs`. |

Reserved (not in v0.1): `warmPool.*`, `tab.policy.*` (broker adapter),
`prompt.respond`.

## 4. Notifications (supervisor → client)
| Method | Params |
|---|---|
| `tab.status` | `{ tabId, phase, conditions }` |
| `stream.end` | `{ channel }`: REH → client EOF |
| `stream.close` | `{ channel, error? }`: the exec child exited or failed; channel ID retired |
| `audit` | `{ ts, tabId?, action, outcome, detail }`: every driver invocation and fence decision; also appended to the supervisor's audit log |
| `log` | `{ level, message }` |

## 5. Errors
JSON-RPC standard codes, plus: `-32001` not initialized, `-32002` invalid
path, `-32003` driver unavailable, `-32004` unknown tab, `-32010` fence
verification failed, `-32011` sandbox failed to start, `-32012` REH not
ready.

## 6. Versioning
`protocolVersion` is `seclab-tabd/<major>.<minor>`. A minor bump only adds
optional fields, methods or notifications; a major bump may break. A client
must ignore unknown notification methods and unknown fields.

## 7. Security properties (what clients may rely on)
- The supervisor never runs a shell: every runtime call is an argv `spawn`,
  and every value interpolated into argv is validated against a strict
  pattern (sandbox names, policy resources) or canonicalised (paths).
- No value from a tab (REH bytes, sandbox output) ever becomes a supervisor
  argv element, a tab ID or a host path. Driver output that the supervisor
  parses (`sbx policy ls --json`, `sbx ls --json`) is treated as untrusted
  and validated before use.
- Fence verification fails closed: if verification can't complete (sbx
  error, timeout), `tab.connect` fails.
- The per-tab REH connection token is minted by the supervisor and written
  into the sandbox by the supervisor. Tabs never choose it.
