# seclab-tabd protocol, v0.2 (`seclab-tabd/0.2`)

Status: **draft**. Changes are versioned (§6); 0.2 adds tab observability
(`tab.events.*`, `tab.observe`, `tab.event`, `tab.observation`; [ADR](../adr/20261104-tab-observability.md),
[event reference](EVENTS.md)). This protocol connects
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
| `initialize` | `{ protocolVersion: "seclab-tabd/0.1", client: { name, version } }` | `{ protocolVersion, supervisor: { version }, drivers: DriverInfo[], templates: TabTemplate[] }` | Must be first. A major-version mismatch is an error. Reconciles running tabs left by a dead supervisor (adopt after fence verification, or quarantine), then garbage-collects: stopped tabs unused for `--gc-days` (default 30; 0 disables) are removed, except tabs that are running, leased by a live supervisor, or holding vaulted secrets. |
| `tab.claim` | `{ workspace: { hostPath }, templateRef?: { name } }` | `{ tab }` | The **only** method that accepts a host path. Validates it (absolute, canonical, an existing directory, not a denylisted root) and returns the existing tab for that path or mints a new one. Persists the mapping. Does not start anything. |
| `tab.get` | `{ tabId }` | `{ tab }` | Unknown ID → error `-32004`. |
| `tab.list` | `{}` | `{ tabs: Tab[] }` | |
| `tab.ensureRunning` | `{ tabId, acceptFindings?: string[] }` | `{ tab, connectionToken }` | **Scans the workspace for secrets first** (gitleaks; ADR pre-mount-secret-scan). Unresolved findings error `-32020`; a scan that is incomplete with no unresolved findings errors `-32021`. Both carry `data: { findings (redacted), incomplete, overflow, error }`, and findings always come first, even from a partial scan. `acceptFindings` (finding ids, plus `scan-incomplete` when incomplete) records an exception. Then creates or starts the sandbox, REH and broker, and applies the fence. Emits `tab.status`. |
| `tab.scan` | `{ tabId }` | `{ complete, error?, overflow, findings: [{ id, source: worktree\|git-dir\|history\|objects, file, line, rule, commit?, movable }] }` | Never returns secret values. `file` is untrusted, escaped display text; `a.tar.gz!inner` marks an archive member. Rules `unscanned-large-file`, `unscanned-large-object`, `unscanned-unreadable`, `unscanned-link`, `unscanned-archive` and `unrecognised-git-dir` mark content that could not be scanned; they block like secrets. |
| `tab.moveSecrets` | `{ tabId, moves: [{ id, bind: { host, path? } }] }` | `{ moved: [{ id, sentinel }] }` | Tab must be stopped. Rewrites each value to a sentinel in the working copy (atomic, no symlinks, never commits) and records it in the host vault. |
| `tab.restoreSecrets` | `{ tabId }` | `{ restored, notRestored }` | Reverses `moveSecrets` (tab stopped). |
| `tab.connect` | `{ tabId }` | `{ channel, connectionToken }` | **Re-verifies the fence first.** On mismatch: error `-32010` with the reason. Opens an exec stream to the REH socket on a new channel. |
| `tab.stop` | `{ tabId }` | `{ tab }` | Ends the tab's channels, then stops the sandbox. |
| `tab.remove` | `{ tabId }` | `{}` | Removes the sandbox and fence rules; forgets the mapping. Refused (`-32022`) while the tab's vault holds moved secrets: restore them first. |
| `tab.reset` | `{ tabId }` | `{ tab }` | Rebuilds the tab from its template: stops it and removes the sandbox and its home (installed extensions, anything dropped there). Keeps the tab ID, workspace mapping, vault and exceptions; the next `ensureRunning` starts it fresh. |
| `stream.end` | `{ channel }` | — (notification) | Client half-close (client → REH EOF). |
| `stream.close` | `{ channel }` | — (notification) | Client abort; the supervisor kills the exec child. |
| `shutdown` | `{ stopTabs?: boolean }` | `{}` | Graceful: ends channels; leaves tabs running unless `stopTabs`. |
| `tab.events.subscribe` | `{ tabId?, sinceSeq?, minPriority?, classes? }` | `{ subscription, lastSeq, observation }` | Live events as `tab.event` notifications; all tabs when `tabId` is absent. `sinceSeq` (needs `tabId`) replays buffered events after it (at most 1000). At most 16 subscriptions. |
| `tab.events.unsubscribe` | `{ subscription }` | `{}` | |
| `tab.events.tail` | `{ tabId, limit? (1–1000, default 200), beforeSeq? }` | `{ events, observation }` | From the supervisor's in-memory ring (last 2000 per tab). Older events: the log (`seclab tab logs`). |
| `tab.events.report` | `{ tabId, events: [{ source, class, priority, summary, detail? }] }` (≤ 64) | `{ accepted, rejected }` | For trusted editor components only: `source: rpc-filter` with `class: rpc.decision` (`gate` reserved). `integrity` is always set to `trusted` by the supervisor; other sources or classes are rejected. RPC-filter decisions reach the Tab Manager over a `MainThreadSeclab*` service that sandboxed hosts can't call. |
| `tab.observe` | `{ tabId, mode: default\|deep }` | `{ mode, appliesOnRestart, observation }` | `deep` also traces file opens under sbx (about 45 µs per open). Takes effect when the collector next starts. |

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
| `tab.event` | `{ subscription, event, replay?, lagged? }`: one [event](EVENTS.md). `lagged: n` means `n` matching events were not sent while the client wasn't reading (stdout backlog over 4 MiB); fetch them with `tab.events.tail`. |
| `tab.observation` | `{ tabId, state: observed\|degraded\|unobserved\|unavailable, since, reason, sensor?, mode?, untrusted: ["reason"] }`: `reason` can carry sensor-derived text; treat it as data |

## 5. Errors
JSON-RPC standard codes, plus: `-32001` not initialized, `-32002` invalid
path, `-32003` driver unavailable, `-32004` unknown tab, `-32010` fence
verification failed, `-32011` sandbox failed to start, `-32012` REH not
ready, `-32020` secrets found in the workspace, `-32021` secret scan
incomplete.

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
- **Observability is one-way.** Under sbx the supervisor starts the in-VM
  collector over `sbx exec -i -u root` before the REH; the collector's
  stdout is the only tab → supervisor observability channel, and its stdin
  carries only a config line and `ensure-reh` commands. Everything a sensor
  says is tab-derived: lines are capped, parsed strictly, escaped, redacted
  and rate-limited, never interpreted, and never become argv, paths, tab IDs
  or policy. Sensor events carry `integrity` `tab-vm-root` (sbx) or
  `host-observed` (OCI); only supervisor-produced events are `trusted`.
- Under sbx the REH relay (`tab.connect`) runs as `990:990` (`seclab-relay`),
  not as the tab user, so the tab can't ptrace it.
