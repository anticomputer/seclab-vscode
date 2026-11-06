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
                    "fileWatch": "native|virtiofs|polling", "sameAbsolutePathMount": true,
                    "writeBack": "gated|ungated" } }
```

`writeBack` is `gated` when tab writes reach the host checkout only through the
write-back gate (sbx: a fuse-overlayfs upper layer in the tab's VM, mounted by
`seclab-wb-mount` before the REH starts), and `ungated` when the tab writes the
host directly (OCI on Docker Desktop). The editor shows "write-back not gated"
for ungated tabs ([ADR](../adr/20261104-write-back-gate.md)).

**Tab IDs** (`metadata.name`) are minted by the supervisor from 128 random
bits: `t-` followed by 26 lowercase base32 characters. They are opaque and
never derived from paths or other input. The editor uses the authority
`seclab+<tabId>`.

## 3. Methods (client → supervisor)
| Method | Params | Result | Notes |
|---|---|---|---|
| `initialize` | `{ protocolVersion: "seclab-tabd/0.1", client: { name, version, capabilities?: { approvals?: boolean } } }` | `{ protocolVersion, supervisor: { version }, drivers: DriverInfo[], templates: TabTemplate[] }` | Must be first. A major-version mismatch is an error. Reconciles running tabs left by a dead supervisor (adopt after fence verification, or quarantine), then garbage-collects: stopped tabs unused for `--gc-days` (default 30; 0 disables) are removed, except tabs that are running, leased by a live supervisor, or holding vaulted secrets. `client.capabilities.approvals: true` declares that the client shows broker prompts (`tab.approval`); only then are prompts enabled in the broker policy of tabs this supervisor starts. Otherwise unlisted egress is denied without a prompt. |
| `tab.claim` | `{ workspace: { hostPath }, templateRef?: { name } }` | `{ tab }` | The **only** method that accepts a host path. Validates it (absolute, canonical, an existing directory, not a denylisted root) and returns the existing tab for that path or mints a new one. Persists the mapping. Does not start anything. |
| `tab.get` | `{ tabId }` | `{ tab }` | Unknown ID → error `-32004`. |
| `tab.list` | `{}` | `{ tabs: Tab[] }` | |
| `tab.ensureRunning` | `{ tabId, acceptFindings?: string[] }` | `{ tab, connectionToken }` | **Scans the workspace for secrets first** (gitleaks; ADR pre-mount-secret-scan). Unresolved findings error `-32020`; a scan that is incomplete with no unresolved findings errors `-32021`. Both carry `data: { findings (redacted), incomplete, overflow, error }`, and findings always come first, even from a partial scan. `acceptFindings` (finding ids, plus `scan-incomplete` when incomplete) records an exception. Then creates or starts the sandbox, REH and broker, and applies the fence. Emits `tab.status`. |
| `tab.scan` | `{ tabId }` | `{ complete, error?, overflow, findings: [{ id, source: worktree\|git-dir\|history\|objects, file, line, rule, commit?, movable }] }` | Never returns secret values. `file` is untrusted, escaped display text; `a.tar.gz!inner` marks an archive member. Rules `unscanned-large-file`, `unscanned-large-object`, `unscanned-unreadable`, `unscanned-link`, `unscanned-archive` and `unrecognised-git-dir` mark content that could not be scanned; they block like secrets. |
| `tab.inspect` | `{ tabId }` | `{ items: [{ kind, path, detail }], truncated }` | Informational summary of what the folder would run automatically or feed to AI agents: folder-open, hidden and fetch-and-run tasks; dev container lifecycle commands; MCP servers; agent instruction, hook and config files; `chat.*` auto-approve settings. Read on the host (bounded, links never followed, nothing executed). `path` and `detail` are the folder's own text: render as plain text. |
| `tab.moveSecrets` | `{ tabId, moves: [{ id, bind: { host, path? } }] }` | `{ moved: [{ id, sentinel }] }` | Tab must be stopped. Rewrites each value to a sentinel in the working copy (atomic, no symlinks, never commits) and records it in the host vault. |
| `tab.restoreSecrets` | `{ tabId }` | `{ restored, notRestored }` | Reverses `moveSecrets` (tab stopped). |
| `tab.connect` | `{ tabId }` | `{ channel, connectionToken }` | **Re-verifies the fence first.** On mismatch: error `-32010` with the reason. Opens an exec stream to the REH socket on a new channel. |
| `tab.stop` | `{ tabId }` | `{ tab }` | Ends the tab's channels, then stops the sandbox. |
| `tab.remove` | `{ tabId }` | `{}` | Removes the sandbox and fence rules; forgets the mapping. Refused (`-32022`) while the tab's vault holds moved secrets: restore them first. |
| `tab.reset` | `{ tabId }` | `{ tab }` | Rebuilds the tab from its template: stops it and removes the sandbox and its home (installed extensions, anything dropped there). Keeps the tab ID, workspace mapping, vault and exceptions; the next `ensureRunning` starts it fresh. Discards the tab's write-back state (its upper layer is gone). |
| `tab.writeback.status` | `{ tabId }` | `{ gated, active, pending: [{ path, kind, reasons, sig, hostHash, size?, mode?, target? }], lastSync?, lastError?, massDeleteDigest? }` | Write-back gate ([ADR](../adr/20261104-write-back-gate.md)). `pending` are held changes, listed again after a restart and never auto-applied. `path` and `target` are tab-controlled: escape them for display. |
| `tab.writeback.sync` | `{ tabId }` | `{ applied, held: [{ path, kind, reasons }], refused: [{ path, reason }], mirrored }` | Syncs now (tabd also syncs every 3 s and before stopping). Error `-32013` if the tab isn't gated or the in-VM feed fails (nothing is applied then). |
| `tab.writeback.content` | `{ tabId, path }` | `{ path, kind, reasons, sig, host: { exists, kind, size, b64?, truncated }, tab: { kind, size?, b64?, truncated?, target?, mode? } }` | Both sides of a held change, for display only (each capped at 64 KiB). `sig` is the signature of exactly the tab bytes returned; if the tab's entry no longer matches what was held, this errors (`-32013`) and the change is listed again. Tab-controlled: render as plain text. The tab must be running. |
| `tab.writeback.decide` | `{ tabId, path, decision: approve\|reject\|always, sig }` | `{ result }` | `sig` is the signature the user was shown; tabd re-reads the tab's entry and refuses (`-32013`) if it changed. `approve` copies exactly that version; `reject` keeps the host's version and restores it into the tab when it is a file the host has; `always` also waives the path reason for this tab (never for git, hook, agent, IDE or host-executable paths). |
| `tab.writeback.confirmDeletes` | `{ tabId, digest }` | `{}` | Releases the sticky mass-deletion hold. `digest` is `massDeleteDigest` from the `tab.writeback.status` the user was shown (it names exactly which deletions are held); refused if the set changed. Deletions of code-running files stay held. |
| `stream.end` | `{ channel }` | — (notification) | Client half-close (client → REH EOF). |
| `stream.close` | `{ channel }` | — (notification) | Client abort; the supervisor kills the exec child. |
| `shutdown` | `{ stopTabs?: boolean }` | `{}` | Graceful: ends channels; leaves tabs running unless `stopTabs`. |
| `tab.events.subscribe` | `{ tabId?, sinceSeq?, minPriority?, classes? }` | `{ subscription, lastSeq, observation }` | Live events as `tab.event` notifications; all tabs when `tabId` is absent. `sinceSeq` (needs `tabId`) replays buffered events after it (at most 1000). At most 16 subscriptions. |
| `tab.events.unsubscribe` | `{ subscription }` | `{}` | |
| `tab.events.tail` | `{ tabId, limit? (1–1000, default 200), beforeSeq? }` | `{ events, observation }` | From the supervisor's in-memory ring (last 2000 per tab). Older events: the log (`seclab tab logs`). |
| `tab.events.report` | `{ tabId, events: [{ source, class, priority, summary, detail? }] }` (≤ 64) | `{ accepted, rejected }` | For trusted editor components only. Each source may report only its classes: `rpc-filter` → `rpc.decision`; `ahp-gate`, `ahp-reverse`, `ahp-credential` → `ahp.decision`; `agent-host` → `agent.session`, `agent.turn`, `agent.tool` (`gate` reserved). `integrity` is set by the supervisor from the source, never from the report: `trusted` for the RPC filter and the AHP gate components, `tab-reported` for `agent-host` (the agent host's own account, relayed; [ADR](../adr/20261105-agent-events-tab-reported.md)). Other sources or classes are rejected. Reports reach the Tab Manager over a `MainThreadSeclab*` service that sandboxed hosts can't call. |
| `tab.observe` | `{ tabId, mode: default\|deep }` | `{ mode, appliesOnRestart, observation }` | `deep` also traces file opens under sbx (about 45 µs per open). Takes effect when the collector next starts. |
| `tab.detections.query` | `{ minPriority? (default warning), tabIds? (≤ 64), limit? (1–500, default 200) }` | `{ events, tabs: [{ tabId, hostPath, phase }] }` | For the Tab Manager's cross-tab summary. Detections, plus trusted fence, lifecycle and "unobserved" events, across every tab in the state directory, running or stopped. They are read from the persisted per-tab logs (whichever supervisor wrote them; at most 16 MiB per tab) and this supervisor's unflushed ring. `phase` is `Running` for a tab leased by a live supervisor. Event text is tab-influenced: render it as data ([ADR](../adr/20261106-detection-notifications.md)). |
| `tab.egress.block` | `{ tabId, host, port? }` | `{ rule }` | The user blocked a destination for this tab (exact host name or IP address, optional port). tabd adds a broker deny rule (`policy.update addDeny`), which precedes every allow rule, the baseline and prompts. It persists the block with the tab and applies it again on every start. Fails with `-32013` unless the tab's broker reports `capabilities.denyRules` (`tab.get` → `status.brokerCapabilities`). Idempotent. |
| `tab.packages.get` | `{ tabId }` | `{ cfs }` | Whether the user turned on GitHub CFS package feeds for this tab (ADR cfs-package-feeds-in-tabs). Off by default. |
| `tab.packages.set` | `{ tabId, cfs: boolean }` | `{ cfs, applied }` | The user turned CFS package feeds on or off for this tab. tabd persists the setting and a host-chosen sentinel with the tab. On every broker start, and at once for a running tab (`applied`): tabd mints the token on the host (`az`, tenant checked, in memory only), imports it as `credential.import cfs` with GET-only bindings on the two feed paths, the `azure-devops` provider and a lifetime budget, and allows those paths. It answers `credential.needed` with a fresh token, and writes the tab's npm and pip config with the sentinel only. Off: the rules are removed, the credential revoked (sentinel rotated) and the config removed. Fails with `-32013` when no token source is available. Only the Tab Manager's per-tab command, behind a modal, sends it. |
| `tab.approval.list` | `{ tabId }` | `{ approvals: Approval[] }` | This tab's pending broker prompts (plan tabd-broker-wiring B3), for a client that (re)connects. `Approval` is `{ approvalId, kind: egress\|credential-binding, request: { scheme, host, port, method, path }, decisions, expiresAt, waiting, risk: { flags, origin, originVerified, userActionSeen }, credentialId? }`, sanitised and capped by tabd. Every string in it is tab-influenced: render as plain text. |
| `tab.approval.decide` | `{ tabId, approvalId, decision }` | `{}` | The user's answer. Only a decision that this tab's approval offered is relayed (`approval.decide`); anything else, another tab's approval, or an unknown one is `-32602`. One decision answers one approval of one tab: there is no "apply to all". |
| `tab.userAction` | `{ tabId }` | `{}` | The user did ordinary work in this tab (editor input, a command they chose). Never send it for consent interactions (Workspace Trust, task permission, the broker's own prompts). tabd relays it as the broker's `tab.event userAction`, at most once a second per tab; it opens the broker's user-action gate. tabd itself sends `tab.event opened` whenever it (re)connects to the tab's broker. |

Reserved (not in v0.1): `warmPool.*`, `tab.policy.*` (broker adapter).

## 4. Notifications (supervisor → client)
| Method | Params |
|---|---|
| `tab.status` | `{ tabId, phase, conditions }` |
| `stream.end` | `{ channel }`: REH → client EOF |
| `stream.close` | `{ channel, error? }`: the exec child exited or failed; channel ID retired |
| `audit` | `{ ts, tabId?, action, outcome, detail }`: every driver invocation and fence decision; also appended to the supervisor's audit log |
| `log` | `{ level, message }` |
| `tab.approval` | `{ tabId, approval: Approval, lineage }`: the tab's broker holds a request and asks the user (see `tab.approval.list`). `lineage` is the process attribution for the request (`confidence`, chain, `integrity`; never `trusted`): show it as quoted data, never use it to decide. Show which tab asks on every prompt; default to deny; never pre-select `allow-tab`. |
| `tab.approval.resolved` | `{ tabId, approvalId, decision, by }`: dismiss the prompt (answered, timed out, or matched a deny rule). |
| `tab.packages.problem` | `{ tabId, feed: "cfs", message }`: the tab's package feeds are on but unavailable, usually because `az` on the host isn't logged in. `message` is `az`'s, capped, and never contains the token. |
| `tab.event` | `{ subscription, event, replay?, lagged? }`: one [event](EVENTS.md). `lagged: n` means `n` matching events were not sent while the client wasn't reading (stdout backlog over 4 MiB); fetch them with `tab.events.tail`. Broker-backed tabs also carry the broker's audit events (source `broker`, `trusted`; tab-chosen text tagged `untrusted`), read by tabd from the control channel it owns ([EDR](../edr/20261105-broker-audit-in-tab-events.md)). |
| `tab.observation` | `{ tabId, state: observed\|degraded\|unobserved\|unavailable, since, reason, sensor?, mode?, untrusted: ["reason"] }`: `reason` can carry sensor-derived text; treat it as data |
| `tab.writeback.pending` | `{ tabId, count }`: the number of held write-back changes changed; the editor prompts for review |

## 5. Errors
JSON-RPC standard codes, plus: `-32001` not initialized, `-32002` invalid
path, `-32003` driver unavailable, `-32004` unknown tab, `-32010` fence
verification failed, `-32011` sandbox failed to start, `-32012` REH not
ready, `-32013` write-back not gated or failed, or (from `tab.ensureRunning`) broker
setup failed, `-32020` secrets found in the workspace, `-32021` secret scan incomplete.

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
- **Broker (the default for both drivers, `seclab-tabd --broker required`;**
  EDRs [OCI](../edr/20261105-oci-tab-broker.md), [sbx](../edr/20261105-sbx-tab-broker.md)).
  `tab.ensureRunning` brings the tab's broker up before the REH starts, and fails with
  `-32013` if any step fails or takes longer than 60 s:
  1. `broker.hello` is checked: protocol, tab, policy schema revision.
  2. A fresh proxy password.
  3. The policy: the user's `broker-policy.json` from the state directory, else deny-all.
     Never from the workspace.
  4. The CA.

  The tab gets the proxy URL and CA through a root-owned directory, `/run/seclab-broker`
  (OCI: a tmpfs; sbx: in the VM). The password is never in argv, audit records or
  notifications. Stop and quarantine send `broker.shutdown`.
  Under sbx the broker is a container on Docker Desktop, published on `127.0.0.1:<P>`; the
  fence's only allow is `localhost:<P>`, read live at every check, and the tab's proxy is
  `host.docker.internal:<P>`.
  The broker image is resolved once to its image ID, and its build labels are checked
  (base digest, protocol, policy revision, a clean revision unless `--broker-dev`); every
  broker is created by that ID, and `broker.hello` must report the labelled version
  ([EDR](../edr/20261105-broker-image-identity.md)).
