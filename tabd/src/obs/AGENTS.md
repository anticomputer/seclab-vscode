# AGENTS.md: tab observability (`tabd/src/obs/`)

Instructions for an agent picking up the observability layer cold. Root rules (`AGENTS.md`
at the repo root) all apply. Every command here has been run. Design:
`docs/adr/20261104-tab-observability.md`; spike:
`docs/edr/20261104-tab-observability-sensor-spike.md`; event reference (generated):
`docs/tabd/EVENTS.md`. (Paths, not links: this directory is also reachable through the
`extensions/seclab-tab-manager/tabd-src` symlink, where relative links break.)

## What it is, and its trust boundary
- **What:** one ordered event stream per tab. Every event carries `integrity`,
  fixed by its **source**, never by its content:
  - `trusted`: produced by tabd, the broker, the RPC filter, the AHP gate
    components, `sbx policy log` or the host workspace watcher;
  - `host-observed`: OCI Falco, outside the tab;
  - `tab-vm-root`: the sbx collector inside the tab VM;
  - `tab-reported`: the tab's agent host describing itself, relayed by the
    renderer (context only; ADR `docs/adr/20261105-agent-events-tab-reported.md`).
- **Hostile input:** everything a sensor says is tab-derived. It is
  bounded, strictly parsed, escaped, redacted and rate-limited, and never
  becomes argv, a path, a tab id or policy. The one-way rule: the collector's
  stdin carries only the config line and `ensure-reh`; its stdout is the
  only tab → host channel.
- **Fail closed:** under sbx the REH starts *only* under the collector (strace
  plus `seclab-obs-guard`). Under OCI, Falco must be capturing with the tab's
  ruleset before the REH starts.

## Layout
| Path | What |
|---|---|
| `schema.ts` | Single source: sources, integrity, classes (OCSF ids), limits, `normalizeDraft`, `toFalco`. Generates `tabd/schema/event.v1.json` and `docs/tabd/EVENTS.md` |
| `text.ts` | `safeText` (controls, bidi, zero-width, surrogates) and redaction (provider tokens, JWT, hex/base64, URL userinfo, sentinels → `[sentinel]`) |
| `strace.ts` | Strict, bounded strace parser; process tracker (lineage, exec deferral until the parent's clone line) |
| `sbx-collector.ts` | tabd side of `sandbox/rootfs/opt/seclab/bin/seclab-obs-collect`: line caps, seq contiguity, heartbeats, REH gate |
| `falco.ts` | OCI host sensor: capture-only rules for exact container ids, SIGHUP reload, ready = rules sha in a metrics snapshot |
| `hub.ts` | Per-tab seq, rate buckets (sensor / tab-driven / client, plus one per broker audit type; `tabd` never limited), JSONL segments, observation state |
| `detect.ts` | Detection rules (one ruleset for all sensors); detections take the weakest integrity |
| `workspace-watch.ts` | Trusted host watcher (lstat only; `package.json` scripts diff only inside the root) |
| `broker-audit.ts` | Broker `audit.event` → trusted events: allowlisted types and fields (tab text into tagged fields), `audit.tail` replay on connect, seq dedupe and gap events, 10 s aggregation of allowed requests and injections |
| `lineage.ts` | Broker request ↔ sensor connect join by time (`egress.attribution`: single / ambiguous / none, weakest integrity, a used connect not reused); `promptLineage` for prompts |
| `glue.ts` | Protocol methods (`tab.events.*`, `tab.observe`), sensor hooks for drivers, policy-log poller |
| `../../tools/gen-obs-docs.ts`, `../../tools/tab-logs.ts` | Doc generator; `seclab tab logs` |
| `sandbox/sbx/seclab-obs-guard.c` | seccomp guard: no `CLONE_UNTRACED`, `clone3`, seccomp listeners or io_uring; closes fds > 2 |
| `test/observability/` | e2e (`run.ts`), `loader.ts` (assembles the inert loader from `fixtures/loader-workspace/.seclab/loader.parts.json` and writes it inside the tab only), `guard-check.py` |

## Commands (all run)
```sh
./seclab test unit                 # includes tabd/test/obs.test.ts (node container)
./seclab docs write                # regenerates EVENTS.md + event.v1.json (then the record indexes)
./seclab docs check                # fails if EVENTS.md/event.v1.json drifted from schema.ts
./seclab template sbx              # template with strace (pinned deb), guard, collector, relay uid 990:990
./seclab image oci
./seclab test obs sbx              # loader -> detections + labels; guard regressions; kill collector -> refused; kill PID 1 -> unobserved
./seclab test obs oci              # same through Falco; killing Falco -> unobserved
./seclab tab logs --state-dir "$PWD/.work/observability/sbx/state" --format falco all
./seclab lint fixtures test/observability
node test/observability/demo.ts prepare ~/.seclab-test/obs sbx   # README screenshot run; prints the background launch
node test/observability/demo.ts teardown ~/.seclab-test/obs      # teardown gate: editor tree, tab, profile, host diff
```
Demo windows must never come to the front over the user's work. Launch with `open -g`,
never activate the app, and capture by window id. See "Demo screenshots" in
`test/README.md`.

## Gotchas (learned the hard way)
- **sbx guest kernel:** no BTF, no ftrace, no modules, no Yama. Falco,
  Tetragon, Tracee and auditd can't run there. strace `--seccomp-bpf` as VM
  root works.
- **`strace --seccomp-bpf -u USER` fails** (`exec: Function not implemented`).
  Drop privileges with `setpriv` *under* strace instead.
- **`--seccomp-bpf` doesn't apply to `-p` attaches.** Attached processes stop
  on every syscall, so start the REH under strace and don't attach to it.
- **`sbx exec -u <uid>` alone takes the passwd gid; gid 999 is `docker` in the
  kit.** Always pass `uid:gid` (the relay uses `990:990`).
- **A child's lines can come before the parent's `clone() = pid` line** in
  strace output. The tracker defers exec events up to about 150 ms for
  lineage.
- **Falco's "Opening 'syscall' source" log line comes before capture starts.**
  Ready means a metrics snapshot whose `falco.sha256_rules_file.rules_yaml`
  equals the rules we wrote.
- **Falco 0.45 dropped enter events.** `evt.dir` in conditions is deprecated
  and always `<`. Failed connects carry the address only in `evt.args`
  (`addr=`).
- **runc's exec setup runs in the container with exepath `/usr/bin/runc`.** It
  is excluded at the source; a read-only, non-root tab can't create that
  path.
- **fanotify:** `EOPNOTSUPP` on the overlay root and `ENODEV` on the virtiofs
  workspace. Honeypots use inotify.
- **Never write loader-shaped text to a file** (a download piped into an
  interpreter, a folder-open task with a fetch tool). Endpoint AV quarantines
  it on the host. Assemble such strings in memory (EDR fixture-safety
  addendum).
- **Externally exec'd processes (`sbx exec -u agent`, the harness) start
  untraced and unguarded.** The collector attaches within 250 ms and reports
  them as `untraced`. In production only the collector (root) and the relay
  (990) are exec'd.
