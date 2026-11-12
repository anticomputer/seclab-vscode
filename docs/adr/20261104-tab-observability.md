# Tab observability: a one-way, integrity-labelled event stream per tab

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** Project owner (2026-11-04): a Falco-style mode that gives the host a full event-log stream of everything happening in the sandbox; strace is accepted for now, with a request filed with Docker for a guest kernel with BTF and ftrace so the project can move to Falco later; OCI Falco runs only while container tabs are open, filters events to tab containers at the source, and keeps output local; coordinator (three integrity labels; honeypot file coverage by default with opt-in deep mode); tab-observability session; fork-build session (template, relay uid, collector lifecycle); RPC-lockdown session (filter decision shape and transport)
- **Related:** [EDR sensor spike](../edr/20261104-tab-observability-sensor-spike.md), [security review](../security-reviews/20261104-tab-observability.md), [ADR tab supervisor](20261104-tab-supervisor.md), [ADR threat model](20261104-threat-model-rogue-extension.md), [ADR no real secret in a tab](20261104-no-real-secret-in-a-tab.md), [ADR RPC capability filter](20261104-rpc-capability-filter.md), [Docker kernel request (draft)](../upstream-requests/docker-sbx-guest-kernel-tracing.md), [event reference](../tabd/EVENTS.md)
- **Editorial redaction (2026-11-12):** quotations of project conversations replaced with neutral statements; decisions unchanged.

## Context
Users should be able to watch what happens inside a tab. The motivating case is
a "Contagious Interview" `tasks.json` folder-open loader: a `nohup`-detached download piped into `node`,
a 5-second beacon, and reads of browser, wallet and keychain data. The
containment boundary stops the damage, but the user can't see the attempt.

The threat model makes the tab hostile, including root inside a tab VM after
a local privilege escalation. Anything produced inside the tab can therefore
be forged or suppressed. The spike found that eBPF sensors can't run in sbx
guests: there is no BTF, no ftrace and no modules.

## Decision

### 1. One stream, three integrity labels
Every event carries `integrity`, chosen by **where it was produced**, never
by what it says:

| `integrity` | Produced by | Can the tab forge or suppress it? |
|---|---|---|
| `trusted` | tabd and other host components: lifecycle, fence verification, the secret scan, broker audit, RPC-filter decisions, `sbx policy log`, host-side workspace watching, sensor-gap detection | No |
| `host-observed` | Falco on the Docker VM kernel, outside the OCI tab's namespaces | Only with a kernel escape. The content (argv, paths) is still chosen by the tab |
| `tab-vm-root` | The sbx collector, running as root inside the tab's own microVM | Yes, after an in-VM root escalation. Without root, the tab user can't kill, ptrace or blind it (spike) |

- Security decisions never rest on `host-observed` or `tab-vm-root` events
  alone. They can enrich a trusted decision, for example by adding lineage to
  a broker prompt, and are shown as such.
- A detection derived from several events takes the **weakest** label of its
  inputs.

### 2. Sensors per driver
- **sbx: `seclab-obs-collect`**. Root in the VM; strace 6.13 in
  `--seccomp-bpf` mode; inotify; python3 in isolated mode.
  - tabd starts it over `sbx exec -i -u root`, as its own child, **before**
    the REH. The REH is started **by the collector, under strace**, so every
    process the tab creates is traced from birth. Fail closed: no collector,
    no REH.
  - **Caveats from the spike, and how each is handled:**
    - *Untraced agent processes are an escape* (no Yama). The collector
      attaches to PID 1 and every existing agent pid. The REH runs under a
      seccomp guard (`seclab-obs-guard`) that refuses
      `clone(CLONE_UNTRACED)` and returns `ENOSYS` for `clone3`, so a tracee
      can't create an untraced child. The collector also rescans `/proc`
      every 250 ms, attaches any agent process whose `TracerPid` isn't one
      of its stracers, and reports it (`sensor.untraced`, high priority).
    - *The REH relay runs as its own uid* (`seclab-relay`), so the tab user
      can't ptrace it.
    - *Unprivileged BPF is disabled* (`kernel.unprivileged_bpf_disabled=1`,
      `kernel.kptr_restrict=2`) before the REH starts.
    - *PID 1 runs as the tab user*, so a `SIGTERM` to it stops the whole
      sandbox, collector included. tabd treats collector EOF, a heartbeat
      gap (no heartbeat for 6 s) or a sequence gap as a `trusted`
      `sensor.gap` event. It also marks the tab **unobserved** in the UI
      until a new collector reports in. A stopped sandbox is reported as
      stopped, never as quietly observed.
  - **File-open coverage:** by default, inotify on root-owned honeypot files
    seeded in the tab user's home (ssh, cloud CLI, browser profiles,
    wallets, keyrings). The kernel attributes no pid, so tabd correlates by
    time.
  - **Deep mode** is opt-in per tab (`tab.observe {mode: "deep"}`). It also
    traces `openat`/`openat2`, which costs about 45 µs per open (about 20×
    on open-heavy loads; see the EDR).
- **OCI: Falco 0.45 `modern_ebpf`**, one privileged container on the Docker
  host, pinned by digest.
  - It runs only while at least one OCI tab is running.
  - It is filtered **at the source** by a capture-only ruleset to
    containers labelled `seclab.tab`.
  - Its output goes only to tabd over its own stdout. No http, gRPC or file
    outputs, no plugins beyond `container`.
  - tabd maps container names to tab IDs from its own state, never from
    event content.
- **Trusted sources**, which need no in-tab sensor:
  - supervisor lifecycle and fence verification;
  - the secret scan;
  - broker `audit.event` notifications, consumed from the broker control
    channel tabd already owns (not duplicated);
  - RPC-filter decisions, reported by the Tab Manager through
    `tab.events.report` (§4);
  - `sbx policy log --json`, polled every 10 s and diffed by `count`;
  - a host-side watcher on the workspace directory, the same directory the
    tab writes through virtiofs or bind mounts.
- **Migration:** when sbx ships a guest kernel with BTF and ftrace (or
  kprobe/tracepoint BPF), sbx moves to Falco in the VM with the same
  capture-only ruleset. It keeps the `tab-vm-root` label, because the VM is
  still the tab. The collector protocol (§3) is the seam: Falco's JSON is
  wrapped in the same envelope.

### 3. Transport: one-way, bounded, schema-validated, no listener
- The collector's **stdout** is the event stream; its **stdin** carries only
  supervisor → collector configuration, one JSON line: mode and token. The
  Falco container is the same: stdout only.
- No socket, port or file is shared between a tab and tabd for observability.
- tabd treats every collector byte as hostile:
  - lines are capped at 64 KiB, and longer lines are discarded and counted;
  - each line is JSON with a fixed set of kinds, then a strict parser for
    strace text;
  - every string is escaped for display (C0/C1 controls, bidi overrides,
    zero-width characters) and capped;
  - argv is capped at 32 items of 256 characters, and lineage at 8.
- Nothing in an event becomes an argv element, a path tabd opens, a tab ID
  or a policy input.
- **Back-pressure:**
  - tabd always drains the pipe;
  - each tab has a token bucket (500 events/s sustained, 5 000 burst);
  - overflow is dropped and summarised as one `sensor.dropped` event per
    second, and the tab is marked `degraded`;
  - the in-memory ring holds the last 2 000 events per tab;
  - disk: 4 × 8 MiB JSONL segments per tab, oldest dropped.

  A noisy tab costs at most that much host memory and disk.

### 4. Consumers
- **Log:** `<state>/events/<tabId>/events-<n>.jsonl`, append-only, rotated,
  written only by the supervisor holding the tab's lease. The schema is
  `tabd/schema/event.v1.json`, generated from `tabd/src/obs/schema.ts`, with
  the reference in [EVENTS.md](../tabd/EVENTS.md). Field names follow
  Falco's JSON output (`time`, `priority`, `rule`, `output`→`summary`,
  `source`). Each class maps to an OCSF `class_uid` for export.
- **Protocol** (`seclab-tabd/0.2`, additive):
  - `tab.events.subscribe`, `tab.events.unsubscribe` and `tab.events.tail`;
  - the notifications `tab.event` and `tab.observation`;
  - `tab.observe`, which sets the mode;
  - `tab.events.report`, used by the trusted client to report RPC-filter
    decisions. RPC-lockdown delivers those to the Tab Manager over a
    `MainThreadSeclab*` service, which the per-host filter makes
    unreachable from sandboxed hosts by default-deny, so a tab can't forge
    them.
- **CLI:** `seclab tab logs [-f] [--format falco] <tabId|all>`. It reads the
  JSONL from the state directory read-only, so it adds no supervisor
  listener. `--format falco` emits Falco-compatible JSON lines for a host SIEM
  forwarder: the file-sink exporter. OTLP is deferred.
- **Editor:** a "Tab activity" **tree view** in the Tab Manager, never a
  webview, so hostile strings are rendered as plain text by construction. It
  shows the live stream for the window's own tab, integrity badges, priority
  and class filters, and an "unobserved" banner and status-bar warning.

### 5. Detection in tabd, not in Falco rules
The threat-model rules run **in tabd over normalised events**, for both
sensors:
- folder-open or extension-host task spawning network tools or
  `node -e`/stdin;
- `nohup`/`setsid` detach;
- download piped to an interpreter;
- credential-path or honeypot reads;
- host-executable workspace writes, including `package.json` script changes;
- connects that bypass the broker;
- eval/require loaders;
- privilege, namespace or BPF syscalls;
- periodic beacons;
- sensor tampering.

Falco is capture-only. One ruleset therefore covers sbx (no Falco), OCI and
the future sbx-Falco, and rules can join `trusted` broker and lifecycle
events with sensor events. Broker prompts get **lineage hints**: the exec
lineage of the `net.connect` to the broker port closest in time, labelled
with that event's integrity and marked `ambiguous` when more than one
candidate matches.

### 6. Privacy and secrets
- No real secret can be in an event, because none exists in the tab, and
  broker audit events are already scrubbed.
- Defence in depth: argv, paths and summaries are redacted against a pattern
  list (provider token prefixes, JWTs, long hex and base64 runs, URL
  userinfo, `--password=`-style flags, `Authorization:` values).
- Broker sentinels (`SECLAB_SNTL_…`) are replaced by `[sentinel]`.

## Alternatives considered
- **Falco, Tetragon or Tracee in the sbx VM:** impossible on the current
  guest kernel ([EDR](../edr/20261104-tab-observability-sensor-spike.md)).
  This is the target once Docker ships the kernel features.
- **Two labels (`trusted`/`tab-reported`):** hides the real difference
  between a host-kernel sensor and an in-VM one.
- **A sensor socket or file shared with the tab:** a new channel into the
  trusted side. Rejected.
- **Threat rules as a Falco ruleset:** they wouldn't run under sbx, and
  couldn't join broker and lifecycle events. Kept capture-only instead.
- **A webview activity panel:** renders hostile HTML-adjacent content.
  Rejected in favour of a tree view.
- **Tracing `openat` by default:** about 20× slower on open-heavy loads.
  Opt-in only.
- **A CLI that attaches to the running supervisor:** needs a listener.
  Reading the log is enough.

## Consequences
- The sbx template gains strace, the guard, the collector and a
  `seclab-relay` user, and the REH socket moves to a group-shared directory.
  Template and CI changes need a security review and digest or checksum pins.
- `Driver.ensureRunning` may return a sensor stream; drivers without one
  report `observation: unavailable`, and the UI says so.
- Exec-heavy workloads in sbx tabs pay about 2 ms per exec; deep mode pays
  per open.
- OCI tabs run a privileged Falco on the user's Docker host while they are
  open. It sees every container but forwards only tab containers.
- Integrity is only as strong as the producer: `tab-vm-root` events are
  evidence, not proof.

## Evidence
- Spike results and commands:
  [EDR](../edr/20261104-tab-observability-sensor-spike.md).
- strace `CLONE_UNTRACED`: `kernel_clone` skips ptrace auto-attach when the
  flag is set
  ([fork.c, v6.12](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/kernel/fork.c#L2768-L2784)).
- Broker audit stream and types: [broker protocol §4](../broker-protocol.md).
- RPC-filter verdicts: `docs/RPC-LOCKDOWN.md` §3 on branch
  `anticomputer-rpc-channel-lockdown`.
