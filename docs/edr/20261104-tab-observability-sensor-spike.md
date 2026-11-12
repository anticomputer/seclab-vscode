# Tab observability: which runtime sensor can run where (spike)

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** tab-observability session (spike); coordinator; project owner (decisions recorded in [ADR tab observability](../adr/20261104-tab-observability.md))
- **Related:** [ADR tab observability](../adr/20261104-tab-observability.md), [ADR tab supervisor](../adr/20261104-tab-supervisor.md), [ADR threat model](../adr/20261104-threat-model-rogue-extension.md), [EDR sbx fence spike](20261104-sbx-fence-spike.md), [EDR sbx 0.51](20261104-sbx-upgrade-0-51.md)
- **Editorial redaction (2026-11-12):** quotations of project conversations replaced with neutral statements; decisions unchanged.

## Context
The project owner requires a Falco-style mode that gives the host a full event-log
stream of everything happening in the sandbox. The brief was to reuse an
off-the-shelf sensor (Falco, Tetragon or Tracee) inside each tab, and to find
out first whether the sbx guest kernel supports it, whether the tab user can
blind it, and whether the OCI driver can host the sensor outside the tab.

## Decision
Spike outcomes, and the sensor each driver should use:

| | sbx (microVM per tab) | OCI (container per tab) |
|---|---|---|
| Kernel | 7.0.14 guest, `CONFIG_DEBUG_INFO_NONE`, no BTF, `CONFIG_FTRACE`/`BPF_EVENTS`/`KPROBE_EVENTS` off, `CONFIG_MODULES` off | Docker Desktop 7.0.12-linuxkit with `/sys/kernel/btf/vmlinux` (CI Linux hosts likewise) |
| Falco / Tetragon / Tracee | **Cannot run.** No kprobe, tracepoint, raw_tracepoint, tracing, lsm or perf_event BPF program types; no kernel module | **Falco modern_ebpf works**, running outside the tab container |
| Linux audit | `auditctl` gets `EPERM`: the sandbox is a container in the VM's init user namespace but a non-init pid namespace, and audit control is init-pid-ns only | not needed |
| fanotify | `EOPNOTSUPP` on the overlay root, `ENODEV` on the virtiofs workspace | not needed |
| Sensor chosen | **strace 6.13 in `--seccomp-bpf` mode, as VM root**, started by the supervisor through `sbx exec -i -u root` | **Falco 0.45.2 modern_ebpf**, one privileged container on the Docker host, filtered to tab containers |

Integrity this gives, against the threat model (the tab user `agent` fully
controls its REH):

- **sbx:** the in-tab user cannot kill, ptrace or read the root collector
  (`EPERM`), has no sudo (locked password), no docker group and no
  capabilities, and cannot undo the sysctls the collector sets. Three caveats:
  1. **Untraced agent processes are an escape.** There is no Yama, so `agent`
     can ptrace-attach to any agent-owned process that root has not already
     traced, and run code from it unobserved. Once root traces a process,
     `agent` gets `EPERM`. The collector must therefore trace PID 1 and every
     agent process, start the REH itself, and the REH connect relay must run
     under a different uid.
  2. **PID 1 of the sbx shell kit runs as `agent`.** A `SIGTERM` to PID 1 stops
     the whole sandbox, killing the collector (exec exit 137) together with
     the REH. Blinding the sensor this way kills the tab, which the
     supervisor sees as stream EOF plus the sandbox state.
  3. **Root in the VM defeats it.** Only an in-VM privilege escalation lets the
     tab tamper with the collector. The collector sets
     `kernel.unprivileged_bpf_disabled=1` and `kernel.kptr_restrict=2` to
     shrink that surface.

  The events are produced by VM root, outside the tab user's control, but
  their content (argv, paths) is tab-controlled.
- **OCI:** Falco runs in the Docker VM's init namespaces. The unprivileged tab
  container cannot see or signal it, so only a kernel escape could suppress
  events. The content is still tab-controlled.

Measured cost of the strace collector in the sbx VM (per run, ms):

| Workload | plain | traced incl. `openat` |
|---|---|---|
| `find … \| xargs cat`, 4000 JS files | 18 | 139 |
| node: 20 000 `open`+`close` | 44 | 965 |
| node: 200 `execFileSync('/usr/bin/true')` | 101 | 519 |

Tracing exec, connect, unlink, rename, setuid and ptrace costs about 2 ms per
exec, which is acceptable. Tracing `openat` costs about 45 µs per open, too
much for the REH's file-heavy workload, so file opens need a narrower
mechanism (see Consequences).

## Alternatives considered
- **Falco / Tetragon / Tracee inside the sbx VM:** impossible on this guest
  kernel. We don't control the sbx kernel; an upstream request to Docker for
  BTF + ftrace in the sandbox kernel would unblock it.
- **Linux audit (auditd, go-audit) in the VM:** blocked by the pid namespace
  (`EPERM` on status, add-rule and list).
- **fatrace / fanotify:** unsupported on overlay and virtiofs here.
- **Taskstats / proc connector:** the proc connector is not built
  (`CONFIG_CONNECTOR` off); taskstats listener registration is init-pid-ns only.
- **A custom collector on `cgroup_sock_addr` BPF** (available in the guest):
  it would give per-connect pid and uid. This means writing a sensor, so it is
  deferred. strace's `connect` tracing plus the trusted `sbx policy log`
  already cover connects.
- **Polling `/proc`:** misses short-lived processes, such as the two halves of a download piped into an interpreter.

## Consequences
- The **trusted** sources need no in-tab sensor:
  - supervisor lifecycle and fence events;
  - broker audit;
  - the RPC filter;
  - the secret scan;
  - `sbx policy log --json`: aggregated per host with allowed/blocked, rule,
    `count`, first and last seen, no pid. It has no follow mode, so poll and
    diff by `count`;
  - host-side file watching on the workspace, since under sbx the workspace is
    a virtiofs share of a host directory.
- The OCI Falco container is privileged and sees every container on the user's
  Docker host. It must filter at the source to tab containers, and should map
  container ids from tabd rather than mount `docker.sock`. It is a new trusted
  component and needs a security review.
- The sbx template must ship strace (the sbx global policy blocks
  `deb.debian.org`, so the debs are copied in, as the REH is).
- The supervisor must start the collector **before** the REH and refuse to
  start the REH without it (fail closed). It must also detect agent processes
  whose `TracerPid` is not the collector and report them as "unobserved".
- strace's text output is hostile input (strace escapes quotes and newlines in
  strings); it needs a strict, bounded parser.
- **Open project owner decisions** (to record in the follow-up ADR):
  1. Integrity labels: two (`trusted`, `tab-reported`), or three
     (`trusted`, `host-observed` for OCI Falco, `tab-vm-root` for sbx strace).
  2. Accept the strace collector and its exec overhead under sbx, or wait for
     an sbx kernel with BTF/ftrace.
  3. How to cover file opens under sbx: honeypot paths watched with inotify
     (no pid), versus tracing `openat` (about 20× slower on open-heavy loads).
  4. Running a privileged Falco on the user's shared Docker Desktop VM for OCI
     tabs.

## Evidence
sbx v0.51.0 on macOS; spike sandbox `seclab-obs-spike` from template
`seclab-tab:local` (built by `sandbox/sbx/build-template.sh`, which removes
`agent` from `sudo` and `docker`). The workspace was `.work/obs-spike/ws`; it
was torn down afterwards, leaving no sandbox, policy rule or container.
```
sbx create --name seclab-obs-spike --no-progress --pull never -t seclab-tab:local -- shell "$PWD/ws"
sbx exec -u root seclab-obs-spike sh -c 'zcat /proc/config.gz | grep -E "BTF|FTRACE|BPF_EVENTS|MODULES"'
  # CONFIG_DEBUG_INFO_NONE=y, # CONFIG_FTRACE is not set, # CONFIG_MODULES is not set
sbx exec -u root seclab-obs-spike bpftool feature probe kernel   # bpftool v7.5.0, debs copied in
  # eBPF program_type kprobe|tracepoint|raw_tracepoint|tracing|lsm|perf_event is NOT available
  # eBPF program_type socket_filter|cgroup_sock_addr is available
docker run --rm --privileged -v /sys/kernel:/sys/kernel:ro falcosecurity/falco:latest falco -o engine.kind=modern_ebpf  # inside the VM
  # Falco version: 0.45.2 … libpman: prog 'BPF_TRACE_RAW_TP' is not supported … Error: Initialization issues during scap_init
falco -o engine.kind=kmod   # error opening device /host/dev/falco0
aquasec/tracee:latest       # could not read from ftrace_enabled file: … no such file or directory
auditctl -s; auditctl -a always,exit -F arch=b64 -S execve   # Operation not permitted
fatrace -t                  # Failed to add watch for /: Operation not supported
cat /proc/self/uid_map      # 0 0 4294967295 (init user ns); pid/mnt/net namespaces are not init
sbx exec -u agent seclab-obs-spike sh -c 'id; sudo -n true; docker ps'
  # uid=1000(agent) groups=1000(agent); sudo: a password is required; permission denied … docker.sock
# root collector via `sbx exec -i -u root`; as agent: kill -9 <collector> -> Operation not permitted;
# /proc/<collector>/environ unreadable; kill -TERM 1 -> sandbox stopped, collector exec exited 137
# as agent: strace -p 2 (untraced agent sleep) -> attached; after root `strace -p 1 -p 2`: PTRACE_SEIZE EPERM
strace -f --seccomp-bpf -qq -ttt -s 200 -e signal=none \
  -e trace=execve,execveat,connect,openat,unlinkat,renameat2,setuid,setresuid,ptrace,kill \
  -- setpriv --reuid=agent --regid=agent --init-groups --reset-env sh -c '<inert chain>'
  # captured: nohup sh -c "<fetch from http://192.0.2.10/payload, piped into node -e 1>", execve curl/node with argv and pids,
  # (the pipeline is paraphrased: loader-shaped text on the host trips endpoint AV; EDR fixture-safety)
  # openat ~/.ssh/id_canary, openat dropped.sh O_CREAT, unlinkat dropped.sh,
  # connect(… 192.0.2.10:80) = -1 EINPROGRESS
  # note: `strace --seccomp-bpf -u agent` fails (exec: Function not implemented); drop privileges with setpriv instead
echo 1 > /proc/sys/kernel/unprivileged_bpf_disabled   # root: ok; agent cannot write it back
docker run --rm --privileged --pid=host alpine ls -la /sys/kernel/btf/vmlinux   # Docker Desktop 7.0.12-linuxkit: present
docker run -d --privileged -v /var/run/docker.sock:/host/var/run/docker.sock -v /proc:/host/proc:ro \
  -v /sys/kernel:/sys/kernel:ro falcosecurity/falco:latest falco -o engine.kind=modern_ebpf -o json_output=true …
  # "Opening 'syscall' source with modern BPF probe"; for a --user 1000 --network none tab container:
  # exec lineage with full cmdline, canary-read cat /tmp/h/.ssh/id_canary, ws-write dropped.sh, exec curl … user=1000
```
