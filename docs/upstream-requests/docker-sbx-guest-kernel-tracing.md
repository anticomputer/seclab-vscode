# Draft: request to Docker for sbx guest kernel tracing support

Status: **draft, not sent.** The user decides where it goes (Docker Sandboxes
feedback, a GitHub issue, or a support contact). Context: [ADR tab
observability](../adr/20261104-tab-observability.md), [spike
EDR](../edr/20261104-tab-observability-sensor-spike.md).

---

**Title:** Docker Sandboxes: enable BTF and tracing in the local microVM guest kernel so runtime security sensors (Falco, Tetragon, Tracee) can run inside a sandbox

Hi Docker Sandboxes team,

We use `sbx` to run one microVM per editor workspace, and we'd like to watch
what code inside each sandbox does at runtime: process execs, connects,
sensitive file reads. The standard tools for that are Falco, Tetragon and
Tracee, but none of them can start in an sbx guest today, because the guest
kernel is built without the features they need.

What we see on sbx v0.51.0 (macOS, arm64), guest kernel `7.0.14 #1 SMP PREEMPT Wed Oct 28 08:37:59 UTC 2026`:

- `CONFIG_DEBUG_INFO_NONE=y`, so there's no `/sys/kernel/btf/vmlinux` and no CO-RE.
- `CONFIG_FTRACE`, `CONFIG_BPF_EVENTS`, `CONFIG_KPROBE_EVENTS` and `CONFIG_FTRACE_SYSCALLS` are off.
- `bpftool feature probe kernel` reports these program types as unavailable: `kprobe`, `tracepoint`, `raw_tracepoint`, `tracing`, `lsm`, `perf_event`.
- `CONFIG_MODULES` is off, so a kernel-module driver isn't an option either.
- Falco 0.45.2 `modern_ebpf` fails with `libpman: prog 'BPF_TRACE_RAW_TP' is not supported`, and Tracee fails reading `/proc/sys/kernel/ftrace_enabled`.
- Linux audit isn't usable from inside the sandbox: `auditctl` gets `EPERM`, since the sandbox runs in a non-init pid namespace.

What would unblock us, in order of preference:

1. `CONFIG_DEBUG_INFO_BTF=y` plus `CONFIG_BPF_EVENTS=y` and `CONFIG_FTRACE=y` with syscall tracepoints (`CONFIG_FTRACE_SYSCALLS=y`). That is enough for Falco's `modern_ebpf` probe, Tetragon and Tracee.
2. If full ftrace is a concern, BTF plus raw tracepoint support (`BPF_PROG_TYPE_RAW_TRACEPOINT` / `BPF_PROG_TYPE_TRACING` on `sys_enter`/`sys_exit` and `sched_process_*`) covers Falco.
3. Optionally `CONFIG_BPF_LSM=y` with `bpf` in the LSM list. It's already in `CONFIG_LSM`, so only the BPF LSM hook support is missing.
4. `CONFIG_SECURITY_YAMA=y` would also help: today any sandbox process can ptrace any other process of the same user.

These would only be usable by root inside the sandbox VM, which is already its own isolation boundary, and they don't change what the sandbox can reach on the host. They'd let sandbox users run off-the-shelf runtime security tooling inside each sandbox instead of a strace-based workaround, which costs roughly 2 ms per exec.

Happy to test a preview kernel and share results.

Thanks!
