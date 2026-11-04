# Tab runtime is a pluggable SandboxProvider; sbx primary, OCI second

- **Status:** superseded-by [20261104-tab-supervisor](20261104-tab-supervisor.md). The provider interface moved out of the editor into the supervisor's driver contract; "sbx primary, OCI second" still holds.
- **Date:** 2026-11-04
- **Deciders:** anticomputer (user decision: "let's build the PoC with docker sbx but keep the design pluggable/swappable as intended"); seclab-vscode coordinator

## Context
The tab boundary needs a real isolation runtime. The runtime survey compared
Docker Sandboxes (sbx), Apple `container`, Lima/Colima, devcontainers plus
gVisor, Kata, Firecracker/Cloud Hypervisor, Podman machine, WSL2, bubblewrap,
Seatbelt-based tools, LiteBox, gh-aw-firewall, E2B and microsandbox. The
host is macOS 26 on Apple silicon with Docker Desktop and sbx installed.

## Decision
- The Tab Manager talks to a runtime-neutral `SandboxProvider` interface:
  `create`, `exec` (returns a byte duplex), `stop`, `remove`, plus thin
  `allowNetwork` and credential hooks that delegate to the broker adapter.
- **`SbxProvider` (Docker Sandboxes) is the primary provider for the PoC.**
  Each tab gets one microVM. sbx mounts the host workspace at the same
  absolute path, has its own egress proxy (used here only as a fence, see the
  [broker ADR](20261104-single-broker-sbx-fence.md)), and its `exec -i` gives
  docker-exec semantics.
- **`OciProvider` (Docker or Podman CLI) is the second implementation**, for
  Linux, CI (hosted runners have no nested virtualisation) and the containment
  suite. Each tab is a pod: a workspace container plus a broker sidecar on an
  `--internal` network, non-root, `--cap-drop ALL`, no docker.sock, only the
  workspace mounted.

## Alternatives considered
- **Apple `container`**: the strongest first-party VM-per-container option,
  but macOS 26 only, with no egress policy or credential layer. Kept as a
  future provider.
- **OCI only**: a namespace boundary on a shared kernel (on macOS, the shared
  Docker Desktop VM), weaker than VM-per-tab.
- **Kata**: dense recent guest-to-host escape history; Linux-only.
- **Seatbelt, bubblewrap or srt as the boundary**: process-level, explicitly
  not VM or container equivalent.

## Consequences
- sbx is closed-source and heavier per tab (one microVM with an inner Docker
  engine). Cost at 10–20 tabs needs benchmarking.
- Inside an sbx tab the default `agent` user has sudo and an inner docker.sock.
  The VM is the boundary, and our template can drop both (follow-up EDR).
- sbx's global policy layer is shared with the user's other sandboxes (see
  [fence EDR](../edr/20261104-sbx-fence-spike.md)).

## Evidence
- [`docs/research/sandbox-runtimes.md`](../research/sandbox-runtimes.md) (comparison table and recommendation)
- [EDR 20261104-sbx-upgrade-0-51](../edr/20261104-sbx-upgrade-0-51.md), [EDR 20261104-sbx-fence-spike](../edr/20261104-sbx-fence-spike.md)
