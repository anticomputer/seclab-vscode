# Introduce a tab supervisor (`seclab-tabd`) with a versioned stdio protocol between the editor and sandbox runtimes

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** Project owner (2026-11-04): the abstraction must ultimately be able to serve other sandboxes as well, which suggests a glue API in the middle; seclab-vscode coordinator; fork-build session
- **Supersedes:** [Tab runtime is a pluggable SandboxProvider](20261104-pluggable-sandbox-provider.md) (the provider interface moves out of the editor into the supervisor's driver contract; sbx primary and OCI second still hold)
- **Security review:** [20261104-tabd-protocol-design](../security-reviews/20261104-tabd-protocol-design.md)
- **Editorial redaction (2026-11-12):** quotations of project conversations replaced with neutral statements; decisions unchanged.

## Context
The first design put a `SandboxProvider` interface **inside** the editor's Tab
Manager extension. That couples tab lifecycle, fencing, broker wiring and
runtime argument handling to VS Code. Other clients would need the same
logic: our test harness, a CLI, other editors and agents, and later a remote or
cloud control plane. The project owner requires a glue API in the middle.

## Decision
A standalone **tab supervisor**, `seclab-tabd`, sits between clients and
sandbox runtimes.

- **Process model:** the client spawns `seclab-tabd` as a **child process** and
  speaks the protocol over the child's **stdio**. There is no listener, no
  daemon, no host port and no new privileged surface (unlike the rejected host
  bridge). The supervisor runs with the client's privileges and dies with it.
- **Protocol:** versioned, framed JSON-RPC 2.0 over stdio. Channel 0 carries
  JSON-RPC; numbered channels carry raw byte streams (the REH connections).
  Spec: [`docs/tabd/PROTOCOL.md`](../tabd/PROTOCOL.md). The same protocol can
  later run over an authenticated transport to reach a remote supervisor.
- **The supervisor owns:**
  - tab identity: it mints the opaque per-tab ID that the RPC filter and broker
    key on;
  - the runtime drivers;
  - broker lifecycle;
  - the sbx fence (mirror plus verify);
  - policy translation;
  - the warm pool;
  - the REH byte streams;
  - the audit log.
- **The Tab Manager shrinks** to the `seclab` resolver, folder routing and UI
  prompts. It only talks to the supervisor.
- **Drivers** implement a narrow contract (create, start, stop, remove, exec,
  fence) and publish **capability descriptors**: isolation class, live
  mounts, network fence type, hold-and-resume, file-watch fidelity, and
  same-path mounts. Clients degrade explicitly based on them. Drivers: `sbx`
  (primary), `oci` (second). Later: Apple `container`, Kubernetes, and remote.
- **Resource model** borrows the vocabulary of kubernetes-sigs/agent-sandbox
  (`Sandbox`, `SandboxTemplate`, `SandboxWarmPool`, `SandboxClaim`) so a future
  Kubernetes driver maps nearly 1:1. We don't adopt the CRDs or the controller
  locally. Mapping:

  | tabd | agent-sandbox | Notes |
  |---|---|---|
  | `Tab` | `Sandbox` | One per workspace window; `status.conditions` like `Ready` |
  | `TabTemplate` | `SandboxTemplate` | Image, resources, fence and broker settings, env-injection policy (`Disallowed` default) |
  | `WarmPool` | `SandboxWarmPool` | `replicas`, `templateRef` |
  | `tab.claim` | `SandboxClaim` | Binds a workspace path to a tab (from the pool if possible) |

- **Tab identity is not spoofable from a tab.** IDs are random 128-bit values
  minted by the supervisor and never derived from tab-controlled input. A tab
  has no channel to the supervisor: it only sees REH bytes. Only `tab.claim`
  accepts a host path, and only a client calls it (user-initiated routing).
  An authority with an unknown tab ID is refused, so a crafted
  `vscode-remote://seclab+…` URI can't mint a tab or choose a mount.

## Alternatives considered
- **Provider interface inside the extension (previous ADR)**: rejected. It is
  not reusable outside VS Code, and the security-critical argument handling
  sits in the editor process.
- **Long-running daemon with a socket**: rejected. It is a new listener and
  privileged surface (the same objection as the bridge), and needs its own
  auth. A remote supervisor can come later over an authenticated transport.
- **Adopt agent-sandbox CRDs and controller locally (kind or k3d)**:
  rejected. It is heavy, requires a cluster on the laptop, and the CRDs
  have no workspace host-mount or exec stdio concepts.
- **Base64 REH bytes inside JSON-RPC**: rejected in favour of binary channel
  frames (no 33% overhead, no JSON parse of bulk data).

## Consequences
- One security-critical component (`seclab-tabd`) holds every `sbx` and
  `docker` invocation. It is small, has no dependencies, uses argv-only spawns
  and strict validators, and every change is security-reviewed.
- The REH channels multiplex over one stdio pair, so one slow channel can
  stall others. v0 accepts this and relies on pipe backpressure; credit-based
  flow control is a protocol follow-up.
- The tab ID → workspace mapping must persist (recents) in the supervisor's
  state directory.
- Implementation language: see [EDR](../edr/20261104-tabd-implementation-language.md).

## Evidence
- agent-sandbox API reference, pinned: https://github.com/kubernetes-sigs/agent-sandbox/blob/bcf5d4a0fed06fe1c2ca6f2373631b6db81f13c6/docs/api.md (Sandbox L134-L154, SandboxTemplate L442-L500, SandboxWarmPool L501-L575, SandboxClaim L366-L423)
- Crafted remote-authority URIs are a known vector: GHSA-5j3g-c7qg-xfvx (`.code-workspace` with an attacker remote authority), see [`workspace-exec-vectors.md`](../research/workspace-exec-vectors.md) §6
- [EDR: REH transport](../edr/20261104-reh-transport-exec-stdio.md), [EDR: sbx fence](../edr/20261104-sbx-fence-spike.md)
