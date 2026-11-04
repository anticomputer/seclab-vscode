# Threat model: the primary attacker is a rogue extension the user installs

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** anticomputer (user: "our threat model is that of someone installing a rogue extension"); seclab-vscode coordinator
- **Supersedes:** the threat-model portion of [the containment-unit ADR](20261104-tab-is-the-containment-unit.md) (attacker list) and of ARCHITECTURE.md §2 as of 296594c
- **Related:** [no real secret ADR](20261104-no-real-secret-in-a-tab.md)

## Context
The earlier model listed malicious extensions, malicious workspaces and
prompt-injected agents as peers. The user narrowed and sharpened it.

## Decision
- **Primary attacker:** a rogue extension that the user installs, from a
  gallery or a VSIX, into a tab. It has **full control of that tab's extension
  host and REH server process**: it can replace the REH, speak the remote
  protocol to the UI as a hostile server, read and write everything in the
  tab, and run any code inside the tab sandbox.
- **Secondary:** malicious workspace content (tasks, git config,
  config-as-code, interpreter paths, MCP configs). It is contained by the same
  boundary, because it can do at most what a rogue extension in that tab can
  do.
- **Goal of the attacker:** reach anything outside its tab, namely host code
  execution, host files, real secrets, other tabs, ungranted network, or
  persistence into other tabs or the host.
- **Out of scope:** kernel and hypervisor escapes. Each driver's isolation is
  defence in depth: sbx gives one microVM per tab; OCI gives namespaces, with
  optional gVisor.

## Consequences
- Every channel from the tab to the host is hostile input: the REH server→client
  protocol, `MainThread*` RPC, the managed socket bytes, and files written to
  the shared workspace mount. That last one matters for later host-side reads,
  for example git on the host. It is why local windows must never open a tab's
  workspace unsandboxed (ADR route-folder-opens-in-main).
- Persistence is in scope. A rogue extension must not be able to install itself
  into other tabs or onto the host
  ([EDR extension persistence](../edr/20261104-extension-persistence.md)).
