# The workspace window ("tab") is the containment unit; Workspace Trust is UX only

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** anticomputer (user); seclab-vscode coordinator

## Context
VS Code runs extensions and workspace-triggered code (tasks, git hooks and
`core.fsmonitor`, config-as-code, interpreter paths, MCP stdio servers) with
the user's full privileges. The only built-in gate is Workspace Trust. Microsoft
states it "can't prevent a malicious extension from executing code and ignoring
Restricted Mode". In code, a trust transition only restarts extension hosts and
changes no privileges. We need a unit of containment that bounds a rogue
extension's or a malicious workspace's blast radius without changing the UI.

## Decision
The containment unit is the **workspace window ("tab")**, analogous to a site
in Chrome. Code that tab *T* causes to run can affect only *T*'s mounted
workspace and *T*'s granted scope. It cannot run code on the host, read host
files, obtain a reusable real credential, reach the network beyond *T*'s
policy, or touch other tabs (threat model: ARCHITECTURE.md §2). Workspace Trust
stays as a UX prompt and is never relied on as a boundary.

## Alternatives considered
- **Strengthen Workspace Trust**: rejected. It is honour-system for extensions
  and has a long bypass history (see `workspace-exec-vectors.md` §2, §6).
- **Per-extension isolation as the unit**: deferred. It is costlier, and
  extensions within one tab sharing the tab's blast radius is accepted for v0
  (ARCHITECTURE.md §8).
- **Per-process OS sandbox (Seatbelt, bubblewrap, MXC)**: rejected as the
  boundary. VS Code's own docs say its agent sandbox "is not a virtual machine
  or user-account boundary". It may be added later as an inner layer.

## Consequences
- Every window must be backed by a sandbox, including empty windows. Anything
  that still executes on the host is a tracked residual (ARCHITECTURE.md §4.7).
- Cross-tab state (SecretStorage, globalState) must be partitioned per tab (M4).

## Evidence
- Trust transition only restarts hosts: [extensionEnablementWorkspaceTrustTransitionParticipant.ts#L32-L49](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/contrib/extensions/browser/extensionEnablementWorkspaceTrustTransitionParticipant.ts#L32-L49)
- https://code.visualstudio.com/docs/editing/workspaces/workspace-trust
- [`docs/research/workspace-exec-vectors.md`](../research/workspace-exec-vectors.md), [`docs/research/vscode-internals.md`](../research/vscode-internals.md) §1, §5
