# Tab Manager routing (M1): extension-level redirect, fail closed

- **Status:** accepted (interim; see the proposed [main-process routing ADR](../adr/20261104-route-folder-opens-in-main.md))
- **Date:** 2026-11-04
- **Deciders:** fork-build session

## Decision
- **Tab windows:** the `seclab` resolver binds the authority to the window's
  folders and workspace file. Each must be `vscode-remote://seclab+<tabId>`
  inside that tab's `hostPath`; otherwise the resolve is refused. The resolver
  returns `isTrusted: true`, because trust is UX only inside the sandbox.
- **Local single-folder `file:` windows:**
  - a folder that is already a tab is re-opened as its tab silently;
  - a new path gets a modal ("Open … in a sandboxed tab?");
  - Cancel or any error closes the folder (`workbench.action.closeFolder`).
- **Local multi-root, `.code-workspace` and non-file windows:** a modal
  explains, then the folder is closed.
- **Empty local windows** stay as they are. Only first-party built-ins run
  there, and every non-built-in extension is workspace-kind (patch 0002).
- **New tabs:** `seclab: Open Folder in New Tab…` (`cmd+O` / `ctrl+K ctrl+O`)
  opens the native host dialog and claims the chosen folder.
- **Allowed roots:** the first claim asks the user to choose a projects folder
  (`seclab.tabs.allowedRoots`, application scope); tabd refuses claims without
  one.

## Residual
The local window exists for a few seconds before it is rerouted or closed. If
the user had **previously trusted** that folder in a local window, built-ins
such as git can run on the host meanwhile. The fix is the main-process routing
patch (proposed).
