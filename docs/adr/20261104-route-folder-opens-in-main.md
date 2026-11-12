# Route folder opens into tabs in the main process (before any window loads them)

- **Status:** accepted (2026-11-12, coordinator's decision: implement as patch 0041 once the
  headless driver is green in CI; meanwhile the interim patch 0042). Implemented as patch 0041
  ([EDR](../edr/20261112-main-process-routing.md)); 0042 removed with it.
- **Date:** 2026-11-04
- **Deciders:** fork-build session (proposal); coordinator (accepted 2026-11-12)
- **Related:** [security review round 2](../security-reviews/20261104-m0-tabd-code.md) finding New-1 (HIGH, open), [EDR Tab Manager routing](../edr/20261104-tab-manager-routing.md)
- **Editorial redaction (2026-11-12):** quotations of project conversations replaced with neutral statements; decisions unchanged.

## Context
M1 routes opens from inside the Tab Manager extension. A `file://` folder
window (opened from the CLI, Finder, the File menu, recents or a
`.code-workspace` file) loads **locally first**, and the Tab Manager re-opens
it as a tab only seconds later. If the user previously trusted that folder,
built-in extensions such as git run on the host in that moment. A tab can
plant `core.fsmonitor` in its own (host-mounted) workspace, which turns that
moment into host code execution.

## Decision
Accepted as proposed below (coordinator, 2026-11-12), given what has landed since:
patch 0003 keeps every workspace extension (git and `core.fsmonitor`, eslint, interpreter
settings) out of local windows, so only core features can act in the moment before the Tab
Manager closes a local folder window. Automatic `folderOpen` tasks are the known one (default
`task.allowAutomaticTasks: off`, but the prompt and a user's `on` remain). Routing in main
removes that moment for every path, including ones nobody has listed.

- Patch **0041** (fork-build range), after the headless driver is green in CI. Its test drives
  the editor over the CDP pipe ([headless driver](../edr/20261112-headless-driver.md)): open a
  `file:` folder through the CLI and assert that no window ever has it as its workspace, and that
  the Tab Manager received the open. That test also covers the close-before-any-dialog finding
  ([round 2](../security-reviews/20261104-m0-tabd-code.md) 3-2).
- Interim, now: patch **0042**. A window with no remote authority neither runs automatic tasks
  nor asks to allow them. It is removed when 0041 lands.

## Proposed decision
Add a small electron-main patch in the `WindowsMainService` open path. When
product.json enables seclab routing, it rewrites any `file:` folder or
workspace open without a remote authority into an empty window, then delivers
`<urlProtocol>://seclab.tab-manager/open?path=<folder>` to the Tab Manager's
URI handler. The Tab Manager then claims (with confirmation) and opens the tab.
No local folder window is ever created.

## Alternatives considered
- **Keep extension-level routing** (M1 today): it has a residual race, but
  only for previously trusted folders. Mitigated by closing every local folder
  window that isn't routed.
- **Force Restricted Mode for local `file:` workspaces** (patch the trust
  service): it relies on Workspace Trust, which is not a boundary.
- **Mint tab IDs in the main process**: duplicates tabd's identity logic in
  the trusted UI process.

## Consequences
- One more core patch (about 30 lines). Every open path converges in main, so
  it covers the CLI, menus, recents, drag and drop, and `vscode://file` links.
