# Route folder opens into tabs in the main process (before any window loads them)

- **Status:** proposed
- **Date:** 2026-11-04
- **Deciders:** fork-build session; needs coordinator and project owner approval (adds a core patch to M1)
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
