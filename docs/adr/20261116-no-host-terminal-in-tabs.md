# A tab window opens no host terminal

- **Status:** accepted. Proof passed, both halves (2026-11-16).
- **Date:** 2026-11-16
- **Deciders:** project owner (2026-11-16); RPC follow-ups session
- **Related:** [tab is the containment unit](20261104-tab-is-the-containment-unit.md),
  [push refusals EDR](../edr/20261116-reh-push-refusals.md) (where the palette's ranking was
  found)

## Context
Upstream gives a remote window two ways to open a shell on the local machine, and in a tab
window the local machine is the host:
- **"Create New Integrated Terminal (Local)"** (`workbench.action.terminal.newLocal`). Upstream
  registers it for every remote window (`terminalNativeContribution.ts`, `terminalRemote.ts` at
  `a717861c`). In a tab window the palette ranks it first for "Terminal: Create New Terminal".
  The first push-proof harness picked it by that query and got a host shell in the host's copy
  of the workspace. Its checks passed until they tested `uname`.
- **"Open New External Terminal"** (`workbench.action.terminal.openNativeConsole`, Ctrl+Shift+C).
  It opens the host's terminal application.

A third path has no command of its own. A terminal whose working folder is a host (`file:`)
URI goes to the local backend (`terminalProcessManager`). That happens with "Open in Integrated
Terminal" on a host document, or a user keybinding that passes a `file:` cwd.

These are user actions, not a tab's. But a host shell is the least contained thing a tab
window can offer, it sits one wrong palette pick away, and its working folder is the
workspace a tab can write to (a hostile `.envrc` or shell hook runs there).

## Decision
A tab window offers and starts no host terminal (project owner, 2026-11-16). Local terminals
open from a normal window. Patch 0050 does it in three layers:
1. **Not offered.** `newLocal` isn't registered in a `seclab+` window. The external terminal's
   palette entry and keybinding carry `remoteName != seclab`, and its handler returns at once
   in a tab window, so a direct `executeCommand` does nothing either. The Explorer's "Open in
   Integrated/External Terminal" items for a host (`file:`) resource carry the same condition.
2. **Not started.** In a tab window, `terminalProcessManager` refuses to start any pty whose
   authority isn't the window's own tab, with a message saying where local terminals live. That
   catches every route to the local backend, including ones nothing names yet.
3. **Recorded** in ARCHITECTURE §4.8, the tab limitations list.

Not changed: pseudo-terminals (an extension's own `Pseudoterminal`) and the tab's own
terminals. Debug's `runInTerminal` with kind `external` runs in the extension host that hosts
the debug adapter. A tab's adapter opens it inside the sandbox. Only a host-side (local
extension host) adapter, driven by a launch configuration the tab wrote, could open the host's
terminal application. No tab can drive one today: `MainThreadDebugService` is default-denied.
When debugging returns to tabs, local-extension-host debuggers need this decision applied.

## Consequences
- Every terminal in a tab window runs in the tab.
- A user who wants a host shell beside a tab uses a normal window. That window is a plain
  local window, so it never opens a folder: the Tab Manager routes folders to tabs. The shell
  starts in the home folder.
- **Proof** (`test/containment/host-terminal.ts`, headless driver, real OCI tab):
  - baseline: the palette offers both entries. The local terminal from the palette,
    `newLocal` by id from a keybinding, and a `file:`-cwd keybinding each start a shell under
    the editor's process tree;
  - patched: neither entry is offered, while the same palette still lists the tab's own
    "Create New Terminal". `newLocal` is reported not found, the `file:`-cwd launch is refused
    with 0050's message, and no host shell starts. A plain new-terminal keybinding in the same
    run opens a tab terminal, and the tab's own terminal still runs inside the tab.
  - `test/containment/host-terminal.test.ts` checks each layer in the patch text against
    mutants.
  - **Baseline: passed** (branch `4a0ab0e9`, the series without 0050, run 43942525846). All
    15 checks passed, and teardown was clean. Each of the three routes (palette, `newLocal` by
    id, `file:` cwd) started one host shell.
  - **Patched: passed** (branch `46d50870`, run 43955964158). All 15 checks passed, and
    teardown was clean. Neither entry was offered, and `newLocal` was reported not found. The
    `file:`-cwd launch showed 0050's refusal, no host shell started, and the tab's terminal
    ran inside the tab.
- **Review:** round NHT ([record](../security-reviews/20261116-no-host-terminal-in-tabs.md)).
  Nothing above low; all four findings were addressed.
