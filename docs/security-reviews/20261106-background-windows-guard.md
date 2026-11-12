# Security review: background windows guard (focus steal)

- **Date:** 2026-11-06
- **Scope:** round AAA, `f96cdc7..fb5979c`:
  - patch 0012's main-process guard (`backgroundWindowsGuard.ts`);
  - the focus watcher in `test/harness.ts`;
  - the focus probe (`test/focus/`);
  - the sbx quarantine fix.
- **Threat model:** a window in background mode must never take focus from the user, whatever a
  tab's extensions do. The guard must not weaken any confirmation, and must stay off outside
  background mode.
- **Records:** [EDR background-windows](../edr/20261105-background-windows.md),
  [EDR sbx-tab-broker](../edr/20261105-sbx-tab-broker.md).
- **Prompt injection:** none found.

## Round AAA
Nothing medium or higher. Confirmed:
- `backgroundWindows` is a constant read from the main process's environment at load, so no
  window, extension, tab or workspace can turn the guard on or off.
- A cancelled dialog answers with its `cancelId`, which `massageMessageBoxOptions` always sets,
  so every confirmation gets its safe answer.
- Removing the tab's own broker allow during quarantine can only tighten the fence.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| AAA-1 | Low | guard | Any extension, a tab's included, can run `toggleDevTools`. DevTools open with `activate: true` and focus natively, past the `focus` patch. | Fixed | `openDevTools` forces `activate: false`, and `toggleDevTools` is rebuilt on it. The probe now has a DevTools step. |
| AAA-2 | Low | guard | The `WebContents` patch ran in an event handler outside the try/exit, so a failure would only log. | Fixed | A failure there exits the app; replacement of `focus` is checked. |
| AAA-3 | Low | harness | Killing the whole tree also killed tabd, leaving tabs running unsupervised (or a policy write half done). | Fixed | tabd and its children are spared; tabd sees EOF and stops its tabs. |
| AAA-4 | Low | harness | A sampling error or an editor relaunch ended the watch silently, so the run passed. | Fixed | Five consecutive errors record "watcher failed" (failing the run) and kill the editor; the watch follows the profile's editor until none has run for 5 s. |
| AAA-5 | Low | tabd | Quarantine's allow cleanup depended on the current `--broker` mode. | Fixed | Unconditional. |
| AAA-6 | Low | probe | Tab-written marks were printed to the terminal unfiltered. | Fixed | Control characters are replaced. |
