# Security review: background windows are click-through; dialogs never shown

- **Date:** 2026-11-06
- **Scope:** round FFF, `9fa5f9f` and its fixes: patch 0012's guard (click-through windows, no
  dialogs), the launcher's stderr capture, and the focus probe's guard check and host steps.
- **Threat model:** a background test window must never become frontmost, including from the
  user's own clicks. No confirmation may be weakened, and the probe's evidence must not be
  forgeable by the tab.
- **Records:** [EDR background-windows](../edr/20261105-background-windows.md).
- **Prompt injection:** none found.

## Round FFF
Nothing medium or higher. Confirmed:
- every message box gets its `cancelId` from `massageMessageBoxOptions`;
- file dialogs return `canceled`;
- background mode is still read once at load;
- click-through covers every BrowserWindow, auxiliary windows and `window.open` included;
- the probe signals only this run's renderers.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| FFF-1 | Low | guard | A detached DevTools window is native, not a BrowserWindow, so it escaped click-through. | Fixed | DevTools are always docked (`mode: 'bottom'`, `activate: false`). |
| FFF-2 | Low | guard | A tab extension's modal message, logged raw, could forge a "click-through" line. | Fixed | Control and line-separator characters are replaced before logging. |
| FFF-3 | Low | probe | One click-through window was enough to pass. | Fixed | It needs at least as many records as the editor has windows (CoreGraphics list). |
| FFF-4 | Low | probe | An interrupted probe could leave renderers stopped. | Fixed | SIGCONT in `finally` and in the SIGINT and SIGTERM handlers. |
