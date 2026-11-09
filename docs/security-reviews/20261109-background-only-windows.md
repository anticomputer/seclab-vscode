# Security review: background-only windows (focus path c)

- **Date:** 2026-11-09
- **Scope:** round LLL, `c32e1c7`, `0a3c210`, `841b7a1` and their fixes:
  - patch 0012's guard (`backgroundWindowsGuard.ts`): activation policy `prohibited`, the
    pinned `setActivationPolicy`, the pinned `setAlwaysOnTop` and the per-window
    `setAlwaysOnTop(true, 'normal', -1)` at creation;
  - `test/harness.ts`: the `BackgroundOnly` launch gate and the window list;
  - `test/focus/probe.ts`: the below-normal count and the exit predicates;
  - `test/focus/spaces.ts` and its `test/safety/allowlist.txt` entry;
  - the AGENTS.md rule and the EDR's "Path c" section.
- **Threat model:** a background editor must never become the front process and must never sit
  over the user's work, whatever a tab's extensions do, and whatever the system decides on a
  Space change. The guard must stay inert outside background mode, must not weaken a
  confirmation, and its evidence must not be forgeable by the tab it watches. `spaces.ts` runs
  on the host, outside every container, and drives the user's own screen.
- **Records:** [EDR background-windows](../edr/20261105-background-windows.md),
  [round KKK](20261109-liveness-gate.md).
- **Prompt injection:** none found.

## Round LLL
One medium, four lows, three residuals. Confirmed:
- `prohibited` closes a, b and c by construction: all three were LaunchServices/WindowServer
  front-process promotions, and a background-only process is never promoted. It is set at
  `ready`, before any window; `setActivationPolicy` and `dock.show` are pinned;
- no tab-side path to the pins: they live in the main process, and the renderer-reachable
  surface (`moveWindowTop`, always-on-top, `focus`, `show`, DevTools, dialogs) is covered;
- in the pinned Electron, `Maximize()` falls back to `ShowInactive()` for a hidden window,
  `ShowInactive()` orders within the window's own level, and `activateIgnoringOtherApps` is
  inert for a prohibited process;
- `replace()` exits the app when a name is missing, so a rebase can't leave a pin off;
- the harness gate fails closed (an `lsappinfo` miss is not `BackgroundOnly`), and `--env`
  can't disable the guard;
- dialogs still answer with `cancelId`: no confirmation is weakened, nothing blocks invisibly;
- the commits state only generic prerequisites, and remove two sentences that described this
  machine.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| LLL-1 | Medium | guard | `setVisibleOnAllWorkspaces` was not pinned. Electron's `DockShow` (unless `skipTransformProcessType`) turns the app into a regular one with a Dock icon, reopening a, b and c after the launch check. It has no caller or IPC in the pinned Code-OSS. | Fixed | Pinned to a no-op, with `setKiosk`, which bypasses the `setFullScreen` pin. `probe.ts check` already re-reads `ApplicationType` and requires `BackgroundOnly`. |
| LLL-2 | Low | spaces probe | The launch line was validated by a loose regex and run with `sh -c`, so shell metacharacters passed. | Fixed | `spaces.ts` takes only `--app` and builds the launch argv from the prepared run's manifest; no shell. |
| LLL-3 | Low | window list | Only layers 0 and -1 were counted, so a window at another level passed vacuously. | Fixed | The list returns every layer. The probe fails if any sizeable window isn't at layer -1. |
| LLL-4 | Low | guard log | The `showErrorBox` record wrote foreign text verbatim, newlines included, into the log the probe parses. | Fixed | One line, control and separator characters replaced, sliced, like the dialog line. |
| LLL-5 | Low | spaces probe | With the shortcut unbound, the keystroke goes to the user's app and the run passes falsely. | Fixed | Each switch must change the on-screen window set (read-only CGWindowList), or the run stops as invalid. |
| — | Residual | dialogs | `cancelled()` falls back to the first button when `cancelId` is absent; VS Code always sets one. | Accepted | Pre-existing; revisit if a direct `electron.dialog` caller appears. |
| — | Residual | visibility | A background run has no on-screen indicator: not in the on-screen list, no Dock icon, no ⌘-Tab entry. | Accepted | The trade-off the hard rule asks for; the watcher, the teardown gate and `window.ts shot` remain. |
| — | Residual | startup | The policy is set at `ready`, so the app is a regular one for the first moments (GGG-1). | Accepted | The bundle is shared with normal runs, so it can't be set statically. |
