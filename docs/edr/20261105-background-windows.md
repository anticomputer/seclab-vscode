# Background windows: an env-gated patch so harness windows never take focus

- **Status:** accepted
- **Date:** 2026-11-05
- **Deciders:** anticomputer (user). Verbatim: "Small env-gated fork patch: windows open inactive when the harness sets a flag, so screenshots stay real macOS". Coordinator: the requirements below. Fork-build session: implementation.
- **Related:** AGENTS.md hard rule "Never steal focus from the user"; [patch queue](../../patches/README.md); [review](../security-reviews/20261104-fixture-safety.md)

## Context
The harness launched demo and Level B windows with `open -g -n` and checked afterwards
whether the editor had become the frontmost app. On a real launch it had. `open -g` can't
prevent this:
- Code-OSS creates windows with `show: true`
  ([`windows.ts:147`](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/windows/electron-main/windows.ts#L147)).
- Electron 43.8.3's macOS `NativeWindowMac::Show()` calls
  `[NSApp activateIgnoringOtherApps:YES]` before `makeKeyAndOrderFront`
  ([`native_window_mac.mm:486`](https://github.com/electron/electron/blob/1c0ee213f150fc4a0d06304dcedabd9b2e8ce0f7/shell/browser/native_window_mac.mm#L486), tag v43.8.3).
- `focus()` adds `app.focus({ steal: true })` in force mode, and a second instance does the
  same.

## Decision
Patch `0012-background-windows-env.patch` (38 lines, five files). If the main process was
launched with `SECLAB_BACKGROUND_WINDOWS=1`:
- **Window creation:** windows are created with `show: false` (`defaultBrowserWindowOptions`,
  which main and auxiliary windows share) and then shown with `showInactive()`. That is
  right after creation for normal windows, after maximize/fullscreen is applied for those,
  and in `did-create-window` for auxiliary windows.
- **Focus:** `BaseWindow.focus()` (every mode, so window restore and the open-time focus
  logic too) is a no-op. So are the second instance's `app.focus({ steal: true })`,
  `moveWindowTop`, and always-on-top (a window above everything covers the user's work
  without becoming frontmost; review UU-1).
- **Utility windows that bypass `BaseWindow`:** the GPU-info, content-tracing and devtools
  child windows (`openChildWindow`) are shown with `showInactive()`, and their
  restore-and-focus is skipped (UU-1).

The flag is `backgroundWindows`, exported from `windows.ts`. It is read once from
`process.env`, at module load of the main process. It is not a setting, a CLI argument or
anything a window, extension, tab or workspace can reach:
- the renderer, the extension hosts and the tab never write the main process's environment;
- a second `code` invocation hands its environment to new windows as `userEnv`, not to the
  main process.

Only `test/harness.ts` sets it, through `open --env`.

## Consequences
- It withholds focus and grants nothing, so it isn't a test hook in the sense of the patch
  queue rule ("test-only hooks never go in patches/"). It ships, inert unless set.
  `./seclab lint source` now scans the lines every core patch adds, and this one environment
  read is an allowlisted, reviewed site (UU-3).
- `test/window.ts launch` checks the frontmost app at launch, then leaves a watcher that
  polls it every second for the editor's whole life. Any steal is logged in the run's
  profile, `window.ts shot` refuses to capture, and teardown fails the run (UU-2). That is
  the regression guard if a future upstream adds another activation path.
- Not covered:
  - the dev-only "show after 10 s when sources failed to load" path, which runs only in
    unbuilt trees (`!isBuilt`), never in our builds;
  - `openDevTools`' own `activate` default (user command only).
- Rebase cost: one exported constant and six guarded call sites in upstream's window code.
  The patch fails to apply loudly if they move.
- 0005-0011 are reserved for the RPC filter series, so this is 0012.
