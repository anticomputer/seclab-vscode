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
  - `openDevTools`' own `activate` default. Superseded 2026-11-06: any extension, including a
    tab's, can run `toggleDevTools`, and the guard now forces `activate: false` (review AAA-1).
- Rebase cost: one exported constant and six guarded call sites in upstream's window code.
  The patch fails to apply loudly if they move.
- 0005-0011 are reserved for the RPC filter series, so this is 0012.

## Addendum 2026-11-06: activation inside Electron, and a watcher that kills
**What happened.** An agentic-gate run on main's release build took focus mid-run. Teardown's
watcher recorded three samples, but `window.ts launch`'s own check had passed, so the editor
kept the user's desktop until the end of the run. The patch guarded VS Code's call sites, but
on macOS Electron 43 activates the app in its own code (permalinks pinned to the `v43.8.3` commit):
- `NativeWindowMac::Show()` calls `activateIgnoringOtherApps:YES`
  ([native_window_mac.mm](https://github.com/electron/electron/blob/1c0ee213f150fc4a0d06304dcedabd9b2e8ce0f7/shell/browser/native_window_mac.mm#L486)),
  so any `show()` activates.
- `WebContents::Focus()` calls `owner_window()->Focus(true)`, which activates
  ([electron_api_web_contents.cc](https://github.com/electron/electron/blob/1c0ee213f150fc4a0d06304dcedabd9b2e8ce0f7/shell/browser/api/electron_api_web_contents.cc#L3976-L3982)).
  VS Code calls `webContents.focus()` in the main process outside `CodeWindow.focus()`,
  for example the browser view's `focus(force)`.
- A dialog with no parent window runs `[NSAlert runModal]`
  ([message_box_mac.mm](https://github.com/electron/electron/blob/1c0ee213f150fc4a0d06304dcedabd9b2e8ce0f7/shell/browser/ui/message_box_mac.mm#L144)).
  Several main-process dialogs pass `BrowserWindow.getFocusedWindow()`, which is undefined
  for a background window.

**Patch.** 0012 adds `backgroundWindowsGuard.ts`, installed first in `main.ts`. In
background mode only:
- `BaseWindow`/`BrowserWindow` `show()` becomes `showInactive()`;
- `focus()` and `moveTop()` do nothing unless a window of ours already has focus (the user
  activated the app);
- `setFullScreen(true)` and `setSimpleFullScreen(true)` are refused;
- `app.focus()` does nothing;
- `webContents.focus()` does nothing unless a window of ours has focus;
- every dialog gets a parent window, so it shows as a sheet, and one with no window to
  attach to is cancelled instead of run app-modal; `showErrorBox` is logged instead.

If the guard can't be installed, the process exits rather than run unguarded.

**Harness.**
- `launchEditorInBackground` (`test/harness.ts`) starts the watcher before `open`, for every
  caller, not only `window.ts`.
- The watcher samples the frontmost app every 200 ms for the editor's whole life. On the first
  sample in which the editor is frontmost, it kills the editor's whole process tree and
  records the steal. A steal can now last at most about 200 ms plus the kill.
- The launch-time check kills too.

**Verified 2026-11-06** with `test/focus/probe.ts`. A benign sbx tab runs a probe extension
that steps through: a notification, a quick pick, focus commands, full screen, a modal dialog,
a new window, a reload, killing the server (the reconnect path), and an extension-host restart.
Each step is timestamped, and the kill-on-steal watcher is armed throughout.
- **Release build** (main `5c18c5f`, run 42185096401): the editor took focus 0.7 s into
  `toggleFullScreen` (Electron's `setFullScreen` activates the app) and was killed within one
  sample. With full screen skipped, every other step stayed in the background, modal dialogs
  included (sheets don't activate).
- **Branch build with the guard** (`751c6c7`, run 42231186243, fetched with
  `./seclab fetch macos-branch`): no step took focus, full screen included. The
  extension-host restart, run alone, recorded no steal either. It restarts the local
  extension host and with it the Tab Manager's tabd, which stops the tab, so the step's
  later marks were lost with the tab.
- **Not reproduced:** the agentic run's exact trigger. Its probes impersonate the agent host
  (MCP UI, auth prompts). The guard covers each class of path Electron activates through, and
  the watcher now kills on the first frontmost sample, so a new path fails closed within
  about 200 ms.
- **Found along the way:** the window doesn't recover after the server is killed or the
  local extension host restarts. That's a reconnect gap for the tabd broker wiring's B3 step,
  not a focus issue. The probe also exposed an sbx quarantine bug, fixed in
  [EDR sbx-tab-broker](20261105-sbx-tab-broker.md).

**Review AAA (2026-11-06): nothing medium or higher; all six lows fixed.**
- **AAA-1:** DevTools open with `activate: true` and focus natively. `openDevTools` now forces
  `activate: false`, and `toggleDevTools` is rebuilt on it.
- **AAA-2:** a failed `WebContents` patch exits the app, as installation failures do.
- **AAA-3:** the watcher kills the editor's processes but spares tabd and its children. tabd
  sees EOF and stops its own tabs, instead of leaving them running unsupervised.
- **AAA-4:** a watcher that can't sample fails the run, and it follows the profile's editor
  across a relaunch.
- **AAA-5:** quarantine removes stale broker allows whatever the current `--broker` mode.
- **AAA-6:** the probe strips control characters from the tab-written marks.

Dialogs cancelled in background mode answer with their `cancelId`, which
`massageMessageBoxOptions` always sets, so a confirmation always gets its safe answer.

## Addendum 2026-11-06 (evening): the user's own clicks
- **Finding:** the RPC core landing session's proof run (85ca160) was killed for focus about
  3m48s after launch. Here, main's release (a986b9d) and the 24fea4c guard build were both
  killed within about 2.5 s of launch, but only while the user was working in another app
  (Microsoft Teams frontmost); the same builds ran clean minutes earlier.
- **Cause, from the unified log:**
  - LaunchServices' bring-forward was denied (`dontMakeFrontmost=1`, "presents 0 windows ...
    Denying the request"), and nothing in the app asked to activate.
  - The WindowServer made the editor frontmost from an input event:
    `PostFilteredEventTapData ... Making seclab-vscode the front process`.
  - `showInactive` orders the window in front of the user's windows without activating the
    app, so the user's next click on that spot landed on the editor. No code path in the guard
    was missed. The window being on top of the user's work was itself the defect.
- **Fix (patch 0012's guard):**
  - In background mode every window is click-through from creation, and
    `setIgnoreMouseEvents` always passes `true`.
  - Dialogs are never shown, because a sheet is its own window a click can reach. Each
    gives its safe answer (a message box its `cancelId`, a file dialog "canceled").
  - Both are recorded on the main process's stderr.
- **Probe:**
  - The launcher captures the editor's stderr (`open --stderr`, inside the run's profile).
  - `test/focus/probe.ts check` fails unless the guard recorded click-through windows. Main's
    release records none, so it fails there.
  - `check` also adds two host-side steps: the renderer stopped until Electron reports it
    unresponsive, and the renderer terminated, as teardown's SIGTERM can do.
  - A behavioural click test isn't possible on a shared desktop. A click posted only to the
    editor's pid doesn't reach WindowServer hit-testing (verified: no activation), and a real
    click would land in the user's app once the fix works.
- **Review FFF** (four lows, all fixed):
  - DevTools stay docked in the click-through window, since a detached DevTools window isn't a
    BrowserWindow;
  - logged dialog text has control and line-separator characters replaced, so tab text can't
    forge a guard line;
  - the probe requires a click-through record for every editor window;
  - stopped renderers always get SIGCONT, even if the probe is interrupted.
- **Second path, found on the fixed build (95f2c83/97a1b09):** with click-through windows and
  no dialogs, the editor was still made frontmost about 76 s after the probe's
  server-connection-lost step.
  - This time the WindowServer logged `SetFrontProcess` from a system connection (`0x5ce03`),
    not from the editor and not from an input event.
  - The same connection promoted the RPC session's editor at 17:22:13Z. Both times another
    app was frontmost.
  - It's the system choosing a new front app, as when the front app's window closes, and
    picking the regular app whose window sits on top.
- **Fix:** in background mode on macOS the editor is an accessory (UI-element) app from
  `ready`, before any window. `setActivationPolicy` and `dock.show` can't switch it back.
  The system doesn't promote accessory apps, and there's no Dock icon to click.
- **Harness:** every background launch must report `ApplicationType` `UIElement`
  (`lsappinfo`), or the launcher kills it and fails the run, whatever the caller. The probe
  also requires the guard's `activation policy: accessory` record. Builds without this fix
  can't be launched in the background at all.
