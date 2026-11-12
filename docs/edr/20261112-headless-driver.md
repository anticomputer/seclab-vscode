# Headless editor driver: tests drive the editor from inside, never through the OS

- **Status:** accepted (measurements marked *pending* run once CI is available)
- **Date:** 2026-11-12
- **Deciders:** Coordinator (direction: drive the editor from inside, no TCP port, screenshots
  from the renderer, permission-free focus checks, OS-level paths on a hosted runner or a
  structural check, Linux under Xvfb). Fork-build session: measurement and implementation.
- **Related:** [background windows](20261105-background-windows.md) (patch 0012, the focus
  paths), [test build variants](20261106-test-build-variants.md),
  [harness teardown](20261104-harness-teardown.md)

## Context

Tests must not need OS privacy permissions: no Accessibility, no Screen Recording, no keystroke
automation, and nothing may ask for them. Three things in the harness did: window screenshots
(`screencapture -l`), the Space-switch focus probe (System Events keystrokes), and the
clipboard canary (now gone; RPC core replaces the clipboard in the test variant). Everything
else an editor test needs (open things, run commands, read UI state, capture the window) can be
done from inside the editor.

## Decision

**Transport: Chrome DevTools Protocol over `--remote-debugging-pipe`.** Electron 43.8.3, the
version upstream 1.145.0 pins, starts Chromium's pipe handler for that switch and quits when the
pipe closes
([`electron_browser_main_parts.cc`](https://github.com/electron/electron/blob/1c0ee213f150fc4a0d06304dcedabd9b2e8ce0f7/shell/browser/electron_browser_main_parts.cc#L610-L621), tag v43.8.3).
CDP is read on fd 3 and written on fd 4, NUL-delimited. There is no port, so no other process,
and no tab, can open a connection. The fds are inheritable socketpair ends, though: a process
the editor's main process starts through `child_process` holds them and could read or forge
frames (not drive the editor). On Linux, libuv's fork passes them to such a child; on macOS,
Node's `posix_spawn` closes them (measured). The child the main process starts on its own is the
user's login shell, to resolve its environment: once from the app with the parsed arguments,
and once from the pty service with empty ones, which ignore `--force-disable-user-env`. So the
driver sets `VSCODE_CLI=1`, as the real `code` launcher does, which skips every such
resolution, and passes the flag as well. The self-test then checks that no other process holds
the editor's fds 3 and 4 (`cdpFdHolders`: `/proc` on Linux, `lsof` on macOS). Electron's utility
processes (extension host, pty host, shared process) go through Chromium's launcher, which
closes descriptors it wasn't told to pass (reviews
[QQQ-1 and RRR-1](../security-reviews/20261112-headless-driver.md)). VS Code's own smoke
tests reach the same renderer through Playwright over a loopback debugging port; we keep their
driver and drop the port.

- `test/driver/cdp.ts`: the pipe client. `test/driver/editor.ts`: launch, attach to the
  workbench page, `evaluate`, upstream's smoke-test `window.driver` (only with
  `--enable-smoke-test-driver`, which also changes some behaviour, e.g. a crashed window quits
  instead of showing a dialog, so focus probes don't use it), key events and text through CDP
  `Input` (delivered to the renderer, not the window server), commands through the palette,
  screenshots, and quit through `Browser.close`.
- **Screenshots** are CDP `Page.captureScreenshot` on the workbench page: the renderer's own
  output, so no OS capture. `test/driver/shot.ts` replaces `window.ts shot`, which is removed
  along with `captureWindow`. `webContents.capturePage()` is the main-process equivalent; CDP
  reaches the renderer without a main-process hook. *Pending:* whether a below-normal,
  never-on-screen macOS window still produces frames (Chromium can stop rendering an occluded
  window). If it doesn't, the fallback is a test-variant main-process hook calling
  `capturePage({ stayHidden: true })`.
- **No app-side hook, so no marker.** The driver uses only Chromium's switch and upstream's
  smoke driver, both present in every build; there is nothing test-only in the app for
  check-release to refuse or for a nonce to arm. The guarantee that matters is that no other
  process can open a connection, which the pipe gives. Launching the editor with a switch already
  takes code execution as the user; a tab can't pass Chromium switches to the host editor.
- **The editor gets a clean environment** (what LaunchServices would give it, plus the run's
  own variables), never the launcher's, which may hold tokens. Unit-tested.

**macOS launch: exec, made safe by the bootstrap.** `open -g` can't hand fds 3 and 4 to the app,
so the driver execs the binary. An exec'd app checks in with LaunchServices without the
"don't activate" flag. Patch 0012's guard set the background-only policy at `ready`, and
upstream's bootstrap loads `electron-main` only after `ready`, so the guard ran too late for
this kind of launch. Patch 0012 now also sets the policy in `mainImpl.ts`'s top level, which
runs before AppKit finishes launching, and logs
`[background windows] activation policy: prohibited (bootstrap)`. The driver refuses an app
whose `out/mainImpl.js` lacks that string (minification keeps strings, not comments). It still
starts the focus watcher and still requires `BackgroundOnly`, like a LaunchServices launch.
*Pending:* a driven launch on a build with the bootstrap policy, with the watcher.

**Focus checks keep the watcher, which needs no permission.** It uses `lsappinfo front`,
`lsappinfo info` and `find` (LaunchServices queries) and one `CGWindowListCopyWindowInfo` query
for window number, layer, bounds and owner pid. Window names and contents, the parts behind
Screen Recording, aren't read: without that permission macOS withholds them, and with it the
watcher still ignores them. Both queries return data without a prompt.

**OS-level focus paths (Space switches).** `test/focus/spaces.ts` needs the `keystrokes` host
capability (`test/host-caps.ts`) and otherwise skips with the reason. Its latest evidence stays
the 2026-11-09 run ([background windows](20261105-background-windows.md)). Two things replace it:

- A structural check: `check-release --desktop` fails a desktop app that lacks the bootstrap
  policy, the guard's policy or the below-normal window level, the three things that make the
  click, window-close and Space-change activation paths impossible. Each has its own marker
  (`… prohibited (bootstrap)`, `… prohibited (guard)`, `is below normal windows`); the first
  two were a prefix of each other until review QQQ-2. Self-tested by removing each.
- `macos-focus-paths.yml` measures whether a hosted macOS runner can drive a Space switch.
  First run, 43251392437 (macOS 15.8.2): the keystroke is accepted (exit 0), but the on-screen
  window set doesn't change, so a switch can't be observed there. The Space path therefore
  stays covered by the structural check and the recorded run.

**Linux under Xvfb.** `./seclab test driver` runs the Linux editor build in a container
(`test/driver/xvfb/`, same pinned base as the builder) with no network, driving it over the pipe:
launch, workbench restored, DOM and title read, a palette command toggling the status bar,
screenshot, quit. `--no-sandbox` there because the container grants no user namespaces; the
container is the boundary. CI: `headless-linux.yml` builds the editor and runs it. The local
editor build doesn't fit 8 GB of Docker memory (esbuild is killed while bundling, twice), so the
first run is CI's. *Pending:* that run.

## Probes, before and after

| Probe | Before | After |
|---|---|---|
| `window.ts shot`, demo and `notify-e2e --shot` screenshots | `screencapture -l` (Screen Recording) | `test/driver/shot.ts` and the driven launch: renderer screenshot. *Pending:* first run |
| Space-switch probe (`spaces.ts`) | System Events keystrokes (Accessibility) | skips with the reason; structural check in check-release (self-tested); the hosted runner can't show a Space switch (run 43251392437) |
| Focus battery (`probe.ts`), Level B, containment editor runs | no permission needed (watcher verified above) | unchanged |
| Clipboard canary | read and restored the host clipboard | removed from the harness; RPC core's in-memory clipboard |

## Consequences

- Editor tests can run on Linux in CI, so most proofs don't need the Mac.
- A macOS build without the bootstrap policy can't be driven; the driver says so and stops.
- `--remote-debugging-pipe` and `--enable-smoke-test-driver` work in release builds too, as
  upstream. Both need the editor to be launched with them.
