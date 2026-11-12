# Security review: headless editor driver, OS-permission-free tests, interim patch 0042

- **Date:** 2026-11-12
- **Scope:** rounds QQQ and RRR:
  - `46d4102`: `test/host-caps.ts`, the Space probe's capability gate, removal of the
    harness's host-clipboard seeding;
  - `e42d8fc`, `7a25fca`: `test/driver/` (CDP over `--remote-debugging-pipe`, the launcher,
    screenshots, `shot.ts`, the Xvfb runner), patch 0012's bootstrap policy, the structural
    check in `check-release --desktop`, `headless-linux.yml`, `macos-focus-paths.yml`;
  - `f723572`: patch 0042 (no automatic tasks in local windows), the accepted routing ADR.
- **Threat model:** the harness must not need or ask for OS privacy permissions, must not read
  the host clipboard, and must not take focus; nothing but the launcher may drive the editor; a
  tab must gain nothing from the driver; a desktop build without the focus guarantees must not
  ship.
- **Records:** [EDR headless-driver](../edr/20261112-headless-driver.md),
  [EDR background-windows](../edr/20261105-background-windows.md),
  [ADR route-folder-opens-in-main](../adr/20261104-route-folder-opens-in-main.md).
- **Prompt injection:** none found.

## Round QQQ (`46d4102`, `e42d8fc`)
Two mediums and one correctness bug. Confirmed:
- no tab-reachable path to the CDP fds: the extension host, pty host and shared process are
  utility processes, which Chromium's launcher starts with only the descriptors it maps;
- the editor's environment is an allowlist, and the background and portable variables are
  applied after the caller's, so they can't be overridden;
- `executable()` can't leave the bundle (both name patterns reject `/` and a leading `.`);
- `driver()` takes only `[a-zA-Z]+` method names and JSON arguments;
- the Xvfb container is digest-pinned, non-root, offline, with only `.work/driver` writable;
- both workflows are `contents: read`, push or dispatch only, actions pinned by SHA;
- no committed text describes anyone's OS permission settings.

An earlier pass over `46d4102` alone found that the RPC probe still read the host clipboard
unconditionally and recorded the raw text. That is RPC core's to fix (an in-memory clipboard in
the test variant, and records that hold no raw strings); the harness side, the opt-in that saved
and restored the host clipboard, is removed here.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| QQQ-1 | Medium | CDP fds | fds 3/4 are inheritable socketpair ends, and the main process always spawns the user's login shell (to resolve its environment), which inherited them and could read or forge CDP frames. The code and EDR claimed only the launcher held them. | Fixed (completed in RRR-1) | The driver passes `--force-disable-user-env`; the claims now say what the pipe gives: no other process can open a connection. |
| QQQ-2 | Medium | structural check | The guard's marker was a prefix of the bootstrap's, so a build with the bootstrap policy but without the guard's passed. | Fixed | The guard logs `… prohibited (guard)`; check-release requires it; a self-test case has the bootstrap and the window level but no guard, and fails. The focus probe accepts the guard line in either form. |
| QQQ-3 | Low | `./seclab test driver` | `local` outside a function aborted the command under `set -e`. | Fixed | A plain variable. |
| — | Residual | CDP frames | A process the editor's main process starts with `child_process` still inherits the fds. None does in a driven run once the login shell is off; utility processes don't inherit them. | Accepted | Recorded in the EDR. |

## Round RRR (`f723572`, `7824d3c`)
One medium, completing QQQ-1. Confirmed:
- 0042: every `folderOpen` path (initial, reconnect-ready, trust change) goes through
  `_tryRunTasks`, and the guard is its first statement, before the trust check, the setting and
  the prompt. Tab windows keep their `seclab+` authority, so they keep automatic tasks. The one
  test that constructs `RunAutomaticTasks` already stubs a remote authority. The web build
  type-checks.
- check-release's three markers are distinct and fail closed; the focus probe still fails a
  build without the guard.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| RRR-1 | Medium | CDP fds | `--force-disable-user-env` doesn't reach the pty service, which resolves the shell environment in the main process with empty arguments, so a login shell still started (and on Linux inherits fds 3/4). | Fixed | `VSCODE_CLI=1` in the editor's environment (as the real `code` launcher sets) skips every resolution; the self-test checks that no other process holds the editor's fds 3 and 4 (`/proc` on Linux, `lsof` on macOS). On macOS, Node's `posix_spawn` closes them anyway (measured). |
| RRR-2 | Low | 0042 log | The guard's log line read "not in a local window" when it fires in one. | Fixed | "skipped in a local window". |
| — | Residual | task reconnection | `_reconnectTasks` reruns saved persistent tasks on a window reload, outside 0042's guard. It needs persistent tasks already saved for that local workspace, which 0042 now stops being started automatically. | Accepted until 0041 | 0041 removes local folder windows. |
| — | Residual | mixed workspaces | The guard is per window: a tab window whose workspace also held a `file:` folder would run that folder's automatic tasks locally. The Tab Manager closes multi-root and workspace-file windows; noted for 0041's design. | Accepted | |
