# Restart Extension Host re-resolves a managed (`seclab+`) authority

- **Status:** accepted
- **Date:** 2026-11-09
- **Deciders:** Coordinator (chose option A, "Fix 1 only, for now"; recorded B for later; patch
  number 0040 in the fork-build range). Fork-build session: diagnosis and implementation.
- **Related:** [egress prompts](20261106-egress-prompts.md) (B3c part 4, where this was found),
  [ARCHITECTURE §4.2](../ARCHITECTURE.md) (the Tab Manager's managed resolver)

## Context

After **Developer: Restart Extension Host** in a `seclab+` window, the window stays
disconnected. The renderer logs "No socket factory found for Managed(1)" five times, then a
permanent error, and the remote extension host never starts.

The cause is in upstream, at the pinned commit
[a717861](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/services/extensions/common/abstractExtensionService.ts#L960-L976):

1. `startExtensionHosts` stops every extension host, local and remote, then starts them again.
2. A `ManagedResolvedAuthority`'s socket factory is registered by the local extension host that
   ran the resolver (the Tab Manager). It stops with that host.
3. The resolution stays cached in the resolver service
   ([electron-browser `getConnectionData`](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/remote/electron-browser/remoteAuthorityResolverService.ts#L58-L71)),
   so the new remote extension host connects through `Managed(1)` straight away. No factory
   exists by that id in the new local host.

Separately, the restart also ends tabd's stdio, since tabd is a child of the old local host.
tabd treats that as client-gone and stops the tab and its REH. So even with the resolver fixed,
the new Tab Manager starts a fresh tabd and the tab restarts.

## Decision

**Option A: Fix 1 only.** Patch
[`0040-reresolve-managed-authority-on-restart.patch`](../../patches/0040-reresolve-managed-authority-on-restart.patch),
in `AbstractExtensionService.startExtensionHosts`:

- Before stopping the hosts, note whether the window's authority resolved to a
  `RemoteConnectionType.Managed` connection. WebSocket authorities keep upstream's behaviour.
- After the stop, `_clearResolvedAuthority`. A remote host that starts now waits on a fresh
  pending request (`resolveAuthority` makes a new `DeferredPromise`).
- Once the new local hosts are ready, run the resolver again through them and
  `_setResolvedAuthority` (or `_setResolvedAuthorityError`). This completes the request the
  remote host is waiting on.
- It deliberately does not call `_resolveAuthorityAgain`: that clears again first, which
  cancels the request the remote host is already waiting on.
- Overlapping restarts (review [OOO-1](../security-reviews/20261109-ext-host-restart-reresolve.md)):
  the managed authority is remembered once seen, so a second restart that finds it already
  cleared still re-resolves. Each restart takes a generation number, and only the newest one
  completes the request; an older resolution went through a stopped host and is dropped.

After a restart the Tab Manager resolves the tab again: tabd restarts the tab, and the remote
extension host connects to the new REH, so extensions run in the tab again. The window's
management connection still belongs to the old REH, which tabd stopped, so the window reports
"Cannot reconnect. Please reload the window." Editor state that lived in the old REH (terminals,
running tasks) is lost. This is the same as when the REH dies, and a window reload is the
recovery. Option B is what would make this seamless.

## Considered for later: option B, a seamless handover

Fix 1, plus a tabd grace period on client EOF. On stdin EOF tabd releases its leases and keeps
its tabs running, and keeps monitoring them, for about 20 s. The new local host's tabd adopts
them (B3c's `reattachBroker` and the `ensureRunning` fast path). The old tabd then stops only
the tabs that no one took. SIGTERM and editor quit still stop tabs immediately.

It was not taken now because Restart Extension Host is rare and option A already matches
server-death behaviour. B adds a new lifecycle state, a tab outliving its client with two tabd
processes overlapping, which brings its own races and its own review surface. The user may
still ask for it.

## Consequences

- One more core patch in the fork-build range (0040–0049). It applies only to the workbench's
  extension service. It changes nothing for windows whose authority isn't `Managed`, and
  nothing for local windows (no remote authority).
- `patches/series` now lists every reserved number range, and `build/apply-patches.sh` fails if
  two patches share a number. This runs in `patch-build` and in `prepare.sh`.
- Proof: the focus battery's `restart-extension-host` step, which is no longer terminal: the
  battery must reach `done`, which only a remote extension host started after the restart can
  mark. Branch build 42728084476 (`db27c77`), every other step skipped: `step 10
  restart-extension-host`, then `activate at step 11` and `done` five seconds later, no focus
  steal, and teardown clean. On build 42707557651, without the patch, the extension never came
  back ([egress prompts](20261106-egress-prompts.md), B3c part 4).
- Requirement for the RPC series (review [OOO-2](../security-reviews/20261109-ext-host-restart-reresolve.md)):
  until the filter lands, tab code can run `workbench.action.restartExtensionHost` and the
  extension install/uninstall commands through `$executeCommand`. Each restart now runs the
  Tab Manager's resolver again, so a tab could repeat its prompts. The filter should deny those
  commands to `seclab+` callers.
