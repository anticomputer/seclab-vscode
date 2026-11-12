# Core patch queue

`NNNN-short-concern.patch` files, applied with `git apply` by
`build/apply-patches.sh` (called by `build/prepare.sh`) **in the order listed in
[`series`](series)** against the commit in `upstream.lock`.
- A patch that doesn't apply fails the build.
- Any file here not listed in `series` (other than this README) fails the build, so a
  test-only patch can't ship by being dropped in the directory
  ([EDR](../docs/edr/20261104-patch-series.md)).
- Test-only hooks never go here; they belong to the test harness.
- `build/apply-patches.sh --check` validates the queue without a checkout (CI).
- The required `patch-build` check applies the series to the pinned upstream, type-checks the
  patched tree with upstream's `typecheck-client`, and requires every patched file to be
  reachable from the desktop build or the REH ([EDR](../docs/edr/20261105-patch-build-gate.md)).
  To see where a file lands: `node build/check-patch-reach.ts PATCHED_TREE --file src/...`.
  To require targets for a security patch, add it to `reach.json`
  (`{ "NNNN-name.patch": ["desktop", "server"] }`).

Rules ([ADR](../docs/adr/20261104-vscodium-style-fork.md)):
- One concern per patch, under about 50 lines.
- Write an EDR (or ADR, if it changes the design) for each patch, and run a
  security review on each new or changed patch.
- Policy that can be expressed in `product.json` goes in
  `build/product/overrides.json`, not here.

Current queue:
- `0001-build-skip-copilot-shim-without-extension.patch`: build only; the
  built-in Copilot extension is removed ([EDR](../docs/edr/20261104-remove-builtin-copilot.md)).
- `0002-extensionkind-product-default.patch`: `extensionKind["*"]` default, so
  every non-built-in extension runs in the tab. Explicit entries apply only to
  scanned system extensions, and the user setting can't override it
  ([ADR](../docs/adr/20261104-extension-placement-hardening.md)).
- `0003-no-workspace-extensions-in-local-windows.patch`: windows without a
  remote run only `ui`-kind (built-in) extensions.
- `0004-extension-description-computed-fields-win.patch`: a `package.json`
  can't override computed description fields such as `isBuiltin`.
- `0012-background-windows-env.patch`: with `SECLAB_BACKGROUND_WINDOWS=1` in the main
  process's launch environment, windows open inactive and nothing focuses or activates the app:
  the bootstrap (`mainImpl.ts`) makes the app background-only before AppKit finishes launching,
  so even a directly exec'd launch (the headless driver's) never activates
  ([EDR](../docs/edr/20261112-headless-driver.md));
  guarded call sites, plus a main-process guard over Electron's own activating paths (`show`,
  `focus`, `webContents.focus`, parentless dialogs)
  ([EDR](../docs/edr/20261105-background-windows.md)). It grants nothing; it only withholds
  focus, which is why it isn't a test hook in the sense below. (0005-0011 are reserved for
  the RPC filter series.)
- `0013-no-local-agent-host.patch`: Electron main creates no agent-host starter or process
  manager, and every window's connection request gets a fatal refusal. The shared process
  registers no SSH, dev-container, WSL or tunnel agent-host provider. So no agent runtime ever
  runs on the host (invariant I8, [EDR](../docs/edr/20261105-no-agent-runtime-on-host.md)).
- `0014-build-desktop-without-copilot-runtime.patch`: build only. The desktop app packages
  no `@github/copilot-sdk` or platform runtime (`runtime.node`), and no `agentHostMain`
  bundle. The REH keeps both for tabs. `build/check-release.sh --desktop` fails a desktop
  build that contains a runtime, and `unreachable.json` (below) fails one that reaches
  agent-host code (same EDR).
  0015 onwards: the secure-agentic-experiences series.
- `0015-seclab-ahp-gate.patch`: in a `seclab+` window the workbench's agent-host transport is
  built over a filtered channel (default-deny verdict tables pinned by type to upstream's
  protocol), the protocol client refuses any ungated transport, and with
  `seclab.agents.enabled` off (the default) no connection is made. Decisions go to the window's
  `seclabAhpGate.log`. New files are edited in `agentic/patch-src` and synced with
  `node agentic/tools/sync-patch.ts --write`
  ([EDR](../docs/edr/20261106-agentic-probe-runner.md), [plan](../docs/plans/agentic-implementation.md) increment 1).
- `0035-seclab-document-sync-provenance.patch`: in a `seclab+` window, a non-local extension host
  is sent a text model only if it owns it:
  - a file on the window's own tab authority;
  - a model its own content provider created (tagged per model, untagged by any other write);
  - a text file born under a filesystem provider it registered;
  - an untitled document it created, or that the user typed;
  - a notebook cell whose notebook is on the tab authority.

  Host settings, output and files opened in a tab window no longer reach the tab. Change, dirty,
  saved and encoding events use the same filter
  ([EDR](../docs/edr/20261109-document-sync-provenance.md)). (0030-0034 are reserved for the RPC
  sessions.)
- `0040-reresolve-managed-authority-on-restart.patch`: after Restart Extension Host, a window
  whose authority resolved to a managed connection (`seclab+`) resolves it again through the
  new local extension host before the remote one connects. Without it, the remote host reuses
  the old socket factory id and fails with "No socket factory found"
  ([EDR](../docs/edr/20261109-ext-host-restart-reresolve.md)).
- `0041-route-local-folder-opens-to-tabs.patch`: no window ever loads a local folder or
  workspace. `WindowsMainService.open`, which every open path reaches (CLI, menus, recents,
  drag and drop, `<urlProtocol>://file` links, session restore), replaces each one with an empty
  window and hands it to the Tab Manager as a trusted `<urlProtocol>://seclab.tab-manager/open`
  URL; the Tab Manager confirms, claims and opens it as a tab. Every workspace file is routed
  (a tab doesn't support multi-root), and no window enters a workspace (Add Folder). Enabled by
  product.json `seclabTabRouter`, a build invariant and a release check
  ([ADR](../docs/adr/20261104-route-folder-opens-in-main.md),
  [EDR](../docs/edr/20261112-main-process-routing.md)).
- `0042-no-automatic-tasks-in-local-windows.patch` (interim): a window with no remote authority
  neither runs `folderOpen` tasks nor asks to allow them. A local folder window exists only for
  the moment before the Tab Manager reopens it as a tab. Removed when 0041 routes folder opens
  in the main process ([ADR](../docs/adr/20261104-route-folder-opens-in-main.md)).

Number ranges are reserved per owner; the header of `series` lists them, and
`build/apply-patches.sh` fails if two patches share a number.

`reach.json` requires targets per patch. `unreachable.json` lists modules, or `dir/` prefixes
with explicit exceptions, that a target must not reach. Both are enforced by `build/check-patch-reach.ts` in the required `patch-build` check.

Test-only patches are **not** kept here. `build/prepare.sh` applies this
directory unconditionally, so a fixture placed here would ship in release
builds. The rogue-REH hook lives at
`test/containment/rogue-reh/serverServices-hook.patch` and is applied by the
containment harness for a dedicated probe build
([EDR](../docs/edr/20261104-rpc-escape-probes.md)).

Expected later patches (M4): the RPC capability filter, auth mediation,
partitioning, webview egress, and main-process folder routing (proposed).
