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
- `0017-seclab-fixed-tab-settings.patch`: in a `seclab+` window four agent-policy settings a
  tab can otherwise write through the REH's remote user settings get fixed values:
  `chat.automations.enabled` and `chat.automations.cloud.enabled` are `false`,
  `workbench.browser.enableRemoteProxy` is `true` and `workbench.browser.dataStorage` is
  `ephemeral`. The read is fixed in `getValue`, `inspect` and `getConfigurationData` (the
  snapshot the extension hosts read from); no registration is changed. The two browser keys
  are one control: the proxy keeps a browser view's traffic on the tab's network, and the
  storage scope stops a tab removing that network by asking for `global`
  ([EDR](../docs/edr/20261106-increment-2-remote-proxy.md), [plan](../docs/plans/agentic-implementation.md) increment 2).
- `0035-seclab-document-sync-provenance.patch`: in a `seclab+` window, a non-local extension host
  is sent a text model only if it owns it:
  - a file on the window's own tab authority;
  - a model its own content provider created (tagged per model, untagged by any other write);
  - a text file born under a filesystem provider it registered;
  - an untitled document it created, or that the user typed;
  - a notebook cell whose notebook is on the tab authority.

  Host settings, output and files opened in a tab window no longer reach the tab. Change, dirty,
  saved and encoding events use the same filter
  ([EDR](../docs/edr/20261109-document-sync-provenance.md)). (0030-0034 and 0050-0059 are reserved for the RPC
  sessions.)
- `0036-seclab-tab-configuration-snapshot.patch`: in a `seclab+` window, a non-local extension host
  receives a cut-down configuration snapshot:
  - host-wide `application` settings never cross;
  - a key whose name, or any key name inside its value, names a credential, or whose strings
    gitleaks' pinned default rules call a secret, is withheld whatever the registry says;
  - of the rest, host user, policy and local-workspace settings cross only for keys registered by
    core (not application, machine or `restricted`); a key an extension declares never receives a
    host value, so extensions in a tab read their settings from the tab's own settings.

  Every change event is refiltered. Withheld user-settings keys are reported by name to the Tab
  Manager over the window's local extension host. The shared classifier and rule table are edited
  in `build/secret-rules/src` and synced with `node build/secret-rules/sync-patch.ts --write`
  ([EDR](../docs/edr/20261112-tab-configuration-snapshot.md)).
- `0038-seclab-editor-tab-provenance.patch`: in a `seclab+` window, a non-local extension host's
  editor-tab model shows host-side editors only as present: an opaque id (a salted hash), an
  unknown input and the label `Editor`. An editor is the tab's own when it shows a resource and
  every resource is on this window's tab authority, a webview panel's or terminal's own id, or a
  model 0035 would sync to this host. Local hosts and other windows are unchanged
  ([EDR](../docs/edr/20261116-editor-tab-provenance.md)).
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
  [EDR](../docs/edr/20261112-main-process-routing.md)). It replaced the interim patch 0042 (no
  automatic tasks in a local window), which is removed: no local window has a folder.

Number ranges are reserved per owner; the header of `series` lists them, and
`build/apply-patches.sh` fails if two patches share a number.

`reach.json` requires targets per patch. `unreachable.json` lists modules, or `dir/` prefixes
with explicit exceptions, that a target must not reach. Both are enforced by `build/check-patch-reach.ts` in the required `patch-build` check.

- `0005-seclab-rpc-capability-filter.patch`: the RPC choke point in
  `rpcProtocol.ts` plus the filter module and its generated policy. The module
  carries the logic for all three enforcement points; 0006 and 0007 only wire
  the other two in, so each core file is touched by exactly one patch
  ([ADR](../docs/adr/20261104-rpc-filter-enforcement-points.md)).
- `0006-seclab-channel-guard.patch`: `ipc.ts`, plus one line in the REH's `createServer`.
  Guards the channels the client serves to a hostile REH, on `ChannelServer` rather than a
  wrapper a caller can bypass, and refuses a tab context while no guard is installed. The
  REH serves the trusted client over the same class with the same `seclab+` context, and runs
  inside the tab where there is nothing to guard, so it installs an explicit allow-all guard
  first thing; without it a patched REH refused every management call and no tab got an
  extension host. `reach.json` pins the patch to the REH (`server`), and desktop may not reach
  `src/vs/server/` (`unreachable.json`).
- `0007-seclab-command-taint.patch`: `commandService.ts` only. Tab-originated
  commands carry the tab identity into everything they trigger
  ([ADR](../docs/adr/20261104-tab-command-taint.md)).
- `0032-seclab-partition-tab-extension-state.patch`: `mainThreadStorage.ts` and
  `mainThreadSecretState.ts`. A tab's `globalState`, `workspaceState` and `SecretStorage` live
  in a partition keyed on the tab's stable id from the connection (`seclab-tab:<tabId>/<id>`,
  `{seclabTab, extensionId, key}`), storage migration is off for tab hosts, and each customer
  registers its rewrite with the filter, which permits those methods only once registered.
  Whatever extension id a tab claims, it addresses only its own partition
  ([ADR addendum](../docs/adr/20261106-tab-state-partition.md)).
- `0033-seclab-sanitise-tab-provider-results.patch`: `mainThreadLanguageFeatures.ts`. A tab's
  hover contents and completion items (command, documentation, on first result and on resolve)
  pass through `seclabFromTab` before the UI sees them, and a selector without a scheme
  matches only the tab's `vscode-remote` documents
  ([ADR](../docs/adr/20261116-response-side-control.md)).
- `0030-seclab-no-remote-cli-push-in-tabs.patch`: `remoteTerminalBackend.ts`. In a tab
  window upstream's `onExecuteCommand` handler, which runs a command the REH names, is never
  registered. A refusing handler answers each push at once with an error, touches no command
  service, and logs the policy key through the filter's decision log (`seclabRefusePush`).
- `0031-seclab-no-variable-resolution-for-tab-pty-hosts.patch`: `baseTerminalBackend.ts`, and
  the remote backend passes its authority. In a tab window upstream's variable resolver for
  pty-host requests, which resolves `${env:…}` over the host user's shell environment, is
  never registered. A refusing handler answers at once with the text unresolved and logs the
  policy key. The local backend passes no authority and keeps upstream's resolver.
- `0034-seclab-no-host-variables-for-tab-terminals.patch`: `remoteTerminalChannel.ts`,
  `terminalProfileResolverService.ts` and `terminalProcessManager.ts`. A tab's REH supplies its
  default shell and profiles, so in a tab window the window resolves no host variables for them:
  `createProcess` sends no `${config:…}`, `selectedText` or `lineNumber` values, and a profile's
  path, arguments and `env` resolve only `${env:…}`, against the REH's own environment. Both
  resolvers key on the window's authority (review findings RFU-1, RFU1R-1).
- `0050-seclab-no-host-terminal-in-tabs.patch`: `terminalNativeContribution.ts`, both
  `externalTerminal.contribution.ts` files and `terminalProcessManager.ts`. A tab window offers and
  starts no host terminal (project owner decision 2026-11-16,
  [ADR](../docs/adr/20261116-no-host-terminal-in-tabs.md)): "Create New Integrated Terminal
  (Local)" isn't registered, "Open New External Terminal" is hidden from the palette and
  keybinding (`remoteName != seclab`) and its handler returns, the Explorer's "Open in …
  Terminal" items are hidden for host (`file:`) folders, and `terminalProcessManager` refuses any
  pty outside the window's own tab. Applies after 0034, which edits the same file.
- `0051-seclab-sanitise-tab-search-responses.patch`: `mainThreadSearch.ts`. What a tab's search
  provider returns reaches the Search view only through `seclabFromTab`: its completion messages
  become untrusted, bounded plain text, and open editors outside the tab's file system are
  dropped from the query the tab is sent (reviews SRCH-2, SRCH-3;
  [EDR](../docs/edr/20261117-search-in-tabs.md)).
- `0052-seclab-split-large-text-matches.patch`: `textSearchManager.ts`. The extension host sends
  one file's text matches in pieces of at most the RPC filter's bound (`MAX_TEXT_MATCHES`); the
  window merges matches for one resource. Upstream batched whole files, so a file with more
  matching lines had its whole batch refused in a tab (PR review on #52).
- `0059-seclab-tab-server-environment-stays-in-the-tab.patch`: `remoteAgentEnvironmentChannel.ts`,
  `abstractRemoteAgentService.ts`, `remoteUserDataProfiles.ts`, `remoteFileSystemProviderClient.ts`,
  `remoteExtensionsScanner.ts`, `extensionManagementServerService.ts`, `nativeExtensionManagementService.ts`,
  `remoteExtensionManagementService.ts`, `remote.contribution.ts`, `nativeMcpRemoteDiscovery.ts`,
  `mcpCopilotGlobalConfigurationService.ts`, `mcpWorkbenchManagementService.ts`, `extensionsWorkbenchService.ts`,
  `extensionsActions.ts`, `extensionManagementService.ts`, `extensionEnablementService.ts`,
  `unsupportedExtensionsMigrationContribution.ts`, `localization.contribution.ts`,
  `extensionGalleryManifestService.ts`, `extensionsResource.ts`, `extensions.contribution.ts`,
  `extensionBisect.ts`, `userDataProfileImportExportService.ts`, `workingCopyHistoryService.ts`, `abstractExtensionService.ts`, `workbench.common.main.ts`, and on the server `extensionManagementIpc.ts` and `mcpManagementIpc.ts`, whose install replies go out as the client's URIs like their other replies. A tab's server names where the window keeps that tab's settings,
  storage, logs, profiles and extensions. In a tab window every such location must be `vscode-remote`
  on the window's own authority, and is rebuilt from its components (`seclabTabUris` in the filter
  module); none may be left out, and local history doesn't fall back to the host's. That covers the `getEnvironmentData` reply, the profiles, logger, extension management and MCP
  management channels' replies and events (URI-shaped values; MCP servers also lose their icon and links, and extension and MCP install events and `installGalleryExtensions` replies their gallery entry), MCP discovery, file change events and scanned extensions. Install events from the
  tab lose any gallery entry; the host never installs a package from the tab's file system or from
  the tab's workspace folders, nor any extension a tab names from the gallery ("Install Locally",
  "Install Remote Extensions Locally", or an update or uninstall a tab language-pack manifest fans
  out to the host), nor the packs and dependencies a tab
  extension's manifest names, and the window doesn't retry installs the tab's server reports failed
  (`host-install`). Behind all of those, a tab window's channel to the host's own extension
  management is read-only (`seclabHostExtensionsChannel`), the host's global enablement is
  read-only (`SeclabGlobalExtensionEnablementService`, logged `host-enablement`), it skips the
  unsupported-extensions migration and the display-language prompt on the tab's install events,
  sends the tab's server no marketplace token and keeps no publisher trust (reviews ENV-28 to ENV-38).
  A foreign location refuses the environment or reply,
  or drops the event or extension, and logs `data:server-locations`. A refused environment stays a
  failure rather than reading as "no remote", whose callers fall back to host locations. Upstream
  trusted all of it, so a server naming the host user's settings file had the window read it as the
  tab's settings and write the tab's settings into it (reviews R5-17, ENV-1 to ENV-51, PR66-1 to PR66-3;
  [EDR](../docs/edr/20261118-tab-server-environment.md)).
- `0060-seclab-no-host-search-excludes-in-tabs.patch`: `seclabTabSettings.ts` (new),
  `queryBuilder.ts`, `explorerViewer.ts`, `searchChatContext.ts`, `promptFilesLocator.ts`,
  `sessionsTelemetry.contribution.ts`, `workspaceWatcher.ts` and 0036's
  `seclabConfigurationSnapshot.ts`. The host user's exclude, watcher and read-only patterns never
  reach a tab: for a folder on a tab, the settings part of every search query and watch request
  comes from the defaults, the tab's remote user settings and the folder's own settings (a
  caller's own patterns are untouched), and the snapshot never lets their host values cross.
  Applies after 0036
  (review SRCH-3; project owner, 2026-11-18; [EDR](../docs/edr/20261118-host-search-excludes.md)).
- `0061-seclab-no-tab-auto-replies-on-the-local-pty-host.patch`: `localTerminalBackend.ts` and
  `remoteTerminalBackend.ts`. In a tab window the local backend installs no terminal auto reply,
  whoever asks: every window registers it, its pty host is shared by every window and applies each
  reply to all its terminals, and a tab window's settings include those the tab's server serves,
  so a tab could type a command into a normal window's local shell (review R5-32, a high on main).
  The tab's own backend installs only pairs in the tab's own settings (0060's rule), never the host
  user's (review AR-5; [EDR](../docs/edr/20261119-tab-auto-replies.md)).
- `0053-seclab-no-host-terminal-settings-for-tabs.patch`: a new
  `contrib/terminal/common/seclabTabTerminalSettings.ts`, `remoteTerminalChannel.ts`,
  `terminalProfileService.ts`, both `terminalProfileResolverService.ts` files and
  `mainThreadTerminalService.ts`. In a tab window the restricted terminal settings come only from
  the layers the tab owns: defaults, the REH's remote user settings, and the workspace's only when
  it is the tab's own (0036's test). Upstream's recursive merge is kept. That covers:
  - `env.<os>` and `cwd` in `createProcess`;
  - `profiles.<os>` in `getProfiles`;
  - `defaultProfile.<os>`, which also picks among the profiles the REH returns, so a host value
    could be confirmed by guessing;
  - the automation and agent-host profiles, which reach the tab's extension host in
    `$acceptDefaultProfile`.

  The window's own extension host is sent no default profile there. The resolver reads the
  window's authority from the environment, not the connection. Patch 0036 already withholds the
  host user's values of these from the tab's extension host (reviews DOCSYNC-R5, RFU1R-2,
  RFU1R2-1, R5-1, R5-3, R5-5, R5-10, R5-13;
  [EDR](../docs/edr/20261118-tab-terminal-settings.md)).
- `0054-seclab-tab-own-terminal-env-collections.patch`: `environmentVariableService.ts` and
  `mainThreadTerminalService.ts`. In a tab window each extension host gets only the environment
  variable collections it set itself (upstream filtered only other origins' `PATH` entries), and a
  tab can't replace or delete a collection another host set under the same id; the window's own
  extension host can (reviews DOCSYNC-R5, R5-8, R5-11).
- `0055-seclab-no-host-file-path-to-tab-terminals.patch`: `remoteTerminalChannel.ts`. In a tab
  window the REH is told only the tab's own folders, active folder and active file, a workspace
  label only from them, and, for a workspace that isn't the tab's own, a workspace id derived from
  the tab rather than a host path; a detach request naming another window's workspace is refused
  without reaching the REH (reviews RFU1R-3, R5-2, R5-12, R5-16). Applies after 0053, whose
  helper it uses.
- `0056-seclab-no-foreign-terminal-icons-in-tabs.patch`: `terminalProfileResolverService.ts`. In a
  tab window a terminal's image icon is kept only if it is on the tab's own file system; anything
  else becomes a codicon. A REH's profiles or the tab's settings could otherwise name any `https`
  image, which the trusted window fetches past the tab's broker (review R5-9).
- `0057-seclab-tab-profile-writes-stay-in-the-tab.patch`: `terminalProfileQuickpick.ts`. In a tab
  window "Select Default Profile" and saving a detected profile write the tab's own (remote) user
  settings, and extend only the tab's own profiles. Upstream wrote the REH's profile (path, args,
  `env`) into the host user's settings, where a normal window's next terminal would run it
  (review R5-14, a high on main).
- `0058-seclab-plain-text-terminal-profile-descriptions.patch`: `platform/terminal/common/terminalProfiles.ts`.
  The Settings editor renders terminal profile descriptions as markdown; their text is now escaped
  and their icon must be a codicon id, so a REH's profile or a tab extension's contributed
  profile can't make the trusted window fetch an image (review R5-15). Applies in every window.

Test-only patches are **not** kept here. `build/prepare.sh` applies this
directory unconditionally, so a fixture placed here would ship in release
builds. The rogue-REH hook lives at
`test/containment/rogue-reh/serverServices-hook.patch`, and only the `containment` test build
variant applies it (`test/builds/variants.json`,
[EDR](../docs/edr/20261106-test-build-variants.md)); `check-release` refuses any artifact
carrying it.

Expected later patches (M4): the RPC capability filter, auth mediation,
partitioning, webview egress, and main-process folder routing (proposed).
