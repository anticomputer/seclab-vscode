# VS Code / Code‑OSS Internals for a Browser‑Style Containment Fork

**Scope note:** All `microsoft/vscode` citations are pinned to commit `881999100739fef36236fe0b93fedc9b730f94a9` (fetched 2026‑11‑04). All `VSCodium/vscodium` citations are pinned to `ca7f7b44b5e5c3faa663f6cdc043998f71936653`. Docs citations are to the live `code.visualstudio.com` pages (undated/versionless by design). Where I infer rather than directly verify, it's flagged **[inference]**.

The single most load‑bearing fact for this whole project, stated by Microsoft itself:

> "The extension host is responsible for running extensions in VS Code. The extension host has the same permissions as VS Code itself. This means that any action that VS Code can perform, an extension can also perform through the extension host." — https://code.visualstudio.com/docs/configure/extensions/extension-runtime-security

Everything below is about where that statement is implemented in code, and where a fork can insert a boundary without touching the front end.

---

## 1. Process model

| Process | Spawns extension code? | Privilege level |
|---|---|---|
| Electron **main** process | No | Full OS user privileges; owns windows, native menus, filesystem, child‑process spawning. |
| **Renderer/workbench** (per window) | No (UI only) | Chromium renderer **sandboxed since ~1.82 (Oct 2023)**: `sandbox: true` in `BrowserWindow` webPreferences. No direct Node.js access from workbench JS; all privileged ops go through main-process IPC. |
| **Shared process** | No | Runs background singletons (extension gallery, telemetry, some file watching); full Node, one per app instance, not per window. |
| **Utility processes** | **Yes** — this is how local extension hosts, pty host, file watcher, etc. are now spawned | Plain OS‑level Node.js process privileges (same as the logged‑in user); Electron's `utilityProcess.fork()` isolates them from Chromium/Electron APIs and from each other's crashes, but it is **not an OS sandbox** (no seccomp/AppContainer/landlock applied by VS Code itself). |
| **Pty host** | No (hosts terminal shells, not extensions) | Full user privileges — it execs the user's shell. |
| **File watcher** | No | Full user privileges, runs as a utility process. |
| **Local (Node.js) extension host(s)** | **Yes** | Full OS user privileges — same as the human user running VS Code. No seccomp/AppArmor/containerization by default. |
| **Web‑worker extension host** | **Yes**, for `web`‑kind extensions | Browser Web Worker sandbox (Chromium's JS sandbox) — much more restricted than the Node hosts, no filesystem/process access except via RPC back to the main thread. |
| **Remote extension host** | **Yes** | Full privileges *of the remote machine/container*, scoped only by whatever OS/VM/container boundary the remote host happens to be running in — VS Code doesn't add anything beyond that. |

Key evidence:

- Renderer sandbox flag: `defaultBrowserWindowOptions()` sets `sandbox: true` in `webPreferences` —
  https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/platform/windows/electron-main/windows.ts#L147-L175
- Extension hosts (and pty host, file watcher, etc.) are spawned via Electron's `utilityProcess.fork()`, a plain Node process, not a Chromium‑sandboxed one:
  https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/platform/utilityProcess/electron-main/utilityProcess.ts#L238-L267
- `ExtensionHostStarter` (electron‑main) creates a `WindowUtilityProcess` per local extension host and forks `vs/workbench/api/node/extensionHostProcess`:
  https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/platform/extensions/electron-main/extensionHostStarter.ts#L72-L129
- `LocalProcessExtensionHost` (electron‑browser) builds the fork options (`execArgv`, inspect flags, env) that get handed to the starter:
  https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/services/extensions/electron-browser/localProcessExtensionHost.ts#L225-L284
- The three logical "extension host kinds" (`LocalProcess`, `LocalWebWorker`, `Remote`) are defined as an enum, confirming there is no fourth, more-restricted kind today:
  https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/services/extensions/common/extensionHostKind.ts#L9-L13
- Official statement that the extension host == VS Code's own permission level: https://code.visualstudio.com/docs/configure/extensions/extension-runtime-security (see "About extension runtime permissions")
- Background on the sandboxed renderer rollout: https://code.visualstudio.com/blogs/2022/11/28/vscode-sandbox (official blog, cited for context — not independently re‑verified line‑by‑line here).

**Takeaway for the fork:** there is no existing per‑extension or per‑window OS sandbox anywhere in this matrix. The closest thing to a privilege *boundary* (not just a process boundary) is the **remote extension host**, because it can be made to run on a different machine/VM/container than the renderer. That's the seam to exploit (see §3 and Implications).

---

## 2. Extension host multiplicity

**Not strictly one host per window.** Per window you can have up to three concurrent extension hosts simultaneously: one `LocalProcess` host, one `LocalWebWorker` host, and one `Remote` host (if connected) — plus **additional** `LocalProcess` hosts if `extensions.experimental.affinity` groups extensions apart. All are owned/orchestrated per-window by an `ExtensionHostManager`/`ExtensionHostManagers` registry tied to that window's workbench instance:
https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/services/extensions/common/extensionHostManager.ts#L58-L130

### `extensionKind` (`ui` / `workspace` / `web`)
Declared in an extension's `package.json`, or deduced if absent. Deduction rule: if the extension has a `main` (Node) entry point, it defaults to `workspace`; `browser`-only entries get `web`; extensions with neither (themes, grammars, keymaps) are unrestricted:
https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/services/extensions/common/extensionManifestPropertiesService.ts#L411-L421

This default matters enormously: **most non‑trivial extensions (anything with real Node code) are `workspace`‑kind by default**, not `ui`.

### Placement algorithm
`BrowserExtensionHostKindPicker.pickRunningLocation()` is the actual placement decision function:
https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/services/extensions/browser/extensionService.ts#L319-L358

Key logic (verbatim behavior):
- `workspace` kind + a remote connection exists → **runs remotely** (preferred, not "last resort").
- `ui` kind + a remote connection exists → runs **locally** unless no local host is available, in which case it falls back to remote ("but only as a last resort" per the inline comment).
- `web` kind → runs in the local web‑worker host if present.

This is the mechanism that, combined with §6's `product.json` overrides, lets a fork force almost all extension code onto a remote/contained host while leaving the UI untouched.

### `remote.extensionKind` setting
User/workspace‑configurable override of an extension's declared kind, read here:
https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/services/extensions/common/extensionManifestPropertiesService.ts#L328-L337
(`this.configurationService.getValue<...>('remote.extensionKind')`). It's layered under `product.json`'s `extensionKind` and above the manifest's own declared/deduced kind (see §6 for precedence).

### `extensions.experimental.affinity`
A `{ [extensionId]: positiveInteger }` map. Extensions sharing the same configured integer get grouped into the same *additional* `LocalProcess` extension host; different integers get different host processes. Implementation:
https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/services/extensions/common/extensionRunningLocationTracker.ts#L125-L221
(reads the setting at L167, builds affinity groups → distinct `LocalProcess` host instances at initial allocation).

**Could per‑extension processes be an off‑the‑shelf isolation hook?** Partially, with real limits:
- It's explicitly labeled `experimental`, gates on a proposed API (`extensionAffinity`) that the *extension itself* must declare it uses (`isProposedApiEnabled(extension, 'extensionAffinity')`, same file L130‑131) — so a hostile extension can simply not declare it and stay colocated with others, or a fork can force it via `extensionEnabledApiProposals` + a product.json-level affinity assignment [inference: forcing affinity per‑extension via product.json override, not just user setting, would need a small patch since today it's keyed off a `configuration` value, not a product.json field].
- Reallocation only happens "when there are no running extension hosts yet" (comment at L197 in extensionRunningLocationTracker.ts: "Ignoring configured affinity ... because extension host(s) are already running. Reload window.") — changing it requires a window reload.
- It only changes **which Node process** an extension's code runs in; all such processes still have full, equal, unsandboxed OS user privileges. It buys *crash/hang isolation* and *RPC-level separation*, not a security boundary. There is no OS-level ACL, seccomp filter, or namespace applied per affinity group anywhere in this code path.

---

## 3. Remote architecture (REH, resolvers, managed connections)

### Build targets
`build/gulpfile.reh.ts` defines the Remote Extension Host server build. Targets are generated programmatically as `vscode-reh-<platform>-<arch>` and `vscode-reh-web-<platform>-<arch>` for `BUILD_TARGETS` (win32/darwin/linux/alpine × x64/arm64):
https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/build/gulpfile.reh.ts#L46-L56 (targets list)
https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/build/gulpfile.reh.ts#L538-L576 (task generation loop: `['reh','reh-web'].forEach(type => ...)`, `destinationFolderName = vscode-${type}${platform}${arch}`)

This is Microsoft's own build of the "VS Code Server" binary (what ships as `vscode-server` for Remote‑SSH/Codespaces/openvscode‑server/code‑server are all variants of this same `vscode-reh-*` output).

### Server CLI / connection token
`ServerConnectionToken` enforces a shared secret for any client connecting to the REH listener: `None` (explicitly disabled, insecure), or `Mandatory` with a value from `--connection-token`, a file, or auto‑generated and persisted to `<user-data-dir>/token` (mode `0o600`):
https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/server/node/serverConnectionToken.ts#L92-L120
Validated against either a query param or cookie on every HTTP request:
https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/server/node/serverConnectionToken.ts#L122-L132

### Remote authority resolver proposed API
Internal (platform) types:
https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/platform/remote/common/remoteAuthorityResolver.ts#L47-L97 (`ResolvedAuthority`, `ResolverResult`, `RemoteAuthorityResolverErrorCode`)

Public proposed‑API surface extensions implement (`vscode.proposed.resolvers.d.ts`):
- `ResolvedAuthority` (host/port/token): https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vscode-dts/vscode.proposed.resolvers.d.ts#L27-L32
- `ManagedResolvedAuthority` / `ManagedMessagePassing` — lets a resolver hand VS Code a **message-channel** (`send`/`onDidReceiveMessage`/`onDidClose`) instead of a raw host:port, i.e. the resolver extension itself proxies all bytes (this is how Codespaces-style and potentially Docker-exec-style connections, with no open TCP port, work):
  https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vscode-dts/vscode.proposed.resolvers.d.ts#L37-L51
- `registerRemoteAuthorityResolver(authorityPrefix, resolver)`:
  https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vscode-dts/vscode.proposed.resolvers.d.ts#L456

Proposed APIs are gated by `product.json#extensionEnabledApiProposals`, enforced here:
https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/services/extensions/common/extensionsProposedApi.ts#L20-L48

### How forks enable it for a built‑in resolver extension
This is directly observable in VSCodium's shipped `product.json` (pinned `VSCodium/vscodium@ca7f7b44b5e5c3faa663f6cdc043998f71936653`):
```json
"jeanp413.open-remote-ssh": ["resolvers","tunnels","terminalDataWriteEvent",
                              "contribRemoteHelp","contribViewsRemote"],
"jeanp413.open-remote-wsl": ["resolvers","contribRemoteHelp","contribViewsRemote"]
```
https://github.com/VSCodium/vscodium/blob/ca7f7b44b5e5c3faa663f6cdc043998f71936653/product.json#L477-L489

This is the exact mechanism for your fork: ship your own built‑in resolver extension id in `extensionEnabledApiProposals` with `["resolvers"]` (plus whatever else it needs), declare the same `enabledApiProposals` in that extension's own `package.json`, and VS Code's gate in `extensionsProposedApi.ts` lets it call `registerRemoteAuthorityResolver`. No core patch required for this part.

**Gitpod openvscode-server / coder code-server / Positron** do the analogous thing: they ship their own `product.json` with their own `extensionsGallery` (Open VSX) and `extensionEnabledApiProposals` entries for whichever community/first‑party extensions they bundle. (Verified for VSCodium directly above; for openvscode‑server/code‑server/Positron this pattern is architecturally identical and well documented in their repos but I did not line‑by‑line diff their `product.json` files in this pass — **[inference, high confidence given shared codebase]**.)

### Licensing blocker for Microsoft's own Remote‑SSH / Dev Containers / VS Code Server
Microsoft's Remote Development extensions and the official VS Code Server binary are licensed under the "Visual Studio Code and Visual Studio Code for Web and Related Microsoft Offerings" EULA (`code.visualstudio.com/License/preview` family), which restricts their use to "validly licensed cop[ies] of Microsoft Visual Studio Code" — i.e., Microsoft's own branded builds, not MIT‑licensed Code‑OSS rebuilds like VSCodium or a custom fork. This is why VSCodium/code-server/Gitpod all ship community reimplementations (`open-remote-ssh`, their own REH packaging) instead of Microsoft's extensions. **[Sourced via web search summarizing the license text at `code.visualstudio.com/preview-license` — I was not able to fetch that exact license page directly in this session (404 on the path I tried); treat the precise wording as reported-secondhand, not independently re-verified against primary text.]** The underlying Code‑OSS *server source* in `microsoft/vscode` (the `vscode-reh-*` build targets above) is MIT‑licensed and freely rebuildable — only Microsoft's pre-built binary distribution and proprietary extensions are restricted.

---

## 4. What crosses the local↔remote boundary, and where a fork intercepts it

Every one of these is implemented as a `MainThread*` class (always instantiated in the **local** renderer/workbench process, registered with `@extHostNamedCustomer`) paired with an `ExtHost*` class (runs inside whichever extension host — local or remote — the calling extension lives in). The `ExtHost*` side only ever has a serialized RPC proxy; the `MainThread*` side holds the real resource. **For remote extensions, every one of these calls crosses the remote connection as an RPC message, is serviced by the `MainThread*` instance in the client/UI process, and the result crosses back.** This RPC boundary is the fork's single most reusable interception point.

| Capability | Runs/decides on | Main‑thread class (interception point) | Notes |
|---|---|---|---|
| `vscode.authentication` | Auth **providers** always run in the UI-side extension host (declared `extensionKind: ["ui","workspace"]` by the built-in `vscode.github-authentication` / `vscode.microsoft-authentication` extensions — see below); tokens are returned over RPC to whichever host (local or remote) asked. | `MainThreadAuthentication.$getSession` / `$getSessionsFromChallenges` | https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadAuthentication.ts#L553-L566 (plus `doGetSession` at L449-L479). A fork can wrap `$getSession`'s return value to substitute a surrogate token/short‑lived credential for remote callers while keeping the real token server‑side only. `trustedExtensionAuthAccess` in `product.json` already restricts *which* extension ids may silently obtain a session for a given provider id without a consent prompt: https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/base/common/product.ts#L195 |
| `context.secrets` (`SecretStorage`) | Physically: one encrypted blob per app instance, stored via OS keyring/keychain (macOS Keychain, Linux libsecret/kwallet, Windows DPAPI) through `IEncryptionService`, inside the local `IStorageService` application‑scope DB. Scoping is **string‑namespacing only**, not process isolation: key = `JSON.stringify({extensionId, key})`. | `MainThreadSecretState.$getPassword/$setPassword/$deletePassword/$getKeys` | https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadSecretState.ts#L38-L92 — the `getKey()` helper at L90-92 is exactly the namespacing logic. All extensions' secrets live in the *same* encrypted store; isolation is purely "the RPC call always carries the calling extension's id, trusted by convention." A fork wanting real per‑window/per‑sandbox secret isolation needs to replace this service (or key it additionally by window/workspace id) — see `BaseSecretStorageService`: https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/platform/secrets/common/secrets.ts#L101-L120. Native keyring binding: https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/services/secrets/electron-browser/secretStorageService.ts#L21-L39 |
| `env.openExternal` / `asExternalUri` | Local-only; decides via `IOpenerService` | `MainThreadWindow.$openUri` / `$asExternalUri` | https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadWindow.ts#L58-L78 |
| `env.clipboard` | Local-only; `IClipboardService` | `MainThreadClipboard.$readText/$writeText` | https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadClipboard.ts#L24-L33 |
| Port forwarding / tunnels | Tunnel creation request crosses from (possibly remote) extension → `MainThreadTunnelService` → local `tunnelService`/`sharedProcessTunnelService`, which opens the actual listening socket on the client machine. | `MainThreadTunnelService` (`src/vs/workbench/api/browser/mainThreadTunnelService.ts`), backed by `src/vs/platform/tunnel/node/tunnelService.ts` and `sharedProcessTunnelService.ts`. File paths confirmed in tree; not deep‑read in this pass. |
| Webviews | **Always render inside the local renderer process**, in a sandboxed `<iframe>`/dedicated webview-content origin, regardless of which extension host (local or remote) supplies the HTML/data. | `MainThreadWebviews` / `MainThreadWebviewPanels` / `MainThreadWebviewViews` (`src/vs/workbench/api/browser/mainThreadWebview*.ts`) orchestrate; actual DOM/CSP enforcement is in `WebviewElement` (`src/vs/workbench/contrib/webview/browser/webviewElement.ts`, CSP handling around L209/L722 — `webviewGenericCspSource`, `no-csp-found` event). |
| URI handlers | Routed to whichever extension host registered the handler for a scheme; `product.json`'s `trustedExtensionProtocolHandlers` governs which extensions can silently register a `vscode://<id>/...` handler without a prompt: https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/base/common/product.ts#L198 |
| Git askpass / credential forwarding | The built-in **Git extension sets `GIT_ASKPASS`/`SSH_ASKPASS`** env vars pointing to a small shim script, which IPCs back into the (local or remote) extension host process running the Git extension; that in turn can call registered `CredentialsProvider`s (e.g. github‑authentication) via `vscode.authentication`. | `extensions/git/src/askpass.ts` — env setup: https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/extensions/git/src/askpass.ts#L23-L48; handler flow at L52-L100. Implements `ITerminalEnvironmentProvider`, so these env vars are also what gets merged into **integrated terminal environment inheritance** for any shell the user opens. |
| SSH agent forwarding | Not implemented in core; Remote‑SSH‑style extensions forward `SSH_AUTH_SOCK` through their own tunnel machinery over the `ManagedResolvedAuthority`/resolver connection. **[inference — not directly re‑verified in MS's Remote-SSH source this pass, since it's closed-source; behavior inferred from public documentation of how Remote-SSH handles agent forwarding and from the general resolver/tunnel API shape above.]** |
| `globalState` sync / Settings Sync | Handled by the (local) Settings Sync service (`userDataSync*`) which reads/writes `context.globalState`'s sync‑eligible keys (declared per‑extension via `product.json`'s `extensionSyncedKeys`: https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/base/common/product.ts#L254) and pushes them to the user's configured sync service (Microsoft account / GitHub by default). Not deep‑read this pass beyond locating the gating field. |

**Pattern for the fork:** every one of these is a small, individually‑swappable `MainThread*` singleton registered via `@extHostNamedCustomer` DI decorators. A "cred sidecar" design can either (a) subclass/replace `MainThreadAuthentication`/`MainThreadSecretState` to mint and hand out short‑lived surrogate tokens to the (sandboxed/remote) extension host while keeping the real credential only in the trusted local process, or (b) leave these classes untouched and instead make the **remote connection itself** the enforcement boundary — i.e., do the credential substitution purely at the network/process edge of the REH container, so these files need **zero patching**. Option (b) is the minimal‑patch path implied by your "cred sidecar" framing.

---

## 5. Workspace Trust: implementation and why it isn't a security boundary

**Implementation:** `IWorkspaceTrustManagementService`/`IWorkspaceTrustRequestService` (interfaces): https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/platform/workspace/common/workspaceTrust.ts#L41-L106. Full state machine (storage of trusted URIs, transition participants, etc.) lives in `src/vs/workbench/services/workspaces/common/workspaceTrust.ts` (1151 lines; not fully read line-by-line, but its public surface matches the interface above).

**What "trusted ⇄ untrusted" transitions actually *do* at the code level:** when a workspace becomes untrusted, VS Code simply **restarts the extension host process(es)** and re‑applies an enablement filter — it does **not** apply any new OS privilege restriction to the process that's about to run:
https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/contrib/extensions/browser/extensionEnablementWorkspaceTrustTransitionParticipant.ts#L32-L49
(`extensionService.stopExtensionHosts(...)` → `updateExtensionsEnablementsWhenWorkspaceTrustChanges()` → `startExtensionHosts()`; if remote, it just does a full window reload instead).

**What Restricted Mode disables (per official docs, https://code.visualstudio.com/docs/editing/workspaces/workspace-trust):**
- AI agents (chat/agent mode) entirely.
- Opening an integrated **terminal** (blocked until trust granted, or opt-in via `terminal.integrated.allowInUntrustedWorkspace`).
- Running/enumerating **tasks**.
- Starting a **debug session**.
- A subset of **workspace settings** tagged `requireTrustedWorkspace` (e.g., settings that point at executable paths).
- **Extensions** that have not declared `capabilities.untrustedWorkspaces.supported` (either fully disabled, or run in a self-declared "limited" mode — entirely dependent on the extension author's honesty/correctness).

**Why it's not a security boundary (official admission):**
> "Workspace Trust can't prevent a malicious extension from executing code and ignoring Restricted Mode. You should only install and run extensions that come from a well-known publisher that you trust." — https://code.visualstudio.com/docs/editing/workspaces/workspace-trust (Caution box, "Extensions" section)

In other words: Workspace Trust is a **consent/UX gate on when VS Code's own built-in features choose to auto-execute code**, enforced entirely by application-level checks scattered across core features and honor-system `package.json` declarations from extension authors. It applies **zero** additional OS-level restriction (no sandbox, no namespace, no capability drop) to any process. Any extension that is enabled — whether because it declared trust support, or because the user clicked through — runs with exactly the same unrestricted process privileges described in §1. This is precisely the gap your ideation calls out: "the basic editor architecture itself should be reinvented beyond 'trust this workspace?'".

---

## 6. UI‑side built‑ins that must stay outside a remote/sandboxed host, and forcing third‑party extensions into containment

**Built‑ins that explicitly declare `extensionKind: ["ui","workspace"]`** (i.e., prefer to run on the client/UI side, falling back to workspace/remote only as a last resort — see §2's picker logic):
- `vscode.github-authentication`: https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/extensions/github-authentication/package.json#L16-L18
- `vscode.microsoft-authentication`: https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/extensions/microsoft-authentication/package.json#L32-L34

Rationale: these need to talk to the OS keyring / native broker flows and present native login UI (browser-based OAuth redirect, MSAL broker) that only make sense on the client machine, and they're the providers that back `vscode.authentication` for everyone else (§4). Theme/icon-theme/grammar/keymap extensions need no `main`/`browser` entry point at all and are unrestricted by the kind system entirely (deduced-kind logic, §2) — they're inert data, not code, so "outside the sandbox" doesn't really apply to them.

**Can `product.json` or policy force all third‑party extensions into the workspace/remote host?** Yes — this is the central mechanism for your whole architecture, and it already exists:

- `product.json#extensionKind: { [extensionId]: ('ui'|'workspace'|'web')[] }` — **overrides** an extension's own declared/deduced kind, taking precedence over the manifest (checked before falling back to deduction in `getExtensionKind`):
  https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/base/common/product.ts#L252
  https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/services/extensions/common/extensionManifestPropertiesService.ts#L299-L325 (precedence logic: `getConfiguredExtensionKind()` — which itself checks `remote.extensionKind` user setting *and* this product.json field — wins over `deduceExtensionKind()`)
- `product.json#extensionPointExtensionKind: { [extensionPointId]: (...)[] }` — same idea scoped to a whole *contribution point* (e.g., force all `debuggers` contributions to run workspace‑side) rather than a specific extension id:
  https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/base/common/product.ts#L253
- `product.json#extensionUntrustedWorkspaceSupport` / `extensionVirtualWorkspacesSupport` — product-level overrides for workspace-trust/virtual-workspace support per extension id, same precedence pattern (configured setting > product.json override > manifest > product.json default):
  https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/base/common/product.ts#L257-L258
  Logic: https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/services/extensions/common/extensionManifestPropertiesService.ts#L338-L351
- `product.json#extensionEnabledApiProposals` — gates proposed-API usage per extension id (used for your built‑in resolver extension, §3):
  https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/base/common/product.ts#L256

**Practical recipe (no core patch needed for the policy itself):** ship a `product.json` with `extensionKind` set to `{"*": ["workspace"]}`-equivalent for everything except an explicit allowlist (`vscode.github-authentication`, `vscode.microsoft-authentication`, theme/icon-theme packs, and your own sidecar/resolver extension) — then by the picker logic in §2, every third-party extension with real code defaults into the `workspace` extension host, which you make synonymous with "runs inside the per-window sandboxed REH container." **[One caveat verified in code but worth flagging: `getExtensionKind()`'s wildcard handling is per-extension-id keyed (`{ readonly [extensionId: string]: ... }`), not inherently wildcard-matched — supporting a literal `"*"` key may require a small patch in `extensionManifestPropertiesService.ts`; I did not find existing `"*"` wildcard support in this specific map during this pass, unlike the `extensions.allowed` policy which explicitly supports `"*"` (§8). Treat per-extension enumeration as the verified-safe approach, and wildcard support as something to test/patch.]**

---

## 7. Fork maintainability patterns

| Project | Structure | Rebase cost characteristics |
|---|---|---|
| **VSCodium** | Separate repo, **no vscode submodule in git** — `prepare_vscode.sh` does a scripted `cp` of upstream's released source tarball into a `vscode/` working dir at build time, then applies `patches/*.patch` (56 patch files currently) with `git apply`/`quilt`-like tooling, plus JSON‑surgery via `jq` directly on `product.json` (not a patch file) for things like `extensionsGallery`, `extensionEnabledApiProposals`, etc. https://github.com/VSCodium/vscodium/blob/ca7f7b44b5e5c3faa663f6cdc043998f71936653/prepare_vscode.sh#L1-L40 ; patch list: https://github.com/VSCodium/vscodium/tree/ca7f7b44b5e5c3faa663f6cdc043998f71936653/patches | **Lowest ongoing cost.** Patches are small, topical (`00-ext-github-authentication-use-pat.patch`, `00-remote-disable-client-validation.patch`, etc.), individually disable-able (`.patch.no` suffix pattern observed), and `product.json` edits are pure data (no merge conflicts, just re-run the `jq` script against the new upstream `product.json`). Breaks only when upstream *moves or renames* the exact code a patch touches. |
| **code-server (coder)** | `lib/vscode` is a **real git submodule** pointing at `microsoft/vscode`, plus `patches/*.diff` (31 files) applied against that submodule checkout, tracked via a `series` file (quilt-style ordered patch stack): https://github.com/coder/code-server (`.gitmodules`: `[submodule "lib/vscode"] url = https://github.com/microsoft/vscode`) | **Low-to-moderate.** Submodule pinning makes "what exact upstream commit are we on" explicit and bisectable; `.diff` files are unified diffs so `git apply --reject` + manual patch-file fixups is the standard workflow on bump. More mechanical overhead than VSCodium's tarball approach but better traceability. |
| **Positron (posit-dev)** | **Full hard fork** — top-level `src/`, `extensions/`, `build/`, `product.json`, `gulpfile.mjs` all live directly in the Positron repo (not a submodule, not a patch dir), consistent with a `git merge`-based upstream-tracking workflow. Confirmed structurally: top-level listing shows the exact vscode tree shape at repo root, not a vendored subdirectory. https://github.com/posit-dev/positron (root listing) | **Highest ongoing cost.** Deep UI/runtime changes (new R/Python data-science panes, variable explorer, plots pane) are woven directly into core files, so every upstream VS Code release requires a real multi-thousand-file `git merge`/rebase with manual conflict resolution. Justified only because Positron's changes are too invasive for a patch queue (new first-class UI surfaces, not toggles). |
| **Theia (Eclipse)** | **Not a fork at all** — independent reimplementation of the VS Code extension API surface on a different core architecture (dependency-injection/Inversify-based, different process model). Not comparable for "patch maintenance cost" purposes; mentioned only to rule it out as a model — your plan needs VS Code's actual workbench/extension-host plumbing, not an API-compatible reimplementation. |

### Recommendation for this prototype
Given the stated goal — "mostly `product.json` changes, one built-in resolver extension, and a small number of workbench patches" — **the VSCodium model is the right fit**, not code-server's submodule-and-diff-stack and definitely not Positron's hard fork:

1. **No vscode submodule.** Script-copy (or shallow-clone-and-reset) a pinned upstream tag/commit at build time, same as VSCodium's `prepare_vscode.sh`.
2. **`product.json` edits as structured data/jq script**, not patches — this is the overwhelming majority of your changes per §3/§6 (`extensionKind` policy, `extensionEnabledApiProposals` for your resolver extension, `extensionsGallery` if you want your own marketplace, `trustedExtensionAuthAccess`, etc.). Zero merge-conflict risk on bump.
3. **Your resolver extension as a genuinely separate repo/directory**, added into `extensions/` at build time (VSCodium does this for a few community extensions too) — it's plain TypeScript against the public + proposed API surface, versioned independently of VS Code core.
4. **A small `patches/` directory (quilt-numbered, one concern per file, each individually toggleable)** for the handful of actual workbench-core touches you can't avoid — e.g., if you do decide to patch `MainThreadAuthentication`/`MainThreadSecretState` for the cred-sidecar (§4), or to add a `"*"` wildcard to `extensionKind` product.json handling (§6 caveat). Keep each patch under ~50 lines and scoped to one file where possible; that's what keeps VSCodium's 56-patch stack maintainable release after release.
5. Track upstream via **tag pinning + a changelog of which tag each patch was last verified against**, not a live submodule you're expected to merge — this matches VSCodium's actual practice and minimizes the surface area that can silently drift.

---

## 8. Enterprise policy: what VS Code can enforce today

Policies are surfaced through `IPolicyService`, implemented natively via the `@vscode/policy-watcher` npm package (Windows Registry‑based Group Policy under `Software\Policies\Microsoft\VSCode`, macOS managed preferences, Linux equivalents):
https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/platform/policy/node/nativePolicyService.ts#L25-L42
plus a cross‑platform JSON "managed settings" file path alternative via `FilePolicyService`:
https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/platform/policy/common/filePolicyService.ts#L28

Official docs (https://code.visualstudio.com/docs/enterprise/policies) confirm the deployment model: ADMX/ADML template files shipped under each release's `policies/` directory, importable into `gpedit.msc`/Intune/Active Directory Central Store; any configured policy **overrides** the corresponding setting at every scope (default/user/workspace) and cannot be overridden back by the user.

**The extension allowlist specifically** (`extensions.allowed`, policy name `AllowedExtensions`, minimum VS Code version 1.96):
https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/platform/extensionManagement/common/extensionManagement.ts#L734-L816
Supports: allow/block by exact extension id, by publisher id (with `"microsoft"` as an umbrella alias across MS's various publisher ids), by specific version (optionally platform-qualified, e.g. `"5.0.0@win32-x64"`), `"stable"` to block pre-release only, and a global `"*": true|false` wildcard — confirmed per official docs at https://code.visualstudio.com/docs/enterprise/extensions, which also explicitly notes: **"these rules use identifiers declared in the package. They do not verify the package's origin, prevent changes to local extension files, or limit an extension's runtime permissions."** — i.e., this is purely an install/enable gate, not a containment mechanism; it does nothing to the process once an allowed extension is actually running. That last caveat is the official documentation independently corroborating §1/§5's core finding.

Other enforceable areas per the same docs page: AI/Copilot feature toggles, telemetry level, automatic-update behavior, private marketplace endpoint, and preinstalled/bootstrap extensions (Windows only, via a `bootstrap\extensions` folder).

---

## Implications for the fork — minimal patch points

Given everything above, the containment architecture you described is **~90% achievable through configuration and one new extension, not a core rewrite**, because VS Code already has the exact seam your ideation describes (local UI ⇄ remote workspace boundary) — it's just never been used as a *security* boundary, only a *connectivity* one. Minimal patch set:

1. **Per‑window sandboxed REH, not a shared one.** Stand up one REH (`vscode-reh-*` build, §3) instance per workspace/window, each inside its own container/VM/Firecracker-style sandbox (the user's "Docker sbx style workspace mount" idea) with real OS ACLs/seccomp applied *at the container boundary*, not inside VS Code. This is infrastructure you build outside the vscode tree entirely — **zero core patch**.
2. **One built‑in resolver extension** that: (a) spins up / attaches to that per‑workspace sandboxed container, (b) implements `registerRemoteAuthorityResolver` possibly using `ManagedResolvedAuthority`/`ManagedMessagePassing` if you want a non-TCP transport (e.g., container exec/vsock) instead of exposing a loopback port, (c) is granted `["resolvers"]` (+ `tunnels` if needed) via `product.json#extensionEnabledApiProposals`, exactly as VSCodium does for `jeanp413.open-remote-ssh` (§3).
3. **`product.json#extensionKind` policy**: force the default kind for all extensions to `workspace` (i.e., into the sandboxed REH) with an explicit, short allowlist staying `ui` (auth providers, themes, your own resolver extension, maybe the built-in debugger-adapter UI glue) — §2 + §6. This single JSON change is the main lever for "code exec on a tab shouldn't imply full access to a system," and the front end is completely unaware of it, because the picker/placement logic (§2) already runs transparently today.
4. **`extensions.allowed` / `AllowedExtensions` policy** (§8) as a secondary, complementary control (install-time gate) — cheap to wire up, but remember it is not itself containment; don't conflate it with the process boundary in #1–3.
5. **Cred‑sidecar for tokens** (§4): the cleanest minimal‑patch option is to do *no* core patch at all and instead make the per‑window sandbox's network egress pass through a local proxy/sidecar that mints and injects surrogate credentials for outbound requests from that container — since `vscode.authentication`/`SecretStorage`/git‑askpass/SSH‑agent‑forwarding *already* funnel every credential operation back over the remote RPC channel to the trusted local process (`MainThreadAuthentication.$getSession`, `MainThreadSecretState`, git's `GIT_ASKPASS` IPC shim — all cited in §4), you can intercept at the RPC/network edge rather than patching these classes directly. If you do need in-process interception for fidelity (e.g., scoping secrets to window, not just extension id), the two files to patch are `src/vs/workbench/api/browser/mainThreadAuthentication.ts` (`$getSession`) and `src/vs/workbench/api/browser/mainThreadSecretState.ts` (`getKey`/`doGetPassword`/`doSetPassword`) — both small, self-contained classes, ideal for a VSCodium-style single-purpose patch file.
6. **Workspace Trust stays exactly as-is** and is explicitly *not* your security boundary (§5) — keep it purely as the UX "do you want agents/terminal/tasks/debugging to run at all" prompt it already is; your new process/ACL boundary from #1 is what actually contains a rogue extension's blast radius, and it operates completely underneath/independently of the Workspace Trust UI, so the front end genuinely does not change.
7. **Fork structure** (§7): VSCodium-style patch queue + scripted `product.json` generation + your resolver extension as an independent package — not a submodule, not a hard fork. This keeps the entire containment feature as: one new extension repo, one `product.json` generation script, and an estimated 2–5 small core patches (affinity wildcarding if needed, the two cred-sidecar files if you choose in-process interception, possibly extensionKind `"*"` wildcard support).

**Gaps / things I did not verify directly** (flagged for follow-up before implementation): the exact precise wording of Microsoft's Remote-SSH/Dev Containers/VS Code Server EULA (fetched secondhand via search, not the primary license page, which 404'd on the path I tried — re-fetch `https://code.visualstudio.com/License/*` variants before relying on exact phrasing); SSH-agent-forwarding implementation details (Remote-SSH extension is closed-source, so this is inferred from the public resolver/tunnel API shape, not read directly); Settings Sync's full data-flow (only the `extensionSyncedKeys` gating field was located, not the sync transport/storage implementation); whether `extensionKind`/`extensionPointExtensionKind` product.json maps support a `"*"` wildcard key today (not found in the code I read — treat as needing either per-id enumeration or a small patch, per §6's caveat); and code-server/Gitpod openvscode-server/Positron's exact `product.json` `extensionEnabledApiProposals` contents (verified directly only for VSCodium; assumed architecturally identical for the others based on shared upstream, not independently diffed).