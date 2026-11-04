# seclab-vscode: Browser-Style Containment for the VS Code Editor

**Status:** Architecture proposal v0.1 (2026-11-04). Not yet built.
**Goal:** Contain a rogue extension, or any code a workspace can make run, to one **tab** by default. A tab is one workspace window, analogous to a site in Chrome. The front-end experience stays the same.

Supporting research, with full citations, is in `docs/research/`:
- `vscode-internals.md`
- `sandbox-runtimes.md`
- `cred-broker.md`
- `workspace-exec-vectors.md`

All VS Code permalinks are pinned to `microsoft/vscode@8819991`.

---

## 1. The core idea in one paragraph

VS Code already splits the trusted UI from the code that runs extensions. The UI is a Chromium-sandboxed renderer plus the Electron main process. Extension code runs in a *remote extension host* (REH) that can live on another machine or container. That split was built for **connectivity** (SSH, Dev Containers, Codespaces). It was never built as a **security boundary**.

We turn it into one. Every workspace window is forced through a built-in remote resolver into its **own sandbox** that runs the REH. Three controls make that sandbox actually contain things:

1. **The sandbox itself.** Only the workspace is mounted, the network has no route out, and there are no host credentials.
2. **One host-side broker** handles everything that leaves the sandbox: network egress, credentials, and scope-expansion prompts.
3. **A capability filter** on the RPC channel from the sandboxed extension host back into the trusted UI.

Control 3 is the one that is easy to miss (§4.6). Without it, a sandboxed extension can ask the UI to open a host terminal and type into it.

## 2. Threat model

| | |
|---|---|
| **Attackers** | (a) A malicious or compromised marketplace extension. (b) A malicious workspace that makes code run through `tasks.json`, `.git/config` (`core.fsmonitor`, hooks, filters), config files that are executable code (ESLint, Prettier, tsserver plugins), interpreter-path settings, `build.rs` and proc macros, Gradle wrappers, notebooks, or `.vscode/mcp.json`. (c) A prompt-injected agent or extension. |
| **Assets** | Host filesystem, host credentials (PATs, OAuth tokens, SSH keys, cloud credentials, LLM keys), other tabs' data and secrets, the ability to run code on the host, and the network position (exfiltration and reaching localhost services). |
| **Guarantee** | Code running in tab *T* can affect only *T*'s mounted workspace and *T*'s granted scope. It cannot run code on the host or read host files. It cannot obtain a reusable real credential. It cannot reach the network except as *T*'s policy allows, and it cannot read or affect other tabs. |
| **Non-goals (v0)** | Isolating extensions from each other *within* one tab (that is the tab's accepted blast radius; see §8 for per-extension processes later). Chromium renderer 0-days (we rely on Electron's renderer sandbox). Malicious first-party UI code. |

Workspace Trust is **not** part of the boundary. Microsoft states that it "can't prevent a malicious extension from executing code and ignoring Restricted Mode" ([docs](https://code.visualstudio.com/docs/editing/workspaces/workspace-trust)). Leaving Restricted Mode only restarts extension hosts and changes no privileges ([source](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/contrib/extensions/browser/extensionEnablementWorkspaceTrustTransitionParticipant.ts#L32-L49)). We keep it purely as UX.

## 3. Chrome ↔ seclab-vscode mapping

| Chrome | seclab-vscode | Built from |
|---|---|---|
| Browser process (trusted) | Electron main process + workbench renderer + first-party UI-side extensions | Stock Code-OSS |
| Site-isolated renderer process | **Tab sandbox**: REH, extension host, pty host, tasks, debug adapters, LSPs, git, MCP stdio servers | Code-OSS REH build + OCI or microVM runtime |
| Network service (single choke point) | **Tab broker**: egress policy, credential injection, prompt source | mitmproxy (addon) as the first engine |
| Mojo IPC interface filtering | **RPC capability filter** on `MainThread*` for sandboxed hosts | Small workbench patch |
| Storage partitioning per top-level site | `SecretStorage` and `globalState` partitioned per tab | Small workbench patch |
| Permission prompts (camera, location…) | Scope-expansion prompts: folder, domain, credential, port | Existing VS Code dialogs, triggered by the broker |
| Extension manifest permissions | Per-tab policy file and per-extension attribution (later) | Our policy schema |

## 4. Architecture

```mermaid
flowchart LR
  subgraph Host["Host (trusted)"]
    UI["Workbench UI<br/>(Chromium-sandboxed renderer)"]
    MAIN["Electron main"]
    LEH["Local ext host<br/>first-party only:<br/>auth providers + Tab Manager"]
    KC[("OS keychain")]
    FILTER{{"RPC capability filter"}}
  end
  subgraph TabA["Tab A pod"]
    direction TB
    SBX["Workspace sandbox<br/>REH · ext host · pty · tasks<br/>LSPs · git · MCP stdio<br/>mount: ~/src/a only<br/>no route out"]
    BRK["Broker sidecar<br/>egress policy · sentinel→real cred<br/>per-tab CA · DNS"]
  end
  subgraph TabB["Tab B pod"]
    SBXB["Workspace sandbox"] --- BRKB["Broker sidecar"]
  end
  UI <-->|"remote protocol<br/>(exec stdio, no listener)"| FILTER
  FILTER <--> SBX
  LEH -->|"lifecycle + policy + JIT creds<br/>(exec stdio)"| BRK
  LEH --- KC
  SBX -->|"HTTP(S)_PROXY only"| BRK
  BRK -->|"allowed egress"| NET(("Internet"))
  BRK -.->|"needs approval"| LEH -.-> UI
```

### 4.1 Fork build (keep the patch set small)

We follow VSCodium's model ([prepare_vscode.sh](https://github.com/VSCodium/vscodium/blob/ca7f7b44b5e5c3faa663f6cdc043998f71936653/prepare_vscode.sh#L1-L40)) and avoid a hard fork like Positron's:

- `upstream.lock` pins a Code-OSS tag and SHA. The build script fetches that exact source.
- `product.json` changes are applied as **data** with a `jq` script, so they never cause merge conflicts:
  - `extensionEnabledApiProposals` grants `resolvers` to our built-in extension. This is the same mechanism VSCodium uses for `open-remote-ssh` ([product.json](https://github.com/VSCodium/vscodium/blob/ca7f7b44b5e5c3faa663f6cdc043998f71936653/product.json#L477-L489)).
  - `extensionKind` overrides force third-party extensions to `workspace`.
  - Open VSX as the gallery.
  - Settings Sync turned off.
- `patches/NNNN-*.patch` holds one concern per file and fewer than about 50 lines each. Expected patches: the RPC capability filter, auth mediation, storage partitioning, routing webview egress through the broker, and wildcard support in `extensionKind` (the map is keyed per extension ID today; [product.ts](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/base/common/product.ts#L252)).
- Each tab sandbox's REH comes from the **same** pinned source (`gulp vscode-reh-linux-<arch>`, [gulpfile.reh.ts](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/build/gulpfile.reh.ts#L538-L576)). Microsoft's VS Code Server and Remote extensions are licensed only for Microsoft builds, so we never use them.

### 4.2 Tab Manager: a built-in UI-side extension

This is the only new orchestration code. It runs in the local, first-party-only extension host.

- It registers the `seclab+<tabId>` remote authority through `registerRemoteAuthorityResolver` and returns a **`ManagedResolvedAuthority`**. Every REH connection becomes a byte stream over `<runtime> exec -i` stdio ([resolvers.d.ts](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vscode-dts/vscode.proposed.resolvers.d.ts#L33-L51)). Nothing listens on the host, and the sandbox exposes no ports.
- It routes Open Folder, the `code <dir>` CLI, recent folders and `vscode://` folder links into `vscode-remote://seclab+<tabId>/<path>`. A window with no folder gets an ephemeral, empty tab.
- It owns tab lifecycle through a `SandboxProvider` interface (§4.3), keeps a warm pool for fast opens, and tears down on close.
- It holds the host side of the broker control channel. It gets real credentials from the keychain and existing auth providers just in time, and turns broker "needs approval" events into standard VS Code dialogs.

### 4.3 Tab sandbox: a pluggable runtime

```ts
interface SandboxProvider {
  create(spec: TabSpec): Promise<Tab>;                   // mounts, image, runtimeClass, resources
  exec(tab: Tab, argv: string[]): Promise<Duplex>;       // REH channel and broker control channel
  stop(tab: Tab): Promise<void>; remove(tab: Tab): Promise<void>;
  addMount?(tab: Tab, m: Mount): Promise<'live' | 'needs-restart'>;
}
```

| Provider | Isolation | When |
|---|---|---|
| **OCI (Docker or Podman CLI)**: a two-container pod with workspace and broker on an `--internal` network | Namespaces; tab-to-host goes through Docker Desktop's VM on macOS. Optional **gVisor** (`--runtime=runsc`) on Linux | **v0 prototype.** Available everywhere, open source, scriptable. Same pod shape as Kubernetes. |
| **VM-per-tab**: Apple `container` (macOS 26), Docker Sandboxes `sbx`, or Kata/Firecracker in the cloud | Hypervisor per tab | v1 hardening. Same interface. |
| **Kubernetes pod** with RuntimeClass gVisor or Kata | Per cloud policy | Cloud tabs. Same pod spec, a different control channel. |

Defaults:
- Only the workspace folder is mounted, read-write. Nothing from `$HOME` is mounted.
- Clean environment: no `SSH_AUTH_SOCK`, no tokens, non-root user, no `docker.sock`, not privileged.
- Process limits.
- Symlinks out of the workspace resolve **inside the sandbox**, so they are contained by construction. We do not rely on VS Code's own path checks, which have repeatedly been bypassed (see `workspace-exec-vectors.md` §7).

Why not Docker Sandboxes as *the* design: it already ships most of this (microVM, host proxy, sentinel credentials, live policy, MCP gateway). However, it is closed source, heavy per tab (one VM plus one Docker engine each), and has no hold-and-prompt hook we control. We keep it as a candidate VM-per-tab provider. We own the broker because its policy and prompt UX *is* the product and must behave the same on every provider.

### 4.4 Network: fail-closed by topology, not by configuration

- The workspace container's only peer is the broker sidecar. There is no default route and no external DNS; the proxy resolves names. Proxy-unaware clients therefore **fail closed** instead of leaking.
- The workspace gets `HTTP(S)_PROXY` and `NO_PROXY=localhost` set, and the per-tab CA is installed in its trust store, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE` and git's config.
- Policy is default-deny with a small baseline: the extension gallery and the package registries the user opts into per tab.
- When a request is denied, the broker **holds the flow** (mitmproxy's `flow.intercept()`/`resume()`) and asks the Tab Manager. The user sees *"Tab `foo` wants to reach `api.example.com` — Allow once / Always for this workspace / Deny"*. If allowed, the request continues without a retry.

### 4.5 Broker: credentials are sentinels until they leave the tab

- **Policy file per tab:**
  ```
  allow:       [{host, methods, path}]
  credentials: [{id, bind: {host, path, methods}, inject: {header, fmt}}]
  ```
  The schema follows Docker Sandboxes' method, path and query rules ([docs](https://docs.docker.com/ai/governance/local/network-rules/)) and tokenizer's rule that the *issuer* sets the injection target ([superfly/tokenizer](https://github.com/superfly/tokenizer)).
- **Sentinels** are random strings scoped to one tab and one credential. They are worthless outside that tab's broker and are swapped only on requests that match the binding. This defeats "paste the token into an allowed gist", because the binding is `GET /repos/**`, not just `github.com`.
- **GitHub and Microsoft auth:** `vscode.authentication.getSession()` from a sandboxed host returns a sentinel session. This is patched in `MainThreadAuthentication.$getSession` ([L553-L566](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadAuthentication.ts#L553-L566)). Without the patch, the real token crosses the RPC channel into the sandbox.
  - Git over HTTPS needs no special plumbing. The git extension's askpass gets the sentinel, and the broker swaps it on egress to `github.com`.
  - Later, the broker should mint downscoped, short-lived GitHub App user tokens instead of injecting long-lived ones.
- **Engine:** mitmproxy runs as the sidecar image with our addon. It is MIT-licensed, handles HTTP/2 and WebSockets, has live policy in Python, and supports intercept and resume. Because the policy schema is ours, we can swap the engine for smokescreen or Envoy later.
- **Later channels, same broker and same prompts:**
  - SSH: a filtering agent socket with per-key and per-host confirmation.
  - Cloud CLIs: `credential_process` or IMDS emulation, reusing aws-vault's server mode.
  - MCP: one gateway endpoint per tab, following the gh-aw MCP gateway spec.

### 4.6 RPC capability filter: the piece that is easy to miss

The sandboxed extension host talks back to the trusted workbench through `MainThread*` RPC services, and today those services do not check where the caller runs. Verified in source:

| Today (remote extension host → UI) | Consequence | Filter rule (sandboxed hosts) |
|---|---|---|
| `$executeCommand` runs **any** command ([L81-L93](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadCommands.ts#L81-L93)). In a remote window, `workbench.action.terminal.newLocal` spawns a **host** terminal ([terminalRemote.ts L16-L42](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/contrib/terminal/electron-browser/terminalRemote.ts#L16-L42)), and `…terminal.sendSequence` types into the active terminal | Inferred from these call sites, not yet tested: escape to code execution on the host | Deny commands that touch host processes, host files, extension management, settings or the window. The allowlist is tagged by command category. |
| `$readFile`/`$writeFile` accept **any URI scheme** through `IFileService` ([L104-L119](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadFileSystem.ts#L104-L119)) | Host files are reachable through non-`file` schemes, for example `vscode-userdata:` for user settings | Allow only `vscode-remote://seclab+<self>`, `untitled:` and the extension's own read-only resources |
| `SecretStorage` key is `{extensionId, key}`, global across windows ([L90-L92](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadSecretState.ts#L90-L92)) | Cross-tab secret read and poisoning by the same extension | Partition by tab: `{tabOrigin, extensionId, key}`. Do the same for `globalState`. |
| `authentication.getSession` returns the real token | Real credential inside the sandbox | Sentinel (§4.5) |
| Webviews render in the **local** renderer and can fetch arbitrary origins | Exfiltration path that bypasses the tab broker | Route the webview session through the tab broker, or force CSP `connect-src` |
| `openExternal`, clipboard, tunnels / port forwarding, URI handlers | Exfiltration, localhost pivot, confused deputy | Prompt-gated, tab-labelled, never silent |

This is one patch, applied where the RPC protocol is wired up for an extension host. It works like Chrome's per-interface Mojo filtering, and it is the main piece of new security engineering in the project. We should develop it **test-first** against a rogue-extension fixture.

### 4.7 Host-side residuals (from the code-execution catalogue)

These are the vectors that would otherwise still run on the host, and how we handle each:

| Vector | Handling |
|---|---|
| UI-kind third-party extensions | Forced to `workspace` through product.json. Only an allowlist of first-party extensions runs locally. |
| `devcontainer.json` `initializeCommand` | Not supported on the host. Dev Container lifecycle commands, if supported at all, run **inside** the tab. |
| `vscode://` deep links and the `code` CLI | Always open into a tab. No command URIs from links. |
| Settings Sync | Off in the prototype. Synced extension installs would be treated as untrusted fresh installs. |
| Notification and Markdown command links | Already gated upstream (GHSA-xf67-g42g-pg73). The filter applies to commands that originate from a tab. |

Everything else in the catalogue runs inside the tab sandbox, so it is **contained by construction**:
- tasks, including `runOn: folderOpen`
- debug adapters
- interpreter and tool path settings
- git `fsmonitor`, hooks and filters
- LSP and build-tool code execution
- MCP stdio servers
- Jupyter kernels

## 5. Local vs cloud

The unit is a **pod**: workspace sandbox plus broker sidecar. Locally it runs on Docker or Podman (later VM-per-tab). In the cloud it is a literal Kubernetes pod with a gVisor or Kata RuntimeClass.

The UI does not care which. The resolver returns a managed byte stream either way, and the broker control channel uses the same protocol. A tab can move between local and cloud without any change to the front end.

## 6. Prototype milestones (each one is a working demo)

| # | Milestone | Proves |
|---|---|---|
| M0 | Reproducible build pipeline: pinned Code-OSS, jq-applied product.json, empty patch queue, REH image | We can track upstream cheaply |
| M1 | Tab Manager, OCI provider, managed exec-stdio resolver. Every folder opens as a tab; UI unchanged | Process and filesystem containment |
| M2 | Broker sidecar: default-deny, hold-and-prompt, per-tab CA | Network containment and the scope-expansion UX |
| M3 | Sentinel credentials: GitHub auth patch, git over HTTPS | "Cred sidecar routed" tokens |
| M4 | RPC capability filter, storage partitioning, webview egress | No confused-deputy escape back to the host |
| M5 | VM-per-tab provider (Apple `container` or `sbx`) and cloud pod | Stronger isolation with no front-end change |

**Containment test suite, built from M1 onward.** A deliberately rogue extension plus malicious workspace fixtures:
- `tasks.json` folder-open task
- `.git/config` `core.fsmonitor`
- `eslint.config.js`
- interpreter-path setting
- `.vscode/mcp.json`

Each fixture is run against assertions such as: cannot read `~/.ssh`, cannot run code on the host, no real token seen in sandbox memory or environment, no un-granted egress, no access to another tab's secrets. This suite is the definition of done, and it guards against regressions on every upstream bump.

## 7. Risks and open questions

- **Cost per tab.** A container pod is cheap. VM-per-tab at 10–20 windows needs benchmarking, plus a warm pool.
- **File watching** over virtiofs on macOS for large repos needs an early spike in M1.
- **Extension compatibility.** UI-kind extensions forced remote, extensions that assume localhost, and pinned-certificate clients all need checking. Pinned clients get a non-MITM path (for example `credential_process`) or are denied.
- **Proposed API churn** in the `resolvers` API is limited to one extension; VSCodium carries the same risk.
- **Live mounts.** Adding a folder to a running tab is not possible on Docker; it restarts the tab. VM providers may differ.
- **Docker Desktop internal networks and the embedded DNS forwarder.** We must verify there is no DNS exfiltration path (this is in the test suite).

## 8. Later work (out of scope for v0)

- Per-extension processes inside a tab, using `extensions.experimental.affinity` today ([source](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/services/extensions/common/extensionRunningLocationTracker.ts#L125-L221)), with distinct uids so the broker can attribute requests to an extension. This is the analogue of Chrome's isolation between extensions.
- VS Code's own agent sandbox (Seatbelt, bubblewrap or MXC) as an **inner** layer for agent terminals inside a tab. Microsoft says explicitly that it is not a VM or container boundary ([docs](https://code.visualstudio.com/docs/agents/run/agent-sandboxing)).
- Downscoped GitHub App tokens minted by the broker. Enterprise policy files for per-org baselines.
