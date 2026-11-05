# No agent runtime on the host: no local agent host, no Copilot runtime in the desktop app

- **Status:** accepted
- **Date:** 2026-11-05
- **Deciders:** anticomputer (user), approving the runtime exception: "Allow the prebuilt runtimes as a recorded exception, hash-pinned, since they only ever run inside tabs". Coordinator: "Remove `copilot-runtime` from the macOS app (invariant I8)", priority 1. Fork-build session: implementation.
- **Related:** secure-agentic-experiences plan (I8, probe A27, §10 "No local agent host"); [patch queue](../../patches/README.md); [patch-build gate](20261105-patch-build-gate.md)

## Context
The runtime exception holds only if the opaque agent runtimes run inside tabs and nowhere
else (I8). Upstream 1.145.0 breaks that in two places:
- **Electron main always creates the agent-host starter and process manager**, and spawns
  the agent-host utility process on a window's first connection request
  ([app.ts#L760-L769](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/code/electron-main/app.ts#L760-L769)).
  That process loads `@github/copilot-sdk` (`CopilotClient`,
  [copilotAgent.ts#L7](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/agentHost/node/copilot/copilotAgent.ts#L7)).
- **The desktop package step re-adds the SDK's platform runtime** after `.moduleignore`
  strips platform packages
  ([gulpfile.vscode.ts#L255-L259](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/build/gulpfile.vscode.ts#L255-L259)).

Our macOS app from main showed it. Its `node_modules.asar.unpacked/@github/copilot-sdk-darwin-arm64`
holds the runtime, and the asar header lists `copilot-sdk`, `copilot-runtime` and
`runtime.node`.

## Decision
Two patches, one concern each:
- **0013 `no-local-agent-host`** (`app.ts`, `sharedProcessMain.ts`). Nothing on the host starts
  an agent host.
  - **Main** creates no starter or process manager. It answers
    `vscode:createAgentHostMessageChannel` itself with the reply the starter already sends on a
    fatal start error: `{ nonce, error, fatal: true }`, the shape of
  [electronAgentHostStarter.ts#L378-L388](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/agentHost/electron-main/electronAgentHostStarter.ts#L378-L388).
  The renderer turns that into a `NonReconnectableTransportError`, so it neither hangs nor
  retries. The compile-cache warm-up no longer starts the process.
  - **The shared process** (review WW-1) registers no SSH, dev-container, WSL or tunnel
    agent-host provider
    ([sharedProcessMain.ts#L432-L442](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/code/electron-utility/sharedProcess/sharedProcessMain.ts#L432-L442),
    [#L524-L539](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/code/electron-utility/sharedProcess/sharedProcessMain.ts#L524-L539)).
    The dev-container provider ran `@devcontainers/cli up` on the host from the workspace's
    own `devcontainer.json`, so its `initializeCommand` ran on the host. The SSH provider used
    the user's keys and forwarded their agent. Callers now get the IPC server's
    "Unknown channel" error after its timeout.
- **0014 `build-desktop-without-copilot-runtime`** (`build/gulpfile.vscode.ts`,
  `build/next/index.ts`, desktop only).
  - It drops `ensureCopilotPlatformPackage` and the prebuild re-add, and filters
    `@github/copilot-sdk`, `@github/copilot-sdk-*`, `@github/copilot` and `@github/copilot-*`
    out of the packaged dependencies.
  - It removes `agentHostMain` from `desktopEntryPoints`, so the desktop app ships no
    agent-host process code at all.
  - The REH keeps both, through `gulpfile.reh.ts` and `serverEntryPoints`, because tabs run
    agents.
- **`patches/unreachable.json`** lists agent-host modules desktop must not reach: the starter,
  the process manager, `agentHostMain`, the four providers, the Copilot, Claude and Codex
  agents, and the SDK downloader. `check-patch-reach.ts` enforces it in the required
  `patch-build` check. A listed file that no longer exists also fails, so an upstream rename
  can't retire the rule silently.
- **`build/check-release.sh --desktop`** runs in `build/build-darwin.sh` over the whole
  `.app`, and in the Linux editor build. It fails the build on any of these, found on disk or
  listed in an asar header:
  - the Copilot SDK or its platform package, `@github/copilot`, the copilot shim;
  - `copilot-runtime*`, `runtime.node`, and any `*agent-sdk*` or `*agent-runtime*` name;
  - Codex (`@openai/codex*`, `codex`, `codex-*`);
  - the Claude agent SDK or Claude Code. `@anthropic-ai/sdk`, a plain API client, is in the
    desktop app and allowed;
  - `agentSdks` in `product.json`. Upstream's downloader takes the download path only when
    that key is set
    ([agentSdkDownloader.ts#L312](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/agentHost/node/agentSdkDownloader.ts#L312)),
    and the gulp step stamps it only from `build/agent-sdk/produce.ts` results, which we
    never produce.

  The REH check stays in release mode.

## Alternatives considered
- **A renderer-side null agent-host service only.** Main would still spawn the process on
  any request, so a renderer bug, or a future window that asks, would reach it. The plan
  rejects this too.
- **Strip the runtime but keep the local agent host.** The process would fail to load the
  SDK and restart up to its limit. That is noisy, and it relies on a missing file instead
  of stating the rule.

## Consequences
- **Verified 2026-11-05:**
  - **0013 type-check.** The `app.ts` part was type-checked against its import closure (876
    files): the error set is identical with and without the patch (`.work/tsc13`). The
    shared-process part relies on the required `patch-build` check (whole tree); the local
    `node_modules` was lost to an npm outage.
  - **0014 type-check.** `build/tsconfig.json` gives the same error set with and without the
    gulpfile part.
  - **Reach.** With the full set applied, desktop reaches 6509 modules (7048 before), and all
    11 forbidden modules are unreachable from desktop and still reachable from the REH. On
    the tree without the shared-process and entry-point changes, 9 of the 11 fail.
  - **Release check.** `check-release.sh --desktop` on the whole current main `.app` fails
    only on the runtime: `copilot-sdk-darwin-arm64/**`, `copilot-runtime`, `copilot-sdk` and
    `runtime.node`. Release mode on the same app is clean.
- **Still to come:**
  - A27, the runtime probe on a built app: no agent-host process, no runtime in the bundle,
    no `agentSdks`.
  - The REH-side runtime lock (hash-pinned at tab-template time) and the `rt-*` register
    entries.
  - The Agents window and the agent-session links. They can no longer start anything on the
    host, but the Agents window can still dial remote agent hosts configured in settings.
    Plan §10 assigns their removal from the desktop app to this session.
  - Each window whose AI features try a local connection shows upstream's fatal agent-host
    toast once (WW-3). A renderer-side null service would silence it.
- **Upstream drift.** A new runtime package name defeats the asar and path rule silently.
  Each upstream bump must re-check the agent-host dependencies, and the A27 probe backs this.
