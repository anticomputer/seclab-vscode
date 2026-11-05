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
- **0013 `no-local-agent-host`** (`app.ts`). Main creates no starter or process manager. It
  answers `vscode:createAgentHostMessageChannel` itself with the reply the starter already
  sends on a fatal start error: `{ nonce, error, fatal: true }`, the shape of
  [electronAgentHostStarter.ts#L378-L388](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/agentHost/electron-main/electronAgentHostStarter.ts#L378-L388).
  The renderer turns that into a `NonReconnectableTransportError`, so it neither hangs nor
  retries. The compile-cache warm-up no longer starts the process.
- **0014 `build-desktop-without-copilot-runtime`** (`build/gulpfile.vscode.ts`, desktop
  only). It drops `ensureCopilotPlatformPackage` and the prebuild re-add, and filters
  `@github/copilot-sdk`, `@github/copilot-sdk-*`, `@github/copilot` and `@github/copilot-*`
  out of the packaged dependencies. The REH is packaged by `gulpfile.reh.ts` and keeps the
  runtime, because tabs run it.
- **`build/check-release.sh --desktop`** runs in `build/build-darwin.sh` and fails the build
  on any of these, found on disk or listed in an asar header:
  - the Copilot SDK or its platform package;
  - `copilot-runtime*`, `runtime.node`;
  - Codex (`@openai/codex*`, `codex`, `codex-*`);
  - the Claude agent SDK or Claude Code;
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
  - **0013 type-check.** Type-checked against its import closure (876 files): the error
    set is identical with and without the patch (`.work/tsc13`); the patch-build gate
    covers the whole tree.
  - **0014 type-check.** `build/tsconfig.json` gives the same error set with and without it.
  - **Positive control.** `check-release.sh --desktop` on the current main app fails on
    `copilot-sdk-darwin-arm64/**`, `copilot-runtime`, `copilot-sdk` and `runtime.node`;
    release mode on the same app is clean.
- **Still to come:**
  - A27, the runtime probe on a built app: no agent-host process, no runtime in the bundle,
    no `agentSdks`.
  - The REH-side runtime lock (hash-pinned at tab-template time) and the `rt-*` register
    entries.
- **Upstream drift.** A new runtime package name defeats the asar and path rule silently.
  Each upstream bump must re-check the agent-host dependencies, and the A27 probe backs this.
