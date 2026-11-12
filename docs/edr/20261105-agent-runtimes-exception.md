# Agent runtimes in tabs: a recorded, hash-pinned exception

- **Status:** accepted
- **Date:** 2026-11-05
- **Deciders:** Project owner (2026-11-05): approved the prebuilt agent runtimes as a recorded exception, hash-pinned, because they only run inside tabs. Coordinator: pin every runtime by hash; patch out the run-time downloads; verify npm provenance where it exists; make "runs only inside tabs" an invariant with a probe; record the residual. Secure-agentic-experiences session (record); fork-build session (build-time fetch, register pins, patch).
- **Related:** [ADR supply-chain provenance](../adr/20261104-supply-chain-provenance.md), [ADR agents run in the tab](../adr/20261105-agents-run-in-the-tab.md), [plan §13 D3](../plans/secure-agentic-experiences.md#13-decisions-for-the-project-owner), [agentic surfaces §14](../research/agentic-surfaces.md#14-supply-chain), [EDR supply-chain exceptions](20261105-supply-chain-exceptions.md)
- **Editorial redaction (2026-11-12):** quotations of project conversations replaced with neutral statements; decisions unchanged.

## Context
The agent host runs provider harnesses whose runtimes are opaque prebuilt code:

| Register entry | Package | Version at the pin | What is opaque |
|---|---|---|---|
| `rt-copilot-sdk` | `@github/copilot-sdk` and its platform packages (`@github/copilot-sdk-linux-arm64`, `-linux-x64`, …) | `1.0.27-unstable.41379698026.g3219c66` | The platform package ships prebuilt `copilot-runtime` and `runtime.node` binaries (upstream `build/lib/copilot.ts` checks for both). MIT-labelled |
| `rt-claude-agent-sdk` | `@anthropic-ai/claude-agent-sdk` and its platform packages | `0.3.304` | A bundled agent runtime per platform |
| `rt-codex` | `@openai/codex` and its platform packages (`0.163.0-linux-arm64`, …) | `0.163.0` | The `codex` native binary |

None of them meets the bar: none is built by us from source, and we have not yet verified a
publisher signature or attestation for any of them (see "Verification" below).

Two upstream delivery paths exist:
- The Copilot SDK is an REH dependency (`remote/package.json`), installed by `npm ci`
  against Microsoft's lockfile, which carries a sha512 `integrity` for every package.
- The Claude and Codex SDKs are **not** in the REH. At run time the agent host downloads
  them from `product.agentSdks.<id>.urlTemplate` and treats a `.complete` marker as proof
  of integrity, with no hash check
  ([agentSdkDownloader.ts#L414-L528](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/agentHost/node/agentSdkDownloader.ts#L414-L528)).
  Upstream stamps `agentSdks` into `product.json` at packaging time, from a results file
  that its distribution build produces (`build/gulpfile.reh.ts` `readAgentSdkResults`).
  Our build has no such file today, so **our REH ships without `agentSdks`, and the
  download path is inert** **[inference from the packaging code; the build-time check
  below makes it a fact]**. The agent host also takes a pre-placed SDK root through a
  dev-override flag or environment variable
  ([agentHostServerMain.ts#L103-L113](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/agentHost/node/agentHostServerMain.ts#L103-L113)).

The ADR for agents in the tab puts every one of these runtimes inside the tab, where they
are contained like any other workload. The open question was provenance.

## Decision
The three runtimes are a recorded exception, on these conditions:

1. **Hash-pinned, every artefact, every platform we build.**
   - `rt-copilot-sdk`: the sha512 `integrity` values in upstream's
     `remote/package-lock.json` at the pinned SHA. `npm ci` already enforces them.
   - `rt-claude-agent-sdk` and `rt-codex`: the sha512 `integrity` values for the same
     versions in upstream's root `package-lock.json` at the pinned SHA, where they are
     dev dependencies. Those values become the pins of a fork-owned lock file. The
     tarballs are fetched by name and version and must match the integrity value before
     extraction.
2. **No run-time download.** Our product data never sets `agentSdks`, and a build check
   fails if the packaged `product.json` has it. A small patch makes the agent host refuse
   any download path, so the only way an SDK is found is the pre-placed root. The Claude
   and Codex SDKs are fetched at **tab-template time** (`./seclab template sbx` and the
   OCI image build), hash-checked, extracted into a read-only path in the template, and
   wired up with the SDK-root environment variable. A tab never downloads a runtime.
3. **Provenance where it exists.** Each fetch also runs `npm audit signatures` over the
   fetched set (registry signatures, plus SLSA provenance attestations where the
   publisher has them), and the result for each package is recorded in the register
   entry. A package with no attestation stays covered by this exception and by its pin;
   a package whose attestation is present but fails to verify stops the build.
4. **Only inside tabs.** These runtimes run only in a tab, never in the trusted editor,
   tabd, the broker or any host process. This is invariant **I8** in the plan:
   - the macOS app is built without them: the local agent host is not created
     ([plan §3.5](../plans/secure-agentic-experiences.md#35-no-other-agent-host-connection-in-a-tab-window)),
     and `build/check-release.sh` fails if a `copilot-runtime`, `runtime.node`, `codex` or
     Claude SDK runtime file is present in the app bundle;
   - probe **A27**: while tabs run agent sessions, no process on the host has any of these
     runtimes as its executable or loaded module (checked from the host process table
     and open files), and the sbx collector sees them only inside the tab.

**Register entries covered:** `rt-copilot-sdk`, `rt-claude-agent-sdk`, `rt-codex`. Each is
`bar: exception` with this record, and carries a `gap` until the fork-build session lands
the build-time fetch, the check and the patch.

**Test use.** The agents-in-the-tab spike (`test/agentic/ahp/in-tab.sh`,
[EDR](20261105-agents-in-tab-spike.md)) runs the REH build's `copilot-runtime` in a plain
Docker container, not an sbx tab, as a stand-in for the fenced tab. The container has
`--network none`, read-only access to the builder volume, and one writable directory
under `.work/agentic/runs/`. It holds only a sentinel and a per-run test CA. A
compromised runtime there could write into that run directory and nothing else; it has
no network, no real credential and no host path. That use is covered by this exception
until the spike moves into a real tab.

## Verification status (2026-11-05)
- The integrity values and versions above were read from the lockfiles at the pinned SHA.
- The npm registry could not be reached from this host when this record was written
  (connection refused at the socket, while other HTTPS hosts worked), so registry
  signatures and attestations were **not** checked. Condition 3 makes that check part of
  the build. No claim of provenance is made here.
- **Condition 4 does not hold today.** `@github/copilot-sdk` is a runtime dependency of
  the desktop app as well as the REH (upstream `package.json`), and the desktop gulp task
  packages the platform runtime into the app (`build/gulpfile.vscode.ts`
  `ensureCopilotPlatformPackage` and `getCopilotRuntimePrebuildFiles`). Our macOS app
  therefore very likely carries `copilot-runtime` **[inference from the build code; the
  release check will confirm]**. The fork-build session strips it from the desktop build
  and adds the release check before the exception is relied on.

## Consequences
- **The residual.** A compromised or malicious runtime runs with the tab's full
  authority: it holds the tab's sentinels and its model access, reads the workspace, and
  can do anything a rogue extension in that tab can. It is **contained to the tab, not
  prevented**. The broker's bindings, budgets and model-host body policy limit what it
  can do with the sentinels, and the write-back gate limits what reaches the host
  checkout. It cannot reach a real secret, the host or another tab, by the same arguments
  as any tab workload.
- A bad release cannot reach users silently: a version or hash change is a lockfile
  change, which goes through review.
- Upstream bumps move the pins. The fork-build session re-derives them from the new
  lockfiles and re-runs the signature check.
- **Revisit** if any of these runtimes is published with build provenance we can verify,
  or open-sourced so it can be built from source; or if we choose BYOK with an
  open-source harness instead.
