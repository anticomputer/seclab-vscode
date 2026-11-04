# Remove the built-in Copilot extension from our build (one build patch)

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** fork-build session
- **Related:** `build/product/remove-extensions.txt`, `patches/0001-build-skip-copilot-shim-without-extension.patch`

## Context
At 1.145.0 the local (non-CI) REH and desktop builds fail in
`prepareBuiltInCopilotRipgrepShim`. It expects
`extensions/copilot/node_modules/@github/copilot/sdk`, but the locked
`@github/copilot@1.0.73` ships `copilot-sdk/`. That package's licence is
"SEE LICENSE IN LICENSE.md" (GitHub's proprietary Copilot CLI terms, not
MIT). Redistributing it in an unsigned fork has the same problem as
Microsoft's Remote extensions.

## Decision
- Remove `extensions/copilot` after `npm ci`, listed as data in
  `build/product/remove-extensions.txt`.
- Carry one **build-only** patch (4 lines) that makes the shim step a no-op
  when the extension directory is absent.

## Alternatives considered
- **VSCodium's removal (`53-ext-copilot-remove-it.patch` plus a JSON removal list
  of core agent-host files)**: rejected for now. It is a far larger patch
  surface, and we only need the build to succeed. Revisit if core agent-host
  code proves to depend on the extension at runtime.
- **Fix the shim path (`sdk` → `copilot-sdk`)**: rejected. We would still be
  shipping the proprietary SDK.
- **Pin an older upstream tag**: rejected, because we want 1.145.0's security
  fixes.

## Consequences
- No built-in Copilot chat in the fork. Users can install chat extensions
  from Open VSX into tabs (sandboxed).
- The patch must be re-checked on each upstream bump. It disappears if
  upstream guards the shim itself.

## Evidence
```
Error: [prepareBuiltInCopilotRipgrepShim] Copilot SDK directory not found at
  /work/vscode-reh-linux-arm64/extensions/copilot/node_modules/@github/copilot/sdk
$ ls extensions/copilot/node_modules/@github/copilot/   ->  … copilot-sdk …   (version 1.0.73)
```
Upstream function: `build/lib/copilot.ts` `prepareBuiltInCopilotRipgrepShim` at a717861c07586a53d83b80d742cd3f59b20a6273.
