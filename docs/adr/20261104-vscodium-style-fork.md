# Fork VSCodium-style: pinned upstream, jq product.json, small patch queue

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** Project owner (2026-11-04); seclab-vscode coordinator
- **Editorial redaction (2026-11-12):** quotations of project conversations replaced with neutral statements; decisions unchanged.

## Context
We must track upstream Code-OSS cheaply, because security fixes land there
monthly, while carrying policy (product.json) and a handful of core patches
(RPC filter, auth mediation, storage partitioning).

## Decision
- `upstream.lock` pins a Code-OSS tag and commit SHA. A script fetches exactly
  that commit and verifies the SHA.
- `product.json` changes are **data**, applied with a `jq` program on every
  build: proposed-API grants, `extensionKind` overrides, Open VSX gallery,
  Settings Sync off. They never cause merge conflicts.
- `patches/NNNN-*.patch` is an ordered queue: one concern per file, under
  about 50 lines each, applied with `git apply`. It is empty for M0/M1.
- Our own code (the Tab Manager extension) lives outside the upstream tree and
  is copied in at build time.

## Alternatives considered
- **Hard fork that merges upstream (Positron)**: rejected. Every release needs
  a large manual merge; justified only for invasive UI work, which we avoid.
- **Git submodule plus diff stack (code-server)**: rejected. It gives the same
  pin with more mechanics, and the submodule invites drive-by edits to
  upstream code.
- **Theia**: rejected. It reimplements the API on a different core, but we
  need VS Code's actual workbench and REH plumbing.

## Consequences
- Bumping upstream is a procedure (AGENTS.md): update the lock, re-run jq,
  rebase patches, run the drift check, containment suite and security review,
  and write an EDR.
- `extensionKind` has no wildcard key, so overrides are per extension ID until
  a small patch adds one.

## Evidence
- VSCodium model: [prepare_vscode.sh#L1-L40](https://github.com/VSCodium/vscodium/blob/ca7f7b44b5e5c3faa663f6cdc043998f71936653/prepare_vscode.sh#L1-L40)
- `extensionKind` is keyed per ID: [product.ts#L252](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/base/common/product.ts#L252), lookup in [extensionManifestPropertiesService.ts](https://github.com/microsoft/vscode/blob/6e35f5ceffa04ac728a0fb3a0dd6fb9cdb4ff100/src/vs/workbench/services/extensions/common/extensionManifestPropertiesService.ts#L493-L506)
- [`docs/research/vscode-internals.md`](../research/vscode-internals.md) §7
