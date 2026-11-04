# seclab-tabd is dependency-free TypeScript, run on the editor's own Node runtime

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** fork-build session
- **Related:** [ADR tab supervisor](../adr/20261104-tab-supervisor.md)

## Context
The supervisor runs on the user's machine, next to the editor. Nothing may be
installed on the host. It must also run in CI and in the test harness, and be
small enough to audit.

## Decision
- Write `seclab-tabd` in **TypeScript with zero npm runtime dependencies**,
  using only the Node standard library (`child_process`, `crypto`, `fs`,
  `path`). Compile it to one JavaScript file.
- **Runtime on macOS:** the editor's own Electron binary in Node mode. The Tab
  Manager spawns `process.execPath` with `ELECTRON_RUN_AS_NODE=1` and the
  bundled script. VS Code already uses this pattern for git askpass helpers,
  so it adds nothing to the host.
- **Runtime in CI and the harness:** any Node ≥ the upstream `.nvmrc` version,
  inside containers.
- The driver contract and protocol types are shared with the Tab Manager
  through a source-level import (one TS module, no package).

## Alternatives considered
- **Go static binary**: it gives a single artifact and a smaller runtime, but
  it is a second language and toolchain, cross-compilation in CI, and no
  type sharing with the extension. It's a good fit later for a remote
  supervisor; revisit then.
- **Rust**: same trade-off as Go, with a heavier toolchain.
- **Shell scripts**: rejected. Argument injection risk is exactly what we
  must avoid.

## Consequences
- The supervisor's Node is whatever Electron ships (pinned by upstream).
- `ELECTRON_RUN_AS_NODE` must not leak into tab environments. The supervisor
  builds runtime argv and env explicitly, and never passes its own env through.
