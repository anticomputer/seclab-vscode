# Patch-build gate: the patched tree must compile, and patches must land in what ships

- **Status:** accepted
- **Date:** 2026-11-05
- **Deciders:** anticomputer (user). Verbatim: "New required CI gate: patched-tree compile". Coordinator: the requirements below. Fork-build session: implementation.
- **Related:** [EDR patch series](20261104-patch-series.md), [patch queue](../../patches/README.md), [review](../security-reviews/20261104-supply-chain.md)

## Context
The RPC session's re-review found that patch 0011 had never been built. It was missing its
dependency-injection imports, and it registered its service in `workbench.web.main.ts`, while
desktop tab windows load `workbench.desktop.main.ts`. Every gate passed it:
- `build/apply-patches.sh --check` and `sync_patch.py --check` show that a patch applies and
  carries what we think it carries;
- neither type-checks, and neither knows which entry points ship.

## Decision
A required check, `patch-build` (`.github/workflows/patch-build.yml`), runs on every push and
pull request, with no path filter:
1. **Fetch and patch.** `build/fetch-upstream.sh` fetches the pinned upstream (tag → SHA
   verified). Node must equal upstream's `.nvmrc`. `build/apply-patches.sh` applies exactly
   `patches/series`.
2. **Install.**
   - `npm ci --ignore-scripts`: type-checking needs the packages' types and runs none of their
     install scripts.
   - Then `build/npm-audit-signatures.sh`.
   - `node_modules` is cached on the pinned SHA plus upstream's lockfile. The cache is saved
     only from main, so a branch can't seed what main restores.
3. **Type-check.** Upstream's own `npm run typecheck-client` (`tsc -p src/tsconfig.json
   --noEmit`) over the whole patched `src`, with a 12 GB heap.
4. **Reachability.** `build/check-patch-reach.ts` reads the entry points from upstream's own
   bundler:
   - `build/next/index.ts`: desktop, worker, code and server entry points;
   - `build/lib/esbuild.ts`: bootstrap entries.
   
   So the entry points follow upstream, and a list it can't parse fails closed. It builds the
   import graph from runtime edges only: static and literal dynamic imports, with comments
   stripped and type-only imports and exports skipped, since those are erased at compile time
   (review VV-6). Every `src/**/*.ts` file
   a patch in the series touches must then be reachable from the desktop build or the REH,
   never only from web. `patches/reach.json` can require specific targets for a security
   patch, for example a channel filter that must sit in both `desktop` and `server`; a patch
   named there that touches no `src/**/*.ts` file fails, rather than passing with nothing checked.
   `--file PATH...` reports targets for patch authors.

`patch-build` joins `unit`, `lint` and `docs` as a required status check in the `main`
ruleset. AGENTS.md has the hard rule: a patch is not done until the patched tree compiles in
CI and a runtime probe shows the patched code executing in the shipped build.

## Consequences
- What compiles and reaches a shipped entry point can still be dead at run time: a
  registration behind a condition, or a contribution that never activates. The runtime probe
  in the AGENTS.md rule covers that, per patch. This gate catches the two static failures
  cheaply.
- File-level reachability is a proxy for the patched symbol. The `patches/reach.json`
  per-target requirement makes it specific for security patches. The RPC session's
  `IRemoteAgentHostService` registration check is the symbol-level special case.
- Cost: a cold run fetches upstream and installs `node_modules`, a few minutes; a cached run
  is dominated by the type-check.
- Verified locally against the cached tree:
  - all nine files patched by 0001–0004 and 0012 reach a shipped target (0012's files reach
    `desktop`);
  - `workbench.web.main.ts` reaches only `web`, so a patch there now fails;
  - patch 0012's type-check (scoped to its import closure, 232 files) gives errors identical
    to the unpatched baseline.
