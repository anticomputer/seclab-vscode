# A failed local install never destroys the working one

- **Status:** accepted
- **Date:** 2026-11-05
- **Deciders:** Coordinator: "Make local builds use a lockfile-verified cache that a failed `npm ci` can't destroy: install into a temp dir, then swap it in." Fork-build session: implementation.
- **Related:** [pinned tools](20261105-pinned-tools.md) (`sig1-` stamp, TT-6), [patch-build gate](20261105-patch-build-gate.md)

## Context
`build/linux/build.sh` reinstalls dependencies when the lockfile stamp changes. The `sig1-`
stamp (TT-6) forces one reinstall of any tree installed before the signature audit existed.
On 2026-11-05, registry.npmjs.org was unreachable locally (TLS EOF). A local editor
build triggered that reinstall. `npm ci` deletes `node_modules` before it fetches, then failed
on the network, so the shared `seclab-vscode-work` volume lost every `node_modules`. Local
builds, scoped type-checks and the agentic spike all depended on it.

## Decision
- **Keep aside, then restore** (`build/linux/nm-keep.sh`, sourced by `build.sh`):
  - Before installing, every `node_modules` under the tree (root, `build/`, `remote/`,
    `extensions/*`, which upstream's postinstall fills) is moved to `/work/.nm-prev`. That is
    on the same volume, so each move is a rename. It is outside the paths `fetch-upstream.sh`
    cleans.
  - If the seed, `npm ci`, the ripgrep check or the signature audit fails, whatever the
    install left is removed and the kept copy is moved back. The build then exits non-zero
    with the old install intact. Its stamp is unchanged, so the next run retries.
  - A run that dies mid-install leaves `/work/.nm-prev`; the next run restores it first.
- **Persistent npm cache** at `/work/.npm-cache`. npm checks each cached tarball against the
  lockfile's `integrity` when extracting, so the cache adds no trust; it only cuts registry
  fetches.

## Alternatives considered
- **Install into a separate directory, then swap**, as the coordinator suggested. Upstream's
  install isn't one directory: the postinstall runs `npm ci` in `build/`, `remote/` and each
  built-in extension, against paths inside the source tree. Installing elsewhere would mean a
  second full copy of the tree. Keeping the old directories aside and swapping back on failure
  gives the same guarantee, a failed install changes nothing, using renames on one volume.
- **Skip the reinstall when only the stamp prefix changed.** The `sig1-` reinstall exists so
  that no tree is used without its registry signatures checked, and skipping it would undo
  that.

## Consequences
- **Verified 2026-11-05:** `build/linux/nm-keep.test.ts` (in `./seclab test unit`) builds a
  tree with root, nested and extension `node_modules`, keeps them aside, simulates a partial
  failed install, restores, and asserts the tree is byte-identical to before.
- **The lost volume still needs one successful install,** which waits on the registry being
  reachable locally. CI is unaffected.
- **macOS builds run on fresh hosted runners,** so they have no cache to lose.
