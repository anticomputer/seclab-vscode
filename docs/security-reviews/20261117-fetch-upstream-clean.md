# Security review: fetch-upstream cleans a previous pin's files (round FU)

- **Date:** 2026-11-17
- **Scope:** round FU, by an Opus-class model, of the `build/fetch-upstream.sh` fix on the
  1.145.3 bump branch. A build volume moved to a new upstream pin kept the untracked files an
  earlier pin's patches had added, so patch 0005's new files failed to apply. The fix cleans
  them after the checkout. The review also covered what the clean leaves behind and what the
  pinned-SHA check proves.
- **Threat model:** nothing from an earlier build, pin, patch queue or test variant reaches a
  shipped artifact, and the tree a build starts from is the pinned upstream commit.

## Round FU

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| FU-1 | Info | fetch-upstream | Every path a shipping patch writes is inside the cleaned set, so nothing a patch created survives a pin change any more. | No finding | — |
| FU-2 | Medium | build.sh | The install stamp hashed only three lockfiles, though built-in extensions bundle their own `node_modules`. A pin bump could keep the old pin's dependency trees and skip the registry audit, which runs only when the stamp changes. | Fixed | The stamp hashes every `package-lock.json` and the upstream commit. Proven by a build that reinstalled once on the new stamp and a rebuild that did not. |
| FU-3 | Low | fetch-upstream | The pinned-SHA check names HEAD only. A reused volume's index (skip-worktree or sparse state, stat info) can hide a modified tracked file from the reset. | Fixed | The index is rebuilt before the reset (and sparse state dropped), and the script fails if the tree still differs. An injected skip-worktree edit survived the old script and not the new one. |
| FU-4 | Low | fetch-upstream | The clean took a hand-kept path list, so a stray untracked file such as `product.json.seclab-test` survived. | Fixed | `git clean -fd` with no pathspec: every untracked file goes, ignored build state stays. An injected stray file survived the old script and not the new one. |
| FU-5 | Info | CI | No regression for a fresh volume or the same-pin path. | No finding | — |

Regression tests: `build/fetch-upstream.test.ts` (in `./seclab test unit`) drives the script and the
stamp against a local two-release upstream. All three cases fail on the code before the fix.

No prompt-injection text was found in the diff.
