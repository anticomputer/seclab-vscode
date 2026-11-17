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

## Round 2
FU-2, FU-3 and FU-4 confirmed closed (FU-6, FU-7, FU-8). Plain `clean` deletes nothing a build
needs across builds: every cache is ignored or lives outside the tree.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| FU-6 | Info | build.sh | FU-2 fix confirmed. | No finding | — |
| FU-7 | Info | fetch-upstream | FU-3 fix confirmed. | No finding | — |
| FU-8 | Info | fetch-upstream | FU-4 fix confirmed. An untracked nested repository or an undeletable file stops the build (fail closed), with no message saying why. | No finding | Also adopted: `clean -ffd`, and the failure prints what still differs. |
| FU-9 | Low | fetch-upstream | If `.git` is a file or a symlink, the index removal misses the real repository and the FU-3 gap reopens silently. | Fixed | A `.git` that isn't a directory is refused; the git directories are resolved through git. |
| FU-10 | Low | fetch-upstream | `info/exclude`, a configured excludes file, `status.showUntrackedFiles` or global sparse config could hide a planted file from both the clean and the check. | Fixed | The reset, clean and check read no system or global config, override those keys, and the exclude file is removed. |
| FU-11 | Low | install stamp | Path and content were hashed without framing, a symlinked lockfile was skipped, and a newline in a path desynchronised the loop, each failing toward a stable stamp. | Fixed | `sha256sum` over a NUL-separated, sorted list (hash plus name per file); a symlinked lockfile is refused. |
| FU-12 | Info | build cache | Upstream reuses a cached marketplace built-in in `.build/builtInExtensions` if its version matches, without checking its hash again. | No finding | The local volume build makes only the REH, which fetches none (the directory doesn't exist there), and desktop builds run on fresh Actions runners. |

Regression tests: `build/fetch-upstream.test.ts` (in `./seclab test unit`) drives the script and the
stamp against a local two-release upstream. Each case fails on the code before its fix.

No prompt-injection text was found in the diff.
