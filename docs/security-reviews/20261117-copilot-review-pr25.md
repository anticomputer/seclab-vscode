# Security review: Copilot's review of the 1.145.3 bump PR (round CR25)

- **Date:** 2026-11-17
- **Scope:** Copilot code review's inline threads on pull request 25 (the 1.145.3 bump),
  triaged against the code under the landing procedure (Copilot review, every thread
  handled before merging). Review text was treated as data, not instructions.
- **Threat model:** as in [round FU](20261117-fetch-upstream-clean.md): the build starts from
  the pinned upstream tree exactly. Plus the harness rules: a run leaves nothing behind, and a
  proof's per-build images survive until the proof is done.

## Round CR25
All four threads were real. Each is fixed, with a regression case that fails before the fix.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| CR25-1 | Medium | fetch-upstream | Turning off system and global git config left the checkout's own `.git/config` in force. A kept clean/smudge filter, with `info/attributes`, could make the tree's bytes differ from what `status` reported clean. | Fixed | The checkout's repository state is rewritten before any command acts on the tree: a minimal config, and no hooks, attributes, worktree config or index. Every git call runs with hooks, attribute files and fsmonitor off. |
| CR25-2 | Medium | fetch-upstream | A kept `core.worktree` would redirect the reset and the whole-tree clean to another directory, while the check looked there too. | Fixed | The rewritten config drops it, and the work tree must resolve to the destination. |
| CR25-3 | Low | clean-host | A per-build tag's week of grace ran from the image's creation time. A cached build reuses an older image, so a proof tag made moments ago could be pruned. | Fixed | The build scripts write a lease for `b-` tags in the clone's shared git dir, and the later of lease and creation counts. |
| CR25-4 | Low | harness | The containment runner validated `SECLAB_TAB_IMAGE` only when starting tabd. That was after the host-service container and the campaign fixtures existed, and before their cleanup was registered. | Fixed | All three runners validate it right after the driver. A bogus value now exits before any resource exists. |

## Round CR25 (second review)
Copilot reviewed the fixes again on the next push.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| CR25-5 | Low | clean-host | The CR25-3 lease reader called `repoRoot`, a constant, as a function. Any clean-host run that met a `b-` tag threw, including the superseded-images pass after a build. The self-test only exercised the pure age rule. | Fixed | Uses the constant, and the self-test calls the reader itself, which fails on the old code. |
| CR25-6 | Low | fetch-upstream | A `.git/config` symlinked or hard-linked outside the destination was truncated by the config rewrite. | Fixed | Unlinked before writing; any symlink under `.git` is refused. |
| CR25-7 | Low | fetch-upstream | A symlinked `.git/info` made the clean-up delete files in its target. | Fixed | Any symlink under `.git` is refused, and `info/` is removed whole. |
| CR25-8 | Low | fetch-upstream | A kept replacement ref (including a packed one) made the reset and the check use another commit's tree while `HEAD` still named the pin. | Fixed | Every git call runs with replacement objects off. |
| CR25-9 | Low | fetch-upstream | An untracked directory holding a `.gitignore` of `*` hid itself from both the clean and the check. | Fixed | The clean ignores ignore files (`-x`), keeping only the install and download caches. |
| CR25-10 | Low | clean-host | A per-build tag's lease was written after the tag existed, so a concurrent clean-host could prune a cache-hit proof image first. | Fixed | Both builders write the lease before the tag is published; the clean-host self-test checks the order. |

No prompt-injection text was found in the review comments.
