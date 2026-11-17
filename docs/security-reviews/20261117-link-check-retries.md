# Security review: link-check retries (round LCR)

- **Date:** 2026-11-17
- **Scope:** round LCR, by an Opus-class model, of the lychee change in
  [EDR link-check-retries](../edr/20261117-link-check-retries.md): the `./seclab docs check
  --online` arguments, and a comment in `docs-check.yml`.
- **Threat model:** the required `docs` job must not pass a dead link, must not give PR content a
  new way to influence the runner, and must fail closed (a timeout or cancel blocks).

## Round LCR
Nothing at medium or above. lychee's arguments are literals, so PR content still only chooses
which URLs are fetched. A cancelled or timed-out job blocks a merge, and the retry loop is finite.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| LCR-1 | Info | cache | A 200 cached up to 3 days ago is replayed even if the link has since died. Unchanged by this change. | No finding | — |
| LCR-2 | Low | cache | Results an earlier run cached as success under the old `--accept 429` would be replayed for up to 3 days. | Fixed | The CI cache key is versioned (`lychee-v2-`). |
| LCR-3 | Info | runner | No new way for PR content to reach the runner: every argument is a literal. | No finding | — |
| LCR-4 | Low | timeout | Six retries with doubling waits could push a throttled run past the job's timeout. That fails closed, but defeats the point. | Fixed | Five retries from 3 seconds. |
| LCR-5 | Info | hang | No hang: requests and retries are bounded, and the job timeout cancels. | No finding | — |
| LCR-6 | Info | cache | Pull requests read main's cache and write none. Unchanged. | No finding | — |
| LCR-7 | Low | cache | GitHub's secondary rate limit answers 403, which could be cached and replayed red. | Fixed | 403 is never cached. |
| LCR-8 | Info | prompt injection | None found. | No finding | — |

## Round LCR2
Of the change that checks GitHub file permalinks at `raw.githubusercontent.com`, after the first CI
run with retries alone still failed on 503s. Nothing at medium or above. No dead github.com
permalink was found that passes at raw, and no link can be remapped into this repo's exclusion
unless it names this repo.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| LCR2-1 | Low | exclusion | The raw exclude that kept this repo's remapped links excluded also skipped raw links to this repo written in a doc, which used to be checked. | Fixed | A first-match remap maps this repo's github.com links to themselves, so no raw exclude is needed; the online check's self-test requires a raw self-link to be checked. |
| LCR2-2 | Info | coverage | Only https blob links were remapped; http, `raw` and `blame` permalinks still went to github.com. Fails closed. | Fixed | The remap takes http or https and blob, raw or blame. |
| LCR2-3 | Info | spurious failures | A blob URL naming a directory, or a private repository, fails at raw. Fails closed; the private case is in the EDR. | No finding | — |
| LCR2-4 | Info | cache | The cache key isn't bumped. No stale success can mask a dead link: an old key replays a real 200, a new key misses. | No finding | — |
| LCR2-5 | Info | prompt injection | None found. | No finding | — |
