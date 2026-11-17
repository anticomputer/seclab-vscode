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
