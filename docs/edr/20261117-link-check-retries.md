# Link check: retry GitHub's rate limits instead of accepting them

- **Status:** accepted
- **Date:** 2026-11-17
- **Deciders:** Coordinator (2026-11-17): retry GitHub's 503 and 429 with backoff, and keep
  failing on links still dead after the retries. Fork-build session: implementation.
- **Related:** [CI hardening](20261104-ci-hardening.md), whose note that GitHub rate limits are
  absorbed by accepting 429 this replaces

## Context
The required `docs` job checks every external link with lychee. A change that adds many permalinks
to one host (the 1.145.3 RPC inventory adds hundreds to `github.com/microsoft/vscode`) drew 503s
from GitHub, which lychee reported as errors after its default three quick retries. So a red
`docs` was ambiguous: a dead link, or GitHub throttling the check. It failed main and several pull
requests that way. 429 was accepted outright, so a throttled link was never checked at all.

## Decision
lychee (`./seclab docs check --online`):
- retries a failed request up to 5 times, waiting at least 3 seconds between tries (about a
  minute and a half for a link that keeps failing, so a throttled run stays inside the job's
  timeout; a timeout cancels the job, which blocks like a failure);
- paces requests per host: at most 4 at once, 200 ms apart as a baseline, which lychee raises
  adaptively when a host pushes back;
- no longer accepts 429. A link still answering 429, 503 or another error after the retries fails;
- never caches a 403 (GitHub's secondary rate limit), 429 or 5xx result, so a throttled answer
  isn't replayed as the link's state. The CI cache key is versioned (`lychee-v2-`), dropping
  entries an earlier run cached when 429 was accepted;
- checks a blob permalink (`github.com/<owner>/<repo>/blob/<ref>/<path>`) at
  `raw.githubusercontent.com/<owner>/<repo>/<ref>/<path>`, the same file at the same commit. The
  first CI run with retries alone still failed: GitHub answered 238 of about 700 unique blob
  permalinks with 503 through all five retries, and every error was a blob page. A missing file,
  path or commit is a 404 at raw too, so a dead permalink still fails. Line anchors were never
  checked, at either host. lychee remaps before it excludes, so this repo's own links are excluded
  under both hosts.

## Proof
On main's tree the online check passed with no errors (2432 links, from a warm local cache). With one dead permalink
injected (a file that doesn't exist at the pinned upstream commit), it failed with a 404 for that
link.

With the raw remap, from an empty cache: 2438 links, 0 errors, the same 13 excluded as before.
Injected dead permalinks failed with 404 at raw: a missing file at the pinned upstream commit,
and an existing path at a commit that doesn't exist.

## Consequences
- A blob permalink to a private repository fails at raw as it would at github.com (no
  credentials ever reach lychee).
- The online check is slower when GitHub pushes back, and stays red when GitHub throttles beyond
  the retries. A persistent 429 is now a failure, where it used to pass silently.
