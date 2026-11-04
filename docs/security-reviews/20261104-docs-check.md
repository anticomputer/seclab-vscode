# Security review: docs-check gate (CI workflow and checker)

- **Date:** 2026-11-04
- **Scope:** `a3d19d2..47d768d`: `.github/workflows/docs-check.yml`, `build/docs/docs-check.ts`, `./seclab docs`; and the fixes in this commit
- **Open high/critical:** none
- **Reviewer:** `security-review` agent

## Round 1
| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| DC-1 | Info | CI risk | Acceptable: there is no `pull_request_target`, permissions are `contents: read`, `persist-credentials: false`, and actions are SHA-pinned. PR code runs, as on any `pull_request`. The token was visible in lychee's argv. | Fixed | The token is passed by environment (`-e GITHUB_TOKEN`). |
| DC-2 | Low | Cache | The lychee cache was keyed only by run, with a broad restore-key. | Fixed | Keyed by `github.ref`; restores the same ref, then main. |
| DC-3 | Low | Fail-open | A `ci: run` block with another fence spelling, CRLF line endings or trailing spaces was silently dropped, and zero blocks passed. | Fixed | Every marker must introduce a block, at least one block must exist, and CRLF and `shell` fences are accepted. |
| DC-4 | Low | Fail-open | The broker check was skipped if its script wasn't executable or was missing. | Fixed | It runs with `bash`; if `broker/` exists without the script, the gate fails. |
| DC-5 | Low | Paired range | Pushes to main and stacked PRs used the wrong base. | Fixed | CI passes `DOCS_BASE` (the PR's base SHA, or the push's `before`), and an unavailable base fails. |
| DC-6 | Low | Trailer | `docs-not-needed:` matched anywhere in any message. | Fixed (partly) | Only real git trailers count (`%(trailers:key=docs-not-needed)`). One trailer still covers the whole range: accepted, since this is a soft rule. |
| DC-7 | Low | Links | Reference-style and `<a href>` links weren't checked, and raw/blame URLs weren't covered by the pin rule. | Fixed | Both forms are parsed, and `raw.githubusercontent.com` and `/(blob|tree|blame|raw)/` must be SHA-pinned. |
| DC-8 | Info | Records | No silent pass found. | — | — |

**No medium-or-higher findings.**
