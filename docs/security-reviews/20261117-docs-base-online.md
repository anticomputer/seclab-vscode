# Security review: the online docs step's DOCS_BASE (round DBO)

- **Date:** 2026-11-17
- **Scope:** round DBO, by an Opus-class model, of the change that passes `DOCS_BASE` to
  `docs-check.yml`'s "External links resolve" step and makes `findings_main_base` refuse, in CI,
  to guess a base when no previous head is given.
- **Why:** that step re-runs the register check. Without `DOCS_BASE`, on main it compared the
  pushed head with its first parent only, so a landing whose last commit registers an entry
  citing an earlier commit of the same push failed main's `docs` (after PR 38).
- **Threat model:** the register check must not get weaker or gain a PR-controlled input; the
  workflow keeps the CI baseline (EDR ci-hardening): values through `env:`, no token in the step.

## Round DBO
Nothing at medium or above. The expression is the gate step's, through `env:`; both operands are
GitHub-computed commit names; `findings_main_base` checks the value's shape before git sees it,
and consults it only when HEAD is on main's history (never on a pull request). Every CI caller
sets `DOCS_BASE`, and both workflows run only on push and pull_request.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| DBO-1 | Low | base | The CI guard covered only an empty previous head; one equal to HEAD still fell back to HEAD^1 silently. | Fixed | In CI, a previous head that is empty or HEAD fails; all zeros (a ref creation, with nothing earlier) still compares with HEAD^1. Self-test cases for both. |
| DBO-2 | Info | prompt injection | None found. | No finding | — |
