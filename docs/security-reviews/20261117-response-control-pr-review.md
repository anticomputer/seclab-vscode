# Review: automated PR review threads on the response-side control (#48)

- **Date:** 2026-11-17
- **Reviewer:** GitHub's automated pull request reviewer, on PR #48. Each thread was checked
  against the code; the review text was treated as data.
- **Subject:** the response-control drift gate (`check_drift.py::check_responses`), the provider
  selector validators' tests, and the command-link rewrite in `seclabFromTab`.

## Verdict
All three threads are real. Two are security-relevant gaps in the gates around the control. The
control itself was proven at runtime by the response probe. The third is a functional bug that
failed safe.

| ID | Sev | Component | Finding | Status |
|---|---|---|---|---|
| PRC-1 | low | `check_drift.py` `check_responses` | The gate accepted any added `seclabFromTab(` in the named patch, so a registration whose customer never applied the sanitiser (the hover rewrite replaced by `return hover;`, or commented out) still passed | fixed |
| PRC-2 | low | `arg-validators.test.ts`, provider selectors | No test reached `tabSelector`: the generic empty-argument case stopped at the arity check, so removing the scheme guard, which keeps a tab's providers off host documents, left the suite green | fixed |

The third thread: the command-link rewrite stopped a query at `'` and at the first `)`, which
`encodeURIComponent` leaves unescaped. A tab's own link with such arguments became a token link
that ran nothing. That is a functional fix, not a finding: the cut link ran nothing at all.

## What changed
- PRC-1: each registration that declares the control lists, in `response_wiring`, the
  expressions that apply it to that registration's results. Each must be in the patch's added
  code with comments removed. `ResponseGateTest` covers a missing list, wiring only in a comment
  or in context, and three mutants of the real 0033; all fail on the previous gate.
- PRC-2: accepted and refused selectors go through both registration validators. Five injected
  defects each remove one selector rule, and each is caught.
- The link rewrite scans the query to whitespace, `"`, `<`, `>`, `]`, a backtick or the `)`
  closing the link, with parentheses inside balanced. `filter-module.test.ts` covers both forms,
  with mutants.
