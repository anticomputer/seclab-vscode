# Findings fixed before they land, and a register that rebases cleanly

- **Status:** accepted
- **Date:** 2026-11-17
- **Deciders:** Project owner (2026-11-17): a finding fixed in the change that raised it is not an owner acceptance. Coordinator: the landing problems to solve. Security-findings-register session: implementation.
- **Related:** [CI hardening](20261104-ci-hardening.md) (the docs workflow), [security findings register](20261110-security-findings-register.md), [landing through pull requests](20261116-pr-landing.md), [review record](../security-reviews/20261110-security-findings-register.md) (round GGGG)

## Context
A review of an unmerged change can find a high, and the change can fix it and add its regression
test before it lands. The register had no honest status for that:
- `fixed` with a `patch:` fix commit closes a high only once the fix is on `main` (CCCC-1), so that
  a change can't close a recorded high with an add-then-revert pair of its own;
- an open high outside the baseline needs an owner acceptance.

So the finding could land only as an owner-accepted residual. The project owner rejected that,
since the vulnerable code never reached `main`. Two highs were waiting on this (RSC-1 and R12-2).

Three more landing problems sit in the same tool:
- `main` went red three times on 2026-11-17 after a correct landing. The required docs gate ran with
  the push's range and passed. The link-check step re-runs `./seclab docs check --online` without
  `DOCS_BASE`, so on `main` it compared with `HEAD^1`. A fix commit from the same push then
  looked older than the change, and the pin rule failed until a follow-up pinned it.
- A hand-resolved rebase re-indented `findings.json` with two spaces, and nothing caught it.
- Every pull request touching the register conflicts in `findings.json` and `FINDINGS.md`, which
  `gh pr update-branch` can't resolve. Each hand resolution restarts the wait for `oci`.

## Decision
1. **A status `fixed-before-landing`.** It counts as fixed (closes a high, leaves the open lists),
   but only for a finding the change itself brings, together with its fix and its test:
   - the entry needs `commit`, `test { file, name }`, `preFix` (the reviewed commit the test fails
     on, as a SHA or `patch:<id>`) and `preFixRef { file, quote }`. That is where the failing run is
     recorded, and the quote names the test and says it failed;
   - the entry is new since the base. An entry the base had can't gain the status, so a recorded
     finding still closes as `fixed` under CCCC-1;
   - its record, its test file and `preFixRef`'s file all change in the same change;
   - on the host, the reviewed commit and the fix are distinct commits on this history, the
     reviewed one an ancestor of the fix, and the reviewed one wasn't there before the change (on a
     pull request its base, on `main` the push's previous head);
   - `preFixRef` is checked for the entry's whole life, like a test, and an entry with no base
     register to compare with fails rather than passing unjudged (review GGGG).
   - an entry the base had only on its branch counts as new when it lands, so it is judged in full
     then; a landed one keeps the status and its evidence (it may reopen, never become plain
     `fixed`); and a local check on `main` with no landing range treats landed entries as landed,
     while CI on `main` without a range fails (pull request #11's automated review, PRR11).

   An add-then-revert pair can't produce this: it has no test that fails on the reviewed commit,
   and a reverted fix still fails findings_ancestry. The gate can't run an arbitrary test, so
   whether the test really failed on `preFix` rests on the review record that `preFixRef` quotes.
   The review round checks it, as it checks every `fixed` entry's test. Once landed, the entry is
   judged like `fixed`: its fix must be on `main`.
2. **Every docs step judges the change's own range.** The link-check step in `docs-check.yml`
   gets the same step-level `DOCS_BASE` as the gate step: the PR's base, or the push's previous
   head. Step-level, so no earlier step's `GITHUB_ENV` can replace it. Reading the event payload in
   the host was considered and dropped (review GGGG-7): that file is writable by earlier steps of
   the job. And on `main` itself, a `patch:` citation that landed before the push is a note to pin,
   never a failure: the pull request already met that rule against its exact base, so a red `main`
   would only report a landing that was correct. `./seclab findings pin` stays a later tidy-up.
3. **One byte format.** The docs check fails unless `findings.json` is exactly what the tool's
   writer produces (tab-indented, final newline). `./seclab docs write` rewrites it into that
   format.
4. **`./seclab findings rebase-resolve`.** Run during a conflicted rebase or merge. It merges the
   register three ways by entry key from the index stages:
   - each side's change to an entry, owner or list member is taken;
   - an entry changed both ways, or changed on one side and removed on the other, is a real clash
     and is refused, left for a hand;
   - a top-level key outside the register, or a finding one side removed, is refused too;
   - the merged register must pass the schema;
   - order: the side being rebased onto first, then entries only the replayed commit adds.

   It also runs when only the generated files conflict, the common case. It then regenerates
   `FINDINGS.md` and the record indexes, and stages only what it resolved. A
   file still holding conflict markers outside its generated part is listed, never staged. A git
   merge driver was not chosen: it would need configuration in every clone, and couldn't
   regenerate the view.

## Consequences
- RSC-1 and R12-2 can land as `fixed-before-landing` in the pull requests that fix them, with no
  owner acceptance.
- A landing no longer turns `main` red on a citation the pull request had right. The citation is
  pinned later, as before.
- A register conflict between two pull requests that touched different entries resolves with
  one command, so `update-branch` failures cost a local rebase but no hand edits.
- The failing-baseline evidence is attested, not executed, by the gate. A false claim is a review
  failure, not a gate failure.
