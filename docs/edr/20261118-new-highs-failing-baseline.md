# New highs closed by their own change show their test failing on main

- **Status:** accepted
- **Date:** 2026-11-18
- **Deciders:** Coordinator (2026-11-18), extending the project owner's principle of 2026-11-17 behind [fixed before landing](20261117-fixed-before-landing.md): a regression test must be shown failing on the baseline. Security-findings-register session: implementation.
- **Related:** [security findings register](20261110-security-findings-register.md), [fixed before landing](20261117-fixed-before-landing.md), [review record](../security-reviews/20261110-security-findings-register.md) (round IIII)

## Context
A high can be found on `main` and fixed in a later pull request, as RPC follow-ups' R5-14 is fixed
by their patch 0057. Under review EEEE the register already lets such a change record the high as
`fixed`, citing its own fix as a `patch:` commit. Only a high that `main` or the merge base had
already recorded needs its fix on `main` first (CCCC-1). The change must name a regression test
that exists, but nothing asks for evidence that the test fails without the fix.
`fixed-before-landing` asks for that evidence for code that never reached `main`. A high in code
that did reach `main` had the weaker bar.

## Decision
1. A high that neither `main`'s register nor the merge base's has, registered `fixed` with a fix
   commit that isn't on the change's base, carries the same evidence as `fixed-before-landing`:
   - `preFix`: a commit on `main` (the change's base or an earlier one) that the fix descends from,
     where the test fails;
   - `preFixRef { file, quote }`: where that failing run is recorded. The quote names the test and
     says it failed.
2. The host checks the commits (`findings_own_fix`):
   - the fix is on the change's history;
   - `preFix` is a different commit that the fix descends from;
   - `preFix` is on the base's history, so on `main`.

   Any `main` ancestor of the fix is allowed, so `gh pr update-branch` (which moves the base)
   doesn't invalidate the citation. A commit already on `main` can't be the first half of an
   add-then-revert pair inside the change, so CCCC-1's protection holds, and a fix that is reverted
   later still closes nothing (EEEE-1, PRR11-2).
3. `findings.ts` lists such entries (`ownfix`) and checks the two fields' shape. `preFixRef` is checked
   for the entry's whole life, as a test is.
4. Grandfathered: an entry `main` already has, and a `fixed` high whose fix commit was already on the
   change's base (an old fix registered late), need neither field. A local check on `main` with no
   landing range skips the commit check, as it skips the other new-entry rules.

## Consequences
- RPC follow-ups adds `preFix` and `preFixRef` to R5-14; any in-flight pull request closing a new
  high EEEE-style does the same.
- Every high closed in the change that fixes it now carries proof that its test failed without the
  fix. `fixed-before-landing` is the variant for code that never reached `main`.
- The failing run is attested by the review record, not executed by the gate, as for
  `fixed-before-landing`.
