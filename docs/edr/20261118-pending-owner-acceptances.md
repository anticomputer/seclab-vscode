# Pending owner acceptances: the owner's decision before the finding's record

- **Status:** accepted
- **Date:** 2026-11-18
- **Deciders:** Coordinator (2026-11-18): a pending owner-acceptance row, valid for seven days. Security-findings-register session: implementation.
- **Related:** [security findings register](20261110-security-findings-register.md), [fixed before landing](20261117-fixed-before-landing.md), [review record](../security-reviews/20261110-security-findings-register.md) (round HHHH)

## Context
The project owner accepted RJG-1, a high in Fork build's required-jobs gate, as a residual on
2026-11-17. Its review record and register entry are on Fork build's branch and haven't landed. The
register couldn't take the acceptance:
- an owner row in `owner-acceptances.md` had to name a finding already in the register, so a PR
  with only the row failed;
- a high that a change brings must already be closed at the change's base, and an owner row closes
  a finding only once it has landed in an earlier change (UUU-4). So a PR with the row, the
  record and the entry together failed too.

Both rules are right on their own, but together they had no order in which an owner acceptance of a
new high could land.

## Decision
1. **A pending row.** An owner row may name a key that isn't in the register yet, only when:
   - its record is a review record name (`YYYYMMDD-slug.md`), so a `register#…` key is never
     pending;
   - that record isn't on `main`, nor on the tree being checked. The host passes `main`'s record
     names (`--main-records`). Without them, a pending row fails rather than passing unjudged;
   - the row is no more than seven days old, counted from the earlier of its Date column and the
     first commit on this history that added its key, so re-dating it or deleting and re-adding it
     never restarts the clock. A date ahead of the run, or one that isn't a real date, fails.

   Once its entry exists, the row is an ordinary row: no age limit, the same matching, the same
   rules.
2. **The order is unchanged.** The row lands first, in a change of its own written by the
   coordinator, as every owner row does. The record and its owner-accepted entry land in a later
   change, where the row is already in the base, so UUU-4 holds. The row and the closure in one
   change still fail.
3. **Expiry fails the check.** A row unmatched after seven days fails every docs check, on `main`
   too, until its record and entry land or the coordinator removes the row. A pending acceptance
   can't sit unnoticed, and a typo in a key shows up within a week.

## Consequences
- The coordinator can land RJG-1's row now, and Fork build's change then closes RJG-1 as an
  owner-accepted residual.
- A row can't name a finding in a record that already exists: those findings are all in the
  register, so an unmatched key there is a mistake, not a pending acceptance.
- The age is judged against the clock of the run, so a tree that passed can fail later. That is
  the expiry's purpose.
- Any change may remove an expired pending row; nothing else is needed to unblock a landing.
- The gate checks a row's shape, not who wrote it: only the coordinator writes rows, and that rule
  is a process control. A pending row widens what a row can name, so making authorship
  machine-checkable (a required reviewer on the file, or signed commits) is an open owner decision
  (review HHHH-4).
