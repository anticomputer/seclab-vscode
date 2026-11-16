# Security review: landing through pull requests (round PRL)

- **Date:** 2026-11-16
- **Scope:** round PRL, by an Opus-class model, of the proposal in
  [EDR pr-landing](../edr/20261116-pr-landing.md):
  - the ruleset change for `main`, proposed and not yet applied: a `pull_request` rule
    (rebase only, no approvals) plus strict required checks;
  - the repository settings for auto-merge and branch update;
  - the landing procedure in AGENTS.md;
  - docs-check downloading attestation bundles on pull requests.
- **Threat model:** landing must not open a path for PR-controlled code to reach the publish
  gate's known-names list or a token it couldn't hold before. A required check must not be
  passable without doing its work. And `main` must keep building and passing.

## Round PRL
No high or critical findings. Confirmed:
- **Ruleset diff:** it is exactly the two intended changes, against the live ruleset fetched
  fresh. Every existing rule is kept. The required checks are bound to GitHub Actions'
  integration id, there are no bypass actors, and no other ruleset or classic protection exists.
- **The known-names list:** no path reaches `SECLAB_DENYLIST` from PR-controlled code. The
  `denylist` job runs only on a push to `main`, in an environment whose branch policy admits only
  `main`. A merged PR reaches `main` as an ordinary push, which still runs the whole-tree scan.
- **Required checks on pull_request:** after the change, none of them does less on a pull
  request than on a push.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| PRL-1 | Low | docs-check | The attestation download (read-only token) was proposed for every pull request, including a fork's, whose code would then hold the token. It also ran after other steps rather than first. | Fixed | Same-repository pull requests only, as the first step after checkout. ci-linux matches, since sessions now wait for its `oci` job on the PR head. |
| PRL-2 | Low | procedure | A rebase merge re-creates commits, so `main`'s new tip is a SHA no required check has seen, and checks that read commit ranges or ancestry see it only afterwards. The EDR didn't say so. | Fixed | The EDR states it, and the procedure confirms the required checks and the `denylist` job on the new `main` SHA before the next PR is armed. |
| PRL-3 | Low | procedure | The wait for ci-linux `oci` sat inside the update-branch step, and after an update auto-merge stays armed and merges without waiting for `oci`, which isn't required. | Fixed | Waiting for `oci` is its own step before arming. After an update, disarm, wait, re-arm. Making `oci` required needs an always-running gate job, recorded as a later change. |
| PRL-4 | Low | records | The EDR said sessions keep fast-forwarding while AGENTS.md replaced that unconditionally, and the CI-hardening record still said no pull request is required. | Fixed | The ruleset is applied only after the register's citation rule lands. The CI-hardening record's branch-protection item points to the new EDR. |
| PRL-5 | Low | required checks | A required check passes when a job-level `if:` skips its job, and a trigger filter can stop its workflow from running. With no required approvals, the workflow files belong to the change. | Fixed | `build/check-required-checks.ts`, run inside the required `lint` check, fails if a required job gains a job-level `if:`, is renamed or removed, or if its workflow filters push or pull_request. |

Also adopted: `delete_branch_on_merge` stays off (register entries resolve on `origin/<branch>`),
the first landing records workflow-lint's push run on `main` with the `denylist` job green, and
tags staying unprotected is noted against the existing CI-1.
