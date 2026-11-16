# Landing through pull requests: rebase merge with auto-merge

- **Status:** accepted
- **Date:** 2026-11-16
- **Deciders:** Project owner (2026-11-16): pull-request landing with auto-merge, the repository staying under its user account; the coordinator (landing order). Fork-build session: implementation.
- **Related:** [CI hardening](20261104-ci-hardening.md) (§9, the ruleset), [security findings register](20261110-security-findings-register.md), [publish gate](20261112-publish-gate.md)

## Context
Every landing so far has been a fast-forward push of a branch SHA to `main`, made by a session
once the required checks were green on it and the coordinator said so. Several sessions land each
day, so the coordinator had to serialise them by hand, and every session held push rights to
`main`.

A GitHub merge queue would serialise landings automatically, but GitHub refuses one on this
repository. A disabled probe ruleset with only a `merge_queue` rule, on a branch that doesn't
exist, was rejected with HTTP 422 "Invalid rule 'merge_queue'", and was never created. Merge
queues need an organisation-owned repository, and this one stays under its user account.

## Decision
- **The `main` ruleset (26572681) gains exactly two things:**
  - a `pull_request` rule, with no required approvals (there is one human), the rebase method
    as the only merge method, and no review conditions;
  - `strict_required_status_checks_policy: true`: a PR merges only when its head contains
    current `main` and the required checks are green on it.

  Every existing rule stays: the four required checks (`unit`, `lint`, `docs`, `patch-build`),
  linear history, no force-push, no deletion, and no bypass actors. The JSON is saved before the
  change and diffed after it; the diff must show only these two changes. (GitHub also stores
  its default `require_extra_approval_for_unattributed_changes: true` and an empty
  `required_reviewers` in the new rule. The former adds an approval only to pull requests opened
  by Copilot under its own identity, and sessions open theirs with `gh` as the owner.)
- **Repository settings:** auto-merge on, and "update branch" on, so an out-of-date PR can be
  rebased onto `main` from `gh` (`gh pr update-branch --rebase`). `delete_branch_on_merge`
  stays off: register entries that name a `branch` resolve their citations on
  `origin/<branch>`, so landed branches must not disappear.
- **Landing procedure** ([AGENTS.md](../../AGENTS.md)): rebase and remap, push, scan the PR
  title and body with `./seclab scan-text`, `gh pr create`, wait for ci-linux `oci` when the
  change touches what it covers, then `gh pr merge --auto --rebase`. If `main` moves first,
  update the branch and let the checks re-run. After the merge, confirm the required checks
  and the `denylist` job on the new `main` SHA before the next PR is armed. The coordinator
  still sets the order.
- **Attestation bundles on same-repository pull requests.** The required `docs` check now has
  to pass on a PR. Without bundles, the broker's `ci:run` block verifies image attestations
  online and unauthenticated, which works but shares the runner IP's 60-request hourly limit,
  the same way the broker e2e flaked on `/zen`. docs-check and ci-linux (whose `oci` job a
  session waits for) now download them on a pull request whose head is in this repository. Its
  author can already push branches, which run the same step with the same read-only token, so
  that adds no exposure. A fork's pull request still never runs the step, so a fork's code
  never holds a token. In docs-check the step moves to right after checkout, as in ci-linux
  (review XX-1). The docs gate itself stays tokenless.
- **The required checks can't be skipped by the change they gate.** GitHub counts a job that a
  job-level `if:` skipped as a passed required check, and a trigger filter can stop the workflow
  from running. With no required approvals, the workflow files belong to the change. So
  `build/check-required-checks.ts`, run by `./seclab lint workflows` inside the required `lint`
  check, fails if a required job gains a job-level `if:`, is renamed or removed, or if its
  workflow gains a filter on `push` or `pull_request`.
- **Main-only jobs stay main-only.** The `denylist` job (`workflow-lint.yml`) still runs only
  on a push to `main` and only in the `denylist` environment, whose deployment-branch rule admits
  `main`. A merged PR reaches `main` as a push, so the job still runs once per landing, after the
  merge. It never runs on a PR's merge ref. Nothing else reads `SECLAB_DENYLIST`.

## Consequences
- **No direct pushes to `main`,** including by the coordinator. A hotfix is a PR too.
- **`main`'s new tip is checked just after it lands, not before.** A rebase merge re-creates
  every commit, so the commit that becomes `main` is never the SHA CI saw. The strict policy
  means CI tested the same tree, but checks that read commit ranges and ancestry (the register's
  citations, the secret scan's range, the publish gate's allowlist range) see the new SHAs
  only in the push run that follows. Step 7 of the procedure confirms that run before the next
  PR is armed. A red `main` is fixed by another PR.
- **Register citations survive the rewrite.** A branch SHA is never the SHA on `main`, so
  unlanded work is cited as `patch:<id>` (the register's rule, on `main` since 6d798949). The
  ruleset change is applied once this EDR is approved; from then on fast-forward landing is
  impossible, and the coordinator switches every session over.
- **`oci` isn't required.** ci-linux is path-filtered, so it can't be a required check as it
  stands, and auto-merge doesn't wait for it. Sessions wait for it by procedure (steps 4 and 6).
  Making it machine-enforced would need an always-running gate job in ci-linux and a fifth
  required context, a later change.
- **No batching.** Two PRs racing means the second updates its branch and re-runs its checks.
  The coordinator's ordering keeps that rare.
- **Unreviewed code can land.** Required approvals are 0, so anyone with write access can merge
  through green checks. There is one: the project owner's account.
- **Tags are still unprotected** (CI-1 in the [CI hardening](20261104-ci-hardening.md) record).
  The ruleset covers `refs/heads/main` only.
- **The first landing is the proof:** a PR carrying this EDR and the AGENTS.md procedure lands
  through the new ruleset, by auto-merge, with no push to `main`. The record names that PR, the
  resulting `main` SHA, and workflow-lint's push run on it with the `denylist` job green. The
  merge must produce a `push` event on `main`, so auto-merge is armed with the owner's
  credential, never an app's.
