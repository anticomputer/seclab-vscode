# Landing through pull requests: rebase merge with auto-merge

- **Status:** proposed
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
  change and diffed after it; the diff must show only these two changes.
- **Repository settings:** auto-merge on, and "update branch" on, so an out-of-date PR can be
  rebased onto `main` from `gh` (`gh pr update-branch --rebase`).
- **Landing procedure** ([AGENTS.md](../../AGENTS.md)): rebase and remap, push, scan the PR
  title and body with `./seclab scan-text`, `gh pr create`, then
  `gh pr merge --auto --rebase`. If `main` moves first, update the branch and let the checks
  re-run. The coordinator still sets the order.
- **docs-check downloads attestation bundles on pull requests too.** The required `docs` check
  now has to pass on a PR. Without bundles, the broker's `ci:run` block verifies image
  attestations online and unauthenticated, which works but shares a runner IP's 60-request
  hourly limit, the same way the broker e2e flaked on `/zen`. The download step already runs
  with the job's read-only token on every branch push, so a same-repository PR adds no new
  exposure. The docs gate itself stays tokenless.
- **Main-only jobs stay main-only.** The `denylist` job (`workflow-lint.yml`) still runs only
  on a push to `main` and only in the `denylist` environment, whose deployment-branch rule admits
  `main`. A merged PR reaches `main` as a push, so the job still runs once per landing, after the
  merge. It never runs on a PR's merge ref. Nothing else reads `SECLAB_DENYLIST`.

## Consequences
- **No direct pushes to `main`,** including by the coordinator. A hotfix is a PR too.
- **SHAs change at landing.** A rebase merge re-creates every commit, so a branch SHA is never
  the SHA on `main`. Register citations of unlanded commits must survive that before any session
  switches over. The register session owns that rule; until it lands, sessions keep the
  fast-forward procedure.
- **No batching.** Two PRs racing means the second updates its branch and re-runs its checks.
  The coordinator's ordering keeps that rare.
- **The first landing proves it:** a PR carrying this EDR and the AGENTS.md procedure lands
  through the new ruleset, by auto-merge, with no push to `main`.
