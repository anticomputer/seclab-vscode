# A pre-merge gate that required jobs ran: one scoped `workflow_run` exception

- **Status:** accepted
- **Supersedes:** [20261104-ci-hardening](20261104-ci-hardening.md), in part: §5's ban on `workflow_run`, for one workflow
- **Date:** 2026-11-17
- **Deciders:** Project owner (2026-11-17): a post-merge `./seclab landing verify`, plus a
  pre-merge `workflow_run` gate running from main's code, as a scoped exception to the CI
  hardening rule; the coordinator applies the ruleset change. Fork-build session: implementation.
- **Related:** [CI hardening](20261104-ci-hardening.md) (the rule this is an exception to),
  [pr-landing-review](20261117-pr-landing-review.md)

## Context
GitHub counts a required job that was skipped as passing, and a pull request controls its own
workflow files. So a PR can skip the `lint` job, or all four required jobs, and nothing that runs
inside those workflows can stop it (a Copilot review thread on PR 7). The required-checks validator
hardens the files a PR is likely to touch, but it runs inside `lint`, which that same PR can skip.
The check has to run from code the PR doesn't control.

CI hardening forbids `pull_request_target` and `workflow_run`, because both run with the base
repository's token while handling PR-controlled events, and are almost always used to run PR code.

## Decision
- **`./seclab landing verify <sha>`**, run after a merge from a main checkout older than the PR. For
  each required workflow file, it reads the latest run for the commit through the API, and requires
  the required job to have concluded `success`. It also requires the gate's status below to be
  `success`. Skipped, cancelled, failed, still running or missing all refuse. Landing step 8 runs it.
- **`.github/workflows/required-jobs-ran.yml`**, a pre-merge gate. It is the one exception to the
  `workflow_run` ban, scoped to this file. It runs when any required workflow completes, from
  main's copy, and posts the commit status `required-jobs-ran` on the head SHA:
  - success when every required job concluded success;
  - pending while a required run is unfinished;
  - failure for anything else, including a missing run or job.

  The coordinator makes it a required check once it has posted a green status on a real PR. A PR
  that deletes or disables CI then never gets the status, so it stays blocked.
- **Invariants**, enforced by `build/check-required-checks.ts` in the required `lint` job, and by
  zizmor (its `dangerous-triggers` finding is suppressed inline on this file only, citing this
  record):
  - the trigger is `workflow_run` alone, after exactly the required workflows;
  - no `uses:` step, so no checkout and no artifact download, and no action runs at all;
  - no secret is read;
  - the only expressions are the token, the repository and the head SHA, passed through `env`
    (plus the concurrency group), never into a script;
  - top-level `permissions: {}`; the job's token holds exactly `actions: read` and
    `statuses: write`;
  - the workflow/job pairs it checks equal the validator's `REQUIRED`, and the workflow names it
    waits on are those workflows' names.

  `statuses: write` is allowed for this file only, and only while every invariant holds. Any other
  workflow granting it fails the validator, since such a step could post a passing context as
  GitHub Actions itself (review CR-8).

## Consequences
- The gate reads data only: run and job metadata. It never runs or downloads anything the PR
  controls, so the `workflow_run` risk this rule exists for (running PR code with the base token)
  doesn't arise. A PR can't change the gate either, because `workflow_run` always runs the default
  branch's file.
- **What the gate proves, and what it can't (review RJG).** It proves that every push and
  pull_request run of each required workflow, for the commit, ran its required job to success. It
  judges every such run, so a file that skips a job on one event and runs it on the other fails
  (RJG-2). It can't prove those jobs did their work. Every required job runs code the PR controls
  (its workflow files, `seclab`, `build/`), so a PR that keeps `name: lint` but guts its steps gets
  a vacuous success. No gate that reads job outcomes can tell those apart. Only review (Copilot's,
  with every thread resolved, and the owner's) or a check that refuses changes to the CI code itself
  can (RJG-1, an owner decision recorded separately).
- **Residual: a forged status.** A PR that skips or guts `lint` escapes the validator, so its
  workflows can request any write scope the validator would refuse. With `statuses: write` it can
  post `required-jobs-ran` itself, after the gate's last post. With `actions: write` it can cancel
  the gate's runs first, so it doesn't even need to win the race (review RJG-7). Both come
  from the Actions token, so GitHub can't tell them apart. The repository's read-only default
  doesn't stop this, because a same-repository workflow can request the scope explicitly; it
  stops forks only. Closing it needs a status source a workflow can't impersonate, such as a
  GitHub App.
- **`landing verify` after the merge** checks the job outcomes from main's code as it was before
  the merge, and refuses when run from a checkout that already contains the commit (RJG-5). Its
  read of the `required-jobs-ran` status is advisory, since merged code could post that context.
- The gate's file is pinned byte for byte (`GATE_SHA256` in the validator), so a change to it is a
  deliberate, reviewed change to both (review RJG-8).
- Every run counts: a manually cancelled run of a required workflow keeps that commit at
  `failure` until it's re-run, even if another run of the same file passed.
- A required workflow renamed on main must be renamed in the gate in the same change; the
  validator fails until it is.

## Proof
On a test PR that sets `if: false` on the `lint` job, the gate must post `failure`, the PR must
stay blocked, and `landing verify` on its head must refuse. A normal PR must get `success`. The
runs are recorded below once the gate is on main.
