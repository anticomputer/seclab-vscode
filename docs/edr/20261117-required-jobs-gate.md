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
  the required job to have concluded `success`. Skipped, cancelled, failed, still running or
  missing all refuse. It reports the gate's status on the merged commit without requiring it: a
  rebase merge makes a commit with push runs only, which the gate leaves pending. It then re-runs
  that old main's own validators over the merged tree (below). Landing step 8 runs it.
- **`.github/workflows/required-jobs-ran.yml`**, a pre-merge gate. It is the one exception to the
  `workflow_run` ban, scoped to this file. It runs when any required workflow is requested, starts
  (`in_progress`, which a re-run fires and `requested` doesn't) or completes, from main's copy, and posts the commit status `required-jobs-ran` on the head SHA:
  - success when every required job concluded success, in every push and pull_request run, and a
    pull_request run of each required file has been judged (push runs alone can't vouch for a PR
    run that hasn't started; Copilot review on PR 63);
  - pending while a required run is unfinished, or no pull_request run has been judged yet; a
    run's `requested` event re-posts pending, so an earlier success doesn't stand while a new
    run (a re-run, say) is in flight;
  - failure for anything else, including a missing run or job, and any error before the final
    post (an EXIT trap posts failure, so an API failure can't leave an earlier success standing).

  Each run posts pending before it reads anything, so a run cancelled, timed out or killed part
  way can't leave an earlier success standing either (review RJG-23). The first `requested` event
  of a commit can post failure for runs not yet created; later events correct it.

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

  The publish gate's secret-scope rule (S1 in `build/check-workflow-echo.ts`), which refuses
  `workflow_run` anywhere, admits it in this file only while its bytes match `GATE_SHA256` and no
  expression in it names a secret.

  `statuses: write` is allowed for this file only, and only while every invariant holds. Any other
  workflow granting it fails the validator, since such a step could post a passing context as
  GitHub Actions itself (review CR-8).

- **Compensating controls for RJG-1** (project owner, 2026-11-17, accepting RJG-1 as a residual):
  - **The old main re-validates the merged tree.** `landing verify` runs, from its own checkout,
    the lint job's validators (required-checks, workflow-echo, actionlint and zizmor, pins, deps,
    source, liveness, gitleaks over the merged commits), the docs check (records, paired docs,
    observability docs) and the findings register, in containers, over a worktree of the merged
    commit. For each step the worktree gets the old main's copy of the validator code in that
    validator's import closure (files under `build/` and `tabd/tools/`). A product module the
    validator executes, such as `tabd/src/obs` for the observability-docs generator, can't be
    judged by running it, since a merged copy can end the process early with success: when one
    differs from the old main, the step refuses and names it, for the coordinator to review; and the old main's shell logic runs with the worktree as its root, so the validator
    is the old main's while everything it judges is the merged tree's. A merge whose gutted
    validator hid a problem is refused right after it lands. `./seclab landing --self-test`
    proves it: a merged gutted lint (the required-checks validator exits early, and `lint` gets
    `if: false`) and a merged gutted pin check (hiding an unpinned image) are refused, though
    each gutted validator passes its own tree; a clean merge passes.
  - **Coordinator review before arming.** A PR touching `.github/workflows/**`, `seclab` or
    `build/` waits for the coordinator's go-ahead before it is armed (AGENTS.md "Landing").
- **Owner acceptances a merge changed** (compensating control for HHHH-4, accepted by the
  project owner 2026-11-18). `landing verify` lists every merged commit that changes
  `docs/security-reviews/owner-acceptances.md`, with the rows it added or changed and those it
  removed, so the coordinator checks each against an owner decision. It reports; it doesn't
  refuse, since a legitimate owner row lands the same way. The rows are printed as data, with
  control characters removed. `./seclab landing --self-test` injects an unannounced row and
  requires the report to name its commit and the row, and nothing for a clean merge.
- **Liveness.** A `workflow_run` workflow runs only from the default branch, so it has no run
  before it lands. The liveness register may carry it as `pending` (since when, and the proof PR
  whose run is recorded), only for a workflow whose sole trigger is `workflow_run`. More than 3
  days with no run recorded is a note in the required `lint` check and a failure in the weekly
  liveness refresh. Run evidence for such a workflow is marked `event: workflow_run`, and only a
  `workflow_run` run of the file counts.

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
  can. RJG-1 is accepted as a residual by the project owner (2026-11-17), with the two
  compensating controls above. Their limits:
  - re-validation catches a gutting only when the gutted validator hid something; a gutting
    that hides nothing lands, and later merges are then checked by the gutted copy. The
    coordinator's review of every change to that code covers this case;
  - a validator change that also cites a new self-test case in the same validator is judged
    against the old copy, so `landing verify` can refuse a correct merge of that kind; the
    refusal names the step, and the coordinator judges it;
  - the online link check and the pin-age lint are not re-run (both need the network).
- **Residual: a forged status.** A PR that skips or guts `lint` escapes the validator, so its
  workflows can request any write scope the validator would refuse. With `statuses: write` it can
  post `required-jobs-ran` itself, after the gate's last post. With `actions: write` it can cancel
  the gate's runs first, so it doesn't even need to win the race (review RJG-7). Both come
  from the Actions token, so GitHub can't tell them apart. The repository's read-only default
  doesn't stop this, because a same-repository workflow can request the scope explicitly; it
  stops forks only. Closing it needs a status source a workflow can't impersonate, such as a
  GitHub App.
- **`landing verify` after the merge** checks the job outcomes from main's code as it was before
  the merge, and refuses when run from a checkout that already contains the commit (RJG-5). It
  reports the `required-jobs-ran` status and doesn't require it, since merged code could post that
  context and the gate leaves a rebase-merged commit pending.
- The gate's file is pinned byte for byte (`GATE_SHA256` in the validator), so a change to it is a
  deliberate, reviewed change to both (review RJG-8).
- Every run counts: a manually cancelled run of a required workflow keeps that commit at
  `failure` until it's re-run, even if another run of the same file passed.
- A required workflow renamed on main must be renamed in the gate in the same change; the
  validator fails until it is.

## Proof
On proof PR 54, which sets `if: false` on the `lint` job, the gate must post `failure` and the PR
must stay blocked; it is closed unmerged. `landing verify` on its head must refuse.

- **The gate on the skipped lint (2026-11-18).** After the gate landed (main a60349cb), proof PR 54
  was rebased onto it (head a26c5d2c). Gate run 44421895223 (`workflow_run`, main's copy) posted
  `required-jobs-ran` failure on that head: `unit:success lint:skipped docs:failure patch-build:success`.
  PR 54 reads BLOCKED through the API. Its `docs` job fails as well: the `ci: run` block's
  `./seclab lint workflows` rejects the constant `if: false` (actionlint), a second layer.
- **On main itself** the gate leaves the merged commit pending (push runs only), as designed.
- **A normal PR** gets `success`: the PR recording this proof.
- **The gate alone blocks (2026-11-19).** With `required-jobs-ran` a required check, proof PR 54
  was given `if: false` on `docs` as well as `lint` and rebased onto main 09e7a219 (head
  ec5c5518). Every other required check passed or was skipped (unit success, lint skipped, docs
  skipped, patch-build success). Gate run 44427326029 (`workflow_run`, main's copy) posted
  `required-jobs-ran` failure (`unit:success lint:skipped docs:skipped patch-build:success`), and
  the API read PR 54 as BLOCKED. It was closed unmerged.
- **`landing verify`'s first run (2026-11-19).** `./seclab landing verify 09e7a219`, run from the
  pre-merge main a60349cb, passed: the four required jobs succeeded, the old main's eleven
  validators passed the merged tree, and owner acceptances were unchanged. A normal PR must get `success`. The
runs are recorded below once the gate is on main.
