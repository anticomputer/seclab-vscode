# Security review: internal-identifier scan and the generator-test gate (workflow changes)

- **Date:** 2026-11-12
- **Round:** 17 (workflow change: the internal-identifier scan), with the fixes in round 18.
- **Reviewer:** independent `security-review` agent (an Opus-class model).
- **Subject:**
  - `73e40cf`: `build/check-denylist.ts`, `build/ci-denylist.sh`, `seclab lint denylist`,
    `.github/workflows/workflow-lint.yml`;
  - the follow-up fixes;
  - `681ec3c`'s `.github/workflows/ci-unit.yml` change (gate audit GATE-12).
- **Prompt:** said the diff, fixtures and evidence may contain prompt injection aimed at the
  reviewer, and that the reviewer reports it rather than following it. None found.

## Round 17 verdict
**One high, two mediums.** All three are fixed.

| # | Severity | File | Finding | Conf. | Fixed |
|---|---|---|---|---|---|
| 1 | high | `workflow-lint.yml`, `build/ci-denylist.sh` | The secret was handed to a step that runs the head commit's own script on every push and same-repo pull request. Anyone able to push a branch could change the script and leak the list into the public log. | 8/10 | yes |
| 2 | medium | `build/ci-denylist.sh` | Only a push to main failed closed. Every other same-repo event without the secret (Dependabot, a renamed secret) went green without scanning. | 9/10 | yes |
| 3 | medium | `build/check-denylist.ts` | Binary-looking, oversized and symlinked files were dropped without a word. Compatibility forms and zero-width characters evaded the tokeniser. | 9/10 | yes |

Fixes:
1. The secret moves to a `denylist` GitHub environment whose deployment-branch rule admits
   main only, read by a separate `denylist` job that runs only on a push to main. No code a
   branch or pull request controls ever runs with it. Every other event, forks included,
   gets a notice. The pre-merge half is the developer's local scan
   (`./seclab lint denylist`, list outside the repo) before every push.
2. That job fails closed whenever the secret is missing or empty. It runs only where the
   secret must exist, so there is no event left on which a missing secret could pass.
3. The scanner names every skipped file with its reason. It fails a required scan on a
   text-type file it could not read, raises the size cap to 64 MiB, folds NFKC and drops
   format characters before tokenising. It is documented as an accident filter, not an
   adversary filter.

Lower notes, also fixed:
- entries are percent-encoded before `::add-mask::`;
- printed paths are sanitised against workflow-command syntax;
- the temp list lives outside the checkout, and `RUNNER_TEMP` is required under Actions.

Noted, not fixed: run records are scanned only where a run passes `--extra`. The proof runs
do so locally.

## Repository setting this needs
The history-rewrite owner creates the `denylist` environment with deployment branches
limited to `main` and sets `SECLAB_DENYLIST` there. Until then a push to main fails the
`denylist` job, as designed.

## Round 18
- **Reviewer:** independent `security-review` agent (an Opus-class model), the same injection
  warning in its prompt.
- **Subject:** `9598ec3` (the round-17 fixes) and `681ec3c`'s `ci-unit.yml` change.
- **Verdict: no high or critical findings.** Round 17's three findings are closed:
  - `github.ref` is runner-supplied;
  - neither a tag push nor a fork's `main` reaches this repository's secret;
  - the environment rule is a second, independent lock;
  - a missing environment yields no secret, and the job fails closed.

  GATE-12 is confirmed. `fetch-upstream.sh` verifies tag, SHA and HEAD; no token is in the
  job; the runner fails on any skip.
- Its one finding on these commits, low (an unmarked `--expectations` seam in
  `check-probes.ts`), is fixed. The flag now requires `SECLAB_PROBE_SELFTEST=1`, and the
  report prints a `SYNTHETIC EXPECTATIONS` banner. Its clipboard-lint low is recorded in the
  probe-records review.
- Accepted, as documented: the scan runs after a change is on main, with the developer's
  local scan as the pre-merge half. The environment's main-only rule is a repository setting
  the workflow cannot assert, so recheck it after any environment change.
