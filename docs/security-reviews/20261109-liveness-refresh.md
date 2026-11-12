# Security review: liveness-refresh workflow

- **Date:** 2026-11-09
- **Scope:** round MMM, `a05d6ed` and its fixes:
  - `.github/workflows/liveness-refresh.yml`: weekly schedule, paths-filtered `push`,
    `workflow_dispatch`; `contents: read` + `actions: read`; one token-bearing step running
    `./seclab liveness verify-runs --refresh`;
  - `seclab`: the `verify-runs` argument handling;
  - `build/liveness/liveness.ts`: `--refresh`, `refreshReport` and its self-test, and the
    trigger model the gate uses;
  - the "Lapsing evidence is caught weekly" paragraph in the liveness-gate EDR.
- **Threat model:** liveness evidence must not lapse silently. The new non-required alarm runs
  branch code with a repository token, so it must add no exposure the required check doesn't
  have, must fail closed, and must not become the next artefact that nothing runs.
- **Records:** [EDR liveness-gate](../edr/20261109-liveness-gate.md),
  [EDR ci-hardening](../edr/20261104-ci-hardening.md), [round KKK](20261109-liveness-gate.md).
- **Prompt injection:** none found.

## Round MMM
One medium, three lows, three residuals. Confirmed:
- `push` adds no exposure: it never fires for forks, there is no `pull_request` trigger, and
  `workflow-lint` already gives the same token to the same `./seclab` on every push;
- the token-bearing container is unchanged (KKK-4), and `refreshReport` adds no import;
- permissions are minimal, `persist-credentials: false`, the token stays in one step's
  `env:`, actions and images are pinned, and the job has a timeout;
- `${2:+"$2"}` is correct and bash-3.2 safe behind the `case` allow-list;
- `--refresh` fails closed: only age notes are promoted, and every lookup failure is already
  an error;
- `refreshReport` is asserted on all 11 run cases.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| MMM-1 | Medium | liveness gate | `triggers()` modelled `branches` but not `paths`/`paths-ignore`, so a push that can never run (`paths-ignore: ['**']`, `paths` matching no file) counted as running on push. | Fixed | `triggers()` drops push/pull_request when `paths-ignore` covers everything or `paths` matches no tracked file, with filters in inline or block-list form. Two injections; with the check removed, the self-test fails. |
| MMM-2 | Low | refresh flag | A lost `--refresh` failed open: the job reverted to the required check's behaviour. `seclab` wasn't in the push paths. | Fixed | The checker prints `liveness: refresh mode`, and the step requires that line (`shell: bash`, pipefail). `seclab` is in the push paths. |
| MMM-3 | Low | concurrency | The group was global, so a branch push could supersede the scheduled run, which then reads as cancelled. | Fixed | `group: liveness-refresh-${{ github.ref }}` (EDR ci-hardening §7). |
| MMM-4 | Low | argument guard | `verify-runs` didn't bound `$#`. | Fixed | `[[ $# -le 2 ]]` before the allow-list. |
| — | Residual | evidence class | A push run can't be register evidence (`verifyRuns` requires dispatch or schedule). The workflow counts as live because it runs on push. | Open | Add a `workflow:liveness-refresh` record citing the first scheduled run. |
| — | Residual | vacuous pass | `verify-runs` checks only `run` evidence; with none left, it passes over nothing. | Accepted | Pre-existing; two entries today. |
| — | Residual | who watches | A failure is a scheduled-run notification only; no owner or response window is named. | Accepted | The trade-off for not blocking PRs on age. |
