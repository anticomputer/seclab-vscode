# Security review: the required-jobs gate and its compensating controls (round RJG)

- **Date:** 2026-11-17 to 2026-11-18
- **Scope:** rounds by an Opus-class model of [EDR required-jobs-gate](../edr/20261117-required-jobs-gate.md):
  `.github/workflows/required-jobs-ran.yml` (the one scoped `workflow_run` exception), its
  invariants in `build/check-required-checks.ts`, `./seclab landing verify` and its re-validation
  of a merged tree with the old main's validators, the S1 exception in
  `build/check-workflow-echo.ts`, and liveness `pending` subjects.
- **Threat model:** a pull request controls its own workflows and the code its required jobs run.
  It must not be able to land with a required job skipped, cancelled, missing or gutted, and
  nothing the gate or `landing verify` does may run or download code the PR controls, or write
  outside its own scratch space.

## Round RJG
The first review of the gate and `landing verify`.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| RJG-1 | High | gate | Every required job runs code the PR controls (its workflow files, `seclab`, `build/`), so a PR can keep a job's name and gut its steps: the job concludes success vacuously, and no gate that reads job outcomes can tell. | Accepted residual (project owner, 2026-11-17) | Two compensating controls: `landing verify` re-runs the old main's validators over the merged tree (round RJG3), and the coordinator reviews every PR touching `.github/workflows/**`, `seclab` or `build/` before it is armed. |
| RJG-2 | High | gate | The gate judged only the latest push or pull_request run of each file: a file that runs a job on push and skips it on the PR run passed, and a later run on another branch could replace a failure. | Fixed | Every push and pull_request run for the commit is judged; any one not ending in success fails it. The self-test runs the gate's own script against a stub `gh`. |
| RJG-3 | Medium | record | The EDR named only a forged status as the residual, claimed a read-only default stopped it, and claimed `landing verify` refuses a skipped `lint` in every case. | Fixed | The EDR states what the gate proves and what it can't (RJG-1), scopes the read-only default to forks, and marks `landing verify`'s status read as advisory. |
| RJG-4 | Medium | invariants | The no-`uses` and pair-list checks matched block style only: a flow-style `uses` step, or the pair list in a comment, passed. | Fixed | No `uses` in any spelling outside the script, no flow collection beyond the fixed lines, exactly one pair loop inside the script. |
| RJG-5 | Medium | landing verify | It ran its required list from whatever checkout it was in, and put each workflow:job pair into an API path and a jq program unchecked. | Fixed | It refuses a checkout that already contains the commit, and validates every pair before use. |

## Round RJG2
A re-review of the round RJG fixes.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| RJG-6 | Medium | gate | The run list was read unpaginated, so runs pushed on other branches for the same commit could page the PR's own run out of view. | Fixed | Every page is read (`gh api --paginate`), in the gate and in `landing verify`. |
| RJG-7 | Medium | record | The forged-status residual named only `statuses: write`; a PR that skips `lint` can also request `actions: write` and cancel the gate's runs. | Fixed | The EDR covers any write scope a PR that skips `lint` can request. |
| RJG-8 | Medium | invariants | Nothing constrained the gate's script or extra steps: an added step, or an unconditional success post, kept every invariant. | Fixed | The gate file is pinned byte for byte (`GATE_SHA256`); any change fails `lint` and withdraws its `statuses: write` exemption. |
| RJG-9 | Medium | landing verify | An empty or trimmed required list made the job half of `landing verify` check nothing; and a checkout merely not containing the commit (another branch) passed. | Fixed | It refuses unless the list holds all four contexts and its checkout is an ancestor of the commit. |

## Round RJG3
The compensating controls for RJG-1: re-validation in `landing verify`, the S1 exception, and
liveness `pending`.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| RJG-10 | High | re-validation | A merged tree could replace a validator's entry with a symlink (to `/dev/null`, say): the old code was written through it, and the step ran the link target and passed. | Fixed | The overlay refuses any closure path with a symlink on it, writes a plain file, and checks it holds the old main's bytes. |
| RJG-11 | Medium | re-validation | The same symlink let the overlay write the old main's files outside the worktree. | Fixed | Every path written or removed is relative, plain and symlink-free under the worktree; a merged tree that tracks anything under `.work/` is refused. |
| RJG-12 | Medium | re-validation | The overlay's undo list was read from the merged tree, so a tracked list could make `landing verify` remove files outside the worktree. | Fixed | The list lives in the verifying checkout, every line is checked, and the clean-tree check runs before any write. |
| RJG-13 | Low | liveness | A later change could re-date `pending.since`, postponing the 3-day expiry indefinitely. | Fixed | `since` is append-only against the base register, and a subject the base already has can't become pending. |
| RJG-14 | Info | re-validation | The path check admitted absolute paths. | Fixed | Relative paths with plain components only. |

## Round RJG4
A re-review of the round RJG3 fixes.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| RJG-15 | Medium | re-validation | The `.work` refusal was case-sensitive; on a case-insensitive host a tracked `.Work` symlink redirected the steps' scratch writes and removals. | Fixed | A top-level `.work` in any case is refused, and so is anything the checkout put at `.work`; `landing verify` creates that directory itself. |
| RJG-16 | Info | liveness | `pending` can be re-added after its subject is removed in an earlier landed change. | Accepted residual | Reaching it takes a visible two-change sequence, and for this gate removing or renaming the gate file, which the required-checks validator refuses. |

## Round RJG5
A check of the RJG-15 fix.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| RJG-17 | Info | re-validation | The `.work` listing was piped into `grep -q`, a shape that fails open under `pipefail` once the listing is large enough for the writer to take SIGPIPE; not reachable at today's size. | Fixed | The listing is captured first, then matched. |
| RJG-18 | Info | prompt injection | None found in any round. | No finding | — |

## Round RJG6
`landing verify`'s report of merged changes to `owner-acceptances.md` (the compensating control
for HHHH-4).

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| RJG-19 | Medium | owner report | A `-diff` or binary attribute on the file in the reporting checkout, landed in an earlier change, made every later report show the commit with no rows. | Fixed | The diff runs with `--text` and no attributes file. |
| RJG-20 | Low | owner report | Added or removed lines starting with `+` or `-` (markdown bullets) were dropped from the report. | Fixed | Every added and removed line after the hunk header is reported. |
| RJG-21 | Low | owner report | Only C0 controls were removed: C1 and bidi characters reached the reader, so a row could render other than it parses. | Fixed | Every byte outside printable ASCII is shown as `?`. |
| RJG-22 | Info | owner report | The report watched one literal path: after a case-only rename, later row changes went unreported. | Fixed | A merged path that is the file under another case, or a merged tree without the file, is refused. |

## Copilot review (PR 63)
Copilot's review of the gate PR.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| CR63-1 | Medium | gate | Push runs that finished before a PR opened could leave `success` standing until the gate ran after the PR's runs, a window in which a PR run that skips `lint` could be merged. | Fixed | The gate runs on `requested` too, and posts `success` only once a pull_request run of each required file has been judged. |
| CR63-2 | Medium | gate | An API read failure exited before the status post, leaving an earlier `success`. | Fixed | An EXIT trap posts `failure` on any error before the final post. |
| CR63-3 | Low | owner report | The case-variant check was a `grep -q` pipeline, which can fail open under `pipefail` with a long list. | Fixed | A captured, pipeline-free check. |
| CR63-4 | Low | re-validation | The observability-docs step overlaid the generator's product inputs with the old main's, so a regenerated schema change was refused and a stale one passed. | Fixed | Only validator code (`build/`, `tabd/tools/`) is overlaid; a changed product module is refused for review (CR63-6), so neither case is judged against the old main's inputs. |
| CR63-5 | Medium | gate | `workflow_run`'s `requested` type doesn't fire for a re-run, so an earlier success stood while a re-run was in flight. | Fixed | The gate also runs on `in_progress`; the validator requires that types line. |
| CR63-6 | Medium | re-validation | Running the merged `tabd/src/obs` modules let a merge end the observability-docs step early with success. | Fixed | A merge that changes a module the validator executes is refused for coordinator review. |

## Round RJG7
A review of the Copilot-review fixes (a workflow change).

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| RJG-23 | Low | gate | The EXIT trap doesn't run when the step is cancelled (SIGINT), timed out or killed, so such a run left an earlier success standing. | Fixed | Each run posts pending before it reads anything, and the trap also covers INT and TERM. |
| RJG-24 | Info | re-validation | With only `build/` and `tabd/tools/` overlaid, the observability-docs step runs the merged `tabd/src/obs` modules (contained: no network, read-only). | Fixed | Superseded by CR63-6: a merge that changes those modules is refused for coordinator review, so merged product code is never run. |
