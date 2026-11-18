# Security review: the required-checks validator and Copilot's review backlog (round CR)

- **Date:** 2026-11-17
- **Scope:** round CR, five rounds by an Opus-class model, of the fixes for Copilot's review
  threads on pull requests 7 and 13 and the landing-procedure change in
  [EDR pr-landing-review](../edr/20261117-pr-landing-review.md): the required-checks validator
  (`build/check-required-checks.ts`), the shared job reader in `build/liveness/liveness.ts`, and
  `build/docs/docs-check.ts`. Plus Copilot's review of the threads themselves and of pull
  request 32, which carries the change.
- **Threat model:** a pull request controls every workflow file. A required job it skips, or a
  job it adds that reports a required context, counts as passing; a token scope it grants can
  post a passing context itself. The validator must read every workflow fail-closed: anything it
  can't read in full fails `lint`. It bounds skipping, not vacuous success: a pull request can
  equally make a required job's steps do nothing, which no check from its own tree can stop (the
  required-jobs gate's EDR).

## Round CR

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| CR-1 | High | required jobs | `needs:` on a skipped gate job, `continue-on-error`, an empty matrix or a reusable `uses:` skips a required job, which counts as passing; `lint` itself could be skipped so. | Fixed | A required job may carry only keys that can't make it skip; the liveness gate's ci evidence jobs share the rule. |
| CR-2 | Low | docs-check | A supersede link resolved by basename, so it could be checked against a same-named record of another kind, and any mention counted as the back-link. | Fixed | Links resolve by path; each side must name the other in Supersedes or Status. |
| CR-3 | Low | procedure | After `update-branch` the procedure re-armed without waiting for the new Copilot review, and the EDR didn't say who resolves threads. | Fixed | Disarm after an update until the new review is handled; the EDR names who resolves. |
| CR-4 | High | reporters | Any workflow could add a job named like a required context and satisfy it while the real job was gutted or deleted. | Fixed | Only the registered job may report a required context; a workflow whose job names can't be read in full fails. |
| CR-5 | Medium | mounts | Importing the validator into liveness.ts dragged it into the token-holding `verify-runs` mount. | Fixed | The shared reader lives in liveness.ts; the validator imports it. |
| CR-6 | Low | required jobs | The key allowlist admitted `defaults:`, which can make every step a no-op. | Fixed | The allowlist is only what the required jobs use. |
| CR-7 | High | job reader | The job reader skipped unrecognised lines and stopped at a column-0 comment, so a decoy name or a hidden `if:` could sit at another indent, behind an escaped key or after a comment. | Fixed | One fail-closed job reader for job contexts and required jobs. |
| CR-8 | High | token scopes | A step holding `checks: write` or `statuses: write` could post a passing required context as GitHub Actions itself. | Fixed | No workflow may grant either, or `write-all`. |
| CR-9 | High | token scopes | The scope check matched literal text, so an escaped key or value, or a block-scalar value, granted those scopes unseen. | Fixed | Permissions are read fail-closed against an allowlist; escapes, complex and merge keys fail. |
| CR-10 | Info | prompt injection | None found. | No finding | — |

## Copilot's review of pull requests 7, 13 and 32

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| CR-11 | High | required jobs | A quoted, escaped, duplicated or merged `if` key on a required job skipped it while the validator saw nothing (pull request 7). | Fixed | Job-level lines are parsed fail-closed. |
| CR-12 | Medium | liveness | An escaped double-quoted branch filter item (`"ma\u0069n"`) was compared literally, so a workflow that ignores main needed no run evidence (pull request 13). | Fixed | An escaped item is unreadable and counts against the workflow. |
| CR-13 | Low | permissions | A step named "Verify permissions" or a comment mentioning `permissions:` failed lint. | Fixed | Only a possible key trips the rule. |
| CR-14 | Medium | reporters | A job named `null`, `~` or empty falls back to its id in Actions, so a decoy job id could report a required context. | Fixed | Such a name is unreadable. |
| CR-15 | Low | permissions | Backslashes or `<<:` in comments and plain scalars failed lint. | Fixed | Comments and plain scalars aren't scanned for escapes. |
| CR-16 | Medium | permissions | An alias as a mapping key (`*p :` with `&p permissions`) granted a scope the scan couldn't see. | Fixed | An alias key fails. |
| CR-17 | Medium | reporters | A `jobs:` line inside an open quoted scalar of a root flow mapping hid the real jobs. | Fixed | Open content before `jobs:` makes the jobs unreadable. |
| CR-18 | Low | permissions | A quoted label containing `permissions:` failed lint. | Fixed | Quoted values are text; a quoted key still fails. |
| CR-19 | Medium | required jobs | A multiline quoted step value with a column-0 continuation ended the job early, hiding a later job-level `if:`. | Fixed | A job doesn't end inside an open value. |
| CR-20 | Medium | reporters | The last job reached end-of-file without the open-value check, so text inside an unterminated quoted step posed as its name. | Fixed | The check runs at end-of-file too. |
| CR-21 | Low | permissions | A backslash inside a single-quoted command failed lint. | Fixed | Single-quoted scalars are skipped whole. |
| CR-22 | Low | job reader | A quote after a bracket inside a plain scalar (`run: echo "["`) read as an open value. | Fixed | Plain scalars are tracked. |
| CR-24 | Low | permissions | A plain label with a lone double quote, and JSON inside a single-quoted value, failed lint. | Fixed | One line tokenizer for escapes, alias keys and permissions keys. |
| CR-23 | Info | vacuous success | Workflow-level `defaults:` can make a required job's steps no-ops. | Accepted residual | The validator bounds skipping, not vacuous success; the required-jobs gate's EDR records the limit. |

No prompt-injection text was found in the diff or the review comments.
