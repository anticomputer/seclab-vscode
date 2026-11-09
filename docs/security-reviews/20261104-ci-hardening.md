# Security review: CI/CD hardening

- **Date:** 2026-11-04
- **Scope:**
  - workflows `build-macos`, `ci-linux`, `ci-unit`, `docs-check`, `workflow-lint`, and `dependabot.yml`;
  - `seclab`: `fetch_macos` provenance, `lint workflows`/`pins`, the lychee token;
  - `build/check-pins.ts` and the digest pins across the tree;
  - repo Actions settings;
  - `build/prepare.sh`: the automatic-tasks guard.
- **Threat:** a compromised or unreviewed workflow, action, image, cache or commit
  reaches the unsigned app that the user runs, or a PR gets a
  token.
- **Decision records:** [EDR ci-hardening](../edr/20261104-ci-hardening.md), [EDR automatic-tasks-off](../edr/20261104-automatic-tasks-off.md).
- **Reviewer:** `security-review` agent.
- **Tools:**
  - actionlint 1.7.12: clean;
  - zizmor 1.32.0: `regular` persona clean; `auditor` persona with online audits showed only informational "anonymous job" notes, now fixed.

## Round 1
No high or critical findings. Questions answered:
- **Tokens:** no PR-controlled code can obtain one.
- **Caches:** saved only on pushes and scoped by ref.
- **Template injection:** none.
- **Dangerous triggers:** none.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| CI-1 | **Medium** | Provenance trust root | The attestation proves "built from main at X", not that X passed the gates. Fetch picked the latest successful build, whatever the other checks said. `v*` tags would build, attest and upload any commit. | Fixed | build-macos is main-only (no tag trigger) and uploads only from main. `fetch_macos` takes only main push runs, requires the `unit`/`lint`/`docs` check runs to have succeeded on the exact SHA, and pins `--source-ref refs/heads/main`. The main ruleset (required checks on the SHA, no force-push or deletion) was approved by the user and is applied with this change. |
| CI-2 | **Medium** | Pin-check evasion | Markdown `ci: run` blocks (which CI executes), untagged images, unlisted Docker Hub images and expression-valued `image:` keys were all unchecked. | Fixed | `ci: run` blocks are scanned (same extractor contract as docs-check). `docker run|create|pull` is parsed structurally: the first non-option argument is the image, from any registry, tagged or not, with continuations joined. Expression-valued keys are flagged. The self-test covers each form. |
| CI-3 | Low | Window after verification | The zip was verified and extracted in place, in the worktree. | Fixed | A private 0700 staging dir; re-hashed immediately before extraction; moved into place; digest printed. |
| CI-4 | Low | Toolchain | Unpinned vsce; Node fetched by version. | Fixed / accepted | vsce pinned to 3.9.2. Node from nodejs.org via setup-node is documented as a residual. |
| CI-5 | Info | Flags | — | Fixed | `--deny-self-hosted-runners`. |
| CI-6 | Info | Online audits | zizmor's online audits run on pushes only. | Accepted | `sha_pinning_required` and GitHub-owned-only actions bound the risk. |

## Round 2 (re-review)
CI-1 to CI-5 verified. The automatic-tasks guard fails closed: a reordered, missing or
changed declaration fails the build.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| R-1 | Low | check-pins coverage | (a) docker as arrays in TS or Python only hit the registry/known-image regex. (b) A variable's definition is checked only by that regex. (c) An unlisted value-taking option makes its value look like the image. | Partly fixed | (c): the option table is extended, and unknown options fail closed. (a)/(b) accepted: harness images come from pinned constants (`test/harness.ts`), and the tree is clean. |
| R-2 | Low | App location | The verified app lives in the worktree (`.work/app`). | Accepted | Writable only by what can already write `./seclab`. Moving it out of the worktree is tracked. |
| R-3 | Info | Check-run gate | Failed re-run attempts and pagination could wrongly refuse a SHA (fail closed). | Fixed | Latest attempt per check name, `--paginate`. |
| R-4 | Low | Toolchain | vsce's transitive dependencies have no lockfile. | Accepted | Level B only (a test path); vendoring into a pinned helper image is tracked. |

Cross-reference (M4): a rogue remote extension can write user settings
(`$updateConfigurationOption`, target USER) and so turn `task.allowAutomaticTasks`
on for every tab. The tasks still run inside each tab, so this is cross-tab
influence, not escape. It is tracked with the RPC filter.

**No high or critical findings. No medium findings remain.**
