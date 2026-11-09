# Security review: deps-updates container mounts and the mount lint (round JJJ)

- **Date:** 2026-11-09
- **Scope:** round JJJ, `3b2416f` and its fixes:
  - `seclab` mount lists (`VERIFY_IMAGE_FILES`, `DEPS_OUTDATED_FILES`, `DEPS_OUTDATED_DATA`)
    and `mount_files`; `verify_signed_image` at `/d`; `deps outdated` and its `--self-test`;
  - `build/import-closure.ts` and `./seclab lint mounts`;
  - `build/deps-outdated.ts` `pickRelease` and its offline self-test;
  - the new `ci-unit` step. `deps-updates.yml` is unchanged (dispatch run 42647703437).
- **Threat model:** the `deps outdated` container is networked and reads anonymous registry
  and GitHub API data; the report it prints is posted to an issue by a job holding
  `issues: write`. Registry and API responses are hostile text. The container must stay at
  single files (no repo content, no run state, no token: EE-2, DD-4), external data must
  reach nothing but quoted report text (EE-3), and the new CI guard must not itself add
  network, credentials or a write path.
- **Records:** [EDR pin-age-cooldown](../edr/20261106-pin-age-cooldown.md),
  [round EE](20261104-supply-chain.md) (EE-1, EE-2, EE-3), DD-4.
- **Prompt injection:** none found. Registry and API strings stay inside `safe()` code spans
  and reach the issue only as `--body-file`.

## Round JJJ
Two lows, three infos. Confirmed:
- no widening: `verify_signed_image` mounts the same two files, only the path moved
  (`/v` flat to `/d/<repo-relative>`), and `build/verify-image.ts` does no cwd-relative
  `fs` or `process.env` access;
- `deps outdated` goes from three to four single-file read-only mounts, the addition being
  `build/release-dates.ts`, which the entry already imports; no `-e`/`--env-file`;
- no token in the networked container: `GH_TOKEN` is set only on the issue step;
- `deps outdated --self-test` runs `--network none` and exits before the register read and
  any `fetch`;
- `lint mounts` runs `--network none` with the repo read-only and writes only to a tmpfs;
- API data reaches only report text (`safe()`, `--body-file`); a malformed `published_at`
  parses to `NaN`, which the cooldown filter rejects;
- a `lint mounts` miss fails closed: an unmounted import is `ERR_MODULE_NOT_FOUND`;
- a branch `workflow_dispatch` with `issues: write` is unchanged by this commit.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| JJJ-1 | Low | lint mounts | The lint enforced mounts ⊇ closure only; the invariant EE-2 and DD-4 protect is the upper bound, so a widened mount passed silently. | Fixed | Each code list must equal its entry's closure: `extra()` fails on mounted code the entry never imports (self-test injects one). Data files are a separate, hand-reviewed list (`DEPS_OUTDATED_DATA`). |
| JJJ-2 | Low | deps outdated | With the pin outside the fetched 30 releases, `pickRelease` still suggested the newest one, which can be older than the pin (downgrade advice). An upstream tag `v<pinned>` with a recent date can suppress a real update row. | Fixed (first); accepted (second) | A pin not among the fetched releases is an error row ("compare by hand"), never a suggestion; self-test case. The re-tag direction only hides a row, needs upstream to re-publish the pinned version, and every update is a reviewed change anyway. |
| JJJ-3 | Info | seclab | `"${MOUNTS[@]}"` with an empty array aborts under `set -u` on bash 3.2. Not reachable. | Fixed | `mount_files` refuses an empty list. |
| JJJ-4 | Info | import-closure | The specifier regex missed `[import('./a.ts'),import('./b.ts')]`; template-literal imports are missed by design. | Fixed | Prefix class widened (self-test case); the template-literal miss is noted in the header. |
| JJJ-5 | Info | deps outdated | An unknown argument silently took the networked branch. | Fixed | Unknown arguments print usage and exit 2. |
| — | Residual | deps-updates | A branch `workflow_dispatch` runs that branch's workflow definition with `issues: write`. Pre-existing, writer-only. | Accepted | Scheduled runs use main; the token stays out of the report container. |
