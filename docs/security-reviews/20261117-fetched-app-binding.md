# Security review: fetched-app binding (round FAB)

- **Date:** 2026-11-17
- **Scope:** round FAB, by an Opus-class model, of
  [EDR fetched-app-binding](../edr/20261117-fetched-app-binding.md): the fetch tool's clearing
  of test-build locations, and the launch-time check (`test/app-build.ts`) in the harness and
  the headless driver.
- **Threat model:** a run must not launch, or attribute evidence to, a build of a commit other
  than the one it was asked to test; a refused or failed fetch must not leave an earlier build
  where a later step takes it as the new one.

## Round FAB
Nothing at high or above. No injection: git runs without a shell and every commit is checked as
40 hex; the clear can't reach outside `.work`.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| FAB-1 | Medium | fetch | Usage errors (no, empty or extra run id) exited before the location was cleared, leaving the earlier build there. | Fixed | The dispatcher clears the branch location before its usage check; the variant fetch clears right after validating the variant. |
| FAB-2 | Medium | launch | `test/driver/local-window.ts` ran the app's CLI to install fixtures before the driver's check. | Fixed | It checks the app first. |
| FAB-3 | Medium | launch | `window-log-probe` launches altered copies with no build info beside them, so its negative controls could no longer run. | Fixed | The copies keep their source's build info. |
| FAB-4 | Low | release rule | The release app passed with any commit in HEAD's history, or with a test build. | Fixed | The release app must be a build of a commit on origin/main, and a test build runs only from `.work/test-builds/`. |
| FAB-5 | Low | binding | Build info is bound to the directory, not to the bundle's bytes; the check-to-launch window is unguarded. | Deferred | Needs a digest of the extracted bundle recorded at fetch time. |
| FAB-6 | Low | paths | The release location was compared lexically: case or a symlink could select the wrong rule. | Fixed | Canonical paths, and a symlinked release location doesn't get the release rule. |
| FAB-7 | Info | git | An inherited `GIT_DIR` could make HEAD another repository's. | Fixed | git runs without inherited `GIT_*` variables. |
| FAB-8 | Info | test builds | A test build at HEAD passed any run, and a variant's REH image wasn't bound to a commit. | Fixed | Test builds run only from `.work/test-builds/`; `image oci --test-variant` requires the REH's build info to name the commit under test. |
| FAB-9 | Info | prompt injection | None found. | No finding | — |
