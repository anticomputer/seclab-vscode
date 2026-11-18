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

## Round FAB2
A re-review of the round FAB fixes. Nothing at high or above; three mediums, one of them in an
agentic harness the change had not touched.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| FAB2-1 | Medium | release fetch | A refused or failed `fetch macos` left the earlier release app, which every run then accepted. | Fixed | The fetch writes `.work/app-fetch-pending` until the new app is in place; runs refuse the release app while it exists. |
| FAB2-2 | Medium | local builds | A dirty tree's build recorded HEAD, and a local build info looked like a CI one. | Fixed | Only a clean tree's build records a commit; `runId` only for CI builds. |
| FAB2-3 | Medium | agentic | The agentic runner's "ran the requested build" check could not fail, and neither agentic harness checked the build at prepare. | Fixed | Both refuse a wrong build at prepare; the check requires the launched app, unchanged build info and a passing build check. |
| FAB2-4 | Low | probe copies | A probe's altered copies were judged by their own location's rule, not their source's. | Fixed | The source app is judged once; copies run as its commit. |
| FAB2-5 | Low | git | The variant fetch's ancestry gate, and the new shell sites, kept inherited `GIT_*` variables. | Fixed | One helper drops every `GIT_*` variable. |
| FAB2-6 | Low | Linux driver | The Linux editor tarball was never bound to a commit. | Fixed | The build info beside the tarball goes beside the extracted editor, with this checkout's HEAD as the commit; a REH-only build's info is refused. |
| FAB2-7 | Low | fetch | The dispatcher hardcoded the branch location, and FAB-1 had no automated test. | Fixed | Usage is checked inside the fetch after the clear; `./seclab fetch --self-test` runs in CI. |
| FAB2-8 | Info | prompt injection | None found. | No finding | — |
