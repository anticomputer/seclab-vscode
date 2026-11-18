# Fetched-app binding: a run launches only the build it was asked to test

- **Status:** accepted
- **Date:** 2026-11-17
- **Deciders:** Coordinator (2026-11-17): a refused or failed fetch must not leave an earlier app
  where a later step takes it as the new build, and every harness and driver run must refuse an
  app whose `build-info.json` commit isn't the one it was asked to test. Fork-build session:
  implementation.
- **Related:** [Branch test builds](20261106-branch-test-builds.md),
  [Test build variants](20261106-test-build-variants.md)

## Context
`./seclab fetch macos-branch` replaced `.work/app-branch` only after a fetch verified. A refused
or failed fetch left the previous app in place, and a later step ran it as the requested build:
a probe found one there from build run 42239456909 (commit 26137e98) after a refused fetch. Nothing
at launch compared the app's recorded commit with the commit under test.

## Decision
- **Fetch.** `fetch macos-branch` and `fetch macos-<variant>` clear their destination
  (`.work/app-branch`, `.work/test-builds/<variant>`) before checking anything, usage errors
  included, so a refusal or failure leaves no app there. `fetch macos` keeps the release app
  (`.work/app`) until a new one verifies: it may be the editor in use, and a failed fetch of a
  newer build shouldn't remove it. Instead it writes `.work/app-fetch-pending` first and removes
  it only when the new app is in place; while it exists, runs refuse the release app.
  `./seclab fetch --self-test` (CI) checks every refusal that needs no network.
- **Launch.** `test/app-build.ts` checks every launch: `launchEditorInBackground`
  (`test/harness.ts`, behind `test/window.ts launch` and the probes that print its line), the
  headless driver (`test/driver/editor.ts`), and `test/driver/local-window.ts` before it runs the
  app's CLI. A probe's altered copy of an app (`test/observability/window-log-probe.ts`) keeps
  its source's build info. It reads the `build-info.json` the fetch placed beside
  the app (`build-info-app.json` for a test variant): a regular file, not a symlink, with a full
  `repoSha`. The commit the run is asked to test is:
  - `SECLAB_APP_SHA` (40 hex) when set, for an app anywhere;
  - otherwise this checkout's HEAD, for a branch or test-variant build;
  - otherwise, for the release app, a build of a commit on origin/main (the release location
    itself, not a symlink there).
  A test build (build info with `testBuild`) runs only from `.work/test-builds/`, whatever
  `SECLAB_APP_SHA` says. Paths are compared canonically, and git runs with no inherited
  `GIT_*` variables. A macOS app with no build info is refused.
  "This checkout" is the one the app was fetched into: the checkout running the harness, or one
  nested in its `.work` (an A/B run's baseline worktree, whose HEAD is the baseline commit).
- **Agentic runs.** `test/agentic/runner/runner.ts` and `test/agentic/browser/run.ts` refuse a
  wrong build at prepare, and the runner's "ran the requested build" check passes only if the
  window was launched from that build's app and its build info still names the prepared commit. A Linux editor this checkout built
  (`./seclab build linux editor`, the driver's container runs) has none and isn't checked.
- The check runs before the focus watcher or anything else starts, so a refusal launches nothing.
- **Test REH.** `./seclab image oci --test-variant V` builds a tab image only from a REH whose
  `build-info-test-V.json` records the commit under test (the same rule). A local Linux build
  records the host checkout's HEAD as `repoSha` (no `runId`), since git inside the build
  container can't read a worktree's HEAD. Only a clean tree's build records a commit (the build
  reads the working tree); `runId` is recorded only for CI builds.
- **Linux driver.** `./seclab test driver|cli-open|local-window` put the build info beside the
  tarball next to the extracted editor and pass this checkout's HEAD as `SECLAB_APP_SHA`, so a
  stale tarball is refused. A build info whose targets lack the editor (a later REH-only build)
  is refused. A dirty tree's build, which records no commit, runs unbound with a warning.

## Proof
- `test/app-build.test.ts` (unit): a stale branch build (an ancestor commit) is refused and the
  build of HEAD passes; `SECLAB_APP_SHA` wins either way and must be full; the release app must be
  a build of a commit on origin/main, and a symlinked release location gets the HEAD rule; a test
  build runs only from `.work/test-builds/`; an inherited `GIT_DIR` doesn't move HEAD; a missing,
  symlinked, non-object or commitless build info is refused; a test variant's
  `build-info-app.json` is the file read. Neutralising each rule fails it.
- With a stale app injected into `.work/app-branch` (build info naming 26137e98): a refused
  `fetch macos-branch` of a main build, and a failed fetch of a run that doesn't exist, each left
  `.work/app-branch` absent, as did usage errors (no run id, an empty one, two) for the branch and
  a variant; `test/window.ts launch` and `test/driver/shot.ts` each refused the stale app with
  exit 1 and started no process; `image oci --test-variant` refused a REH whose build info names
  another commit. A fake Linux editor tarball whose build info names an old commit was refused
  inside the driver's container before the editor started.

## Limits
- The build info is bound to the directory, not to the bundle's bytes: an app edited in place,
  or a stale bundle beside a fresh build info, passes. Binding needs a digest of the extracted
  bundle recorded at fetch time (review FAB-5, deferred). The check-to-launch window is unguarded.
- The release app is any build of a main commit, not necessarily the newest; a fetch that
  didn't complete is caught by its marker.
- A dirty tree's local Linux build isn't bound to a commit.

## Consequences
- A run from a branch checkout that tests a build of another commit (a newer main build, or a
  branch build after local commits) sets `SECLAB_APP_SHA` to that commit.
- A local Linux editor build isn't bound to a commit; it is rebuilt from the checkout it runs in.
