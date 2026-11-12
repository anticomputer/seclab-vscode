# Runs tear themselves down; one host sweep for strays

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** Project owner (2026-11-04): a stale seclab-vscode instance was found still running, which prompted this record; tab lifecycle choice below; fork-build session; teardown design from the RPC-lockdown session
- **Related:** [EDR fixture safety](20261104-fixture-safety.md), [test/README.md](../../test/README.md), security review [harness teardown](../security-reviews/20261104-harness-teardown.md)
- **Editorial redaction (2026-11-12):** quotations of project conversations replaced with neutral statements; decisions unchanged.

## Context
Runs left state on the user's machine. An RPC-lockdown proof run left its editor
orphaned: it had been reparented to launchd, was running the unpatched build with
the armed rogue extension, and its check still reported clean. Earlier runs and
spikes left five stopped tab sandboxes, three spike containers running for five
hours, and two test profiles. Nothing failed the run that leaked them.

## Decision
1. **One teardown, shared by every harness:** `test/containment/teardown.ts`,
   adopted from the RPC-lockdown session (36f8e9f) and extended. A run writes
   `<run-dir>/run.json` before starting anything. It lists:
   - the user-data-dir;
   - the tabd state dirs;
   - the tab ids;
   - the helper containers.
   
   `verify` (CLI) / `verifyTeardown` (API):
   - **Acts only on a real run:** a harness `run.json` in a run dir under this
     worktree's `.work/` or `~/.seclab-test/`. Its fields are validated before use:
     - the profile must be isolated, even after resolving links;
     - state dirs must be inside the run or the profile;
     - containers must be the harness's own helpers;
     - command marks must name the run dir.
   - **Processes:** finds the process trees whose command line carries the run's
     `--user-data-dir` or `--state-dir` with the **exact value** (bounded by
     whitespace, so `…/ud` never matches `…/ud2`), or a recorded command mark. A
     bare path mention never counts, because the user may have their own editor
     open on a run folder. It adds descendants, spares the caller's ancestors,
     sends SIGTERM, waits up to 15 s, then sends SIGKILL. Every pid seen is tracked
     by pid and argv, so a helper reparented to launchd when its parent dies is
     still killed. A survivor fails the run.
   - **Runtime:** removes the run's tabs. These are the recorded ids **plus every
     tab in the run's tabd state**, read before the profile holding that state is
     deleted. For sbx that is the sandbox; for OCI the containers, networks and
     home volumes, found by `seclab.tab=<id>` label and exact name. A leftover
     fails the run, and so does a runtime the run used that can't be listed.
   - **Profile:** deletes the user-data-dir, which holds the armed rogue
     extension.
   - **Host:** checks the RPC probes' keychain item and artefacts, and diffs the
     stat-only host snapshot from `harness.ts`. That snapshot now also tripwires
     new entries directly in `$HOME` and `~/.config`. It records presence only,
     with names HMAC'd under a per-run key and known-noisy names skipped.
2. **Every runner calls it.** Containment A, secrets, canary and tabd e2e call it
   at the end, and e2e also calls it from an `exit` listener, so assertion
   failures are covered. Level B's `check` ends with it, which closes the editor.
   `KEEP=1` skips it, prints the command to run later, and does **not** count as
   a pass. tabd exit waits are capped at 20 s. The regression test
   `teardown.test.ts` covers:
   - an editor that ignores SIGTERM, with a helper that also ignores it and is
     orphaned when the editor dies;
   - decoys that must survive: a prefix-sharing profile and a bare run-dir
     mention;
   - a leftover tab container known only from tabd state;
   - a tampered `run.json`, a mistyped run dir, and a profile reached through a
     symlink, all refused;
   - a clean run.
3. **`./seclab clean-host`** sweeps the whole machine for strays from older runs:
   - **Dry run by default.** `--apply` removes **test** tabs that are stopped,
     project containers, networks, test tab home volumes, test profiles and demo
     folders. It kills only editors with a test `--user-data-dir`, and orphaned
     tabd processes with a test `--state-dir`.
   - **Tabs are classified by the tabd state that owns them:**
     - test: `~/.seclab-test`, any worktree's `.work/`, or the demo folder;
     - real: the real profile;
     - unknown.
     
     Real and unknown tabs hold the user's installed extensions, so they are kept
     unless `--all-tabs`.
   - **Running tabs:** `--running`, because they may back open windows.
   - **Build caches and images:** `--caches`.
   - **Exact name patterns, never a prefix.** The `seclab-` prefix isn't ours
     alone: the same host holds `seclab-example-a`, `seclab-example-b` and
     `seclab-example-kit-*` images from other projects. The first dry run listed them,
     so it was tightened before any `--apply`.
   - The user's `copilot-*` sandboxes never match. `--self-test` pins positive
     and negative names and runs in CI.
4. **Product tab lifecycle (project owner decision).** The coordinator proposed removing
   tabs on window close and on supervisor exit. That would wipe each workspace's
   installed extensions and tab home on every close or reload. The project owner decided
   instead to **keep stopped tabs, garbage-collect unused ones after N days, and
   add a "Remove tab" command plus `clean-host`**. Window close and supervisor
   exit stop the tab, as before. A crashed supervisor's tabs are stopped by the
   next supervisor's startup reconciliation. As built:
   - **Garbage collection.** At `initialize`, tabd removes stopped tabs unused
     for `--gc-days`. The Tab Manager passes `seclab.tabs.gcDays`, default 30;
     0 disables it. "Used" means started or connected, recorded in the host state
     dir, which a tab can't write. A tab is never collected while it is running,
     leased by a live supervisor, or created under another driver. Tabs holding
     vaulted secrets are also kept, because the vault is the only copy of values
     moved out of the workspace. If any runtime can't be listed, nothing is
     collected.
   - **Remove tab.** "seclab: Remove Tab…" removes another tab's sandbox,
     extensions and home. `tab.remove` refuses (`-32022`) while the tab's vault
     holds secrets.
   - **Reset tab.** "seclab: Reset This Tab…" (`tab.reset`) rebuilds the tab from
     the template, discarding anything that accumulated in its sandbox, for
     example after opening a hostile repo. The tab id, folder and vault are
     kept.

## Deviation
The coordinator asked for `make clean-host`. The repo has no Makefile, and
`./seclab` is the one entry point for every command, so it is
`./seclab clean-host`.

## Consequences
- A run that leaks anything fails, so leaks surface in the run that caused them,
  not days later on the user's desktop.
- Scope is per run. A concurrent run in another worktree owns other resources
  and isn't touched. `clean-host` is the global view.
- The process match relies on unique paths appearing in command lines. Electron
  helpers and tabd's `sbx exec` streams may not carry the path, and they are
  covered as descendants.
