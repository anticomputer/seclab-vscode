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

## Addendum (2026-11-17): Falco sensors outlive their tabd
Three `seclab-falco-*` containers kept running on the development host after their runs ended,
the oldest for about four hours. They were found by hand ([review round 3](../security-reviews/20261104-harness-teardown.md#round-3-falco-sensors-ps-1)).

**Why they survived.** tabd runs Falco as `docker run -i --rm`, named
`seclab-falco-<sha256(state dir)[0:8]>-<tabd pid>` and labelled `seclab.obs=falco`,
`seclab.state`, `seclab.pid`. There is no `seclab.run` or `seclab.tab` label, so nothing that
claims resources by run or by tab ever matched them. When tabd is SIGKILLed (teardown's
escalation, or a crash), its docker client dies with it and the container keeps running with
no reader. Then:
- teardown found a run's sensor only by hashing the manifest's `stateDirs`. The editor-driven
  harnesses record a `userDataDir` instead, and the Tab Manager's tabd keeps its state under
  the profile (`User/globalStorage/seclab.tab-manager/tabd`). `runTabs()` already read that
  dir, but the Falco lookup didn't;
- `clean-host` had no Falco rule at all: the names don't match its tab patterns;
- tabd's own `cleanupStale` sweeps only at the next Falco start in the same state dir, and a
  test profile is deleted before that can happen.

**Decision.**
- Teardown hashes every state dir of the run, the profile's included, so a run's own sensor
  is a leftover that fails the run until removed.
- Teardown and `clean-host` both remove any `seclab.obs=falco` container whose tabd is gone:
  the pid in its name and `seclab.pid` label is dead, or now runs something other than a tabd
  command line (`tabd/src/main.ts`, `dist/tabd.js`). `clean-host` also removes the sensor of a
  stray test tabd it kills in the same pass, running or not, because an orphan has no reader.
- This is the one host-wide sweep in teardown, an exception to "scope is per run". An
  orphaned sensor has no owner left by construction, and the rule claims only sensors whose
  owner is provably gone: a live tabd's sensor, a label that disagrees with the name, and any
  other name are never touched. If docker or the process table can't be listed in full,
  nothing is removed, and `clean-host` says so rather than reporting the host clean.
- **A pid is only judged by its own namespace.** One Docker engine can serve several pid
  namespaces (a remote engine, a VM or devcontainer on the same socket, other users under
  `hidepid`), and a pid missing from our `ps` says nothing about theirs. tabd labels its
  sensor `seclab.host` (a hash of the pid namespace, the uid and, on Linux, the hostname and
  boot id; the root namespace's link is the same on every Linux machine) and `seclab.boot`
  (boot time), and the sweep only judges sensors whose labels match its own, boot within
  10 s. macOS leaves the hostname out because it follows the network. Sensors from an older
  tabd without the labels, or from another namespace, are never claimed: teardown notes any
  whose pid isn't running here without failing, and `clean-host` lists them to check by hand.
  A clock step larger than the slack keeps a sensor rather than removing it.
- The live check is the pid, not the state-dir hash, because the real editor's state dir
  contains a space and `ps` doesn't preserve argv boundaries. A pid reused by another tabd
  keeps an orphan alive until that tabd exits; that errs on the side of keeping.

**Proof.** `teardown.test.ts` plants inert `sleep` containers with Falco's name and labels:
one whose pid is dead, one tagged with the run profile's tabd state, one owned by a live fake
tabd, and one whose pid is dead but whose owner labels name another namespace. Against main's
teardown the first two survived while verify reported clean; with the fix both are removed,
the live and the foreign ones survive, and verify passes. A `ps` that prints part of the table
and fails leaves the sweep unknown, and `clean-host` with a failing docker shows the failure.
`clean-host` on main didn't list the leftovers; with the fix the dry run lists both with the
reason. `clean-host --self-test` pins the classifier (dead pid, reused pid, live tabd, label
mismatch, unlabelled, other namespace, other boot, foreign names).
