# Security review: harness teardown, clean-host, tab GC/reset

- **Date:** 2026-11-04
- **Scope:**
  - `test/containment/teardown.ts` (shared teardown, adopted from the RPC-lockdown
    session's 36f8e9f) and its regression test;
  - `test/clean-host.ts`, and the runner wiring in containment, secrets, canary, e2e and
    level B;
  - `test/harness.ts`: the snapshot and profile checks;
  - tabd garbage collection, `tab.reset`, and `tab.remove` refusing while the vault
    holds secrets.
- **Threats:**
  - teardown or clean-host kills or deletes something that isn't the run's or the
    project's: the user's own editor, `copilot-*` sandboxes, other projects' `seclab-*`
    images;
  - a run leaks and still reports clean;
  - GC destroys the only copy of user data.
- **Decision record:** [EDR harness teardown](../edr/20261104-harness-teardown.md).
- **Reviewer:** `security-review` agent.

## Round 1
| # | Sev | Area | Finding | Disposition | Fix | Regression |
|---|---|---|---|---|---|---|
| T-1 | **Medium** | Wrong-process kill | Substring matching on the profile, state dir and **bare run dir**. `…/ud` matched `…/ud2`, and the user's editor opened on a run folder (or a `tail` on a run log) matched and was killed along with its tree. | Fixed | Only `--user-data-dir`/`--state-dir` with the exact value, bounded by whitespace, plus recorded command marks. The bare run-dir mark is removed. | `teardown.test.ts`: prefix-sharing and bare-mention decoys survive |
| T-2 | **Medium** | Leak reported clean | A failed `sbx`/`docker` listing read as "no leftovers". Tabs opened in the run that weren't recorded in `run.json` were orphaned when the profile, which holds their state, was deleted. | Fixed | A failed listing of a required runtime fails the check, and every run records its driver. `runTabs()` reads tab ids from the state dirs and the profile's tabd state before anything is deleted. | a tab known only from state is found and removed |
| T-3 | **Medium** | clean-host vs real editor | Tab names are identical for test and real tabs, so `--apply` would remove the real editor's stopped tabs and every tab home volume. | Fixed | Tabs are classified by the tabd state that owns them: test, real or unknown. Only test tabs are removed unless `--all-tabs`. Containers, networks and volumes follow their tab id. | by hand: a fake tab network is "remove (test)" with test state and "keep (unknown)" without it; `--self-test` pins the name patterns |
| T-4 | Low | `run.json` trust | Its fields drove `rm -rf`, kills and `docker rm` unvalidated. A tab can't write it, because only the workspace subdir is mounted. | Fixed | `manifestProblems()` refuses before acting: the profile must be isolated, state dirs inside the run or the profile, containers must match the helper pattern, and tab ids must be well-formed. | a tampered `run.json` is refused and nothing is deleted |
| T-5 | Low | Leak reported clean | `KEEP=1` passed; a hung tabd blocked teardown. | Fixed | KEEP is "not verified", so the gate returns false. tabd exit waits are capped at 20 s, after which teardown kills it. | — |
| T-6 | Low | clean-host processes | An "orphaned tabd" was any ppid-1 process naming tabd; any `.work/…userdata` path counted as a test profile. | Fixed | Matching on option values: editors with a test `--user-data-dir` only; tabd only when `tabd/src/main.ts` or `dist/tabd.js` has a test `--state-dir` and ppid is 1. | — |
| T-7 | Low | Snapshot | Unsalted name hashes; some configs and autostart were missing; noisy entries in `$HOME`. | Fixed | HMAC with a per-run key (v2 snapshot, mode 0600), more configs watched stat-only, noisy names skipped. | — |

## Round 2 (re-review)
T-1 to T-7 were verified fixed. GC, `tab.reset` and `tab.remove` (`-32022`) have no
issue: GC collects nothing if a driver can't list, and skips tabs that are running,
owned, leased or holding a vault.

| # | Sev | Area | Finding | Disposition | Fix | Regression |
|---|---|---|---|---|---|---|
| R-1 | Low | Process match | A command mark equal to the bare run dir was accepted. | Fixed | A mark must be a program plus arguments naming the run dir, and is never the run dir itself. | refused in `teardown.test.ts` |
| R-2 | Low | Operator error | `verify ~/src` with no `run.json` would remove every `seclab-t-*` sandbox whose workspace was under it. | Fixed | Requires a harness `run.json` (`startedAt`) in a run dir under this worktree's `.work/` or `~/.seclab-test/`. Removal only by tab id, never by workspace match. | a dir without `run.json` and `$HOME` are both refused |
| R-3 | Low | Profile check | The lexical `startsWith` could be bypassed through a symlink inside `~/.seclab-test`. | Fixed | The deepest existing ancestor, resolved, must lie inside a resolved test root. | a link to `$HOME` is refused |
| R-4 | Low | Snapshot privacy | The HMAC key is stored next to the names. | Accepted | The file is 0600 and local; the key only defeats precomputed dictionaries. | — |
| R-5 | Low | GC across drivers | A tab created under sbx, collected by an OCI supervisor, would be forgotten while its sandbox was orphaned. | Fixed | `TabRecord.driver` is recorded at claim. GC only collects tabs of the loaded driver. Older records without a driver are never collected. | `supervisor.test.ts`: an other-driver tab survives GC |

**No medium-or-higher findings remain.**
