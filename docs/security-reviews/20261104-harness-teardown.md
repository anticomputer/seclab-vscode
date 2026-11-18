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

## Round 3: Falco sensors (PS-1)
Three host-side Falco sensors (`seclab-falco-*`, privileged, `/proc` mounted) kept running
after their runs, the oldest for about four hours, and both teardown and `clean-host` reported
the host clean. Scope: `test/containment/teardown.ts`, `test/clean-host.ts`, the sensor's
owner labels in `tabd/src/obs/falco.ts` and `tabd/src/main.ts`, and the regression tests.
Decision and root cause: [EDR addendum](../edr/20261104-harness-teardown.md#addendum-2026-11-17-falco-sensors-outlive-their-tabd).
Reviewed by the `security-review` agent (Opus-class) over two passes.

| # | Sev | Area | Finding | Disposition | Fix | Regression |
|---|---|---|---|---|---|---|
| PS-1 | **Medium** | Leak reported clean | A Falco sensor outlives a SIGKILLed tabd (its `docker run -i --rm` client dies with it). Teardown found a run's sensor only from the manifest's `stateDirs`, never the profile's tabd state; `clean-host` had no Falco rule; the sensors carry no `seclab.run` or `seclab.tab` label. | Fixed | Teardown hashes every state dir of the run; teardown and `clean-host` remove any sensor whose tabd pid is dead or no longer a tabd. | `teardown.test.ts`: a dead-pid orphan and a profile-tagged sensor are removed, a live tabd's survives |
| PS-2 | **Medium** | Wrong-container kill | The sweep judged "tabd dead" from our own `ps`, but a Docker engine can be shared by other pid namespaces (remote engine, VM or devcontainer on the socket, `hidepid`), whose live sensors would be removed. | Fixed | tabd labels its sensor `seclab.host` and `seclab.boot`; only sensors matching the caller's own are judged. | a foreign-owner dead-pid sensor survives |
| PS-3 | Low | Leak or kill on partial data | A `ps` that failed partway was read as the full table. | Fixed | The sweep judges nothing unless `ps` exits 0 with output. | a fake `ps` printing one line then failing leaves the sweep unknown |
| PS-4 | Low | Leak reported clean | A failed `docker ps` listed no sensors, and `clean-host` could say the host was clean. | Fixed | `clean-host` shows a kept "(docker ps failed)" item. | `clean-host` with a failing docker shows it |
| PS-5 | Low | Wrong-container kill | On Linux the root pid namespace link is the same on every machine, so cloned machines on one engine differed only by boot time. | Fixed | The Linux identity adds the boot id. | `--self-test`: other-host and other-boot sensors are not claimed |
| PS-6 | Low | Leak reported clean | Sensors the sweep can't judge (older tabd, other namespace, changed macOS hostname) were skipped silently. | Fixed | macOS leaves the hostname out; teardown notes unjudgeable sensors whose pid isn't running, `clean-host` says to check them by hand. | verify notes the foreign sensor without failing |
| PS-7 | Low | Test residue | The test left its inert fake `docker` script under `.work/`. | Fixed | Removed at the end of the test. | — |

**No medium-or-higher findings remain.**

## Round 4: code review of the Falco sweep (CR16)
Copilot code review on the PS-1 pull request raised three points after it merged (CR16-1 to
CR16-3), and four more on the fix's own pull request (CR16-8 to CR16-11). Each was checked against the code and fixed with a regression test. The fix was then
reviewed by the `security-review` agent (Opus-class), which found four lows (CR16-4 to
CR16-7), all fixed; nothing at medium or above remains.

| # | Sev | Area | Finding | Disposition | Fix | Regression |
|---|---|---|---|---|---|---|
| CR16-1 | Low | Wrong-container kill | On macOS the owner identity was only the uid (no hostname, no `/proc`), so two Macs with the same uid on one shared engine, booted within 10 s, matched. | Fixed | macOS hashes the boot session UUID (`sysctl kern.bootsessionuuid`); with no per-machine id the identity is unknown and nothing is judged. | `clean-host --self-test`: unknown identity never matches |
| CR16-2 | **Medium** | Wrong-container kill | Run-scoped removal took every sensor with the run's state tag. The tag hashes a path another namespace on a shared engine can share (the same profile path), so its live sensor was removed, also when `ps` failed. | Fixed | A tagged sensor is the run's only with this namespace's owner labels or when named for one of the run's processes (captured before stopping them); a foreign-labelled one is neither removed nor a leftover, an unlabelled unproven one is reported. | `teardown.test.ts`: a foreign sensor with the profile's tag survives and isn't a leftover; an unlabelled one named for a run process is removed |
| CR16-3 | Low | Wrong-container kill | `clean-host` removed a stray test tabd's sensor after a kill it never confirmed (the callback returned success even if the signal failed). | Fixed | The kill reports success only once the process has exited, and the sensor goes only once its tabd is gone. | `clean-host --self-test`: a sensor whose stray tabd survives termination is kept |
| CR16-4 | Low | Wrong-container kill | A run pid proved ownership even for a sensor with foreign owner labels, so a pid collision could remove another namespace's sensor. | Fixed | A run pid proves ownership only for an unlabelled sensor. | `clean-host --self-test`: a foreign-labelled sensor named for a run pid is not the run's |
| CR16-5 | Low | Leak reported clean | A run's own sensor whose labels drifted (a clock step, a renamed Linux host) was neither the run's nor reported. | Fixed | Tagged sensors with foreign labels whose pid isn't running here are noted in verify, never removed and never failed (they may be another namespace's). | `clean-host --self-test`: they are classified `unjudged` |
| CR16-6 | Low | Wrong-container kill | tabd's own stale-sensor cleanup removed any same-tag sensor whose pid wasn't alive locally, without the owner check. | Fixed | `staleFalcoNames`: a labelled sensor only if its owner labels are this supervisor's; an unlabelled one by its pid as before. | `obs.test.ts`: another host's or another boot's sensor is kept |
| CR16-7 | Low | Test soundness | The test wrote the label `undefined` when the identity was unknown, and run-scoped ownership had no pure test. | Fixed | Empty label for an unknown identity; pure cases for `classifyRunFalco` and `staleFalcoNames`. | the cases above |
| CR16-8 | Low | Wrong-container kill | (Code review of the fix.) If the kill of a stray tabd failed and `ps` failed too, `clean-host` read that as the process gone and could remove its live sensor. | Fixed | `pidAliveFrom`: when `ps` gives no answer, only ESRCH from `kill(pid, 0)` proves absence. | `clean-host --self-test`: a failed `ps` with EPERM is alive |
| CR16-9 | Low | Wrong-container kill | (Code review of the fix.) With no owner identity of its own (no boot id), tabd's stale-sensor cleanup still removed unlabelled same-tag sensors whose pid wasn't alive locally, which could be another namespace's. | Fixed | A supervisor with no identity removes no stale sensor; teardown and `clean-host` report them. | `obs.test.ts`: an unknown identity removes nothing, labelled or not |
| CR16-10 | Low | Leak reported clean | (Code review of the fix.) Adding the macOS UUID reordered the Linux owner-hash inputs, so sensors labelled by an earlier build looked foreign after an upgrade and nothing reclaimed them. | Fixed | Linux keeps its input order (hostname, pid namespace, boot id, uid); the macOS UUID takes the boot id's place. | `obs.test.ts`: the Linux hash equals the earlier order's |
| CR16-11 | Low | Robustness | (Code review of the fix.) A `ps` that failed to spawn has no stdout, so the liveness check threw before its `kill(pid, 0)` fallback and aborted cleanup. | Fixed | Missing stdout reads as empty; the probe decides. | `clean-host --self-test`: a spawn failure with EPERM is alive, with ESRCH gone |

## Round 5: a sensor reported left over while still being removed (PS-8)
A ci-linux `oci` run failed the teardown gate "no Falco sensor outlives its tabd" for a sensor
whose tabd had exited, while the pull request run on the same head passed. Checked against the
code and reproduced: nothing leaked. tabd removes Falco when the last tab stops, but runs that
removal without awaiting it; on exit its shutdown found no Falco child and returned, so tabd
exited while its own `docker rm -f` was still running. The gate's `rm -f` then failed at once
("removal ... is already in progress") while `docker ps -a` still listed the container, and the
listing straight after read that as a leak. With a removal in flight, the old remove-then-list
failed 5 of 5 times and the fix 0 of 5. Fixed, then reviewed by the `security-review` agent
(Opus-class), which found three lows, and by Copilot code review, which found two more; all
fixed. Nothing at medium or above remains.

| # | Sev | Area | Finding | Disposition | Fix | Regression |
|---|---|---|---|---|---|---|
| PS-8 | Low | Leak reported clean (false positive) | tabd exited before its own Falco removal finished, and the teardown gate listed the container straight after its own `rm -f`, which fails while a removal is in progress: a flaky failure, and a queued `add` could have started Falco again after shutdown. | Fixed | Every `stop()` waits for a removal already in flight; tabd's shutdown uses `close()`, which also refuses to start Falco again. Teardown and `clean-host` remove sensors and wait, bounded (20 s), until docker no longer lists them; a failed listing never counts as gone. | `obs.test.ts` and `teardown.test.ts` PS-8 cases |
| PS-9 | Low | Robustness | (Review of the fix.) An `add` refused after close still left a readiness waiter whose timeout became an unhandled rejection. | Fixed | The closed check comes before any waiter exists. | `obs.test.ts`: no unhandled rejection past the timeout |
| PS-10 | Low | Robustness | (Review of the fix.) A failed removal would have been re-thrown to every later `stop()`. | Fixed | The stored removal never rejects. | `obs.test.ts`: repeated stops after a failed removal |
| PS-11 | Low | Leak reported clean | (Review of the fix.) `clean-host` read a failed `docker ps` as the sensor gone. | Fixed | It reports success only from the bounded wait, which needs a listing. | the `awaitGone` failed-listing case |
| PS-12 | Low | Robustness | (Code review.) Closed while the first `add` was still in its stale-sensor cleanup, `apply()` went on to create a readiness waiter that later timed out unhandled. | Fixed | The closed check is repeated after the cleanup, before any waiter exists. | `obs.test.ts`: close during a held cleanup leaves no waiter and starts nothing |
| PS-13 | Low | Robustness | (Code review.) The 20 s bound didn't cover the docker calls: a stalled daemon could hang teardown or `clean-host` in `rm -f` or the listing. | Fixed | One deadline covers every `rm -f` and listing, each given only the time left; a call that times out never counts as gone. | `teardown.test.ts`: a stalled docker ends at the deadline |

