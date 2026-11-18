# Security review: Level B's expected losses on a filtered build (round FXF)

- **Date:** 2026-11-17
- **Scope:** seven rounds, by an Opus-class model, of the change that makes the editor-driven
  run's `[fsmonitor]` "ran" check an expected failure on a build with the RPC capability filter.
  Plus Copilot's review of the pull request that carries it (26). Code: `test/containment/assert.ts`,
  `check-evidence.ts`, the fixture's `probe.sh`, their tests, and `docs/RPC-LOCKDOWN.md` §7.1.
- **Why the change:** on a filtered build the git extension opens no repository in a tab, because
  `$requestResourceTrust` is denied, so the fsmonitor hook never fires. Every filtered Level B run
  failed `[fsmonitor]`, on 1.145.0 and 1.145.3 alike. A live run confirmed the cause: the trusted-side
  decision log held the denial, and the tab's git log showed a scan that opened no repository.
- **Threat model:** a hostile tab must not be able to turn a real host-side run of a workspace
  vector into an expected failure, or hide one. Evidence, the decision log's `ref` strings, and
  every workspace file are within a tab's reach.

## Outcome
An expected failure now excuses only the in-tab "ran" row, and only with its denial observed.
Every host fact is a plain failing row:
- the run-dir marker: `probe.sh` takes a host run's run dir and marker from the harness's
  trusted environment, confirmed by a nonce and an arming window in the run dir;
- the files a host run reads, digested byte for byte;
- no file added to the checkout beyond the run's own output, and no `.git`;
- no evidence withheld in the tab while the host holds a copy.

Level B on 1.145.3 passes on sbx (21/23) and OCI (20/22), with only expected failures, each tied
to an observed denial. A tab that tampers with a non-held file and restores it before the check
isn't caught, which is the ungated checkout's race (ADR write-back-gate §7).

## Rounds 1 to 7

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| FXF-1 | High | check-evidence | Both halves of the expected-failure condition were within a tab's reach (a denial it can cause, evidence it can withhold), so a host run could read as expected. | Fixed | The expected failure covers only the "ran" row; host facts stay hard checks. |
| FXF-2 | Medium | assert | With no evidence file, the host-marker check vanished while the marker sweep exempted that vector's marker. | Fixed | The host-marker row is kept on the no-evidence path. |
| FXF-3 | Medium | docs | The gap text claimed Level A covers fsmonitor, though Level A never exercises a host run. | Fixed | Wording. |
| FXF-4 | Low | decision log | The excusing denial is matched across the profile, with no window, tab or time binding. | Accepted residual | With host facts hard, the denial only explains an in-tab non-run, which a tab could equally cause by breaking its own probe. |
| FXF-5 | Info | check-evidence | Removing the unconditional `[task]` expected failure is strictly narrower. | No finding | — |
| FXF-6 | Medium | check-evidence | On OCI the fsmonitor marker was exempt from the marker sweep with no fsmonitor row behind it. | Fixed | One vector list drives the checks and the sweep. |
| FXF-7 | Medium | probe.sh | A tab could blank the marker line in the probe's targets, so a host run wrote no marker. | Fixed | The trusted route: the run dir and marker come from the harness's environment, never the workspace. |
| FXF-8 | Low | check-evidence | The vector list was written out three times. | Fixed | One list. |
| FXF-9 | Info | check-evidence | The sbx host-evidence row rested on an unstated premise (no write-back sync during Level B). | Fixed | The premise proved false (FXF-20) and the row is gone. |
| FXF-10 | Medium | probe.sh | On the trusted route an out-of-run canary line still made the probe exit before its marker. | Fixed | Such a path is skipped, not fatal. |
| FXF-11 | Medium | check-evidence | The marker-line check accepted any matching line while the probe reads the first. | Fixed | Byte-for-byte digest of the arming files. |
| FXF-12 | Medium | check-evidence | On OCI the probe, its task or the fsmonitor config could be rewritten in the host checkout unseen. | Fixed | The digest, and no `.git` in the host checkout. |
| FXF-13 | Low | probe.sh | The trusted route had no arming window, and the fixture's safety header described only one route. | Fixed | An until file beside the nonce; the header describes both routes. |
| FXF-14 | Medium | check-evidence | Digesting every fixture file failed every OCI run, because the rogue extension rewrites its settings by design. | Fixed | Only what host-run vectors read is pinned. |
| FXF-15 | Low | check-evidence | Files a tab adds to the checkout were invisible. | Fixed | The whole tree is recorded; additions beyond the run's output fail. |
| FXF-16 | Info | check-evidence | Keys from the arming record weren't path-checked. | Fixed | The record is parsed strictly. |
| FXF-17 | Low | check-evidence | An unreadable directory read as "nothing added". | Fixed | It fails the row, and prepare refuses to record. |
| FXF-18 | Low | check-evidence | Host OS artifacts (`.DS_Store`) would fail a clean run. | Fixed | A narrow exemption. |
| FXF-19 | Info | rogue extension | A dead field pointed inside the pinned directory. | Fixed | Removed. |
| FXF-20 | Medium | check-evidence | A real sbx run showed evidence syncing to the host checkout, so the host-evidence row proved nothing and would fail any build where the task runs. | Fixed | Row removed; evidence is run output on both drivers. |
| FXF-21 | Medium | docs | The comments scoped tampering to OCI, though sbx syncs non-held paths such as the targets. | Fixed | Wording; the digest covers both drivers. |
| FXF-22 | Low | check-evidence | Evidence present on the host but hidden in the tab read as "no evidence". | Fixed | A plain failing row. |
| FXF-23 | Low | check-evidence | The OS-artifact filter matched at any depth. | Fixed | Narrowed. |
| FXF-26 | Low | check-evidence | A tab that tampers with a non-held arming file and restores it before the check isn't caught. A host run descended from the editor is marked anyway. | Accepted residual | The ungated checkout's race (ADR write-back-gate §7). |

## Copilot's review of pull request 26

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| FXF-24 | Low | check-evidence | A directory named like an OS artifact was skipped with its subtree. | Fixed | Exempt only as the right file type. |
| FXF-25 | Medium | check-evidence | On OCI a FIFO in place of an arming file blocked the check before its report and teardown. | Fixed | Arming files are read non-blocking, without following symlinks, regular files only, bounded. |
| FXF-27 | Low | check-evidence | `O_NOFOLLOW` guards only the last component: a tab that swapped `.vscode` for a symlink could make the check read and hash a host file. | Fixed | Host reads of workspace content take the workspace root: the opened file must be the one its real path names, inside the root (same device and inode); a directory that now resolves outside is unreadable. |

No prompt-injection text was found in the diff or review comments (the rogue extension's AI-probe
payload is deliberate fixture content).
