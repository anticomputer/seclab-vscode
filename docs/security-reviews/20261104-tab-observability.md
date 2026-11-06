# Security review: tab observability (one-way event stream, sbx collector, OCI Falco, Tab Activity view)

- **Date:** 2026-11-04
- **Scope:**
  - Round 1: `origin/main..8b1df33` (pre-rebase), that is the whole layer:
    - `tabd/src/obs/*`, plus the hooks in `supervisor.ts`, `main.ts`, `drivers/{sbx,oci,types}.ts`;
    - `sandbox/rootfs/opt/seclab/bin/seclab-obs-collect`, `seclab-reh-{start,connect}`;
    - `sandbox/sbx/{seclab-obs-guard.c,build-template.sh,obs-debs.lock}`;
    - `tabd/tools/*`;
    - `extensions/seclab-tab-manager/src/activity.ts`;
    - the tests.
  - Round 2: the round-1 fixes in `80c98bb`, after the linear rebase onto `10415e3`.
  - Round 3: the round-2 fixes in this commit.
- **Question:** does the layer add any channel from a tab into the trusted side beyond a one-way, size-limited, schema-validated event stream? Can the tab user, or a rogue extension (not root in the VM), forge or hide events?
- **Reviewer:** `security-review` agent (default model); triage by the tab-observability session.
- **Related:** [ADR tab observability](../adr/20261104-tab-observability.md), [EDR sensor spike](../edr/20261104-tab-observability-sensor-spike.md), [events](../tabd/EVENTS.md)

## Round 1
| # | Sev | Area | Finding | Disposition | Fix | Regression |
|---|---|---|---|---|---|---|
| OR-1 | **High** | sbx guard | The tab user can install its own seccomp filter that has a listener (`SECCOMP_FILTER_FLAG_NEW_LISTENER`) and returns `USER_NOTIF`. That outranks strace's `SECCOMP_RET_TRACE`; a sibling `CONTINUE`s the syscall, so it runs with no trace line. io_uring ops never pass syscall tracing at all. Reproduced with strace 6.13 and the guard. | Fixed | The guard refuses `seccomp()` with `NEW_LISTENER` (`EPERM`) and `io_uring_*` (`ENOSYS`). The collector also sets `kernel.io_uring_disabled=2`. | `test/observability/guard-check.py` in `./seclab test obs sbx`: refused under the guard; the control run without the guard succeeds, which proves the bypass is real |
| OR-2 | Medium | sbx collector | The REH inherited the write end of strace's output pipe, so the tab user could forge `tab-vm-root` trace lines or corrupt real ones. Corrupt lines were only counted. | Fixed | The guard runs `close_range(3, ~0U)` before exec. tabd marks the tab `degraded` on corrupted or forged sensor output. | guard-check (`fds` empty; control sees fd 7); unit `obs review OR-2` |
| OR-3 | Medium | hub | Tab-driven trusted sources (workspace watcher) shared one rate bucket with RPC-filter decisions and supervisor events, so a tab could push those out. | Fixed | Separate buckets: sensor; tab-driven (watcher, policy log, broker, scan); client (RPC filter, gate). Supervisor (`tabd`) events are never limited. | unit `obs review OR-3` |
| OR-4 | Medium | sbx collector | Root `chown`ed honeypot directories by name inside the agent-owned home, so a hardlink race could hand the agent a root-owned file. | Fixed | `fchown` through the opened, verified directory fd. `fs.protected_hardlinks` and `fs.protected_symlinks` are set to 1 before seeding. | `./seclab test obs sbx` asserts the sysctls |
| OR-L1 | Low | UI | Observation reasons (which can carry collector text) weren't escaped. | Fixed | `safeText` in `setObservation`. | unit `obs review low` |
| OR-L2 | Low | watcher | The `package.json` read could follow a parent swapped for a symlink after `realpath`. | Partly fixed; accepted | dev/ino are checked after open. Only a scripts hash is computed and nothing returns to the tab. | — |

## Round 2 (verifies round 1; reviews the rebase and the write-back mount hook)
No high or critical findings. OR-1 to OR-4 are verified correct, including the BPF jump offsets on both architectures.

| # | Sev | Area | Finding | Disposition | Fix | Regression |
|---|---|---|---|---|---|---|
| OR-5 | Medium | watcher | Regression from the OR-3 fix: past the 50-per-flush cap, host-executable writes were folded into a debug-level bulk summary. Fifty create-and-delete decoys hid a git hook. | Fixed | Host-executable paths are never bulked. Deletions don't count toward the cap. Overflow becomes a `warning` that names the paths (hidden config paths first) and feeds the detector. | unit `obs review OR-5` (real fs.watch) |
| OR-6 | Medium | sbx collector | An `execve` with a padded argv makes an over-cap strace line, which the collector dropped whole, so the exec and its detections vanished. | Fixed | The collector keeps the record's head (pid, syscall, program path). tabd emits a `warning` exec with `truncated`, and degrades the tab on the first corrupt or oversized record. | unit `obs review OR-6` |
| OR-L3 | Low | guard | fd 2 of the guarded tree was strace's stderr pipe, so the tab could inject `strace-err` debug lines. | Fixed | The guard points fd 2 at `/dev/null` before exec. | guard-check |
| OR-L4 | Low | collector | A process the watchdog re-attached after it ran untraced only warned. | Fixed | Any untraced process marks the tab `degraded`. | e2e (harness execs are external) |
| OR-R1 | — | design | Tab-driven trusted sources (watcher, policy log, broker, scan) still share one bucket with each other: a workspace flood can drop a broker egress event, which is then summarised as "tabDriven events dropped". | Accepted | Separate from RPC and supervisor events, as OR-3 requires. Broker audit is also in the broker's own log. | — |
| OR-R2 | — | design | Agent processes the collector attaches to with `-p` (PID 1, its `sleep`) never ran under the guard; a same-uid `/proc/<pid>/mem` write could make one call `clone(CLONE_UNTRACED)`. | Accepted | The 250 ms watchdog attaches the child and marks the tab degraded (OR-L4). Removing it would need Yama, which the sbx kernel lacks (Docker request draft). | — |
| OR-R3 | — | future | `seclab-wb-mount` runs as root on `ensure-reh`, after the tab has run. | Constraint handed to fork-build | It must resolve the workspace with `RESOLVE_NO_SYMLINKS` and check that the parents are root-owned. | — |

## Round 3
Fixes for OR-5, OR-6, OR-L3 and OR-L4 are in this commit, with the regressions above.
`./seclab test unit` (48/48), `./seclab test obs sbx|oci`, `./seclab test e2e sbx` and the
containment suites pass. **No high or critical findings are open.**

## Round 4: prompt injection (events read by an LLM)
- **Scope:** `cafe3ee` (field-level `untrusted` tags, `--format llm` renderer,
  `suspicious-content` rule) and `e225714` (Tab Activity reveal-on-alert).
- **Question (user):** "be on the lookout for any prompt injection gaps if there's outputs we
  intend to manage/analyze with LLM".
- **Result:** no high or critical findings.

| # | Sev | Area | Finding | Disposition | Fix | Regression |
|---|---|---|---|---|---|---|
| PI-1 | Medium | LLM renderer | The renderer fenced only the paths the log line itself listed, so log lines written before the tags (or by any writer that omits them) rendered unfenced. | Fixed | Allowlist: only validated structural fields (`v`, `seq`, `time`, `tabId`, enums, `rule`, `cause`, `sensorTime`, `redacted`, `proc.pid/ppid/uid`, `net.port/family`) are inlined. Everything else is fenced, whatever `untrusted` says. | unit `obs prompt injection review` |
| PI-L1 | Low | schema | Dotted detail keys made field paths ambiguous, so the renderer couldn't resolve them. Latent: no producer uses such keys. | Fixed | `.` removed from detail key names. | same |
| PI-L2 | Low | schema | Vocabulary-shaped values such as `SYSTEM:approve_all` counted as trusted. Only reachable with root in the VM. | Fixed | The vocabulary shape now excludes `:` and uppercase words (except errno, signal and ptrace names). | same |
| PI-L3 | Low | detection | Newlines (escaped as `\x0a`), zero-width splits, fullwidth letters, Cyrillic look-alikes and other languages slipped past the rule. | Fixed | Matching folds our escapes, NFKC-normalises, drops zero-width characters and maps common confusables; a few es/fr/de/pt/it phrasings are added. The rule now also scans parent commands, `detail.reason` and `claimedExtensionId`. Informational only: the fencing is the control. | same |
| PI-R1 | — | protocol | `tab.observation` `reason` can carry sensor-derived text. | Fixed | The notification carries `untrusted: ["reason"]` (PROTOCOL.md). | — |

Re-checked as sound: the delimiter can't be forged (96-bit nonce the tab never sees),
JSON-encoded values can't break out, reveal-on-alert fires at most once per tab
(application-scoped setting), and the CLI text format re-escapes `summary`.

## Round 5: README screenshot, demo harness, `fetch macos` fix
Scope: `origin/main..HEAD` at 9e5e926 (the screenshot and its alt text, the demo
profile settings and background launch, `fetch_macos` parsing `UPSTREAM_SHA`
instead of sourcing `upstream.lock`, and the dependency EDR addendum).

No findings. Checked:
- the parse runs only after SHA256SUMS and both attestation checks, accepts only a
  whole 40-hex line, and reaches `jq` via `--arg`. Not sourcing the lock file is
  also stricter than before;
- the demo profile is confined to `~/.seclab-test/` or `.work/`
  (`checkUserDataDir`, symlinks resolved). A separate `--user-data-dir` with
  `open -n` gives a separate instance, so nothing is handed off to the user's own
  editor;
- the screenshot holds demo data only: an RFC 5737 beacon, a seeded honeypot path,
  the worktree path, no tokens;
- the addendum's cosign, Falco and Debian pins match `falco.lock`, `seclab`,
  `tabd/src/obs/falco.ts` and the register.

Gitleaks over the diff: no leaks.

## Round 6: loader fixture defang (a5135fb)
Scope: the loader fixture moved to parts on the host, assembled in memory and written
inside the tab (`test/observability/loader.ts`, `run.ts`, `demo.ts`, EDR
observability-loader-in-tab). No vulnerabilities. Checked:
- No assembled content reaches a host file. Under OCI, `$HOME` is a per-tab named
  volume and only the workspace is bind-mounted. Under sbx, `ensureRunning` requires
  the overlay, and held files are copied only on a user decision.
- The piped bytes are never logged.
- The arming contract matches the old checks one for one.
- The parts charset blocks shell breakout.

| ID | Sev | Area | Finding | Status | Fix |
|---|---|---|---|---|---|
| LD-1 | Info | EDR | Overstated the post-write `.vscode` check as the guard; the real guard is `ensureRunning`'s overlay requirement. | Fixed | EDR reworded. |
| LD-2 | Info | EDR | Didn't mention that a run's event log records the loader's argv and honeypot paths (by design). | Fixed | EDR Consequences. |

The endpoint protection's threat list before and after: no new detection.

## Round 7: broker audit events in the stream (EDR broker-audit-in-tab-events)
Scope: `tabd/src/obs/broker-audit.ts`, the hub's broker buckets, `rule` vocabulary,
supervisor wiring, tests. Four passes (7, 7b, 7c, 7d).

| ID | Sev | Area | Finding | Status | Fix |
|---|---|---|---|---|---|
| BA-1 | Medium | rate | Cheap denials shared the tab-driven bucket with critical findings (sentinel misplaced, blocked token), so a tab could push findings out. | Fixed | See the passes below. |
| BA-1b | Medium | rate | (7b) A single cheap finding type (`sentinel.misplaced` via WebSocket frames) could drain the shared finding bucket. | Fixed | Findings aggregated on (type, host, port, credential, hook). |
| BA-1c | Medium | aggregation | (7c) Tab-chosen methods minted aggregation keys. Once a type's key pool was full, events were only counted and their destination was lost. | Fixed | Keys use broker-determined fields only. A full pool emits the event on its own. |
| BA-1d | Medium | rate | (7c) A flood of cheap `model.denied` events drained the shared bucket for every other broker event. | Fixed | One bucket per broker audit type. The model, token and session types are aggregated. |
| BA-2 | Low | tagging | `rule` counted as vocabulary, but an `allow-tab` rule is named by the host the tab chose. | Fixed | `rule` is always tagged untrusted. |
| BA-L1 | Low | EDR | Unlisted types, the broker's `untrusted` list and flood claims were described inaccurately. | Fixed | Unlisted types now carry only type and seq. EDR corrected. |

How the fixes fit together:
- Every broker audit type has its own bucket: findings 20/s with a burst of 200, others
  100/s with a burst of 1000. Broker events share no bucket with any other source.
- Each type has a pool of 64 aggregation keys (1024 overall).
- Drop reports name the type and give the dropped broker seq range.

Also hardened (7, questions): broker restart is detected by seq too, and an attach
generation stops a stale replay from draining into a newer attach.

7d found no issues. It accepted the residual: a flood of distinct broker-determined keys of
one type can drop other events of that same type, and the drop is reported with its type
and seq range.

Regression tests (`tabd/test/obs.test.ts`), "broker audit review" × 2:
- method variants collapse into one key;
- a 6000-denial flood plus a sentinel flood leave another credential's finding, a new
  destination and `policy.updated` intact;
- the per-type drop is reported with its seq range;
- `rule` is tagged;
- restart is detected by seq;
- a stale replay is ignored.

`tabd/test/broker-supervisor.test.ts` "broker audit" covers replay, dedupe, gap
reporting, the foreign-tab drop and tagging.

### Round 7e: broker endpoint and beacons through the broker
Scope:
- the `brokerEndpoint` sensor hook (sbx port from the host, OCI address from
  `docker inspect`);
- broker connects are no longer flagged as `egress.bypass` (every proxied request had
  been);
- broker per-destination timing feeds the beacon rule before aggregation.

| ID | Sev | Area | Finding | Status | Fix |
|---|---|---|---|---|---|
| BA-3 | Low | detection | Sensor and broker beacon state shared one map, and a VM-root collector could forge `net.addr` text to collide with a broker key. Mostly `tab-vm-root` evidence could then fire a `trusted` beacon, or suppress one. | Fixed | Broker timings get their own map. Regression test added. |
| BA-L2 | Low | rate | Beacon detections from broker timing bypassed the hub's buckets. | Fixed | Rate-limited like findings (`#broker-beacon`). |
| BA-L3 | Info | robustness | `docker inspect` printing `null` would have thrown in the OCI start path. | Fixed | `?? {}`. |
| BA-L4 | Info | EDR | Overstated `trusted` for the beacon cause; left out that sbx endpoint addresses are `tab-vm-root` data and that allowed destinations aren't timed. | Fixed | EDR decision 6. |

Accepted: under sbx, VM root can poison `brokerAddrs` (`/etc/hosts`, forged hello) and so
hide bypass detection to that address. That gives root nothing new: the whole collector
stream is `tab-vm-root`, and sbx's network policy, not detection, is what blocks egress.

## Round 8: process lineage for broker requests (EDR broker-request-lineage)
Scope:
- `tabd/src/obs/lineage.ts`: a time join of broker requests to sensor connects, and
  `promptLineage`;
- strace: deferral of connects from new threads, and `socket()` traced to set
  `net.proto`;
- Falco `fd.l4proto`;
- the resolver exemption.

Two passes (8, 8b).

| ID | Sev | Area | Finding | Status | Fix |
|---|---|---|---|---|---|
| LN-1 | Medium | integrity | A `none` attribution ("no process observed") was labelled `trusted`, though the tab can cause it with a kept-alive connection or a dropped line. | Fixed | Never `trusted`: it takes the tab's sensor level, and the event the weakest of both. |
| LN-2 | Low | accuracy | `single` and "never someone else" overstated the join: a kept-alive request can be pinned on whoever connects next. | Fixed | Semantics stated as "one unused connect in the window". EDR, comments and tests corrected. |
| LN-3 | Low | API | The `promptLineage` cache was global (one tab could evict another's entries), and computed results looked recorded. | Fixed | Per-tab maps, cleared on remove. Computed results are marked `computed`. |
| LN-L1 | Info | EDR | DNS tunnelling blind spot, the deferral bound, "not known to be UDP", stale fd labels. | Fixed | EDR Consequences. |

8b found no issues.

## Round 9: agent events and the `tab-reported` label (ADR agent-events-tab-reported)
Scope:
- the `tab-reported` integrity label;
- client sources `ahp-gate`, `ahp-reverse`, `ahp-credential` (trusted) and `agent-host`
  (tab-reported), with integrity now taken from the source table;
- `ahp` and `agent` rate buckets;
- the `ahp.ungated` and `ahp.deny-burst` detections, and the suspicious-content scan of
  tool and method names;
- the UI and CLI badges.

Two passes (9, 9b).

| ID | Sev | Area | Finding | Status | Fix |
|---|---|---|---|---|---|
| AE-1 | Medium | detection | A tab could provoke enough gate denials to drain the shared `ahp` bucket, dropping `ahp-gate.opened`/`verified` (a missed or a false `ahp.ungated`). The timer's detection also went through the tab-floodable sensor bucket. | Fixed | See below. |
| AE-L1 | Info | robustness | One global cap on connections awaiting verification. | Fixed | Per tab: 64 each, 1024 overall. |

AE-1 fix:
- the connection watch runs on the validated report, before rate limiting;
- opened/verified reports have their own `ahpLife` bucket;
- `ahp.ungated` is stamped directly, outside every bucket (`hub.detection`);
- an unwatchable connection is reported at once (fail closed);
- the watch state is cleared on tab removal.

Regression test: after 2560 gate denials, opened connection 3 is flagged, and connection
4 (opened, then verified) is not.

Checked as sound: `agent-host` can't reach a trusted event or detection. Its integrity
comes from the source table, its classes are pinned, the watch requires source `ahp-gate`,
and the deny burst counts only trusted events. The `rpc-filter` path is unchanged.

## Round 10: detection notifications and the cross-tab summary (ADR detection-notifications)
Scope:
- `tabd/src/obs/notify.ts`: notify policy, trusted templates, `quote()`, coalescing and
  rate limits;
- Tab Manager notifications and the Detections view;
- `tab.detections.query` and `tab.egress.block`, with broker capabilities;
- the e2e harness, and the teardown network fix.

Two passes (10, 10b).

| ID | Sev | Area | Finding | Status | Fix |
|---|---|---|---|---|---|
| NT-1 | Low | suppression | The per-minute budget was first come, first served. A tab could spend it on three cheap detections, then blind its sensor, so "tab unobserved" was only a count in a later summary. | Fixed | The trusted-only kinds (unobserved, fence failure, quarantine, broker loss) skip the budget; per-tab coalescing still bounds them. The overflow summary names the kinds it held back. Regression test. |
| NT-L1 | Info | wording | The Block success message overstated a port-specific block. | Fixed | Says "on that port". |

Checked as sound:
- Every tab-influenced string in a message goes through `quote()`: file, destination,
  chain, origin label, and the tab name from tabd's record. Brackets are removed from
  each quoted part and the templates contain none, so no markdown link can form across
  parts.
- Notifications fire only for the window's own subscription, never on replay.
- `tab-reported` events and unknown rules never notify, and no `seclab.*` command is
  reachable from a tab (unit test against the RPC filter policy).
- Block is limited to broker events and validated. The deny rule only narrows policy.
- The query is bounded and reads only store tab ids, `O_NOFOLLOW`, and the event's own
  tab.
- The e2e is inert and AV-safe, and tears down on every path.
- The screenshot shows demo content only.

## Accepted residuals (documented in the ADR)
- `tab-vm-root` events are forgeable by root inside the tab VM. The collector's heartbeats are `tab-vm-root` evidence, not proof. Never base a decision on them alone.
- Under OCI the privileged Falco sees every container on the Docker host. Only rules for the exact tab container ids are loaded, and its only output is stdout to tabd.
