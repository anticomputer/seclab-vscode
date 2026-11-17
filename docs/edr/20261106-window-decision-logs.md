# Window decision logs: AHP gate and RPC filter decisions into tabd

- **Status:** accepted
- **Date:** 2026-11-06
- **Deciders:** project owner (forward RPC-filter and AHP-gate decisions to tabd, 2026-11-06); coordinator (scope); RPC channel lockdown session (`seclabRpcFilter.log` shape and its trust dependencies); tab-observability session
- **Related:** [ADR tab observability](../adr/20261104-tab-observability.md), [ADR agent events](../adr/20261105-agent-events-tab-reported.md), [ADR RPC filter enforcement points](../adr/20261104-rpc-filter-enforcement-points.md), patch 0015 (`seclabAhpGate.log`), [security review](../security-reviews/20261104-tab-observability.md) round 12

## Context
`tab.events.report` was designed for the trusted client to report RPC-filter and AHP-gate
decisions over a `MainThreadSeclab*` service. That service was never built. Patch 0015
writes the gate's decisions to a per-window log, `seclabAhpGate.log`, through
`ILoggerService`, one JSON object per line in the report shape. The RPC session found
that the filter's decision stream (`seclabOnDecision`) had no consumer at all, and is
adding the same kind of log, `seclabRpcFilter.log`. So no filter or gate decision
reached the stream, Tab Activity or the detections.

## Decision
1. **The Tab Manager tails its own window's logs** (`tabd/src/obs/windowlog.ts`,
   bundled into the extension) and reports each line with `tab.events.report`.
   - The window's log folder is two levels above the extension's `logUri`
     (`<windowLogsPath>/exthost/<id>`). If that layout ever changes, it warns and
     forwards nothing, rather than guessing.
   - The tab id is the window's own `seclab+<tab>` authority, never a field of a line.
     The lines carry no tab id.
   - **Only this window session's lines** (review round 14). A window keeps its log folder
     when it is reused for another workspace, so one log can hold several tabs' lines. Each
     renderer installs the filter once and writes `rpc:seclab.installed` first, so the
     latest install line starts the current session. The forwarder starts the RPC log there
     and drops RPC lines stamped (by the logger, on the host) before it. The gate logs from
     the same renderer slightly earlier (it is asked at startup, before the filter installs:
     0.2 s in the real run), so gate lines get 3 s of grace before the install line, but
     never reach back to the previous session's last RPC-filter line. Until an install line
     exists, nothing is forwarded. A resume position is used only when it lies after the
     install line in the same file.
     - **Residual:** on a reused window, gate lines the previous tab wrote after its own last
       RPC line and within 3 s of the new tab's install line would be credited to the new
       tab. A gate install line, asked of the gate's owner, would remove the grace.
2. **Line shape (agreed with the RPC session):**
   ```json
   {"source":"rpc-filter","class":"rpc.decision","priority":"warning","summary":"deny rpc","detail":{"surface":"rpc","ref":"rpc:MainThreadTerminalService.$createTerminal","verdict":"deny","reason":"policy","claimedExtensionId":"evil.ext"}}
   ```
   - `detail` is the filter's `SeclabDecision` minus `tabId` and `at`. `summary` is fixed
     text; `ref`, `reason` and `claimedExtensionId` are tab-chosen and tagged untrusted.
   - `priority` is `warning` for deny and prompt, `notice` for rewrite, `informational`
     for allows. The filter collapses repeats of one (surface, id, verdict) within 10 s,
     denials included, into a follow-up line with `count`.
   - The landed writer (patch 0005, `cc51fa7d`) bounds `ref` to 256 characters and
     `reason` to 512 before serialising, and a line to 4096; a line still over budget is
     written without its free text, never cut. Its byte budget is 512 KiB per rolling
     60 s window, refilled each window; a suppressed run is summarised as one
     `rpc:seclab.log-throttled` deny with its `count`. The gate caps at 2000 decisions per
     connection.
3. **Each file may carry only its own sources:** `seclabAhpGate.log` carries `ahp-gate`,
   `ahp-reverse` and `ahp-credential`; `seclabRpcFilter.log` carries `rpc-filter`. tabd
   then pins each source's classes and sets integrity from the source (`trusted`).
4. **Lines are still parsed as hostile.** Only the prefix-stripped JSON object, at most
   8 KiB, with five fields and flat scalar detail is forwarded. Malformed and oversized
   lines are counted in the Tab Manager log, not forwarded. Symlinks are not followed.
5. **Nothing is buffered in memory beyond one read.** The tailer reads at most 256 KiB a
   round and stops reading while a batch is undelivered, so the files on disk (bounded by
   the logger's rotation) are the buffer. When tabd is unavailable, batches are retried, not
   dropped. Each round handles at most four batches of 64 per file, gate log first, every
   500 ms, so a flood of filter denials can't delay the gate's `opened`/`verified` pair past
   tabd's 2 s `ahp.ungated` window (review round 12).
   - **Rotation:** spdlog rotates by rename (`a.log` → `a.1.log` → …). The tailer reads
     its open file to the end, then opens the file one index below it, found by inode, so
     no rotated file is skipped however far behind it is. If its file has rotated off the
     end, lines may be lost: it reports the file's trusted skipped marker
     (`rpc:seclab.log-skipped` or `ahp-gate.log-skipped`, verdict deny) and goes on from
     the oldest file left.
   - **Resume:** the delivered position (inode and offset, current or rotated file) is kept
     in workspace state, so a reloaded window doesn't report the same lines again.
6. **A ref that fails tabd's pattern no longer rejects the event.** tabd used to reject
   any report whose `ref` wasn't printable ASCII. A tab could then hide a denial behind a
   command id with a space or non-ASCII character, out of the stream and the burst count.
   Such a ref now lands as escaped `detail.refText`, and `ref` stays exact or absent. The
   `data:` surface is accepted too.
7. **New detection `rpc.deny-burst`:** 20 or more trusted filter denials (or prompts,
   which fail closed until they are wired) from one tab within 60 s, each line weighted by
   its `count` (at most 1000), so probing one method hard still counts (review round 14).
   Reported at most once per 10 minutes. It notifies like `ahp.deny-burst`.

## Why the label is `trusted`
The logs are written by the main process on the host. A tab could forge a line only by:
- calling `MainThreadLogger.*` (`$log` writes to any existing logger by URI). All six
  methods are denied by the RPC filter, and the service default is deny, so a new upstream
  method is denied until it is classified;
- writing a `file:` path in the window log folder. `MainThreadFileSystem.$writeFile` is
  limited to the tab's own `vscode-remote://seclab+<tab>` URIs, `untitled:` and its
  extensions' read-only resources; `$mkdir`, `$copy` and `$rename` are denied.

The RPC session gates both facts in CI (`check_log_trust` in `rpc-filter/tools/check.sh`).
On `cc51fa7d` that check is narrower than "fails if either weakens" (review round 14). It
accepts any `allow_with_constraint` on `$writeFile`, and couldn't do better as written: the
constraint is free text, so the check had no machine-readable handle on whether the URI rule
applies. It also didn't pin `$delete` (deleting the log would stop forwarding: silence, not
forgery) or other host-file writers such as `$tryApplyWorkspaceEdit` and `$trySaveDocument`,
and it skipped a method missing from the policy instead of failing. All are denied or
URI-constrained in the landed policy today. The RPC session's fix, on main as
[`96156496`](https://github.com/anticomputer/seclab-vscode/commit/96156496a2783d89d59f8d79135d469f329df924)
(recorded in [`20261116-log-trust-gate`](../security-reviews/20261116-log-trust-gate.md), LT-1
to LT-4), checks the generated positional URI table for `$writeFile`, pins the others to
`deny`, and fails on absence.

**Merge order is enforced in code** (review round 12, HIGH before this fix). Before the
filter ships, a tab can reach `MainThreadLogger.$log`, and its init data names the logger
URIs. The Tab Manager forwards nothing, with a warning in its log, unless both of these hold:
- its own `<appRoot>/product.json` has `seclabRpcPolicy.sha256`. The build stamps it after
  patching, if and only if 0005 is in `patches/series`
  ([EDR rpc-policy-stamp](20261106-rpc-policy-stamp.md)). The stamp proves only that the
  policy table was applied, so the log calls it "RPC policy table applied", never "filter
  active";
- the built workbench bundle (`out/vs/workbench/workbench.desktop.main.js`) contains
  `seclabRpcFilterEnforcing:<that sha256>`. The marker is a literal in `seclabRpcFilter.ts`
  (patch 0005, the same patch as the filter and its log), and the filter names it in the
  log's first line (`rpc:seclab.installed`), so tree-shaking can't drop it. A series with
  0005 but without the enforcing code therefore forwards nothing.

Together these establish **policy table applied and enforcement code present**; that the
filter is attached to every RPC protocol rests on the RPC session's runtime proof, run
before the core landed (`cc51fa7d`). `check-release` also requires every marker in a
release artefact to name the stamped table.

The bundle is scanned once per window, off the activation path.

## Alternatives considered
- **A `MainThreadSeclab*` service from the renderer to the Tab Manager**, as first
  designed: more patch surface for the same data. The logs already exist for tests and
  for investigators.
- **tabd reads the logs itself:** tabd doesn't know which window belongs to which tab, and
  a window's logs folder is the editor's business.
- **Forward the logger's timestamp:** tabd stamps arrival time, as for every report. Lines
  arrive within a second; after a tabd outage they are late, and the stream's order still
  holds.

## Consequences
- Filter and gate denials appear in Tab Activity (the refused request shown quoted), feed
  `ahp.ungated`, `ahp.deny-burst` and `rpc.deny-burst`, and are kept in the per-tab log.
- Lines written while a window has no tab connection wait in the file and go out once
  it has one.
- A build without the filter forwards nothing; filter and gate decisions then stay in the
  window logs only.

## Evidence on record
- **`fixture:test/observability/rpc-prober`:** `node test/observability/window-log-probe.ts
  --app .work/app-branch/seclab-vscode.app`, branch build 43953524461 (`688f15b`, on main
  with the RPC core: stamp `seclabRpcPolicy.sha256` c4d64e51…, the matching enforcing
  marker, and this forwarder with the review round 14 fixes), sbx, headless driver,
  2026-11-16. In each variant the prober ran in the tab and the RPC filter refused its call;
  the window's `seclabRpcFilter.log` had the install line and the denial, and
  `seclabAhpGate.log` had one gate decision, written before the filter's install line.
  - **Unmodified build:** all 41 lines (40 RPC filter, 1 AHP gate) reached tabd as trusted
    `rpc.decision` / `ahp.decision` events, the probed command's `ref` tagged untrusted.
  - **A copy without the product stamp:** tabd got none of the 60 lines; the Tab Manager
    logged "no RPC policy table applied in this build".
  - **A copy with the bundle's marker altered:** tabd got none; the Tab Manager logged "RPC
    policy table applied (c4d64e51691e), enforcement marker missing in this build".

  The editor ran background-only and never took focus; every variant's teardown was clean,
  and the altered copies were unregistered and deleted. Earlier runs on builds 43935119119
  and 43942841086 found the leftover copies (WL-6) and the dropped gate line (WL-7).
