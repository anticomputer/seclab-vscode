# Window decision logs: AHP gate and RPC filter decisions into tabd

- **Status:** accepted
- **Date:** 2026-11-06
- **Deciders:** user ("forward the RPC-filter and gate denial logs to tabd"); coordinator (scope); RPC channel lockdown session (`seclabRpcFilter.log` shape and its trust dependencies); tab-observability session
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
2. **Line shape (agreed with the RPC session):**
   ```json
   {"source":"rpc-filter","class":"rpc.decision","priority":"warning","summary":"deny rpc","detail":{"surface":"rpc","ref":"rpc:MainThreadTerminalService.$createTerminal","verdict":"deny","reason":"policy","claimedExtensionId":"evil.ext"}}
   ```
   - `detail` is the filter's `SeclabDecision` minus `tabId` and `at`. `summary` is fixed
     text; `ref`, `reason` and `claimedExtensionId` are tab-chosen and tagged untrusted.
   - `priority` is `warning` for deny and prompt, `notice` for rewrite, `informational`
     for aggregated allows (with `count`).
   - Lines are at most 4 KiB, with `ref` cut to 1 KiB. A window writes at most 2 MB of
     filter decisions (rpc-core `8be17a6`, counted in bytes written), then one
     `rpc:seclab.log-capped` deny, so the log fits one spdlog file (5 MB). The gate caps at
     2000 decisions per connection.
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
   which fail closed until they are wired) from one tab within 60 s, reported at most
   once per 10 minutes. It notifies like `ahp.deny-burst`.

## Why the label is `trusted`
The logs are written by the main process on the host. A tab could forge a line only by:
- calling `MainThreadLogger.*` (`$log` writes to any existing logger by URI). All six
  methods are denied by the RPC filter, and the service default is deny, so a new upstream
  method is denied until it is classified;
- writing a `file:` path in the window log folder. `MainThreadFileSystem.$writeFile` is
  limited to the tab's own `vscode-remote://seclab+<tab>` URIs, `untitled:` and its
  extensions' read-only resources; `$mkdir`, `$copy` and `$rename` are denied.

The RPC session gates both facts in its build (`check_log_trust`, rpc-core `889cbf7`), so
the build fails if either weakens.

**Merge order is enforced in code** (review round 12, HIGH before this fix). Before the
filter ships, a tab can reach `MainThreadLogger.$log`, and its init data names the logger
URIs. The Tab Manager forwards nothing, with a warning in its log, unless both of these hold:
- its own `<appRoot>/product.json` has `seclabRpcPolicy.sha256`. The build stamps it after
  patching, if and only if 0005 is in `patches/series`
  ([EDR rpc-policy-stamp](20261106-rpc-policy-stamp.md)). The stamp proves only that the
  policy table was applied, so the log calls it "RPC policy table applied", never "filter
  active";
- the built workbench bundle (`out/vs/workbench/workbench.desktop.main.js`) contains
  `seclabRpcFilterEnforcing:<that sha256>`. The marker is generated into `seclabRpcFilter.ts`
  (rpc-core `597b92c`, the same patch as the filter and its log), and `emit_policy.py --check`
  fails on drift. The filter names it in the log's first line (`rpc:seclab.installed`), so
  tree-shaking can't drop it. A series with 0005 but without the enforcing code therefore
  forwards nothing.

Together these establish **policy table applied and enforcement code present**, not
enforcement demonstrated. That the filter is attached to every RPC protocol is the RPC
session's runtime proof, which is not yet complete. Nothing yet checks in a release artefact
that the marker agrees with the stamp: that `check-release` assertion is owed by Fork-build.
Until it exists, this runtime check is the only one.

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
