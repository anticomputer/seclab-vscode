# Every tab test in the patch series agrees with the RPC filter's, in any case

- **Date:** 2026-11-19
- **Status:** accepted.
- **Owner:** the RPC follow-ups session (register owner `rpc`).
- **Related:** [host search excludes](20261118-host-search-excludes.md) (review SRCH3-14, which
  this closes), [review record](../security-reviews/20261119-tab-authority-case.md),
  [RPC lockdown](../RPC-LOCKDOWN.md).

## Context
A window is a tab window when its remote authority is `seclab+<tab>`. The RPC filter module's test,
`seclabIsTabAuthority`, is `/^seclab\+/i`, case-insensitive since patch 0060's round 4. Seven other
tests in the series compared case-sensitively (0006's channel-guard context, 0015's gate and its
transport identity, 0017's fixed settings, 0018's chat sessions, 0035's document sync twice, 0036's
configuration snapshot), and 0050's menu gates compared the remote name to `seclab`. A mixed-case
authority would have been a tab to the filter and not to them. Nothing lets a tab choose its
window's authority, so this was a consistency gap, not a reachable escape.

## Decision
- Workbench files (0035, 0036) call the filter module's `seclabIsTabAuthority`.
- Base and platform files (0006's `ipc.ts`, 0015, 0017, 0018), which cannot import the workbench,
  compare the lower-cased authority with the `seclab+` prefix. For the ASCII prefix this agrees
  with the filter's `/i` test.
- 0050's menu and keybinding gates use `ContextKeyExpr.regex(RemoteNameContext.key, /^seclab$/i)`,
  negated.
- `test/containment/filter-module.test.ts` checks every patch in `patches/series`: an added line that
  tests the authority or remote name case-sensitively fails the suite, unless a later patch in the
  series removes that line from the same file (0034's, which 0053 rewrites). It reads each line
  for `seclab` regex literals (anchored and case-insensitive only), `seclab+`/`seclab` strings and
  the constants a file declares to hold them (compared only by a lower-cased `startsWith`, or a
  `startsWith` on a variable the file lower-cased), and allows building, slicing and logging.

## Proof
- **Unit:** the series-wide guard, and mixed-case cases in the channel-guard, host-terminal and
  agentic gate suites; each fails on main's patches and passes here. 0006's tab test is evaluated
  from the shipped patch, not a copy.
- **Build:** the changed files typecheck with the whole series applied.
- **Runtime:** `test/containment/reh-push.ts patched` on the branch's containment build (run
  44506121908, `efc90fce`): 30/30 and 14/14, with 0015's gate logging its refusal of the tab's
  agent-host transport and the control window dialling; clean teardown. Lower-case authorities
  behave as before; nothing lets a tab choose a mixed-case one to test at runtime.

## Consequences
- A new tab test in a patch must be case-insensitive, or the rpc-filter suite fails, for the
  shapes the guard reads. It reads one line at a time: a call and its argument on different lines,
  object keys and computed comparisons are beyond it, and review still covers those.
- Outside the series, the Tab Manager (`extensions/seclab-tab-manager`) tests the authority
  case-sensitively on purpose: its resolver refuses any authority but `seclab+<tab id>` in lower
  case, so a mixed-case window never connects, and its status bar and current-tab lookup only ever
  see the authorities it resolved.
