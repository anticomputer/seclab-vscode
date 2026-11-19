# A tab window installs no terminal auto reply on the shared local pty host

- **Date:** 2026-11-19
- **Status:** accepted. Runtime proof: see below.
- **Owner:** the RPC follow-ups session (register owner `rpc`).
- **Related:** [review record](../security-reviews/20261119-tab-auto-replies.md),
  [no host terminal in tabs](../adr/20261116-no-host-terminal-in-tabs.md) (0050),
  [RPC lockdown](../RPC-LOCKDOWN.md).

## Context
`terminal.integrated.autoReplies` maps text a terminal prints to text the terminal is sent back, a
carriage return included. Upstream's `TerminalAutoRepliesContribution` reads it from the window's
settings and installs every pair on every terminal backend the window registered. Every window
registers the local backend, a tab window included, and the local pty host behind it is one per
app: it applies each pair to every terminal it runs, in every window, now and later.

A tab window's settings include the remote user settings its tab's server serves, and the
setting is window-scoped, so a tab could name a pair. A tab window then installed it on the local
pty host, where it typed into normal windows' local terminals: once a user's shell printed the
match, the reply ran as a command in it (review R5-32, found by the terminal-settings review, a
high on main). Patch 0050 stops a tab window starting a local terminal, but not this call.

## Decision
Patch 0061, in a `seclab+` window:
- the local backend's `installAutoReply` installs nothing, whoever calls it (R5-32);
- the tab's own backend installs a pair only if the tab's own settings hold it: the defaults, the
  tab's remote user settings and the tab folder's settings, 0060's rule. The host user's pairs
  went to the tab's server before, though the setting is restricted and patch 0036 withholds it
  from the tab's extension host (AR-5, the terminal-settings review's R5-31, a medium on main).

The tab's own terminals keep the tab's replies. Outside tab windows nothing changes. The gate sits in the local
backend rather than the contribution because the backend already holds the window's environment
service, and upstream's tests construct the contribution with its three arguments, so a new
dependency there would not compile.

A sweep of every other path from a tab window to the local backend found none that carries tab
data (layout, titles, icons, detach and persistence go to the tab's own backend; revival, profile
detection and process creation are behind 0050 or the window's own authority).

## Proof
- **Unit:** `test/containment/auto-replies.test.ts` (`./seclab test auto-replies`, in
  `./seclab test rpc-filter`) runs upstream's `_installListenersOnBackend` against a local backend
  running the tree's `LocalTerminalBackend.installAutoReply` (series applied) and the tab's own
  backend, at start and on a settings change. On
  main the case "a tab window installs no auto reply on the shared local pty host" fails, with
  the reply installed on the local pty host; with 0061 it passes, a window that isn't a tab is
  unchanged, and every mutant of 0061 is caught.
- **Runtime:** `test/containment/auto-reply-probe.ts` in a real OCI tab of the containment build.
  As the tab, the run writes one pair (`seclabcanary` strings with the run's nonce, no newline)
  into the REH's remote user settings. The tab's own terminal must answer it (control). The tab
  window then opens a normal window in the same app, whose local terminal runs `/bin/cat`, never a
  shell; a host-user pair must answer there (control), and the probe checks whether the tab's
  reply appears. Only booleans are recorded, and no `cat` may outlive the run.
  - The tab's own terminal also echoes the host user's match: the host's reply must not come
    back from the tab's server.
  - Baseline: main `3633e20d`, containment build run 44455956648: 13/13. The tab's reply was
    typed into the normal window's local terminal, and the host user's reply came back in the
    tab's terminal.
  - Patched: branch `feaca0b1`, containment build run 44471495981: 13/13. Both controls answered,
    the tab's reply never reached the normal window's terminal, and the host user's never came
    back from the tab's server. Both runs tore down clean, with no `cat` left. The commits after
    `feaca0b1` change only the unit test and the records.

## Consequences
- Auto replies a tab sets apply in that tab's own terminals only, and the host user's auto replies
  don't apply in a tab's terminals.
- The local backend in a tab window still receives argument-free calls (performance marks,
  readiness) and the window's own uninstall, which removes only that window's replies.
