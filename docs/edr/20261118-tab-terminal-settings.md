# Tab windows send their tab no host terminal settings, and take no tab profile into host settings

- **Date:** 2026-11-18
- **Status:** accepted. Runtime proof: see below.
- **Owner:** the RPC follow-ups session (register owner `rpc`).
- **Related:** [no host variables for tab terminals](20261116-reh-push-refusals.md) (patch 0034),
  [no host terminal in tabs](../adr/20261116-no-host-terminal-in-tabs.md) (0050),
  [configuration snapshot](20261112-tab-configuration-snapshot.md) (0036),
  [review record](../security-reviews/20261118-tab-terminal-settings.md),
  [RPC lockdown](../RPC-LOCKDOWN.md).

## Context
Document sync handed the RPC follow-ups a sibling of its own push controls (DOCSYNC-R5): the window
still pushed the terminal default profile and environment variable collections to a tab's extension
host. Two findings from patch 0034's review sat on the same code: the window sent the host user's
terminal env, cwd and profile settings to the tab's REH (RFU1R-2) and the automation profile to its
extension host (RFU1R2-1), and named a host file as the active file (RFU1R-3).

All of `terminal.integrated.env.<os>`, `cwd`, `profiles.<os>`, `defaultProfile.<os>`,
`automationProfile.<os>` and `agentHostProfile.<os>` are registered `restricted`, so patch 0036
never lets a host value of theirs reach the tab's extension host. The terminal code read them with
`getValue`, which merges the host user's layers in, and sent them on by other paths.

Twelve review rounds of the fix (an Opus-class model) widened it: a tab's REH chooses the profiles a
tab window shows, so their names, paths and icons are tab data, and upstream let them into a host
settings write (R5-14, a high on main), a CSS `url()` the window fetches (R5-9) and markdown the
Settings editor renders (R5-15). The terminal hover rendered the title and command line the tab's
shell sets as markdown (R5-18, also a high on main).

## Decision
In a `seclab+` window (patches 0053-0058):
- **0053:** every one of those settings comes from the layers the tab owns: the defaults, the REH's
  remote user settings, and the workspace's only when the workspace is the tab's own (0036's test).
  Upstream's recursive merge is kept. That holds for `createProcess`, `getProfiles`, the default
  profile's name (which picks among the names the REH returns), and the automation and agent-host
  profiles in `$acceptDefaultProfile`. The window's own extension host is sent no default profile.
  The resolver reads the window's authority from the environment, not the connection. A new
  terminal's cwd for a tab folder and the process switches (shell integration, suggest, ConPTY,
  locale, `inheritEnv`) come from the same layers. The helper returns a fresh copy, so a caller that
  edits it never edits a configuration model. A tab window is any authority matching the filter module's
  `seclab+` test, in any case, and every inlined copy of that test is pinned to the filter's.
- **0054:** each extension host gets only the environment variable collections it set itself. A tab
  can't replace or delete another host's collection; the window's own host can.
- **0055:** the REH learns only the tab's own folders, active folder and active file. A workspace
  that isn't the tab's own gets a workspace id derived from the tab, and a detach request naming
  another window's workspace never reaches the REH.
- **0056:** a terminal image icon is kept only on the tab's own file system; else a codicon.
- **0057:** choosing or saving a terminal profile writes the tab's own (remote) settings, never the
  host user's, and extends only the tab's own profiles. So does an extension's contributed profile,
  and allowing a link scheme, which goes to the tab's workspace settings when they set the list.
  A terminal link's scheme is checked against the tab's own list.
- **0058 (every window):** terminal profile descriptions in Settings are escaped text with a codicon.
  In tab windows the terminal hover's title, command line and status tooltips are escaped too.

A single helper, `contrib/terminal/common/seclabTabTerminalSettings.ts`, holds the layer rule; it
is dependency-free because the channel file is in the REH bundle too. 0053 is larger than the
patch-size guideline (about 130 changed lines) because it adds that helper and passes the
environment service into both resolver subclasses; the alternative, a choke point in the
configuration service, would change every setting in tab windows.

Measured before fixing, on main's containment build: no shipped built-in sets an environment
collection from the window's local extension host, so the collection push carried only the tab's
own data. 0054 closes the path for any future host-side setter and is shown at unit level.

## Known losses in tab windows
- Terminal profiles, env, cwd, the default and automation profiles set in the host user's settings
  don't apply in tabs; the tab's own settings (the REH's or the workspace's) do.
- Terminal icons are codicons, or images on the tab's own file system.
- "Select Default Profile" in a tab sets that tab's default, not the host's.

## Proof
- **Unit:** `test/containment/terminal-settings.test.ts` (`./seclab test terminal-settings`, in
  `./seclab test rpc-filter`) runs upstream's own methods, sliced from the pinned checkout with the
  series applied: the baseline (without 0053-0058) opens every leak path the test knows, the patched
  build none, a non-tab window is unchanged apart from 0058's escaping, and every mutant of the
  patches is caught by the leak it reopens.
- **Runtime:** `test/containment/reh-push.ts` in a real OCI tab of the containment build, with
  host-settings canaries. Two probes: `reh-terminal-host-settings` (what the window sends the REH)
  and `reh-exthost-terminal-profile` (the rogue REH scans its extension host's memory; the control
  canary rides in the REH's own default profile). A step drives "Terminal: Select Default Profile"
  and reads where the choice was written.
  - Baseline: main `3633e20d`, containment build run 44455956648, judging both probes:
    10/10 and 14/14. The host terminal env and profiles reached the REH, the host automation
    profile was in the extension host's memory, and the picked REH profile was written to the host
    user's settings (R5-14).
  - Patched: branch `6fadc8f7`, run 44457923287, every registered REH probe judged: 30/30 and
    14/14. Neither probe found a host canary, the control canary was found, and the picked profile
    went to the tab's own settings. Both runs tore down clean.
  - Re-run on the same build with the scan counting what it couldn't read (PR #70 review): 30/30
    and 14/14, 0 unread regions of 435 MB, clean teardown. A patched judgement now needs every
    writable region read.
  - The commits after `6fadc8f7` change only the tab test's case handling, the contributed
    profile's base, the helper's copy, where `inheritEnv` is read and the tests, each shown by the unit suite.

## Consequences
- Terminal auto replies, found by rounds 9 and 10 (R5-31, R5-32, a high on main), are closed by
  patch 0061, which landed first ([EDR](20261119-tab-auto-replies.md)).
- RPC-LOCKDOWN's "still open" list loses the terminal default profile and environment collections.
- Residual: the unfiltered `mergedCollection` still has consumers outside tabs' reach today
  (the local agent host, removed by 0013, and local terminal revival, unused in tab windows since
  0050).
