# Server-initiated pushes refused in tab windows (0030, 0031), and 0011 retired

- **Date:** 2026-11-16
- **Status:** accepted. Proof passed, both halves (2026-11-16).
- **Owner:** the RPC follow-ups session (register owner `rpc`).
- **Supersedes in part:** the [handoff](20261106-rpc-core-handoff.md)'s statement that
  `0011-seclab-no-remote-agent-host-dialing` is still needed after 0015. That was true of the
  0015 of 2026-11-06; it isn't of the 0015 on main now (below).

## Decision

Patches 0030 and 0031 land; 0011 is retired.

- **0030** (`remoteTerminalBackend.ts`): in a `seclab+` window upstream's `onExecuteCommand`
  handler, which runs a command the REH names, is never registered.
- **0031** (`baseTerminalBackend.ts`): in a `seclab+` window upstream's resolver for pty-host
  variable requests, which resolves `${env:…}` over the host user's shell environment, is never
  registered. The local backend keeps it.

In both, a refusing handler takes the subscription's place. Decided by the project owner,
through the coordinator, 2026-11-16, with these conditions:
- it logs through the existing decision log (`seclabRefusePush`), so the same throttle, byte
  budget and untrusted-detail rules apply, and it logs only the policy key, a count and a fixed
  reason, never the command id or variable names;
- it answers at once (0030: an error; 0031: the text unresolved), so neither side waits;
- it never calls upstream's logic or touches a command service, resolver or environment;
- a structural check shows upstream's handler is unreachable in a tab window
  (`test/containment/push-refusal.test.ts`, each rule shown failing on a mutant of the real
  patch);
- the proof shows the tab's own terminal still works after the refusals.

The alternative, not subscribing at all (the held patches), left nothing observable: no
trusted-side denial for proof condition 2 and no evidence the patched code ran.

A refusal can arrive before the window's first extension host installs the decision log (the
pty host asks as soon as the backend exists), so the filter now holds up to 64 decisions until
the log installs, and counts any beyond that.

## 0011 is not needed: 0015 refuses the dial before the socket opens

`chat.workspaceRemoteAgentHosts` is tab-writable and the editor window dials every address it
lists. On main's containment build (`235a1559`, run 43909820977), with the workspace settings
file listing a loopback agent host:
- the window reconciles to that address and tries to connect, and every attempt fails with
  0015's `seclab: refusing an agent-host transport that does not pass through the gate`;
- `seclabAhpGate.log` records `ahp-gate.refused` (verdict `deny`) for each attempt (6 in the run);
- neither the host-side listener nor the one inside the tab is reached;
- positive control: an empty window (no tab) reading the same kind of entry from user settings
  does reach the host listener, so the address, the listener and the dial work where nothing
  gates them.

0015's check runs when the protocol client installs a transport, which is before the WebSocket
connects, so no connection leaves the host. With no connection there is no token to forward,
which retires 0011's `agentHostAuth.ts` hunk too. The proof harness checks all of this on every
run, so a regression in 0015 shows up here. The register's 0011 findings close as fixed by
0015 with this test.

## The proof harness

`node test/containment/reh-push.ts baseline|patched <user-data-dir> --app <test app>` runs one
OCI tab of the `containment` test build ([EDR](20261106-test-build-variants.md)), driven
headlessly ([EDR](20261112-headless-driver.md)):
1. the workspace lists a loopback agent host, with a listener on each side of the boundary;
2. the rogue-REH payload is staged with `only=push` before the window has a terminal, and
   learns the terminal the way a hostile REH would, by wrapping its own `createProcess`;
3. the window opens a terminal (the default keybinding) and runs `uname -s` into a workspace
   file, which must say Linux; that file is also the payload's signal to start;
4. the payload fires `windowOpen` (an empty background window), `manageExtensions` (a list),
   `getSystemStatus` and a variable request for the run's canary at that window;
5. the terminal runs a second command, which must also say Linux;
6. an empty window runs the dial control;
7. `check-probes.ts --only` judges the four push probes against the window's decision log.

Fixes needed before any of it could run, each the "complete except for the part that runs it"
shape:
- the payload armed only from the environment, which a tab never has (`env -i`);
- `listProcesses()` lists only orphaned terminals, so the payload never found a pty, and its
  workspace id came from fields the REH doesn't have;
- each command probe recorded only that something replied, which is true on both builds;
- `hostEffectAbsolute` named bare filenames that resolved against the checker's working
  directory and that nothing ever wrote.

The `openExternal` vector became `getSystemStatus`: on a baseline build `openExternal` launches
the host's default browser, a window outside the run's control that takes focus.

## Baseline: passed (main `235a1559`, run 43909820977, 2026-11-16)

All 15 checker checks and 11 harness checks passed, and teardown was clean (no process,
container or profile left; the editor never took focus).
- `reh-onexecutecommand-windowopen`, `-manageextensions`, `-getsystemstatus`: each ran on the
  trusted side; the status describes the macOS host.
- `reh-resolve-variables-host-env`: the run's editor-only canary came back to the REH.
- The terminal ran inside the tab before and after the pushes.
- Dial: as above.

## Patched: passed (branch `5f14df2c`, run 43926319765, 2026-11-16)

All 17 checker checks and 11 harness checks passed, and teardown was clean (no process,
container or profile left; the editor never took focus).
- Each of the four push probes is denied on its own: the three command pushes get the refusal's
  fixed reply, the variable request gets its text back unresolved, and the decision log holds
  `push:remoteterminal:$onExecuteCommand` and `…$onPtyHostRequestResolveVariablesEvent` denials.
  The lines carry the policy key, the fixed reason and a count, nothing the REH named.
- The terminal ran inside the tab before and after the refusals.
- Dial: the same as the baseline, as 0015 is unchanged.

The window refuses variable requests from the tab's pty host routinely, not only the probe's:
the log counted over 30 in one short run. They are the pty host resolving terminal profile
paths. With the refusal, a profile path that uses `${env:…}` stays unresolved in a tab, which
is the intended cost: those values come from the host user's environment.

## Review (round RFU, [record](../security-reviews/20261116-rpc-follow-ups.md))
No high or critical finding. RFU-1 (medium, open): a REH that answers `getDefaultSystemShell` or
`getProfiles` with a path containing `${config:…}` gets the host user's setting back, resolved
by the window's terminal profile resolver and sent in `createProcess`. 0031 closes the `${env:…}`
push only; this request/response path needs its own control.

## Found on the way

In a tab window the command palette ranks "Terminal: Create New Integrated Terminal (Local)"
first for the query "Terminal: Create New Terminal", so Enter opens a shell on the host, in
the host's copy of the workspace. The first harness version did exactly that, and its terminal
checks passed until they were made to check `uname`. The local terminal is the user's own
action, not a tab's, but it's an easy wrong turn in a sandboxed window. Reported to the
coordinator; not changed here.

## Follow-up: patch 0034 closes RFU-1 (2026-11-16)

Patch 0034 makes a tab window resolve no host variables in its REH's terminal launch config.
All three resolvers key on the window's own authority (review findings RFU-1, RFU1R-1, RFU1R-6;
[review](../security-reviews/20261116-rfu1-terminal-variables.md)).
- `remoteTerminalChannel.createProcess` skips `resolveAsync`, so it sends no `${config:…}`,
  `selectedText` or `lineNumber` values. The authority test is inlined because the REH bundles
  this file too and must not load the filter module.
- `terminalProfileResolverService` resolves only `${env:…}` in a tab profile's path and
  arguments, against the REH's environment.
- `terminalProcessManager` resolves only `${env:…}` in the launch config's `env`, a REH
  profile's included.
- `${config:…}`, `${userHome}` and the other host-state variables stay as written.

The probe `reh-profile-config-host-setting` (policy `data:remoteterminal-profile-path`):
- The rogue REH offers a `seclab-probe` profile through `$getProfiles`. Its path is
  `/bin/sh${config:seclab.test.canary}` and its `env` names the same setting. It also answers
  `getDefaultSystemShell` with that path.
- The harness seeds the setting with the run's canary in the host user settings, then makes the
  profile the host's `terminal.integrated.defaultProfile.linux`.
- The probe reads `$createProcess` at the channel, before the server's own resolution, then
  starts plain `/bin/sh` without the probe's variable.
- `test/containment/terminal-variables.test.ts` evaluates the patch's two resolver expressions
  and fails on a mutant of each rule.

- **Baseline: passed** (main `235a1559`, run 43909820977). 18 checker checks and 11 harness
  checks passed, and teardown was clean. The canary came back to the REH in both the profile
  path and its `env`. An earlier run, with only the path probe, also passed; on 0034's first
  version it showed only the path closed, which the review then found incomplete.
- **Patched: passed** (branch `4a0ab0e9`, run 43942525846). 21 checker checks and 11 harness
  checks passed, and teardown was clean.
  - The window sent the profile path and `env` back unresolved, with no canary anywhere in the
    request.
  - The four push probes were denied as before.
  - The terminal ran inside the tab before and after.

The cost: `${userHome}` and the other host variables stay unresolved in a tab's profiles. A tab
profile names its paths literally or through `${env:…}`. Still open: the window sends the REH
the host's raw terminal env, cwd and profile settings (RFU1R-2), and the active file's host
path (RFU1R-3).
