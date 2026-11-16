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

## Found on the way

In a tab window the command palette ranks "Terminal: Create New Integrated Terminal (Local)"
first for the query "Terminal: Create New Terminal", so Enter opens a shell on the host, in
the host's copy of the workspace. The first harness version did exactly that, and its terminal
checks passed until they were made to check `uname`. The local terminal is the user's own
action, not a tab's, but it's an easy wrong turn in a sandboxed window. Reported to the
coordinator; not changed here.
