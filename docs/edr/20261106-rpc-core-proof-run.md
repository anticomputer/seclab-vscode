# The rpc-core proof run: DO NOT LAND

- **Date:** 2026-11-06
- **Status:** accepted. Result of the three-condition runtime proof the
  [handoff](20261106-rpc-core-handoff.md) required before `rpc-core` lands.
- **Verdict: do not land.** The patched build does not contain the attack. It
  stops the tab's extension host from working at all, so nothing ran, and the
  absent marker means nothing.

Both halves were run on the same base (`90fc1fa`), attested, de-quarantined,
launched only through `test/window.ts`, and torn down.

| | baseline | patched |
|---|---|---|
| build | main `90fc1fa`, run `42253795569` | `anticomputer-rpc-core-landing` `85ca160`, run `42257521300` |
| 1. the fixture ran | **yes** (`rogue-extension-host.json`, `rogue-observed.json`, `rogue-agent.json`, `task.json`, `rpc-probes.json`) | **no** (`.seclab-evidence/` does not exist, in the tab or on the host) |
| 2. denial recorded trusted-side | n/a (no filter in that build; `seclabRpcFilter.log` absent, correctly) | **no** (5001 lines, none of them `cmd:workbench.action.terminal.newLocal`) |
| 3. no host marker | **marker written**: `PWNED-newlocal` | no marker |
| checks | 28/34, 2 XFAIL, 4 FAIL | 7/13, 6 FAIL |

The baseline half stands: **host code execution from a tab is real and
reproduced** on main's current release. `workbench.action.terminal.newLocal`
plus `sendSequence` wrote `PWNED-newlocal` on the user's Mac.

The patched half is not containment. It is the exact false negative the
three-condition bar exists to reject, and it reproduces the handoff's
unexplained "13 checks instead of 32" — now explained.

## What actually happens in the patched build

`MainThreadErrors.$onUnexpectedError` is denied by the default verdict. Denying
the extension host's error channel makes the denial itself an unexpected error,
which is reported through the same channel, which is denied again:

```
4932  rpc:MainThreadErrors.$onUnexpectedError
  16  rpc:MainThreadTelemetry.$publicLog2
  16  rpc:MainThreadStorage.$initializeExtensionStorage
  10  rpc:MainThreadExtensionService.$onExtensionActivationError
   8  rpc:MainThreadExtensionService.$onWillActivateExtension
   1  rpc:seclab.log-capped
```

4932 denials in **666 ms** (12:18:33.576 to 12:18:34.242), then the log's
5000-denial cap latches and the window records nothing for the rest of its
life. No attacker is involved: this is the editor starting up.

The extension host lifecycle is denied with it. `$onWillActivateExtension` and
`$onExtensionActivationError` are denied, so **no extension activates** —
hostile or first-party. The REH log stops at `Launched Extension Host Process`.
The rogue extension never reached the first line of its activation, which is
why there is no evidence directory and no marker.

So three separate properties were all untestable at once, and only the last of
them looked like success:

1. the fixture could not run, so condition 1 is unobtainable;
2. the log had already capped, so condition 2 is unobtainable even if the
   denial had happened;
3. no marker — because nothing ran.

## Two findings this surfaced, beyond "it does not work"

**The policy denies the plumbing it needs to be observable.** A default-deny
table over every `MainThread*` method is correct in direction, but the error,
telemetry, storage and activation-lifecycle channels are not capabilities a tab
exercises against the user: they are how the host learns anything happened.
Denying `$onUnexpectedError` in particular is self-amplifying by construction.
These need reviewed entries before the filter can be evaluated at all.

**The log cap is reachable by accident, and latches.** The security review
round (alert 1, medium) predicted a tab could silence its own decision log with
~512 crafted calls. The measured run is worse: ordinary startup silenced it in
two thirds of a second, with 4932 copies of one repeated line. A cap that a
normal boot reaches is not a cap. Repeated denies must be collapsed per
`(surface, ref, verdict)` the way allows already are, and a first-seen key must
always get quota.

## Focus steal, reported not worked around

Teardown reported:

```
FAIL  the editor never took focus from the user during the run
  -> 2026-11-06T17:22:13.782Z editor pid 86965 became the frontmost app;
     killed it and its processes
```

The watcher caught it and killed the editor's process tree, as designed. The
baseline run on the same machine, same profile shape and same launch path did
**not** steal focus, so this is a property of the patched build, most likely an
error dialog raised by the dead extension host taking an activation path patch
0012 does not cover. It is recorded here and not worked around.

Timing caveat, stated rather than hidden: the sample is at `17:22:13`, within
seconds of the `check` invocation that also tears the run down, so "the dying
editor was activated by its own teardown" is not fully excluded.
`node test/focus/probe.ts` against `.work/app-branch` is the regression check
that would settle it, and should be run before the next landing attempt.

## What has to happen before another landing attempt

1. Give the extension host's own plumbing reviewed entries, at minimum
   `MainThreadErrors.$onUnexpectedError`,
   `MainThreadExtensionService.$onWillActivateExtension` and
   `$onExtensionActivationError`. Until a tab window can run an extension, the
   filter cannot be proved to contain one.
2. Fix the log cap so a boot cannot reach it (collapse repeats, reserve
   first-seen quota) — security review alert 1.
3. Re-run the three-condition proof. A patched run that produces
   `rogue-extension-host.json` **and** the `cmd:workbench.action.terminal.newLocal`
   deny line **and** no marker is the landing bar. Nothing weaker is.
4. Run `node test/focus/probe.ts` against the patched app.
5. Clear security review alerts 2-5 (see
   [`../security-reviews/20261106-rpc-core-landing.md`](../security-reviews/20261106-rpc-core-landing.md)).

The held-back patches `0015-seclab-no-remote-cli-push-in-tabs` and
`0016-seclab-no-variable-resolution-for-tab-pty-hosts` remain held, and
`remoteTerminal.$onExecuteCommand` and `$onPtyHostRequestResolveVariablesEvent`
remain open on main. So does the `newLocal` chain this round failed to close.

## Links

- Handoff: [`20261106-rpc-core-handoff.md`](20261106-rpc-core-handoff.md)
- Evidence channel and the reader this round added:
  [`20261106-containment-proof-reads-the-tab.md`](20261106-containment-proof-reads-the-tab.md)
- Architecture and residuals: [`../RPC-LOCKDOWN.md`](../RPC-LOCKDOWN.md)
