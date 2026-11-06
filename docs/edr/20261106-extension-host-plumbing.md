# The extension host's own plumbing is not a capability

- **Date:** 2026-11-06
- **Status:** accepted for the policy change; **the runtime proof is outstanding.**
- **Follows:** [the failed proof run](20261106-rpc-core-proof-run.md).

## What was measured

A clean boot of the patched build (`f1ddfce`, attested, run `42269930238`) in an
sbx tab, with the rogue extension deliberately **not** installed
(`SECLAB_BENIGN_ONLY=1`) and only the new positive control present. The point
was to read the denial set of an ordinary boot from a log that had not capped —
the previous measurement was taken through one that had.

The rewritten decision log did its job:

| | first patched build (`85ca160`) | this boot (`f1ddfce`) |
|---|---|---|
| lines in `seclabRpcFilter.log` | 5001, then silent for the window's life | **52** |
| denials represented | ~5000 before the cap latched | **1,200,274** |
| `$onUnexpectedError` | 4932 lines | 1 line + summaries, `count: 92365` |
| first line | a denial | the enforcing marker |

1.2 million decisions in 52 lines, with nothing dropped silently. The first line
is `seclabRpcFilterEnforcing:<sha256 of seclabPolicyData.ts>`, so a reader can
tie the log to the table being enforced.

**The benign extension still did not activate.** No `benign.json`. The positive
control fails exactly where it should, and that is the finding: the filter was
not containing the tab, it was stopping the extension host working.

Denied on a boot with nothing hostile in it (distinct keys, by volume):

```
92365  MainThreadErrors.$onUnexpectedError
   15  MainThreadStorage.$initializeExtensionStorage
   15  MainThreadTelemetry.$publicLog2
    9  MainThreadExtensionService.$onExtensionActivationError
    7  MainThreadExtensionService.$onWillActivateExtension
    3  MainThreadConsole.$logExtensionHostMessage
    1  each: MainThreadLogger.$registerLogger, MainThreadFileSystem.$ensureActivation,
          MainThreadCommands.$registerCommand, MainThreadExtensionService.$setPerformanceMarks,
          MainThreadLanguageFeatures.$registerDocumentSymbolProvider, MainThreadSearch.*,
          MainThreadTask.*, MainThreadDebugService.$registerDebugTypes,
          MainThreadTerminalService.$registerProcessSupport,
          MainThreadTunnelService.$setRemoteTunnelService, MainThreadWindow.$getInitialState,
          MainThreadChatSkills.$getTools
```

## The decision

Default-deny over every `MainThread*` method is right in direction, but it was
applied to the channels through which the host **learns that anything
happened**. Those are not capabilities a tab exercises against the user. Six
are now classified `allow`, individually, each with its upstream body as
evidence in `policy.json`:

| Method | Why it is not a capability |
|---|---|
| `MainThreadErrors.$onUnexpectedError` | deserialises and calls `onUnexpectedError`; returns nothing. Denying it is **self-amplifying**: the denial is itself an unexpected error reported through the denied channel. 92,365 calls on a clean boot. |
| `MainThreadConsole.$logExtensionHostMessage` | routes a console entry to the log service; the local console only under development flags. |
| `MainThreadExtensionService.$onWillActivateExtension` | one internal notification with an extension id, on the path of **every** activation. |
| `…$onDidActivateExtension` | the same, plus three numeric timings. |
| `…$onExtensionRuntimeError` | internal notification plus `console.error`. |
| `…$setPerformanceMarks` | marks into the timer service, bucketed by host kind; a tab is always `remoteExtHost`, so it cannot write marks attributed to the local host. |

Their payloads are tab-chosen text. That is unchanged from every other tab
string: consumers tag it untrusted and the UI quotes it
([prompt-injection-hygiene](20261104-prompt-injection-hygiene.md)). The residual
is log noise, bounded by the window log's rotation; the rpc-filter log itself
aggregates per key, so noise cannot hide a denial.

**`$onExtensionActivationError` stays denied**, alone among its siblings, and
that asymmetry is the point. With a non-null `missingExtensionDependency` it
reaches `_handleMissingNotInstalledDependency`, which **prompts the user to
install an extension the tab named**, and raises `notificationService.error` in
a development window. It is on the failure path, not the success path. Allowing
it needs an argument constraint pinning that parameter to `null`, which the
constraint machinery cannot express yet — and an unimplemented constraint fails
closed.

Still denied and **not** yet justified as compatible: `$initializeExtensionStorage`
(returns another extension's stored state, and `shared: true` reaches
profile-wide storage), `$publicLog2` (telemetry leaves the box),
`MainThreadLogger.*` (pinned denied by the log-trust invariant),
`$registerCommand` (needs the namespacing constraint), and the provider
registrations. Whether any of those also blocks activation is the next
measurement, not a guess.

The coverage digest moved from 27 reachable to 33, and
`rpc-filter/tools/check.sh` listed exactly the six intended changes and nothing
else before the baseline was re-accepted.

## The positive control

`test/containment/benign-extension/` does only what an ordinary workspace
extension does — registers and executes its own command, reads and writes a file
in its own workspace through `workspace.fs`, opens a document, finds files,
reads configuration, writes an output channel, uses workspace state, and
registers and invokes a hover provider — and records each step's outcome to
`.seclab-evidence/benign.json`. Nothing is armed, nothing hostile, no network,
no host path.

It exists because every other check in the editor-driven suite asserts that
something did **not** happen, and a build whose extension host cannot start
satisfies all of them at once. That is precisely the state the first patched
build was in, and it read as success.

## Not yet proved

The six entries are classified and gated; **no run has yet shown an extension
activating in a patched tab.** Editor launches are held until Fork-build's
focus fix is on main (background windows appear over the user's work and take
their next click; the patched run's steal was that, not an activation path).
When it lands: rebase so the patched build carries it, rebuild, then
`SECLAB_BENIGN_ONLY=1` to confirm activation, then the three-condition proof.

Until the positive control passes, nothing here may be read as containment.

## Links

- Failed proof run: [`20261106-rpc-core-proof-run.md`](20261106-rpc-core-proof-run.md)
- Decision log and the four gates: [`20261106-decision-log-and-four-gates.md`](20261106-decision-log-and-four-gates.md)
- Review round 9: [`../security-reviews/20261106-rpc-core-landing.md`](../security-reviews/20261106-rpc-core-landing.md)
