# Tab-originated commands carry the tab identity through a tainted command service

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** user; RPC-lockdown session
- **Extends:** [20261104-rpc-filter-enforcement-points.md](20261104-rpc-filter-enforcement-points.md)
- **Design:** [docs/RPC-LOCKDOWN.md](../RPC-LOCKDOWN.md) §2.5.2

## Context

The Phase 2 design left one hole open, and the review called it the most likely
bypass: **verdict laundering**. The commands table is consulted in
`MainThreadCommands.$executeCommand`, so it sees the command the tab *names*. It
does not see commands that command's handler then executes, because those calls
do not arrive from the tab.

`_remoteCLI.windowOpen` is the shape, in upstream source: its handler takes an
`accessor`, resolves `ICommandService`, and executes `_files.windowOpen`
([mainThreadCLICommands.ts L35-L41](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/api/browser/mainThreadCLICommands.ts#L35-L41)).
Deny the inner id and the outer one still reaches it.

The user decided: **"Taint the command context: anything a tab command triggers
carries the tab's identity and goes through the filter."**

The question is how, given two constraints found in source:

- `CommandService.executeCommand` is the single funnel for workbench command
  execution, and `_tryExecuteCommand` invokes handlers via
  `this._instantiationService.invokeFunction(command.handler, ...args)`
  ([commandService.ts L88-L105](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/services/commands/common/commandService.ts#L88-L105)).
- There is **no `AsyncLocalStorage`**. The workbench renderer is a browser
  context, not Node, and `grep` finds no use of `node:async_hooks` anywhere in
  `src/vs/workbench` or `src/vs/platform`. So the usual ambient-context
  mechanism for "survives await, timers and event re-entry" is unavailable.

## Decision

Propagate the taint as a **capability, not as ambient state**: a tab-originated
command is invoked through a child instantiation service whose `ICommandService`
binding is a tainted wrapper carrying `(tabId, remoteAuthority)`.

```ts
// in CommandService._tryExecuteCommand, when the call is tab-originated
const tainted = new TaintedCommandService(this, origin);
const scoped = this._instantiationService.createChild(
    new ServiceCollection([ICommandService, tainted]));
const result = scoped.invokeFunction(command.handler, ...args);
```

`TaintedCommandService.executeCommand` applies the same policy verdict as
`$executeCommand` and then recurses with the same origin, so depth is unbounded
and every level is checked.

`createChild` and `invokeFunction` are existing API
([instantiation.ts L65, L74](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/instantiation/common/instantiation.ts#L65-L74)).

**Why this answers "must survive async hops."** It is not time-scoped at all.
The handler receives the tainted service as an object reference, so an `await`,
a `setTimeout`, or an event handler that later calls
`accessor.get(ICommandService).executeCommand(...)` is still calling the tainted
instance. Ambient taint is what breaks across async hops; a captured reference
does not.

**Fail closed when the context is lost.** A handler reaching the *global*
`ICommandService` instead escapes the taint. Two measures:

1. The global `CommandService` refuses any command whose verdict is `deny`
   while a tab-originated command is in flight (a counter incremented for the
   outer call's lifetime). Over-denial is possible if the user triggers a denied
   command concurrently; that is the closed direction and is acceptable.
2. The escape is observable rather than silent: the wrapper tags the origin and
   the global service logs any denied execution attributed to an in-flight tab
   command, which the probes assert on.

## Alternatives considered

- **`AsyncLocalStorage`.** The natural mechanism, and the one most systems use.
  Rejected: not available in a browser renderer, and adopting it would mean
  un-sandboxing the renderer, which is the opposite of this project.
- **Ambient flag over the synchronous extent only.** Rejected as the primary
  mechanism: it is exactly what breaks across `await`, `setTimeout` and event
  re-entry, which the user named. Kept only as the backstop in (1).
- **Zone.js-style monkey-patching of the task queue.** Rejected: large, fragile,
  and it would have to be carried as a core patch forever.
- **Explicitly threading an origin parameter through `executeCommand`.**
  Rejected: changes a signature used at thousands of call sites, which is
  irreconcilable with a small patch queue.
- **Denying all nesting from tab-originated commands.** Rejected: too many
  legitimate commands delegate internally, so it would break ordinary use.

## Consequences

- Nested commands are filtered at every depth, with the same table and the same
  verdicts as the top-level call.
- **Residual:** a handler that uses a *constructor-injected* or module-imported
  `ICommandService`, rather than resolving it from its `accessor`, keeps the
  untainted reference. The backstop catches the denied subset of those; the
  allowed subset is unfiltered. This must be probed, not assumed, and the probe
  set includes a handler of that shape.
- **Residual:** services that execute commands on a caller's behalf — notably
  `IOpenerService` for `command:` URIs — are a second escape and need the same
  treatment or an explicit deny.
- A small amount of per-command allocation on the tab path. Not on the UI path.

## Validation

Probes, each of which must succeed on the unpatched build first:

- `launder/direct` — allowed outer command executes a denied inner one.
- `launder/await` — the nested call happens after an `await`.
- `launder/timer` — the nested call happens from a `setTimeout`.
- `launder/event` — the nested call happens from an event handler registered by
  the outer command.
- `launder/captured-service` — handler uses a constructor-injected command
  service; expected to exercise the backstop rather than the taint.
