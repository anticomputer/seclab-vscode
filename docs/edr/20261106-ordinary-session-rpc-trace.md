# Measure an ordinary session's RPC calls once, then classify them by name

- **Date:** 2026-11-06
- **Status:** accepted
- **Follows:** [the extension host's own plumbing](20261106-extension-host-plumbing.md)

## Context
The last two patched builds each found one more layer of denied plumbing. A denial stops
the code path that would have made the next call, so measuring through the filter can only
ever show the first wall. With a build cycle per layer, that is the slowest way to learn
what an extension needs.

## Decision
Measure once, on an **unfiltered** build, with upstream's own tracer.
`--logExtensionHostCommunication` makes `RPCLogger` (`extensionHostManager.ts` L252 at
`a717861c`) log every Ext → Win request to the renderer console. Chromium's
`--enable-logging=file --log-file=` puts that console in a file. No build variant, no hook,
nothing new in the shipped app.

`test/containment/rpc-trace.ts` does it end to end:
- `prepare` sets up a benign workspace (`fixtures/trace-workspace`: a `.ts`, `.md` and
  `.json` file in a git repo, fake data) and the benign extension only. It refuses
  everything else.
- The editor is launched through the background harness. `test/window.ts --rpc-trace`
  accepts only a plain path under this checkout's `.work/`.
- In the trace workspace the benign extension also opens files, so the built-in language
  extensions activate, and reloads once for a warm start.
- `check` derives method names, counts and `$executeCommand` ids. It **deletes the raw
  trace**, which carries argument values, then runs the teardown gate. Only the derived
  list enters the repo:
  [`rpc-filter/probes/traces/20261106-ordinary-session.json`](../../rpc-filter/probes/traces/20261106-ordinary-session.json).

The benign control gained the ordinary shapes it lacked:
- `globalState` with `setKeysForSync`;
- a contributed command;
- a completion provider;
- a status bar item;
- its own secret, with a fake value.

## Result
Run on main `bc85925` (run 42288509087): one pass, 2,677 requests, **69 distinct remote
calls**. The benign control activated with every step passing, nothing took focus, and
teardown was clean. Against the policy at the time, **64 of the 69 were denied**. The
patched builds had shown at most a dozen of them, one layer at a time.

Two things the trace showed that no build had:
1. **Storage blocks every activation.** Every activation awaits both
   `$initializeExtensionStorage(true, …)` and `(false, …)`, so allowing only the
   workspace scope would still have left every extension dead. Reading the main-thread
   side showed the id is a raw storage key. The answer is the per-tab partition
   ([ADR](../adr/20261106-tab-state-partition.md)), not an id check.
2. **Every extension calls trusted commands:** `_setContext` ×129, and
   `_executeHoverProvider` / `_executeCompletionItemProvider`. The deferred-laundering
   residual kept every command at deny. The user approved these three as the residual's
   only **leaf exceptions**:
   - each handler is shown never to reach `ICommandService`;
   - each is argument-validated, because a leaf can still leak or spoof host state on its
     own. The provider commands open a model on the caller's URI, and `file:` is the host
     disk; `_setContext` writes the window's global context.

   `check_residuals` now enforces exactly that. The residual stays open; fixing it properly
   is a follow-up after landing.

The trace also exposed a scanner gap. `registerModelAndPositionCommand` was not a
recognised registration form, so `_executeHoverProvider` and 15 siblings were missing from
the inventory. The generator now recognises it; the policy was not bent to fit.

## Named argument validators
`rpc-filter/patch-src/seclabArgValidators.ts`, shipped in 0005, holds every validator. It
has **no imports**: whatever needs the workbench (URI revival, the command registry,
context keys) is injected. So `test/containment/arg-validators.test.ts` tests the shipped
code, not a model of it.
- A policy entry names its validator (`"validator"`). An unknown name, a throw, or a
  constraint with no validator denies.
- `check_validators` fails on:
  - an undefined validator;
  - a validator nothing names;
  - a validator on a verdict that never runs it;
  - a constrained command with no validator.
- Each validator is proved by injection: the check is deleted from a copy of the source, and
  the dangerous shape must then pass (8 defects).

Revival needed a hardening found while writing them. `URI.revive` takes `external` and
`fsPath` from the wire as the URI's cached string and path, and on macOS a missing `_sep`
satisfies the marker check. So a URI with this tab's scheme and authority could carry a
host `fsPath`. Every tab URI is now compared with a canonical rebuild, and refused if its
cached forms differ.

## Rules this keeps
- The trace is what a session **needs**, not what is safe. Every method on it gets its own
  classification from its upstream body; anything not classified stays denied.
- The raw trace is sensitive and is never kept. Only names, counts and command ids are
  recorded.
