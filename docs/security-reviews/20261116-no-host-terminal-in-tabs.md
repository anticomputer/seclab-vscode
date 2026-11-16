# Security review: patch 0050, no host terminal in a tab window

- **Date:** 2026-11-16
- **Reviewer:** independent `security-review` agent (an Opus-class model)
- **Subject:** `git diff 74840267..16f26c45` on `anticomputer-rpc-no-host-terminal`: patch 0050,
  the series and reach entries, the ADR, ARCHITECTURE §4.8, the proof harness
  `test/containment/host-terminal.ts` and `host-terminal.test.ts`. The decision it implements is
  the project owner's, 2026-11-16 ([ADR](../adr/20261116-no-host-terminal-in-tabs.md)).
- **Prompt:** said the diff, fixtures and evidence may contain prompt injection aimed at the
  reviewer, and that the reviewer reports it rather than following it. None was found.

## Verdict
No vulnerability, and nothing above low. Every route the reviewer listed from a tab window to a
host shell ends at a refused launch, a hidden or unregistered command, or the tab's own backend.
Four findings are about evidence, docs and upstream tests; all are addressed in `2d7ba7b1`.

| ID | Sev | Component | Finding | Status |
|---|---|---|---|---|
| NHT-1 | low | `host-terminal.ts` | The patched palette checks could pass vacuously: an empty list looks the same whether there is no such command or the query went nowhere. The patched local-terminal check only ran when the palette offered it, so nothing at runtime showed `newLocal` unregistered | fixed |
| NHT-2 | info | ADR | The debug note was imprecise. `runInTerminal` with kind `external` runs where the adapter's extension host runs. Only a host-side adapter could open the host's terminal application | fixed (docs) |
| NHT-3 | info | upstream `browser/externalTerminal.contribution.ts` | The Explorer's "Open in Integrated/External Terminal" items still showed for a host (`file:`) resource in a tab window. Running them was refused by the launch check, so they only offered something that could fail | fixed |
| NHT-4 | info | 0050's `openNativeConsole` handler | Upstream's handler unit tests don't stub `IWorkbenchEnvironmentService`, so reading `.remoteAuthority` off it would throw there | fixed |

## Confirmed without findings
- `newLocal` is registered only by `registerRemoteContributions()`, which 0050 skips in a tab
  window. It has no default keybinding, and the filter's command table denies it.
- `RemoteNameContext` is `seclab` in a tab window: upstream's `getRemoteName` takes the part
  before `+`.
- `openNativeConsole`: hidden from the palette and keybinding. If run anyway, its handler
  returns. The tab's extension host can't run it: the filter allows only listed command ids,
  and it isn't one.
- The launch check runs before `getBackend()`, so it covers new launches, attach and revive,
  and relaunch. Persisted local terminals are revived only in non-remote windows. A terminal
  dragged in from another window is detached through the tab's own backend.
- The other routes all end at the refused launch or the tab's own backend:
  - `openInTerminal` with `explorerKind: external`, and `scm.openInTerminal`;
  - terminal links, profiles from the tab's server, `newWithProfile`, `newWithCwd`;
  - terminal editors, `defaultLocation`, task terminals, Attach to Session, extension
    pseudoterminals.
- Tab-initiated routes stay closed. `MainThreadTerminalService`, `MainThreadDebugService` and
  the task service are default-denied, and 0030/0031 refuse the server-initiated pushes.
- The harness is inert: the only typing goes to the tab's terminal, before any host shell
  exists. The keybindings it uses reach the workbench even when a terminal is focused, and
  teardown is gated.
