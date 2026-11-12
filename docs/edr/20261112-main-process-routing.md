# Main-process routing: no window loads a local folder or workspace (patch 0041)

- **Status:** accepted (CI proof pending: the driven CLI-open test runs in `headless-linux`)
- **Date:** 2026-11-12
- **Deciders:** Coordinator (2026-11-12: implement the accepted ADR as patch 0041 once the
  headless driver is green in CI). Fork-build session: implementation and test.
- **Related:** [ADR route-folder-opens-in-main](../adr/20261104-route-folder-opens-in-main.md),
  [Tab Manager routing](20261104-tab-manager-routing.md) (the extension-level fallback),
  [headless driver](20261112-headless-driver.md), findings m0#2b-1 and m0#3-2
  ([round 2](../security-reviews/20261104-m0-tabd-code.md))

## Context

Until now, a local folder opened from the CLI, a menu, recents or a link loaded in a local
window first; the Tab Manager then closed it and reopened it as a tab. In that moment core
features ran on the host for the folder (automatic tasks, which interim patch 0042 stopped). The
ADR decided to route opens in the main process instead.

## Decision

**One choke point.** Every open reaches `WindowsMainService.open`
([windowsMainService.ts#L337](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/windows/electron-main/windowsMainService.ts#L337)):
the CLI and second-instance launches, File menus and recents, drag and drop,
`<urlProtocol>://file/…` links, session restore and extension development windows. With
product.json `seclabTabRouter` set, 0041 takes every resolved path that has a workspace (a
folder or a `.code-workspace`) and no remote authority out of the open, and opens an empty
window instead. Untitled workspaces restored at startup
([#L411](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/windows/electron-main/windowsMainService.ts#L411))
are filtered the same way. Tab windows (`seclab+` authority) are untouched. The empty window
follows the same reuse rules the folder would have.

**Hand-over.** When the empty window is ready, main opens
`<urlProtocol>://seclab.tab-manager/open?path=…&windowId=N` through its URL service with
`trusted: true`. This is the pattern upstream uses for a link that needs a new window
([app.ts#L1186](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/code/electron-main/app.ts#L1186)).
The URL router sends it to that window
([urlIpc.ts#L57](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/url/common/urlIpc.ts#L57)),
and `trusted` skips the "allow this extension to open the URI" prompt
([extensionUrlHandler.ts#L179](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/services/extensions/browser/extensionUrlHandler.ts#L179)).
A `.code-workspace` or a non-`file:` folder is passed as `unsupported`, and the Tab Manager
says so. The Tab Manager's handler confirms a folder that has no tab yet, claims it and opens
it, reusing the empty window when it has no editors. A link from outside (a web page) reaches
the same handler only after upstream's prompt, and still gets the confirmation.

**Add Folder.** A local window never enters a workspace
([workspacesManagementMainService.ts#L247](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/workspaces/electron-main/workspacesManagementMainService.ts#L247)),
which is how an empty window would otherwise become a local multi-root workspace without
going through `open`.

**Enforced.** `product.jq` fails the build unless `seclabTabRouter` names the Tab Manager, and
`check-release --desktop` fails a desktop app without either guard's log string (self-tested by
removing each).

**Test.** `test/driver/cli-open.ts` (`./seclab test cli-open`, in `headless-linux`) launches the
editor with a folder as its CLI argument. Every page is auto-attached paused, before its first
script, and a reporter sends each document's window configuration back over a CDP binding; no
document may hold a workspace, and the run fails without reports. The Tab Manager must show the
folder in its confirmation, and the main log must show main routed it. The run then declines.
Measured on the macOS build without 0041: the check fails (the window's configuration holds the
folder before the fallback closes it), and the routing check fails. Polling or title events
missed that window: the fallback reloads it within about a second.

The Tab Manager's extension-level routing stays as a fallback for a build without 0041.

## Consequences

- Closes m0#2b-1 and m0#3-2 once the test is green on a 0041 build; then interim patch 0042 is
  removed.
- One more upstream file pair to rebase (two hunks in `windowsMainService.ts`, one in
  `workspacesManagementMainService.ts`).
- The agents window, which opens a local workspace, is routed too and so doesn't open locally;
  agents run in tabs.
