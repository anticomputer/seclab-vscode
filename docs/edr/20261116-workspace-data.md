# A tab's workspace data names only the tab's folder (DOCSYNC-R6)

- **Status:** proposed (measured; closure as fixed by patch 0041 pending with the coordinator)
- **Date:** 2026-11-16
- **Deciders:** coordinator (assignment: close the 0035 siblings in turn). Document-sync session: measurement.
- **Related:** [document sync provenance](20261109-document-sync-provenance.md) (0035); [RPC lockdown](../RPC-LOCKDOWN.md) §7 item 10

## Context
`MainThreadWorkspace` sends every extension host the window's workspace: its folders, the
workspace configuration URI, its id and its label, at start (init data) and on every change
([mainThreadWorkspace.ts#L129-L143](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/api/browser/mainThreadWorkspace.ts#L129-L143),
[remoteExtensionHost.ts#L234](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/services/extensions/common/remoteExtensionHost.ts#L234)).
There is no origin check, so this is the register's DOCSYNC-R6: a workspace that held a host
folder, or a local `.code-workspace` file, would name host paths to the tab.

## Analysis
A tab window is a folder window on its own `seclab+` authority. For anything else to appear in its
workspace data, the window would have to become a multi-folder workspace:
- adding a folder (Add Folder to Workspace, `code --add`, a drop on the explorer) to a folder
  window creates an untitled workspace and enters it
  ([abstractWorkspaceEditingService.ts#L207-L216](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/services/workspaces/browser/abstractWorkspaceEditingService.ts#L207-L216));
- opening a workspace file loads it in a window.

Patch 0041 refuses both in the main process: no window enters a workspace, and local folder or
workspace opens go to the Tab Manager, which opens them as their own tabs. A tab's own
`$updateWorkspaceFolders` is refused by the RPC filter (`MainThreadWorkspace` defaults to deny).
So the workspace data of a tab window carries only the tab's folder, whose path the tab is given on
purpose (sbx mounts it at the same host path), its id (a hash of that folder) and its label.

## Measurement
`test/wsdata/probe.ts drive` names a host folder outside the tab's mount and the isolated
profile with a generated `seclabcanary_` token, launches the window on the tab with `--add` naming
the host folder (1.145 ignores it at start-up), and reads what the tab's extension host is told.

**Main `6589051b` (run 43929230851), 2026-11-16:** the tab saw one folder, its own, for the whole
run; no canary in any folder URI, folder name, workspace name or configuration URI (there was
none); no focus steal; the teardown gate passed.

The add path itself was not driven: a second CLI invocation or the Add Folder dialog could take
focus from the user. Its refusal rests on 0041's main-process guard, whose presence in the desktop
app `build/check-release.sh` already requires (`[seclab] a window does not enter a workspace`).

## Decision
Proposed: close DOCSYNC-R6 as fixed by patch 0041 (`8ce6cc70`), with this probe as the runtime
regression test for what a tab window's workspace data holds. No new patch.

## Evidence
- **`fixture:test/wsdata/probe-extension`:** `test/wsdata/probe.ts drive` on main `6589051b`,
  sbx tab, headless driver, 2026-11-16: `DOCSYNC-R6 …` and both controls pass; the teardown gate
  passed.
