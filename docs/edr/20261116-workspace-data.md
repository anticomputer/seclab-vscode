# A tab's workspace data names only the tab's folder (DOCSYNC-R6)

- **Status:** accepted
- **Date:** 2026-11-16
- **Deciders:** coordinator, 2026-11-16 (close DOCSYNC-R6 as fixed by patch 0041, with `test/driver/cli-open.ts` and this probe as its regression tests; drive the add path in-process through the headless driver). Document-sync session: measurement.
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

**The add path, main `6589051b`, 2026-11-17.** The probe then runs Workspaces: Add Folder to
Workspace in the window, in-process: the headless driver opens the command, and the file picker
is the renderer's own (`files.simpleDialog.enable`), so no native dialog or second CLI call is
involved. The picker browses only the tab's file system: the host folder does not exist there, and
it offers no way to the host's. Adding one of the tab's own folders still means entering a
workspace, and the main process refused it (its log: `[seclab] a window does not enter a
workspace`). The window stopped its extension hosts to enter the workspace and restarted them when
that failed; across both activations the tab saw only its own folder and no canary.

**Correction (PR #37 review, WSD-2).** The runs above checked for the canary token only, while the
host folder's name (`<canary>_folder`) is one token to the extension, so the folder itself
reaching the tab would not have been flagged. The probe now treats that name as a marker too, and
every run checks that the leak check flags the folder's URI. Rerun on main `6589051b`,
2026-11-17: the tab saw only its own folder, with neither marker anywhere in its workspace data.

## Decision
DOCSYNC-R6 is closed as fixed by patch 0041 (`8ce6cc70`). No new patch. Regression tests:
- `test/wsdata/probe.ts drive`: the add path is refused in the main process, and the tab's
  workspace data holds only its own folder;
- `test/driver/cli-open.ts`: a local folder or a `.code-workspace` file claiming a tab authority,
  opened from the command line, never loads in a window.

## Evidence
- **`fixture:test/wsdata/probe-extension`:** `test/wsdata/probe.ts drive` on main `6589051b`,
  sbx tab, headless driver: 2026-11-16, the workspace data alone; 2026-11-17, with the add path
  driven in-process. Every assertion passed, including the main process's refusal; no focus steal;
  the teardown gate passed.
