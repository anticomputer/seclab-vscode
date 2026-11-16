# Host notebooks and a tab: notebook sync measurement (DOCSYNC-R2)

- **Status:** accepted
- **Date:** 2026-11-16
- **Deciders:** coordinator, 2026-11-16 (close DOCSYNC-R2 as fixed by patch 0005 with this probe as its regression test; notebooks in tabs listed as a tab limitation; the enabling plan is a follow-up tied to the RPC follow-ups session's landing D, which needs a validator for `MainThreadNotebook`). Document-sync session: measurement.
- **Related:** [document sync provenance](20261109-document-sync-provenance.md) (0035); [RPC lockdown](../RPC-LOCKDOWN.md) §7 item 10

## Context
`MainThreadNotebooksAndEditors` sends every notebook in the window, with its cells, to every
extension host
([mainThreadNotebookDocumentsAndEditors.ts#L172](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/api/browser/mainThreadNotebookDocumentsAndEditors.ts#L172)),
and `MainThreadNotebookDocuments` forwards dirty and saved events for every notebook
([mainThreadNotebookDocuments.ts#L37-L38](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/api/browser/mainThreadNotebookDocuments.ts#L37-L38)).
Patch 0035 covers text documents only, so this is the register's DOCSYNC-R2.

There is a second path no sync filter closes. A notebook's bytes are turned into cells by the
serializer its type registered, and `ipynb` is a workspace-kind extension, so in a tab window it
runs in the tab. Opening a host `.ipynb` there hands the host file's bytes to the tab.

## Measurement
`test/nbsync/probe.ts` seeds fake canaries in a host `.ipynb` (a markdown cell) and a host
`.seclabnb` (a type only the probe's own serializer reads), and a detection value in the tab's
own notebook. The probe extension in the tab reports schemes and line hashes per channel: the
notebook sync (documents, cells, open and change events), cell text documents, and its
serializer. `drive` mode has the window open the host notebooks itself through the headless
driver, as a user would.

**Main `607873da` (run 43264609543; before the RPC filter landed), the tab opening the host
notebooks through `vscode.open`, measure mode, 2026-11-16:**
- the host `.ipynb` cells reached the tab through the notebook sync, the open events and cell
  documents (NB-1);
- the host `.seclabnb` bytes reached the tab's serializer (NB-2);
- the tab's own notebook and a notebook it created were synced. The created notebook's cell edit
  was applied in the window but never came back to the tab: patch 0035 syncs cells only on the
  tab's authority, and an untitled notebook's cells are not. That matters only if notebooks are
  enabled in tabs (below).

**Main `6589051b` (run 43929230851; with patch 0005), `drive` mode, 2026-11-16.** The RPC
filter's default verdict is `deny`, and `MainThreadNotebook` has no entry. The window's filter log
shows `$registerNotebookSerializer`, `$tryOpenNotebook` and `$tryCreateNotebook` refused. So a
tab registers no serializer, and no notebook opens in a tab window: not the host notebooks, not
the tab's own `nb.ipynb`, not one it creates. The probe saw no notebook and no cell on any
channel, and no canary. The host notebooks passed to the window on its command line
(`--file-uri`) did not open in it either (main routes local opens to the Tab Manager, patch
0041). Opening a host `.ipynb` without a notebook serializer would leave a text editor, whose
model patch 0035 already keeps out of the tab.

## Decision
DOCSYNC-R2 is closed as fixed by the RPC filter (patch 0005), which refuses a tab's notebook
serializer, so no notebook reaches the notebook sync of a tab window. The
probe is the regression test: NB-1 and NB-2 must hold, and on a build where notebooks open its
detection controls must hold too; it fails on `607873da` and passes on `6589051b`.

Consequence: notebooks don't work in tabs today (ARCHITECTURE §4.8). Enabling them (an allow for
the serializer and notebook calls) is a follow-up (register DOCSYNC-R9), with the RPC follow-ups
session's landing D, which needs a validator for `MainThreadNotebook`. It needs:
1. per-model provenance for the notebook sync and the dirty and saved events: a notebook on this
   tab's authority, or a model this host's `$tryCreateNotebook` made (tagged per model, never by
   URI; `$tryOpenNotebook` never tags);
2. a serializer rule: the window hands a tab's serializer only bytes of this tab's files;
3. 0035's cell rule extended to cells of notebooks the tab made, so its edits come back;
4. this probe passing with notebooks on.

## Evidence
- **`fixture:test/nbsync/probe-extension`:** `test/nbsync/probe.ts` on main `607873da`, sbx tab,
  background launch through `test/window.ts`, measure mode, 2026-11-16: NB-1 and NB-2 as above;
  no focus steal; the teardown gate passed.
- `test/nbsync/probe.ts drive` on main `6589051b`, headless driver, 2026-11-16: notebooks off in
  the tab (serializer refused, per the filter log); `DOCSYNC-R2 NB-1` and `NB-2` pass; no focus
  steal; the teardown gate passed. The same assertions on `607873da` fail (NB-1, NB-2).
