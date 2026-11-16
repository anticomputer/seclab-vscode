# Host notebooks and a tab: notebook sync measurement (DOCSYNC-R2)

- **Status:** proposed (measurement in progress; no decision yet)
- **Date:** 2026-11-16
- **Deciders:** coordinator (assignment: close the 0035 siblings in turn). Document-sync session: measurement.
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
- the tab's own notebook and a notebook it created were synced; the created notebook's edit
  control did not hold and is being checked.

**Current main (with patch 0005).** The filter's default verdict is `deny`, and
`MainThreadNotebook` (serializer registration) has no entry, so a tab may not be able to register
a serializer at all. Then no notebook opens in a tab window, which would close both paths and make
notebooks unusable in tabs. To be measured on main `6589051b` (run 43929230851) with `drive`.

## Decision
None yet. The options depend on the measurement on current main:
1. If notebooks don't open in tabs: record that, make the probe the regression test for NB-1
   and NB-2, and treat notebook support in tabs as its own feature.
2. If they do: per-model provenance for the notebook sync (a notebook on this tab's authority, or
   one this host created), and a rule that a tab's serializer only reads this tab's files.

## Evidence
- **`fixture:test/nbsync/probe-extension`:** `test/nbsync/probe.ts` on main `607873da`, sbx tab,
  background launch through `test/window.ts`, measure mode, 2026-11-16: NB-1 and NB-2 as above;
  no focus steal; the teardown gate passed.
