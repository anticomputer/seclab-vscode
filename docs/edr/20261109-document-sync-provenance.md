# Host documents don't sync into a tab: per-model provenance for the document sync (patch 0035)

- **Status:** proposed
- **Date:** 2026-11-09
- **Deciders:** coordinator (assignment: "close an open leak … the trusted window pushes host-side document contents into the sandboxed tab's extension host"; decision on review: "use per-model provenance … Correctness beats the 50-line target; a second file is fine if each part has one concern"). Document-sync session: implementation.
- **Related:** [RPC lockdown](../RPC-LOCKDOWN.md) §2.6 and §7; [patch queue](../../patches/README.md); [threat model](../adr/20261104-threat-model-rogue-extension.md); [no real secret in a tab](../adr/20261104-no-real-secret-in-a-tab.md); [patch-build gate](20261105-patch-build-gate.md)

## Context
`MainThreadDocumentsAndEditors` sends every text model in the window to every extension host.
Its only filter is `shouldSynchronizeModel`, which checks size and the simple-widget flag, never
origin
([model.ts#L1624-L1628](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/editor/common/model.ts#L1624-L1628),
[mainThreadDocumentsAndEditors.ts#L165-L212](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/api/browser/mainThreadDocumentsAndEditors.ts#L157-L190)).
In a `seclab+` window the tab's extension host is one of those hosts. So when the user opens host
content in a tab window, the tab receives its full text through `$acceptDocumentsAndEditorsDelta`,
and every later edit through `$acceptModelChanged`
([mainThreadDocuments.ts#L98-L118](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/api/browser/mainThreadDocuments.ts#L98-L118)).
Examples are user settings and keybindings (`vscode-userdata:`), an output channel (`output:`), a
host `file:`, or a host virtual document. Settings files can hold tokens. The tab also learns host
paths through the dirty, saved and encoding events (`_shouldHandleFileEvent`, same filter).

These are window-to-tab pushes. The RPC filter screens calls from the tab to the window, so it never
sees them.

A rule by scheme ("sync schemes the tab provides") can be hijacked in two ways:
- **Provider for a host scheme.** A tab may register a text content provider for any scheme,
  including the host's (`output`, `perf`, …). The resolver even tries the newest registration
  first (`providers.unshift`,
  [textModelResolverService.ts#L163-L170](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/services/textmodelResolver/common/textModelResolverService.ts#L163-L170)).
  A scheme-level rule would then sync the host's own models of that scheme.
- **Pre-creating a model at a host URI.** Host code that reuses an existing model writes host
  content into whatever model is already at its URI. An example is the startup performance view,
  `getModel(resource) || createModel(...)` followed by `setValue`
  ([perfviewEditor.ts#L124](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/performance/browser/perfviewEditor.ts#L124),
  [#L165](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/performance/browser/perfviewEditor.ts#L165)).
  If the tab created `perf:Startup Performance` first, a rule that trusts the creator would sync
  the host data written into it later.

## Decision
Patch `0035-seclab-document-sync-provenance` decides per model. The check applies only in a
`seclab+` window, and only to extension hosts that aren't `LocalProcess`. The local host (Tab
Manager and the other first-party `ui` built-ins) and every non-seclab window behave as upstream.
A model is sent to such a host only if `shouldSynchronizeModel` holds and the model belongs to that
host:

1. **Tab files:** a `vscode-remote` URI whose authority equals this window's own `seclab+<tabId>`.
2. **Models the host's own content provider made:** tagged when
   `MainThreadDocumentContentProviders` creates them for this host. The tag is per model, never per
   scheme, so a provider for `output` gains nothing: the host's own output models stay untagged.
3. **Revocation:** a tagged model loses its tag on any content change other than this host's own
   `$onVirtualDocumentChange` write to that model. The tab then gets a remove delta. The change
   itself isn't sent either: `ModelTracker` re-checks the predicate before `$acceptModelChanged`,
   and the revoking listener is registered at tagging time, before the model is ever synced, so it
   runs first.
4. **Filesystem providers the host registered:** the model's scheme is served right now
   (`fileService.getProvider`) by a provider this host registered through `MainThreadFileSystem`.
   `registerProvider` throws on a scheme that's already taken, so a tab can't take over a
   registered host filesystem scheme.
5. **Untitled:** synced if this host created it (`openTextDocument({ content })`, `untitled:`
   paths), or if it was empty with no associated path when the window first saw it: the user typed
   it. Untitled documents the host seeds with content don't sync.
6. **Notebook cells:** a `vscode-notebook-cell` URI is judged by its notebook URI
   (`CellUri.parse`), with rules 1 and 4.

Everything else isn't sent, so the tab never sees it. `vscode.workspace.openTextDocument` on a host
URI fails, as it already does for a model too large to sync.

Files, one concern each:
- `seclabDocumentOrigin.ts` (new): the per-host tags, the write scope, revocation and the
  predicate.
- `mainThreadDocumentsAndEditors.ts`: the state computer uses the predicate and recomputes on
  revocation.
- `mainThreadDocuments.ts`: the change, dirty, saved and encoding events use the predicate, and
  untitled documents the host creates are tagged.
- `mainThreadDocumentContentProviders.ts`: tags on create, and marks the host's own writes.
- `mainThreadFileSystem.ts`: records the providers the host registers.

The patch is longer than the queue's usual 50 lines because a scheme-level rule is unsound (above).
It's still one concern: who owns a document.

`patches/reach.json` requires the patch in the desktop build. `patches/sole-consumer.json` pins the
window side's only holders of the `ExtHostDocumentsAndEditors` and `ExtHostDocuments` proxies, so a
second sender of document text fails `patch-build`.

## Alternatives considered
- **Allow by scheme** (tab authority plus "schemes the tab provides"): rejected because of both
  hijacks above.
- **Tag at creation, without revocation:** rejected because of the pre-creation hijack. Host
  features that reuse a model by URI exist upstream (perf view, REPL input, search editor and
  others).
- **Deny a tab content provider for host schemes:** rejected. There's no complete list of host
  schemes, and host contributions use many (`output`, `perf`, `vscode-chat-*`, `walkThrough`, …).
  Provenance doesn't need the list.
- **Filter in the RPC layer:** it's the wrong direction. The RPC filter screens tab-to-window
  calls, and these are window-to-tab pushes.

## Consequences
- **Host data opened in a tab window stays on the host.** That covers settings, keybindings,
  output, host files, diffs against host files and host virtual documents. Tab extensions don't
  get language features on them, which is the intent.
- **Fail-closed cases** (the tab doesn't see these documents):
  - an untitled document restored from a hot-exit backup, or one that existed before the tab's
    extension host restarted;
  - a tab-provided virtual document that something other than its provider edits (for example a
    workspace edit by the tab on its own virtual document).
- **Residual:** a host feature that creates an empty untitled document and then fills it with host
  data programmatically would sync. None was seen in the measurement below.
- **Siblings** (other window-to-tab pushes of host data) aren't covered by this patch. They're
  reported to the coordinator: the configuration snapshot (every user setting value), notebook
  document sync (cells of host notebooks), the editor-tab model (host URIs), ext-host init
  telemetry ids, the terminal default profile and environment, workspace data, and filesystem
  scheme squatting.

## Evidence
Measurement, proof and review: to be added once runs are complete.
