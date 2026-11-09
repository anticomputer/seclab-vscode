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
4. **Text files of a filesystem provider the host registered** (review round 1, F1; round 4, R2-1).
   All three must hold:
   - the model was born as this text file's own model;
   - it was born under a provider this host registered through `MainThreadFileSystem`;
   - that provider still serves the scheme.

   "Born" means what the window saw the first time any host's predicate observed the model, which
   is at `onModelAdded`. "Its own model" means that at birth the URI's `TextFileEditorModel` had
   finished reading the file (`lastResolvedFileStat`) and had no text model yet.
   `resolveFromContent` sets the stat and creates the text model synchronously, so the only model
   that can meet that is the one the text file creates. A text file model that took over a model
   born otherwise is tainted, and its later text models never count (review round 4).

   A tab can register a filesystem provider for a host scheme that has none (`output`, or
   `inmemory`, where anonymous host models get sequential URIs). It can also stall its own
   provider's read. A rule keyed on the current provider, or on a text file model merely existing,
   would then sync host models. A model born otherwise never qualifies, even if a text file model
   later wraps it, as `BaseTextEditorModel` does when a model already exists at its URI.
5. **Untitled:** synced in two cases.
   - This host's call created it: `openTextDocument({ content })` or an `untitled:` path. Only a
     model the call really created is tagged (`untitled.onDidCreate`). A call that names an existing
     untitled URI reopens the host's model, and that model isn't tagged (review round 1, F2).
   - It was empty with no associated path when the window first saw it, meaning the user typed it.

   Untitled documents the host seeds with content don't sync.
6. **Notebook cells:** a `vscode-notebook-cell` URI syncs only if its notebook (`CellUri.parse`) is
   on this window's own tab authority. A parse failure fails closed.

A filtered host's `$onVirtualDocumentChange` also only writes to models its own provider made
(review round 1, F3). Before, it could replace the text of any loaded model, host settings included.

Everything else isn't sent, so the tab never sees it. `vscode.workspace.openTextDocument` on a host
URI fails, as it already does for a model too large to sync.

Files, one concern each:
- `seclabDocumentOrigin.ts` (new): the per-host tags, the write scope, revocation and the
  predicate.
- `mainThreadDocumentsAndEditors.ts`: the state computer uses the predicate and recomputes on
  revocation.
- `mainThreadDocuments.ts`: the change, dirty, saved and encoding events use the predicate, and
  untitled documents the host creates are tagged.
- `mainThreadDocumentContentProviders.ts`: tags on create, and limits a host's writes to its own
  models.
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
    workspace edit by the tab on its own virtual document);
  - the SCM commit input box (`vscode-scm`), so extensions get no language features there (its
    text reaches the tab anyway, through the SCM API).
- **Residual:** a host feature that creates an empty untitled document and then fills it with host
  data programmatically would sync. None was seen in the measurement below.
- **Review:** [security review](../security-reviews/20261109-document-sync-provenance.md), four
  rounds, no open high or critical.
- **Siblings** (other window-to-tab pushes of host data) aren't covered by this patch. They're
  reported to the coordinator: the configuration snapshot (every user setting value), notebook
  document sync (cells of host notebooks), the editor-tab model (host URIs), ext-host init
  telemetry ids, the terminal default profile and environment, workspace data, and filesystem
  scheme squatting.

## Evidence
- **`fixture:test/docsync/probe-extension`:** `test/docsync/probe.ts` against main build
  42302662001 (`87efb67`), 2026-11-09, three runs. The last run ran every step and failed as
  designed on the baseline (below).

**Measurement and baseline** (main build `87efb67`, Actions run 42302662001, attested; sbx tab;
`node test/docsync/probe.ts prepare|seed|check` with a background launch through
`test/window.ts`). These are the documents the probe extension in the tab saw during ordinary use,
by scheme. Counts are open/change/close/snapshot; names and counts only, never contents:

| Scheme | Counts | What it was |
|---|---|---|
| `vscode-userdata` | 2/0/2/5 | user `settings.json` and `keybindings.json` (host) |
| `output` | 1/7/0/9 | the window log channel (host) |
| `vscode-local` | 1/0/1/2 | a host file, opened alone and in a diff (the tab side sees the window's `file:` as `vscode-local:`) |
| `perf` | 2/1/1/12 | the startup performance view (host data), and the tab's pre-created model |
| `chatSessionInput` | 0/14/0/15 | the chat input box (host-created, user-typed) |
| `vscode-scm` | 1/0/0/15 | the SCM input box of the tab's git repository |
| `file` | 1/4/0/7 | the tab's own file (the tab side sees `vscode-remote` as `file:`) |
| `git` | 3/0/2/8 | the tab's git extension's content provider |
| `vscode-notebook-cell` | 1/0/0/5 | the cell of a notebook in the tab |
| `untitled` | 2/2/0/7 | one typed untitled document, and one the tab created |

Canary hits on the baseline: the settings comment, settings value and keybindings comment (via
`vscode-userdata`), the window log (via `output`), and the host file (via `vscode-local`). Hijack 2
also leaked: the tab pre-created `perf:Startup Performance`, its window reference expired, the
perf provider reused the model and its `setValue` reached the tab (`foreignSeen=true`).

Decisions from the measurement:
- **No rule for `vscode-scm`.** The input box URI's `rootUri` query carries the tab's form of the
  path (`file:`), which can't be told apart from a host path. Its text already reaches the tab
  through `$onInputBoxValueChange`, and the RPC series denies SCM registration in tabs. So it isn't
  synced, and only language features on the commit box are lost.
- **No rule for `chatSessionInput`:** a host input, and chat is off in tabs.
- `git:`, cells and untitled are covered by rules 2, 6 and 5. Diff sides are separate models and
  need no rule.

**Proof on the patched build:** to be added.
