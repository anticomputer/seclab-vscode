# Host editors stay anonymous to a tab: provenance for the editor-tab model (patch 0038)

- **Status:** accepted
- **Date:** 2026-11-16
- **Deciders:** coordinator, 2026-11-16 (close the 0035 siblings in turn; this one next; the patched-build proof run). Document-sync session: measurement and implementation.
- **Related:** [document sync provenance](20261109-document-sync-provenance.md) (0035); [RPC lockdown](../RPC-LOCKDOWN.md) §7 item 10

## Context
`MainThreadEditorTabs` sends every extension host the window's whole editor-tab model: for each
open editor, an id built from its canonical resource, its label, and an input naming its URIs
([mainThreadEditorTabs.ts#L91-L104](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/api/browser/mainThreadEditorTabs.ts#L91-L104),
[#L244-L254](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/api/browser/mainThreadEditorTabs.ts#L244-L254)).
Patch 0035 keeps host documents' text out of a tab, but a host editor's URI still names a host
path: the user's settings and keybindings live under the user's home directory, a host file's path
names the file. This is the register's DOCSYNC-R3. The RPC filter doesn't see it: it is a push
from the window. The filter does refuse the tab's `$moveTab`, `$closeTab` and `$closeGroup`, so a
tab sends no ids back today.

## Measurement
`test/edtabs/probe.ts drive` names the isolated profile's directory with a generated
`seclabcanary_` token, so every host path under it carries the canary. The window opens the user's settings and keybindings as a user would (command
palette, headless driver). The probe in the tab reports input kinds, URI schemes and hashes of
every label and URI token. The login name is not a marker: the tab's own folder is a host path
under the user's home (sbx mounts it at the same path), which the tab is given on purpose.

**Main `6589051b` (run 43929230851), 2026-11-16:** both editors opened in the window, and the tab
saw `vscode-userdata` URIs carrying the profile canary and the login name (the host home path),
and a `vscode:` URI for the default keybindings. Its own `README.md` arrived as expected.

## Decision
Patch `0038-seclab-editor-tab-provenance`, for a non-`LocalProcess` host in a `seclab+` window
(0035's predicate). An editor is the tab's own when it shows at least one resource and every
resource it shows (both sides of a diff of any kind, merge inputs, multi-diff entries, an
interactive window's input) is:
- a `vscode-remote` URI on this window's tab authority;
- a webview panel's or terminal's own id (`webview-panel:`, `vscode-terminal:`), which names no
  resource;
- any other URI only if its model is one 0035 would sync to this host (`seclabShouldSync`: a model
  this host's provider made, a file born under a filesystem provider this host registered, an
  untitled document this host created or that was empty when it appeared). Never by scheme, so a
  tab can't claim a host scheme by registering a provider for it (review EDT-3).

The document sync's `MainThreadDocumentsAndEditors` publishes that judgement, by URI, on the
host's 0035 origin record, so the editor-tab model takes no new services and its constructor keeps
upstream's signature (upstream's unit test constructs it). Until the judgement is published,
nothing counts as the tab's own; publishing it fires 0035's change event, which rebuilds the model.
Filtering is decided from the host context's own authority, as 0035's fail-closed path does.

A multi-diff is judged by the resources it shows, not by its own source id (review EDT-9). Because
an untitled editor joins its group before its model exists, the document sync also fires the
origin change when a model is added, after recording its birth, so the user's own untitled tab
shows as the tab's own (EDT-10).

Any other editor, including one with no resource at all, reaches the tab as present only: an
opaque id, `UnknownInput` and the label `Editor`. Ids are a salted SHA-1 of upstream's id for every
editor, so an id never changes when an editor's status does. When 0035's tags change (a provider's
model appears after its diff tab opened), the model is rebuilt and resent.

## Alternatives considered
- **Drop host editors from the model.** The extension API indexes tabs by position; dropping
  entries would misreport active tabs and group sizes. Present but anonymous keeps the shape.
- **Trust schemes a tab registered a content provider for.** Rejected for the same reason as in
  0035: a tab can register a provider for a host scheme.

## Consequences
- An extension in a tab sees host-side editors as `Editor` tabs with an unknown input. A tab's
  own untitled editor shows as `Editor` until its model exists.
- Webview panels and terminals keep their titles (review EDT-5, EDT-6): under the RPC filter a tab
  creates no webview panel, and terminal names already reach every host through the terminal
  service (DOCSYNC-R5).
- At 76 changed lines in three files (the editor-tab model, and the two 0035 files that publish
  the judgement) the patch is over the usual size; it is one concern.
- If the filter ever allows `$moveTab` or `$closeTab`, the opaque ids already round-trip (the
  window's lookup uses the same ids).

## Evidence
- **`fixture:test/edtabs/probe-extension`:** `test/edtabs/probe.ts drive` on main `6589051b`,
  sbx tab, headless driver, 2026-11-16 (attested builds):
  - main `6589051b` (run 43929230851): every control holds and `DOCSYNC-R3 …` fails, the profile
    canary reaching the tab in `vscode-userdata` URIs, as it must without the patch;
  - this branch at `a5239620` (run 43953763295): 4 of 4 runs pass. The host editors reach the tab
    as `unknown` inputs, no canary in any label or URI, its own `README.md` still arrives. No
    focus steal; the teardown gate passed every run.
- After the pull-request review (EDT-8): the probe also drops a host media file into the window
  (its folder carries a second canary) and creates an untitled document there. On main the media
  preview reaches the tab as a custom-editor input with its host path; on the patched build it is
  anonymous. The untitled control fails on `a5239620`, which predates the EDT-10 fix.
- Final proof, 2026-11-17, with every case above: this branch at `bb91e728` (build run
  44176135490) passes 4 of 4 runs (no canary in any label or URI; the media preview and the
  host editors anonymous; the user's untitled document a text tab of the tab's own); main
  `6589051b` fails `DOCSYNC-R3 …` and `EDT-1 …`. No focus steal; the teardown gate passed every run.
- Typecheck: the patched file adds no error against the pinned tree.
- Review: [20261116-editor-tab-provenance](../security-reviews/20261116-editor-tab-provenance.md),
  three rounds; no high or critical finding.
