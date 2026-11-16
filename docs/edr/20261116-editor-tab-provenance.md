# Host editors stay anonymous to a tab: provenance for the editor-tab model (patch 0038)

- **Status:** proposed (patched-build proof and review pending)
- **Date:** 2026-11-16
- **Deciders:** coordinator, 2026-11-16 (close the 0035 siblings in turn; this one next). Document-sync session: measurement and implementation.
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
`seclabcanary_` token, so every host path under it carries the canary; the user's login name is a
second marker. The window opens the user's settings and keybindings as a user would (command
palette, headless driver). The probe in the tab reports input kinds, URI schemes and hashes of
every label and URI token.

**Main `6589051b` (run 43929230851), 2026-11-16:** both editors opened in the window, and the tab
saw `vscode-userdata` URIs carrying the profile canary and the login name (the host home path),
and a `vscode:` URI for the default keybindings. Its own `README.md` arrived as expected.

## Decision
Patch `0038-seclab-editor-tab-provenance`, for a non-`LocalProcess` host in a `seclab+` window
(0035's predicate). An editor is the tab's own when every resource it shows (both sides of a diff,
merge inputs, multi-diff entries, an interactive window's input) is:
- a `vscode-remote` URI on this window's tab authority;
- a model this host's own content provider made, or a resource of a filesystem provider this host
  registered (0035's per-model and per-provider tags, so a tab can't claim a host scheme by
  registering a provider for it);
- an untitled document without a path (its label, `Untitled-1`, carries nothing).

Any other editor reaches the tab as present only: an opaque id, `UnknownInput` and the label
`Editor`. Terminals and webview panels keep their input (no URI; a title the panel's owner set).
Ids are a salted SHA-1 of upstream's id for every editor, so an id never changes when an editor's
status does. When 0035's tags change (a provider's model appears after its diff tab opened), the
model is rebuilt and resent.

## Alternatives considered
- **Drop host editors from the model.** The extension API indexes tabs by position; dropping
  entries would misreport active tabs and group sizes. Present but anonymous keeps the shape.
- **Trust schemes a tab registered a content provider for.** Rejected for the same reason as in
  0035: a tab can register a provider for a host scheme.

## Consequences
- An extension in a tab sees host-side editors as `Editor` tabs with an unknown input.
- At 61 changed lines the patch is over the usual size; it is one concern in one file.
- If the filter ever allows `$moveTab` or `$closeTab`, the opaque ids already round-trip (the
  window's lookup uses the same ids).

## Evidence
- **`fixture:test/edtabs/probe-extension`:** `test/edtabs/probe.ts drive` on main `6589051b`,
  sbx tab, headless driver, measure mode, 2026-11-16: the profile canary and the login name reached
  the tab in `vscode-userdata` URIs; no focus steal; the teardown gate passed.
- Typecheck: the patched file adds no error against the pinned tree.
