# Security review: patch 0038, the editor-tab model

- **Date:** 2026-11-16
- **Scope:** origin/main..branch head: patch 0038, `test/edtabs` and the EDR.
  - Round 1: `e56e7575`.
  - Round 2: the round-1 fixes, at `1ad537ee`.
- **Reviewer:** security-review agent (an Opus-class model), triage by the document-sync session. Finding IDs `EDT-n`.
- **Threat model:** a rogue extension owns the tab's extension host, sends any RPC and registers
  providers for any scheme. The editor-tab model must not tell it host paths, file names or other
  host data about editors in its window. Local windows and the local host behave as upstream.
- **Related:** [EDR editor-tab-provenance](../edr/20261116-editor-tab-provenance.md).
- **Prompt injection:** none found.

## Findings
| # | Sev | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| EDT-1 | Medium | ownership | The webview exemption (`WebviewInput` but not `CustomEditorInput`) also exempted the media preview and custom-editor diffs, which extend `WebviewInput` and show files: a host video dragged into the window reached the tab with its full path. | fixed | No type exemption: only `webview-panel:` and `vscode-terminal:` ids pass by scheme, and diff resources of every kind are collected. | test/edtabs/probe.ts "DOCSYNC-R3 no host path reaches the tab through the editor-tab model (profile canary)" |
| EDT-2 | Low | ownership | Any path-less untitled editor counted as the tab's own, so a host-created untitled document's first line reached the tab as its label. | fixed | Non-remote resources pass only through 0035's `seclabShouldSync` on their model (created by this host, or empty at birth). | none |
| EDT-3 | Low | ownership | A filesystem provider the tab registered later claimed host editors already open in that scheme (latent: the filter refuses provider registration). | fixed | Same predicate: born under this host's provider, never by scheme. | none |
| EDT-4 | Info | harness | The probe could pass without the host editors reaching the tab's model. | fixed | A control requires them to arrive, anonymous or not; the tab's own files are recognised as `file:` (URI transformer). | none |

## Round 2
Confirmed EDT-1 to EDT-4, and that calling `seclabShouldSync` from the editor-tab model never
records a model's birth first (every host's document-sync state computer does that on model add).
Editors without any resource now fail closed. No high or critical finding.

Below the reporting bar, recorded:

| # | Sev | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| EDT-5 | Low | webviews | Webview panels pass by scheme, so a host-side panel's title and view type reach the tab. | accepted-residual | Under the RPC filter a tab can't create a webview panel, so every panel in a tab window is the window's; none found whose title carries host data (Release Notes is a constant). If panels are ever allowed, own only panels this host created. | none |
| EDT-6 | Info | terminals | A host-local terminal's title (`user@host: ~/dir`) reaches the tab as an editor label. | accepted-residual | No new exposure: the terminal service already pushes every terminal's name to every host (DOCSYNC-R5). | none |

## Round 3
At `a0c20243`: 0038 no longer adds constructor parameters (upstream's unit test constructs the
class); the document sync publishes its ownership judgement on the host's 0035 record. Confirmed:
the editor-tab model can't be built before the judgement exists (every host object is constructed
in one synchronous pass, and publishing fires the rebuild), and the host context's authority is
the window's `seclab+` authority for the tab's remote host. No high or critical finding.

| # | Sev | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| EDT-7 | Info | hosts | Filtering keys on the host's own authority, so a desktop web-worker host in a tab window is unfiltered, where 0035 filters it by the window's authority. | accepted-residual | The desktop app never runs tab-installed extensions in the local web worker, only host-installed web extensions; 0038 is desktop-only. Revisit if the web build is ever in scope. | none |

## Copilot review (PR #24)
Five threads from the automated pull-request review, each checked against the code.

| # | Sev | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| EDT-8 | Low | harness | EDT-1's cited test opened only settings and keybindings, so restoring the webview exemption would have left it passing. | fixed | The probe drops a host media file whose folder carries a canary into the window (CDP drag events) and asserts its path never reaches the tab. It fails on main, where the media preview reaches the tab as a custom-editor input with its host path, which is exactly what the old exemption sent. | test/edtabs/probe.ts "EDT-1 a host media file dropped in the window reaches the tab without its path" |
| EDT-9 | Low | ownership | A multi-diff's own resource is a source id (`multi-diff-editor:`) with no model, so a multi-diff of the tab's own files went anonymous. | fixed | Only the shown resources are judged. | none |
| EDT-10 | Low | ownership | An untitled editor joins its group before its model exists, so the user's own untitled tab stayed anonymous until an unrelated rebuild. | fixed | The document sync fires the origin change when a model is added, after recording its birth. The control fails on the build before the fix and passes on `bb91e728`. | test/edtabs/probe.ts "control: an untitled document the user created in the window shows to the tab as its own text tab (EDT-10)" |
| EDT-11 | Medium | harness | 0038 hides host untitled URIs from the docsync probe, which found them through tab inputs. On builds with the RPC filter that probe is already broken: the filter refuses most of its steps (commands, opens, provider registrations, its own edit), so 0035's runtime regression test no longer runs. | open | The docsync probe needs reworking to drive host-side actions from the window through the headless driver and pass test URIs on a test-only channel; a follow-up. | none |
| EDT-12 | Info | harness | A failure while setting up the tab skipped the probe's teardown gate. | fixed | Setup is wrapped so the gate always runs. | none |

## Copilot review (PR #24, second pass)

| # | Sev | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| EDT-13 | Low | ownership | The EDT-10 fix rebuilt the whole tab model, which fires only `onDidChangeTabGroups`, so an extension listening to `onDidChangeTabs` never saw the user's untitled tab turn from unknown to text. | fixed | Each tab whose label or input changes with ownership is sent as `TAB_UPDATE`. The control fails on `bb91e728`. | test/edtabs/probe.ts "control: the tab learned of its untitled text tab through onDidChangeTabs (EDT-13)" |
