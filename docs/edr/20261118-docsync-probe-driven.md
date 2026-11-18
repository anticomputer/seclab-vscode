# The document-sync probe drives host actions from the window (EDT-11)

- **Status:** accepted
- **Date:** 2026-11-18
- **Deciders:** coordinator, 2026-11-18 (rework 0035's runtime regression test to drive host-side actions from the trusted window through the headless driver, keep a control that fails without 0035, and prove it fails on a build without 0035). Document-sync session: probe and record.
- **Related:** [document sync provenance](20261109-document-sync-provenance.md) (0035, whose evidence section this replaces as the current test); [editor-tab provenance review](../security-reviews/20261116-editor-tab-provenance.md) (EDT-11); [scheme squatting](20261116-scheme-squatting.md); [RPC lockdown](../RPC-LOCKDOWN.md) §7 item 10

## Context
`test/docsync/probe.ts` is patch 0035's runtime regression test. Its extension drove every step
from the tab: commands that open host settings and logs, `vscode.open` on a host file, untitled
creation, `applyEdit`, its own content providers, and opens by URI. Patch 0005's filter now refuses
all of those from a tab (commands outside the table, provider registrations, `$tryOpenDocument` on
anything but the tab's own `vscode-remote` resources), and 0038 hides host untitled URIs from the
tab. So every step failed on a filtered build and the probe no longer tested 0035 (EDT-11).

## Decision
Host-side actions come from the trusted window, as a user would make them, through the headless
driver (`DrivenEditor`: CDP over a pipe, never focused):
- **Host content, each a control judged by its canary on the window's screen:** user settings
  (JSON) and keybindings (JSON), each with a canary in a comment; the window's own log, with a
  canary line seeded into it; a host file dropped on the editor area (CDP drag events); that file
  compared with its saved state after an unsaved edit (a derived document); and the keyboard-mapping
  dump, a host-seeded untitled document.
- **Positive controls:** the tab's own file holds a `detect` canary the tab must see; an edit typed
  into that file in the window reaches the tab and is saved to the tab's disk; an untitled document
  typed in the window reaches the tab.
- **The tab extension only observes**, plus what a tab may still do: show its own file, and attempt
  both hijacks (providers for `output`, `vscode-userdata`, `vscode-local` and `perf`; a model at
  `perf:` and a host file by its window URI; claiming `untitled:Untitled-N` by URI). The filter's
  decision log must show the provider registrations and the opens refused.
- **Palette commands are picked by exact label.** The palette's fuzzy match ranks look-alikes first
  ("Open Default Keyboard Shortcuts (JSON)" for the user's, "Compare with Saved" for "File: Save"),
  so the harness moves to the row whose label is exactly the command's, and fails the step otherwise.
- **The headline control fails without 0035:** no canary but `detect` may appear in any document the
  tab sees. Without 0035 the window syncs every text model it opens, so the host settings,
  keybindings, log and file reach the tab.
- One mode, `drive --app PATH`, about three minutes; the teardown gate as in every probe. Probe
  hygiene as in PH-1 to PH-14: the arm stays on the host, writes into the workspace go through the
  tab, every `sbx exec` is bounded, and the workspace text is read through the tab.

What the probe no longer covers: git documents and notebook cells, because a tab's content-provider
registration (`git:`) and notebook serializer are refused, so neither opens in a tab window; and
0035's per-model rule under the two hijacks, which the filter now stops before 0035 is reached.
The hijacks stay in the probe as attempts the decision log must show refused.

## Alternatives
- **Allow the old tab-side steps for a test build.** A test variant could loosen the filter for the
  probe's commands. Rejected: the test would then run on a build users never get, and the hooks
  would loosen the boundary under test.
- **Pass test URIs to the tab on a test-only channel** (the gap's suggestion, for host untitled
  URIs). Not needed: the window opens the untitled document, and the tab tries plausible
  `Untitled-N` URIs, which the filter refuses whatever they name.

## Evidence
Both runs on 2026-11-18, sbx tabs from a 1.145.3 REH, the headless driver, no focus steal, the
teardown gate passing every run:
- **`fixture:test/docsync/probe-extension`:** `test/docsync/probe.ts drive` on main `3fee3b55` (build run 44275612663), with 0035: passes every assertion in 3 of 3 runs.
  Every window control holds; the tab saw only its own file (`file`, with the `detect` canary) and
  the untitled document typed in its window, and the decision log shows the tab's provider
  registrations and opens of host URIs refused.
- **Without 0035:** a throwaway branch at `bc251331`, main without 0035 and the two patches that
  build on it (build run 44325569857), fails in 2 of 2 runs, and only the leak assertions: the
  settings and keybindings canaries reach the tab through `vscode-userdata`, the window log's
  through `output`, the host file's through `vscode-local` and its saved-state diff
  (`showModifications`), and the keyboard-mapping dump as untitled text. Every control and both
  hijack refusals hold there too, so the failures are the missing patch, not the run.

## Consequences
- 0035's regression test runs on every shipped configuration again, and fails without 0035.
- The baseline needs a build without 0035; 0036 and 0038 build on 0035's origin module, so they go
  too. Such a build comes only from a throwaway branch's `build-macos` dispatch and runs only under
  the headless driver.
