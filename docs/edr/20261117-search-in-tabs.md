# File and text search in tabs, for the tab's own file system

- **Date:** 2026-11-17
- **Status:** accepted. Proof passed, both halves (2026-11-17).
- **Owner:** the RPC follow-ups session (register owner `rpc`).
- **Related:** [RPC-LOCKDOWN §7.1](../RPC-LOCKDOWN.md#71-what-a-tabs-extensions-cannot-do-yet),
  [response-side control ADR](../adr/20261116-response-side-control.md)

## Decision
Search is the first feature restored to tabs, as RPC-LOCKDOWN §7.1 designed it. Inside a tab,
the extension host serves search itself: it registers its file and text search providers for
`vscode-remote`. The filter now allows:
- `$registerFileSearchProvider` and `$registerTextSearchProvider` for exactly `vscode-remote`
  (validator `tabSearchProvider`). So no host-scheme search, and none of its query text, reaches
  the tab.
- `$handleFileMatch`, with `tabFileMatches`: every item is a plain URI, canonical `vscode-remote`
  on this tab's authority.
- `$handleTextMatch`, with `tabTextMatches`: each match has only a plain URI `resource` and a
  non-empty `results` list; each result `uri` is checked the same way, and previews are bounded.
  Both validators follow the window's consumer, which reads an item with `results` as a text
  match and anything else as a URI (review SRCH-1).
- `$unregisterProvider`: the handle map is per extension host, so it reaches only this host's own
  providers.

Patch 0052 makes the extension host send one file's text matches in pieces within
`tabTextMatches`' bound. Upstream batched whole files, and a file with more matching lines had its
whole batch refused (PR review on #52). The window merges matches for one resource, and
`test/containment/search-split.test.ts` runs upstream's own collector on such a file, with and
without the patch.

Both registrations name patch 0051 as their response control (`check_drift.py`'s
`check_responses`). The patch makes the provider's completion messages untrusted plain text, and
drops open editors outside the tab's file system from the query the tab is sent
([review](../security-reviews/20261117-search-in-tabs.md), SRCH-2 and SRCH-3).
`test/containment/arg-validators.test.ts` covers each validator, with injected defects.

## Proof
The fixture `test/containment/search-probe` is run by `test/containment/search-probe.ts`, with
the editor driven headlessly in an OCI tab of the containment test build. Each run plants a
needle file holding a unique token, then searches for it three ways:
- `workspace.findFiles` in the tab. The extension records facts only: whether the call returned
  within 30 s, how many results, and whether each is in the tab's own workspace folder.
- Quick Open ("Go to File") in the trusted window.
- The Search view ("Find in Files") in the trusted window.

The positive control in both modes: the window's explorer lists the workspace, and the probe
recorded its search.

- **Before: passed** (`059c5b66`, the response-side control build, run 44138193537). All 8
  checks passed, and teardown was clean.
  - Both searches were typed into their inputs, and neither found anything.
  - `findFiles` never returned.
  - The decision log holds the file search provider registration denied.
- **After: passed** (`a0fb6e29`, run 44164815992, the build with every review fix). All 9 checks
  passed, and teardown was clean.
  - `findFiles` returned the one needle, in the tab's own workspace folder.
  - Quick Open and the Search view both found it.
  - The decision log holds both registrations as allowed.
  - An earlier build, `b4badf48` (run 44162058593), without the SRCH2-1 tightening, also passed
    9/9.
- **`fixture:test/containment/search-probe`:** run by `test/containment/search-probe.ts` in both
  modes on 2026-11-17 (runs above).

Inside the tab's extension host, workspace URIs arrive through the remote URI transformer. So
the probe compares results against the workspace folder's own scheme and authority, not
`vscode-remote`. The window-side checks of `vscode-remote` on the tab's authority are the
validators'.
