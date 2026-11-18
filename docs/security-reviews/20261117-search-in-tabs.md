# Security review: file and text search in tabs

- **Date:** 2026-11-17
- **Reviewer:** independent `security-review` agent (an Opus-class model)
- **Subject:** the search restoration on `anticomputer-rpc-search`: the policy entries and
  validators for `MainThreadSearch`, the response-gate exemptions, the search probe and its
  harness, and the records ([EDR](../edr/20261117-search-in-tabs.md)).
- **Prompt:** said the diff, fixtures and evidence may contain prompt injection aimed at the
  reviewer, and that the reviewer reports it rather than following it. None was found.

## Verdict
Two mediums: a tab could still put host files in search results, and could put a trusted
command link in the Search view. Both are fixed, along with the lower findings, except part of
SRCH-3, which is open.

| ID | Sev | Component | Finding | Status |
|---|---|---|---|---|
| SRCH-1 | medium | `$handleFileMatch`, `$handleTextMatch` validators | Upstream's consumer reads an item with truthy `results` as a text match on its nested `resource`, and any other item as a URI itself. The filter checked the other field in each case, so it was bypassed two ways. A URI-shaped file result carrying `results` and a host `resource` passed the positional rule. A text match without `results` passed, and was then revived as a host URI. Host paths could appear and open in Quick Open and the Search view, and Replace All would edit them | fixed |
| SRCH-2 | medium | Search view messages; `check_drift.py` `RESPONSE_NONE` | A tab provider's completion messages reach the Search view unchecked. A `trusted` message with a `command:` link runs that command on the trusted side when clicked. The gate exempted both search registrations as returning nothing that carries a command | fixed |
| SRCH-3 | low | query sent to the tab | The query carries `extraFileResources`, which are open editors outside the workspace (host files, user settings). It also carries include and exclude globs built from the host's `files.exclude` and `search.exclude` | open (part fixed) |
| SRCH-4 | info | `$handleFileMatch` | The positional rule also admits `untitled:` results | fixed |
| SRCH-5 | info | search validators | `$handleFileMatch` had no bound on its result count | fixed |
| SRCH-6 | low | `search-probe.ts` | The proof could pass vacuously. `before` passed if nothing was typed, and didn't need the registration's deny. There's no hostile-result negative | fixed (untested: the harness runs are its evidence) |
| SRCH-7 | info | ARCHITECTURE, RPC-LOCKDOWN, policy, `check_drift.py` | The records overclaimed (SRCH-1, SRCH-2), and a rationale said opened documents sync to the tab, which has been stale since 0035 | fixed |

## Confirmed without findings
- Registration requires exactly `vscode-remote` and a non-negative handle.
- The AI text search provider, keyword results and search telemetry stay denied.
- Handles and sessions belong to one `MainThreadSearch` per extension host, so a tab can't reach
  or unregister another host's providers.
- The tab is sent only `vscode-remote` folder queries.
- Normal windows are unaffected.
- Previews and Quick Open labels render as plain text.
- The validators are fail-closed and see only `JSON.parse` output.
- The fixture is inert and the harness is safe.

## What changed in response
- SRCH-1: `tabFileMatches` (new) and `tabTextMatches` check each item the way the consumer reads
  it.
  - A file result is a plain URI with no other keys, canonical `vscode-remote` on this tab.
  - A text match has only `resource` and a non-empty `results` list.
  - `test/containment/arg-validators.test.ts` gains three injected defects for these shapes.
- SRCH-4, SRCH-5: `$handleFileMatch` uses `tabFileMatches`, which refuses `untitled:` and caps
  results at 10000 per call. There is an injected defect for `untitled:`.
- SRCH-2: patch 0051 passes a tab provider's completion messages through
  `seclabFromTab.searchMessages`: untrusted, at most 8, each at most 1000 characters. Both search
  registrations leave `RESPONSE_NONE` and name 0051 as their response control, so
  `check_responses` holds them to it.
  - `filter-module.test.ts` covers `searchMessages`, with mutants.
  - `search-responses.test.ts` checks 0051's wiring, with mutants.
- SRCH-3: 0051 drops `extraFileResources` outside the tab's own file system from the query. The
  host-derived globs still reach the tab: filtering them changes which files a search returns,
  a design trade-off left open with a follow-up.
- SRCH-6: the proof records that each search was typed, and requires it in both modes. `before`
  needs the registration's deny in the decision log.
  - A runtime hostile-result negative would need the extension host's internals or a proposed
    API the fixture can't enable. The injected-defect cases cover those shapes against the
    shipped validators instead.
- SRCH-7: the records are corrected.

## Second pass (same date, same reviewer setup)
Subject: the fixes above (`b4badf48`, `452c1fd3`). The prompt carried the same prompt-injection
warning; none was found. Both mediums are closed. The reviewer tried the bypasses named in the
prompt, and none got through:
- `results: []` with a host resource;
- falsy `results` values on file items;
- `$mid` variants;
- other fields of the completion stats;
- authority case tricks on `extraFileResources`.

Nothing new at medium or above, 0051 included.

| ID | Sev | Component | Finding | Status |
|---|---|---|---|---|
| SRCH2-1 | info | `tabTextMatches` | The nested values of a text match weren't pinned to a type. `revive()` acts on `$mid`, so a resource could become a RegExp or Date, or a result could become a host URI. No consumer reads a URI from them, so the effect was a broken match, not a host file in results | fixed |
| SRCH2-2 | info | 0051 | Two response fields still pass as they are: the error text a tab rejects a search with, shown in the Search view's input as plain text, and the stats, sent to sampled telemetry. Neither carries a command, a link or markup: the UI-spoofing residual the policy already lists | accepted residual |
| SRCH2-3 | info | records | This record called SRCH-6 fixed while the register had it as fixed-untested, and SRCH-3's summary still named `extraFileResources`, which 0051 now filters | fixed |

In response: `tabTextMatches` requires each resource and result `uri` to be a plain serialised
URI (`$mid` 1, URI keys only), and a result to carry only its own keys and never `$mid`. Two
injected defects cover this (`a0fb6e29`). SRCH2-2 is accepted as the listed UI-spoofing
residual. The records are aligned.

## Automated PR review on #52
One thread, real and functional: upstream batches a file's text matches whole, so a file with
more matching lines than `tabTextMatches` accepts had its whole batch refused, and its results went
missing without a warning. Patch 0052 splits a file's matches at that bound in the extension host,
and the window merges them. `search-split.test.ts` runs upstream's own collector on such a file,
unpatched as the control and patched, with a mutant.
