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
| SRCH-6 | low | `search-probe.ts` | The proof could pass vacuously. `before` passed if nothing was typed, and didn't need the registration's deny. There's no hostile-result negative | fixed |
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
