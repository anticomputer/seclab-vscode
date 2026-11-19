# Security review: the host user's search and watcher excludes stay on the host (patch 0060)

- **Date:** 2026-11-18
- **Reviewer:** independent `security-review` agent (an Opus-class model), five rounds.
- **Subject:** patch 0060 on `anticomputer-rpc-srch3-host-excludes`, which closes SRCH-3
  ([search review](20261117-search-in-tabs.md)), its unit suite and runtime probe
  ([EDR](../edr/20261118-host-search-excludes.md)).
- **Prompt:** said the diff, fixtures and evidence may contain prompt injection aimed at the
  reviewer, and that the reviewer reports it rather than following it. None was found.

## Verdict
No high or critical finding in any round. Round 1 found the query and watcher paths the first
version missed; round 2 found that removing host patterns where a query leaves for the tab was an
oracle, so the design moved to where queries are built; rounds 3 and 4 found one more query source
each, and the authority comparison; round 5 found no vulnerability. Every finding is fixed except a
low-entropy residual (SRCH3-10) and a consistency follow-up outside 0060 (SRCH3-14).

## How the evidence was made
The branch keeps each reviewed version of 0060 as its own commit, followed by the commit that fixes
that round's findings. The final unit test (`test/containment/search-excludes.test.ts`) runs
upstream's own code with whichever version of 0060 a tree has. Its case "a tab gets none of the
host user's patterns and keeps its own" fails on main with every leak, and on the trees round 1 and
round 3 reviewed with their findings; its case "a caller's own patterns reach the tab untouched, so
a query says nothing about the host's" fails on the tree round 2 reviewed; its case "a window that
is not a tab's keeps upstream's settings" fails on the tree round 3 reviewed (the authority case);
and the first case fails on the tree round 4 reviewed with the empty-file search walk. All pass on
the final version (run logs kept outside the repo, under the session's `.work/`).

## Findings

| # | Sev | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| SRCH3-1 | Medium | queries | Explorer find, the chat file picker, prompt-file discovery and sessions telemetry build file queries by hand from the merged settings, bypassing the first version's QueryBuilder change, so the host's patterns still reached the tab. | fixed | Each builds its excludes through 0060's helper; a whole-tree check requires it of every caller. | test/containment/search-excludes.test.ts "a tab gets none of the host user's patterns and keeps its own" |
| SRCH3-2 | Medium | watcher | The window's watch requests for a tab's workspace carried the host user's `files.watcherExclude` and `files.watcherInclude`, and the snapshot let `files.watcherExclude` cross. | fixed | The watch requests take both from the tab's own layers; the snapshot withholds their host values. | same |
| SRCH3-3 | Low | layers | The first version kept a workspace file's settings, wherever the file was. | fixed | A workspace file's settings are left out; a single folder's settings are its folder layer too. | same |
| SRCH3-4 | Medium | queries | Removing host patterns by key where a query leaves for the tab also removed a caller's matching pattern, so a tab passing a guess to `findFiles` learned whether the host's settings held it. | fixed | The tab's own excludes replace the host's where each query builds its settings part; a caller's patterns are never touched. | test/containment/search-excludes.test.ts "a caller's own patterns reach the tab untouched, so a query says nothing about the host's" |
| SRCH3-5 | Medium | snapshot | `files.readonlyInclude`, `files.readonlyExclude` and `explorer.autoRevealExclude` are glob maps with boolean values, so their host values crossed to the tab's extension host. | fixed | Withheld from host layers. | test/containment/search-excludes.test.ts "a tab gets none of the host user's patterns and keeps its own" |
| SRCH3-6 | Low | layers | Round 2's helper merged the tab's own values across folders and keys, and an object spread of a `__proto__` key defeated its own-property check. | fixed | Values are taken per folder and key, by object spread into fresh objects. | same |
| SRCH3-7 | Medium | queries | Sessions telemetry took excludes for the session's workspace URI and used them for every folder it queried, so a session whose URI isn't the tab's sent the host's patterns. | fixed | Each folder's own excludes. | same |
| SRCH3-8 | Low | tab test | The tab test compared the authority case-sensitively, while URIs keep its case. | fixed | Case-insensitive, in the filter module's tab test for every caller (SRCH3-13). | test/containment/search-excludes.test.ts "a window that is not a tab's keeps upstream's settings" |
| SRCH3-9 | Info | tests | The oracle case passed whatever the chokepoint did, and the structural guard read a fixed list of files. | fixed | The oracle case runs the tree's real step and QueryBuilder with a caller pattern; the guard reads the whole pinned tree. | none |
| SRCH3-10 | Info | residual | Exclude defaults that host-installed extensions contribute, `files.encoding`, the ignore-file and symlink switches, and `editor.wordSeparators` still follow the host in a tab's query. | accepted-residual | Defaults a host extension ships aren't the user's files; the rest are low-entropy switches and encodings that name no file. | none |
| SRCH3-11 | Medium | walk | The sessions empty-file search walks a folder's directories skipping excluded ones, and a tab sees which it is asked to resolve; it was wrongly exempted as local-only. | fixed | Its excludes go through 0060's helper; the exemption is gone. | test/containment/search-excludes.test.ts "a tab gets none of the host user's patterns and keeps its own" |
| SRCH3-12 | Low | tests | The guard missed namespace imports of search's module and files a patch makes callers. | fixed | Any import shape, in the patched sources. | none |
| SRCH3-14 | Info | tab test | Seven `seclab+` prefix tests outside 0060 (in `ipc.ts`, `mainThreadConfiguration.ts`, `seclabDocumentOrigin.ts`, `seclabFixedSettings.ts`, `seclabAhpGateCheck.ts`, `seclabChatSessions.ts`) still compare case-sensitively, so a mixed-case window authority would be a tab to the filter and not to them; nothing lets a tab set a window's authority. | deferred | Centralise every `seclab+` prefix test on `seclabIsTabAuthority` in a follow-up across the patches that own them (rpc session). | none |
| SRCH3-15 | Low | tests | The guard read upstream's files only, not those the series' patches create. | fixed | It reads every file a shipped patch creates too. | none |
| PR68-1 | Low | tab test | With the tab test case-insensitive (SRCH3-13), the tab id parser still took only a lowercase prefix, so a mixed-case tab authority was a tab whose filter and storage partition couldn't be derived (both threw). | fixed | The parser takes the prefix in any case and keeps the id as written. | test/containment/filter-module.test.ts "attachment fails closed: unparseable tab throws, unknown remote is deny-all, local is unfiltered" |
| PR68-2 | Low | tests | The structural guard picked files by upstream's text, so a patch that makes a file its first caller of `getExcludes` was never scanned. | fixed | The guard reads every file as the whole shipped series leaves it; a mutant adds an unwrapped caller through a patch. | none |
| SRCH3-13 | Low | tab test | Round 3's case fix was local to 0060; the filter module's tab test stayed case-sensitive for its other callers. | fixed | `SECLAB_AUTHORITY` matches case-insensitively, and the local lowercase goes. | test/containment/search-excludes.test.ts "a window that is not a tab's keeps upstream's settings" |

PR68-1 and PR68-2 came from the automated review of #68. The filter-module case fails on the tree it
reviewed with the mixed-case authority, and passes on the fix.

Exploring residuals in round 3 found that `[language]` overrides don't leak (neither the folder
query nor the snapshot reads them unfiltered). Reaching SRCH3-10's switches takes no file name.
