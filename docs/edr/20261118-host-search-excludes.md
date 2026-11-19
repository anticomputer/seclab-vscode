# The host user's search and watcher excludes stay on the host

- **Date:** 2026-11-18
- **Status:** accepted. Proof passed, unit and runtime (2026-11-19).
- **Owner:** the RPC follow-ups session (register owner `rpc`).
- **Related:** [search in tabs](20261117-search-in-tabs.md) (0051),
  [configuration snapshot](20261112-tab-configuration-snapshot.md) (0036),
  [review record](../security-reviews/20261118-host-search-excludes.md).

## Context
SRCH-3 found that a tab's search provider was sent the host user's `files.exclude` and
`search.exclude` patterns, which name the host user's own files and folders. 0051 dropped the open
editors outside the tab from the query; the patterns stayed. The project owner decided on
2026-11-18 that the host user's search-exclude settings don't reach a tab: a tab's search uses the
defaults and the tab's own settings. The patterns reached the tab three ways:
- in search queries sent to the tab's provider: QueryBuilder's folder queries, and the queries
  other features build by hand from the merged settings (explorer find, the chat file picker,
  prompt-file discovery);
- in the watch requests the window sends the tab for its workspace folders, as
  `files.watcherExclude` excludes and `files.watcherInclude` paths, the same kind of pattern;
- in the configuration snapshot the tab's extension host receives (0036), which lets a core
  setting cross from host layers when its leaves are booleans, as exclude maps' are.

## Decision
Patch 0060, in a `seclab+` window:
- For a folder on a tab, a setting that names files takes its value from the tab's own layers: the
  defaults, the tab's remote user settings and the folder's own settings
  (`seclabTabSettings.ts`). A single folder's settings are both its folder and its workspace layer,
  so the workspace layer is left out: a workspace file's settings could be anywhere. The host
  user's settings, application settings, policy and in-memory values are never read for it.
- Every place that builds the settings part of a search query for a folder reads its
  `files.exclude` and `search.exclude` that way: QueryBuilder's folder queries, and the queries
  explorer find, the chat file picker, prompt-file discovery and sessions telemetry build by hand.
  So does the sessions empty-file search, whose walk skips excluded folders in requests the tab
  sees (review SRCH3-11).
  A caller's own patterns (what the user typed, or what an extension passes to `findFiles`) are
  never touched, so a query says nothing about the host's settings. An earlier version removed host
  patterns where a query leaves for the tab; that also removed a caller's matching pattern, which
  let a tab test guesses against the host's settings (review SRCH3-4).
- The watch requests for a tab's workspace folder take `files.watcherExclude` and
  `files.watcherInclude` the same way.
- The filter module's tab test (`seclabIsTabAuthority`) compares the authority case-insensitively,
  as URIs keep its case (review SRCH3-13).
- The snapshot never lets `files.exclude`, `search.exclude`, `files.watcherExclude`,
  `files.watcherInclude`, `files.readonlyInclude`, `files.readonlyExclude` or
  `explorer.autoRevealExclude` cross from host layers: their keys are glob patterns naming the
  user's files, and their values are booleans that 0036's text rule lets through.

The tab's remote user settings count as the tab's own: they are written by and kept in the tab
(and 0059 keeps their location there). Windows that aren't a tab's are unchanged. A unit check
lists every call that builds a query's excludes from settings and requires 0060's helper there,
so a new one fails until it is wrapped or listed as local-only.

## Proof
- **Unit:** `test/containment/search-excludes.test.ts` (`./seclab test search-excludes`, in
  `./seclab test rpc-filter`) runs upstream's own QueryBuilder folder query, the hand-built queries
  of the chat file picker and sessions telemetry, `doSearch`, `watchWorkspace` and 0036's snapshot
  filter, with this tree's 0060, against host canary patterns. On main every path carries them;
  with 0060 none does, the defaults and the tab's own patterns stay, a caller's patterns reach the
  tab untouched, and a window that isn't a tab's is unchanged. A whole-tree check requires every
  caller of search's `getExcludes` and every reader of `files.watcherExclude`, in upstream and in
  the files the series creates, to go through 0060's helper or be listed with why it sends nothing
  to a tab. Each of ten mutants brings its leak back.
- **Runtime:** `test/containment/search-probe.ts excludes-baseline|excludes-patched` in a real OCI
  tab of the containment test build. The host user settings exclude two canary files by name, one
  through `files.exclude` and one through `search.exclude`; the tab's own workspace settings exclude
  a third. The probe extension records whether the host patterns are in its configuration and which
  files `findFiles` returns; Quick Open looks for the `search.exclude` file. Both runs passed 14/14
  with every positive control (the probe ran, both searches were typed, the tab's own exclude held)
  and a clean teardown:
  - Baseline: Actions run 44439744560, main `b3c6525c`. The host patterns were in the tab's
    configuration, `findFiles` in the tab didn't return the `files.exclude` file, and Quick Open
    didn't find the `search.exclude` one.
  - Patched: Actions run 44448577665, this branch at `9930790d`. Neither host pattern was in the tab's
    configuration, `findFiles` returned the `files.exclude` file and Quick Open found the
    `search.exclude` one. The later change on this branch (PR68-1) only lets the tab id parser take
    the prefix in any case; it touches none of the exclude paths.

## Consequences
- A tab's search, file watching and extensions follow the defaults and the tab's own exclude
  settings. Exclude settings a user wants in tabs go in the tab's folder or remote user settings,
  not in a multi-root workspace file (ARCHITECTURE §4.8).
