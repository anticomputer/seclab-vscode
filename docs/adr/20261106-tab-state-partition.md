# A tab's extension state is partitioned by the tab

- **Status:** accepted
- **Date:** 2026-11-06
- **Deciders:** anticomputer (user: "Partition both scopes per tab via a new small patch (key prefixed by tab id, migration off for tabs, rewrite verdict)", keyed "on the tab's stable identity ... so one tab's state persists across its restarts but never crosses tabs", and "Apply the same tab partition to SecretStorage"); RPC-core landing session
- **Related:** [tab is the containment unit](20261104-tab-is-the-containment-unit.md), [no real secret in a tab](20261104-no-real-secret-in-a-tab.md), [RPC filter enforcement points](20261104-rpc-filter-enforcement-points.md), [ordinary-session trace EDR](../edr/20261106-ordinary-session-rpc-trace.md)

## Context
The tab-is-the-containment-unit ADR said cross-tab state (`globalState`, SecretStorage)
"must be partitioned per tab (M4)". Nothing did it, and the RPC filter denied the storage
methods instead. That was not containment: **every activation awaits both mementos**
(`extHostExtensionService.ts` L504-L517 at `a717861c`), so with either scope denied no
extension activates in a tab at all.

Reading the main-thread side showed the gap is wider than cross-tab sharing. The caller
names the extension id, and `ExtensionStorageService` uses that id **verbatim as a storage
key** (`extensionStorage.ts` L159-L177). Unfiltered, a tab can read or write any key of the
profile store (shared by every window) or of the window's workspace store, including:
- the same extension's state written in another tab;
- UI-side extensions' state, such as the Tab Manager's pending routes in `globalState`;
- workbench keys.

SecretStorage keys are `{extensionId, key}`, global across windows, with the id again an
argument.

## Decision
A tab's `globalState`, `workspaceState` and SecretStorage live in a **partition keyed on
the tab's stable id**: the `<tabId>` in its `seclab+<tabId>` authority. tabd mints it once
per workspace claim and persists it (`tabd/src/state.ts`), so a tab keeps its state across
restarts and never sees another tab's. The id comes from the connection
(`seclabPartitionOf`), never from an argument. An unparseable `seclab+` authority throws
rather than falling back to the shared store.

- Patch `0011-seclab-partition-tab-extension-state` (35 changed lines, one concern):
  - `MainThreadStorage` prefixes both scopes with `seclab-tab:<tabId>/`. The shared-key
    watcher maps the prefix back.
  - **Migration is off for tab hosts.** It copies a source id's state into the target, and
    would import unpartitioned state into the partition.
  - `MainThreadSecretState` keys `{seclabTab, extensionId, key}`. `$getKeys` and the change
    listener see only their own partition; trusted hosts keep upstream's shape and never
    see a tab's keys.
- The policy verdict is **`rewrite`**. The filter permits these methods only once the
  customer has registered its rewrite, so a build without 0011 denies them rather than
  reaching the shared store. Each has a shape validator: an extension id, a bounded key, a
  state object.
- `$registerExtensionStorageKeysToSync` stays denied: Settings Sync would carry tab state
  off the box.

Within a partition the extension id is still a claim. That is no weaker than the threat
model already allows: every extension in a tab shares the one extension host a rogue
extension controls.

## Consequences
- Extensions activate in tabs, and their state persists per tab.
- Whatever id a tab claims, it can address only its own partition. The rogue probes
  `state-claim-tab-manager-{read,write}` and `secret-claim-tab-manager-write` claim the Tab
  Manager's id. Against a seeded canary, the harness reads the profile's state database
  host-side (`test/containment/state-db.ts`).
- State a tab wrote before this patch (unpartitioned) is not migrated into its partition.
  Tabs start with empty state once.
- Partition keys of a removed tab stay in the profile store until cleared. This is a hygiene
  item, not a boundary.
- A trusted host's storage is unchanged.
