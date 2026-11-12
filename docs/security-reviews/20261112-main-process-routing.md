# Security review: main-process routing (patch 0041)

- **Date:** 2026-11-12
- **Scope:** round VVV, by an Opus-class model:
  - `patches/0041-route-local-folder-opens-to-tabs.patch`;
  - the Tab Manager's `/open` URI handler (`extensions/seclab-tab-manager/src/extension.ts`);
  - `seclabTabRouter` in `build/product/overrides.json` and `product.jq`, the
    `check-release --desktop` markers;
  - the driven test `test/driver/cli-open.ts`.
- **Threat model:** the trusted host editor must never load a local folder or workspace in a
  window, because core features would then act on the host for attacker-controlled folder
  content ([ADR](../adr/20261104-route-folder-opens-in-main.md),
  [EDR](../edr/20261112-main-process-routing.md)).

## Round VVV
One high, one medium. Confirmed:
- every caller traced reaches `WindowsMainService.open`: CLI and second instance, native host
  opens and the renderer's `hostService.openWindow`, empty windows, the agents window,
  extension development windows, protocol links (including `workspace` URLs) and session
  restore;
- the only other way a window gets a workspace is `enterWorkspace`, now refused; a reload only
  re-validates the workspace a window already has;
- a tab can't forge the trusted hand-over: `trusted` is set only by main, and an extension's
  `openExternal` never carries it. An outside link still gets upstream's prompt and the Tab
  Manager's confirmation;
- the query survives the trip (both ends use `URLSearchParams`; the URI travels as
  components);
- the test isn't vacuous: auto-attach is armed before the first page, the reporter is
  installed before the paused page resumes, and missing or unresolved reports fail;
- `product.jq` and the new check-release markers fail closed.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| VVV-1 | High | routing rule | A local `.code-workspace` that declares a `remoteAuthority` in its own contents wasn't routed, and loaded its local folders in a window; the same claim also turns off the local-window guards (0003, 0042). | Fixed | 0041 routes every workspace file, local or remote (a tab doesn't support multi-root), and every `file:` folder whatever authority comes with it; no window enters a workspace. `cli-open.ts` opens such a file; the build without 0041 fails it. |
| VVV-2 | Medium | check-release | The release gate checked the guards' log strings but not product.json's `seclabTabRouter`, without which both guards are off. | Fixed | `--desktop` requires it in every product.json of the app; self-test case without it. |
| VVV-3 | Low | Tab Manager | "Already a tab" (which skips the confirmation) compared paths case-insensitively, so on Linux a case variant of a tab's folder was claimed without confirmation; newly reachable from a link. | Fixed | Case-insensitive only off Linux. |
| VVV-4 | Low | Tab Manager | One rejected request poisoned the request chain, so later opens were dropped silently. | Fixed | The chain recovers, and a failure is shown. |
| VVV-5 | Info | hand-over | Upstream's URL router matches `window:<id>` unanchored, so the hand-over could reach a window whose id starts with the same digits. Host side only. | Accepted | The Tab Manager reuses a window only when it is empty with no editors. |
| VVV-6 | Info | behaviour | `--add`/`--remove` with a local folder now offer a tab; several local folders arrive as one untitled workspace (unsupported); local untitled workspaces are not restored. All fail closed. | Accepted | Recorded in the EDR. |
| VVV-7 | Info | test | "Received the open" matched any toast naming the folder, including the Tab Manager's error. | Fixed | It waits for the confirmation text itself. |
