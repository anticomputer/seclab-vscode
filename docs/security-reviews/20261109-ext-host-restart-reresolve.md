# Security review: patch 0040, Restart Extension Host re-resolves a managed authority

- **Date:** 2026-11-09
- **Scope:** round OOO, `da4bad4` and its fix:
  - `patches/0040-reresolve-managed-authority-on-restart.patch`
    (`AbstractExtensionService.startExtensionHosts`);
  - `build/apply-patches.sh` (two patches may not share a number), the reserved-range header in
    `patches/series`, and the `ci-unit` injection;
  - `test/focus/probe.ts` and the probe extension (`restart-extension-host` is no longer terminal).
- **Threat model:** the resolver and its socket factory are UI-side and trusted. Code in the tab
  must not be able to choose which authority or resolver the window uses, nor get a connection
  that bypasses the Tab Manager's binding checks.
- **Records:** [EDR ext-host-restart-reresolve](../edr/20261109-ext-host-restart-reresolve.md),
  [round NNN](20261109-level-b-repair.md).
- **Prompt injection:** none found.

## Round OOO
No medium or higher findings; two lows. Confirmed:
- the re-resolved authority is the window's own `environmentService.remoteAuthority`, fixed at
  window creation; the tab has no input into it;
- the re-resolve goes through the local extension host's resolver (the Tab Manager), which
  checks the tab id and the folder binding again; there is no WebSocket fallback, since that
  branch only takes authorities without `+`;
- a dead `Managed(id)` fails closed ("No socket factory found"); an unresolved authority
  (`getConnectionData` null) leaves upstream's behaviour unchanged;
- a late `_setResolvedAuthority` can't overwrite a settled request (`DeferredPromise` ignores a
  second completion);
- workspace trust's remote authority is resolved once at startup and is unaffected;
- the ci-unit step interpolates no untrusted `${{ }}` data and asserts the exact refusal
  message; the duplicate-number check runs after comments and whitespace are stripped and the
  strict `NNNN-*.patch` form is enforced, so it can't be bypassed by padding.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| OOO-1 | Low | overlapping restarts | A second restart during the first's re-resolve saw the authority already cleared, so it skipped the re-resolve; the first then completed the second's request with a factory from a stopped host. Recovery needed a reload. | Fixed | The managed authority is remembered once seen, and each restart takes a generation number; a resolution whose generation is stale is dropped, so only the newest restart completes the request. |
| OOO-2 | Low | tab-triggered restarts | Until the RPC filter lands, tab code can run `workbench.action.restartExtensionHost` (or the install/uninstall path) through `$executeCommand`. Each restart now re-runs the UI-side resolver, so a tab can repeat the Tab Manager's prompts. Prompt pressure, not a boundary crossing. | Deferred to the RPC filter | Recorded in the EDR as a requirement for the RPC series: deny that command and the extension install/uninstall commands to `seclab+` callers. |
| — | Residual | reconnect overlap | Upstream's own `_resolveAuthorityAgain` on `onReconnecting` can interleave with a restart. It resolves through the current local host, and the window recovers by reload in the worst case. | Accepted | Upstream behaviour, unchanged by 0040. |
