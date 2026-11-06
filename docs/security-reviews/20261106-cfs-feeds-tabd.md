# Security review: CFS package feeds in tabs, tabd side (B4)

- **Date:** 2026-11-06
- **Scope:** round EEE, `20fb5bb` and its fixes:
  - the token source (`tabd/src/cfs.ts`);
  - `tab.packages.set` and the CFS import in the supervisor;
  - the feed install script, and the drivers' `installFeed`;
  - `seclab-tab-env`;
  - the Tab Manager's package-feeds command.
- **Threat model:** the user's Azure DevOps token must never reach the tab, a log or disk.
  Only the user turns feeds on, per tab. The tab must not be able to choose the feed, the
  tenant or the scope, and turning feeds off must take effect.
- **Records:** [EDR cfs-feeds-tabd](../edr/20261106-cfs-feeds-tabd.md),
  [ADR cfs-package-feeds-in-tabs](../adr/20261105-cfs-package-feeds-in-tabs.md).
- **Prompt injection:** none found.

## Round EEE
Confirmed:
- no token path to the tab, logs, argv, notifications or disk;
- the install line is validated twice and written with a fixed `printf` format;
- the broker refuses dot segments and encoded separators, so the `**` binding can't be
  traversed;
- `credential.needed` is filtered by id and sentinel;
- concurrent token requests share one `az` run, and an expired token is refused.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| EEE-1 | Medium | tabd | A revision 6 broker's `credential.import` ignores `budget`, so the CFS credential would have had no limit, contrary to what the modal says. | Fixed | Enabling and importing are refused below broker policy schema revision 7. The test asserts the refusal now, and runs the full path from revision 7. |
| EEE-2 | Medium | tabd | A background import waiting for `az` could land after the user turned feeds off. Disable also swallowed broker errors and reported success. | Fixed | CFS work runs one step at a time per tab. The import re-checks after the token and after importing, and undoes itself if feeds were turned off or the broker changed. If the broker doesn't confirm the removal, the tab is stopped and the error reported. A test holds `az` across a restart and a disable. |
| EEE-3 | Medium | Tab Manager | Until the RPC filter lands, tab code can open the command, and a timed Enter accepts the modal's default button. | Fixed | After the modal, the user must type a fresh random 4-letter code. |
| EEE-4 | Low | tabd | `installFeed` on sbx could start a stopped sandbox without `ensureRunning`'s checks. | Fixed | Only a running sandbox is touched; otherwise the setting applies at the next start (tested). |
| EEE-5 | Low | seclab-tab-env | The pip URL pattern's `*` could span `@` and `/`. | Fixed | The password is cut out and must be a `seclab_cfs_` sentinel of base64url characters, and the rest must equal the fixed URL exactly. Sentinels everywhere match exactly what tabd mints. |
