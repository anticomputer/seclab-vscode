# Security review: egress prompts (B3a, B3b)

- **Date:** 2026-11-06
- **Scope:** round BBB, `ec43825..79dcbea`:
  - tabd's approval relay (`tabd/src/approvals.ts`, `supervisor.ts`);
  - the Tab Manager prompt (`extensions/seclab-tab-manager/src/prompts.ts`);
  - the prompts capability (`initialize`, `broker-policy.ts`).
- **Threat model:** a tab's broker holds egress the policy doesn't list, and the user decides.
  Everything in an approval is tab-influenced. Nothing may be allowed without an explicit click,
  one tab's decision must not answer another's, and the tab must not be able to fake the user
  activity that relaxes the broker's early-after-open defence.
- **Records:** [EDR egress-prompts](../edr/20261106-egress-prompts.md).
- **Prompt injection:** none found.

## Round BBB
Confirmed:
- every tab-influenced field goes through `quote` (no links, icons, bidi or invisible characters);
- dismissal and expiry send nothing and the broker denies; a late click is refused by the Tab
  Manager and again by tabd's pending check;
- deny is first, "Allow for This Tab" last, and nothing is pre-selected;
- decisions are routed per tab; only the Tab Manager declares the prompts capability.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| BBB-1 | Medium | Tab Manager | An extension in the tab can run `cursorMove` with `source: 'mouse'`, or `type`, so the local window sees a Mouse or Keyboard selection change and sends `tab.userAction`. That turns off the broker's auto-deny of risky destinations before user action. | Fixed (mitigated) | `tab.userAction` also requires `window.state.focused && window.state.active`, which follow the window's own input, not commands. A core fix (strip `source` from commands run by remote extension hosts) is passed to the RPC filter work. |
| BBB-2 | Medium | tabd | `quote` cut long hosts from the right, so `api.github.com.<padding>.attacker.example` showed only its trusted-looking start. | Fixed | The host is never cut (`HOST_RE` caps it at 253); test with a long host. |
| BBB-3 | Low | tabd | The broker holds every request to one destination under one approval, but the prompt showed only the first request's method and path. | Fixed | The text says "first request", the number waiting, and that the answer covers every held request for the destination. |
| BBB-4 | Low | Tab Manager | The prompt named the tab from `workspaceFolders[0].name`, which a `.code-workspace` in the tab sets. | Fixed | Named from tabd's `hostPath` basename plus the tab ID. |
| BBB-5 | Low | tabd | A user policy file was used as is, so its `prompt.enabled` ignored whether a client could answer. | Fixed | `enabled` is the capability AND the user's setting; other prompt settings are kept. |
