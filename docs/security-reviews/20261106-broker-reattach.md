# Security review: adopted tabs reconnect broker control (B3c), and the CFS install e2e

- **Date:** 2026-11-06
- **Scope:** round HHH:
  - `474e82f`: `attachBroker`/`reattachBroker`, `Driver.openBrokerControl`;
  - `1cf3e23`: the `tabd/test/e2e-cfs.ts` install path, test only;
  - their fixes.
- **Threat model:** an adopted tab must reconnect to its own, pinned broker only, without two
  controllers or a reset of its state, and a user's settings must hold across the gap.
- **Records:** [EDR egress-prompts](../edr/20261106-egress-prompts.md),
  [EDR cfs-feeds-tabd](../edr/20261106-cfs-feeds-tabd.md).
- **Prompt injection:** none found.

## Round HHH
Nothing medium or higher. Confirmed:
- the reconnect uses the bring-up argv and container name;
- adoption follows the fence check, which verifies the pinned broker image;
- `hello` checks protocol, tab and schema;
- tabd reattaches only when the lease holder is dead;
- CFS usage counters survive a re-import within one broker;
- the e2e installs run in the tab with scripts off and hashes required, and the token is only
  compared, never printed.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| HHH-1 | Low | tabd | A reattach kept the dead supervisor's prompt mode, and surfaced prompts to a client that can't answer them. | Fixed | Prompts are surfaced only to an approvals-capable client. Otherwise held requests time out to deny, as with no controller. |
| HHH-2 | Low | tabd | Feeds turned off while no control connection existed were not applied to the running broker. | Fixed | A reattach with feeds off removes the feed rules, revokes the credential (sentinel rotated) and removes the tab's config, idempotently (tested). |
| HHH-3 | Low | Tab Manager | The modal promised a budget "over the tab's lifetime", but the broker keeps usage in memory per start. | Fixed | The text, the comment and PROTOCOL.md say per tab start. |
