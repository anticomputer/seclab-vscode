# Egress prompts through the Tab Manager (plan increment B3)

- **Status:** accepted (B3a and B3b landed; B3c follows)
- **Date:** 2026-11-06
- **Deciders:** Coordinator (the plan's prompt decision: visual grouping is fine, but each tab's decision stays separate, the originating tab shows on every prompt, the broker's per-tab rate limit stays, and there is no "apply to all"). Fork-build session: implementation.
- **Related:** [plan tabd-broker-wiring](../plans/tabd-broker-wiring.md), [B1](20261105-oci-tab-broker.md), [B2](20261105-sbx-tab-broker.md), [broker protocol](../broker-protocol.md), [request lineage](20261105-broker-request-lineage.md)

## Context
With B1 and B2, every tab egresses through its broker, but prompts were off: anything not in
the policy was denied. B3 makes a held request visible to the user, who can allow it once,
allow it for the tab, or deny it.

## Decision
- **B3a: tabd plumbing** (`tabd/src/approvals.ts`, `supervisor.ts`).
  - On every (re)connect to a tab's broker, tabd subscribes to `approval.requested` and
    `approval.resolved`.
  - It sends the broker `tab.event opened`, which resets the user-action clock, so a
    folder-open loader is gated.
  - It replays `approval.list`, so prompts pending across a reconnect resurface.
- **Forwarding to the Tab Manager.** A requested approval is sanitised and forwarded as
  `tab.approval` with the request's process lineage:
  - the approval ID must match a strict pattern;
  - host and port are validated;
  - only known decisions pass, and strings are capped;
  - at most 64 are pending per tab;
  - lineage is quoted data, never a decision input.

  Resolution, including timeouts and deny-rule matches, is forwarded as
  `tab.approval.resolved`.
- **`tab.approval.decide`** relays only a decision that this tab's pending approval offered.
  Another tab's approval, an unknown one or an unoffered decision gets `-32602`, so one
  decision answers one approval of one tab. Every decision is audited (host, decision), with
  no tab text beyond the host.
- **`tab.userAction`** relays the broker's `tab.event userAction`, at most once a second per
  tab. The client must send it only for ordinary editor work, never for consent dialogs.
- **Prompts stay off by default** until the Tab Manager can answer them (B3b). Turning them on
  earlier would hold every unlisted request until it times out.
- **B3b: the Tab Manager prompt** (`extensions/seclab-tab-manager/src/prompts.ts`; text and
  buttons in `tabd/src/approvals.ts` so they are unit-tested without VS Code).
  - Prompts are on only for a tabd whose client declared `initialize`
    `client.capabilities.approvals: true`. The Tab Manager does; the CLI, the e2e harness and
    older clients don't, so their tabs keep the deny-all policy instead of holding requests
    nobody can answer. The flag is read when a tab's broker policy is built, at its start.
  - The prompt names the tab first, then the destination, the method and path, the risk flags
    in words, the tab's own origin label marked unverified, and the process chain with its
    integrity. An `ambiguous` lineage says it may be another process; `none` shows no chain.
    Every one of these strings is tab-influenced and goes through `quote`, so it can't render
    as a link, an icon or bidi-reordered text.
  - Buttons: Deny, Deny All New Destinations, Allow Once, Allow for This Tab, in that order,
    filtered to the decisions the broker offered. VS Code never pre-selects a notification
    button. Dismissing or ignoring the prompt answers nothing, and the broker denies it at
    its timeout. A click after `tab.approval.resolved` (answered elsewhere, timed out, or a
    deny rule) says so and sends nothing.
  - Warning severity when there are risk flags or a credential is involved; information
    otherwise.
  - `tab.userAction` comes only from keyboard or mouse selection changes in an editor of this
    window's tab, at most once a second. Notification buttons, commands and programmatic
    selection changes don't produce it, so answering a prompt can't open the user-action gate.
  - Prompts arrive in the window whose tabd owns the tab's broker control connection, which
    is the window that opened the tab. If that window closes while the tab runs, its prompts
    time out and are denied until B3c reconnects control at adoption.

## Consequences
- Unit tests (`tabd/test/broker-supervisor.test.ts`) cover sanitising, capping and dropping
  malformed approvals, the decision checks (unoffered, unknown, another tab's), relaying,
  resolution forwarding and the `userAction` rate limit.
- B3b's tests cover the prompt text (tab first, no link, icon or bidi characters from tab
  text, lineage confidence and integrity, the credential wording), the button order, and that
  the broker policy enables prompts only for an approvals-capable client.
- **Next:**
  - B3c: control reconnect at adoption, and recovering the window after its server dies or
    the local extension host restarts (found by the focus probe).
