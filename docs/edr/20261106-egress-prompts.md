# Egress prompts through the Tab Manager (plan increment B3)

- **Status:** accepted (B3a landed; B3b and B3c follow)
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

## Consequences
- Unit tests (`tabd/test/broker-supervisor.test.ts`) cover sanitising, capping and dropping
  malformed approvals, the decision checks (unoffered, unknown, another tab's), relaying,
  resolution forwarding and the `userAction` rate limit.
- **Next:**
  - B3b: the Tab Manager prompt (originating tab, host prominent, flags and quoted lineage,
    default deny, `allow-tab` never pre-selected, no "apply to all"), `userAction` from editor
    input, and prompts on by default;
  - B3c: control reconnect at adoption, and recovering the window after its server dies or
    the local extension host restarts (found by the focus probe).
