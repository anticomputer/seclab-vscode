# Egress prompts through the Tab Manager (plan increment B3)

- **Status:** accepted (B3a, B3b and B3c part 1 landed; B3c part 2 follows)
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
  - The prompt names the tab first (its host folder's basename and tab ID, from tabd's record;
    never `workspaceFolders[].name`, which a `.code-workspace` in the tab sets), then the
    whole destination host (never cut, so its owning domain shows), the first request's method
    and path, how many requests wait, and that the answer covers every request held for that
    destination (the broker holds them under one approval). Then the risk flags in words, the
    tab's own origin label marked unverified, and the process chain with its integrity. An
    `ambiguous` lineage says it may be another process; `none` shows no chain.
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
    window's tab, while the window is focused and `active`, at most once a second.
    Notification buttons and programmatic selection changes don't produce it, so answering a
    prompt can't open the user-action gate. The selection kind alone is not enough: an
    extension in the tab can run `cursorMove` with `source: 'mouse'`, or `type` (review
    BBB-1). `window.state.active` follows the window's own input events, which a command can't
    produce. While the user is working in the window, a tab extension can still fake the kind;
    that only says the user is active, which is then true. A core fix that strips `source` from
    commands run by remote extension hosts belongs with the RPC filter.
  - A user policy file keeps its prompt settings, but `enabled` is the capability AND the
    user's own `enabled` (review BBB-5).
  - Prompts arrive in the window whose tabd owns the tab's broker control connection, which
    is the window that opened the tab. If that window closes while the tab runs, its prompts
    time out and are denied until B3c reconnects control at adoption.

## Consequences
- Unit tests (`tabd/test/broker-supervisor.test.ts`) cover sanitising, capping and dropping
  malformed approvals, the decision checks (unoffered, unknown, another tab's), relaying,
  resolution forwarding and the `userAction` rate limit.
- B3b's tests cover the prompt text (tab first, no link, icon or bidi characters from tab
  text, a long host shown whole, lineage confidence and integrity, the credential wording), the
  button order, and that the broker policy enables prompts only for an approvals-capable client
  and a user policy that doesn't turn them off. Review: [round BBB](../security-reviews/20261106-egress-prompts.md).
- The broker e2e (`./seclab test e2e-broker [oci|sbx]`, also in ci-linux) now runs with prompts
  on and a scripted decider in place of the Tab Manager: a prompt before user action carries
  `no-user-action-yet` and a deny gets 403; a risky destination before user action is denied
  without a prompt; an unanswered prompt is denied at its timeout; a POST outside a GET rule is
  prompted and denied; after `tab.userAction`, allow-once lets the request through.
- **B3c (part 1): control reconnect at adoption.**
  - When tabd adopts a running tab whose supervisor died (`initialize` reconciliation,
    after the fence check), it reconnects to the tab's broker through the driver's
    `openBrokerControl`: the same fixed `seclab-broker control` argv as bring-up.
  - It attaches the same handlers as bring-up: the audit stream, prompts with `tab.event
    opened` and the `approval.list` replay, and the CFS refresh and re-import.
  - The broker's state is left alone: no `policy.load`, no new proxy credential, no CA
    fetch.
  - The fence check has already verified that the running broker is the pinned image.
  - A failed reconnect is audited (`broker.control reattach-fail`). The tab stays adopted, and
    its prompts time out to deny as before.
  - Unit test: a second supervisor over the same state adopts the tab, reconnects without
    touching broker state, and relays the broker's next prompt.
- **Next:**
  - B3c (part 2): recovering the window after its server dies or the local extension host
    restarts (found by the focus probe).
- **B3c (part 2): the window reconnects after its server dies.**
  - The Tab Manager's connection factory runs `tab.ensureRunning` before every reconnect, but
    not on its first call, right after the resolver's own.
  - `tab.ensureRunning` is idempotent and the connection token is the tab's own, so a dead
    REH, or a tab stopped with its supervisor, comes back under the same token.
  - Correction (part 3, focus probe): the window still needs a reload after its server dies.
    The new REH doesn't know the old extension-host session ("Unknown reconnection token"),
    so the window offers its reload at once instead of retrying a missing socket, and the
    reload lands on the restarted tab. A dropped connection to a live REH reconnects without
    a reload.
  - Secret-scan findings on a restart still need the resolver's trusted UI. The reconnect then
    fails and the window offers its reload.
  - tabd e2e (`./seclab test e2e oci`): after the tab's REH processes are killed, a
    connection closes; `tab.ensureRunning` returns the same token and the handshake succeeds
    again.
  - Review [HHH](../security-reviews/20261106-broker-reattach.md): three lows, all fixed.
- **B3c (part 3): `tab.ensureRunning` is idempotent on a running tab.** Found by the focus
  probe on branch build 42289834002: the battery restarted at every step and stopped after
  three, with "Cannot reconnect".
  - Cause: VS Code opens several connections per window (management, extension host), so
    "every call after the first" is not a reconnect. Each ran `tab.ensureRunning`, which
    reconfigured the broker (a fresh proxy password) and started the REH again.
  - On sbx the start was never a no-op. Each `seclab-reh-start` runs in its own Landlock
    domain with signals scoped (`seclab-obs-guard`), so `kill -0` on the previous REH failed
    with EPERM. The live REH looked dead, could not be stopped either, and a second REH took
    its socket ("Unknown reconnection token").
  - Fix, in two layers, each enough on its own (both proven by the sbx e2e):
    - `seclab-reh-start` checks liveness through `/proc/<pid>/cmdline`, not signals. It
      refuses to start a second REH beside one it can't stop. `--check` reports without
      starting anything.
    - The supervisor returns at once for a tab it runs, with broker control up (when
      required) and the REH alive under the tab's token (`Driver.rehAlive`, which runs
      `seclab-reh-start --check` as the tab user).
  - The fast path also requires the sandbox to be running, and on sbx a live collector session
    (an adopted tab has none, and its next `ensureRunning` restores observation). The probe
    holds a per-tab lock that quarantine's stop also takes, since `sbx exec` boots a stopped
    VM. Quarantine and an external stop take the tab out of `Running`.
  - `rehAlive` is tab-asserted (the tab owns the pid and token files and can fake a match). It
    only saves a restart and never gates a security step.
  - Trade-off: the per-connection secret rescan and deny sync no longer run on a running tab.
    Nothing is remounted then; the fence is still checked on every `tab.connect` and by the
    monitor.
  - tabd e2e: a second `tab.ensureRunning` keeps the REH pid. With the fast path removed and
    the old template, it fails (pid 386, then 444). The REH kill step now fails unless it
    killed something; it had matched nothing on Linux CI (wrong uid).
  - Review [III](../security-reviews/20261106-reh-idempotent.md): one medium and three lows,
    all fixed. The unit test proves III-1 by injection: without the running-sandbox check it
    probes a stopped tab.
  - Focus probe, branch build 42295175158: exit 0, with no steal. The battery ran in one pass
    from step 0 to `server-connection-lost`; before, it restarted at every step.
  - The `--skip server-connection-lost` variant: no steal. After `restart-extension-host` the
    window stays disconnected: the managed socket factory dies with the local extension host
    ("No socket factory found for Managed(1)"). This is still open.
