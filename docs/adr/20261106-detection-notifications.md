# Detection notifications and a cross-tab detections summary

- **Status:** accepted
- **Date:** 2026-11-06
- **Deciders:** Project owner (2026-11-06): unexpected or possibly malicious events must be surfaced to the user, with notifications that carry clear explanations and actions, plus a cross-tab summary; coordinator (scope, severity list, anti-spoofing requirements); tab-observability session; broker session (deny rules)
- **Related:** extends [ADR tab observability](20261104-tab-observability.md) §4 (consumers), [ADR agent events](20261105-agent-events-tab-reported.md), [EDR broker request lineage](../edr/20261105-broker-request-lineage.md), [ADR RPC capability filter](20261104-rpc-capability-filter.md), [ADR write-back gate](20261104-write-back-gate.md), [protocol](../tabd/PROTOCOL.md), [security review](../security-reviews/20261104-tab-observability.md)
- **Editorial redaction (2026-11-12):** quotations of project conversations replaced with neutral statements; decisions unchanged.

## Context
High-severity detections only badged the Tab Activity view and revealed it once, and an
unobserved tab turned the status bar red. A user working in the editor could miss both.
The project owner requires unexpected, possibly malicious events to be surfaced clearly, with actions, and
a view across tabs. Notifications are also a new attack surface: a hostile tab chooses
much of the text an event carries (paths, commands, host names). It must not be able to
word, forge, multiply or suppress what the user is told, or turn a notification into a
link or command.

## Decision
1. **Who notifies.** Each window's Tab Manager notifies for its own tab, from tabd's event
   stream for that tab. Replayed history never notifies. A local window has no tab and
   shows nothing; the cross-tab summary covers every tab.
2. **What notifies (severity tuning).** The `notifyKind` table in
   `tabd/src/obs/notify.ts`, unit-tested, decides:

   | Notifies | Doesn't notify |
   |---|---|
   | Honeypot reads | `egress.bypass` attempts (the fence stops them) |
   | Download piped into an interpreter | Beacons |
   | A network tool started from the extension host right after open (critical form only) | Routine broker denials |
   | Host-executable workspace writes | Non-critical network tools, credential-path opens |
   | Container-socket access, root inside the tab | Everything `tab-reported` |
   | Sensor tampering | |
   | An ungated agent connection, an agent-gate denial burst | |
   | Broker findings: misplaced sentinel, backstop, blocked token | |
   | Trusted only: tab unobserved, fence failure, quarantine, broker loss | |

   The non-notifying events stay in the Tab Activity view and the summary.
   Held write-back changes keep their own review prompt
   ([ADR](20261104-write-back-gate.md)).
3. **What it says.**
   - A trusted template per kind: what happened and why it matters, in plain language.
   - The originating tab, named from tabd's record (the folder's name), never from tab text.
   - Quoted facts: file, destination, process chain, with the event's integrity in words
     ("seen inside the tab's VM; root in the tab could fake it").
   - Tab-chosen text is quoted and cleaned (`quote()`):
     - control, bidi, zero-width and line-separator characters are removed;
     - markdown link brackets become look-alikes;
     - `://`, `command:`, `vscode:`, `file:` and `http(s):` are broken;
     - codicon syntax is defused;
     - the result is capped.

     No markdown, link or command can come from a tab.
4. **Actions.** Every action is an explicit button press.
   - **Stop Tab**.
   - **Open Activity**.
   - **Review Held Changes**: when the gate holds items, or for host-executable writes.
   - **Block Destination**: broker events with a destination only. It calls
     `tab.egress.block`, which adds a broker deny rule that precedes every allow, the
     baseline and prompts, and replays it on every start. It is offered only when the
     tab's broker reports `capabilities.denyRules` (broker schema revision 5). Until
     then there is no button that doesn't actually block.
   - **Dismiss**.
   
   Non-modal: notifications never take focus.
5. **Coalescing and rate limits** (`NotificationGate`).
   - A kind repeated in one tab within 5 minutes folds into a count, shown once when
     the window closes. 5000 `ahp.deny-burst` events produce one notification and one
     "4999 more".
   - At most 3 notifications a minute per window. Beyond that, one summary
     notification says how many events in how many tabs weren't shown, names their
     kinds, and points to the summary view.
   - The trusted-only kinds (unobserved, fence failure, quarantine, broker loss) skip
     the per-minute budget (review NT-1). A tab could otherwise spend the budget on
     cheap detections and then hide "this tab is no longer observed". Per-tab coalescing
     still bounds them.
6. **Anti-spoofing.** A tab can only make a notification happen by causing a real
   detection. It can't write one:
   - notifications come only from tabd's stream, which takes integrity from its source;
   - `tab-reported` events never notify;
   - the RPC filter keeps every `seclab.*` command unreachable from tabs (default deny,
     no grant; unit-tested);
   - view actions re-check the tab id against tabd's tab list;
   - stopping another window's tab asks first.
7. **Cross-tab summary.** The **Detections (All Tabs)** view uses the new
   `tab.detections.query`. It reads every tab's persisted log (running or stopped,
   whichever supervisor wrote it; at most 16 MiB per tab and 500 events) plus this
   supervisor's unflushed ring.
   - Filters: severity, tab, rule.
   - Actions: Stop Tab, Open Tab.
   - Plain-text tree only; no webview, no markdown.
8. **A record of what was shown.** Each notification is appended to
   `<globalStorage>/seclab.tab-manager/notifications.jsonl` (0600, rotated at 1 MiB).
   That supports audit and the e2e harness.

## Alternatives considered
- **One notifier for all tabs in every window:** each window would repeat every other
  tab's alerts. The summary already gives the cross-tab view.
- **Webview cards with rich formatting:** a webview is an HTML surface fed by
  tab-influenced text. A plain TreeView and plain notification text can't be scripted.
- **"Block" by removing allow rules:** the broker policy was allow-only, so a wildcard
  allow or a prompt could let the host back in. A real deny list was asked of the broker
  session instead.
- **Modal alerts:** they steal focus, and a tab could provoke them on purpose.

## Consequences
- A malicious workspace (Contagious Interview) now produces a visible, explained,
  actionable alert, not just a log line.
- A tab can make the user see "something happened" (by doing it), but it can't choose
  the words or invent a kind. Rate limits bound the noise.
- **Block Destination** appears once the broker's deny rules land (revision 5). tabd's
  side is in place and tested against a fake broker.
