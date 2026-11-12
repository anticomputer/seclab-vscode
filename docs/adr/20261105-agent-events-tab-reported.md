# Agent events in the tab's stream: a fourth integrity label, `tab-reported`

- **Status:** accepted
- **Date:** 2026-11-05
- **Deciders:** coordinator (assignment: agent event classes for the secure-agentic work); secure-agentic session (event shapes, sources); tab-observability session
- **Related:** extends [ADR tab observability](20261104-tab-observability.md) (integrity labels, `tab.events.report`), [ADR agents run in the tab](20261105-agents-run-in-the-tab.md), [EDR broker audit in tab events](../edr/20261105-broker-audit-in-tab-events.md) (`model.call`), [event reference](../tabd/EVENTS.md), [security review](../security-reviews/20261104-tab-observability.md)
- **Editorial redaction (2026-11-12):** quotations of project conversations replaced with neutral statements; decisions unchanged.

## Context
Agents now run in the tab ([ADR](20261105-agents-run-in-the-tab.md)). The trusted renderer
mediates the Agent Host Protocol (AHP) between the workbench and the tab's agent host
through three components: a transport gate, a reverse-request layer and an authenticate
module. Their decisions are facts produced outside the tab. The agent host's own account
of what it does (sessions, turns, tool calls) is not: the tab writes it, and the
renderer only relays it. The existing labels don't fit that. `tab-vm-root` means "seen
by root in the tab's VM", which a tab *user* can't forge. The agent host's account is
forgeable by the tab user.

## Decision
1. **A fourth integrity label, `tab-reported`, the weakest:** `tab-reported <
   tab-vm-root < host-observed < trusted`. It means "the tab says so". It is context
   only and never a basis for a decision. A detection takes the weakest integrity of
   its causes, as before.
2. **New sources, all reported by the trusted client over `tab.events.report`.** Each
   source has a fixed integrity and a pinned set of classes; tabd never takes integrity
   from the report.

   | Source | Integrity | Classes |
   |---|---|---|
   | `ahp-gate`, `ahp-reverse`, `ahp-credential` | `trusted` | `ahp.decision` |
   | `agent-host` | `tab-reported` | `agent.session`, `agent.turn`, `agent.tool` |

   - `agent.tool` carries a tool name and a sha256 digest of the arguments, never the
     arguments themselves. No class carries prompt text, message bodies or a credential
     value.
   - The reporting surface is unreachable from the tab: the renderer reaches the Tab
     Manager over a non-command `MainThreadSeclab*` service, as RPC-filter decisions do.
3. **Separate rate buckets.** A tab can make the gate deny, or make its agent host
   chatter, so `ahp-*` and `agent-host` each get a bucket shared with nothing else.
   Neither can push out RPC-filter decisions, workspace-watch events, or each other.
4. **Detections.**
   - **`ahp.ungated`** (critical, trusted): the renderer reports `ahp-gate.opened`
     for every agent-host connection and `ahp-gate.verified` once its gate is in
     place. Opened with no verified within 2 s means an ungated transport.
     - Both signals are trusted, so the tab can't forge them.
     - The tab can't drop them either (review AE-1):
       - tabd watches them on the validated report, before any rate limit;
       - they are recorded in a bucket of their own that gate denials can't drain;
       - the detection is stamped directly, outside every bucket;
       - beyond 64 connections awaiting verification in one tab (1024 overall), a new
         one is reported at once (fail closed).
   - **`ahp.deny-burst`** (warning, trusted): 20 or more gate denials within 60 s.
   - **`suspicious-content`** also scans tool names, AHP methods, action types and
     resource hosts.
   - **Model budget:** comes from the broker (`model.call` class:
     `model.budget_exceeded`, `model.denied`), not from the agent host.
5. **Not detected here: an agent runtime running outside a tab (invariant I8).** No
   sensor watches the macOS host, by design. I8 is enforced by removing the local
   agent host and checked by probe A27.

## Consequences
- The Tab Activity view and `seclab tab logs` badge `tab-reported` events as "tab says"
  (`TAB-SAYS`). The view's tooltip says the tab can make them up.
- The secure-agentic work must flatten its `ahp` object into `detail` (at most 16 keys,
  no dots), send rule ids as `detail.gateRule`, and use Falco priority names. That was
  agreed with that session.
- Once the renderer emits, `agent.tool` events can be joined to the sbx collector's
  process events: a tool call that runs a shell also shows up as `tab-vm-root` exec
  events. That join is not built yet.
