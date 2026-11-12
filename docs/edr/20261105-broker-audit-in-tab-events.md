# Broker audit events in the tab's event stream

- **Status:** accepted
- **Date:** 2026-11-05
- **Deciders:** coordinator (assignment: broker events into the stream); tab-observability session
- **Related:** [ADR tab observability](../adr/20261104-tab-observability.md), [broker protocol §4](../broker-protocol.md), [ADR broker output is data](../adr/20261104-broker-output-is-data.md), [plan tabd-broker-wiring](../plans/tabd-broker-wiring.md), [security review](../security-reviews/20261104-tab-observability.md)
- **Editorial redaction (2026-11-12):** quotations of project conversations replaced with neutral statements; decisions unchanged.

## Context
sbx and OCI tabs now run behind their broker (B1, B2), and tabd owns each broker's control
channel. The observability ADR names broker `audit.event` as a `trusted` source, but nothing
consumed it yet. The broker sends one notification per audit event and keeps the last 2000
(`audit.tail`). Its `seq` restarts with each broker process. Its strings are already
scrubbed (no real value, no sentinel). tabd doesn't rely on the broker's own `untrusted`
list: it tags fields itself (below).

## Decision
1. **Every broker audit event becomes a `trusted` event with source `broker`.**
   `tabd/src/obs/broker-audit.ts` maps each documented type to a class and priority:
   `egress.request`, `egress.approval`, `credential.use`, `broker.status`, and a new
   `model.call` class for model calls, body-policy denials and budget denials. An unlisted
   type becomes a `broker.status` notice that carries only its type name.
2. **Allowlisted fields only; tab text lands in tagged fields.**
   - The host and port go into `net`.
   - Method, path, reason, location, header, server, origin label and the broker's
     `detail` go into `detail` keys. tabd always tags these as untrusted.
   - Broker identifiers (`auditType`, `scheme`, `by`, `provider`, `approvalId`,
     `credentialId`, …) count as vocabulary only while they keep vocabulary shape, and
     are tagged otherwise. `rule` is always tagged: rules added by an `allow-tab`
     approval are named by the host the tab chose (review BA-2).
   - Everything passes through `normalizeDraft`: escaped, capped, at most 16 detail keys.
   - The origin label is stored with `originVerified: false`.
3. **Replay and dedupe.** When a control channel attaches:
   - tabd subscribes first, then replays `audit.tail` (2000 events), then drains events
     that arrived during the replay;
   - events are deduplicated by `seq`;
   - a new broker process is detected by its `broker.started` `ts`, or by a tail whose
     seqs all lie below the last one seen, and the sequence is reset;
   - a stale replay from an older channel is ignored (attach generation);
   - a jump in `seq` emits a `broker-audit-gap` status event with the count missed;
   - an event naming another tab is dropped and reported.
4. **Aggregation and rate.** Every audit type a tab can trigger cheaply is aggregated:
   allowed requests, injections, denials, upstream and TCP/UDP blocks, prompt-limit
   denials, model denials and budget denials, stripped sessions, redacted tokens,
   waiting credentials and findings.
   - Keys use broker-determined fields only: type, host, port, rule, credential,
     provider and hook. A tab can't mint keys by varying a method, a header name or a
     reason.
   - The first event per key goes out at once. Repeats within 10 s become one event
     with `count`.
   - Each type holds up to 64 keys at a time, and 1024 overall. Beyond that, events go
     out on their own, so aggregation never loses a record.
   - Prompts, credential lifecycle events and model calls are emitted one by one.
   - **One rate bucket per audit type.** A flood of one type can only drop events of
     that type, and the drop is reported with the type: critical for findings,
     warning otherwise.
     - Findings (`error` or worse): 20/s, burst 200.
     - Other types: 100/s, burst 1000.
     - Broker events share no bucket with other sources (review BA-1).
5. **No new channel and no host action.** The feed reads the control channel tabd
   already owns. Nothing in an audit event drives a host action.
6. **Detection context.**
   - **Broker endpoint.** The driver tells tabd the broker's endpoint inside the tab:
     - sbx: `host.docker.internal:<port>`. The port comes from the host. What that
       name resolves to in the VM is reported by the collector, so recognising broker
       connects rests on `tab-vm-root` data, like every sbx sensor event;
     - OCI: the broker's address on the pod network (`docker inspect`, host side),
       port 8080.
     
     A connect to it is no longer an `egress.bypass`. Before this, every proxied
     request was flagged.
   - **Beacons through the broker.** Proxied traffic all goes to the broker's
     address, so connects to it are no longer beacon candidates.
     - The feed hands each denied or blocked request to the beacon rule before
       aggregation, timed by the broker's clock and keyed by the real destination.
     - That state is kept apart from the sensors' beacon state (review BA-3), and
       its detections are rate-limited like findings.
     - A periodic proxied beacon is a `beacon.periodic` with the integrity of its
       cause: the latest broker event emitted for that destination, normally
       `trusted`. If the hub dropped that event, an older one or none is cited.
     - Limit: only denied or blocked proxied requests are timed. A periodic
       request to an allowed destination isn't a beacon candidate, because routine
       polling would drown the rule.

## Alternatives considered
- **Parse the broker's stderr `{"audit": …}` lines:** this duplicates the control
  channel, and stderr has no replay.
- **Re-report through the Tab Manager (`tab.events.report`):** this adds a second
  producer for the same fact, and a path through the workbench.
- **Emit every allowed request:** an `npm install` would fill the ring and the rate
  bucket with routine events and push out the denials.

## Consequences
- The Tab Activity view and `seclab tab logs` show egress decisions, prompts, credential
  use, model calls and backstop findings next to the process events.
- Lineage on prompts is the next increment: joining broker requests to exec and connect
  events (plan B6).
- An event dropped by its type's rate bucket is counted and reported with its type. A
  tab that floods one type with distinct destinations (for example, many hosts under a
  wildcard allow rule) can still lose other events of that same type past the burst.
  This is the residual of a bounded host. The drop report carries the first and last
  broker `seq` dropped, so the records can be found in the broker's own audit log.

## Evidence
- `tabd/test/broker-supervisor.test.ts`, "broker audit: …": a fake broker replays
  `broker.started` and a denial, then streams a duplicate, three allowed requests, a
  model call, a foreign-tab event and a seq jump. The test checks that:
  - the events arrive once, as `trusted`;
  - tab text is tagged untrusted;
  - the aggregate carries `count: 2`;
  - the gap (2 missed) and the drop are reported.
- `./seclab test unit`: 115 pass. This includes the review regressions: a 6000-denial
  flood followed by `sentinel.misplaced` (BA-1), a tab-named `rule` tagged (BA-2),
  restart detection by seq, and a stale replay.
- `./seclab test obs sbx` and `oci`, against a real broker: a proxied request to an
  RFC 5737 address arrives as a trusted `request.denied_unprompted` with its tab text
  tagged, and `broker.started` is replayed.
