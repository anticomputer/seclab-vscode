# Process lineage for broker requests

- **Status:** accepted
- **Date:** 2026-11-05
- **Deciders:** coordinator ("Verified lineage on prompts … label the integrity honestly"); tab-observability session
- **Related:** [ADR tab observability §5](../adr/20261104-tab-observability.md) (lineage hints), [EDR broker audit in tab events](20261105-broker-audit-in-tab-events.md), [plan tabd-broker-wiring](../plans/tabd-broker-wiring.md) B3 (prompts) and B6 (attribution), [security review](../security-reviews/20261104-tab-observability.md)

## Context
The broker sees requests but not processes. Its only process hint is the origin label in
the proxy username, which any process in the tab can set, so the broker marks it
unverified. The sensors see processes, but proxied traffic all goes to one place, the
broker. A prompt such as "Tab X wants to reach api.example.com" is far more useful with
"task `env` → bash → node" next to it, provided that line is honest about how sure it is.

## Decision
1. **Join by time, in tabd.** `tabd/src/obs/lineage.ts` keeps each tab's recent sensor
   connects to the broker endpoint (the last 256). These are connects not known to be
   UDP, successful or in progress, and come from the sensors only, never from a
   `trusted` source. For a live broker event that carries a destination, tabd waits
   600 ms so a late or deferred connect can arrive, then takes the connects from 5 s
   before to 0.5 s after it.
   - **One unused connect** in the window: `confidence: single`.
   - **Several:** `ambiguous`, naming the nearest in time and the candidate count.
   - **None:** `none`. For a prompt it still says so; otherwise nothing is emitted.
   
   `single` doesn't prove that this process made the request (point 2).
2. **A connect is used up once it has been attributed.** One connection normally
   carries one request, so concurrent requests aren't all pinned on one connect.
   - A kept-alive connection carries later requests without a new connect. Such a
     request reads as `none` if no other connect is in the window, but is pinned on
     whoever connected next if one is (review LN-2).
   - A tab can therefore steer the chain onto another process it runs. That is
     acceptable only because the chain is display data labelled "probable".
   - The exact join (below) would close this for OCI.
3. **Honest labels.**
   - The result is an `egress.attribution` event, source `detector`, with:
     - `proc` (lineage);
     - `net` (the destination);
     - `detail.confidence` and `detail.candidates`;
     - `cause`: the broker event, then the connects.
   - Integrity is the weakest of the broker event and the candidates: `tab-vm-root`
     under sbx (strace), `host-observed` under OCI (Falco). A `none` result has the
     tab's sensor level too, never `trusted`, because the tab can cause "no process
     observed" with a kept-alive connection or a dropped line (review LN-1).
   - The summary says "probable". The chain is display data that the tab chose: it
     is tagged untrusted and never drives a decision.
   - The broker's origin label stays a separate, unverified claim.
4. **For prompts (B3).** `ObsGlue.promptLineage(tabId, approvalId)` returns the
   attribution recorded for that tab's `approval.requested`. The record is kept per
   tab (64 each), so one tab's prompt flood can't evict another's. If none was
   recorded, it computes one for now and marks it `computed`.
   `lineageFor(tabId, atMs)` always computes, and marks its result `computed` too.
5. **Sensor fixes this needed.**
   - **Thread connects:** strace prints a new thread's lines before its parent's
     `clone()` line, so its connects were anonymous. Connects from a pid with no
     known parent are now held until the collector's next flush (at most about
     150 ms), as exec events already were.
   - **Socket type:** `socket()` is now traced under sbx, so a connect knows its
     socket type, and Falco's `fd.l4proto` gives the same under OCI (`net.proto`).
     glibc's UDP address-selection probes during `getaddrinfo` connect to the
     broker's address too, and were being counted as candidates.
   - **DNS lookups:** they go to the VM's resolvers, which the collector reports from
     `/etc/resolv.conf`. Port 53 to them is no longer flagged `egress.bypass`.

## Alternatives considered
- **Exact join on the client port:** the broker knows the peer port, and Falco gives
  the full tuple under OCI. That would make OCI attribution exact. Under sbx the
  connection reaches the broker through sbx's port forwarding, so the port is lost.
  This needs a broker audit field (`clientPort`); it is the next step for OCI and is
  noted for the broker session.
- **Trust the origin label:** any process can claim any label.
- **Trace `read`/`write` to see the CONNECT line:** too costly, and it would put request
  bytes into the sensor stream.

## Consequences
- Prompts and the Tab Activity view can show "bash → node → curl → api.example.com
  (probable)" with an integrity badge. A tab that controls its VM (sbx root) can
  forge the sensor side, and the label says so.
- Concurrent proxied requests within a few seconds read as `ambiguous`, and a reused
  connection as `none`. Both are stated, never guessed.
- Repeated denials to one destination are aggregated (counted, not emitted), so only
  the emitted ones are attributed.
- **DNS through the tab's own resolver** no longer raises `egress.bypass` or a beacon
  alert. Before this, every lookup did, which was noise. DNS tunnelling through that
  resolver is a blind spot of this layer; sbx's network policy governs that path.
  Port 53 to any other address is still flagged.
- **Socket types are tracked per thread and fd.** `close` and `dup2` aren't traced, so
  a reused fd can carry a stale `udp` label. That only drops a connect from the
  candidates, which reads as fewer candidates or `none`. Bypass detection doesn't use
  `proto`.

## Evidence
- `tabd/test/obs.test.ts`, "lineage: …": these cover single, ambiguous and none, a
  used connect, a UDP probe, and a thread's connect before its clone line.
- `./seclab test obs sbx` and `oci`: a proxied curl's denied request is attributed
  to `sh → curl` as a single candidate, with integrity `tab-vm-root` (sbx) or
  `host-observed` (OCI). The proxied curl raises no `egress.bypass`.
