# Exact request lineage on OCI via the broker's client port

- **Status:** accepted
- **Date:** 2026-11-06
- **Deciders:** coordinator (2026-11-06: use `clientPort` for exact OCI attribution, and keep the integrity label honest, because the port is tab-influenced); broker session (`clientPort` in request audits, broker 0.5.0); tab-observability session
- **Related:** extends [EDR broker request lineage](20261105-broker-request-lineage.md) (its "exact join on the client port" alternative), [ADR detection notifications](../adr/20261106-detection-notifications.md) (Block Destination), [security review](../security-reviews/20261104-tab-observability.md) round 11
- **Editorial redaction (2026-11-12):** quotations of project conversations replaced with neutral statements; decisions unchanged.

## Context
The time join in the lineage EDR is a guess: concurrent requests read as `ambiguous`,
a kept-alive connection as `none`, and a tab can steer the chain onto another of its
processes (review LN-2). Broker 0.5.0 now puts `clientPort`, the tab-side TCP source
port of the proxy connection, in every request summary. Under OCI the tab reaches its
broker on the pod network with no NAT, so that port is the one the sensor saw at
`connect`.

## Decision
1. **The sensor records the source port.** The Falco connect rule adds `%fd.cport`,
   the client end of the connection (`%fd.lport` is the server's: it read 8080). The
   parser falls back to the client side of `tuple=…:port->…`, and drops anything
   outside 1–65535. It lands in the schema as `net.localPort`.
2. **tabd joins on it first.** For a broker event with `clientPort`, the correlator
   takes the most recent connect to the broker with that `localPort`, up to 10 minutes
   back (a kept-alive connection) and 0.5 s ahead. That gives `confidence: exact`,
   `detail.joinedBy: client-port` and the summary "(matched by connection)". With no
   match it falls back to the time join, unchanged.
3. **Integrity stays the sensor's** (`host-observed` under OCI). The join makes it
   certain that the request and the connect are the same TCP connection, but it does
   not raise trust in what the sensor reported about the process.
4. **The port is tab-chosen** (any process can `bind` before `connect`), so
   `detail.clientPort` is tagged untrusted on the broker event although it is a
   number. A tab that binds a port another of its processes used earlier gains nothing
   new: the most recent connect with that port wins, and that is its own connection.
5. **sbx keeps the time join.** Its connections reach the broker through sbx's port
   forwarding, so `clientPort` is the forwarder's port, which no in-VM connect has.
   No sbx connect carries `localPort` (strace records none), so the exact branch never
   fires there.
6. **Repeats are emitted once.** Exact matching ignores the time join's used-up flag
   (an exact match still sets it), so every event on a kept-alive connection can join
   it. An exact join for the same port and
   destination within a second of the last is not emitted again; a prompt's
   `approval.requested` always is, since prompts look their lineage up by approval id.

## Alternatives considered
- **Raise integrity to trusted on an exact match:** the process details still come
  from the sensor; only the join is certain.
- **Treat the port as trusted because the broker observed it:** the broker observed
  it, but the tab picked it. The tag says who controls the value, not who saw it.
- **Exact join under sbx via the forwarder's mapping:** sbx doesn't expose it.

## Consequences
- Under OCI, prompts and the Tab Activity view show the process chain for the exact
  connection, including later requests on a kept-alive connection. The e2e asserts
  every OCI attribution is `exact` (`./seclab test obs oci`).
- LN-2 (steering by timing) no longer applies under OCI when the broker reports the
  port. It still applies under sbx, and the label still says "probable" there.
- Ephemeral ports are reused. The 10-minute bound and "most recent first" keep a reused
  port from joining a connection that has since closed, as long as the sensor saw the
  newer connect.
