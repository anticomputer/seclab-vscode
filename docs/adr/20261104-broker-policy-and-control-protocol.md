# Broker policy is a versioned, engine-agnostic JSON document; the broker is driven by JSON-RPC over exec stdio

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** Project owner (2026-11-04): scope, and a preference for proven components over new ones; broker session; coordinator
- **Related:** [ADR single broker, sbx fence](20261104-single-broker-sbx-fence.md), [ADR no real secret enters a tab](20261104-no-real-secret-enters-a-tab.md), [protocol](../broker-protocol.md), [security review](../security-reviews/20261104-broker-m2-m3.md)
- **Editorial redaction (2026-11-12):** quotations of project conversations replaced with neutral statements; decisions unchanged.

## Context
ARCHITECTURE.md §4.5 sketches a per-tab policy
(`allow: [{host, methods, path}]`, `credentials: [{id, bind, inject}]`) and an
exec-stdio control channel. Several parties consume the contract:
- the tab supervisor (`seclab-tabd`, Fork-build session);
- the editor's prompts;
- possibly a different proxy engine later (smokescreen or Envoy).

Policy must change at runtime. Nothing may listen on the host.

## Decision
- **Policy v1 is a JSON document validated by
  [`broker/schema/policy.v1.schema.json`](../../broker/schema/policy.v1.schema.json)**
  (draft-07). It contains:
  - `allow[]`: `{id?, host, schemes?, ports?, methods?, path?}`. The default is
    `https`, the scheme's default port, any method, and `/**`.
  - `credentials[]`: `{id, bind: Binding | Binding[], inject?, provider?, sentinelPrefix?}`.
    A binding is `{host, path, methods, ports?, inject?}`, and `inject` is
    `{header, fmt}`. The broker, never the caller, picks where the value goes.
  - Settings: `prompt{…}`, `sentinelMismatch`, `baseline` and `tabId`.

  Hosts are canonical ASCII names, strict-subdomain wildcards, or IP literals.
  Paths are globs over the decoded canonical path. The document names only
  HTTP concepts and no engine internals.
- **Matching code is engine-agnostic** ([`policy.py`](../../broker/seclab_broker/policy.py)).
  An engine adapter produces a `RequestView` (scheme, host, port, method,
  canonical path, query) and applies the decisions.
- **Control is JSON-RPC 2.0, one JSON object per line.** The client runs
  `docker exec -i <broker> seclab-broker control`, which bridges stdio to a
  private Unix socket inside the broker. The client sends requests and the
  broker sends notifications, as specified in [docs/broker-protocol.md](../broker-protocol.md).
- **Versioning:**
  - The schema `version` integer changes only for breaking changes; additive
    optional fields stay v1.
  - The protocol is `seclab-broker/<major>` with the same rule.
  - `broker.hello.capabilities` lets clients degrade explicitly.

## Alternatives considered
- **Engine-native config** (mitmproxy script options, Envoy xDS, smokescreen
  ACL YAML): rejected. It ties the supervisor and prompts to one engine, which
  is exactly what §4.5 says to avoid.
- **The proxy process's own stdio as the channel** (`docker run -i`): rejected.
  The channel dies with the client, so the supervisor could not reconnect after
  a restart, and only one client could attach. The bridge keeps "nothing
  listens on the host" and adds both.
- **A TCP or HTTP control API on the broker:** rejected. It would be a
  listening socket the tab, or other host processes, might reach.
- **LSP-style `Content-Length` framing:** rejected. NDJSON is simpler to drive
  by hand (`printf … | docker exec -i`), and vscode-jsonrpc and other
  libraries can speak it.
- **Broker-to-host requests** (the broker asks and the host answers): rejected
  in favour of notifications plus host-called methods. Approvals survive client
  reconnects (`approval.list`), and several clients can attach.
- **The `jsonschema` library:** rejected because it pulls in `rpds-py` (Rust)
  with no wheel for Python 3.15 in the base image. `fastjsonschema` is pure
  Python and hash-pinned.

## Consequences
- The supervisor needs no knowledge of mitmproxy. Swapping engines is an
  adapter change, with the same tests.
- Rules added with `allow-tab` live in the broker until the next
  `policy.load`. The supervisor persists them from `policy.changed`.
- The schema must stay readable by other validators (for example ajv in the
  TypeScript supervisor). Escape `$` inside character classes (see
  [broker/AGENTS.md](../../broker/AGENTS.md)).

## Evidence
- Implementation: [`policy.py`](https://github.com/anticomputer/seclab-vscode/blob/b398fedca43f78e5152a26bec0b3d5e9de7a579f/broker/seclab_broker/policy.py), [`core.py`](https://github.com/anticomputer/seclab-vscode/blob/b398fedca43f78e5152a26bec0b3d5e9de7a579f/broker/seclab_broker/core.py), [`control.py`](https://github.com/anticomputer/seclab-vscode/blob/b398fedca43f78e5152a26bec0b3d5e9de7a579f/broker/seclab_broker/control.py).
- Tests (`broker/test.sh`): 128 unit and 38 integration tests passing at
  `b398fed`, including protocol error handling (`test_control_protocol_errors`).
- mitmproxy hold and resume: `Flow.intercept/resume/wait_for_resume`
  ([flow.py](https://github.com/mitmproxy/mitmproxy/blob/51c1d6b2d8d3367a773411eb7a3eeccec82b3ea7/mitmproxy/flow.py)).
  The proxy server awaits `wait_for_resume` after each hook
  ([mode_servers.py](https://github.com/mitmproxy/mitmproxy/blob/51c1d6b2d8d3367a773411eb7a3eeccec82b3ea7/mitmproxy/proxy/mode_servers.py)).
- Docker Sandboxes rule granularity (method, path, query):
  https://docs.docker.com/ai/governance/local/network-rules/. Tokenizer's
  rule that the issuer sets the injection target:
  https://github.com/superfly/tokenizer.
