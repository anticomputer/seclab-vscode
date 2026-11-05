# AGENTS.md: broker/

Instructions for an agent picking up the broker cold. Root rules live in
[../AGENTS.md](../AGENTS.md); they all apply here. Every command in this
file has been run. Anything not yet built is marked **TODO**.

## What this is, and its trust boundary
- **What it is.** There is one broker per tab: mitmproxy 12.3.1 plus our addon,
  in a container. It is the tab's only egress. It enforces a default-deny
  policy, holds denied requests while the user is asked, and swaps sentinels
  for real credentials only in the header a binding names.
- **Trust.** The broker is **trusted**; the tab is **hostile**. The threat
  model is a rogue extension in full control of its tab. The broker's client is
  the host supervisor (`seclab-tabd`), which is trusted. It talks to the broker
  over `docker exec -i … seclab-broker control`.
- **Invariant (user decision):** no real secret ever enters a tab, including
  derived secrets. Real values live only in broker memory: never on disk, in
  env, argv, logs, audit events or error messages.
- **Isolation domain.** Under sbx the tab is a microVM and the broker is in
  Docker Desktop's VM. Under OCI they share a kernel, which is a weaker class
  (see the README matrix).

## Layout
| Path | What |
|---|---|
| `seclab_broker/policy.py` | Engine-agnostic: schema validation, host/path canonicalisation, `Rule`/`Binding`/`Inject`, baseline, provider backstop. **No mitmproxy imports.** |
| `seclab_broker/credentials.py` | Sentinels, in-memory values, encoding variants, scanners, `scrub()` |
| `seclab_broker/scanner.py` | Minted-token detection (rules in `data/token-rules.json`) |
| `seclab_broker/netguard.py` | Upstream address guard and broker-local address discovery |
| `seclab_broker/core.py` | `Broker`: state, approvals, JIT waits, audit, every `rpc_*` control method |
| `seclab_broker/protocol.py` | Loads `schema/protocol.v1.json` (+ policy definitions); validators used by dispatch and tests |
| `seclab_broker/control.py` | NDJSON JSON-RPC server on the unix socket; stdio bridge |
| `seclab_broker/engine_mitmproxy.py` | The only mitmproxy-specific code (hooks) |
| `seclab_broker/__main__.py` | `seclab-broker run` / `control`; hardening, CA, mitmproxy options |
| `seclab_broker/data/` | Baseline, `providers/github.json` (backstop), `token-rules.json` |
| `schema/policy.v1.schema.json` | Policy schema (copied into the image's `data/`) |
| `schema/protocol.v1.json` | Control-protocol definition: the single source for dispatch validation, tests and generated docs |
| `schema/capabilities.v1.json` | Capability matrix notes, sbx-native column, and the tests behind each row |
| `tools/docs.py`, `docs-check.sh` | Doc generator and drift checker (`--write`, `--run-commands`) |
| `tools/fixture_lint.py` | Fixtures may only target test-owned endpoints; no token-shaped literals |
| `tools/supplychain.py`, `tools/pin_check.py` | Strict requirements and Dockerfile parsers shared by both gates; every external base image pinned by digest; the one canonical hash-checked, binary-only pip command; every image and pin present in `deps.json`; `--self-test` covers known bypass forms (offline, run by docs-check) |
| `deps.json` | Dependency register: tier, source, expected publisher for every image, Python pin, system package set and host tool |
| `provenance-check.sh`, `tools/provenance.py`, `tools/verify-images.sh`, `tools/attest/` | Online provenance gate: PyPI-served hashes, PEP 740 publishers, sigstore verification bound to the pinned sha256 and the registered workflow (hash-locked verifier image), signed image provenance (`gh attestation verify`) |
| `examples/` | Example policies, validated by unit tests |
| `tests/unit/` | pytest, run inside the broker image with `--network none` |
| `tests/integration/` | Pod-shaped suite: harness container + docker.sock |
| `tests/sbx/` | Real sbx fence validation (host: docker + sbx only) |

## Commands (all verified; `ci: run` blocks run in CI via `broker/docs-check.sh --run-commands`)
Build and test, in containers:

<!-- ci: run -->
```sh
broker/build.sh
broker/test.sh
broker/test.sh -k "absolute_form"
docker run --rm --network none seclab-broker-unit:test
broker/docs-check.sh
```
- `build.sh` verifies the mitmproxy base image's signed provenance, then
  produces `seclab-broker:dev`.
- `test.sh` runs docs-check, then the dependency provenance gate
  (`provenance-check.sh`; needs network and `gh`), then the unit tests, then the
  integration suite.
  It takes about a minute after the first build. Arguments are passed to
  pytest for the integration suite.
- The unit image `seclab-broker-unit:test` exists after `test.sh` has run;
  `docker run` it, as in the block above, to rerun only the unit tests.

Regenerate generated doc sections after changing the protocol, schema, data,
examples or capabilities:

<!-- ci: skip: rewrites files; CI runs the read-only check above -->
```sh
broker/docs-check.sh --write
```
Real sbx fence. Results land in `.work/broker/sbx-validation/results.txt`:

<!-- ci: skip: needs sbx (nested virtualisation), unavailable on hosted runners -->
```sh
broker/tests/sbx/validate.sh
```
Driving the protocol by hand, with a fake host, against a throwaway broker:

<!-- ci: run -->
```sh
docker run -d --name sb-smoke-$$ --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /run/seclab:rw,nosuid,nodev,noexec,size=16m,uid=1000,gid=1000,mode=0700 seclab-broker:dev
trap 'docker rm -f sb-smoke-$$ >/dev/null' EXIT
sleep 3
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"broker.hello"}' \
  '{"jsonrpc":"2.0","id":2,"method":"health"}' \
  '{"jsonrpc":"2.0","id":3,"method":"policy.load","params":{"policy":{"version":1}}}' \
  | docker exec -i sb-smoke-$$ seclab-broker control
```
For an interactive fake host, use `tests/integration/controller.py`
(`Controller(container).call(method, params)`; `handlers[...]` auto-answer
notifications).

## Docs, schema and protocol: single sources of truth
| Source | Feeds |
|---|---|
| `schema/protocol.v1.json` | Request validation in `core.dispatch`; result and notification validation in the tests; generated sections of [docs/broker-protocol.md](../docs/broker-protocol.md) |
| `schema/policy.v1.schema.json` | `Policy.from_json`; generated sections of [docs/broker-policy.md](../docs/broker-policy.md) |
| `core.CAPABILITIES` + `schema/capabilities.v1.json` | `broker.hello`; the generated matrix in [README](README.md#engine-capability-matrix) |
| `seclab_broker/data/*`, `examples/*` | Runtime behaviour; generated sections of the policy doc |

`broker/docs-check.sh` (run by `test.sh`, and in CI) fails when:
- any generated section is stale;
- any ```json block in the broker docs lacks a `<!-- check: … -->`
  annotation, or fails validation;
- any ```sh block lacks a `<!-- ci: run -->` or `<!-- ci: skip: reason -->`
  annotation;
- the code's methods, notifications, audit types or error codes differ from
  `protocol.v1.json`;
- a capability flag lacks a matrix row, or a row names a test that doesn't
  exist.

**Same-change rule.** A behaviour change and the docs that describe it (the
protocol or schema JSON, generated docs, README, this file, and the ADR or EDR)
go in **one commit**. That includes changes made while integrating the broker
into the supervisor. Never edit inside `BEGIN GENERATED` blocks; edit the source
and run `--write`.

### Changing the schema or protocol safely
- **Schema `version` is an integer.**
  - Additive, optional fields with a default that keeps today's behaviour stay
    `version: 1`.
  - Anything that changes meaning, removes a field, or makes an old policy
    validate differently needs `version: 2`, a new schema file, and a parser
    that keeps accepting v1.
- **The schema is also enforced by Python checks** (canonical hosts,
  forbidden inject headers, explicit binding methods). Change both together and
  add unit tests.
- **fastjsonschema gotcha:** it rewrites an unescaped `$` to `\Z` anywhere in a
  pattern, including inside a character class, and Python 3.15 rejects that.
  Escape a literal `$` as `\\$`.
- **The validator must never fetch.** `policy.py` strips `$id` and installs
  handlers that refuse http, https and file refs; `protocol.py` reuses them.
  Keep it that way: an earlier version fetched the `$id` URL from the network.
- **Protocol:**
  - New methods, notifications, optional params and result fields keep
    `seclab-broker/1`. Anything else bumps the major in `__init__.PROTOCOL`
    and in `protocol.v1.json`.
  - Params are strict (`additionalProperties: false`), so clients must check
    `broker.hello` before sending anything newer.
  - Tell the Fork-build session, which owns `seclab-tabd`.

## Engine capability matrix
See the generated [README matrix](README.md#engine-capability-matrix).
- **mitmproxy** (OCI, or behind the sbx fence) does everything.
- **The sbx native proxy** cannot hold and resume, or bind a credential by
  path or method, so it is a fallback only and never used for credentials.

To add a capability:
1. Add the flag to `core.CAPABILITIES`.
2. Add a row to `schema/capabilities.v1.json` that names the tests proving it.
3. Run `--write`.

## Matcher invariants that must never regress
Each has a unit or integration test; grep for the phrase.

**Hosts**
- Host comparison happens only after `normalize_host`: lowercase, no trailing
  dot, IDNA, IPv4-mapped IPv6 converted to IPv4.
- Numeric or hex host forms (`2130706433`, `0x7f.1`, `127.1`), zone ids, `%`,
  `_` and empty labels are rejected.
- `*.example.com` matches strict subdomains only.

**Paths**
- Matching is on the decoded canonical path.
- Rejected: `.`/`..` segments, `//`, `;`, `\`, encoded `. / \ ; % NUL`,
  invalid UTF-8 and control characters.
- Allow and bind globs are case-sensitive. Backstop globs are
  case-insensitive and tolerate a trailing `/`.

**Methods**
- `X-HTTP-Method-Override`, `X-HTTP-Method`, `X-Method-Override` and a
  `_method` query parameter are rejected.

**Authority**
- The `Host` header, HTTP/2 `:authority`, the HTTP/1 absolute-form authority,
  the TLS SNI and the CONNECT target must all equal the request host and port;
  otherwise `421`.
- HTTP/1 is always forwarded in origin-form.

**Rules and bindings**
- Rules default to `https` on port 443. Cleartext needs `schemes: ["http"]`.
- Bindings never match `http`.
- Binding methods must be explicit (no `*`).

**Credentials**
- Injection happens only into `binding.inject.header`, only when the sentinel
  sits in that header (raw, or inside Basic). The header is overwritten, never
  find-and-replaced.
- A sentinel anywhere else (other header, URL, body, trailer, WebSocket frame)
  is misplaced: blocked in `block` mode and never swapped.
- The provider backstop is checked before any injection. It beats bindings.

**Responses and approvals**
- On injected flows and bound hosts:
  - raw echoes become sentinels;
  - other encodings block;
  - minted tokens are derived or redacted;
  - session headers are stripped.
- Binding approvals are keyed by credential, origin, method, path and inject
  spec, and a decision never releases a request that the approved binding does
  not cover.

**Prompts (folder-open loaders, beacons)**
- `allow-tab` is never offered for a raw IP, an IP-in-hostname name or a
  risky destination, and `approval.decide` rejects any decision the approval
  didn't offer.
- An approval-sourced rule or binding must cover the held request, and must
  never name a raw IP or overlap a risky destination (`pattern_overlaps_risky`).
  The broker enforces this even when the client asks otherwise.
- Before the first `tab.event userAction`, risky and raw-IP egress is denied
  without a prompt. Raw IPs are denied by default even after a user action.
- Every way into a prompt goes through the rate limit, the cooldown and the
  `deny-new-destinations` checks.
- The baseline and examples never match the risky list (enforced by
  docs-check).
- The origin label is display-only. Never use it for a decision.

**Proxy auth and upstream guard**
- Proxy auth happens before everything. Unauthenticated requests are never
  held, prompted, resolved or connected.
- The upstream guard resolves the name itself, denies if *any* address is
  non-public or broker-local, and pins the vetted IP.

**Hook failures**
- Hooks fail closed (`@fail_closed`): an exception yields 502, a dropped frame
  or a server error, and never passes the flow through unchanged.

## Known pitfalls
- **Adding or bumping a dependency:**
  1. Update the lock with hashes. For a closure, use `pip-compile
     --generate-hashes` in a container.
  2. Run `python broker/tools/provenance.py report <req files>` inside the
     `broker/tools/attest` image.
  3. Record the tier and publisher in `deps.json`.
  4. Run `broker/provenance-check.sh`.

  Never set a publisher from the provenance you are checking: confirm the
  repository is the project's real one. Lockfiles installed into the mitmproxy
  image may pin only pure `py3-none-any` wheels.
- **Requirements files and Dockerfiles have one accepted shape**
  (`tools/supplychain.py`). Do not add extras, URLs, markers, pip options,
  `# syntax=`, `ADD` or other installers. Extend the parser, its `self_test()`
  vectors and the EDR together if a new form is truly needed.
- **Never relax the provenance gate to skip on network errors.** It must fail
  closed.
- **Fixtures must only target test-owned endpoints.** That means
  `*.example.test`, the broker, loopback, or RFC 5737 addresses.
  - Never probe real hosts, metadata IPs, the Docker gateway or host ports,
    even in "should be blocked" tests. A regression turns the probe into an
    attack.
  - Two lints enforce this, and both run from `broker/test.sh`:
    - `tools/fixture_lint.py` is broker-scoped and stricter. Opt a line out with
      `# fixture-lint: ignore`.
    - The repo-wide `test/safety/fixture-lint.sh broker/tests` is shared and owned
      by the Fork-build session. It also checks host-secret paths,
      persistence, destructive and download-exec calls. Opt a line out with
      `fixture-lint: allow <rule> -- <reason>`. `test.sh` skips it, with a
      notice, if the script isn't in the tree yet.
- **The sbx script never touches global sbx state.** It snapshots that state
  and verifies it at teardown.
  - New sbx probes must target this run's own loopback ports.
  - Per-sandbox rules must be removed in `cleanup()`.
- **The broker's networks must be attached before `docker start`.**
  `local_addresses()` reads `/proc/net/route` once.
- **mitmproxy logs hook exceptions and continues.** That is why
  `@fail_closed` exists. Keep it on every hook.
- **In mitmproxy, `connection_strategy` must stay `lazy`.** `eager` connects
  upstream at CONNECT time, before the policy decision.
- **`rawtcp=False`, plus `tcp_start`/`udp_start` kill.** Non-HTTP inside a
  tunnel must never be forwarded.
- **curl through the broker negotiates HTTP/2 by default,** so header names
  arrive lowercase. Compare them case-insensitively.
- **In the test pod, `NO_PROXY=localhost` makes `curl http://localhost…`
  bypass the proxy.** Use `--noproxy ""` when probing the broker's own
  loopback guard.
- **Python 3.13+ `ssl` rejects CAs without `keyUsage`.** The test upstream CA
  is generated with it.
- **Test upstreams sit on a public-range subnet (`11.250.x.0/24`)** because the
  guard refuses private addresses, with no test backdoor.
- **sbx specifics:** the allow rule must name `localhost:P`, not
  `host.docker.internal:P`. Set both cases of the proxy variables. `curl
  --noproxy "*"` also disables `-x`.
- **`PR_SET_DUMPABLE=0`** makes `/proc/1/*` unreadable to `docker exec`
  sessions. That is intended: custody tests assert it.

## TODO
- **Supervisor integration (`seclab-tabd`)** is owned by the Fork-build session.
  The contract is in the protocol doc.
- **sbx-native adapter (fallback):** not built. Its capability column is
  documented only.
- **Per-extension attribution** (distinct uids, ARCHITECTURE §8), SSH-agent
  filtering, cloud-CLI credentials, and the MCP gateway.
- **GitHub App user tokens:** mint downscoped ones in the broker instead of
  injecting long-lived tokens.
- **Name-constrained per-tab CA.**
