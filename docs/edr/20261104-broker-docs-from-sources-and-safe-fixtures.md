# Broker docs are generated from, and checked against, the code's sources of truth; fixtures are test-owned only

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** anticomputer (user). Verbatim: "make sure docs stay updated as we work, drift should be prevented where possible" and "make sure our vuln examples are not actively malicious against our host". Broker session (implementation); Fork-build session (CI hook).
- **Related:** [ADR policy and protocol](../adr/20261104-broker-policy-and-control-protocol.md), [security review](../security-reviews/20261104-broker-docs-drift-and-fixtures.md)

## Context
- **Docs could drift from code.** The protocol doc, the capability matrix and
  the policy reference were hand-written. Nothing stopped them from diverging
  from the code, the schema or the tests. The JSON examples were not valid JSON
  (`[Binding]`, `//` comments), and the commands in `broker/AGENTS.md` were
  never run in CI.
- **Some probes could reach real hosts.** Fixtures made probes that would have
  touched non-test endpoints if containment had failed:
  - `1.1.1.1`;
  - `host.docker.internal:22` (a host service);
  - `169.254.169.254` (cloud metadata, on CI runners);
  - the Docker gateway;
  - an external DNS name.
- **The sbx script left room for collisions and leftovers.** It used fixed
  ports and a fixed sandbox name, and never checked that the user's global sbx
  state was untouched.

## Decision
**Sources of truth:**
- `broker/schema/protocol.v1.json` defines every method's params and result,
  every notification, the errors and the audit types. `core.dispatch` validates
  params against it; unit tests validate every result and notification; the
  integration harness validates all live traffic.
- `core.CAPABILITIES` is the capability descriptor. `capabilities.v1.json` adds
  notes, the sbx-native column, and the tests that prove each row.
- The policy schema, `seclab_broker/data/*` and `broker/examples/*`.

**Generated docs.** `broker/tools/docs.py` renders these sections:
- in `docs/broker-protocol.md`: errors, methods, notifications, types and
  audit types;
- the capability matrix in `broker/README.md`;
- in `docs/broker-policy.md`: fields, types, forbidden headers, baseline,
  provider backstop, token rules and examples.

**`broker/docs-check.sh`** runs in the unit image, with no network and the repo
mounted read-only. It fails when:
- a generated section is stale;
- a ```json block lacks a `<!-- check: … -->` annotation or fails validation;
- a ```sh block lacks `<!-- ci: run -->` or `<!-- ci: skip: reason -->`;
- the code's methods, notifications, audit types or error codes differ from
  the definition;
- a capability has no row, or a row names a test that doesn't exist.

`--run-commands` runs every `ci: run` block. `broker/test.sh` runs the check
first. The Fork-build session's docs-check CI job calls
`broker/docs-check.sh --run-commands`.

**Same-change rule** (in `broker/AGENTS.md`): behaviour, definitions, generated
docs and records change in one commit.

**Fixtures are test-owned only:**
- integration probes target `*.example.test` containers, the broker itself,
  loopback, or RFC 5737 addresses;
- link-local and metadata addresses are covered by unit tests, not live
  probes.

**`broker/tools/fixture_lint.py`** (run by docs-check) enforces this. It also
rejects committed literals that look like real tokens. It will be replaced by
the shared `test/safety/fixture-lint.sh` when that lands.

**sbx validation:**
- a random per-run tag;
- ephemeral loopback-only ports;
- explicit removal of the per-sandbox rule;
- teardown on any exit;
- a snapshot of global rules and secrets, compared after teardown, plus a check
  that no sandbox or rule from the run remains.

`SECLAB_VALIDATE_ABORT_AFTER_SETUP=1` exercises the failure path.

## Alternatives considered
- **Hand-written docs plus a reviewer checklist:** rejected. That is exactly
  the drift the user asked us to prevent.
- **Generating docs from Python type hints or dataclasses:** rejected. JSON
  Schema is language-neutral. The TypeScript supervisor (tabd) can validate
  against the same file, and the broker already depends on a validator.
- **Generating the whole protocol doc:** rejected. Transport, lifecycle and
  proxy-behaviour prose isn't derivable from code. Those sections are checked
  through their annotated examples and runnable blocks.
- **Keeping the live probes to real metadata and host addresses for realism:**
  rejected. A regression would turn the test into the attack. Unit tests cover
  the classifier exhaustively.

## Consequences
- Adding a method, notification, audit type, error code or capability without
  updating the definition fails `broker/test.sh` and CI.
- Strict params (`additionalProperties: false`) mean clients must check
  `broker.hello` before using anything newer. tabd has confirmed it sends only
  schema fields.
- A tampered markdown ```sh block marked `ci: run` would execute in CI. The
  blocks are reviewed like code, and CI runs them with read-only repo
  permissions.

## Evidence
- Negative tests (scratch copy in a container), each producing the expected
  failure:
  - an edited generated section;
  - an audit type renamed in code;
  - a capability with no row;
  - a row naming a missing test;
  - an invalid JSON example;
  - an unannotated sh block;
  - an invalid example policy;
  - an external URL, a public IP and a token-shaped literal in fixtures.
- `broker/test.sh` at `e6fdfe7`: docs-check ok, 139 unit and 40 integration
  tests passed, including `test_all_control_traffic_matched_protocol_definition`.
- sbx 0.51, 2026-11-04: all 14 checks passed, "global policy and secrets
  unchanged", and nothing left behind. The abort self-test exited 3 and left no
  sandbox, rule, container or network.
