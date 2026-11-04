# Security review: broker docs-drift tooling, protocol enforcement and fixture safety

- **Date:** 2026-11-04
- **Scope:** `1bcae4b..e6fdfe7`, plus the follow-up in this commit. Areas given explicit attention:
  - params validation in `core.dispatch` against `protocol.v1.json`: bypasses,
    semantic drift from the handlers, defaults injection, error-message echo,
    remote `$ref`, ReDoS;
  - the wildcard-binding guard in `engine_mitmproxy.py`;
  - `broker/tools/docs.py`, `fixture_lint.py` and `docs-check.sh`, including
    `--run-commands` piping markdown into bash;
  - test fixtures and `broker/tests/sbx/validate.sh` (host services, external
    endpoints, the user's global sbx state, failure paths, published ports).

  Threat model: ARCHITECTURE.md §2 and §4.5, plus the rule that no real or
  derived secret enters a tab, with a rogue extension in full control of its tab.
- **Reviewer:** `security-review` agent (default model; did not refuse). It ran
  the unit suite, `docs.py check` and `fixture_lint.py` in the unit image, and
  probed fastjsonschema 2.22.3 directly. It did not run sbx. Triage by the
  broker session.
- **Related:** [EDR docs from sources and safe fixtures](../edr/20261104-broker-docs-from-sources-and-safe-fixtures.md), [ADR policy and protocol](../adr/20261104-broker-policy-and-control-protocol.md)

## Findings
| # | Severity | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| 1 | Medium (self-found before review) | Credential import | The first use of an unconfirmed imported credential built `suggestedBinding` from the path the tab chose. A literal `*` in that path became a glob, so `allow-tab` would have confirmed a wildcard binding. | fixed `30b8975` | The prompt is refused if the path contains `*` or cannot be expressed as an exact binding. The reviewer confirmed `*`/`**` are the only glob metacharacters, and that `%2A` is caught because the check runs on the decoded path. | `test_unbound_credential_never_offers_a_wildcard_binding` |
| 2 | Medium (self-found, fixture audit) | Test fixtures | Probes would have touched real endpoints if containment regressed: `1.1.1.1`, `host.docker.internal:22` (a host service), `169.254.169.254` (cloud metadata on CI), the Docker gateway, and `example.com`. | fixed `e6fdfe7` | Probes go only to test-owned targets. Metadata and link-local cases are unit-tested. `fixture_lint.py` enforces this. | `test_upstream_address_guard`, `test_proxy_unaware_clients_fail_closed`, fixture lint |
| 3 | Low (self-found, fixture audit) | sbx validation | Fixed ports and sandbox name. No explicit removal of the per-sandbox rule. No check that the user's global sbx state was untouched. | fixed `e6fdfe7` | Random per-run tag; ephemeral loopback ports; explicit rule removal; teardown on EXIT, INT and TERM; global snapshot compared after teardown; leftover check. | `SECLAB_VALIDATE_ABORT_AFTER_SETUP=1` self-test (exit 3, nothing left) |
| 4 | Info (review) | sbx validation | Only broker 1's published port was asserted to be loopback-only. | fixed (this commit) | Broker 2 is now asserted too. | n/a (script assertion) |
| 5 | Info (review) | docs-check | `CHECKED_DOCS` listed this record before it existed, so `docs-check` (and therefore `test.sh`) failed. | fixed (this commit) | This file now exists. | docs-check |

What the reviewer confirmed has **no issues**:
- **Dispatch validation.** The schema only narrows. Handler checks still run;
  injected defaults equal the handlers' defaults; messages never contain
  values (only unexpected property names, from the trusted client, scrubbed);
  there are no remote refs; schema patterns applied to tab input are linear;
  and compilation is cached only per known method.
- **`--run-commands`.** It has the same trust level as `test.sh`. Images are
  digest-pinned and installs hash-pinned.
- **Fixtures.** The suite publishes no ports, and every endpoint is a test
  container.

## Re-review
- **Result:** no high or critical findings in `1bcae4b..e6fdfe7`. Items 4 and
  5 were fixed in this commit (a script assertion and a missing file).
- **Tests:** `broker/test.sh` passes, with docs-check, the unit tests and the
  integration tests.
