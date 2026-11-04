# Security review: RPC escape probes and rogue-REH fixture (Phase 3, increment 1)

- **Date:** 2026-11-04
- **Round:** 2 (first Phase 3 increment)
- **Reviewer:** independent `security-review` agent, an Opus-class model
- **Subject:** commit `8696c07` — `test/containment/rogue-extension/rpc-probes.js`,
  `test/containment/rogue-reh/probes.js`, `test/containment/check-probes.ts`,
  `test/containment/beacon.ts`, `rpc-filter/probes/expectations.json`, and the
  test-only REH hook patch
- **Upstream:** `microsoft/vscode@a717861c07586a53d83b80d742cd3f59b20a6273`
- **Outcome:** five findings fixed in `f1a7f0e`; no high or critical left open.

## Scope

The increment is test apparatus, not the filter. So the review was aimed at the
failure mode that matters for test apparatus: **false assurance** — any way a
probe or the checker could report containment that is not real. Secondary:
coverage gaps against the policy table, correctness of the rogue-REH calls
against pinned source, and whether the test-only patch is itself a liability.

## Findings and disposition

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | **Critical** | The checker read only `rpc-probes.json` and ignored `reh-probes.json` entirely. Seven probes — the whole client-served channel surface (`chan:download`, `chan:mcpGatewayToolBroker`), the raw-RPC identity spoof and the proxy-auth lookup — had **no baseline at all**, and their absence read as containment. Uniquely time-sensitive: a baseline recorded through this checker cannot be repaired afterwards, and nothing in the artefacts would say it should be. | **Fixed.** Both fixtures load into one result map; `expectations.rehProbes` merges into the spec set so the policy-link check, the ERROR-is-not-a-pass rule and the unexpected-result guard all apply. A missing REH file fails unless `--no-reh` is passed. Checks went 44 → 60. |
| 2 | **High** | `patchedAssertion` was free text that nothing executed. `auth-get-session` — the direct test of *no real secret may enter a tab* — would pass while returning a live token. Likewise `command-enumeration` and `secret-read-cross-tab`. | **Fixed.** Free text removed; executable predicates in `check-probes.ts`. A `patchedOutcome` other than `denied` without a predicate is now itself a failure. Verified: a 40-char token fails with *"accessToken length 40 is not a sentinel"*. |
| 3 | High | The beacon log was optional in `patched` mode, so a forgotten argument certified every egress claim, including all of `webview-egress`. | **Fixed.** Beacon and denial logs are both required in `patched` mode. Verified: omitting them fails. |
| 4 | High | `classify()` decided denial from the error message, but the design deliberately makes a denial *indistinguishable* from an unsupported operation. The two goals contradict, so message sniffing would score incidental failures as containment. | **Fixed** by moving the oracle. `classify()` is documented as a hint only; `patched` mode now requires the denial to be corroborated by a host-side filter denial log keyed on the policy ref. Emitting that log is a requirement on the filter patch. |
| 5 | Medium | `patches/0005` shipped in every build: `build/prepare.sh:42` globs `patches/[0-9][0-9][0-9][0-9]-*.patch` unconditionally. It `require()`s an env-supplied path and hands it `socketServer` plus a renderer-targeted router — a greppable RCE primitive in release builds of an isolation product. | **Fixed.** Moved to `test/containment/rogue-reh/serverServices-hook.patch`, out of the shipping queue; applied only by the containment harness for a dedicated probe build. Verified the queue glob no longer matches it. |

## Also raised, tracked not fixed

- **`terminal-onexecutecommand` had an expectation but no implementation.** It
  needs a live `persistentProcessId` from the remote terminal channel. Now
  recorded explicitly as `ERROR` with the reason, so it cannot be mistaken for
  containment. Implementation is outstanding.
- **Coverage gaps** with no probe yet: `MainThreadTunnelService.$openTunnel`,
  `$registerCommand` shadowing, and the `tab_data` surfaces
  (`terminal-osc-sequence`, `workspace-configuration`, `uri-handler`,
  `mcp-server-definition`, `quick-input-password`). Each is a reachable or
  rewrite verdict in the policy table, so each needs a probe before the filter
  can be called validated.
- **Probes that may not prove what they claim** — e.g. `host-terminal-newlocal`
  returning without demonstrating a *host* terminal. These are exactly what the
  unpatched run exists to expose, and with the oracles above the run will now
  surface them rather than bless them.
- **`globalThis.__seclabMainThreadRpc` does not exist yet**, so the two raw-RPC
  probes correctly report `ERROR` rather than passing.

## Verification

Re-run against synthetic evidence after the fixes:

- both fixtures load: 60 checks, up from 44;
- an `error` outcome still fails in `unpatched` mode;
- `patched` with no `--beacon`/`--denials` fails on the oracles *and* on every
  uncorroborated denial;
- `auth-get-session` with a 40-char token fails the sentinel predicate;
- `webview-egress` fails when a `/webview` beacon hit is present.

## The one thing still outstanding

No probe has yet succeeded against a real unpatched build, so the probe set
remains unproven. That run is gated on the macOS build from the fork-build
pipeline.
