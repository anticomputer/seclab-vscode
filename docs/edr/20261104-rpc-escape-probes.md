# RPC escape probes: validity before coverage

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** RPC-lockdown session
- **Related:** [ADR: enforcement points](../adr/20261104-rpc-filter-enforcement-points.md), [ADR: command taint](../adr/20261104-tab-command-taint.md)

## Context

The filter is only worth what its tests prove. The usual failure mode for a
security test is a probe that has never worked: it "passes" after the patch
because it was broken all along, and nobody notices because a green suite looks
the same either way.

So the ordering is a rule, not a preference: **every probe must SUCCEED against
the unpatched build before the patch that denies it lands.**

## Decision

Probes live in two fixtures, because the two attacker positions reach different
surfaces:

- **Rogue extension** (`test/containment/rogue-extension/rpc-probes.js`), 19
  probes driven through the public extension API, which is what a real rogue
  extension has.
- **Rogue REH** (`test/containment/rogue-reh/probes.js`), 7 probes for surfaces
  the extension host cannot reach at all: channels the *client* registers on the
  remote connection (`download`, `mcpGatewayToolBroker`), and raw `MainThread*`
  calls with arguments no public API can express, such as a spoofed extension
  identity for `$getKeys`.

Expected outcomes are data, in `rpc-filter/probes/expectations.json`, and
`test/containment/check-probes.ts` enforces them. The two modes are deliberately
asymmetric:

| Mode | Rule |
|---|---|
| `unpatched` | every required probe must report `succeeded` |
| `patched` | every required probe must report `denied`, unless `patchedOutcome` names another |

`patchedOutcome` exists because denial is not always the right answer: after
patching, `$getSession` still returns a session (with a sentinel token),
`$getCommands` still returns a list (filtered), and `secret-read-cross-tab` still
returns a value (this tab's own, never the other tab's).

Three properties make the checker hard to fool, each verified by running it:

1. **An `ERROR` is not a pass.** In `unpatched` mode only `succeeded` counts, so
   a broken probe fails loudly at the moment it would otherwise be enshrined.
2. **Egress is proven by a beacon, not a return value.** A call can succeed while
   the request is blocked, and fail while the request still went out.
   `test/containment/beacon.ts` is a 127.0.0.1 listener that logs hits; probes
   with a `beacon` path must hit it when unpatched and must not when patched.
3. **Every probe must name a policy entry that exists** in
   `policy/coverage.json`, so a probe cannot drift away from the table it tests.
   A result with no expectation is also a failure, because silently ignoring one
   is how a probe set rots.

## Alternatives considered

- **Assert inside the probes.** Rejected: the expected outcome depends on the
  build, so the probe would need to know which build it is in, and a probe that
  decides its own verdict cannot be used to validate itself.
- **One fixture for everything.** Rejected: the extension host genuinely cannot
  call a client-registered channel, so a single fixture would quietly report
  "denied" for the entire channel surface and look like containment.
- **Skip the unpatched run and trust the probes.** Rejected; see Context.

## The test-only patch

`patches/0005-test-only-rogue-reh-hook.patch` (16 lines) loads the rogue-REH
payload in `serverServices.ts`, next to where the server already builds its
`StaticRouter` to the renderer. It is inert unless both `SECLAB_ROGUE_REH=1` and
`SECLAB_ROGUE_REH_PAYLOAD` are set.

It uses `createRequire(import.meta.url)` because the server bundle is ESM
(`"type": "module"`), following the pattern already in
`remoteExtensionHostAgentServer.ts:43`. Verified to apply cleanly against the
`upstream.lock` commit.

Carrying a fixture in the patch queue is a real cost and was weighed: the
alternative is reimplementing enough of the remote protocol to speak as a
server, which would be far more code and would test our reimplementation rather
than the real server.

## Consequences

- The unpatched run is a prerequisite, and it needs a built editor, so probe
  validity is gated on the macOS build from the fork-build pipeline.
- `_seclabTest.launder` does not exist yet. Four laundering probes
  (`await`, `timer`, `event`, `captured-service`) therefore report `ERROR`, not
  `succeeded`, which is correct: a missing fixture must never read as
  containment. The contribution lands with the taint patch.

## Verification so far

The checker was exercised against synthetic results before any build existed:

- missing `rpc-probes.json` → fails;
- all-`succeeded` results → 44/44 in `unpatched`, 25/44 in `patched`;
- flipping one probe to `error` → that probe fails in `unpatched` mode;
- beacon assertions fire in both directions.

What is **not** yet verified: that any probe actually succeeds against a real
unpatched build. Until that run happens, the probe set is unproven.
