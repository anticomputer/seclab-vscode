# Drift check: a digest gate over the surface-to-verdict mapping

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** RPC-lockdown session
- **Related:** [ADR: RPC filter enforcement points](../adr/20261104-rpc-filter-enforcement-points.md), [EDR: inventory generator](20261104-rpc-inventory-generator.md)

## Context

Default-deny bounds what an *unclassified* surface can do, but on its own it
degrades badly: a surface upstream adds is denied silently, and the first
symptom is an extension breaking for reasons nobody can trace. The project's
whole cost model is the upstream bump, so the bump has to produce a reviewable
list of what changed.

## Decision

`rpc-filter/tools/check_drift.py` resolves every inventoried surface to a
verdict, then pins the whole mapping by SHA-256 in `policy/coverage.json`. Any
new, changed or removed surface fails the build and is named in the output.
`--accept` re-records the mapping, which is the explicit "I have reviewed this"
step.

Reachable surfaces are pinned by a hash of their **entire policy entry**, not
just the verdict, so weakening a `constraint` or adding `"residual_impact": []`
cannot pass unnoticed.

Three checks run alongside coverage:

- `keys` — rejects a policy key that is not a real wire `sid` (in particular a
  `MainContext` property name, which would silently never match), a channel not
  in the inventory, a `commands.exact` entry absent from the inventory (which
  indicts the *scanner*, not the policy), and any category rule whose verdict is
  not `deny`.
- `undeclared` — every method callable via `actor[methodName]` but absent from
  its Shape must carry an explicit verdict.
- `invariants` — `no-real-secret-in-tab` and `identity-never-from-arguments`
  evaluated across the **whole resolved mapping**. Any reachable surface must
  have an individually reviewed entry recording an impact.

## Alternatives considered

- **Count-based check** ("fail if the number of methods changed"). Rejected: it
  passes when one method is added and another removed, and it names nothing.
- **Review the diff of `inventory.json` by eye.** Rejected: 35k lines, and it
  misses a *policy* edit that changes a verdict without changing the inventory.
- **Verdict-only digest.** Tried, then rejected during the design review: it
  lets `residual_impact` be used to relabel rather than mitigate.
- **Checking only the entries someone wrote.** Rejected during review: it misses
  exactly the dangerous case, a surface made reachable by a bulk rule that
  nobody looked at.

## Verification

The gate was tested, not assumed:

- Injecting a new RPC method (`$pwnNewUpstreamMethod`) and a new command
  (`workbench.action.terminal.newLocalV2`) into the inventory → **exit 1**, both
  named as `NEW … -> deny`.
- Clean tree → **exit 0**, `3768 surfaces, 14 reachable, 3754 denied`.

Writing the checks also found four real defects in work that already looked
finished: the channel extractor recording a constant's name rather than its
value; two undeclared `MainThreadChatAgents2` methods with no verdict;
`$readFile` contradicting the credential invariant; and the category-based
allow set, which the review escalated to critical.

## Consequences

- An upstream bump produces an explicit list of new surfaces to classify.
- `--accept` is a trust boundary in the workflow: running it without reading the
  diff defeats the gate. It should require a reviewed commit.
- **Open:** CI must regenerate `inventory.json` from the source actually being
  built and fail on any diff. Until then the gate compares policy against a
  committed artefact, so a stale or under-scanning inventory yields a green
  build over a grown surface. This is the highest-value remaining tooling work.
- **Open:** a verdict is pinned to an id, not to behaviour. If upstream changes
  what an allowed command does, the digest is unchanged. Candidate fix is to
  hash each reachable surface's defining source region.
