# Docs are generated or checked in CI (docs-check gate)

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** Project owner (2026-11-04): docs must stay current as work proceeds, with drift prevented where possible; fork-build session
- **Related:** broker counterpart [EDR broker docs from sources](20261104-broker-docs-from-sources-and-safe-fixtures.md); [AGENTS.md](../../AGENTS.md) process rule
- **Editorial redaction (2026-11-12):** quotations of project conversations replaced with neutral statements; decisions unchanged.

## Context
Three sessions write docs in parallel. The hand-maintained indexes had already drifted:
the broker's ADRs, EDRs and reviews weren't listed, ARCHITECTURE.md didn't link six
accepted ADRs, the M0 review row was stale, and one research link was dead. AGENTS.md
promises that it lists only commands that have actually been run.

## Decision
A `docs-check` job runs on every push and PR (`.github/workflows/docs-check.yml`). The
same gate runs locally as `./seclab docs check [--run-commands] [--online] [--paired]`.
Everything runs in containers.
1. **Generated, not hand-maintained.** The ADR, EDR and security-review index tables are
   generated from each record's header (title, Date, Status with supersede links,
   Scope) between `<!-- index:begin/end -->` markers. `./seclab docs write` regenerates
   them, and the check fails on any difference. Records must be named
   `YYYYMMDD-slug.md` and have a title. The Date must match the file name. ADRs and
   EDRs need a Status keyword. Supersede links must work in both directions.
2. **Executable docs.** Shell blocks marked `<!-- ci: run -->` in AGENTS.md and the
   READMEs run in CI. Today that's the fast container-only set: unit tests, fixture
   lint, source lint and the patch-series check. Heavier commands (builds, sbx suites)
   stay documented but run elsewhere: on build CI, or locally for sbx. The broker's
   `docs-check.sh --run-commands` runs its own documented blocks.
3. **Links.** Every relative link in tracked markdown must resolve. GitHub
   `blob`/`tree` links must be pinned to a 40-hex SHA. External links must resolve
   (lychee 0.24.2, digest-pinned, cached for 3 days in an Actions cache, so CI isn't
   flaky). Reserved and test hosts are excluded.
4. **Architecture consistency.** ARCHITECTURE.md links every accepted ADR, never links a
   superseded ADR as current, and every `` `seclab-*` `` component it names exists in
   the tree.
5. **Paired changes (soft rule).** Changes under these paths must come with their docs
   in the same range (against `origin/main`), unless a commit carries a
   `docs-not-needed: <reason>` trailer:
   - the tabd protocol files → `docs/tabd/PROTOCOL.md`;
   - `tabd/src/drivers/` → an ADR, an EDR or ARCHITECTURE.md;
   - `patches/` → an ADR, an EDR or `patches/README.md`;
   - `build/product/` → an ADR or EDR;
   - `broker/schema/` → `docs/broker-protocol.md`.

## Alternatives considered
- **markdownlint:** skipped for now, since the cost of style churn across three sessions
  outweighs the drift it catches. It can be added later.
- **YAML front matter in records:** not adopted. The existing `- **Field:**` header
  block already carries the fields, and rewriting accepted records would break the
  append-only rule.
- **A README status table checked against milestones:** not feasible to verify
  mechanically yet. It stays a review item.

## Consequences
- An index edit by hand fails CI. Write the record, then run `./seclab docs write`.
- A command documented in a `ci: run` block that stops working fails the build.
- Two ADRs for one decision (`no-real-secret-in-a-tab` and `no-real-secret-enters-a-tab`)
  pass the gate. Duplicate detection is a review item.

## Evidence
`./seclab docs check --run-commands --paired` passes on the tree: the broker docs check
runs its 14 docs and their commands, and the AGENTS.md block runs. `./seclab docs check
--online` gives 537 links, 526 OK, 1 dead third-party link (fixed) and 10 excluded.
While building it, the gate found 8 real problems, all fixed:
- 6 accepted ADRs missing from ARCHITECTURE.md;
- 2 false positives from a regex in inline code.
