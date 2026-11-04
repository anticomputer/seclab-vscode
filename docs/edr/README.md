# Engineering Decision Records (EDR)

EDRs record **engineering** decisions: implementation, tooling, build/CI,
library choice, test strategy and **spike outcomes**. Write one when you make
the decision or finish the spike, not afterwards. System-shape decisions
(boundaries, components, runtimes, trust model, protocols) go in
[`../adr/`](../adr/README.md). If an engineering finding forces a design
change, write an ADR for the change and link this EDR as its evidence.

Same rules as ADRs:

- **File name:** `YYYYMMDD-short-slug.md`. No sequence numbers (parallel branches).
- **Append-only:** supersede rather than rewrite, and link both ways.
- **Status:** `proposed` → `accepted` → (`superseded-by …` | `deprecated`).
- **Evidence:** the exact commands run and their relevant output, scrubbed of
  secrets; code permalinks pinned to SHAs; doc links.

## Template (MADR-style)

```markdown
# <Title>

- **Status:** proposed | accepted | superseded-by [YYYYMMDD-slug](YYYYMMDD-slug.md) | deprecated
- **Date:** YYYY-MM-DD
- **Deciders:** <people / sessions>
- **Related:** <ADR / EDR / security review links>

## Context
## Decision
## Alternatives considered
- **<Alternative>**: rejected because …
## Consequences
## Evidence
<commands + trimmed output, permalinks>
```

## Index

| Date | Record | Status |
|---|---|---|
| 2026-11-04 | [sbx upgraded to 0.51.0: findings](20261104-sbx-upgrade-0-51.md) | accepted |
| 2026-11-04 | [sbx per-tab egress fence and broker chaining (spike)](20261104-sbx-fence-spike.md) | accepted |
| 2026-11-04 | [REH transport over `exec -i` stdio (viability spike)](20261104-reh-transport-exec-stdio.md) | superseded-by reh-transport-e2e |
| 2026-11-04 | [seclab-tabd is dependency-free TypeScript on the editor's Node](20261104-tabd-implementation-language.md) | accepted |
| 2026-11-04 | [Remove the built-in Copilot extension (one build patch)](20261104-remove-builtin-copilot.md) | accepted |
| 2026-11-04 | [Linux builds in a trixie container; sbx template via snapshot](20261104-linux-builder-and-sbx-template.md) | accepted |
| 2026-11-04 | [REH transport over `sbx exec -i` stdio works end to end](20261104-reh-transport-e2e.md) | accepted |
| 2026-11-04 | [Extensions never persist across tabs or onto the host](20261104-extension-persistence.md) | accepted |
| 2026-11-04 | [Tab Manager routing (M1): extension-level redirect, fail closed](20261104-tab-manager-routing.md) | superseded-by local-window-close-first (local part) |
| 2026-11-04 | [Local folder windows are closed before any dialog](20261104-local-window-close-first.md) | accepted |
| 2026-11-04 | [Canary acceptance harness](20261104-canary-harness.md) | accepted |
| 2026-11-04 | [OCI tabs on a native Linux engine run as the workspace owner](20261104-oci-tab-user-on-linux.md) | accepted |
| 2026-11-04 | [Test fixtures are inert and host-safe by construction](20261104-fixture-safety.md) | accepted |
| 2026-11-04 | [Ship exactly the reviewed patch series; check release artifacts for test hooks](20261104-patch-series.md) | accepted |
