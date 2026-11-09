# Security review: patch 0035, host documents don't sync into a tab

- **Date:** 2026-11-09
- **Scope:**
  - Round 1: `origin/main..a6c6a66`. Areas: patch 0035 (`seclabDocumentOrigin.ts`, and the
    document, content-provider and filesystem main-thread customers), `patches/sole-consumer.json`,
    and the `test/docsync` harness and probe extension.
  - Round 2: `a6c6a66..6f3fdeb` (the round-1 fixes).
- **Reviewer:** security-review agent (default model), triage by the document-sync session.
- **Threat model:** a rogue extension owns the tab's extension host and sends any RPC. No host
  document text, and no host path, may reach it through the documents and editors sync. Local
  windows and the local extension host must behave exactly as upstream.
- **Related:** [EDR document-sync-provenance](../edr/20261109-document-sync-provenance.md),
  [RPC lockdown §7](../RPC-LOCKDOWN.md#7-residual-risks).
- **Prompt injection:** none found in either round.

## Findings
| # | Severity | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| F1 | high | filesystem rule | The tab registers a filesystem provider for `output`, a host scheme that has none. The window accepts it, and the rule ("the scheme's current provider is this host's") then synced every host output model. | fixed (6f3fdeb) | Decided per model: a text file model born under this host's provider. A model born otherwise never qualifies. | probe step `register-output-fs-provider` (after the window log exists); `no windowLog canary in any tab document` |
| F2 | medium | untitled | `openTextDocument('untitled:Untitled-N')` reopened the host's existing untitled model and tagged it as the tab's. | fixed (6f3fdeb) | Only a model the call created is tagged (`untitled.onDidCreate`). | probe step `host-seeded-untitled`: the host's untitled is found through editor tabs and claimed; `untitledForeign` must be false and the claim must have happened |
| F3 | low | content providers | `$onVirtualDocumentChange` could replace the text of any loaded model, host settings included (pre-existing; line touched). | fixed (6f3fdeb, then the round-2 hardening) | A filtered host writes only models its own provider made. Filtering also holds on the tab's remote authority alone. | code review; no probe (it needs the user settings path in the tab) |
| F4 | info | cells, pins, `$tryOpenDocument` | `CellUri.parse` on a tab-made URI could throw. The sole-consumer pin matches substrings only. Other calls still name host URIs. | fixed (parse fails closed; cells only on the tab authority) / accepted | The pin documents the known shapes; the other URI paths are siblings, reported. | none |
| P1 | medium | probe | A failed step, a failed seed or a hijack-2 step that does nothing would have passed the leak checks vacuously. | fixed (6f3fdeb) | Every step must succeed. `seeded` is asserted. Hijack 2 must show the tab losing the model at the host write. The run's nonce is checked. | the harness itself |
| P2 | medium | probe | No step for F1 or F2. | fixed (6f3fdeb, round 2) | Added both steps, with an assertion that the host-seeded untitled existed. | as above |
| P3 | info | probe | A change sent for a document the tab no longer holds is invisible to the extension API. | accepted | The revoking listener runs first and removes the document synchronously, and `ModelTracker` re-checks. Confirmed in round 2. | none |
| R2-1 | low | filesystem rule | "Born as a text file" means a text file model exists for the URI. A tab that stalls its own provider's `readFile` could keep one pending while host code creates a model directly at that URI. | accepted | No host feature found that creates a model with host data directly at a URI under a tab's filesystem scheme. Output and perf models are created only through their content providers, which the resolver never reaches once the scheme is a filesystem. A stricter rule (sync only after the text file model resolves and created the model itself) is the follow-up if one appears. | none |

## Re-review
Round 2, over `a6c6a66..6f3fdeb`, confirmed F1, F2, F3 and the cell fix, and found R2-1 (low). Open
high or critical: none.
