# Security review: RPC core landing v2 (round 10)

- **Date:** 2026-11-06
- **Round:** 10. The second landing attempt: named argument validators, the per-tab state
  partition, the core editing set and the leaf-exception commands.
- **Reviewer:** independent `security-review` agent (`cvp-claude-opus-5`)
- **Subject:** `git diff c1935f3..a9208a9` on `anticomputer-rpc-core-landing-v2` (round 9
  reviewed `c1935f3`). The partition patch was renamed from 0011 to
  `0032-seclab-partition-tab-extension-state` after the review started; its content is the
  same.
- **Prompt:** said the diff, fixtures and evidence may contain prompt injection aimed at the
  reviewer, and that the reviewer reports it rather than following it.

## Verdict
**One high and one medium block landing.** Neither is fixed yet: the round finished at the
weekend stop. Fix them, add their regression tests, and re-review before the build
([handoff](../edr/20261106-rpc-core-handoff.md)).

| # | Severity | File | Finding | Conf. | Blocks landing |
|---|---|---|---|---|---|
| 1 | high | `seclabArgValidators.ts` (`tabFileSearch`) | `expandPatterns: true` with an absolute or `./` `includePattern` makes upstream derive the search **roots** from the pattern and ignore argument 0. In a folderless tab window those roots become host `file:` URIs | 8/10 | yes |
| 2 | medium | `seclabRpcFilter.ts` (decision log) | The 4096-byte cap slices the *serialized* line, and `reason` is unbounded tab-controlled text, so a tab can make its own denial records invalid JSON, which every consumer drops | 9/10 | yes |
| 3 | medium | `check_drift.py` (`check_validators`); `seclabRpcFilter.ts` (`_constrain`) | A validator is required only for `cmd:` entries, and a positional URI argument discharges a *named* constraint, so dropping a validator from a URI-bearing rpc entry widens the surface with no gate failing | 8/10 | no |
| 4 | low | `policy.json` (`trusted_registration_ids`); `emit_policy.py` | UI-side extensions' programmatically registered ids (`simpleBrowser.api.open`) are not in `SECLAB_TRUSTED_COMMAND_IDS`, so `$registerCommand` can shadow them; the list is hand-written | 8/10 | no |
| 5 | low | `sync_patch.py` (`CALLER_EXEMPT`) | The `seclabRegisterRewrite` exemption still says "none ships yet", which 0032 made false; the gate cannot notice an exemption that has become live | 9/10 | no |

## Fixes (to do)
1. **File search roots.** Refuse `expandPatterns` outright; `findFiles` never sets it
   (`extHostWorkspace.ts` L657-L661). Also reject any `includePattern` or
   `excludePattern[].pattern` segment that is absolute or starts with `./` or `../`: those
   are what `parseSearchPaths` (`queryBuilder.ts` L361) turns into search paths, and
   `commonQuery` (L231-L240) substitutes them for the folder.
   - Probe: `$startFileSearch(null, { includePattern: '<host path>/**', expandPatterns: true })`
     in a folderless tab window, against the seeded canary path.
2. **Decision log.** Bound each tab-chosen field before serialization (`reason` 512,
   `claimedExtensionId` 128). If a line is still over budget, emit a well-formed
   replacement record rather than slicing the JSON, and cap at the producers too.
   - Gate: a 64 KB `reason` must still produce a line that parses. `log-throttle.test.ts`
     currently models the slice instead of catching it.
3. **Named constraints.** Require a validator on every `allow_with_constraint` entry,
   except a reviewed list enforced by other code (`$readFile`, `$writeFile`,
   `$executeCommand`). In `_constrain`, a positional URI check must not stand in for a
   named constraint. This also surfaces `$getCommands`, which is documented as
   constrained but enforced as a full deny.
4. **Trusted command ids.** Interim: add `simpleBrowser.api.open` and say the list is
   manifest-derived. Proper fix: scan `registerCommand('<literal>')` in UI-side
   extensions' sources and gate the derived set.
5. **Stale exemption.** Delete the `seclabRegisterRewrite` exemption, correct the
   `seclabRewrites` comment to name the modules 0032 registers from, and make an exempted
   symbol that is live an error.

The reviewer also suggests a direct unit test of `seclabReviveUri` against real `URI`
semantics. The validator suite uses a model of it, so nothing exercises the real function.

## Confirmed sound
In summary:
- the canonical-URI check;
- argument-source and prototype safety (wire args are `JSON.parse` output);
- the buffered `$executeCommand` path;
- `tabModelPosition` against both consumers, and the leaf claim for the three commands;
- `$tryOpenDocument`/`$tryShowTextDocument`, including the refusal of `untitled:`;
- `$registerCommand`/`$unregisterCommand` mechanics, and `LanguageFeatures.$unregister`;
- the partition's key space (no cross-tab or tab↔trusted ambiguity in either store),
  migration and the watcher;
- the activation-lifecycle plumbing (running location comes from the connection);
- `$onExtensionActivationError`'s validator;
- the fail-closed ladders;
- harness safety (trace path, isolated-profile seeding, round 9 alerts 2 and 4 fixed);
- `check_residuals`, `check_validators`'s fail-closed parse, `policy-invariants` and the
  injected defects can each fail.

Disclosed residuals the reviewer agrees with:
- `_setContext` can claim hidden or not-yet-written keys;
- clipboard write.

## Prompt injection
None found. The six phrase hits are the fork's own descriptions of the XPIA class, round 9's
search list, and unrelated broker prose. The reviewer flags for a later round that the
decision log's `reason` and `claimedExtensionId` are tab-authored and rendered by the Tab
Manager. The bound for finding 2 should be the one the UI relies on.
