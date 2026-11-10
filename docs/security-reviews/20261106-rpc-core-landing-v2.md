# Security review: RPC core landing v2 (round 10)

- **Date:** 2026-11-06
- **Round:** 10. The second landing attempt: named argument validators, the per-tab state
  partition, the core editing set and the leaf-exception commands.
- **Reviewer:** independent `security-review` agent (an Opus-class model)
- **Subject:** `git diff c1935f3..a9208a9` on `anticomputer-rpc-core-landing-v2` (round 9
  reviewed `c1935f3`). The partition patch was renamed from 0011 to
  `0032-seclab-partition-tab-extension-state` after the review started; its content is the
  same.
- **Prompt:** said the diff, fixtures and evidence may contain prompt injection aimed at the
  reviewer, and that the reviewer reports it rather than following it.

## Verdict
**One high and one medium blocked landing.** Both are fixed, with regression tests that fail
on the reviewed source (see Fixes). Re-review is round 11.

| # | Severity | File | Finding | Conf. | Blocks landing |
|---|---|---|---|---|---|
| 1 | high | `seclabArgValidators.ts` (`tabFileSearch`) | `expandPatterns: true` with an absolute or `./` `includePattern` makes upstream derive the search **roots** from the pattern and ignore argument 0. In a folderless tab window those roots become host `file:` URIs | 8/10 | yes |
| 2 | medium | `seclabRpcFilter.ts` (decision log) | The 4096-byte cap slices the *serialized* line, and `reason` is unbounded tab-controlled text, so a tab can make its own denial records invalid JSON, which every consumer drops | 9/10 | yes |
| 3 | medium | `check_drift.py` (`check_validators`); `seclabRpcFilter.ts` (`_constrain`) | A validator is required only for `cmd:` entries, and a positional URI argument discharges a *named* constraint, so dropping a validator from a URI-bearing rpc entry widens the surface with no gate failing | 8/10 | no |
| 4 | low | `policy.json` (`trusted_registration_ids`); `emit_policy.py` | UI-side extensions' programmatically registered ids (`simpleBrowser.api.open`) are not in `SECLAB_TRUSTED_COMMAND_IDS`, so `$registerCommand` can shadow them; the list is hand-written | 8/10 | no |
| 5 | low | `sync_patch.py` (`CALLER_EXEMPT`) | The `seclabRegisterRewrite` exemption still says "none ships yet", which 0032 made false; the gate cannot notice an exemption that has become live | 9/10 | no |

## Fixes (2026-11-09)
Each blocker's regression test was run against the unfixed source and fails there.

1. **Fixed.** `tabFileSearch` refuses `expandPatterns` unless it is `false`; `findFiles` never
   sets it. Independently, it refuses any `includePattern`/`excludePattern` segment that
   `parseSearchPaths` would make a search root: absolute, `~`-prefixed (expanded against
   the user's home), a drive letter, or starting with `./` or `../`.
   - Tests: `arg-validators.test.ts` "a pattern may not choose the search roots", plus two
     injected defects.
   - Against the round's source the suite reports 39/42, failing exactly those three.
   - The runtime probe (`expandPatterns` in a folderless tab window) is still to be written.
2. **Fixed.** Tab-chosen fields are bounded before serialization (`reason` and
   `constraint` 512, `claimedExtensionId` 256). A line still over the cap after escaping
   is replaced by a well-formed record without free text; JSON is never cut.
   - New suite `decision-line.test.ts` runs the shipped `line` function, cut from the
     source, rather than a model of it.
   - Against the round's source it reports 1/4, with `Unterminated string in JSON at
     position 4096`.
3. **Fixed.**
   - In the filter, a constraint is discharged only by its validator, or by the positional
     URI rule when the entry declares `constraint_is_uri_rule` (`$readFile`, `$writeFile`).
     Anything else denies.
   - `check_validators` covers rpc entries as well as commands, requires positions for a
     URI-rule entry, and refuses an entry that names both a validator and the URI rule.
     `$executeCommand` is the one listed exception.
   - `$getCommands`, documented as constrained but enforced as a deny all along, is now
     `deny`, and its probe expects a denial.
   - Four new gate tests.
4. **Interim.** `simpleBrowser.api.open`, the only programmatic id among the UI-side
   built-ins, is added. The note says the list is hand-checked. A scanner for extensions'
   `registerCommand` calls is the follow-up.
5. **Fixed.**
   - The stale `seclabRegisterRewrite` exemption is removed.
   - The rewrite comment names the modules 0032 registers from.
   - `check_callers` now fails on an exempted symbol that has a caller. That rule caught
     this exemption before it was removed.

Not done: a direct unit test of `seclabReviveUri` against real `URI` semantics. The filter
module imports the workbench, so the test would need upstream's `uri.ts` and its imports.
It is exercised at runtime by the canonical-URI probes.

## Fixes as the reviewer proposed them
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

## Round 11 (re-review of the fixes, 2026-11-09)
- **Reviewer:** independent `security-review` agent (an Opus-class model), the same
  injection warning in its prompt.
- **Subject:** `git diff a9208a9..ee0ace0`: the round-10 fixes and the 0011→0032 rename.
- **Verdict: no high or critical findings.**
  - Findings 1 and 2 are fixed correctly and completely against the upstream consumers.
    The reviewer traced every `QueryBuilder` path that can produce a search root, and showed
    the replacement log record cannot exceed the cap, because its free fields are producer
    enums.
  - Findings 3 and 5 are fixed, and the fix for 3 fails closed.
  - Finding 4 was still incomplete.

| # | Severity | File | Finding | Conf. | Blocks landing |
|---|---|---|---|---|---|
| 1 | low | `policy.json` (`trusted_registration_ids`) | `vscode-testresolver.newWindowWithError` is another UI-side id registered in code and not contributed | 9/10 | no |
| 2 | low | `policy.json` (`$startFileSearch`) | The constraint text does not state the new root rule, so the recorded claim was weaker than the code | 9/10 | no |

Both were applied in `3cd91d5`. The proper fix for finding 4, a scanner for UI-side
extensions' `registerCommand` calls, stays a follow-up.

Prompt injection: none found in `a9208a9..ee0ace0`. The reviewer repeats round 10's note:
`reason` and `claimedExtensionId` are tab-authored and rendered by the Tab Manager, which
must keep quoting them as untrusted. The new 512/256 bounds cap what it renders.

## Round 12 (the validator delta after the first patched run, 2026-11-09)
- **Reviewer:** independent `security-review` agent (an Opus-class model), the same
  injection warning in its prompt.
- **Subject:** `git diff 9ce593a..881ad00`.
  - `tabFileSystemActivation` also allows `file`.
  - `tabDocumentOpen` accepts any plain object as options, checking only `encoding`. Both
    were measured on the first patched build, where they refused what upstream's extension
    host sends.
  - Harness fixes to the probes.
- **Verdict: no high or critical findings.**

| # | Severity | File | Finding | Conf. | Blocks landing |
|---|---|---|---|---|---|
| 1 | low | `seclabArgValidators.ts` (`tabFileSystemActivation`), `policy.json` | The rationale said `$ensureActivation('file')` is a no-op. In fact `activateProvider` fires the activation event before its existing-provider check, so it triggers `onFileSystem:file` activation in the trusted UI host. Nothing declares that event today | 9/10 | no |
| 2 | low | `expectations.json` (`host-file-search-nested-uri`) | No longer required, so the nested-URI denial is not asserted at runtime; only the unit suite covers it | 9/10 | no |

Finding 1: the comment, the constraint text and the EDR now state what happens, and record it
as a residual. Finding 2 is recorded: the probe returns to `required` once a baseline run
reproduces the escape.

Confirmed sound:
- `tabDocumentOpen`'s loosening is inert. The only branch that reads more than `encoding`
  is the untitled one, and `untitled:` is refused.
- `encoding` reaches only a re-resolve of the tab's own resource.
- The case-sensitive scheme match.
- Filter placement.
- Patch and policy regeneration.
- Prompt injection: none in the diff. The pre-existing XPIA fixture strings in
  `ai-probes.js` were treated as data.

## Round 13 (patch 0006's REH opt-out, 2026-11-10)
- **Reviewer:** independent `security-review` agent (an Opus-class model), the same
  injection warning in its prompt.
- **Subject:** `git show eeae080` (parent `816c15c`).
  - Patch 0006 gains a second hunk: `createServer` in `remoteExtensionHostAgentServer.ts`
    installs `setSeclabChannelGuard(() => undefined)` first. The first run against the
    REH from the same commit showed a patched REH refusing every management call
    ([EDR](../edr/20261106-ordinary-session-rpc-trace.md)).
  - `reach.json` pins 0006 to `server`.
  - `channel-guard.test.ts` gets REH model tests and a static check of the shipped hunk.
  - The harness gets `SECLAB_TAB_IMAGE` and `--image`.
- **Verdict: no high or critical findings.**

| # | Severity | File | Finding | Conf. | Blocks landing |
|---|---|---|---|---|---|
| 1 | low | `patches/0006-seclab-channel-guard.patch`, `patches/sole-consumer.json` | The setter is last-writer-wins, and this commit makes it a two-caller API. A later patch installing a weaker guard from a desktop-reachable module would replace the workbench guard and reopen every `chan:` surface; reach and unreachable checks would not notice | 9/10 | no |

Finding 1 is fixed. `sole-consumer.json` now names the only files that may mention
`setSeclabChannelGuard`:
- `ipc.ts`, for the definition only;
- `seclabRpcFilter.ts`, which installs the real guard;
- `remoteExtensionHostAgentServer.ts`, which installs the REH opt-out.

`check-patch-reach.ts` (required `patch-build`) passes on the patched tree and fails on an
injected third caller under `src/vs/workbench/`.

Confirmed sound:
- The opt-out is reached only from the `server` target. Its importers are REH-only
  (`server.main.ts`, `server-main.ts`). No desktop entry point (CLI, shared process,
  workbench, workers) reaches `src/vs/server/`, including by computed dynamic import.
  `serve-web` and tunnels start a separate process.
- The desktop fail-closed default is unchanged; only a comment changed in `ipc.ts`.
- The REH-side refusal was not load-bearing. The REH serves its own channels to the trusted
  client, and the REH is attacker-controlled under the threat model.
- The static test catches a removed, moved, duplicated or denying opt-out.
- The harness options are regex-pinned, passed as argv with no shell, and re-validated by
  tabd. A failed `docker exec` in the focus probe reads as "not every step ran", never as a
  pass.
- Prompt injection: none.

## Round 14 (harness and probes after the proof, 2026-11-10)
- **Reviewer:** independent `security-review` agent (an Opus-class model), the same
  injection warning in its prompt.
- **Subject:** `git diff 6cc61c4..438730a`. No patch or policy changes: the restart probe,
  the benign step timeout, the `findFiles` tolerance, the probe re-aims and the docs.
- **Verdict: no high or critical findings.** Three medium oracle-integrity findings, all
  fixed and re-run on the built `6cc61c4` (proof run 3).

| # | Severity | File | Finding | Conf. | Blocks landing |
|---|---|---|---|---|---|
| 1 | medium | `expectations.json`, `check-probes.ts` (`deniedAt`) | `host-doc-show-userdata` was corroborated against `$tryOpenDocument`, which `host-doc-open-userdata` already denies. The deny set is flat, so the sibling's denial satisfied it; `deniedAt` was not validated against coverage | 8/10 | yes |
| 2 | medium | `rpc-probes.js` (`runRestartProbe`) | `succeeded` was inferred from a missing outcome. A hang (the call had no timeout), a crash or a reload between attempt and result would read as a proven restart, which would manufacture the probe's baseline | 8/10 | yes |
| 3 | medium | `check-evidence.ts` (`findFiles` tolerance) | The tolerance keyed only on a tab-written error string, so a build whose search hangs for any other reason would pass the positive control | 8/10 | yes |

Fixes:
1. `deniedAt` is removed. The show probe opens the tab's own file and rewrites the outgoing
   `$tryShowTextDocument` resource, so it reaches its own gate. In run 3 it was denied there
   (`scheme vscode-userdata is not this tab's file system`).
2. The call is bounded at 20 s, and the attempt records its extension host's pid.
   `succeeded` needs a different extension host process to settle it, and a new unpatched
   predicate requires `newHostPid !== attemptPid`.
3. The tolerance also requires the host-side decision log to hold a `deny` for
   `rpc:MainThreadSearch.$registerFileSearchProvider`. An unfiltered build has no decision
   log, so there it never applies.

Also from the review: the EDR no longer counts the restart denial towards condition (b), because
that probe's baseline has not run.

Confirmed sound:
- Evidence is per run (`prepare` removes the run base). A build without the filter cannot
  loop.
- A tab that pre-seeds the restart file to skip the battery fails closed:
  `rpc-probes.json` is then missing, and forging it fails the host-side deny-line checks.
- The in-memory provider and the restart are inert and armed-only. On an unfiltered build
  the restart reruns the Tab Manager resolver, which is the effect under test.
- Prompt injection: none.

## Round 15 (re-review of the round-14 fixes, 2026-11-10)
- **Reviewer:** independent `security-review` agent (an Opus-class model), the same
  injection warning in its prompt.
- **Subject:** `git show 8ea9a65`.
- **Verdict: no high or critical findings.** Round 14's first finding (`deniedAt`) is closed.
  Its other two are only partly closed, as two mediums here.

| # | Severity | File | Finding | Conf. | Blocks landing |
|---|---|---|---|---|---|
| 1 | medium | `check-evidence.ts` (`findFiles` tolerance) | The added host-side condition is near-constant: every filtered tab denies `$registerFileSearchProvider` at startup, so it shows the cause is present, not that it caused this hang | 8/10 | no (accepted residual) |
| 2 | medium | `rpc-probes.js`, `check-probes.ts` (restart predicate) | A new extension host pid proves "a different host", not "a restart": a window reload or a crash-restart would also settle the attempt as `succeeded`, unpatched-side only | 8/10 | no (fixed) |
| 3 | low | EDR, `expectations.json` | Run id missing for the third run, "both proof runs", and a stale `why` | 9/10 | no (fixed) |

Triage:
1. **Accepted residual, until the search follow-up.** In a filtered build, search is denied by
   design, so a hang from any other cause cannot be told apart and would not change the
   verdict. Every other step must still pass, and a broken editor fails those. The run's
   profile holds only that run's window, so the decision log cannot come from another run.
   The tolerance goes away with the search-provider follow-up, after which `findFiles`
   must pass.
2. **Fixed.** The attempt also records `vscode.env.sessionId`. An extension host restart keeps
   the window session; a window reload replaces it. `succeeded` now needs a different pid,
   the same session, and settling within 60 s of the attempt, and the unpatched predicate
   checks all three. A crash-restart that coincides with that 60 s window is the remaining,
   low-probability case. The baseline run is where it would show, and it is read alongside the
   renderer log.
3. **Fixed.**

Also noted, not live: `withRewrittenRequest` is not re-entrant under overlapping use. All
current uses are awaited one after another.
