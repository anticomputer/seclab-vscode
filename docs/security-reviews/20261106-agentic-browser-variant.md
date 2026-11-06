# Security review: the `agentic-browser` test build variant

- **Date:** 2026-11-06
- **Scope:** `test/builds/variants.json` (new `agentic-browser` variant),
  `test/agentic/browser-drive/browserView-hook.patch` (new desktop hook), and the
  `agentic-browser` option added to `build-macos.yml`'s `test_variant` choice list.
- **Why:** AGENTS.md requires a review round for every workflow change, and
  [the variants EDR](../edr/20261106-test-build-variants.md) requires one for every new
  variant or hook.
- **Related:** [increment 2 EDR](../edr/20261106-increment-2-remote-proxy.md),
  [the AHP gate rounds](20261106-agentic-ahp-gate.md) (0017 itself, rounds 6 and 7).

## Why the hook exists
Patch 0017 fixes `workbench.browser.enableRemoteProxy` to `true` and
`workbench.browser.dataStorage` to `ephemeral` in a tab window, so a browser view's traffic
stays on the tab's network. Proving that requires driving the browser **tool** path, which
normally needs a model to choose a URL. The hook calls what `openBrowserTool._openNewPage`
calls and nothing else.

## Result
**No high or critical finding.** The reviewer confirmed the hook cannot fire on a user's
machine and cannot reach a release artifact:
- `INativeWorkbenchEnvironmentService.userHome` is the **host** home even in a remote window,
  and an `IFileService` read of a `file:` URI goes to the host disk, so the arming path is on
  the host, outside the workspace, which is the only thing a tab mounts. A hostile tab,
  workspace or extension cannot stage it. Host write access arms it, which is
  attacker-already-wins and the same position the `rogue-reh` hook takes.
- The marker is a runtime string literal in two live log calls, so it survives minification;
  the `bundle` path is the file the code really lands in, so the build's presence check is a
  real check and not vacuous; `check-release` scans for it and `build-darwin.sh` asserts
  check-release *fails* on the variant artifact; both upload paths are guarded on
  `test_variant == 'none'`.
- The workflow change is one added `choice` option. It holds the CI baseline (pinned actions,
  least-privilege permissions, `persist-credentials: false`, no `${{ github.event.* }}` in
  `run:`), the input reaches only `env:`/`with:`, and the concurrency group already keys on
  the variant, so a test dispatch cannot displace a queued release build.

Six defects were found and fixed.

1. **The hook could not apply on `main`, so the U baseline it describes was unbuildable.** Its
   context had been generated against a tree that included 0017, whose own hunk touches the
   same import block. Fixed by writing the hook against the series **without** 0017 and
   placing its import away from 0017's hunk; verified by applying it to a tree with 0017 and
   to a tree without it, both clean.
2. **A duplicate import of a module the file already imports.** Removed by inlining
   `getAgentBrowserViewCreationDefaults` (three lines, and `BrowserViewStorageScope` is
   already imported), which also removed the import that caused defect 1.
3. **The expiry check failed open.** `Date.now() > Number(until)` is `false` for a
   non-numeric `until`, so a malformed arming file counted as unexpired. Inverted to
   `Number(until) > Date.now()`, which fails closed, matching the rogue-REH hook. The unit
   (epoch milliseconds) is now stated.
4. **The nonce was unvalidated.** Any non-empty string armed the hook; it now requires
   `/^[0-9a-f]{32}$/` as rogue-REH does.
5. **An async latch race could open two pages for one run.** The callback is `async` and the
   latch was set after the awaited read, so two ticks could both pass the guard — ambiguous
   evidence, which is this project's recurring failure mode. The latch is now set before the
   await and released only on a miss.
6. **The `review` field named a record that did not cover the variant.** It now points here.

## Known limits, recorded rather than fixed
The hook omits the tool's URL handling (`rewriteRemoteLocalhostUrl`, the network policy
errors) and its `storageAffinity`, which is `undefined` for a plain tab window and a session
id otherwise. So it measures the tool faithfully **only** in a `seclab+` tab window, with no
sandbox restrictions, against a non-localhost target. Every divergence outside that shape
pushes toward the host network, i.e. toward a false "not contained" rather than a false
"contained". This is stated in the hook's own comment and in the variant's description, so a
run outside that shape is not mistaken for a measurement of the tool.
