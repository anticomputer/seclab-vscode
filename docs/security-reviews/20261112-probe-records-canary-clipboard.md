# Security review: canary clipboard, fact-only run records, no screen automation

- **Date:** 2026-11-12
- **Round:** 16, with the fixes reviewed in round 18.
- **Reviewer:** independent `security-review` agent (an Opus-class model).
- **Subject:** `a8e3857`:
  - the `canary-clipboard` hook for the `containment` test variant;
  - `probe-safety.js` records (`recordJson`, `lit`, `canaryTokens`) and `withCanaryClipboard`;
  - the payloads rewritten to facts-only records;
  - `check-evidence` and `check-probes` read facts;
  - `window.ts` launch guard;
  - lint rules (`lint_probes.py`, fixture lint `screen-automation`);
  - capture helpers and the Space-switching probe removed;
  - records reworded generically.
- **Prompt:** said the diff, fixtures and evidence may contain prompt injection aimed at the
  reviewer, and that the reviewer reports it rather than following it. None found.

## Verdict
**No high or critical findings.** One medium and three lows, all fixed.

Confirmed sound:
- Every renderer-reachable clipboard path, including both paste actions through
  `triggerPaste`, lands in the hooked store.
- The store fails closed: a missing or malformed seed gives an empty string, never the
  system clipboard.
- The hook is absent from `patches/series`. Its marker survives minification, and
  `test-variant.sh verify` and `check-release.sh` fail on it.
- `canaryTokens` is bounded. The oracles are not weakened: every required probe still
  needs a host-side denial line.
- No committed record describes local permission state or any clipboard content.

| # | Severity | File | Finding | Conf. | Fixed |
|---|---|---|---|---|---|
| CCB-1 | medium | `test/window.ts` | The launch guard parsed only `vscode-remote:` folder arguments. Given a `file:` URI or a plain path, a workspace whose targets claim the canary clipboard could be launched against a stock app. | 8/10 | yes |
| CCB-2 | low | `lint_probes.py` | The clipboard rule matched literal spellings, so aliasing, computed access or destructuring would dodge it. | 9/10 | yes |
| CCB-3 | low | `lint_probes.py` | AppleScript `the clipboard as text` was not matched, and the harness roots left out `patches/` and most of `rpc-filter/`. | 9/10 | yes |
| CCB-4 | low | `probe-safety.js`, `lint_probes.py` | A computed object key, or a `lit()`/probe id taken from a member expression, could carry a host string. | 9/10 | yes |

Fixes:
1. `window.ts` resolves the workspace from `vscode-remote:`, `file:` and absolute-path
   arguments, and refuses any other form.
2. The rule is inverted. In a payload's code, with strings and comments blanked, the
   identifier `clipboard` (or `$readText`) may appear only inside a `withCanaryClipboard(...)`
   argument list. Paste actions, `execCommand('paste')` and `navigator.clipboard` are refused
   outright.
3. The pasteboard rule also matches `return the clipboard` and `the clipboard as …`, and
   scans `patches/` and all of `rpc-filter/`.
4. A new rule, `computed-record-key`, refuses computed keys in record writers. A probe id or
   policy ref must be a literal, `v.id` or an ALL_CAPS constant. `lit()` no longer accepts
   `/`.

Each is pinned by a test in `test_lint_probes.py` (23 tests) or `probe-safety.test.ts`.

Also noted, not reachable: a focused webview's own paste, and page-side `navigator.clipboard`.
The harness forbids focus, and no probe injects such script; the lint now refuses both
spellings in payloads.

## Round 18 (re-review of the fixes, 2026-11-12)
- **Reviewer:** independent `security-review` agent (an Opus-class model), the same injection
  warning in its prompt.
- **Subject:** `05e4198`.
- **Verdict: no high or critical findings.** Round 16's four findings are closed.

One new low, fixed. The comment claimed the inverted clipboard rule could not be dodged, but
blanking whole template literals hid code inside `${...}`, and computed or `Reflect.get`
access went unseen. Now:
- template substitutions are scanned as code;
- dynamic property access on `vscode.env`, `Reflect.get(` and `globalThis[` is refused in
  payloads;
- the comment says the lint complements the runtime guards rather than replacing them.

Pinned by `test_template_substitutions_and_dynamic_access_fail`.
