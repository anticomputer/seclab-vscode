# Review: automated PR review threads on the response-side control (#48)

- **Date:** 2026-11-17
- **Reviewer:** GitHub's automated pull request reviewer, on PR #48, in five rounds. Each thread
  was checked against the code; the review text was treated as data.
- **Subject:** the response-control drift gate (`check_drift.py::check_responses`), the provider
  selector validators' tests, and the command-link rewrite in `seclabFromTab`.

## Verdict
All three threads are real. Two are security-relevant gaps in the gates around the control. The
control itself was proven at runtime by the response probe. The third is a functional bug that
failed safe.

| ID | Sev | Component | Finding | Status |
|---|---|---|---|---|
| PRC-1 | low | `check_drift.py` `check_responses` | The gate accepted any added `seclabFromTab(` in the named patch, so a registration whose customer never applied the sanitiser (the hover rewrite replaced by `return hover;`, or commented out) still passed | fixed |
| PRC-2 | low | `arg-validators.test.ts`, provider selectors | No test reached `tabSelector`: the generic empty-argument case stopped at the arity check, so removing the scheme guard, which keeps a tab's providers off host documents, left the suite green | fixed |
| PRC-3 | high | patch 0033, completion resolve | Resolving a tab completion merged the result into the shown item with upstream's recursive `mixin`, which follows a JSON-parsed own `__proto__` key into the trusted renderer's `Object.prototype`. A tab could set any property on every object there, for example `isTrusted` | fixed before landing |
| PRC-4 | low | `seclabFromTab` markdown | Tab markdown of any length reached the synchronous lexer before the length check, so a huge hover or completion document could stall the trusted UI, past the renderer's own 100,000-character cut | fixed |
| PRC-5 | low | `response-probe` image vectors | With `SECLAB_BEACON_PORT=1024` the extension dropped the port and silently left all three image payloads out, so a control run could pass its listener self-check and report no image fetches without testing any image vector | fixed |

The third thread: the command-link rewrite stopped a query at `'` and at the first `)`, which
`encodeURIComponent` leaves unescaped. A tab's own link with such arguments became a token link
that ran nothing. That is a functional fix, not a finding: the cut link ran nothing at all.

## What changed
- PRC-1: each registration that declares the control lists, in `response_wiring`, the
  expressions that apply it to that registration's results. Each must be in the patch's added
  code with comments removed. `ResponseGateTest` covers a missing list, wiring only in a comment
  or in context, and three mutants of the real 0033; all fail on the previous gate.
- PRC-2: accepted and refused selectors go through both registration validators. Five injected
  defects each remove one selector rule, and each is caught.
- The link rewrite scans the query to whitespace, `"`, `<`, `>`, `]`, a backtick or the `)`
  closing the link, with parentheses inside balanced. `filter-module.test.ts` covers both forms,
  with mutants.

## Second round
Two more threads, both real, both functional regressions this change would have shipped:
- **Bundled providers refused.** Every bundled extension's selector carries `isBuiltin: true`,
  and TypeScript's also names `untitled` and notebook-cell schemes, so TypeScript's hover and
  completion providers were refused in tabs. `isBuiltin` only lowers a provider's priority. The
  validator now accepts plain filters with any short scheme, and 0033 keeps only the tab's own
  documents (`seclabFromTab(...).selector`: other schemes dropped, an absent one made
  `vscode-remote`). The scheme restriction PRC-2 is about now lives there. It is tested on
  TypeScript's real wire shape, with a mutant that keeps host schemes.
- **Code in tab markdown changed.** Escaping `<` and `![` also changed code, where markdown shows
  text literally. Code is now found with the renderer's own lexer (upstream's vendored marked) and
  left as written. Escaping outside code can change how the rest lexes: a backtick freed from an
  escaped attribute re-pairs, and an image kept in code would render. So the result is lexed
  again under both GFM settings, and any image or HTML token, a command link other than the token
  link, or a length past the renderer's cut makes everything escaped instead, as before. Tests
  cover the kept code, the re-pairing case and the length cut, each with a mutant.

## Third round
Four threads, all real.
- PRC-3: on resolve, a tab window now merges with `seclabFromTab(...).resolved`, one level deep and
  never on `__proto__`, `constructor` or `prototype`; other windows keep `mixin`. The case
  `response: a resolved tab completion cannot write through __proto__ (review on #48)` fails on
  the reviewed commit, where 0033 merged with `mixin` and no non-recursive merge existed. Its
  control step, a copy of upstream's `mixin`, pollutes `Object.prototype` there and here. It
  passes with the fix, and a mutant that lets `__proto__` through is caught.
- PRC-4: markdown past the renderer's cut is escaped whole without lexing. A counting wrapper
  around upstream's `marked` shows the lexer is skipped.
- Functional: angle-bracket link destinations (`[docs](<https://…>)`, `[run](<command:…>)`) lost
  their `<`. They keep it now; the re-lex check still decides.
- Functional: with `SECLAB_BEACON_PORT` set, the response probe bound the same port for all three
  image listeners and stopped. Only the first takes it now (`loopbackCounters`, tested in
  `harness-hygiene.test.ts`).

## Fourth round
Three threads, all real.
- PRC-5: the extension takes image ports from 1024 and reports `imagesArmed` in its ready mark.
  The harness requires it and refuses privileged ports. `harness-hygiene.test.ts` pins the three
  rules, each failing on a mutant.
- Functional: an angle-bracket command link with an unbalanced `)` in its arguments was cut
  short. Its query now runs to the `>`.
- Functional: run directly with `SECLAB_MARKED` set to upstream's path, the test's resolve hook
  redirected the counting wrapper's own import to itself. The wrapper's import is excluded now,
  and the runner mounts marked at the upstream path so the standard run covers it.

## Fifth round
Two threads, both real and functional:
- A token command that ran in the tab and failed was reported as a refusal (`Unsupported
  operation` and a deny event), hiding its own error. Only upstream's "does not exist" or
  "Unknown command" rejection is a refusal now. The tab chooses the message, so it can only
  mislabel how its own command ended; nothing runs on the trusted side either way.
- URI autolinks (`<command:…>`, `<https://…>`) lost their `<` and stopped being links. They keep
  it now, and the re-lex check still decides.
