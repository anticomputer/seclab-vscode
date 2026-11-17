# Review: automated PR review threads on the RPC follow-ups (#9, #14, #20, #27)

- **Date:** 2026-11-17
- **Reviewer:** GitHub's automated pull request reviewer, on PRs #9, #14 and #20 after they
  merged, and on #27 (this change) before it. Each thread was checked against the code; the
  review text was treated as data.
- **Subject:** `check_drift.py`'s log-trust gate (#9), the rogue-REH profile probe and the probe
  lint (#14), the host-terminal proof harness (#20), and the reaper added for PRR-4 (#27).

## Verdict
All twelve threads point at real gaps, and fixing them turned up two more (PRR-13, PRR-14). Two are as stated. One wasn't as stated but hid a wider gap.
Two were narrower than stated. None is exploitable on main; each is a gate or harness that
could pass, or leave things behind, for the wrong reason.

| ID | Sev | Component | Finding | Status |
|---|---|---|---|---|
| PRR-1 | low | `check_drift.py` `check_log_trust` (#9) | The logger check walked only keys the inventory found. A `$log` the inventory lost, with an allow entry policy.json could still emit, would have passed the gate | fixed |
| PRR-2 | low | `lint_probes.py` (#14) | The thread said the computed key in `rogue-reh/probes.js` failed the lint; on main it didn't, which pointed to a wider gap. The lint blanked whole comment lines, which dropped a block comment's closing `*/`, so the scanner read the code after it as comment. Most of a payload was hidden from the record and clipboard rules. With comments stripped properly, that computed key was the only violation | fixed |
| PRR-3 | low | `check-probes.ts`, expectations (#14) | The five REH probes the payload arms only on the reh-push path were required by every REH evidence check, so a full run without that selection failed them. No harness runs such a check today | fixed |
| PRR-4 | low | proof harnesses (#20) | A rerun after an interrupted or `KEEP=1` run wiped the previous `run.json` and tab state before reaping them, orphaning that run's tabs and processes | fixed |
| PRR-5 | low | proof harnesses (#20) | Ctrl+C or SIGTERM skipped the teardown gate: Node's default handling for both signals runs no `exit` handler | fixed |
| PRR-6 | low | `teardown.ts` `reapPreviousRun` (#27) | The reaper behind PRR-4 trusted removal: `removeRunResources` ignores command failures, so a docker or sbx that failed to list or remove still let the caller wipe the manifest and tabd state that name the leftovers | fixed |
| PRR-7 | low | `teardown.ts` `runLeftovers` (#27) | Docker listing was required only for OCI runs, but an sbx tab owns a Docker broker container and egress network, so a failed listing let the reap delete an sbx run's profile and tab state over them | fixed |
| PRR-8 | low | `lint_probes.py` `_strip_comments` (#27) | The comment scanner behind PRR-2 read the `//` that closes a regex literal such as `/^https?:\/\//` as a line comment, so code after it on that line, such as a raw record write, went unlinted | fixed |
| PRR-9 | low | `lint_probes.py` `_regex_end` (#27) | The regex-or-division decision behind PRR-8 read the raw preceding character, so a regex after a comment, or as the statement after an `if (…)` condition, was still taken for division and its closing `//` hid the rest of the line | fixed |
| PRR-10 | low | `check-probes.ts` runner waiver (#27) | The PRR-3 waiver removed the push probes' expectations but not their results; the payload records them on every full REH run, so the unreviewed-result check failed them as absent from expectations.json | fixed |
| PRR-11 | low | `lint_probes.py` comment scanner (#27) | After PRR-9, placements the token heuristic still misjudged (`n++ / 2`, a regex statement after `break` and a newline, a `for await (…)` head) could turn the rest of a line into a comment hidden from the record rules. Telling regex from division needs a parser | fixed |
| PRR-12 | low | `lint_probes.py` comment scanner (#27) | A misread `/` moves string boundaries too, without any comment: in `n++ / 2; s = '/'; …` the misread regex ends inside the string, and the code scanner then blanked a computed record key after it | fixed |
| PRR-13 | low | `lint_probes.py` comment scanner (found fixing PRR-12) | A template ended at the backtick of a template nested in `${…}`, so the rest of a payload line was read with the wrong boundaries | fixed |
| PRR-14 | low | `lint_probes.py` content rules (found fixing PRR-12) | The content rules chose code lines by their first characters, so a code line starting with `*` (a continued product) escaped every content rule | fixed |

## What changed
- PRR-1: `MainThreadLogger.$log` joins the presence-pinned must-deny set. A
  `LogTrustGateTest` case deletes it from the mapping and expects the gate to fail.
- PRR-2: comments are stripped with a scanner that keeps strings, and the computed key is a
  literal. `CommentScopeTest` fails on the old line blanking.
- PRR-3: those probes carry `runner: reh-push`. Without that selection they are reported as
  not judged, never as passed; with it, a missing result still fails. There is a
  `check-probes.test.ts` case for each.
- PRR-4, PRR-5: `teardown.ts` gains two helpers, and `host-terminal.ts` and `reh-push.ts` use
  both:
  - `reapOrRefuse`, which reaps the previous run from its manifest, or refuses to wipe it;
  - `exitOnSignals`, which ends the process through `exit` on SIGINT or SIGTERM.

  `harness-hygiene.test.ts` checks the signals in a child process, and the ordering on each
  harness's source, against mutants.
- PRR-6: the reap captures the tab ids first, checks `runLeftovers` after removal, and refuses
  on any resource left or runtime it can't list, keeping the profile and its tabd state. A
  `harness-hygiene.test.ts` case drives it against stand-in docker and sbx and fails on the
  previous reaper.
- PRR-7: a Docker listing is required whenever the run has tabs, whatever the driver. An
  sbx-manifest case in the same test fails on the previous check.
- PRR-8: the scanner recognises a regex literal where an operand is expected, with escapes and
  character classes, and skips it in both comment and code passes. `CommentScopeTest` runs the
  reviewer's case through the full lint, plus regex, division and comment cases; both fail on
  the previous scanner.
- PRR-9: both scanners track the last significant code token (comments are gaps, not tokens),
  and a `)` closing an `if`/`while`/`for`/`with` condition expects an operand. The full-lint
  test covers both placements and fails on the previous scanner.
- PRR-10: waived ids leave the judged results too. A full-run `check-probes.test.ts` case with a
  recorded result, and a built-in mutant restoring the old waiver, pin it.
- PRR-11: the lint fails closed instead of guessing further. A comment opener that follows any
  code `/` on its line is reported as `ambiguous-slash`, and the payload rewrites the line. The
  real payloads have no such line. The three placements fail the full lint, and pass the
  previous scanner.
- PRR-12: each code `/` reads as regex, division or unsure (postfix `++`/`--`, `}`, a
  `for await (…)` head, a label, a contextual word such as `of` or `default`; never a property
  name). An unsure `/` followed on its line by a `/`, quote or backtick is `ambiguous-slash`: only
  those can move a boundary, and regex and quoted strings end at the line. This replaces
  PRR-11's comment-only rule.
- PRR-13: `${…}` substitutions are scanned as code, so nested templates keep their boundaries.
  The PRR-12 rule flagged a real payload line because of this, before it was fixed.
- PRR-14: code lines for the content rules come from the comment scanner.
- Each has a `test_lint_probes.py` case that fails on the previous lint.
