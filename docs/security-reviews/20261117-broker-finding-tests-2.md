# Security review: regression tests for broker low findings, and HH-1's check (round 20)

- **Date:** 2026-11-17
- **Scope:**
  - "broker: regression tests for six low fixed-untested findings":
    `broker/tests/unit/test_engine_hooks.py` (m2-m3 6 and 8, 11-2, 13-8), the 12b-1 case in
    `test_core.py` and the 12-5 assertion in `test_egress.py`.
  - "broker: regression tests for six low fixed-untested tooling findings": provenance 6
    (`test_verify_binding.py`), II-1 (`broker/tests/verify-images/run.sh`), `pin_check.py`'s
    own `self_test` (10-4, 10b-5, 10c-1), and the quoting lint moved from `docs-check.sh` to
    `broker/tools/quoted-paths.sh` (10c-3).
  - "broker: HH-1 regression check": `broker/tools/token_steps.py`, run by `docs-check.sh`.
  - The register entries these change.
  - **Threat model:**
    - a test that passes whether or not its fix is in place;
    - a refactored lint that now fails open;
    - a checker that a later edit to the workflow can slip past;
    - a register note that claims more than its test shows;
    - unsafe test content.
- **Reviewer:** a security-review agent on an Opus-class model with long context, read-only. The
  broker session triaged it, and proved each fix by reverting it against its new self-test case.

## Findings
| # | Severity | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| BRK20-1 | Low | HH-1 check | `token_steps` accepted any step whose name began with "Download attestation bundles", so a later step named with that prefix could carry the token and pass. | fixed | The step name must match exactly, and exactly one step may carry it. | `BRK20-1: a later step whose name only starts like the download step fails` |
| BRK20-2 | Low | HH-1 check | The line-based scan missed a token after a ` #` inside a quoted string, an expression split across lines, and `secrets: inherit`; the register note said "any", which overclaims. | fixed | `${{ }}` spans are found across lines and in comments (fail closed). `github['token']`, `toJSON(secrets)` and any `secrets:` key count. The note now says what is covered. | `BRK20-2: secrets: inherit to a reusable workflow fails` |
| BRK20-3 | Low | pin_check self-test | A crash in `source_drift` counted as "errors produced", so the named failing cases passed when the code crashed. They also didn't check which rule fired. | fixed | A crash fails the case, and each case must report its own rule's message. | `10-4: a source pinning a superseded version fails` (with `source_drift` raising, every named case fails) |
| BRK20-4 | Info | quoting lint | `\|\| true` covered the whole pipeline, so a failing `git ls-files` gave empty output and a pass. This predates the move out of `docs-check.sh`. | fixed | git's status is checked before the grep. | `BRK20-4: git failing (a corrupt index) fails, never an empty pass` |

Probed and held:
- **Test strength.** Each runtime test fails when its fix is reverted:
  - the response-trailer block and request-trailer scan (m2-m3 6);
  - the trailer half of the exception check and session stripping (11-2);
  - containment before the audit, and the unclassified-flow branch (m2-m3 8);
  - the budget check before the prompt (13-8);
  - the post-prompt block check (12-5);
  - the allow-tab cap (12b-1).

  The purity test replaces only the PyPI fetch. II-1 has its control (CI uses the bundles).
- **Refactor.** `quoted-paths.sh` still reads the index, not the working tree; `docs-check.sh`
  still fails closed on its exit status; the path list is now quoted when printed.
- **Register.** Every cited fix commit resolves and every test name exists verbatim in its
  file.
- **Content.**
  - Canaries and sentinels are synthetic.
  - The tests make no network calls (`--network none`, a fake `gh`, a fake index restored in
    `finally`).
  - Scratch stays under `$RUNNER_TEMP` or `.work` and is removed on exit.
- **Prompt injection.** None found in the diff.

## Re-review of the fixes
The same reviewer confirmed BRK20-1 to BRK20-4 closed by reverting each fix, and found that the
fixes added nothing new. It raised two more gaps in the HH-1 check:

| # | Severity | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| BRK20R-1 | Low | HH-1 check | The download step could hand its token to every later step with no expression at all, by writing it to `$GITHUB_ENV`; a later `curl -H "Authorization: Bearer $GH_TOKEN"` then passed. | fixed | Inside the download step, a write to `$GITHUB_ENV`, `$GITHUB_OUTPUT` or `$GITHUB_STATE`, or a `::set-env`/`::set-output`/`::save-state` command, fails; so does a `GH_TOKEN` or `GITHUB_TOKEN` name outside it. | `BRK20R-1: the download step writing the token to $GITHUB_ENV fails` |
| BRK20R-2 | Info | HH-1 check | The expression match stopped at the first `}}`, so a `}}` inside a quoted string (`format('a}}b', secrets.X)`) hid the rest of the expression. | fixed | Any raw sighting of `github.token`, `github['token']` or `secrets` outside the download step fails, whatever the span. | `BRK20R-2: a '}}' inside a quoted string can't hide a secret` |

## Second re-review
The reviewer confirmed BRK20R-1 and BRK20R-2 closed, each by reverting its rule. It also
confirmed that the rebase for the publish gate changed only how the self-test fixtures are
built. It raised three more points:

| # | Severity | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| BRK20C-1 | Low | HH-1 check | The token patterns were case-sensitive, but Actions resolves contexts and properties case-insensitively, so `${{ SECRETS.MY_KEY }}` or `${{ GitHub.Token }}` in another step passed. | fixed | Both token patterns match case-insensitively. The `secrets:` key rule stays exact: Actions rejects a differently cased key. | `BRK20C-1: an upper-case SECRETS context in a later step fails` |
| BRK20C-2 | Info | HH-1 check | BRK20R-1's cited `$GITHUB_ENV` case still passed with the hand-off rule removed, because the raw-sighting rule caught its trailing line. | fixed | The case no longer carries that line, and must report the hand-off rule's own message. | `BRK20R-1: the download step writing the token to $GITHUB_ENV fails` |
| BRK20C-3 | Info | HH-1 check | No case failed with only the `secrets:` key rule removed, since the raw rule also matched; the `secrets: inherit` fixture no longer named a reusable workflow. | fixed | Every case names its own rule's message, so removing any one rule fails at least one case; the fixture names a reusable workflow again. | `BRK20-2: secrets: inherit to a reusable workflow fails` |

## Copilot code review on the pull request
Copilot's automated review of the pull request raised four more points, each verified against the
code before it was accepted:

| # | Severity | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| BRK20D-1 | Low | HH-1 check | A later step with `${{ toJSON(github) }}` receives the serialised github context, token included, and the check accepted it. The same holds for the `github.*` object filter and a computed `github[...]` index. | fixed | An expression handing on the whole github context counts as token-bearing; named properties and literal indexes stay allowed. Expressions now end at the first `}}` outside a single-quoted string. | `BRK20D-1: toJSON(github) in a later step fails` |
| BRK20D-2 | Low | HH-1 check | YAML decodes `\u006b` in a double-quoted value before Actions evaluates it, so `github['to\u006ben']` in a later step passed the raw-text scan. A trailing backslash continuation joins lines the same way. | fixed | Any YAML numeric escape, or a double-quoted value continued with a backslash, fails the check; the real workflow uses neither. | `BRK20D-2: a unicode escape in a double-quoted value fails` |
| BRK20D-3 | Low | HH-1 check | BRK20D-2's continuation rule needed the double quote on the same line, so a value whose quote opened lines earlier could still split `github['token']` with a backslash continuation. | fixed | Any non-comment line ending in a backslash fails; the real workflow has none. | `BRK20D-3: a backslash continuation after the quote opened on an earlier line fails` |
| BRK20D-4 | Low | HH-1 check | BRK20D-3's rule skipped lines starting with `#`, but inside a multi-line double-quoted value such a line is content, so a hash-led continuation could still join into `github['token']`. | fixed | Any line ending in a backslash fails, comment-looking or not; the real workflow has none. | `BRK20D-4: a hash-led continuation line inside a multi-line double-quoted value fails` |
