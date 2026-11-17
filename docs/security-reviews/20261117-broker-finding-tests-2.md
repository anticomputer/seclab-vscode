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
