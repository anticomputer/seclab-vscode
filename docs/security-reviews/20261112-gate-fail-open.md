# Security review: gate fail-open fixes (GATE-2 to GATE-8, GATE-10)

- **Date:** 2026-11-12
- **Scope:** round SSS, the fixes for the gate fail-open audit's fork-build findings and the
  round's own follow-ups:
  - `build/check-patch-reach.ts` (GATE-2, GATE-3), `build/patch-reach-imports.test.ts`;
  - `build/check-pins.ts` (GATE-4, GATE-7), `test/safety/fixture-lint.ts` (GATE-5 to GATE-7),
    `test/safety/gate-inputs.test.ts`;
  - `seclab` `verify_signed_image` (GATE-8), `build/tools/tool.sh`;
  - `test/harness.ts` `watchFocus`/`focusWatchProblem`, `test/containment/teardown.ts`
    (GATE-10).
- **Threat model:** a required gate must never report success while checking nothing or less
  than it claims; a local verifier must not be skippable or replaceable by a file or name any
  local process can create.
- **Records:** [EDR liveness-gate](../edr/20261109-liveness-gate.md) ("check the prover before
  believing it"), [EDR pinned tools](../edr/20261105-pinned-tools.md),
  [ADR supply-chain provenance](../adr/20261104-supply-chain-provenance.md).
- **Prompt injection:** none found.

## Round SSS
Two mediums, two lows. Confirmed:
- `unreachable.json` with only an `except`, an unknown target, a `reach.json` naming a patch
  not in the series, and a misspelt target all fail closed;
- the evidence-directory scan can't mask an empty root (the zero-scanned check runs first);
- the only tracked symlink is a directory link inside the repo, so skipping symlinks hides no
  file;
- every new `catch` fails the gate, and exit codes propagate.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| SSS-1 | Medium | list-driven gates | The canary was the one file each gate skips, so a list naming only it reported "clean (0 files)"; a list cut after `build/check-pins.ts` (early in sort order) passed check-pins. | Fixed | Both require anchors spread through `git ls-files` order, ending with the last tracked file (`upstream.lock`), and fail when nothing was scanned. Tests: canary-only, truncated. |
| SSS-2 | Medium | tool images | `build/tools/tool.sh` reused any local image carrying the content tag, a name any local process could `docker tag` onto another image, so the cosign that GATE-8 relies on could be replaced. | Fixed | No reuse by tag: the image is rebuilt on every use (cache hits: about 6 s); a release artifact that still matches its sha256 pin isn't downloaded again. |
| SSS-3 | Low | reach.json | An entry emptied to `[]` (or naming no known target) dropped that patch's requirement. | Fixed | Each value must be a non-empty list of known targets; two injected cases. |
| SSS-4 | Low | watcher record | The watcher's record lived in the editor's own profile, which the editor writes; and the watcher could start before the profile existed. | Fixed | The record is a sibling of the profile (`<profile>.focus-watch.log`), removed by teardown; its directory always exists. |
| SSS-5 | Low | launch record | The launch record that turns the watcher check on is still in the profile. Removing it needs host-side code; tab code can't reach the host profile. | Accepted | |
| SSS-6 | Low | Docker store | A process with Docker access controls the image store and build cache. That is root on the Docker VM, outside these gates. | Accepted | |

## Round UUU (the register entries for these findings and the headless driver's)
Reviewed the commit that registers GATE-2 to GATE-10, m0#3-1, m0#4-1 and rounds QQQ to TTT,
by an Opus-class model. One medium. Confirmed:
- each cited fix commit is the one that fixed its finding, and each cited test injects the
  finding's failure mode;
- the baseline only shrank, and only for findings now fixed with a test; m0#2b-1 and m0#3-2 stay
  in it until patch 0041;
- GATE-8 is honestly untested, and the residual rationales match the code;
- the TTT-2 assertion runs as root in the unit container and fails if either sentinel check is
  removed.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| UUU-1 | Medium | `build/deps.ts` | GATE-7 was marked fixed, but `deps.ts` (one of its three components) still skipped a tracked file it couldn't read, dropping its pins from the check. | Fixed | It reports the file, as check-pins does; a case in `test/safety/gate-inputs.test.ts` injects a missing listed file and fails without the fix. |
| UUU-2 | Low | local-window test | The control was matched on the element id and the fixtures on status text, and every fixture check is a negative, so an empty innerText or a renamed marker would pass them all. | Fixed | The control must show status text through the same path, and each fixture must set exactly the marker the run looks for. macOS 17/17. |
| UUU-3 | Low | `cdpFdHolders` | If the editor's own fds 3 and 4 couldn't be read, it returned no holders, so the self-test passed without evidence. | Fixed | It reports "unknown" unless it found both. macOS 8/8. |
| UUU-4 | Low | focus evidence | Besides the launch record (SSS-5), the focus-steal log is also inside the profile, so deleting either there turns "nobody looked" or "took focus" into clean. | Accepted | Only host code writes the profile; tab code can't reach it, and local windows run only ui built-ins (m0#3-1). |
| UUU-5 | Info | register citations | Three entries cited fragments of a case table rather than whole names. | Fixed | The check-patch-reach cases carry their finding IDs; the register cites whole labels. |
| UUU-6 | Info | ARCHITECTURE.md | It still said main-process routing was proposed. | Fixed | Accepted, patch 0041 pending, interim 0042. |
| UUU-7 | Info | round labels | Labels QQQ to TTT also exist in the register's own record with other meanings, so bare labels in code comments are ambiguous. | Accepted | Register keys are record-qualified; new comments name the record when it matters. |
