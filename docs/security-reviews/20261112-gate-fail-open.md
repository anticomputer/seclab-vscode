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
