# Security review: test build variants, and the gitleaks build fail-closed fix

- **Date:** 2026-11-06
- **Scope:** round CCC:
  - `6f4f450` and its fixes: test build variants (`test/builds/variants.json`,
    `build/test-variant.sh`, `build-macos.yml` `test_variant` and `reh-test`, `check-release`,
    `./seclab fetch macos-<variant>`, `image oci --test-variant`, `test/builds/require-hooks.ts`,
    the rogue-REH hook);
  - `128dbb1`: the gitleaks build failing closed when an arch isn't built.
- **Threat model:** a test build carries test-only hooks by design. It must never reach a
  release path (upload, fetch, tab image tag, check-release), must fail loudly when a listed
  hook is absent, and must not let a probe run report clean against a build without its hook.
- **Records:** [EDR test-build-variants](../edr/20261106-test-build-variants.md).
- **Prompt injection:** none found.

## Round CCC
Confirmed:
- no path from a variant to a release:
  - a variant dispatch skips the release and branch uploads;
  - every test artifact name says `-test-` or `TEST`;
  - release and branch fetches refuse `testBuild`;
  - `:local` refuses a test REH;
  - check-release fails on `seclabTestBuild`, and the hook's marker is a runtime literal that
    survives minification;
- `inputs.test_variant` reaches only `env:` and `with:`, and `reh-test` has only
  `contents: read`, `id-token` and `attestations`;
- the gitleaks fix holds: retries exit correctly, the offline build fails on either arch, and
  `check_bins` and its self-test refuse a missing pin, binary or mismatch.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| CCC-1 | Medium | variants | The record in product.json carried each hook's marker, and the build inlines product.json into several bundles, so "hook present" matched the record even with the hook's code missing. | Fixed | The record has no marker. Each hook names its `bundle` (`out/server-main.js` for rogue-REH), and `verify` and `require-hooks` require the marker in that file. A self-test covers a record inlined elsewhere while the hook bundle lacks the marker. |
| CCC-2 | Low | workflow | A variant dispatch on main shared the release concurrency group, so it could cancel a pending release build. | Fixed | The group includes the variant (`release` otherwise). |
| CCC-3 | Low | fetch | The fetch matched the hook list against this checkout, not the run's commit, so another branch's series and build scripts were accepted. | Fixed | The run's commit must be HEAD or an ancestor of it. |
| CCC-4 | Low | patch-build | `check-all` looped over a command substitution, so a failed or empty manifest read passed. | Fixed | Read on its own line, empty refused; a target's hooks are checked together, in order. |
