# Ship exactly the reviewed patch series; check release artifacts for test hooks

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** fork-build session (raised by the RPC-lockdown session)
- **Related:** [ADR VSCodium-style fork](../adr/20261104-vscodium-style-fork.md), [patches/README.md](../../patches/README.md), security review (patch guard) in [20261104-fixture-safety.md](../security-reviews/20261104-fixture-safety.md)

## Context
- `build/prepare.sh` applied every `patches/[0-9][0-9][0-9][0-9]-*.patch` file
  unconditionally.
- The RPC-lockdown session nearly added an env-gated rogue-REH test hook as such a
  patch, which would then have shipped in every release build.
- A test hook in a release is a backdoor. The usual shape is `require(process.env.X)`.

## Decision
1. **Explicit series.** `patches/series` lists exactly the patches that ship, in order.
   - `build/apply-patches.sh` applies only those.
   - It fails on any other file in `patches/` (except README.md and `series`), on a
     missing, duplicate or malformed entry, on a non-regular file, and on an empty
     series.
   - `--check` validates without a checkout. CI runs it in the `unit` job.
   - It works under bash 3.2, as on hosted macOS runners.
2. **Release-artifact check.** `build/check-release.sh` scans the shipped JS (the
   REH tarball in ci-linux, and the `.app` in `build-darwin.sh`). It fails on:
   - test-hook markers: `SECLAB_TEST_ONLY`, `seclab-test-hook`, `rogue-reh`,
     `rogue-extension`;
   - env-controlled module loading: `require(`/`import(` of `process.env…`;
   - any scan error;
   - a path without JS (a wrong path would otherwise pass silently).
   
   Locally it runs in a network-less container. On CI runners without docker
   (macOS), it runs the same POSIX logic natively.
3. **Convention:** test-only code that could ever reach a build must carry
   `SECLAB_TEST_ONLY`, so the check finds it. Test hooks live in the harness, not in
   `patches/`.

## Addendum (review PG-1, same day)
The guard covers everything we overlay, not just `patches/`:
- **`extensions/series`** lists the built-in extensions that ship, and `prepare.sh`
  fails on any other `extensions/seclab-*`.
- **`build/check-source.ts`** (`./seclab lint source`, CI) scans the shipped sources,
  that is the series extensions plus `tabd/src`:
  - every `process.env` and child-process site must be in the reviewed
    `build/source-allowlist.txt`, matching the exact line, and stale entries fail;
  - dynamic module loading and test markers always fail.
- The Tab Manager no longer forwards the `SECLAB_SBX`/`SECLAB_DOCKER` overrides.

Record: [security review](../security-reviews/20261104-patch-guard.md).

## Alternatives considered
- **Separate `patches-test/` directory, applied by a flag:** possible later, but the
  series file plus the release check already make shipping by accident impossible.
- **Rely on review alone:** rejected, because the near-miss happened under review.

## Consequences
- Adding a patch takes two edits: the file and the series. That is intended.
- The release check is a tripwire for the known hook shapes, not a proof. Obfuscated
  loaders (for example a computed `require`) need review.

## Evidence
`build/apply-patches.sh --check` passes on the tree. It fails on a planted
`0005-test-only-hook.patch` ("not in patches/series") and on a missing listed patch.
Under `/bin/bash` 3.2 it passes.

`build/check-release.sh`:
- clean on the real REH tarball and on the macOS app (run 41885877522);
- fails on a planted `require(process.env.HOOK)` and on a `SECLAB_TEST_ONLY` marker,
  in a directory and in a tar.gz;
- the native CI mode gives the same results.

While testing, two silent-pass bugs were found and fixed:
- busybox `grep --include` errors had been swallowed;
- a tarball mounted without its extension was never extracted.

Both are now covered by the fail-closed rules.
