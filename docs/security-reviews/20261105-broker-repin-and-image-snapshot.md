# Security review: broker re-pin to CFS-served versions, and the image snapshot

- **Date:** 2026-11-05
- **Scope:**
  - `5f41596`: `broker/build.sh` builds the broker image from a snapshot of
    `broker/`'s git-tracked files (review ZZ from the Fork-build session: an
    ignored file could ship under a clean revision label).
  - `eefcc07`: re-pin to the newest versions CFS serves, following the user's
    decision: "Pin back to the newest versions already past the 7-day hold".
    - `fastjsonschema` 2.22.3 to 2.22.2, `dnspython` 2.9.2 to 2.9.1,
      `platformdirs` 4.14.5 to 4.14.0, `pypi-attestations` 0.0.31 to 0.0.30,
      `typing-inspection` 0.4.5 to 0.4.4;
    - `pyasn1` 0.6.5 added.
  - `c15072d`: the harness's `docker` CLI image moves to
    `docker:29.9.2-cli`, under the shared 7-day pin-age rule.
  - Fixes: the round 10 commit.
  - Threat model:
    - an image whose identity labels (revision, base digest, version) don't
      describe what was built, which tabd would then trust (XX-6);
    - a downgrade that weakens what the broker accepts, or that brings a
      reachable vulnerability into the broker or its verifier.
- **Reviewer:** a general-purpose agent on an Opus-class model with long
  context. Triage and fixes by the broker session.
  - It confirmed findings in a throwaway clone.
  - It ran a differential of the two fastjsonschema versions over our real
    schemas.
  - It traced module loads during a real `provenance.py verify` run.

## Findings
| # | Severity | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| 10-1 | Medium | Image identity | `build.sh` built from the snapshot but read the base digest, version and policy revision from the working tree. It also sourced `tools/pybuild.sh` and ran `tools/verify-images.sh` from the working tree before taking the snapshot. `git update-index --assume-unchanged` or `--skip-worktree` hid edits from both `git status` and `git stash create`. The reviewer got a clean label on an image with a different base digest, and a label of version 6.6.6 on an image of 0.3.1. | fixed (round 10 commit) | The snapshot is taken first. Every check and label is then read from it, and `pybuild.sh` and `verify-images.sh` run from it. Any index entry that `git ls-files -v` doesn't show as `H` (assume-unchanged, skip-worktree, unmerged) marks the build `-dirty`. | Clone probes: assume-unchanged plus an edit, and skip-worktree over a committed `VERSION`, both give `-dirty`, with the version read from the snapshot. |
| 10-2 | Low | Image identity | `git archive` honours a committed `export-ignore`, so a tracked file could be dropped from the context under a clean label. Other attributes (`eol`, filters) could change file contents. | fixed (round 10 commit) | The context is written from the git objects (`git cat-file blob`, no filters), not with `git archive`. Only regular files and symlinks are allowed; a submodule fails the build. Symlinks are created last and never over an existing path, so a crafted tree with both `x` and `x/` can't write outside the context. | Clone probes: the context equals the tree by object ID with `export-ignore` and `eol=crlf` committed; a submodule fails; a crafted duplicate-entry tree is refused, and nothing is written through the link. |
| 10-3 | Low | Records | The EDR linked `GHSA-vvf4-9x63-8xvv` in the global advisory database, which returns 404. | fixed (round 10 commit) | It's a published repository advisory (2026-11-04) that isn't in the global database or OSV yet. The EDR links the repository advisory and the v2.9.2 release notes. | n/a |
| 10-4 | Low | Lock drift | `tools/attest/requirements.in` still pinned `pypi-attestations==0.0.31`, so the next `pip-compile` would undo the re-pin and drop `pyasn1`. | fixed (round 10 commit) | The `.in` pins 0.0.30. `pin_check.py` now fails when a lock's `requirements*.in` pins a different version, or holds anything but `name==version` lines. | `broker/docs-check.sh` (checked by setting the `.in` back to 0.0.31: it fails) |
| 10-5 | Info | Policy | Nothing enforced the 7-day rule, and Dependabot had no cooldown. | handed off | The Fork-build session owns the shared `./seclab lint pin-age` and the Dependabot `cooldown` (including `/broker/tools/attest`). Both land with it. | `./seclab lint pin-age` |
| 10-6 | Info | Other images | Only `build.sh` uses the snapshot. The unit, harness, upstream and verifier images still build from the working tree, so ignored files can enter them. | accepted | None of them carries an identity label, and tabd runs none of them, so no label can be wrong. | n/a |

Confirmed sound:
- **Hashes.** All 11 new hashes are the files PyPI serves for those
  versions. No superseded hash remains, and `provenance.py verify` passes
  (44 pins, 32 attestations).
- **fastjsonschema 2.22.2.** The reviewer compiled 80 real validators (the
  policy root, its definitions, and every protocol message) with both
  versions. It ran 84 adversarial inputs through each: booleans in numeric
  fields, braces in keys and values, and `uniqueItems` collisions.
  - **Result:** 6,720 cases, none accepted by one version and rejected by the
    other, and no crashes. Only some error-message texts differ.
  - **The format-string fix** escapes schema keys. Data-derived names are
    substituted as values in both versions. The two dynamic-key sites were
    probed directly.
  - **One validated value can come from a tab or upstream:** the request
    path, through `validate_fragment("path")`. It's covered by the
    differential.
- **dnspython 2.9.1.** During a real `provenance.py verify` (32 attestations,
  live PyPI and Sigstore), neither `dns` nor `email_validator` is loaded;
  `python -m sigstore` loads neither either.
- **pyasn1 0.6.5.**
  - It's reachable: `pypi-attestations` DER-decodes Fulcio claim extensions
    from the Sigstore signing certificate.
  - It has no OSV advisory, and is the newest 0.6.x.
  - `v0.0.30...v0.0.31` of `pypi-attestations` changes only that decoder.
    Verification is unchanged.
- **docker:29.9.2-cli.** The digest is the Docker Official Image index for
  that tag, with linux/arm64. The harness copies only the CLI binary and uses
  no `pull`, `load`, `save`, `build`, content trust or Swarm, so none of the
  29.9.3 fixes is reachable.
- **Nothing found:**
  - `export-subst` doesn't apply when archiving a tree.
  - Tracked symlinks behave as before.
  - Paths with spaces are quoted correctly.
  - Running outside a checkout fails closed.
  - The EXIT trap cleans up.
