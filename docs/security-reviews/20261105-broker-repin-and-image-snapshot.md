# Security review: broker re-pin to CFS-served versions, and the image snapshot

- **Date:** 2026-11-05
- **Scope:**
  - `4ac288b`: `broker/build.sh` builds the broker image from a snapshot of
    `broker/`'s git-tracked files (review ZZ from the Fork-build session: an
    ignored file could ship under a clean revision label).
  - "broker: re-pin to versions CFS serves": re-pin to the newest versions CFS serves, following the project owner's
    decision to pin back to the newest versions already past the 7-day hold.
    - `fastjsonschema` 2.22.3 to 2.22.2, `dnspython` 2.9.2 to 2.9.1,
      `platformdirs` 4.14.5 to 4.14.0, `pypi-attestations` 0.0.31 to 0.0.30,
      `typing-inspection` 0.4.5 to 0.4.4;
    - `pyasn1` 0.6.5 added.
  - "broker: harness docker CLI image to docker:29.9.2-cli": the harness's `docker` CLI image moves to
    `docker:29.9.2-cli`, under the shared 7-day pin-age rule.
  - Fixes: the commits titled "broker: fix security review round 10", "… round 10b"
    and the round 10c commit. The 10b re-review checked the round 10 fixes and
    found new holes in the rewritten snapshot writer; the 10c re-review
    confirmed every 10b fix on both shells and found three lows.
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
- **Editorial redaction (2026-11-12):** quotations of project conversations replaced with neutral statements; decisions unchanged.

## Findings
| # | Severity | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| 10-1 | Medium | Image identity | `build.sh` built from the snapshot but read the base digest, version and policy revision from the working tree. It also sourced `tools/pybuild.sh` and ran `tools/verify-images.sh` from the working tree before taking the snapshot. `git update-index --assume-unchanged` or `--skip-worktree` hid edits from both `git status` and `git stash create`. The reviewer got a clean label on an image with a different base digest, and a label of version 6.6.6 on an image of 0.3.1. | fixed (round 10 commit) | The snapshot is taken first. Every check and label is then read from it, and `pybuild.sh` and `verify-images.sh` run from it. Any index entry that `git ls-files -v` doesn't show as `H` (assume-unchanged, skip-worktree, unmerged) marks the build `-dirty`. | Clone probes: assume-unchanged plus an edit, and skip-worktree over a committed `VERSION`, both give `-dirty`, with the version read from the snapshot. |
| 10-2 | Low | Image identity | `git archive` honours a committed `export-ignore`, so a tracked file could be dropped from the context under a clean label. Other attributes (`eol`, filters) could change file contents. | fixed (round 10 commit, completed by the 10b fixes) | The context is written from the git objects (`git cat-file blob`, no filters), not with `git archive`. Only regular files and symlinks are allowed; a submodule fails the build. As first written, the symlink handling was not safe; see 10b-1 and 10b-2. | Clone probes: the context equals the tree by object ID with `export-ignore`, `eol=crlf` and a smudge filter configured; a submodule fails. |
| 10-3 | Low | Records | The EDR linked `GHSA-vvf4-9x63-8xvv` in the global advisory database, which returns 404. | fixed (round 10 commit) | It's a published repository advisory (2026-11-04) that isn't in the global database or OSV yet. The EDR links the repository advisory and the v2.9.2 release notes. | n/a |
| 10-4 | Low | Lock drift | `tools/attest/requirements.in` still pinned `pypi-attestations==0.0.31`, so the next `pip-compile` would undo the re-pin and drop `pyasn1`. | fixed (round 10 commit) | The `.in` pins 0.0.30. `pin_check.py` now fails when a lock's `requirements*.in` pins a different version, or holds anything but `name==version` lines. | `broker/docs-check.sh` (checked by setting the `.in` back to 0.0.31: it fails) |
| 10-5 | Info | Policy | Nothing enforced the 7-day rule, and Dependabot had no cooldown. | handed off | The Fork-build session owns the shared `./seclab lint pin-age` and the Dependabot `cooldown` (including `/broker/tools/attest`). Both land with it. | `./seclab lint pin-age` |
| 10-6 | Info | Other images | Only `build.sh` uses the snapshot. The unit, harness, upstream and verifier images still build from the working tree, so ignored files can enter them. | accepted | None of them carries an identity label, and tabd runs none of them, so no label can be wrong. | n/a |
| 10b-1 | High | Snapshot writer | `ln -s` had no `--`. On Linux (CI), a committed symlink whose target starts with `-` (e.g. `-f`, `-rf`) made GNU `ln` read it as options: the entry was dropped from the context, a stray link was made in the working directory (`-f` overwrote a file there), and the label stayed clean. The tree is valid and pushable. macOS `ln` failed closed. | fixed (round 10b commit) | `ln -s -- "$target" "$out"`; an empty target is refused. | Writer probes under macOS `/bin/sh` and dash with GNU `ln` 9.7: links to `-rf` and `-f` match the tree by object ID; no stray link appears. Replayed in CI since 2026-11-12: `broker/tests/snapshot/run.sh` (dash and `bash --posix`, GNU `ln`). |
| 10b-2 | Medium | Snapshot writer | In the links pass, `mkdir -p` followed a symlink made earlier in the same pass. A tree with a symlink `esc` and entries under `esc/` wrote outside the context under a clean label. Such a tree fails `git fsck`, so GitHub refuses it; the vector is local only. This refuted the first version of 10-2's claim. | fixed (round 10b commit) | Three passes: every parent directory first (no symlink exists yet), then files, then symlinks. No entry may already exist, or have a symlink parent, when it is written; parents are computed with parameter expansion, not `dirname`. | Writer probes (both shells): `esc` link plus `esc/`, a file and a directory with the same name, and an empty link are all refused; nothing is written outside the context. In CI: `broker/tests/snapshot/run.sh`. |
| 10b-3 | Low | Snapshot writer | `dirname` without `--`: a path whose first component starts with `-` aborted the build. | fixed (round 10b commit) | The parent is `${path%/*}`. | Writer probe: `-n/f.txt` builds and matches. In CI: `broker/tests/snapshot/run.sh`. |
| 10b-4 | Low | Snapshot writer | Any path git quotes (a non-ASCII name, a tab, `"`, `\`) aborts the build, and nothing warned earlier. | fixed (round 10b commit) | `pin_check.py` flags such paths under `broker/`, so `docs-check` fails first. The build still refuses them. | `broker/docs-check.sh` with `broker/café.md` present: it fails. |
| 10b-5 | Low | Lock drift | A missing, empty or comment-only `requirements.in` turned the drift check off. | fixed (round 10b commit) | A lock that is pip-compile output (`# via` annotations) must have its `.in`. The `.in` must pin something, and every direct requirement (`via -r requirements.in`) must be pinned in it. | `broker/docs-check.sh` with the `.in` missing, empty and comment-only: all three fail. |
| 10b-6 | Info | Comment | The comment said local runs never use attestation bundles, but an explicit `SECLAB_ATTESTATION_DIR` makes `verify-images.sh` use them. A forged bundle still fails; only staleness is exposed. | fixed (round 10b commit) | The comment now states the real contract. That contract (`$CI` or `$SECLAB_ATTESTATION_DIR`) is unchanged. | n/a |
| 10b-7 | Info | Snapshot writer | The files pass had no collision guard. On a case-insensitive filesystem two names that differ only in case collapse into one. The label was already `-dirty`, because the working tree can't represent such a tree. | fixed (round 10b commit) | The same "must not exist yet" guard as for symlinks. | n/a |
| 10c-1 | Low | Lock drift | The drift gate decided that a lock was pip-compile output from its own `# via` comments. Deleting the `.in` and stripping those comments turned the gate off. | fixed (round 10c commit) | The pairing is registered in `broker/deps.json` `lockSources`. A registered pair needs both files, and every `requirements*.in` must be registered. | `broker/docs-check.sh` with the `.in` deleted and the annotations stripped fails; so does an unregistered `.in`. |
| 10c-2 | Low | Snapshot writer | `$(git cat-file blob …)` drops trailing newlines, so a symlink whose target ends in `\n` was written one byte short of the tree, under a clean label. | fixed (round 10c commit) | The target's byte length must equal the blob's size (`git cat-file -s`); otherwise the build fails. | Writer probe (macOS `/bin/sh` and dash): a trailing-newline target is refused; embedded newlines and plain targets are written exactly. |
| 10c-3 | Low | Path lint | The quoting lint walked the working tree, so an ignored or untracked local file broke `docs-check`, and a tracked path that wasn't checked out was missed. | fixed (round 10c commit) | `broker/docs-check.sh` lints `git ls-files -- broker` (tracked paths, the set `build.sh` snapshots) instead of `pin_check.py` walking the tree. | An untracked odd name passes; the same name once added to the index fails. |

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
