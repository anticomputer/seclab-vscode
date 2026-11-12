# CFS feed values live in host-side config, not the tree

- **Status:** accepted
- **Date:** 2026-11-12
- **Deciders:** project owner (scrub the CFS feed URLs and IDs from history, 2026-11-12); coordinator; the broker and Fork-build sessions (shape).
- **Related:** [CFS local builds](20261105-cfs-local-builds.md), [ADR CFS package feeds in tabs](../adr/20261105-cfs-package-feeds-in-tabs.md), [CFS feeds, tabd side](20261106-cfs-feeds-tabd.md)

## Context
The repository is public. Its history carried the internal CFS feed URLs and the PyPI feed's
GUIDs, and a history rewrite replaced them with example values. Local builds and tabs still
need the real ones, so they must come from somewhere outside the tree.

## Decision
- **One host-side file:** `$SECLAB_CFS_CONFIG`, or `~/.config/seclab/cfs.json`, version 1, with
  `npmRegistry`, `pypiIndex`, `pypiDownload` (the feed-GUID path the index links files under)
  and `tenant`. `./seclab cfs config` writes it from `gh cfs guide npm|pip` and one CFS
  `pip download -v`, mode 0600, and prints no value.
- **One validator:** `tabd/src/cfs-config.ts`, pure (`fs`, `os`, `path`), which ships with tabd;
  `build/cfs-config.ts` is the host-only CLI (`check`, `get`, `write`, `--self-test`). Every
  field is checked against its shape: the host is exactly `pkgs.dev.azure.com`, segments are
  plain names, no dot segments, the download path has two GUIDs, and all three URLs name one
  organisation. The file is refused when it sits inside any git repository, is a symlink, is
  not owned by the user, or is accessible by group or others.
- **Fail closed:** a missing or malformed file means CFS is off, and local Python builds stop
  with a pointer to `./seclab cfs config`. Nothing falls back to a value in the tree. CI keeps
  using public PyPI and needs no file.
- **No value in an image:** `broker/tools/pybuild.sh` passes the index to `pip-fetch.py` as
  the BuildKit secret `cfs_feed_index`, so it never lands in image history. pip-fetch checks
  it with the same rule.
- **No drift:** the TS self-test (`./seclab cfs --self-test`, CI `ci-unit`) and the broker's
  pip-fetch unit test both run `broker/tools/cfs-config.vectors.json`, which holds example
  values only.
- **The local path is tested in CI:** hosted CI builds from public PyPI, so
  `broker/tests/cfs-path/run.sh` (CI `ci-unit`) exercises the CFS path without CFS. A fake `gh`
  records that `pybuild.sh` passes the config's index as `cfs_feed_index`, and that a missing,
  group-readable or malformed config stops the build first. `pip-fetch.py` in CFS mode, with
  both secrets mounted as BuildKit mounts them, fetches a hash-pinned wheel from a stub feed
  (TLS, answering as the feed host on an `--internal` network) with Basic auth, and refuses a
  missing or malformed index secret.
- **Tabs:** tabd builds the tab's CFS policy from the file, and passes the registry and index
  into the tab at creation; the tab-side script checks their shape only (Fork-build session).

## Consequences
- **One setup step per host:** `./seclab cfs config` after `az login`.
- **The reader runs from the working tree, not the broker build's snapshot.** It only chooses
  the index: every wheel is still hash-locked, so a modified reader can't change what is
  installed.
- **Committed files keep example values:** `broker/examples/cfs-feeds.policy.json`, tests and
  docs.
