# Security review: CFS feed values from host-side config, and GATE-9 (round 17)

- **Date:** 2026-11-12
- **Scope:**
  - "CFS feed values come from host-side config, never the tree": the host file
    (`~/.config/seclab/cfs.json` or `$SECLAB_CFS_CONFIG`), the validator
    `tabd/src/cfs-config.ts`, the CLI `build/cfs-config.ts`, the BuildKit secret
    `cfs_feed_index` through `pybuild.sh` and `pip-fetch.py`, the shared vectors, and the
    CI test of the local path (`broker/tests/cfs-path/run.sh`). Design:
    [EDR cfs-config-outside-repo](../edr/20261112-cfs-config-outside-repo.md).
  - "broker docs: --run-commands fails on a missing doc or zero blocks" (GATE-9).
  - **Threat model:** the repository is public. The real feed URLs and GUIDs must not reach
    the tree, image layers or metadata, BuildKit cache keys or provenance, or CI logs; the
    stub test must not reach the real feed, a real network, the real `gh`, or the
    developer's config; `--run-commands` must not pass having run nothing.
- **Reviewer:** a security-review agent on an Opus-class model with long context,
  read-only, with no access to the host config. Two passes: a general one, and one on the
  coordinator's two questions. Triage by the broker session.

## Findings
None.

Questions asked by the coordinator:
- **Can a config value leave the developer's machine?** No. The index reaches the build
  only as a BuildKit secret (an env-sourced secret, never a build arg), so image history and
  config show only the mount's id. `pip download` writes nothing carrying the URL into
  `/wheels`, and the final stage installs offline. Secret contents are not cache keys, and
  nothing on this path exports provenance. No error message on the path echoes a value: the
  CLI reports a failed `gh` call by exit status only, and an unexpected error as `failed`.
  CI runners are GitHub-hosted with `CI` set, so builds take the public branch, and both new
  CI steps use their own scratch config. pip prints the index in the developer's own
  terminal during a local build; no caller on this path writes that output to a file.
- **Can the stub test reach anything real?** No. The fake `gh` is first on `PATH` and
  `pybuild.sh` calls `gh` by name; every call sets `SECLAB_CFS_CONFIG` to a scratch file,
  and the container fallback for Node has no network and no home mount. The stub feed and
  every fetch run on an `--internal` network with no published port. Cleanup removes only
  the scratch directory and the test's two randomly named Docker objects.

Probed and held:
- **Validator:** anchored per-field shapes, dot segments refused separately, unknown keys
  (including `__proto__`) refused, one organisation across the URLs, the parent directory
  resolved before the repository walk, and symlinks, other owners and group or other access
  refused. The self-test checks each refusal by its message.
- **pip-fetch:** the token can't inject netrc lines, the netrc names only the feed host and
  lives on a verified tmpfs, the child environment is an allowlist, a missing or bad index
  secret fails closed, and the token is checked absent from every fetched file.
- **supplychain:** the fetch flags are an exact, ordered list, and the index secret can't be
  mounted in a stage that produces a layer.
- **GATE-9:** a missing doc and zero blocks both fail with nothing to run, the empty-script
  guard holds under `set -e`, and the self-test runs on every docs check.
- **Records:** no committed record quotes or paraphrases a conversation; deciders are named
  by role.

Runtime proof: a real npm and pip install in a CFS-enabled tab, with the feed values read
from the host config, succeeded on the broker built from these commits (EDR).
