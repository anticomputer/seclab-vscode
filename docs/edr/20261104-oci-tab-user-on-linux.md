# OCI tabs on a native Linux engine run as the workspace owner

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** fork-build session
- **Related:** [ADR sandbox provider](../adr/README.md), ci-linux run 41882000366 (failure)

## Context
- A tab must be able to write its own workspace.
- **Docker Desktop (macOS)** maps bind-mount ownership, so the image user
  (`agent`, uid 1000) can write the user's folder.
- **A native Linux engine doesn't.** On the GitHub runner the workspace is
  owned by uid 1001, so every in-tab write failed with `Permission denied`:
  the containment suite was 1/6 on CI and 86/86 locally.

## Decision
- **macOS:** the OCI driver keeps uid 1000.
- **Linux** (`process.platform === 'linux'`): the tab runs as the workspace
  directory's owner, `uid:gid`.
  - It refuses root-owned workspaces.
  - `HOME=/home/agent` is set explicitly.
  - The `/run/user/1000` tmpfs is owned by that uid.
  - The fence check compares the container user against the same value.
- **Home volume.** The per-tab home volume is populated from the image as uid
  1000, so before the first run it is chowned to the tab user. That runs in a
  throwaway container with `--network none`, only `CHOWN` and
  `DAC_READ_SEARCH`, `no-new-privileges`, and only that tab's volume mounted.
- **Tests** exec as the container's own user rather than a hard-coded uid.

## Alternatives considered
- **chown the fixture to 1000 in CI:** hides a real Linux-host problem.
- **idmapped bind mounts:** not available in Docker's `--mount` on the runner
  engine (Podman has `idmap`). Revisit when the Docker CLI supports them.
- **userns-remap:** a daemon-wide setting, outside what the driver controls.
- **Run as root inside the container:** rejected outright.

## Consequences
- On Linux, the tab's uid equals the user's. The container boundary
  (`--cap-drop ALL`, no-new-privileges, internal network, only the workspace
  mounted) is unchanged.
- The image's `/etc/passwd` has no entry for that uid, so `id -un` fails in the
  tab. This is cosmetic.

## Evidence
- `tabd/src/drivers/oci.ts` `tabUser()`.
- The containment suite passes locally on macOS (86/86).
- The CI result is linked from the review record once green.
