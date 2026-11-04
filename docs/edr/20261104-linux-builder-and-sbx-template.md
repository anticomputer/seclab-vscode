# Linux builds run in a Debian trixie container; the sbx template is a saved sbx snapshot

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** fork-build session
- **Related:** [ADR fork](../adr/20261104-vscodium-style-fork.md), [ADR tab supervisor](../adr/20261104-tab-supervisor.md)

## Context
M0 needs a reproducible container build of the REH (and optionally the Linux
editor) from the pinned upstream. Tabs under sbx need that REH inside the
microVM.

## Decision
- **Builder image** `node:24.22.1-trixie`. Node matches upstream `.nvmrc`
  (checked in `build/linux/build.sh`).
  - trixie is required because Electron 43 headers fail with bookworm's
    gcc 12 (`native-keymap`: "expected identifier before `__attribute__`").
  - glibc 2.41 matches the sbx shell kit (DHI Debian 13), so REH native
    modules load there.
- **Durable cache:** the upstream checkout and `node_modules` live in the
  named volume `seclab-vscode-work`. Outputs go to `.work/out/` (gitignored).
  Nothing goes in `/tmp`.
- **Default target is the REH** (`./seclab build linux`). The Linux editor
  bundle is OOM-killed in Docker Desktop's 8 GB VM: esbuild peaked at about
  5.3 GB RSS (dmesg: `Killed process … (esbuild) anon-rss:5334324kB`). It
  needs about 12 GB or more of Docker memory. The macOS editor builds on
  Actions instead.
- **sbx template:** `sandbox/sbx/build-template.sh` creates a throwaway
  `shell` sandbox, `sbx cp`s in the REH plus `/opt/seclab/bin/*`, removes
  `agent` from `sudo` and `docker` (defence in depth inside the VM), and runs
  `sbx template save … seclab-tab:local`. This is sbx's native snapshot
  mechanism, so no Dockerfile and no registry are needed (about 20 s).

## Alternatives considered
- **bookworm with a Chromium sysroot and clang (as upstream CI does)**:
  heavier to reproduce; trixie suffices.
- **`sbx cp` the REH into every new tab**: slower per tab, and it leaves the
  REH writable by the tab user.
- **Build the template FROM the kit image with Docker**: the kit image lives
  in sbx's image store, not Docker's, so it would need an export round-trip.

## Consequences
- The sbx template is tied to the sbx shell kit version; rebuild it after sbx
  upgrades.
- In-tab hardening verified: `id` → `uid=1000(agent) gid=1000(agent) groups=1000(agent)`,
  `sudo -n true` → "a password is required".

## Evidence
`./seclab build linux reh` → `.work/out/seclab-reh-linux-arm64.tar.gz` (161 MB);
`./seclab template sbx` → `Saved template docker.io/library/seclab-tab:local` in 20 s.
