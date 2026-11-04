# The trusted editor runs natively on macOS, built unsigned on GitHub Actions

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** anticomputer (user decision: "Push to a private GitHub repo and build an unsigned macOS app on GitHub Actions macOS runners, fetched with gh; the editor runs natively and drives sbx directly with no bridge"); seclab-vscode coordinator

## Context
The original constraint was "nothing installed on the macOS host; all builds
and runs in containers". Taken literally, that meant a Linux Electron editor in
a dev container, viewed through noVNC. The editor then cannot drive sbx (a
host-side, VM-per-tab runtime) without a privileged host bridge that the
container calls.

## Decision
- The editor (Electron main, workbench, local extension host with the Tab
  Manager) runs **natively on macOS**. It is built **unsigned** from the same
  pinned upstream, jq product.json and patch queue on a **GitHub Actions
  arm64 macOS runner**, uploaded as an artifact, and fetched with
  `gh run download`. Clearing quarantine on the downloaded app needs the
  user's approval.
- The Tab Manager calls `sbx` and `docker` directly. **There is no host
  bridge.**
- The Linux container build stays: it is used for CI, the REH that runs inside
  tabs, and the OCI-provider tests. noVNC is optional, for Linux/CI only.

## Constraints revised, and why
| Original constraint | Revised to | Why |
|---|---|---|
| Nothing installed on the host | No *toolchain* on the host; sbx (upgraded through its existing Homebrew cask) and the built app are allowed | A containerised editor plus a bridge would add a privileged host component, a wider attack surface than a native app |
| Build everything in local containers | Linux builds in containers; macOS builds on hosted runners | A darwin app can't be built in a Linux container |
| Local-only git repo | Private GitHub repo ([ADR](20261104-private-github-repo.md)) | Needed for Actions |

## Alternatives considered
- **Containerised editor plus noVNC plus a host bridge** (a perl script on
  loopback with a token and allowlisted sbx verbs): rejected. It adds a new
  trusted privileged component and an IPC path from the container to the host,
  and the UX is worse.
- **Build toolchain on the host**: rejected because of the host-hygiene rule.

## Consequences
- The macOS app is unsigned, so Gatekeeper needs quarantine removed. That
  happens per download, with approval.
- Hosted runners lack nested virtualisation, so sbx tests run locally. CI runs
  the OCI-provider suite.
- The workflow is a supply-chain surface (token permissions, artifact
  provenance) and is in security-review scope.

## Evidence
- User decisions relayed by the coordinator on 2026-11-04 (quoted above).
