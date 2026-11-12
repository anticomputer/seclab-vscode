# Move from a local-only repo to private anticomputer/seclab-vscode

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** Project owner (2026-11-04): the repo named in the title, private
- **Editorial redaction (2026-11-12):** quotations of project conversations replaced with neutral statements; decisions unchanged.

## Context
The repo was local-only. Building the native macOS editor ([ADR](20261104-native-editor-on-actions.md))
needs GitHub Actions macOS runners, so the repo must be hosted on GitHub.

## Decision
`origin` is the **private** repo `anticomputer/seclab-vscode`. Session
branches are pushed there, and Actions builds artifacts from them.

## Alternatives considered
- **Stay local and use a self-hosted runner on the Mac**: rejected. A runner
  is a long-lived privileged host agent, and installing it violates host
  hygiene.
- **Public repo**: rejected. The project's work in progress includes security
  findings about upstream.

## Consequences
- Workflow security is in scope: least-privilege `permissions:`, no
  `pull_request_target`, pinned actions, and artifact provenance.
- Never commit real credentials or unredacted host data. Spike logs must be
  scrubbed (for example sbx's `PROXY_CA_CERT_B64` is fine, but tokens are not).

## Evidence
- `git remote -v` → `git@github.com:anticomputer/seclab-vscode.git`
