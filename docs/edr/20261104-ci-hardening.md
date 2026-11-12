# CI/CD hardening baseline

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** Project owner (2026-11-04): the GitHub workflows (CI/CD) must also receive careful security review and follow best practices; fork-build session
- **Related:** [EDR docs-check](20261104-docs-check.md), [EDR patch series](20261104-patch-series.md), security review [CI hardening](../security-reviews/20261104-ci-hardening.md)
- **Editorial redaction (2026-11-12):** quotations of project conversations replaced with neutral statements; decisions unchanged.

## Context
CI builds the unsigned macOS app that the user runs. It
also gates `main` for three sessions. A compromised workflow, action, image or
cache would therefore reach the user's machine directly. Already in place:
- actions pinned to full SHAs;
- `persist-credentials: false`;
- top-level `permissions`;
- a read-only default token.

## Decision
1. **Provenance of the app.**
   - `build-macos` attests the zip and `build-info.json` with
     `actions/attest-build-provenance` (SHA-pinned). Only that job gets
     `id-token: write` and `attestations: write`.
   - It builds on pushes to `main` only. It has no `pull_request` trigger and
     uploads only from `main`. `v*` tags come back once a ruleset restricts tag
     creation to reviewed `main` SHAs; until then a tag could attest an
     unreviewed commit (review CI-1). A manual dispatch on a branch is a compile
     check: it is attested but uploads nothing.
   - `./seclab fetch macos` accepts only a successful `main` push run. It checks
     that the commit itself passed the required checks (`unit`, `lint`, `docs`
     check runs from GitHub Actions on that exact SHA), so a built commit isn't
     trusted just for being built. It then downloads into a private 0700 staging
     dir and checks `SHA256SUMS`. Next, `gh attestation verify` runs for both
     files, pinned to `--signer-workflow …/build-macos.yml`,
     `--source-ref refs/heads/main`, `--source-digest <head SHA>` and
     `--deny-self-hosted-runners`. The download is re-hashed immediately before
     extraction, and only then moved to `.work/app`. Clearing quarantine stays a
     separate step that needs the project owner's approval.
2. **Everything third-party is pinned by digest or SHA.** Container images
   (node, alpine, nginx, debian, lychee, gitleaks, actionlint, zizmor, and the
   broker's) are written `tag@sha256:…`. Harness code takes them from
   `test/harness.ts`. `build/check-pins.ts` (`./seclab lint pins`, with
   `--self-test`) fails on any of these:
   - an unpinned `FROM`, except build stages and `scratch`;
   - a workflow `uses:` that isn't a 40-hex SHA, or a `docker://`, `image:` or
     `container:` reference without a digest, including expression-valued ones;
   - a `docker run|create|pull` whose image argument has no digest, tagged or
     not, from any registry, with continuations joined. Variables count where
     they are defined, and locally built `seclab-*` images are allowed;
   - an external `repo:tag` image reference anywhere in code.
   
   Markdown is scanned only inside the `<!-- ci: run -->` blocks CI executes. The
   Level B harness pins `@vscode/vsce` to an exact version.
   
   Residuals:
   - the sbx `shell` kit is managed by sbx and pinned through the sbx version
     (0.51);
   - `setup-node` fetches the Node release named by upstream's `.nvmrc` over TLS
     from nodejs.org, without a digest.
3. **Repository Actions settings**, applied with `gh api` on 2026-11-04:
   | Setting | Before | After |
   |---|---|---|
   | allowed actions | `all` | `selected`: GitHub-owned only, no verified-creator or pattern allowlist; we use no third-party actions, and our linters run as digest-pinned images |
   | `sha_pinning_required` | false | **true** |
   | default token | read | read (unchanged) |
   | Actions can approve PRs | off | off (unchanged) |
4. **Static analysis.** actionlint 1.7.12 and zizmor 1.32.0 run as digest-pinned
   images: `./seclab lint workflows` locally, and the `workflow-lint` workflow on
   every push and PR. Both run offline, with `--network none` and no credentials,
   because they are third-party images (superseded 2026-11-04 by the supply-chain
   ADR; zizmor's online audits used to get the read-only token on pushes). Impostor
   commits and ref confusion are covered by `sha_pinning_required` and the
   GitHub-owned-actions allowlist. At adoption, zizmor reported no findings at either the `regular` or the
   `auditor` persona, apart from informational "unnamed job" notes, which are
   now fixed.
5. **Token scope, triggers, caches.**
   - Every job declares `permissions: contents: read`, except the attesting
     build job.
   - Triggers are only `push`, `pull_request` and `workflow_dispatch`. There is
     no `pull_request_target` or `workflow_run`.
   - `docs-check` never passes `GITHUB_TOKEN` to lychee, a third-party image
     (superseded 2026-11-04 by the supply-chain ADR; it was previously passed on
     pushes). GitHub rate limits are absorbed by the cache and by accepting 429.
   - The lychee cache is keyed per ref. It is restored with `cache/restore` and
     saved only on pushes, so a PR can never seed what `main` or a tag restores.
     `setup-node` runs with `package-manager-cache: false`.
6. **Template injection.** No `${{ github.event.* }}` or `github.head_ref` value
   appears in `run:`. Values go through `env:`, for example `DOCS_BASE`.
7. **Bounds.** Every job has `timeout-minutes`. Concurrency groups are per ref,
   with `cancel-in-progress` everywhere except `main` and tags, where every SHA
   is verified.
8. **Dependency updates.** Dependabot covers github-actions, docker (our and the
   broker's Dockerfiles) and pip (the broker's hash-locked requirements), weekly
   and grouped per ecosystem. Updates arrive as PRs through the same CI and
   review. Image digests in shell or TS, the linter pins and `upstream.lock` are
   bumped by hand; `lint pins` keeps them pinned. npm isn't covered, because our
   extensions declare no dependencies.
9. **Branch protection.** A ruleset on `main`, approved by the project owner. It requires
   the `unit`, `lint` and `docs` status checks on the pushed SHA, has no bypass
   actors, and blocks non-fast-forward pushes and deletion. History stays linear
   and no pull request is required. Sessions push their branch, wait for the
   checks on that SHA, then fast-forward `main` to it.
10. **Process.** Every workflow change gets its own security-review round and
    must pass `lint workflows` and `lint pins` (AGENTS.md hard rule).

## Consequences
- The fetch-and-run path verifies who built the app, from which commit, and that
  the commit passed the gates, not only that the download is intact.
- Branch builds no longer produce a downloadable app. Testing a branch on the Mac
  means landing it on `main`, or a local Linux build.
- If artifact attestations turn out to be unavailable for this private repo on
  its plan, the attest step fails on `main`. The fallback would then be a signed
  `SHA256SUMS` (Sigstore keyless via `cosign`), recorded as an addendum.
