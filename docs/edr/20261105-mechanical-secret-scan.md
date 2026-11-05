# Secret scanning before push is mechanical: a pre-push hook and a required CI step

- **Status:** accepted
- **Date:** 2026-11-05
- **Deciders:** anticomputer (user). Verbatim: "Make the gitleaks-before-push rule mechanical." Coordinator: the requirements below. Fork-build session: implementation.
- **Related:** [EDR pinned tools](20261105-pinned-tools.md) (the scanner), [review](../security-reviews/20261104-supply-chain.md)

## Context
"Run gitleaks before a push" was a manual rule in AGENTS.md. A session pushed a test
containing the RFC 6455 example WebSocket key and only scanned afterwards. It was public
example data, not a secret, but the rule had been skipped, and nothing would have stopped a
real one.

## Decision
- **`./seclab lint secrets [BASE [TIP]]`** pipes `git diff BASE..TIP` (no external diff
  drivers or textconv) through the gitleaks built from pinned source. It runs
  `--network none`, read-only, with no capabilities, as nobody, `--pull never`, and redacts
  findings. The base defaults to the merge base with `origin/main`; an unavailable base falls
  back to that, which is stricter, never looser. It fails closed if docker or the scanner is
  missing.
- **Pre-push hook:** `build/hooks/pre-push`, installed per clone by `./seclab hooks install`
  (`core.hooksPath=build/hooks`). That setting is shared by every worktree of the clone and
  resolves per worktree. It scans each pushed range, remote head to pushed commit, or from
  the merge base with main for a new ref. A hit or an unrunnable scan blocks the push before
  anything reaches GitHub.
- **CI:** the required `lint` check (`workflow-lint`) runs the same command over the push's
  range (the previous head, or the PR base).
- **Fixtures:** the existing rule stands. Values are generated or obviously fake
  (`seclabcanary_…`), match no real token format, and are not public example values either.

## Consequences
- Verified 2026-11-05:
  - the branch range scans clean;
  - a generated GitHub-token-shaped value piped through the same invocation is reported as
    `github-pat` with the secret redacted, and exits 1.
- The hook can be bypassed with `git push --no-verify`. That is what the required CI step
  is for: nothing reaches `main` without it.
- A false positive in a legitimate change needs a reviewed fix. Either replace the value with
  an obviously fake one, or add a `gitleaks:allow` comment that a reviewer approves.
