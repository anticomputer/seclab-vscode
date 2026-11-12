# Secret scanning before push is mechanical: a pre-push hook and a required CI step

- **Status:** accepted
- **Date:** 2026-11-05
- **Deciders:** Project owner (2026-11-05): the gitleaks-before-push rule must be mechanical. Coordinator: the requirements below. Fork-build session: implementation.
- **Related:** [EDR pinned tools](20261105-pinned-tools.md) (the scanner), [review](../security-reviews/20261104-supply-chain.md)
- **Editorial redaction (2026-11-12):** quotations of project conversations replaced with neutral statements; decisions unchanged.

## Context
"Run gitleaks before a push" was a manual rule in AGENTS.md. A session pushed a test
containing the RFC 6455 example WebSocket key and only scanned afterwards. It was public
example data, not a secret, but the rule had been skipped, and nothing would have stopped a
real one.

## Decision
- **`./seclab lint secrets [BASE [TIP]]`** pipes every commit in `BASE..TIP` through the
  gitleaks built from pinned source: `git log -p -m --text` with no external diff drivers or
  textconv, so a secret added and removed in an intermediate commit, one in a merge, and one
  in a file marked binary or `-diff` are all scanned (review VV-1, VV-3). It runs
  `--network none`, read-only, with no capabilities, as nobody, `--pull never`, and redacts
  findings. The base defaults to the merge base with `origin/main`; an unavailable base falls
  back to that, which is stricter, never looser. It fails closed if docker or the scanner is
  missing.
- **Pre-push hook:** `build/hooks/pre-push`, installed per clone by `./seclab hooks install`.
  The install writes it into the clone's common git dir (`.git/seclab-hooks`) with the
  scanner's image ID and pinned binary sha256 baked in, and points `core.hooksPath` at that
  absolute path, so a branch can't weaken or drop it by editing its own `build/hooks` (review
  VV-4). The hook is self-contained (VV-8): it runs no code from the pushing checkout, checks
  the scanner binary's hash, and runs the same `git log -p -m --text` scan itself over every
  pushed commit the remote doesn't have yet: from the remote head (or the merge base with main
  for a new ref), excluding anything already on an `origin` ref, so a rebase onto main doesn't
  re-flag main's own public history.
  A missing image, a hash mismatch, a hit or an unrunnable scan blocks the push before anything
  reaches GitHub. Re-run the install after the hook or the scanner pin changes.
- **A shared hook must not depend on code that isn't on main.** The first self-installed hook
  called the pushing checkout's `./seclab lint secrets`, which only this branch had. The hook
  is shared by every worktree of the clone, so for about an hour no session based on main could
  push. Self-contained hooks avoid that by construction; AGENTS.md states the rule.
- **CI:** the required `lint` check (`workflow-lint`) runs the same command. A push to `main`
  scans from the previous head; every other push and PR scans every commit since the merge
  base with `main`, so a secret pushed earlier on a branch can't ride a later clean push onto
  `main` (review VV-2).
- **Fixtures:** the existing rule stands. Values are generated or obviously fake
  (`seclabcanary_…`), match no real token format, and are not public example values either.

## Consequences
- Verified 2026-11-05:
  - the branch range scans clean;
  - a generated GitHub-token-shaped value piped through the same invocation is reported as
    `github-pat` with the secret redacted, and exits 1;
  - a generated token added in one commit and removed in the next, then repeated in a
    `-diff` file: the old `git diff` scan exits 0, the commit-by-commit scan exits 1;
  - the installed hook, run from a worktree whose `./seclab` has no `lint secrets`, scans that
    branch's range clean, and blocks a range with a planted generated token. A first version
    lost its stdin to the hash check's `docker run -i` and scanned nothing; the hash check now
    reads `/dev/null`, and the hook prints how many refs it checked.
- The hook can be bypassed with `git push --no-verify`. That is what the required CI step
  is for: nothing reaches `main` without it.
- A false positive in a legitimate change needs a reviewed fix. Either replace the value with
  an obviously fake one, or add a `gitleaks:allow` comment that a reviewer approves.
