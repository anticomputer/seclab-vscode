# History rewrite: internal identifiers removed from every branch

- **Status:** accepted
- **Date:** 2026-11-12
- **Deciders:** Project owner (2026-11-12): the repository is public, so history is rewritten,
  not just fixed forward, after a full sweep for internal information; the owner set the scope
  of the scrub. Coordinator: the procedure. History-rewrite session: implementation.
- **Related:** [CI hardening](20261104-ci-hardening.md) (the `main` ruleset),
  [prompt-injection hygiene](20261104-prompt-injection-hygiene.md),
  [CFS local builds](20261105-cfs-local-builds.md), [liveness gate](20261109-liveness-gate.md)

## Context
The repository is public by design, and several kinds of internal information had been
committed:
- **Internal infrastructure identifiers:** package-feed organisation, project and feed names,
  feed and tenant IDs, storage account names, and the names of non-public repositories.
- **A value a probe captured from the host,** in a committed run record.
- **An internal chat excerpt** with colleagues' handles, in the origin note.
- **Local machine details:** an absolute home path, names of other projects' resources on the
  host, and which apps were in use.
- **Prose stating internal policy as fact:** the endpoint-protection product and how it behaved,
  managed-device registry blocking, internal feed policy, and a non-public model identifier.

Deleting the files in a new commit would have left all of it in history.

## Decision
Rewrite all history, covering everything a full sweep found. It took two passes.

- **Sweep.** Covered every branch, pull-request ref, blob and commit message:
  - regex extraction;
  - a visibility check of every `owner/repo` mentioned;
  - parallel model readers over every unique prose line, read to the end;
  - gitleaks over the full history in a container with no network.

  The original strings and the replacement map stay outside the repository.
- **Rewrite.** git-filter-repo v2.47.0 ran in a `--rm`, `--network none` container on a fresh
  mirror clone. It was fetched through git and checked against the tag's commit SHA, not
  installed on the host and not committed. It used `--replace-text` and `--replace-message`
  with one ordered rule list.
  - **Replacements keep code and tests valid:** example organisation, project and feed names;
    `00000000-…` IDs; and example storage accounts with the same shape the policy tests check.
    The captured value became `<redacted>`.
  - **Rewording:** prose became generic ("endpoint protection", "unavailable locally"). The
    origin note keeps only the owner's own text.
  - **The `gh cfs` tool name stays** where code calls it.
- **Second pass.** The first pass matched only the full IDs, and a record still held truncated
  ones (8-hex prefixes, written with an ellipsis). The second pass added every prefix of seven
  or more hex characters of each scrubbed ID and SHA (dashed or not, any case), plus test
  values derived from a real storage account name. Commits without such content kept their
  SHAs. One branch, which didn't contain them, was untouched.
- **Verification.** After each pass: zero full or truncated forms across every object and
  message reachable from a branch. On the rewritten `main`: unit tests, every lint, the
  patch-queue check and the docs check ran locally; then the four required checks ran green
  in CI.
- **Ruleset.** The `main` ruleset was saved as JSON first. Only for each force-push of `main`
  was it reduced to its `deletion` rule:
  - `non_fast_forward` and `required_status_checks` had to go, because no check can have run on
    a new SHA before it is pushed;
  - `required_linear_history` had to go, because main's history contains two merges and every
    rewritten commit counts as new.

  Each window lasted about 3 seconds. Each time, the restored ruleset matches the saved JSON in
  every configuration field; only `updated_at` differs. Other branches aren't covered by the
  ruleset and were pushed with per-ref leases pinned to the SHAs they were rewritten from.
- **Branches.** Every branch with unique work was force-pushed. Five were deleted:
  - `rpc-core` and `anticomputer-rpc-core-landing`, superseded by the RPC core landing branches;
  - three whose every patch was already in `main`: `rpc-tooling-determinism`,
    `anticomputer-rpc-channel-lockdown` and `anticomputer-rpc-tooling`.

  Dependabot's branches were deleted and its open PRs closed; it recreates them.
- **SHA citations.** A follow-up commit remapped short and long SHA citations in docs, records
  and tests through filter-repo's commit maps (both passes composed):
  - **Not remapped:** the liveness register's run evidence (verify-runs compares it with the
    run's recorded head SHA), and a comment inside patch 0015 and its source.
  - **Re-pinned:** the two liveness runs, re-dispatched on the rewritten `main`.
  - **Still dead:** citations of commits from the deleted RPC core branches, as before.
- **Recurrence.** The confirmed literals, including the truncated forms, are the secret
  `SECLAB_DENYLIST`, one per line. It lives in the `denylist` environment, whose deployments
  are limited to `main`. The RPC core landing's internal-identifier check reads it; the list is
  never committed.

## Consequences
- **Every rewritten commit has a new SHA.** Sessions hard-reset onto the rewritten branches; a
  branch that was never pushed is rebased using the commit maps. Commit signatures don't
  survive a rewrite, and attestations made over old SHAs don't carry over.
- **Residuals.** Closed pull requests keep `refs/pull/*/head` refs to pre-rewrite commits, and
  GitHub may serve cached views of old commits. A request for GitHub Support to purge them is
  drafted for the project owner to send.
- **Local CFS builds** now carry example feed values. Real feed URLs come from local
  configuration at run time; the egress and credential broker session owns that. CI uses the
  public registries and is unaffected.
- **No conversation content in records.** The project owner also set a rule: records state the
  decision and its rationale, never quotes or paraphrases of conversations. A separate commit
  applies it to existing records.
