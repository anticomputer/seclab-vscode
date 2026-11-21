# Security review: the pre-push hook refuses pushes to main (round RMP)

- **Date:** 2026-11-20
- **Scope:** round RMP, by an Opus-class model, of the shared pre-push hook's refusal of any ref
  line whose remote ref is `refs/heads/main` (`build/hooks/pre-push`, `refuse_main_push`),
  `seclab`'s `hooks_problems` reporting a hook without it, the tests in
  `test/hooks/hook-lock.test.sh`, and the AGENTS.md and EDR pr-landing text.
- **Threat model:** no push from this clone reaches `main` outside a pull request, whatever the
  branch's upstream, the spelling of the push, or the hook's environment; the refusal must not
  weaken the scans of the other refs in a push.

## Round RMP
The reviewer probed git in a container: every way of pushing to main (`main`, `HEAD:main`,
`topic:main`, `+main`, `--all`, a bare push with upstream `origin/main`, a delete, a mirror push)
reaches the hook as exactly `refs/heads/main`, and git rejects the respellings that would dodge an
exact match. In a push of main and a branch, the branch is still scanned and the push fails.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| RMP-1 | Medium | hook | The refusal's verdict was the exit status of its message: with the hook's stderr closed the `echo` failed, the refusal returned false, and the push to main went on to the scans and out. | Fixed | The refusal returns 0 whatever the message write does; a test runs the hook with stderr closed. |
| RMP-2 | Low | hook | The refusal applies to `refs/heads/main` on every remote, not only `origin`, so a push to main on a fork or mirror needs `--no-verify`, which skips both scans. | Accepted | The coordinator's rule: any push whose remote ref is `refs/heads/main`. A remote's name doesn't say which repository it is, and this clone's work reaches main only through a PR. Documented in the hook and the EDR. |
| RMP-3 | Info | prompt injection | None found in the diff, the tests or the docs. | No finding | — |
