# Security review: broker local builds through CFS

- **Date:** 2026-11-05
- **Scope:**
  - `440d80f`: CFS local builds.
    - A token-holding `wheels*` stage per image runs `tools/pip-fetch.py` with
      the BuildKit secret `cfs_feed_token`, on a tmpfs.
    - The final stage installs offline from a read-only bind.
    - The build arg `PIP_SOURCE` (`cfs` or `public`) chooses the index.
    - `tools/pybuild.sh` wraps the build in `gh cfs`.
    - `tools/supplychain.py` gains a strict Dockerfile grammar.
  - Fixes: `20aac37` (round 9) and the round 9b commit.
  - Threat model: a change to a broker Dockerfile that reads the user's Azure
    DevOps token during a local build, or installs packages other than the
    checked, hash-locked ones, while `pin_check.py` passes.
- **Reviewer:** `security-review` agent (default model; it did not refuse).
  - Round 9 and 9b were separate agents; the first round-9 re-review was lost
    in an app restart and re-run.
  - Both confirmed findings against real BuildKit (Docker 29.8, buildx
    0.37.1), with a fake token and `--output type=cacheonly`.
  - Triage and fixes by the broker session.

## Findings
| # | Severity | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| 9-1 | High | Gate lexing | The keyword was split on a space only. BuildKit also accepts tab, VT and FF there, so `RUN<TAB>--mount=type=secret,…` was skipped by the gate and leaked the token. | fixed `20aac37` | The keyword ends at any whitespace. Unknown keywords, `SHELL`, heredocs and control characters are refused. | `pin_check.py --self-test` (tab, VT, FF, heredoc, SHELL vectors) |
| 9-2 | Medium | Wheels stage | Other instructions in the token-holding stage could run code beside the token: an `ENV PYTHONPATH` hook, `RUN cp` over the fetch script, or a `//` destination alias. The installed requirements file could differ from the checked one, and a quoted `P"IP_"` evaded the config check. | fixed `20aac37` | `wheels*` stages must match an exact template. The fetch runs `python3 -I`. `pip-fetch.py` builds pip's environment from an allowlist and runs pip with `-I`. The install must directly follow the COPY of its file. Destinations are normalised, and `PIP_*` is checked on shell tokens. | `pin_check.py --self-test` |
| 9b-1 | High | Gate lexing | The gate decided continuations on a `strip()`ped line, and universal newlines hid a lone `\r`. A backslash followed by U+00A0, U+0085, or `\r` then a space hid a whole secret-mount `RUN` inside a `CMD`. It leaked the fake token under real BuildKit. | fixed (round 9b commit) | The Dockerfile is read as bytes and must be printable ASCII, tab and `\n`; `\r` is allowed only before `\n`. Whitespace after a continuation backslash is refused. Lines are joined exactly as BuildKit joins them: no added space, leading whitespace kept. | `pin_check.py --self-test` (NBSP, NEL, CR, backslash-space vectors) |
| 9b-2 | Medium | Install identity | A `$HOME` in a COPY destination and the `-r` path resolves differently under BuildKit (unset) and the RUN shell (`/root`). So the gate recorded the checked file while pip read an attacker's file. The gate also joined `p\` + `ip install` with a space. | fixed (round 9b commit) | Tracked destinations must match `^/[A-Za-z0-9_./-]+$`. The install command's raw text may not contain `$`, quotes, backslashes or backticks. Joining is exact. | `pin_check.py --self-test` |
| 9b-3 | Note | Installer heuristic | `RUN x=p; ${x}ip install …` gets past the installer check. | accepted, documented | Any final-stage `RUN` can run arbitrary shell, so spotting stray installers can only be a heuristic. The gate guarantees two things: token isolation, and that the canonical install installs exactly the checked file. Both are now stated in `supplychain.py` and the EDR. Dockerfile changes are reviewed code. | n/a |

Confirmed sound:
- **The token:** not in logs, argv, layers or the build cache. The netrc is
  on a tmpfs and removed in `finally`. `pip download --only-binary --no-deps`
  executes no code. Redirects drop `Authorization`.
- **Index choice:** `PIP_SOURCE=public` writes no netrc. A local build can't
  fall back to public PyPI silently.
- **pip-fetch.py:** the token regex blocks netrc injection, and the
  mountinfo tmpfs check is sound.

**After fixes:** all the reviewers' PoCs are rejected except the documented
heuristic case (9b-3), and no high or critical findings remain.
