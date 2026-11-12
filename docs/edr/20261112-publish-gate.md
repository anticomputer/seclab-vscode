# Publish gate: only what can be shown to be public is published

- **Status:** accepted
- **Date:** 2026-11-12
- **Deciders:** Repository owner. RPC core landing session: implementation.
- **Related:** [CI hardening](20261104-ci-hardening.md), [mechanical secret scan](20261105-mechanical-secret-scan.md), [fixture safety](20261104-fixture-safety.md)

## Context
The repository is public. A push to any branch publishes, and so do PR and issue text, review
comments, release notes and Actions logs. Internal identifiers and conversation excerpts have
reached the public record more than once, and a history rewrite was needed to take them back.

A known-names list catches only names someone thought to list. CI runs after the push, so it
can only detect. The control has to run before anything leaves the machine, and it has to allow
only what can be shown to be public rather than block known bad names.

## Decision
One engine, `build/publish-gate.ts`, and one driver, `build/hooks/publish-gate.sh`, used by:
- the **pre-push hook** (mandatory; `./seclab hooks install`), over what a push publishes;
- `./seclab scan-text`, over text before it is posted with `gh`;
- `./seclab lint publish`, over HEAD's tree;
- CI, through `build/ci-denylist.sh`: the `denylist` job on a push to main, over the whole tree
  and, for the allowlist discipline, the range since the previous main tip.

**No branch scan in CI.** A scan of branch-controlled input with the list would tell a public log
which candidate names are on it: push a file of guesses, read which lines matched (review round
19, R19-1). A branch can also suppress any push-triggered workflow (`[skip ci]`, deleting the
workflow; R19-2), so such a scan would stop no one willing to probe. The `workflow_run` design
was built, reviewed and dropped for those reasons; the CI-hardening baseline (no `workflow_run`)
stands. For the same reason the main job reports every layer as a count, never a location: which
locations are printed or withheld, and in what order, would also tell the log (R20-1).

A push publishes the ref name, an annotated tag's message, and for each new commit its message,
the paths it writes and the lines it adds (removed and unchanged lines are already public). Git is
read only through plumbing (`rev-list`, `diff-tree`, `ls-tree`, `cat-file`) with no hooks,
filters, textconv or user config. A diff line the parser doesn't recognise is scanned, never
dropped. In a tree scan, a text-type file that can't be read (binary-looking or oversized) blocks;
other skipped blobs are counted.

Layers:

| Layer | Passes |
|---|---|
| repo | Every GitHub repository reference (URL forms, `uses:` pins, `owner/name#N`, `--repo`, `repo:`, and bare `owner/name` under a watched owner) is checked live with `gh api repos/<owner>/<name> --jq .visibility`. Only `public` passes. Private, internal, not found, malformed or the API unreachable (after three tries) blocks. Results are cached per run only. |
| host | URL hosts (network schemes only), protocol-relative hosts, email domains and bare domains must match the allowlist (exact, or `*.suffix` with at least two labels; only the reserved test TLDs stand alone). IP literals pass in loopback and RFC 5737 ranges only. |
| id | GUIDs, whole or truncated (`<8 hex>-…`), and hex IDs of 16 or more characters that are not hash-length (40, 64, 128) must be allowlisted. |
| path | Home paths (`/Users/<name>`, `/home/<name>`, `C:\Users\<name>`) need an allowlisted placeholder name. Agent session-state and worktree paths never pass. |
| handle | GitHub handles (an at-sign before a name) must be allowlisted (the owner's among them). Doc-comment tags, DI decorators, decorator lines, npm scopes, emails and digest suffixes are not handles. |
| record | Run-record JSON (`runs/`, `results/`, `traces/`, `evidence/`, `*.measured.json`) holds booleans, numbers, null, canary tokens and token-like literals only, checked in every commit that writes it (one deleted before the tip was still published). Legacy records are pinned by blob and fail again once changed. |
| allow | The allowlist changes only in a commit of its own whose message has a line `public: <what was checked> YYYY-MM-DD` (the hook, and CI over the range it was pushed). In a tree scan, an entry nothing uses, wildcards included, is stale and fails, so a value scrubbed from the tree can't live on in the allowlist. |
| denylist | The known-names list, last. Matching is fixed-string in spirit: case, Unicode forms and the joiners `-`, `_`, `.` are folded; a one-word entry is found at joiner boundaries inside a word, also wrapped across a line; a multi-word entry is also matched as one joined word; a separator an entry names (`/`) needs a path- or key-like separator in the text. The same words as spaced prose or in parentheses don't match (round 21). Locations are withheld on a looser check. |
| review | Prose and messages that may record a private conversation: quote markers, and a person's words or choices attributed to them. It only flags, because product text that describes what a person picks in the UI is legitimate. The hook blocks until the pusher sets `SECLAB_PUBLISH_REVIEWED=<the pushed commit>`; `scan-text` exits 3; CI posts a notice. |

Every finding prints its layer and location, never the value. A location that itself holds a
finding is withheld. Exit 0 is clean, 1 is blocked, 3 is review-only; anything else blocks.

**The list.** `~/.config/seclab/denylist.txt` (or `SECLAB_DENYLIST_FILE`), a regular file owned by
the user with no group or other permission bits. Anything else fails closed. In CI it is the
`SECLAB_DENYLIST` secret of the `denylist` environment, whose deployment-branch rule admits main.

**The hook is self-contained.** The install takes the engine, driver and hook template from
main's objects, never the working tree, so a branch checked out for testing can't become every
worktree's gate; it notes any local difference. It bakes in their sha256 and the node image ID.
The hook checks them, then runs the engine in that image with no network, a read-only root, no
capabilities, as the invoking user (so the private list is readable on a Linux engine without
widening it), with the git directory and the list mounted read-only. It runs no code
from the pushing checkout. The install refuses until main carries the gate.

**Actions logs.** `build/check-workflow-echo.ts`, run by `./seclab lint workflows`, over every
workflow, the CI scripts and the shell they source: no `secrets.*` inside `run:`, no environment
dump or shell trace, no echo of a secret-derived value to the log (taint follows assignments,
here-string reads and temp files the secret is written to; masking excepted), no host-data
commands. A line can be excused only with a reasoned `# lint-allow: echo <reason>`.

## Evidence
- `./seclab lint publish --self-test`, 78 cases, every layer proved by injecting a hit first,
  through real commits in a throwaway repository: an added line, a commit message, a path, a ref
  name, an annotated tag message, a run record (also one deleted before the tip), an allowlist
  widened in a mixed commit (push mode, and tree mode with a base), a stale entry and a stale
  wildcard, a one-label wildcard, an unreadable text-type file, the known-names list, and CI's
  count-only report; and the controls: a removal publishes nothing, a separate evidenced
  allowlist commit clears a host, a pinned legacy record passes until it changes, no list or no
  allowlist fails closed. Values are built at runtime, so the source holds none of them.
- `./seclab lint denylist --self-test` (43 cases) covers the matcher and the git modes the gate
  builds on. Against the real list, every entry is found as written, uppercased, with joiners
  swapped, inside a URL and inside JSON, and main's tree has no match, as a fixed-string search agrees.
- `build/check-workflow-echo.ts --self-test`, 26 cases, one injection per rule and per taint
  path; the current workflows, CI scripts and the driver are clean.
- The installed hook, end to end in a scratch clone against a local bare remote, 12 scenarios,
  each asserting its expected reason: a clean push passes; an unknown host, a repository that
  doesn't verify public, a known name, a free-text run record, a mixed allowlist commit, no list,
  a list others can read, and a tampered installed engine each block; a conversation line blocks
  until that commit is marked reviewed. This run found a real bug first: the hook read the remote
  ref into a different variable than it used, so every push failed for that reason alone.
- On the tree before the second rewrite pass, the tree scan found truncated feed-GUID prefixes,
  two repository references that are not public, and storage-account fixture names. That pass
  removed all of them. On the rewritten tree, every repository reference verifies public live
  and only review-only lines remain.
- The first branch push through the gate in push mode was clean apart from two review-only
  lines that use the quote-marker word in its technical sense.

## Limitations
- Heuristics catch accidents, not adversaries: bare domains count only with a curated TLD
  set; uppercase-only hosts, cross-script lookalikes and split values can pass; hash-length hex
  passes as a content address; bare `owner/name` is checked only under a watched owner.
- Author and committer identities are not scanned.
- `git push --no-verify` skips the hook. CI on main catches what reaches main, after the fact;
  nothing scans a branch with the list after it is pushed.
- The repository check depends on the GitHub API; when it can't be reached, pushes block.

## Consequences
- Every push needs Docker, `gh` and the private list. Without them the hook refuses.
- The allowlist grows only by evidenced commits and shrinks when the tree does.
- Posting to GitHub goes through `./seclab scan-text` first (AGENTS.md).
