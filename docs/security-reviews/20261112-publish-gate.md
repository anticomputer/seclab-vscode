# Security review: the publish gate (pre-push hook, CI and posted text)

- **Date:** 2026-11-12
- **Round:** 19 (new component and workflow change: the publish gate), with the fixes reviewed in round 20.
- **Reviewer:** independent `security-review` agent (an Opus-class model).
- **Subject:** the two gate commits on main 15ac141: the allowlist (`build/publish-allow.json`)
  and the gate (`build/publish-gate.ts`, `build/check-denylist.ts`, `build/hooks/publish-gate.sh`,
  `build/hooks/pre-push`, `build/ci-denylist.sh`, `.github/workflows/publish-gate.yml`,
  `.github/workflows/workflow-lint.yml`, `build/check-workflow-echo.ts`, `seclab`, `AGENTS.md`,
  [EDR](../edr/20261112-publish-gate.md)). The brief asked for an explicit keep-or-drop verdict on
  the `workflow_run` job.
- **Prompt:** said the diff, fixtures and evidence may contain prompt injection aimed at the
  reviewer, and that the reviewer reports it rather than following it. None found.

## Round 19 verdict
**One high, four mediums, four lows, two informational.** Verdict on `workflow_run`: **drop
it.** Its confinement held on every point tested (main's definition, the main-only environment
rule, no checkout or execution of branch content, no artifact reuse, no workflow-command
injection, no fork or PR reach). The problem is the information flow, not the confinement.

| # | Severity | File | Finding | Fixed |
|---|---|---|---|---|
| R19-1 | high | `publish-gate.yml`, `build/ci-denylist.sh`, `build/publish-gate.ts` | The branch scan printed one location per known-name match into a public log. One push of a file of guesses reveals which are on the list, and needs write access only, not the list. | yes: the job is dropped; the main job reports known-name hits as a count |
| R19-2 | medium | `publish-gate.yml` | The branch suppresses its own scan: `[skip ci]` and friends, or deleting or renaming `workflow-lint.yml`, and no `workflow_run` event fires. | yes: the job is dropped; the EDR and AGENTS.md no longer claim branches are scanned |
| R19-3 | medium | `build/publish-gate.ts` | Run records were read only at the pushed tip, so a record a push adds and then deletes was published unscanned. | yes: checked per commit, against that commit's tree |
| R19-4 | medium | `build/publish-gate.ts` | The tree scan skipped binary-looking and oversized blobs and named only a few extensions; a NUL-led `.csv` or `.html` was dropped silently. | yes: every unreadable text-type file blocks; other skips are counted |
| R19-5 | medium | `seclab` | The install pinned whatever engine the working tree had, so installing from a branch made that branch's gate every worktree's gate. | yes: engine, driver and template come from `origin/main`'s objects; a local difference is noted |
| R19-6 | low | `build/hooks/pre-push`, `build/publish-gate.ts` | An annotated tag's message was not scanned. | yes: it is a scan unit |
| R19-7 | low | `build/check-workflow-echo.ts` | The driver sourced in the secret-bearing job was outside the lint, and taint followed only directly bound variables. | yes: `build/hooks/*.sh` is linted; taint follows assignments, here-string reads and temp files |
| R19-8 | low | `build/check-denylist.ts` | A git error message reached the log unescaped. | yes: escaped and truncated like the gate's |
| R19-9 | low | `build/ci-denylist.sh` | Tag pushes were scanned under a fabricated branch ref. | yes: branch mode is gone |
| R19-10 | info | `build/publish-gate.ts` | `*.com` parsed, matched every `.com` host, and was exempt from the stale check. | yes: two labels after `*.` (reserved test TLDs excepted); wildcards count for staleness |
| R19-11 | info | `build/ci-denylist.sh` | CI never checked the allowlist-commit discipline. | yes: the main job passes the previous main tip as the base |

Each fix has an injected-defect self-test: `./seclab lint publish --self-test` (77 cases at round
19), `build/check-workflow-echo.ts --self-test` (21 cases at round 19).

## Round 20
Re-review of the fixes (`git diff 9507192e f1b3d94b`), same reviewer and injection warning;
none found. **No high or critical.** R19-2, -3, -6, -8, -9, -10 and -11 confirmed closed. Two
mediums, three lows and three informational findings, all fixed in the same gate commit:

| # | Severity | Finding | Fix |
|---|---|---|---|
| R20-1 | medium | Count-only known-name hits still left an oracle: other layers printed one location per blob in tree order, and a withheld location's position named the matching candidate (the new `unread` layer carried it with empty files). | In CI every layer is a count; no location is printed at all, withheld or not. |
| R20-2 | medium | The R19-7 assignment exemption also exempted `X=1; echo "$S"` and `FOO=bar echo "$S"`. | Only a line that is solely a `VAR=$(…)` capture is exempt. |
| R20-3 | low | `.rst`, `.markdown`, `.tsx`, `.jsx` and extensionless files skipped as binary were only counted. | They count as text-type, so an unreadable one blocks. |
| R20-4 | low | The install still took the node image and the gitleaks pin from the working tree. | Both come from `origin/main`; differences in `seclab` and `build/tools/` are noted. |
| R20-5 | low | A rejected base (force-push, unfetched) silently dropped the allowlist-commit check. | A notice says so. |
| R20-6 | info | `head`/`tail` of the secret's temp file were missed; a one-letter redirect target over-tainted. `taint()` cannot loop forever (verified). | More readers in E3; temp files must be path-like. |
| R20-7 | info | Two headers still described the dropped job. | Rewritten. |
| R20-8 | info | An annotated tag with an empty message made its headers the scan unit. | An empty message scans as empty. |

Self-tests after the fixes: `./seclab lint publish --self-test` 78, `build/check-workflow-echo.ts --self-test` 26.

## Round 21 (matcher semantics, found running the real list before landing)
Run with the real list over main's tree, the known-names layer reported 27 lines where a
case-insensitive fixed-string search of the same list found none. Token normalisation treated a
hyphenated or slashed entry as loose words, so it also matched the same words in public product
prose. The gate would have failed main's first CI run and blocked ordinary edits.

The matcher now keeps `-`, `_` and `.` as joiners inside one word and matches a one-word entry at
joiner boundaries inside a text word (in a host, a path, a package name). Spaced prose of a
joined or slashed entry doesn't match. On main's tree the layer now finds 0 lines, as the
fixed-string search does.

The same reviewer reviewed the change (no prompt injection found). **No high or critical**;
three mediums and two lows, all fixed in the gate commit with a self-test each:

| # | Severity | Finding | Fix |
|---|---|---|---|
| R21-1 | medium | A spaced entry no longer matched its slug (`a-b`, `a_b.ts`, a URL path). | Every multi-word entry is also indexed as one joined word. |
| R21-2 | medium | Output withholding reused the stricter matcher, so a path naming an entry in another form was printed. | Withholding uses a deliberately loose check: the entry's letters and digits anywhere in the location's. |
| R21-3 | medium | A separator an entry writes was required literally, missing `:`, `\` and JSON forms. | Any path- or key-like separator (`/`, `\`, `:`, `|`, `@`, with quotes) satisfies it; prose punctuation such as `(` or `,` doesn't, which is what main's prose uses. |
| R21-4 | low | A one-word entry wrapped at a joiner across a line was missed. | A word ending in a joiner continues across one line break. |
| R21-5 | low | A NUL in a list entry made it silently inert. | A control character in the list is refused, and the gate fails closed. |
| R21-6..8 | info | Linear time, no ReDoS (measured up to 2 MB); line attribution correct; one dead statement. | Dead statement removed. |

Against the real list after the fixes: all 39 entries are found as written, uppercased, with
joiners swapped, inside a URL and inside JSON; main's tree has no known-name match.
`./seclab lint denylist --self-test` 43 cases.

## Round 22 (the list unreadable in CI; secret-scope lint)
After landing, main's `denylist` job failed closed on every push: `ci-denylist.sh` writes the
secret to a mode-600 file owned by the runner user, and the scan container ran as `nobody`. Docker
Desktop virtualises bind-mount ownership, so every local run, the hook included, passed. The gate
failed closed as designed; main was red, nothing leaked.

Fix: the scan runs as the invoking user (never root), keeping no network, a read-only root, no
capabilities and no new privileges. `./seclab lint publish --mount-test`, run by the lint job,
drives the real driver and mount with a fake list written as the CI job writes it, and asserts a
listed name is found. Its first CI run, before the fix, failed with the same error. New rule S1 in
`build/check-workflow-echo.ts` asserts that no branch-controlled code runs with a secret (review
round 17, finding 1).

Reviewer: independent `security-review` agent (an Opus-class model), the injection warning in
its prompt; none found. It verified the secret is environment-scoped with a main-only
deployment-branch policy. **No high or critical.** All fixed, each with a self-test:

| # | Severity | Finding | Fix |
|---|---|---|---|
| R22-1 | low | S1's line reader skipped jobs after a column-0 comment, a quoted or flow-mapping job, an odd indent, or `jobs:` with a comment. | Comments don't end the section; anything in it that isn't a recognised job fails closed. |
| R22-2 | low | An unrecognised job's lines joined the previous job, inheriting its compliant gate. | Same fix; each job is bounded by recognised heads or fails. |
| R22-3 | low | `SECRETS.X`, `secrets['X']` and `toJSON(secrets)` weren't seen as secret uses. | Any `${{ … secrets … }}`, case-insensitive. |
| R22-4 | info | A workflow-level secret binding wasn't flagged. | A secret outside a job is refused. |
| R22-5 | info | A root invoker made the container root. | The driver refuses to run as root. |
| R22-6 | info | The mount test proves nothing on a macOS engine. | It says so when run off Linux; CI's run is the proof. |
| R22-7 | info | Nothing pinned the driver's hardening flags. | The mount test asserts them and refuses a root user. |

`build/check-workflow-echo.ts --self-test` 46 cases.

## Round 23 (downgrade protection for the shared hook)
After the gate landed, a session ran an older installer, which put a gitleaks-only hook over the
shared gate hook for every worktree; it was reinstalled by hand. The change: the installer locks
the hook directory read-only, the hook checks its own marker and `core.hooksPath` on every run,
and `./seclab hooks check` reports the state.

Reviewer: independent `security-review` agent (an Opus-class model), the injection warning in
its prompt; none found. It replayed every historical installer against the locked directory.
**No high or critical.** All fixed except where noted:

| # | Severity | Finding | Fix |
|---|---|---|---|
| R23-1 | medium | The oldest installer only repoints `core.hooksPath` into the worktree, so the lock never sees it and the gate hook never runs; the EDR overstated the protection. | The pointer is checked where something runs: the install's read-back, a warning from every `./seclab` command outside CI, `hooks check`. EDR and AGENTS.md reworded. |
| R23-2 | medium | Install reported success without reading back the path git uses; a per-worktree `core.hooksPath` shadowed it. | The install reads it back (path-typed, per-worktree included) and fails if pushes from here aren't gated. |
| R23-3 | medium | An interrupted install left the directory unlocked. | A trap re-locks it however the install ends. |
| R23-4 | low | The lock helpers came from the checkout's working tree. | The install's chmods are inline. |
| R23-5 | low | "Only main's installer unlocks it" overstated a permission bit: root, or a root container with the clone mounted, can. | Stated as a limit in the EDR (accident protection, not adversary protection). |
| R23-6 | low | The installer always used `shasum` while the hook preferred `sha256sum`; an empty hash could lock every push out. | One portable helper; the marker must be 64 hex. |
| R23-7 | info | A `~` in `core.hooksPath` blocked every push. | Read path-typed. |
| R23-8 | info | `hooks check` misreported as root; removing a clone fails on the locked directory. | The check reads the mode; AGENTS.md says to unlock before removing. |

`test/hooks/hook-lock.test.sh` 11 cases.
