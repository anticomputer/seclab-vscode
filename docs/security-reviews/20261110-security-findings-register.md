# Security review: the security findings register and its gate (rounds QQQ, RRR)

- **Date:** 2026-11-10
- **Scope:**
  - round QQQ, the register and its gate as first written, without the workflow: `build/docs/findings.ts` (extractor,
    schema, check, generated view, `commits`/`baseline` modes, self-test), `seclab`
    (`findings_check`, the `findings` subcommand, `docs write` ordering), `build/docs/docs-check.ts`
    (FINDINGS.md isn't a record), `docs/security-reviews/findings.json` and FINDINGS.md, AGENTS.md,
    the review README, [EDR security-findings-register](../edr/20261110-security-findings-register.md);
  - round RRR, the workflow change on its own: `liveness-refresh.yml` lists the findings baseline
    weekly (`./seclab findings baseline`), and its push paths now include the register;
  - their fixes, re-reviewed in rounds SSS onward. The branch landed as one squashed change, which the register cites as the fix commit for these rounds.
- **Reviewer:** security-review agent (an Opus-class model), one agent per round; triage and fixes
  by the findings-register session.
- **Threat model:** a CI gate in the required `docs` job, not a runtime boundary. The question is
  whether it can be satisfied falsely: an unregistered finding, a high closed without a real test or
  without the user, a baseline that grows. Records, register text and test files are
  attacker-shaped input. The weekly listing runs in a workflow job next to a token-holding job.
- **Prompt injection:** every prompt carried the standing warning. None found; the only
  user-voice strings are real quoted decisions in `ref` evidence and a self-test fixture.

## Round QQQ
Two highs, four mediums, three lows. Confirmed sound: the host-side git step (SHA re-validated
before `merge-base --is-ancestor`, fail-closed under `set -euo pipefail`, full history in the docs
job), the `docs write` ordering, the narrow docs-check exclusion, anchor stability under appends and
deletions, fail-closed JSON parsing, and no sensitive data in the 706 entries.

| # | Sev | Area | Finding | Disposition | Fix | Regression test |
|---|---|---|---|---|---|---|
| QQQ-1 | High | branch entries | `branch` suppressed every evidence check while `fixed` still satisfied the high/critical ratchet, so one field closed a critical; 11 branch highs were counted compliant. | Fixed | `compliant()` requires no `branch`; a branch entry must drop `branch` once its record finding (or its ref) is on the tree, which brings its evidence under the check. Branch highs now sit in the baseline. | `findings.ts` self-test "a fixed high on a branch is not compliant" |
| QQQ-2 | High | user acceptance | A `ref` could cite `findings.json` or FINDINGS.md, so an entry could quote itself as "the user accepted this" and close any high. | Fixed | No citation may point at the register or its view; paths must be plain. A user acceptance cites a dated ADR, EDR or review record, with a quote of 30+ characters naming the user. False positives cite a review record. | self-test "a ref to the register itself fails (self-citation)", "a user acceptance whose quote names no user decision fails" |
| QQQ-3 | Medium | test evidence | `fixed` needed only a substring in any file: workflow lines, YAML comments and fixture strings stood in for tests, including two criticals. | Fixed | The test is a test file or a case in a checker with a `--self-test`; its name is 12+ characters and occurs once. The 18 entries that cited a CI step or a non-test file are now `fixed-untested`. | self-test "a test name too short to name one case fails" |
| QQQ-4 | Medium | extraction | Shapes the extractor can't read created no obligation: `Sev/Conf` headers, tables without outer pipes, `\|-\|` delimiters, mixed-case headings, `#####`, HTML tables, an unbalanced fence, subdirectories, a finding in a dash row. | Fixed | Each supported shape is read; a findings-shaped table without a Sev column, an HTML table, an unbalanced fence, a stray entry and a record that yields nothing (unless `noFindings` lists it) fail. | self-test "a record that yields no finding fails" and the "extractor:" shape cases |
| QQQ-5 | Medium | strict IDs | The explicit-ID rule keyed on a file-name date the author chooses, and an appended round in an old record escaped it. | Fixed | `check --base`: a finding new relative to the merge base's register needs a unique explicit ID, whatever the record's date. | self-test "a new placeholder ID fails against the base" |
| QQQ-6 | Medium | ratchet | "The baseline only shrinks" was documented but not enforced: a new open high could be added to the baseline. | Fixed | A baseline key the merge base's baseline doesn't have fails. | self-test "a key added to the baseline fails against the base (it only shrinks)" |
| QQQ-7 | Low | severity | A Sev cell with no severity word left the register's severity unconstrained. | Fixed | A new finding needs a severity word. Legacy rows keep the register's judgement with a `severityNote`. | self-test "a new finding with no severity word fails against the base" |
| QQQ-8 | Low | view | Only `\|` was escaped: HTML fragments vanished from the rendered view, file fields could inject links, and agent-written text sat unmarked in a doc agents read. | Fixed | Every rendered field is escaped into one cell (`&lt;`, brackets, pipes); cited paths are validated; the view carries a data-not-instructions banner. | self-test "the view neutralises HTML and links in register text" |
| QQQ-9 | Low | self-test | No injection for `manual`, `severityNote`, several schema rules, shape coverage, or the host-side ancestry step. | Fixed | Injection and control pairs for each; `./seclab findings --self-test` also runs the host step's own cases. | `seclab` "findings host self-test: a non-ancestor SHA passed" |

## Round RRR
Three lows, two infos. Confirmed sound: the listing step held no token and couldn't affect the
token-holding step; no `pull_request` trigger; pinned checkout and image; no `${{ }}` in `run:`;
the liveness gate still sees a push trigger.

| # | Sev | Area | Finding | Disposition | Fix | Regression test |
|---|---|---|---|---|---|---|
| RRR-1 | Low | liveness-refresh | The listing step gated the job: a register problem stopped the liveness refresh listing. | Fixed | The listing is its own job, `findings-baseline`. | — (workflow structure; no check covers it) |
| RRR-2 | Low | baseline mode | An unresolvable baseline key was dropped silently and the header count shrank with it. | Fixed | `baseline` mode fails on any unresolved, non-high or compliant key, and the header counts every key; the job checks the header. | self-test "baseline mode: an unresolved key is a problem" |
| RRR-3 | Low | baseline mode | `evidence()` interpolated `test.file` unescaped into step output. | Fixed | Every rendered field is escaped; paths are validated by the schema. | self-test "the view neutralises HTML and links in register text" |
| RRR-4 | Info | permissions | The listing ran in the job holding `actions: read` and a token. | Fixed | Its own job has only `contents: read`. | — (workflow structure) |
| RRR-5 | Info | disclosure | The public repo now lists open highs weekly in run summaries. | Accepted | No new detail: the records and FINDINGS.md already hold it. Recorded in the EDR's consequences. | — |

## Round SSS (re-review of the QQQ and RRR fixes)
Verdicts: QQQ-1, QQQ-9 and RRR-1 to RRR-3 fixed; QQQ-2 to QQQ-8 partially fixed, completed by the
findings below. Two highs, four mediums, two lows, one info, all fixed. Confirmed
sound: `compliant()` and branch semantics, path validation, the exactly-once test name, the host
ancestry step, and a replay of the extractor over every record (no unregistered finding).

| # | Sev | Area | Finding | Disposition | Fix | Regression test |
|---|---|---|---|---|---|---|
| SSS-1 | High | ratchet | The base register was consulted only for additions: editing a record's Sev cell and the register's severity together dropped a baselined high, and removing an entry with its row was silent. | Fixed | Every key in the merge base's register must still exist, never at a lower severity, and a baseline key leaves only when compliant. | self-test "a severity lowered since the merge base fails, even if the record was edited too" |
| SSS-2 | High | base resolution | Any `git show` failure became an empty base, which skipped the rules; branches forked before the register and pushes to main had no useful base. | Fixed | `findings_base` tells a missing file from an error and fails closed; an empty merge-base register falls back to origin/main's; on main the push's previous head is the base; a tree without the register fails when origin/main has one. | `seclab` "findings host self-test: a commit before the register didn't give an empty base" |
| SSS-3 | Medium | test evidence | Any file mentioning `--self-test` counted as a test container, including workflows and docs: a critical and a high cleared the ratchet on a workflow step name. | Fixed | Docs and workflows are never tests; in a checker, the case must sit after its self-test entry point. The two RPC entries are now `fixed-untested` and in the baseline. | self-test "a workflow that mentions --self-test is still not a test (SSS-3)" |
| SSS-4 | Medium | acceptance | An acceptance quote wasn't bound to its finding: one user sentence, or any short line of a review record, could clear many highs. | Fixed | A high closed by acceptance or as a false positive needs the quoted line to name its anchor. | self-test "a high accepted by a user quote that" |
| SSS-5 | Medium | escape hatches | `noFindings` was unverified, and one manual entry exempted a whole record from the no-finding rule. | Fixed | A `noFindings` record must say it has none; a record with only manual entries must be listed under `manualOnly`, which no record may join after the merge base. | self-test "a record with only manual entries must be listed under manualOnly (SSS-5)" |
| SSS-6 | Medium | severity | A legacy row with no severity word left the register's severity unchecked. | Fixed | Such an entry needs a `severityNote`; with SSS-1 its severity can't fall later. | self-test "a legacy row with no severity word needs a severityNote (SSS-6)" |
| SSS-7 | Low | view | The escaper wasn't backslash-aware (`\[x\](url)` and `\|` became a live link or cell) and owner fields were raw. | Fixed | Backslashes are escaped first, backticks too; owner session escaped; branch names validated. | self-test "a register cell stays one cell, backslash tricks included" |
| SSS-8 | Low | false failures | A `.DS_Store` would fail the gate; a pipe line over a setext rule read as a table; `### Low hanging fruit` read as a finding. | Fixed | Dotfiles ignored; delimiter rows need a pipe; a mixed-case severity heading needs punctuation after it. | self-test "control: a dotfile under the reviews dir is ignored (SSS-8)" |
| SSS-9 | Info | self-test | No case for base-file plumbing, a stray file, fenced tables or `~~~` fences. | Fixed | Added, with controls. | self-test "a stray file under the reviews dir fails (SSS-9)" |

## Round TTT (re-review of the SSS fixes)
Verdicts: SSS-1, SSS-2, SSS-6, SSS-7 and SSS-9 fixed; SSS-3, SSS-4, SSS-5 and SSS-8 partially
fixed, completed by the findings below. One high, three mediums, three lows, four infos, all fixed
in the commit that adds this section. Confirmed sound: branch semantics, the self-citation ban,
path validation, the host ancestry step and `set -e` paths in `findings_check`, and a
re-implementation of the ratchet over the whole register (no violation).

| # | Sev | Area | Finding | Disposition | Fix | Regression test |
|---|---|---|---|---|---|---|
| TTT-1 | High | false positives | A high closed as a false positive needed only agent-written record text: its own row as the quote would do, so an agent could close a baselined high alone. | Fixed | A high or critical false positive needs `acceptedBy: user` (a dated ADR, EDR or record naming the user's decision), not on the finding's own record, naming it. | self-test "a high false positive on the agent's own record text alone fails (TTT-1)" |
| TTT-2 | Medium | acceptance binding | The binding was a substring test on a stripped anchor: a digit, a date or `A-10` named `A-1`. | Fixed | Only ID-shaped anchors can be closed by a quote, and the line must name the whole ID. | self-test "a quote naming A-10 doesn't close A-1 (whole-ID match, TTT-2)" |
| TTT-3 | Medium | test evidence | "After the first `--self-test` mention" was the whole file below a header comment. | Fixed | The case must sit inside the self-test function or top-level `--self-test` branch (TS, Python, shell), up to where it ends; nine entries became `fixed-untested`. | self-test "a name below a header mention of --self-test but outside the self-test fails (TTT-3)" |
| TTT-4 | Medium | extraction | Narrowing severity headings dropped `### High severity …`; "says none" matched mid-sentence or in fences. | Fixed | Severity-led headings are matched in any case (a false match only asks for a registration); "none" must be a line of its own outside fences. | self-test "a \"### High severity …\" heading is a finding (TTT-4)" |
| TTT-5 | Low | weekly listing | The listing used a weaker predicate than the gate and could tell you to remove a baseline key the gate keeps. | Fixed | One predicate for both. | self-test "baseline mode: an unresolved key is a problem" |
| TTT-6 | Low | conservation | A finding that legitimately moved (an incident gaining a record) read as removed. | Fixed | `wasKey` names the earlier key; conservation follows it. | self-test "control: a finding moved under wasKey is conserved" |
| TTT-7 | Low | base on main | On main without a usable previous head, the base was HEAD itself. | Fixed | Falls back to the first parent, and says which base it used. | — (shell control flow; the base plumbing is covered by the host self-test) |
| TTT-8 | Info | stray entries | Every dotted name was ignored, so `.2026….md` hid a record. | Fixed | Only `.DS_Store`, `.gitkeep` and `.gitignore` are ignored. | self-test "a dotted record name is an unexpected entry, not ignored (TTT-8)" |
| TTT-9 | Info | extraction | A Sev-first table gave an empty anchor that could never be registered. | Fixed | The next cell anchors the row. | self-test "a Sev-first table row is anchored by its next cell (TTT-9)" |
| TTT-10 | Info | view | Bare URLs in register text still autolinked. | Fixed | `://` and `www.` are broken in rendered text. | self-test "a bare URL in register text is not autolinked (TTT-10)" |
| TTT-11 | Info | DOCS_BASE | `DOCS_BASE` reached git before any shape check. | Fixed | Validated as a 40-hex SHA first. | — (shell guard) |

## Round UUU (re-review of the TTT fixes)
Verdicts: TTT-2, TTT-4, TTT-5 and TTT-8 to TTT-11 fixed; TTT-1, TTT-3 and TTT-7 partially fixed;
TTT-6 regressed into a bypass (UUU-2, UUU-3). Three highs, two mediums, one low, one info, all
fixed. Confirmed sound: whole-ID binding (no regex metacharacter can reach the
dynamic pattern), multiple self-test regions, the `acceptedBy` schema, fail-closed base handling,
and a replay over all 90 high/critical entries (each compliant or baselined, none by accident).

| # | Sev | Area | Finding | Disposition | Fix | Regression test |
|---|---|---|---|---|---|---|
| UUU-1 | High | user acceptance | A high `accepted-residual` with `acceptedBy: user` could cite a row the agent wrote in the finding's own review record. | Fixed | User acceptances cite a dated ADR or EDR only, never a review record. | self-test "a user acceptance written into a review record fails (UUU-1)" |
| UUU-2 | High | wasKey | `wasKey` was shape-checked only: hanging a removed finding's key on any compliant entry erased it, including baselined highs with no record. | Fixed | The earlier key must be gone, claimed once, in the base register, and the claiming entry must itself be new since the base; the view shows it. | self-test "wasKey on an entry the base already had can't launder a removal (UUU-2)" |
| UUU-3 | High | ratchet | A new open high joined the baseline by naming any baseline key as its `wasKey`. | Fixed | Only a validated move carries a baseline key. | self-test "a new high can't join the baseline via wasKey of a live baseline key (UUU-3)" |
| UUU-4 | Medium | user acceptance | An agent could write the "user decision" in a new doc in the same change and close a high with it. | Fixed | `./seclab` passes the files the change writes; a high can't be closed by one of them, so the decision lands first. | self-test "a high accepted by a doc this same change writes fails (UUU-4)" |
| UUU-5 | Medium | test evidence | A self-test start with no end opened a region to EOF, and `selfTest`-prefixed names matched. | Fixed | Exact identifiers; an unterminated region is discarded (except Python's, which ends by indentation). | self-test "a self-test start that never ends opens no region (UUU-5)" |
| UUU-6 | Low | base on main | On main, the pre-register fallback compared the register with itself. | Fixed | The fallback to `origin/main` applies only off main. | — (shell control flow) |
| UUU-7 | Info | CI reality | The base rules are inert until the register is on main. | Fixed | Stated in the EDR; the check prints that it skipped them. | — |

## Round VVV (re-review of the UUU fixes)
Verdicts: UUU-1, UUU-6 and UUU-7 fixed; UUU-2, UUU-3 and UUU-5 partially fixed; UUU-4 fixed with
a new defect (VVV-3). Two highs, three mediums, two lows, one info, all fixed in the commit that
adds this section. Confirmed sound: `--changed` covers the whole branch and renames, the regex
escaping, the `wasKey` arithmetic, and the register's 95 high/critical entries (each compliant or
baselined for the right reason).

| # | Sev | Area | Finding | Disposition | Fix | Regression test |
|---|---|---|---|---|---|---|
| VVV-1 | High | acceptance binding | A full key matched a longer sibling key (`#2` in `#2.1`), so a decision about a medium could close a critical. | Fixed | A name ends where the token does: no word character, `#`, `.`, `/` or `-` may follow. | self-test "a key that is a prefix of a sibling's key doesn't close it (VVV-1)" |
| VVV-2 | High | wasKey | A fresh unrelated entry could claim a deleted baselined high's key, erasing it and taking its baseline place. | Fixed | A move keeps the base entry's summary, component and owner. | self-test "wasKey substitution by an unrelated entry fails (VVV-2)" |
| VVV-3 | Medium | decision landing | Any later edit to an accepting ADR or EDR reopened the finding for good. | Fixed | `./seclab` passes the base text of each changed ADR and EDR; the closure fails only when the quoted decision isn't in it. | self-test "an unrelated later edit to the decision's doc doesn't reopen it (VVV-3)" |
| VVV-4 | Medium | pre-register branches | A branch forked before the register would fail the docs job once it lands. | Fixed | No register on the tree and none at the base: skipped, with a note to rebase. | — (shell control flow) |
| VVV-5 | Low | test evidence | A self-test start inside a block comment or docstring still opened a region. | Fixed | Block comments (TS/JS) and triple-quoted strings (Python) are blanked before regions are found. | self-test "a self-test start inside a block comment opens no region (VVV-5)" |
| VVV-6 | Low | `--changed` | Uncommitted files weren't in the changed set, and a check without `--changed` said nothing. | Fixed | Uncommitted and untracked files count; the check prints that the rule was skipped. | — (shell plumbing) |
| VVV-7 | Low | docs | The EDR's consequences and the review README still allowed review records for user acceptances. | Fixed | Both say ADR or EDR only, with the full-key line and the landing order. | — (docs) |
| VVV-8 | Info | acceptance binding | A bare ID two records share could be closed by a line about the other record's finding. | Fixed | Such an ID must be named by its full key. | self-test "a bare ID that two records use doesn't close either (VVV-8)" |

## Round WWW (re-review of the VVV fixes), and owner acceptances
Verdicts: VVV-1, VVV-6 and VVV-8 fixed; VVV-2, VVV-3, VVV-4 and VVV-5 partially fixed. Then a new
project rule replaced the acceptance design: committed records never capture private
conversations, so a closure can't rest on a quoted decision. An owner acceptance is now a row in
`owner-acceptances.md` (full key, date, scope, closing condition, "accepted by the project
owner"), written only by the coordinator on an explicit owner decision. The gate refuses quotation
marks in that file, matches rows by exact key, and still requires the row to land before the
closure. Quote binding, the source of VVV-1, VVV-8 and WWW-1, is gone. The fixes below landed in
the same change as the redesign.

| # | Sev | Area | Finding | Disposition | Fix | Regression test |
|---|---|---|---|---|---|---|
| WWW-1 | High | decision landing | The landing check matched the quoted words anywhere in the base text, so one new naming line over old words closed a high in the same change. | Fixed | Replaced: an owner row is matched by exact key in the base text of `owner-acceptances.md`. | self-test "an owner row added in this same change does not close it (UUU-4)" |
| WWW-2 | High | pre-register branches | A tree with no register, whose merge base predated it, was skipped even when main had one, so the register could be deleted. | Fixed | Missing while the base or main has it fails ("rebase onto main to adopt it"); skipped only when neither ever had one. | `seclab` host self-test "a missing register passed while main has one (WWW-2)" |
| WWW-3 | Medium | ancestry | After the history rewrite every cited fix commit was off the new history. | Fixed | Every SHA in the register is remapped through the rewrite's commit maps and this branch's rebase. | — (the docs job's ancestry step) |
| WWW-4 | Low | test evidence | A `/*` inside a string could blank a region's end and stretch the region over other code. | Fixed | Only line-leading block comments and docstrings are masked. | self-test "a /* inside a string cannot blank a self-test end and stretch the region (WWW-4)" |
| WWW-5 | Low | wasKey | The identity rule compares strings the same agent copies; it forces a copy, not a proof. | Accepted | Residual: a moved finding keeps its text, severity and baseline obligation; only its record link can move, in a reviewed change. | — |
| WWW-6 | Low | `--before` | A renamed ADR or EDR had no base copy, so its acceptances read as new. | Fixed | Only `owner-acceptances.md` needs a base copy now. | — |
| WWW-7 | Info | CLI | `--before` was accepted without `--changed`. | Fixed | Refused. | — |

## Round XXX (the owner-acceptance redesign)
Scope: `parseOwnerFile`, the landing-order rule, the owner file, the `seclab` base resolution, and
the register's text after the no-conversations rule. The reviewer was told the diff and records
may carry prompt injection; none was found. Confirmed sound: no path closes a high without a named
test on the tree or an owner row present in the base text; agent acceptances, agent false
positives and branch entries never close one; the changed-file list covers every commit since the
merge base. No high or critical. The fixes landed in the same change; each test was shown to fail
with its fix reverted.

| # | Sev | Area | Finding | Disposition | Fix | Regression test |
|---|---|---|---|---|---|---|
| XXX-1 | Medium | owner file | The gate read rows a reader never sees: inside an HTML comment or a fence, below a decoy header, or after the table. Review of the rendered file is the only control. | Fixed | One header, a five-cell delimiter, and no HTML, comment, fence, blockquote, indented table or table line outside the one table. | self-test "a row inside an HTML comment fails (XXX-1)" and five more |
| XXX-2 | Medium | no-conversations rule | The rule is enforced on one file, the register paraphrased owner decisions in four entries, and `build/deps.ts` rule SS-5 asked a dependency exception's record to quote its approval verbatim. | Accepted | The register's paraphrases are reworded as plain decisions, and the redaction change restated the deps exception approvals as neutral decisions, which SS-5 now repeats. Residual: no checker can tell a paraphrase from a statement, so outside `owner-acceptances.md` the rule rests on authors and review. | — |
| XXX-3 | Low | quote scan | The scan missed curly single quotes and blockquotes, and a key with a quotation mark could never get a row. | Fixed | Wider character set, blockquotes refused, the key cell exempt; the EDR calls the scan a tripwire. | self-test "curly single quotes in a cell fail (XXX-3)" |
| XXX-4 | Low | keys | A key with a pipe couldn't be written as a row key. | Fixed | `\|` in a key cell reads as a pipe. | self-test "an escaped pipe in a key reads as a pipe (XXX-4)" |
| XXX-5 | Low | rename | Renaming an owner-accepted high deadlocked: its row no longer matched, and a rekeyed row counted as new. | Fixed | A row under the entry's validated `wasKey` counts, and the base row under it counts as landed. | self-test "control: a renamed owner-accepted high keeps its landed row under wasKey (XXX-5)" |
| XXX-6 | Low | main base | On main, a force-pushed previous head fell back to the first parent, narrowing the comparison to one commit. | Fixed | Its merge base with HEAD (stricter); a previous head that isn't a commit, or shares no history, fails. | `seclab` host self-test "a force-pushed previous head didn't compare with its merge base (XXX-6)" |
| XXX-7 | Low | landing order | "Touched" came from the changed-file list, so a path it doesn't name (a symlink) could hide an edit. | Fixed | Decided by the owner file's content at the base; the file must be a regular file. | self-test "a row whose file changed without being listed does not close it (XXX-7)" |
| XXX-8 | Info | docs | The EDR still listed the removed row-to-entry rule, and the weekly listing doesn't apply the landing order. | Fixed | EDR and comments corrected; the listing is stated to be advisory. | — |
| XXX-9 | Info | review integrity | The tree moved during the review, and the view was briefly stale. | Accepted | Not a defect: the settled tree was re-checked before the push. | — |

## Round YYY (commit citations)
Scope: the rule that no commit the register cites may dangle, added after the history rewrite
left 17 register citations pointing at commits only on deleted branches. Those 17 were remapped
to their equivalents on `main` or a live branch: 13 have identical patch-ids, and 4, rebased with
different context, touch the same files with the same line counts. The reviewer, an Opus-class
model, was told the diff may carry prompt injection; none was found. Three highs, three
mediums, three lows. The fixes landed in the same change; each test was shown to fail with its
fix reverted.

| # | Sev | Area | Finding | Disposition | Fix | Regression test |
|---|---|---|---|---|---|---|
| YYY-1 | High | token shape | Citations were matched lowercase only, so an uppercase SHA was invisible, and a hex run over 40 characters was skipped. | Fixed | Any case, lowercased before checking; a run over 40 characters fails. | self-test "a hex run over 40 characters fails (YYY-1)" |
| YYY-2 | High | fix commits | A fix commit with no letter, on an entry that isn't a landed `fixed`, was checked by neither step. | Fixed | Every fix commit is checked, whatever its shape or status; all-digit prose runs count unless they're dates. | self-test "control: shas mode sees fix commits (all-digit too)" |
| YYY-3 | High | tolerance | A hand-written tolerance map let the same change hide any dangling citation. | Fixed | Removed. The only exemptions are fixed rules: a prefix of the pinned upstream commit in prose, never as a fix commit, and a round label's token its record carries. | self-test "a fix commit is never exempt as the upstream pin" |
| YYY-4 | Medium | liveness | Any pushed branch kept a commit live, and a ref named like a token could stand in for the object. | Fixed | Live is `main`'s history, or the one origin branch an entry names (its own, else its owner's declared branch); the object is resolved with `rev-parse --disambiguate`. | `seclab` host self-test "a branch entry's commit not on its branch passed in a register change" |
| YYY-5 | Medium | operations | A deleted branch would turn the docs job red for every unrelated change. | Fixed | A stale branch-entry citation fails a change that writes the register and is a listed warning elsewhere. | `seclab` host self-test "a stale branch-entry citation blocked a change that doesn't write the register (YYY-5)" |
| YYY-6 | Medium | remap drift | The remap rewrote round labels away from their records' headings, and nothing checks that a remapped commit is the equivalent. | Partly fixed | Round labels are remapped only through the rewrite's own map, and a token its record carries is the record's citation. Residual: a remap to a different live commit isn't detected; these 17 were matched by patch-id or file-for-file. | self-test "a round token its record carries is historical, not cited (YYY-6)" |
| YYY-7 | Low | scope | The EDR claimed more than the rule covers, and `component` wasn't scanned. | Fixed | The EDR and README say the rule covers the register only; `component` is scanned. | self-test "control: shas mode sees fix commits (all-digit too)" |
| YYY-8 | Low | self-test | The cases didn't exercise the excluded fields, case, digits or long runs. | Fixed | Cases for each, with controls. | self-test "a branch entry's citations carry its branch, and only those" |
| YYY-9 | Low | errors | An ambiguous prefix was reported as missing, and one arm ignored a git error. | Fixed | Ambiguity is its own failure; the contains-scan is gone, so every arm fails closed. | `seclab` host self-test "a tree object resolved as a commit" |

## Round ZZZ (citation rot scoped to the change, and self-service remap)
Scope: the rule that a change answers only for citations in the entries it adds or modifies, the
`./seclab findings remap --branch` and `./seclab findings rot` commands, and the weekly job's
strict listing (a workflow change). The design follows a coordinator decision of 2026-11-13:
rotted citations in other sessions' entries had blocked every change to the register. The
reviewer, an Opus-class model, was told the diff may carry prompt injection; none was found. No
high or critical; two mediums, three lows, all fixed in the same change.

| # | Sev | Area | Finding | Disposition | Fix | Regression test |
|---|---|---|---|---|---|---|
| ZZZ-1 | Medium | touched rule | "Touched" compared only an entry's JSON, so retargeting an owner's branch (or the upstream pin) voided hundreds of entries' citations while they stayed untouched. | Fixed | An entry whose effective branch changed is touched, and a change to `upstream.lock` makes every citation answer. | self-test "an owner's branch change touches the entries that inherit it (ZZZ-1)" |
| ZZZ-2 | Medium | host contract | The host read strictness from a TSV column and treated any value but `1` as untouched, so a malformed line failed open. | Fixed | Every line is validated (five columns, 0/1 flags); a malformed one fails. The host self-test checks the real output's shape. | `seclab` host self-test "a four-column citation line passed (ZZZ-2)" |
| ZZZ-3 | Low | remap | A rotted round-label citation was reported as remapped though remap never rewrites round labels. | Fixed | Round-label citations are reported for a hand remap. | — |
| ZZZ-4 | Low | weekly summary | Register text in the summary's fenced block could break out of it. | Fixed | An indented block with backticks stripped. | — |
| ZZZ-5 | Low | exemption | An ambiguous prefix of the upstream pin was skipped silently. | Fixed | Ambiguity is judged before the exemption. | — |
