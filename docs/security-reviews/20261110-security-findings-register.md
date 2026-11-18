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

## Round AAAA (patch-id citations, and the weekly job as a listing)
Scope: `patch:<patch-id>` citations for changes not yet on `main` (input from the agentic session,
routed by the coordinator), `./seclab findings remap --patch`, and the weekly `liveness-refresh`
findings job, which now lists open highs and rotted citations and passes, failing only on a
defect in a listing or a baseline larger than a week ago (coordinator decision, 2026-11-16). The
reviewer, an Opus-class model, was told the diff may carry prompt injection; none was found. No
high or critical; one medium and four lows, four fixed in the same change and one accepted.

| # | Sev | Area | Finding | Disposition | Fix | Regression test |
|---|---|---|---|---|---|---|
| AAAA-1 | Medium | patch-id cache | The patch-id cache under `.work/` was trusted whenever present, so a file a change committed there could make any `patch:` citation read live. | Fixed | The cache is emptied once per run, and a line that isn't the tool's own shape fails the lookup. | `seclab` host self-test "a malformed patch-id cache was trusted (AAAA-1)" |
| AAAA-2 | Low | patch-id evidence | A patch-id ignores whitespace and is derived from the path for a mode-only change, so it doesn't pin content. | Accepted | Residual: a `patch:` fix commit is allowed only on an entry with its own `branch`, which is never compliant; the landing change drops `branch` and must then pin a SHA, which the schema enforces. | self-test "a patch: fix commit never makes a high compliant (AAAA-2)" |
| AAAA-3 | Low | pin on main | A change on `main` whose branch still carried a copy read as live, so the pin rule never fired. | Fixed | `main` is checked first. | `seclab` host self-test "a patch-id on main wasn't reported for pinning (AAAA-3)" |
| AAAA-4 | Low | inherited branch | The schema allowed a `patch:` fix commit on an entry that only inherits its branch, which the ancestry step then rejected confusingly; remap could create one. | Fixed | A `patch:` fix commit needs the entry's own `branch`; remap leaves such an entry's fix commit a SHA. | self-test "a patch: fix commit on an entry that only inherits its branch fails the schema (AAAA-4)" |
| AAAA-5 | Low | weekly ratchet | The week-ago comparison point was chosen by any commit's date and was skipped silently when it lacked the register. | Fixed | It is the register's own last change over a week old, else its first commit; no comparison point fails. | — |

## Round BBBB (the weekly job's SIGPIPE)
Scope: the fix for a weekly `liveness-refresh` run that failed with exit 141 (SIGPIPE): its
growth step piped `git rev-list` into `head -1` under `pipefail`. The step moved into
`./seclab findings growth`, the listings print through a file, and the host self-test runs each
listing into `head -1` and `true` and refuses a pipe into an early-closing reader anywhere in
`seclab`. The reviewer, an Opus-class model, was told the diff may carry prompt injection; none
was found. No high or critical; one medium, three lows and one info, all fixed in the same change.

| # | Sev | Area | Finding | Disposition | Fix | Regression test |
|---|---|---|---|---|---|---|
| BBBB-1 | Medium | baseline listing | The listing wrote into `.work/` without creating it, so on a fresh runner the job failed before the growth check could run. | Fixed | The directory is created first. | — |
| BBBB-2 | Low | growth | The old register was read back through the bind mount, which can serve a partial file on macOS. | Fixed | Both registers reach node on stdin. | — |
| BBBB-3 | Low | growth | `growth 0` compared the register with itself and passed. | Fixed | DAYS must be positive, and HEAD itself is never the comparison point. | `seclab` host self-test "growth 0 compared the register with itself (BBBB-3)" |
| BBBB-4 | Low | structural check | The check missed `command head`, continuation lines and `grep -q`, covered only findings functions, and misread one-line functions. | Fixed | The whole of `seclab` is scanned, continuation lines are joined, `\|\|` and comments are skipped; the one remaining pipe into `head` (in the hook installer) now reads to the end. | `seclab` host self-test "seclab pipes into a reader that closes early" |
| BBBB-5 | Info | output | `findings_emit` hid a real read error's message. | Fixed | The file is checked before printing, and a failed check prints. | — |
| BBBB-6 | Medium | output | Found by CI after the round: runners ignore SIGPIPE, so `cat` gets EPIPE and exits 1, which the 141 tolerance missed. | Fixed | Any output error after the file check is the reader having gone, and passes. | `seclab` host self-test, the SIGPIPE-ignored cases |

## Round CCCC (citations that survive a rebase-merge, and upstream bumps)
Scope: the project owner's switch to pull-request landing with auto-merge's rebase method, which
re-creates every commit, so a branch SHA never lands. A citation of work not yet on `main` is now
`patch:<patch-id>` in any entry, resolved against the history being checked or `main`, and
`./seclab findings pin` writes the SHAs after landing. Also: a prefix of any pin `upstream.lock`
has held on `main` is exempt, and hex inside file paths isn't a citation (both for the 1.145.3
bump). The reviewer, an Opus-class model, was told the diff may carry prompt injection; none was
found. No high or critical; four mediums and three lows, all fixed in the same change. The change
withdraws the AAAA-4 schema rule (a `patch:` fix commit only on an entry with its own branch): a
`patch:` fix commit is allowed on any entry now, and the schema and the ancestry step agree on it.
AAAA-2's mitigation is restated: a `patch:` fix commit closes a high only once that change is on
`main`, so a change can't close a high on its own commits; whitespace equivalence stays a residual.

| # | Sev | Area | Finding | Disposition | Fix | Regression test |
|---|---|---|---|---|---|---|
| CCCC-1 | Medium | closing highs | A `patch:` fix commit resolved on the change's own history, so an add-then-revert pair in one PR could close a high. | Fixed | A high's `patch:` fix commit must be on `main`; the high closes in a follow-up. | `seclab` host self-test "a high closed on its PR's own patch: commit (CCCC-1)" |
| CCCC-2 | Medium | upstream pins | The exempt pins came from HEAD's history, so a change could add a pin and revert it to exempt any token. | Fixed | Only `main`'s history counts. | `seclab` host self-test "a pin outside main's history counted (CCCC-2)" |
| CCCC-3 | Medium | path hex | One adjacent `-`, `/` or `.` dropped a token, so the right end of every `A..B` round range and joined forms escaped. | Fixed | Only a real path (a non-hex segment beside `/`, or a file extension) is exempt; ranges never are. | self-test "both ends of a range and joined forms are (CCCC-3)" |
| CCCC-4 | Medium | pinning | A landed `patch:` was never a failure, nothing forced a pin, and a 3000-commit window would later fail every change with no repair. | Fixed | A later change touching an entry with an unpinned landed citation must pin it (the landing change isn't asked); resolution covers the whole history. | `seclab` host self-test "a later change touching an unpinned landed citation passed (CCCC-4)" |
| CCCC-5 | Low | test seam | An environment variable could replace `origin/main`, and an unresolvable one skipped the rule silently. | Fixed | `main` is a parameter, and an unresolvable one is a defect. | `seclab` host self-test "an unresolvable main didn't fail as a defect (CCCC-5)" |
| CCCC-6 | Low | earlier rounds | AAAA-2's rationale and AAAA-4's test rested on the withdrawn rule. | Fixed | Both are restated above and in the register. | — |
| CCCC-7 | Low | self-test | No case for a poisoned whole-history cache, an unresolvable main, or a pin from outside `main`. | Fixed | Added. | `seclab` host self-test "a malformed whole-history cache was trusted (CCCC-7)" |

## Round DDDD (explicit-ID clashes, and the first pin)
Scope: a warning when a change adds a clash between explicit finding IDs (`WL-5`) across records,
suggested by the RPC channel lockdown session, and the first `./seclab findings pin`, which wrote
round CCCC's `patch:` fix commit as the SHA it landed as (verified by patch-id). The reviewer, an
Opus-class model, was told the diff may carry prompt injection; none was found. One high, found in
code that predates this change, and three lows and an info, all fixed in the same change.

| # | Sev | Area | Finding | Disposition | Fix | Regression test |
|---|---|---|---|---|---|---|
| DDDD-1 | High | fix-commit lines | An anchor could hold a tab or newline, so a high's line to the host ancestry step split in two and the second, keyless half was skipped, defeating CCCC-1. | Fixed | Anchors must be one line with no control characters; keys are flattened in that output; the host refuses a malformed line. | self-test "an anchor with a tab fails the schema (DDDD-1)", `seclab` host self-test "a four-field fix-commit line passed (DDDD-1)" |
| DDDD-2 | Low | log output | Register text printed to the CI log could start a workflow command. | Fixed | Anchors can't start one, owner ids are `[a-z0-9-]`, and the warning text is flattened. | self-test "an anchor that starts a workflow command fails the schema (DDDD-2)" |
| DDDD-3 | Low | clash scope | Concurrent branches are usually different owners, which a same-owner rule never warned. | Fixed | Any owner; summaries compared normalised. | self-test "an explicit ID a change reuses with another meaning is warned, across owners (DDDD-3)" |
| DDDD-4 | Low | clash noise | Touching any entry already in a clash warned about it again. | Fixed | Only clashes the base didn't have; no base, no warnings. | self-test "control: editing an entry whose clash the base already had is not warned (DDDD-4)" |
| DDDD-5 | Info | self-test | Numbered anchors, other owners, edits and the check's exit code weren't covered. | Fixed | Added. | self-test "control: a clash warning never fails the check (DDDD-5)" |

## Round EEEE (recording a high fixed in its own change)
Scope: recording DDDD-1, a high found and fixed in one change, showed that CCCC-1 (a high's
`patch:` fix commit must already be on `main`) made any such high unrecordable. A high the register
already had still needs its fix on `main`; a high new in the change may cite the change's own
commits. The same reviewer re-checked DDDD-1 to DDDD-5 (closed, with DDDD-2's remainder below).
No high or critical; one medium and two lows, all fixed in the same change.

| # | Sev | Area | Finding | Disposition | Fix | Regression test |
|---|---|---|---|---|---|---|
| EEEE-1 | Medium | new highs | "New" meant absent from the merge base, so a stale fork point could demote a high on `main`, and an add-then-revert pair could close a new high for good. | Fixed | "Already recorded" means on `main` or at the merge base; a fix whose revert is also in the history closes nothing. | `seclab` host self-test "a reverted fix passed ancestry (EEEE-1)" |
| EEEE-2 | Low | log output | Other problem lines still printed register text raw. | Fixed | Every printed line is flattened at the sink. | self-test "every printed line is one line and never a workflow command (EEEE-2)" |
| EEEE-3 | Low | host contract | An empty severity flag passed as not-high. | Fixed | The flag must be 0 or 1. | `seclab` host self-test "a fix-commit line with no severity flag passed (EEEE-3)" |

## Round FFFF (finding-ID clashes across concurrent branches)
Scope: a clash between two findings of one owner now fails the docs check once the first has
landed, and `./seclab findings clashes` compares a change's new IDs with every open pull request's
head before landing (advisory, local). Reviewed before it was committed, by an Opus-class model.
No high or critical; one medium and five lows, all fixed in the same change.

| # | Sev | Area | Finding | Disposition | Fix | Regression test |
|---|---|---|---|---|---|---|
| FFFF-1 | Low | clash freshness | A cross-owner clash the base had became one owner's two meanings by changing an owner, with no failure. | Fixed | A pair is a fresh same-owner clash unless the base had it as one. | self-test "a clash the base had across owners fails once one owner holds both (FFFF-1)" |
| FFFF-2 | Medium | generic IDs | The failure would block an owner's next generic round ID (`R-1`), a convention in its records. | Fixed | A one-letter round ID, or one its owner already reuses in the base, stays a warning. | self-test "a generic round ID reused by its owner is a warning, not a failure (FFFF-2)" |
| FFFF-3 | Low | stale heads | A stale PR head counted an entry main changed later as one it mints, a false clash. | Fixed | An entry main already has is never the PR's. | self-test "a stale PR head does not claim an entry main already has (FFFF-3)" |
| FFFF-4 | Low | own PR | This branch's own PR was found by branch name, so local amendments could be reported against themselves. | Fixed | The own PR comes from gh, and any head HEAD contains is skipped. | `seclab` host self-test "PR heads to compare weren't own-PR, fork and ancestor filtered (FFFF-4, FFFF-6)" |
| FFFF-5 | Low | unreadable input | A PR register that wasn't JSON was dropped silently, and an internal error exited like a clash. | Fixed | It is reported and counted as skipped; an internal error exits 3. | self-test "a PR register that does not parse is reported, not dropped (FFFF-5)" |
| FFFF-6 | Low | untrusted PRs | A fork's PR, which anyone can open, was compared and could steer a rename. | Fixed | A fork's PR is noted and never compared. | `seclab` host self-test "PR heads to compare weren't own-PR, fork and ancestor filtered (FFFF-4, FFFF-6)" |

## Round GGGG (fixed before landing, a green main, byte format, rebase-resolve)
Scope: the `fixed-before-landing` status, the docs workflow's link-check step getting the same
`DOCS_BASE` as the gate (a workflow change), the on-main pin note, the byte-format check and
`./seclab findings rebase-resolve` ([EDR](../edr/20261117-fixed-before-landing.md)). Reviewed by an
Opus-class model. The paths that would close a recorded high under the new status (rename without
`wasKey`, rename with it, delete and re-add, unrelated commits, a forged changed-files list) were
checked and are blocked. No high or critical; one medium, two lows and three informational
findings, all fixed in the same change, then three lows from the re-review below.

| # | Sev | Area | Finding | Disposition | Fix | Regression test |
|---|---|---|---|---|---|---|
| GGGG-5 | Medium | evidence | The record of the failing run was checked only while the entry was new, so a later change could remove it. | Fixed | `preFixRef` is checked for the entry's whole life. | self-test "a landed fixed-before-landing entry whose failing-run quote is gone fails (GGGG-5)" |
| GGGG-6 | Low | absent base | With no base register every fixed-before-landing check was skipped. | Fixed | Such an entry fails, and the host judges it as new. | self-test "fixed-before-landing with no base register fails (GGGG-6)" |
| GGGG-7 | Low | comparison point | The first draft read the push's previous head from the event file, which earlier steps of the job can rewrite. | Fixed | The link-check step gets a step-level `DOCS_BASE` instead; the event file is not read. | `seclab` host self-test "a docs workflow step runs the gate without DOCS_BASE (GGGG-7)" |
| GGGG-8 | Info | main | On `main` the reviewed commit wasn't compared with the push's previous head. | Fixed | It is, as on a pull request. | `seclab` host self-test "doesn't judge fixed-before-landing against its base (GGGG-8)" |
| GGGG-9 | Info | merge | The register merge copied unknown top-level keys (a `__proto__` key vanished) and dropped a finding one side removed. | Fixed | Both are refused. | self-test "a finding one side removed is refused by merge3, never dropped (GGGG-9)" |
| GGGG-10 | Info | markers | The conflict-marker scan matched seven-character markers only. | Fixed | Seven or more, and the diff3 base marker. | `seclab` host self-test "an 8-character conflict marker wasn't seen (GGGG-10)" |

Re-review of the fixes and the workflow change, by the same reviewer: GGGG-5 to GGGG-10 verified
closed. The workflow change meets the CI baseline: the expression is in step-level `env:`, never in
`run:`; no new action, image, permission or token; nothing echoes the environment. No high or
critical; three lows, fixed in the same change.

| # | Sev | Area | Finding | Disposition | Fix | Regression test |
|---|---|---|---|---|---|---|
| GGGG-11 | Low | branch entries | A fixed-before-landing entry on a branch failed for evidence not yet on this tree. | Fixed | A branch entry is judged when it lands, as its record and test are. | self-test "a branch fixed-before-landing entry is not failed for evidence not yet on this tree (GGGG-11)" |
| GGGG-12 | Low | rebase-resolve | It regenerated files it didn't stage, and still reported them resolved. | Fixed | Every refreshed file is staged unless it holds a marker. | `seclab` host self-test "a refreshed view that wasn't conflicted wasn't staged, or a file with markers was (GGGG-12)" |
| GGGG-13 | Low | test strength | GGGG-7's test counted lines, not steps, and the prefix base rule had no test. | Fixed | The workflow is checked step by step, block runs included; the base rule has a case. | `seclab` host self-test "a block-run gate step without its own DOCS_BASE passed (GGGG-13)" |

## Round PRR11 (pull request #11's automated review)
Scope: the three threads the automated pull-request reviewer opened on #11, checked against the
code. No high or critical; one medium and two lows, fixed in the same change. The first thread's
own claim, that `::command::` runs after other text on a line, is not what the runner does: it
takes that form only at the start of a line, after leading spaces (actions/runner@7afce9ed,
`src/Runner.Common/ActionCommand.cs`, `TryParseV2`). The legacy `##[command]` form, though, is
taken anywhere in a line (`TryParse`), and the printed lines didn't break it.

| # | Sev | Area | Finding | Disposition | Fix | Regression test |
|---|---|---|---|---|---|---|
| PRR11-1 | Low | log output | A printed line could carry a legacy `##[command]` from register text anywhere in it. | Fixed | Every printed line, and every key the host prints, breaks `##[`. | self-test "a legacy workflow command anywhere in a printed line is broken (PRR11-1)" |
| PRR11-2 | Medium | reverted fixes | Once a fix was pinned to its SHA, a later revert of it no longer reopened the finding. | Fixed | A SHA fix commit is checked for a later revert as a `patch:` one is. | `seclab` host self-test "a pinned fix that was reverted later passed ancestry (PRR11-2)" |
| PRR11-3 | Low | reverted fixes | The revert search covered commits before the fix, so a fix that reverts the change that brought the issue was taken for a reverted fix. | Fixed | Only commits after the fix count. | `seclab` host self-test "a fix that reverts the unsafe change was taken for a reverted fix (PRR11-3)" |

Second pass, on the fixed head: three more threads, all true when checked against the code, fixed in
the same change. No high or critical.

| # | Sev | Area | Finding | Disposition | Fix | Regression test |
|---|---|---|---|---|---|---|
| PRR11-4 | Medium | branch entries | A fixed-before-landing entry the base had on its branch skipped the new-entry checks when it landed. | Fixed | An entry the base had only on its branch counts as new when it lands. | self-test "landing a branch fixed-before-landing entry judges it as new (PRR11-4)" |
| PRR11-5 | Low | evidence | A landed fixed-before-landing entry could become plain `fixed` and drop its failing-run evidence. | Fixed | It keeps the status; it may reopen. | self-test "a landed fixed-before-landing entry turned into fixed fails (PRR11-5)" |
| PRR11-6 | Low | local runs | A local check on `main` without a range compared with `HEAD^1` and failed a correct multi-commit landing. | Fixed | With no range, landed entries count as landed; CI on `main` without a range fails. | self-test "on main with no range a landed fixed-before-landing entry is not re-judged (PRR11-6)" |

Third pass: two more threads, both true, fixed in the same change. No high or critical.

| # | Sev | Area | Finding | Disposition | Fix | Regression test |
|---|---|---|---|---|---|---|
| PRR11-7 | Low | local runs | On `main` with no range, an entry `HEAD^1` had open was still refused once it became fixed-before-landing. | Fixed | With no range nothing is compared with `HEAD^1`; the evidence is still checked. | self-test "on main with no range an entry HEAD^1 had open is not refused (PRR11-7)" |
| PRR11-8 | Low | new refs | A new branch or tag pushed at a landed commit (an all-zero previous head) would fail for a missing range. | Fixed | Only an update of `main` itself needs the range; other refs at landed commits are landed history. | `seclab` host self-test "a new branch or tag pushed at a landed commit wasn't landed history (PRR11-8)" |

Fourth pass: one more thread, true, fixed in the same change. No high or critical. (A fifth comment,
on the cost of the PR-head comparison, was a performance fix and isn't a finding.)

| # | Sev | Area | Finding | Disposition | Fix | Regression test |
|---|---|---|---|---|---|---|
| PRR11-9 | Low | landed entries | After landing, a fixed-before-landing entry's reviewed commit could be edited to equal its fix (or follow it) and still pass. | Fixed | The host checks every entry's commits; only the comparison with the landing base is for new ones. | `seclab` host self-test "a landed entry whose reviewed commit is its own fix passed (PRR11-9)" |

Fifth pass: two threads. One is true and fixed in the same change. The other, a reopened
fixed-before-landing finding later closed as plain `fixed`, is not a defect. A reopened finding is
an ordinary recorded one, and closing it as `fixed` needs its fix on `main` and a regression test,
like any other. The earlier failing-run evidence stays in its record and the history.

| # | Sev | Area | Finding | Disposition | Fix | Regression test |
|---|---|---|---|---|---|---|
| PRR11-10 | Low | clashes | `findings clashes` listed pull requests from the caller's directory but fetched them from this checkout, so another checkout's numbers could be compared. | Fixed | gh runs in this checkout. | `seclab` host self-test "gh ran outside this checkout (PRR11-10)" |

Sixth pass: one thread, true, fixed in the same change.

| # | Sev | Area | Finding | Disposition | Fix | Regression test |
|---|---|---|---|---|---|---|
| PRR11-11 | Low | local runs | On `main` with no range, the fixed-before-landing to `fixed` transition rule still compared with `HEAD^1`, which may be the same landing's own commit. | Fixed | With no range that rule compares nothing, as the new-entry rules don't. | self-test "on main with no range a transition from HEAD^1 is not judged (PRR11-11)" |

Seventh pass: one thread, true, fixed in the same change.

| # | Sev | Area | Finding | Disposition | Fix | Regression test |
|---|---|---|---|---|---|---|
| PRR11-12 | Low | local runs | On `main` with no range, uncommitted register edits were exempted as landed history, so a recorded finding could be switched to fixed-before-landing locally. | Fixed | Uncommitted edits on `main` are judged against `HEAD` with every rule on. | `seclab` host self-test "uncommitted edits on main without a range weren't judged exactly (PRR11-12)" |

Eighth pass: one thread, true, fixed in the same change.

| # | Sev | Area | Finding | Disposition | Fix | Regression test |
|---|---|---|---|---|---|---|
| PRR11-13 | Low | reverted fixes | A fix whose revert was itself reverted (the fix reapplied) still counted as reverted. | Fixed | The newest revert or reapplication after the fix decides. | `seclab` host self-test "a fix whose revert was reverted was taken as reverted (PRR11-13)" |

## Round HHHH (pending owner acceptances)
Scope: an owner row that may name a finding whose record hasn't landed, for at most seven days
([EDR](../edr/20261118-pending-owner-acceptances.md)). Reviewed by an Opus-class model. Checked and
sound: `register#` keys and malformed keys are never pending, a pending key can't be claimed by an
unvalidated `wasKey`, and the row and its closure in one change still fail (UUU-4). No high or
critical; two mediums, two lows and one low accepted as designed. HHHH-1 to HHHH-3 tag the self-tests
written with the change.

| # | Sev | Area | Finding | Disposition | Fix | Regression test |
|---|---|---|---|---|---|---|
| HHHH-4 | Medium | row authorship | The gate checks a row's shape, not who wrote it, so a pending row lets a session that writes a row itself close a new high two landings later. | Deferred: making authorship machine-checkable (a required reviewer or signed commits) is an owner decision | — | — |
| HHHH-5 | Medium | expiry | Re-dating a pending row, or deleting and re-adding it, restarted its seven days. | Fixed | Age counts from the earlier of the row's date and the first commit that added its key. | self-test "a re-dated or re-added pending row is judged from its first commit (HHHH-5)" |
| HHHH-6 | Low | main's records | An empty list of main's records was read as "nothing on main". | Fixed | An empty list fails like a missing one. | self-test "an empty main record list fails closed like a missing one (HHHH-6)" |
| HHHH-7 | Low | dates | A date a day ahead stretched the window to about eight days, and an impossible date was reported as a future one. | Fixed | The first commit bounds the window; an impossible date says so. | self-test "a pending row with an impossible date says so (HHHH-7)" |
| HHHH-8 | Low | expiry | An expired row fails every landing until someone removes it. | Accepted | Failing on expiry is the coordinator's design; any change may remove an expired pending row. | self-test "control: removing an expired pending row passes (HHHH-8)" |

## Round PRR58 (pull request #58's automated review)
Scope: the five threads the automated pull-request reviewer opened on #58 (pending owner rows),
checked against the code. All true, all fixed in the same change. No high or critical.

| # | Sev | Area | Finding | Disposition | Fix | Regression test |
|---|---|---|---|---|---|---|
| PRR58-1 | Low | row keys | A key with no `#`, or no anchor after it, could pass as pending. | Fixed | A pending key is `record#anchor` with both parts. | self-test "a row key without record and anchor is never pending" |
| PRR58-2 | Low | dates | A date like `2026-13-01` threw instead of being reported. | Fixed | An invalid timestamp is reported as not a real date. | self-test "is reported, not thrown (PR #58 review)" |
| PRR58-3 | Low | dates | A row dated tomorrow passed. | Fixed | A date after the run's UTC day fails. | self-test "a pending row dated tomorrow fails (PR #58 review)" |
| PRR58-4 | Low | first seen | The first-seen lookup matched only one spelling of a row, so a backticked row could be re-dated. | Fixed | The owner file's history is parsed as the gate reads rows. | self-test "first-seen dates read rows as the gate does: backticks, spacing and escaped pipes (PR #58 review)" |
| PRR58-5 | Low | first seen | An uncommitted last row made the lookup exit non-zero and stopped the check. | Fixed | The history is read in one `git log`; a row with no commit uses its own date. | `seclab` host self-test "the history isn't oldest first" |

Second pass: one thread, true, fixed in the same change.

| # | Sev | Area | Finding | Disposition | Fix | Regression test |
|---|---|---|---|---|---|---|
| PRR58-6 | Low | first seen | A row dated before its first commit could be re-dated to restart its window, since only the commit date was kept. | Fixed | The earliest of the first commit and every Date the key's rows have had starts the clock. | self-test "a pending row dated before its first commit and later re-dated keeps its first date (PRR58-6)" |

Third pass: one thread, true, fixed in the same change.

| # | Sev | Area | Finding | Disposition | Fix | Regression test |
|---|---|---|---|---|---|---|
| PRR58-7 | Low | first seen | An impossible historical Date (`2026-02-30`) could become the first date, then be rejected, so the window fell back to the current date. | Fixed | Historical dates pass the same round-trip check as the current one. | self-test "an impossible historical date never becomes the first date (PRR58-7)" |

## Round IIII (a new high closed by its own change shows its test failing on main)
Scope: a high new in a change, registered `fixed` by that change's fix, carries `preFix` (a `main`
commit the fix descends from) and `preFixRef`, as `fixed-before-landing` does
([EDR](../edr/20261118-new-highs-failing-baseline.md)). Reviewed by an Opus-class model. One high,
three mediums and two lows from the review, and one low found while proving the fixes, all fixed in
the same change before it landed. IIII-1 and IIII-2 tag the self-tests written with the change.

| # | Sev | Area | Finding | Disposition | Fix | Regression test |
|---|---|---|---|---|---|---|
| IIII-3 | High | grandfathering | Naming any commit already on `main` as the fix exempted a new high from the evidence. | Fixed | Every listed entry needs `preFix`; an old fix cites one before it. | `seclab` host self-test "naming a fix already on main skipped the evidence (IIII-3)" |
| IIII-4 | Medium | main | On `main`, `origin/main`'s register is the tree's own, so the check listed nothing. | Fixed | On `main` it compares with the base's register. | `seclab` host self-test "findings_check doesn't run the own-fix check against its base (IIII-7, IIII-4)" |
| IIII-5 | Medium | evidence | A later change could drop a `fixed` entry's `preFix` and `preFixRef`. | Fixed | They never change while it is fixed. | self-test "dropping a fixed entry preFix evidence fails (IIII-5)" |
| IIII-6 | Medium | severity | A key registered medium and raised to high later escaped the rule. | Fixed | Only a key already high on `main` or the base is grandfathered. | self-test "a key raised to high in this change is listed for the own-fix check (IIII-6)" |
| IIII-7 | Low | wiring | No tripwire held the new check's call in `findings_check`. | Fixed | A tripwire on `findings_check`'s body. | `seclab` host self-test "findings_check doesn't run the own-fix check against its base (IIII-7, IIII-4)" |
| IIII-8 | Low | resolution | A `patch:` preFix could resolve to a different commit than meant. | Fixed | `preFix` is on `main`, so it is a SHA. | `seclab` host self-test "a patch: preFix passed (IIII-8)" |
| IIII-9 | Low | wiring | The GGGG-8 tripwire searched the whole file and matched its own text, so it could never fail. | Fixed | Both tripwires search `findings_check`'s body only; each proved by removing its call. | `seclab` host self-test "findings_check doesn't judge fixed-before-landing against its base (GGGG-8)" |

IIII-3 was found in review of the unmerged change and fixed in it, so it is registered
fixed-before-landing: the host self-test naming a fix already on main skipped the evidence (IIII-3)
failed on the reviewed commit and passes with the fix.

Re-review of the fixes by the same reviewer: IIII-3 to IIII-9 verified closed, IIII-3's evidence
chain and HEAD's HHHH-4 closure checked. Three more, about the strength of the cited tests, fixed in
the same change.

| # | Sev | Area | Finding | Disposition | Fix | Regression test |
|---|---|---|---|---|---|---|
| IIII-10 | Low | test strength | IIII-8's test used an empty commit's patch-id, so a malformed-line rule refused it before the SHA rule. | Fixed | The case names a real main commit the fix descends from, which only the SHA rule refuses. | `seclab` host self-test "the control (the same base by SHA) failed (IIII-10)" |
| IIII-11 | Low | test strength | Nothing pinned the tripwires' body scoping, so a return to a whole-file search stayed green. | Fixed | A synthetic file with the call missing and its text in a tripwire must not match. | `seclab` host self-test "the tripwire matched text outside findings_check (IIII-11)" |
| IIII-12 | Info | schema | The schema still accepted a `patch:` preFix on a `fixed` entry. | Fixed | Only a SHA. | self-test "a patch: preFix on a fixed entry fails the schema (IIII-12)" |

## Round PRR61 (pull request #61's automated review)
Two threads. One restated IIII-10, already fixed in this change. The other is true and fixed here.

| # | Sev | Area | Finding | Disposition | Fix | Regression test |
|---|---|---|---|---|---|---|
| PRR61-1 | Medium | grandfathering | A landed high was no longer listed, so a later change could set its fix to its own preFix and pass. | Fixed | An entry that carries a preFix is always listed, so its evidence is always checked. | self-test "a grandfathered high that carries a preFix is still listed for its evidence check (PRR61-1)" |

## Round JJJJ (recorded highs on a tip behind main)
Scope: a recorded high closed on a landed `patch:` fix failed the check on any branch or checkout
behind a newer `origin/main` (IIII-3 off `main`), since the gate required all of `main` in the
tree. The fix asks only that the landed commit be on the tree's history. Also a retry for
`rebase-resolve`'s regeneration step. Reviewed by an Opus-class model. No high or critical.

| # | Sev | Area | Finding | Disposition | Fix | Regression test |
|---|---|---|---|---|---|---|
| JJJJ-1 | Medium | ancestry | A recorded high's landed `patch:` fix failed on any tree behind a newer `origin/main`, blocking pull requests. | Fixed | The commit on `main` that carries the fix must be on the tree's history. | `seclab` host self-test "a landed high's fix failed on a tip behind main (JJJJ-1)" |
| JJJJ-2 | Low | rebase-resolve | The regeneration step failed when Docker Desktop's bind mount showed a file git had just written as it was, and a re-run worked. | Fixed | One retry after a pause; the second result stands. | `seclab` host self-test "a step that fails once wasn't retried (JJJJ-2)" |
| JJJJ-3 | Medium | ancestry | With the JJJJ-1 relaxation, a tip behind a revert on `main` could close a high on a fix `main` no longer has. | Fixed | The fix must also not be reverted on `main`. | `seclab` host self-test "a high closed on a fix main has reverted since (JJJJ-3)" |

## Round PRR65 (pull request #65's automated review)
Two threads, both true, fixed in the same change. No high or critical.

| # | Sev | Area | Finding | Disposition | Fix | Regression test |
|---|---|---|---|---|---|---|
| PRR65-1 | Low | ancestry | When main reverted and reapplied a fix, only the newest carrier counted, so a tree at the original fix failed. | Fixed | Any main commit carrying the fix that is on the tree's history counts. | `seclab` host self-test "a tip at the original fix failed after main reverted and reapplied it (PRR65-1)" |
| PRR65-2 | Medium | ancestry | The main-side revert check applied only to `patch:` citations, so a pinned high escaped it. | Fixed | A recorded high's SHA fix is checked for a revert on main too. | `seclab` host self-test "a pinned high closed on a fix main has reverted since (PRR65-2)" |
