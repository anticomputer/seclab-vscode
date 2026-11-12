# Security findings register: one current-state view, enforced by the docs gate

- **Status:** accepted
- **Date:** 2026-11-10
- **Deciders:** the project owner (the request to have pending review findings addressed; the
  ratchet for highs open today, with each baseline entry naming an owning session and component,
  a failure when a fixed entry is still in the baseline, and a weekly listing of the baseline; the
  rule that committed records never capture private conversations).
  Coordinator: the register, the CI conditions and the known items. Findings-register session:
  implementation.
- **Related:** [security reviews](../security-reviews/README.md),
  [docs-check](20261104-docs-check.md), [liveness gate](20261109-liveness-gate.md),
  [prompt-injection hygiene](20261104-prompt-injection-hygiene.md)

## Context
Every review round is recorded in `docs/security-reviews/`, and records are append-only. Each round
chose its own shape: tables with `#`/`ID` and `Sev`/`Severity` columns, numeric IDs restarting per
round, lettered rounds (`KKK-1`), placeholder rows (`—`, `(self)`) for residuals, prose `### HIGH`
sections and numbered `1. **HIGH, …**` items. Several rounds live only on unmerged branches. Nothing
answered "what is still open?", and the rule "a regression test for every real finding" was checked
by nobody: a record saying "Fixed" was the only evidence.

## Decision
1. **Source of truth:** `docs/security-reviews/findings.json`, schema-checked by
   `build/docs/findings.ts`. One entry per finding: record and anchor (its key), severity, summary,
   component, owning session, and a status:
   - `fixed`: the fix commit (must be on HEAD's history) **and** a regression test: a test file, or
     a case in a checker's own `--self-test`, and an exact name in it of at least 12 characters
     that occurs exactly once (a test title, a self-test case);
   - `fixed-untested`: the fix exists, the test doesn't (a CI step or a workflow line is not a
     test); counts as open;
   - `accepted-residual`: `acceptedBy` owner or agent, and a rationale. An agent's acceptance
     cites a record (`ref` quote). The owner's acceptance is a row in
     `docs/security-reviews/owner-acceptances.md`: the finding's full key, the date, the scope, the
     closing condition and "accepted by the project owner". No quotation marks are allowed in that
     file, and nothing in the register quotes or paraphrases a conversation;
   - `deferred`: the named follow-up;
   - `open`: the gap;
   - `false-positive`: concluded by a review (a quote from a review record), or for a high, by the
     owner (a row, as above).

   No citation may point at the register or its view (an entry citing itself). Entries for records
   or fixes that exist only on a branch carry `branch`; such an entry never satisfies the ratchet,
   and as soon as its record finding (or its ref, with no record) is on the tree it must drop
   `branch`, which brings every citation under the check. Items written down only in an EDR or plan
   (residuals, incidents) have `record: null` and a `ref`.
2. **Generated view:** `docs/security-reviews/FINDINGS.md` (`./seclab docs write`): the baseline
   first, then everything not fixed by owner, then every finding by record. Register text is
   escaped into one table cell (no HTML or links of its own), under a banner that it is data, not
   instructions.
3. **Extraction, not trust:** the check reads every record and extracts its findings. That covers
   each row of a table with a column starting "Sev" (keyed by its first cell; GFM tables with or
   without outer pipes), each `###`–`######` heading starting with a severity word, and each list
   item starting with a bold severity. A repeated anchor in a record gets `#n` by occurrence, so
   appending a round never renames an earlier finding. Shapes it can't read fail: a findings-shaped
   table with no Sev column, an HTML table, an unbalanced code fence, a stray file or subdirectory,
   and a record that yields no finding unless `noFindings` lists it.
   Prose findings without a marker are registered by hand (`manual`, with a quote that must stay in
   the record). A finding new since the merge base with `main` (judged against that base's
   register, not a file date) must have a unique explicit ID and a severity word.
4. **The gate** runs inside `./seclab docs check`, the required `docs` job (no new required check).
   It fails when:
   - a record has a finding the register lacks, or the register has an entry its record no longer
     yields;
   - a `fixed` entry's test is missing, ambiguous or not a test, or its commit isn't on HEAD's
     history;
   - a commit the register cites isn't a commit on `main`'s history or on the one origin branch
     its entry names (its `branch`, else its owner's declared branch). Cited means every fix commit, whatever its shape, and any
     hex run in the entry's own prose (round, note, gap, follow-up, rationale, summary, severity
     note, component), in any case, all-digit runs included unless they're dates; a run over 40
     characters fails. The host resolves the object itself, so a ref named like a token can't
     stand in for it, and an ambiguous prefix fails as such. Nothing is tolerated by hand; the
     fixed exemptions are a prefix of the pinned upstream Code-OSS commit (`upstream.lock`) in
     prose, never as a fix commit, and a round label's token its record carries verbatim (the
     record's own citation), both listed in FINDINGS.md. Quotes and test names copy committed
     text verbatim and aren't the register's citations;
   - the register lowers a severity the record states;
   - a high or critical is anything but `fixed`, owner-`accepted-residual` or an owner or reviewed
     `false-positive` on this tree, and isn't in the baseline;
   - a baseline entry is now compliant (it must be removed), isn't high, has no entry, or is new
     relative to the merge base's baseline;
   - the merge base's register isn't conserved: a key it had is gone, its severity dropped, or it
     left the baseline while still open;
   - an owner acceptance has no row in `owner-acceptances.md` (under its key, or its validated
     `wasKey` while a rename lands), a row names no registered finding, a row is malformed or
     duplicated, the file holds a quotation mark outside a key cell, or it holds anything that
     doesn't render as what the gate reads (HTML, a comment, a fence, a blockquote, an indented or
     second table, a table line outside the one table). A row may precede its entry's
     `acceptedBy: owner`: that is the required order;
   - a high is closed by an owner row this same change adds (the row lands first, judged by the
     file's content at the base, whatever the changed-file list says, and the file must be a
     regular file); a high false positive needs the owner too;
   - a `wasKey` (a moved finding's earlier key) names a live finding, is claimed twice, isn't in
     the merge base's register, sits on an entry the base already had, or changes the finding's
     summary, component or owner;
   - a record yields nothing the extractor reads and isn't listed (`noFindings` records must say
     they have none; `manualOnly` records, whose findings are prose registered by hand, take no
     newcomers);
   - FINDINGS.md is stale.
   The base is the register at the merge base with `origin/main` (on `main`, the push's previous
   head; after a force-push, that head's merge base with HEAD, which is stricter, and a previous
   head that isn't a commit or shares no history fails); a branch forked before the register is
   judged against `origin/main`'s; a read error fails closed. The baseline listing has no change
   to judge, so it doesn't apply the landing order: it is advisory, and the docs check is the gate. The rules that compare with the base engage once the register is on `main`:
   until then (this change's own landing) there is no base, and the check says so.
   `./seclab findings --self-test` injects each of these and requires the failure, with a control
   case beside each, including the host-side ancestry step; it runs in AGENTS.md's `ci: run` block.
5. **The ratchet (the owner's decision):** the highs and criticals open when the register started sit in
   `baseline`. Each names its owning session and component, nothing may join, and each leaves when
   fixed on `main` with its test or accepted by the owner. The weekly `liveness-refresh` workflow
   lists the baseline in its own job (`./seclab findings baseline`: offline, no token, only
   `contents: read`), which fails if a baseline key doesn't resolve, so none goes quiet.

## Liveness
The check is reached from `./seclab docs check`, which the required `docs` job runs on every push and
PR. `build/` is outside the liveness gate's export scope, and the script exports nothing. The weekly
listing is a job in `liveness-refresh.yml`, which runs on push of the files it lists (now including the
register), so it isn't a dispatch-only workflow. The liveness register has no subject kind for a
script run by a required job: what runs it is the docs job, and its evidence is every docs run's
`findings: ok` line.

## Consequences
- A review round isn't done until its findings are in the register (AGENTS.md §5, review README step
  7). Fixing a finding means updating its entry, with the test, in the same change.
- "Fixed" now needs a test that names the case; a large share of historical fixes are
  `fixed-untested`. Those are open work for their owners, listed in FINDINGS.md.
- An agent can't accept a high on its own, but the guarantee is now **procedural**, not
  cryptographic. Committed records never capture the owner's private conversations (no quotes, no
  paraphrases, no excerpts), so there is no quoted proof to check. Instead, an owner acceptance is
  a row in `docs/security-reviews/owner-acceptances.md` that only the coordinator writes, on an
  explicit owner decision, in its own change. The gate checks the row's shape and refuses quotation
  marks, and refuses a closure that lands in the same change as its row, so the row is on `main`,
  in history, a change before the closure, where the owner can see it. Since review of the
  rendered file is the control, the gate refuses anything in it that renders differently from what
  it reads. Nothing in the check can
  tell a coordinator-written row from an agent-written one: that rests on who may write the file
  and on review. A stronger option, owner-signed commits for that file, is with the owner.
- The no-conversations rule is project-wide, but this gate enforces it only on
  `owner-acceptances.md`, and its quotation-mark scan is a tripwire for the obvious form, not a
  detector of paraphrase. The register itself carries no owner quotes or paraphrases. Elsewhere,
  the redaction change restated earlier records and the deps exception approvals as neutral
  decisions, which `build/deps.ts` rule SS-5 now repeats. Beyond that the rule rests on authors and
  review (review XXX-2).
- `fixed` evidence is shape-checked: a named case in a test file or inside a checker's self-test.
  Whether the case really fails without the fix is for the review round to confirm.
- Branch sessions inherit the register when they rebase. A branch that adds a round, or lands a
  record the register lists with `branch`, must update the register in the same change. A high
  fixed only on a branch stays in the baseline until it lands.
- The register's commit citations never dangle silently. When a branch is rebased, squashed or
  deleted, its entries are remapped to the equivalent commit (same subject and change; the
  history-rewrite remap matched 17 by patch-id or file-for-file). A branch entry whose branch
  no longer holds its commit fails any change that writes the register and is listed as a
  warning in every other run, so an unrelated landing isn't blocked by another session's
  branch. The rule covers the register only: review records and EDRs are append-only and keep
  the SHAs they were written with, some of them now historical (review YYY-7).
- The repo is public, so FINDINGS.md and the weekly listing publish the open findings with their
  gaps. The register adds no detail the records didn't already hold (review RRR-5).

## Reviews
[Round QQQ](../security-reviews/20261110-security-findings-register.md) (the gate), round RRR
(the weekly listing, a workflow change) and re-review rounds SSS onward, in the same record.

## Alternatives considered
- **Hand-maintained FINDINGS.md:** drifts; the docs-drift rule asks for generated views.
- **Rewriting old records into one format:** records are append-only.
- **Failing on every open high now:** main would be red until every owner fixed theirs; the project
  owner chose the ratchet.
- **Quoted user decisions as proof:** an earlier design closed a high on a quoted decision in an ADR
  or EDR. Dropped: committed records never capture private conversations.
