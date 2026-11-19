# Security review: every tab test agrees with the RPC filter's (SRCH3-14)

- **Date:** 2026-11-19
- **Reviewer:** independent `security-review` agent (an Opus-class model).
- **Subject:** `anticomputer-rpc-tab-authority`: patches 0006, 0015, 0017, 0018, 0035, 0036 and
  0050, their sources under `agentic/patch-src`, and the series-wide guard in
  `test/containment/filter-module.test.ts` ([EDR](../edr/20261119-tab-authority-case.md)).
- **Prompt:** said the diff, fixtures and evidence may contain prompt injection aimed at the
  reviewer, and that the reviewer reports it rather than following it. None was found.

## Verdict
Round 1 confirmed each change agrees exactly with the filter's `/^seclab\+/i`: a lower-cased
`startsWith('seclab+')` matched it for every code point substituted at every position, the context
key regex keeps upstream's behaviour for an empty remote name, and nothing in base or platform
imports the workbench. It found one low, in the guard (TA-1), fixed. No high or critical.

## How the evidence was made
On main (e30877c7) the case "every seclab+ tab test the series ships is case-insensitive, as the filter's (SRCH3-14)" fails, listing the twelve case-sensitive tests; it passes here.
The channel-guard, host-terminal and agentic gate suites each fail on main's code with their
mixed-case cases.

## Findings

| # | Sev | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| TA-1 | Low | tests | The series-wide guard matched a short list of shapes (no `!==`, `indexOf`, `includes`, unanchored or flagless regexes, a `vscode-remote://` literal), stripped `//` inside strings, excused a line removed from any file, and read `patches/series` differently from the build. | fixed | It reads every `seclab` token: regex literals must be anchored and case-insensitive, strings and prefix constants may only go to a lower-cased `startsWith`; comments are stripped outside quotes, a removal counts only in the same file, and the series is read as the build reads it. | none |
