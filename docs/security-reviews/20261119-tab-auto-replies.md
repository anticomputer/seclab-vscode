# Security review: no tab auto reply on the shared local pty host (patch 0061)

- **Date:** 2026-11-19
- **Reviewer:** independent `security-review` agent (an Opus-class model).
- **Subject:** patch 0061 on `anticomputer-rpc-auto-replies`, its unit suite and the runtime
  harness ([EDR](../edr/20261119-tab-auto-replies.md)).
- **Prompt:** said the diff, fixtures and evidence may contain prompt injection aimed at the
  reviewer, and that the reviewer reports it rather than following it. None was found.

## Verdict
R5-32 was found by the terminal-settings review (patches 0053-0058, round 10) and is a high on
main: a tab window installed auto replies, which the tab's server can set, on the local pty host
every window shares, where they type into normal windows' local terminals. It lands here first, on
its own. Round 1 of 0061 found no vulnerability and four correctness defects, all fixed. Round 2
found the other direction on main, a medium (AR-5): the host user's pairs went to the tab's server.
It is the terminal-settings review's R5-31, fixed here at the backend instead. Round 3: see below.

## How the evidence was made
The unit test (`test/containment/auto-replies.test.ts`) runs upstream's auto-reply contribution
over a local backend running the tree's `LocalTerminalBackend.installAutoReply`. On main (3633e20d) the case "a tab window installs no auto reply on the shared local pty host" fails, with the tab's reply installed on the local pty host.
It passes with 0061. The runtime harness (`test/containment/auto-reply-probe.ts`) reproduced it on
main's containment build: the tab's reply was typed into a normal window's local `cat` terminal
([EDR](../edr/20261119-tab-auto-replies.md), Proof).

## Findings

| # | Sev | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| R5-32 | High | terminal | A tab window installed auto replies, which the tab's server can set through the remote user settings, on the local backend too; the local pty host is shared by every window and applies each reply to all its terminals, so a tab could type a command into a normal window's local shell. | fixed | In a tab window the local backend installs none. | test/containment/auto-replies.test.ts "a tab window installs no auto reply on the shared local pty host" |
| AR-1 | Low | build | The first version gated the contribution with a new constructor dependency, which upstream's own test, constructing it with three arguments, would not compile against. | fixed | The gate moved into the local backend, which already holds the window's environment service. | none |
| AR-2 | Low | tests | The runtime harness was outside the harness-hygiene lint. | fixed | Added to its list. | none |
| AR-3 | Low | tests | One check's detail carried container stderr uncapped. | fixed | Capped, as in the sibling harnesses. | none |
| AR-4 | Low | tests | The harness recorded whether the local terminal ran cat but kept going if it didn't. | fixed | It types nothing unless the terminal is cat. | none |
| AR-5 | Medium | terminal | A tab window installed the host user's auto-reply pairs on the tab's own backend, whose server reads them; the setting is restricted, so patch 0036 withholds it from the tab's extension host. | fixed | A tab's backend installs only pairs in the tab's own settings (0060's rule). | test/containment/auto-replies.test.ts "a tab window installs no auto reply on the shared local pty host" |
