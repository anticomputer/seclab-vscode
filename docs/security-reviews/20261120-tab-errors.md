# Security review: errors that cross to a tab carry no host stack (patch 0062, AIP-4)

- **Date:** 2026-11-20
- **Reviewer:** independent `security-review` agent (an Opus-class model), round 1.
- **Subject:** `anticomputer-rpc-denial-errors-aip-4`: patch 0062 (`seclabErrorForTab` in
  `errors.ts`, the refusal path and error replies in `rpcProtocol.ts`, error replies to a tab's
  server in `ipc.ts`); the refusal text of 0030 and of the agent-host gate (0015); the unit suite
  `test/containment/tab-errors.test.ts`; the runtime harness `test/containment/error-probe.ts` and
  its tab extension. Design: [EDR](../edr/20261120-tab-errors.md). The finding it fixes, AIP-4, was
  raised by the AI-feature probes review.
- **Prompt:** said the diff, fixtures and evidence may contain prompt injection aimed at the
  reviewer, and that the reviewer reports it rather than following it. None was found.

## Verdict
No high or critical finding. The reviewer traced every window-to-tab error path (RPC replies,
window-to-tab requests that carry an error, IPC replies, the agent-host gate, the terminal pushes)
and found AIP-4's property holding on each; the tab can't switch the IPC cleaning off, since the
window's channel server context is built locally. Eight low or informational findings, all handled
here: six fixed (two with a regression test), two recorded in the EDR as residuals. Round 2
reviewed those fixes and found no high or critical: five more low or informational findings, all
handled (TE-9 to TE-13). Round 3 found none either, and two informational findings (TE-14, TE-15), both fixed.

## How the evidence was made
The unit suite runs upstream's real RPC protocol and IPC channel server and client with the series
applied, loaded from a virtual install path holding a canary user name. On main (`d34da65f`) the
case "patched: every refusal and the ordinary failure reach the tab with no host stack (AIP-4)"
fails: every refusal and failure sends its frames, the RPC refusal names the canary path and
`_deny`, and an error whose message can't be read gets no reply (TE-2). It passes with this change,
and each of ten mutants of 0062 is caught. On the commit round 1 reviewed (the one that adds 0062) the case
"patched: every refusal and the ordinary failure reach the tab with no host stack (AIP-4)" fails with TE-1's nested stack sent and TE-2's call left unanswered. The runtime harness reproduced AIP-4 on main's
containment build, the canary install path in the tab's own log
([EDR](../edr/20261120-tab-errors.md), Proof).

## Findings

| # | Sev | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| TE-1 | Low | patch 0062 | A rejection that isn't an `Error` lost only a top-level `stack`; a plain object carrying one deeper, or an error-like object of another class, passed as it was. | fixed | Plain objects and arrays lose every `stack` and `stacktrace` to a bounded depth; an object with a string `stack` and a `message` is cleaned as an error. | test/containment/tab-errors.test.ts "patched: every refusal and the ordinary failure reach the tab with no host stack (AIP-4)" |
| TE-2 | Low | patch 0062 | An error whose fields throw when read made the cleaning throw inside the reply handler, so the tab's call never settled. | fixed | Anything that can't be read becomes `Error: Unsupported operation`. | test/containment/tab-errors.test.ts "patched: every refusal and the ordinary failure reach the tab with no host stack (AIP-4)" |
| TE-3 | Low | patch 0030 | 0030's answer is upstream's text, but upstream never refuses its four remote CLI commands and stays silent for a terminal the window doesn't own, so the tab's server can still tell a refusal from upstream's behaviour. | accepted-residual | Recorded in the EDR. The tab's server knows it serves a tab; what it no longer gets is a policy name. | none |
| TE-4 | Low | tests | The unit suite built 0009's error itself, so a change to 0009's message would have passed. | fixed | The message is read from the patch, which must throw one message, and judged as every refusal is. | test/containment/tab-errors.test.ts "patched: every refusal and the ordinary failure reach the tab with no host stack (AIP-4)" |
| TE-5 | Low | tests | The runtime harness judged stack shape from facts the extension writes inside the tab. | fixed | It judges from the tab's own log, read host-side: each logged stack's header, length, frames and canary. The extension's facts are reported as its claim. | none |
| TE-6 | Info | records | The EDR and liveness entry read as complete while the runtime runs were pending. | fixed | The EDR says which runs are recorded. | none |
| TE-7 | Info | patch 0062 | The REH cleans its own error replies too (its connection context is the tab's), and the IPC logger sees the cleaned reply. | accepted-residual | Recorded in the EDR; fail-safe, the server's stacks are the tab's own. | none |
| TE-8 | Info | records | One refusal message for every call is the documented policy (RPC-LOCKDOWN 8.2), not each call's own upstream failure, so the EDR's first claim was stronger than what ships. | fixed | The EDR now says what a tab can and can't learn. | none |

## Round 2
Round 2 reviewed the branch with round 1's fixes. On its code the case "patched: every refusal and the ordinary failure reach the tab with no host stack (AIP-4)" fails, with TE-9's class instance sending the host stack below it; it passes with the fix.

| # | Sev | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| TE-9 | Low | patch 0062 | Only plain objects and arrays were walked, so an instance of another class, or a plain object of another realm, crossed whole with any stack below it. | fixed | Every object is copied without `stack` or `stacktrace` (its `toJSON` result first, as JSON would take it); binary data passes as it is. | test/containment/tab-errors.test.ts "patched: every refusal and the ordinary failure reach the tab with no host stack (AIP-4)" |
| TE-10 | Info | patch 0062 | A rejection that is a string, or a message, could still carry a stack's text; none is produced on the window side. | accepted-residual | Recorded in the EDR: a message is the call's answer, judged per surface. | none |
| TE-11 | Info | records | The EDR's liveness evidence line said both modes had run while the patched run was pending. | fixed | The line names each run as it is recorded. | none |
| TE-12 | Info | tests | The runtime harness took the first matching entry in the tab's log, which the tab writes, so a planted earlier entry would have been judged. | fixed | Each entry must appear exactly once; the canary and the bundle path, which only the host knows, stay the anchor. | none |
| TE-13 | Info | tests | The depth bound had no case: a cyclic rejection, or one deeper than the bound, was untested. | fixed | A cyclic object with a chain deeper than the bound; its other fields must arrive and its reply stay bounded, and removing the bound is a mutant the suite catches. | none |

## Round 3
Round 3 reviewed the branch with round 2's fixes and found no high or critical. On its code the case "patched: every refusal and the ordinary failure reach the tab with no host stack (AIP-4)" fails, with TE-15's object losing its fields; it passes with the fix.

| # | Sev | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| TE-14 | Info | tests | The depth-bound mutant was caught only through the reply's size, which rests on how deep serialising a stack-deep result gets. | fixed | The mutant's expectation takes any of the ways the loss shows. | none |
| TE-15 | Info | patch 0062 | A `toJSON` returning its own object (URI's shape) was asked again until the depth bound, so the value was lost; JSON asks once. | fixed | `toJSON` is asked once and its result walked. | test/containment/tab-errors.test.ts "patched: every refusal and the ordinary failure reach the tab with no host stack (AIP-4)" |

## PR review on #78
Copilot's review of the pull request. On its head the case "patched: every refusal and the ordinary failure reach the tab with no host stack (AIP-4)" fails, with PR78-1's binary data and PR78-2's second toJSON sending a host stack; it passes with the fix.

| # | Sev | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| PR78-1 | Low | patch 0062 | A rejected byte view or buffer was passed as it was, so properties of its own (a stack among them) reached the serialiser. | fixed | Binary data is sent as a fresh copy of its bytes. | test/containment/tab-errors.test.ts "patched: every refusal and the ordinary failure reach the tab with no host stack (AIP-4)" |
| PR78-2 | Low | patch 0062 | A `toJSON` on the result of `toJSON` was copied, and the serialiser asked it again after the cleaning. | fixed | No function is sent (PR78-4's fix), a copied `toJSON` included. | test/containment/tab-errors.test.ts "patched: every refusal and the ordinary failure reach the tab with no host stack (AIP-4)" |
| PR78-3 | Low | tests | The runtime harness cloned the app before its manifest and exit handler were in place, so a failed copy left the clone and the armed workspace. | fixed | It clones once the teardown is in place. | none |
| PR78-4 | Low | patch 0062 | A function, as a field or as what `toJSON` returns, was sent as it was, and a `toJSON` of its own ran in the serialiser after the cleaning. | fixed | No function is sent. | test/containment/tab-errors.test.ts "patched: every refusal and the ordinary failure reach the tab with no host stack (AIP-4)" |

On the head before PR78-4's fix the case "patched: every refusal and the ordinary failure reach the tab with no host stack (AIP-4)" fails, with PR78-4's function field and function from toJSON sending a host stack.
