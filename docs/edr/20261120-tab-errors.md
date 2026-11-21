# An error that crosses to a tab carries no host stack, and a refusal answers in upstream's form

- **Date:** 2026-11-20
- **Status:** accepted. Runtime proof: see below.
- **Owner:** the RPC follow-ups session (register owner `rpc`).
- **Related:** [review record](../security-reviews/20261120-tab-errors.md), the AI-feature probes
  review that found it (AIP-4), [RPC lockdown](../RPC-LOCKDOWN.md) section 8.2 (hard denial reads
  as an unsupported operation).

## Context
The RPC filter answers a call it refuses with `new Error('Unsupported operation')`, made host side.
Upstream serialises an error reply with its stack (`transformErrorForSerialization`), and the
tab's extension host keeps that stack on the error it rejects with, so an extension that logs it
wrote the window's stack into the tab's log: the app's install path, which is under the host
user's home for a fetched build, and the `_deny`/`checkRpc` frames, which tell a policy refusal
from an ordinary failure (review AIP-4, a medium, found by the AI-feature probes in a run's logs).
The refusal also took its own route: it answered at once with no acknowledgement, where upstream
acknowledges every request before it answers, so the message sequence alone marked a refusal.

The same holds for every error the window sends a tab, not only refusals: an allowed handler that
fails sends its host stack too, and the channel guard's refusals, and every channel failure, go to
the tab's server the same way over IPC. Two refusals answer a tab themselves, with text of their
own: patch 0030 told the tab's server `seclab: denied`, and the agent-host gate (0015) answered
the tab's agent host `Refused by the seclab agent-host gate`.

## Decision
Patch 0062, and the refusal text of 0030 and 0015:
- `seclabErrorForTab` (`base/common/errors.ts`) makes the error a tab may get: name, message, code
  and cause kept, the stack only its header line (`Error: Unsupported operation`), the cause
  cleaned the same way. Another object loses any `stack`. The original is untouched, so the
  window's own logs and the decision log keep the detail.
- The RPC protocol of a filtered extension host (every host that isn't the trusted local kind)
  sends every error reply through it, and a refusal takes upstream's path for a handler that
  throws: acknowledged, then answered, after the same microtask an ordinary failure takes.
- The IPC channel server sends every error reply through it when its context is a tab's
  (`seclab+`, 0006's test), so the channel guard's refusals and every channel failure the tab's
  server sees carry no host stack.
- 0030 answers a refused remote CLI command with upstream's own answer to a command it doesn't
  run, `Invalid remote cli command: <id>`; the agent-host gate answers a refused reverse request
  with upstream's own answer to a method it has no handler for, code `-32000` and
  `Unknown method: <method>`. Both echo only what the tab sent.

Every refusal a tab can receive is now `Error: Unsupported operation` with a one-line stack,
acknowledged like any failure, or upstream's own text for that request. It is still a failure of a
call upstream would serve, so the tab knows the call failed, and a tab that knows upstream's
answer for a call (`command 'x' not found` for a command it knows exists, say) can still tell that
some layer refused it: the policy keeps one refusal message (RPC-LOCKDOWN 8.2) rather than
mimicking each call's failure. What it no longer learns is the host: no path, user name or frame,
and no filter internals. The same holds for 0030: its text is upstream's, but upstream never
refuses its four remote CLI commands and stays silent for a terminal the window doesn't own,
where 0030 answers every push (review TE-3). The tab's server knows it is a tab's server either
way.

Anything `seclabErrorForTab` can't read (a throwing getter, say) becomes `Error: Unsupported
operation`, so the tab always gets an answer (TE-2). An error-like object (a string `stack` and a
`message`, from another realm, say) is cleaned as an error. Any other object, its `toJSON` result
first as JSON would take it, is copied without a `stack` or `stacktrace` at any level, to a depth
of eight (TE-1, TE-9); binary data passes as it is.

Not tab-facing, checked: patch 0009's throws reach a tab only as RPC replies (cleaned); 0031
answers with the text unresolved (no error); 0050's refusal is a launch message shown in the window;
0059's location refusals and the host extensions channel's refusal go to window code; a tab's
data command refused on the trusted side (`refuseDataCommand`) answers the trusted UI. The one
window-to-tab request carrying a serialised error, `$acceptResponseDone`, follows a language-model
request the policy denies to a tab.

## Proof
- **Unit:** `test/containment/tab-errors.test.ts` (`./seclab test tab-errors`, in
  `./seclab test rpc-filter`) runs upstream's real `RPCProtocol`, `ChannelServer` and
  `ChannelClient`, with every series patch applied, loaded from a virtual install path holding a
  canary user name. For the filter's refusal, the command taint's, the fail-closed route's, 0009's
  throw (its message read from the patch), the unguarded channel refusal, the channel guard's and
  an ordinary failure on each protocol, it checks the window's raw bytes and the error the tab
  builds: no canary, install path, frame or filter name; a one-line stack; acknowledged; the
  ordinary failure's message, code and cause still sent (the control). Five rejections that aren't
  plain errors (a plain object with stacks at depth, an error of another realm, an error whose
  message throws, an instance of another class with a stack below it, a cyclic object with a chain
  deeper than the bound) must each be answered with no host detail, their other fields kept and
  the reply bounded. It also pins 0030's and
  the gate's answers to upstream's text in the pinned source. On main (`d34da65f`) the case
  "patched: every refusal and the ordinary failure reach the tab with no host stack (AIP-4)"
  fails: every call sends its frames, the refusal names the canary path and `_deny`, and the
  unreadable error gets no reply. Every mutant of 0062 is caught.
- **Runtime:** `test/containment/error-probe.ts` in a real OCI tab of the containment build. The
  run clones the app (APFS clone) into a directory named for a canary under
  `.work/test-builds/`, and a tab extension makes a call the filter refuses (`getCommands`), a
  command it refuses, and an ordinary failing call (opening a missing file of its own workspace,
  the control), logging each stack it receives to its own log. The harness reads the tab's logs
  in memory and judges from them, not from the extension's facts (review TE-5): each logged stack's
  header and length, its frames, and the canary and the app's bundle path anywhere in the logs.
  - Baseline: main `d34da65f`, containment build run 44841250059: 10/10. Both refusals reached
    the tab as `Error: Unsupported operation` with 32 and 33 stack lines of host frames naming the
    canary install path; the control's stack carried them too; the canary and the bundle path are
    in the tab's log.
  - Patched: branch `9f274e32`, containment build run 44847427182: 13/13. Both refusals and the
    control reached the tab with a one-line stack (`Error: Unsupported operation` for the
    refusals, the control's own message naming its file), and neither the canary nor the bundle
    path is anywhere in the tab's logs. The decision log holds the refusal (control). Both runs,
    with the harness as committed here, tore down clean.
- **`fixture:test/containment/error-probe`:** run by `test/containment/error-probe.ts` in both
  modes on 2026-11-20 (runs 44841250059 and 44847427182, above).

## Consequences
- Diagnosing a failure a tab sees needs the window's logs: the tab gets the message only. The
  decision log already holds every refusal.
- Errors a tab's server sends the window over IPC are cleaned on the server too (the server's
  connection context is the tab's authority); the window's view of a server failure keeps its
  message and loses the server's stack. The IPC logger, when tracing is on, sees the cleaned reply
  (review TE-7).
- A message can still carry host detail if upstream puts it there (a host file path in an
  allowed call's failure, say), and so can a rejection that is a string rather than an error
  (review TE-10; none found on the window side). That is the call's answer, not its stack, and is
  judged per surface by the policy.
