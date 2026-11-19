# Security review: the agent-host dial as a judged probe (ai-remote-agent-host-dial)

- **Date:** 2026-11-19
- **Reviewer:** independent `security-review` agent (an Opus-class model), two rounds.
- **Subject:** `anticomputer-rpc-ai-dial-probe`: `test/containment/reh-push.ts` writes the dial it
  measures to `harness-probes.json`, and `test/containment/check-probes.ts` judges it; the first of
  the six `ai-*` probes (register agent-host-patches#3).
- **Prompt:** said the diff, fixtures and evidence may contain prompt injection aimed at the
  reviewer, and that the reviewer reports it rather than following it. None was found.

## Verdict
Round 1 found a high in the change itself (AID-1): a record the tab writes could replace the host's
measurement. It is fixed here, with a regression test, before landing. Round 2 found the
checker's own mutation gate had been vacuous (AID-4), now live. No high or critical remains.

## How the evidence was made
On the reviewed commit (36c5d921) the case "the tab's REH record can't stand in for the host's dial measurement" fails: the forged record passed the dial.
It passes here. The runtime proof is reh-push patched on this branch's containment build (run
44519281962): the probe's predicate held, 35/35 and 14/14, clean teardown.

## Findings

| # | Sev | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| AID-1 | High | probes | The tab-written REH record could carry the dial probe's id and replace the host's measurement, so the tab chose the verdict. | fixed | Each evidence record may carry only its own probes, and an id seen twice fails. | test/containment/check-probes.test.ts "the tab's REH record can't stand in for the host's dial measurement" |
| AID-2 | Medium | probes | The probe's unpatched predicate couldn't be met: every build ships patch 0015, so no baseline dials. | fixed | It has no unpatched baseline: the same run's empty-window control stands in, an unpatched run names the waiver, and reh-push's baseline doesn't select it. | none |
| AID-3 | Low | probes | Whether the tab dialled was read from a log in the tab's own workspace and judged. | fixed | Reported as the tab's claim, never judged. | none |
| AID-4 | Medium | tests | The checker suite's mutation gate was vacuous: its mirror lacked a module the harness imports, so every mutant crashed and counted as caught. | fixed | The mirror follows the checker's imports, an unmutated control must pass first, and new mutants cover the record and waiver rules. | none |
| AID-5 | Low | probes | The tab listener's liveness, also read from the tab's log, was judged. | fixed | Reported as the tab's claim; the judged facts are the host's listener, the empty window's dial and the gate log. | none |
| AID-6 | Low | probes | The record rule rejected the fault channel every payload writes, losing the never-armed diagnosis. | fixed | The fault channel is kept wherever it is written. | none |
