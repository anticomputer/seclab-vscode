# Security review: the liveness gate (round KKK)

- **Date:** 2026-11-09
- **Scope:** round KKK, `eab5cb8` (rebased as `991e818`) and its fixes:
  - `build/liveness/liveness.ts`: lexer, import resolution, liveness propagation, entries,
    the in-tab program check, exemptions, discovery, workflow parsing, the evidence checks,
    `verify-runs`, `marks`, the self-test;
  - `build/liveness/register.json`;
  - `test/liveness.ts` and its three call sites;
  - the `./seclab liveness` subcommand;
  - `workflow-lint.yml` (`actions: read`, three steps), and the `ci-linux.yml` oci job's
    `GITHUB_ENV` write and final marks step;
  - the AGENTS.md rule; the `assertPort` deletion.
- **Threat model:** a CI gate, not a runtime boundary. The question is whether it can be
  satisfied falsely, which is the failure it exists to prevent. It adds a workflow permission
  and a token-holding networked container on a workflow that runs on `pull_request`. The mark
  log is host state in a job that runs hostile fixtures in tabs. Register content, workflow
  text and sources are attacker-shaped input to the analyser.
- **Records:** [EDR liveness-gate](../edr/20261109-liveness-gate.md),
  [round JJJ](20261109-deps-updates-mounts.md).
- **Prompt injection:** none found. The gate feeds no model; register strings reach only
  error text and string or regex comparisons.

## Round KKK
Two mediums, five lows, one info. Confirmed:
- every register-named read is gated by the tracked-file set; `record` is limited to
  `docs/**.md`; tracked symlinks resolve only to tracked targets;
- `--self-test`, `check` and `marks` run `--network none` with read-only mounts; `marks`
  mounts the log only if it exists, and a missing log fails closed;
- bash 3.2: `${local_log[@]+"${local_log[@]}"}` is safe under `set -u`;
- the `GITHUB_ENV` write is a constant plus `$RUNNER_TEMP`, in a push/pull_request workflow;
- a tab can't reach `$RUNNER_TEMP/liveness.log`, and `SECLAB_LIVENESS_LOG` is not in the
  tab environment;
- the three `liveMark` calls mark on evidence, not on start;
- run ids are scoped to `GITHUB_REPOSITORY`; a foreign run 404s.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| KKK-1 | Medium | ci evidence | Checked as workflow text only. A job `if: false`, a step `continue-on-error` or `|| true`, or a dispatch-only job passed. | Fixed | The job must run on push or pull_request, with no `if:` or `continue-on-error:`. Its last step must be exactly `./seclab liveness marks <job> "$SECLAB_LIVENESS_LOG"` with neither key. Four self-test injections. |
| KKK-2 | Medium | marks | The static check matched `liveMark('<mark>'` in any test file, strings included. The runtime log accepts any appended line. | Fixed (static), accepted (runtime) | Evidence names its `runner`. The call must be in that file, in code: found in the string-blanked lexer output, argument read at the same offset. Two injections. The append-anywhere log is the accepted residual below. |
| KKK-3 | Low | entry | `entry` was a quiet, broad hatch: `declaredIn` was any file naming the stem, `calledBy` unchecked, no note. | Fixed | Only `activate`/`deactivate` of an extension, in the module its own `package.json` `main` names. Probed over code, printed on every run, documented in AGENTS.md. One injection. |
| KKK-4 | Low | verify-runs | A token-holding networked container mounted the whole repo, diverging from EE-2/DD-4. | Fixed | `./seclab liveness verify-runs` mounts only `liveness.ts` and `register.json` (`lint mounts` keeps the list exact). The whole-repo check stays offline and has no token. |
| KKK-5 | Low | run, record | Head sha and branch were unchecked; `record` was a substring match; runs deleted at retention would fail every PR. | Fixed | Evidence pins `sha` and `date`, checked against the run. `record` needs a `- **\`<id>\`:** …` line. A 404 older than 85 days is a printed note. Seven fake-API cases and one injection. |
| KKK-6 | Low | uses | A bare word let `.name`, `{ name: …}` and same-named locals vouch for an export. | Fixed | Member access, object/destructuring keys and keyword arguments don't count, except `alias.name` through a module alias for the declaring file. Control cases (Python `mod.fn`, TS `ns.fn`) and an injection. |
| KKK-7 | Low | discovery | A push or pull_request filtered off main exempted a workflow; fixture discovery relies on naming. | Fixed | A trigger whose `branches` can't match main doesn't count; one injection. The fixtures-dir and `package.json` conventions are an AGENTS.md rule. |
| KKK-8 | Info | regexes | Lazy spans over repo files; unescaped interpolations. | Fixed | Interpolations escaped (`escapeRe`); the ci step is compared as a string. Backtracking cost on repo text is self-inflicted only. |
| — | Residual | mark log | `$RUNNER_TEMP/liveness.log` has no integrity. Host-side code in the job, including an escape the suite exists to detect, could forge every mark. | Accepted | Tabs can't reach it. Out of reach while marks are host-side text. |
