# Security review: patch queue and release guard

- **Date:** 2026-11-04
- **Scope:**
  - `1aa8ccb`: `build/apply-patches.sh`, `patches/series`, `build/prepare.sh`,
    `build/check-release.sh`, CI wiring;
  - the follow-up fixes (this record).
- **Threat:** a test-only hook, for example an env-gated rogue REH, ships in a release build.
- **Decision record:** [EDR patch series](../edr/20261104-patch-series.md).
- **Reviewer:** `security-review` agent.

## Round 1
| # | Sev | Area | Finding | Disposition | Fix | Regression |
|---|---|---|---|---|---|---|
| PG-1 | **Medium** | Guard scope | The series covered only `patches/`. `prepare.sh` overlays **every** `extensions/seclab-*` (with tabd dereferenced into it), so a test-only built-in or an env-gated branch in the Tab Manager or tabd would ship. The artifact regex only caught the literal `require(process.env.X)` form. | Fixed | (1) `extensions/series`: `prepare.sh` overlays exactly the listed extensions, and fails on any other `extensions/seclab-*` or a missing one. (2) `build/check-source.ts` (`./seclab lint source`, CI) scans the shipped sources (series extensions plus `tabd/src`): every `process.env` and child-process site must be in the reviewed `build/source-allowlist.txt`, where an exact line must match and stale entries fail. Dynamic loading always fails: a non-literal `require`/`import` argument (including concatenation and template literals), `createRequire`, `module.require`, `new Function`, `vm`. So do test markers. (3) `check-release.sh` stays as the artifact backstop. | `check-source` self-test: env-gated `require`, a concatenated `import()`, a template `import()` and `{env} = process` are all caught; a literal `import()` passes. Clean on the tree. |
| PG-2 | Low | Existing env hook | The Tab Manager forwarded `SECLAB_SBX`/`SECLAB_DOCKER` (runtime binary overrides) from the editor's env to tabd. | Fixed | No longer forwarded. The tabd-side override stays for developer CLI use; it needs control of the editor's environment (a host compromise) and is reviewed in `source-allowlist.txt`. | — |
| PG-3 | Low | Scan evasion | `grep -I` skipped files with a NUL byte; only JS/JSON was scanned. | Fixed | `grep -a`; also `*.sh` and everything under `bin/`. Nested archives inside the artifact (`.asar`/`.vsix`) are not extracted; our own code ships as plain files. Accepted. | real REH and app: clean |
| PG-4 | Info | Series parsing | No bypass found. | — | — | — |

Fail-closed behaviour: stderr is merged into the output, so any find or grep error makes
the check fail even though `grep -c` exit codes overlap. Paths with no JS fail too.

**No medium-or-higher findings remain.**
