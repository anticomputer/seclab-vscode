# Security review: Level B repair and the portable data dir

- **Date:** 2026-11-09
- **Scope:** round NNN, `9fbd37f` and `a911c9c`, and their fixes:
  - `probe.sh`: one marker per vector; `assert.ts`: the host-write row on `<marker>.<vector>`;
  - `check-evidence.ts`: evidence read through the tab, the `[rpc]` rows, the canary scan,
    fsmonitor armed in the tab;
  - `test/harness.ts` (`editorLaunchArgv`, `editorPortableDir`, `preparePortable`, the launch
    record), `test/containment/teardown.ts` (`removePortable`), `test/clean-host.ts`;
  - `build/liveness/liveness.ts` (dated records, the 30-day rule), `register.json`.
- **Threat model:** Level B is the proof that containment holds against the real editor. Its
  evidence is written and read by the hostile side, so every row must be anchored host-side or
  fail closed. A probe's host write must be credited to that probe alone, and arming a hostile
  `.git` inside a tab must not put it on the host.
- **Records:** [EDR liveness-gate](../edr/20261109-liveness-gate.md),
  [EDR fixture-safety](../edr/20261104-fixture-safety.md),
  [ADR write-back gate](../adr/20261104-write-back-gate.md), [RPC lockdown](../RPC-LOCKDOWN.md),
  [round MMM](20261109-liveness-refresh.md).
- **Prompt injection:** none found.

## Round NNN
Three mediums, three lows, three residuals. Confirmed:
- `$MARKER.$VECTOR` is appended after `inrun`, and `VECTOR` is `[a-z0-9-]`;
- attribution is disjoint: `probe.sh` writes `<marker>.<vector>`, the RPC probes `PWNED*`, the
  campaign `<work>/PWNED`; Level A still detects its own host writes;
- the tab can't reach the host process table or `product.json`, and an unreadable
  `product.json` fails closed;
- fsmonitor arming is a static string; `.git/**` is held and outside `gitAuto`; OCI is
  excluded;
- `removePortable` is symlink-safe (`checkIsolatedProfile`, and `rmSync` unlinks the link);
  `clean-host`'s deletion is anchored, home-only, in-use-guarded and dry-run by default;
- portable mode moves `argv.json` and extensions from a persistent home folder to a per-run
  dir;
- no file describes this machine's local permission state.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| NNN-1 | Medium | canary scan | A failed read in the tab (oversized, unreadable, odd name) became an empty buffer with no row, so the tab could hide a canary. | Fixed | A listed file that can't be read is its own failing row; `maxBuffer` is 64 MiB; odd names fail rather than being dropped. |
| NNN-2 | Medium | `[rpc]` rows | The rows were hand-maintained and missed `host-fs-write-userdata` (`userDataDir:/User/seclab-probe-marker.txt`); nothing caught stray markers. | Fixed | Rows are derived from `rpc-filter/probes/expectations.json` (`hostEffect`, `hostEffectAbsolute`), plus the negative control, and any unattributed `PWNED*` or `probe-marker*` in the run dir fails. All are checked before teardown. |
| NNN-3 | Medium | write-back gate | "Always allow" could be offered for `.git/**`; check mode had no exit disarm. | Partly already enforced; fixed | `writeback.ts:509` already refuses "Always allow" for any `.git` path (`isGitPath`) and for `.husky`/`.githooks`/lefthook (`isHookish`). Check mode now disarms a host `.git` on exit and on signals. |
| NNN-4 | Low | build detection | The editor's app was taken from the process table, and only the stamp's presence was checked. | Fixed | The launcher records `{ app, pid }` in the profile; the check requires the pid to match, and a present stamp must equal the repo's policy-table digest, otherwise the build is unknown (a failing row). |
| NNN-5 | Low | tab-authored evidence | Level B didn't pass `expectHostname`. | Fixed | It passes the tab's hostname, as Level A does. |
| NNN-6 | Low | liveness record age | A shape-valid but impossible or future date switched off the 30-day rule. | Fixed | The date must parse to itself and not be in the future; three self-test cases. |
| — | Residual | OCI coverage | fsmonitor isn't armed on OCI. | Fixed | On OCI it is an explicit known-gap row naming the write-back-gate ADR. |
| — | Residual | evidence provenance | The vector rows are written and read by the untrusted side. | Accepted | Host-side anchors remain: the host canary, the RPC host effects, the teardown gate and the `~` snapshot. |
| — | Residual | portable dir | A teardown that fails to remove `<profile>-portable` leaves a dangling link, and the next launch fails with `EEXIST`. | Accepted | Fails closed; teardown reports the removal failure. |
