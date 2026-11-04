# Security review: test fixtures are host-safe

- **Date:** 2026-11-04
- **Scope:**
  - `d02dec5..cf6738e`;
  - all of `test/containment/fixtures/`, `test/containment/rogue-extension/`,
    `test/canary/`, `test/secrets/`, `test/harness.ts` and `test/safety/`.
- **Threat:** our own hostile payloads harming the developer's Mac if containment fails.
- **Rules:** [EDR fixture safety](../edr/20261104-fixture-safety.md) and the AGENTS.md hard rule.
- **Reviewer:** `security-review` agent.

## Round 1
| # | Sev | Area | Finding | Disposition | Fix | Regression |
|---|---|---|---|---|---|---|
| FS-1 | **Medium** | Real data | If it ran on the host, the rogue extension would write the developer's real env **values** (tokens) to `rogue-observed.json`, along with the full `getSession()` results (`accessToken`) and the settings. | Fixed | Values are recorded only when `remoteName === 'seclab' && SECLAB_TAB === '1'`. On the host it records env **names** only and `ranOnHost: true`. Raw tokens are never recorded, in or out of a tab: only `present`, `tokenLength` and `carriesCanary`. Settings, clipboard and secret storage are read only in a tab. | containment suites (rogue extension still reports `inTab`) |
| FS-2 | Low | Arming | The probe's arming was loose: an empty `run=` armed it anywhere, the nonce was checked only by its prefix, and target paths weren't confined. | Fixed | The nonce must be exactly 32 hex. `run=` must be an absolute dir containing the workspace. `canary`, `othertab` and `marker` must lie under `run`. `loopback` must be numeric. | suites pass with the strict arming |
| FS-3 | Low | Arming | A prepared Level B workspace stays armed indefinitely, and host git would run its fsmonitor probe. | Fixed (bounded) | `until=<epoch>` in `targets` (Level A: 1 h; Level B: 4 h, set by `SECLAB_ARM_SECONDS`). The probe and the rogue extension refuse to run after it expires. | — |
| FS-4 | Low | Lint | Private LAN ranges were accepted, and IPs were matched by prefix (`127.evil.com`). | Fixed | Literal IPs are checked with `net.isIP`. Only loopback, RFC 5737 and the broker test net `11.250/16` are allowed; general LAN ranges are not. | lint self-test |
| FS-5 | Low | Lint | The regex lint is easy to evade. | Partly fixed; accepted | Now catches `homedir()` used with secret directory names, `<(curl`, `sh -c "$(curl"`, and scheme-less hosts given to curl/wget. Fixture trees are linted whole, whatever the file names. Opt-outs count only if listed in the reviewed `test/safety/allowlist.txt`. It stays a tripwire: code review is the real control. | lint self-test (6 planted cases) |
| FS-6 | Low | Snapshot | The snapshot only covered directory stats, missed several paths, and Level B's window is long. | Fixed | The stat-only snapshot now recurses into watched directories (entry names hashed, never stored), and adds `~/.aws`, `~/.npmrc`, `~/.docker/config.json`, `~/.netrc`, `~/.git-credentials` and `~/.seclab-vscode`. | containment suites pass the snapshot check |

Result: one medium finding (FS-1), fixed. Re-review: see round 2.
