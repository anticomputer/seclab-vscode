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

## Round 2 (`cf6738e..c0b4436`)
- FS-1 fixed, FS-2 fixed, FS-3 fixed, FS-4 fixed, FS-6 fixed.
- FS-5 partly fixed; accepted as a tripwire. Variable hosts and `net.connect`/`getent` aren't linted; code review covers them.
- The low residuals the reviewer listed are all fixed in the follow-up commit:
  - off-tab, the rogue extension no longer even calls `getSession`;
  - `inrun` rejects `..` components;
  - the snapshot drops the two paths that change in normal use (`~/.docker/config.json`, `~/.seclab-vscode`) and reports when a depth or size cap is hit.

**No medium-or-higher findings remain.**

## Round SS (2026-11-05): focus rule, supply-chain exceptions, AV-signature fixture safety
Scope: `feb5331` (background editor launch, `focus-steal` lint), `0c89f88` (recorded
exceptions, `./seclab deps host`), `388ec4d` (workspace-level AV-shape lint,
`materialiseFixture`, clean-host fixture sweep). No prompt injection was found in the diff,
the fixtures or the evidence.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| SS-1 | **Medium** | clean-host | The sweep treated any directory with `.seclab/` under `.work/` as a stale copy, so `--apply` would delete tracked fixtures inside a checkout nested in `.work/` (e.g. `.work/main-wt`). | Fixed | `materialiseFixture` marks copies (`.seclab-materialised`). clean-host deletes only marked roots, roots a `run.json` lists under `workspaces`, or exact legacy harness paths. It never descends into a directory with a `.git` entry, never treats depth 0-1 as a root, and counts kept sandboxes' mounts as in use. Anything else is reported, not deleted. |
| SS-2 | **Medium** | AV lint | Split-file detection resolved script references and missed `options.cwd`, extensionless or renamed stages, `npm run`, `node .`, `${workspaceRoot}`, JSON escapes and `*.code-workspace` tasks. JS fetch/eval forms were not traits. | Fixed | No reference resolution. If a workspace has a folder-open or hidden task (`tasks.json` or `*.code-workspace`), any file in it with loader traits fails. Every `fixtures/` tree is walked whole. JS traits added (fetch of an http URL, axios, http(s) request calls, the Function constructor, vm.runIn*). Self-tests cover the reported forms. |
| SS-3 | Low | deps host | gh downloaded and attested its own release archive. | Fixed | The archive and the release checksums file are fetched with `curl`. The archive must match the checksums, and the byte comparison uses `shasum`. EDR states what is still not covered. |
| SS-4 | Low | deps host | `codesign --verify` without a requirement plus a text match on the team ID. | Fixed | `-R='anchor apple generic and certificate leaf[subject.OU] = "9BNSXJN65R"'`; a wrong team ID fails (checked). |
| SS-5 | Low | deps.ts | Any non-empty approval and any EDR satisfied an exception. | Fixed | The EDR must quote the approval verbatim and list the entry id; self-test. |
| SS-6 | Low | harness | `editorPid` matched `/x/run1` against `/x/run10`. | Fixed | The path must end the option value. |
| SS-7 | Low | lint | `focus-steal` missed combined flags, a bare `.app`, and `-g` after `--args`. | Fixed | Leading flags tokenised; JS array form requires `-g` before `--args`; self-tests. |
| SS-8 | Low | harness | The AV check skipped symlinks, big files and anything past 4,000 files, and the copy didn't. | Fixed | The copy filter matches the check (no symlinks, `node_modules`, `.git`, or files ≥2 MiB), and the walk refuses past its cap. |

## Round UU (2026-11-05): patch 0012 background windows; TT fixes confirmed
Scope: `922c34f` (patch 0012, harness, EDR [background windows](../edr/20261105-background-windows.md)),
plus the round-TT fixes. Requirements 2 (host launch env only, read once, not a setting) and 3
(only the harness sets it) hold; without the flag the patch is a no-op. TT-1..6 confirmed closed.
No prompt injection found.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| UU-1 | Low | patch 0012 | Raise paths that bypass `BaseWindow`: `openChildWindow` (GPU info, tracing, devtools windows) show/restore/focus, and always-on-top. | Fixed | `showInactive()` and skipped restore/focus there; always-on-top is a no-op under the flag. |
| UU-2 | Low | harness | Focus was checked once at launch. | Fixed | A watcher polls the frontmost app every second while the editor lives; steals are logged in the profile; `shot` refuses and teardown fails the run. |
| UU-3 | Low | check-source | Core patches weren't scanned for shipped env/spawn sites. | Fixed | The lines each patch in `patches/series` adds are scanned; 0012's env read is allowlisted. |
| UU-4 | Low | tabd scan | The scanner was checked by name once; a later retag or a doctored `bash`/`find` in a same-binary image would pass. | Fixed / accepted | The name is resolved to an image id once, the binary checked in that id, and every scan runs by id (a retag changes nothing). Accepted: the local Docker daemon is trusted; a process that can build images there can also doctor any of them. |
| UU-5 | Low | npm | A lockfile without a `packages` map (v1) passed the registry-only check. | Fixed | Refused. |
| UU-6 | Low | sbx collector | The clipboard bridge could come back after the start-time stop. | Fixed | The watchdog stops any that reappear and reports it. |
