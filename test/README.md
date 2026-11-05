# Test harnesses

| Suite | Command | What it proves |
|---|---|---|
| Containment, level A | `./seclab test containment sbx` (or `oci`) | Malicious-workspace vectors run inside real tabs and reach nothing on the host. Includes the Contagious-Interview loader (`campaign.ts`, own tab): every TTP mapped in the [threat-model ADR](../docs/adr/20261104-threat-model-rogue-extension.md). |
| Containment, level B | `./seclab test evidence prepare ~/.seclab-test/ud sbx`, then the printed `node test/window.ts launch …`, then `… check …` | The same, driven by the real editor, plus a rogue extension and editor-side canaries. |
| Canary | `./seclab test canary sbx` | No host secret is observable from a tab, in any encoding. |
| Secrets | `./seclab test secrets sbx` | The pre-mount gitleaks gate: block, move to the vault, restore. |
| Fixture lint | `./seclab lint fixtures` | The payloads themselves are host-safe ([EDR](../docs/edr/20261104-fixture-safety.md)). |
| Teardown regression | `node test/containment/teardown.test.ts` | Teardown stops a run's editor process tree (orphans included) and its tab pods, and reports clean only after they're gone. |
| Host sweep | `./seclab clean-host` (dry run), `--apply` | Lists or removes every seclab-vscode resource on this machine ([EDR](../docs/edr/20261104-harness-teardown.md)). |

## Rules that bite
- **Editor windows never take focus** (AGENTS.md hard rule). `test/window.ts launch`
  opens the editor in the background (`open -g -n`) and fails if it became frontmost;
  `test/window.ts shot` captures the covered window by id (`screencapture -o -l`).
  The `focus-steal` fixture-lint rule rejects activate calls, a foreground `open` and
  direct `bin/code` launches in test code.
- **Every run tears itself down, and fails if it can't** ([EDR](../docs/edr/20261104-harness-teardown.md)).
  A run records what it owns in `<run-dir>/run.json` before it starts anything:
  its user-data-dir, tabd state dirs, tab ids and helper containers.
  `teardown.ts` then:
  - stops those process trees, matching the unique paths and never program
    names;
  - removes the tabs and helpers;
  - deletes the profile;
  - diffs the host snapshot.
  
  A survivor or leftover fails the run. Level B's `check` ends with that
  teardown, so it closes the editor. `KEEP=1` skips it and prints the
  `teardown.ts verify <run-dir>` command to run later.
- **Hostile fixtures are armed per run.** A nonce, the run dir and an expiry are
  written to `.seclab/targets` in the workspace. Copied or opened anywhere else,
  they do nothing.
- **No environment variables reach a tab** (`env -i`). Arming, targets and opt-ins
  go through `.seclab/targets`, never env.
- **`--user-data-dir` must be short and isolated.** macOS caps unix socket paths at
  104 bytes, and Electron puts its main IPC socket in the user-data dir, so a deep
  path (such as a worktree's `.work/`) makes the editor exit with no window. Use
  `~/.seclab-test/<name>`. `harness.ts` refuses anything else.
- **Concurrency.** Each run picks a free beacon port (`SECLAB_BEACON_PORT` pins
  it). Docker names carry a per-worktree id, and runs take a lock under `.work/`.
  `SECLAB_EVIDENCE_DIR` moves the level B fixture dir; it must stay under this
  worktree's `.work/` or `~/.seclab-test/`, because teardown refuses to act
  anywhere else.
- **The clipboard canary is opt-in** (`SECLAB_CANARY_CLIPBOARD=1`), because it
  overwrites your clipboard.
