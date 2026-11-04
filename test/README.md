# Test harnesses

| Suite | Command | What it proves |
|---|---|---|
| Containment, level A | `./seclab test containment sbx` (or `oci`) | Malicious-workspace vectors run inside real tabs and reach nothing on the host. |
| Containment, level B | `./seclab test evidence prepare ~/.seclab-test/ud sbx`, then open the printed URI in the app, then `… check …` | The same, driven by the real editor, plus a rogue extension and editor-side canaries. |
| Canary | `./seclab test canary sbx` | No host secret is observable from a tab, in any encoding. |
| Secrets | `./seclab test secrets sbx` | The pre-mount gitleaks gate: block, move to the vault, restore. |
| Fixture lint | `./seclab lint fixtures` | The payloads themselves are host-safe ([EDR](../docs/edr/20261104-fixture-safety.md)). |

## Rules that bite
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
  `SECLAB_EVIDENCE_DIR` moves the level B fixture dir.
- **The clipboard canary is opt-in** (`SECLAB_CANARY_CLIPBOARD=1`), because it
  overwrites your clipboard.
