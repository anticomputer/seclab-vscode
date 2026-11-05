# Test fixtures are inert and host-safe by construction

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** anticomputer ("make sure our vuln examples are not actively malicious against our host"); fork-build session
- **Related:** [ADR rogue-extension threat model](../adr/README.md), [AGENTS.md hard rules](../../AGENTS.md), security review [fixture safety](../security-reviews/20261104-m0-tabd-code.md)

## Context
The containment and canary suites deliberately run hostile payloads:
- a rogue extension;
- `tasks.json` folder-open tasks;
- `core.fsmonitor`;
- `eslint.config.js`;
- interpreter-path settings;
- an MCP stdio server.

They run against real sandboxes on the developer's Mac. If containment failed (that is
what the tests exist to detect), the same payloads would run on the host. So they must be
harmless even then.

## Decision
1. **Inert payloads.** If a payload runs on the host, it does nothing except:
   - read harness-seeded canaries;
   - write one fixed marker under the run's `.work/` directory;
   - write evidence into its own workspace.
   
   It runs no shells beyond the probe, makes no downloads, persists nothing, deletes
   nothing and changes no host settings. The sudo probe only *lists* privileges
   (`sudo -n -l`).
2. **Reads only harness-seeded canaries.** Payloads never touch real `~/.ssh`, `~/.aws`,
   the keychain, editor or browser profiles, or other repos. Demo screenshots use a
   fake canary under `/Users/Shared/seclab-demo/host-only/`.
3. **Fake credentials only.**
   - Canaries are `seclabcanary_<TAG>_<hex>` and never use real token formats.
   - Test profiles are isolated, which the harness enforces: `--user-data-dir` must
     be under `~/.seclab-test/` or the worktree's `.work/`.
   - The clipboard canary is opt-in (`SECLAB_CANARY_CLIPBOARD=1`), because seeding it
     overwrites the user's clipboard. Unless opted in, the rogue extension doesn't
     read the clipboard at all.
   - No keychain canaries exist yet. When they're added, they must be namespaced and
     removed in teardown.
4. **Network only to test targets:**
   - the run's loopback beacon;
   - RFC 5737 TEST-NET addresses;
   - reserved `*.test`/`*.invalid` names;
   - the broker and private test nets.
   
   Whether the tab is fenced off sbx's global allows (for example `api.anthropic.com`)
   is checked with `sbx policy check`, never by connecting to those hosts.
5. **Arming switch.**
   - The probe and the rogue extension act only when the workspace's
     `.seclab/targets` carries a per-run nonce (`arm=`, 32 hex) and the workspace lies
     inside that run's directory (`run=`).
   - The fixtures in the repo have no `targets` file, so they do nothing if opened or
     installed anywhere else.
   - The check lives in the workspace itself, because the run directory isn't mounted
     in the tab.
6. **Teardown check.** Both suites take a stat-only snapshot (inode, size, mtime;
   never content) of watched host paths, and fail if any changed:
   `~/.ssh`, shell rc files, `~/.gitconfig`, `~/.config/git` and `~/Library/LaunchAgents`.
7. **Enforced by a lint.** `./seclab lint fixtures` runs `test/safety/fixture-lint.ts`
   in a network-less container and in CI (ci-linux `unit` job). It flags:
   - host-secret paths;
   - non-test URL hosts;
   - persistence and settings changes;
   - broad deletes;
   - download-and-execute;
   - token-shaped literals.
   
   A line can opt out of one rule with `fixture-lint: allow <rule> -- <reason>`. The
   interface (`test/safety/fixture-lint.sh [PATH...]`) is shared with the broker and
   RPC sessions. It exits 0 when clean, 1 on violations, and 2 when an explicit PATH
   does not exist, so a typo or a tree that lacks the directory can never report
   "clean". The summary line gives the number of files scanned.

## Alternatives considered
- **Run hostile fixtures only in CI:** rejected. sbx needs local nested virtualisation,
  and the user runs these suites locally.
- **Keep real external hosts in egress probes** (`example.com`, `api.anthropic.com`):
  rejected by rule 4. An escaped probe would really contact them. The trade-off is
  that the empirical "global allow is blocked" check becomes a policy check.
- **Arm via an environment variable:** not possible, because tab environments are
  scrubbed. A nonce file in the workspace plus a location check works in both the
  host and the tab.

## Consequences
- The egress evidence keys changed: `testnet_*` and `reserved_name_*` replace
  `example_*` and `global_allow_*`.
- A copied prepared workspace stays inert outside its run directory.

## Evidence
- `./seclab lint fixtures` reports clean on the tree.
- A planted file with `cat ~/.ssh/id_rsa`, `curl … | sh`, a `ghp_`-shaped literal and
  `launchctl` gives 5 violations.
- `./seclab test containment oci`: 92/92, including the host-snapshot check.

## Addendum (2026-11-04): no AV-signature content on the host
Microsoft Defender for Endpoint on the developer Mac quarantined a faithful, inert
Contagious-Interview `tasks.json` twice (`Trojan:Script/MalTask.A`), within a second of
it being written. Because the build is enterprise Defender, each detection can alert the
user's security team. It was never committed or pushed, on any branch.

Rule (user decision: "Defang on disk"):
- **No file on the host may match an endpoint-protection signature for a live-malware
  pattern.** Signature-bearing content is stored as parts, for example
  `test/containment/fixtures/contagious-interview/.seclab/loader.parts.json`. The harness
  assembles it in memory and runs it inside the tab. A file such as a real `tasks.json`
  is only ever written inside a tab's VM-private storage; with the write-back overlay,
  that is the upper layer, which never reaches the host.
- **The lint enforces it.** `download-exec` (fetch piped into an interpreter) can no
  longer be opted out, and the new file-level `av-loader` rule refuses a folder-open
  task and a fetch tool in the same file. Both are covered by
  `test/safety/fixture-lint.sh --self-test`.
- **If a detection happens anyway:** stop, check `mdatp threat list`, tell the user so
  they can inform their security team, and never retry variants of the content to find
  what triggers the signature.

## Addendum (2026-11-05): the loader shape across files, and host copies
The user reported further Defender `tasks.json` detections on their corporate endpoint. The
file-level rule missed a split shape: the observability fixture's hidden folder-open
`tasks.json` ran `sh .seclab/loader.sh`, and the script held the loader traits (detach,
fetch, inline `node -e` eval, browser and wallet paths). The harness also left host copies
of fixture workspaces under every worktree's `.work/` after runs.

Rule (coordinator decision, user-reported):
- **`av-loader` is workspace-level** (`test/safety/av-shape.ts`). A folder-open or hidden
  task fails if the task file, or any script its command or args name in the same
  workspace, carries a fetch tool, inline `node -e`/eval, `nohup`/detach, or
  browser/wallet/keychain data paths.
- **`av-fetch-eval` applies to any host file.** A fetch command together with inline
  node/eval or a pipe into an interpreter fails, whether in the walked roots or in the
  `--av` pass over every tracked file. Test strings with that shape are assembled at run
  time.
- **Exempt:** only encoded `*.parts.json`. `malicious-workspace/.seclab/probe.sh` now reads
  its HTTP client's name from `probe.parts.json`, so its folder-open task no longer sits
  next to a literal fetch tool.
- **Harness:** fixtures reach the host only through `materialiseFixture` (teardown.ts).
  It refuses a source with an AV shape and records the copy in `run.json` before
  copying. Teardown deletes it, and checks that it is gone.
- **`./seclab clean-host`** lists stale fixture copies (roots with our `.seclab/` dir)
  in every worktree's `.work/` and removes them with `--apply`. Trees that aren't ours
  but have an AV shape, such as upstream source checkouts, are reported and never
  deleted.
- **Detections:** stop, run `mdatp threat list`, tell the coordinator, and never probe the
  signature (AGENTS.md hard rule).
