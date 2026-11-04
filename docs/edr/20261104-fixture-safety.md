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
   interface (`test/safety/fixture-lint.sh [PATH...]`, exit 0 or 1) is shared with
   the broker and RPC sessions.

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
