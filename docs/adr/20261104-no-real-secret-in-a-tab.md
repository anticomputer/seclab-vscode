# No real secret ever enters a tab

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** Project owner (2026-11-04): a core design requirement is that a sandboxed environment never obtains a real secret; seclab-vscode coordinator
- **Related:** [threat model ADR](20261104-threat-model-rogue-extension.md), [single broker ADR](20261104-single-broker-sbx-fence.md), [RPC filter ADR](20261104-rpc-capability-filter.md)
- **Editorial redaction (2026-11-12):** quotations of project conversations replaced with neutral statements; decisions unchanged.

## Context
A rogue extension controls its tab's extension host and REH server ([threat
model](20261104-threat-model-rogue-extension.md)). Anything that reaches the
tab must be assumed exfiltrated, either through an allowed egress path or
through a later compromise.

## Decision
**No real secret ever enters a tab**, in any form: raw, encoded, derived or
newly minted.

- A **real secret** is any credential that works outside our broker. That
  includes:
  - PATs, OAuth access and refresh tokens, cloud keys, SSH keys and LLM keys;
  - session cookies and keychain items;
  - anything derived from them;
  - credentials minted on demand, such as short-lived GitHub App tokens. If
    such a token is usable without our broker, it is real.
- A **tab-scoped capability** is a value that is worthless outside that tab
  and is rotated with it. These **are allowed** inside a tab:
  - broker **sentinels** (placeholders the broker swaps on matching egress);
  - **per-tab proxy auth** to that tab's broker;
  - the **REH connection token**.

### Enforcement points
| Point | What is enforced | Owner |
|---|---|---|
| Tab environment | REH and all children start from `env -i` plus a fixed allowlist (`seclab-tab-env`). The runtime's injected proxy variables are overridden. | fork-build (sandbox scripts) |
| Supervisor and runtime CLIs | tabd wipes its own env. `sbx`/`docker` get an allowlisted env, never the bare `-e KEY` form, and secrets only via stdin. | fork-build (tabd) |
| sbx stored secrets | tabd refuses to create or connect a tab if any sbx service or custom secret could apply to it, or if sbx reports secret-like env vars. | fork-build (tabd sbx driver) |
| Mounts | Only the workspace is mounted. Credential directories and dotfiles can never be claimed. | fork-build (tabd validate) |
| Extensions placement | Every non-built-in extension runs in the tab, so UI-side code that holds secrets is first-party only (`extensionKind` `*` default plus patch 0002). | fork-build (product.json, patch) |
| Auth sessions and SecretStorage over RPC | `authentication.getSession` returns sentinels. SecretStorage and globalState are partitioned per tab. Server→client IPC is filtered. | RPC-lockdown session (M3/M4) |
| Egress | Real credentials are injected only by the broker, on egress that matches the binding. | broker session (M2/M3) |
| Verification | The **shared canary harness** seeds unique canaries in every host-side store and asserts that none appears, in any encoding, in anything a tab can observe or in supervisor and broker logs. | fork-build (harness); other sessions plug in |

## Alternatives considered
- **Short-lived real tokens in the tab**: rejected. They are still real for
  their lifetime and can be exfiltrated through any allowed host.
- **Trust sbx's placeholder injection alone**: rejected. It binds by host only
  (EDR sbx 0.51) and is not provider-neutral.

## Consequences
- Every feature that "just needs a token in the tab" must go through the
  broker (git over HTTPS, package registries, LLM APIs). Pinned-certificate
  clients that the broker can't serve are denied.
- The canary harness is the headline acceptance test. A canary found in a tab
  is a release blocker.

## Addendum (2026-11-04): environment invariant
**No host environment variable reaches anything in a tab.** This holds by construction:
- tabd spawns runtimes with an allowlisted env (`tabd/src/run.ts` `cleanEnv`);
- the tab template starts every REH process through `/opt/seclab/bin/seclab-tab-env`,
  which runs `env -i` with a fixed list;
- proxy variables are overridden in both cases.

So nothing may rely on passing configuration into a tab through environment variables:
not tests, not arming switches, not features. Use a file in the workspace, or the
tabd protocol. The RPC-lockdown session's env-based arming broke on exactly this, and
it now arms via a workspace file, as the fixture harness does.
