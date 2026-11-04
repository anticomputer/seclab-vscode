# Canary acceptance harness (shared; headline acceptance test)

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** fork-build session (owner); broker and RPC-lockdown sessions plug in
- **Related:** [ADR no real secret in a tab](../adr/20261104-no-real-secret-in-a-tab.md)

## Decision
`test/canary/` holds the shared harness:
- `canary.ts`:
  - `mintCanary(store)` produces token-shaped values that are unique per store;
  - `encodings()` produces raw, base64, base64url, URL-encoded and hex forms
    (plus base64 at all three byte alignments);
  - `scan()` and `StreamScanner` search observed data for any canary in any of
    those forms, streaming so they can cover GBs.
- **Level A**, `run.ts` (`./seclab test canary [sbx|oci]`, runs in CI on OCI):
  1. Seeds canaries into the editor/supervisor process environment
     (`GITHUB_TOKEN`, `GH_TOKEN`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`,
     `AWS_SECRET_ACCESS_KEY`, `NPM_TOKEN`, `SSH_AUTH_SOCK`,
     `VSCODE_GIT_IPC_HANDLE`, `HTTPS_PROXY` userinfo, generic) and into a host
     credential file. tabd is deliberately spawned with that leaky env.
  2. Runs a real tab and exercises the REH transport.
  3. Scans, **as root inside the tab** (stronger than the attacker), every
     process's environ and cmdline plus the whole VM filesystem except the
     workspace mount. Also scans the tabd audit log, stderr, protocol
     notifications and state files.
  4. Self-test: the scanner finds all canaries in the host-side file.
     Positive control: a base64 canary planted in the tab is detected.
- **Level B**, `test/containment/check-evidence.ts prepare|check`, editor-driven:
  - seeds user settings (`seclab.test.canary`, `http.proxyAuthorization`), the
    host clipboard (`pbcopy`) and the editor's environment;
  - the rogue extension dumps what the API gives it (process env, the whole
    configuration, clipboard, GitHub/Microsoft sessions, its SecretStorage);
  - every evidence file is scanned.

## How other sessions plug in
- **Add a store:** mint a canary with `mintCanary('<store>')`, put it in the
  store, and append it to the run's canary list.
  - broker: proxy auth, injected credentials;
  - RPC-lockdown: SecretStorage of UI-side extensions, auth sessions, MCP inputs.
- **Add an observation source:** pass the data to `scan()` or a
  `StreamScanner`. Examples are broker logs, the RPC transcript seen by a rogue
  REH, and network responses received by the tab.

## Results (2026-11-04)
- sbx: 696 MB scanned in the tab, 11 canaries, **0 hits**; positive control
  detected.
- OCI: 334 MB scanned, **0 hits**; positive control detected.
- Level B: pending the macOS app. It is **expected to fail** for user-settings
  and clipboard canaries until the M4 RPC filter lands, because the remote
  extension host receives user configuration and can read the host clipboard
  through the API. That is the harness doing its job.
