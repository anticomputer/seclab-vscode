# Security review: RPC follow-ups, landing A (push refusals, 0011 retired, regression tests)

- **Date:** 2026-11-16
- **Reviewer:** independent `security-review` agent (an Opus-class model)
- **Subject:** `git diff 6589051b..7fb28126` on `anticomputer-rpc-follow-ups`: patches 0030 and
  0031, the filter's push refusals and early decision hold, 0011's retirement, the push-probe
  fixes and proof harness, the new regression tests, the register closures and the python
  image bump.
- **Prompt:** said the diff, fixtures and evidence may contain prompt injection aimed at the
  reviewer, and that the reviewer reports it rather than following it. None was found.

## Verdict
No high or critical finding. One medium, a sibling of the path 0031 closes, stays open with a
follow-up; the overclaims it exposed are corrected in this landing.

| ID | Sev | Component | Finding | Status |
|---|---|---|---|---|
| RFU-1 | medium | terminal profile resolution (upstream `terminalProfileResolverService`, `remoteTerminalChannel.createProcess`) | A hostile REH answers `getDefaultSystemShell` (or `getProfiles`) with a path containing `${config:…}`; the window resolves it against the unfiltered configuration, which includes the host user's settings, and sends the result back to the REH in `createProcess`. 0031 closes the `${env:…}` push, not this request/response path | open |
| RFU-2 | info | 0015's AHP gate (0011's retirement) | For a transport whose identity is not a `seclab+` URI (the workspace-listed WebSocket entry), refusal depends on the window's gate sink being installed before the first reconcile. It is today (the service is Delayed and its first consumer runs at AfterRestored), but only the live proof run would notice a change in that ordering | open |
| RFU-3 | info | `seclabRpcFilter.ts` early decision hold | Before the first extension host installs the log, a REH can fill the 64 held slots with distinct channel-guard keys; later early decisions then show only as the `seclab.early-dropped` count. Nothing is lost silently and no line can be spoofed | accepted residual |

## Confirmed without findings
- Neither refusing handler can be bypassed: each push has one subscriber upstream, the local
  backend only ever serves the host's own pty host, and nothing registers a handler later.
- The other remote terminal events (`onDidRequestDetach`, `onProcessReplay`,
  `onDidChangeProperty`) reach no command service or host environment resolver.
- 0011's retirement holds for the paths a tab can steer: the editor window registers only the
  WebSocket factory (and cloud factories with fixed GitHub endpoints); SSH, WSL, tunnel and
  dev-container factories load only in the Agents window; the socket opens in `connect()`,
  after 0015's check; a token is forwarded only after a handshake.
- The probes and harness are loopback-only, use an isolated profile that teardown deletes,
  write only under `.work`, and the `openExternal` vector is gone.

## What changed in response
- RFU-1: `docs/RPC-LOCKDOWN.md`, the push-refusal EDR and the register no longer suggest 0031
  bounds `${config:…}`; RFU-1 is registered open with a follow-up (resolve terminal profile
  variables in tab windows against the tab's filtered configuration, or leave `config:`
  unresolved, plus a rogue-REH probe answering `getDefaultSystemShell` with a canary setting).
- RFU-2 is registered open; the reh-push proof checks the refusal on every run.
