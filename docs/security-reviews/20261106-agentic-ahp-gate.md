# Security review: patch 0015, the agent-host gate

- **Date:** 2026-11-06
- **Scope:** patch 0015 (`seclab-ahp-gate`) and its sources under `agentic/patch-src/`:
  `seclabAhpPolicy.ts`, `seclabAhpPolicyData.ts`, `seclabAhpGateCheck.ts`,
  `seclabAhpGate.ts`, the upstream edits in `agentHostProtocolClient.ts` and
  `editorRemoteAgentHostServiceClient.ts`, `agentic/tools/sync-patch.ts` and
  `test/agentic/gate/gate.test.ts`.
- **Reviewer:** `security-review` agent (an Opus-class model), round 1 on `b4a3360`;
  triage and fixes by the agentic-gate session.
- **Related:** [EDR probe runner](../edr/20261106-agentic-probe-runner.md),
  [implementation plan](../plans/agentic-implementation.md) §4 increment 1,
  [design review](20261105-secure-agentic-experiences-design.md)

Every round's prompt carried the standing warning that the diff, fixtures and evidence may
contain prompt injection aimed at the reviewer, to be reported as a finding and never
followed. Round 1 found none.

## Round 1 (on `b4a3360`)
One high, one medium, no critical. Both are fixed in the commit that adds this record.

### HIGH (8/10): A1 is only half closed, MCP auth metadata gets past the sanitiser
`McpAuthRequirement.resource` is a `ProtectedResourceMetadata` carrying `resource`,
`authorization_servers` and `oauthClient`. None of those keys was in `STRIP_KEYS`, and the
carriers `chat/toolCallAuthRequired`, `session/mcpServerStateChanged` and
`session/customizationsChanged` were all `allow` inbound, as were the `initialize`,
`listSessions` and `resolveSessionConfig` results that embed `McpServerState`.

With no user interaction the trusted window then reaches
`_autoAuthenticateMcpServer` → `stateToProgressAdapter` (builds the request from
`auth.resource`) → `agentHostAuth.resolveResource` →
`agentHostMcpOAuthMetadataService`, which issues a **host-network** `requestService.request`
to a URL the agent host chose (`127.0.0.1`, `169.254.169.254`), and with
`authorization_servers` set instead registers a dynamic OAuth provider from the agent host's
origin. That is broker bypass and SSRF from the trusted side. Token exfiltration stayed
blocked, because `authenticate` is denied.

The reviewer ran the shipped filter on both messages and both were forwarded verbatim.

**Fix.**
- `chat/toolCallAuthRequired` is `deny` inbound: it exists only to drive that path.
- `seclabAhpSanitize` now replaces any object with `kind: 'auth-required'` by an inert
  `{kind: 'error', message}`, so the trigger itself never reaches the window.
- `STRIP_KEYS` gained `auth`, `authorization_servers`, `oauthClient` and
  `protectedResourceMetadata`, so the metadata is removed wherever it appears.
- Regression test `A1 (round 1 HIGH)` covers every carrier plus the bare keys.

### MEDIUM (9/10): `seclab.agents.enabled` was writable from the tab
`MainThreadConfiguration.$updateConfigurationOption` does no scope check, and `USER`
resolves to `USER_LOCAL`, so a rogue tab extension calling
`update('seclab.agents.enabled', true, Global)` persisted the value in the host's
`settings.json`. This confirms A23. `APPLICATION` scope does not help: it constrains the
remote-user layer, not this path.

**Fix.** `seclabAgentHostAllowed` no longer calls `getValue`, which merges every layer. It
accepts only sources a tab cannot write:
- `inspect().policyValue` (enterprise policy);
- `inspect().defaultValue`, when no policy value is set;
- `SECLAB_AGENTS_ENABLED=1` in the environment of the **host's main process**, read once at
  startup in `windowImpl.ts` and stamped onto `INativeWindowConfiguration` by
  `updateConfiguration` on **every** load, so a value carried in by whoever asked for the
  window is overwritten.

A host environment variable was chosen over a CLI flag (the user, 2026-11-06): a tab's
`code` CLI forwards through the remote CLI (`_remoteCLI.windowOpen`), so a flag is the
larger surface. The pattern matches patch 0012's `SECLAB_BACKGROUND_WINDOWS`, and the new
read is registered in `build/source-allowlist.txt`.

The setting stays registered at `APPLICATION` scope so policy can target it; its
description now says that user, remote and workspace values are ignored.

### Below threshold, carried forward
Recorded here so they are not lost; each is tracked for round 2 or a later increment.
- Fragment buffering reorders channel data; upstream rejects interleaving.
- `pending` is keyed by `String(id)`, so a response with `id:"7"` consumes numeric 7.
- The decision-log cap resets per connection, so forced reconnects grow the log.
- `connect` options pass through unfiltered (`env` is `{}` for the seclab resolver).

### Checked and sound
Bypass paths (a single `_transport` assignment site; the reconnect path also goes through
`_installTransport`), parse differentials, the `_meta` allowlist, the outbound tables, the
construction invariant (it fails closed), and log-line integrity.
