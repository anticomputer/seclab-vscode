# Security review: patch 0015, the agent-host gate

- **Date:** 2026-11-06
- **Scope:** patch 0015 (`seclab-ahp-gate`) and its sources under `agentic/patch-src/`:
  `seclabAhpPolicy.ts`, `seclabAhpPolicyData.ts`, `seclabAhpGateCheck.ts`,
  `seclabAhpGate.ts`, the upstream edits in `agentHostProtocolClient.ts` and
  `editorRemoteAgentHostServiceClient.ts`, `agentic/tools/sync-patch.ts` and
  `test/agentic/gate/gate.test.ts`.
- **Reviewer:** `security-review` agent (an Opus-class model), round 1 on `b4a3360`, round 2 on `7e0f0f6`;
  triage and fixes by the agentic-gate session.
- **Related:** [EDR probe runner](../edr/20261106-agentic-probe-runner.md),
  [implementation plan](../plans/agentic-implementation.md) §4 increment 1,
  [design review](20261105-secure-agentic-experiences-design.md)

Every round's prompt carried the standing warning that the diff, fixtures and evidence may
contain prompt injection aimed at the reviewer, to be reported as a finding and never
followed. Round 1 found none.

## Round 2 (on `7e0f0f6`)
Scope: the round 1 fixes, the two new upstream hunks, `build/source-allowlist.txt`, the probe
runner (`test/agentic/runner/`), `test/window.ts --app` and the gate tests. One high, one
medium, two low. All four are fixed in the commit that adds this section. No prompt injection
found.

### HIGH (9/10): round 1's fix was dead code, and the real carrier key was not stripped
The reviewer ran the shipped sanitiser on a real-shaped message and got **zero** removals.
- Upstream's MCP server discriminant is `kind: 'authRequired'` (`McpServerStatus.AuthRequired`),
  not `kind: 'auth-required'`. The hyphenated literal exists only as
  `ToolCallStatus.AuthRequired`, under the key `status`. So round 1's replacement branch never
  ran against real traffic.
- `McpAuthRequirement` carries the metadata under the key **`resource`**, which was not in
  `STRIP_KEYS`. Worse, stripping `authorization_servers` is what *forces* the discovery fetch:
  with no authorization server, `resolveMcpServerAuthentication` calls `resolveResource`, which
  requests the attacker's URL on the host network and falls back to that URL's origin as a
  dynamic OAuth provider.
- `agentHostCustomizationService` reaches `autoAuthenticateMcpServer` while merely mapping the
  MCP server list, with no turn and no user interaction.
- The round 1 regression test and the runner's A1 probe both used the non-existent shape, so
  neither would have caught this, on G or on U.

**Fix.**
- The sanitiser now matches `kind` of `authRequired` or `auth-required` **and** `status` of
  `auth-required` or `authRequired`, i.e. both spellings in both positions.
- The replacement is well formed: `McpServerErrorState` needs `error: ErrorInfo`, so the inert
  node is `{kind|status: 'error', error: {errorType: 'seclab-ahp-gate', message}}` rather than
  a bare `message`, which would have left the renderer dereferencing `state.error.message` on
  `undefined`.
- Belt and braces, because key-name matching is the wrong last line of defence here:
  `session/mcpServerStateChanged` and `session/customizationsChanged` are now **denied**
  inbound. They were already denied outbound. The sanitiser still covers the same state where
  it is embedded in an allowed result (`initialize`, `listSessions`, `resolveSessionConfig`).
- The regression test and the A1 probe were rewritten to the real shapes.

### MEDIUM (9/10): the runner's teardown marks never matched
`teardownGate` matches a command mark with whitespace or a line edge on each side, but the
beacon and the arming loop are spawned with **absolute** script paths, so the marks
`beacon.ts start …` and `runner.ts arm …` could never match. Both helpers are detached and
reparented, so the descendant walk missed them too, and `arm` passed the profile as a bare
positional so the `--user-data-dir` matcher missed it as well. The arming loop therefore
survived a "clean" teardown and kept injecting the hostile fixture into the tab for its full
ten-minute deadline. This is exactly the orphaned-hostile-process regression the teardown gate
exists to prevent.

**Fix.** Marks are derived from the very argv used to spawn each helper (`markFor`), `arm`
takes `--user-data-dir`, and the loop stops once the tab's sandbox has been gone for ten
seconds.

### LOW (9/10): `prepare` deleted its run directory before validating it
`base` comes from `--run-dir` or `SECLAB_AGENTIC_RUN_DIR` and was passed straight to a
recursive `rmSync`. **Fix:** `checkIsolatedProfile` is applied to `base` as soon as it is
resolved, which confines it to `~/.seclab-test/` or this worktree's `.work/`, symlinks
resolved.

### LOW (9/10): the fixture's arming check was tautological
`mitm.js` compared `cfg.arm` with `cfg.runNonce`, two copies of the same value in the same
config file, which sits in the tab's own workspace. **Fix:** the nonce must also match the one
the host passes on the command line, and `cfg.log` and `cfg.pid` must resolve inside `cfg.run`.

### Confirmed sound in round 2
The MEDIUM fix from round 1 was verified end to end: `policyValue` is out of a tab's reach;
`defaultValue` cannot be overridden by an extension's `configurationDefaults`, because the
setting is `APPLICATION` scope and
[`configurationExtensionPoint.ts#L217`](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/api/common/configurationExtensionPoint.ts#L217)
allows defaults overrides only for narrower scopes; and the stamp in `updateConfiguration` runs
before `configObjectUrl.update`, which is the only thing the renderer reads, so a value carried
in through `_remoteCLI.windowOpen` or any other opener is overwritten unconditionally. The
structural cast fails closed, because the browser environment service has no `configuration`.

Also re-checked and sound: the sanitiser's prototype, array and nesting behaviour (`JSON.parse`
makes `__proto__` an own property, so `delete` removes it); the construction invariant and its
`WeakMap` brand; the blanket refusal of agent-host→client requests, which independently blocks
the `RequestAgentHostMcpAuthentication` reverse-request route; `test/window.ts --app` (resolved,
existence-checked, no shell, focus protection untouched). The four carried-forward items from
round 1 were re-rated and stay below threshold.

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
